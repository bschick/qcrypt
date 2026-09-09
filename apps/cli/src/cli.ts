import './setup-color';
import {
   cryptoReady,
   decryptStream,
   encryptStream,
   getCipherStreamInfo,
   makeCipherArmor,
   parseCipherArmor,
   base64ToBytes,
   bytesToBase64,
   readStreamAll,
   Ciphers,
   PWDKeyProvider,
   setLogErrors,
} from '@qcrypt/crypto';
import * as cc from '@qcrypt/crypto/consts';
import fs from 'node:fs';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { getSystemErrorMap } from 'node:util';
import { Readable, Writable } from 'node:stream';
import { once } from 'node:events';
import yargs from 'yargs/yargs';
import { hideBin } from 'yargs/helpers';
import { input, select, number, password } from '@inquirer/prompts';
import { makeTheme } from '@inquirer/core';
// @ts-expect-error package does not ship with types
import reopenTTY from 'reopen-tty';

interface IO {
   ttyIn?: NodeJS.ReadableStream;
   ttyOut: NodeJS.WritableStream;
   pipedIn?: ReadableStream<Uint8Array>;
   binaryIn: boolean;
   pipedOut: NodeJS.WritableStream;
   binaryOut: boolean;
   b64urlIn: boolean;
   b64urlOut: boolean;
}

// Returns a disposable Writable that delegates to io.ttyOut.
// Inquirer's cleanup ends the output stream it receives via pipe;
// by giving it a throwaway proxy, ttyOut itself stays open for
// subsequent prompts and showAnswered calls.
function iqOutput(io: IO): Writable {
   return new Writable({
      write(chunk: string | Uint8Array, encoding: BufferEncoding, callback: (error?: Error | null) => void) {
         if (typeof chunk === 'string') {
            io.ttyOut.write(chunk, encoding, callback);
         } else {
            io.ttyOut.write(chunk, callback);
         }
      },
   });
}

class ParamError extends Error {
   constructor(message: string) {
      super(message);
      this.name = 'ParamError';
   }
}

// Display a pre-supplied answer using inquirer's own theme so it looks
// identical to an interactively answered prompt.
const iqTheme = makeTheme();
function showAnswered(message: string, answer: string, io: IO): void {
   const prefixDone = typeof iqTheme.prefix === 'string' ? iqTheme.prefix : iqTheme.prefix.done;
   io.ttyOut.write(`${prefixDone} ${iqTheme.style.message(message, 'done')} ${iqTheme.style.answer(answer)}\n`);
}

async function peekBinary(
   source: Readable,
): Promise<{ pipedIn: ReadableStream<Uint8Array>; binaryIn: boolean; empty: boolean }> {
   const firstChunk: Buffer = await new Promise<Buffer>((resolve) => {
      // An empty source never becomes readable, so end has to resolve this too
      source.once('end', () => resolve(Buffer.alloc(0)));
      const tryRead = () => {
         const chunk = source.read(16);
         if (chunk) {
            resolve(chunk);
         } else {
            source.once('readable', tryRead);
         }
      };
      tryRead();
   });
   const head = firstChunk.subarray(0, 16).toString('utf-8');
   const binary = firstChunk.length === 0 || !/^\s*\{\s*"[\x20-\x7e]*$/.test(head);

   async function* prependedStream() {
      // A zero length chunk reads as a stalled source rather than the end of one
      if (firstChunk.length) {
         yield firstChunk.subarray(0);
      }
      for await (const chunk of source) {
         yield chunk;
      }
   }

   // ReadableStream.from is Node-only and absent from the DOM lib types
   const nodeReadableStream = ReadableStream as unknown as {
      from(iterable: AsyncIterable<Uint8Array>): ReadableStream<Uint8Array>;
   };
   return {
      pipedIn: nodeReadableStream.from(prependedStream()),
      binaryIn: binary,
      empty: firstChunk.length === 0,
   };
}

function streamFromBytes(data: Uint8Array<ArrayBuffer>): ReadableStream<Uint8Array> {
   return new ReadableStream({
      start(controller) {
         controller.enqueue(data);
         controller.close();
      },
   });
}

async function writeAndCloseStream(
   readableStream: ReadableStream<Uint8Array>,
   writeableStream: NodeJS.WritableStream,
): Promise<number> {
   const reader = readableStream.getReader();
   let written = 0;

   while (true) {
      const { done, value } = await reader.read();
      if (value) {
         // Without waiting, a consumer slower than the cipher queues the whole output in memory
         if (!writeableStream.write(value) && !(writeableStream as Writable).destroyed) {
            await once(writeableStream, 'drain');
         }
         written += value.byteLength;
      }
      if (done) {
         writeableStream.end();
         reader.releaseLock();
         break;
      }
   }

   return written;
}

async function getUserCred(
   args: {
      cred?: string;
      silent?: boolean;
      debug?: boolean;
   },
   io: IO,
): Promise<Uint8Array<ArrayBuffer>> {
   let credText: string;
   if (args.cred) {
      credText = args.cred;
      if (!args.silent) {
         showAnswered('User Credential:', '******', io);
      }
   } else if (args.silent) {
      throw new ParamError('User Credential is required in silent mode (use --cred)');
   } else {
      credText = await getSensitiveInput('User Credential', io);
   }

   try {
      credText = new URL(credText).searchParams.get('usercred') ?? credText;
   } catch {}

   return base64ToBytes(credText.trim());
}

async function getCipherStream(io: IO, silent?: boolean): Promise<ReadableStream<Uint8Array>> {
   let stream: ReadableStream<Uint8Array>;
   if (io.pipedIn && io.b64urlIn) {
      const text = await readStreamAll(io.pipedIn, true);
      if (!text) {
         throw new Error('Cipher text is empty (use positional arg, --infile, or stdin)');
      }
      stream = streamFromBytes(base64ToBytes(text.trim()));
   } else if (io.pipedIn && io.binaryIn) {
      stream = io.pipedIn;
   } else if (io.pipedIn) {
      const text = await readStreamAll(io.pipedIn, true);
      if (!text) {
         throw new Error('Cipher text is empty (use positional arg, --infile, or stdin)');
      }
      stream = streamFromBytes(parseCipherArmor(text));
   } else if (silent) {
      throw new ParamError('Cipher text is required in silent mode (use positional arg, --infile, or stdin)');
   } else {
      const text = await input(
         { message: io.b64urlIn ? 'Cipher (b64url):' : 'Cipher Armor:', required: true },
         { input: io.ttyIn, output: iqOutput(io) },
      );
      if (!text) {
         throw new Error('Cipher text is empty (use positional arg, --infile, or stdin)');
      }
      stream = io.b64urlIn ? streamFromBytes(base64ToBytes(text.trim())) : streamFromBytes(parseCipherArmor(text));
   }
   return stream;
}

async function getClearStream(io: IO, silent?: boolean): Promise<ReadableStream<Uint8Array>> {
   let stream: ReadableStream<Uint8Array>;
   if (io.pipedIn && io.b64urlIn) {
      const text = await readStreamAll(io.pipedIn, true);
      if (!text) {
         throw new Error('Clear text is empty (use positional arg, --infile, or stdin)');
      }
      stream = streamFromBytes(base64ToBytes(text.trim()));
   } else if (io.pipedIn) {
      stream = io.pipedIn;
   } else if (silent) {
      throw new ParamError('Clear text is required in silent mode (use positional arg, --infile, or stdin)');
   } else {
      const text = await input(
         { message: io.b64urlIn ? 'Clear (b64url):' : 'Clear Text:', required: true },
         { input: io.ttyIn, output: iqOutput(io) },
      );
      if (!text) {
         throw new Error('Clear text is empty (use positional arg, --infile, or stdin)');
      }
      stream = io.b64urlIn
         ? streamFromBytes(base64ToBytes(text.trim()))
         : streamFromBytes(new TextEncoder().encode(text));
   }
   return stream;
}

async function info(
   args: {
      cred?: string;
      silent?: boolean;
      debug?: boolean;
   },
   io: IO,
): Promise<void> {
   try {
      const cipherStream = await getCipherStream(io, args.silent);
      const userCred = await getUserCred(args, io);

      const cdInfo = await getCipherStreamInfo(cipherStream, new PWDKeyProvider(userCred, undefined));

      io.pipedOut.write(`Cipher and Mode   : ${Ciphers.algDescription(cdInfo.alg)}
PBKDF2 Iterations : ${cdInfo.ic}
Salt (b64Url)     : ${bytesToBase64(cdInfo.slt)}
Password Hint     : ${showHint(cdInfo.hint ?? '')}
Loops             : ${cdInfo.lpEnd}
Version           : ${cdInfo.ver}\n`);
   } catch (err) {
      if (args.debug) {
         console.error(err);
      } else {
         console.error('\nget info failed: ', (err as Error).message);
      }
      process.exitCode = 1;
   }
}

async function getSensitiveInput(msg: string, io: IO): Promise<string> {
   const val = await password(
      { message: `${msg}:`, mask: '*', validate: (v) => (!v ? `${msg} is required` : true) },
      { input: io.ttyIn, output: iqOutput(io) },
   );
   // inquirer's answered render leaves the cursor on the same line; ensure the
   // next direct write to ttyOut/pipedOut starts on a fresh line.
   io.ttyOut.write('\n');
   return val;
}

async function encrypt(
   args: {
      cred?: string;
      pwds?: string[];
      hints?: string[];
      iters?: number;
      algs?: string;
      loops: number;
      readStart?: number;
      readMax?: number;
      silent?: boolean;
      debug?: boolean;
   },
   io: IO,
): Promise<void> {
   try {
      args.loops = Math.max(Math.min(args.loops, 6), 1);

      let nextAlg: cc.CipherAlgs = 'X20-PLY';
      const keys = Ciphers.algs();
      const choices = keys.map((key) => {
         return { name: Ciphers.algDescription(key), value: key };
      });

      const algs: cc.CipherAlgs[] = [];

      for (let l = 1; l <= args.loops; l++) {
         const lpMsg = args.loops > 1 ? ` for loop ${l} of ${args.loops}` : '';
         let alg: cc.CipherAlgs;
         if (args.algs?.[l - 1]) {
            alg = Ciphers.validateAlg(args.algs[l - 1]);
            if (!args.silent) {
               showAnswered(`Select Cipher Mode${lpMsg}:`, Ciphers.algDescription(alg), io);
            }
         } else {
            alg = nextAlg;
            if (!args.silent) {
               alg = await select(
                  {
                     message: `Select Cipher Mode${lpMsg}:`,
                     choices,
                     default: nextAlg,
                  },
                  { input: io.ttyIn, output: iqOutput(io) },
               );
            }
         }

         const idx = keys.indexOf(alg);
         nextAlg = keys[(idx + 1) % keys.length];

         algs.push(alg);
      }

      let iters: number | undefined;
      if (args.iters && args.iters >= cc.ICOUNT_MIN) {
         iters = args.iters;
         if (!args.silent) {
            showAnswered('Password Hash Iterations:', String(iters), io);
         }
      } else if (args.silent) {
         iters = cc.ICOUNT_DEFAULT;
      } else {
         iters = await number(
            {
               message: 'Password Hash Iterations:',
               default: cc.ICOUNT_DEFAULT,
               min: cc.ICOUNT_MIN,
               required: true,
            },
            { input: io.ttyIn, output: iqOutput(io) },
         );
      }

      if (args.silent && (!args.pwds || args.pwds.length < args.loops)) {
         throw new ParamError(
            `${args.loops} password(s) required in silent mode but ${args.pwds?.length ?? 0} provided (use --pwds)`,
         );
      }

      const clearStream = await getClearStream(io, args.silent);
      const userCred = await getUserCred(args, io);

      const keyProvider = new PWDKeyProvider(userCred, async (cdinfo) => {
         const pos = cdinfo.lp - 1;
         const lpMsg = cdinfo.lpEnd > 1 ? ` for loop ${cdinfo.lp} of ${cdinfo.lpEnd}` : '';
         const argHint = args.hints && pos < args.hints.length ? args.hints[pos] : undefined;
         if (args.pwds && pos < args.pwds.length) {
            if (!args.silent) {
               showAnswered(`Password${lpMsg}:`, '******', io);
               if (argHint) {
                  showAnswered(`Password Hint${lpMsg}:`, argHint, io);
               }
            }
            return [args.pwds[pos]!, argHint];
         } else {
            const pwd = await getSensitiveInput(`Password${lpMsg}`, io);
            let hint: string | undefined;
            if (argHint) {
               if (!args.silent) {
                  showAnswered(`Password Hint${lpMsg}:`, argHint, io);
               }
               hint = argHint;
            } else {
               hint = await input(
                  { message: `Password Hint${lpMsg}:`, required: false },
                  { input: io.ttyIn, output: iqOutput(io) },
               );
            }
            return [pwd, hint];
         }
      });

      const readOpts =
         args.readStart || args.readMax ? { startSize: args.readStart, maxSize: args.readMax } : undefined;
      const cipherStream = await encryptStream(clearStream, keyProvider, { algs, ic: iters!, readOpts });

      let cipherLen: number;
      if (io.b64urlOut) {
         const cipherData = await readStreamAll(cipherStream);
         cipherLen = cipherData.byteLength;
         io.pipedOut.write(`${bytesToBase64(cipherData)}\n`);
      } else if (io.binaryOut) {
         cipherLen = await writeAndCloseStream(cipherStream, io.pipedOut);
      } else {
         const cipherData = await readStreamAll(cipherStream);
         cipherLen = cipherData.byteLength;
         io.pipedOut.write(`${makeCipherArmor(cipherData, 'compact')}\n`);
      }

      // Empty output means the clear stream was lost, not that there was nothing to encrypt
      if (cipherLen === 0) {
         throw new Error('encrypted output was empty');
      }
   } catch (err) {
      if (args.debug) {
         console.error(err);
      } else {
         console.error('\nencryption failed: ', (err as Error).message);
      }
      process.exitCode = 1;
   }
}

async function decrypt(
   args: {
      cred?: string;
      pwds?: string[];
      silent?: boolean;
      debug?: boolean;
   },
   io: IO,
): Promise<void> {
   try {
      const cipherStream = await getCipherStream(io, args.silent);
      const userCred = await getUserCred(args, io);

      const keyProvider = new PWDKeyProvider(userCred, async (cdinfo) => {
         const pos = cdinfo.lpEnd - cdinfo.lp;
         const lpMsg = cdinfo.lpEnd > 1 ? ` for loop ${cdinfo.lp} of ${cdinfo.lpEnd}` : '';
         if (args.pwds && pos < args.pwds.length) {
            if (!args.silent) {
               showAnswered(`Password${lpMsg}:`, '******', io);
            }
            return [args.pwds[pos]!];
         } else if (args.silent) {
            throw new ParamError(
               `${cdinfo.lpEnd} password(s) required in silent mode but ${args.pwds?.length ?? 0} provided (use --pwds)`,
            );
         } else {
            const hintMsg = lpMsg + (cdinfo.hint ? ` (hint: ${showHint(cdinfo.hint)})` : '');
            const pwd = await getSensitiveInput(`Password${hintMsg}`, io);
            return [pwd];
         }
      });

      const clearStream = await decryptStream(cipherStream, keyProvider);

      let clearLen: number;
      if (io.b64urlOut) {
         const clearData = await readStreamAll(clearStream);
         clearLen = clearData.byteLength;
         io.pipedOut.write(`${bytesToBase64(clearData)}\n`);
      } else if (io.binaryOut) {
         clearLen = await writeAndCloseStream(clearStream, io.pipedOut);
      } else {
         const clearText = await readStreamAll(clearStream, true);
         clearLen = clearText.length;
         io.pipedOut.write(`${clearText}\n`);
      }

      // Encryption rejects empty input, so every valid cipher text decrypts to at
      // least one byte. Empty output means the stream was lost, not decrypted
      if (clearLen === 0) {
         throw new Error('decrypted output was empty');
      }
   } catch (err) {
      if (args.debug) {
         console.error(err);
      } else {
         console.error('\ndecryption failed: ', (err as Error).message);
      }
      process.exitCode = 1;
   }
}

function CoerceNumber(argName: string) {
   return (val: unknown) => {
      const num = Number(val);
      if (Number.isNaN(num)) {
         throw new Error(`${argName} is not a valid number`);
      }
      return num;
   };
}

function CoerceAlgs(algs: string[]): cc.CipherAlgs[] {
   return Ciphers.validateAlgs(algs.map((alg: string) => alg.toUpperCase()));
}

//yargs seems to have a bug with nargs not working as described... if the credential starts with
// a -, it still gets picked up as an option. To work around, you can quoate it and start with a
// space that will be stripped (also works for [text])
const args = yargs(hideBin(process.argv))
   .usage('Usage: $0 <command> [text] [options]')
   // Without this, text that looks like a number is encrypted as a different string
   .parserConfiguration({ 'nargs-eats-options': true, 'parse-positional-numbers': false })
   .strict()
   .command({
      command: '$0 [text] [options]',
      aliases: ['dec'],
      describe: 'decrypt cipher data',
      builder: (yargs) => {
         return yargs
            .positional('text', { desc: 'cipher armor to decrypt (or use -f or stdin)', type: 'string' })
            .example('$0 -c 97jQeo8N16L4vhKzWy7ys -f doc.qq', ': prints decrypted text of doc.qq');
      },
      handler: () => {},
   })
   .command({
      command: 'info [text] [options]',
      describe: 'show information about cipher data',
      builder: (yargs) => {
         return yargs
            .positional('text', { desc: 'cipher armor to describe (or use -f or stdin)', type: 'string' })
            .example('$0 info -c 97jQeo8N16L4vhKzWy7ys -f doc.qq', ': prints encryption params for doc.qq');
      },
      handler: () => {},
   })
   .command({
      command: 'enc [text] [options]',
      describe: 'encrypt clear text',
      builder: (yargs) => {
         return yargs
            .positional('text', { desc: 'clear text to encrypt (or use -f or stdin)', type: 'string' })
            .options({
               iters: { alias: 'i', desc: `password hash iterations (min ${cc.ICOUNT_MIN})`, type: 'number' },
               algs: {
                  alias: 'a',
                  desc: 'encryption cipher mode(s)',
                  type: 'string',
                  array: true,
                  choices: Object.keys(cc.AlgInfo),
               },
               hints: {
                  alias: 'H',
                  desc: 'password hint(s), aligned by position with --pwds',
                  type: 'string',
                  array: true,
               },
               loops: { alias: 'l', desc: 'nested encryption loops (max 6)', type: 'number', default: 1 },
               'read-start': { desc: 'initial read chunk size in bytes (testing only)', type: 'number', hidden: true },
               'read-max': { desc: 'maximum read chunk size in bytes (testing only)', type: 'number', hidden: true },
            })
            .coerce({
               algs: CoerceAlgs,
               iters: CoerceNumber('iters'),
               loops: CoerceNumber('loops'),
               'read-start': CoerceNumber('read-start'),
               'read-max': CoerceNumber('read-max'),
            })
            .example('$0 enc -c 97jQeo8N16L4vhKzWy7ys -f doc.txt', ': prints encrypted text of doc.txt');
      },
      handler: () => {},
   })
   .options({
      cred: { alias: 'c', desc: 'user credential from https://quickcrypt.org/cmdline', type: 'string', nargs: 1 },
      credfile: { desc: 'read user credential from file', type: 'string', nargs: 1 },
      infile: { alias: 'f', desc: 'read input from file', type: 'string' },
      outfile: { alias: 'o', desc: 'save output to file', type: 'string' },
      force: { desc: 'overwrite --outfile if it already exists', boolean: true },
      pwds: { alias: 'p', desc: 'password(s)', type: 'string', array: true },
      b64url: {
         alias: 'b',
         desc: 'base64url-encode input, output, or both',
         type: 'string',
         choices: ['in', 'out', 'both'],
      },
      silent: { alias: 's', desc: 'ask for only required input and show fewer messages', boolean: true },
      debug: { alias: 'd', desc: 'show debug info', boolean: true },
      nocolor: { desc: 'disable colored output', boolean: true },
   })
   .conflicts('infile', 'text')
   .conflicts('cred', 'credfile')
   .epilog(
      'Values given on the command line are visible to other users while the command runs and are kept in shell history. Prefer --credfile and omit --cred and --pwds to be prompted.',
   )
   .version(false)
   .wrap(95)
   .check((argv, _options) => {
      // biome-ignore lint/suspicious/noExplicitAny: yargs argv shape is built dynamically from the option chain
      const args = argv as any;
      if (args.algs && args.algs.length > args.loops) {
         throw new Error(`${args.algs.length} algs provided for ${args.loops} loops`);
      }
      if (args.pwds && args.pwds.length > args.loops) {
         throw new Error(`${args.pwds.length} pwds provided for ${args.loops} loops`);
      }
      if (args.hints && args.hints.length > args.loops) {
         throw new Error(`${args.hints.length} hints provided for ${args.loops} loops`);
      }
      if (args._[0] === 'info' && args.b64url && args.b64url !== 'in') {
         throw new Error(`--b64url ${args.b64url} is not supported with the info command (only "in" is allowed)`);
      }
      return true;
   })
   .demandCommand(1)
   // biome-ignore lint/suspicious/noExplicitAny: yargs argv shape is built dynamically from the option chain
   .parseSync() as any;

// yargs repeats each option under its long name, alias, and camelCase form, so debug output names
// what is safe to print rather than trying to name every spelling of every value that must not be
const DEBUG_SHOW_KEYS = new Set([
   '_',
   '$0',
   'algs',
   'a',
   'iters',
   'i',
   'loops',
   'l',
   'b64url',
   'b',
   'force',
   'silent',
   's',
   'debug',
   'd',
   'nocolor',
   'credfile',
   'infile',
   'f',
   'outfile',
   'o',
   'read-start',
   'readStart',
   'read-max',
   'readMax',
]);

// Hints come from whoever encrypted the data, so controls are shown rather than run or dropped
function showHint(hint: string): string {
   return hint.replace(/\p{Cc}/gu, (ch) => `\\u${ch.charCodeAt(0).toString(16).padStart(4, '0')}`);
}

function maskForDebug(key: string, value: unknown): unknown {
   // Everything after -- lands in _ alongside the command, and may be text the user meant to pass
   if (key === '_' && Array.isArray(value)) {
      return value.map((entry, index) => (index === 0 ? entry : '******'));
   }
   if (DEBUG_SHOW_KEYS.has(key)) {
      return value;
   }
   // Cipher armor already reveals how long the cleartext is, so its length gives nothing away
   if (key === 'text' && typeof value === 'string') {
      return `****** (${value.length} chars)`;
   }
   return Array.isArray(value) ? value.map(() => '******') : '******';
}

if (args.debug) {
   const shown: Record<string, unknown> = {};
   for (const [key, value] of Object.entries(args)) {
      shown[key] = maskForDebug(key, value);
   }
   console.error('args ->', shown);
} else {
   setLogErrors(false);
}

function openTTY(kind: 'stdin' | 'stdout'): Promise<(fs.ReadStream & fs.WriteStream) | undefined> {
   return new Promise((resolve) => {
      reopenTTY[kind]((err: Error | null, stream: fs.ReadStream & fs.WriteStream) => {
         resolve(err ? undefined : stream);
      });
   });
}

type OutFile = {
   stream: fs.WriteStream;
   finish: () => Promise<void>;
};

const EXIT_SIGNALS = ['SIGINT', 'SIGTERM', 'SIGHUP'] as const;

function errDetail(err: unknown): string {
   const { errno, code, message } = err as NodeJS.ErrnoException;
   const reason = errno === undefined ? undefined : getSystemErrorMap().get(errno)?.[1];
   return reason ?? code ?? message;
}

// Output is written beside the destination and moved into place once complete, so decrypted data
// never inherits the destination's permissions, follows a symlink, or appears half written.
// Nothing this run creates should outlive a failure, including one delivered as a signal.
function openOutFile(outfile: string, force: boolean): OutFile {
   if (fs.existsSync(outfile)) {
      if (!force) {
         throw new Error(`${outfile} already exists, use --force to overwrite`);
      }
      try {
         // Otherwise the rename below would replace even a read-only file
         fs.accessSync(outfile, fs.constants.W_OK);
      } catch {
         throw new Error(`could not write ${outfile}: permission denied`);
      }
   }

   const prefix = path.join(path.dirname(outfile), `.${path.basename(outfile)}.`);
   const temp = `${prefix}${randomBytes(4).toString('hex')}`;
   // Masks the random part of a temp name, which the user never asked to write
   const showPath = `${prefix}*`;

   let created = false;
   const remove = (): void => {
      if (created) {
         created = false;
         try {
            fs.rmSync(temp, { force: true });
         } catch (err) {
            console.error(`\ncould not remove ${showPath}: ${errDetail(err)}`);
         }
      }
   };

   const onSignal = (signal: NodeJS.Signals): void => {
      remove();
      process.removeListener(signal, onSignal);
      process.kill(process.pid, signal);
   };
   // Registered before the file exists so nothing that can throw runs while it is unguarded
   for (const signal of EXIT_SIGNALS) {
      process.on(signal, onSignal);
   }

   // wx rather than w so a name taken since it was generated is refused rather than replaced
   const stream = fs.createWriteStream(temp, { mode: 0o600, flags: 'wx' });
   stream.once('open', () => {
      created = true;
   });
   // Attached now because a failure during the command closes the stream before it is ended
   const closed = new Promise<void>((resolve) => stream.once('close', () => resolve()));
   stream.on('error', (err) => {
      console.error(`\ncould not write ${showPath}: ${errDetail(err)}`);
      process.exitCode = 1;
   });

   const takenError = (): Error => new Error(`${outfile} already exists, use --force to overwrite`);

   // Claiming the name first keeps the refusal atomic, at the cost of an instant where the
   // destination is empty. Only for filesystems that cannot hard link, which have no better option
   const claimAndMove = (): void => {
      try {
         fs.closeSync(fs.openSync(outfile, 'wx', 0o600));
      } catch (err) {
         throw (err as NodeJS.ErrnoException).code === 'EEXIST' ? takenError() : err;
      }
      try {
         fs.renameSync(temp, outfile);
      } catch (err) {
         fs.rmSync(outfile, { force: true });
         throw err;
      }
   };

   // A hard link refuses a destination taken during the run, which rename would silently replace
   const commit = (): void => {
      if (force) {
         fs.renameSync(temp, outfile);
      } else {
         let linked = false;
         try {
            fs.linkSync(temp, outfile);
            linked = true;
         } catch (err) {
            if ((err as NodeJS.ErrnoException).code === 'EEXIST') {
               throw takenError();
            }
            claimAndMove();
         }
         if (linked) {
            try {
               // The destination is already complete, so a stranded temp is not worth failing over
               fs.rmSync(temp, { force: true });
            } catch (err) {
               console.error(`\ncould not remove ${showPath}: ${errDetail(err)}`);
            }
         }
      }
   };

   const finish = async (): Promise<void> => {
      if (!stream.destroyed) {
         stream.end();
      }
      await closed;
      for (const signal of EXIT_SIGNALS) {
         process.removeListener(signal, onSignal);
      }

      // Read after the close, since a write can still fail while the last of it is flushed
      if (process.exitCode === 1) {
         remove();
      } else {
         try {
            commit();
            created = false;
         } catch (err) {
            remove();
            throw err;
         }
      }
   };

   return { stream, finish };
}

async function main() {
   await cryptoReady();

   if (args.credfile) {
      try {
         args.cred = fs.readFileSync(args.credfile, 'utf-8').trim();
      } catch (err) {
         console.error(`\ncould not read ${args.credfile}: ${(err as Error).message}`);
         process.exitCode = 1;
         return;
      }
   }

   let pipedIn: ReadableStream<Uint8Array> | undefined;
   let binaryIn = false;
   if (args.infile) {
      ({ pipedIn, binaryIn } = await peekBinary(fs.createReadStream(args.infile)));
   } else if (!process.stdin.isTTY) {
      let emptyIn: boolean;
      ({ pipedIn, binaryIn, empty: emptyIn } = await peekBinary(process.stdin));
      // Redirected but empty stdin is what a scheduled job looks like, so the text is still meant
      if (args.text && emptyIn) {
         pipedIn = streamFromBytes(new TextEncoder().encode(args.text));
         binaryIn = false;
      } else if (args.text) {
         console.error('\ntext cannot be given together with piped input');
         process.exitCode = 1;
         return;
      }
   } else if (args.text) {
      pipedIn = streamFromBytes(new TextEncoder().encode(args.text));
   }

   const reopenedIn: fs.ReadStream | undefined = await openTTY('stdin');
   const reopenedOut: fs.WriteStream | undefined = !process.stdout.isTTY ? await openTTY('stdout') : undefined;

   if (!reopenedIn) {
      console.warn('Warning: no TTY available. All values must be passed via command-line options.');
      // Prompting anyway would echo answers, including clear text, into the output stream
      args.silent = true;
   }

   let outFile: OutFile | undefined;
   if (args.outfile) {
      try {
         outFile = openOutFile(args.outfile, args.force);
      } catch (err) {
         console.error(`\n${(err as Error).message}`);
         process.exitCode = 1;
         return;
      }
   }

   const b64urlIn = args.b64url === 'in' || args.b64url === 'both';
   const b64urlOut = args.b64url === 'out' || args.b64url === 'both';

   const io: IO = {
      ttyIn: reopenedIn,
      // stderr rather than stdout when there is no terminal, so prompts stay out of the data
      ttyOut: reopenedOut ?? (process.stdout.isTTY ? process.stdout : process.stderr),
      pipedIn,
      binaryIn,
      pipedOut: outFile?.stream ?? process.stdout,
      binaryOut: !!outFile || !process.stdout.isTTY,
      b64urlIn,
      b64urlOut,
   };

   if (args._.length && args._[0] === 'info') {
      await info(args, io);
   } else if (args._.length && args._[0] === 'enc') {
      await encrypt(args, io);
   } else {
      await decrypt(args, io);
   }

   if (outFile) {
      try {
         await outFile.finish();
      } catch (err) {
         // Errors raised here rather than by the filesystem already name the destination
         if ((err as NodeJS.ErrnoException).code) {
            console.error(`\ncould not write ${args.outfile}: ${errDetail(err)}`);
         } else {
            console.error(`\n${(err as Error).message}`);
         }
         process.exitCode = 1;
      }
   }
   reopenedIn?.destroy();
   reopenedOut?.destroy();
   completed = true;
}

// A stream that stalls rather than ending drains the event loop and would otherwise exit 0,
// reporting success for data that was never written
let completed = false;
process.on('exit', () => {
   // An already reported failure has said what went wrong, so only silence needs this
   if (!completed && process.exitCode !== 1) {
      console.error('\nthe operation did not finish');
      process.exitCode = 1;
   }
});

main();
