import './setup-color';
import sodium from 'libsodium-wrappers';
import {
   decryptStream, encryptStream, getCipherStreamInfo,
   makeCipherArmor, parseCipherArmor,
   base64ToBytes, bytesToBase64, readStreamAll,
} from '@qcrypt/crypto';
import * as cc from '@qcrypt/crypto/consts';
import fs from 'fs';
import { Readable, Writable } from 'node:stream';
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
}

// Returns a disposable Writable that delegates to io.ttyOut.
// Inquirer's cleanup ends the output stream it receives via pipe;
// by giving it a throwaway proxy, ttyOut itself stays open for
// subsequent prompts and showAnswered calls.
function iqOutput(io: IO): Writable {
   return new Writable({
      write(chunk: any, encoding: BufferEncoding, callback: (error?: Error | null) => void) {
         io.ttyOut.write(chunk, encoding, callback);
      }
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
   io.ttyOut.write(
      `${prefixDone} ${iqTheme.style.message(message, 'done')} ${iqTheme.style.answer(answer)}\n`
   );
}

async function peekBinary(source: Readable): Promise<{ pipedIn: ReadableStream<Uint8Array>, binaryIn: boolean }> {
   const firstChunk: Buffer = await new Promise(resolve => {
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
   const binary = firstChunk.length === 0 || !/^\s*\{/.test(firstChunk.subarray(0, 16).toString('utf-8'));

   async function* prependedStream() {
      yield new Uint8Array(firstChunk.buffer, firstChunk.byteOffset, firstChunk.byteLength);
      for await (const chunk of source) {
         yield chunk;
      }
   }

   return { pipedIn: (ReadableStream as any).from(prependedStream()), binaryIn: binary };
}

function streamFromBytes(data: Uint8Array<ArrayBuffer>): ReadableStream<Uint8Array> {
   return new ReadableStream({
      start(controller) {
         controller.enqueue(data);
         controller.close();
      }
   });
}

async function writeAndCloseStream(
   readableStream: ReadableStream<Uint8Array>,
   writeableStream: NodeJS.WritableStream
) {
   const reader = readableStream.getReader();

   while (true) {
      const { done, value } = await reader.read();
      if (value) {
         writeableStream.write(value);
      }
      if (done) {
         writeableStream.end();
         reader.releaseLock();
         break;
      }
   }
}

async function getUserCred(args: {
   cred?: string,
   silent?: boolean,
   debug?: boolean
}, io: IO): Promise<Uint8Array> {

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
   } catch (err) { }

   return base64ToBytes(credText.trim());
}

async function getCipherStream(
   io: IO,
   silent?: boolean
): Promise<ReadableStream<Uint8Array>> {
   let stream;
   if (io.pipedIn && io.binaryIn) {
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
         { message: 'Cipher Armor:', required: true },
         { input: io.ttyIn, output: iqOutput(io) }
      );
      if (!text) {
         throw new Error('Cipher text is empty (use positional arg, --infile, or stdin)');
      }
      stream = streamFromBytes(parseCipherArmor(text));
   }
   return stream;
}

async function getClearStream(
   io: IO,
   silent?: boolean
): Promise<ReadableStream<Uint8Array>> {
   let stream;
   if (io.pipedIn) {
      stream = io.pipedIn;
   } else if (silent) {
      throw new ParamError('Clear text is required in silent mode (use positional arg, --infile, or stdin)');
   } else {
      const text = await input(
         { message: 'Clear Text:', required: true },
         { input: io.ttyIn, output: iqOutput(io) }
      );
      if (!text) {
         throw new Error('Clear text is empty (use positional arg, --infile, or stdin)');
      }
      stream = streamFromBytes(new TextEncoder().encode(text));
   }
   return stream;
}

async function info(
   args: {
      cred?: string,
      silent?: boolean,
      debug?: boolean
   },
   io: IO
): Promise<void> {

   try {
      const cipherStream = await getCipherStream(io, args.silent);
      const userCred = await getUserCred(args, io);

      const cdInfo = await getCipherStreamInfo(
         userCred,
         cipherStream
      );

      io.pipedOut.write(`Cipher and Mode   : ${cc.AlgInfo[cdInfo.alg]['description']}
PBKDF2 Iterations : ${cdInfo.ic}
Salt (b64Url)     : ${bytesToBase64(cdInfo.slt)}
Password Hint     : ${cdInfo.hint}
Loops             : ${cdInfo.lpEnd}
Version           : ${cdInfo.ver}\n`);
   }
   catch (err) {
      if (args.debug) {
         console.error(err);
      } else {
         console.error('\nget info failed: ', (err as any).message);
      }
      process.exitCode = 1;
   }
}

async function getSensitiveInput(msg: string, io: IO): Promise<string> {
   const val = await password(
      { message: msg + ':', mask: '*', validate: (v) => !v ? `${msg} is required` : true },
      { input: io.ttyIn, output: iqOutput(io) }
   );
   return val;
}

async function encrypt(
   args: {
      cred?: string,
      pwds?: string[],
      iters?: number,
      algs?: string,
      loops: number,
      silent?: boolean,
      debug?: boolean
   },
   io: IO
): Promise<void> {

   try {
      const clearStream = await getClearStream(io, args.silent);
      const userCred = await getUserCred(args, io);

      args.loops = Math.max(Math.min(args.loops, 6), 1);

      let nextAlg = 'X20-PLY';
      let keys = Object.keys(cc.AlgInfo);
      let choices = keys.map((key) => {
         return { name: cc.AlgInfo[key]['description'] as string, value: key };
      });

      let algs = [];

      for (let l = 1; l <= args.loops; l++) {
         const lpMsg = args.loops > 1 ? ` for loop ${l} of ${args.loops}` : '';
         let alg;
         if (args.algs && args.algs[l - 1]) {
            alg = args.algs[l - 1];
            if (!args.silent) {
               showAnswered(`Select Cipher Mode${lpMsg}:`, cc.AlgInfo[alg]['description'] as string, io);
            }
         } else {
            alg = nextAlg;
            if (!args.silent) {
               alg = await select({
                     message: `Select Cipher Mode${lpMsg}:`,
                     choices: choices,
                     default: nextAlg
                  },
                  { input: io.ttyIn, output: iqOutput(io) }
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
         iters = await number({
               message: 'Password Hash Iterations:',
               default: cc.ICOUNT_DEFAULT,
               min: cc.ICOUNT_MIN,
               required: true
            },
            { input: io.ttyIn, output: iqOutput(io) }
         );
      }

      if (args.silent && (!args.pwds || args.pwds.length < args.loops)) {
         throw new ParamError(
            `${args.loops} password(s) required in silent mode but ${args.pwds?.length ?? 0} provided (use --pwds)`
         );
      }

      const econtext = {
         lpEnd: args.loops,
         algs: algs,
         ic: iters!
      };

      const cipherStream = await encryptStream(
         econtext,
         async (cdinfo) => {
            const pos = cdinfo.lp - 1;
            const lpMsg = cdinfo.lpEnd > 1 ? ` for loop ${cdinfo.lp} of ${cdinfo.lpEnd}` : '';
            if (args.pwds && pos < args.pwds.length) {
               if (!args.silent) {
                  showAnswered(`Password${lpMsg}:`, '******', io);
               }
               return [args.pwds[pos]!, undefined];
            } else {
               const pwd = await getSensitiveInput(`Password${lpMsg}`, io);
               const hint = await input(
                  { message: `Password Hint${lpMsg}:`, required: false },
                  { input: io.ttyIn, output: iqOutput(io) }
               );
               return [pwd, hint];
            }
         },
         userCred,
         clearStream
      );

      if (io.binaryOut) {
         await writeAndCloseStream(cipherStream, io.pipedOut);
      } else {
         const cipherData = await readStreamAll(cipherStream);
         io.pipedOut.write(makeCipherArmor(cipherData, 'compact') + '\n');
      }
   }
   catch (err) {
      if (args.debug) {
         console.error(err);
      } else {
         console.error('\nencryption failed: ', (err as any).message);
      }
      process.exitCode = 1;
   }
}

async function decrypt(
   args: {
      cred?: string,
      pwds?: string[],
      silent?: boolean,
      debug?: boolean
   },
   io: IO
): Promise<void> {

   try {
      const rawStream = await getCipherStream(io, args.silent);
      const userCred = await getUserCred(args, io);

      let cipherStream: ReadableStream<Uint8Array>;
      if (args.silent) {
         const [infoStream, mainStream] = rawStream.tee();
         const cdInfo = await getCipherStreamInfo(userCred, infoStream);
         await infoStream.cancel();
         if (!args.pwds || args.pwds.length < cdInfo.lpEnd) {
            await mainStream.cancel();
            throw new ParamError(
               `${cdInfo.lpEnd} password(s) required in silent mode but ${args.pwds?.length ?? 0} provided (use --pwds)`
            );
         }
         cipherStream = mainStream;
      } else {
         cipherStream = rawStream;
      }

      const clearStream = await decryptStream(
         async (cdinfo) => {
            const pos = cdinfo.lpEnd - cdinfo.lp;
            const lpMsg = cdinfo.lpEnd > 1 ? ` for loop ${cdinfo.lp} of ${cdinfo.lpEnd}` : '';
            if (args.pwds && pos < args.pwds.length) {
               if (!args.silent) {
                  showAnswered(`Password${lpMsg}:`, '******', io);
               }
               return [args.pwds[pos]!, undefined];
            } else {
               const hintMsg = lpMsg + (cdinfo.hint ? ` (hint: ${cdinfo.hint})` : '');
               const pwd = await getSensitiveInput(`Password${hintMsg}`, io);
               return [pwd, undefined];
            }
         },
         userCred,
         cipherStream
      );

      if (io.binaryOut) {
         await writeAndCloseStream(clearStream, io.pipedOut);
      } else {
         const clearText = await readStreamAll(clearStream, true);
         io.pipedOut.write(clearText + '\n');
      }
   }
   catch (err) {
      if (args.debug) {
         console.error(err);
      } else {
         console.error('\ndecryption failed: ', (err as any).message);
      }
      process.exitCode = 1;
   }
}

function CoerceNumber(argName: string) {
   return (val: any) => {
      let num = Number(val);
      if (isNaN(num)) {
         throw new Error(`${argName} is not a valid number`);
      }
      return num;
   };
}

function CoerceAlgs(algs: string[]) {
   const upperAlgs = algs.map((alg: string) => alg.toUpperCase());
   const validChoices = Object.keys(cc.AlgInfo);
   for (const alg of upperAlgs) {
      if (!validChoices.includes(alg)) {
         throw new Error(`Unsupported cipher mode: ${alg}. Valid choices are: ${validChoices.join(', ')}`);
      }
   }
   return upperAlgs;
}

//yargs seems to have a bug with nargs not working as described... if the credential starts with
// a -, it still gets picked up as an option. To work around, you can quoate it and start with a
// space that will be stripped (also works for [text])
const args = yargs(hideBin(process.argv))
   .usage('Usage: $0 <command> [text] [options]')
   .parserConfiguration({ 'nargs-eats-options': true })
   .strict()
   .command({
      command: '$0 [text] [options]',
      aliases: ['dec'],
      describe: 'decrypt cipher data',
      builder: (yargs) => {
         return yargs.positional('text', { desc: 'cipher armor to decrypt (or use -f or stdin)' })
            .example('$0 -c 97jQeo8N16L4vhKzWy7ys -f doc.qq', ': prints decrypted text of doc.qq');
      },
      handler: () => {}
   })
   .command({
      command: 'info [text] [options]',
      describe: 'show information about cipher data',
      builder: (yargs) => {
         return yargs.positional('text', { desc: 'cipher armor to describe (or use -f or stdin)' })
            .example('$0 info -c 97jQeo8N16L4vhKzWy7ys -f doc.qq', ': prints encryption params for doc.qq');
      },
      handler: () => {}
   })
   .command({
      command: 'enc [text] [options]',
      describe: 'encrypt clear text',
      builder: (yargs) => {
         return yargs.positional('text', { desc: 'clear text to encrypt (or use -f or stdin)' })
            .options({
               'iters': { alias: 'i', desc: `password hash iterations (min ${cc.ICOUNT_MIN})`, type: 'number' },
               'algs': { alias: 'a', desc: 'encryption cipher mode(s)', type: 'string', array: true, choices: Object.keys(cc.AlgInfo) },
               'loops': { alias: 'l', desc: 'nested encryption loops (max 6)', type: 'number', default: 1 },
            })
            .coerce({
               algs: CoerceAlgs,
               iters: CoerceNumber('iters'),
               loops: CoerceNumber('loops')
            })
            .example('$0 enc -c 97jQeo8N16L4vhKzWy7ys -f doc.txt', ': prints encrypted text of doc.txt');
      },
      handler: () => {}
   })
   .options({
      'cred': { alias: 'c', desc: 'user credential from https://quickcrypt.org/cmdline', type: 'string', nargs: 1 },
      'infile': { alias: 'f', desc: 'read input from file', type: 'string' },
      'outfile': { alias: 'o', desc: 'save output to file', type: 'string' },
      'pwds': { alias: 'p', desc: 'password(s)', type: 'string', array: true },
      'silent': { alias: 's', desc: 'ask for only required input and show fewer messages', boolean: true },
      'debug': { alias: 'd', desc: 'show debug info', boolean: true },
      'nocolor': { desc: 'disable colored output', boolean: true }
   })
   .conflicts('infile', 'text')
   .version(false)
   .wrap(95)
   .check((argv, options) => {
      const args = argv as any;
      if (args.algs && (args.algs.length > args.loops)) {
         throw new Error(`${args.algs.length} algs provided for ${args.loops} loops`);
      }
      if (args.pwds && (args.pwds.length > args.loops)) {
         throw new Error(`${args.pwds.length} pwds provided for ${args.loops} loops`);
      }
      return true;
   })
   .demandCommand(1).parseSync() as any;

if (args.debug) {
   console.error('args ->', args);
}

function openTTY(kind: 'stdin' | 'stdout'): Promise<any> {
   return new Promise(resolve => {
      reopenTTY[kind]((err: any, stream: any) => {
         resolve(err ? undefined : stream);
      });
   });
}

async function main() {
   await sodium.ready;

   let pipedIn: ReadableStream<Uint8Array> | undefined;
   let binaryIn = false;
   if (args.infile) {
      ({ pipedIn, binaryIn } = await peekBinary(fs.createReadStream(args.infile)));
   } else if (!process.stdin.isTTY) {
      ({ pipedIn, binaryIn } = await peekBinary(process.stdin));
   } else if (args.text) {
      pipedIn = streamFromBytes(new TextEncoder().encode(args.text));
   }

   const reopenedIn: fs.ReadStream | undefined = await openTTY('stdin');
   const reopenedOut: fs.WriteStream | undefined = !process.stdout.isTTY
      ? await openTTY('stdout') : undefined;

   if (!reopenedIn) {
      console.warn('Warning: no TTY available. All values must be passed via command-line options.');
   }

   let outfileStream: fs.WriteStream | undefined;
   if (args.outfile) {
      outfileStream = fs.createWriteStream(args.outfile);
   }

   const io: IO = {
      ttyIn: reopenedIn,
      ttyOut: reopenedOut ?? process.stdout,
      pipedIn,
      binaryIn,
      pipedOut: outfileStream ?? process.stdout,
      binaryOut: !!outfileStream || !process.stdout.isTTY,
   };

   if (args._.length && args._[0] === 'info') {
      await info(args, io);
   } else if (args._.length && args._[0] === 'enc') {
      await encrypt(args, io);
   } else {
      await decrypt(args, io);
   }

   outfileStream?.end();
   reopenedIn?.destroy();
   reopenedOut?.destroy();
}

main();
