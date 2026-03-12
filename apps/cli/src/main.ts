import sodium from 'libsodium-wrappers';
import {
   decryptStream, encryptStream, getCipherStreamInfo,
   makeCipherArmor, parseCipherArmor,
   base64ToBytes, bytesToBase64, readStreamAll,
} from '@qcrypt/crypto';
import * as cc from '@qcrypt/crypto/consts';
import fs from 'fs';
import ws from 'node:stream/web';
import yargs from 'yargs/yargs';
import { hideBin } from 'yargs/helpers';
import { input, select, number, password } from '@inquirer/prompts';
import { makeTheme } from '@inquirer/core';
// @ts-expect-error package does not ship with types
import reopenTTY from 'reopen-tty';

let ttyStream: fs.ReadStream;

class ParamError extends Error {
   constructor(message: string) {
      super(message);
      this.name = 'ParamError';
   }
}

// Display a pre-supplied answer using inquirer's own theme so it looks
// identical to an interactively answered prompt.
const iqTheme = makeTheme();
function showAnswered(message: string, answer: string): void {
   console.log(`${iqTheme.prefix.done} ${iqTheme.style.message(message)} ${iqTheme.style.answer(answer)}`);
}

function streamFromBytes(data: Uint8Array<ArrayBuffer>): ReadableStream<Uint8Array> {
   const blob = new Blob([data], { type: 'application/octet-stream' });
   return blob.stream();
}

async function writeToFile(
   readableStream: ReadableStream<Uint8Array>,
   outFile: string
) {
   const writeableStream = fs.createWriteStream(outFile);
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
}): Promise<Uint8Array> {

   let credText: string;
   if (args.cred) {
      credText = args.cred;
      if (!args.silent) {
         showAnswered('User Credential:', '******');
      }
   } else if (args.silent) {
      throw new ParamError('User Credential is required in silent mode (use --cred)');
   } else {
      credText = await getSensitiveInput('User Credential', args);
   }

   try {
      credText = new URL(credText).searchParams.get('usercred') ?? credText;
   } catch (err) { }

   return base64ToBytes(credText.trim());
}

async function getCipherStream(
   args: {
      text?: string,
      infile?: string,
      silent?: boolean,
   },
   piped?: string
): Promise<ReadableStream<Uint8Array>> {
   let stream;
   if (args.infile && !args.infile.endsWith('.json')) {
      const nodeStream = fs.createReadStream(args.infile);
      // This does not produce a byod binary stream... but it still works
      stream = ws.ReadableStream.from(nodeStream) as ReadableStream<Uint8Array>;
   } else {
      let text: string | undefined = '';
      if (args.infile) {
         // json file containing... json
         const nodeStream = fs.createReadStream(args.infile);
         nodeStream.setEncoding('utf8');
         for await (const chunk of nodeStream) {
            text += chunk;
         }
      } else {
         text = args.text ?? piped;
         if (text && !args.silent) {
            showAnswered('Cipher Armor:', piped ? '(from stdin)' : '(from options)');
         } else if (!text && args.silent) {
            throw new ParamError('Cipher text is required in silent mode (use positional arg, --infile, or stdin)');
         }
         text = text ?? await input(
            { message: 'Cipher Armor:', required: true },
            { input: ttyStream }
         );
      }
      if (!text) {
         throw new Error('Cipher text is empty (use positional arg, --infile, or stdin)');
      }
      stream = streamFromBytes(parseCipherArmor(text));
   }

   return stream;
}

async function getClearStream(
   args: {
      text?: string,
      infile?: string,
      silent?: boolean,
   },
   piped?: string
): Promise<ReadableStream<Uint8Array>> {
   let stream;
   if (args.infile) {
      const nodeStream = fs.createReadStream(args.infile);
      // This does not produce a byod binary stream... but it still works
      stream = ws.ReadableStream.from(nodeStream) as ReadableStream<Uint8Array>;
   } else {
      let text = args.text ?? piped;
      if (text && !args.silent) {
         showAnswered('Clear Text:', piped ? '(from stdin)' : '(from options)');
      } else if (!text && args.silent) {
         throw new ParamError('Clear text is required in silent mode (use positional arg, --infile, or stdin)');
      }
      text = text ?? await input(
         { message: 'Clear Text:', required: true },
         { input: ttyStream }
      );
      if (!text) {
         throw new Error('Clear text is empty (use positional arg, --infile, or stdin)');
      }
      const bytes = new TextEncoder().encode(text);
      stream = streamFromBytes(bytes);
   }

   return stream;
}

async function info(
   args: {
      cred?: string,
      text?: string,
      pwds?: string[],
      infile?: string,
      outfile?: string,
      silent?: boolean,
      debug?: boolean
   },
   piped?: string
): Promise<string> {

   let returnText = '';
   try {
      const cipherStream = await getCipherStream(args, piped);
      const userCred = await getUserCred(args);

      const cdInfo = await getCipherStreamInfo(
         userCred,
         cipherStream
      );

      returnText = `Cipher and Mode   : ${cc.AlgInfo[cdInfo.alg]['description']}
PBKDF2 Iterations : ${cdInfo.ic}
Salt (b64Url)     : ${bytesToBase64(cdInfo.slt)}
IV/Nonce (b64Url) : ${bytesToBase64(cdInfo.iv)}
Password Hint     : ${cdInfo.hint}
Loops             : ${cdInfo.lpEnd}
Version           : ${cdInfo.ver}\n`;

      if (args.outfile) {
         await writeToFile(await getClearStream({ text: returnText, silent: args.silent }), args.outfile);
         returnText = `saved to '${args.outfile}'`;
      }
   }
   catch (err) {
      if (args.debug) {
         console.error(err);
      } else if (err instanceof ParamError) {
         console.error(`\n${err.message}`);
      } else {
         console.error('\nget info failed: ', (err as any).message);
      }
      process.exitCode = 1;
   }

   return returnText;
}

async function getSensitiveInput(
   msg: string,
   args: {
      silent?: boolean,
      debug?: boolean
   }): Promise<string> {
   const val = await password(
      { message: msg + ':', mask: '*', validate: (v) => !v ? `${msg} is required` : true },
      { input: ttyStream }
   );
   return val;
}

async function encrypt(
   args: {
      cred?: string,
      text?: string,
      pwds?: string[],
      infile?: string,
      outfile?: string,
      iters?: number,
      algs?: string,
      loops: number,
      silent?: boolean,
      debug?: boolean
   },
   piped?: string,
): Promise<string> {

   let returnText = '';
   try {
      const clearStream = await getClearStream(args, piped);
      const userCred = await getUserCred(args);

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
            // Show pre-supplied values if not silent
            if (!args.silent) {
               showAnswered(`Select Cipher Mode${lpMsg}:`, cc.AlgInfo[alg]['description'] as string);
            }
         } else {
            alg = nextAlg;
            if (!args.silent) {
               alg = await select({
                     message: `Select Cipher Mode${lpMsg}:`,
                     choices: choices,
                     default: nextAlg
                  },
                  { input: ttyStream }
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
            showAnswered('Password Hash Iterations:', String(iters));
         }
      } else {
         iters = await number({
               message: 'Password Hash Iterations:',
               default: cc.ICOUNT_DEFAULT,
               min: cc.ICOUNT_MIN,
               required: true
            },
            { input: ttyStream }
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
                  showAnswered(`Password${lpMsg}:`, '******');
               }
               return [args.pwds[pos]!, undefined];
            } else {
               const pwd = await getSensitiveInput(`Password${lpMsg}`, args);
               const hint = await input(
                  { message: `Password Hint${lpMsg}:`, required: false },
                  { input: ttyStream }
               );
               return [pwd, hint];
            }
         },
         userCred,
         clearStream
      );

      if (args.outfile) {
         await writeToFile(cipherStream, args.outfile);
         returnText = `saved to '${args.outfile}'`;
      } else {
         const clearData = await readStreamAll(cipherStream);
         returnText = makeCipherArmor(clearData, 'compact');
      }
   }
   catch (err) {
      if (args.debug) {
         console.error(err);
      } else if (err instanceof ParamError) {
         console.error(`\n${err.message}`);
      } else {
         console.error('\nencryption failed: ', (err as any).message);
      }
      process.exitCode = 1;
   }

   return returnText;
}

async function decrypt(
   args: {
      cred?: string,
      text?: string,
      pwds?: string[],
      infile?: string,
      outfile?: string,
      silent?: boolean,
      debug?: boolean
   },
   piped?: string
): Promise<string> {

   let returnText = '';
   try {
      const userCred = await getUserCred(args);

      if (args.silent) {
         const infoStream = await getCipherStream(args, piped);
         const cdInfo = await getCipherStreamInfo(userCred, infoStream);
         if (!args.pwds || args.pwds.length < cdInfo.lpEnd) {
            throw new ParamError(
               `${cdInfo.lpEnd} password(s) required in silent mode but ${args.pwds?.length ?? 0} provided (use --pwds)`
            );
         }
      }

      const cipherStream = await getCipherStream(args, piped);
      const clearStream = await decryptStream(
         async (cdinfo) => {
            const pos = cdinfo.lpEnd - cdinfo.lp;
            const lpMsg = cdinfo.lpEnd > 1 ? ` for loop ${cdinfo.lp} of ${cdinfo.lpEnd}` : '';
            if (args.pwds && pos < args.pwds.length) {
               if (!args.silent) {
                  showAnswered(`Password${lpMsg}:`, '******');
               }
               return [args.pwds[pos]!, undefined];
            } else {
               const hintMsg = lpMsg + (cdinfo.hint ? ` (hint: ${cdinfo.hint})` : '');
               const pwd = await getSensitiveInput(`Password${hintMsg}`, args);
               return [pwd, undefined];
            }
         },
         userCred,
         cipherStream
      );

      if (args.outfile) {
         await writeToFile(clearStream, args.outfile);
         returnText = `saved to '${args.outfile}'`;
      } else {
         returnText = await readStreamAll(clearStream, true);
      }
   }
   catch (err) {
      if (args.debug) {
         console.error(err);
      } else if (err instanceof ParamError) {
         console.error(`\n${err.message}`);
      } else {
         console.error('\ndecryption failed: ', (err as any).message);
      }
      process.exitCode = 1;
   }

   return returnText;
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
      'debug': { alias: 'd', desc: 'show debug info', boolean: true }
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
   console.log('args ->', args);
}

async function main() {
   await sodium.ready;

   let piped: string | undefined;
   if (!process.stdin.isTTY) {
      try {
         piped = fs.readFileSync(process.stdin.fd, 'utf-8');
      } catch (err) { }
   }

   reopenTTY.stdin(async (err: any, stream: fs.ReadStream) => {
      ttyStream = stream;

      if (!ttyStream) {
         console.warn('Warning: no TTY available. All values must be passed via command-line options.');
      }

      if (args._.length && args._[0] === 'info') {
         const infoText = await info(args, piped);
         console.log(`\n${infoText}`);
      }
      else if (args._.length && args._[0] === 'enc') {
         const cipherText = await encrypt(args, piped);
         console.log(`\n${cipherText}`);
      } else {
         const clearText = await decrypt(args, piped);
         console.log(`\n${clearText}`);
      }

      if (ttyStream) {
         ttyStream.destroy();
      }
   });
}

main();
