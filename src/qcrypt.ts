import sodium from 'libsodium-wrappers';
import { decryptStream, encryptStream, getCipherStreamInfo } from './app/services/cipher-streams';
import { makeCipherArmor, parseCipherArmor } from './app/core/armor';
import { base64ToBytes, bytesToBase64, readStreamAll } from './app/services/utils';
import * as cc from './app/services/cipher.consts';
import fs from 'fs';
import ws from 'node:stream/web';
import { Readable } from 'node:stream';
import yargs from 'yargs/yargs';
import { hideBin } from 'yargs/helpers';
import { input, select, number } from '@inquirer/prompts';
import reopenTTY from 'reopen-tty';

let ttyStream: fs.ReadStream;

function streamFromBytes(data: Uint8Array): ReadableStream<Uint8Array> {
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
   cred?: string
}): Promise<Uint8Array> {

   let credText = args.cred ?? await input(
      { message: 'User Credential:', required: true },
      { input: ttyStream }
   );
   try {
      credText = new URL(credText).searchParams.get('usercred') ?? credText;
   } catch (err) { }

   return base64ToBytes(credText.trim());
}

async function getCipherStream(
   args: {
      text?: string,
      infile?: string,
   },
   piped?: string
): Promise<ReadableStream<Uint8Array>> {
   let stream;
   if (args.infile && !args.infile.endsWith('.json')) {
      const nodeStream = fs.createReadStream(args.infile);
      // This does not produce a byod binary stream... but it still works
      stream = ws.ReadableStream.from(nodeStream) as ReadableStream<Uint8Array>;
   } else {
      let text;
      if (args.infile) {
         // json file containing... json
         const nodeStream = fs.createReadStream(args.infile);
         nodeStream.setEncoding('utf8');
         for await (const chunk of nodeStream) {
            text += chunk;
         }
      } else {
         text = args.text ?? piped;
         text = text ?? await input(
            { message: 'Cipher Armor:', required: true },
            { input: ttyStream }
         );
      }
      stream = streamFromBytes(parseCipherArmor(text!));
   }

   return stream;
}

async function getClearStream(
   args: {
      text?: string,
      infile?: string,
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
      text = text ?? await input(
         { message: 'Clear Text:', required: true },
         { input: ttyStream }
      );
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
   piped: string
): Promise<string> {

   let returnText = '';
   try {
      const userCred = await getUserCred(args);
      const cipherStream = await getCipherStream(args, piped);

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
         await writeToFile(await getClearStream({ text: returnText }), args.outfile);
         returnText = `saved to '${args.outfile}'`;
      }
   }
   catch (err) {
      console.error('\nget info failed: ', err.message);
      if (args.debug) {
         console.error(err);
      }
   }

   return returnText;
}

async function getPwd(
   lpMsg: string,
   args: {
      silent?: boolean,
      debug?: boolean
   }): Promise<string> {
   const pwd = await input(
      { message: `Password${lpMsg}:`, required: true },
      { input: ttyStream, clearPromptOnDone: true }
   );
   if (!args.silent) {
      await input(
         { message: `Password${lpMsg}:` },
         { input: Readable.from('******\n') }
      );
   }
   return pwd;
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
      trand: boolean,
      loops: number,
      silent?: boolean,
      debug?: boolean
   },
   piped: string,
): Promise<string> {

   let returnText = '';
   try {
      const userCred = await getUserCred(args);
      const clearStream = await getClearStream(args, piped);

      let nextAlg = 'X20-PLY';
      let keys = Object.keys(cc.AlgInfo);
      let choices = keys.map((key) => {
         return { name: cc.AlgInfo[key]['description'] as string, value: key };
      });

      let algs = [];

      for (let l = 1; l <= args.loops; l++) {
         const lpMsg = args.loops > 1 ? ` for loop ${l} or ${args.loops}` : '';
         let alg;
         if (args.algs && args.algs[l - 1]) {
            alg = args.algs[l - 1];
            // Show pre-supplied values if not silient
            if (!args.silent) {
               await input(
                  { message: `Select Cipher Mode${lpMsg}:` },
                  { input: Readable.from(cc.AlgInfo[alg]['description'] as string + '\n') }
               );
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

         do {
            nextAlg = keys[(Math.random() * keys.length) | 0]
         } while (nextAlg == alg);

         algs.push(alg);
      }

      let iters = !args.iters || args.iters < cc.ICOUNT_MIN ? await number({
            message: 'Password Hash Iterations:',
            default: cc.ICOUNT_DEFAULT,
            min: cc.ICOUNT_MIN,
            required: true
         },
         { input: ttyStream }
      ) : args.iters;

      const econtext = {
         lpEnd: Math.max(Math.min(args.loops, 10), 1),
         algs: algs,
         ic: iters!,
         trueRand: args.trand,
         fallbackRand: true
      };

      const cipherStream = await encryptStream(
         econtext,
         async (cdinfo) => {
            const pos = cdinfo.lp - 1;
            const lpMsg = cdinfo.lpEnd > 1 ? ` for loop ${cdinfo.lp} or ${cdinfo.lpEnd}` : '';
            if (args.pwds && pos < args.pwds.length) {
               // Show that we pre-supplied values (no hints for pre-supplied pwds)
               if (!args.silent) {
                  await input(
                     { message: `Password${lpMsg}:` },
                     { input: Readable.from('******\n') }
                  );
               }
               return [args.pwds[pos]!, undefined];
            } else {
               const pwd = await getPwd(lpMsg, args);
               let hint;
               // Don't ask for hints in silent mode
               if (!args.silent) {
                  hint = await input(
                     { message: `Password Hint${lpMsg}:`, required: false },
                     { input: ttyStream }
                  );
               }
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
      console.error('\nencryption failed: ', err.message);
      if (args.debug) {
         console.error(err);
      }
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
   piped: string
): Promise<string> {

   let returnText = '';
   try {
      const userCred = await getUserCred(args);
      const cipherStream = await getCipherStream(args, piped);

      const clearStream = await decryptStream(
         async (cdinfo) => {
            const pos = cdinfo.lpEnd - cdinfo.lp;
            const lpMsg = cdinfo.lpEnd > 1 ? ` for loop ${cdinfo.lp} or ${cdinfo.lpEnd}` : '';
            if (args.pwds && pos < args.pwds.length) {
               // Show pre-supplied values (no hints for pre-supplied pwds)
               if (!args.silent) {
                  await input(
                     { message: `Password${lpMsg}:` },
                     { input: Readable.from('******\n') }
                  );
               } return [args.pwds[pos], undefined];
            } else {
               const hintMsg = lpMsg + cdinfo.hint ? ` (hint: ${cdinfo.hint})` : '';
               const pwd = await getPwd(hintMsg, args);
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
      console.error('\ndecryption failed: ', err.message);
      if (args.debug) {
         console.error(err);
      }
   }

   return returnText;
}

function CoerceNumber(val: any) {
   let num = Number(val);
   if (isNaN(num)) {
      throw new Error(`${val} is not a number`);
   }
   return num;
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
      desc: 'decrypt cipher data',
      builder: (yargs) => {
         yargs.positional('text', { desc: 'cipher armor to decrypt (or use -f or stdin)' })
            .example('$0 -c 97jQeo8N16L4vhKzWy7ys -f doc.qq', ': prints decrypted text of doc.qq');
      }
   })
   .command({
      command: 'info [text] [options]',
      desc: 'show information about cipher data',
      builder: (yargs) => {
         yargs.positional('text', { desc: 'cipher armor to describe (or use -f or stdin)' })
            .example('$0 info -c 97jQeo8N16L4vhKzWy7ys -f doc.qq', ': prints encryption params for doc.qq');
      }
   })
   .command({
      command: 'enc [text] [options]',
      desc: 'encrypt clear text',
      builder: (yargs) => {
         yargs.positional('text', { desc: 'clear text to encrypt (or use -f or stdin)' })
            .options({
               'iters': { alias: 'i', desc: `password hash iterations (min ${cc.ICOUNT_MIN})`, type: 'number' },
               'algs': { alias: 'a', desc: 'encryption cipher mode(s)', type: 'string', array: true, choices: Object.keys(cc.AlgInfo) },
               'loops': { alias: 'l', desc: 'nested encryption loops (max 10)', type: 'number', default: 1 },
               'trand': { alias: 't', desc: 'use true random numbers', boolean: true, default: false },
            })
            .coerce({
               algs: (algs) => algs.map((alg: string) => alg.toUpperCase()),
               iters: CoerceNumber,
               loops: CoerceNumber
            })
            .example('$0 enc -c 97jQeo8N16L4vhKzWy7ys -f doc.txt', ': prints encrypted text of doc.txt');
      }
   })
   .options({
      'cred': { alias: 'c', desc: 'user credential from recovery url', type: 'string', nargs: 1 },
      'infile': { alias: 'f', desc: 'read input from file', type: 'string' },
      'outfile': { alias: 'o', desc: 'save output to file', type: 'string' },
      'pwds': { alias: 'p', desc: 'password(s)', type: 'string', array: true },
      'silent': { alias: 's', desc: 'ask for only required input and show fewer messages', boolean: true },
      'debug': { alias: 'd', desc: 'show debug info', boolean: true }
   })
   .conflicts('infile', 'text')
   .conflicts('debug', 'silent')
   .version(false)
   .wrap(95)
   .check((args, options) => {
      if (args.algs && (args.algs.length > args.loops)) {
         throw new Error(`${args.algs.length} algs provided for ${args.loops} loops`);
      }
      if (args.pwds && (args.pwds.length > args.loops)) {
         throw new Error(`${args.pwds.length} pwds provided for ${args.loops} loops`);
      }
      return true;
   })
   .demandCommand(1).parse();

if (args.debug) {
   console.log('args ->', args);
}

async function main() {
   await sodium.ready;

   let piped: string;
   try {
      piped = fs.readFileSync(process.stdin.fd, 'utf-8');
   } catch (err) { }

   reopenTTY.stdin(async (err, handle) => {
      ttyStream = handle;

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

      ttyStream.destroy();
   });
}

main();
