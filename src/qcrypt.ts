import sodium from 'libsodium-wrappers';
import { decryptStream, encryptStream, getCipherStreamInfo } from './app/services/cipher-streams';
import { makeCipherArmor, parseCipherArmor } from './app/core/armor';
import { base64ToBytes, bytesToBase64, readStreamAll } from './app/services/utils';
import fs from 'fs';
import ws from 'node:stream/web';
import yargs from 'yargs/yargs';
import { hideBin } from 'yargs/helpers';
import { input, select, number } from '@inquirer/prompts';

let piped: string;

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
   cred: string
}): Promise<Uint8Array> {

   let credText = args.cred ?? await input({ message: 'User Credential:', required: true });
   try {
      credText = new URL(credText).searchParams.get('usercred') ?? credText;
   } catch (err) { }

   return base64ToBytes(credText.trim());
}

async function getCipherStream(args: {
   text?: string,
   infile?: string,
}): Promise<ReadableStream<Uint8Array>> {
   let stream;
   if (args.infile && !args.infile.endsWith('.json')) {
      const nodeStream = fs.createReadStream(args.infile);
      // This does not produce a byod binary stream... but it still works
      stream = ws.ReadableStream.from(nodeStream) as ReadableStream<Uint8Array>;
   } else {
      let text = '';
      if (args.infile) {
         // json file containing... json
         const nodeStream = fs.createReadStream(args.infile);
         nodeStream.setEncoding('utf8');
         for await (const chunk of nodeStream) {
            text += chunk;
         }
      } else {
         text = args.text ?? piped;
         text = text ?? await input({ message: 'Cipher Armor:', required: true });
      }
      stream = streamFromBytes(parseCipherArmor(text));
   }

   return stream;
}

async function getClearStream(args: {
   text?: string,
   infile?: string,
}): Promise<ReadableStream<Uint8Array>> {
   let stream;
   if (args.infile) {
      const nodeStream = fs.createReadStream(args.infile);
      // This does not produce a byod binary stream... but it still works
      stream = ws.ReadableStream.from(nodeStream) as ReadableStream<Uint8Array>;
   } else {
      const text = args.text ?? await input({ message: 'Clear Text:', required: true });
      const bytes = new TextEncoder().encode(text);
      stream = streamFromBytes(bytes);
   }

   return stream;
}

async function info(args: {
   cred: string,
   text?: string,
   pwds?: string,
   infile?: string,
   outfile?: string,
   debug?: boolean
}): Promise<string> {

   let returnText = '';
   try {
      const userCred = await getUserCred(args);
      const cipherStream = await getCipherStream(args);

      const cdInfo = await getCipherStreamInfo(
         userCred,
         cipherStream
      );

      returnText =`Cipher and Mode   : ${cdInfo.alg}
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
      if(args.debug) {
         console.error(err);
      }
   }

   return returnText;
}

async function encrypt(args: {
   cred: string,
   text?: string,
   pwds?: string[],
   infile?: string,
   outfile?: string,
   iters?: number,
   alg?: string,
   trand: boolean,
   loops: number,
   debug?: boolean
}): Promise<string> {

   let returnText = '';
   try {
      const userCred = await getUserCred(args);
      const clearStream = await getClearStream(args);

      let alg = !args.alg ? await select({
         message: 'Select Cipher Mode:',
         choices: [
            { name: 'AES 256 GCM ', value: 'AES-GCM' },
            { name: 'XChaCha20 Poly1305', value: 'X20-PLY' },
            { name: 'AEGIS 256', value: 'AEGIS-256' },
         ],
         default: 'X20-PLY'
      }) : args.alg.toUpperCase();

      let iters = !args.iters || args.iters < 400000 ? await number({
         message: 'Password Hash Iterations:',
         default: 1100000,
         min: 400000,
         required: true
      }) : args.iters;

      const econtext = {
         lpEnd: args.loops,
         alg: alg,
         ic: iters!,
         trueRand: args.trand,
         fallbackRand: true
      };

      const cipherStream = await encryptStream(
         econtext,
         async (cdinfo) => {
            const pos = cdinfo.lp - 1;
            if (args.pwds && pos < args.pwds.length) {
               return [args.pwds[pos], undefined];
            } else {
               const lpMsg = cdinfo.lpEnd > 1 ? ` for loop ${cdinfo.lp} or ${cdinfo.lpEnd}` : '';
               const pwd = await input({ message: `Password${lpMsg}:`, required: true });
               const hint = await input({ message: `Password Hint${lpMsg}:`, required: true });
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
      if(args.debug) {
         console.error(err);
      }
   }

   return returnText;
}

async function decrypt(args: {
   cred: string,
   text?: string,
   pwds?: string[],
   infile?: string,
   outfile?: string,
   debug?: boolean
}): Promise<string> {

   let returnText = '';
   try {
      const userCred = await getUserCred(args);
      const cipherStream = await getCipherStream(args);

      const clearStream = await decryptStream(
         async (cdinfo) => {
            const pos = cdinfo.lpEnd - cdinfo.lp;
            if (args.pwds && pos < args.pwds.length) {
               return [args.pwds[pos], undefined];
            } else {
               const lpMsg = cdinfo.lpEnd > 1 ? ` for loop ${cdinfo.lp} or ${cdinfo.lpEnd}` : '';
               const hintMsg = cdinfo.hint ? ` (hint: ${cdinfo.hint})` : '';
               return [await input({ message: `Password${lpMsg}${hintMsg}:`, required: true }), undefined];
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
      if(args.debug) {
         console.error(err);
      }
   }

   return returnText;
}

function CoerceNumber(val: any) {
   let num = Number(val);
   if(isNaN(num)) {
      throw new Error(`${val} is not a number`);
   }
   return num;
}

//yargs seems to have a bug with nargs not working as described... if the credential starts with
// a -, it still gets picked up as an option. To work around, you can quoate it and start with a
// space that will be stripped (also works for [text])
const args = yargs(hideBin(process.argv))
   .usage('Usage: $0 <command> [text] [options]')
   .strict()
   .command({
      command: '$0 [text] [options]',
      aliases: ['dec'],
      desc: 'decrypt cipher data',
      builder: (yargs) => {
         yargs.positional('text', { desc: 'cipher armor to decrypt (or use -f)' })
            .example('$0 -c 97jQeo8N16L4vhKzWy7ys -f doc.qq', ': prints decrypted text of doc.qq');
      }
   })
   .command({
      command: 'info [text] [options]',
      desc: 'show information about cipher data',
      builder: (yargs) => {
         yargs.positional('text', { desc: 'cipher armor to describe (or use -f)' })
            .example('$0 info -c 97jQeo8N16L4vhKzWy7ys -f doc.qq', ': prints encryption params for doc.qq');
      }
   })
   .command({
      command: 'enc [text] [options]',
      desc: 'encrypt clear text',
      builder: (yargs) => {
         yargs.positional('text', { desc: 'clear text to encrypt (or use -f)' })
            .options({
               'iters': { alias: 'i', desc: 'password hash iterations (min 400000)' },
               'alg': { alias: 'a', desc: 'cipher algorithm and mode', choices: ['aes-gcm', 'x20-ply', 'aegis-256'] },
               'loops': { alias: 'l', desc: 'nested encryption loops', default: 1 },
               'trand': { alias: 't', desc: 'use true random numbers', boolean: true, default: false },
            })
            .coerce({
               alg: (alg) => alg.toLowerCase(),
               iters: CoerceNumber,
               loops: CoerceNumber
             })
            .example('$0 enc -c 97jQeo8N16L4vhKzWy7ys -f doc.txt', ': prints encrypted text of doc.txt');
      }
   })
   .options({
      'cred': { alias: 'c', desc: 'user credential from recovery url', nargs: 1 },
      'infile': { alias: 'f', desc: 'read input from file' },
      'outfile': { alias: 'o', desc: 'save output to file' },
      'pwds': { alias: 'p', desc: 'password(s)', array: true },
      'debug': { alias: 'd', desc: 'show debug info', boolean: true}
   })
   .conflicts('infile', 'text')
   .version(false)
   .wrap(95)
   .demandCommand(1).parse();

if(args.debug) {
   console.log('args ->', args);
}

async function main() {
   await sodium.ready;

   // Tried to support reading from piped input, but haven't figured out how to
   // get node stdin to switch from the pipe to tty. If you pipe something in
   // this part works, but then the prompts error out.
   try {
      piped = fs.readFileSync(process.stdin.fd, 'utf-8');
   } catch (err) {}

   if (args._.length && args._[0] === 'info') {
      const infoText = await info(args);
      console.log(`\n${infoText}`);
   }
   else if (args._.length && args._[0] === 'enc') {
      const cipherText = await encrypt(args);
      console.log(`\n${cipherText}`);
   } else {
      const clearText = await decrypt(args);
      console.log(`\n${clearText}`);
   }
}

main().then(() => {
});
