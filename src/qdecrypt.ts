import { alias } from "yargs";

const { createInterface } = require('node:readline/promises');
const { decryptStream, getCipherStreamInfo } = require('./app/services/cipher-streams');
const { base64ToBytes, bytesToBase64, readStreamAll } = require('./app/services/utils');
const fs = require('fs');
const ws = require('node:stream/web');
const yargs = require('yargs/yargs')
const { hideBin } = require('yargs/helpers')

const rl = createInterface({ input: process.stdin, output: process.stdout });

function streamFromBase64(b64: string): ReadableStream<Uint8Array> {
   const data = base64ToBytes(b64);
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

async function credAndStream(args: {
   cred: string,
   text: string | undefined,
   infile: string | undefined,
}) : Promise<[Uint8Array, ReadableStream<Uint8Array>]> {

   let credText = args.cred ?? await rl.question('User Credential (base64): ');
   const userCred = base64ToBytes(credText.trim());

   let cipherStream;
   if (args.infile) {
      const nodeStream = fs.createReadStream(args.infile);
      // This does not produce a byod binary stream... but it still works
      cipherStream = ws.ReadableStream.from(nodeStream);
   } else {
      let cipherText = args.text ?? await rl.question('Cipher text (base64): ');
      console.log();
      cipherText = cipherText.trim();
      cipherStream = streamFromBase64(cipherText);
   }

   return [userCred, cipherStream];
}

async function info(args: {
   cred: string,
   text: string | undefined,
   pwd: string | undefined,
   infile: string | undefined,
   outfile: string | undefined
}) {

   try {
      const [userCred, cipherStream] = await credAndStream(args);

      const cdInfo = await getCipherStreamInfo(
         userCred,
         cipherStream
      );

      console.log( `\nCipher and Mode   : ${cdInfo.alg}`);
      console.log( `PBKDF2 Iterations : ${cdInfo.ic}`);
      console.log( `Salt (b64Url)     : ${bytesToBase64(cdInfo.slt)}`);
      console.log( `IV/Nonce (b64Url) : ${bytesToBase64(cdInfo.iv)}`);
      console.log( `Password Hint     : ${cdInfo.hint}`);
      console.log( `Loops             : ${cdInfo.lpEnd}`);
      console.log( `Version           : ${cdInfo.ver}`);
   }
   catch (err) {
      console.error('\ndecryption failed: ', err.message);
   }
}

async function decrypt(args: {
   cred: string,
   text: string | undefined,
   pwd: string[] | undefined,
   infile: string | undefined,
   outfile: string | undefined
}): Promise<string> {

   let returnText = '';

   // Tried to support reading from stdin, but node seems to close stdin
   // after reading the piped data. So givin up on that and just prompting.
   //   piped = fs.readFileSync(process.stdin.fd, 'utf-8');

   try {
      const [userCred, cipherStream] = await credAndStream(args);

      const clearStream = await decryptStream(
         async (cdinfo) => {
            const pos = cdinfo.lpEnd - cdinfo.lp;
            if (args.pwd && pos < args.pwd.length) {
               return [args.pwd[pos], undefined];
            } else {
               const lpMsg = cdinfo.lpEnd > 1 ? ` for loop ${cdinfo.lp} or ${cdinfo.lpEnd}` : '';
               return [await rl.question(`Password${lpMsg} (hint: ${cdinfo.hint}): `), undefined];
            }
         },
         userCred,
         cipherStream
      );

      if (args.outfile) {
         await writeToFile(clearStream, args.outfile);
      } else {
         returnText = await readStreamAll(clearStream, true);
      }
   }
   catch (err) {
      console.error('\ndecryption failed: ', err.message);
   }

   return Promise.resolve(returnText);
}

//yargs seems to have a bug with nargs not working as described... if the credential starts with
// a -, it still gets picked up as an option. To work around, you can quoate it and start with a
// space that will be stripped (also works for [text])
const args = yargs(hideBin(process.argv))
   .usage('Usage: $0 <command> [text] [options]')
   .example('$0 -c 97jQeo8N16Lo0h6BKzy4vhhrWy7ys -i armor.qq', ': prints decrypted clear text of armor.qq')
   .strict()
   .command({
      command: '$0 [text]',
      aliases: ['dec'],
      desc: 'decrypt cipher data',
      builder: (yargs) => {
         yargs.positional('text', { desc: 'cipher text to decrypt (or use -i)' });
      }
   })
   .command({
      command: 'info [text]',
      desc: 'show information about cipher data',
      builder: (yargs) => {
         yargs.positional('text', { desc: 'cipher text to describe (or use -i)' });
      }
   })
   .options({
      'cred': { alias: 'c', desc: 'user credential from recovery url', nargs: 1 },
      'infile': { alias: 'i', desc: 'input file' },
      'outfile': { alias: 'o', desc: 'output file' },
      'pwd': { alias: 'p', desc: 'password', array: true },
   })
   .conflicts('infile', 'text')
   .version(false)
   .wrap(null)
   .demandCommand(1).parse();

if(args._.length && args._[0] === 'info') {
   info(args).then(() => {
      rl.close();
   });
} else {
   decrypt(args).then((clearText) => {
      if (clearText) {
         console.log( `\n${clearText}`);
      }
      rl.close();
   });
}
