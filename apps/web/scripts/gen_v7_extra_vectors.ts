// Standalone generator for the vectors used by the ciphers.spec.ts tests in
// "Decryption known values, key providers and extra key material".
//
// Self contained so it can be dropped into a v7.5.0 checkout without disturbing
// gen_helpers.ts, whose term-override monkey-patch targets a method that was
// later renamed.
//
// Copy to apps/web/scripts/ of the target checkout and run with:
//   TSX_TSCONFIG_PATH=apps/web/scripts/tsconfig.json pnpm exec tsx apps/web/scripts/gen_v7_extra_vectors.ts

import {
   cryptoReady,
   base64ToBytes,
   bytesToBase64,
   concatArrays,
   getLatestEncipher,
   PWDKeyProvider,
   MasterKeyKeyProvider,
} from '@qcrypt/crypto';
import type { KeyProvider, ReadOpts } from '@qcrypt/crypto';
import * as cc from '@qcrypt/crypto/consts';

const ver = cc.CURRENT_VERSION;
const plain = 'A nice 🦫 came to say hello';
const pwd = 'a 🌲 of course';
const hint = '🌧️';
const userCred = base64ToBytes('Ohyqajb6nFOm2Y5lOTkIkhc3uAaF8sUrYrQ9pts2pDc=');
const masterKey = base64ToBytes('TWFzdGVyS2V5Rml4ZWRTZWVkVmFsdWUwMTIzNDU2Nzg=');
const extra = base64ToBytes('RXh0cmFLZXlNYXQ=');
const ic = 1800000;
const algs: cc.CipherAlgs[] = ['AES-GCM', 'X20-PLY', 'AEGIS-256'];
const readOpts: ReadOpts = { startSize: 20, maxSize: 320 };

function streamFromStr(str: string): ReadableStream<Uint8Array> {
   const data = new TextEncoder().encode(str);
   return new Blob([data], { type: 'application/octet-stream' }).stream();
}

async function encryptAllBlocks(keyProvider: KeyProvider, alg: cc.CipherAlgs, icount: number): Promise<string> {
   const encipher = getLatestEncipher(streamFromStr(plain), keyProvider, alg, 1, 1, icount, readOpts);
   const parts: Uint8Array[] = [];
   while (true) {
      const block = await encipher.encryptBlock();
      for (const part of block.parts) {
         parts.push(part);
      }
      // CipherState.Finished is the terminal state. Use the numeric form to
      // avoid importing the enum (see ciphers-current.ts).
      if (block.state === 4 /* CipherState.Finished */) {
         break;
      }
   }
   return bytesToBase64(concatArrays(parts));
}

function printBanner(name: string): void {
   const rule = '═'.repeat(Math.min(process.stdout.columns ?? 80, 100) - 1);
   console.log(rule);
   console.log(`   ${name}`);
   console.log(rule);
}

async function main() {
   await cryptoReady();

   printBanner(`PWDKeyProvider without extra key material (V${ver})`);
   for (const alg of algs) {
      const keyProvider = new PWDKeyProvider(userCred.slice(0), [pwd, hint]);
      console.log(`               '${alg}': '${await encryptAllBlocks(keyProvider, alg, ic)}',`);
   }
   console.log();

   printBanner(`PWDKeyProvider with extra key material (V${ver})`);
   for (const alg of algs) {
      const keyProvider = new PWDKeyProvider(userCred.slice(0), [pwd, hint], extra.slice(0));
      console.log(`               '${alg}': '${await encryptAllBlocks(keyProvider, alg, ic)}',`);
   }
   console.log();

   // Master keys carry no password, so the iteration count is unused and passed as zero
   printBanner(`MasterKeyKeyProvider (V${ver})`);
   for (const alg of algs) {
      const keyProvider = new MasterKeyKeyProvider(masterKey.slice(0));
      console.log(`               '${alg}': '${await encryptAllBlocks(keyProvider, alg, 0)}',`);
   }
   console.log();

   printBanner(`MasterKeyKeyProvider with extra key material (V${ver})`);
   for (const alg of algs) {
      const keyProvider = new MasterKeyKeyProvider(masterKey.slice(0), extra.slice(0));
      console.log(`               '${alg}': '${await encryptAllBlocks(keyProvider, alg, 0)}',`);
   }
   console.log();
}

main().catch((err) => {
   console.error(err);
   process.exit(1);
});
