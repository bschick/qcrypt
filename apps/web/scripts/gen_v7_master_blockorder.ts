// Generates the v7 entry for the "Block order change and deletion detection,
// MasterKeyKeyProvider, multi-version" test in
// apps/web/src/app/services/cipher.service.spec.ts.
//
// Only the latest protocol version can be encrypted, so v7 vectors have to come
// from a v7.5.0 checkout. Copy this file to apps/web/scripts/ there and run:
//   TSX_TSCONFIG_PATH=apps/web/scripts/tsconfig.json pnpm exec tsx apps/web/scripts/gen_v7_master_blockorder.ts
//
// Emits a complete `vers` entry, ready to paste ahead of the v8 one.

// v7.5.0 calls the second MasterKeyKeyProvider argument `customAd`, which is
// positionally the extra key material this passes.
import {
   cryptoReady,
   base64ToBytes,
   bytesToBase64,
   concatArrays,
   getLatestEncipher,
   MasterKeyKeyProvider,
} from '@qcrypt/crypto';
import type { ReadOpts } from '@qcrypt/crypto';
import * as cc from '@qcrypt/crypto/consts';
import { morphInMemory, parseBuffer } from './parser.ts';
import { withTermOverrideEvery } from './gen_helpers.ts';

const ver = cc.CURRENT_VERSION;
const masterKey = base64ToBytes('TWFzdGVyS2V5Rml4ZWRTZWVkVmFsdWUwMTIzNDU2Nzg=');
const extra = base64ToBytes('RXh0cmFLZXlNYXQ=');
const alg: cc.CipherAlgs = 'AES-GCM';
const readOpts: ReadOpts = { startSize: 9, maxSize: 144 };

const morphs: Array<[string, string]> = [
   ['Block0 Block7 swap', 'b0^b7'],
   ['Block1 Block7 swap', 'b1^b7'],
   ['Block1 Block4 swap', 'b1^b4'],
   ['Block0 repeated', 'b0x2'],
   ['Block0 deleted', 'b0-'],
   ['Block1 repeated', 'b1x2'],
   ['Block1 deleted', 'b1-'],
   ['Block2 repeated', 'b2x2'],
   ['Block2 deleted', 'b2-'],
   ['Block7 (last) repeated', 'b7x2'],
   ['Block7 (last) deleted', 'b7-'],
   ['Block1 Block7 deleted', 'b1- b7-'],
];

// clearData copied verbatim from cipher.service.spec.ts
const clearData = new Uint8Array([
   118, 101, 114, 115, 105, 111, 110, 58, 32, 34, 51, 46, 56, 34, 10, 115, 101, 114, 118, 105, 99, 101, 115, 58, 10, 32,
   32, 100, 111, 99, 107, 103, 101, 58, 10, 32, 32, 32, 32, 105, 109, 97, 103, 101, 58, 32, 108, 111, 117, 105, 115,
   108, 97, 109, 47, 100, 111, 99, 107, 103, 101, 58, 49, 10, 32, 32, 32, 32, 114, 101, 115, 116, 97, 114, 116, 58, 32,
   117, 110, 108, 101, 115, 115, 45, 115, 116, 111, 112, 112, 101, 100, 10, 32, 32, 32, 32, 112, 111, 114, 116, 115, 58,
   10, 32, 32, 32, 32, 32, 32, 45, 32, 53, 48, 48, 49, 58, 53, 48, 48, 49, 10, 32, 32, 32, 32, 118, 111, 108, 117, 109,
   101, 115, 58, 10, 32, 32, 32, 32, 32, 32, 45, 32, 47, 118, 97, 114, 47, 114, 117, 110, 47, 100, 111, 99, 107, 101,
   114, 46, 115, 111, 99, 107, 58, 47, 118, 97, 114, 47, 114, 117, 110, 47, 100, 111, 99, 107, 101, 114, 46, 115, 111,
   99, 107, 10, 32, 32, 32, 32, 32, 32, 45, 32, 46, 47, 100, 97, 116, 97, 58, 47, 97, 112, 112, 47, 100, 97, 116, 97,
   10, 32, 32, 32, 32, 32, 32, 35, 32, 83, 116, 97, 99, 107, 115, 32, 68, 105, 114, 101, 99, 116, 111, 114, 121, 10, 32,
   32, 32, 32, 32, 32, 35, 32, 226, 154, 160, 239, 184, 143, 32, 82, 69, 65, 68, 32, 73, 84, 32, 67, 65, 82, 69, 70, 85,
   76, 76, 89, 46, 32, 73, 102, 32, 121, 111, 117, 32, 100, 105, 100, 32, 105, 116, 32, 119, 114, 111, 110, 103, 44, 32,
   121, 111, 117, 114, 32, 100, 97, 116, 97, 32, 99, 111, 117, 108, 100, 32, 101, 110, 100, 32, 117, 112, 32, 119, 114,
   105, 116, 105, 110, 103, 32, 105, 110, 116, 111, 32, 97, 32, 87, 82, 79, 78, 71, 32, 80, 65, 84, 72, 46, 10, 32, 32,
   32, 32, 32, 32, 35, 32, 226, 154, 160, 239, 184, 143, 32, 49, 46, 32, 70, 85, 76, 76, 32, 112, 97, 116, 104, 32, 111,
   110, 108, 121, 46, 32, 78, 111, 32, 114, 101, 108, 97, 116, 105, 118, 101, 32, 112, 97, 116, 104, 32, 40, 77, 85, 83,
   84, 41, 10, 32, 32, 32, 32, 32, 32, 35, 32, 226, 154, 160, 239, 184, 143, 32, 50, 46, 32, 76, 101, 102, 116, 32, 83,
   116, 97, 99, 107, 115, 32, 80, 97, 116, 104, 32, 61, 61, 61, 32, 82, 105, 103, 104, 116, 32, 83, 116, 97, 99, 107,
   115, 32, 80, 97, 116, 104, 32, 40, 77, 85, 83, 84, 41, 10, 32, 32, 32, 32, 32, 32, 45, 32, 47, 111, 112, 116, 47,
   115, 116, 97, 99, 107, 115, 58, 47, 111, 112, 116, 47, 115, 116, 97, 99, 107, 115, 10, 32, 32, 32, 32, 101, 110, 118,
   105, 114, 111, 110, 109, 101, 110, 116, 58, 10, 32, 32, 32, 32, 32, 32, 35, 32, 84, 101, 108, 108, 32, 68, 111, 99,
   107, 103, 101, 32, 119, 104, 101, 114, 101, 32, 116, 111, 32, 102, 105, 110, 100, 32, 116, 104, 101, 32, 115, 116,
   97, 99, 107, 115, 10, 32, 32, 32, 32, 32, 32, 45, 32, 68, 79, 67, 75, 71, 69, 95, 83, 84, 65, 67, 75, 83, 95, 68, 73,
   82, 61, 47, 111, 112, 116, 47, 115, 116, 97, 99, 107, 115,
]);

function streamFromBytes(data: Uint8Array<ArrayBuffer>): ReadableStream<Uint8Array> {
   return new Blob([data], { type: 'application/octet-stream' }).stream();
}

// Master keys carry no password, so the iteration count is unused and passed as zero
async function encryptOnce(): Promise<Uint8Array> {
   const keyProvider = new MasterKeyKeyProvider(masterKey.slice(0), extra.slice(0));
   const encipher = getLatestEncipher(streamFromBytes(clearData), keyProvider, alg, 1, 1, 0, readOpts);
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
   return concatArrays(parts);
}

function printBadCt(index: number, label: string, value: string): void {
   console.log(`            '${index}. ${label}':`);
   console.log(`               '${value}',`);
}

async function main() {
   await cryptoReady();

   const goodBytes = await encryptOnce();
   const parsed = parseBuffer(Buffer.from(goodBytes), 'goodCt', { maxHex: 64, maxBlocks: 256 });

   console.log(`      //v${ver} — generated by apps/web/scripts/gen_v7_master_blockorder.ts in a v7.5.0 checkout`);
   console.log(`      {`);
   console.log(`         ver: ${ver},`);
   console.log(`         goodCt:`);
   console.log(`            '${bytesToBase64(goodBytes)}',`);
   console.log(`         badCts: {`);

   let count = 0;
   for (const [label, morph] of morphs) {
      count += 1;
      const result = morphInMemory(parsed, morph);
      const bytes = new Uint8Array(result.bytes.buffer, result.bytes.byteOffset, result.bytes.byteLength);
      printBadCt(count, label, bytesToBase64(bytes));
   }

   const allTerm = await withTermOverrideEvery(true, encryptOnce);
   count += 1;
   printBadCt(count, 'All Term', bytesToBase64(allTerm));

   const noTerm = await withTermOverrideEvery(false, encryptOnce);
   count += 1;
   printBadCt(count, 'No Term', bytesToBase64(noTerm));

   console.log(`         },`);
   console.log(`      },`);

   // Diagnostics go to stderr so stdout stays a clean paste of the entry
   console.error(`   sanity: parsed ${parsed.blocks.length} blocks (morphs reference indices 0..7).`);
   if (parsed.blocks.length !== 8) {
      console.error(`   WARNING: got ${parsed.blocks.length} blocks; the Block7 morphs will be wrong.`);
   }
}

main().catch((err) => {
   console.error(err);
   process.exit(1);
});
