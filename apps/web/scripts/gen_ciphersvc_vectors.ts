// AI-Assist: 100% Claude Code Generated
//
// Generates v{CURRENT_VERSION} cipher text vectors for tests in
// apps/web/src/app/services/cipher.service.spec.ts:
//   - "confirm successful version decryption, multi-version"
//   - "confirm successful version decryption, multi-version loops"
//   - "detect missing terminal block indicator, multi-version"
//   - "detect extra terminal block indicator, multi-version"
//   - "detect flipped terminal block indicator, multi-version"
//   - "detect corrupt cipher text, all algs, multi-version"
//   - "Stream manipulation, multi-version"
//   - "Block order change and deletion detection, multi-version"
//
// Run with: pnpm vectors:ciphersvc

import {
   cryptoReady,
   PWDKeyProvider,
   encryptStream,
   readStreamAll,
   base64ToBytes,
   Ciphers,
} from '@qcrypt/crypto';
import type { EContext } from '@qcrypt/crypto';
import * as cc from '@qcrypt/crypto/consts';
import {
   morphInMemory,
   parseBuffer,
} from './parser.ts';
import {
   streamFromStr,
   streamFromBytes,
   withTermOverride,
   withTermOverrideEvery,
   encryptOneLoop,
   uint8ArrayLiteral,
   toBase64,
   printBanner,
} from './gen_helpers.ts';

const VER = cc.CURRENT_VERSION;

// Single-loop, multi-alg vectors for "confirm successful version decryption,
// multi-version". Inputs match the test's userCred / pwd / hint / clear text.
async function genSingleLoopMultiVersion(): Promise<void> {
   const PLAIN = 'physical farm bolt correct bee nonchalant glib high able pinch left quaint strip valuable exultant disgusted curved bless geese snatch zoom fat touch boot abject wink pretty accessible foamy';
   const CRED = base64ToBytes('xhKm2Q404pGkqfWkTyT3UodUR-99bN0wibH6si9uF8I');
   const PWD = '9j5J4QnKD3D2R7Ks5gAAa';
   const HINT = 'royal';
   const ALGS: cc.CipherAlgs[] = ['AES-GCM', 'X20-PLY', 'AEGIS-256'];

   printBanner(`confirm successful version decryption, multi-version (V${VER})`);

   for (const alg of ALGS) {
      const bytes = await encryptOneLoop(streamFromStr(PLAIN), CRED, PWD, HINT, alg, cc.ICOUNT_MIN);
      console.log(`               // ${alg}: V${VER}`);
      console.log(`               "${toBase64(bytes)}",`);
   }
   console.log();
}

// Generates the 3-loop vectors. Each entry is one ciphertext with a 3-alg
// loop chain. Algs match the comments above the existing v6 vectors.
async function genMultiVersionLoops(): Promise<void> {
   const PLAIN = 'physical farm bolt correct bee nonchalant glib high able pinch left quaint strip valuable exultant disgusted curved bless geese snatch zoom fat touch boot abject wink pretty accessible foamy';
   const CRED = base64ToBytes('xhKm2Q404pGkqfWkTyT3UodUR-99bN0wibH6si9uF8I');

   // Algs per loop. The order is innermost-first (lp=1 is the first encrypt).
   const LOOP_ALGS: ReadonlyArray<{ algs: cc.CipherAlgs[] }> = [
      { algs: ['AES-GCM', 'X20-PLY', 'AEGIS-256'] },
      { algs: ['AEGIS-256', 'X20-PLY', 'AEGIS-256'] },
      { algs: ['AEGIS-256', 'AES-GCM', 'AES-GCM'] },
   ];

   printBanner(`confirm successful version decryption, multi-version loops (V${VER})`);

   for (const { algs } of LOOP_ALGS) {
      // Per-loop pwd/hint = String(cdinfo.lp) — matches the test callback.
      const kp = new PWDKeyProvider(CRED.slice(0), async (cdinfo) => {
         return [String(cdinfo.lp), String(cdinfo.lp)];
      });
      const econtext: EContext = { algs, ic: cc.ICOUNT_MIN };
      const cipherStream = await encryptStream(streamFromStr(PLAIN), kp, econtext);
      const cipherBytes = await readStreamAll(cipherStream);
      console.log(`               // ${algs.join(", ")}, V${VER}, 3 LPS`);
      console.log(`               "${toBase64(cipherBytes)}",`);
   }
   console.log();
}

async function genMissingTerminal(): Promise<void> {
   // Same plaintext / userCred / pwd / hint / ic / alg as the existing
   // v5 / v6 entries in the test, with small READ_OPTS to force multi-block
   // and a forced term=false on the last block.
   const PLAIN = 'A nice 🦫 came to say hello';
   const PWD = 'a 🌲 of course';
   const HINT = '🌧️';
   const CRED = base64ToBytes('Ohyqajb6nFOm2Y5lOTkIkhc3uAaF8sUrYrQ9pts2pDc=');
   const IC = 1800000;
   const ALG: cc.CipherAlgs = 'X20-PLY';
   const READ_OPTS = { startSize: 20, maxSize: 320 };

   printBanner(`detect missing terminal block indicator, multi-version (V${VER})`);

   const bytes = await withTermOverride(false, false, async () => {
      return encryptOneLoop(streamFromStr(PLAIN), CRED, PWD, HINT, ALG, IC, READ_OPTS);
   });
   console.log(`            cipherData: ${uint8ArrayLiteral(bytes)}`);
   console.log();
}

async function genExtraAndFlippedTerminal(): Promise<void> {
   // Same inputs as genMissingTerminal so the test reuses the same userCred/pwd/hint.
   const PLAIN = 'A nice 🦫 came to say hello';
   const PWD = 'a 🌲 of course';
   const HINT = '🌧️';
   const CRED = base64ToBytes('Ohyqajb6nFOm2Y5lOTkIkhc3uAaF8sUrYrQ9pts2pDc=');
   const IC = 1800000;
   const ALG: cc.CipherAlgs = 'X20-PLY';
   const READ_OPTS = { startSize: 20, maxSize: 320 };

   printBanner(`detect extra terminal block indicator, V${VER}`);
   const extraBytes = await withTermOverride(true, true, async () => {
      return encryptOneLoop(streamFromStr(PLAIN), CRED, PWD, HINT, ALG, IC, READ_OPTS);
   });
   console.log(`         cipherData: ${uint8ArrayLiteral(extraBytes)}`);
   console.log();

   printBanner(`detect flipped terminal block indicator, V${VER}`);
   const flippedBytes = await withTermOverride(true, false, async () => {
      return encryptOneLoop(streamFromStr(PLAIN), CRED, PWD, HINT, ALG, IC, READ_OPTS);
   });
   console.log(`         cipherData: ${uint8ArrayLiteral(flippedBytes)}`);
   console.log();
}

async function genCorruptCipherText(): Promise<void> {
   const PLAIN = 'this 🐞 is encrypted';
   const PWD = 'asdf';
   const HINT = 'asdf';
   const CRED = base64ToBytes('ZfZIlUPklSM8fFG7nWDQ2XuT5DxU1sZ0wKKykzJ3Yfs');
   const IC = 1100000;
   const ALGS: cc.CipherAlgs[] = ['AES-GCM', 'X20-PLY', 'AEGIS-256'];

   printBanner(`detect corrupt cipher text, all algs, multi-version (V${VER})`);

   for (const alg of ALGS) {
      const bytes = await encryptOneLoop(streamFromStr(PLAIN), CRED, PWD, HINT, alg, IC);
      console.log(`               //${alg}`);
      console.log(`               "${toBase64(bytes)}",`);
   }
   console.log();
}

async function genStreamManipulation(clearData: Uint8Array): Promise<void> {
   const PWD = 'asdf';
   const HINT = '4321';
   const CRED = base64ToBytes('xhKm2Q404pGkqfWkTyT3UodUR-99bN0wibH6si9uF8I');
   const IC = 1100000;
   const ALG: cc.CipherAlgs = 'AES-GCM';
   const READ_OPTS = { startSize: 256, maxSize: 10496 };

   printBanner(`Stream manipulation, multi-version (V${VER})`);

   const bytes = await encryptOneLoop(
      streamFromBytes(clearData), CRED, PWD, HINT, ALG, IC, READ_OPTS
   );

   // Extract slt and iv from block0 at the v6+ offsets (FLAGS in payload AD).
   const ivLen = Number(Ciphers.algIVByteLength(ALG));
   const ivOffset = cc.MAC_BYTES + cc.VER_BYTES + cc.PAYLOAD_SIZE_BYTES + cc.FLAGS_BYTES + cc.ALG_BYTES;
   const sltOffset = ivOffset + ivLen;
   const iv = bytes.slice(ivOffset, ivOffset + ivLen);
   const slt = bytes.slice(sltOffset, sltOffset + cc.SLT_BYTES);
   const block0Size = cc.MAC_BYTES + cc.VER_BYTES + cc.PAYLOAD_SIZE_BYTES + readU24LE(bytes, cc.MAC_BYTES + cc.VER_BYTES);

   console.log(`         ct: "${toBase64(bytes)}",`);
   console.log(`         slt: ${uint8ArrayLiteral(slt)},`);
   console.log(`         iv: ${uint8ArrayLiteral(iv)},`);
   console.log();
   console.log(`   // sanity: total cipher bytes=${bytes.byteLength}, block0 size=${block0Size}, expected block1MACOffset=366`);
   if (block0Size !== 366) {
      console.log(`   // WARNING: block0 ends at ${block0Size}, but the test hardcodes block1MACOffset=366. Update the offset constants in the spec or adjust READ_OPTS.`);
   }
   console.log();
}

async function genBlockOrder(clearData: Uint8Array): Promise<void> {
   const PWD = 'asdf';
   const HINT = '4321';
   const CRED = base64ToBytes('xhKm2Q404pGkqfWkTyT3UodUR-99bN0wibH6si9uF8I');
   const IC = 1100000;
   const ALG: cc.CipherAlgs = 'AES-GCM';
   const READ_OPTS = { startSize: 9, maxSize: 144 };

   printBanner(`Block order change and deletion detection, multi-version (V${VER})`);

   // goodCt: encrypted normally
   const goodBytes = await encryptOneLoop(
      streamFromBytes(clearData), CRED, PWD, HINT, ALG, IC, READ_OPTS
   );
   const parsed = parseBuffer(Buffer.from(goodBytes), 'goodCt', { maxHex: 64, maxBlocks: 256 });
   const blockCount = parsed.blocks.length;

   // (label, morph string). The morph operators are documented in parser.ts.
   const MORPHS: Array<[string, string]> = [
      ['Block0 Block7 swap',  'b0^b7'],
      ['Block1 Block7 swap',  'b1^b7'],
      ['Block1 Block4 swap',  'b1^b4'],
      ['Block0 repeated',     'b0x2'],
      ['Block0 deleted',      'b0-'],
      ['Block1 repeated',     'b1x2'],
      ['Block1 deleted',      'b1-'],
      ['Block2 repeated',     'b2x2'],
      ['Block2 deleted',      'b2-'],
      ['Block7 (last) repeated', 'b7x2'],
      ['Block7 (last) deleted',  'b7-'],
      ['Block1 Block7 deleted',  'b1- b7-'],
   ];

   console.log(`         goodCt: "${toBase64(goodBytes)}",`);
   console.log(`         badCts: {`);
   let n = 0;
   for (const [label, morph] of MORPHS) {
      n += 1;
      try {
         const result = morphInMemory(parsed, morph);
         const b64 = toBase64(new Uint8Array(result.bytes.buffer, result.bytes.byteOffset, result.bytes.byteLength));
         console.log(`            '${n}. ${label}': '${b64}',`);
      } catch (err) {
         const msg = err instanceof Error ? err.message : String(err);
         console.log(`            // ERROR for '${n}. ${label}': ${msg}`);
      }
   }

   // 'All Term' / 'No Term' need code-level term-flag overrides — re-encrypt
   // the same plaintext with every block forced terminal=true / =false.
   const allTerm = await withTermOverrideEvery(true, async () => {
      return encryptOneLoop(streamFromBytes(clearData), CRED, PWD, HINT, ALG, IC, READ_OPTS);
   });
   n += 1;
   console.log(`            '${n}. All Term': '${toBase64(allTerm)}',`);

   const noTerm = await withTermOverrideEvery(false, async () => {
      return encryptOneLoop(streamFromBytes(clearData), CRED, PWD, HINT, ALG, IC, READ_OPTS);
   });
   n += 1;
   console.log(`            '${n}. No Term': '${toBase64(noTerm)}',`);
   console.log(`         }`);

   console.log();
   console.log(`   // sanity: parsed ${blockCount} blocks (morphs reference indices 0..7, so 8 blocks expected).`);
   if (blockCount !== 8) {
      console.log(`   // WARNING: got ${blockCount} blocks; some Block7 morphs will fail. Adjust READ_OPTS or clearData.`);
   }
   console.log();
}

function readU24LE(buf: Uint8Array, offset: number): number {
   return buf[offset] | (buf[offset + 1] << 8) | (buf[offset + 2] << 16);
}

// clearData copied verbatim from cipher.service.spec.ts (Stream manipulation
// and Block order tests share it).
const CLEAR_DATA = new Uint8Array([118, 101, 114, 115, 105, 111, 110, 58, 32, 34, 51, 46, 56, 34, 10, 115, 101, 114, 118, 105, 99, 101, 115, 58, 10, 32, 32, 100, 111, 99, 107, 103, 101, 58, 10, 32, 32, 32, 32, 105, 109, 97, 103, 101, 58, 32, 108, 111, 117, 105, 115, 108, 97, 109, 47, 100, 111, 99, 107, 103, 101, 58, 49, 10, 32, 32, 32, 32, 114, 101, 115, 116, 97, 114, 116, 58, 32, 117, 110, 108, 101, 115, 115, 45, 115, 116, 111, 112, 112, 101, 100, 10, 32, 32, 32, 32, 112, 111, 114, 116, 115, 58, 10, 32, 32, 32, 32, 32, 32, 45, 32, 53, 48, 48, 49, 58, 53, 48, 48, 49, 10, 32, 32, 32, 32, 118, 111, 108, 117, 109, 101, 115, 58, 10, 32, 32, 32, 32, 32, 32, 45, 32, 47, 118, 97, 114, 47, 114, 117, 110, 47, 100, 111, 99, 107, 101, 114, 46, 115, 111, 99, 107, 58, 47, 118, 97, 114, 47, 114, 117, 110, 47, 100, 111, 99, 107, 101, 114, 46, 115, 111, 99, 107, 10, 32, 32, 32, 32, 32, 32, 45, 32, 46, 47, 100, 97, 116, 97, 58, 47, 97, 112, 112, 47, 100, 97, 116, 97, 10, 32, 32, 32, 32, 32, 32, 35, 32, 83, 116, 97, 99, 107, 115, 32, 68, 105, 114, 101, 99, 116, 111, 114, 121, 10, 32, 32, 32, 32, 32, 32, 35, 32, 226, 154, 160, 239, 184, 143, 32, 82, 69, 65, 68, 32, 73, 84, 32, 67, 65, 82, 69, 70, 85, 76, 76, 89, 46, 32, 73, 102, 32, 121, 111, 117, 32, 100, 105, 100, 32, 105, 116, 32, 119, 114, 111, 110, 103, 44, 32, 121, 111, 117, 114, 32, 100, 97, 116, 97, 32, 99, 111, 117, 108, 100, 32, 101, 110, 100, 32, 117, 112, 32, 119, 114, 105, 116, 105, 110, 103, 32, 105, 110, 116, 111, 32, 97, 32, 87, 82, 79, 78, 71, 32, 80, 65, 84, 72, 46, 10, 32, 32, 32, 32, 32, 32, 35, 32, 226, 154, 160, 239, 184, 143, 32, 49, 46, 32, 70, 85, 76, 76, 32, 112, 97, 116, 104, 32, 111, 110, 108, 121, 46, 32, 78, 111, 32, 114, 101, 108, 97, 116, 105, 118, 101, 32, 112, 97, 116, 104, 32, 40, 77, 85, 83, 84, 41, 10, 32, 32, 32, 32, 32, 32, 35, 32, 226, 154, 160, 239, 184, 143, 32, 50, 46, 32, 76, 101, 102, 116, 32, 83, 116, 97, 99, 107, 115, 32, 80, 97, 116, 104, 32, 61, 61, 61, 32, 82, 105, 103, 104, 116, 32, 83, 116, 97, 99, 107, 115, 32, 80, 97, 116, 104, 32, 40, 77, 85, 83, 84, 41, 10, 32, 32, 32, 32, 32, 32, 45, 32, 47, 111, 112, 116, 47, 115, 116, 97, 99, 107, 115, 58, 47, 111, 112, 116, 47, 115, 116, 97, 99, 107, 115, 10, 32, 32, 32, 32, 101, 110, 118, 105, 114, 111, 110, 109, 101, 110, 116, 58, 10, 32, 32, 32, 32, 32, 32, 35, 32, 84, 101, 108, 108, 32, 68, 111, 99, 107, 103, 101, 32, 119, 104, 101, 114, 101, 32, 116, 111, 32, 102, 105, 110, 100, 32, 116, 104, 101, 32, 115, 116, 97, 99, 107, 115, 10, 32, 32, 32, 32, 32, 32, 45, 32, 68, 79, 67, 75, 71, 69, 95, 83, 84, 65, 67, 75, 83, 95, 68, 73, 82, 61, 47, 111, 112, 116, 47, 115, 116, 97, 99, 107, 115]);

async function main() {
   await cryptoReady();
   await genSingleLoopMultiVersion();
   await genMultiVersionLoops();
   await genMissingTerminal();
   await genExtraAndFlippedTerminal();
   await genCorruptCipherText();
   await genStreamManipulation(CLEAR_DATA);
   await genBlockOrder(CLEAR_DATA);
}

main().catch((err) => {
   console.error(err);
   process.exit(1);
});
