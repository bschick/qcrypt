// AI-Assist: 100% Claude Code Generated
//
// Generates v7 cipher text vectors used by these tests in
// libs/crypto/src/lib/ciphers.spec.ts:
//   - "correct cipherdata info and decryption, multi version"
//   - "missing terminal block indicator, multi version"
//   - "extra terminal block indicator, multi version"
//   - "flipped terminal block indicator, multi version"
//
// Run with: pnpm vectors:ciphers

import {
   cryptoReady,
   base64ToBytes,
} from '@qcrypt/crypto';
import * as cc from '@qcrypt/crypto/consts';
import {
   streamFromStr,
   withTermOverride,
   encryptOneLoop,
   toBase64,
   printBanner,
} from './gen_helpers.ts';

const VER = cc.CURRENT_VERSION;
const PLAIN = 'A nice 🦫 came to say hello';
const PWD = 'a 🌲 of course';
const HINT = '🌧️';
const CRED = base64ToBytes('Ohyqajb6nFOm2Y5lOTkIkhc3uAaF8sUrYrQ9pts2pDc=');
const IC = 1800000;
const ALGS: cc.CipherAlgs[] = ['AES-GCM', 'X20-PLY', 'AEGIS-256'];
const READ_OPTS = { startSize: 20, maxSize: 320 };

// (label, force block0 term, force blockN term). null = no override.
const CASES: Array<[string, boolean | null, boolean | null]> = [
   ['correct cipherdata info and decryption', null, null],
   ['missing terminal block indicator', false, false],
   ['extra terminal block indicator', true, true],
   ['flipped terminal block indicator', true, false],
];

async function genCipherText(
   alg: cc.CipherAlgs,
   forceBlock0Term: boolean | null,
   forceBlockNTerm: boolean | null
): Promise<string> {
   return withTermOverride(forceBlock0Term, forceBlockNTerm, async () => {
      const bytes = await encryptOneLoop(
         streamFromStr(PLAIN),
         CRED,
         PWD,
         HINT,
         alg,
         IC,
         READ_OPTS
      );
      return toBase64(bytes);
   });
}

async function main() {
   await cryptoReady();
   for (const [name, forceB0, forceBN] of CASES) {
      printBanner(`${name} (V${VER})`);
      for (const alg of ALGS) {
         const txt = await genCipherText(alg, forceB0, forceBN);
         console.log(`               '${alg}': '${txt}',`);
      }
      console.log();
   }
}

main().catch((err) => {
   console.error(err);
   process.exit(1);
});
