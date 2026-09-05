// AI-Assist: 100% Claude Code Generated
//
// Generates v{CURRENT_VERSION} cipher text vectors used by these tests in
// libs/crypto/src/lib/ciphers.spec.ts:
//   - "correct cipherdata info and decryption, multi version"
//   - "missing terminal block indicator, multi version"
//   - "extra terminal block indicator, multi version"
//   - "flipped terminal block indicator, multi version"
//   - "bad pwd to cipherdata info and decrypt, multi version" (reuses the
//     "correct cipherdata info and decryption" output)
//
// Run with: pnpm vectors:ciphers

import { cryptoReady, base64ToBytes } from '@qcrypt/crypto';
import * as cc from '@qcrypt/crypto/consts';
import {
   streamFromStr,
   withTermOverride,
   encryptOneLoop,
   encryptOneLoopMaster,
   toBase64,
   printBanner,
   printVersionedBlock,
   collectedBlocks,
} from './gen_helpers.ts';
import { spliceInto } from './splice_vectors.ts';

const SPEC_PATH = 'libs/crypto/src/lib/ciphers.spec.ts';

const VER = cc.CURRENT_VERSION;
const PLAIN = 'A nice 🦫 came to say hello';
const PWD = 'a 🌲 of course';
const HINT = '🌧️';
const CRED = base64ToBytes('Ohyqajb6nFOm2Y5lOTkIkhc3uAaF8sUrYrQ9pts2pDc=');
const MASTER_KEY = base64ToBytes('TWFzdGVyS2V5Rml4ZWRTZWVkVmFsdWUwMTIzNDU2Nzg=');
const EXTRA = base64ToBytes('RXh0cmFLZXlNYXQ=');
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
   forceBlockNTerm: boolean | null,
): Promise<string> {
   return withTermOverride(forceBlock0Term, forceBlockNTerm, async () => {
      const bytes = await encryptOneLoop(streamFromStr(PLAIN), CRED, PWD, HINT, alg, IC, READ_OPTS);
      return toBase64(bytes);
   });
}

// Block names, in CASES order. The bad-pwd test decrypts the same ciphertexts as the
// correct-decryption test, so both regions receive one generated set.
const CASE_NAMES = ['correctDecryption', 'missingTerminal', 'extraTerminal', 'flippedTerminal'];

async function algLines(produce: (alg: cc.CipherAlgs) => Promise<string>, indent: string): Promise<string[]> {
   const lines: string[] = [];
   for (const alg of ALGS) {
      lines.push(`${indent}'${alg}': '${await produce(alg)}',`);
   }
   return lines;
}

async function main() {
   await cryptoReady();

   let correctCts: string[] = [];
   for (const [index, [name, forceB0, forceBN]] of CASES.entries()) {
      printBanner(`${name} (V${VER})`);
      const cts = await algLines((alg) => genCipherText(alg, forceB0, forceBN), '               ');
      if (index === 0) {
         correctCts = cts;
      }
      printVersionedBlock(CASE_NAMES[index], '         ', VER, 'vectors:ciphers', [
         '            cts: {',
         ...cts,
         '            },',
      ]);
      console.log();
   }

   printBanner(`bad pwd, reusing the correct decryption vectors (V${VER})`);
   printVersionedBlock('badPwd', '         ', VER, 'vectors:ciphers', [
      '            cts: {',
      ...correctCts,
      '            },',
   ]);
   console.log();

   printBanner(`PWDKeyProvider and MasterKeyKeyProvider, with and without extra key material (V${VER})`);
   const providerLines = [
      '         pwdNoExtra: {',
      ...(await algLines(
         async (alg) => toBase64(await encryptOneLoop(streamFromStr(PLAIN), CRED, PWD, HINT, alg, IC, READ_OPTS)),
         '            ',
      )),
      '         },',
      '         pwdWithExtra: {',
      ...(await algLines(
         async (alg) =>
            toBase64(await encryptOneLoop(streamFromStr(PLAIN), CRED, PWD, HINT, alg, IC, READ_OPTS, EXTRA)),
         '            ',
      )),
      '         },',
      '         masterNoExtra: {',
      ...(await algLines(
         async (alg) => toBase64(await encryptOneLoopMaster(streamFromStr(PLAIN), MASTER_KEY, alg, READ_OPTS)),
         '            ',
      )),
      '         },',
      '         masterWithExtra: {',
      ...(await algLines(
         async (alg) => toBase64(await encryptOneLoopMaster(streamFromStr(PLAIN), MASTER_KEY, alg, READ_OPTS, EXTRA)),
         '            ',
      )),
      '         },',
   ];
   printVersionedBlock('providers', '      ', VER, 'vectors:ciphers', providerLines);
   console.log();

   if (process.argv.includes('--write')) {
      const onlyAt = process.argv.indexOf('--only');
      const only = onlyAt === -1 ? undefined : process.argv.slice(onlyAt + 1).filter((arg) => !arg.startsWith('--'));
      spliceInto(SPEC_PATH, collectedBlocks(), only);
   }
}

main().catch((err) => {
   console.error(err);
   process.exit(1);
});
