// Generates pinned key-derivation vectors used by tests in
// libs/crypto/src/lib/keys.spec.ts:
//   - "PWDKeyProvider keys match expected values"
//   - "MasterKeyKeyProvider keys match expected values"
//   - "PWDKeyProvider keys match expected values, multi-loop with customAd"
//   - "MasterKeyKeyProvider keys match expected values, multi-loop with customAd"
//
// Outputs both the existing single-loop V7 entries (regeneration) and the
// new multi-loop V7 entries with customAd.
//
// Run with: pnpm vectors:keys

import {
   cryptoReady,
   PWDKeyProvider,
   MasterKeyKeyProvider,
   Ciphers,
} from '@qcrypt/crypto';
import * as cc from '@qcrypt/crypto/consts';
import {
   uint8ArrayLiteral,
   printBanner,
} from './gen_helpers.ts';

const VER = cc.CURRENT_VERSION;
const ALGS: cc.CipherAlgs[] = ['AES-GCM', 'X20-PLY', 'AEGIS-256'];

// PWDKeyProvider inputs (match keys.spec.ts pinned values).
const PWD_USERCRED = new Uint8Array([214, 245, 252, 122, 133, 39, 76, 162, 64, 201, 143, 217, 237, 57, 18, 207, 199, 153, 20, 28, 162, 9, 236, 66, 100, 103, 152, 159, 226, 50, 225, 129]);
const PWD_SLT = new Uint8Array([160, 202, 135, 230, 125, 174, 49, 189, 171, 56, 203, 1, 237, 233, 27, 76]);
const PWD_IV = new Uint8Array([46, 22, 226, 86, 89, 132, 143, 185, 198, 129, 242, 241, 183, 195, 191, 229, 162, 127, 162, 148, 75, 16, 28, 140, 53, 215, 85, 89, 158, 248, 52, 175]);
const PWD_PWD = 'a good pwd';
const PWD_CUSTOMAD = new Uint8Array([120, 190, 112, 41, 122, 140, 204, 6, 253, 18]);

// MasterKeyKeyProvider inputs (match keys.spec.ts pinned values).
const MASTER_KEY = new Uint8Array([88, 164, 150, 177, 85, 43, 43, 25, 42, 250, 120, 190, 112, 26, 41, 122, 140, 204, 6, 253, 225, 220, 237, 10, 80, 64, 148, 152, 204, 30, 231, 18]);
const MASTER_SLT = new Uint8Array([247, 229, 145, 155, 90, 26, 149, 132, 44, 75, 197, 178, 187, 88, 41, 244]);
const MASTER_IV = new Uint8Array([110, 248, 21, 150, 142, 146, 67, 223, 194, 230, 44, 28, 247, 71, 109, 61, 53, 215, 85, 89, 158, 248, 52, 175, 53, 215, 169, 223, 219, 248, 52, 175]);
const MASTER_CUSTOMAD = new Uint8Array([120, 190, 112, 41, 122, 140, 204, 6, 253, 18]);

type DerivedKeys = {
   ek: Uint8Array;
   sk: Uint8Array;
   hk: Uint8Array;
   hIV: Uint8Array;
   bk: Uint8Array;
};

async function deriveAll(
   keyProvider: PWDKeyProvider | MasterKeyKeyProvider,
   alg: cc.CipherAlgs,
   iv: Uint8Array
): Promise<DerivedKeys> {
   const ek = await keyProvider.getCipherKey(false);
   const sk = await keyProvider.getSigningKey();
   const [hk, hIV] = await keyProvider.getHintCipherKeyAndIV(iv.slice(0, Ciphers.algIVByteLength(alg)));
   const bk = await keyProvider.getBlockCipherKey(1);
   // Copy before purge — purge() wipes cached buffers we'd otherwise reference.
   return {
      ek: ek.slice(0),
      sk: sk.slice(0),
      hk: hk.slice(0),
      hIV: hIV.slice(0),
      bk: bk.slice(0),
   };
}

function emitAlgEntry(
   alg: cc.CipherAlgs,
   keys: DerivedKeys,
   customAd: Uint8Array | undefined
): void {
   console.log(`            '${alg}': {`);
   if (customAd) {
      console.log(`               customAd: ${uint8ArrayLiteral(customAd)},`);
   }
   console.log(`               ek: ${uint8ArrayLiteral(keys.ek)},`);
   console.log(`               sk: ${uint8ArrayLiteral(keys.sk)},`);
   console.log(`               hk: ${uint8ArrayLiteral(keys.hk)},`);
   console.log(`               hIV: ${uint8ArrayLiteral(keys.hIV)},`);
   console.log(`               bk: ${uint8ArrayLiteral(keys.bk)},`);
   console.log(`            },`);
}

async function genPwdBlock(
   customAd: Uint8Array<ArrayBuffer> | undefined,
   lp: number,
   lpEnd: number,
   includeLpInTuple: boolean = false
): Promise<void> {
   const header = includeLpInTuple
      ? `         [cc.VERSION${VER}, ${lp}, {`
      : `         [cc.VERSION${VER}, {`;
   console.log(header);
   for (const alg of ALGS) {
      const keyProvider = new PWDKeyProvider(PWD_USERCRED.slice(0), [PWD_PWD, undefined], customAd);
      keyProvider.setCipherDataInfo({
         ver: VER,
         alg,
         ic: cc.ICOUNT_MIN,
         slt: PWD_SLT.slice(0),
         lp,
         lpEnd,
      });
      const keys = await deriveAll(keyProvider, alg, PWD_IV);
      keyProvider.purge();
      emitAlgEntry(alg, keys, customAd);
   }
   console.log(`         }],`);
}

async function genMasterBlock(
   customAd: Uint8Array<ArrayBuffer> | undefined,
   lp: number,
   lpEnd: number,
   includeLpInTuple: boolean = false
): Promise<void> {
   const header = includeLpInTuple
      ? `         [cc.VERSION${VER}, ${lp}, {`
      : `         [cc.VERSION${VER}, {`;
   console.log(header);
   for (const alg of ALGS) {
      const keyProvider = new MasterKeyKeyProvider(MASTER_KEY.slice(0), customAd);
      keyProvider.setCipherDataInfo({
         ver: VER,
         alg,
         ic: 0,
         slt: MASTER_SLT.slice(0),
         lp,
         lpEnd,
      });
      const keys = await deriveAll(keyProvider, alg, MASTER_IV);
      keyProvider.purge();
      emitAlgEntry(alg, keys, customAd);
   }
   console.log(`         }],`);
}

async function main() {
   await cryptoReady();

   printBanner(`PWDKeyProvider, V${VER}, single-loop, no customAd (re-emit)`);
   await genPwdBlock(undefined, 1, 1);

   printBanner(`PWDKeyProvider, V${VER}, single-loop, with customAd (re-emit)`);
   await genPwdBlock(PWD_CUSTOMAD, 1, 1);

   printBanner(`PWDKeyProvider, V${VER}, lp=1 of 2, with customAd`);
   await genPwdBlock(PWD_CUSTOMAD, 1, 2, true);

   printBanner(`PWDKeyProvider, V${VER}, lp=2 of 2, with customAd`);
   await genPwdBlock(PWD_CUSTOMAD, 2, 2, true);

   printBanner(`MasterKeyKeyProvider, V${VER}, single-loop, no customAd (re-emit)`);
   await genMasterBlock(undefined, 1, 1);

   printBanner(`MasterKeyKeyProvider, V${VER}, single-loop, with customAd (re-emit)`);
   await genMasterBlock(MASTER_CUSTOMAD, 1, 1);

   printBanner(`MasterKeyKeyProvider, V${VER}, lp=1 of 2, with customAd`);
   await genMasterBlock(MASTER_CUSTOMAD, 1, 2, true);

   printBanner(`MasterKeyKeyProvider, V${VER}, lp=2 of 2, with customAd`);
   await genMasterBlock(MASTER_CUSTOMAD, 2, 2, true);
}

main().catch((err) => {
   console.error(err);
   process.exit(1);
});
