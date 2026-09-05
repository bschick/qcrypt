// AI-Assist: 100% Claude Code Generated

/* AES-GCM is not key committing. Its tag is affine in the ciphertext, so a single block can
 * be solved to verify under two different cipher keys. These tests build that collision from
 * real derived keys and feed it to the real decipher, pinning which layer stops it. Across
 * passwords only v8 stops it, because the signing key behind the outer MAC does not depend on
 * the password. Across user credentials the outer MAC stops it in both v7 and v8, and so it
 * does across master keys and their extra key material, which is why the master-key path
 * stores no commitment of its own.
 */
import { cryptoReady, getSodium } from './crypto';
import * as cc from './cipher.consts';
import { getStreamDecipher, Ciphers, Packer, concatArrays, getRandom } from '../index';
import type { KeyProvider } from '../index';
import { MasterKeyKeyProvider, PWDKeyProvider } from './keys';
import { isEqualArray, streamFromBytes } from './test-helpers';

// GF(2^128) in the bit order GHASH uses
const GF_MASK = (1n << 128n) - 1n;
const GF_REDUCE = 0xe1n << 120n;

function bytesToBig(bytes: Uint8Array): bigint {
   let value = 0n;
   for (const byte of bytes) {
      value = (value << 8n) | BigInt(byte);
   }
   return value;
}

function bigToBytes(value: bigint): Uint8Array<ArrayBuffer> {
   const out = new Uint8Array(16);
   let rest = value;
   for (let pos = 15; pos >= 0; pos--) {
      out[pos] = Number(rest & 0xffn);
      rest >>= 8n;
   }
   return out;
}

function gfMul(left: bigint, right: bigint): bigint {
   let acc = 0n;
   let cur = right;
   for (let bit = 0; bit < 128; bit++) {
      if ((left >> BigInt(127 - bit)) & 1n) {
         acc ^= cur;
      }
      if (cur & 1n) {
         cur = (cur >> 1n) ^ GF_REDUCE;
      } else {
         cur = cur >> 1n;
      }
   }
   return acc & GF_MASK;
}

function gfInv(value: bigint): bigint {
   let result = 1n << 127n;
   let cur = value;
   let exponent = (1n << 128n) - 2n;
   while (exponent > 0n) {
      if (exponent & 1n) {
         result = gfMul(result, cur);
      }
      cur = gfMul(cur, cur);
      exponent >>= 1n;
   }
   return result;
}

function ghash(hashKey: bigint, blocks: bigint[]): bigint {
   let acc = 0n;
   for (const block of blocks) {
      acc = gfMul(acc ^ block, hashKey);
   }
   return acc;
}

function toBlocks(bytes: Uint8Array): bigint[] {
   const blocks: bigint[] = [];
   for (let pos = 0; pos < bytes.byteLength; pos += 16) {
      const chunk = new Uint8Array(16);
      chunk.set(bytes.subarray(pos, Math.min(pos + 16, bytes.byteLength)));
      blocks.push(bytesToBig(chunk));
   }
   return blocks;
}

function lenBlock(adBytes: number, ctBytes: number): bigint {
   const block = new Uint8Array(16);
   const view = new DataView(block.buffer);
   view.setBigUint64(0, BigInt(adBytes) * 8n, false);
   view.setBigUint64(8, BigInt(ctBytes) * 8n, false);
   return bytesToBig(block);
}

// Raw AES block encryption, reached through AES-CTR over a zero plaintext
async function aesBlock(keyBytes: Uint8Array, block: Uint8Array<ArrayBuffer>): Promise<Uint8Array> {
   const key = await crypto.subtle.importKey('raw', keyBytes.slice(0), 'AES-CTR', false, ['encrypt']);
   const out = await crypto.subtle.encrypt({ name: 'AES-CTR', counter: block, length: 32 }, key, new Uint8Array(16));
   return new Uint8Array(out).slice(0, 16);
}

type GcmParams = { hashKey: bigint; tagMask: bigint };

async function gcmParams(keyBytes: Uint8Array, iv: Uint8Array<ArrayBuffer>): Promise<GcmParams> {
   const hashKey = bytesToBig(await aesBlock(keyBytes, new Uint8Array(16)));
   const counter0 = new Uint8Array(16);
   counter0.set(iv);
   counter0[15] = 1;
   return { hashKey, tagMask: bytesToBig(await aesBlock(keyBytes, counter0)) };
}

async function gcmOpen(
   keyBytes: Uint8Array,
   iv: Uint8Array<ArrayBuffer>,
   ad: Uint8Array<ArrayBuffer>,
   sealed: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array> {
   const key = await crypto.subtle.importKey('raw', keyBytes.slice(0), 'AES-GCM', false, ['decrypt']);
   return new Uint8Array(
      await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: ad, tagLength: 128 }, key, sealed),
   );
}

/* Returns one ciphertext block plus tag that both keys accept. Both associated data values
 * must be the same length so the trailing GCM length block matches.
 */
function solveCollision(
   paramsOrig: GcmParams,
   adOrig: Uint8Array,
   paramsAlt: GcmParams,
   adAlt: Uint8Array,
): Uint8Array<ArrayBuffer> {
   const lengths = lenBlock(adOrig.byteLength, 16);
   const constOrig = ghash(paramsOrig.hashKey, [...toBlocks(adOrig), 0n, lengths]);
   const constAlt = ghash(paramsAlt.hashKey, [...toBlocks(adAlt), 0n, lengths]);
   const squareOrig = gfMul(paramsOrig.hashKey, paramsOrig.hashKey);
   const squareAlt = gfMul(paramsAlt.hashKey, paramsAlt.hashKey);

   const cipherBlock = gfMul(
      constOrig ^ constAlt ^ paramsOrig.tagMask ^ paramsAlt.tagMask,
      gfInv(squareOrig ^ squareAlt),
   );
   const tag = constOrig ^ gfMul(cipherBlock, squareOrig) ^ paramsOrig.tagMask;
   return concatArrays([bigToBytes(cipherBlock), bigToBytes(tag)]);
}

describe('Key commitment against an AEAD tag collision', () => {
   beforeEach(async () => {
      await cryptoReady();
   });

   const ALG = 'AES-GCM';
   const PWD_ORIG = 'the password the file was written for';
   const PWD_ALT = 'a completely different password';
   const CLEAR_BYTES = 16;

   type CraftedBlock = {
      crafted: Uint8Array<ArrayBuffer>;
      encryptedData: Uint8Array<ArrayBuffer>;
      ekOrig: Uint8Array<ArrayBuffer>;
      ekAlt: Uint8Array<ArrayBuffer>;
      adOrig: Uint8Array<ArrayBuffer>;
      adAlt: Uint8Array<ArrayBuffer>;
   };

   // Omit ver to leave the provider unprimed, as it is when decrypting from a stream
   function makePWDKeyProvider(
      userCred: Uint8Array<ArrayBuffer>,
      pwd: string,
      slt: Uint8Array<ArrayBuffer>,
      ver?: number,
   ): PWDKeyProvider {
      const keyProvider = new PWDKeyProvider(userCred.slice(0), [pwd]);
      if (ver !== undefined) {
         keyProvider.setCipherDataInfo({ ver, alg: ALG, ic: cc.ICOUNT_MIN, slt: slt.slice(0), lp: 1, lpEnd: 1 });
      }
      return keyProvider;
   }

   // Master keys are not password stretched, so the iteration count must stay zero
   function makeMasterKeyProvider(
      masterKey: Uint8Array<ArrayBuffer>,
      extraKeyMaterial: Uint8Array<ArrayBuffer> | undefined,
      slt: Uint8Array<ArrayBuffer>,
      ver?: number,
   ): MasterKeyKeyProvider {
      const keyProvider = new MasterKeyKeyProvider(masterKey.slice(0), extraKeyMaterial?.slice(0));
      if (ver !== undefined) {
         keyProvider.setCipherDataInfo({ ver, alg: ALG, ic: 0, slt: slt.slice(0), lp: 1, lpEnd: 1 });
      }
      return keyProvider;
   }

   /* storedCommit is what lands on the wire: the derived commitment for providers that
    * support one, and empty for the master-key path, which relies on the outer MAC instead.
    */
   function buildFileAD(
      ver: number,
      iv: Uint8Array<ArrayBuffer>,
      slt: Uint8Array<ArrayBuffer>,
      ic: number,
      storedCommit: Uint8Array<ArrayBuffer>,
   ): Uint8Array<ArrayBuffer> {
      const packer = new Packer(cc.ADDIONTAL_DATA_MAX_BYTES);
      packer.flags = 1;
      packer.alg = ALG;
      packer.iv = iv;
      packer.slt = slt;
      packer.ic = ic;
      packer.lpp(1, 1);
      packer.hint = new Uint8Array(0);
      if (ver >= cc.VERSION8) {
         packer.commit = storedCommit;
      }
      return packer.trim().slice(0);
   }

   /* v8 stores the commitment on the wire, so every key sees the same associated data.
    * v7 stores nothing and appends the extra key material and the commit key it derived,
    * so each key sees its own.
    */
   function aeadAD(
      ver: number,
      fileAD: Uint8Array<ArrayBuffer>,
      extraKeyMaterial: Uint8Array<ArrayBuffer> | undefined,
      keyCommitment: Uint8Array<ArrayBuffer>,
   ): Uint8Array<ArrayBuffer> {
      let aeadAd = fileAD;
      if (ver < cc.VERSION8) {
         const parts: Uint8Array<ArrayBuffer>[] = [fileAD];
         if (extraKeyMaterial) {
            parts.push(extraKeyMaterial);
         }
         parts.push(keyCommitment);
         aeadAd = concatArrays(parts);
      }
      return aeadAd;
   }

   // Mirrors EncipherV8._createHeader, which cannot be reused because it stamps its own version
   function createHeader(
      ver: number,
      signingKey: Uint8Array,
      fileAD: Uint8Array,
      encryptedData: Uint8Array,
   ): Uint8Array<ArrayBuffer> {
      const packer = new Packer(cc.HEADER_BYTES_6P, cc.MAC_BYTES);
      packer.ver = ver;
      packer.size = fileAD.byteLength + encryptedData.byteLength;

      const sodium = getSodium();
      const state = sodium.crypto_generichash_init(signingKey, cc.MAC_BYTES);
      sodium.crypto_generichash_update(state, new Uint8Array(packer.buffer, cc.MAC_BYTES));
      sodium.crypto_generichash_update(state, fileAD);
      sodium.crypto_generichash_update(state, encryptedData);
      sodium.crypto_generichash_update(state, new Uint8Array([0]));

      packer.offset = 0;
      packer.mac = sodium.crypto_generichash_final(state, cc.MAC_BYTES);
      return packer.detach();
   }

   // Signs with the first provider's signing key, since only one MAC can be stored
   async function craftCollisionBlock(
      ver: number,
      iv: Uint8Array<ArrayBuffer>,
      slt: Uint8Array<ArrayBuffer>,
      keyProviderOrig: KeyProvider,
      keyProviderAlt: KeyProvider,
   ): Promise<CraftedBlock> {
      const ekOrig = (await keyProviderOrig.getCipherKey(true)).slice(0);
      const commitOrig = keyProviderOrig.supportsCommitment
         ? (await keyProviderOrig.getKeyCommitment()).slice(0)
         : new Uint8Array(0);
      const signingKey = (await keyProviderOrig.getSigningKey()).slice(0);

      const ekAlt = (await keyProviderAlt.getCipherKey(true)).slice(0);
      const commitAlt = keyProviderAlt.supportsCommitment
         ? (await keyProviderAlt.getKeyCommitment()).slice(0)
         : new Uint8Array(0);
      expect(isEqualArray(ekOrig, ekAlt)).toBe(false);

      const fileAD = buildFileAD(ver, iv, slt, keyProviderOrig.getCipherDataInfo().ic, commitOrig);
      const adOrig = aeadAD(ver, fileAD, keyProviderOrig.getExtraKeyMaterial(), commitOrig);
      const adAlt = aeadAD(ver, fileAD, keyProviderAlt.getExtraKeyMaterial(), commitAlt);

      const encryptedData = solveCollision(await gcmParams(ekOrig, iv), adOrig, await gcmParams(ekAlt, iv), adAlt);
      const crafted = concatArrays([createHeader(ver, signingKey, fileAD, encryptedData), fileAD, encryptedData]);
      return { crafted, encryptedData, ekOrig, ekAlt, adOrig, adAlt };
   }

   // Confirms the collision is real, so a rejection below cannot be a false pass from a broken solver
   async function expectAESGCMAcceptsBoth(block: CraftedBlock, iv: Uint8Array<ArrayBuffer>): Promise<void> {
      await expect(gcmOpen(block.ekOrig, iv, block.adOrig, block.encryptedData)).resolves.toBeDefined();
      await expect(gcmOpen(block.ekAlt, iv, block.adAlt, block.encryptedData)).resolves.toBeDefined();
   }

   async function decryptBlock0(crafted: Uint8Array<ArrayBuffer>, keyProvider: KeyProvider): Promise<Uint8Array> {
      const [cipherStream] = streamFromBytes(crafted);
      const decipher = await getStreamDecipher(cipherStream, keyProvider);
      return decipher.decryptBlock0();
   }

   it('v7 opens one crafted block under two different passwords', async () => {
      const userCred = getRandom(cc.USERCRED_BYTES);
      const slt = getRandom(cc.SLT_BYTES);
      const iv = getRandom(Ciphers.algIVByteLength(ALG));

      const block = await craftCollisionBlock(
         cc.VERSION7,
         iv,
         slt,
         makePWDKeyProvider(userCred, PWD_ORIG, slt, cc.VERSION7),
         makePWDKeyProvider(userCred, PWD_ALT, slt, cc.VERSION7),
      );
      // The AES-GCM take either key
      await expectAESGCMAcceptsBoth(block, iv);

      // v7 is not fully key-commiting, both passwords open the same bytes to different plaintext
      const clearOrig = await decryptBlock0(block.crafted, makePWDKeyProvider(userCred, PWD_ORIG, slt));
      const clearAlt = await decryptBlock0(block.crafted, makePWDKeyProvider(userCred, PWD_ALT, slt));

      expect(clearOrig).toHaveLength(CLEAR_BYTES);
      expect(clearAlt).toHaveLength(CLEAR_BYTES);
      expect(isEqualArray(clearOrig, clearAlt)).toBe(false);
   });

   it('v8+ rejects one crafted block under two different passwords', async () => {
      const userCred = getRandom(cc.USERCRED_BYTES);
      const slt = getRandom(cc.SLT_BYTES);
      const iv = getRandom(Ciphers.algIVByteLength(ALG));

      const block = await craftCollisionBlock(
         cc.CURRENT_VERSION,
         iv,
         slt,
         makePWDKeyProvider(userCred, PWD_ORIG, slt, cc.CURRENT_VERSION),
         makePWDKeyProvider(userCred, PWD_ALT, slt, cc.CURRENT_VERSION),
      );
      // The AES-GCM take either key
      await expectAESGCMAcceptsBoth(block, iv);

      await expect(decryptBlock0(block.crafted, makePWDKeyProvider(userCred, PWD_ORIG, slt))).resolves.toHaveLength(
         CLEAR_BYTES,
      );
      // Stored commitment rejects, fully key-committing
      await expect(decryptBlock0(block.crafted, makePWDKeyProvider(userCred, PWD_ALT, slt))).rejects.toThrow(
         /key commitment/,
      );
   });

   /* The signing key derives from the user credential but not from the password, so the outer
    * MAC binds the credential in every version.
    */
   it('v7 and v8 reject a second user credential at the outer MAC', async () => {
      for (const ver of [cc.VERSION7, cc.CURRENT_VERSION]) {
         const userCredOrig = getRandom(cc.USERCRED_BYTES);
         const userCredAlt = getRandom(cc.USERCRED_BYTES);
         const slt = getRandom(cc.SLT_BYTES);
         const iv = getRandom(Ciphers.algIVByteLength(ALG));

         const block = await craftCollisionBlock(
            ver,
            iv,
            slt,
            makePWDKeyProvider(userCredOrig, PWD_ORIG, slt, ver),
            makePWDKeyProvider(userCredAlt, PWD_ORIG, slt, ver),
         );
         // The AES-GCM take either key
         await expectAESGCMAcceptsBoth(block, iv);

         await expect(
            decryptBlock0(block.crafted, makePWDKeyProvider(userCredOrig, PWD_ORIG, slt)),
         ).resolves.toHaveLength(CLEAR_BYTES);
         // Outer MAC rejects, key-committing across userCreds
         await expect(decryptBlock0(block.crafted, makePWDKeyProvider(userCredAlt, PWD_ORIG, slt))).rejects.toThrow(
            /Invalid MAC/,
         );
      }
   });

   /* The master-key path derives the cipher key and the signing key from the same root, so
    * nothing can change one without changing the other. That is why v8 stores no commitment
    * here, and these two tests are what make that omission safe to rely on.
    */
   it('v7 and v8 reject a second master key at the outer MAC', async () => {
      for (const ver of [cc.VERSION7, cc.CURRENT_VERSION]) {
         const masterKeyOrig = getRandom(cc.KEY_BYTES);
         const masterKeyAlt = getRandom(cc.KEY_BYTES);
         const slt = getRandom(cc.SLT_BYTES);
         const iv = getRandom(Ciphers.algIVByteLength(ALG));

         const block = await craftCollisionBlock(
            ver,
            iv,
            slt,
            makeMasterKeyProvider(masterKeyOrig, undefined, slt, ver),
            makeMasterKeyProvider(masterKeyAlt, undefined, slt, ver),
         );
         // The AES-GCM take either key
         await expectAESGCMAcceptsBoth(block, iv);

         await expect(
            decryptBlock0(block.crafted, makeMasterKeyProvider(masterKeyOrig, undefined, slt)),
         ).resolves.toHaveLength(CLEAR_BYTES);
         await expect(
            decryptBlock0(block.crafted, makeMasterKeyProvider(masterKeyAlt, undefined, slt)),
         ).rejects.toThrow(/Invalid MAC/);
      }
   });

   /* Extra key material is the per-user domain separator on the master-key path, so a file
    * written for one user must not open for another holding the same master key.
    */
   it('v7 and v8 reject different extra key material at the outer MAC', async () => {
      for (const ver of [cc.VERSION7, cc.CURRENT_VERSION]) {
         const masterKey = getRandom(cc.KEY_BYTES);
         const extraOrig = getRandom(16);
         const extraAlt = getRandom(16);
         const slt = getRandom(cc.SLT_BYTES);
         const iv = getRandom(Ciphers.algIVByteLength(ALG));

         const block = await craftCollisionBlock(
            ver,
            iv,
            slt,
            makeMasterKeyProvider(masterKey, extraOrig, slt, ver),
            makeMasterKeyProvider(masterKey, extraAlt, slt, ver),
         );
         // The AES-GCM take either key
         await expectAESGCMAcceptsBoth(block, iv);

         await expect(
            decryptBlock0(block.crafted, makeMasterKeyProvider(masterKey, extraOrig, slt)),
         ).resolves.toHaveLength(CLEAR_BYTES);
         await expect(decryptBlock0(block.crafted, makeMasterKeyProvider(masterKey, extraAlt, slt))).rejects.toThrow(
            /Invalid MAC/,
         );
      }
   });
});
