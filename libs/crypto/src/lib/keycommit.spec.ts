/* MIT License

Copyright (c) 2026 Brad Schick

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE. */

/* AES-GCM is not key committing. Its tag is affine in the ciphertext, so a single block can
 * be solved to verify under two different cipher keys. These tests build that collision from
 * real derived keys and feed it to the real decipher, pinning which layer stops it. Across
 * passwords only v8 stops it, because the signing key behind the outer MAC does not depend on
 * the password. Across user credentials the outer MAC stops it in both v7 and v8.
 */
import { cryptoReady, getSodium } from './crypto';
import * as cc from './cipher.consts';
import { getStreamDecipher, Ciphers, Packer, concatArrays, getRandom } from '../index';
import { PWDKeyProvider } from './keys';
import { isEqualArray, streamFromBytes } from './utils.spec';

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
   function makeKeyProvider(
      userCred: Uint8Array<ArrayBuffer>,
      pwd: string,
      slt: Uint8Array<ArrayBuffer>,
      ver?: number,
   ): PWDKeyProvider {
      const keyProvider = new PWDKeyProvider(userCred.slice(0), [pwd, undefined]);
      if (ver !== undefined) {
         keyProvider.setCipherDataInfo({ ver, alg: ALG, ic: cc.ICOUNT_MIN, slt: slt.slice(0), lp: 1, lpEnd: 1 });
      }
      return keyProvider;
   }

   function buildFileAD(
      ver: number,
      iv: Uint8Array<ArrayBuffer>,
      slt: Uint8Array<ArrayBuffer>,
      keyCommitment: Uint8Array<ArrayBuffer>,
   ): Uint8Array<ArrayBuffer> {
      const packer = new Packer(cc.ADDIONTAL_DATA_MAX_BYTES);
      packer.flags = 1;
      packer.alg = ALG;
      packer.iv = iv;
      packer.slt = slt;
      packer.ic = cc.ICOUNT_MIN;
      packer.lpp(1, 1);
      packer.hint = new Uint8Array(0);
      if (ver >= cc.VERSION8) {
         packer.commit = keyCommitment;
      }
      return packer.trim().slice(0);
   }

   /* v8 stores the commitment on the wire, so every key sees the same associated data.
    * v7 stores nothing and appends the commit key it derived, so each key sees its own.
    */
   function aeadAD(
      ver: number,
      fileAD: Uint8Array<ArrayBuffer>,
      keyCommitment: Uint8Array<ArrayBuffer>,
   ): Uint8Array<ArrayBuffer> {
      return ver >= cc.VERSION8 ? fileAD : concatArrays([fileAD, keyCommitment]);
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
      keyProviderOrig: PWDKeyProvider,
      keyProviderAlt: PWDKeyProvider,
   ): Promise<CraftedBlock> {
      const ekOrig = (await keyProviderOrig.getCipherKey(true)).slice(0);
      const commitOrig = (await keyProviderOrig.getKeyCommitment()).slice(0);
      const signingKey = (await keyProviderOrig.getSigningKey()).slice(0);

      const ekAlt = (await keyProviderAlt.getCipherKey(true)).slice(0);
      const commitAlt = (await keyProviderAlt.getKeyCommitment()).slice(0);
      expect(isEqualArray(ekOrig, ekAlt)).toBe(false);

      const fileAD = buildFileAD(ver, iv, slt, commitOrig);
      const adOrig = aeadAD(ver, fileAD, commitOrig);
      const adAlt = aeadAD(ver, fileAD, commitAlt);

      const encryptedData = solveCollision(await gcmParams(ekOrig, iv), adOrig, await gcmParams(ekAlt, iv), adAlt);
      const crafted = concatArrays([createHeader(ver, signingKey, fileAD, encryptedData), fileAD, encryptedData]);
      return { crafted, encryptedData, ekOrig, ekAlt, adOrig, adAlt };
   }

   // Confirms the collision is real, so a rejection below cannot be a false pass from a broken solver
   async function expectAESGCMAcceptsBoth(block: CraftedBlock, iv: Uint8Array<ArrayBuffer>): Promise<void> {
      await expect(gcmOpen(block.ekOrig, iv, block.adOrig, block.encryptedData)).resolves.toBeDefined();
      await expect(gcmOpen(block.ekAlt, iv, block.adAlt, block.encryptedData)).resolves.toBeDefined();
   }

   async function decryptBlock0(crafted: Uint8Array<ArrayBuffer>, keyProvider: PWDKeyProvider): Promise<Uint8Array> {
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
         makeKeyProvider(userCred, PWD_ORIG, slt, cc.VERSION7),
         makeKeyProvider(userCred, PWD_ALT, slt, cc.VERSION7),
      );
      // The AES-GCM take either key
      await expectAESGCMAcceptsBoth(block, iv);

      // v7 is not fully key-commiting, both passwords open the same bytes to different plaintext
      const clearOrig = await decryptBlock0(block.crafted, makeKeyProvider(userCred, PWD_ORIG, slt));
      const clearAlt = await decryptBlock0(block.crafted, makeKeyProvider(userCred, PWD_ALT, slt));

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
         makeKeyProvider(userCred, PWD_ORIG, slt, cc.CURRENT_VERSION),
         makeKeyProvider(userCred, PWD_ALT, slt, cc.CURRENT_VERSION),
      );
      // The AES-GCM take either key
      await expectAESGCMAcceptsBoth(block, iv);

      await expect(decryptBlock0(block.crafted, makeKeyProvider(userCred, PWD_ORIG, slt))).resolves.toHaveLength(
         CLEAR_BYTES,
      );
      // Stored commitment rejects, fully key-committing
      await expect(decryptBlock0(block.crafted, makeKeyProvider(userCred, PWD_ALT, slt))).rejects.toThrow(
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
            makeKeyProvider(userCredOrig, PWD_ORIG, slt, ver),
            makeKeyProvider(userCredAlt, PWD_ORIG, slt, ver),
         );
         // The AES-GCM take either key
         await expectAESGCMAcceptsBoth(block, iv);

         await expect(decryptBlock0(block.crafted, makeKeyProvider(userCredOrig, PWD_ORIG, slt))).resolves.toHaveLength(
            CLEAR_BYTES,
         );
         // Outer MAC rejects, key-committing across userCreds
         await expect(decryptBlock0(block.crafted, makeKeyProvider(userCredAlt, PWD_ORIG, slt))).rejects.toThrow(
            /Invalid MAC/,
         );
      }
   });
});
