/* MIT License

Copyright (c) 2025 Brad Schick

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
import sodium from 'libsodium-wrappers';
import * as cc from '@qcrypt/crypto/consts';
import {
   getRandom48, BYOBStreamReader, readStreamAll,
   Encipher, streamDecipher, latestEncipher,
   EncipherV7, _genCipherKey, _genHintCipherKeyAndIV, _genSigningKey,
   _genSigningKeyOld, _genHintCipherKeyOld,
} from '@qcrypt/crypto';

import type { EParams, CipherDataBlock } from '@qcrypt/crypto';

// Faster than .toEqual, resulting in few timeouts
function isEqualArray(a: Uint8Array, b: Uint8Array): boolean {
   if (a.length != b.length) {
      return false;
   }
   for (let i = 0; i < a.length; ++i) {
      if (a[i] != b[i]) {
         return false;
      }
   }
   return true;
}

// Faster than .toEqual, resulting in few timeouts
async function areEqual(a: Uint8Array | ReadableStream<Uint8Array>, b: Uint8Array | ReadableStream<Uint8Array>): Promise<boolean> {

   if (a instanceof ReadableStream) {
      a = await readStreamAll(a);
   }
   if (b instanceof ReadableStream) {
      b = await readStreamAll(b);
   }

   if (a.byteLength != b.byteLength) {
      return false;
   }

   for (let i = 0; i < a.byteLength; ++i) {
      if (a[i] != b[i]) {
         return false;
      }
   }
   return true;
}

function streamFromBytes(data: Uint8Array | Uint8Array[]): [
   ReadableStream<Uint8Array>,
   Uint8Array
] {

   let parts: Uint8Array[];
   if (data instanceof Uint8Array) {
      parts = [data];
   }
   else {
      parts = data;
   }

   let length = 0;
   parts.forEach(part => {
      length += part.length;
   });

   let merged = new Uint8Array(length);
   let offset = 0;
   parts.forEach(part => {
      merged.set(part, offset);
      offset += part.length;
   });

   const blob = new Blob([merged], { type: 'application/octet-stream' });
   return [blob.stream(), merged];
}

function streamFromStr(str: string): [
   ReadableStream<Uint8Array>,
   Uint8Array
] {
   const data = new TextEncoder().encode(str);
   const blob = new Blob([data], { type: 'application/octet-stream' });
   return [blob.stream(), data];
}

function streamFromCipherBlock(cdBlocks: CipherDataBlock[]): [
   ReadableStream<Uint8Array>,
   Uint8Array
] {

   let bytes = 0;
   for (let cdBlock of cdBlocks) {
      for (let part of cdBlock.parts) {
         bytes += part.byteLength;
      }
   }

   let pos = 0;
   const cipherData = new Uint8Array(bytes);
   for (let cdBlock of cdBlocks) {
      for (let part of cdBlock.parts) {
         cipherData.set(part, pos);
         pos += part.byteLength;
      }
   }

   return streamFromBytes(cipherData);
}

describe("Key generation", function () {
   beforeEach(async () => {
      await sodium.ready;
   });

   it("successful and not equivalent key generation", async function () {

      for (let alg in cc.AlgInfo) {
         const pwd = 'not a good pwd';
         const ic = cc.ICOUNT_MIN;
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

         const randomArray = getRandom48();
         const slt = randomArray.slice(0, cc.SLT_BYTES);
         const iv = randomArray.slice(cc.SLT_BYTES, cc.SLT_BYTES + 12);

         const ek = await _genCipherKey(alg, ic, pwd, userCred, slt);
         const sk = _genSigningKey(userCred, slt);
         const [hk, hIV] = _genHintCipherKeyAndIV(userCred, iv, slt);

         expect(ek.byteLength).toBe(32);
         expect(sk.byteLength).toBe(32);
         expect(hk.byteLength).toBe(32);

         expect(isEqualArray(ek, sk)).toBe(false);
         expect(isEqualArray(ek, hk)).toBe(false);
         expect(isEqualArray(sk, hk)).toBe(false);

         expect(isEqualArray(ek, userCred)).toBe(false);
         expect(isEqualArray(sk, userCred)).toBe(false);
         expect(isEqualArray(hk, userCred)).toBe(false);
      }
   });

   it("keys should match expected values", async function () {

      const expected: {
         [kv: number]: {
            [k1: string]: {
               [k2: string]: Uint8Array;
            };
         };
      } = {
         [cc.VERSION6]: {
            'AES-GCM': {
               ek: new Uint8Array([158, 221, 13, 155, 167, 216, 81, 115, 151, 193, 225, 53, 187, 156, 175, 196, 85, 234, 233, 199, 86, 45, 149, 120, 1, 57, 14, 102, 147, 123, 7, 150]),
               sk: new Uint8Array([172, 133, 166, 39, 233, 237, 204, 73, 234, 53, 191, 16, 169, 71, 164, 71, 36, 51, 18, 87, 19, 33, 25, 50, 224, 33, 120, 21, 233, 20, 154, 79]),
               hk: new Uint8Array([34, 121, 121, 4, 207, 55, 202, 73, 83, 4, 58, 102, 135, 111, 186, 242, 3, 187, 239, 108, 251, 245, 3, 245, 3, 77, 228, 197, 101, 4, 16, 94]),
               hIV: new Uint8Array([46, 22, 226, 86, 89, 132, 143, 185, 198, 129, 242, 241, 183, 195, 191, 229, 162, 127, 162, 148, 75, 16, 28, 140]),
               skOld: new Uint8Array([238, 127, 13, 239, 238, 127, 177, 22, 231, 87, 89, 23, 88, 52, 42, 22, 6, 170, 172, 112, 111, 101, 147, 204, 238, 28, 203, 159, 118, 54, 139, 151]),
               hkOld: new Uint8Array([253, 30, 237, 129, 147, 186, 235, 65, 217, 78, 219, 38, 163, 12, 23, 248, 3, 118, 123, 120, 237, 0, 56, 103, 67, 76, 88, 126, 153, 83, 238, 85]),
            },
            'X20-PLY': {
               ek: new Uint8Array([158, 221, 13, 155, 167, 216, 81, 115, 151, 193, 225, 53, 187, 156, 175, 196, 85, 234, 233, 199, 86, 45, 149, 120, 1, 57, 14, 102, 147, 123, 7, 150]),
               sk: new Uint8Array([172, 133, 166, 39, 233, 237, 204, 73, 234, 53, 191, 16, 169, 71, 164, 71, 36, 51, 18, 87, 19, 33, 25, 50, 224, 33, 120, 21, 233, 20, 154, 79]),
               hk: new Uint8Array([34, 121, 121, 4, 207, 55, 202, 73, 83, 4, 58, 102, 135, 111, 186, 242, 3, 187, 239, 108, 251, 245, 3, 245, 3, 77, 228, 197, 101, 4, 16, 94]),
               hIV: new Uint8Array([46, 22, 226, 86, 89, 132, 143, 185, 198, 129, 242, 241, 183, 195, 191, 229, 162, 127, 162, 148, 75, 16, 28, 140]),
               skOld: new Uint8Array([238, 127, 13, 239, 238, 127, 177, 22, 231, 87, 89, 23, 88, 52, 42, 22, 6, 170, 172, 112, 111, 101, 147, 204, 238, 28, 203, 159, 118, 54, 139, 151]),
               hkOld: new Uint8Array([253, 30, 237, 129, 147, 186, 235, 65, 217, 78, 219, 38, 163, 12, 23, 248, 3, 118, 123, 120, 237, 0, 56, 103, 67, 76, 88, 126, 153, 83, 238, 85]),
            },
            'AEGIS-256': {
               ek: new Uint8Array([158, 221, 13, 155, 167, 216, 81, 115, 151, 193, 225, 53, 187, 156, 175, 196, 85, 234, 233, 199, 86, 45, 149, 120, 1, 57, 14, 102, 147, 123, 7, 150]),
               sk: new Uint8Array([172, 133, 166, 39, 233, 237, 204, 73, 234, 53, 191, 16, 169, 71, 164, 71, 36, 51, 18, 87, 19, 33, 25, 50, 224, 33, 120, 21, 233, 20, 154, 79]),
               hk: new Uint8Array([34, 121, 121, 4, 207, 55, 202, 73, 83, 4, 58, 102, 135, 111, 186, 242, 3, 187, 239, 108, 251, 245, 3, 245, 3, 77, 228, 197, 101, 4, 16, 94]),
               hIV: new Uint8Array([46, 22, 226, 86, 89, 132, 143, 185, 198, 129, 242, 241, 183, 195, 191, 229, 162, 127, 162, 148, 75, 16, 28, 140]),
               skOld: new Uint8Array([238, 127, 13, 239, 238, 127, 177, 22, 231, 87, 89, 23, 88, 52, 42, 22, 6, 170, 172, 112, 111, 101, 147, 204, 238, 28, 203, 159, 118, 54, 139, 151]),
               hkOld: new Uint8Array([253, 30, 237, 129, 147, 186, 235, 65, 217, 78, 219, 38, 163, 12, 23, 248, 3, 118, 123, 120, 237, 0, 56, 103, 67, 76, 88, 126, 153, 83, 238, 85]),
            }
         },
         [cc.CURRENT_VERSION]: {
            'AES-GCM': {
               ek: new Uint8Array([158, 221, 13, 155, 167, 216, 81, 115, 151, 193, 225, 53, 187, 156, 175, 196, 85, 234, 233, 199, 86, 45, 149, 120, 1, 57, 14, 102, 147, 123, 7, 150]),
               sk: new Uint8Array([12, 11, 234, 82, 207, 215, 131, 80, 38, 32, 132, 108, 3, 142, 171, 167, 122, 64, 206, 141, 38, 119, 244, 14, 84, 157, 79, 143, 230, 193, 123, 152]),
               hk: new Uint8Array([186, 23, 116, 170, 237, 110, 92, 251, 20, 233, 24, 0, 10, 15, 167, 201, 128, 120, 73, 71, 132, 103, 171, 49, 154, 150, 49, 100, 201, 201, 137, 45]),
               hIV: new Uint8Array([209, 157, 68, 198, 140, 129, 200, 180, 195, 7, 203, 152, 159, 48, 27, 169, 238, 3, 71, 245, 252, 45, 165, 23]),
               skOld: new Uint8Array([238, 127, 13, 239, 238, 127, 177, 22, 231, 87, 89, 23, 88, 52, 42, 22, 6, 170, 172, 112, 111, 101, 147, 204, 238, 28, 203, 159, 118, 54, 139, 151]),
               hkOld: new Uint8Array([253, 30, 237, 129, 147, 186, 235, 65, 217, 78, 219, 38, 163, 12, 23, 248, 3, 118, 123, 120, 237, 0, 56, 103, 67, 76, 88, 126, 153, 83, 238, 85]),
            },
            'X20-PLY': {
               ek: new Uint8Array([158, 221, 13, 155, 167, 216, 81, 115, 151, 193, 225, 53, 187, 156, 175, 196, 85, 234, 233, 199, 86, 45, 149, 120, 1, 57, 14, 102, 147, 123, 7, 150]),
               sk: new Uint8Array([12, 11, 234, 82, 207, 215, 131, 80, 38, 32, 132, 108, 3, 142, 171, 167, 122, 64, 206, 141, 38, 119, 244, 14, 84, 157, 79, 143, 230, 193, 123, 152]),
               hk: new Uint8Array([186, 23, 116, 170, 237, 110, 92, 251, 20, 233, 24, 0, 10, 15, 167, 201, 128, 120, 73, 71, 132, 103, 171, 49, 154, 150, 49, 100, 201, 201, 137, 45]),
               hIV: new Uint8Array([209, 157, 68, 198, 140, 129, 200, 180, 195, 7, 203, 152, 159, 48, 27, 169, 238, 3, 71, 245, 252, 45, 165, 23]),
               skOld: new Uint8Array([238, 127, 13, 239, 238, 127, 177, 22, 231, 87, 89, 23, 88, 52, 42, 22, 6, 170, 172, 112, 111, 101, 147, 204, 238, 28, 203, 159, 118, 54, 139, 151]),
               hkOld: new Uint8Array([253, 30, 237, 129, 147, 186, 235, 65, 217, 78, 219, 38, 163, 12, 23, 248, 3, 118, 123, 120, 237, 0, 56, 103, 67, 76, 88, 126, 153, 83, 238, 85]),
            },
            'AEGIS-256': {
               ek: new Uint8Array([158, 221, 13, 155, 167, 216, 81, 115, 151, 193, 225, 53, 187, 156, 175, 196, 85, 234, 233, 199, 86, 45, 149, 120, 1, 57, 14, 102, 147, 123, 7, 150]),
               sk: new Uint8Array([12, 11, 234, 82, 207, 215, 131, 80, 38, 32, 132, 108, 3, 142, 171, 167, 122, 64, 206, 141, 38, 119, 244, 14, 84, 157, 79, 143, 230, 193, 123, 152]),
               hk: new Uint8Array([186, 23, 116, 170, 237, 110, 92, 251, 20, 233, 24, 0, 10, 15, 167, 201, 128, 120, 73, 71, 132, 103, 171, 49, 154, 150, 49, 100, 201, 201, 137, 45]),
               hIV: new Uint8Array([209, 157, 68, 198, 140, 129, 200, 180, 195, 7, 203, 152, 159, 48, 27, 169, 238, 3, 71, 245, 252, 45, 165, 23]),
               skOld: new Uint8Array([238, 127, 13, 239, 238, 127, 177, 22, 231, 87, 89, 23, 88, 52, 42, 22, 6, 170, 172, 112, 111, 101, 147, 204, 238, 28, 203, 159, 118, 54, 139, 151]),
               hkOld: new Uint8Array([253, 30, 237, 129, 147, 186, 235, 65, 217, 78, 219, 38, 163, 12, 23, 248, 3, 118, 123, 120, 237, 0, 56, 103, 67, 76, 88, 126, 153, 83, 238, 85]),
            }
         }
      };

      for (let alg in cc.AlgInfo) {
         for (let ver of [cc.VERSION6, cc.CURRENT_VERSION]) {
            const pwd = 'a good pwd';
            const ic = cc.ICOUNT_MIN;
            const userCred = new Uint8Array([214, 245, 252, 122, 133, 39, 76, 162, 64, 201, 143, 217, 237, 57, 18, 207, 199, 153, 20, 28, 162, 9, 236, 66, 100, 103, 152, 159, 226, 50, 225, 129]);
            const slt = new Uint8Array([160, 202, 135, 230, 125, 174, 49, 189, 171, 56, 203, 1, 237, 233, 27, 76]);
            const iv = new Uint8Array([46, 22, 226, 86, 89, 132, 143, 185, 198, 129, 242, 241, 183, 195, 191, 229, 162, 127, 162, 148, 75, 16, 28, 140]);

            const ek = await _genCipherKey(alg, ic, pwd, userCred, slt);
            const sk = _genSigningKey(userCred, slt, ver);
            const [hk, hIV] = _genHintCipherKeyAndIV(userCred, iv, slt, ver);
            const skOld = await _genSigningKeyOld(userCred, slt);
            const hkOld = await _genHintCipherKeyOld(alg, userCred, slt);

            expect(isEqualArray(ek, expected[ver][alg]['ek'])).toBe(true);
            expect(isEqualArray(sk, expected[ver][alg]['sk'])).toBe(true);
            expect(isEqualArray(hk, expected[ver][alg]['hk'])).toBe(true);
            expect(isEqualArray(hIV, expected[ver][alg]['hIV'])).toBe(true);
            expect(isEqualArray(skOld, expected[ver][alg]['skOld'])).toBe(true);
            expect(isEqualArray(hkOld, expected[ver][alg]['hkOld'])).toBe(true);

            expect(isEqualArray(ek, userCred)).toBe(false);
            expect(isEqualArray(sk, userCred)).toBe(false);
            expect(isEqualArray(hk, userCred)).toBe(false);
            expect(isEqualArray(hIV, userCred)).toBe(false);
            expect(isEqualArray(skOld, userCred)).toBe(false);
            expect(isEqualArray(hkOld, userCred)).toBe(false);
         }
      }
   });
});


describe("Encryption and decryption", function () {
   beforeEach(async () => {
      await sodium.ready;
   });

   function signAndRepack(encipher: EncipherV7, userCred: Uint8Array, block: CipherDataBlock, savedSlt: Uint8Array): Uint8Array {

      // cheating... parts[1] is _additionalData, parts[2] is encryptedData
      // and reset _lastMac and recreate _sk with specified (potentially forged) userCred
      encipher['_sk'] = _genSigningKey(userCred, savedSlt);
      encipher['_lastMac'] = new Uint8Array([0]);
      const headerData = encipher._createHeader(block.parts[2], block.parts[1]);

      const output = new Uint8Array(headerData.byteLength +
         block.parts[1].byteLength +
         block.parts[2].byteLength);

      output.set(headerData);
      output.set(block.parts[1], headerData.byteLength);
      output.set(block.parts[2], headerData.byteLength + block.parts[1].byteLength);

      return output;
   }

   // More complex test to ensure that having the wrong usercred causes
   // decryption to fail. We test this by extracting and not changing original
   // CipherData from "Alice's" original encrypted data that was encrypted with
   // Alice's userCredA. We then creating a new valid MAC signature with "Bob's"
   // userCredB signature attached to the front of the Alice's CipherData
   // (and encypted txt).

   // In the wild if the MAC signature was swapped with someone else's
   // valid signature Quick Crypt would report the error to Alice at signature
   // validation time because it would use Alice's userCredA not Bob's userCredB to
   // test.

   // But what could happen is that an evil site might closely mimicked
   // Quick Crypt, and if Alice was tricked into going there, it would
   // not tell Alice about the MAC signature failure. So what this test
   // validates is that even with a replaced MAC signature
   // (which is equivalent to an ignored MAC signature), the clear
   // text can still not be retrived. This test tries to ensures that
   // even having tricked Alice into entering her PWD at the evil website,
   // the ciphertext still cannot be decrypted because the
   // evil site does not have access to Alice's userCredA which is
   // combined with her password to generate the cipher key.

   it("decryption should fail with replaced valid signature", async function () {

      for (let alg in cc.AlgInfo) {

         const [clearStream, clearData] = streamFromStr('This is a secret 🐓');
         const pwd = 'a good pwd';
         const userCredA = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));
         const userCredB = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

         const eparams: EParams = {
            alg: alg,
            ic: cc.ICOUNT_MIN,
            lp: 1,
            lpEnd: 1
         };

         const reader = new BYOBStreamReader(clearStream);
         const encipher = new EncipherV7(userCredA, reader);
         let savedSlt: Uint8Array;
         const cipherBlock = await encipher.encryptBlock0(eparams, async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            savedSlt = new Uint8Array(cdinfo.slt);
            return [pwd, undefined];
         });

         // Sign and repack with both the original (correct) values to help ensure the
         // code for repacking is valid and then with a new signature. Ensure the correct
         // one works (to ensure that signAndRepack works) and the replacment is detected.
         let [cipherstreamA, cipherDataA] = streamFromBytes(signAndRepack(encipher, userCredA, cipherBlock, savedSlt!));
         let [cipherstreamB, cipherDataB] = streamFromBytes(signAndRepack(encipher, userCredB, cipherBlock, savedSlt!));

         // These should fail because using the wrong userCred for each
         let decipherA = await streamDecipher(userCredB, cipherstreamA);
         let decipherB = await streamDecipher(userCredA, cipherstreamB);

         await expect(decipherA._decodeBlock0()).rejects.toThrow(/MAC/);
         await expect(decipherB._decodeBlock0()).rejects.toThrow(/MAC/);

         // Reaload streams, then test with correct matching userCreds
         [cipherstreamA] = streamFromBytes(cipherDataA);
         [cipherstreamB] = streamFromBytes(cipherDataB);
         decipherA = await streamDecipher(userCredA, cipherstreamA);
         decipherB = await streamDecipher(userCredB, cipherstreamB);

         // Both should succeed since the singatures are valid with the userCreds
         // passed below. Decrypting, cipherText should fail on B (checked below).
         // Also, these would fail if there was an encrypted hint
         await expect(decipherA._decodeBlock0()).resolves.not.toThrow();
         await expect(decipherB._decodeBlock0()).resolves.not.toThrow();

         // should succeed since we repacked with correct userCred
         await expect(decipherA.decryptBlock0(async (cdinfo) => {
            return [pwd, undefined];
         })).resolves.toEqual(clearData);

         // The big moment... perhaps should have better validation that the decryption
         // failed, but not much else returns DOMException from cipher.service. Note that
         // this is using the correct PWD because we assume the evil site has tricked
         // Alice into provider it and just doesn't have userCred since site cannot retrieve
         await expect(decipherB.decryptBlock0(async (cdinfo) => {
            return [pwd, undefined];
         })).rejects.toThrow(DOMException);
      }
   });

   it("round trip block0, all algorithms", async function () {

      for (let alg in cc.AlgInfo) {

         const [clearStream, clearData] = streamFromStr('This is a secret 🦆');
         const pwd = 'a good pwd';
         const hint = 'not really';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

         const eparams: EParams = {
            alg: alg,
            ic: cc.ICOUNT_MIN,
            lp: 1,
            lpEnd: 1
         };

         const latest = latestEncipher(userCred, clearStream);
         const block0 = await latest.encryptBlock0(eparams, async (cdinfo) => {
            expect(cdinfo.alg).toEqual(alg);
            const ivBytes = Number(cc.AlgInfo[alg]['iv_bytes']);
            expect(cdinfo.iv.byteLength).toEqual(ivBytes);
            expect(cdinfo.slt.byteLength).toEqual(cc.SLT_BYTES);
            expect(cdinfo.ic).toBe(cc.ICOUNT_MIN);
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
            return [pwd, hint];
         });

         const [cipherStream] = streamFromCipherBlock([block0]);
         const decipher = await streamDecipher(userCred, cipherStream);

         const decrypted = await decipher.decryptBlock0(async (cdinfo) => {
            expect(cdinfo.alg).toEqual(alg);
            const ivBytes = Number(cc.AlgInfo[alg]['iv_bytes']);
            expect(cdinfo.iv.byteLength).toEqual(ivBytes);
            expect(cdinfo.slt.byteLength).toEqual(cc.SLT_BYTES);
            expect(cdinfo.ic).toBe(cc.ICOUNT_MIN);
            expect(cdinfo.hint).toEqual(hint);
            expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
            return [pwd, undefined];
         });

         await expect(areEqual(decrypted, clearData)).resolves.toEqual(true);
      }
   });


   it("round trip blockN, all algorithms", async function () {

      for (let alg in cc.AlgInfo) {

         let [clearStream, clearData] = streamFromStr('This is a secret 🦀');
         const pwd = 'a not good pwd';
         const hint = 'sorta';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

         const eparams: EParams = {
            alg: alg,
            ic: cc.ICOUNT_MIN,
            lp: 1,
            lpEnd: 1
         };

         let latest = latestEncipher(userCred, clearStream);
         const readStart = 12;
         //@ts-ignore force multiple blocks
         latest['_readTarget'] = readStart;

         await expect(latest.encryptBlockN(eparams)).rejects.toThrow(/Encipher invalid state/);

         // once invalidated, it stays that way...
         await expect(latest.encryptBlock0(eparams, async (cdinfo) => {
            return [pwd, hint];
         })).rejects.toThrow(new RegExp('Encipher invalid state.+'));

         [clearStream, clearData] = streamFromStr('This is a secret 🦀');
         latest = latestEncipher(userCred, clearStream);
         //@ts-ignore force multiple blocks
         latest['_readTarget'] = readStart;

         const block0 = await latest.encryptBlock0(eparams, async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, hint];
         });
         const blockN = await latest.encryptBlockN(eparams);

         let [cipherStream] = streamFromCipherBlock([block0, blockN]);
         let decipher = await streamDecipher(userCred, cipherStream);

         let decb0 = await decipher.decryptBlock0(async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, undefined];
         });
         await expect(areEqual(decb0, clearData.slice(0, readStart))).resolves.toEqual(true);

         const decb1 = await decipher.decryptBlockN();
         await expect(areEqual(decb1, clearData.slice(readStart))).resolves.toEqual(true);

         // Try again, but copy block0 head to block N
         const badBlockN = {
            ...blockN
         };
         badBlockN.parts[0] = block0.parts[0];

         [cipherStream] = streamFromCipherBlock([block0, badBlockN]);
         decipher = await streamDecipher(userCred, cipherStream);

         decb0 = await decipher.decryptBlock0(async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, undefined];
         });
         await expect(areEqual(decb0, clearData.slice(0, readStart))).resolves.toEqual(true);

         await expect(decipher.decryptBlockN()).rejects.toThrow(/Cipher data length mismatch2/);

      }
   });

   it("correct cipherdata info and decryption, v4", async function () {
      const [_, clearData] = streamFromStr('A nice 🦫 came to say hello');
      const pwd = 'a 🌲 of course';
      const hint = '🌧️';
      // base64url userCred for use in commandline for recreation (see Python helper function):
      // Ohyqajb6nFOm2Y5lOTkIkhc3uAaF8sUrYrQ9pts2pDc=
      const userCred = new Uint8Array([58, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98, 180, 61, 166, 219, 54, 164, 55]);
      const [cipherStream] = streamFromBytes(new Uint8Array([117, 163, 250, 117, 59, 97, 3, 10, 139, 12, 55, 161, 115, 52, 28, 105, 246, 126, 220, 0, 129, 151, 165, 136, 46, 97, 163, 160, 91, 9, 189, 218, 4, 0, 116, 0, 0, 0, 2, 0, 16, 242, 98, 46, 102, 223, 79, 227, 209, 73, 22, 207, 92, 80, 75, 125, 125, 234, 18, 21, 88, 64, 43, 68, 25, 193, 133, 31, 159, 156, 8, 184, 10, 164, 33, 46, 20, 159, 218, 222, 64, 119, 27, 0, 0, 23, 5, 135, 172, 203, 4, 101, 163, 155, 133, 221, 40, 227, 91, 222, 227, 213, 97, 77, 24, 117, 60, 188, 27, 153, 253, 134, 10, 112, 75, 76, 146, 132, 123, 217, 7, 171, 211, 24, 206, 186, 248, 244, 119, 18, 165, 195, 59, 160, 76, 31, 90, 80, 53, 19, 39, 143, 99, 141, 109, 68, 72, 63, 121, 199, 96, 95, 157, 81]));

      const decipher = await streamDecipher(userCred, cipherStream);
      const cdInfo = await decipher.getCipherDataInfo();

      expect(cdInfo.alg).toEqual('X20-PLY');
      expect(cdInfo.ic).toEqual(1800000);
      expect(isEqualArray(cdInfo.iv, new Uint8Array([16, 242, 98, 46, 102, 223, 79, 227, 209, 73, 22, 207, 92, 80, 75, 125, 125, 234, 18, 21, 88, 64, 43, 68]))).toBe(true);
      expect(isEqualArray(cdInfo.slt, new Uint8Array([25, 193, 133, 31, 159, 156, 8, 184, 10, 164, 33, 46, 20, 159, 218, 222]))).toBe(true);
      expect(cdInfo.ver).toEqual(cc.VERSION4);
      expect(cdInfo.hint).toEqual(hint);

      await expect(decipher.decryptBlock0(async (cdinfo) => {
         expect(cdinfo.hint).toEqual(hint);
         expect(cdinfo.lp).toEqual(1);
         expect(cdinfo.lpEnd).toEqual(1);
         expect(cdinfo.alg).toBe('X20-PLY');
         expect(cdinfo.ic).toBe(1800000);
         expect(cdinfo.hint).toEqual(hint);
         expect(cdinfo.ver).toEqual(cc.VERSION4);
         expect(isEqualArray(cdInfo.iv, new Uint8Array([16, 242, 98, 46, 102, 223, 79, 227, 209, 73, 22, 207, 92, 80, 75, 125, 125, 234, 18, 21, 88, 64, 43, 68]))).toBe(true);
         expect(isEqualArray(cdInfo.slt, new Uint8Array([25, 193, 133, 31, 159, 156, 8, 184, 10, 164, 33, 46, 20, 159, 218, 222]))).toBe(true);
         return [pwd, undefined];
      })).resolves.toEqual(clearData);
   });

   it("correct cipherdata info and decryption, v5", async function () {
      const [_, clearData] = streamFromStr('A nice 🦫 came to say hello');
      const pwd = 'a 🌲 of course';
      const hint = '🌧️';
      // base64url userCred for use in commandline for recreation (see Python helper function):
      // Ohyqajb6nFOm2Y5lOTkIkhc3uAaF8sUrYrQ9pts2pDc=
      const userCred = new Uint8Array([58, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98, 180, 61, 166, 219, 54, 164, 55]);
      const [cipherStream] = streamFromBytes(new Uint8Array([166, 123, 188, 183, 212, 97, 47, 147, 59, 39, 78, 222, 101, 74, 221, 53, 27, 11, 194, 67, 156, 235, 116, 104, 65, 64, 76, 166, 29, 220, 71, 179, 5, 0, 116, 0, 0, 1, 2, 0, 121, 78, 37, 8, 192, 196, 110, 22, 164, 106, 59, 161, 122, 165, 176, 147, 49, 43, 41, 250, 163, 111, 218, 4, 174, 61, 6, 169, 145, 216, 66, 166, 139, 82, 19, 207, 29, 75, 105, 149, 64, 119, 27, 0, 0, 23, 93, 92, 56, 163, 242, 71, 208, 3, 190, 44, 140, 222, 149, 159, 152, 193, 162, 44, 177, 93, 197, 119, 131, 88, 92, 53, 108, 167, 253, 64, 216, 200, 121, 212, 193, 153, 180, 39, 92, 35, 142, 6, 240, 115, 51, 211, 198, 63, 12, 126, 128, 206, 178, 114, 65, 37, 246, 197, 19, 79, 58, 96, 56, 86, 172, 162, 217, 70]));

      const decipher = await streamDecipher(userCred, cipherStream);
      const cdInfo = await decipher.getCipherDataInfo();

      expect(cdInfo.alg).toEqual('X20-PLY');
      expect(cdInfo.ic).toEqual(1800000);
      expect(isEqualArray(cdInfo.iv, new Uint8Array([121, 78, 37, 8, 192, 196, 110, 22, 164, 106, 59, 161, 122, 165, 176, 147, 49, 43, 41, 250, 163, 111, 218, 4]))).toBe(true);
      expect(isEqualArray(cdInfo.slt, new Uint8Array([174, 61, 6, 169, 145, 216, 66, 166, 139, 82, 19, 207, 29, 75, 105, 149]))).toBe(true);
      expect(cdInfo.ver).toEqual(cc.VERSION5);
      expect(cdInfo.hint).toEqual(hint);

      await expect(decipher.decryptBlock0(async (cdinfo) => {
         expect(cdinfo.hint).toEqual(hint);
         expect(cdinfo.lp).toEqual(1);
         expect(cdinfo.lpEnd).toEqual(1);
         expect(cdinfo.alg).toBe('X20-PLY');
         expect(cdinfo.ic).toBe(1800000);
         expect(cdinfo.hint).toEqual(hint);
         expect(cdinfo.ver).toEqual(cc.VERSION5);
         expect(isEqualArray(cdInfo.iv, new Uint8Array([121, 78, 37, 8, 192, 196, 110, 22, 164, 106, 59, 161, 122, 165, 176, 147, 49, 43, 41, 250, 163, 111, 218, 4]))).toBe(true);
         expect(isEqualArray(cdInfo.slt, new Uint8Array([174, 61, 6, 169, 145, 216, 66, 166, 139, 82, 19, 207, 29, 75, 105, 149]))).toBe(true);
         return [pwd, undefined];
      })).resolves.toEqual(clearData);

      await expect(decipher.decryptBlockN()).resolves.toEqual(new Uint8Array(0));
   });

   it("correct cipherdata info and decryption, v6", async function () {
      const [_, clearData] = streamFromStr('A nice 🦫 came to say hello');
      const pwd = 'a 🌲 of course';
      const hint = '🌧️';
      // base64url userCred for use in commandline for recreation (see Python helper function):
      // Ohyqajb6nFOm2Y5lOTkIkhc3uAaF8sUrYrQ9pts2pDc=
      const userCred = new Uint8Array([58, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98, 180, 61, 166, 219, 54, 164, 55]);
      const [cipherStream] = streamFromBytes(new Uint8Array([6, 96, 26, 215, 92, 226, 157, 130, 104, 27, 37, 39, 156, 244, 118, 186, 163, 217, 181, 220, 148, 183, 115, 69, 212, 144, 69, 184, 232, 175, 121, 248, 6, 0, 117, 0, 0, 1, 2, 0, 182, 155, 226, 214, 133, 101, 225, 193, 160, 76, 50, 50, 81, 174, 29, 73, 153, 121, 174, 60, 118, 42, 201, 149, 164, 52, 159, 208, 233, 162, 104, 60, 88, 170, 241, 87, 39, 144, 27, 9, 64, 119, 27, 0, 0, 23, 39, 229, 13, 184, 77, 68, 136, 183, 209, 252, 108, 46, 43, 205, 134, 87, 252, 6, 137, 0, 87, 185, 232, 81, 118, 182, 118, 213, 206, 208, 109, 156, 228, 114, 188, 28, 150, 5, 239, 220, 247, 53, 192, 38, 56, 0, 190, 42, 95, 177, 83, 44, 31, 173, 51, 32, 94, 177, 93, 144, 3, 149, 167, 10, 114, 79, 141, 182]));

      const decipher = await streamDecipher(userCred, cipherStream);
      const cdInfo = await decipher.getCipherDataInfo();

      expect(cdInfo.alg).toEqual('X20-PLY');
      expect(cdInfo.ic).toEqual(1800000);
      expect(isEqualArray(cdInfo.iv, new Uint8Array([182, 155, 226, 214, 133, 101, 225, 193, 160, 76, 50, 50, 81, 174, 29, 73, 153, 121, 174, 60, 118, 42, 201, 149]))).toBe(true);
      expect(isEqualArray(cdInfo.slt, new Uint8Array([164, 52, 159, 208, 233, 162, 104, 60, 88, 170, 241, 87, 39, 144, 27, 9]))).toBe(true);
      expect(cdInfo.ver).toEqual(cc.VERSION6);
      expect(cdInfo.hint).toEqual(hint);

      await expect(decipher.decryptBlock0(async (cdinfo) => {
         expect(cdinfo.hint).toEqual(hint);
         expect(cdinfo.lp).toEqual(1);
         expect(cdinfo.lpEnd).toEqual(1);
         expect(cdinfo.alg).toBe('X20-PLY');
         expect(cdinfo.ic).toBe(1800000);
         expect(cdinfo.hint).toEqual(hint);
         expect(cdinfo.ver).toEqual(cc.VERSION6);
         expect(isEqualArray(cdInfo.iv, new Uint8Array([182, 155, 226, 214, 133, 101, 225, 193, 160, 76, 50, 50, 81, 174, 29, 73, 153, 121, 174, 60, 118, 42, 201, 149]))).toBe(true);
         expect(isEqualArray(cdInfo.slt, new Uint8Array([164, 52, 159, 208, 233, 162, 104, 60, 88, 170, 241, 87, 39, 144, 27, 9]))).toBe(true);
         return [pwd, undefined];
      })).resolves.toEqual(clearData);

      await expect(decipher.decryptBlockN()).resolves.toEqual(new Uint8Array(0));
   });

   it("missing terminal block indicator, v5", async function () {
      const [_, clearData] = streamFromStr('A nice 🦫 came to say hello');
      const pwd = 'a 🌲 of course';
      const hint = '🌧️';
      // base64url userCred for use in commandline for recreation (see Python helper function):
      // Ohyqajb6nFOm2Y5lOTkIkhc3uAaF8sUrYrQ9pts2pDc=
      const userCred = new Uint8Array([58, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98, 180, 61, 166, 219, 54, 164, 55]);
      const [cipherStream] = streamFromBytes(new Uint8Array([225, 67, 20, 31, 134, 179, 27, 202, 138, 52, 68, 42, 197, 34, 48, 209, 76, 235, 39, 166, 101, 12, 253, 101, 237, 25, 234, 119, 91, 227, 169, 172, 5, 0, 116, 0, 0, 0, 2, 0, 53, 140, 213, 212, 134, 206, 178, 102, 222, 97, 207, 8, 252, 103, 8, 64, 25, 112, 206, 146, 159, 150, 220, 236, 162, 203, 172, 111, 119, 158, 192, 123, 81, 141, 89, 174, 126, 4, 65, 105, 64, 119, 27, 0, 0, 23, 138, 253, 130, 153, 78, 2, 31, 195, 254, 142, 102, 116, 200, 50, 125, 8, 178, 151, 113, 13, 205, 228, 10, 85, 83, 101, 57, 149, 191, 166, 4, 221, 153, 198, 0, 18, 185, 165, 203, 53, 211, 218, 24, 198, 162, 13, 99, 240, 249, 210, 255, 200, 217, 232, 10, 187, 212, 92, 204, 165, 217, 7, 202, 6, 114, 70, 200, 221]));

      const decipher = await streamDecipher(userCred, cipherStream);
      const cdInfo = await decipher.getCipherDataInfo();

      expect(cdInfo.alg).toEqual('X20-PLY');
      expect(cdInfo.ic).toEqual(1800000);
      expect(isEqualArray(cdInfo.iv, new Uint8Array([53, 140, 213, 212, 134, 206, 178, 102, 222, 97, 207, 8, 252, 103, 8, 64, 25, 112, 206, 146, 159, 150, 220, 236]))).toBe(true);
      expect(isEqualArray(cdInfo.slt, new Uint8Array([162, 203, 172, 111, 119, 158, 192, 123, 81, 141, 89, 174, 126, 4, 65, 105]))).toBe(true);
      expect(cdInfo.ver).toEqual(cc.VERSION5);
      expect(cdInfo.hint).toEqual(hint);

      // Although the cipherData for block0 above is missing the "terminal block" indicator,
      // that isn't detected until we hit the end of the file (below in blockN)
      await expect(decipher.decryptBlock0(async (cdinfo) => {
         expect(cdinfo.hint).toEqual(hint);
         expect(cdinfo.lp).toEqual(1);
         expect(cdinfo.lpEnd).toEqual(1);
         expect(cdinfo.alg).toBe('X20-PLY');
         expect(cdinfo.ic).toBe(1800000);
         expect(cdinfo.hint).toEqual(hint);
         expect(cdinfo.ver).toEqual(cc.VERSION5);
         expect(isEqualArray(cdInfo.iv, new Uint8Array([53, 140, 213, 212, 134, 206, 178, 102, 222, 97, 207, 8, 252, 103, 8, 64, 25, 112, 206, 146, 159, 150, 220, 236]))).toBe(true);
         expect(isEqualArray(cdInfo.slt, new Uint8Array([162, 203, 172, 111, 119, 158, 192, 123, 81, 141, 89, 174, 126, 4, 65, 105]))).toBe(true);
         return [pwd, undefined];
      })).resolves.toEqual(clearData);

      await expect(decipher.decryptBlockN()).rejects.toThrow(/Missing terminal/);
   });


   it("missing terminal block indicator, v6", async function () {
      const [_, clearData] = streamFromStr('A nice 🦫 came to say hello');
      const pwd = 'a 🌲 of course';
      const hint = '🌧️';
      // base64url userCred for use in commandline for recreation (see Python helper function):
      // Ohyqajb6nFOm2Y5lOTkIkhc3uAaF8sUrYrQ9pts2pDc=
      // creating the proper cipherdata requires a hacked/rebuilt cmdline that always sets flags to 0
      const userCred = new Uint8Array([58, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98, 180, 61, 166, 219, 54, 164, 55]);
      const [cipherStream] = streamFromBytes(new Uint8Array([132, 28, 138, 123, 147, 127, 43, 62, 165, 146, 225, 63, 193, 229, 103, 67, 52, 78, 235, 87, 222, 81, 39, 59, 221, 183, 97, 72, 255, 88, 246, 58, 6, 0, 117, 0, 0, 0, 2, 0, 34, 40, 133, 44, 12, 94, 228, 213, 26, 168, 170, 128, 158, 80, 186, 10, 199, 186, 216, 165, 74, 175, 77, 14, 167, 87, 224, 153, 52, 15, 148, 75, 171, 2, 77, 176, 158, 14, 41, 21, 64, 119, 27, 0, 0, 23, 60, 217, 5, 30, 103, 244, 158, 250, 216, 37, 3, 99, 119, 58, 27, 195, 99, 129, 80, 65, 210, 179, 102, 243, 232, 235, 177, 129, 48, 29, 127, 154, 58, 17, 16, 73, 65, 218, 12, 57, 251, 92, 205, 101, 8, 236, 63, 89, 47, 41, 190, 168, 125, 241, 136, 131, 63, 67, 146, 42, 204, 9, 202, 62, 160, 22, 123, 154]));

      const decipher = await streamDecipher(userCred, cipherStream);
      const cdInfo = await decipher.getCipherDataInfo();

      expect(cdInfo.alg).toEqual('X20-PLY');
      expect(cdInfo.ic).toEqual(1800000);
      expect(isEqualArray(cdInfo.iv, new Uint8Array([34, 40, 133, 44, 12, 94, 228, 213, 26, 168, 170, 128, 158, 80, 186, 10, 199, 186, 216, 165, 74, 175, 77, 14]))).toBe(true);
      expect(isEqualArray(cdInfo.slt, new Uint8Array([167, 87, 224, 153, 52, 15, 148, 75, 171, 2, 77, 176, 158, 14, 41, 21]))).toBe(true);
      expect(cdInfo.ver).toEqual(cc.VERSION6);
      expect(cdInfo.hint).toEqual(hint);

      // Although the cipherData for block0 above is missing the "terminal block" indicator,
      // that isn't detected until we hit the end of the file (below in blockN)
      await expect(decipher.decryptBlock0(async (cdinfo) => {
         expect(cdinfo.hint).toEqual(hint);
         expect(cdinfo.lp).toEqual(1);
         expect(cdinfo.lpEnd).toEqual(1);
         expect(cdinfo.alg).toBe('X20-PLY');
         expect(cdinfo.ic).toBe(1800000);
         expect(cdinfo.hint).toEqual(hint);
         expect(cdinfo.ver).toEqual(cc.VERSION6);
         expect(isEqualArray(cdInfo.iv, new Uint8Array([34, 40, 133, 44, 12, 94, 228, 213, 26, 168, 170, 128, 158, 80, 186, 10, 199, 186, 216, 165, 74, 175, 77, 14]))).toBe(true);
         expect(isEqualArray(cdInfo.slt, new Uint8Array([167, 87, 224, 153, 52, 15, 148, 75, 171, 2, 77, 176, 158, 14, 41, 21]))).toBe(true);
         return [pwd, undefined];
      })).resolves.toEqual(clearData);

      await expect(decipher.decryptBlockN()).rejects.toThrow(/Missing terminal/);
   });

   it("extra terminal block indicator, v6", async function () {
      const [_, clearData] = streamFromStr('A nice 🦫 came to say hello');
      const pwd = 'a 🌲 of course';
      const hint = '🌧️';
      // base64url userCred for use in commandline for recreation (see Python helper function):
      // Ohyqajb6nFOm2Y5lOTkIkhc3uAaF8sUrYrQ9pts2pDc=
      // creating the proper cipherdata requires a hacked/rebuilt cmdline that always sets flags to 0 and READ_SIZE_START to 20
      const userCred = new Uint8Array([58, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98, 180, 61, 166, 219, 54, 164, 55]);
      const [cipherStream] = streamFromBytes(new Uint8Array([114, 105, 149, 122, 214, 68, 66, 254, 204, 60, 108, 90, 88, 145, 24, 13, 64, 232, 184, 211, 137, 68, 207, 107, 242, 54, 26, 74, 31, 99, 61, 110, 6, 0, 108, 0, 0, 1, 2, 0, 38, 7, 93, 115, 159, 181, 216, 73, 45, 124, 29, 242, 220, 98, 213, 145, 114, 236, 39, 248, 11, 6, 42, 127, 123, 242, 217, 57, 58, 205, 0, 255, 238, 184, 227, 83, 181, 100, 188, 208, 64, 119, 27, 0, 0, 23, 154, 92, 181, 175, 144, 243, 53, 142, 153, 165, 44, 241, 86, 111, 236, 209, 43, 164, 62, 163, 196, 163, 117, 144, 20, 60, 205, 74, 135, 202, 75, 142, 62, 9, 135, 94, 49, 180, 28, 58, 209, 97, 164, 112, 49, 76, 42, 209, 140, 8, 93, 78, 168, 68, 248, 120, 26, 49, 28, 173, 242, 51, 71, 237, 8, 237, 174, 172, 162, 15, 13, 206, 208, 202, 130, 231, 36, 205, 62, 47, 252, 216, 35, 203, 182, 64, 202, 194, 87, 132, 92, 6, 0, 52, 0, 0, 1, 2, 0, 51, 173, 77, 222, 222, 129, 65, 79, 156, 158, 88, 144, 22, 46, 77, 72, 215, 184, 30, 152, 149, 40, 86, 78, 225, 236, 11, 99, 214, 240, 246, 48, 170, 7, 183, 213, 15, 213, 179, 207, 3, 190, 145, 97, 125, 81, 96, 46, 74]));

      const decipher = await streamDecipher(userCred, cipherStream);
      const cdInfo = await decipher.getCipherDataInfo();

      expect(cdInfo.alg).toEqual('X20-PLY');
      expect(cdInfo.ic).toEqual(1800000);
      expect(isEqualArray(cdInfo.iv, new Uint8Array([38, 7, 93, 115, 159, 181, 216, 73, 45, 124, 29, 242, 220, 98, 213, 145, 114, 236, 39, 248, 11, 6, 42, 127]))).toBe(true);
      expect(isEqualArray(cdInfo.slt, new Uint8Array([123, 242, 217, 57, 58, 205, 0, 255, 238, 184, 227, 83, 181, 100, 188, 208]))).toBe(true);
      expect(cdInfo.ver).toEqual(cc.VERSION6);
      expect(cdInfo.hint).toEqual(hint);

      // Although the cipherData for block0 above is missing the "terminal block" indicator,
      // that isn't detected until we hit the end of the file (below in blockN)
      await expect(decipher.decryptBlock0(async (cdinfo) => {
         expect(cdinfo.hint).toEqual(hint);
         expect(cdinfo.lp).toEqual(1);
         expect(cdinfo.lpEnd).toEqual(1);
         expect(cdinfo.alg).toBe('X20-PLY');
         expect(cdinfo.ic).toBe(1800000);
         expect(cdinfo.hint).toEqual(hint);
         expect(cdinfo.ver).toEqual(cc.VERSION6);
         expect(isEqualArray(cdInfo.iv, new Uint8Array([38, 7, 93, 115, 159, 181, 216, 73, 45, 124, 29, 242, 220, 98, 213, 145, 114, 236, 39, 248, 11, 6, 42, 127]))).toBe(true);
         expect(isEqualArray(cdInfo.slt, new Uint8Array([123, 242, 217, 57, 58, 205, 0, 255, 238, 184, 227, 83, 181, 100, 188, 208]))).toBe(true);
         return [pwd, undefined];
      })).resolves.toEqual(clearData.slice(0, 20));

      await expect(decipher.decryptBlockN()).rejects.toThrow(/Extra data block/);
   });


   it("flipped terminal block indicator, v6", async function () {
      const [_, clearData] = streamFromStr('A nice 🦫 came to say hello');
      const pwd = 'a 🌲 of course';
      const hint = '🌧️';
      // base64url userCred for use in commandline for recreation (see Python helper function):
      // Ohyqajb6nFOm2Y5lOTkIkhc3uAaF8sUrYrQ9pts2pDc=
      // creating the proper cipherdata requires a hacked/rebuilt cmdline that flips flags to 0 and READ_SIZE_START to 20
      const userCred = new Uint8Array([58, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98, 180, 61, 166, 219, 54, 164, 55]);
      const [cipherStream] = streamFromBytes(new Uint8Array([24, 212, 67, 36, 232, 163, 170, 119, 145, 211, 157, 196, 172, 177, 63, 167, 12, 22, 20, 81, 250, 166, 94, 226, 132, 226, 253, 243, 133, 249, 38, 46, 6, 0, 108, 0, 0, 1, 2, 0, 85, 112, 249, 39, 40, 215, 94, 63, 122, 204, 193, 102, 64, 65, 163, 82, 69, 123, 185, 109, 204, 27, 14, 222, 237, 33, 135, 94, 11, 145, 15, 204, 88, 25, 166, 108, 158, 106, 108, 144, 64, 119, 27, 0, 0, 23, 249, 240, 198, 170, 184, 70, 4, 93, 213, 139, 151, 175, 168, 83, 58, 110, 57, 141, 165, 35, 67, 130, 224, 145, 19, 200, 206, 7, 210, 27, 238, 115, 65, 227, 65, 86, 173, 49, 27, 61, 214, 163, 247, 237, 148, 168, 221, 228, 49, 197, 130, 72, 232, 83, 9, 108, 84, 44, 172, 115, 101, 0, 244, 178, 175, 216, 196, 5, 182, 210, 63, 180, 227, 122, 3, 70, 210, 255, 100, 185, 98, 226, 215, 183, 55, 131, 223, 16, 182, 177, 109, 6, 0, 52, 0, 0, 0, 2, 0, 117, 159, 80, 68, 25, 102, 215, 193, 132, 143, 200, 39, 19, 204, 47, 81, 213, 236, 77, 70, 22, 228, 220, 182, 58, 75, 143, 225, 66, 207, 162, 138, 118, 145, 133, 192, 55, 108, 217, 36, 155, 122, 39, 41, 30, 18, 66, 109, 59]));

      const decipher = await streamDecipher(userCred, cipherStream);
      const cdInfo = await decipher.getCipherDataInfo();

      expect(cdInfo.alg).toEqual('X20-PLY');
      expect(cdInfo.ic).toEqual(1800000);
      expect(isEqualArray(cdInfo.iv, new Uint8Array([85, 112, 249, 39, 40, 215, 94, 63, 122, 204, 193, 102, 64, 65, 163, 82, 69, 123, 185, 109, 204, 27, 14, 222]))).toBe(true);
      expect(isEqualArray(cdInfo.slt, new Uint8Array([237, 33, 135, 94, 11, 145, 15, 204, 88, 25, 166, 108, 158, 106, 108, 144]))).toBe(true);
      expect(cdInfo.ver).toEqual(cc.VERSION6);
      expect(cdInfo.hint).toEqual(hint);

      // Although the cipherData for block0 above is missing the "terminal block" indicator,
      // that isn't detected until we hit the end of the file (below in blockN)
      await expect(decipher.decryptBlock0(async (cdinfo) => {
         expect(cdinfo.hint).toEqual(hint);
         expect(cdinfo.lp).toEqual(1);
         expect(cdinfo.lpEnd).toEqual(1);
         expect(cdinfo.alg).toBe('X20-PLY');
         expect(cdinfo.ic).toBe(1800000);
         expect(cdinfo.hint).toEqual(hint);
         expect(cdinfo.ver).toEqual(cc.VERSION6);
         expect(isEqualArray(cdInfo.iv, new Uint8Array([85, 112, 249, 39, 40, 215, 94, 63, 122, 204, 193, 102, 64, 65, 163, 82, 69, 123, 185, 109, 204, 27, 14, 222]))).toBe(true);
         expect(isEqualArray(cdInfo.slt, new Uint8Array([237, 33, 135, 94, 11, 145, 15, 204, 88, 25, 166, 108, 158, 106, 108, 144]))).toBe(true);
         return [pwd, undefined];
      })).resolves.toEqual(clearData.slice(0, 20));

      await expect(decipher.decryptBlockN()).rejects.toThrow(/Extra data block/);
   });

   it("bad input to cipherdata info and decrypt, v4", async function () {
      const [_, clearData] = streamFromStr('A nice 🦫 came to say hello');
      const pwdGood = 'a 🌲 of course';
      const pwdBad = 'a 🌵 of course';
      const userCredBad = new Uint8Array([0, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98, 180, 61, 166, 219, 54, 164, 55]);

      // copied from "correct cipherdata info and decryption" spec above
      const userCredGood = new Uint8Array([58, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98, 180, 61, 166, 219, 54, 164, 55]);

      let [cipherStream, cipherData] = streamFromBytes(new Uint8Array([117, 163, 250, 117, 59, 97, 3, 10, 139, 12, 55, 161, 115, 52, 28, 105, 246, 126, 220, 0, 129, 151, 165, 136, 46, 97, 163, 160, 91, 9, 189, 218, 4, 0, 116, 0, 0, 0, 2, 0, 16, 242, 98, 46, 102, 223, 79, 227, 209, 73, 22, 207, 92, 80, 75, 125, 125, 234, 18, 21, 88, 64, 43, 68, 25, 193, 133, 31, 159, 156, 8, 184, 10, 164, 33, 46, 20, 159, 218, 222, 64, 119, 27, 0, 0, 23, 5, 135, 172, 203, 4, 101, 163, 155, 133, 221, 40, 227, 91, 222, 227, 213, 97, 77, 24, 117, 60, 188, 27, 153, 253, 134, 10, 112, 75, 76, 146, 132, 123, 217, 7, 171, 211, 24, 206, 186, 248, 244, 119, 18, 165, 195, 59, 160, 76, 31, 90, 80, 53, 19, 39, 143, 99, 141, 109, 68, 72, 63, 121, 199, 96, 95, 157, 81]));
      let decipher = await streamDecipher(userCredGood, cipherStream);

      // First make sure the good values are actually good
      await expect(decipher.decryptBlock0(async (cdinfo) => {
         expect(cdinfo.alg).toBe('X20-PLY');
         expect(cdinfo.ic).toBe(1800000);
         expect(cdinfo.hint).toBeTruthy();
         expect(cdinfo.ver).toEqual(cc.VERSION4);
         return [pwdGood, undefined];
      })).resolves.toEqual(clearData);

      // Ensure bad password fails
      [cipherStream] = streamFromBytes(cipherData);
      decipher = await streamDecipher(userCredGood, cipherStream);

      await expect(decipher.decryptBlock0(async (cdinfo) => {
         return [pwdBad, undefined];
      })).rejects.toThrow(DOMException);

      // Test wrong userCred
      [cipherStream] = streamFromBytes(cipherData);
      decipher = await streamDecipher(userCredBad, cipherStream);

      await expect(decipher.getCipherDataInfo()).rejects.toThrow(/Invalid MAC/);

      // decipher now in invalid state from prevous getCipherDataInfo call
      await expect(decipher.decryptBlock0(async (cdinfo) => {
         return [pwdGood, undefined];
      })).rejects.toThrow(new RegExp('Decipher invalid.+'));

      // Test wrong userCred with block decrypt first (error msg is diffeernt)
      [cipherStream] = streamFromBytes(cipherData);
      decipher = await streamDecipher(userCredBad, cipherStream);

      await expect(decipher.decryptBlock0(async (cdinfo) => {
         return [pwdGood, undefined];
      })).rejects.toThrow(new RegExp('Invalid MAC.+'));
   });

   it("bad input to cipherdata info and decrypt, v5", async function () {
      const [_, clearData] = streamFromStr('A nice 🦫 came to say hello');
      const pwdGood = 'a 🌲 of course';
      const pwdBad = 'a 🌵 of course';
      const userCredBad = new Uint8Array([0, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98, 180, 61, 166, 219, 54, 164, 55]);

      // copied from "correct cipherdata info and decryption" spec above
      const userCredGood = new Uint8Array([58, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98, 180, 61, 166, 219, 54, 164, 55]);

      let [cipherStream, cipherData] = streamFromBytes(new Uint8Array([166, 123, 188, 183, 212, 97, 47, 147, 59, 39, 78, 222, 101, 74, 221, 53, 27, 11, 194, 67, 156, 235, 116, 104, 65, 64, 76, 166, 29, 220, 71, 179, 5, 0, 116, 0, 0, 1, 2, 0, 121, 78, 37, 8, 192, 196, 110, 22, 164, 106, 59, 161, 122, 165, 176, 147, 49, 43, 41, 250, 163, 111, 218, 4, 174, 61, 6, 169, 145, 216, 66, 166, 139, 82, 19, 207, 29, 75, 105, 149, 64, 119, 27, 0, 0, 23, 93, 92, 56, 163, 242, 71, 208, 3, 190, 44, 140, 222, 149, 159, 152, 193, 162, 44, 177, 93, 197, 119, 131, 88, 92, 53, 108, 167, 253, 64, 216, 200, 121, 212, 193, 153, 180, 39, 92, 35, 142, 6, 240, 115, 51, 211, 198, 63, 12, 126, 128, 206, 178, 114, 65, 37, 246, 197, 19, 79, 58, 96, 56, 86, 172, 162, 217, 70]));
      let decipher = await streamDecipher(userCredGood, cipherStream);

      // First make sure the good values are actually good
      await expect(decipher.decryptBlock0(async (cdinfo) => {
         expect(cdinfo.alg).toBe('X20-PLY');
         expect(cdinfo.ic).toBe(1800000);
         expect(cdinfo.hint).toBeTruthy();
         expect(cdinfo.ver).toEqual(cc.VERSION5);
         return [pwdGood, undefined];
      })).resolves.toEqual(clearData);

      // Ensure bad password fails
      [cipherStream] = streamFromBytes(cipherData);
      decipher = await streamDecipher(userCredGood, cipherStream);

      await expect(decipher.decryptBlock0(async (cdinfo) => {
         return [pwdBad, undefined];
      })).rejects.toThrow(DOMException);

      // Test wrong userCred
      [cipherStream] = streamFromBytes(cipherData);
      decipher = await streamDecipher(userCredBad, cipherStream);

      await expect(decipher.getCipherDataInfo()).rejects.toThrow(/MAC/);

      // Does not get MAC error because the decipher instance is now if a
      // bad state and will remain so... forever...
      await expect(decipher.decryptBlock0(async (cdinfo) => {
         return [pwdGood, undefined];
      })).rejects.toThrow(new RegExp('Decipher invalid state.+'));
   });

   it("bad input to cipherdata info and decrypt, v6", async function () {
      const [_, clearData] = streamFromStr('A nice 🦫 came to say hello');
      const pwdGood = 'a 🌲 of course';
      const pwdBad = 'a 🌵 of course';
      const userCredBad = new Uint8Array([0, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98, 180, 61, 166, 219, 54, 164, 55]);

      // copied from "correct cipherdata info and decryption" spec above
      const userCredGood = new Uint8Array([58, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98, 180, 61, 166, 219, 54, 164, 55]);
      let [cipherStream, cipherData] = streamFromBytes(new Uint8Array([6, 96, 26, 215, 92, 226, 157, 130, 104, 27, 37, 39, 156, 244, 118, 186, 163, 217, 181, 220, 148, 183, 115, 69, 212, 144, 69, 184, 232, 175, 121, 248, 6, 0, 117, 0, 0, 1, 2, 0, 182, 155, 226, 214, 133, 101, 225, 193, 160, 76, 50, 50, 81, 174, 29, 73, 153, 121, 174, 60, 118, 42, 201, 149, 164, 52, 159, 208, 233, 162, 104, 60, 88, 170, 241, 87, 39, 144, 27, 9, 64, 119, 27, 0, 0, 23, 39, 229, 13, 184, 77, 68, 136, 183, 209, 252, 108, 46, 43, 205, 134, 87, 252, 6, 137, 0, 87, 185, 232, 81, 118, 182, 118, 213, 206, 208, 109, 156, 228, 114, 188, 28, 150, 5, 239, 220, 247, 53, 192, 38, 56, 0, 190, 42, 95, 177, 83, 44, 31, 173, 51, 32, 94, 177, 93, 144, 3, 149, 167, 10, 114, 79, 141, 182]));
      let decipher = await streamDecipher(userCredGood, cipherStream);

      // First make sure the good values are actually good
      await expect(decipher.decryptBlock0(async (cdinfo) => {
         expect(cdinfo.alg).toBe('X20-PLY');
         expect(cdinfo.ic).toBe(1800000);
         expect(cdinfo.hint).toBeTruthy();
         expect(cdinfo.ver).toEqual(cc.VERSION6);
         return [pwdGood, undefined];
      })).resolves.toEqual(clearData);

      // Ensure bad password fails
      [cipherStream] = streamFromBytes(cipherData);
      decipher = await streamDecipher(userCredGood, cipherStream);

      await expect(decipher.decryptBlock0(async (cdinfo) => {
         return [pwdBad, undefined];
      })).rejects.toThrow(DOMException);

      // Test wrong userCred
      [cipherStream] = streamFromBytes(cipherData);
      decipher = await streamDecipher(userCredBad, cipherStream);

      await expect(decipher.getCipherDataInfo()).rejects.toThrow(/MAC/);

      // Does not get MAC error because the decipher instance is now if a
      // bad state and will remain so... forever...
      await expect(decipher.decryptBlock0(async (cdinfo) => {
         return [pwdGood, undefined];
      })).rejects.toThrow(new RegExp('Decipher invalid state.+'));
   });
});



describe("Detect changed cipher data", function () {
   beforeEach(async () => {
      await sodium.ready;
   });

   it("detect changed headerData", async function () {

      for (let alg in cc.AlgInfo) {
         const [clearStream, clearData] = streamFromStr('This is a secret 🦆');
         const pwd = 'a good pwd';
         const hint = 'not really';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

         const eparams: EParams = {
            alg: alg,
            ic: cc.ICOUNT_MIN,
            lp: 1,
            lpEnd: 1
         };

         const latest = latestEncipher(userCred, clearStream);
         const block0 = await latest.encryptBlock0(eparams, async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            expect(cdinfo.alg).toBe(alg);
            expect(cdinfo.ic).toBe(cc.ICOUNT_MIN);
            return [pwd, hint];
         });

         const savedHeader = new Uint8Array(block0.parts[0]);

         // set byte in MAC
         block0.parts[0][12] = block0.parts[0][12] == 123 ? 124 : 123;
         let [cipherStream] = streamFromCipherBlock([block0]);
         let decipher = await streamDecipher(userCred, cipherStream);

         await expect(decipher.decryptBlock0(async (cdinfo) => {
            return [pwd, undefined];
         })).rejects.toThrow(/Invalid MAC.+/);

         block0.parts[0] = new Uint8Array(savedHeader);
         [cipherStream] = streamFromCipherBlock([block0]);
         decipher = await streamDecipher(userCred, cipherStream);

         await expect(decipher.decryptBlock0(async (cdinfo) => {
            return [pwd, undefined];
         })).resolves.toEqual(clearData);

         // set version
         block0.parts[0][33] = block0.parts[0][33] == 43 ? 45 : 43;
         [cipherStream] = streamFromCipherBlock([block0]);

         await expect(streamDecipher(userCred, cipherStream)).rejects.toThrow(/Invalid version/);

         // set length
         block0.parts[0] = new Uint8Array(savedHeader);
         block0.parts[0][36] = block0.parts[0][36] == 43 ? 45 : 43;
         [cipherStream] = streamFromCipherBlock([block0]);
         decipher = await streamDecipher(userCred, cipherStream);

         await expect(decipher.decryptBlock0(async (cdinfo) => {
            return [pwd, undefined];
         })).rejects.toThrow(/Cipher data length mismatch+/);
      }
   });

   it("detect changed additionalData", async function () {

      for (let alg in cc.AlgInfo) {
         const [clearStream, clearData] = streamFromStr('This is a secret 🦆');
         const pwd = 'a good pwd';
         const hint = 'not really';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

         const eparams: EParams = {
            alg: alg,
            ic: cc.ICOUNT_MIN,
            lp: 1,
            lpEnd: 1
         };

         const latest = latestEncipher(userCred, clearStream);
         const block0 = await latest.encryptBlock0(eparams, async (cdinfo) => {
            expect(cdinfo.alg).toBe(alg);
            expect(cdinfo.ic).toBe(cc.ICOUNT_MIN);
            return [pwd, hint];
         });

         const savedAD = new Uint8Array(block0.parts[1]);

         block0.parts[1][12] = block0.parts[1][12] == 123 ? 124 : 123;
         let [cipherStream] = streamFromCipherBlock([block0]);
         let decipher = await streamDecipher(userCred, cipherStream);

         await expect(decipher.decryptBlock0(async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, undefined];
         })).rejects.toThrow(new RegExp('.+MAC.+'));

         // Confirm we're back to good state
         block0.parts[1] = new Uint8Array(savedAD);
         [cipherStream] = streamFromCipherBlock([block0]);
         decipher = await streamDecipher(userCred, cipherStream);

         await expect(decipher.decryptBlock0(async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, undefined];
         })).resolves.toEqual(clearData);

         // set byte near end
         const back = block0.parts[1].byteLength - 4;
         block0.parts[1][back] = block0.parts[1][back] == 43 ? 45 : 43;
         [cipherStream] = streamFromCipherBlock([block0]);
         decipher = await streamDecipher(userCred, cipherStream);

         await expect(decipher.decryptBlock0(async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, undefined];
         })).rejects.toThrow(new RegExp('.+MAC.+'));
      }
   });

   it("detect changed encryptedData", async function () {

      for (let alg in cc.AlgInfo) {
         const [clearStream] = streamFromStr('This is a secret 🦆');
         const pwd = 'a good pwd';
         const hint = 'not really';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

         const eparams: EParams = {
            alg: alg,
            ic: cc.ICOUNT_MIN,
            lp: 1,
            lpEnd: 1
         };

         const latest = latestEncipher(userCred, clearStream);
         const block0 = await latest.encryptBlock0(eparams, async (cdinfo) => {
            expect(cdinfo.alg).toBe(alg);
            expect(cdinfo.ic).toBe(cc.ICOUNT_MIN);
            return [pwd, hint];
         });

         block0.parts[2][12] = block0.parts[2][12] == 123 ? 124 : 123;
         let [cipherStream] = streamFromCipherBlock([block0]);
         let decipher = await streamDecipher(userCred, cipherStream);

         await expect(decipher.decryptBlock0(async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, undefined];
         })).rejects.toThrow(new RegExp('.+MAC.+'));
      }
   });

   it("does not detect changed headerData, skip MAC verify", async function () {

      for (let alg in cc.AlgInfo) {
         const [clearStream, clearData] = streamFromStr('This is a secret 🦆');
         const pwd = 'a good pwd';
         const hint = 'not really';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

         const eparams: EParams = {
            alg: alg,
            ic: cc.ICOUNT_MIN,
            lp: 1,
            lpEnd: 1
         };

         const latest = latestEncipher(userCred, clearStream);
         const block0 = await latest.encryptBlock0(eparams, async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            expect(cdinfo.alg).toBe(alg);
            expect(cdinfo.ic).toBe(cc.ICOUNT_MIN);
            return [pwd, hint];
         });

         // set byte in MAC
         block0.parts[0][12] = block0.parts[0][12] == 123 ? 124 : 123;
         let [cipherStream] = streamFromCipherBlock([block0]);
         let decipher = await streamDecipher(userCred, cipherStream);

         // Monkey patch to skip MAC validation
         //@ts-ignore
         decipher['_verifyMAC'] = (): Promise<boolean> => {
            return Promise.resolve(true);
         };

         // This should succeed even though the MAC has been changed (because
         // MAC was not tested due to monkey patch)
         await expect(decipher.decryptBlock0(async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, undefined];
         })).resolves.toEqual(clearData);
      }
   });

   it("detect changed additionalData, skip MAC verify", async function () {

      for (let alg in cc.AlgInfo) {
         const [clearStream, clearData] = streamFromStr('This is a secret 🦆');
         const pwd = 'a good pwd';
         const hint = 'not really';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

         const eparams: EParams = {
            alg: alg,
            ic: cc.ICOUNT_MIN,
            lp: 1,
            lpEnd: 1
         };

         const latest = latestEncipher(userCred, clearStream);
         const block0 = await latest.encryptBlock0(eparams, async (cdinfo) => {
            expect(cdinfo.alg).toBe(alg);
            expect(cdinfo.ic).toBe(cc.ICOUNT_MIN);
            return [pwd, hint];
         });

         // set byte in additional data
         block0.parts[1][12] = block0.parts[1][12] == 123 ? 124 : 123;
         let [cipherStream] = streamFromCipherBlock([block0]);
         let decipher = await streamDecipher(userCred, cipherStream);

         // Monkey patch to skip MAC validation
         //@ts-ignore
         decipher['_verifyMAC'] = (): Promise<boolean> => {
            return Promise.resolve(true);
         };

         // This should fail (even though MAC check wass skipped) because
         // AD check is part of all encryption algorithms. Note that this
         // should fail with DOMException rather than Error with MAC in message
         await expect(decipher.decryptBlock0(async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, undefined];
         })).rejects.toThrow(DOMException);
      }
   });

   it("detect changed encryptedData, skip MAC verify", async function () {

      for (let alg in cc.AlgInfo) {
         const [clearStream, clearData] = streamFromStr('This is a secret 🦆');
         const pwd = 'a good pwd';
         const hint = 'not really';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

         const eparams: EParams = {
            alg: alg,
            ic: cc.ICOUNT_MIN,
            lp: 1,
            lpEnd: 1
         };

         const latest = latestEncipher(userCred, clearStream);
         const block0 = await latest.encryptBlock0(eparams, async (cdinfo) => {
            expect(cdinfo.alg).toBe(alg);
            expect(cdinfo.ic).toBe(cc.ICOUNT_MIN);
            return [pwd, hint];
         });

         // set byte in encrypted data
         block0.parts[2][12] = block0.parts[2][12] == 123 ? 124 : 123;
         let [cipherStream] = streamFromCipherBlock([block0]);
         let decipher = await streamDecipher(userCred, cipherStream);

         // Monkey patch to skip MAC validation
         //@ts-ignore
         decipher['_verifyMAC'] = (): Promise<boolean> => {
            return Promise.resolve(true);
         };

         // This should fail (even though MAC check is skipped) because
         // encrypted data was modified. Note that this should
         // fail with DOMException rather than Error with MAC in message
         await expect(decipher.decryptBlock0(async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, undefined];
         })).rejects.toThrow(DOMException);
      }
   });
});

describe("Detect block order changes", function () {
   beforeEach(async () => {
      await sodium.ready;
   });

   const pwd = 'a not good pwd';
   const hint = 'sorta';
   const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));
   const clearStr = 'This is a secret 🦀 with extra wording for more blocks';

   async function get_blocks(alg: string): Promise<[
      CipherDataBlock,
      CipherDataBlock,
      CipherDataBlock
   ]> {
      const eparams: EParams = {
         alg: alg,
         ic: cc.ICOUNT_MIN,
         lp: 1,
         lpEnd: 1
      };

      const [clearStream] = streamFromStr(clearStr);

      const latest = latestEncipher(userCred, clearStream);
      const readStart = 11;
      //@ts-ignore force multiple blocks
      latest['_readTarget'] = readStart;

      const block0 = await latest.encryptBlock0(eparams, async (cdinfo) => {
         expect(cdinfo.lp).toEqual(1);
         expect(cdinfo.lpEnd).toEqual(1);
         return [pwd, hint];
      });
      const block1 = await latest.encryptBlockN(eparams);
      const block2 = await latest.encryptBlockN(eparams);

      return [block0, block1, block2];
   }

   it("block order good, all algorithms", async function () {

      const clearData = new TextEncoder().encode(clearStr);

      for (let alg in cc.AlgInfo) {

         const [block0, block1, block2] = await get_blocks(alg);

         // First make sure we can decrypt in the proper order
         let [cipherStream] = streamFromCipherBlock([block0, block1, block2]);
         let decipher = await streamDecipher(userCred, cipherStream);

         const decb0 = await decipher.decryptBlock0(async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, undefined];
         });
         const decb1 = await decipher.decryptBlockN();
         const decb2 = await decipher.decryptBlockN();

         let [decrypted] = streamFromBytes([decb0, decb1, decb2]);

         await expect(areEqual(decrypted, clearData)).resolves.toEqual(true);
      }
   });

   it("blockN bad order detected, all algorithms", async function () {

      const clearData = new TextEncoder().encode(clearStr);

      for (let alg in cc.AlgInfo) {

         const [block0, block1, block2] = await get_blocks(alg);

         // Order of block N+ changed
         let [cipherStream] = streamFromCipherBlock([block0, block2, block1]);
         let decipher = await streamDecipher(userCred, cipherStream);

         const decb0 = await decipher.decryptBlock0(async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, undefined];
         });

         const partial = new TextDecoder().decode(decb0);
         expect(clearStr.startsWith(partial)).toBe(true);

         // In V4 this worked, but should fail in V5
         await expect(decipher.decryptBlockN()).rejects.toThrow(/Invalid MAC/);
      }
   });

   it("block0 bad order detected, all algorithms", async function () {

      const clearData = new TextEncoder().encode(clearStr);

      for (let alg in cc.AlgInfo) {

         const [block0, block1, block2] = await get_blocks(alg);

         let [cipherStream] = streamFromCipherBlock([block1, block0, block2]);
         let decipher = await streamDecipher(userCred, cipherStream);

         // Will fail in V4 and later because block0 format or MAC is invalid.
         // Failure detection can happen at different spots while data is unpacked
         // since random values may look valid. MAC will alsways be
         // invalid if we get that far.
         await expect(decipher.decryptBlock0(async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, undefined];
         })).rejects.toThrow(new RegExp('Invalid.+'));

      }
   });
});


// Python helper function to recreate values
// from base64 import urlsafe_b64decode as b64d
/*
def b64Tou8a(b64str):
   padds = (4 - len(b64str) % 4) % 4
   b64str = b64str + '=' * padds
   ba = b64d(b64str);
   ia = [int(v) for v in ba]
   print(f'new Uint8Array({ia});')

def hexTou8a(hstr):
   ta = hstr.split()
   ia = [int(v, 16) for v in ta]
   print(f'new Uint8Array({ia});')
*/
