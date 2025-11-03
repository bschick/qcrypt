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
import { TestBed } from '@angular/core/testing';
import * as cc from './cipher.consts';
import { getRandom48, BYOBStreamReader, readStreamAll } from './utils';
import {
   Encipher,
   Decipher,
   EParams,
   _genCipherKey,
   CipherDataBlock,
   _genHintCipherKey,
   _genSigningKey,
   EncipherV6
} from './ciphers';
import { _genSigningKeyOld } from './deciphers-old';

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
async function areEqual(
   a: Uint8Array | ReadableStream<Uint8Array>,
   b: Uint8Array | ReadableStream<Uint8Array>
): Promise<boolean> {

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

function streamFromBytes(
   data: Uint8Array | Uint8Array[]
): [ReadableStream<Uint8Array>, Uint8Array] {

   let parts: Uint8Array[];
   if (data instanceof Uint8Array) {
      parts = [data];
   } else {
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

function streamFromStr(str: string): [ReadableStream<Uint8Array>, Uint8Array] {
   const data = new TextEncoder().encode(str);
   const blob = new Blob([data], { type: 'application/octet-stream' });
   return [blob.stream(), data];
}

function streamFromCipherBlock(
   cdBlocks: CipherDataBlock[]
): [ReadableStream<Uint8Array>, Uint8Array] {

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
   beforeEach(() => {
      TestBed.configureTestingModule({});
   });

   it("successful and not equivalent key generation", async function () {

      for (let alg in cc.AlgInfo) {
         const pwd = 'not a good pwd';
         const ic = cc.ICOUNT_MIN;
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

         const randomArray = getRandom48();
         const slt = randomArray.slice(0, cc.SLT_BYTES);

         const ek = await _genCipherKey(alg, ic, pwd, userCred, slt);
         const sk = await _genSigningKey(userCred, slt);
         const hk = await _genHintCipherKey(alg, userCred, slt);

         expect(ek.byteLength).toBe(32);
         expect(sk.byteLength).toBe(32);
         expect(hk.byteLength).toBe(32);

         expect(isEqualArray(ek, sk)).toBeFalse();
         expect(isEqualArray(ek, hk)).toBeFalse();
         expect(isEqualArray(sk, hk)).toBeFalse();
      }
   });

   it("keys should match expected values", async function () {

      const expected: { [k1: string]: { [k2: string]: Uint8Array } } = {
         'AES-GCM': {
            ek: new Uint8Array([158, 221, 13, 155, 167, 216, 81, 115, 151, 193, 225, 53, 187, 156, 175, 196, 85, 234, 233, 199, 86, 45, 149, 120, 1, 57, 14, 102, 147, 123, 7, 150]),
            skOld: new Uint8Array([238, 127, 13, 239, 238, 127, 177, 22, 231, 87, 89, 23, 88, 52, 42, 22, 6, 170, 172, 112, 111, 101, 147, 204, 238, 28, 203, 159, 118, 54, 139, 151]),
            hk: new Uint8Array([253, 30, 237, 129, 147, 186, 235, 65, 217, 78, 219, 38, 163, 12, 23, 248, 3, 118, 123, 120, 237, 0, 56, 103, 67, 76, 88, 126, 153, 83, 238, 85]),
         },
         'X20-PLY': {
            ek: new Uint8Array([158, 221, 13, 155, 167, 216, 81, 115, 151, 193, 225, 53, 187, 156, 175, 196, 85, 234, 233, 199, 86, 45, 149, 120, 1, 57, 14, 102, 147, 123, 7, 150]),
            skOld: new Uint8Array([238, 127, 13, 239, 238, 127, 177, 22, 231, 87, 89, 23, 88, 52, 42, 22, 6, 170, 172, 112, 111, 101, 147, 204, 238, 28, 203, 159, 118, 54, 139, 151]),
            hk: new Uint8Array([253, 30, 237, 129, 147, 186, 235, 65, 217, 78, 219, 38, 163, 12, 23, 248, 3, 118, 123, 120, 237, 0, 56, 103, 67, 76, 88, 126, 153, 83, 238, 85]),
         },
         'AEGIS-256': {
            ek: new Uint8Array([158, 221, 13, 155, 167, 216, 81, 115, 151, 193, 225, 53, 187, 156, 175, 196, 85, 234, 233, 199, 86, 45, 149, 120, 1, 57, 14, 102, 147, 123, 7, 150]),
            skOld: new Uint8Array([238, 127, 13, 239, 238, 127, 177, 22, 231, 87, 89, 23, 88, 52, 42, 22, 6, 170, 172, 112, 111, 101, 147, 204, 238, 28, 203, 159, 118, 54, 139, 151]),
            hk: new Uint8Array([253, 30, 237, 129, 147, 186, 235, 65, 217, 78, 219, 38, 163, 12, 23, 248, 3, 118, 123, 120, 237, 0, 56, 103, 67, 76, 88, 126, 153, 83, 238, 85]),
         }
      };

      for (let alg in cc.AlgInfo) {
         const pwd = 'a good pwd';
         const ic = cc.ICOUNT_MIN;
         const userCred = new Uint8Array([214, 245, 252, 122, 133, 39, 76, 162, 64, 201, 143, 217, 237, 57, 18, 207, 199, 153, 20, 28, 162, 9, 236, 66, 100, 103, 152, 159, 226, 50, 225, 129]);
         const baseArray = new Uint8Array([160, 202, 135, 230, 125, 174, 49, 189, 171, 56, 203, 1, 237, 233, 27, 76, 46, 22, 226, 86, 89, 132, 143, 185, 198, 129, 242, 241, 183, 195, 191, 229, 162, 127, 162, 148, 75, 16, 28, 140]);
         const slt = baseArray.slice(0, cc.SLT_BYTES);

         const ek = await _genCipherKey(alg, ic, pwd, userCred, slt);
         const skOld = await _genSigningKeyOld(userCred, slt);
         const hk = await _genHintCipherKey(alg, userCred, slt);

         expect(isEqualArray(ek, expected[alg]['ek'])).toBeTrue();
         expect(isEqualArray(skOld, expected[alg]['skOld'])).toBeTrue();
         expect(isEqualArray(hk, expected[alg]['hk'])).toBeTrue();
      }
   });
});

describe("Encryption and decryption", function () {
   beforeEach(() => {
      TestBed.configureTestingModule({});
   });

   // async function signAndRepack(
   //    encipher: Encipher,
   //    userCred: Uint8Array,
   //    block: CipherDataBlock
   // ): Promise<Uint8Array> {

   //    // cheating... parts[1] is _additionalData, parts[2] is encryptedData
   //    //@ts-ignore
   //    const sk = await EncipherV5._genSigningKey(userCred, encipher['_slt']!);
   //    const [headerData] = await EncipherV6._createHeader(sk, block.parts[2], block.parts[1], new Uint8Array(0), true);

   //    const output = new Uint8Array(headerData.byteLength +
   //       block.parts[1].byteLength +
   //       block.parts[2].byteLength
   //    );

   //    output.set(headerData);
   //    output.set(block.parts[1], headerData.byteLength);
   //    output.set(
   //       block.parts[2],
   //       headerData.byteLength + block.parts[1].byteLength
   //    );

   //    return output;
   // }

   // More complex test to ensure that having the wrong usercred causes
   // decryption to fail. We test this by extracting and not changing original
   // CipherData (with its encrypted data) from "Alice's" original encryption,
   // then creating a new valid MAC signature with "Bob's" userCredB signature
   // attached to the front of the Alice's CipherData (and encypted txt).
   //
   // In the wild if the MAC signature was swapped with someone else's
   // valid signature Quick Crypt would report the error to Alice at signature
   // validation time because it would use Alice's userCredA not Bob's userCredB to
   // test.
   //
   // But what could happen is that an evil site might closely mimicked
   // Quick Crypt, and if Alice was tricked into going there, it could
   // not tell Alice about the MAC signature failure. So what this test
   // validates is that even with a replaced MAC signature
   // (which is equivalent to an ignored MAC signature), the clear
   // text can still not be retrived. This test tries to ensures that
   // even having tricked Alice into entering her PWD at the evil website,
   // the ciphertext still cannot be decrypted because the
   // evil site does not have access to Alice's userCredA which is
   // combined with her password to generate the cipher key.
   //
   // it("decryption should fail with replaced valid signature", async function () {

   //    for (let alg in cc.AlgInfo) {

   //       const [clearStream, clearData] = streamFromStr('This is a secret 🐓');
   //       const pwd = 'a good pwd';
   //       const userCredA = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));
   //       const userCredB = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

   //       const eparams: EParams = {
   //          alg: alg,
   //          ic: cc.ICOUNT_MIN,
   //          lp: 1,
   //          lpEnd: 1
   //       };

   //       const reader = new BYOBStreamReader(clearStream);
   //       const encipher = new EncipherV5(userCredA, reader);
   //       const cipherBlock = await encipher.encryptBlock0(
   //          eparams,
   //          async (cdinfo) => {
   //             expect(cdinfo.lp).toEqual(1);
   //             expect(cdinfo.lpEnd).toEqual(1);
   //             return [pwd, undefined];
   //          }
   //       );

   //       // First sign and repack with the original (correct) values to help ensure the
   //       // code for repacking is valid and that the 2nd attempt with a new signature
   //       // detects the userCred change rather than bug in signAndRepack. Then resign
   //       // and pack with Bob's userCred
   //       let [cipherstreamA, cipherDataA] = streamFromBytes(
   //          await signAndRepack(encipher, userCredA, cipherBlock)
   //       );
   //       let [cipherstreamB, cipherDataB] = streamFromBytes(
   //          await signAndRepack(encipher, userCredB, cipherBlock)
   //       );

   //       // These should fail  because using the wrong userCred on each
   //       let decipherA = await Decipher.fromStream(userCredB, cipherstreamA)
   //       let decipherB = await Decipher.fromStream(userCredA, cipherstreamB)

   //       await expectAsync(
   //          decipherA._decodePayload0()
   //       ).toBeRejectedWithError(Error, new RegExp('.+MAC.+'));
   //       await expectAsync(
   //          decipherB._decodePayload0()
   //       ).toBeRejectedWithError(Error, new RegExp('.+MAC.+'));

   //       // Reload with matching userCreds
   //       [cipherstreamA] = streamFromBytes(cipherDataA);
   //       [cipherstreamB] = streamFromBytes(cipherDataB);
   //       decipherA = await Decipher.fromStream(userCredA, cipherstreamA)
   //       decipherB = await Decipher.fromStream(userCredB, cipherstreamB)

   //       // Both should succeed since the singatures are valid with the userCreds
   //       // passed below. Decryptiong, cipherText would fail on B (checked below).
   //       // Also, these would fail if there was an encrypted hint
   //       await expectAsync(
   //          decipherA._decodePayload0()
   //       ).toBeResolved();
   //       await expectAsync(
   //          decipherB._decodePayload0()
   //       ).toBeResolved();

   //       // should succeed since we repacked with correct userCred
   //       await expectAsync(
   //          decipherA.decryptBlock0(
   //             async (cdinfo) => {
   //                return [pwd, undefined];
   //             }
   //          )
   //       ).toBeResolvedTo(clearData);

   //       // The big moment... perhaps should have better validation that the decryption
   //       // failed, but not much else returns DOMException from cipher.service. Note that
   //       // this is using the correct PWD because we assume the evil site has tricked
   //       // Alice into provider it (just not her userCred since site cannot retrieve)
   //       await expectAsync(
   //          decipherB.decryptBlock0(
   //             async (cdinfo) => {
   //                return [pwd, undefined];
   //             }
   //          )
   //       ).toBeRejectedWithError(DOMException);
   //    }
   // });

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

         const latest = Encipher.latest(userCred, clearStream);
         const block0 = await latest.encryptBlock0(
            eparams,
            async (cdinfo) => {
               expect(cdinfo.alg).toEqual(alg);
               const ivBytes = Number(cc.AlgInfo[alg]['iv_bytes']);
               expect(cdinfo.iv.byteLength).toEqual(ivBytes);
               expect(cdinfo.slt.byteLength).toEqual(cc.SLT_BYTES);
               expect(cdinfo.ic).toBe(cc.ICOUNT_MIN);
               expect(cdinfo.lp).toEqual(1);
               expect(cdinfo.lpEnd).toEqual(1);
               expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
               return [pwd, hint];
            }
         );

         const [cipherStream] = streamFromCipherBlock([block0]);
         const decipher = await Decipher.fromStream(userCred, cipherStream);

         const decrypted = await decipher.decryptBlock0(
            async (cdinfo) => {
               expect(cdinfo.alg).toEqual(alg);
               const ivBytes = Number(cc.AlgInfo[alg]['iv_bytes']);
               expect(cdinfo.iv.byteLength).toEqual(ivBytes);
               expect(cdinfo.slt.byteLength).toEqual(cc.SLT_BYTES);
               expect(cdinfo.ic).toBe(cc.ICOUNT_MIN);
               expect(cdinfo.hint).toEqual(hint);
               expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
               return [pwd, undefined];
            }
         );

         await expectAsync(
            areEqual(decrypted, clearData)
         ).toBeResolvedTo(true);
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

         let latest = Encipher.latest(userCred, clearStream);
         const readStart = 12
         //@ts-ignore force multiple blocks
         latest['_readTarget'] = readStart;

         await expectAsync(
            latest.encryptBlockN(eparams)
         ).toBeRejectedWithError(Error, new RegExp('Encipher invalid state.+'));

         // once invalidated, it stays that way...
         await expectAsync(
            latest.encryptBlock0(
               eparams,
               async (cdinfo) => {
                  return [pwd, hint];
               })
         ).toBeRejectedWithError(Error, new RegExp('Encipher invalid state.+'));

         [clearStream, clearData] = streamFromStr('This is a secret 🦀');
         latest = Encipher.latest(userCred, clearStream);
         //@ts-ignore force multiple blocks
         latest['_readTarget'] = readStart;

         const block0 = await latest.encryptBlock0(
            eparams,
            async (cdinfo) => {
               expect(cdinfo.lp).toEqual(1);
               expect(cdinfo.lpEnd).toEqual(1);
               return [pwd, hint];
            }
         );
         const blockN = await latest.encryptBlockN(eparams);

         let [cipherStream] = streamFromCipherBlock([block0, blockN]);
         let decipher = await Decipher.fromStream(userCred, cipherStream);

         let decb0 = await decipher.decryptBlock0(
            async (cdinfo) => {
               expect(cdinfo.lp).toEqual(1);
               expect(cdinfo.lpEnd).toEqual(1);
               return [pwd, undefined];
            }
         );
         await expectAsync(
            areEqual(decb0, clearData.slice(0, readStart))
         ).toBeResolvedTo(true);

         const decb1 = await decipher.decryptBlockN()
         await expectAsync(
            areEqual(decb1, clearData.slice(readStart))
         ).toBeResolvedTo(true);

         // Try again, but copy block0 head to block N
         const badBlockN = {
            ...blockN
         };
         badBlockN.parts[0] = block0.parts[0];

         [cipherStream] = streamFromCipherBlock([block0, badBlockN]);
         decipher = await Decipher.fromStream(userCred, cipherStream);

         decb0 = await decipher.decryptBlock0(
            async (cdinfo) => {
               expect(cdinfo.lp).toEqual(1);
               expect(cdinfo.lpEnd).toEqual(1);
               return [pwd, undefined];
            }
         );
         await expectAsync(
            areEqual(decb0, clearData.slice(0, readStart))
         ).toBeResolvedTo(true);

         await expectAsync(
            decipher.decryptBlockN()
         ).toBeRejectedWithError(Error, new RegExp('Cipher data length mismatch2.+'));

      }
   });

   it("correct cipherdata info and decryption, v4", async function () {
      const [_, clearData] = streamFromStr('A nice 🦫 came to say hello');
      const pwd = 'a 🌲 of course';
      const hint = '🌧️';
      // base64url userCred for injection into browser for recreation:
      // Ohyqajb6nFOm2Y5lOTkIkhc3uAaF8sUrYrQ9pts2pDc=
      const userCred = new Uint8Array([58, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98, 180, 61, 166, 219, 54, 164, 55]);
      const [cipherStream] = streamFromBytes(new Uint8Array([117, 163, 250, 117, 59, 97, 3, 10, 139, 12, 55, 161, 115, 52, 28, 105, 246, 126, 220, 0, 129, 151, 165, 136, 46, 97, 163, 160, 91, 9, 189, 218, 4, 0, 116, 0, 0, 0, 2, 0, 16, 242, 98, 46, 102, 223, 79, 227, 209, 73, 22, 207, 92, 80, 75, 125, 125, 234, 18, 21, 88, 64, 43, 68, 25, 193, 133, 31, 159, 156, 8, 184, 10, 164, 33, 46, 20, 159, 218, 222, 64, 119, 27, 0, 0, 23, 5, 135, 172, 203, 4, 101, 163, 155, 133, 221, 40, 227, 91, 222, 227, 213, 97, 77, 24, 117, 60, 188, 27, 153, 253, 134, 10, 112, 75, 76, 146, 132, 123, 217, 7, 171, 211, 24, 206, 186, 248, 244, 119, 18, 165, 195, 59, 160, 76, 31, 90, 80, 53, 19, 39, 143, 99, 141, 109, 68, 72, 63, 121, 199, 96, 95, 157, 81]));

      const decipher = await Decipher.fromStream(userCred, cipherStream);
      const cdInfo = await decipher.getCipherDataInfo();

      expect(cdInfo.alg).toEqual('X20-PLY');
      expect(cdInfo.ic).toEqual(1800000);
      expect(isEqualArray(cdInfo.iv, new Uint8Array([16, 242, 98, 46, 102, 223, 79, 227, 209, 73, 22, 207, 92, 80, 75, 125, 125, 234, 18, 21, 88, 64, 43, 68]))).toBeTrue();
      expect(isEqualArray(cdInfo.slt, new Uint8Array([25, 193, 133, 31, 159, 156, 8, 184, 10, 164, 33, 46, 20, 159, 218, 222]))).toBeTrue();
      expect(cdInfo.ver).toEqual(cc.VERSION4);
      expect(cdInfo.hint).toEqual(hint);

      await expectAsync(
         decipher.decryptBlock0(
            async (cdinfo) => {
               expect(cdinfo.hint).toEqual(hint);
               expect(cdinfo.lp).toEqual(1);
               expect(cdinfo.lpEnd).toEqual(1);
               expect(cdinfo.alg).toBe('X20-PLY');
               expect(cdinfo.ic).toBe(1800000);
               expect(cdinfo.hint).toEqual(hint);
               expect(cdinfo.ver).toEqual(cc.VERSION4);
               expect(isEqualArray(cdInfo.iv, new Uint8Array([16, 242, 98, 46, 102, 223, 79, 227, 209, 73, 22, 207, 92, 80, 75, 125, 125, 234, 18, 21, 88, 64, 43, 68]))).toBeTrue();
               expect(isEqualArray(cdInfo.slt, new Uint8Array([25, 193, 133, 31, 159, 156, 8, 184, 10, 164, 33, 46, 20, 159, 218, 222]))).toBeTrue();
               return [pwd, undefined];
            }
         )
      ).toBeResolvedTo(clearData);
   });

   it("correct cipherdata info and decryption, v5", async function () {
      const [_, clearData] = streamFromStr('A nice 🦫 came to say hello');
      const pwd = 'a 🌲 of course';
      const hint = '🌧️';
      // base64url userCred for injection into browser for recreation:
      // Ohyqajb6nFOm2Y5lOTkIkhc3uAaF8sUrYrQ9pts2pDc=
      const userCred = new Uint8Array([58, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98, 180, 61, 166, 219, 54, 164, 55]);
      const [cipherStream] = streamFromBytes(new Uint8Array([166, 123, 188, 183, 212, 97, 47, 147, 59, 39, 78, 222, 101, 74, 221, 53, 27, 11, 194, 67, 156, 235, 116, 104, 65, 64, 76, 166, 29, 220, 71, 179, 5, 0, 116, 0, 0, 1, 2, 0, 121, 78, 37, 8, 192, 196, 110, 22, 164, 106, 59, 161, 122, 165, 176, 147, 49, 43, 41, 250, 163, 111, 218, 4, 174, 61, 6, 169, 145, 216, 66, 166, 139, 82, 19, 207, 29, 75, 105, 149, 64, 119, 27, 0, 0, 23, 93, 92, 56, 163, 242, 71, 208, 3, 190, 44, 140, 222, 149, 159, 152, 193, 162, 44, 177, 93, 197, 119, 131, 88, 92, 53, 108, 167, 253, 64, 216, 200, 121, 212, 193, 153, 180, 39, 92, 35, 142, 6, 240, 115, 51, 211, 198, 63, 12, 126, 128, 206, 178, 114, 65, 37, 246, 197, 19, 79, 58, 96, 56, 86, 172, 162, 217, 70]));

      const decipher = await Decipher.fromStream(userCred, cipherStream);
      const cdInfo = await decipher.getCipherDataInfo();

      expect(cdInfo.alg).toEqual('X20-PLY');
      expect(cdInfo.ic).toEqual(1800000);
      expect(isEqualArray(cdInfo.iv, new Uint8Array([121, 78, 37, 8, 192, 196, 110, 22, 164, 106, 59, 161, 122, 165, 176, 147, 49, 43, 41, 250, 163, 111, 218, 4]))).toBeTrue();
      expect(isEqualArray(cdInfo.slt, new Uint8Array([174, 61, 6, 169, 145, 216, 66, 166, 139, 82, 19, 207, 29, 75, 105, 149]))).toBeTrue();
      expect(cdInfo.ver).toEqual(cc.VERSION5);
      expect(cdInfo.hint).toEqual(hint);

      await expectAsync(
         decipher.decryptBlock0(
            async (cdinfo) => {
               expect(cdinfo.hint).toEqual(hint);
               expect(cdinfo.lp).toEqual(1);
               expect(cdinfo.lpEnd).toEqual(1);
               expect(cdinfo.alg).toBe('X20-PLY');
               expect(cdinfo.ic).toBe(1800000);
               expect(cdinfo.hint).toEqual(hint);
               expect(cdinfo.ver).toEqual(cc.VERSION5);
               expect(isEqualArray(cdInfo.iv, new Uint8Array([121, 78, 37, 8, 192, 196, 110, 22, 164, 106, 59, 161, 122, 165, 176, 147, 49, 43, 41, 250, 163, 111, 218, 4]))).toBeTrue();
               expect(isEqualArray(cdInfo.slt, new Uint8Array([174, 61, 6, 169, 145, 216, 66, 166, 139, 82, 19, 207, 29, 75, 105, 149]))).toBeTrue();
               return [pwd, undefined];
            }
         )
      ).toBeResolvedTo(clearData);

      await expectAsync(
         decipher.decryptBlockN(
         )
      ).toBeResolvedTo(new Uint8Array(0));
   });

   it("missing terminal block indicator, v5", async function () {
      const [_, clearData] = streamFromStr('A nice 🦫 came to say hello');
      const pwd = 'a 🌲 of course';
      const hint = '🌧️';
      // base64url userCred for injection into browser for recreation:
      // Ohyqajb6nFOm2Y5lOTkIkhc3uAaF8sUrYrQ9pts2pDc=
      const userCred = new Uint8Array([58, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98, 180, 61, 166, 219, 54, 164, 55]);
      const [cipherStream] = streamFromBytes(new Uint8Array([225, 67, 20, 31, 134, 179, 27, 202, 138, 52, 68, 42, 197, 34, 48, 209, 76, 235, 39, 166, 101, 12, 253, 101, 237, 25, 234, 119, 91, 227, 169, 172, 5, 0, 116, 0, 0, 0, 2, 0, 53, 140, 213, 212, 134, 206, 178, 102, 222, 97, 207, 8, 252, 103, 8, 64, 25, 112, 206, 146, 159, 150, 220, 236, 162, 203, 172, 111, 119, 158, 192, 123, 81, 141, 89, 174, 126, 4, 65, 105, 64, 119, 27, 0, 0, 23, 138, 253, 130, 153, 78, 2, 31, 195, 254, 142, 102, 116, 200, 50, 125, 8, 178, 151, 113, 13, 205, 228, 10, 85, 83, 101, 57, 149, 191, 166, 4, 221, 153, 198, 0, 18, 185, 165, 203, 53, 211, 218, 24, 198, 162, 13, 99, 240, 249, 210, 255, 200, 217, 232, 10, 187, 212, 92, 204, 165, 217, 7, 202, 6, 114, 70, 200, 221]));

      const decipher = await Decipher.fromStream(userCred, cipherStream);
      const cdInfo = await decipher.getCipherDataInfo();

      expect(cdInfo.alg).toEqual('X20-PLY');
      expect(cdInfo.ic).toEqual(1800000);
      expect(isEqualArray(cdInfo.iv, new Uint8Array([53, 140, 213, 212, 134, 206, 178, 102, 222, 97, 207, 8, 252, 103, 8, 64, 25, 112, 206, 146, 159, 150, 220, 236]))).toBeTrue();
      expect(isEqualArray(cdInfo.slt, new Uint8Array([162, 203, 172, 111, 119, 158, 192, 123, 81, 141, 89, 174, 126, 4, 65, 105]))).toBeTrue();
      expect(cdInfo.ver).toEqual(cc.VERSION5);
      expect(cdInfo.hint).toEqual(hint);

      // Although the cipherData for block0 above is missing the "terminal block" indicator,
      // that isn't detected until we hit the end of the file (below in blockN)
      await expectAsync(
         decipher.decryptBlock0(
            async (cdinfo) => {
               expect(cdinfo.hint).toEqual(hint);
               expect(cdinfo.lp).toEqual(1);
               expect(cdinfo.lpEnd).toEqual(1);
               expect(cdinfo.alg).toBe('X20-PLY');
               expect(cdinfo.ic).toBe(1800000);
               expect(cdinfo.hint).toEqual(hint);
               expect(cdinfo.ver).toEqual(cc.VERSION5);
               expect(isEqualArray(cdInfo.iv, new Uint8Array([53, 140, 213, 212, 134, 206, 178, 102, 222, 97, 207, 8, 252, 103, 8, 64, 25, 112, 206, 146, 159, 150, 220, 236]))).toBeTrue();
               expect(isEqualArray(cdInfo.slt, new Uint8Array([162, 203, 172, 111, 119, 158, 192, 123, 81, 141, 89, 174, 126, 4, 65, 105]))).toBeTrue();
               return [pwd, undefined];
            }
         )
      ).toBeResolvedTo(clearData);

      await expectAsync(
         decipher.decryptBlockN(
         )
      ).toBeRejectedWithError(Error, new RegExp('Missing terminal.+'));
   });

   it("bad input to cipherdata info and decrypt, v4", async function () {
      const [_, clearData] = streamFromStr('A nice 🦫 came to say hello');
      const pwdGood = 'a 🌲 of course';
      const pwdBad = 'a 🌵 of course';
      const userCredBad = new Uint8Array([0, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98, 180, 61, 166, 219, 54, 164, 55]);

      // copied from "correct cipherdata info and decryption" spec above
      const userCredGood = new Uint8Array([58, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98, 180, 61, 166, 219, 54, 164, 55]);

      let [cipherStream, cipherData] = streamFromBytes(new Uint8Array([117, 163, 250, 117, 59, 97, 3, 10, 139, 12, 55, 161, 115, 52, 28, 105, 246, 126, 220, 0, 129, 151, 165, 136, 46, 97, 163, 160, 91, 9, 189, 218, 4, 0, 116, 0, 0, 0, 2, 0, 16, 242, 98, 46, 102, 223, 79, 227, 209, 73, 22, 207, 92, 80, 75, 125, 125, 234, 18, 21, 88, 64, 43, 68, 25, 193, 133, 31, 159, 156, 8, 184, 10, 164, 33, 46, 20, 159, 218, 222, 64, 119, 27, 0, 0, 23, 5, 135, 172, 203, 4, 101, 163, 155, 133, 221, 40, 227, 91, 222, 227, 213, 97, 77, 24, 117, 60, 188, 27, 153, 253, 134, 10, 112, 75, 76, 146, 132, 123, 217, 7, 171, 211, 24, 206, 186, 248, 244, 119, 18, 165, 195, 59, 160, 76, 31, 90, 80, 53, 19, 39, 143, 99, 141, 109, 68, 72, 63, 121, 199, 96, 95, 157, 81]));
      let decipher = await Decipher.fromStream(userCredGood, cipherStream);

      // First make sure the good values are actually good
      await expectAsync(
         decipher.decryptBlock0(
            async (cdinfo) => {
               expect(cdinfo.alg).toBe('X20-PLY');
               expect(cdinfo.ic).toBe(1800000);
               expect(cdinfo.hint).toBeTruthy();
               expect(cdinfo.ver).toEqual(cc.VERSION4);
               return [pwdGood, undefined];
            }
         )
      ).toBeResolvedTo(clearData);

      // Ensure bad password fails
      [cipherStream] = streamFromBytes(cipherData);
      decipher = await Decipher.fromStream(userCredGood, cipherStream);

      await expectAsync(
         decipher.decryptBlock0(
            async (cdinfo) => {
               return [pwdBad, undefined];
            }
         )
      ).toBeRejectedWithError(DOMException);

      // Test wrong userCred
      [cipherStream] = streamFromBytes(cipherData);
      decipher = await Decipher.fromStream(userCredBad, cipherStream);

      await expectAsync(
         decipher.getCipherDataInfo()
      ).toBeRejectedWithError(Error, new RegExp('Invalid MAC.+'));

      // decipher now in invalid state from prevous getCipherDataInfo call
      await expectAsync(
         decipher.decryptBlock0(
            async (cdinfo) => {
               return [pwdGood, undefined];
            }
         )
      ).toBeRejectedWithError(Error, new RegExp('Decipher invalid.+'));

      // Test wrong userCred with block decrypt first (error msg is diffeernt)
      [cipherStream] = streamFromBytes(cipherData);
      decipher = await Decipher.fromStream(userCredBad, cipherStream);

      await expectAsync(
         decipher.decryptBlock0(
            async (cdinfo) => {
               return [pwdGood, undefined];
            }
         )
      ).toBeRejectedWithError(Error, new RegExp('Invalid MAC.+'));
   });

   it("bad input to cipherdata info and decrypt, v5", async function () {
      const [_, clearData] = streamFromStr('A nice 🦫 came to say hello');
      const pwdGood = 'a 🌲 of course';
      const pwdBad = 'a 🌵 of course';
      const userCredBad = new Uint8Array([0, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98, 180, 61, 166, 219, 54, 164, 55]);

      // copied from "correct cipherdata info and decryption" spec above
      const userCredGood = new Uint8Array([58, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98, 180, 61, 166, 219, 54, 164, 55]);

      let [cipherStream, cipherData] = streamFromBytes(new Uint8Array([166, 123, 188, 183, 212, 97, 47, 147, 59, 39, 78, 222, 101, 74, 221, 53, 27, 11, 194, 67, 156, 235, 116, 104, 65, 64, 76, 166, 29, 220, 71, 179, 5, 0, 116, 0, 0, 1, 2, 0, 121, 78, 37, 8, 192, 196, 110, 22, 164, 106, 59, 161, 122, 165, 176, 147, 49, 43, 41, 250, 163, 111, 218, 4, 174, 61, 6, 169, 145, 216, 66, 166, 139, 82, 19, 207, 29, 75, 105, 149, 64, 119, 27, 0, 0, 23, 93, 92, 56, 163, 242, 71, 208, 3, 190, 44, 140, 222, 149, 159, 152, 193, 162, 44, 177, 93, 197, 119, 131, 88, 92, 53, 108, 167, 253, 64, 216, 200, 121, 212, 193, 153, 180, 39, 92, 35, 142, 6, 240, 115, 51, 211, 198, 63, 12, 126, 128, 206, 178, 114, 65, 37, 246, 197, 19, 79, 58, 96, 56, 86, 172, 162, 217, 70]));
      let decipher = await Decipher.fromStream(userCredGood, cipherStream);

      // First make sure the good values are actually good
      await expectAsync(
         decipher.decryptBlock0(
            async (cdinfo) => {
               expect(cdinfo.alg).toBe('X20-PLY');
               expect(cdinfo.ic).toBe(1800000);
               expect(cdinfo.hint).toBeTruthy();
               expect(cdinfo.ver).toEqual(cc.VERSION5);
               return [pwdGood, undefined];
            }
         )
      ).toBeResolvedTo(clearData);

      // Ensure bad password fails
      [cipherStream] = streamFromBytes(cipherData);
      decipher = await Decipher.fromStream(userCredGood, cipherStream);

      await expectAsync(
         decipher.decryptBlock0(
            async (cdinfo) => {
               return [pwdBad, undefined];
            }
         )
      ).toBeRejectedWithError(DOMException);

      // Test wrong userCred
      [cipherStream] = streamFromBytes(cipherData);
      decipher = await Decipher.fromStream(userCredBad, cipherStream);

      await expectAsync(
         decipher.getCipherDataInfo()
      ).toBeRejectedWithError(Error, new RegExp('.+MAC.+'));

      // Does not get MAC error because the decipher instance is now if a
      // bad state and will remain so... forever...
      await expectAsync(
         decipher.decryptBlock0(
            async (cdinfo) => {
               return [pwdGood, undefined];
            }
         )
      ).toBeRejectedWithError(Error, new RegExp('Decipher invalid state.+'));
   });
});


describe("Detect changed cipher data", function () {
   beforeEach(() => {
      TestBed.configureTestingModule({});
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

         const latest = Encipher.latest(userCred, clearStream);
         const block0 = await latest.encryptBlock0(
            eparams,
            async (cdinfo) => {
               expect(cdinfo.lp).toEqual(1);
               expect(cdinfo.lpEnd).toEqual(1);
               expect(cdinfo.alg).toBe(alg);
               expect(cdinfo.ic).toBe(cc.ICOUNT_MIN);
               return [pwd, hint];
            }
         );

         const savedHeader = new Uint8Array(block0.parts[0]);

         // set byte in MAC
         block0.parts[0][12] = block0.parts[0][12] == 123 ? 124 : 123;
         let [cipherStream] = streamFromCipherBlock([block0]);
         let decipher = await Decipher.fromStream(userCred, cipherStream);

         await expectAsync(
            decipher.decryptBlock0(
               async (cdinfo) => {
                  return [pwd, undefined];
               }
            )
         ).toBeRejectedWithError(Error, /Invalid MAC.+/);

         block0.parts[0] = new Uint8Array(savedHeader);
         [cipherStream] = streamFromCipherBlock([block0]);
         decipher = await Decipher.fromStream(userCred, cipherStream);

         await expectAsync(
            decipher.decryptBlock0(
               async (cdinfo) => {
                  return [pwd, undefined];
               }
            )
         ).toBeResolvedTo(clearData);

         // set version
         block0.parts[0][33] = block0.parts[0][33] == 43 ? 45 : 43;
         [cipherStream] = streamFromCipherBlock([block0]);

         await expectAsync(
            Decipher.fromStream(userCred, cipherStream)
         ).toBeRejectedWithError(Error, /Invalid version+/);

         // set length
         block0.parts[0] = new Uint8Array(savedHeader);
         block0.parts[0][36] = block0.parts[0][36] == 43 ? 45 : 43;
         [cipherStream] = streamFromCipherBlock([block0]);
         decipher = await Decipher.fromStream(userCred, cipherStream);

         await expectAsync(
            decipher.decryptBlock0(
               async (cdinfo) => {
                  return [pwd, undefined];
               }
            )
         ).toBeRejectedWithError(Error, /Cipher data length mismatch+/);
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

         const latest = Encipher.latest(userCred, clearStream);
         const block0 = await latest.encryptBlock0(
            eparams,
            async (cdinfo) => {
               expect(cdinfo.alg).toBe(alg);
               expect(cdinfo.ic).toBe(cc.ICOUNT_MIN);
               return [pwd, hint];
            }
         );

         const savedAD = new Uint8Array(block0.parts[1]);

         block0.parts[1][12] = block0.parts[1][12] == 123 ? 124 : 123;
         let [cipherStream] = streamFromCipherBlock([block0]);
         let decipher = await Decipher.fromStream(userCred, cipherStream);

         await expectAsync(
            decipher.decryptBlock0(
               async (cdinfo) => {
                  expect(cdinfo.lp).toEqual(1);
                  expect(cdinfo.lpEnd).toEqual(1);
                  return [pwd, undefined];
               }
            )
         ).toBeRejectedWithError(Error, new RegExp('.+MAC.+'));

         // Confirm we're back to good state
         block0.parts[1] = new Uint8Array(savedAD);
         [cipherStream] = streamFromCipherBlock([block0]);
         decipher = await Decipher.fromStream(userCred, cipherStream);

         await expectAsync(
            decipher.decryptBlock0(
               async (cdinfo) => {
                  expect(cdinfo.lp).toEqual(1);
                  expect(cdinfo.lpEnd).toEqual(1);
                  return [pwd, undefined];
               }
            )
         ).toBeResolvedTo(clearData);

         // set byte near end
         const back = block0.parts[1].byteLength - 4;
         block0.parts[1][back] = block0.parts[1][back] == 43 ? 45 : 43;
         [cipherStream] = streamFromCipherBlock([block0]);
         decipher = await Decipher.fromStream(userCred, cipherStream);

         await expectAsync(
            decipher.decryptBlock0(
               async (cdinfo) => {
                  expect(cdinfo.lp).toEqual(1);
                  expect(cdinfo.lpEnd).toEqual(1);
                  return [pwd, undefined];
               }
            )
         ).toBeRejectedWithError(Error, new RegExp('.+MAC.+'));
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

         const latest = Encipher.latest(userCred, clearStream);
         const block0 = await latest.encryptBlock0(
            eparams,
            async (cdinfo) => {
               expect(cdinfo.alg).toBe(alg);
               expect(cdinfo.ic).toBe(cc.ICOUNT_MIN);
               return [pwd, hint];
            }
         );

         block0.parts[2][12] = block0.parts[2][12] == 123 ? 124 : 123;
         let [cipherStream] = streamFromCipherBlock([block0]);
         let decipher = await Decipher.fromStream(userCred, cipherStream);

         await expectAsync(
            decipher.decryptBlock0(
               async (cdinfo) => {
                  expect(cdinfo.lp).toEqual(1);
                  expect(cdinfo.lpEnd).toEqual(1);
                  return [pwd, undefined];
               }
            )
         ).toBeRejectedWithError(Error, new RegExp('.+MAC.+'));
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

         const latest = Encipher.latest(userCred, clearStream);
         const block0 = await latest.encryptBlock0(
            eparams,
            async (cdinfo) => {
               expect(cdinfo.lp).toEqual(1);
               expect(cdinfo.lpEnd).toEqual(1);
               expect(cdinfo.alg).toBe(alg);
               expect(cdinfo.ic).toBe(cc.ICOUNT_MIN);
               return [pwd, hint];
            }
         );

         // set byte in MAC
         block0.parts[0][12] = block0.parts[0][12] == 123 ? 124 : 123;
         let [cipherStream] = streamFromCipherBlock([block0]);
         let decipher = await Decipher.fromStream(userCred, cipherStream);

         // Monkey patch to skip MAC validation
         //@ts-ignore
         decipher['_verifyMAC'] = (): Promise<boolean> => {
            return Promise.resolve(true);
         }

         // This should succeed even though the MAC has been changed (because
         // MAC was not tested due to monkey patch)
         await expectAsync(
            decipher.decryptBlock0(
               async (cdinfo) => {
                  expect(cdinfo.lp).toEqual(1);
                  expect(cdinfo.lpEnd).toEqual(1);
                  return [pwd, undefined];
               }
            )
         ).toBeResolvedTo(clearData);
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

         const latest = Encipher.latest(userCred, clearStream);
         const block0 = await latest.encryptBlock0(
            eparams,
            async (cdinfo) => {
               expect(cdinfo.alg).toBe(alg);
               expect(cdinfo.ic).toBe(cc.ICOUNT_MIN);
               return [pwd, hint];
            }
         );

         // set byte in additional data
         block0.parts[1][12] = block0.parts[1][12] == 123 ? 124 : 123;
         let [cipherStream] = streamFromCipherBlock([block0]);
         let decipher = await Decipher.fromStream(userCred, cipherStream);

         // Monkey patch to skip MAC validation
         //@ts-ignore
         decipher['_verifyMAC'] = (): Promise<boolean> => {
            return Promise.resolve(true);
         }

         // This should fail (even though MAC check wass skipped) because
         // AD check is part of all encryption algorithms. Note that this
         // should fail with DOMException rather than Error with MAC in message
         await expectAsync(
            decipher.decryptBlock0(
               async (cdinfo) => {
                  expect(cdinfo.lp).toEqual(1);
                  expect(cdinfo.lpEnd).toEqual(1);
                  return [pwd, undefined];
               }
            )
         ).toBeRejectedWithError(DOMException);
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

         const latest = Encipher.latest(userCred, clearStream);
         const block0 = await latest.encryptBlock0(
            eparams,
            async (cdinfo) => {
               expect(cdinfo.alg).toBe(alg);
               expect(cdinfo.ic).toBe(cc.ICOUNT_MIN);
               return [pwd, hint];
            }
         );

         // set byte in encrypted data
         block0.parts[2][12] = block0.parts[2][12] == 123 ? 124 : 123;
         let [cipherStream] = streamFromCipherBlock([block0]);
         let decipher = await Decipher.fromStream(userCred, cipherStream);

         // Monkey patch to skip MAC validation
         //@ts-ignore
         decipher['_verifyMAC'] = (): Promise<boolean> => {
            return Promise.resolve(true);
         }

         // This should fail (even though MAC check is skipped) because
         // encrypted data was modified. Note that this should
         // fail with DOMException rather than Error with MAC in message
         await expectAsync(
            decipher.decryptBlock0(
               async (cdinfo) => {
                  expect(cdinfo.lp).toEqual(1);
                  expect(cdinfo.lpEnd).toEqual(1);
                  return [pwd, undefined];
               }
            )
         ).toBeRejectedWithError(DOMException);
      }
   });
});

describe("Detect block order changes", function () {
   beforeEach(() => {
      TestBed.configureTestingModule({});
   });

   const pwd = 'a not good pwd';
   const hint = 'sorta';
   const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));
   const clearStr ='This is a secret 🦀 with extra wording for more blocks';

   async function get_blocks(
      alg: string
   ): Promise<[CipherDataBlock, CipherDataBlock, CipherDataBlock]>  {
         const eparams: EParams = {
            alg: alg,
            ic: cc.ICOUNT_MIN,
            lp: 1,
            lpEnd: 1
         };

         const [clearStream] = streamFromStr(clearStr);

         const latest = Encipher.latest(userCred, clearStream);
         const readStart = 11
         //@ts-ignore force multiple blocks
         latest['_readTarget'] = readStart;

         const block0 = await latest.encryptBlock0(
            eparams,
            async (cdinfo) => {
               expect(cdinfo.lp).toEqual(1);
               expect(cdinfo.lpEnd).toEqual(1);
               return [pwd, hint];
            }
         );
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
         let decipher = await Decipher.fromStream(userCred, cipherStream);

         const decb0 = await decipher.decryptBlock0(
            async (cdinfo) => {
               expect(cdinfo.lp).toEqual(1);
               expect(cdinfo.lpEnd).toEqual(1);
               return [pwd, undefined];
            }
         );
         const decb1 = await decipher.decryptBlockN();
         const decb2 = await decipher.decryptBlockN();

         let [decrypted] = streamFromBytes([decb0, decb1, decb2]);

         await expectAsync(
            areEqual(decrypted, clearData)
         ).toBeResolvedTo(true);
      }
   });

   it("blockN bad order detected, all algorithms", async function () {

      const clearData = new TextEncoder().encode(clearStr);

      for (let alg in cc.AlgInfo) {

         const [block0, block1, block2] = await get_blocks(alg);

         // Order of block N+ changed
         let [cipherStream] = streamFromCipherBlock([block0, block2, block1]);
         let decipher = await Decipher.fromStream(userCred, cipherStream);

         const decb0 = await decipher.decryptBlock0(
            async (cdinfo) => {
               expect(cdinfo.lp).toEqual(1);
               expect(cdinfo.lpEnd).toEqual(1);
               return [pwd, undefined];
            }
         );

         const partial = new TextDecoder().decode(decb0);
         expect(clearStr.startsWith(partial)).toBeTrue();

         // In V4 this worked, but should fail in V5
         await expectAsync(
            decipher.decryptBlockN()
         ).toBeRejectedWithError(Error, /Invalid MAC+/);
      }
   });

   it("block0 bad order detected, all algorithms", async function () {

      const clearData = new TextEncoder().encode(clearStr);

      for (let alg in cc.AlgInfo) {

         const [block0, block1, block2] = await get_blocks(alg);

         let [cipherStream] = streamFromCipherBlock([block1, block0, block2]);
         let decipher = await Decipher.fromStream(userCred, cipherStream);

         // Will fail in V4 and later because block0 format or MAC is invalid.
         // Failure detection can happen at different spots while data is unpacked
         // since random values may look valid. MAC will alsways be
         // invalid if we get that far.
         await expectAsync(
            decipher.decryptBlock0(
               async (cdinfo) => {
                  expect(cdinfo.lp).toEqual(1);
                  expect(cdinfo.lpEnd).toEqual(1);
                  return [pwd, undefined];
            })
         ).toBeRejectedWithError(Error, new RegExp('Invalid.+'));

      }
   });
});