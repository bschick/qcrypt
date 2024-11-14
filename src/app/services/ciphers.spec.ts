/* MIT License

Copyright (c) 2024 Brad Schick

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
import { Random48, BYOBStreamReader, readStreamAll } from './utils';
import { Ciphers, Encipher, Decipher, EncipherV4, EParams, CipherDataBlock } from './ciphers';

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

function streamFromBytes(data: Uint8Array): [ReadableStream<Uint8Array>, Uint8Array] {
   const blob = new Blob([data], { type: 'application/octet-stream' });
   return [blob.stream(), data];
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
      Encipher.testingFlag = true;
   });

   it("successful and not equivalent key generation", async function () {

      for (let alg in cc.AlgInfo) {
         const pwd = 'not a good pwd';
         const ic = cc.ICOUNT_MIN;
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

         const random48 = new Random48(true);
         const randomArray = await random48.getRandomArray(false, true);
         const slt = randomArray.slice(0, cc.SLT_BYTES);

         const ek = await Ciphers._genCipherKey(alg, ic, pwd, userCred, slt);
         const sk = await Ciphers._genSigningKey(userCred, slt);
         const hk = await Ciphers._genHintCipherKey(alg, userCred, slt);

         let exported = await window.crypto.subtle.exportKey("raw", ek);
         const ekBytes = new Uint8Array(exported);
         expect(ekBytes.byteLength).toBe(32);

         exported = await window.crypto.subtle.exportKey("raw", sk);
         const skBytes = new Uint8Array(exported);
         expect(skBytes.byteLength).toBe(32);

         exported = await window.crypto.subtle.exportKey("raw", hk);
         const hkBytes = new Uint8Array(exported);
         expect(hkBytes.byteLength).toBe(32);

         expect(isEqualArray(ekBytes, skBytes)).toBeFalse();
         expect(isEqualArray(ekBytes, hkBytes)).toBeFalse();
         expect(isEqualArray(skBytes, hkBytes)).toBeFalse();
      }
   });

   it("keys should match expected values", async function () {

      const expected: { [k1: string]: { [k2: string]: Uint8Array } } = {
         'AES-GCM': {
            ek: new Uint8Array([50, 99, 104, 47, 247, 255, 94, 71, 52, 222, 53, 60, 161, 13, 61, 74, 164, 221, 87, 193, 104, 161, 236, 71, 170, 158, 28, 202, 176, 233, 209, 124]),
            sk: new Uint8Array([238, 127, 13, 239, 238, 127, 177, 22, 231, 87, 89, 23, 88, 52, 42, 22, 6, 170, 172, 112, 111, 101, 147, 204, 238, 28, 203, 159, 118, 54, 139, 151]),
            hk: new Uint8Array([253, 30, 237, 129, 147, 186, 235, 65, 217, 78, 219, 38, 163, 12, 23, 248, 3, 118, 123, 120, 237, 0, 56, 103, 67, 76, 88, 126, 153, 83, 238, 85]),
         },
         'X20-PLY': {
            ek: new Uint8Array([50, 99, 104, 47, 247, 255, 94, 71, 52, 222, 53, 60, 161, 13, 61, 74, 164, 221, 87, 193, 104, 161, 236, 71, 170, 158, 28, 202, 176, 233, 209, 124]),
            sk: new Uint8Array([238, 127, 13, 239, 238, 127, 177, 22, 231, 87, 89, 23, 88, 52, 42, 22, 6, 170, 172, 112, 111, 101, 147, 204, 238, 28, 203, 159, 118, 54, 139, 151]),
            hk: new Uint8Array([253, 30, 237, 129, 147, 186, 235, 65, 217, 78, 219, 38, 163, 12, 23, 248, 3, 118, 123, 120, 237, 0, 56, 103, 67, 76, 88, 126, 153, 83, 238, 85]),
         },
         'AEGIS-256': {
            ek: new Uint8Array([50, 99, 104, 47, 247, 255, 94, 71, 52, 222, 53, 60, 161, 13, 61, 74, 164, 221, 87, 193, 104, 161, 236, 71, 170, 158, 28, 202, 176, 233, 209, 124]),
            sk: new Uint8Array([238, 127, 13, 239, 238, 127, 177, 22, 231, 87, 89, 23, 88, 52, 42, 22, 6, 170, 172, 112, 111, 101, 147, 204, 238, 28, 203, 159, 118, 54, 139, 151]),
            hk: new Uint8Array([253, 30, 237, 129, 147, 186, 235, 65, 217, 78, 219, 38, 163, 12, 23, 248, 3, 118, 123, 120, 237, 0, 56, 103, 67, 76, 88, 126, 153, 83, 238, 85]),
         }
      };

      for (let alg in cc.AlgInfo) {
         const pwd = 'a good pwd';
         const ic = cc.ICOUNT_MIN;
         const userCred = new Uint8Array([214, 245, 252, 122, 133, 39, 76, 162, 64, 201, 143, 217, 237, 57, 18, 207, 199, 153, 20, 28, 162, 9, 236, 66, 100, 103, 152, 159, 226, 50, 225, 129]);
         const baseArray = new Uint8Array([160, 202, 135, 230, 125, 174, 49, 189, 171, 56, 203, 1, 237, 233, 27, 76, 46, 22, 226, 86, 89, 132, 143, 185, 198, 129, 242, 241, 183, 195, 191, 229, 162, 127, 162, 148, 75, 16, 28, 140]);
         const slt = baseArray.slice(0, cc.SLT_BYTES);

         const ek = await Ciphers._genCipherKey(alg, ic, pwd, userCred, slt);
         const sk = await Ciphers._genSigningKey(userCred, slt);
         const hk = await Ciphers._genHintCipherKey(alg, userCred, slt);

         let exported = await window.crypto.subtle.exportKey("raw", ek);
         const ekBytes = new Uint8Array(exported);
         expect(isEqualArray(ekBytes, expected[alg]['ek'])).toBeTrue();

         exported = await window.crypto.subtle.exportKey("raw", sk);
         const skBytes = new Uint8Array(exported);
         expect(isEqualArray(skBytes, expected[alg]['sk'])).toBeTrue();

         exported = await window.crypto.subtle.exportKey("raw", hk);
         const hkBytes = new Uint8Array(exported);
         expect(isEqualArray(hkBytes, expected[alg]['hk'])).toBeTrue();
      }
   });
});

describe("Encryption and decryption", function () {
   beforeEach(() => {
      TestBed.configureTestingModule({});
      Encipher.testingFlag = true;
   });

   async function signAndRepack(
      encipher: Encipher,
      userCred: Uint8Array,
      block: CipherDataBlock
   ): Promise<Uint8Array> {

      // cheating... parts[1] is _additionalData, parts[2] is encryptedData
      const sk = await EncipherV4._genSigningKey(userCred, encipher['_slt']!);
      const headerData = await EncipherV4._createHeader(sk, block.parts[2], block.parts[1]);

      const output = new Uint8Array(headerData.byteLength +
         block.parts[1].byteLength +
         block.parts[2].byteLength
      );

      output.set(headerData);
      output.set(block.parts[1], headerData.byteLength);
      output.set(
         block.parts[2],
         headerData.byteLength + block.parts[1].byteLength
      );

      return output;
   }

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
   it("decryption should fail with replaced valid signature", async function () {

      for (let alg in cc.AlgInfo) {

         const [clearStream, clearData] = streamFromStr('This is a secret 🐓');
         const pwd = 'a good pwd';
         const userCredA = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));
         const userCredB = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

         const eparams: EParams = {
            alg: alg,
            ic: cc.ICOUNT_MIN,
            trueRand: false,
            fallbackRand: true,
            lp: 1,
            lpEnd: 1
         };

         const reader = new BYOBStreamReader(clearStream);
         const encipher = new EncipherV4(userCredA, reader);
         const cipherBlock = await encipher.encryptBlock0(
            eparams,
            async (cdinfo) => {
               expect(cdinfo.lp).toEqual(1);
               expect(cdinfo.lpEnd).toEqual(1);
               return [pwd, undefined];
            }
         );

         // First sign and repack with the original (correct) values to help ensure the
         // code for repacking is valid and that the 2nd attempt with a new signature
         // detects the userCred change rather than bug in signAndRepack. Then resign
         // and pack with Bob's userCred
         let [cipherstreamA, cipherDataA] = streamFromBytes(
            await signAndRepack(encipher, userCredA, cipherBlock)
         );
         let [cipherstreamB, cipherDataB] = streamFromBytes(
            await signAndRepack(encipher, userCredB, cipherBlock)
         );

         // These should fail  because using the wrong userCred on each
         let decipherA = await Decipher.fromStream(userCredB, cipherstreamA)
         let decipherB = await Decipher.fromStream(userCredA, cipherstreamB)

         await expectAsync(
            decipherA._decodePayload0()
         ).toBeRejectedWithError(Error, new RegExp('.+MAC.+'));
         await expectAsync(
            decipherB._decodePayload0()
         ).toBeRejectedWithError(Error, new RegExp('.+MAC.+'));

         // Reload with matching userCreds
         [cipherstreamA] = streamFromBytes(cipherDataA);
         [cipherstreamB] = streamFromBytes(cipherDataB);
         decipherA = await Decipher.fromStream(userCredA, cipherstreamA)
         decipherB = await Decipher.fromStream(userCredB, cipherstreamB)

         // Both should succeed since the singatures are valid with the userCreds
         // passed below. Decryptiong, cipherText would fail on B (checked below).
         // Also, these would fail if there was an encrypted hint
         await expectAsync(
            decipherA._decodePayload0()
         ).toBeResolved();
         await expectAsync(
            decipherB._decodePayload0()
         ).toBeResolved();

         // should succeed since we repacked with correct userCred
         await expectAsync(
            decipherA.decryptBlock0(
               async (cdinfo) => {
                  return [pwd, undefined];
               }
            )
         ).toBeResolvedTo(clearData);

         // The big moment... perhaps should have better validation that the decryption
         // failed, but not much else returns DOMException from cipher.service. Note that
         // this is using the correct PWD because we assume the evil site has tricked
         // Alice into provider it (just not her userCred since site cannot retrieve)
         await expectAsync(
            decipherB.decryptBlock0(
               async (cdinfo) => {
                  return [pwd, undefined];
               }
            )
         ).toBeRejectedWithError(DOMException);
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
            trueRand: false,
            fallbackRand: true,
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

         const [clearStream, clearData] = streamFromStr('This is a secret 🦀');
         const pwd = 'a not good pwd';
         const hint = 'sorta';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

         const eparams: EParams = {
            alg: alg,
            ic: cc.ICOUNT_MIN,
            trueRand: false,
            fallbackRand: true,
            lp: 1,
            lpEnd: 1
         };

         const latest = Encipher.latest(userCred, clearStream);
         const readStart = 12
         //@ts-ignore force multiple blocks
         latest['_readTarget'] = readStart;

         await expectAsync(
            latest.encryptBlockN(eparams)
         ).toBeRejectedWithError(Error, new RegExp('Data not initialized.+'));

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

         await expectAsync(
            decipher.decryptBlockN()
         ).toBeRejectedWithError(Error, new RegExp('Data not initialized.*'));

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

   it("correct cipherdata info and decryption", async function () {
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

   it("bad input to cipherdata info and decrypt", async function () {
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
      ).toBeRejectedWithError(Error, new RegExp('.+MAC.+'));

      // Does not get MAC error because MAC check only happens on the first call
      // to getCipherDataInfo or decryptBlock0
      await expectAsync(
         decipher.decryptBlock0(
            async (cdinfo) => {
               return [pwdGood, undefined];
            }
         )
      ).toBeRejectedWithError(DOMException);
   });
});

describe("Detect changed cipher data", function () {
   beforeEach(() => {
      TestBed.configureTestingModule({});
      Encipher.testingFlag = true;
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
            trueRand: false,
            fallbackRand: true,
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
         ).toBeRejectedWithError(Error, new RegExp('.+MAC.+'));

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

         // set byte past MAC
         const back = block0.parts[0].byteLength - 4;
         block0.parts[0][back] = block0.parts[0][back] == 43 ? 45 : 43;
         [cipherStream] = streamFromCipherBlock([block0]);
         decipher = await Decipher.fromStream(userCred, cipherStream);

         await expectAsync(
            decipher.decryptBlock0(
               async (cdinfo) => {
                  return [pwd, undefined];
               }
            )
         ).toBeRejectedWithError(Error);
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
            trueRand: false,
            fallbackRand: true,
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
            trueRand: false,
            fallbackRand: true,
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
            trueRand: false,
            fallbackRand: true,
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
            trueRand: false,
            fallbackRand: true,
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
            trueRand: false,
            fallbackRand: true,
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
