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
import { Random48, bytesToBase64 } from './utils';
import { Ciphers, EParams, CipherDataBlock } from './ciphers';


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

// sometime is seems like javascript tried to make things hard
function setCharAt(str: string, index: number, chr: string) {
   if (index > str.length - 1) {
      return str;
   }
   return str.substring(0, index) + chr + str.substring(index + 1);
}


describe("Key generation", function () {
   beforeEach(() => {
      TestBed.configureTestingModule({});
      Ciphers.testingFlag = true;
   });

   it("successful and not equivalent key generation", async function () {

      for (let alg in cc.AlgInfo) {
         const pwd = 'a good pwd';
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
         //         console.log(alg, 'ek: ', ekBytes);
         expect(isEqualArray(ekBytes, expected[alg]['ek'])).toBeTrue();

         exported = await window.crypto.subtle.exportKey("raw", sk);
         const skBytes = new Uint8Array(exported);
         //         console.log(alg, 'sk: ', skBytes);
         expect(isEqualArray(skBytes, expected[alg]['sk'])).toBeTrue();

         exported = await window.crypto.subtle.exportKey("raw", hk);
         const hkBytes = new Uint8Array(exported);
         //         console.log(alg, 'hk: ', hkBytes);
         expect(isEqualArray(hkBytes, expected[alg]['hk'])).toBeTrue();
      }
   });
});

describe("Encryption and decryption", function () {
   beforeEach(() => {
      TestBed.configureTestingModule({});
      Ciphers.testingFlag = true;
   });

   async function signAndRepack(
      ciphers: Ciphers,
      userCred: Uint8Array,
      block: CipherDataBlock
   ): Promise<Uint8Array> {

      const sk = await Ciphers._genSigningKey(userCred, ciphers['_slt']!);
      const headerData = await Ciphers._createHeader(sk, block.encryptedData, block.additionalData);

      const output = new Uint8Array(headerData.byteLength +
         block.additionalData.byteLength +
         block.encryptedData.byteLength
      );

      output.set(headerData);
      output.set(block.additionalData, headerData.byteLength);
      output.set(block.encryptedData,
         headerData.byteLength + block.additionalData.byteLength);

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

         const clearText = 'This is a secret 🐓';
         const clearData = new TextEncoder().encode(clearText);
         const pwd = 'a good pwd';
         const hint = 'not really';
         const userCredA = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));
         const userCredB = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

         const eparamsA: EParams = {
            alg: alg,
            ic: cc.ICOUNT_MIN,
            trueRand: false,
            fallbackRand: true,
            pwd: pwd,
            hint: hint,
            userCred: userCredA,
         };

         const ciphers = Ciphers.latest();
         const cipherDataA = await ciphers.encryptBlock0(eparamsA, clearData);

         ciphers.decodeHeader(cipherDataA.headerData);

         // First sign and repack with the original (correct) values to help ensure the
         // code for repacking is valid and that the 2nd attempt with a new signature
         // detects the userCred change rather than bug in signAndRepack. Then resign
         // and pack with Bob's userCred
         const blockA = await signAndRepack(ciphers, userCredA, cipherDataA);
         const blockB = await signAndRepack(ciphers, userCredB, cipherDataA);

         const ciphersA = Ciphers.fromHeader(blockA);
         let consumedBytes = ciphersA.decodeHeader(blockA);
         const payloadA = new Uint8Array(blockA.buffer, consumedBytes);

         const ciphersB = Ciphers.fromHeader(blockB);
         consumedBytes = ciphersB.decodeHeader(blockB);
         const payloadB = new Uint8Array(blockB.buffer, consumedBytes);

         expect(isEqualArray(payloadA, payloadB)).toBeTrue();

         // both should succeed since the singatures are valid with the userCreds
         // passed below (just cannot decrypt cipherText)
         await expectAsync(
            ciphersA._decodePayload0(userCredA, payloadA)
         ).toBeResolved();
         await expectAsync(
            ciphersB._decodePayload0(userCredB, payloadB)
         ).toBeResolved();

         // The original should succeed since we repacked with correct userCred
         await expectAsync(
            ciphersA.decryptPayload0(
               async (decHint) => {
                  return pwd;
               },
               userCredA,
               payloadA
            )
         ).toBeResolvedTo(clearData);

         // The big moment... perhaps should have better validation that the decryption
         // failed, but not much else returns DOMException from cipher.service. Note
         // this this is using the correct PWD because we assume the evil site has
         // tricked Alice into provider it (just not her userCred)
         await expectAsync(
            ciphersB.decryptPayload0(
               async (decHint) => {
                  return pwd;
               },
               userCredB,
               payloadB
            )
         ).toBeRejectedWithError(DOMException);
      }
   });

   it("round trip block0, all algorithms", async function () {

      for (let alg in cc.AlgInfo) {

         const clearText = 'This is a secret 🦆';
         const clearData = new TextEncoder().encode(clearText);
         const pwd = 'a good pwd';
         const hint = 'not really';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

         const eparams: EParams = {
            alg: alg,
            ic: cc.ICOUNT_MIN,
            trueRand: false,
            fallbackRand: true,
            pwd: pwd,
            hint: hint,
            userCred: userCred,
         };

         const latest = Ciphers.latest();
         const block0 = await latest.encryptBlock0(
            eparams,
            clearData,
            (params) => {
               expect(params.alg).toBe(alg);
               expect(params.ic).toBe(cc.ICOUNT_MIN);
            }
         );

         const payload0 = new Uint8Array(block0.additionalData.byteLength + block0.encryptedData.byteLength);
         payload0.set(block0.additionalData);
         payload0.set(block0.encryptedData, block0.additionalData.byteLength);

         const ciphers = Ciphers.fromHeader(block0.headerData);

         // header not loaded
         await expectAsync(
            ciphers.decryptPayload0(
               async (decHint) => {
                  return pwd;
               },
               userCred,
               payload0
            )
         ).toBeRejectedWithError(Error, new RegExp('Data not initialized.*'));

         const consumedBytes = ciphers.decodeHeader(block0.headerData);
         expect(consumedBytes).toEqual(block0.headerData.byteLength);

         const decrypted = await ciphers.decryptPayload0(
            async (decHint) => {
               return pwd;
            },
            userCred,
            payload0,
            (params) => {
               expect(params.alg).toBe(alg);
               expect(params.ic).toBe(cc.ICOUNT_MIN);
               expect(params.hint).toBeTrue();
            }
         );

         const clearTest = new TextDecoder().decode(decrypted);
         //      console.log(alg + ": '" + decrypted + "'");
         expect(clearTest).toBe(clearText);
      }
   });

   it("round trip blockN, all algorithms", async function () {

      for (let alg in cc.AlgInfo) {

         const clearText = 'This is a secret 🦀';
         const clearData = new TextEncoder().encode(clearText);
         const pwd = 'a not good pwd';
         const hint = 'sorta';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

         const eparams: EParams = {
            alg: alg,
            ic: cc.ICOUNT_MIN,
            trueRand: false,
            fallbackRand: true,
            pwd: pwd,
            hint: hint,
            userCred: userCred,
         };

         const latest = Ciphers.latest();
         await expectAsync(
            latest.encryptBlockN(eparams, clearData)
         ).toBeRejectedWithError(Error, new RegExp('Data not initialized.+'));

         const block0 = await latest.encryptBlock0(eparams, clearData)
         const blockN = await latest.encryptBlockN(eparams, clearData);

         const payload0 = new Uint8Array(block0.additionalData.byteLength + block0.encryptedData.byteLength);
         payload0.set(block0.additionalData);
         payload0.set(block0.encryptedData, block0.additionalData.byteLength);

         const payloadN = new Uint8Array(blockN.additionalData.byteLength + blockN.encryptedData.byteLength);
         payloadN.set(blockN.additionalData);
         payloadN.set(blockN.encryptedData, blockN.additionalData.byteLength);

         const ciphers = Ciphers.fromHeader(block0.headerData);

         await expectAsync(
            ciphers.decryptPayloadN(payloadN)
         ).toBeRejectedWithError(Error, new RegExp('Data not initialized.*'));

         // Mixing block N header with block0 payload
         ciphers.decodeHeader(blockN.headerData);
         await expectAsync(
            ciphers.decryptPayload0(
               async (decHint) => {
                  return pwd;
               },
               userCred,
               payload0
            )
         ).toBeRejectedWithError(Error, new RegExp('.+MAC.+'));

         let consumedBytes = ciphers.decodeHeader(block0.headerData);
         expect(consumedBytes).toEqual(block0.headerData.byteLength);

         await expectAsync(
            ciphers.decryptPayload0(
               async (decHint) => {
                  return pwd;
               },
               userCred,
               payload0
            )
         ).toBeResolved();

         // make failure because blockN head has not been loaded
         await expectAsync(
            ciphers.decryptPayloadN(payloadN)
         ).toBeRejectedWithError(Error, new RegExp('.+MAC.+'));

         // finally, do blockN correctly
         consumedBytes = ciphers.decodeHeader(blockN.headerData);
         expect(consumedBytes).toEqual(blockN.headerData.byteLength);
         const decrypted = await ciphers.decryptPayloadN(payloadN)
         const clearTest = new TextDecoder().decode(decrypted);
         expect(clearTest).toBe(clearText);
      }
   });

   it("correct cipherdata info and decryption", async function () {
      const clearText = 'A nice 🦫 came to say hello';
      const clearData = new TextEncoder().encode(clearText);
      const pwd = 'a 🌲 of course';
      const hint = '🌧️';
      // base64url or userCred for injection into browser for recreation:
      // Ohyqajb6nFOm2Y5lOTkIkhc3uAaF8sUrYrQ9pts2pDc=
      const userCred = new Uint8Array([58, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98, 180, 61, 166, 219, 54, 164, 55]);
      const cipherData = new Uint8Array([162, 122, 176, 92, 17, 118, 3, 21, 200, 50, 240, 31, 67, 146, 170, 244, 74, 73, 120, 177, 213, 15, 102, 200, 221, 19, 194, 255, 12, 129, 94, 33, 4, 0, 115, 0, 0, 0, 2, 0, 196, 214, 166, 50, 166, 132, 209, 32, 217, 123, 195, 177, 134, 142, 73, 117, 85, 242, 50, 93, 93, 143, 154, 136, 4, 69, 111, 200, 122, 230, 194, 138, 212, 62, 46, 76, 65, 170, 189, 196, 64, 119, 27, 0, 23, 143, 125, 198, 210, 206, 171, 238, 185, 78, 164, 19, 126, 92, 108, 0, 68, 100, 203, 121, 133, 125, 79, 40, 207, 93, 99, 46, 146, 185, 230, 118, 67, 182, 98, 116, 118, 191, 38, 83, 170, 147, 225, 62, 242, 47, 37, 132, 90, 30, 244, 230, 120, 88, 32, 79, 178, 33, 164, 140, 197, 21, 67, 38, 20, 212, 117, 244, 25]);

      const ciphers = Ciphers.fromHeader(cipherData);
      const consumedBytes = ciphers.decodeHeader(cipherData);
      const cdInfo = await ciphers.getCipherDataInfo(
         userCred,
         new Uint8Array(cipherData.buffer, consumedBytes),
      );

      expect(cdInfo.alg).toEqual('X20-PLY');
      expect(cdInfo.ic).toEqual(1800000);
      expect(cdInfo.iv).toEqual(new Uint8Array([196, 214, 166, 50, 166, 132, 209, 32, 217, 123, 195, 177, 134, 142, 73, 117, 85, 242, 50, 93, 93, 143, 154, 136]));
      expect(cdInfo.slt).toEqual(new Uint8Array([4, 69, 111, 200, 122, 230, 194, 138, 212, 62, 46, 76, 65, 170, 189, 196]));
      expect(cdInfo.ver).toEqual(cc.CURRENT_VERSION);
      expect(cdInfo.hint).toBeTrue();

      await expectAsync(
         ciphers.decryptPayload0(
            async (decHint) => {
               expect(decHint).toEqual(hint);
               return pwd;
            },
            userCred,
            new Uint8Array(cipherData.buffer, consumedBytes),
            (params) => {
               expect(params.alg).toBe('X20-PLY');
               expect(params.ic).toBe(1800000);
               expect(params.hint).toBeTrue();
            }
         )
      ).toBeResolvedTo(clearData);
   });

   it("bad input to cipherdata info and decrypt", async function () {
      const pwdGood = 'a 🌲 of course';
      const pwdBad = 'a 🌵 of course';
      const userCredBad = new Uint8Array([0, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98, 180, 61, 166, 219, 54, 164, 55]);
      const userCredGood = new Uint8Array([58, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98, 180, 61, 166, 219, 54, 164, 55]);
      const cipherData = new Uint8Array([162, 122, 176, 92, 17, 118, 3, 21, 200, 50, 240, 31, 67, 146, 170, 244, 74, 73, 120, 177, 213, 15, 102, 200, 221, 19, 194, 255, 12, 129, 94, 33, 4, 0, 115, 0, 0, 0, 2, 0, 196, 214, 166, 50, 166, 132, 209, 32, 217, 123, 195, 177, 134, 142, 73, 117, 85, 242, 50, 93, 93, 143, 154, 136, 4, 69, 111, 200, 122, 230, 194, 138, 212, 62, 46, 76, 65, 170, 189, 196, 64, 119, 27, 0, 23, 143, 125, 198, 210, 206, 171, 238, 185, 78, 164, 19, 126, 92, 108, 0, 68, 100, 203, 121, 133, 125, 79, 40, 207, 93, 99, 46, 146, 185, 230, 118, 67, 182, 98, 116, 118, 191, 38, 83, 170, 147, 225, 62, 242, 47, 37, 132, 90, 30, 244, 230, 120, 88, 32, 79, 178, 33, 164, 140, 197, 21, 67, 38, 20, 212, 117, 244, 25]);

      const ciphers = Ciphers.fromHeader(cipherData);
      const consumedBytes = ciphers.decodeHeader(cipherData);

      // First make sure the good values are actually good
      await expectAsync(
         ciphers.decryptPayload0(
            async (decHint) => {
               return pwdGood;
            },
            userCredGood,
            new Uint8Array(cipherData.buffer, consumedBytes),
            (params) => {
               expect(params.alg).toBe('X20-PLY');
               expect(params.ic).toBe(1800000);
               expect(params.hint).toBeTrue();
            }
         )
      ).toBeResolved();

      // Then test bad values
      await expectAsync(
         ciphers.getCipherDataInfo(
            userCredBad,
            new Uint8Array(cipherData.buffer, consumedBytes),
         )
      ).toBeRejectedWithError(Error, new RegExp('.+MAC.+'));

      await expectAsync(
         ciphers.decryptPayload0(
            async (decHint) => {
               return pwdBad;
            },
            userCredGood,
            new Uint8Array(cipherData.buffer, consumedBytes)
         )
      ).toBeRejectedWithError(DOMException);

      await expectAsync(
         ciphers.decryptPayload0(
            async (decHint) => {
               return pwdGood;
            },
            userCredBad,
            new Uint8Array(cipherData.buffer, consumedBytes)
         )
      ).toBeRejectedWithError(Error, new RegExp('.+MAC.+'));
   });
});

describe("Detect changed cipher data", function () {
   beforeEach(() => {
      TestBed.configureTestingModule({});
      Ciphers.testingFlag = true;
   });

   it("detect changed headerData", async function () {

      for (let alg in cc.AlgInfo) {
         const clearText = 'This is a secret 🦆';
         const clearData = new TextEncoder().encode(clearText);
         const pwd = 'a good pwd';
         const hint = 'not really';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

         const eparams: EParams = {
            alg: alg,
            ic: cc.ICOUNT_MIN,
            trueRand: false,
            fallbackRand: true,
            pwd: pwd,
            hint: hint,
            userCred: userCred,
         };

         const latest = Ciphers.latest();
         const block0 = await latest.encryptBlock0(
            eparams,
            clearData,
            (params) => {
               expect(params.alg).toBe(alg);
               expect(params.ic).toBe(cc.ICOUNT_MIN);
            }
         );

         const payload0 = new Uint8Array(block0.additionalData.byteLength + block0.encryptedData.byteLength);
         payload0.set(block0.additionalData);
         payload0.set(block0.encryptedData, block0.additionalData.byteLength);

         const savedHeader = new Uint8Array(block0.headerData);

         let bad = block0.headerData[12] == 123 ? 124 : 123;
         block0.headerData.set([bad], 12);

         let ciphers = Ciphers.fromHeader(block0.headerData);
         ciphers.decodeHeader(block0.headerData);

         await expectAsync(
            ciphers.decryptPayload0(
               async (decHint) => {
                  return pwd;
               },
               userCred,
               payload0
            )
         ).toBeRejectedWithError(Error, new RegExp('.+MAC.+'));

         // Confirm we're back to good state
         ciphers = Ciphers.fromHeader(savedHeader);
         ciphers.decodeHeader(savedHeader);

         await expectAsync(
            ciphers.decryptPayload0(
               async (decHint) => {
                  return pwd;
               },
               userCred,
               payload0
            )
         ).toBeResolved();

         // set byte past MAC
         const back = savedHeader.byteLength - 4;
         bad = savedHeader[back] == 43 ? 45 : 43;
         savedHeader.set([bad], back);
         ciphers = Ciphers.fromHeader(savedHeader);
         ciphers.decodeHeader(savedHeader);

         await expectAsync(
            ciphers.decryptPayload0(
               async (decHint) => {
                  return pwd;
               },
               userCred,
               payload0
            )
         ).toBeRejectedWithError(Error, new RegExp('.+MAC.+'));
      }

   });

   it("detect changed additionalData", async function () {

      for (let alg in cc.AlgInfo) {
         const clearText = 'This is a secret 🦆';
         const clearData = new TextEncoder().encode(clearText);
         const pwd = 'a good pwd';
         const hint = 'not really';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

         const eparams: EParams = {
            alg: alg,
            ic: cc.ICOUNT_MIN,
            trueRand: false,
            fallbackRand: true,
            pwd: pwd,
            hint: hint,
            userCred: userCred,
         };

         const latest = Ciphers.latest();
         const block0 = await latest.encryptBlock0(
            eparams,
            clearData,
            (params) => {
               expect(params.alg).toBe(alg);
               expect(params.ic).toBe(cc.ICOUNT_MIN);
            }
         );

         const savedAD = new Uint8Array(block0.additionalData);

         let bad = block0.additionalData[12] == 123 ? 124 : 123;
         block0.additionalData.set([bad], 12);

         let payload0 = new Uint8Array(block0.additionalData.byteLength + block0.encryptedData.byteLength);
         payload0.set(block0.additionalData);
         payload0.set(block0.encryptedData, block0.additionalData.byteLength);

         let ciphers = Ciphers.fromHeader(block0.headerData);
         ciphers.decodeHeader(block0.headerData);

         await expectAsync(
            ciphers.decryptPayload0(
               async (decHint) => {
                  return pwd;
               },
               userCred,
               payload0
            )
         ).toBeRejectedWithError(Error, new RegExp('.+MAC.+'));

         // Confirm we're back to good state
         payload0.set(savedAD);
         payload0.set(block0.encryptedData,savedAD.byteLength);

         await expectAsync(
            ciphers.decryptPayload0(
               async (decHint) => {
                  return pwd;
               },
               userCred,
               payload0
            )
         ).toBeResolved();

         // set byte near end
         const back = savedAD.byteLength - 4;
         bad = savedAD[back] == 43 ? 45 : 43;
         savedAD.set([bad], back);

         payload0.set(savedAD);
         payload0.set(block0.encryptedData,savedAD.byteLength);

         await expectAsync(
            ciphers.decryptPayload0(
               async (decHint) => {
                  return pwd;
               },
               userCred,
               payload0
            )
         ).toBeRejectedWithError(Error, new RegExp('.+MAC.+'));
      }
   });

   it("detect changed encryptedData", async function () {

      for (let alg in cc.AlgInfo) {
         const clearText = 'This is a secret 🦆';
         const clearData = new TextEncoder().encode(clearText);
         const pwd = 'a good pwd';
         const hint = 'not really';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

         const eparams: EParams = {
            alg: alg,
            ic: cc.ICOUNT_MIN,
            trueRand: false,
            fallbackRand: true,
            pwd: pwd,
            hint: hint,
            userCred: userCred,
         };

         const latest = Ciphers.latest();
         const block0 = await latest.encryptBlock0(
            eparams,
            clearData,
            (params) => {
               expect(params.alg).toBe(alg);
               expect(params.ic).toBe(cc.ICOUNT_MIN);
            }
         );

         let bad = block0.encryptedData[12] == 123 ? 124 : 123;
         block0.encryptedData.set([bad], 12);

         const payload0 = new Uint8Array(block0.additionalData.byteLength + block0.encryptedData.byteLength);
         payload0.set(block0.additionalData);
         payload0.set(block0.encryptedData, block0.additionalData.byteLength);

         const ciphers = Ciphers.fromHeader(block0.headerData);
         ciphers.decodeHeader(block0.headerData);

         await expectAsync(
            ciphers.decryptPayload0(
               async (decHint) => {
                  return pwd;
               },
               userCred,
               payload0
            )
         ).toBeRejectedWithError(Error, new RegExp('.+MAC.+'));
      }
   });

   it("does not detect changed headerData, skip MAC verify", async function () {

      for (let alg in cc.AlgInfo) {
         const clearText = 'This is a secret 🦆';
         const clearData = new TextEncoder().encode(clearText);
         const pwd = 'a good pwd';
         const hint = 'not really';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

         const eparams: EParams = {
            alg: alg,
            ic: cc.ICOUNT_MIN,
            trueRand: false,
            fallbackRand: true,
            pwd: pwd,
            hint: hint,
            userCred: userCred,
         };

         const latest = Ciphers.latest();
         const block0 = await latest.encryptBlock0(
            eparams,
            clearData,
            (params) => {
               expect(params.alg).toBe(alg);
               expect(params.ic).toBe(cc.ICOUNT_MIN);
            }
         );

         const payload0 = new Uint8Array(block0.additionalData.byteLength + block0.encryptedData.byteLength);
         payload0.set(block0.additionalData);
         payload0.set(block0.encryptedData, block0.additionalData.byteLength);

         let bad = block0.headerData[12] == 123 ? 124 : 123;
         block0.headerData.set([bad], 12);

         let ciphers = Ciphers.fromHeader(block0.headerData);
         ciphers.decodeHeader(block0.headerData);

         // Monkey patch to skip MAV validation
         ciphers['_verifyMAC'] = (): Promise<boolean> => {
            return Promise.resolve(true);
         }

         // This should even though the MAC has been changed since verifyMAC
         // was replaced to always return true.
         await expectAsync(
            ciphers.decryptPayload0(
               async (decHint) => {
                  return pwd;
               },
               userCred,
               payload0
            )
         ).toBeResolved();
      }
   });

   it("detect changed additionalData, skip MAC verify", async function () {

      for (let alg in cc.AlgInfo) {
         const clearText = 'This is a secret 🦆';
         const clearData = new TextEncoder().encode(clearText);
         const pwd = 'a good pwd';
         const hint = 'not really';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

         const eparams: EParams = {
            alg: alg,
            ic: cc.ICOUNT_MIN,
            trueRand: false,
            fallbackRand: true,
            pwd: pwd,
            hint: hint,
            userCred: userCred,
         };

         const latest = Ciphers.latest();
         const block0 = await latest.encryptBlock0(
            eparams,
            clearData,
            (params) => {
               expect(params.alg).toBe(alg);
               expect(params.ic).toBe(cc.ICOUNT_MIN);
            }
         );

         let bad = block0.additionalData[12] == 123 ? 124 : 123;
         block0.additionalData.set([bad], 12);

         let payload0 = new Uint8Array(block0.additionalData.byteLength + block0.encryptedData.byteLength);
         payload0.set(block0.additionalData);
         payload0.set(block0.encryptedData, block0.additionalData.byteLength);

         let ciphers = Ciphers.fromHeader(block0.headerData);
         ciphers.decodeHeader(block0.headerData);

         // Monkey patch to skip MAV validation
         ciphers['_verifyMAC'] = (): Promise<boolean> => {
            return Promise.resolve(true);
         }

         // This should fail (even though MAC check is skipped) because
         // AD check is part of all encryption algorithms. Note that this
         // should fail with DOMException rather than Error with MAC in message
         await expectAsync(
            ciphers.decryptPayload0(
               async (decHint) => {
                  return pwd;
               },
               userCred,
               payload0
            )
         ).toBeRejectedWithError(DOMException);

      }
   });

   it("detect changed encryptedData, skip MAC verify", async function () {

      for (let alg in cc.AlgInfo) {
         const clearText = 'This is a secret 🦆';
         const clearData = new TextEncoder().encode(clearText);
         const pwd = 'a good pwd';
         const hint = 'not really';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

         const eparams: EParams = {
            alg: alg,
            ic: cc.ICOUNT_MIN,
            trueRand: false,
            fallbackRand: true,
            pwd: pwd,
            hint: hint,
            userCred: userCred,
         };

         const latest = Ciphers.latest();
         const block0 = await latest.encryptBlock0(
            eparams,
            clearData,
            (params) => {
               expect(params.alg).toBe(alg);
               expect(params.ic).toBe(cc.ICOUNT_MIN);
            }
         );

         let bad = block0.encryptedData[12] == 123 ? 124 : 123;
         block0.encryptedData.set([bad], 12);

         const payload0 = new Uint8Array(block0.additionalData.byteLength + block0.encryptedData.byteLength);
         payload0.set(block0.additionalData);
         payload0.set(block0.encryptedData, block0.additionalData.byteLength);

         const ciphers = Ciphers.fromHeader(block0.headerData);
         ciphers.decodeHeader(block0.headerData);

         // Monkey patch to skip MAV validation
         ciphers['_verifyMAC'] = (): Promise<boolean> => {
            return Promise.resolve(true);
         }

         // This should fail (even though MAC check is skipped) because
         // encrypted data was modified. Note that this should
         // fail with DOMException rather than Error with MAC in message
         await expectAsync(
            ciphers.decryptPayload0(
               async (decHint) => {
                  return pwd;
               },
               userCred,
               payload0
            )
         ).toBeRejectedWithError(DOMException);
      }
   });
});
