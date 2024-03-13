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
import * as cs from './cipher.service';

describe('CipherService', () => {
   let cipherSvc: cs.CipherService;
   beforeEach(() => {
      TestBed.configureTestingModule({});
      cipherSvc = TestBed.inject(cs.CipherService);
   });

   it('should be created', () => {
      expect(cipherSvc).toBeTruthy();
   });
});

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
   let cipherSvc: cs.CipherService;
   beforeEach(() => {
      TestBed.configureTestingModule({});
      cipherSvc = TestBed.inject(cs.CipherService);
   });

   it("successful and not equivalent key generation", async function () {

      for (let alg in cs.AlgInfo) {
         const pwd = 'a good pwd';
         const ic = cs.ICOUNT_MIN;
         const userCred = crypto.getRandomValues(new Uint8Array(cs.USERCRED_BYTES));

         const random40 = new cs.Random40();
         const randomArray = await random40.getRandomArray(false, true);
         const slt = randomArray.slice(0, cs.SLT_BYTES);

         const ek = await cipherSvc._genCipherKey(alg, ic, pwd, userCred, slt);
         const sk = await cipherSvc._genSigningKey(userCred, slt);
         const hk = await cipherSvc._genHintCipherKey(alg, userCred, slt);

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
         }
      };

      for (let alg in cs.AlgInfo) {
         const pwd = 'a good pwd';
         const ic = cs.ICOUNT_MIN;
         const userCred = new Uint8Array([214, 245, 252, 122, 133, 39, 76, 162, 64, 201, 143, 217, 237, 57, 18, 207, 199, 153, 20, 28, 162, 9, 236, 66, 100, 103, 152, 159, 226, 50, 225, 129]);
         const baseArray = new Uint8Array([160, 202, 135, 230, 125, 174, 49, 189, 171, 56, 203, 1, 237, 233, 27, 76, 46, 22, 226, 86, 89, 132, 143, 185, 198, 129, 242, 241, 183, 195, 191, 229, 162, 127, 162, 148, 75, 16, 28, 140]);
         const slt = baseArray.slice(0, cs.SLT_BYTES);

         const ek = await cipherSvc._genCipherKey(alg, ic, pwd, userCred, slt);
         const sk = await cipherSvc._genSigningKey(userCred, slt);
         const hk = await cipherSvc._genHintCipherKey(alg, userCred, slt);

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

   let cipherSvc: cs.CipherService;
   beforeEach(() => {
      TestBed.configureTestingModule({});
      cipherSvc = TestBed.inject(cs.CipherService);
   });

   it("successful round trip, all algorithms, no pwd hint", async function () {

      for (let alg in cs.AlgInfo) {

         const clearText = 'This is a secret 🦆';
         const pwd = 'a good pwd';
         const userCred = crypto.getRandomValues(new Uint8Array(cs.USERCRED_BYTES));

         const clearEnc = new TextEncoder().encode(clearText);
         const eparams: cs.EParams = {
            alg: alg,
            ic: cs.ICOUNT_MIN,
            trueRand: false,
            fallbackRand: true,
            pwd: pwd,
            userCred: userCred,
            clear: clearEnc,
         };

         const cipherText = await cipherSvc.encrypt(
            eparams,
            (params) => {
               expect(params.alg).toBe(alg);
               expect(params.ic).toBe(cs.ICOUNT_MIN);
            }
         );

         const decrypted = await cipherSvc.decrypt(
            async (decHint) => {
               expect(decHint).toBe('');
               return pwd;
            },
            userCred,
            cipherText,
            (params) => {
               expect(params.alg).toBe(alg);
               expect(params.ic).toBe(cs.ICOUNT_MIN);
            }
         );
         const clearTest = new TextDecoder().decode(decrypted);
         expect(clearTest).toBe(clearText);
      }
   });


   it("successful round trip, all algorithms", async function () {

      for (let alg in cs.AlgInfo) {

         const clearText = 'This is a secret 🦆';
         const pwd = 'a good pwd';
         const hint = 'not really';
         const userCred = crypto.getRandomValues(new Uint8Array(cs.USERCRED_BYTES));

         /*    Used to generate CTS in: detect corrupt cipher text 
               const clearText = "this 🐞 is encrypted";
               const pwd = 'asdf';
               const hint = 'asdf';
               const userCred = new Uint8Array([101, 246, 72, 149, 67, 228, 149, 35, 60, 124, 81, 187, 157, 96, 208, 217, 123, 147, 228, 60, 84, 214, 198, 116, 192, 162, 178, 147, 50, 119, 97, 251]);
         */
         const clearEnc = new TextEncoder().encode(clearText);
         const eparams: cs.EParams = {
            alg: alg,
            ic: cs.ICOUNT_MIN,
            trueRand: false,
            fallbackRand: true,
            pwd: pwd,
            hint: hint,
            userCred: userCred,
            clear: clearEnc,
         };

         const cipherText = await cipherSvc.encrypt(
            eparams,
            (params) => {
               expect(params.alg).toBe(alg);
               expect(params.ic).toBe(cs.ICOUNT_MIN);
            }
         );
         //      console.log(alg + ": " + cipherText.length + ": " + cipherText);

         const decrypted = await cipherSvc.decrypt(
            async (decHint) => {
               expect(decHint).toBe(hint);
               return pwd;
            },
            userCred,
            cipherText,
            (params) => {
               expect(params.alg).toBe(alg);
               expect(params.ic).toBe(cs.ICOUNT_MIN);
            }
         );
         const clearTest = new TextDecoder().decode(decrypted);
         //      console.log(alg + ": '" + clearTest + "'");
         expect(clearTest).toBe(clearText);
      }
   });

   // using  base64-url alphabet
   const b64a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
   const b64o = 'BCDEFGHIJKLMNOPQRSTUVWXYZAbcdefghijklmnopqrstuvwxyza1234567890_-';

   it("detect corrupt cipher text", async function () {
      //AES-GCM then X20-PLY
      const cts = [
         "seRdKoX7rFV3W5r0qEwhK5eEERUQVxsPaHH0RC_yuyUBAG1fsqBocOlC28IE5zpL-X5EKKdpXeMmwM8QceL52fMrnSG8mYghurGAGgYAAQAUxG1GRW5YYpIy2tGFejTWYmbV1hiWYRAB0bm-jOtbR_8eFE2KynZMXX4tPoN-JakS_O_bViGw-Yy9Tw",
         "-FP1A_1X8Kpr7e1-0uXkSBQE5eYlTHoPNJPfiK1zxVwCAJ2jIJL5Jrm-i9WqgGMnmD8X__n3z2A6O-ZLhyM3J8k9QZ-9v-Vw4oyAGgYAAQAUvA8AxjhwLrl4acJAYsqs2XRQ_euGwGkvwMfYrL6sjufuY3kAZ6Rz6LaxIP6LVEhkYmYC-mTcFovOvw",
      ];

      for (let ct of cts) {
         const ctBytes = cs.base64ToBytes(ct);
         // userCred used for creation of the CTS above
         const userCred = new Uint8Array([101, 246, 72, 149, 67, 228, 149, 35, 60, 124, 81, 187, 157, 96, 208, 217, 123, 147, 228, 60, 84, 214, 198, 116, 192, 162, 178, 147, 50, 119, 97, 251]);

         // First ensure we can decrypt with valid inputs
         const clear = await cipherSvc.decrypt(
            async (hint) => {
               expect(hint).toBe("asdf");
               return "asdf";
            },
            userCred,
            ct
         );
         expect(new TextDecoder().decode(clear)).toBe("this 🐞 is encrypted");

         let skipCount = 0;

         // Tweak on character at a time using b64o offsets (will remain a valid b64 string)
         for (let i = 0; i < ct.length; ++i) {
            const pos = b64a.indexOf(ct[i]);
            let corruptCt = setCharAt(ct, i, b64o[pos]);

            var corruptBytes = cs.base64ToBytes(corruptCt);

            // Multiple b64 strings can produce the same result, so skip those
            if (isEqualArray(ctBytes, corruptBytes!)) {
               ++skipCount;
               expect(skipCount).toBeLessThan(10);
               continue;
            }

            await expectAsync(
               cipherSvc.decrypt(
                  async (hint) => {
                     expect(hint).toBe("asdf");
                     return "asdf";
                  },
                  userCred,
                  corruptCt
               )).toBeRejectedWithError(Error);
         }
      }
   });

   it("detect valid hmac wrong password, all alogrithms", async function () {
      for (let alg in cs.AlgInfo) {
         const clearText = 'This is a secret 🦄';
         const pwd = 'the correct pwd';
         const hint = '';
         const userCred = crypto.getRandomValues(new Uint8Array(cs.USERCRED_BYTES));

         const clearEnc = new TextEncoder().encode(clearText);
         const eparams: cs.EParams = {
            alg: alg,
            ic: cs.ICOUNT_MIN,
            trueRand: false,
            fallbackRand: true,
            pwd: pwd,
            hint: hint,
            userCred: userCred,
            clear: clearEnc,
         };

         const cipherText = await cipherSvc.encrypt(eparams);

         await expectAsync(
            cipherSvc.decrypt(
               async (decHint) => {
                  expect(decHint).toBe(hint);
                  return 'the wrong pwd';
               },
               userCred,
               cipherText
            )
         ).toBeRejectedWithError(DOMException);
      }
   });

   it("detect corrupted hmac sig, all algorithms", async function () {

      for (let alg in cs.AlgInfo) {

         const clearEnc = crypto.getRandomValues(new Uint8Array(16));
         const pwd = 'another good pwd';
         const hint = 'nope';
         const userCred = crypto.getRandomValues(new Uint8Array(cs.USERCRED_BYTES));

         const eparams: cs.EParams = {
            alg: alg,
            ic: cs.ICOUNT_MIN,
            trueRand: false,
            fallbackRand: true,
            pwd: pwd,
            hint: hint,
            userCred: userCred,
            clear: clearEnc,
         };

         let cipherText = await cipherSvc.encrypt(eparams);

         // Set character in HMAC
         cipherText = setCharAt(cipherText, 3, cipherText[3] == 'a' ? 'b' : 'a');

         await expectAsync(
            cipherSvc.decrypt(
               async (decHint) => {
                  expect(decHint).toBe(hint);
                  return pwd;
               },
               userCred,
               cipherText
            )
         ).toBeRejectedWithError(Error, new RegExp('.+HMAC.+'));
      }
   });

   it("detect crafted bad cipher text, all algorithms", async function () {

      for (let alg in cs.AlgInfo) {
         const clearEnc = crypto.getRandomValues(new Uint8Array(16));
         const pwd = 'another good pwd';
         const hint = 'nope';
         const userCred = crypto.getRandomValues(new Uint8Array(cs.USERCRED_BYTES));

         const eparams: cs.EParams = {
            alg: alg,
            ic: cs.ICOUNT_MIN,
            trueRand: false,
            fallbackRand: true,
            pwd: pwd,
            hint: hint,
            userCred: userCred,
            clear: clearEnc,
         };

         let cipherText = await cipherSvc.encrypt(eparams);

         // Set character in cipher text (past first HMAC ~32*4/3 characters) 
         // this is in the hint
         let problemText = setCharAt(cipherText, 108, cipherText[108] == 'a' ? 'b' : 'a');

         await expectAsync(
            cipherSvc.decrypt(
               async (decHint) => {
                  // Should never execute
                  expect(false).toBe(true);
                  return pwd;
               },
               userCred,
               problemText
            )
         ).toBeRejectedWithError(Error, new RegExp('.+HMAC.+'));

         // Set character in cipher text (past first ~32*4/3 characters) 
         // this changes the encrypted text
         problemText = setCharAt(cipherText, 118, cipherText[118] == 'c' ? 'e' : 'c');

         await expectAsync(
            cipherSvc.decrypt(
               async (decHint) => {
                  // Should never execute
                  expect(false).toBe(true);
                  return pwd;
               },
               userCred,
               problemText
            )
         ).toBeRejectedWithError(Error, new RegExp('.+HMAC.+'));
      }
   });

   async function signAndRepack(
      userCred: Uint8Array,
      slt: Uint8Array,
      encoded: Uint8Array
   ): Promise<[string, CryptoKey, Uint8Array]> {

      const sk = await cipherSvc._genSigningKey(userCred, slt);
      const hmac = await cipherSvc._signCipherBytes(sk, encoded);
      let extended = new Uint8Array(hmac.byteLength + encoded.byteLength);
      extended.set(hmac);
      extended.set(encoded, hmac.byteLength);

      return [cs.bytesToBase64(extended), sk, hmac];
   }

   // More complex test to ensure that having the wrong usercred causes
   // decryption to fail. We test this by extracting and not changing original
   // CipherData (with its encrypted data) from "Alice's" original encryption,
   // then creating a new valid HMAC signature with "Bob's" userCredB signature
   // attached to the front of the Alice's CipherData (and encypted txt).
   //
   // In the wild if the HMAC signature was swapped with someone else's
   // valid signature Quick Crypt would report the error to Alice at signature
   // validation time because it would use Alice's userCredA not Bob's userCredB to
   // test.
   //
   // But what could happen is that an evil site might closely mimicked
   // Quick Crypt, and if Alice was tricked into going there, it could just
   // not tell Alice about the HMAC signature failure. So what this test
   // validates is that even with a replaced HMAC signature
   // (which is equivalent to an ignored HMAC signature), the clear
   // text can still not be retrived. This test tries to ensures that
   // even having tricked Alice into entering her PWD at the evil website,
   // the ciphertext still cannot be decrypted because the
   // evil site does not have access to Alice's userCredA which is
   // combined with her password to generate the cipher key.
   //
   it("decryption should fail with replaced valid signature", async function () {

      for (let alg in cs.AlgInfo) {

         const clearText = 'This is a secret 🐓';
         const pwd = 'a good pwd';
         const hint = 'not really';
         const userCredA = crypto.getRandomValues(new Uint8Array(cs.USERCRED_BYTES));
         const userCredB = crypto.getRandomValues(new Uint8Array(cs.USERCRED_BYTES));

         const clearEnc = new TextEncoder().encode(clearText);
         const eparamsA: cs.EParams = {
            alg: alg,
            ic: cs.ICOUNT_MIN,
            trueRand: false,
            fallbackRand: true,
            pwd: pwd,
            hint: hint,
            userCred: userCredA,
            clear: clearEnc,
         };
         const cipherTextA = await cipherSvc.encrypt(eparamsA);
         const extendedA = cs.base64ToBytes(cipherTextA);
         const encodedA = extendedA.slice(cs.HMAC_BYTES);
         const cipherDataA = cipherSvc._decodeCipherData(encodedA);

         // First sign and repack with the original (correct) values to help ensure the
         // code for repacking is valid and that the 2nd attempt with a new signature
         // detects the userCred change rather than bug in signAndRepack. Then resign
         // and pack with Bob's sitkey
         const [cipherTextAA, skA, hmacA] = await signAndRepack(userCredA, cipherDataA.slt, encodedA);
         const [cipherTextBA, skB, hmacB] = await signAndRepack(userCredB, cipherDataA.slt, encodedA);

         // both should succeed since the singatures are valid (just cannot decrypt cipherText)
         expect(await cipherSvc._verifyCipherBytes(skA, hmacA, encodedA)).toBeTrue();
         expect(await cipherSvc._verifyCipherBytes(skB, hmacB, encodedA)).toBeTrue();

         // The original should succeed
         const decryptedAA = await cipherSvc.decrypt(
            async (decHint) => {
               return pwd;
            },
            userCredA,
            cipherTextAA
         );
         const clearTest = new TextDecoder().decode(decryptedAA);
         expect(clearTest).toBe(clearText);

         // The big moment! Perhaps should have better validation that the decryption
         // failed, but not much else returns DOMException from cipher.service. Note
         // this this is using the correct PWD because we assume the evil site has
         // tricked Alice into provider it
         await expectAsync(
            cipherSvc.decrypt(
               async (decHint) => {
                  return pwd;
               },
               userCredB,
               cipherTextBA
            )
         ).toBeRejectedWithError(DOMException);
      }
   });

   it("detect encryption argument errors", async function () {

      const hint = 'nope';
      const pwd = 'another good pwd';
      const userCred = crypto.getRandomValues(new Uint8Array(cs.USERCRED_BYTES));
      const clearEnc = crypto.getRandomValues(new Uint8Array(16));

      const eparams: cs.EParams = {
         alg: 'AES-GCM',
         ic: cs.ICOUNT_MIN,
         trueRand: false,
         fallbackRand: true,
         pwd: pwd,
         hint: hint,
         userCred: userCred,
         clear: clearEnc,
      };
      // ensure the defaults work
      await expectAsync(
         cipherSvc.encrypt(eparams)
      ).not.toBeRejectedWithError();

      // empty pwd
      let bparams = {
         ...eparams,
         pwd: ''
      }
      await expectAsync(
         cipherSvc.encrypt(bparams)
      ).toBeRejectedWithError(Error, new RegExp('.+userCred.*'));

      // no userCred
      bparams = {
         ...eparams,
         userCred: new Uint8Array(0)
      }
      await expectAsync(
         cipherSvc.encrypt(bparams)
      ).toBeRejectedWithError(Error, new RegExp('.+userCred.*'));

      // extra long userCred
      bparams = {
         ...eparams,
         userCred: crypto.getRandomValues(new Uint8Array(cs.USERCRED_BYTES + 2))
      }
      await expectAsync(
         cipherSvc.encrypt(bparams)
      ).toBeRejectedWithError(Error, new RegExp('.+userCred.*'));

      // empty clear data
      bparams = {
         ...eparams,
         clear: new Uint8Array(0)
      }
      await expectAsync(
         cipherSvc.encrypt(bparams)
      ).toBeRejectedWithError(Error, new RegExp('No data.+'));

      // ic too small
      bparams = {
         ...eparams,
         ic: cs.ICOUNT_MIN - 1
      }
      await expectAsync(
         cipherSvc.encrypt(bparams)
      ).toBeRejectedWithError(Error);

      // ic too big
      bparams = {
         ...eparams,
         ic: cs.ICOUNT_MAX + 1
      }
      await expectAsync(
         cipherSvc.encrypt(bparams)
      ).toBeRejectedWithError(Error);

      // invalid alg 
      bparams = {
         ...eparams,
         alg: 'ABS-GCM'
      }
      await expectAsync(
         cipherSvc.encrypt(bparams)
      ).toBeRejectedWithError(Error);

      // really invalid alg 
      bparams = {
         ...eparams,
         alg: 'asdfadfsk'
      }
      await expectAsync(
         cipherSvc.encrypt(bparams)
      ).toBeRejectedWithError(Error);

      // both rands false 
      bparams = {
         ...eparams,
         trueRand: false,
         fallbackRand: false
      }
      await expectAsync(
         cipherSvc.encrypt(bparams)
      ).toBeRejectedWithError(Error);

      // hint too long
      bparams = {
         ...eparams,
         hint: 'this is too long'.repeat(8)
      }
      await expectAsync(
         cipherSvc.encrypt(bparams)
      ).toBeRejectedWithError(Error);

   });
});


describe("Get cipherdata from cipher text", function () {

   let cipherSvc: cs.CipherService;
   beforeEach(() => {
      TestBed.configureTestingModule({});
      cipherSvc = TestBed.inject(cs.CipherService);
   });


   it("expected CipherData, all algorithms", async function () {

      for (let alg in cs.AlgInfo) {

         const clearText = 'This is a secret 🦋';
         const pwd = 'not good pwd';
         const hint = 'try a himt';
         const userCred = crypto.getRandomValues(new Uint8Array(cs.USERCRED_BYTES));

         const clearEnc = new TextEncoder().encode(clearText);
         const eparams: cs.EParams = {
            alg: alg,
            ic: cs.ICOUNT_MIN,
            trueRand: false,
            fallbackRand: true,
            pwd: pwd,
            hint: hint,
            userCred: userCred,
            clear: clearEnc,
         };
         const cipherText = await cipherSvc.encrypt(eparams);
         const cipherData = await cipherSvc.getCipherData(userCred, cipherText);

         expect(cipherData.alg).toBe(alg);
         expect(cipherData.ic).toBe(cs.ICOUNT_MIN);
         expect(cipherData.iv.byteLength).toBe(cs.IV_BYTES);
         expect(cipherData.slt.byteLength).toBe(cs.SLT_BYTES);
         expect(cipherData.encryptedHint.byteLength).toBeGreaterThanOrEqual(hint.length);
         expect(cipherData.encryptedData.byteLength).toBeGreaterThanOrEqual(clearEnc.byteLength);

         // confirm that hint and clear output aren't the same as inputs
         const hintEnc = new TextEncoder().encode(hint);
         expect(isEqualArray(hintEnc, cipherData.encryptedHint)).toBeFalse();
         expect(isEqualArray(clearEnc, cipherData.encryptedData)).toBeFalse();
      }
   });

   it("detect corrupted cipherdata HMAC, all algorithms", async function () {

      for (let alg in cs.AlgInfo) {

         const clearEnc = crypto.getRandomValues(new Uint8Array(16));
         const pwd = 'another good pwd';
         const hint = 'nope';
         const userCred = crypto.getRandomValues(new Uint8Array(cs.USERCRED_BYTES));

         const eparams: cs.EParams = {
            alg: alg,
            ic: cs.ICOUNT_MIN,
            trueRand: false,
            fallbackRand: true,
            pwd: pwd,
            hint: hint,
            userCred: userCred,
            clear: clearEnc,
         };

         let cipherText = await cipherSvc.encrypt(eparams);

         // Set character in CipherData
         cipherText = setCharAt(cipherText, 37, cipherText[37] == 'a' ? 'b' : 'a');

         await expectAsync(
            cipherSvc.getCipherData(
               userCred,
               cipherText
            )
         ).toBeRejectedWithError(Error, new RegExp('.+HMAC.+'));
      }
   });

   it("detect invalid userCred", async function () {

      const clearEnc = crypto.getRandomValues(new Uint8Array(16));
      const pwd = 'another good pwd';
      const hint = 'nope';
      const userCred = crypto.getRandomValues(new Uint8Array(cs.USERCRED_BYTES));

      const eparams: cs.EParams = {
         alg: 'AES-GCM',
         ic: cs.ICOUNT_MIN,
         trueRand: false,
         fallbackRand: true,
         pwd: pwd,
         hint: hint,
         userCred: userCred,
         clear: clearEnc,
      };
      let cipherText = await cipherSvc.encrypt(eparams);

      // Doesn't match orignal userCred
      let problemUserCred = crypto.getRandomValues(new Uint8Array(cs.USERCRED_BYTES));
      await expectAsync(
         cipherSvc.getCipherData(
            problemUserCred,
            cipherText
         )
      ).toBeRejectedWithError(Error, new RegExp('.+HMAC.+'));

      // Missing one byte of userCred
      problemUserCred = userCred.slice(0, userCred.byteLength - 1);
      await expectAsync(
         cipherSvc.getCipherData(
            problemUserCred,
            cipherText
         )
      ).toBeRejectedWithError(Error);

      // One bytes extra
      problemUserCred = new Uint8Array(cs.USERCRED_BYTES + 1);
      problemUserCred.set(userCred);
      problemUserCred.set([0], userCred.byteLength);
      await expectAsync(
         cipherSvc.getCipherData(
            problemUserCred,
            cipherText
         )
      ).toBeRejectedWithError(Error);
   });
});


describe("Benchmark execution", function () {

   let cipherSvc: cs.CipherService;
   beforeEach(() => {
      TestBed.configureTestingModule({});
      cipherSvc = TestBed.inject(cs.CipherService);
   });

   it("reasonable benchmark results", async function () {
      const [icount, icountMax, hashRate] = await cipherSvc.benchmark(cs.ICOUNT_MIN);
      expect(icount).toBeGreaterThanOrEqual(cs.ICOUNT_DEFAULT);
      expect(icount).toBeLessThanOrEqual(cs.ICOUNT_MAX);
      expect(icountMax).toBeGreaterThanOrEqual(icount);
      expect(icountMax).toBeLessThanOrEqual(cs.ICOUNT_MAX);
      expect(hashRate).toBeGreaterThanOrEqual(1);
      expect(hashRate).toBeLessThanOrEqual(100000);

      // should be cashed, so 2nd call should match 1st
      const [icount2, icountMax2, hashRate2] = await cipherSvc.benchmark(cs.ICOUNT_MIN);
      expect(icount2).toEqual(icount);
      expect(icountMax2).toEqual(icountMax);
      expect(hashRate2).toEqual(hashRate);
   });

});

describe("CipherData encode and decode", function () {

   let cipherSvc: cs.CipherService;
   beforeEach(() => {
      TestBed.configureTestingModule({});
      cipherSvc = TestBed.inject(cs.CipherService);
   });

   it("valid CipherData", function () {
      const dp: cs.CipherData = {
         alg: 'X20-PLY',
         ic: 2000000,
         iv: crypto.getRandomValues(new Uint8Array(24)),
         slt: crypto.getRandomValues(new Uint8Array(16)),
         encryptedHint: crypto.getRandomValues(new Uint8Array(14)),
         encryptedData: crypto.getRandomValues(new Uint8Array(42))
      }

      const packed = cipherSvc._encodeCipherData(dp);
      const rdp = cipherSvc._decodeCipherData(packed);

      expect(rdp.alg).toBe(dp.alg);
      expect(rdp.ic).toBe(dp.ic);
      expect(isEqualArray(rdp.iv, dp.iv)).toBeTrue();
      expect(isEqualArray(rdp.slt, dp.slt)).toBeTrue();
      expect(isEqualArray(rdp.encryptedHint, dp.encryptedHint)).toBeTrue();
      expect(isEqualArray(rdp.encryptedData, dp.encryptedData)).toBeTrue();
   });

   it("detect invalid CipherData encode", function () {

      //valid
      let dp: cs.CipherData = {
         alg: 'X20-PLY',
         ic: cs.ICOUNT_MIN,
         iv: new Uint8Array(cs.IV_BYTES),
         slt: new Uint8Array(cs.SLT_BYTES),
         encryptedHint: new Uint8Array(0),
         encryptedData: new Uint8Array(1)
      }
      // exect we start valid
      expect(() => cipherSvc._encodeCipherData(dp)).not.toThrowError();

      // iv too short
      let bdp = {
         ...dp,
         iv: new Uint8Array(cs.IV_BYTES - 1)
      }
      expect(() => cipherSvc._encodeCipherData(bdp)).toThrowError();

      // iv too long
      bdp = {
         ...dp,
         iv: new Uint8Array(cs.IV_BYTES + 1)
      }
      expect(() => cipherSvc._encodeCipherData(bdp)).toThrowError();

      // salt too short
      bdp = {
         ...dp,
         slt: new Uint8Array(0)
      }
      expect(() => cipherSvc._encodeCipherData(bdp)).toThrowError();

      // salt too long
      bdp = {
         ...dp,
         slt: new Uint8Array(cs.SLT_BYTES + 1)
      }
      expect(() => cipherSvc._encodeCipherData(bdp)).toThrowError();

      // hint too long
      bdp = {
         ...dp,
         encryptedHint: new Uint8Array(Array(256).fill(0))
      }
      expect(() => cipherSvc._encodeCipherData(bdp)).toThrowError();

      // make sure we're good...
      bdp = {
         ...dp,
      }
      expect(() => cipherSvc._encodeCipherData(bdp)).not.toThrowError();

      // ic too large
      bdp = {
         ...dp,
         ic: cs.ICOUNT_MAX + 1
      }
      expect(() => cipherSvc._encodeCipherData(bdp)).toThrowError();

      // ic too small
      bdp = {
         ...dp,
         ic: -1
      }
      expect(() => cipherSvc._encodeCipherData(bdp)).toThrowError();

      // invalid alg
      bdp = {
         ...dp,
         alg: 'AES-XYV'
      }
      expect(() => cipherSvc._encodeCipherData(bdp)).toThrowError();

      bdp = {
         ...dp,
         alg: ''
      }
      expect(() => cipherSvc._encodeCipherData(bdp)).toThrowError();

   });

   it("detect invalid CipherData decode", function () {

      // initially valid
      let dp: cs.CipherData = {
         alg: 'X20-PLY',
         ic: 2000000,
         iv: new Uint8Array(24),
         slt: new Uint8Array(16),
         encryptedHint: new Uint8Array(10),
         encryptedData: new Uint8Array(42)
      };
      // Expect we start valid
      expect(() => cipherSvc.validateCipherData(dp)).not.toThrowError();
      let packed = cipherSvc._encodeCipherData(dp);
      expect(() => cipherSvc._decodeCipherData(packed)).not.toThrowError();

      packed = cipherSvc._encodeCipherData(dp);
      // Invalid alrogirthm id
      packed.set([7], 0);
      // So that this should throw an exception
      expect(() => cipherSvc._decodeCipherData(packed)).toThrowError();

      packed = cipherSvc._encodeCipherData(dp);
      // Invalid version number
      packed.set([5], 46);
      // So that this should throw an exception
      expect(() => cipherSvc._decodeCipherData(packed)).toThrowError();

      packed = cipherSvc._encodeCipherData(dp);
      // This pokes in a zero at the top two bytes of IC, making out of range
      // 44 = ALG_BYTES+IV_BYTES+SLT_BYTES+IC_BYTES-2
      packed.set([0, 0], 44);
      // So that this should throw an exception
      expect(() => cipherSvc._decodeCipherData(packed)).toThrowError();

      packed = cipherSvc._encodeCipherData(dp);
      // Change changes the hint length length
      // 48 = ALG_BYTES+IV_BYTES+SLT_BYTES+IC_BYTES+VER_BYTES
      packed.set([75], 48);
      // So that this should throw an exception
      expect(() => cipherSvc._decodeCipherData(packed)).toThrowError();

      // shortest valid CipherData
      dp = {
         alg: 'X20-PLY',
         ic: 2000000,
         iv: new Uint8Array(24),
         slt: new Uint8Array(16),
         encryptedHint: new Uint8Array(0),
         encryptedData: new Uint8Array(1)
      }
      // Expect we start valid
      packed = cipherSvc._encodeCipherData(dp);
      expect(() => cipherSvc._decodeCipherData(packed)).not.toThrowError();

      // should be too short with 1 byte removed
      let sliced = packed.slice(0, packed.byteLength - 1);
      expect(() => cipherSvc._decodeCipherData(sliced)).toThrowError();

   });

});

describe("Base64 encode decode", function () {

   it("random bytes", function () {
      const rb = crypto.getRandomValues(new Uint8Array(43))
      const b64 = cs.bytesToBase64(rb);
      expect(b64.length).toBeGreaterThanOrEqual(rb.byteLength);
      expect(isEqualArray(rb, cs.base64ToBytes(b64))).toBeTrue();
   });

   it("detect bad encodings", function () {
      // correct values
      const correctBytes = new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x3e, 0x33]);
      const correctText = 'Hello>3';

      // expect we start valid
      const good = 'SGVsbG8-Mw';
      const bytes = cs.base64ToBytes(good);
      expect(bytes).toEqual(correctBytes);
      expect(new TextDecoder().decode(bytes)).toBe(correctText);

      // underlying simplewebauthn library concers nonURL base64 to base64URL
      // so this should work also (goodRfc is standard base64)
      const goodRfc = 'SGVsbG8+Mw==';
      const bytes2 = cs.base64ToBytes(goodRfc);
      expect(bytes2).toEqual(correctBytes);

      // extra padding is stripped (so not an error to be missing some)
      const extraPadding = 'SGVsbG8-Mw=';
      const bytes3 = cs.base64ToBytes(extraPadding);
      expect(bytes3).toEqual(new Uint8Array(correctBytes));

      const badChar = 'SGVsbG8.Mw';
      expect(() => cs.base64ToBytes(badChar)).toThrowError();

      const badLen = 'SGVsbG8Mw';
      expect(() => cs.base64ToBytes(badLen)).toThrowError();
   });
});

describe("Random40 tests", function () {

   let cipherSvc: cs.CipherService;
   beforeEach(() => {
      TestBed.configureTestingModule({});
      cipherSvc = TestBed.inject(cs.CipherService);
   });


   it("true random", async function () {
      let rand = new cs.Random40();
      const r1 = await rand.getRandomArray(true, false);
      const r2 = await rand.getRandomArray(true, false);

      expect(r1.byteLength).toBe(40);
      expect(r2.byteLength).toBe(40);
      expect(isEqualArray(r1, r2)).toBeFalse();
   });

   it("pseudo random", async function () {
      let rand = new cs.Random40();
      const r1 = await rand.getRandomArray(false, true);
      const r2 = await rand.getRandomArray(false, true);

      expect(r1.byteLength).toBe(40);
      expect(r2.byteLength).toBe(40);
      expect(isEqualArray(r1, r2)).toBeFalse();
      await expectAsync(rand.getRandomArray(false, false)).toBeRejectedWithError(Error);
   });
});

describe("Number byte packing", function () {

   it("one byte ok", function () {
      let a1 = cs.numToBytes(0, 1);
      expect(cs.bytesToNum(a1)).toBe(0);
      expect(a1.byteLength).toBe(1);

      a1 = cs.numToBytes(1, 1);
      expect(cs.bytesToNum(a1)).toBe(1);
      expect(a1.byteLength).toBe(1);

      a1 = cs.numToBytes(255, 1);
      expect(cs.bytesToNum(a1)).toBe(255);
      expect(a1.byteLength).toBe(1);
   });

   it("detect overflow check", function () {
      expect(() => cs.numToBytes(256, 1)).toThrowError();
      expect(() => cs.numToBytes(2456, 1)).toThrowError();
      expect(() => cs.numToBytes(65536, 2)).toThrowError();
      expect(() => cs.numToBytes(18777216, 3)).toThrowError();
      expect(() => cs.numToBytes(187742949672967216, 4)).toThrowError();
   });

   it("other lengths ok", function () {
      let a2 = cs.numToBytes(567, 2);
      expect(cs.bytesToNum(a2)).toBe(567);
      expect(a2.byteLength).toBe(2);

      a2 = cs.numToBytes(65535, 2);
      expect(cs.bytesToNum(a2)).toBe(65535);
      expect(a2.byteLength).toBe(2);

      let a3 = cs.numToBytes(2, 3);
      expect(cs.bytesToNum(a3)).toBe(2);
      expect(a3.byteLength).toBe(3);

      let a4 = cs.numToBytes(4294000000, 4);
      expect(cs.bytesToNum(a4)).toBe(4294000000);
      expect(a4.byteLength).toBe(4);
   });
});
