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
import * as cs from './cipher-stuff';

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

describe("Encryption and decryption", function () {

   it("successful round trip, all algorithms", async function () {

      for (let alg in cs.AlgInfo) {
         //      console.log(alg);

         const clearText = 'This is a secret 🦆';
         const pwd = 'a good pwd';
         const hint = 'not really';
         const pksig = crypto.getRandomValues(new Uint8Array(cs.PKSIG_BYTES));

         let cipher = new cs.Cipher(alg, cs.ICOUNT_MIN, false, true);
         let clearEnc = new TextEncoder().encode(clearText);

         const cipherText = await cipher.encrypt(
            pwd, hint, pksig, clearEnc,
            (cparams) => {
               expect(cparams.alg).toBe(alg);
               expect(cparams.hint).toBe(hint);
               expect(cparams.ic).toBe(cs.ICOUNT_MIN);
            }
         );
         //      console.log(cipherText.length + ": " + cipherText);

         const decrypted = await cs.Cipher.decrypt(
            async (decHint) => {
               expect(decHint).toBe(hint);
               return pwd;
            },
            pksig,
            cipherText,
            (cparams) => {
               expect(cparams.alg).toBe(alg);
               expect(cparams.hint).toBe(hint);
               expect(cparams.ic).toBe(cs.ICOUNT_MIN);
            }
         );
         const clearTest = new TextDecoder().decode(decrypted);
         //      console.log(alg + ": '" + clearTest + "'");
         expect(clearTest).toBe(clearText);
      }
   });

   const b64a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
   const b64o = 'BCDEFGHIJKLMNOPQRSTUVWXYZAbcdefghijklmnopqrstuvwxyza1234567890,/+';

   it("detect corrupt cipher text", async function () {
      const ct = "oWu4W89MIyapikE4hQYaL6ZkUqOEamrDBHGs/u0Qk9kBAEahmxcmyK/OkZqWywE9MbE4x333o40s8v5Ql/ZL5J4r9g5iRd/CBI9AQg8AAQAEYXNkZggOIhCJpt562Xz44hM0m/slMtPzxxXUzEyvA6Zx6bjluQcjFKo9";
      const ctBytes = cs.base64ToBytes(ct);

      // pksig used for encryption in testing
      const pksig = new Uint8Array([101, 246, 72, 149, 67, 228, 149, 35, 60, 124, 81, 187, 157, 96, 208, 217, 123, 147, 228, 60, 84, 214, 198, 116, 192, 162, 178, 147, 50, 119, 97, 251]);

      // First ensure we can decrypt with valid inputs
      const clear = await cs.Cipher.decrypt(
         async (hint) => {
            expect(hint).toBe("asdf");
            return "asdf";
         },
         pksig,
         ct
      );
      expect(new TextDecoder().decode(clear)).toBe("this 🐞 is encrypted");

      let skipCount = 0;

      // Tweak on character at a time using b64o offsets (will remain a valid b64 string)
      for (let i = 0; i < ct.length; ++i) {
         const pos = b64a.indexOf(ct[i]);
         let corruptCt = setCharAt(ct, i, b64o[pos]);

         // Multiple b64 strings can produce the same result, so skip those
         const corruptBytes = cs.base64ToBytes(corruptCt);

         if (isEqualArray(ctBytes, corruptBytes)) {
            ++skipCount;
            expect(skipCount).toBeLessThan(10);
            continue;
         }

         await expectAsync(
            cs.Cipher.decrypt(
               async (hint) => {
                  expect(hint).toBe("asdf");
                  return "asdf";
               },
               pksig,
               corruptCt
            )).toBeRejectedWithError();
      }
   });

   it("detect valid hmac wrong password, all alogrithms", async function () {
      for (let alg in cs.AlgInfo) {
         const clearText = 'This is a secret 🦄';
         const pwd = 'the correct pwd';
         const hint = '';
         const pksig = crypto.getRandomValues(new Uint8Array(cs.PKSIG_BYTES));

         let cipher = new cs.Cipher(alg, cs.ICOUNT_MIN, false, true);
         let clearEnc = new TextEncoder().encode(clearText);

         const cipherText = await cipher.encrypt(pwd, hint, pksig, clearEnc);

         await expectAsync(
            cs.Cipher.decrypt(
               async (decHint) => {
                  console.log(alg + ' decrypt');
                  expect(decHint).toBe(hint);
                  return 'the wrong pwd';
               },
               pksig,
               cipherText
            )
         ).toBeRejectedWithError();
      }
   });

   it("detect corrupted hmac sig, all algorithms", async function () {

      for (let alg in cs.AlgInfo) {

         const clearEnc = crypto.getRandomValues(new Uint8Array(16));
         const pwd = 'another good pwd';
         const hint = 'nope';
         const pksig = crypto.getRandomValues(new Uint8Array(cs.PKSIG_BYTES));

         let cipher = new cs.Cipher(alg, cs.ICOUNT_MIN, false, true);

         let cipherText = await cipher.encrypt(pwd, hint, pksig, clearEnc);

         // Set character in HMAC
         cipherText = setCharAt(cipherText, 3, cipherText[3] == 'a' ? 'b' : 'a');

         await expectAsync(
            cs.Cipher.decrypt(
               async (decHint) => {
                  expect(decHint).toBe(hint);
                  return pwd;
               },
               pksig,
               cipherText
            )
         ).toBeRejectedWithError();
      }
   });

   it("detect corrupted cipher text, all algorithms", async function () {

      for (let alg in cs.AlgInfo) {
         const clearEnc = crypto.getRandomValues(new Uint8Array(16));
         const pwd = 'another good pwd';
         const hint = 'nope';
         const pksig = crypto.getRandomValues(new Uint8Array(cs.PKSIG_BYTES));

         let cipher = new cs.Cipher(alg, cs.ICOUNT_MIN, false, true);

         let cipherText = await cipher.encrypt(pwd, hint, pksig, clearEnc);

         // Set character in cipher text (past first ~32*4/3 characters) 
         // this changes the hint
         let problemText = setCharAt(cipherText, 108, cipherText[108] == 'a' ? 'b' : 'a');

         await expectAsync(
            cs.Cipher.decrypt(
               async (decHint) => {
                  // Should never execute
                  expect(false).toBe(true);
                  return pwd;
               },
               pksig,
               problemText
            )
         ).toBeRejectedWithError();

         // Set character in cipher text (past first ~32*4/3 characters) 
         // this changes the encrypted text
         problemText = setCharAt(cipherText, 118, cipherText[118] == 'c' ? 'e' : 'c');

         await expectAsync(
            cs.Cipher.decrypt(
               async (decHint) => {
                  // Should never execute
                  expect(false).toBe(true);
                  return pwd;
               },
               pksig,
               problemText
            )
         ).toBeRejectedWithError();
      }
   });

   it("detect encryption parameter errors", async function () {

      let clearEnc = crypto.getRandomValues(new Uint8Array(16));
      const hint = 'nope';
      const pwd = 'ok now';
      const pksig = crypto.getRandomValues(new Uint8Array(cs.PKSIG_BYTES));

      let cipher = new cs.Cipher('AES-GCM', cs.ICOUNT_MIN, false, true);

      // ensure the defaults work
      await expectAsync(
         cipher.encrypt(pwd, hint, pksig, clearEnc)
      ).not.toBeRejectedWithError();

      // empty pwd
      await expectAsync(
         cipher.encrypt('', hint, pksig, clearEnc)
      ).toBeRejectedWithError();

      // no signature
      await expectAsync(
         cipher.encrypt(pwd, hint, new Uint8Array(0), clearEnc)
      ).toBeRejectedWithError();

      // extra signature
      await expectAsync(
         cipher.encrypt(pwd, hint, crypto.getRandomValues(new Uint8Array(cs.PKSIG_BYTES + 2)), clearEnc)
      ).toBeRejectedWithError();

      // empty clear data
      await expectAsync(
         cipher.encrypt(pwd, hint, pksig, new Uint8Array(0))
      ).toBeRejectedWithError();

   });
});


describe("Get cipher params from cipher text", function () {
   // This covers many decryption test also since decrypt starts
   // with Cipher.etCipherParams

   it("successful params, all algorithms", async function () {

      for (let alg in cs.AlgInfo) {

         const clearText = 'This is a secret 🦋';
         const pwd = 'not good pwd';
         const hint = 'try a himt';
         const pksig = crypto.getRandomValues(new Uint8Array(cs.PKSIG_BYTES));

         let cipher = new cs.Cipher(alg, cs.ICOUNT_MIN, false, true);
         let clearEnc = new TextEncoder().encode(clearText);

         const cipherText = await cipher.encrypt(pwd, hint, pksig, clearEnc);

         const cparams = await cs.Cipher.getCipherParams(
            pksig,
            cipherText
         );

         expect(cparams.alg).toBe(alg);
         expect(cparams.ic).toBe(cs.ICOUNT_MIN);
         expect(cparams.iv.byteLength).toBe(cs.IV_BYTES);
         expect(cparams.slt.byteLength).toBe(cs.SLT_BYTES);
         expect(cparams.et.byteLength).toBeGreaterThanOrEqual(clearEnc.byteLength);
      }
   });

   it("corrupted params sig, all algorithms", async function () {

      for (let alg in cs.AlgInfo) {

         const clearEnc = crypto.getRandomValues(new Uint8Array(16));
         const pwd = 'another good pwd';
         const hint = 'nope';
         const pksig = crypto.getRandomValues(new Uint8Array(cs.PKSIG_BYTES));

         let cipher = new cs.Cipher(alg, cs.ICOUNT_MIN, false, true);

         let cipherText = await cipher.encrypt(pwd, hint, pksig, clearEnc);

         // Set character in CParams
         cipherText = setCharAt(cipherText, 37, cipherText[37] == 'a' ? 'b' : 'a');

         await expectAsync(
            cs.Cipher.getCipherParams(
               pksig,
               cipherText
            )
         ).toBeRejectedWithError();
      }
   });

   it("detect invalid pksig", async function () {

      const clearEnc = crypto.getRandomValues(new Uint8Array(16));
      const pwd = 'another good pwd';
      const hint = 'nope';
      const pksig = crypto.getRandomValues(new Uint8Array(cs.PKSIG_BYTES));

      let cipher = new cs.Cipher('AES-GCM', cs.ICOUNT_MIN, false, true);
      let cipherText = await cipher.encrypt(pwd, hint, pksig, clearEnc);

      // Doesn't match orignal signature
      let problemSig = crypto.getRandomValues(new Uint8Array(cs.PKSIG_BYTES));
      await expectAsync(
         cs.Cipher.getCipherParams(
            problemSig,
            cipherText
         )
      ).toBeRejectedWithError();

      // Doesn't missing on byte
      problemSig = pksig.slice(0, pksig.byteLength - 1);
      await expectAsync(
         cs.Cipher.getCipherParams(
            problemSig,
            cipherText
         )
      ).toBeRejectedWithError();

      // One bytes extra
      problemSig = new Uint8Array(cs.PKSIG_BYTES + 1);
      problemSig.set(pksig);
      problemSig.set([0], pksig.byteLength);
      await expectAsync(
         cs.Cipher.getCipherParams(
            problemSig,
            cipherText
         )
      ).toBeRejectedWithError();
   });
});


describe("Cipher object creation", function () {

   it("valid construction, all algs", function () {
      for (let alg in cs.AlgInfo) {
         const cipher = new cs.Cipher(alg, 2000000, false, true);
         expect(cipher.ic).toBe(2000000);
         expect(cipher.alg).toBe(alg);
         expect(cipher.trueRand).toBe(false);
         expect(cipher.fallbackRand).toBe(true);
      }
   });

   it("detect invalid Cipher construction", function () {
      // ic too small
      expect(() =>
         new cs.Cipher('AES-GCM', cs.ICOUNT_MIN - 1, false, true)
      ).toThrowError();

      // ic too big
      expect(() =>
         new cs.Cipher('AES-GCM', cs.ICOUNT_MAX + 1, false, true)
      ).toThrowError();

      // invalid alg 
      expect(() =>
         new cs.Cipher('ABS-GCM', cs.ICOUNT_DEFAULT, false, true)
      ).toThrowError();

      // really invalid alg 
      expect(() =>
         new cs.Cipher('asdfadfsk', cs.ICOUNT_DEFAULT, false, true)
      ).toThrowError();

      // both rands false 
      expect(() =>
         new cs.Cipher('AES-GCM', cs.ICOUNT_DEFAULT, false, false)
      ).toThrowError();
   });
});


describe("CParam encode and decode", function () {

   it("valid CParams", function () {
      const cp = {
         alg: 'X20-PLY',
         ic: 2000000,
         iv: crypto.getRandomValues(new Uint8Array(24)),
         slt: crypto.getRandomValues(new Uint8Array(16)),
         hint: "don't know",
         et: crypto.getRandomValues(new Uint8Array(42))
      }

      const packed = cs.Cipher._encodeCipherText(cp);
      const rcp = cs.Cipher._decodeCipherText(packed);

      expect(rcp.alg).toBe(cp.alg);
      expect(rcp.ic).toBe(cp.ic);
      expect(isEqualArray(rcp.iv, cp.iv)).toBeTrue();
      expect(isEqualArray(rcp.slt, cp.slt)).toBeTrue();
      expect(rcp.hint).toBe(cp.hint);
      expect(isEqualArray(rcp.et, cp.et)).toBeTrue();
   });

   it("detect invalid CParams encode", function () {

      //valid
      let cp = {
         alg: 'X20-PLY',
         ic: cs.ICOUNT_MIN,
         iv: new Uint8Array(cs.IV_BYTES),
         slt: new Uint8Array(cs.SLT_BYTES),
         hint: "",
         et: new Uint8Array(1)
      }
      // exect we start valid
      expect(() => cs.Cipher._encodeCipherText(cp)).not.toThrowError();

      // iv too short
      cp.iv = new Uint8Array(cs.IV_BYTES - 1);
      expect(() => cs.Cipher._encodeCipherText(cp)).toThrowError();

      // iv too long
      cp.iv = new Uint8Array(cs.IV_BYTES + 1);
      expect(() => cs.Cipher._encodeCipherText(cp)).toThrowError();

      // iv ok, salt too short
      cp.iv = new Uint8Array(cs.IV_BYTES);
      cp.slt = new Uint8Array(0);
      expect(() => cs.Cipher._encodeCipherText(cp)).toThrowError();

      // salt too long
      cp.slt = new Uint8Array(cs.SLT_BYTES + 1);
      expect(() => cs.Cipher._encodeCipherText(cp)).toThrowError();

      // slt ok, hint too long
      cp.slt = new Uint8Array(cs.SLT_BYTES);
      cp.hint = 'try a hint that is more than 128 chars, it should throw an error.......................................................................';
      expect(() => cs.Cipher._encodeCipherText(cp)).toThrowError();

      // make sure we're good...
      cp.hint = 'better';
      expect(() => cs.Cipher._encodeCipherText(cp)).not.toThrowError();

      // ic too large
      cp.ic = cs.ICOUNT_MAX + 1;
      expect(() => cs.Cipher._encodeCipherText(cp)).toThrowError();

      // ic too small
      cp.ic = -1;
      expect(() => cs.Cipher._encodeCipherText(cp)).toThrowError();

      // invalid alg
      cp.ic = cs.ICOUNT_DEFAULT;
      cp.alg = 'AES-XYV';
      expect(() => cs.Cipher._encodeCipherText(cp)).toThrowError();

      cp.ic = cs.ICOUNT_DEFAULT;
      cp.alg = '';
      expect(() => cs.Cipher._encodeCipherText(cp)).toThrowError();

      // make sure end good...
      cp.alg = 'AES-GCM';
      expect(() => cs.Cipher._encodeCipherText(cp)).not.toThrowError();

   });

   it("detect invalid CParams decode", function () {

      // initially valid
      let cp = {
         alg: 'X20-PLY',
         ic: 2000000,
         iv: new Uint8Array(24),
         slt: new Uint8Array(16),
         hint: "don't know",
         et: new Uint8Array(42)
      };
      // Expect we start valie
      expect(() => cs.Cipher.validateCParams(cp)).not.toThrowError();
      let packed = cs.Cipher._encodeCipherText(cp);
      expect(() => cs.Cipher._decodeCipherText(packed)).not.toThrowError();

      packed = cs.Cipher._encodeCipherText(cp);
      // Invalid alrogirthm id
      packed.set([7], 0);
      // So that this should throw an exception
      expect(() => cs.Cipher._decodeCipherText(packed)).toThrowError();

      packed = cs.Cipher._encodeCipherText(cp);
      // Invalid version number
      packed.set([5], 46);
      // So that this should throw an exception
      expect(() => cs.Cipher._decodeCipherText(packed)).toThrowError();

      packed = cs.Cipher._encodeCipherText(cp);
      // This pokes in a zero at the top two bytes of IC, making out of range
      // 44 = ALG_BYTES+IV_BYTES+SLT_BYTES+IC_BYTES-2
      packed.set([0, 0], 44);
      // So that this should throw an exception
      expect(() => cs.Cipher._decodeCipherText(packed)).toThrowError();

      packed = cs.Cipher._encodeCipherText(cp);
      // Change changes the hint length length
      // 48 = ALG_BYTES+IV_BYTES+SLT_BYTES+IC_BYTES+VER_BYTES
      packed.set([75], 48);
      // So that this should throw an exception
      expect(() => cs.Cipher._decodeCipherText(packed)).toThrowError();

      // shortest valid CParams
      cp = {
         alg: 'X20-PLY',
         ic: 2000000,
         iv: new Uint8Array(24),
         slt: new Uint8Array(16),
         hint: "",
         et: new Uint8Array(1)
      }
      // Expect we start valid
      packed = cs.Cipher._encodeCipherText(cp);
      expect(() => cs.Cipher._decodeCipherText(packed)).not.toThrowError();

      // should be too short with 1 byte removed
      let sliced = packed.slice(0, packed.byteLength - 1);
      expect(() => cs.Cipher._decodeCipherText(sliced)).toThrowError();

   });

});

describe("Base64 encode decode", function () {
   it("random bytes", function () {
      const rb = crypto.getRandomValues(new Uint8Array(43))
      const b64 = cs.bytesToBase64(rb);
      expect(b64.length).toBeGreaterThanOrEqual(rb.byteLength);
      expect(isEqualArray(rb, cs.base64ToBytes(b64))).toBeTrue();
   });
});

describe("Random40 tests", function () {
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
      await expectAsync(rand.getRandomArray(false, false)).toBeRejectedWithError();
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
