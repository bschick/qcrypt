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

describe("Encrypt and Decrypt", function () {

   it("successful round trip all algorithms", async function () {

      for (let alg in cs.AlgInfo) {
         //      console.log(alg);

         const clearText = 'This is a secret 🦆';
         const pwd = 'a good pwd';
         const hint = 'not really';
         const singature = crypto.getRandomValues(new Uint8Array(32));

         let cipher = new cs.Cipher(alg, cs.ICOUNT_MIN, false, true);
         let clearEnc = new TextEncoder().encode(clearText);

         const cipherText = await cipher.encrypt(pwd, hint, singature, clearEnc);
         //      console.log(cipherText.length + ": " + cipherText);

         const decrypted = await cs.Cipher.decrypt(
            async (decHint) => {
               expect(decHint).toBe(hint);
               return pwd;
            },
            singature,
            cipherText
         );
         const clearTest = new TextDecoder().decode(decrypted);
         //      console.log(alg + ": '" + clearTest + "'");
         expect(clearTest).toBe(clearText);
      }
   });

   it("corrupted hmac sig all algorithms", async function () {

      for (let alg in cs.AlgInfo) {

         const clearEnc = crypto.getRandomValues(new Uint8Array(16));
         const pwd = 'another good pwd';
         const hint = 'nope';
         const singature = crypto.getRandomValues(new Uint8Array(32));

         let cipher = new cs.Cipher(alg, cs.ICOUNT_MIN, false, true);

         let cipherText = await cipher.encrypt(pwd, hint, singature, clearEnc);

         // Set character in HMAC
         cipherText = setCharAt(cipherText, 3, cipherText[3] == 'a' ? 'b' : 'a');

         await expectAsync(
            cs.Cipher.decrypt(
               async (decHint) => {
                  expect(decHint).toBe(hint);
                  return pwd;
               },
               singature,
               cipherText
            )
         ).toBeRejectedWithError();
      }
   });

   it("corrupted cipher text all algorithms", async function () {

      for (let alg in cs.AlgInfo) {
         const clearEnc = crypto.getRandomValues(new Uint8Array(16));
         const pwd = 'another good pwd';
         const hint = 'nope';
         const singature = crypto.getRandomValues(new Uint8Array(32));

         let cipher = new cs.Cipher(alg, cs.ICOUNT_MIN, false, true);

         let cipherText = await cipher.encrypt(pwd, hint, singature, clearEnc);

         // Set character in cipher text (past first ~32*4/3 characters) 
         // this changes the hint
         cipherText = setCharAt(cipherText, 108, cipherText[108] == 'a' ? 'b' : 'a');

         await expectAsync(
            cs.Cipher.decrypt(
               async (decHint) => {
                  expect(decHint).toBe(hint);
                  return pwd;
               },
               singature,
               cipherText
            )
         ).toBeRejectedWithError();
      }
   });
});


describe("Get cipher params from cipher text", function () {

   it("successful params all algorithms", async function () {

      for (let alg in cs.AlgInfo) {

         const clearText = 'This is a secret 🦋';
         const pwd = 'not good pwd';
         const hint = 'try a himt';
         const singature = crypto.getRandomValues(new Uint8Array(49));

         let cipher = new cs.Cipher(alg, cs.ICOUNT_MIN, false, true);
         let clearEnc = new TextEncoder().encode(clearText);

         const cipherText = await cipher.encrypt(pwd, hint, singature, clearEnc);

         const cparams = await cs.Cipher.getCipherParams(
            async (decHint) => {
               expect(decHint).toBe(hint);
               return pwd;
            },
            singature,
            cipherText
         );

         expect(cparams.alg).toBe(alg);
         expect(cparams.ic).toBe(cs.ICOUNT_MIN);
         expect(cparams.iv.byteLength).toBe(cs.IV_BYTES);
         expect(cparams.slt.byteLength).toBe(cs.SLT_BYTES);
         expect(cparams.et.byteLength).toBeGreaterThanOrEqual(clearEnc.byteLength);
      }
   });

   it("corrupted params sig all algorithms", async function () {

      for (let alg in cs.AlgInfo) {

         const clearEnc = crypto.getRandomValues(new Uint8Array(16));
         const pwd = 'another good pwd';
         const hint = 'nope';
         const singature = crypto.getRandomValues(new Uint8Array(32));

         let cipher = new cs.Cipher(alg, cs.ICOUNT_MIN, false, true);

         let cipherText = await cipher.encrypt(pwd, hint, singature, clearEnc);

         // Set character in CParams
         cipherText = setCharAt(cipherText, 37, cipherText[37] == 'a' ? 'b' : 'a');

         await expectAsync(
            cs.Cipher.getCipherParams(
               async (decHint) => {
                  expect(decHint).toBe(hint);
                  return pwd;
               },
               singature,
               cipherText
            )
         ).toBeRejectedWithError();
      }
   });
});

describe("Cipher object creation", function () {

   it("Valid construction all algs", function () {
      for (let alg in cs.AlgInfo) {
         const cipher = new cs.Cipher(alg, 2000000, false, true);
         expect(cipher.ic).toBe(2000000);
         expect(cipher.alg).toBe(alg);
         expect(cipher.trueRand).toBe(false);
         expect(cipher.fallbackRand).toBe(true);
      }
   });

   it("Invalid construction", function () {
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

   it("Valid CParams", function () {
      const cp = {
         alg: 'X20-PLY',
         ic: 2000000,
         iv: crypto.getRandomValues(new Uint8Array(24)),
         slt: crypto.getRandomValues(new Uint8Array(16)),
         hint: "don't know",
         et: crypto.getRandomValues(new Uint8Array(42))
      }

      const packed = cs.Cipher.encode(cp);
      const rcp = cs.Cipher.decode(packed);

      expect(rcp.alg).toBe(cp.alg);
      expect(rcp.ic).toBe(cp.ic);
      expect(isEqualArray(rcp.iv, cp.iv)).toBeTrue();
      expect(isEqualArray(rcp.slt, cp.slt)).toBeTrue();
      expect(rcp.hint).toBe(cp.hint);
      expect(isEqualArray(rcp.et, cp.et)).toBeTrue();
   });

   it("Invalid CParams encode", function () {

      //valid
      let cp = {
         alg: 'X20-PLY',
         ic: cs.ICOUNT_MIN,
         iv: new Uint8Array(cs.IV_BYTES), 
         slt: new Uint8Array(cs.SLT_BYTES),
         hint: "",
         et: new Uint8Array(1)
      }
      expect(() => cs.Cipher.encode(cp)).not.toThrowError();

      // iv too short
      cp.iv = new Uint8Array(cs.IV_BYTES - 1);
      expect(() => cs.Cipher.encode(cp)).toThrowError();

      // too big
      // iv too short
      cp.iv = new Uint8Array(cs.IV_BYTES + 1);
      expect(() => cs.Cipher.encode(cp)).toThrowError();

      cp.iv = new Uint8Array(cs.IV_BYTES);
      cp.hint = 'try a hit that is more than 128 chars, it should be clipped at 128.......................................................................';
      expect(() => cs.Cipher.encode(cp)).toThrowError();
   });

   it("Invalid CParams decode", function () {

      // packed version of the following (with invalid IC). 
      let cp = {
         alg: 'X20-PLY',
         ic: 2000000,
         iv: new Uint8Array(24),
         slt: new Uint8Array(16),
         hint: "don't know",
         et: new Uint8Array(42)
      };

      let packed = cs.Cipher.encode(cp);
      // Invalid alrogirthm id
      packed.set([7], 0);
      // So that this should throw an exception
      expect(() => cs.Cipher.decode(packed)).toThrowError();

      packed = cs.Cipher.encode(cp);
      // Invalid version number
      packed.set([5], 46);
      // So that this should throw an exception
      expect(() => cs.Cipher.decode(packed)).toThrowError();

      packed = cs.Cipher.encode(cp);
      // This pokes in a zero at the top two bytes of IC, making out of range
      // 44 = ALG_BYTES+IV_BYTES+SLT_BYTES+IC_BYTES-2
      packed.set([0, 0], 44);
      // So that this should throw an exception
      expect(() => cs.Cipher.decode(packed)).toThrowError();

      packed = cs.Cipher.encode(cp);
      // Change changes the hint length length
      // 48 = ALG_BYTES+IV_BYTES+SLT_BYTES+IC_BYTES+VER_BYTES
      packed.set([75], 48);
      // So that this should throw an exception
      expect(() => cs.Cipher.decode(packed)).toThrowError();

      // shortest valid CParams
      cp = {
         alg: 'X20-PLY',
         ic: 2000000,
         iv: new Uint8Array(24),
         slt: new Uint8Array(16),
         hint: "",
         et: new Uint8Array(1)
      }
      packed = cs.Cipher.encode(cp);
      // should be too short with 1 byte removed
      let sliced = packed.slice(0, packed.byteLength - 1);
      expect(() => cs.Cipher.decode(sliced)).toThrowError();

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

   it("overflow check", function () {
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
