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
import { CipherService, EParams } from './cipher.service';
import { Ciphers } from './ciphers';
import { readStreamFill, readStreamUntil, base64ToBytes, bytesToBase64 } from './utils';

describe('CipherService', () => {
   let cipherSvc: CipherService;
   beforeEach(() => {
      TestBed.configureTestingModule({});
      Ciphers.testingFlag = true;
      cipherSvc = TestBed.inject(CipherService);
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

describe("Encryption and decryption", function () {

   let cipherSvc: CipherService;
   beforeEach(() => {
      TestBed.configureTestingModule({});
      Ciphers.testingFlag = true;
      cipherSvc = TestBed.inject(CipherService);
   });

   it("successful round trip, all algorithms, no pwd hint", async function () {

      for (const alg of cipherSvc.algs()) {

         const clearText = 'This is a secret 🦆';
         const pwd = 'a good pwd';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

         const eparams: EParams = {
            alg: alg,
            ic: cc.ICOUNT_MIN,
            trueRand: false,
            fallbackRand: true,
            pwd: pwd,
            userCred: userCred,
         };

         const cipherText = await cipherSvc.encryptString(
            eparams,
            clearText,
            (params) => {
               expect(params.alg).toBe(alg);
               expect(params.ic).toBe(cc.ICOUNT_MIN);
            }
         );

         const decrypted = await cipherSvc.decryptString(
            async (decHint) => {
               expect(decHint).toBe('');
               return pwd;
            },
            userCred,
            cipherText,
            (params) => {
               expect(params.alg).toBe(alg);
               expect(params.ic).toBe(cc.ICOUNT_MIN);
            }
         );
         expect(decrypted).toBe(clearText);
      }
   });


   it("successful round trip, all algorithms", async function () {

      for (const alg of cipherSvc.algs()) {

         const clearText = 'This is a secret 🦆';
         const pwd = 'a good pwd';
         const hint = 'not really';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

         /*    Used to generate CTS in: detect corrupt cipher text
               const clearText = "this 🐞 is encrypted";
               const pwd = 'asdf';
               const hint = 'asdf';
               const userCred = new Uint8Array([101, 246, 72, 149, 67, 228, 149, 35, 60, 124, 81, 187, 157, 96, 208, 217, 123, 147, 228, 60, 84, 214, 198, 116, 192, 162, 178, 147, 50, 119, 97, 251]);
*/
         const eparams: EParams = {
            alg: alg,
            ic: cc.ICOUNT_MIN,
            trueRand: false,
            fallbackRand: true,
            pwd: pwd,
            hint: hint,
            userCred: userCred,
         };

         const cipherText = await cipherSvc.encryptString(
            eparams,
            clearText,
            (params) => {
               expect(params.alg).toBe(alg);
               expect(params.ic).toBe(cc.ICOUNT_MIN);
            }
         );
//         console.log(alg + ": " + cipherText.length + ": " + cipherText);

         const decrypted = await cipherSvc.decryptString(
            async (decHint) => {
               expect(decHint).toBe(hint);
               return pwd;
            },
            userCred,
            cipherText,
            (params) => {
               expect(params.alg).toBe(alg);
               expect(params.ic).toBe(cc.ICOUNT_MIN);
            }
         );
         //      console.log(alg + ": '" + decrypted + "'");
         expect(decrypted).toBe(clearText);
      }
   });

   it("confirm successful version decryption", async function () {
      // These are generated with running website
      const cts = [
         // AEG-GCM: V1, V4
         '4FhRcUaBCS6rrfj8pmkyclbGORk-nVoo-Epq_0NZ3E0BAEE8XuQyAPODSpDZLh9fCrOSLERyCwWq9rzth9VAdxsAAQAV3pKmSTgTx99M_cAWV51Z2AFzgXyEQk-iZznhBgEsdTvIlwTdet5j7a8FqrlMlZiQRvlvLhOgAvsO0n5Pxkhxhv-lK9mLQ670gilLRTrRR-pKATz4hGMWIDCgC4ojnOMwluTtK0XosZ0dCcSy9nMgIhWP5co-LWwr-NWsY29uXFC9WZI5ZA4Ujt1BAsv-gUe7vhwFcPLkhFGgc6tIeo4ObcSm7oC7z4AjTQ9WtURpvgwoqA9ovHEMum2ViGSifXlemw304KMKGDQgsM3Fn9YacZjJO0YYMyiNi48ywQVCNkw_Fvo',
         'y0SaxQp26pd_UopQ0QRXPgI1jkT4FLZvrORdOIBXlzoEAAYBAAABAM9IezkEqREmcKPz7uc1cB92dbdotcUXT7hgaaBAdxsAFaQv7dZzGLwXv0QM6wuIYXIbusLB9ioNmLXY7ZuQ_X8k5ToM1tfNO5Y9QXzJ7QtIKeHmprBILRuk56mVGmec4VfmHVWc5ibavRuq7mYPEONH0P6LESxP3wqE9wkNvrrxEOvAtsrrC1zqlKDsLkJLG8vc5gM_9wLuRrP3mjLKHFlSuw37KGp4MnwovrQMHukTlNFHSYeK4jBBIGu0makpYh6NyM5e9vszbaXxqPe5mTdgV6498oepCmhV-lAh26rjwUZ6cdYuT6Ql-9YodLhxFRSmLC_8CEX8GHZuFoeiCNkicYOc',

         // XChaCha: V1, V4
         'D0WSIi0s18fTxqsg5CGOHV3boHS7yaCo9AGOmWM8G30CAKFIuXF7m1ZxGo4bL6P7SaXqw-IIv8N9ZKR44xaZKIdgys4pysPqkIRAdxsAAQAVSEeOnFNPWdrAli-fyq8dWfUK2aBmXWF7T6vt06Fl5ehzCOh9DtT4W6uckFBh7S_VFBpmeh1_VN1WWAVV-PUB8HvIRtrVAoRiZy6H-BhkOaZflJnIQpu15AkrZC5aY8e4ulwiWIrV_ep88a963_B5mme9TaVZyzeXuBbo6xFOuGsVoPybjU-DWBDKK3i2rGju62NOlthYTn3eP3e2UuT_wIt1IB30XNO3dsxmcKQAW70GwSDvlGH-KnNqoUw3BUf07PlOYaiP0YfwqxZa7Mr4FjZ-sgTZTg2yKB0Xc-LeuuRprvs',
         'Ul5PloDpBMvn_D6S9RuIaj7Xu5RhQk_CNJv5Ttueg-MEABIBAAACAOg3nkrGoM6kd663ABirC6EVHAdq6mSCNlxSLcwOd8I_YRszMP-YalNAdxsAFbSBMyQ53PFVP1aoUZ7-PW_vNgq3Uv4vRceAWZZtRWiqOPkxtW7nmG0dlCPoVIYdCXi-FxIVyAJRSc6cUUEzITKQqyUDIqgeyErhmURWToVhHItNESwJIC7Vn0zW0MRWIs2msx_Xclz_k7vIzTWVUm_Uu_e4kghWNWTvC9vdmBg3duY6z1_GTyPi2aS7B-awVN6Y9toODSVR5dGKwbR7CQczIXh18X7rNTHizVtekFYhKvyWWgdLTMcuGiA8p6ebAPNFLYCl9eyM2dihIw1FnHrpmAxb0bk9FAEs8FM79YjHvJVU',

         // AEGIS: V1, V4
         'ZhiPRZ7YOIjWXEMBFmyZsSWwor9WNId6oPXqBgJmCxkDAMCrHZhWSw5s_dZzPc-k9R2TqHmrs-8kYl2YCxT3PblxGLL51besQyoLQsuJHYvKGUB3GwABACXwMpAj4tQpvDM0yLAUJWwWFpSPHMxwMtxvB6xUvbQQDRdzkm1rFPPYm_PfWPXh_vekCrJTjXCp22hvGCr9NhPTCxnhrPu4hpVkIaPawZ77bB6uAoXI8htcZoLrf2CuSx2-F-v7XRCNYtFfOpwLQQx1u_df4xpFZWXwz_pZafMN6dvbYniu3-x4Iwcj1RtzqOajBPrgMO143pTu9n2LlKUkeUVR3VmeJIFeXhdbUaVWo498Jeboltf7XLUGy--Ox5yVFaCcmPiYUZFe0UolFPJLPIAEHB4Smdw83LoHwwjgjedzvuyzi5SHpq03OYME87dUQBVdgIDwaxwIyJDxpbLvXP9P',
         '_ec1F_Gme1ydJHBVEVRz0W-6yXzFG6psnN2ptLTzfm4EADoBAAADAGIQU9XkWCAVWNBX9jthhM2J_7-BaCmDhTIm56hvNHALl89E8t7HZwFd4tWH19mk0kB3GwAlPG0kg10bo2T_07Ent1LaEt0N1579OiJvN8WVth0H9ToYUFLqwYrEuiGesaWlF3GABL3Fpw7k5RACncuNftVy7O59yCzqBxReo8RH8oDO2cyedywojhwy_LwX_RHCf4CtdxaO80JzRDn3UkVTOB7Vurx-DWvzyEXFOeI8REEg43BAHG4I-ed8SyBVk2XHRceo2u8nv19wlnhxjYw0UycA5CHIXF6T7S3P8bOfgxenGOn7xfjEddQqOa-GyNl-2njEcPzrkHnBxDvs4clGK4LjgUAAi_9WqdgmC6m-V3Lv8iP-APSUYb7CXU5JWkk-1JpMorslki63eBU5tHZfd8GsRrGOyA',
      ];

      for (let ct of cts) {
         const ctBytes = base64ToBytes(ct);
         // userCred used for creation of the CTS above
         // b64url userCred for browsser injection: xhKm2Q404pGkqfWkTyT3UodUR-99bN0wibH6si9uF8I
         const userCred = new Uint8Array([198, 18, 166, 217, 14, 52, 226, 145, 164, 169, 245, 164, 79, 36, 247, 82, 135, 84, 71, 239, 125, 108, 221, 48, 137, 177, 250, 178, 47, 110, 23, 194]);
         const clearCheck = 'physical farm bolt correct bee nonchalant glib high able pinch left quaint strip valuable exultant disgusted curved bless geese snatch zoom fat touch boot abject wink pretty accessible foamy';
         const hintCheck = 'royal';
         const pwd = '9j5J4QnKD3D2R7Ks5gAAa';

         const clear = await cipherSvc.decryptString(
            async (hint) => {
               expect(hint).toBe(hintCheck);
               return pwd;
            },
            userCred,
            ct
         );

         expect(clear).toBe(clearCheck);
      }
   });

   // using  base64-url alphabet
   const b64a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
   const b64o = 'BCDEFGHIJKLMNOPQRSTUVWXYZAbcdefghijklmnopqrstuvwxyza1234567890_-';

   it("detect corrupt cipher text", async function () {
      //AES-GCM, X20-PLY, AEGIS-256
      const cts = [
         "ExHzC-I423iEmmIYcEiKUPXuDxs38c7XxYeIH5VserwBAF3A8dWm0OuY2__I0OEGuZQ5a_bNMWm5o638mfKAGgYAAQAUcwbniou1lvVl4JeH_OlRdUtkdfznC-1mRl6oSUVWaH7ZgRz2MLMLr-6F2vCVa6UiXLZt_j_ZGfJoiA",
         "ualvQTnXR9Qpmc6GpCqq6RcCoOV5An5XXfaNlBkagqcCADMNs_2x3EsdGpYpsoRPYSKGMLUN_wjYbCOy060g4nEU5-ZuTN31SGGAGgYAAQAUWACcspBFLRVnwqCNuJZD4HMu7vxB9nc6qrV5U-Faob2RnUDlTl9g-vbu4y3j8NeHzkU7LvmX6NwNDA",
         "lr-eRI1od9LvRqeQImYd9ZVd-Mbc9_Z2kjQYCOOJ9PEDAKAcZiMeYGvwmPooMw4R4Qn8ifLQaqitpXjKL2v3BHGraM9YtogMkVNkKmBrhc7GVoAaBgABACRnRmxD29B5d3pP-Bck_Y9CFnL8DTX-imq1opljFiNRc4CvehpKN8VGWxVQxiNBcPzSkV9ZMZ8lMZma_nakSq78T4mh1Y6pS9GRWxnFPIbq4aGaDy5-tJ_0-ww"
      ];

      for (let ct of cts) {
         const ctBytes = base64ToBytes(ct);
         // userCred used for creation of the CTS above
         const userCred = new Uint8Array([101, 246, 72, 149, 67, 228, 149, 35, 60, 124, 81, 187, 157, 96, 208, 217, 123, 147, 228, 60, 84, 214, 198, 116, 192, 162, 178, 147, 50, 119, 97, 251]);

         // First ensure we can decrypt with valid inputs
         const clear = await cipherSvc.decryptString(
            async (hint) => {
               expect(hint).toBe("asdf");
               return "asdf";
            },
            userCred,
            ct
         );
         expect(clear).toBe("this 🐞 is encrypted");

         let skipCount = 0;

         // Tweak on character at a time using b64o offsets (will remain a valid b64 string)
         for (let i = 0; i < ct.length; ++i) {
            const pos = b64a.indexOf(ct[i]);
            let corruptCt = setCharAt(ct, i, b64o[pos]);

            var corruptBytes = base64ToBytes(corruptCt);

            // Multiple b64 strings can produce the same result, so skip those
            if (isEqualArray(ctBytes, corruptBytes!)) {
               ++skipCount;
               expect(skipCount).toBeLessThan(10);
               continue;
            }

            await expectAsync(
               cipherSvc.decryptString(
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

   it("detect valid MAC wrong password, all alogrithms", async function () {
      for (const alg of cipherSvc.algs()) {
         const clearText = 'This is a secret 🦄';
         const pwd = 'the correct pwd';
         const hint = '';
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

         const cipherText = await cipherSvc.encryptString(eparams, clearText);

         await expectAsync(
            cipherSvc.decryptString(
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

   it("detect corrupted MAC sig, all algorithms", async function () {

      for (const alg of cipherSvc.algs()) {

         const clearText = "asefwlefj4oh09f jw90fu w09fu 9";
         const pwd = 'another good pwd';
         const hint = 'nope';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

         const eparams: EParams = {
            alg: alg,
            ic: cc.ICOUNT_MIN,
            trueRand: false,
            fallbackRand: true,
            pwd: pwd,
            hint: hint,
            userCred: userCred
         };

         let cipherText = await cipherSvc.encryptString(eparams, clearText);

         // Set character in MAC
         cipherText = setCharAt(cipherText, 3, cipherText[3] == 'a' ? 'b' : 'a');

         await expectAsync(
            cipherSvc.decryptString(
               async (decHint) => {
                  expect(decHint).toBe(hint);
                  return pwd;
               },
               userCred,
               cipherText
            )
         ).toBeRejectedWithError(Error, new RegExp('.+MAC.+'));
      }
   });

   it("detect crafted bad cipher text, all algorithms", async function () {

      for (const alg of cipherSvc.algs()) {
         const clearText = "asdfh3roij 02f23kff 8u 3r90";
         const pwd = 'another good pwd';
         const hint = 'nope';
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

         let cipherText = await cipherSvc.encryptString(eparams, clearText);

         // Set character in cipher text
         // past ~(MAC + VER + ALG + MAX_IV + CHUCKSZ)*4/3 characters)
         let problemText = setCharAt(cipherText, 100, cipherText[100] == 'a' ? 'b' : 'a');

         await expectAsync(
            cipherSvc.decryptString(
               async (decHint) => {
                  // Should never execute
                  expect(false).toBe(true);
                  return pwd;
               },
               userCred,
               problemText
            )
         ).toBeRejectedWithError(Error, new RegExp('.+MAC.+'));

         // Set character in encyrpted hint
         // back ~(IC + SLT *4/3 characters) from end
         problemText = setCharAt(cipherText, cipherText.length - 30, cipherText[cipherText.length - 30] == 'c' ? 'e' : 'c');

         await expectAsync(
            cipherSvc.decryptString(
               async (decHint) => {
                  // Should never execute
                  expect(false).toBe(true);
                  return pwd;
               },
               userCred,
               problemText
            )
         ).toBeRejectedWithError(Error, new RegExp('.+MAC.+'));
      }
   });


   it("detect encryption argument errors", async function () {

      const hint = 'nope';
      const pwd = 'another good pwd';
      const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));
      const clearText = "()*Hskdfo892hj3f09";

      const eparams: EParams = {
         alg: 'AES-GCM',
         ic: cc.ICOUNT_MIN,
         trueRand: false,
         fallbackRand: true,
         pwd: pwd,
         hint: hint,
         userCred: userCred,
      };
      // ensure the defaults work
      await expectAsync(
         cipherSvc.encryptString(eparams, clearText)
      ).not.toBeRejectedWithError();

      // empty pwd
      let bparams = {
         ...eparams,
         pwd: ''
      }
      await expectAsync(
         cipherSvc.encryptString(bparams, clearText)
      ).toBeRejectedWithError(Error, new RegExp('.+userCred.*'));

      // no userCred
      bparams = {
         ...eparams,
         userCred: new Uint8Array(0)
      }
      await expectAsync(
         cipherSvc.encryptString(bparams, clearText)
      ).toBeRejectedWithError(Error, new RegExp('.+userCred.*'));

      // extra long userCred
      bparams = {
         ...eparams,
         userCred: crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES + 2))
      }
      await expectAsync(
         cipherSvc.encryptString(bparams, clearText)
      ).toBeRejectedWithError(Error, new RegExp('.+userCred.*'));

      // empty clear data
      bparams = {
         ...eparams
      }
      await expectAsync(
         cipherSvc.encryptString(bparams, '')
      ).toBeRejectedWithError(Error, new RegExp('Missing clear.+'));

      // ic too small
      bparams = {
         ...eparams,
         ic: cc.ICOUNT_MIN - 1
      }
      await expectAsync(
         cipherSvc.encryptString(bparams, clearText)
      ).toBeRejectedWithError(Error, new RegExp('Invalid ic.+'));

      // ic too big
      bparams = {
         ...eparams,
         ic: cc.ICOUNT_MAX + 1
      }
      await expectAsync(
         cipherSvc.encryptString(bparams, clearText)
      ).toBeRejectedWithError(Error, new RegExp('Invalid ic.+'));

      // invalid alg
      bparams = {
         ...eparams,
         alg: 'ABS-GCM'
      }
      await expectAsync(
         cipherSvc.encryptString(bparams, clearText)
      ).toBeRejectedWithError(Error, new RegExp('Invalid alg.+'));

      // really invalid alg
      bparams = {
         ...eparams,
         alg: 'asdfadfsk'
      }
      await expectAsync(
         cipherSvc.encryptString(bparams, clearText)
      ).toBeRejectedWithError(Error, new RegExp('Invalid alg.+'));

      // both rands false
      bparams = {
         ...eparams,
         trueRand: false,
         fallbackRand: false
      }
      await expectAsync(
         cipherSvc.encryptString(bparams, clearText)
      ).toBeRejectedWithError(Error, new RegExp('Either trueRand.+'));

      // hint too long
      bparams = {
         ...eparams,
         hint: 'this is too long'.repeat(8)
      }
      await expectAsync(
         cipherSvc.encryptString(bparams, clearText)
      ).toBeRejectedWithError(Error, new RegExp('Hint length.+'));

   });
});


describe("Benchmark execution", function () {

   let cipherSvc: CipherService;
   beforeEach(() => {
      TestBed.configureTestingModule({});
      Ciphers.testingFlag = true;
      cipherSvc = TestBed.inject(CipherService);
   });

   it("reasonable benchmark results", async function () {
      const [icount, icountMax, hashRate] = await cipherSvc.benchmark(cc.ICOUNT_MIN, 500, 5 * 60 * 1000);
      expect(icount).toBeGreaterThanOrEqual(cc.ICOUNT_DEFAULT);
      expect(icount).toBeLessThanOrEqual(cc.ICOUNT_MAX);
      expect(icountMax).toBeGreaterThanOrEqual(icount);
      expect(icountMax).toBeLessThanOrEqual(cc.ICOUNT_MAX);
      expect(hashRate).toBeGreaterThanOrEqual(1);
      expect(hashRate).toBeLessThanOrEqual(100000);
   });

});

describe("Cipher alg validate", function () {

   let cipherSvc: CipherService;
   beforeEach(() => {
      TestBed.configureTestingModule({});
      Ciphers.testingFlag = true;
      cipherSvc = TestBed.inject(CipherService);
   });

   it("detect invalid alg", async function () {
      expect(cipherSvc.validateAlg('AES_GCM')).toBeFalse();
      expect(cipherSvc.validateAlg('')).toBeFalse();
      expect(cipherSvc.validateAlg('f2f33flin2o23f2j3f90j2')).toBeFalse();
   });

   it("should be valid algs", async function () {
      expect(cipherSvc.validateAlg('AES-GCM')).toBeTrue();
      expect(cipherSvc.validateAlg('X20-PLY')).toBeTrue();
      expect(cipherSvc.validateAlg('AEGIS-256')).toBeTrue();
   });

});

describe("Get cipherinfo from cipher text", function () {

   let cipherSvc: CipherService;
   beforeEach(() => {
      TestBed.configureTestingModule({});
      Ciphers.testingFlag = true;
      cipherSvc = TestBed.inject(CipherService);
   });

   it("expected CipherInfo, all algorithms", async function () {

      for (const alg of cipherSvc.algs()) {

         const clearText = 'This is a secret 🦋';
         const pwd = 'not good pwd';
         const hint = 'try a himt';
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
         const cipherText = await cipherSvc.encryptString(eparams, clearText);
         const cipherInfo = await cipherSvc.getCipherTextInfo(userCred, cipherText);

         const expected_iv_bytes = Number(cc.AlgInfo[alg]['iv_bytes']);

         expect(cipherInfo.alg).toBe(alg);
         expect(cipherInfo.ic).toBe(cc.ICOUNT_MIN);
         expect(cipherInfo.iv.byteLength).toBe(expected_iv_bytes);
         expect(cipherInfo.slt.byteLength).toBe(cc.SLT_BYTES);
         expect(cipherInfo.hint).toBeTrue();
      }
   });

   it("detect corrupted cipherdata MAC, all algorithms", async function () {

      for (const alg of cipherSvc.algs()) {

         const clearText = "OIH8whfsiodhf s.kd";
         const pwd = 'another good pwd';
         const hint = 'nope';
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

         let cipherText = await cipherSvc.encryptString(eparams, clearText);

         // Set character in CipherData
         cipherText = setCharAt(cipherText, 37, cipherText[37] == 'a' ? 'b' : 'a');

         await expectAsync(
            cipherSvc.getCipherTextInfo(
               userCred,
               cipherText
            )
         ).toBeRejectedWithError(Error, new RegExp('.+MAC.+'));
      }
   });

   it("detect invalid userCred", async function () {

      const clearText = "f";
      const pwd = 'another good pwd';
      const hint = 'nope';
      const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

      const eparams: EParams = {
         alg: 'AES-GCM',
         ic: cc.ICOUNT_MIN,
         trueRand: false,
         fallbackRand: true,
         pwd: pwd,
         hint: hint,
         userCred: userCred,
      };
      let cipherText = await cipherSvc.encryptString(eparams, clearText);

      // Doesn't match orignal userCred
      let problemUserCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));
      await expectAsync(
         cipherSvc.getCipherTextInfo(
            problemUserCred,
            cipherText
         )
      ).toBeRejectedWithError(Error, new RegExp('.+MAC.+'));

      // Missing one byte of userCred
      problemUserCred = userCred.slice(0, userCred.byteLength - 1);
      await expectAsync(
         cipherSvc.getCipherTextInfo(
            problemUserCred,
            cipherText
         )
      ).toBeRejectedWithError(Error);

      // One bytes extra
      problemUserCred = new Uint8Array(cc.USERCRED_BYTES + 1);
      problemUserCred.set(userCred);
      problemUserCred.set([0], userCred.byteLength);
      await expectAsync(
         cipherSvc.getCipherTextInfo(
            problemUserCred,
            cipherText
         )
      ).toBeRejectedWithError(Error);
   });
});
