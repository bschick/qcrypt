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
import { CipherService, EncContext3 } from './cipher.service';
import { Ciphers } from './ciphers';
import {
   readStreamAll,
   base64ToBytes,
   BYOBStreamReader
} from './utils';

jasmine.DEFAULT_TIMEOUT_INTERVAL = 10000;

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

// Faster than .toEqual, resulting in few timeouts
async function areEqual(
   a: Uint8Array | ReadableStream<Uint8Array>,
   b: Uint8Array | ReadableStream<Uint8Array>
): Promise<boolean> {

   if(a instanceof ReadableStream) {
      a = await readStreamAll(a);
   }
   if(b instanceof ReadableStream) {
      b = await readStreamAll(b);
   }

//   console.log("a", a);
//   console.log("b", b);

   if (a.byteLength != b.byteLength) {
//      console.log("false1");
      return false;
   }

   for (let i = 0; i < a.byteLength; ++i) {
      if (a[i] != b[i]) {
//         console.log("false2", i, a[i],  b[i]);
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

// sometime is seems like javascript tried to make things hard
function pokeValue(src: Uint8Array, index: number, shift: number): Uint8Array {
   const dst = new Uint8Array(src);
   dst[index] += shift;
   return dst;
}

const READ_SIZE_START = 1048576; // 1 MiB

function randomBlob(byteLength: number): Blob {
   // Create on max-size array and repeate it
   const randData = crypto.getRandomValues(new Uint8Array(512));
   const count = Math.ceil(byteLength / 512);

   let arr = new Array<Uint8Array>;
   for (let i = 0; i < count; ++i) {
      arr.push(randData);
   }
   return new Blob(arr, { type: 'application/octet-stream' });
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

function streamFromBase64(b64: string) : [ReadableStream<Uint8Array>, Uint8Array] {
   const data = base64ToBytes(b64);
   const blob = new Blob([data], { type: 'application/octet-stream' });
   return [blob.stream(), data];
}

describe("String encryption and decryption", function () {

   let cipherSvc: CipherService;
   beforeEach(() => {
      TestBed.configureTestingModule({});
      Ciphers.testingFlag = true;
      cipherSvc = TestBed.inject(CipherService);
   });

   it("successful round trip, all algorithms, no pwd hint", async function () {

      for (const alg of cipherSvc.algs()) {

         const [clearStream, clearData] = streamFromStr('This is a secret 🦆');
         const pwd = 'a good pwd';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

         const econtext: EncContext3 = {
            alg: alg,
            ic: cc.ICOUNT_MIN,
            trueRand: false,
            fallbackRand: true,
            lpEnd: 1
         };

         const cipherStream = await cipherSvc.encryptStream(
            econtext,
            async (lp, lpEnd) => {
               return [pwd, undefined];
            },
            userCred,
            clearStream,
            (params) => {
               expect(params.alg).toEqual(alg);
               expect(params.ic).toEqual(cc.ICOUNT_MIN);
            }
         );

         const decrypted = await cipherSvc.decryptStream(
            async (lp, lpEnd, decHint) => {
               expect(lp).toEqual(1);
               expect(lpEnd).toEqual(1);
               expect(decHint).toEqual('');
               return [pwd, undefined];
            },
            userCred,
            cipherStream,
            (params) => {
               expect(params.alg).toEqual(alg);
               expect(params.ic).toEqual(cc.ICOUNT_MIN);
            }
         );
         await expectAsync(
            areEqual(decrypted, clearData)
         ).toBeResolvedTo(true);
      }
   });


   it("successful round trip, all algorithms", async function () {

      for (const alg of cipherSvc.algs()) {

         const [clearStream, clearData] = streamFromStr('This is a secret 🦆');
         const pwd = 'a good pwd';
         const hint = 'not really';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

         /*    Used to generate CTS in: detect corrupt cipher text
               const clearData = new TextEncoder().encode("this 🐞 is encrypted");
               const pwd = 'asdf';
               const hint = 'asdf';
               const userCred = new Uint8Array([101, 246, 72, 149, 67, 228, 149, 35, 60, 124, 81, 187, 157, 96, 208, 217, 123, 147, 228, 60, 84, 214, 198, 116, 192, 162, 178, 147, 50, 119, 97, 251]);
*/
         const econtext: EncContext3 = {
            alg: alg,
            ic: cc.ICOUNT_MIN,
            trueRand: false,
            fallbackRand: true,
            lpEnd: 1
         };

         const cipherStream = await cipherSvc.encryptStream(
            econtext,
            async (lp, lpEnd) => {
               return [pwd, hint];
            },
            userCred,
            clearStream,
            (params) => {
               expect(params.alg).toEqual(alg);
               expect(params.ic).toEqual(cc.ICOUNT_MIN);
            }
         );
         //         console.log(alg + ": " + cipherData.length + ": " + cipherData);

         const decrypted = await cipherSvc.decryptStream(
            async (lp, lpEnd, decHint) => {
               expect(lp).toEqual(1);
               expect(lpEnd).toEqual(1);
               expect(decHint).toEqual(hint);
               return [pwd, undefined];
            },
            userCred,
            cipherStream,
            (params) => {
               expect(params.alg).toEqual(alg);
               expect(params.ic).toEqual(cc.ICOUNT_MIN);
            }
         );
         //      console.log(alg + ": '" + decrypted + "'");
         await expectAsync(
            areEqual(decrypted, clearData)
         ).toBeResolvedTo(true);
      }
   });

   it("confirm successful version decryption, v1", async function () {
      // These are generated with running website
      const cts = [
         // AEG-GCM: V1
         '4FhRcUaBCS6rrfj8pmkyclbGORk-nVoo-Epq_0NZ3E0BAEE8XuQyAPODSpDZLh9fCrOSLERyCwWq9rzth9VAdxsAAQAV3pKmSTgTx99M_cAWV51Z2AFzgXyEQk-iZznhBgEsdTvIlwTdet5j7a8FqrlMlZiQRvlvLhOgAvsO0n5Pxkhxhv-lK9mLQ670gilLRTrRR-pKATz4hGMWIDCgC4ojnOMwluTtK0XosZ0dCcSy9nMgIhWP5co-LWwr-NWsY29uXFC9WZI5ZA4Ujt1BAsv-gUe7vhwFcPLkhFGgc6tIeo4ObcSm7oC7z4AjTQ9WtURpvgwoqA9ovHEMum2ViGSifXlemw304KMKGDQgsM3Fn9YacZjJO0YYMyiNi48ywQVCNkw_Fvo',

         // XChaCha: V1
         'D0WSIi0s18fTxqsg5CGOHV3boHS7yaCo9AGOmWM8G30CAKFIuXF7m1ZxGo4bL6P7SaXqw-IIv8N9ZKR44xaZKIdgys4pysPqkIRAdxsAAQAVSEeOnFNPWdrAli-fyq8dWfUK2aBmXWF7T6vt06Fl5ehzCOh9DtT4W6uckFBh7S_VFBpmeh1_VN1WWAVV-PUB8HvIRtrVAoRiZy6H-BhkOaZflJnIQpu15AkrZC5aY8e4ulwiWIrV_ep88a963_B5mme9TaVZyzeXuBbo6xFOuGsVoPybjU-DWBDKK3i2rGju62NOlthYTn3eP3e2UuT_wIt1IB30XNO3dsxmcKQAW70GwSDvlGH-KnNqoUw3BUf07PlOYaiP0YfwqxZa7Mr4FjZ-sgTZTg2yKB0Xc-LeuuRprvs',

         // AEGIS: V1
         'ZhiPRZ7YOIjWXEMBFmyZsSWwor9WNId6oPXqBgJmCxkDAMCrHZhWSw5s_dZzPc-k9R2TqHmrs-8kYl2YCxT3PblxGLL51besQyoLQsuJHYvKGUB3GwABACXwMpAj4tQpvDM0yLAUJWwWFpSPHMxwMtxvB6xUvbQQDRdzkm1rFPPYm_PfWPXh_vekCrJTjXCp22hvGCr9NhPTCxnhrPu4hpVkIaPawZ77bB6uAoXI8htcZoLrf2CuSx2-F-v7XRCNYtFfOpwLQQx1u_df4xpFZWXwz_pZafMN6dvbYniu3-x4Iwcj1RtzqOajBPrgMO143pTu9n2LlKUkeUVR3VmeJIFeXhdbUaVWo498Jeboltf7XLUGy--Ox5yVFaCcmPiYUZFe0UolFPJLPIAEHB4Smdw83LoHwwjgjedzvuyzi5SHpq03OYME87dUQBVdgIDwaxwIyJDxpbLvXP9P',
      ];

      for (let ct of cts) {
         const [cipherStream, cipherData] = streamFromBase64(ct);

         // userCred used for creation of the CTS above
         // b64url userCred for browser injection: xhKm2Q404pGkqfWkTyT3UodUR-99bN0wibH6si9uF8I
         const userCred = new Uint8Array([198, 18, 166, 217, 14, 52, 226, 145, 164, 169, 245, 164, 79, 36, 247, 82, 135, 84, 71, 239, 125, 108, 221, 48, 137, 177, 250, 178, 47, 110, 23, 194]);
         const [_, clearCheck] = streamFromStr('physical farm bolt correct bee nonchalant glib high able pinch left quaint strip valuable exultant disgusted curved bless geese snatch zoom fat touch boot abject wink pretty accessible foamy');
         const hintCheck = 'royal';
         const pwd = '9j5J4QnKD3D2R7Ks5gAAa';

         const clearStream = await cipherSvc.decryptStream(
            async (lp, lpEnd, hint) => {
               expect(hint).toEqual(hintCheck);
               return [pwd, undefined];
            },
            userCred,
            cipherStream
         );

         await expectAsync(
            areEqual(clearStream, clearCheck)
         ).toBeResolvedTo(true);
      }
   });

   /*

   it("confirm successful version decryption, v4", async function () {
      // These are generated with running website
      const cts = [
         // AEG-GCM: V4
         'y0SaxQp26pd_UopQ0QRXPgI1jkT4FLZvrORdOIBXlzoEAAYBAAABAM9IezkEqREmcKPz7uc1cB92dbdotcUXT7hgaaBAdxsAFaQv7dZzGLwXv0QM6wuIYXIbusLB9ioNmLXY7ZuQ_X8k5ToM1tfNO5Y9QXzJ7QtIKeHmprBILRuk56mVGmec4VfmHVWc5ibavRuq7mYPEONH0P6LESxP3wqE9wkNvrrxEOvAtsrrC1zqlKDsLkJLG8vc5gM_9wLuRrP3mjLKHFlSuw37KGp4MnwovrQMHukTlNFHSYeK4jBBIGu0makpYh6NyM5e9vszbaXxqPe5mTdgV6498oepCmhV-lAh26rjwUZ6cdYuT6Ql-9YodLhxFRSmLC_8CEX8GHZuFoeiCNkicYOc',

         // XChaCha: V4
         'Ul5PloDpBMvn_D6S9RuIaj7Xu5RhQk_CNJv5Ttueg-MEABIBAAACAOg3nkrGoM6kd663ABirC6EVHAdq6mSCNlxSLcwOd8I_YRszMP-YalNAdxsAFbSBMyQ53PFVP1aoUZ7-PW_vNgq3Uv4vRceAWZZtRWiqOPkxtW7nmG0dlCPoVIYdCXi-FxIVyAJRSc6cUUEzITKQqyUDIqgeyErhmURWToVhHItNESwJIC7Vn0zW0MRWIs2msx_Xclz_k7vIzTWVUm_Uu_e4kghWNWTvC9vdmBg3duY6z1_GTyPi2aS7B-awVN6Y9toODSVR5dGKwbR7CQczIXh18X7rNTHizVtekFYhKvyWWgdLTMcuGiA8p6ebAPNFLYCl9eyM2dihIw1FnHrpmAxb0bk9FAEs8FM79YjHvJVU',

         // AEGIS: V4
         '_ec1F_Gme1ydJHBVEVRz0W-6yXzFG6psnN2ptLTzfm4EADoBAAADAGIQU9XkWCAVWNBX9jthhM2J_7-BaCmDhTIm56hvNHALl89E8t7HZwFd4tWH19mk0kB3GwAlPG0kg10bo2T_07Ent1LaEt0N1579OiJvN8WVth0H9ToYUFLqwYrEuiGesaWlF3GABL3Fpw7k5RACncuNftVy7O59yCzqBxReo8RH8oDO2cyedywojhwy_LwX_RHCf4CtdxaO80JzRDn3UkVTOB7Vurx-DWvzyEXFOeI8REEg43BAHG4I-ed8SyBVk2XHRceo2u8nv19wlnhxjYw0UycA5CHIXF6T7S3P8bOfgxenGOn7xfjEddQqOa-GyNl-2njEcPzrkHnBxDvs4clGK4LjgUAAi_9WqdgmC6m-V3Lv8iP-APSUYb7CXU5JWkk-1JpMorslki63eBU5tHZfd8GsRrGOyA',
      ];

      for (let ct of cts) {
         const ctBytes = base64ToBytes(ct);
         // userCred used for creation of the CTS above
         // b64url userCred for browsser injection: xhKm2Q404pGkqfWkTyT3UodUR-99bN0wibH6si9uF8I
         const userCred = new Uint8Array([198, 18, 166, 217, 14, 52, 226, 145, 164, 169, 245, 164, 79, 36, 247, 82, 135, 84, 71, 239, 125, 108, 221, 48, 137, 177, 250, 178, 47, 110, 23, 194]);
         const clearCheck = new TextEncoder().encode('physical farm bolt correct bee nonchalant glib high able pinch left quaint strip valuable exultant disgusted curved bless geese snatch zoom fat touch boot abject wink pretty accessible foamy');
         const hintCheck = 'royal';
         const pwd = '9j5J4QnKD3D2R7Ks5gAAa';

         const clear = await cipherSvc.decryptBuffer(
            async (hint) => {
               expect(hint).toEqual(hintCheck);
               return pwd;
            },
            userCred,
            base64ToBytes(ct)
         );

         expect(isEqualArray(clear, clearCheck)).toBeTrue();
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
      const clearCheck = new TextEncoder().encode("this 🐞 is encrypted");

      for (let ct of cts) {
         const ctBytes = base64ToBytes(ct);
         // userCred used for creation of the CTS above
         const userCred = new Uint8Array([101, 246, 72, 149, 67, 228, 149, 35, 60, 124, 81, 187, 157, 96, 208, 217, 123, 147, 228, 60, 84, 214, 198, 116, 192, 162, 178, 147, 50, 119, 97, 251]);

         // First ensure we can decrypt with valid inputs
         const clear = await cipherSvc.decryptBuffer(
            async (hint) => {
               expect(hint).toEqual("asdf");
               return "asdf";
            },
            userCred,
            base64ToBytes(ct)
         );
         expect(isEqualArray(clear, clearCheck)).toBeTrue();

         let skipCount = 0;

         // Tweak one character at a time using b64o offsets (will remain a valid b64 string)
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
               cipherSvc.decryptBuffer(
                  async (hint) => {
                     expect(hint).toEqual("asdf");
                     return "asdf";
                  },
                  userCred,
                  base64ToBytes(corruptCt)
               )).toBeRejectedWithError(Error);
         }
      }
   });

   it("detect valid MAC wrong password, all alogrithms", async function () {
      for (const alg of cipherSvc.algs()) {
         const clearData = new TextEncoder().encode('This is a secret 🦄');
         const pwd = 'the correct pwd';
         const hint = '';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

         const econtext: EncContext3 = {
            alg: alg,
            ic: cc.ICOUNT_MIN,
            trueRand: false,
            fallbackRand: true,
            pwd: pwd,
            hint: hint,
            userCred: userCred,
         };

         const cipherData = await cipherSvc.encryptBuffer(econtext, clearData);

         await expectAsync(
            cipherSvc.decryptBuffer(
               async (decHint) => {
                  expect(decHint).toEqual(hint);
                  return 'the wrong pwd';
               },
               userCred,
               cipherData
            )
         ).toBeRejectedWithError(DOMException);
      }
   });

   it("detect corrupted MAC sig, all algorithms", async function () {

      for (const alg of cipherSvc.algs()) {

         const clearData = new TextEncoder().encode("asefwlefj4oh09f jw90fu w09fu 9");
         const pwd = 'another good pwd';
         const hint = 'nope';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

         const econtext: EncContext3 = {
            alg: alg,
            ic: cc.ICOUNT_MIN,
            trueRand: false,
            fallbackRand: true,
            pwd: pwd,
            hint: hint,
            userCred: userCred
         };

         let cipherData = await cipherSvc.encryptBuffer(econtext, clearData);

         // change in MAC
         let problemData = pokeValue(cipherData, 3, -1);

         await expectAsync(
            cipherSvc.decryptBuffer(
               async (decHint) => {
                  expect(decHint).toEqual(hint);
                  return pwd;
               },
               userCred,
               problemData
            )
         ).toBeRejectedWithError(Error, new RegExp('.+MAC.+'));
      }
   });

   it("detect crafted bad cipher text, all algorithms", async function () {

      for (const alg of cipherSvc.algs()) {
         const clearData = new TextEncoder().encode("asdfh3roij 02f23kff 8u 3r90");
         const pwd = 'another good pwd';
         const hint = 'nope';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

         const econtext: EncContext3 = {
            alg: alg,
            ic: cc.ICOUNT_MIN,
            trueRand: false,
            fallbackRand: true,
            pwd: pwd,
            hint: hint,
            userCred: userCred,
         };

         let cipherData = await cipherSvc.encryptBuffer(econtext, clearData);

         // Set character in cipher text
         // past ~(MAC + VER + ALG + MAX_IV + CHUCKSZ)*4/3 characters)
         let problemData = pokeValue(cipherData, 100, -1);

         await expectAsync(
            cipherSvc.decryptBuffer(
               async (decHint) => {
                  // Should never execute
                  expect(false).toBeTrue();
                  return pwd;
               },
               userCred,
               problemData
            )
         ).toBeRejectedWithError(Error, new RegExp('.+MAC.+'));

         // Set character in encyrpted hint
         // back ~(IC + SLT *4/3 characters) from end
         problemData = pokeValue(cipherData,  cipherData.length - 30, 4);

         await expectAsync(
            cipherSvc.decryptBuffer(
               async (decHint) => {
                  // Should never execute
                  expect(false).toBeTrue();
                  return pwd;
               },
               userCred,
               problemData
            )
         ).toBeRejectedWithError(Error, new RegExp('.+MAC.+'));
      }
   });

   it("detect encryption argument errors", async function () {

      const hint = 'nope';
      const pwd = 'another good pwd';
      const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));
      const clearData = new TextEncoder().encode("()*Hskdfo892hj3f09");

      const econtext: EncContext3 = {
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
         cipherSvc.encryptBuffer(econtext, clearData)
      ).not.toBeRejectedWithError();

      // empty pwd
      let bparams = {
         ...econtext,
         pwd: ''
      }
      await expectAsync(
         cipherSvc.encryptBuffer(bparams, clearData)
      ).toBeRejectedWithError(Error, new RegExp('.+userCred.*'));

      // no userCred
      bparams = {
         ...econtext,
         userCred: new Uint8Array(0)
      }
      await expectAsync(
         cipherSvc.encryptBuffer(bparams, clearData)
      ).toBeRejectedWithError(Error, new RegExp('.+userCred.*'));

      // extra long userCred
      bparams = {
         ...econtext,
         userCred: crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES + 2))
      }
      await expectAsync(
         cipherSvc.encryptBuffer(bparams, clearData)
      ).toBeRejectedWithError(Error, new RegExp('.+userCred.*'));

      // empty clear data
      bparams = {
         ...econtext
      }
      await expectAsync(
         cipherSvc.encryptBuffer(bparams, new Uint8Array())
      ).toBeRejectedWithError(Error, new RegExp('Missing clear.+'));

      // ic too small
      bparams = {
         ...econtext,
         ic: cc.ICOUNT_MIN - 1
      }
      await expectAsync(
         cipherSvc.encryptBuffer(bparams, clearData)
      ).toBeRejectedWithError(Error, new RegExp('Invalid ic.+'));

      // ic too big
      bparams = {
         ...econtext,
         ic: cc.ICOUNT_MAX + 1
      }
      await expectAsync(
         cipherSvc.encryptBuffer(bparams, clearData)
      ).toBeRejectedWithError(Error, new RegExp('Invalid ic.+'));

      // invalid alg
      bparams = {
         ...econtext,
         alg: 'ABS-GCM'
      }
      await expectAsync(
         cipherSvc.encryptBuffer(bparams, clearData)
      ).toBeRejectedWithError(Error, new RegExp('Invalid alg.+'));

      // really invalid alg
      bparams = {
         ...econtext,
         alg: 'asdfadfsk'
      }
      await expectAsync(
         cipherSvc.encryptBuffer(bparams, clearData)
      ).toBeRejectedWithError(Error, new RegExp('Invalid alg.+'));

      // both rands false
      bparams = {
         ...econtext,
         trueRand: false,
         fallbackRand: false
      }
      await expectAsync(
         cipherSvc.encryptBuffer(bparams, clearData)
      ).toBeRejectedWithError(Error, new RegExp('Either trueRand.+'));

      // hint too long
      bparams = {
         ...econtext,
         hint: 'this is too long'.repeat(8)
      }
      await expectAsync(
         cipherSvc.encryptBuffer(bparams, clearData)
      ).toBeRejectedWithError(Error, new RegExp('Hint length.+'));

   });
*/
});

/*
describe("Stream manipulation", function () {

   let cipherSvc: CipherService;
   beforeEach(() => {
      TestBed.configureTestingModule({});
      Ciphers.testingFlag = true;
      cipherSvc = TestBed.inject(CipherService);
   });

   const encryptedData = new Uint8Array([62, 237, 190, 103, 252, 64, 149, 12, 129, 22, 216, 155, 54, 121, 79, 196, 149, 110, 1, 197, 231, 33, 150, 194, 129, 6, 88, 203, 184, 103, 246, 70, 4, 0, 83, 1, 0, 0, 2, 0, 2, 19, 162, 123, 41, 226, 6, 196, 69, 81, 38, 224, 154, 26, 134, 113, 180, 24, 226, 95, 142, 222, 59, 36, 34, 184, 222, 45, 62, 232, 107, 106, 10, 15, 108, 161, 29, 187, 38, 19, 64, 119, 27, 0, 20, 154, 205, 154, 62, 40, 180, 14, 44, 233, 232, 212, 208, 237, 23, 44, 146, 45, 92, 135, 179, 85, 92, 234, 181, 218, 8, 66, 58, 174, 30, 99, 215, 75, 254, 186, 90, 134, 178, 154, 51, 211, 222, 71, 145, 43, 187, 130, 85, 193, 9, 241, 9, 112, 23, 210, 101, 86, 0, 0, 84, 94, 185, 46, 27, 15, 97, 88, 62, 90, 220, 112, 202, 255, 57, 142, 176, 67, 66, 220, 237, 94, 250, 229, 68, 82, 177, 250, 216, 97, 124, 29, 31, 224, 244, 191, 123, 247, 134, 130, 146, 164, 199, 18, 28, 32, 179, 255, 22, 32, 211, 141, 143, 1, 50, 96, 164, 107, 179, 102, 38, 83, 83, 165, 122, 150, 8, 223, 245, 200, 54, 42, 127, 91, 153, 30, 29, 138, 249, 106, 108, 136, 151, 1, 179, 133, 45, 48, 154, 247, 196, 117, 94, 241, 179, 80, 218, 214, 102, 243, 226, 115, 123, 106, 163, 251, 161, 106, 79, 40, 137, 28, 24, 79, 203, 145, 119, 191, 233, 142, 125, 231, 69, 161, 107, 226, 187, 238, 140, 62, 185, 1, 30, 175, 17, 211, 166, 88, 156, 136, 76, 116, 34, 13, 57, 87, 174, 199, 44, 75, 80, 1, 152, 214, 201, 241, 209, 96, 23, 248, 224, 46, 105, 194, 164, 253, 27, 117, 221, 52, 182, 219, 106, 187, 217, 89, 56, 58, 233, 14, 202, 75, 169, 109, 153, 65, 77, 209, 85, 61, 189, 150, 220, 10, 242, 200, 244, 225, 158, 159, 36, 84, 209, 156, 50, 31, 227, 32, 126, 239, 67, 220, 27, 119, 253, 194, 97, 161, 194, 205, 168, 221, 71, 131, 31, 129, 110, 230, 109, 81, 23, 192, 118, 253, 187, 233, 235, 226, 103, 142, 17, 53, 144, 1, 116, 153, 14, 46, 7, 1, 68, 232, 62, 88, 150, 163, 130, 51, 124, 73, 165, 78, 71, 100, 45, 4, 0, 123, 1, 0, 0, 2, 0, 226, 17, 254, 221, 177, 108, 188, 116, 173, 141, 17, 162, 131, 104, 205, 37, 179, 198, 15, 108, 38, 76, 41, 156, 200, 19, 100, 82, 234, 65, 126, 127, 52, 100, 183, 167, 37, 224, 117, 89, 254, 187, 255, 163, 206, 140, 221, 65, 144, 205, 153, 169, 106, 81, 28, 241, 100, 208, 171, 192, 1, 6, 42, 184, 239, 224, 25, 25, 227, 203, 53, 180, 80, 126, 47, 75, 103, 59, 20, 144, 213, 103, 181, 46, 162, 91, 18, 170, 24, 90, 57, 51, 69, 36, 101, 231, 238, 105, 247, 10, 96, 50, 233, 147, 36, 250, 1, 27, 220, 229, 61, 33, 168, 250, 188, 160, 96, 58, 228, 28, 15, 222, 106, 233, 224, 181, 236, 238, 31, 9, 102, 121, 253, 162, 244, 45, 205, 130, 175, 137, 213, 219, 29, 27, 187, 135, 119, 77, 163, 146, 218, 114, 88, 113, 79, 85, 118, 63, 188, 24, 195, 181, 220, 203, 62, 104, 98, 139, 46, 159, 72, 111, 99, 2, 46, 45, 154, 137, 254, 199, 50, 169, 189, 49, 14, 219, 98, 160, 88, 93, 110, 89, 32, 185, 156, 208, 247, 185, 201, 118, 206, 105, 117, 21, 43, 13, 243, 25, 192, 239, 188, 2, 63, 20, 167, 96, 213, 167, 34, 108, 53, 103, 4, 115, 155, 130, 79, 46, 209, 34, 254, 177, 92, 13, 96, 205, 26, 45, 131, 170, 39, 29, 84, 86, 7, 78, 64, 222, 219, 36, 147, 89, 77, 61, 34, 30, 7, 148, 199, 127, 217, 126, 29, 164, 44, 72, 10, 32, 125, 37, 77, 191, 47, 37, 10, 50, 45, 45, 114, 236, 11, 74, 149, 166, 55, 112, 221, 198, 63, 35, 43, 87, 70, 53, 85, 22, 111, 25, 109, 202, 52, 184, 174, 103, 156, 222, 196, 164, 95, 132, 163, 185, 20, 217, 228, 102, 31, 238, 29, 204, 160, 203, 72, 27, 178, 142, 223, 210, 175, 206, 77, 122, 115, 39, 224, 44, 89, 185, 82, 40, 35, 42, 131, 174, 213, 33, 156, 15, 225, 67, 149, 87, 187, 142, 11, 80, 102, 211, 250, 204, 13, 117, 103, 175, 3, 68, 142, 235, 35, 243, 78, 15, 93, 231, 88, 182, 126]);
   const clearData = new Uint8Array([118, 101, 114, 115, 105, 111, 110, 58, 32, 34, 51, 46, 56, 34, 10, 115, 101, 114, 118, 105, 99, 101, 115, 58, 10, 32, 32, 100, 111, 99, 107, 103, 101, 58, 10, 32, 32, 32, 32, 105, 109, 97, 103, 101, 58, 32, 108, 111, 117, 105, 115, 108, 97, 109, 47, 100, 111, 99, 107, 103, 101, 58, 49, 10, 32, 32, 32, 32, 114, 101, 115, 116, 97, 114, 116, 58, 32, 117, 110, 108, 101, 115, 115, 45, 115, 116, 111, 112, 112, 101, 100, 10, 32, 32, 32, 32, 112, 111, 114, 116, 115, 58, 10, 32, 32, 32, 32, 32, 32, 45, 32, 53, 48, 48, 49, 58, 53, 48, 48, 49, 10, 32, 32, 32, 32, 118, 111, 108, 117, 109, 101, 115, 58, 10, 32, 32, 32, 32, 32, 32, 45, 32, 47, 118, 97, 114, 47, 114, 117, 110, 47, 100, 111, 99, 107, 101, 114, 46, 115, 111, 99, 107, 58, 47, 118, 97, 114, 47, 114, 117, 110, 47, 100, 111, 99, 107, 101, 114, 46, 115, 111, 99, 107, 10, 32, 32, 32, 32, 32, 32, 45, 32, 46, 47, 100, 97, 116, 97, 58, 47, 97, 112, 112, 47, 100, 97, 116, 97, 10, 32, 32, 32, 32, 32, 32, 35, 32, 83, 116, 97, 99, 107, 115, 32, 68, 105, 114, 101, 99, 116, 111, 114, 121, 10, 32, 32, 32, 32, 32, 32, 35, 32, 226, 154, 160, 239, 184, 143, 32, 82, 69, 65, 68, 32, 73, 84, 32, 67, 65, 82, 69, 70, 85, 76, 76, 89, 46, 32, 73, 102, 32, 121, 111, 117, 32, 100, 105, 100, 32, 105, 116, 32, 119, 114, 111, 110, 103, 44, 32, 121, 111, 117, 114, 32, 100, 97, 116, 97, 32, 99, 111, 117, 108, 100, 32, 101, 110, 100, 32, 117, 112, 32, 119, 114, 105, 116, 105, 110, 103, 32, 105, 110, 116, 111, 32, 97, 32, 87, 82, 79, 78, 71, 32, 80, 65, 84, 72, 46, 10, 32, 32, 32, 32, 32, 32, 35, 32, 226, 154, 160, 239, 184, 143, 32, 49, 46, 32, 70, 85, 76, 76, 32, 112, 97, 116, 104, 32, 111, 110, 108, 121, 46, 32, 78, 111, 32, 114, 101, 108, 97, 116, 105, 118, 101, 32, 112, 97, 116, 104, 32, 40, 77, 85, 83, 84, 41, 10, 32, 32, 32, 32, 32, 32, 35, 32, 226, 154, 160, 239, 184, 143, 32, 50, 46, 32, 76, 101, 102, 116, 32, 83, 116, 97, 99, 107, 115, 32, 80, 97, 116, 104, 32, 61, 61, 61, 32, 82, 105, 103, 104, 116, 32, 83, 116, 97, 99, 107, 115, 32, 80, 97, 116, 104, 32, 40, 77, 85, 83, 84, 41, 10, 32, 32, 32, 32, 32, 32, 45, 32, 47, 111, 112, 116, 47, 115, 116, 97, 99, 107, 115, 58, 47, 111, 112, 116, 47, 115, 116, 97, 99, 107, 115, 10, 32, 32, 32, 32, 101, 110, 118, 105, 114, 111, 110, 109, 101, 110, 116, 58, 10, 32, 32, 32, 32, 32, 32, 35, 32, 84, 101, 108, 108, 32, 68, 111, 99, 107, 103, 101, 32, 119, 104, 101, 114, 101, 32, 116, 111, 32, 102, 105, 110, 100, 32, 116, 104, 101, 32, 115, 116, 97, 99, 107, 115, 10, 32, 32, 32, 32, 32, 32, 45, 32, 68, 79, 67, 75, 71, 69, 95, 83, 84, 65, 67, 75, 83, 95, 68, 73, 82, 61, 47, 111, 112, 116, 47, 115, 116, 97, 99, 107, 115, 10]);
   const block0MACOffset = 0;
   const block0VerOffset = block0MACOffset + cc.MAC_BYTES;
   const block0SizeOffset = block0VerOffset + cc.VER_BYTES;
   const block0ADOffset = block0SizeOffset + cc.PAYLOAD_SIZE_BYTES;
   const block0AlgOffset = block0ADOffset;
   const block0IVOffset = block0AlgOffset + cc.ALG_BYTES;
   const block0SltOffset = block0IVOffset + Number(cc.AlgInfo['X20-PLY']['iv_bytes']);
   const block0ICOffset = block0SltOffset + cc.SLT_BYTES;
   const block0HintLenOffset = block0ICOffset + cc.IC_BYTES;
   const block0HintOffset = block0HintLenOffset + cc.HINT_LEN_BYTES;
   const block0EncOffset = block0MACOffset + 190; // in the middle of enc data

   const block1MACOffset = 377;
   const block1VerOffset = block1MACOffset + cc.MAC_BYTES;
   const block1SizeOffset = block1VerOffset + cc.VER_BYTES;
   const block1ADOffset = block1SizeOffset + cc.PAYLOAD_SIZE_BYTES;
   const block1AlgOffset = block1ADOffset;
   const block1IVOffset = block1AlgOffset + cc.ALG_BYTES;
   const block1EncOffset = block1MACOffset + 190; // in the middle of enc data

   // userCred used for creation of the CTS above
   // b64url userCred for browsser injection: xhKm2Q404pGkqfWkTyT3UodUR-99bN0wibH6si9uF8I
   const userCred = new Uint8Array([198, 18, 166, 217, 14, 52, 226, 145, 164, 169, 245, 164, 79, 36, 247, 82, 135, 84, 71, 239, 125, 108, 221, 48, 137, 177, 250, 178, 47, 110, 23, 194]);
   // Also replace following value in cipher.service.ts to create small block
   //const READ_SIZE_START = 1048576/1024/4;
   //const READ_SIZE_MAX = READ_SIZE_START * 41


   it("detect manipulated cipher stream header, block0", async function () {

      // First make sure it decrypts as expected
      let blob = new Blob([encryptedData], { type: 'application/octet-stream' });
      let dec = cipherSvc.decryptStream(
         async (decHint) => { expect(decHint).toEqual('4321'); return 'asdf'; },
         userCred,
         blob.stream(),
      );

      const value = await readStreamAll(dec);
      expect(isEqualArray(value, new Uint8Array(clearData.buffer, 0, value!.byteLength))).toBeTrue();

      // Modified block0 MAC
      const b0Mac = new Uint8Array(encryptedData);
      b0Mac.set([255], block0MACOffset);
      blob = new Blob([b0Mac], { type: 'application/octet-stream' });
      dec = cipherSvc.decryptStream(
         async (decHint) => { return 'asdf' },
         userCred,
         blob.stream(),
      );
      await expectAsync(
         readStreamAll(dec)
      ).toBeRejectedWithError(Error, new RegExp('Invalid MAC.+'));

      // Test modified block0 version
      const b0Ver = new Uint8Array(encryptedData);
      b0Ver.set([6], block0VerOffset);
      blob = new Blob([b0Ver], { type: 'application/octet-stream' });
      dec = cipherSvc.decryptStream(
         async (decHint) => { return 'asdf' },
         userCred,
         blob.stream(),
      );
      await expectAsync(
         readStreamAll(dec)
      ).toBeRejectedWithError(Error, new RegExp('Invalid version.+'));

      // Test modified block0 size, too small valid
      let b0Size = new Uint8Array(encryptedData);
      b0Size.set([20, 1], block0SizeOffset);
      blob = new Blob([b0Size], { type: 'application/octet-stream' });
      dec = cipherSvc.decryptStream(
         async (decHint) => { return 'asdf' },
         userCred,
         blob.stream(),
      );
      await expectAsync(
         readStreamAll(dec)
      ).toBeRejectedWithError(Error, new RegExp('Invalid MAC.+'));

      // Too small block0 size, too small invalid
      b0Size = new Uint8Array(encryptedData);
      b0Size.set([0, 0], block0SizeOffset);
      blob = new Blob([b0Size], { type: 'application/octet-stream' });
      dec = cipherSvc.decryptStream(
         async (decHint) => { return 'asdf' },
         userCred,
         blob.stream(),
      );
      await expectAsync(
         readStreamAll(dec)
      ).toBeRejectedWithError(Error, new RegExp('Invalid payload.+'));

      // Test too big block0 size, invalid
      b0Size = new Uint8Array(encryptedData);
      b0Size.set([255, 255, 255, 255], block0SizeOffset);
      blob = new Blob([b0Size], { type: 'application/octet-stream' });
      dec = cipherSvc.decryptStream(
         async (decHint) => { return 'asdf' },
         userCred,
         blob.stream(),
      );
      await expectAsync(
         readStreamAll(dec)
      ).toBeRejectedWithError(Error, new RegExp('Invalid payload.+'));

      // Test too big block0 but valid
      b0Size = new Uint8Array(encryptedData);
      b0Size.set([255, 255, 255, 0], block0SizeOffset);
      blob = new Blob([b0Size], { type: 'application/octet-stream' });
      dec = cipherSvc.decryptStream(
         async (decHint) => { return 'asdf' },
         userCred,
         blob.stream(),
      );
      await expectAsync(
         readStreamAll(dec)
      ).toBeRejectedWithError(Error, new RegExp('Invalid payload.+'));

      });

   it("detect manipulated cipher stream header, blockN", async function () {

      // First make sure it decrypts as expected
      let blob = new Blob([encryptedData], { type: 'application/octet-stream' });
      let dec = cipherSvc.decryptStream(
         async (decHint) => { expect(decHint).toEqual('4321'); return 'asdf'; },
         userCred,
         blob.stream(),
      );

      const value = await readStreamAll(dec);
      expect(isEqualArray(value, new Uint8Array(clearData.buffer, 0, value!.byteLength))).toBeTrue();

      // Modified blockN MAC
      const bNMac = new Uint8Array(encryptedData);
      bNMac.set([255], block1MACOffset);
      blob = new Blob([bNMac], { type: 'application/octet-stream' });
      dec = cipherSvc.decryptStream(
         async (decHint) => { return 'asdf' },
         userCred,
         blob.stream(),
      );
      await expectAsync(
         readStreamAll(dec)
      ).toBeRejectedWithError(Error, new RegExp('Invalid MAC.+'));

      // Modified blockN version
      const bNVer = new Uint8Array(encryptedData);
      bNVer.set([4, 1], block1VerOffset);
      blob = new Blob([bNVer], { type: 'application/octet-stream' });
      dec = cipherSvc.decryptStream(
         async (decHint) => { return 'asdf' },
         userCred,
         blob.stream(),
      );
      await expectAsync(
         readStreamAll(dec)
      ).toBeRejectedWithError(Error, new RegExp('Invalid version.+'));

      // Test modified blockN size, too small valid
      let bNSize = new Uint8Array(encryptedData);
      bNSize.set([20, 1], block1SizeOffset);
      blob = new Blob([bNSize], { type: 'application/octet-stream' });
      dec = cipherSvc.decryptStream(
         async (decHint) => { return 'asdf' },
         userCred,
         blob.stream(),
      );
      await expectAsync(
         readStreamAll(dec)
      ).toBeRejectedWithError(Error, new RegExp('Invalid MAC.+'));

      // Too small blockN size, too small invalid
      bNSize = new Uint8Array(encryptedData);
      bNSize.set([0, 0], block1SizeOffset);
      blob = new Blob([bNSize], { type: 'application/octet-stream' });
      dec = cipherSvc.decryptStream(
         async (decHint) => { return 'asdf' },
         userCred,
         blob.stream(),
      );
      await expectAsync(
         readStreamAll(dec)
      ).toBeRejectedWithError(Error, new RegExp('Invalid payload.+'));

      // Test too big blockN size, invalid
      bNSize = new Uint8Array(encryptedData);
      bNSize.set([255, 255, 255, 255], block1SizeOffset);
      blob = new Blob([bNSize], { type: 'application/octet-stream' });
      dec = cipherSvc.decryptStream(
         async (decHint) => { return 'asdf' },
         userCred,
         blob.stream(),
      );
      await expectAsync(
         readStreamAll(dec)
      ).toBeRejectedWithError(Error, new RegExp('Invalid payload.+'));

      // Test too big blockN but valid
      bNSize = new Uint8Array(encryptedData);
      bNSize.set([255, 255, 255, 0], block1SizeOffset);
      blob = new Blob([bNSize], { type: 'application/octet-stream' });
      dec = cipherSvc.decryptStream(
         async (decHint) => { return 'asdf' },
         userCred,
         blob.stream(),
      );
      await expectAsync(
         readStreamAll(dec)
      ).toBeRejectedWithError(Error, new RegExp('Invalid payload.+'));
   });


   it("detect manipulated cipher stream additional data, block0", async function () {

      // First make sure it decrypts as expected
      let blob = new Blob([encryptedData], { type: 'application/octet-stream' });
      let dec = cipherSvc.decryptStream(
         async (decHint) => { expect(decHint).toEqual('4321'); return 'asdf'; },
         userCred,
         blob.stream(),
      );

      const value = await readStreamAll(dec);
      expect(isEqualArray(value, new Uint8Array(clearData.buffer, 0, value!.byteLength))).toBeTrue();

      // Modified block0 invalid ALG
      let b0Alg = new Uint8Array(encryptedData);
      b0Alg.set([128], block0AlgOffset);
      blob = new Blob([b0Alg], { type: 'application/octet-stream' });
      dec = cipherSvc.decryptStream(
         async (decHint) => { return 'asdf' },
         userCred,
         blob.stream(),
      );
      await expectAsync(
         readStreamAll(dec)
      ).toBeRejectedWithError(Error, new RegExp('Invalid alg.+'));

      // Modified block0 valid but changed ALG
      b0Alg = new Uint8Array(encryptedData);
      b0Alg.set([1], block0AlgOffset);
      blob = new Blob([b0Alg], { type: 'application/octet-stream' });
      dec = cipherSvc.decryptStream(
         async (decHint) => { return 'asdf' },
         userCred,
         blob.stream(),
      );
      await expectAsync(
         readStreamAll(dec)
      ).toBeRejectedWithError(Error, new RegExp('Invalid MAC.+'));

      // Modified block0 IV
      const b0OIV = new Uint8Array(encryptedData);
      b0OIV.set([0], block0IVOffset);
      blob = new Blob([b0OIV], { type: 'application/octet-stream' });
      dec = cipherSvc.decryptStream(
         async (decHint) => { return 'asdf' },
         userCred,
         blob.stream(),
      );
      await expectAsync(
         readStreamAll(dec)
      ).toBeRejectedWithError(Error, new RegExp('Invalid MAC.+'));

      // Modified block0 Salt
      const b0Slt = new Uint8Array(encryptedData);
      b0Slt.set([1], block0SltOffset);
      blob = new Blob([b0Slt], { type: 'application/octet-stream' });
      dec = cipherSvc.decryptStream(
         async (decHint) => { return 'asdf' },
         userCred,
         blob.stream(),
      );
      await expectAsync(
         readStreamAll(dec)
      ).toBeRejectedWithError(Error, new RegExp('Invalid MAC.+'));

      // Modified block0 invalid IC
      let b0IC = new Uint8Array(encryptedData);
      b0IC.set([0, 0, 0, 0], block0ICOffset);
      blob = new Blob([b0IC], { type: 'application/octet-stream' });
      dec = cipherSvc.decryptStream(
         async (decHint) => { return 'asdf' },
         userCred,
         blob.stream(),
      );
      await expectAsync(
         readStreamAll(dec)
      ).toBeRejectedWithError(Error, new RegExp('Invalid ic.+'));

      // Modified block0 valid but changed IC
      b0IC = new Uint8Array(encryptedData);
      b0IC.set([64, 119, 21, 1], block0ICOffset);
      blob = new Blob([b0IC], { type: 'application/octet-stream' });
      dec = cipherSvc.decryptStream(
         async (decHint) => { return 'asdf' },
         userCred,
         blob.stream(),
      );
      await expectAsync(
         readStreamAll(dec)
      ).toBeRejectedWithError(Error, new RegExp('Invalid MAC.+'));

      // Modified block0 hint length
      let b0HintLen = new Uint8Array(encryptedData);
      b0HintLen.set([12], block0HintLenOffset);
      blob = new Blob([b0HintLen], { type: 'application/octet-stream' });
      dec = cipherSvc.decryptStream(
         async (decHint) => { return 'asdf' },
         userCred,
         blob.stream(),
      );
      await expectAsync(
         readStreamAll(dec)
      ).toBeRejectedWithError(Error, new RegExp('Invalid MAC.+'));

      // Modified block0 hint
      let b0Hint = new Uint8Array(encryptedData);
      b0Hint.set([12], block0HintOffset);
      blob = new Blob([b0Hint], { type: 'application/octet-stream' });
      dec = cipherSvc.decryptStream(
         async (decHint) => { return 'asdf' },
         userCred,
         blob.stream(),
      );
      await expectAsync(
         readStreamAll(dec)
      ).toBeRejectedWithError(Error, new RegExp('Invalid MAC.+'));

   });

   it("detect manipulated cipher stream additional data, blockN", async function () {

      // First make sure it decrypts as expected
      let blob = new Blob([encryptedData], { type: 'application/octet-stream' });
      let dec = cipherSvc.decryptStream(
         async (decHint) => { expect(decHint).toEqual('4321'); return 'asdf'; },
         userCred,
         blob.stream(),
      );

      const value = await readStreamAll(dec);
      expect(isEqualArray(value, new Uint8Array(clearData.buffer, 0, value!.byteLength))).toBeTrue();

      // Modified blockN invalid ALG
      let bNAlg = new Uint8Array(encryptedData);
      bNAlg.set([128], block1AlgOffset);
      blob = new Blob([bNAlg], { type: 'application/octet-stream' });
      dec = cipherSvc.decryptStream(
         async (decHint) => { return 'asdf' },
         userCred,
         blob.stream(),
      );
      await expectAsync(
         readStreamAll(dec)
      ).toBeRejectedWithError(Error, new RegExp('Invalid alg.+'));

      // Modified blockN valid but changed ALG
      bNAlg = new Uint8Array(encryptedData);
      bNAlg.set([1], block1AlgOffset);
      blob = new Blob([bNAlg], { type: 'application/octet-stream' });
      dec = cipherSvc.decryptStream(
         async (decHint) => { return 'asdf' },
         userCred,
         blob.stream(),
      );
      await expectAsync(
         readStreamAll(dec)
      ).toBeRejectedWithError(Error, new RegExp('Invalid MAC.+'));

      // Modified blockN IV
      const bNOIV = new Uint8Array(encryptedData);
      bNOIV.set([0], block1IVOffset);
      blob = new Blob([bNOIV], { type: 'application/octet-stream' });
      dec = cipherSvc.decryptStream(
         async (decHint) => { return 'asdf' },
         userCred,
         blob.stream(),
      );
      await expectAsync(
         readStreamAll(dec)
      ).toBeRejectedWithError(Error, new RegExp('Invalid MAC.+'));

   });

   it("detect manipulated cipher stream encrypted data", async function () {

      // First make sure it decrypts as expected
      let blob = new Blob([encryptedData], { type: 'application/octet-stream' });
      let dec = cipherSvc.decryptStream(
         async (decHint) => { expect(decHint).toEqual('4321'); return 'asdf'; },
         userCred,
         blob.stream(),
      );

      const value = await readStreamAll(dec);
      expect(isEqualArray(value, new Uint8Array(clearData.buffer, 0, value!.byteLength))).toBeTrue();


      // Modified block0 encrypted data
      let b0Enc = new Uint8Array(encryptedData);
      b0Enc.set([0], block0EncOffset);
      blob = new Blob([b0Enc], { type: 'application/octet-stream' });
      dec = cipherSvc.decryptStream(
         async (decHint) => { return 'asdf' },
         userCred,
         blob.stream(),
      );
      await expectAsync(
         readStreamAll(dec)
      ).toBeRejectedWithError(Error, new RegExp('Invalid MAC.+'));

      // Modified blockN encrypted data
      let bNEnc = new Uint8Array(encryptedData);
      bNEnc.set([128], block1EncOffset);
      blob = new Blob([bNEnc], { type: 'application/octet-stream' });
      dec = cipherSvc.decryptStream(
         async (decHint) => { return 'asdf' },
         userCred,
         blob.stream(),
      );
      await expectAsync(
         readStreamAll(dec)
      ).toBeRejectedWithError(Error, new RegExp('Invalid MAC.+'));

   });

});


describe("Stream encryption and decryption", function () {

   let cipherSvc: CipherService;
   beforeEach(() => {
      TestBed.configureTestingModule({});
      Ciphers.testingFlag = true;
      cipherSvc = TestBed.inject(CipherService);
   });

   it("successful round trip, all algorithms, no pwd hint", async function () {

      for (const alg of cipherSvc.algs()) {

         const blob = randomBlob(READ_SIZE_START * 3.5);
         const pwd = 'a good pwd';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

         const econtext: EncContext3 = {
            alg: alg,
            ic: cc.ICOUNT_MIN,
            trueRand: false,
            fallbackRand: true,
            pwd: pwd,
            userCred: userCred,
         };

         const cipherStream = cipherSvc.encryptStream(
            econtext,
            blob.stream(),
            (params) => {
               expect(params.alg).toEqual(alg);
               expect(params.ic).toEqual(cc.ICOUNT_MIN);
            }
         );

         const decryptedStream = cipherSvc.decryptStream(
            async (decHint) => {
               expect(decHint).toEqual('');
               return pwd;
            },
            userCred,
            cipherStream,
            (params) => {
               expect(params.alg).toEqual(alg);
               expect(params.ic).toEqual(cc.ICOUNT_MIN);
            }
         );

         let decrypted = await readStreamAll(decryptedStream);
         expect(isEqualArray(
            new Uint8Array(await blob.arrayBuffer()),
            decrypted
         )).toBeTrue();


      }
   });


   it("successful round trip, all algorithms", async function () {

      for (const alg of cipherSvc.algs()) {

         const blob = randomBlob(READ_SIZE_START * 3.5);
         const pwd = 'a good pwd';
         const hint = 'not really';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

         const econtext: EncContext3 = {
            alg: alg,
            ic: cc.ICOUNT_MIN,
            trueRand: false,
            fallbackRand: true,
            pwd: pwd,
            hint: hint,
            userCred: userCred,
         };

         const cipherStream = cipherSvc.encryptStream(
            econtext,
            blob.stream(),
            (params) => {
               expect(params.alg).toEqual(alg);
               expect(params.ic).toEqual(cc.ICOUNT_MIN);
            }
         );

         const decryptedStream = cipherSvc.decryptStream(
            async (decHint) => {
               expect(decHint).toEqual(hint);
               return pwd;
            },
            userCred,
            cipherStream,
            (params) => {
               expect(params.alg).toEqual(alg);
               expect(params.ic).toEqual(cc.ICOUNT_MIN);
            }
         );

         let decrypted = await readStreamAll(decryptedStream);
         expect(isEqualArray(
            new Uint8Array(await blob.arrayBuffer()),
            decrypted
         )).toBeTrue();
      }
   });


   it("confirm successful version decryption", async function () {
      // These are generated with running website
      const cts = [
         // AEG-GCM: V4
         new Uint8Array([120, 48, 246, 74, 133, 223, 247, 58, 48, 12, 88, 247, 176, 3, 76, 56, 176, 222, 84, 240, 100, 142, 106, 230, 110, 39, 10, 251, 99, 166, 21, 25, 4, 0, 1, 1, 0, 0, 1, 0, 40, 8, 137, 212, 219, 182, 5, 44, 48, 95, 71, 10, 118, 97, 158, 73, 27, 193, 22, 217, 32, 4, 246, 14, 200, 169, 69, 164, 64, 119, 27, 0, 24, 69, 5, 214, 155, 134, 73, 117, 184, 5, 90, 238, 98, 180, 74, 33, 44, 228, 24, 92, 116, 115, 34, 96, 119, 92, 191, 44, 28, 222, 116, 194, 7, 204, 255, 196, 102, 166, 35, 67, 216, 160, 0, 120, 169, 211, 160, 50, 236, 94, 56, 146, 57, 68, 111, 70, 210, 53, 169, 12, 83, 175, 224, 121, 199, 178, 165, 202, 21, 92, 83, 226, 146, 162, 177, 118, 212, 129, 168, 25, 232, 144, 26, 72, 188, 191, 95, 100, 145, 249, 54, 235, 55, 122, 211, 109, 77, 90, 214, 100, 166, 134, 223, 65, 171, 117, 0, 230, 250, 48, 238, 110, 132, 155, 117, 247, 117, 6, 226, 245, 158, 63, 31, 154, 114, 184, 161, 58, 161, 208, 178, 215, 16, 131, 149, 60, 243, 39, 185, 46, 169, 137, 134, 246, 16, 72, 182, 209, 174, 111, 170, 233, 248, 121, 41, 56, 158, 36, 84, 148, 82, 167, 151, 188, 213, 176, 138, 252, 183, 158, 27, 123, 29, 93, 252, 124, 111, 193, 1, 210, 111, 44, 240, 41, 60, 86, 194, 199, 245, 111, 20, 233, 164, 69, 12, 245, 242, 191, 121, 11, 53, 201, 198, 162, 23, 12, 146, 11, 214, 124, 52, 87, 159, 15, 7, 197, 173, 163, 179, 113, 97, 36, 182]),

         // XChaCha: V4
         new Uint8Array([101, 38, 169, 199, 124, 199, 8, 90, 94, 156, 23, 78, 253, 92, 37, 77, 180, 105, 187, 143, 20, 11, 73, 172, 10, 252, 102, 6, 90, 179, 215, 50, 4, 0, 13, 1, 0, 0, 2, 0, 253, 81, 94, 14, 146, 158, 247, 17, 227, 179, 186, 150, 206, 71, 96, 195, 249, 223, 89, 243, 244, 91, 3, 254, 213, 43, 153, 50, 0, 148, 57, 215, 126, 221, 184, 203, 186, 51, 228, 1, 64, 119, 27, 0, 24, 234, 218, 9, 71, 138, 71, 151, 159, 14, 74, 6, 52, 223, 210, 255, 111, 99, 137, 146, 72, 23, 97, 116, 144, 202, 182, 177, 202, 76, 137, 200, 21, 41, 182, 91, 3, 136, 110, 12, 19, 253, 145, 46, 208, 25, 85, 82, 9, 15, 171, 169, 78, 75, 225, 45, 226, 58, 5, 96, 86, 104, 100, 215, 180, 167, 57, 33, 44, 203, 93, 108, 72, 212, 42, 250, 86, 219, 163, 137, 152, 116, 200, 149, 65, 31, 58, 143, 150, 50, 47, 105, 22, 184, 188, 118, 139, 126, 227, 183, 102, 249, 39, 171, 253, 105, 33, 140, 163, 166, 27, 142, 225, 215, 190, 38, 142, 32, 32, 161, 167, 85, 194, 128, 137, 61, 226, 241, 61, 115, 229, 38, 151, 38, 58, 20, 24, 221, 36, 107, 55, 217, 23, 194, 19, 220, 121, 194, 248, 141, 5, 153, 99, 214, 52, 142, 216, 193, 217, 164, 190, 181, 93, 76, 70, 234, 34, 20, 146, 178, 248, 51, 111, 57, 54, 145, 79, 91, 53, 49, 25, 161, 228, 98, 134, 151, 52, 90, 73, 110, 160, 112, 100, 116, 51, 250, 62, 40, 233, 144, 35, 134, 79, 227, 195, 86, 140, 19, 99, 230, 125, 47, 97, 217, 181, 230, 111, 152, 145, 128, 91, 221, 10]),

         // AEGIS: V4
         new Uint8Array([192, 148, 75, 184, 255, 192, 62, 152, 107, 167, 152, 245, 247, 141, 122, 91, 25, 49, 179, 186, 37, 252, 248, 203, 245, 90, 38, 117, 107, 182, 124, 55, 4, 0, 53, 1, 0, 0, 3, 0, 254, 211, 215, 39, 176, 250, 113, 181, 210, 157, 191, 154, 145, 58, 231, 214, 141, 102, 239, 127, 102, 41, 14, 195, 198, 16, 75, 151, 172, 173, 60, 97, 10, 98, 4, 38, 31, 112, 125, 127, 43, 29, 205, 94, 166, 28, 41, 109, 64, 119, 27, 0, 40, 95, 191, 89, 255, 5, 68, 170, 158, 222, 107, 110, 43, 171, 124, 220, 94, 173, 138, 26, 208, 129, 101, 145, 130, 51, 124, 210, 195, 236, 113, 34, 240, 30, 90, 245, 184, 128, 233, 122, 72, 192, 129, 11, 250, 38, 228, 93, 193, 110, 186, 121, 114, 109, 163, 7, 4, 107, 227, 179, 118, 127, 128, 236, 199, 192, 69, 218, 9, 53, 113, 234, 16, 70, 226, 31, 60, 252, 167, 100, 201, 185, 204, 49, 252, 130, 115, 23, 176, 53, 200, 239, 32, 100, 76, 176, 145, 180, 171, 102, 110, 110, 245, 6, 25, 248, 249, 233, 173, 151, 105, 17, 194, 196, 188, 8, 150, 114, 62, 93, 249, 246, 133, 208, 249, 77, 15, 8, 37, 138, 49, 222, 117, 225, 61, 95, 96, 36, 37, 94, 53, 96, 133, 220, 35, 34, 243, 57, 10, 149, 201, 161, 176, 45, 50, 135, 204, 186, 10, 124, 87, 140, 96, 225, 176, 226, 251, 65, 239, 85, 59, 157, 230, 141, 235, 183, 221, 139, 5, 209, 173, 51, 212, 209, 52, 41, 167, 132, 171, 190, 157, 188, 52, 51, 68, 102, 176, 70, 2, 5, 66, 196, 138, 109, 124, 31, 111, 6, 196, 36, 200, 6, 221, 97, 162, 166, 150, 200, 221, 144, 13, 197, 119, 38, 1, 248, 190, 144, 140, 54, 137, 52, 230, 24, 120, 103, 115, 60, 154, 11, 209, 14, 24, 4, 160, 215, 163, 194, 123, 146, 63, 220, 50, 84, 242]),
      ];

      for (let ctBytes of cts) {
         // userCred used for creation of the CTS above
         // b64url userCred for browsser injection: xhKm2Q404pGkqfWkTyT3UodUR-99bN0wibH6si9uF8I
         const userCred = new Uint8Array([198, 18, 166, 217, 14, 52, 226, 145, 164, 169, 245, 164, 79, 36, 247, 82, 135, 84, 71, 239, 125, 108, 221, 48, 137, 177, 250, 178, 47, 110, 23, 194]);
         const clearCheck = new TextEncoder().encode('nord farm bolt correct bee nonchalant flap high able pinch left quaint angle 2055 exultant disgusted curved bless geese snatch zoom fat touch boot abject wink pretty accessible foamy');
         const hintCheck = 'roylalty';
         const pwd = 'lkf3h20osdfid';
         const blob = new Blob([ctBytes], { type: 'application/octet-stream' });

         const decryptedStream = await cipherSvc.decryptStream(
            async (hint) => {
               expect(hint).toEqual(hintCheck);
               return pwd;
            },
            userCred,
            blob.stream()
         );

         // use byod mode to also test stream byod support
         const reader = new BYOBStreamReader(decryptedStream);
         let buffer = new ArrayBuffer(clearCheck.byteLength);

         const [decrypted] = await reader.readFill(buffer);
         reader.cleanup();
         expect(isEqualArray(decrypted, clearCheck)).toBeTrue();
      }
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

         const clearData = new TextEncoder().encode('This is a secret 🦋');
         const pwd = 'not good pwd';
         const hint = 'try a himt';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

         const econtext: EncContext3 = {
            alg: alg,
            ic: cc.ICOUNT_MIN,
            trueRand: false,
            fallbackRand: true,
            pwd: pwd,
            hint: hint,
            userCred: userCred,
         };
         const cipherData = await cipherSvc.encryptBuffer(econtext, clearData);
         const cipherInfo = await cipherSvc.getCipherTextInfo(userCred, cipherData);

         const expected_iv_bytes = Number(cc.AlgInfo[alg]['iv_bytes']);

         expect(cipherInfo.alg).toEqual(alg);
         expect(cipherInfo.ic).toEqual(cc.ICOUNT_MIN);
         expect(cipherInfo.iv.byteLength).toEqual(expected_iv_bytes);
         expect(cipherInfo.slt.byteLength).toEqual(cc.SLT_BYTES);
         expect(cipherInfo.hint).toBeTrue();
      }
   });

   it("detect corrupted cipherdata MAC, all algorithms", async function () {

      for (const alg of cipherSvc.algs()) {

         const clearData = new TextEncoder().encode("OIH8whfsiodhf s.kd");
         const pwd = 'another good pwd';
         const hint = 'nope';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

         const econtext: EncContext3 = {
            alg: alg,
            ic: cc.ICOUNT_MIN,
            trueRand: false,
            fallbackRand: true,
            pwd: pwd,
            hint: hint,
            userCred: userCred,
         };

         let cipherData = await cipherSvc.encryptBuffer(econtext, clearData);

         // Change value in payload
         let problemData = pokeValue(cipherData, 42, 1);

         await expectAsync(
            cipherSvc.getCipherTextInfo(
               userCred,
               problemData
            )
         ).toBeRejectedWithError(Error, new RegExp('.+MAC.+'));
      }
   });

   it("detect corrupted payload Size, all algorithms", async function () {

      for (const alg of cipherSvc.algs()) {

         const clearData = new TextEncoder().encode("OIH8whfsiodhf s.kd");
         const pwd = 'another good pwd';
         const hint = 'nope';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

         const econtext: EncContext3 = {
            alg: alg,
            ic: cc.ICOUNT_MIN,
            trueRand: false,
            fallbackRand: true,
            pwd: pwd,
            hint: hint,
            userCred: userCred,
         };

         let cipherData = await cipherSvc.encryptBuffer(econtext, clearData);

         // Change value in payload size
         let problemData = pokeValue(cipherData, 37, 3);

         await expectAsync(
            cipherSvc.getCipherTextInfo(
               userCred,
               problemData
            )
         ).toBeRejectedWithError(Error, new RegExp('.+payload size.+'));
      }
   });

   it("detect invalid userCred", async function () {

      const clearData = new TextEncoder().encode("f");
      const pwd = 'another good pwd';
      const hint = 'nope';
      const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

      const econtext: EncContext3 = {
         alg: 'AES-GCM',
         ic: cc.ICOUNT_MIN,
         trueRand: false,
         fallbackRand: true,
         pwd: pwd,
         hint: hint,
         userCred: userCred,
      };
      let cipherData = await cipherSvc.encryptBuffer(econtext, clearData);

      // Doesn't match orignal userCred
      let problemUserCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));
      await expectAsync(
         cipherSvc.getCipherTextInfo(
            problemUserCred,
            cipherData
         )
      ).toBeRejectedWithError(Error, new RegExp('.+MAC.+'));

      // Missing one byte of userCred
      problemUserCred = userCred.slice(0, userCred.byteLength - 1);
      await expectAsync(
         cipherSvc.getCipherTextInfo(
            problemUserCred,
            cipherData
         )
      ).toBeRejectedWithError(Error);

      // One bytes extra
      problemUserCred = new Uint8Array(cc.USERCRED_BYTES + 1);
      problemUserCred.set(userCred);
      problemUserCred.set([0], userCred.byteLength);
      await expectAsync(
         cipherSvc.getCipherTextInfo(
            problemUserCred,
            cipherData
         )
      ).toBeRejectedWithError(Error);
   });
});
*/