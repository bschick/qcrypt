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
import { Ciphers, Encipher, Decipher } from './ciphers';
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
      Encipher.testingFlag = true;
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

function streamFromBase64(b64: string): [ReadableStream<Uint8Array>, Uint8Array] {
   const data = base64ToBytes(b64);
   const blob = new Blob([data], { type: 'application/octet-stream' });
   return [blob.stream(), data];
}

describe("Stream encryption and decryption", function () {

   let cipherSvc: CipherService;
   beforeEach(() => {
      TestBed.configureTestingModule({});
      Encipher.testingFlag = true;
      cipherSvc = TestBed.inject(CipherService);
   });

   it("successful round trip, all algorithms, no pwd hint", async function () {

      for (const alg of cipherSvc.algs()) {

         const srcString = 'This is a secret 🦆';
         const [clearStream, clearData] = streamFromStr(srcString);
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

         const resString = await readStreamAll(decrypted, true);
         expect(resString).toEqual(srcString);
      }
   });

   it("successful round trip, all algorithms", async function () {

      for (const alg of cipherSvc.algs()) {

         const srcString = 'This is a secret 🦆';
         const [clearStream, clearData] = streamFromStr(srcString);
         const pwd = 'a good pwd';
         const hint = 'not really';
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
               return [pwd, hint];
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

         const resString = await readStreamAll(decrypted, true);
         expect(resString).toEqual(srcString);
      }
   });

   it("successful round trip, all algorithms, loops", async function () {

      for (const alg of cipherSvc.algs()) {

         const srcString = 'This is a secret 🦆';
         const [clearStream, clearData] = streamFromStr(srcString);
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

         const econtext: EncContext3 = {
            alg: alg,
            ic: cc.ICOUNT_MIN,
            trueRand: false,
            fallbackRand: true,
            lpEnd: 3
         };

         let expectedLp = 1;

         const cipherStream = await cipherSvc.encryptStream(
            econtext,
            async (lp, lpEnd) => {
               expect(lp).toEqual(expectedLp);
               expect(lpEnd).toEqual(3);
               expectedLp += 1;
               return [String(lp), String(lp)];
            },
            userCred,
            clearStream,
            (params) => {
               expect(params.alg).toEqual(alg);
               expect(params.ic).toEqual(cc.ICOUNT_MIN);
            }
         );

         expectedLp = 3;

         const decrypted = await cipherSvc.decryptStream(
            async (lp, lpEnd, decHint) => {
               expect(lp).toEqual(expectedLp);
               expect(lpEnd).toEqual(3);
               expect(decHint).toEqual(String(lp));
               expectedLp -= 1;
               return [decHint!, undefined];
            },
            userCred,
            cipherStream,
            (params) => {
               expect(params.alg).toEqual(alg);
               expect(params.ic).toEqual(cc.ICOUNT_MIN);
            }
         );

         const resString = await readStreamAll(decrypted, true);
         expect(resString).toEqual(srcString);
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

   it("confirm successful version decryption, v4", async function () {
      // These are generated with running website
      const cts = [
         // AEG-GCM: V4
         "4pbVthrII9ejsB0QMVxM_8eVhBcx9AniiH_jB9f0oAkEAAcBAAABAMBOfz4z4j-XjmUIjdm2maNK1HObgT-jCNiGB1fgyBAAABVTww8FCVeXexY7HYAoPkKQsx24Pqxu451SMBrhGDVScst_s7Ep8uNMVUbglWitlMEI9pmOWxAkUZYVMEFxVlka_Hbq9qBheD5YRijGqlzaRiSAz6D6Gh5eTecJ0xfQpKIe4qXgQ-1AsWbEUig4Zk1r7fpMIszUAU3qy2wbD3JAqiSszUu1pWFtgfwPLFSjZv6oO3-exZSuOCNi7G8zqpbDPsquTdyc8FX_GpG4YD_OD755seUtVT4oBKXmwcKIoM_RhgcoBiRDqOvCWurBDIjbLVRcONe2PrZgotRDwgZ2UvEYtw",

         // XChaCha: V4
         "0hCjaRFwORsn5JPafhwRy9qV1Qt6t07FBFN9_wLNVeIEABMBAAACAJwKA2CZb8-wP4QC5wpi1KOuqI2kuurdtZij3ss2J3VxW8z0AZeunm3gyBAAABV0wEHCHvwmalDVcixk-Kk3whlnehP3UQuIZ8PZlSD04D5pDnsy7PjzXZnkfqd79fOcSpa7VfSG0NAVyGGjicLxMGPcio7wE71Pn2BC1m9jklIZGbw_Szzp7l9iorLBd9KOQq5bl5bo3D6iLFsZcHYVXc9_miqHXSI9_iorXRrS0BurFpsFSPHjbiSONOYFT2mdh-MwSQDNU-0Egab0GoltvM4-vxbjFMwLeFpR7_QRVHOXqlhdQLGyGjW6UtIpDLZLE0Ym-fiBR6A7STjeYWZWnqFni7yKygy_Ojqy5EdeRjfvOA",

         // AEGIS: V4
         "9qNOjLZ9-rH4psG5tikgFRhLfhiHLQCQrROmpFPqAAkEADsBAAADAIijvSZ00lRB-Edts0p2oEYxlrL5emmsclderCvjedg0UqNiq9mwx79iufCn3rCwieDIEAAAJfCjOKlYsM_LPXZLEmj6Bq0tOClxc764eABkaL_oxK6Ynx5SDj_Pzwa-iTXT2hbgShLadz4kMcaba_baFzmbD8HjfMehHaRApQ86KZRvfkMA1E5eFp7IIe1szgx7fyT0vE5wQeZzIB_mhsomYLdW46aP0_g5e95qjP2rLBAqav_AdC2rzWLR6AwZsuA2XgRr6uNVot4OYgFeJkVVaI0uvrmQj07D84e78-UjuU66zo6KbydWLRFm2zQBkRyGn1vAFoiv7RKM9pHWPoATJYiEG6V5pxQyZGZe-_6zKCqWF5H4wZXTuHCdb5EauQjwYGCQz2GCk7ZSztl-KYmKsSowCYPjRuw",
      ];

      for (let ct of cts) {
         const [cipherStream, cipherData] = streamFromBase64(ct);

         // userCred used for creation of the CTS above
         // b64url userCred for browsser injection: xhKm2Q404pGkqfWkTyT3UodUR-99bN0wibH6si9uF8I
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

   it("confirm successful version decryption, v4 loops", async function () {
      // These are generated with running website
      const cts = [
         // AEG-GCM, V4, 3 LPS
         "UAOJ5M6cU9KADQ8nSJcXp8qP0oS7nb3ASMXwazWynpkEANkBAAABAPkCZdIRcEGl6M_ilpaCHAG9aVYHeKeW_PgAsczgyBAAIhGvvNZ2B7hguRfFWUFg7V-QhL6Q-FIV38VshhSFjWOOFUpvVEMm8_DFCYIuBg-ejfcn8A7Qct7NcjxjHsPllutcg1sBhz8oDnYUm96g4Yp0ME_Ep1ak3qGRrBqetlN2Nomy3gDnibp4AHFVR-Gdj94wyI8GtEuWSS_m64e6026IMo3lrOucJ8IZ8oEL_OwOccBp6StpW_s9IkvCxW-Bivka2c113H-GkDMpmdc9HPX12-FOjyglSNIeuRJ0_2r4QUebLGIUZcxoK3qAOa3u6VRGt7elCRDv_GDKoWQyIXtaBOB8h2AX3h-1RGzHTAHcDWx3O_ad4ULyjoLntka66Y_LoU6Sq2GMrvB5l8eMJkHivFkD8SVcpwKJDjyvMLvJWpJo-FL-l9jnoMe2AxSIJ28qBl9bdCb931p1NZIBHlXTikhTTOkFa820JSiXkWNxF_5csS4MX4TVrHQ5-EIN-MaRif1uQoTf5XMUtoh2gPLLGEBVc9HqtGATvS6p9_PPnrHZ2XvC0JZyReAq57zXGTMfB8O2xL-hEmMzItDVi9sidRGKdM8LDvOrApBB1IEg7ZYzmq4LnA",

         // XChaCha: V4, 3 LPS
         "z0snbVnUg6MCrAC09OyOhDXGWDZ_SrpI_SKVs9fF4IwEAP0BAAACAN3UG9BXiATI48NUlSAvXH530dx-f7NC02mqNAJWcq3_tEBKS2XKnobgyBAAIhFBAXexQmL6gjq4FQcmJDZlV9av_GZ2BmWKTpcsBjrJVl1jL8A8wddfhHbrELWGytolPHiFPB3sCkTXF7Nvwud0pA04W3qTpt1LgCR4Zqwd-QFGNAkl2_yD8Hw8vQMJu1zoi1T05wvYTSFtQu68FVYHh1Hg_BLC3qXKQdmEePWP0YDzxTKqGbp1zzXmAY4X8NtIyw7lPyOaEaL0JNulCvkLMq-7rxBL4v-OUmK4CSTYn3_tSpzaU2e2b1hcJGIM_1s5VEYpixwH4U53CRNeUhhVy1V-BYrr_Wb34eAejYIA-G08ztHz5NxBQlfS849jNif5qihO-6pQDRN_gTYZ4pv0uAQzL2A2gi-jBPqTI7ES1hkX3VYfRBgJ33-9_y-fcBIH-k4RVlbg0NZ_Gy_umTc_gRYBocIZrlXHfYyyCHGQvkUpK3pFXrggB4B4YCfMrmWGwze6iJk9A0-jFBNnFmkglwfF8ru9PeHdK-Duf-lkqx70cRyAOCiWk55EwfTaXM80zRCvef6kG77mppK_2MhvWgsqAqqyRqgv8xUUwiO658UCjaeuOuAf2m1EsOQpmqcqEueuSHRW3JNajKPRE47K4Mq1bAZ1yL-hDTLfYQ",

         // AEGIS: V4, 3 LPS
         "AqjJe0x_GChxY-Z9bt2ZSk0-PUIeKoCoLUBleSCPp5gEAHUCAAADAKz1zLmRbFugjv3u5xN4k2H6Lb_WGPeRsBX-J3n4_j8VZwA9BPGMfnH2GltYCtKqMuDIEAAiIdMVRyGeIb0OpQG1_NCGvTVzdWwTfjq9vAR9g1cfm9Q6MDxX3p2TS_EKH26O4SOqwrmilRV6Qyer4Tx7NTUpMaJIXmD_j5KOh3P_nkfZ1IAGYj_nUfDaGTaW7_fao1udKaxlTSj7M-_-mRZ18UUEvEazOwrkuYFBBcur8y-k5tKLZSfhjeODD4-rup7rSON2XOvaX_FET5S13ga-DOluX7ITb9NJphSW3_g1l7267iLrmFOmVO3XBGnenPgeUl2D4aadSHfzc0iIkLIWs8WOe54LAwAvbJFMupAC-NDCZ4_OamDb4OwLq81AXnMXN1g5fifSn6SIWArQ9oN4j42y7CWpow0UfB8ansFv5F95rpljGrLJkKg1oEetP1U2YZXreSGo0seSoEFB1KlKojI5YN9UC2GeiHpzbH0dSKhhzVShJWpDG_NRNV9M-D2feNZ2E-bhsM747euXpGymFXZIxYTksF3dzQ50tJbomvLdAGNau8wS5fFDIptwK1C9p6OwZYlPWhCPs5JhBMOTdbeGvfV2rvx-fN5BTYT0hflFe-Or2YjX_jAI1YCDqYM5TxaS9XGKhqfFNYbXyexbB3V7yx4w4QqP1_NwnTn9WEsCJhQvRhBoQPYqHAJTKiaMjcCLmXMeNDDwb_5oHCJY-LTY8n0Ifn9safDdSKLnJMCypAtgOuk1ZB0JtvX7KzNisy-Dd8iyAIpKS89Y5g1sxfpXZQ8frAJnL6-O-Dcb2QU4oW3Db22JjVL_2L2dVHCwGw",
      ];

      for (let ct of cts) {
         const [cipherStream, cipherData] = streamFromBase64(ct);
         let expectedLp = 3;

         // userCred used for creation of the CTS above
         // b64url userCred for browsser injection: xhKm2Q404pGkqfWkTyT3UodUR-99bN0wibH6si9uF8I
         const userCred = new Uint8Array([198, 18, 166, 217, 14, 52, 226, 145, 164, 169, 245, 164, 79, 36, 247, 82, 135, 84, 71, 239, 125, 108, 221, 48, 137, 177, 250, 178, 47, 110, 23, 194]);
         const [_, clearCheck] = streamFromStr('physical farm bolt correct bee nonchalant glib high able pinch left quaint strip valuable exultant disgusted curved bless geese snatch zoom fat touch boot abject wink pretty accessible foamy');
         const hintCheck = 'royal';

         const clearStream = await cipherSvc.decryptStream(
            async (lp, lpEnd, hint) => {
               expect(lp).toEqual(expectedLp);
               expect(lpEnd).toEqual(3);
               expect(Number(hint)).toEqual(expectedLp);
               expectedLp -= 1;
               return [hint!, undefined];
            },
            userCred,
            cipherStream
         );

         await expectAsync(
            areEqual(clearStream, clearCheck)
         ).toBeResolvedTo(true);
      }
   });

   // using  base64-url alphabet
   const b64a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
   const b64o = 'BCDEFGHIJKLMNOPQRSTUVWXYZAbcdefghijklmnopqrstuvwxyza1234567890_-';

   it("detect corrupt cipher text, all algs", async function () {
      //AES-GCM, X20-PLY, AEGIS-256
      const cts = [
         "eVMF6PzrEgx_XjftDM_dNDQgVWEGxAMuh0tSPEzVmFgEAF4AAAABAI_U2i3D1Q2QkdYuJTW2foBDIGBT122M_RGcb5vgyBAAABQtwX__YvRYteI4K7_YuNFgWVirS-6iuULsadb2_1n4yiTbUE_PVjMCtSOqZcT9Tk254T3TdiOv0-WB",
         "p5q5r4dV44AsP9pxwrwOK7uf90EynliXMqpQaiOczHYEAGoAAAACAMJWRiT0rS-ivexQXh-uqAZgWjQQT-vON15dSo6XwD3zs51ix2T3k8HgyBAAABTzx6m-vqvQYCQpGcaJjO-6PmqurA32TDa_Ibq2rtCsuXLAGbO-8DM6JjfJua4tNUOHZ1W1itDO7xJ9",
         "1Jnt7bRakMkdgo9s0DhbdA3RZgTxQjdpczG4bVqLtdsEAJIAAAADACkhdnd1jqoOrNpifLk1Cg7qUi6-j_0EBJyyTAvtSXxxZe2cMLuH14b8TGNIsFQ6L-DIEAAAJGmwNdy_5f7etj9t6Q1l9zwg1er2CcW4gk2AnVyzqZXvxZrq1heuiam-6RtQ4Wkx2NIUruYKnYah4IRKMfuRJVLYge042ICZneCwQ6Tg1cG8adP0P1nzEXcdJA"
      ];

      // base64Url usercred for injection in browser: ZfZIlUPklSM8fFG7nWDQ2XuT5DxU1sZ0wKKykzJ3Yfs=
      const userCred = new Uint8Array([101, 246, 72, 149, 67, 228, 149, 35, 60, 124, 81, 187, 157, 96, 208, 217, 123, 147, 228, 60, 84, 214, 198, 116, 192, 162, 178, 147, 50, 119, 97, 251]);

      for (let ct of cts) {
         const [_, clearData] = streamFromStr('this 🐞 is encrypted');
         const [cipherStream, cipherData] = streamFromBase64(ct);

         // First ensure we can decrypt with valid inputs
         const clear = await cipherSvc.decryptStream(
            async (lp, lpEnd, hint) => {
               expect(hint).toEqual("asdf");
               return ["asdf", undefined];
            },
            userCred,
            cipherStream
         );
         await expectAsync(
            areEqual(clearData, clear)
         ).toBeResolvedTo(true);

         let skipCount = 0;

         // Tweak one character at a time using b64o offsets (will remain a valid b64 string)
         for (let i = 0; i < ct.length; ++i) {
            const pos = b64a.indexOf(ct[i]);
            let corruptCt = setCharAt(ct, i, b64o[pos]);

            const [corruptStream] = streamFromBase64(corruptCt);

            // Multiple b64 strings can produce the same result, so skip those
            const orig = base64ToBytes(ct);
            const bad = base64ToBytes(corruptCt);
            if (isEqualArray(orig, bad)) {
               ++skipCount;
               expect(skipCount).toBeLessThan(10);
               continue;
            }

            await expectAsync(
               cipherSvc.decryptStream(
                  async (lp, lpEnd, hint) => {
                     expect(hint).toEqual("asdf");
                     return ["asdf", undefined];
                  },
                  userCred,
                  corruptStream
               )).toBeRejectedWithError(Error);
         }
      }
   });

   it("detect wrong password, all alogrithms", async function () {
      for (const alg of cipherSvc.algs()) {
         const [clearStream] = streamFromStr('This is a secret 🦄');
         const pwd = 'the correct pwd';
         const hint = '';
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
               expect(lp).toEqual(1);
               expect(lpEnd).toEqual(1);
               return [pwd, hint];
            },
            userCred,
            clearStream,
            (params) => {
               expect(params.alg).toEqual(alg);
               expect(params.ic).toEqual(cc.ICOUNT_MIN);
            }
         );

         const badStream = await cipherSvc.decryptStream(
            async (lp, lpEnd, decHint) => {
               expect(decHint).toEqual(hint);
               return ['the wrong pwd', undefined];
            },
            userCred,
            cipherStream
         );

         // Password isn't used until stream reading starts
         await expectAsync(
            readStreamAll(badStream)
         ).toBeRejectedWithError(DOMException);
      }
   });

   it("detect corrupted MAC sig, all algorithms", async function () {

      for (const alg of cipherSvc.algs()) {

         const [clearStream, clearData] = streamFromStr("asefwlefj4oh09f jw90fu w09fu 9");

         const pwd = 'another good pwd';
         const hint = 'nope';
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
               return [pwd, hint];
            },
            userCred,
            clearStream
         );

         const cipherData = await readStreamAll(cipherStream);

         // change in MAC
         const corruptData = pokeValue(cipherData, 3, -1);
         const [corruptStream] = streamFromBytes(corruptData);

         await expectAsync(
            cipherSvc.decryptStream(
               async (lp, lpEnd, decHint) => {
                  // should never execute
                  expect(false).toBeTrue();
                  return [pwd, undefined];
               },
               userCred,
               corruptStream
            )
         ).toBeRejectedWithError(Error, new RegExp('.+MAC.+'));
      }
   });

   it("detect crafted bad cipher text, all algorithms", async function () {

      for (const alg of cipherSvc.algs()) {
         const [clearStream, clearData] = streamFromStr("asdfh3roij 02f23kff 8u 3r90");

         const pwd = 'another good pwd';
         const hint = 'nope';
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
               return [pwd, hint];
            },
            userCred,
            clearStream
         );

         const cipherData = await readStreamAll(cipherStream);

         // Set character in cipher text
         // past ~(MAC + VER + ALG + MAX_IV + CHUCKSZ)*4/3 characters)
         let corruptData = pokeValue(cipherData, 100, -1);
         let [corruptStream] = streamFromBytes(corruptData);

         await expectAsync(
            cipherSvc.decryptStream(
               async (lp, lpEnd, decHint) => {
                  // should never execute
                  expect(false).toBeTrue();
                  return [pwd, undefined];
               },
               userCred,
               corruptStream
            )
         ).toBeRejectedWithError(Error, new RegExp('.+MAC.+'));

         // Hit another value
         corruptData = pokeValue(cipherData, cipherData.length - 30, 4);
         [corruptStream] = streamFromBytes(corruptData);

         await expectAsync(
            cipherSvc.decryptStream(
               async (lp, lpEnd, decHint) => {
                  // should never execute
                  expect(false).toBeTrue();
                  return [pwd, undefined];
               },
               userCred,
               corruptStream
            )
         ).toBeRejectedWithError(Error, new RegExp('.+MAC.+'));
      }
   });


   it("detect encryption argument errors", async function () {

      let [clearStream, clearData] = streamFromStr("()*Hskdfo892hj3f09");

      const hint = 'nope';
      const pwd = 'another good pwd';
      const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

      const econtext: EncContext3 = {
         alg: 'AES-GCM',
         ic: cc.ICOUNT_MIN,
         trueRand: false,
         fallbackRand: true,
         lpEnd: 1
      };

      let cipherStream = await cipherSvc.encryptStream(
         econtext,
         async (lp, lpEnd) => {
            return [pwd, hint];
         },
         userCred,
         clearStream
      );

      await expectAsync(
         readStreamAll(cipherStream)
      ).toBeResolved();

      // empty pwd
      [clearStream] = streamFromBytes(clearData);

      cipherStream = await cipherSvc.encryptStream(
         econtext,
         async (lp, lpEnd) => {
            return ['', hint];
         },
         userCred,
         clearStream
      );

      await expectAsync(
         readStreamAll(cipherStream)
      ).toBeRejectedWithError(Error, new RegExp('Missing password.*'));


      // hint too long
      [clearStream] = streamFromBytes(clearData);

      cipherStream = await cipherSvc.encryptStream(
         econtext,
         async (lp, lpEnd) => {
            return [pwd, 'this is too long'.repeat(8)];
         },
         userCred,
         clearStream
      );

      await expectAsync(
         readStreamAll(cipherStream)
      ).toBeRejectedWithError(Error, new RegExp('Hint length.+'));

      // no userCred
      [clearStream] = streamFromBytes(clearData);

      await expectAsync(
         cipherSvc.encryptStream(
            econtext,
            async (lp, lpEnd) => {
               return [pwd, hint];
            },
            new Uint8Array(0),
            clearStream
         )
      ).toBeRejectedWithError(Error, new RegExp('.+userCred.*'));

      // extra long userCred
      [clearStream] = streamFromBytes(clearData);

      await expectAsync(
         cipherSvc.encryptStream(
            econtext,
            async (lp, lpEnd) => {
               return [pwd, hint];
            },
            crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES + 2)),
            clearStream
         )
      ).toBeRejectedWithError(Error, new RegExp('.+userCred.*'));

      // empty clear data
      [clearStream] = streamFromBytes(new Uint8Array());

      cipherStream = await cipherSvc.encryptStream(
         econtext,
         async (lp, lpEnd) => {
            return [pwd, hint];
         },
         userCred,
         clearStream
      );

      await expectAsync(
         readStreamAll(cipherStream)
      ).toBeRejectedWithError(Error, new RegExp('Missing clear.+'));

      // ic too small
      [clearStream] = streamFromBytes(clearData);

      let bcontext = {
         ...econtext,
         ic: cc.ICOUNT_MIN - 1
      };

      await expectAsync(
         cipherSvc.encryptStream(
            bcontext,
            async (lp, lpEnd) => {
               return [pwd, hint];
            },
            userCred,
            clearStream
         )
      ).toBeRejectedWithError(Error, new RegExp('Invalid ic.+'));

      // ic too big
      [clearStream] = streamFromBytes(clearData);

      bcontext = {
         ...econtext,
         ic: cc.ICOUNT_MAX + 1
      };

      await expectAsync(
         cipherSvc.encryptStream(
            bcontext,
            async (lp, lpEnd) => {
               return [pwd, hint];
            },
            userCred,
            clearStream
         )
      ).toBeRejectedWithError(Error, new RegExp('Invalid ic.+'));


      // invalid alg
      [clearStream] = streamFromBytes(clearData);

      bcontext = {
         ...econtext,
         alg: 'ABS-GCM'
      };

      await expectAsync(
         cipherSvc.encryptStream(
            bcontext,
            async (lp, lpEnd) => {
               return [pwd, hint];
            },
            userCred,
            clearStream
         )
      ).toBeRejectedWithError(Error, new RegExp('Invalid alg.+'));

      // really invalid alg
      [clearStream] = streamFromBytes(clearData);

      bcontext = {
         ...econtext,
         alg: 'asdfadfsk'
      };

      await expectAsync(
         cipherSvc.encryptStream(
            bcontext,
            async (lp, lpEnd) => {
               return [pwd, hint];
            },
            userCred,
            clearStream
         )
      ).toBeRejectedWithError(Error, new RegExp('Invalid alg.+'));

      // both rands false
      [clearStream] = streamFromBytes(clearData);

      bcontext = {
         ...econtext,
         trueRand: false,
         fallbackRand: false
      };

      await expectAsync(
         cipherSvc.encryptStream(
            bcontext,
            async (lp, lpEnd) => {
               return [pwd, hint];
            },
            userCred,
            clearStream
         )
      ).toBeRejectedWithError(Error, new RegExp('Either trueRand.+'));
   });
});

describe("Stream manipulation", function () {

   let cipherSvc: CipherService;
   beforeEach(() => {
      TestBed.configureTestingModule({});
      Encipher.testingFlag = true;
      cipherSvc = TestBed.inject(CipherService);
   });

   // userCred used for creation of the CTS above
   // b64url userCred for browsser injection: xhKm2Q404pGkqfWkTyT3UodUR-99bN0wibH6si9uF8I
   const userCred = new Uint8Array([198, 18, 166, 217, 14, 52, 226, 145, 164, 169, 245, 164, 79, 36, 247, 82, 135, 84, 71, 239, 125, 108, 221, 48, 137, 177, 250, 178, 47, 110, 23, 194]);
   // Also replace following value in cipher.ts to create small blocks
   //const READ_SIZE_START = 1048576/1024/4;
   //const READ_SIZE_MAX = READ_SIZE_START * 41


   const ct = "2RjcbWSoJnBeV0P6ORbkOMWg2F301QTpYDAXnHsXBP4EAEgBAAABAAKtugV3PYYkwIdrtOAmA6tCubzGl8Wh9AS2_uLgyBAAABRI-cqQ1QNm7pco71Laehr8i5Lt7jUO7ZA3YD377qe9OTjKAt5FKYaHosrz4X3xGXwhkr4j5AgmQaVI6h8jm7nmj820LBsjEe2ydWs7U9nzceyNJxblSQsj1ysYYWZGoTzRzgsMtBpM3Qgh1CQPqUZljH28FwejuZdnzP5goO6mkp2fS7NDKmVCZal8nvE0r2SeCK3MbPuK-l3IZsGKb9QnebTTninA3ua1l5kb0E2rNcxJOPc46qr3Um6UEg1IR-1Bmjl0yBQsTW_Zz29blsGUbB6gITjA-_bPrb4IpqmMdJ9un_mkuEnW4eKykdAkOxcd-fXZ7rd2OdN4y_YOubAv5KotdlB8yqL9Tctq7X010Y0LhUKNhcE7wQNytAxcYQgM_XjnNl2fw_G7OiwbryKuftS7eLm9Hs8q_TCNU2H0sHIp2VcEAG4BAAABAGcbFf4hutrWIBfz4T-1F2hDy2DElsXYIVmNKX32BOAqxigAPDWI-25OJiIXvIkz74wSUEVX-o00nNgIi3fkpBKy0WA3IC1ZGsVhtfsxcD79QXuXDEqY3iyecc4stBQbRgBSlio60skuTmvK0rbgyLoKIcVCcZub2QvIMOZzYe2OLBXBI8f7kXi3v7FcK9QX__n4rjQrWsYin4CaQWU6NM-k6pUPjAKTDxOUPZsJSF0sJaCYbM9mEbztmT-bTbWn_eGcTs6ZsiVZBB_IaBHPgZUYaAxCivZcM9hb9Jc41P7OlLPCG_7Dj-KKHktkAT51Yr74gWIEb0-vzK1CWLdo9WBTdxPkc2tjIV2A8Kqm9nwVl1_aqw8sXrOIVmGyMhmE53nd5dZtl-DptGuErjC9PD1UDnkvumCadbiioUtXXFGFZ3ovDWjsR37b6HAdIu8n3JNe3uYTqbKh20ns2T2wwfrcVXLmmeR495mT5FU";
   const cipherData = new Uint8Array([217, 24, 220, 109, 100, 168, 38, 112, 94, 87, 67, 250, 57, 22, 228, 56, 197, 160, 216, 93, 244, 213, 4, 233, 96, 48, 23, 156, 123, 23, 4, 254, 4, 0, 72, 1, 0, 0, 1, 0, 2, 173, 186, 5, 119, 61, 134, 36, 192, 135, 107, 180, 224, 38, 3, 171, 66, 185, 188, 198, 151, 197, 161, 244, 4, 182, 254, 226, 224, 200, 16, 0, 0, 20, 72, 249, 202, 144, 213, 3, 102, 238, 151, 40, 239, 82, 218, 122, 26, 252, 139, 146, 237, 238, 53, 14, 237, 144, 55, 96, 61, 251, 238, 167, 189, 57, 56, 202, 2, 222, 69, 41, 134, 135, 162, 202, 243, 225, 125, 241, 25, 124, 33, 146, 190, 35, 228, 8, 38, 65, 165, 72, 234, 31, 35, 155, 185, 230, 143, 205, 180, 44, 27, 35, 17, 237, 178, 117, 107, 59, 83, 217, 243, 113, 236, 141, 39, 22, 229, 73, 11, 35, 215, 43, 24, 97, 102, 70, 161, 60, 209, 206, 11, 12, 180, 26, 76, 221, 8, 33, 212, 36, 15, 169, 70, 101, 140, 125, 188, 23, 7, 163, 185, 151, 103, 204, 254, 96, 160, 238, 166, 146, 157, 159, 75, 179, 67, 42, 101, 66, 101, 169, 124, 158, 241, 52, 175, 100, 158, 8, 173, 204, 108, 251, 138, 250, 93, 200, 102, 193, 138, 111, 212, 39, 121, 180, 211, 158, 41, 192, 222, 230, 181, 151, 153, 27, 208, 77, 171, 53, 204, 73, 56, 247, 56, 234, 170, 247, 82, 110, 148, 18, 13, 72, 71, 237, 65, 154, 57, 116, 200, 20, 44, 77, 111, 217, 207, 111, 91, 150, 193, 148, 108, 30, 160, 33, 56, 192, 251, 246, 207, 173, 190, 8, 166, 169, 140, 116, 159, 110, 159, 249, 164, 184, 73, 214, 225, 226, 178, 145, 208, 36, 59, 23, 29, 249, 245, 217, 238, 183, 118, 57, 211, 120, 203, 246, 14, 185, 176, 47, 228, 170, 45, 118, 80, 124, 202, 162, 253, 77, 203, 106, 237, 125, 53, 209, 141, 11, 133, 66, 141, 133, 193, 59, 193, 3, 114, 180, 12, 92, 97, 8, 12, 253, 120, 231, 54, 93, 159, 195, 241, 187, 58, 44, 27, 175, 34, 174, 126, 212, 187, 120, 185, 189, 30, 207, 42, 253, 48, 141, 83, 97, 244, 176, 114, 41, 217, 87, 4, 0, 110, 1, 0, 0, 1, 0, 103, 27, 21, 254, 33, 186, 218, 214, 32, 23, 243, 225, 63, 181, 23, 104, 67, 203, 96, 196, 150, 197, 216, 33, 89, 141, 41, 125, 246, 4, 224, 42, 198, 40, 0, 60, 53, 136, 251, 110, 78, 38, 34, 23, 188, 137, 51, 239, 140, 18, 80, 69, 87, 250, 141, 52, 156, 216, 8, 139, 119, 228, 164, 18, 178, 209, 96, 55, 32, 45, 89, 26, 197, 97, 181, 251, 49, 112, 62, 253, 65, 123, 151, 12, 74, 152, 222, 44, 158, 113, 206, 44, 180, 20, 27, 70, 0, 82, 150, 42, 58, 210, 201, 46, 78, 107, 202, 210, 182, 224, 200, 186, 10, 33, 197, 66, 113, 155, 155, 217, 11, 200, 48, 230, 115, 97, 237, 142, 44, 21, 193, 35, 199, 251, 145, 120, 183, 191, 177, 92, 43, 212, 23, 255, 249, 248, 174, 52, 43, 90, 198, 34, 159, 128, 154, 65, 101, 58, 52, 207, 164, 234, 149, 15, 140, 2, 147, 15, 19, 148, 61, 155, 9, 72, 93, 44, 37, 160, 152, 108, 207, 102, 17, 188, 237, 153, 63, 155, 77, 181, 167, 253, 225, 156, 78, 206, 153, 178, 37, 89, 4, 31, 200, 104, 17, 207, 129, 149, 24, 104, 12, 66, 138, 246, 92, 51, 216, 91, 244, 151, 56, 212, 254, 206, 148, 179, 194, 27, 254, 195, 143, 226, 138, 30, 75, 100, 1, 62, 117, 98, 190, 248, 129, 98, 4, 111, 79, 175, 204, 173, 66, 88, 183, 104, 245, 96, 83, 119, 19, 228, 115, 107, 99, 33, 93, 128, 240, 170, 166, 246, 124, 21, 151, 95, 218, 171, 15, 44, 94, 179, 136, 86, 97, 178, 50, 25, 132, 231, 121, 221, 229, 214, 109, 151, 224, 233, 180, 107, 132, 174, 48, 189, 60, 61, 84, 14, 121, 47, 186, 96, 154, 117, 184, 162, 161, 75, 87, 92, 81, 133, 103, 122, 47, 13, 104, 236, 71, 126, 219, 232, 112, 29, 34, 239, 39, 220, 147, 94, 222, 230, 19, 169, 178, 161, 219, 73, 236, 217, 61, 176, 193, 250, 220, 85, 114, 230, 153, 228, 120, 247, 153, 147, 228, 85]);
   const clearData = new Uint8Array([118, 101, 114, 115, 105, 111, 110, 58, 32, 34, 51, 46, 56, 34, 10, 115, 101, 114, 118, 105, 99, 101, 115, 58, 10, 32, 32, 100, 111, 99, 107, 103, 101, 58, 10, 32, 32, 32, 32, 105, 109, 97, 103, 101, 58, 32, 108, 111, 117, 105, 115, 108, 97, 109, 47, 100, 111, 99, 107, 103, 101, 58, 49, 10, 32, 32, 32, 32, 114, 101, 115, 116, 97, 114, 116, 58, 32, 117, 110, 108, 101, 115, 115, 45, 115, 116, 111, 112, 112, 101, 100, 10, 32, 32, 32, 32, 112, 111, 114, 116, 115, 58, 10, 32, 32, 32, 32, 32, 32, 45, 32, 53, 48, 48, 49, 58, 53, 48, 48, 49, 10, 32, 32, 32, 32, 118, 111, 108, 117, 109, 101, 115, 58, 10, 32, 32, 32, 32, 32, 32, 45, 32, 47, 118, 97, 114, 47, 114, 117, 110, 47, 100, 111, 99, 107, 101, 114, 46, 115, 111, 99, 107, 58, 47, 118, 97, 114, 47, 114, 117, 110, 47, 100, 111, 99, 107, 101, 114, 46, 115, 111, 99, 107, 10, 32, 32, 32, 32, 32, 32, 45, 32, 46, 47, 100, 97, 116, 97, 58, 47, 97, 112, 112, 47, 100, 97, 116, 97, 10, 32, 32, 32, 32, 32, 32, 35, 32, 83, 116, 97, 99, 107, 115, 32, 68, 105, 114, 101, 99, 116, 111, 114, 121, 10, 32, 32, 32, 32, 32, 32, 35, 32, 226, 154, 160, 239, 184, 143, 32, 82, 69, 65, 68, 32, 73, 84, 32, 67, 65, 82, 69, 70, 85, 76, 76, 89, 46, 32, 73, 102, 32, 121, 111, 117, 32, 100, 105, 100, 32, 105, 116, 32, 119, 114, 111, 110, 103, 44, 32, 121, 111, 117, 114, 32, 100, 97, 116, 97, 32, 99, 111, 117, 108, 100, 32, 101, 110, 100, 32, 117, 112, 32, 119, 114, 105, 116, 105, 110, 103, 32, 105, 110, 116, 111, 32, 97, 32, 87, 82, 79, 78, 71, 32, 80, 65, 84, 72, 46, 10, 32, 32, 32, 32, 32, 32, 35, 32, 226, 154, 160, 239, 184, 143, 32, 49, 46, 32, 70, 85, 76, 76, 32, 112, 97, 116, 104, 32, 111, 110, 108, 121, 46, 32, 78, 111, 32, 114, 101, 108, 97, 116, 105, 118, 101, 32, 112, 97, 116, 104, 32, 40, 77, 85, 83, 84, 41, 10, 32, 32, 32, 32, 32, 32, 35, 32, 226, 154, 160, 239, 184, 143, 32, 50, 46, 32, 76, 101, 102, 116, 32, 83, 116, 97, 99, 107, 115, 32, 80, 97, 116, 104, 32, 61, 61, 61, 32, 82, 105, 103, 104, 116, 32, 83, 116, 97, 99, 107, 115, 32, 80, 97, 116, 104, 32, 40, 77, 85, 83, 84, 41, 10, 32, 32, 32, 32, 32, 32, 45, 32, 47, 111, 112, 116, 47, 115, 116, 97, 99, 107, 115, 58, 47, 111, 112, 116, 47, 115, 116, 97, 99, 107, 115, 10, 32, 32, 32, 32, 101, 110, 118, 105, 114, 111, 110, 109, 101, 110, 116, 58, 10, 32, 32, 32, 32, 32, 32, 35, 32, 84, 101, 108, 108, 32, 68, 111, 99, 107, 103, 101, 32, 119, 104, 101, 114, 101, 32, 116, 111, 32, 102, 105, 110, 100, 32, 116, 104, 101, 32, 115, 116, 97, 99, 107, 115, 10, 32, 32, 32, 32, 32, 32, 45, 32, 68, 79, 67, 75, 71, 69, 95, 83, 84, 65, 67, 75, 83, 95, 68, 73, 82, 61, 47, 111, 112, 116, 47, 115, 116, 97, 99, 107, 115]);

   const block0MACOffset = 0;
   const block0VerOffset = block0MACOffset + cc.MAC_BYTES;
   const block0SizeOffset = block0VerOffset + cc.VER_BYTES;
   const block0ADOffset = block0SizeOffset + cc.PAYLOAD_SIZE_BYTES;
   const block0AlgOffset = block0ADOffset;
   const block0IVOffset = block0AlgOffset + cc.ALG_BYTES;
   const block0SltOffset = block0IVOffset + Number(cc.AlgInfo['AES-GCM']['iv_bytes']);
   const block0ICOffset = block0SltOffset + cc.SLT_BYTES;
   const block0LPOffset = block0ICOffset + cc.IC_BYTES;    //LP should be at 72
   const block0HintLenOffset = block0LPOffset + cc.LPP_BYTES;
   const block0HintOffset = block0HintLenOffset + cc.HINT_LEN_BYTES;
   const block0EncOffset = block0MACOffset + 190; // in the middle of enc data

   const block1MACOffset = 366;
   const block1VerOffset = block1MACOffset + cc.MAC_BYTES;
   const block1SizeOffset = block1VerOffset + cc.VER_BYTES;
   const block1ADOffset = block1SizeOffset + cc.PAYLOAD_SIZE_BYTES;
   const block1AlgOffset = block1ADOffset;
   const block1IVOffset = block1AlgOffset + cc.ALG_BYTES;
   const block1EncOffset = block1MACOffset + 190; // in the middle of enc data

   it("detect manipulated cipher stream header, block0", async function () {

      // First make sure it decrypts as expected
      let [cipherStream] = streamFromBase64(ct);
      let dec = await cipherSvc.decryptStream(
         async (lp, lpEnd, decHint) => {
            expect(decHint).toEqual('4321');
            return ['asdf', undefined];
         },
         userCred,
         cipherStream,
         (info) => {
            expect(info.alg).toBe('AES-GCM');
            expect(info.ver).toBe(cc.VERSION4);
            expect(info.lp).toBe(1);
            expect(info.lpEnd).toBe(1);
            expect(info.ic).toBe(1100000);
            expect(info.hint).toBe(true);
         }
      );
      await expectAsync(
         areEqual(dec, clearData)
      ).toBeResolvedTo(true);

      // Modified block0 MAC
      const b0Mac = new Uint8Array(cipherData);
      b0Mac[block0MACOffset] = 255;

      let [stream] = streamFromBytes(b0Mac);
      await expectAsync(
         cipherSvc.decryptStream(
            async (lp, lpEnd) => { return ['asdf', undefined] },
            userCred,
            stream
         )
      ).toBeRejectedWithError(Error, new RegExp('Invalid MAC.+'));

      // Test modified block0 version
      const b0Ver = new Uint8Array(cipherData);
      b0Ver[block0VerOffset] = 6;
      [stream] = streamFromBytes(b0Ver);
      await expectAsync(
         cipherSvc.decryptStream(
            async (lp, lpEnd) => { return ['asdf', undefined] },
            userCred,
            stream
         )
      ).toBeRejectedWithError(Error, new RegExp('Invalid version.+'));

      // Test modified block0 size, valid size but too small
      let b0Size = new Uint8Array(cipherData);
      b0Size.set([20, 1], block0SizeOffset);
      [stream] = streamFromBytes(b0Size);
      await expectAsync(
         cipherSvc.decryptStream(
            async (lp, lpEnd) => { return ['asdf', undefined] },
            userCred,
            stream
         )
      ).toBeRejectedWithError(Error, new RegExp('Invalid MAC.+'));

      // Too small block0 size, invalid
      b0Size = new Uint8Array(cipherData);
      b0Size.set([0, 0], block0SizeOffset);
      [stream] = streamFromBytes(b0Size);
      await expectAsync(
         cipherSvc.decryptStream(
            async (lp, lpEnd) => { return ['asdf', undefined] },
            userCred,
            stream
         )
      ).toBeRejectedWithError(Error, new RegExp('Invalid payload size3.+'));

      // Test too big block0 size, invalid
      b0Size = new Uint8Array(cipherData);
      b0Size.set([255, 255, 255, 255], block0SizeOffset);
      [stream] = streamFromBytes(b0Size);
      await expectAsync(
         cipherSvc.decryptStream(
            async (lp, lpEnd) => { return ['asdf', undefined] },
            userCred,
            stream
         )
      ).toBeRejectedWithError(Error, new RegExp('Invalid payload size3.+'));

      // Test too big block0 but valid
      b0Size = new Uint8Array(cipherData);
      b0Size.set([255, 255, 255, 0], block0SizeOffset);
      [stream] = streamFromBytes(b0Size);
      await expectAsync(
         cipherSvc.decryptStream(
            async (lp, lpEnd) => { return ['asdf', undefined] },
            userCred,
            stream
         )
      ).toBeRejectedWithError(Error, new RegExp('Cipher data length mismatch1.+'));
   });

   it("detect manipulated cipher stream header, blockN", async function () {

      // First make sure it decrypts as expected
      let [cipherStream] = streamFromBase64(ct);
      let dec = await cipherSvc.decryptStream(
         async (lp, lpEnd, decHint) => {
            expect(decHint).toEqual('4321');
            return ['asdf', undefined];
         },
         userCred,
         cipherStream
      );
      await expectAsync(
         areEqual(dec, clearData)
      ).toBeResolvedTo(true);

      // Modified blockN MAC
      const bNMac = new Uint8Array(cipherData);
      bNMac[block1MACOffset] = 255;
      let [stream] = streamFromBytes(bNMac);
      dec = await cipherSvc.decryptStream(
         async (lp, lpEnd) => { return ['asdf', undefined] },
         userCred,
         stream
      );
      await expectAsync(
         readStreamAll(dec)
      ).toBeRejectedWithError(Error, new RegExp('Invalid MAC.+'));

      // Modified blockN version
      const bNVer = new Uint8Array(cipherData);
      bNVer.set([4, 1], block1VerOffset);
      [stream] = streamFromBytes(bNVer);
      dec = await cipherSvc.decryptStream(
         async (lp, lpEnd) => { return ['asdf', undefined] },
         userCred,
         stream
      );
      await expectAsync(
         readStreamAll(dec)
      ).toBeRejectedWithError(Error, new RegExp('Invalid version.+'));

      // Test modified blockN size, too small valid
      let bNSize = new Uint8Array(cipherData);
      bNSize.set([20, 1], block1SizeOffset);
      [stream] = streamFromBytes(bNSize);
      dec = await cipherSvc.decryptStream(
         async (lp, lpEnd) => { return ['asdf', undefined] },
         userCred,
         stream
      );
      await expectAsync(
         readStreamAll(dec)
      ).toBeRejectedWithError(Error, new RegExp('Invalid MAC.+'));

      // Too small blockN size, too small invalid
      bNSize = new Uint8Array(cipherData);
      bNSize.set([0, 0], block1SizeOffset);
      [stream] = streamFromBytes(bNSize);
      dec = await cipherSvc.decryptStream(
         async (lp, lpEnd) => { return ['asdf', undefined] },
         userCred,
         stream
      );
      await expectAsync(
         readStreamAll(dec)
      ).toBeRejectedWithError(Error, new RegExp('Invalid payload.+'));

      // Test too big blockN size, invalid
      bNSize = new Uint8Array(cipherData);
      bNSize.set([255, 255, 255, 255], block1SizeOffset);
      [stream] = streamFromBytes(bNSize);
      dec = await cipherSvc.decryptStream(
         async (lp, lpEnd) => { return ['asdf', undefined] },
         userCred,
         stream
      );
      await expectAsync(
         readStreamAll(dec)
      ).toBeRejectedWithError(Error, new RegExp('Invalid payload.+'));

      // Test too big blockN but valid
      bNSize = new Uint8Array(cipherData);
      bNSize.set([255, 255, 255, 0], block1SizeOffset);
      [stream] = streamFromBytes(bNSize);
      dec = await cipherSvc.decryptStream(
         async (lp, lpEnd) => { return ['asdf', undefined] },
         userCred,
         stream
      );
      await expectAsync(
         readStreamAll(dec)
      ).toBeRejectedWithError(Error, new RegExp('Cipher data length mismatch2.+'));
   });


   it("detect manipulated cipher stream additional data, block0", async function () {

      // First make sure it decrypts as expected
      let [cipherStream] = streamFromBase64(ct);
      let dec = await cipherSvc.decryptStream(
         async (lp, lpEnd, decHint) => {
            expect(decHint).toEqual('4321');
            return ['asdf', undefined];
         },
         userCred,
         cipherStream
      );
      await expectAsync(
         areEqual(dec, clearData)
      ).toBeResolvedTo(true);

      // Modified block0 invalid ALG
      let b0Alg = new Uint8Array(cipherData);
      b0Alg[block0AlgOffset] = 128;
      let [stream] = streamFromBytes(b0Alg);
      await expectAsync(
         cipherSvc.decryptStream(
            async (lp, lpEnd) => { return ['asdf', undefined] },
            userCred,
            stream
         )
      ).toBeRejectedWithError(Error, new RegExp('Invalid alg.+'));

      // Modified block0 valid but changed ALG
      b0Alg = new Uint8Array(cipherData);
      b0Alg[block0AlgOffset] = 2;
      [stream] = streamFromBytes(b0Alg);
      // Error will be different given different cipherdata because changing the alg changes
      // the IV read len and therefore location of following values. With the current
      // cipherData, the error if first hit as invalite lp value (because wrong lp
      // position is read). Maybe change this too not look for specific error txt...
      await expectAsync(
         cipherSvc.decryptStream(
            async (lp, lpEnd) => { return ['asdf', undefined] },
            userCred,
            stream
         )
      ).toBeRejectedWithError(Error, new RegExp('Invalid lp of.+'));

      // Modified block0 IV
      let b0OIV = new Uint8Array(cipherData);
      b0OIV[block0IVOffset] = 0;
      [stream] = streamFromBytes(b0OIV);
      await expectAsync(
         cipherSvc.decryptStream(
            async (lp, lpEnd) => { return ['asdf', undefined] },
            userCred,
            stream
         )
      ).toBeRejectedWithError(Error, new RegExp('Invalid MAC.+'));

      // Modified block0 Salt
      let b0Slt = new Uint8Array(cipherData);
      b0Slt[block0SltOffset] = 1;
      [stream] = streamFromBytes(b0Slt);
      await expectAsync(
         cipherSvc.decryptStream(
            async (lp, lpEnd) => { return ['asdf', undefined] },
            userCred,
            stream
         )
      ).toBeRejectedWithError(Error, new RegExp('Invalid MAC.+'));

      // Modified block0 invalid IC
      let b0IC = new Uint8Array(cipherData);
      b0IC.set([0, 0, 0, 0], block0ICOffset);
      [stream] = streamFromBytes(b0IC);
      await expectAsync(
         cipherSvc.decryptStream(
            async (lp, lpEnd) => { return ['asdf', undefined] },
            userCred,
            stream
         )
      ).toBeRejectedWithError(Error, new RegExp('Invalid ic.+'));

      // Modified block0 valid but changed IC
      b0IC = new Uint8Array(cipherData);
      b0IC.set([64, 119, 21, 1], block0ICOffset);
      [stream] = streamFromBytes(b0IC);
      await expectAsync(
         cipherSvc.decryptStream(
            async (lp, lpEnd) => { return ['asdf', undefined] },
            userCred,
            stream
         )
      ).toBeRejectedWithError(Error, new RegExp('Invalid MAC.+'));

      // Modified block0 invalid LPP
      let b0LP = new Uint8Array(cipherData);
      b0LP[block0LPOffset] = 24; // lp > lpEnd
      [stream] = streamFromBytes(b0LP);
      await expectAsync(
         cipherSvc.decryptStream(
            async (lp, lpEnd) => { return ['asdf', undefined] },
            userCred,
            stream
         )
      ).toBeRejectedWithError(Error, new RegExp('Invalid lp.+'));

      // Modified block0 valid but changed LPP
      b0LP = new Uint8Array(cipherData);
      b0LP[block0LPOffset] = 48;
      [stream] = streamFromBytes(b0LP);
      await expectAsync(
         cipherSvc.decryptStream(
            async (lp, lpEnd) => { return ['asdf', undefined] },
            userCred,
            stream
         )
      ).toBeRejectedWithError(Error, new RegExp('Invalid MAC.+'));

      // Modified block0 hint length
      let b0HintLen = new Uint8Array(cipherData);
      b0HintLen[block0HintLenOffset] = 12;
      [stream] = streamFromBytes(b0HintLen);
      await expectAsync(
         cipherSvc.decryptStream(
            async (lp, lpEnd) => { return ['asdf', undefined] },
            userCred,
            stream
         )
      ).toBeRejectedWithError(Error, new RegExp('Invalid MAC.+'));

      // Modified block0 hint
      let b0Hint = new Uint8Array(cipherData);
      b0Hint[block0HintOffset] = 12;
      [stream] = streamFromBytes(b0Hint);
      await expectAsync(
         cipherSvc.decryptStream(
            async (lp, lpEnd) => { return ['asdf', undefined] },
            userCred,
            stream
         )
      ).toBeRejectedWithError(Error, new RegExp('Invalid MAC.+'));
   });

   it("detect manipulated cipher stream additional data, blockN", async function () {

      // First make sure it decrypts as expected
      let [cipherStream] = streamFromBase64(ct);
      let dec = await cipherSvc.decryptStream(
         async (lp, lpEnd, decHint) => {
            expect(decHint).toEqual('4321');
            return ['asdf', undefined];
         },
         userCred,
         cipherStream
      );
      await expectAsync(
         areEqual(dec, clearData)
      ).toBeResolvedTo(true);

      // Modified blockN invalid ALG
      let bNAlg = new Uint8Array(cipherData);
      bNAlg[block1AlgOffset] = 128;
      let [stream] = streamFromBytes(bNAlg);
      dec = await cipherSvc.decryptStream(
         async (lp, lpEnd) => { return ['asdf', undefined] },
         userCred,
         stream
      );
      await expectAsync(
         readStreamAll(dec)
      ).toBeRejectedWithError(Error, new RegExp('Invalid alg.+'));

      // Modified blockN valid but changed ALG
      bNAlg = new Uint8Array(cipherData);
      bNAlg[block1AlgOffset] = 2;
      [stream] = streamFromBytes(bNAlg);
      dec = await cipherSvc.decryptStream(
         async (lp, lpEnd) => { return ['asdf', undefined] },
         userCred,
         stream
      );
      // Error will be different given different cipherdata because changing the alg changes
      // the IV read len and therefore location of following values. With the current
      // cipherData, the error if first hit as invalite mac.
      // Maybe change this too not look for specific error txt...
      await expectAsync(
         readStreamAll(dec)
      ).toBeRejectedWithError(Error, new RegExp('Invalid MAC.+'));

      // Modified blockN IV
      let bNIV = new Uint8Array(cipherData);
      bNIV[block1IVOffset] = 0;
      [stream] = streamFromBytes(bNIV);
      dec = await cipherSvc.decryptStream(
         async (lp, lpEnd) => { return ['asdf', undefined] },
         userCred,
         stream
      );
      await expectAsync(
         readStreamAll(dec)
      ).toBeRejectedWithError(Error, new RegExp('Invalid MAC.+'));
   });

   it("detect manipulated cipher stream encrypted data, block0 & blockN", async function () {

      // First make sure it decrypts as expected
      let [cipherStream] = streamFromBase64(ct);
      let dec = await cipherSvc.decryptStream(
         async (lp, lpEnd, decHint) => {
            expect(decHint).toEqual('4321');
            return ['asdf', undefined];
         },
         userCred,
         cipherStream
      );
      await expectAsync(
         areEqual(dec, clearData)
      ).toBeResolvedTo(true);

      // Modified block0 encrypted data
      let b0Enc = new Uint8Array(cipherData);
      b0Enc[block0EncOffset] = 0;
      let [stream] = streamFromBytes(b0Enc);
      await expectAsync(
         cipherSvc.decryptStream(
            async (lp, lpEnd) => { return ['asdf', undefined] },
            userCred,
            stream
         )
      ).toBeRejectedWithError(Error, new RegExp('Invalid MAC.+'));

      // Modified blockN encrypted data
      let bNEnc = new Uint8Array(cipherData);
      bNEnc[block1EncOffset] = 0;
      [stream] = streamFromBytes(bNEnc);
      dec = await cipherSvc.decryptStream(
         async (lp, lpEnd) => { return ['asdf', undefined] },
         userCred,
         stream
      );
      await expectAsync(
         readStreamAll(dec)
      ).toBeRejectedWithError(Error, new RegExp('Invalid MAC.+'));
   });
});


describe("Benchmark execution", function () {

   let cipherSvc: CipherService;
   beforeEach(() => {
      TestBed.configureTestingModule({});
      Encipher.testingFlag = true;
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
      Encipher.testingFlag = true;
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
      Encipher.testingFlag = true;
      cipherSvc = TestBed.inject(CipherService);
   });

   it("expected CipherInfo, all algorithms", async function () {

      for (const alg of cipherSvc.algs()) {

         const srcString = 'This is a secret 🦋';
         const [clearStream, clearData] = streamFromStr(srcString);

         const pwd = 'not good pwd';
         const hint = 'try a himt';
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
               return [pwd, hint];
            },
            userCred,
            clearStream,
            (params) => {
               expect(params.alg).toEqual(alg);
               expect(params.ic).toEqual(cc.ICOUNT_MIN);
            }
         );

         const cipherInfo = await cipherSvc.getCipherStreamInfo(userCred, cipherStream);

         const expectedIVBytes = Number(cc.AlgInfo[alg]['iv_bytes']);

         expect(cipherInfo.ver).toEqual(cc.CURRENT_VERSION);
         expect(cipherInfo.alg).toEqual(alg);
         expect(cipherInfo.ic).toEqual(cc.ICOUNT_MIN);
         expect(cipherInfo.lp).toEqual(1);
         expect(cipherInfo.iv.byteLength).toEqual(expectedIVBytes);
         expect(cipherInfo.slt.byteLength).toEqual(cc.SLT_BYTES);
         expect(cipherInfo.hint).toBeTrue();
      }
   });

   it("detect invalid userCred", async function () {

      const srcString = 'f';
      const [clearStream, clearData] = streamFromStr(srcString);

      const pwd = 'another good pwd';
      const hint = 'nope';
      const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

      const econtext: EncContext3 = {
         alg: 'AEGIS-256',
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
         clearStream
      );

      // Valid, but doesn't match orignal userCred
      let problemUserCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));
      await expectAsync(
         cipherSvc.getCipherStreamInfo(
            problemUserCred,
            cipherStream
         )
      ).toBeRejectedWithError(Error, new RegExp('.+MAC.+'));

      // Missing one byte of userCred
      problemUserCred = userCred.slice(0, userCred.byteLength - 1);
      await expectAsync(
         cipherSvc.getCipherStreamInfo(
            problemUserCred,
            cipherStream
         )
      ).toBeRejectedWithError(Error, new RegExp('Invalid userCred length.+'));

      // One bytes extra userCred
      problemUserCred = new Uint8Array(cc.USERCRED_BYTES + 1);
      problemUserCred.set(userCred);
      problemUserCred.set([0], userCred.byteLength);
      await expectAsync(
         cipherSvc.getCipherStreamInfo(
            problemUserCred,
            cipherStream
         )
      ).toBeRejectedWithError(Error, new RegExp('Invalid userCred length.+'));
   });

});
