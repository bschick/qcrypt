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
import { CipherService } from './cipher.service';
import { Encipher } from './ciphers';
import {
   readStreamAll,
   base64ToBytes,
   getArrayBuffer,
} from './utils';

jasmine.DEFAULT_TIMEOUT_INTERVAL = 10000;

describe('CipherService', () => {
   let cipherSvc: CipherService;
   beforeEach(() => {
      TestBed.configureTestingModule({});
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

function randomInclusive(lower: number, upper: number): number {
   return Math.floor(Math.random() * (upper - lower + 1) + lower);
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

function streamFromBytes(data: Uint8Array): [ReadableStream<Uint8Array>, Uint8Array] {
   const blob = new Blob([getArrayBuffer(data)], { type: 'application/octet-stream' });
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
      cipherSvc = TestBed.inject(CipherService);
   });

   it("successful round trip, all algorithms, no pwd hint", async function () {

      for (const alg of cipherSvc.algs()) {

         const srcString = 'This is a secret 🦆';
         const [clearStream, clearData] = streamFromStr(srcString);
         const pwd = 'a good pwd';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

         const econtext = {
            algs: [alg],
            ic: cc.ICOUNT_MIN
         };

         const cipherStream = await cipherSvc.encryptStream(
            econtext,
            async (cdinfo) => {
               expect(cdinfo.alg).toEqual(alg);
               const ivBytes = Number(cc.AlgInfo[alg]['iv_bytes']);
               expect(cdinfo.iv.byteLength).toEqual(ivBytes);
               expect(cdinfo.slt.byteLength).toEqual(cc.SLT_BYTES);
               expect(cdinfo.ic).toEqual(cc.ICOUNT_MIN);
               expect(cdinfo.lp).toEqual(1);
               expect(cdinfo.lpEnd).toEqual(1);
               expect(cdinfo.hint).toBeFalsy();
               expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
               return [pwd, undefined];
            },
            userCred,
            clearStream
         );

         const decrypted = await cipherSvc.decryptStream(
            async (cdinfo) => {
               expect(cdinfo.alg).toEqual(alg);
               const ivBytes = Number(cc.AlgInfo[alg]['iv_bytes']);
               expect(cdinfo.iv.byteLength).toEqual(ivBytes);
               expect(cdinfo.slt.byteLength).toEqual(cc.SLT_BYTES);
               expect(cdinfo.ic).toEqual(cc.ICOUNT_MIN);
               expect(cdinfo.lp).toEqual(1);
               expect(cdinfo.lpEnd).toEqual(1);
               expect(cdinfo.hint).toBeFalsy();
               expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
               return [pwd, undefined];
            },
            userCred,
            cipherStream
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

         const econtext = {
            algs: [alg],
            ic: cc.ICOUNT_MIN
         };

         const cipherStream = await cipherSvc.encryptStream(
            econtext,
            async (cdinfo) => {
               expect(cdinfo.alg).toEqual(alg);
               const ivBytes = Number(cc.AlgInfo[alg]['iv_bytes']);
               expect(cdinfo.iv.byteLength).toEqual(ivBytes);
               expect(cdinfo.slt.byteLength).toEqual(cc.SLT_BYTES);
               expect(cdinfo.ic).toEqual(cc.ICOUNT_MIN);
               expect(cdinfo.lp).toEqual(1);
               expect(cdinfo.lpEnd).toEqual(1);
               expect(cdinfo.hint).toBeFalsy();
               expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
               return [pwd, hint];
            },
            userCred,
            clearStream
         );

         const decrypted = await cipherSvc.decryptStream(
            async (cdinfo) => {
               expect(cdinfo.alg).toEqual(alg);
               const ivBytes = Number(cc.AlgInfo[alg]['iv_bytes']);
               expect(cdinfo.iv.byteLength).toEqual(ivBytes);
               expect(cdinfo.slt.byteLength).toEqual(cc.SLT_BYTES);
               expect(cdinfo.ic).toEqual(cc.ICOUNT_MIN);
               expect(cdinfo.lp).toEqual(1);
               expect(cdinfo.lpEnd).toEqual(1);
               expect(cdinfo.hint).toEqual(hint);
               expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
               return [pwd, undefined];
            },
            userCred,
            cipherStream
         );

         const resString = await readStreamAll(decrypted, true);
         expect(resString).toEqual(srcString);
      }
   });

   it("successful round trip, all algorithms, loops", async function () {

      const maxLps = 3;
      for (const alg of cipherSvc.algs()) {

         const srcString = 'This is a secret 🦆';
         const [clearStream, clearData] = streamFromStr(srcString);
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

         const econtext = {
            algs: Array(maxLps).fill(alg),
            ic: cc.ICOUNT_MIN
         };

         let expectedEncLp = 1;

         const cipherStream = await cipherSvc.encryptStream(
            econtext,
            async (cdinfo) => {
               expect(cdinfo.lp).toEqual(expectedEncLp);
               expect(cdinfo.lpEnd).toEqual(maxLps);
               expect(cdinfo.alg).toEqual(alg);
               expect(cdinfo.ic).toEqual(cc.ICOUNT_MIN);
               expect(cdinfo.hint).toBeFalsy();
               expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
               expectedEncLp += 1;
               return [String(cdinfo.lp), String(cdinfo.lp)];
            },
            userCred,
            clearStream
         );

         let expectedDecLp = maxLps;

         const decrypted = await cipherSvc.decryptStream(
            async (cdinfo) => {
               expect(cdinfo.lp).toEqual(expectedDecLp);
               expect(cdinfo.lpEnd).toEqual(maxLps);
               expect(cdinfo.alg).toEqual(alg);
               expect(cdinfo.ic).toEqual(cc.ICOUNT_MIN);
               expect(cdinfo.hint).toEqual(String(cdinfo.lp));
               expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
               expectedDecLp -= 1;
               return [cdinfo.hint!, undefined];
            },
            userCred,
            cipherStream
         );

         const resString = await readStreamAll(decrypted, true);
         expect(resString).toEqual(srcString);
      }
   });

   it("successful round trip, mixed algorithms, loops", async function () {

      const algKeys = Object.keys(cc.AlgInfo);
      const maxLps = algKeys.length;

      const srcString = 'This is a secret 🦆';
      const [clearStream, clearData] = streamFromStr(srcString);
      const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

      const econtext = {
         algs: algKeys,
         ic: cc.ICOUNT_MIN
      };

      let expectedEncLp = 1;

      const cipherStream = await cipherSvc.encryptStream(
         econtext,
         async (cdinfo) => {
            expect(cdinfo.lp).toEqual(expectedEncLp);
            expect(cdinfo.lpEnd).toEqual(maxLps);
            expect(cdinfo.alg).toEqual(algKeys[cdinfo.lp - 1]);
            expect(cdinfo.ic).toEqual(cc.ICOUNT_MIN);
            expect(cdinfo.hint).toBeFalsy();
            expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
            expectedEncLp += 1;
            return [String(cdinfo.lp), String(cdinfo.lp)];
         },
         userCred,
         clearStream
      );

      let expectedDecLp = maxLps;

      const decrypted = await cipherSvc.decryptStream(
         async (cdinfo) => {
            expect(cdinfo.lp).toEqual(expectedDecLp);
            expect(cdinfo.lpEnd).toEqual(maxLps);
            expect(cdinfo.alg).toEqual(algKeys[cdinfo.lp - 1]);
            expect(cdinfo.ic).toEqual(cc.ICOUNT_MIN);
            expect(cdinfo.hint).toEqual(String(cdinfo.lp));
            expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
            expectedDecLp -= 1;
            return [cdinfo.hint!, undefined];
         },
         userCred,
         cipherStream
      );

      const resString = await readStreamAll(decrypted, true);
      expect(resString).toEqual(srcString);
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
            async (cdinfo) => {
               expect(cdinfo.hint).toEqual(hintCheck);
               expect(cdinfo.ver).toEqual(cc.VERSION1);
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
            async (cdinfo) => {
               expect(cdinfo.hint).toEqual(hintCheck);
               expect(cdinfo.ver).toEqual(cc.VERSION4);
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

         const clearStream = await cipherSvc.decryptStream(
            async (cdinfo) => {
               expect(cdinfo.lp).toEqual(expectedLp);
               expect(cdinfo.lpEnd).toEqual(3);
               expect(Number(cdinfo.hint)).toEqual(expectedLp);
               expect(cdinfo.ver).toEqual(cc.VERSION4);
               expectedLp -= 1;
               return [cdinfo.hint!, undefined];
            },
            userCred,
            cipherStream
         );

         await expectAsync(
            areEqual(clearStream, clearCheck)
         ).toBeResolvedTo(true);
      }
   });

   it("confirm successful version decryption, v5", async function () {
      // These are generated with running website
      const cts = [
         // AEG-GCM: V5
         "EJclA00j4FKhWMLo8zMBbT_WWDtbYo1jOJxbms2AyY4FAAcBAAEBAKi_hNzCMN2QmjCIt-NcYBDvPRpv-t45wprgBjLgyBAAABUoqck_zYTvLssZib47B_sE5nucUsko-Q7ZMkwa01AppnXeXBP2P3Ey-xHq5aeDz2E0QF4FHHTxcG1b2q6r-uDteGWqIMg-UTvIeJjTkDL-k7qmFDUx5IpQBYrtoQ_v-OFHe9YeB5LER7MXBMYkOMnoFh84gCi2pV-fnX-7hmshvMFym_zjctpk1uXsdiFUd7rJnf7S8nG5xK3FEC4b_B4F7tUmvNUqevfOZohhweC7YlUMpo0LqRC9LDOduuoTZDz2X2YmZ14dEsTuy51SvgrP_d3L-l1SK3zE6d9GGyVJLkb3GQ",

         // XChaCha: V5
         "SAJ9PKhT8wjZjBskbt4vdzg161W2KMz61C-9VKMUsagFABMBAAECADbgwlhg2FbbXs7I9uOyhtHwK3hLkNeSkE7RcghFE9tER3gZbWW4ro7gyBAAABXuVU3WRRokICOeJCnqnhmKvTQ8I0r9cu_DbFnVJuFCB604K-qQqAV84sOvNu4Dp6_b8oFbe7B97hwvy59RkJ7YVhZJbOWUgSd8SyeSxsS_8vxctfW26FuBRHGCjmCHaIzTKvhRE-A5XeWZ_E5TI9cilLmze0Gqk4Ob7c3sfB6btro-nGj5dbdQyYPST1o7IdM34F2sn8aq2no8W3q2e6IFv7t3jHpvN8hl5abkFRIAz9zBbh_U8mO36R2vimNbYwSgcawPzPSSkX83bf11qnFEu4KxJ2_JQQxWh8lGp56YhRANDQ",

         // AEGIS: V5
         "ZUDYZTXyYnJhG-9MZMD4j8ymWuNP8Oy5jr_qmISjOF0FADsBAAEDANHCkN2qd1mYu4zrsjS5AzIg9LsqLr3Dh8dJpcPkC9wK0Bwl_iFu5hpDTmyQ3P1G-eDIEAAAJbNfK1hDFINnuh3UpFAzOJnyH1fzCbjPuKFQcuZj8YfWkZV-_USgfgSqG1NLt2szc6ZMDEWoHKPPYgsRS6IH3JqrCJF8_W8RhV_1X51v9FAHE7D1VvNs5qiMiuKWN7IU9pXad18isn2leUwI0O24-8tCK7rCIX-CqGaY5y3mHEQavpoNHBD9QQKyKWNUqnWhvO39a_FtgNrtNaLx0LFLYKOpXYzFWSCbwQfeCDxXMK-J81u7z_K_OqLWTaZdjvEqaBDCqJQPapSRlgi0eh5bu94Vg9QsLKPYcFIXXjBMLOU7gNm0oRDMDok5Qu-Ln9OeWIAv1lNVS56JcYfEpOdZKYCStRc",
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
            async (cdinfo) => {
               expect(cdinfo.hint).toEqual(hintCheck);
               expect(cdinfo.ver).toEqual(cc.VERSION5);
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

   it("confirm successful version decryption, v5 loops", async function () {
      // These are generated with running website
      const cts = [
         // AES-GCM, XChaCha, AEGIS, V5, 3 LPS
         "fr1l3aTIL4-4O5shIllF7cmgx9JZ0iZdIHQLLDc71_sFABkCAAEDAI436nhP6Y5r9CQJL4ny_B9y2tylKH2ZxSzdvN6uqxoFG8CP2YqVB0vbQ46sdRAkheDIEAAiIa7leKW-j2vN4CT31z2cAH3bm1ddjQ9KPfKXIKLds8gJVy4UPbA8mQ_SKDLARhJuReb2SqmKU_17X6_nWnScIIPBMBvoOWdul0jb2cBlioOZ968OipMLRggD74pVeegvePLzQhTQvBZiyqOyRkta7tSfiwY6Pqb8efej-T3ItJ2q-It-NQdnloZBrThoP9Lh3hJUt5OwMgFrhTMy_5wOYDI_X8t-kmnfSKt8BdQKoCG-tri0Xe2OVN9_ae2u_l4bvE9-GkTjvFCw3l_egIYjYRAmBJTWv9SnIAwXDuxonTHMiw0QO3x0AYCF9rJ1Lu2pSeLZbL8ke8XUFqfULTlOiXb4Xc13q-DWFhEYNHz2go6zBmXg3dElK94mv2f8mfZyA5psvl4Kte5BJq9G4uJdqrFkqX7Snx5i5AQhP4JISK_3xCuC0DNNAk6fG0ARjMS2zrRbfjVwyPY_vw4HcQU2JhYqsgsRauoBABy-LmH3VUvFXkdvQi_lRPBD7hVqu0ZKjh0k6ZypFR_nXo4zwoi84IAG_527NCevoxgGqBvEdVaUL8-XjcJhxkreysrCFYSTYdhA-6qbBPgkoooSMhFwZjN-qku4lqKo7KIIIeGO7HT7XbyxldZN6pm4Q82gecrAGYs",

         // AEGIS, XChaCha, AEGIS: V5, 3 LPS
         "hV1RikjDpxKuimJkPcHs0ZX95pPW6LHIllYhoMdte2YFAE0CAAEDAKvbjrnfg3VDgvnILDZKbIaUGxMp5Iv9JYYr09KEhmQGVgyB62xjoffJabxC5zz3FeDIEAAiIWrG6htNwiOOBXfZu2IUwQpMiNqQVR0GegoX-aESZ1gppQNKj-b63ucKTaybnvSeiqExW9rsGFYxOz8u5qLH15_p2qZsNO-mGpc1wylR_Ge-aXaUF9P1bZn9AAMOxX3q2dtP5ey7bA22SYe_JeQiDPBGAvfzAk3WJ5GuHPmGzc3yoHZXmMMxSm2tytvJy6fEx2TkktobNnhI9eAXBxn82xX-rmM00djST2LAZQZG_SSQByzFk5rZUGLmhomiZz-SQQdVZDY45BD-zjNqj0jSGXAr8vKKwXPsAGKIq_uK7Gr-G4uw1_kkI02yu1AQjb3Jfpc8AvkD5KJ5V1Y42CSkmf07oMmrxqJ0QSGgEIxS0Za-XNdsDKJP2YoggGnRTW__EEp15xnnqwDzPxFgvhMBdCN4z03ERPy0rqTSeSYnY35ag6OrA9cBYD6kEVMIi-VVSErsqJCDNmq0kqnM2FBMFFCCVOT8pasoRtQuzXQzaXZiovmceXsGUNeMgU38AnYgYjUtYhNonYnHw-A3LsIYvzKDtshJRh1qekNqBMdycFrkxF405nEJe6kdyiaxKajYkjlXY9xbSt-AK3_0MWNNB3Adr_HiO9IQaj7hByCqQgxbHm8aLM2oK4KtIxNEE2AWSZ8xSpBrj2naCLNg21zo9iYfHytX8a_eDvTYIi-zwoh7725S2RkqRuRUQYPhX3RPhVzqKUfq",

         // AEGIS: AES-GCM, AES-GCM V5, 3 LPS
         "5HrnYQIAB6OTA8HO27AviugsbVz_otVhIU9SUGfAKN8FAA0CAAEBAJyuTIwejjoTJAMKQ5jI6umcC7Tdy3KzFfKF4qDgyBAAIhHh4OAHh7b9A0cRZQqcwvP_Y7xOKHQzGn55oxKi0YuOXtser60NoJxoMARtP0Pe-8x9aYT5T_Ml7d87zxZXfFcMk2MfOYLPpUZO6rHKZ1IXIFbrzW_YlVTgLwUwLYM01tmr9gg17kz5D1hTKRXxJ5CWq6nu_xlXwsi8Yo44OY6Ei1hpSLF8xhw1-w6oz0DRSqUedXlo2Y1KBj7e0rLBnW1WLnnJWhwSvOOaX6Cu7qslwBRQ3w12bxGQNIJLpbcw6LriQ1Tf7iBI6vmDDpSFN4r9zvJomyB2RqO9eTa6Y4u3yDrdpBlujw8LY3c0DSA_1SSkVKinYucKhNYWtwjSD9hCE-n0qgRcHZYLZB0JlyFv3on9mIdMhRDH_4sbs6b-car5nqzXxTIaoiDu5la78Y_gWjLRk7nCTONVluVHlk3pf4tZ2pf5C9SRC1PrH5q7OVmGDWhiHIpL-9twubrjB9e2_UQa2QZsVLiMdeNpmzeiqQM5maGIVFVi9AbE8q2kq8CqeHHu2YvJuG8Q2fH2RIUb4DCT-FHvyeLPl91k1ADw4JFtrHSwMHC1fxj3ZqIRic-f6MNEoJDm5ROV9O_4V77RMX3NqpSjQyxyvOk3lmaO7au-mJYg6txDqKlSeQXoxcLV4LG2Tdhj-D4",
      ];

      for (let ct of cts) {
         const [cipherStream, cipherData] = streamFromBase64(ct);
         let expectedLp = 3;

         // userCred used for creation of the CTS above
         // b64url userCred for browsser injection: xhKm2Q404pGkqfWkTyT3UodUR-99bN0wibH6si9uF8I
         const userCred = new Uint8Array([198, 18, 166, 217, 14, 52, 226, 145, 164, 169, 245, 164, 79, 36, 247, 82, 135, 84, 71, 239, 125, 108, 221, 48, 137, 177, 250, 178, 47, 110, 23, 194]);
         const [_, clearCheck] = streamFromStr('physical farm bolt correct bee nonchalant glib high able pinch left quaint strip valuable exultant disgusted curved bless geese snatch zoom fat touch boot abject wink pretty accessible foamy');

         const clearStream = await cipherSvc.decryptStream(
            async (cdinfo) => {
               expect(cdinfo.lp).toEqual(expectedLp);
               expect(cdinfo.lpEnd).toEqual(3);
               expect(Number(cdinfo.hint)).toEqual(expectedLp);
               expect(cdinfo.ver).toEqual(cc.VERSION5);
               expectedLp -= 1;
               return [cdinfo.hint!, undefined];
            },
            userCred,
            cipherStream
         );

         await expectAsync(
            areEqual(clearStream, clearCheck)
         ).toBeResolvedTo(true);
      }
   });

   it("detect missing terminal block indicator, v5", async function () {
      const [_, clearData] = streamFromStr('A nice 🦫 came to say hello');
      const pwd = 'a 🌲 of course';
      const hint = '🌧️';
      // base64url userCred for injection into browser for recreation:
      // Ohyqajb6nFOm2Y5lOTkIkhc3uAaF8sUrYrQ9pts2pDc=
      const userCred = new Uint8Array([58, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98, 180, 61, 166, 219, 54, 164, 55]);
      // manually created with missing terminal flag bit
      const [cipherStream] = streamFromBytes(new Uint8Array([225, 67, 20, 31, 134, 179, 27, 202, 138, 52, 68, 42, 197, 34, 48, 209, 76, 235, 39, 166, 101, 12, 253, 101, 237, 25, 234, 119, 91, 227, 169, 172, 5, 0, 116, 0, 0, 0, 2, 0, 53, 140, 213, 212, 134, 206, 178, 102, 222, 97, 207, 8, 252, 103, 8, 64, 25, 112, 206, 146, 159, 150, 220, 236, 162, 203, 172, 111, 119, 158, 192, 123, 81, 141, 89, 174, 126, 4, 65, 105, 64, 119, 27, 0, 0, 23, 138, 253, 130, 153, 78, 2, 31, 195, 254, 142, 102, 116, 200, 50, 125, 8, 178, 151, 113, 13, 205, 228, 10, 85, 83, 101, 57, 149, 191, 166, 4, 221, 153, 198, 0, 18, 185, 165, 203, 53, 211, 218, 24, 198, 162, 13, 99, 240, 249, 210, 255, 200, 217, 232, 10, 187, 212, 92, 204, 165, 217, 7, 202, 6, 114, 70, 200, 221]));

      const decryptedStream = await cipherSvc.decryptStream(
         async (cdinfo) => {
            expect(cdinfo.hint).toEqual(hint);
            expect(cdinfo.alg).toBe('X20-PLY');
            expect(cdinfo.ver).toBe(cc.VERSION5);
            expect(cdinfo.lp).toBe(1);
            expect(cdinfo.lpEnd).toBe(1);
            expect(cdinfo.ic).toBe(1800000);
            return [pwd, undefined];
         },
         userCred,
         cipherStream
      );

      await expectAsync(
         readStreamAll(decryptedStream)
      ).toBeRejectedWithError(Error, new RegExp('Missing terminal.+'));
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
            async (cdinfo) => {
               expect(cdinfo.hint).toEqual("asdf");
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
                  async (cdinfo) => {
                     expect(cdinfo.hint).toEqual("asdf");
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

         const econtext = {
            algs: [alg],
            ic: cc.ICOUNT_MIN
         };

         const cipherStream = await cipherSvc.encryptStream(
            econtext,
            async (cdinfo) => {
               expect(cdinfo.lp).toEqual(1);
               expect(cdinfo.lpEnd).toEqual(1);
               expect(cdinfo.alg).toEqual(alg);
               expect(cdinfo.ic).toEqual(cc.ICOUNT_MIN);
               return [pwd, hint];
            },
            userCred,
            clearStream
         );

         const decryptedStream = await cipherSvc.decryptStream(
            async (cdinfo) => {
               expect(cdinfo.hint).toEqual(hint);
               return ['the wrong pwd', undefined];
            },
            userCred,
            cipherStream
         );

         // Password isn't used until stream reading starts
         await expectAsync(
            readStreamAll(decryptedStream)
         ).toBeRejectedWithError(DOMException);
      }
   });

   it("detect wrong password, all alogrithms, loops", async function () {

      const maxLps = 3;
      const positions = [...Array(maxLps)].map((_, i) => i + 1); // javascript is so ugly sometimes
      for (const badLp of positions) {

         for (const alg of cipherSvc.algs()) {

            const srcString = 'This is a secret 🦆';
            const [clearStream, clearData] = streamFromStr(srcString);
            const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

            const econtext = {
               algs: Array(maxLps).fill(alg),
               ic: cc.ICOUNT_MIN
            };

            let expectedEncLp = 1;

            const cipherStream = await cipherSvc.encryptStream(
               econtext,
               async (cdinfo) => {
                  expect(cdinfo.lp).toEqual(expectedEncLp);
                  expect(cdinfo.lpEnd).toEqual(maxLps);
                  expect(cdinfo.alg).toEqual(alg);
                  expect(cdinfo.ic).toEqual(cc.ICOUNT_MIN);
                  expectedEncLp += 1;
                  return [String(cdinfo.lp), String(cdinfo.lp)];
               },
               userCred,
               clearStream
            );

            let expectedDecLp = maxLps;

            // When looping, a bad password (or other wrong decryption params) gets detected at different
            // points depending on the loop number. Bad values in the outer most loop are not detected until
            // reading of the decrypted stream since decryption does not start until then. Bad values for any
            // inner loop are detected at stream creation time. This happens because a decryption stream
            // reads AdditionalData at creation time to optain values like lpEnd. When the source is itself
            // another decryption stream, the inner password is required to decrypt the additionaldata. That
            // at creation of the outer stream when value like pwd are incorrect. With just one loop
            // (no nesting), additionaldata is not encrypted so the password isn't used until the data stream
            // is read.

            // In the tests Below we just ensure an exception is thrown and don't worry about which point
            // detected the bad pwd. Perhaps this is a poor design of the looped (nesting) encryption design...
            let detected = false;
            try {
               const decryptedStream = await cipherSvc.decryptStream(
                  async (cdinfo) => {
                     expect(cdinfo.lp).toEqual(expectedDecLp);
                     expect(cdinfo.lpEnd).toEqual(maxLps);
                     expect(cdinfo.hint).toEqual(String(cdinfo.lp));
                     expect(cdinfo.alg).toEqual(alg);
                     expect(cdinfo.ic).toEqual(cc.ICOUNT_MIN);
                     expectedDecLp -= 1;
                     if (cdinfo.lp == badLp) {
                        return ['wrong', undefined];
                     } else {
                        return [cdinfo.hint!, undefined];
                     }
                  },
                  userCred,
                  cipherStream
               );

               await readStreamAll(decryptedStream);

            } catch (err) {
               expect(err).toBeInstanceOf(DOMException);
               detected = true;
            }

            expect(detected).toBeTrue();
         }
      }
   });

   it("detect corrupted MAC sig, all algorithms", async function () {

      for (const alg of cipherSvc.algs()) {

         const [clearStream, clearData] = streamFromStr("asefwlefj4oh09f jw90fu w09fu 9");

         const pwd = 'another good pwd';
         const hint = 'nope';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

         const econtext = {
            algs: [alg],
            ic: cc.ICOUNT_MIN
         };

         const cipherStream = await cipherSvc.encryptStream(
            econtext,
            async (cdinfo) => {
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
               async (cdinfo) => {
                  // should never execute
                  expect(false).withContext('should not execute').toBeTrue();
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

         const econtext = {
            algs: [alg],
            ic: cc.ICOUNT_MIN
         };

         const cipherStream = await cipherSvc.encryptStream(
            econtext,
            async (cdinfo) => {
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
               async (cdinfo) => {
                  // should never execute
                  expect(false).withContext('should not execute').toBeTrue();
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
               async (cdinfo) => {
                  // should never execute
                  expect(false).withContext('should not execute').toBeTrue();
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

      const econtext = {
         algs: ['AES-GCM'],
         ic: cc.ICOUNT_MIN
      };

      let cipherStream = await cipherSvc.encryptStream(
         econtext,
         async (cdinfo) => {
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
         async (cdinfo) => {
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
         async (cdinfo) => {
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
            async (cdinfo) => {
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
            async (cdinfo) => {
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
         async (cdinfo) => {
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
            async (cdinfo) => {
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
            async (cdinfo) => {
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
         algs: ['ABS-GCM']
      };

      await expectAsync(
         cipherSvc.encryptStream(
            bcontext,
            async (cdinfo) => {
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
         algs: ['asdfadfsk']
      };

      await expectAsync(
         cipherSvc.encryptStream(
            bcontext,
            async (cdinfo) => {
               return [pwd, hint];
            },
            userCred,
            clearStream
         )
      ).toBeRejectedWithError(Error, new RegExp('Invalid alg.+'));

   });
});

describe("Stream manipulation", function () {

   let cipherSvc: CipherService;
   beforeEach(() => {
      TestBed.configureTestingModule({});
      cipherSvc = TestBed.inject(CipherService);
   });

   // userCred used for creation of the CTS above
   // b64url userCred for browser injection: xhKm2Q404pGkqfWkTyT3UodUR-99bN0wibH6si9uF8I
   const userCred = new Uint8Array([198, 18, 166, 217, 14, 52, 226, 145, 164, 169, 245, 164, 79, 36, 247, 82, 135, 84, 71, 239, 125, 108, 221, 48, 137, 177, 250, 178, 47, 110, 23, 194]);
   // Also replace following value in cipher.ts to create small blocks
   //const READ_SIZE_START = 1048576/1024/4;
   //const READ_SIZE_MAX = READ_SIZE_START * 41

   const ct = "YxDP37WZjE6JP5EBZYd113DywXGmChJgQwJ27yUZkEgFAEgBAAABAKJehRspDKhtYi8y5MvSXUNDxyqrov5RGGOs5BzgyBAAABTw7-eoyC1TGBuraNUCj00sv1OwfcpiwKyOcCZKhPdYt63ia-dg3bV9b0IOCBleMeQyCRhc61FNyKZmUp7vonh5lIbXMUKFODQqRJRhECYDUzBLuCFvfs6ojmRKXll_-unkhH9hRtFvaTR4GDWkJKI62QP992yAIPVtPjN7Y0PlxDshWrfWMKR0_-fd7cKoHmO3JXKB7i6blEupayrqtI1VRhpY1OmGkVYSQcFjlPBkXms-VCxroGk_oA2blfrocNuf0mv2-4rdL4j9ev-k0YiKDu_HkE4tuwkhJ3pdmONEIpW7KMugg3Tg6uWk4KIMYpQKI0R1M-6CYbLXWpKL71vrJ6v_qukX8nUkpiQaqaOTYX8OhFqOPhsU5ChyTmK7ChOscZ_PwjmibGRacyvou6dRDyA_sXs7wqhUe7w3CJfQaZnQAv4FAG4BAAEBAPXFxXNhZ3Gem8pWhq4W9QT8pfUpDpHNKuNcSamS6gnfE0bg9T5FDEp-B0d0LjrhUu_fstk4VOd3k_UfrHjuQ5qD-I8s4Fd9NMkjraXLh2pdAc6E8mCOhdB3pXJp7PEByohXmxfQ6wSpacnckhB4OAPSiUBASNSNNuSWQDRJHBeYIJeNKr8znow9rIRwEe7Nsc_dbmkmfsAknLZO8QR_Glpu4by16DuULi_RLtEfgjAeRzisX7WY65CqlhiQ9KbJtiVKWZXUgVAhTPv1Kyle_uCCgB4dSeZ0C9BC7F1F15QZIEogaxM8OsgpM1szhCahQQjUdj_JVWVeyQ0YKCR9Ku-WszcBdXf7v2RA6A6C30p-B7GFrT8EWod9KSYwu-jA8PMzCymt5rINNB81uOxDc3mJwfgXI0Cailb9RMiuSSvBvUQ1yOWENXhD-L6J9Dn4b6buO4RW3Jx3qrPlwn-LndPzfJgN8P19U-PBAOA=";
   const cipherData = new Uint8Array([99, 16, 207, 223, 181, 153, 140, 78, 137, 63, 145, 1, 101, 135, 117, 215, 112, 242, 193, 113, 166, 10, 18, 96, 67, 2, 118, 239, 37, 25, 144, 72, 5, 0, 72, 1, 0, 0, 1, 0, 162, 94, 133, 27, 41, 12, 168, 109, 98, 47, 50, 228, 203, 210, 93, 67, 67, 199, 42, 171, 162, 254, 81, 24, 99, 172, 228, 28, 224, 200, 16, 0, 0, 20, 240, 239, 231, 168, 200, 45, 83, 24, 27, 171, 104, 213, 2, 143, 77, 44, 191, 83, 176, 125, 202, 98, 192, 172, 142, 112, 38, 74, 132, 247, 88, 183, 173, 226, 107, 231, 96, 221, 181, 125, 111, 66, 14, 8, 25, 94, 49, 228, 50, 9, 24, 92, 235, 81, 77, 200, 166, 102, 82, 158, 239, 162, 120, 121, 148, 134, 215, 49, 66, 133, 56, 52, 42, 68, 148, 97, 16, 38, 3, 83, 48, 75, 184, 33, 111, 126, 206, 168, 142, 100, 74, 94, 89, 127, 250, 233, 228, 132, 127, 97, 70, 209, 111, 105, 52, 120, 24, 53, 164, 36, 162, 58, 217, 3, 253, 247, 108, 128, 32, 245, 109, 62, 51, 123, 99, 67, 229, 196, 59, 33, 90, 183, 214, 48, 164, 116, 255, 231, 221, 237, 194, 168, 30, 99, 183, 37, 114, 129, 238, 46, 155, 148, 75, 169, 107, 42, 234, 180, 141, 85, 70, 26, 88, 212, 233, 134, 145, 86, 18, 65, 193, 99, 148, 240, 100, 94, 107, 62, 84, 44, 107, 160, 105, 63, 160, 13, 155, 149, 250, 232, 112, 219, 159, 210, 107, 246, 251, 138, 221, 47, 136, 253, 122, 255, 164, 209, 136, 138, 14, 239, 199, 144, 78, 45, 187, 9, 33, 39, 122, 93, 152, 227, 68, 34, 149, 187, 40, 203, 160, 131, 116, 224, 234, 229, 164, 224, 162, 12, 98, 148, 10, 35, 68, 117, 51, 238, 130, 97, 178, 215, 90, 146, 139, 239, 91, 235, 39, 171, 255, 170, 233, 23, 242, 117, 36, 166, 36, 26, 169, 163, 147, 97, 127, 14, 132, 90, 142, 62, 27, 20, 228, 40, 114, 78, 98, 187, 10, 19, 172, 113, 159, 207, 194, 57, 162, 108, 100, 90, 115, 43, 232, 187, 167, 81, 15, 32, 63, 177, 123, 59, 194, 168, 84, 123, 188, 55, 8, 151, 208, 105, 153, 208, 2, 254, 5, 0, 110, 1, 0, 1, 1, 0, 245, 197, 197, 115, 97, 103, 113, 158, 155, 202, 86, 134, 174, 22, 245, 4, 252, 165, 245, 41, 14, 145, 205, 42, 227, 92, 73, 169, 146, 234, 9, 223, 19, 70, 224, 245, 62, 69, 12, 74, 126, 7, 71, 116, 46, 58, 225, 82, 239, 223, 178, 217, 56, 84, 231, 119, 147, 245, 31, 172, 120, 238, 67, 154, 131, 248, 143, 44, 224, 87, 125, 52, 201, 35, 173, 165, 203, 135, 106, 93, 1, 206, 132, 242, 96, 142, 133, 208, 119, 165, 114, 105, 236, 241, 1, 202, 136, 87, 155, 23, 208, 235, 4, 169, 105, 201, 220, 146, 16, 120, 56, 3, 210, 137, 64, 64, 72, 212, 141, 54, 228, 150, 64, 52, 73, 28, 23, 152, 32, 151, 141, 42, 191, 51, 158, 140, 61, 172, 132, 112, 17, 238, 205, 177, 207, 221, 110, 105, 38, 126, 192, 36, 156, 182, 78, 241, 4, 127, 26, 90, 110, 225, 188, 181, 232, 59, 148, 46, 47, 209, 46, 209, 31, 130, 48, 30, 71, 56, 172, 95, 181, 152, 235, 144, 170, 150, 24, 144, 244, 166, 201, 182, 37, 74, 89, 149, 212, 129, 80, 33, 76, 251, 245, 43, 41, 94, 254, 224, 130, 128, 30, 29, 73, 230, 116, 11, 208, 66, 236, 93, 69, 215, 148, 25, 32, 74, 32, 107, 19, 60, 58, 200, 41, 51, 91, 51, 132, 38, 161, 65, 8, 212, 118, 63, 201, 85, 101, 94, 201, 13, 24, 40, 36, 125, 42, 239, 150, 179, 55, 1, 117, 119, 251, 191, 100, 64, 232, 14, 130, 223, 74, 126, 7, 177, 133, 173, 63, 4, 90, 135, 125, 41, 38, 48, 187, 232, 192, 240, 243, 51, 11, 41, 173, 230, 178, 13, 52, 31, 53, 184, 236, 67, 115, 121, 137, 193, 248, 23, 35, 64, 154, 138, 86, 253, 68, 200, 174, 73, 43, 193, 189, 68, 53, 200, 229, 132, 53, 120, 67, 248, 190, 137, 244, 57, 248, 111, 166, 238, 59, 132, 86, 220, 156, 119, 170, 179, 229, 194, 127, 139, 157, 211, 243, 124, 152, 13, 240, 253, 125, 83, 227, 193, 0, 224]);
   const clearData = new Uint8Array([118, 101, 114, 115, 105, 111, 110, 58, 32, 34, 51, 46, 56, 34, 10, 115, 101, 114, 118, 105, 99, 101, 115, 58, 10, 32, 32, 100, 111, 99, 107, 103, 101, 58, 10, 32, 32, 32, 32, 105, 109, 97, 103, 101, 58, 32, 108, 111, 117, 105, 115, 108, 97, 109, 47, 100, 111, 99, 107, 103, 101, 58, 49, 10, 32, 32, 32, 32, 114, 101, 115, 116, 97, 114, 116, 58, 32, 117, 110, 108, 101, 115, 115, 45, 115, 116, 111, 112, 112, 101, 100, 10, 32, 32, 32, 32, 112, 111, 114, 116, 115, 58, 10, 32, 32, 32, 32, 32, 32, 45, 32, 53, 48, 48, 49, 58, 53, 48, 48, 49, 10, 32, 32, 32, 32, 118, 111, 108, 117, 109, 101, 115, 58, 10, 32, 32, 32, 32, 32, 32, 45, 32, 47, 118, 97, 114, 47, 114, 117, 110, 47, 100, 111, 99, 107, 101, 114, 46, 115, 111, 99, 107, 58, 47, 118, 97, 114, 47, 114, 117, 110, 47, 100, 111, 99, 107, 101, 114, 46, 115, 111, 99, 107, 10, 32, 32, 32, 32, 32, 32, 45, 32, 46, 47, 100, 97, 116, 97, 58, 47, 97, 112, 112, 47, 100, 97, 116, 97, 10, 32, 32, 32, 32, 32, 32, 35, 32, 83, 116, 97, 99, 107, 115, 32, 68, 105, 114, 101, 99, 116, 111, 114, 121, 10, 32, 32, 32, 32, 32, 32, 35, 32, 226, 154, 160, 239, 184, 143, 32, 82, 69, 65, 68, 32, 73, 84, 32, 67, 65, 82, 69, 70, 85, 76, 76, 89, 46, 32, 73, 102, 32, 121, 111, 117, 32, 100, 105, 100, 32, 105, 116, 32, 119, 114, 111, 110, 103, 44, 32, 121, 111, 117, 114, 32, 100, 97, 116, 97, 32, 99, 111, 117, 108, 100, 32, 101, 110, 100, 32, 117, 112, 32, 119, 114, 105, 116, 105, 110, 103, 32, 105, 110, 116, 111, 32, 97, 32, 87, 82, 79, 78, 71, 32, 80, 65, 84, 72, 46, 10, 32, 32, 32, 32, 32, 32, 35, 32, 226, 154, 160, 239, 184, 143, 32, 49, 46, 32, 70, 85, 76, 76, 32, 112, 97, 116, 104, 32, 111, 110, 108, 121, 46, 32, 78, 111, 32, 114, 101, 108, 97, 116, 105, 118, 101, 32, 112, 97, 116, 104, 32, 40, 77, 85, 83, 84, 41, 10, 32, 32, 32, 32, 32, 32, 35, 32, 226, 154, 160, 239, 184, 143, 32, 50, 46, 32, 76, 101, 102, 116, 32, 83, 116, 97, 99, 107, 115, 32, 80, 97, 116, 104, 32, 61, 61, 61, 32, 82, 105, 103, 104, 116, 32, 83, 116, 97, 99, 107, 115, 32, 80, 97, 116, 104, 32, 40, 77, 85, 83, 84, 41, 10, 32, 32, 32, 32, 32, 32, 45, 32, 47, 111, 112, 116, 47, 115, 116, 97, 99, 107, 115, 58, 47, 111, 112, 116, 47, 115, 116, 97, 99, 107, 115, 10, 32, 32, 32, 32, 101, 110, 118, 105, 114, 111, 110, 109, 101, 110, 116, 58, 10, 32, 32, 32, 32, 32, 32, 35, 32, 84, 101, 108, 108, 32, 68, 111, 99, 107, 103, 101, 32, 119, 104, 101, 114, 101, 32, 116, 111, 32, 102, 105, 110, 100, 32, 116, 104, 101, 32, 115, 116, 97, 99, 107, 115, 10, 32, 32, 32, 32, 32, 32, 45, 32, 68, 79, 67, 75, 71, 69, 95, 83, 84, 65, 67, 75, 83, 95, 68, 73, 82, 61, 47, 111, 112, 116, 47, 115, 116, 97, 99, 107, 115]);
   const slt = new Uint8Array([203, 210, 93, 67, 67, 199, 42, 171, 162, 254, 81, 24, 99, 172, 228, 28]);
   const iv = new Uint8Array([162, 94, 133, 27, 41, 12, 168, 109, 98, 47, 50, 228]);

   const block0MACOffset = 0;
   const block0VerOffset = block0MACOffset + cc.MAC_BYTES;
   const block0SizeOffset = block0VerOffset + cc.VER_BYTES;
   const block0FlagsOffset = block0SizeOffset + cc.PAYLOAD_SIZE_BYTES;
   const block0ADOffset = block0FlagsOffset + cc.FLAGS_BYTES;
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
   const block1FlagsOffset = block1SizeOffset + cc.PAYLOAD_SIZE_BYTES;
   const block1ADOffset = block1FlagsOffset + cc.FLAGS_BYTES;
   const block1AlgOffset = block1ADOffset;
   const block1IVOffset = block1AlgOffset + cc.ALG_BYTES;
   const block1EncOffset = block1MACOffset + 190; // in the middle of enc data

   it("detect manipulated cipher stream header, block0", async function () {

      // First make sure it decrypts as expected
      let [cipherStream] = streamFromBase64(ct);
      let dec = await cipherSvc.decryptStream(
         async (cdinfo) => {
            expect(cdinfo.hint).toEqual('4321');
            expect(cdinfo.alg).toBe('AES-GCM');
            expect(cdinfo.ver).toBe(cc.VERSION5);
            expect(cdinfo.lp).toBe(1);
            expect(cdinfo.lpEnd).toBe(1);
            expect(cdinfo.ic).toBe(1100000);
            expect(cdinfo.slt).toEqual(slt);
            expect(cdinfo.iv).toEqual(iv);
            expect(Boolean(cdinfo.hint)).toBe(true);
            return ['asdf', undefined];
         },
         userCred,
         cipherStream
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
            async (cdinfo) => { return ['asdf', undefined] },
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
            async (cdinfo) => { return ['asdf', undefined] },
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
            async (cdinfo) => { return ['asdf', undefined] },
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
            async (cdinfo) => { return ['asdf', undefined] },
            userCred,
            stream
         )
      ).toBeRejectedWithError(Error, new RegExp('Invalid payload size3.+'));

      // Test too big block0 size
      b0Size = new Uint8Array(cipherData);
      b0Size.set([255, 255, 255], block0SizeOffset);
      [stream] = streamFromBytes(b0Size);
      await expectAsync(
         cipherSvc.decryptStream(
            async (cdinfo) => { return ['asdf', undefined] },
            userCred,
            stream
         )
      ).toBeRejectedWithError(Error, new RegExp('Cipher data length mismatch1.+'));

      // Test modified block0 flags, invalid
      let b0Flags = new Uint8Array(cipherData);
      b0Flags[block0FlagsOffset] = 6;
      [stream] = streamFromBytes(b0Flags);
      await expectAsync(
         cipherSvc.decryptStream(
            async (cdinfo) => { return ['asdf', undefined] },
            userCred,
            stream
         )
      ).toBeRejectedWithError(Error, new RegExp('Invalid flags.+'));

      // Test modified block0 flags, early terminal (detected by MAC first because
      // early term isn't known until next block)
      b0Flags = new Uint8Array(cipherData);
      b0Flags[block0FlagsOffset] = 1;
      [stream] = streamFromBytes(b0Flags);
      await expectAsync(
         cipherSvc.decryptStream(
            async (cdinfo) => { return ['asdf', undefined] },
            userCred,
            stream
         )
      ).toBeRejectedWithError(Error, new RegExp('Invalid MAC.+'));

   });

   it("detect manipulated cipher stream header, blockN", async function () {

      // First make sure it decrypts as expected
      let [cipherStream] = streamFromBase64(ct);
      let dec = await cipherSvc.decryptStream(
         async (cdinfo) => {
            expect(cdinfo.hint).toEqual('4321');
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
         async (cdinfo) => { return ['asdf', undefined] },
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
         async (cdinfo) => { return ['asdf', undefined] },
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
         async (cdinfo) => { return ['asdf', undefined] },
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
         async (cdinfo) => { return ['asdf', undefined] },
         userCred,
         stream
      );
      await expectAsync(
         readStreamAll(dec)
      ).toBeRejectedWithError(Error, new RegExp('Invalid payload.+'));

      // Test too big blockN but valid
      bNSize = new Uint8Array(cipherData);
      bNSize.set([255, 255, 255], block1SizeOffset);
      [stream] = streamFromBytes(bNSize);
      dec = await cipherSvc.decryptStream(
         async (cdinfo) => { return ['asdf', undefined] },
         userCred,
         stream
      );
      await expectAsync(
         readStreamAll(dec)
      ).toBeRejectedWithError(Error, new RegExp('Cipher data length mismatch2.+'));

      // Test modified block0 flags, invalid
      let bNFlags = new Uint8Array(cipherData);
      bNFlags[block1FlagsOffset] = 6;
      [stream] = streamFromBytes(bNFlags);
      dec = await cipherSvc.decryptStream(
         async (cdinfo) => { return ['asdf', undefined] },
         userCred,
         stream
      );
      await expectAsync(
         readStreamAll(dec)
      ).toBeRejectedWithError(Error, new RegExp('Invalid flags.+'));

      // Test modified block0 flags, early terminal (detected by MAC first)
      bNFlags = new Uint8Array(cipherData);
      bNFlags[block1FlagsOffset] = 0;
      [stream] = streamFromBytes(bNFlags);
      dec = await cipherSvc.decryptStream(
         async (cdinfo) => { return ['asdf', undefined] },
         userCred,
         stream
      );
      await expectAsync(
         readStreamAll(dec)
      ).toBeRejectedWithError(Error, new RegExp('Invalid MAC.+'));

   });


   it("detect manipulated cipher stream additional data, block0", async function () {

      // First make sure it decrypts as expected
      let [cipherStream] = streamFromBase64(ct);
      let dec = await cipherSvc.decryptStream(
         async (cdinfo) => {
            expect(cdinfo.hint).toEqual('4321');
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
            async (cdinfo) => { return ['asdf', undefined] },
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
            async (cdinfo) => { return ['asdf', undefined] },
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
            async (cdinfo) => { return ['asdf', undefined] },
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
            async (cdinfo) => { return ['asdf', undefined] },
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
            async (cdinfo) => { return ['asdf', undefined] },
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
            async (cdinfo) => { return ['asdf', undefined] },
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
            async (cdinfo) => { return ['asdf', undefined] },
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
            async (cdinfo) => { return ['asdf', undefined] },
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
            async (cdinfo) => { return ['asdf', undefined] },
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
            async (cdinfo) => { return ['asdf', undefined] },
            userCred,
            stream
         )
      ).toBeRejectedWithError(Error, new RegExp('Invalid MAC.+'));
   });

   it("detect manipulated cipher stream additional data, blockN", async function () {

      // First make sure it decrypts as expected
      let [cipherStream] = streamFromBase64(ct);
      let dec = await cipherSvc.decryptStream(
         async (cdinfo) => {
            expect(cdinfo.hint).toEqual('4321');
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
         async (cdinfo) => { return ['asdf', undefined] },
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
         async (cdinfo) => { return ['asdf', undefined] },
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
         async (cdinfo) => { return ['asdf', undefined] },
         userCred,
         stream
      );
      await expectAsync(
         readStreamAll(dec)
      ).toBeRejectedWithError(Error, new RegExp('Invalid MAC.+'));
   });

   it("detect manipulated cipher stream encrypted data, block0 & blockN", async function () {

      // First make sure ct decrypts as expected
      let [cipherStream] = streamFromBase64(ct);
      let dec = await cipherSvc.decryptStream(
         async (cdinfo) => {
            expect(cdinfo.hint).toEqual('4321');
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
            async (cdinfo) => { return ['asdf', undefined] },
            userCred,
            stream
         )
      ).toBeRejectedWithError(Error, new RegExp('Invalid MAC.+'));

      // Modified blockN encrypted data
      let bNEnc = new Uint8Array(cipherData);
      bNEnc[block1EncOffset] = 0;
      [stream] = streamFromBytes(bNEnc);
      dec = await cipherSvc.decryptStream(
         async (cdinfo) => { return ['asdf', undefined] },
         userCred,
         stream
      );
      await expectAsync(
         readStreamAll(dec)
      ).toBeRejectedWithError(Error, new RegExp('Invalid MAC.+'));
   });

   it("detect random changed bytes, all algorithms", async function () {

      const [_, clearData] = streamFromBytes(crypto.getRandomValues(new Uint8Array(14)));

      for (const alg of cipherSvc.algs()) {
         const [clearStream] = streamFromBytes(clearData);

         const pwd = 'another good pwd';
         const hint = 'nope';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

         const econtext = {
            algs: [alg],
            ic: cc.ICOUNT_MIN
         };

         const cipherStream = await cipherSvc.encryptStream(
            econtext,
            async (cdinfo) => {
               return [pwd, hint];
            },
            userCred,
            clearStream
         );

         const cipherData = await readStreamAll(cipherStream);
         const modLen = randomInclusive(1, 10);
         const modData = crypto.getRandomValues(new Uint8Array(modLen));
         const modPos = randomInclusive(0, cipherData.byteLength - modLen);

         cipherData.set(modData, modPos);
         const [corruptStream] = streamFromBytes(cipherData);

         await expectAsync(
            cipherSvc.decryptStream(
               async (cdinfo) => {
                  // should never execute
                  expect(false).withContext('should not execute').toBeTrue();
                  return [pwd, undefined];
               },
               userCred,
               corruptStream
            )
         ).withContext(`alg ${alg}, modLen ${modLen}, modPos ${modPos}, modData ${modData}\ncorruptData ${cipherData}`)
            .toBeRejectedWithError(Error);
      }
   });

   it("detect fuzz cipher data decryption, all algorithms", async function () {

      // Test both small invalid and normal size "cipher data"
      const minValid = cc.HEADER_BYTES + cc.PAYLOAD_SIZE_MIN;
      const ranges = [
         [0, minValid - 1],
         [minValid, minValid + 51]
      ];

      for (const range of ranges) {
         for (const alg of cipherSvc.algs()) {
            const fuzzLen = randomInclusive(range[0], range[1]);
            const [fuzzStream, fuzzData] = streamFromBytes(crypto.getRandomValues(new Uint8Array(fuzzLen)));

            const pwd = 'another good pwd';
            const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

            await expectAsync(
               cipherSvc.decryptStream(
                  async (cdinfo) => {
                     // should never execute
                     expect(false).withContext('should not execute').toBeTrue();
                     return [pwd, undefined];
                  },
                  userCred,
                  fuzzStream
               )
            ).withContext(`alg ${alg}, fuzzLen ${fuzzLen}\nfuzzData ${fuzzData}`)
               .toBeRejectedWithError(Error);
         }
      }
   });


   it("detect removed bytes, all algorithms", async function () {

      for (const alg of cipherSvc.algs()) {
         const [clearStream, clearData] = streamFromBytes(new Uint8Array(20));

         const pwd = 'another good pwd';
         const hint = 'nope';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

         const econtext = {
            algs: [alg],
            ic: cc.ICOUNT_MIN
         };

         const cipherStream = await cipherSvc.encryptStream(
            econtext,
            async (cdinfo) => {
               return [pwd, hint];
            },
            userCred,
            clearStream
         );

         const cipherData = await readStreamAll(cipherStream);
         const rmLen = randomInclusive(1, 10);

         for (let rmPos of [...Array(cipherData.byteLength - rmLen).keys()]) {

            let corruptData = new Uint8Array(cipherData.byteLength - rmLen);
            corruptData.set(cipherData.slice(0, rmPos));
            corruptData.set(cipherData.slice(rmPos + rmLen), rmPos);
            let [corruptStream] = streamFromBytes(corruptData);

            await expectAsync(
               cipherSvc.decryptStream(
                  async (cdinfo) => {
                     // should never execute
                     expect(false).withContext('should not execute').toBeTrue();
                     return [pwd, undefined];
                  },
                  userCred,
                  corruptStream
               )
            ).withContext(`alg ${alg}, cipherLen  ${cipherData.byteLength}, corruptLen  ${corruptData.byteLength}, rmLen ${rmLen}, rmPos ${rmPos}\ncipherData ${cipherData}\ncorruptData ${corruptData}`)
               .toBeRejectedWithError(Error);
         }
      }
   });

   it("detect added bytes, all algorithms", async function () {

      for (const alg of cipherSvc.algs()) {
         const [clearStream, clearData] = streamFromBytes(new Uint8Array(20));

         const pwd = 'another good pwd';
         const hint = 'nope';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

         const econtext = {
            algs: [alg],
            ic: cc.ICOUNT_MIN
         };

         const cipherStream = await cipherSvc.encryptStream(
            econtext,
            async (cdinfo) => {
               return [pwd, hint];
            },
            userCred,
            clearStream
         );

         const cipherData = await readStreamAll(cipherStream);
         const addLen = randomInclusive(1, 10);
         const addData = crypto.getRandomValues(new Uint8Array(addLen));

         for (let addPos of [...Array(cipherData.byteLength).keys()]) {

            let corruptData = new Uint8Array(cipherData.byteLength + addLen);
            corruptData.set(cipherData.slice(0, addPos));
            corruptData.set(addData, addPos);
            corruptData.set(cipherData.slice(addPos), addPos + addLen);
            let [corruptStream] = streamFromBytes(corruptData);

            await expectAsync(
               cipherSvc.decryptStream(
                  async (cdinfo) => {
                     // should never execute
                     expect(false).withContext('should not execute').toBeTrue();
                     return [pwd, undefined];
                  },
                  userCred,
                  corruptStream
               )
            ).withContext(`alg ${alg}, cipherLen  ${cipherData.byteLength}, corruptLen  ${corruptData.byteLength}, addLen ${addLen}, addPos ${addPos}\naddData ${addData}\ncipherData ${cipherData}\ncorruptData ${corruptData}`)
               .toBeRejectedWithError(Error);
         }

         // Appending data after block0 throws and error at stream read since
         // only block0 is validated during stream construction
         let corruptData = new Uint8Array(cipherData.byteLength + addLen);
         corruptData.set(cipherData);
         corruptData.set(addData, cipherData.byteLength);
         let [corruptStream] = streamFromBytes(corruptData);

         const corrupStream = await cipherSvc.decryptStream(
            async (cdinfo) => {
               return [pwd, undefined];
            },
            userCred,
            corruptStream
         );

         await expectAsync(
            readStreamAll(corrupStream)
         ).withContext(`alg ${alg}, cipherLen  ${cipherData.byteLength}, corruptLen  ${corruptData.byteLength}, addLen ${addLen}, addPos ${cipherData.byteLength}\naddData ${addData}\ncipherData ${cipherData}\ncorruptData ${corruptData}`)
            .toBeRejectedWithError(Error);
      }
   });
});

describe("Block order change and deletion detection", function () {
   let cipherSvc: CipherService;
   beforeEach(() => {
      TestBed.configureTestingModule({});
      cipherSvc = TestBed.inject(CipherService);
   });

   // userCred used for creation of the CTS above
   // b64url userCred for browser injection: xhKm2Q404pGkqfWkTyT3UodUR-99bN0wibH6si9uF8I
   const userCred = new Uint8Array([198, 18, 166, 217, 14, 52, 226, 145, 164, 169, 245, 164, 79, 36, 247, 82, 135, 84, 71, 239, 125, 108, 221, 48, 137, 177, 250, 178, 47, 110, 23, 194]);
   // Also replace following value in cipher.ts to create small blocks
   //const READ_SIZE_START = 9;
   //const READ_SIZE_MAX = READ_SIZE_START * 16

   // Original valid
   const goodCt = "v6xsVVBD4pOtHHfzLsKBVHscJ7Q4kv_KqOKH3X_Fx1IFAFEAAAABAAZsrNtMucZUIr2UFJF3Y9R2FtBAqbm_YLotMSzgyBAAABRnUeng3ADKX8ZIicklSvESgyOeUPCFnOoBhpY-g10PWujfV7mwWWJZdMylaext9jLzwDxOLnu6u4cxcgbt1Ga1Vn5F0qDCyO0Xp9W1mAUAMAAAAAEAQTScPYuFjasQGAKP6oqkR9d58Q0YgvW3zEg50a0en8vK2ShqzFWqL5E9A_mmkaAvhGj9rr43RZhZiInC6ccflFeTqERnpm0jqQL9ysQtBQBCAAAAAQCH0B81axAaykKtBBNhvA0of9kUOniwBgdkzLFYwPH_pz75AdARszabKfDmBWOZFAzy9dDJfiqIz2Nbfr4S59sVkfpg_FPiD6_QgqLXQtv7_SDDAHb5a3C-NLGvP4KhxAYFAGYAAAABAIVBoUjIij7b-5zUE6FMbuAaiegCEYXBcSuLeeKfCH5WHveQq6-8KA4U-IQ6IZ5Rz_ocEv1L5e9uqanzYvGkFMfbhjO3oNH5-C_CqfCIF_1OzrgztnYx2feFXB0DGiR7PBWkPKErkb7VBUkVLd8T-ZqVhNFQstJrXxEXdriJzUfeLrGV3wUArgAAAAEA44DnCIDUxMUHlsvdM6d5QAs_MSRUx0y7_a6hecMnN1K5eOxDxqGDf-3xzL0dpb5CrbW99lYJLwZz9zqyAmPMeCx2KNFL2YFkhBSMy7XrDV9u2wT1ulIKPq6IQpOCos7LqBhiTeh46TqpYgYpeckATiYUrIS5RBfHdxAVQ6Sy-VOAPwHGochCI4AYBjcLGWWYKYkZD3d3CGjjI-haOmFab1vWKNIPE4Cyuvh0bH8dXs3DmHv4vEU8bW5JwioVuw5ciDOH7wgZTdCOBOLqBQCuAAAAAQCwx1-ma6ln7jlEN5K8rAzplIiJ5_iWANGMRdIJhjzQEX7KKCw-bffXnbx_gdPBU0o5ZzkU-HfQih-BeR6nzMsK5KSZBMJUwCAZ9ibCPjkO9cB_iyXAj_82Kk2argCNVaVNVD1rIg8Ig2lyi7btAsFiF5ANSlTv6lpJIqYapa_d1eaNIT6SOEWs2cVCgu4OaGAAzzFg_cw6A1z8VAhBFeyX-VBgerpVZVMijFcgvRxCglN1AVY8Ts5kORAaVCh9w2JFytcXHS4YElml_mgFAK4AAAABAOBdI8pBAWBb4TWSeJEQGRBchmv2EnJ_GKiBxdUuDtTO2ayK-iYjZdXrfxrKenbMcfcKrOZv7zccFcsICw-YqrS6TuKYzlbWUFm_5-mLNuDCQwTjDSok50r0j3vFD2I03wBB9j1NgGgDkhq8LMrRBCIMt0xRv6rz1RXdftsZ-gRklpvNCJPsw20SMBB8jVO7owExMM7HQZ289lY_z8q4hFA8_RepUItTnckfZtl0ZWxnf1JY05yAOI17w8-h80jjQfLXityWRu29nWAsdgUANwAAAQEA-CZxmBlulfdy7xc9NP2C2PH1FoGV4ClHPFor1PaqvS8PIGwJjYpN4Pq0S9o4DPPVd-WzFhg=";

   const badCts = {
      'Block0 Block7 swap':
         'dGVsZ39SWNOcgDiNe8PPofNI40Hy14rclkbtvZ1gLHYFADcAAAEBAPgmcZgZbpX3cu8XPTT9gtjx9RaBleApRzxaK9T2qr0vDyBsCY2KTeD6tEvaOAzz1XflsxYYbfYy88A8Ti57uruHMXIG7dRmtVZ-RdKgwsjtF6fVtZgFADAAAAABAEE0nD2LhY2rEBgCj-qKpEfXefENGIL1t8xIOdGtHp_LytkoasxVqi-RPQP5ppGgL4Ro_a6-N0WYWYiJwunHH5RXk6hEZ6ZtI6kC_crELQUAQgAAAAEAh9AfNWsQGspCrQQTYbwNKH_ZFDp4sAYHZMyxWMDx_6c--QHQEbM2mynw5gVjmRQM8vXQyX4qiM9jW36-EufbFZH6YPxT4g-v0IKi10Lb-_0gwwB2-WtwvjSxrz-CocQGBQBmAAAAAQCFQaFIyIo-2_uc1BOhTG7gGonoAhGFwXEri3ninwh-Vh73kKuvvCgOFPiEOiGeUc_6HBL9S-Xvbqmp82LxpBTH24Yzt6DR-fgvwqnwiBf9Ts64M7Z2Mdn3hVwdAxokezwVpDyhK5G-1QVJFS3fE_malYTRULLSa18RF3a4ic1H3i6xld8FAK4AAAABAOOA5wiA1MTFB5bL3TOneUALPzEkVMdMu_2uoXnDJzdSuXjsQ8ahg3_t8cy9HaW-Qq21vfZWCS8Gc_c6sgJjzHgsdijRS9mBZIQUjMu16w1fbtsE9bpSCj6uiEKTgqLOy6gYYk3oeOk6qWIGKXnJAE4mFKyEuUQXx3cQFUOksvlTgD8BxqHIQiOAGAY3CxllmCmJGQ93dwho4yPoWjphWm9b1ijSDxOAsrr4dGx_HV7Nw5h7-LxFPG1uScIqFbsOXIgzh-8IGU3QjgTi6gUArgAAAAEAsMdfpmupZ-45RDeSvKwM6ZSIief4lgDRjEXSCYY80BF-yigsPm331528f4HTwVNKOWc5FPh30IofgXkep8zLCuSkmQTCVMAgGfYmwj45DvXAf4slwI__NipNmq4AjVWlTVQ9ayIPCINpcou27QLBYheQDUpU7-paSSKmGqWv3dXmjSE-kjhFrNnFQoLuDmhgAM8xYP3MOgNc_FQIQRXsl_lQYHq6VWVTIoxXIL0cQoJTdQFWPE7OZDkQGlQofcNiRcrXFx0uGBJZpf5oBQCuAAAAAQDgXSPKQQFgW-E1kniREBkQXIZr9hJyfxiogcXVLg7UztmsivomI2XV638aynp2zHH3Cqzmb-83HBXLCAsPmKq0uk7imM5W1lBZv-fpizbgwkME4w0qJOdK9I97xQ9iNN8AQfY9TYBoA5IavCzK0QQiDLdMUb-q89UV3X7bGfoEZJabzQiT7MNtEjAQfI1Tu6MBMTDOx0GdvPZWP8_KuIRQPP0XqVCLU53JH2bZdGVsZ39SWNOcgDiNe8PPofNI40Hy14rclkbtvZ1gLHYFADcAAAEBAPgmcZgZbpX3cu8XPTT9gtjx9RaBleApRzxaK9T2qr0vDyBsCY2KTeD6tEvaOAzz1XflsxYYv6xsVVBD4pOtHHfzLsKBVHscJ7Q4kv_KqOKH3X_Fx1IFAFEAAAABAAZsrNtMucZUIr2UFJF3Y9R2FtBAqbm_YLotMSzgyBAAABRnUeng3ADKX8ZIicklSvESgyOeUPCFnOoBhpY-g10PWujfV7mwWWJZdMylaew=',

      'Block1 Block4 swap':
         'v6xsVVBD4pOtHHfzLsKBVHscJ7Q4kv_KqOKH3X_Fx1IFAFEAAAABAAZsrNtMucZUIr2UFJF3Y9R2FtBAqbm_YLotMSzgyBAAABRnUeng3ADKX8ZIicklSvESgyOeUPCFnOoBhpY-g10PWujfV7mwWWJZdMylaewrkb7VBUkVLd8T-ZqVhNFQstJrXxEXdriJzUfeLrGV3wUArgAAAAEA44DnCIDUxMUHlsvdM6d5QAs_MSRUx0y7_a6hecMnN1K5eOxDxqGDf-3xzL0dpb5CrbW99lYJLwZz9zqyAmPMeCx2KNFL2YFkhBSMy7XrDV9u2wT1ulIKPq6IQpOCos7LqBhiTeh46TqpYgYpeckATiYUrIS5RBfHdxAVQ6Sy-VOAPwHGochCI4AYBjcLGWWYKYkZD3d3CGjjI-haOmFab1vWKNIPE4Cyuvh0bKAvhGj9rr43RZhZiInC6ccflFeTqERnpm0jqQL9ysQtBQBCAAAAAQCH0B81axAaykKtBBNhvA0of9kUOniwBgdkzLFYwPH_pz75AdARszabKfDmBWOZFAzy9dDJfiqIz2Nbfr4S59sVkfpg_FPiD6_QgqLXQtv7_SDDAHb5a3C-NLGvP4KhxAYFAGYAAAABAIVBoUjIij7b-5zUE6FMbuAaiegCEYXBcSuLeeKfCH5WHveQq6-8KA4U-IQ6IZ5Rz_ocEv1L5e9uqanzYvGkFMfbhjO3oNH5-C_CqfCIF_1OzrgztnYx2feFXB0DGiR7PBWkPKFt9jLzwDxOLnu6u4cxcgbt1Ga1Vn5F0qDCyO0Xp9W1mAUAMAAAAAEAQTScPYuFjasQGAKP6oqkR9d58Q0YgvW3zEg50a0en8vK2ShqzFWqL5E9A_mmkX8dXs3DmHv4vEU8bW5JwioVuw5ciDOH7wgZTdCOBOLqBQCuAAAAAQCwx1-ma6ln7jlEN5K8rAzplIiJ5_iWANGMRdIJhjzQEX7KKCw-bffXnbx_gdPBU0o5ZzkU-HfQih-BeR6nzMsK5KSZBMJUwCAZ9ibCPjkO9cB_iyXAj_82Kk2argCNVaVNVD1rIg8Ig2lyi7btAsFiF5ANSlTv6lpJIqYapa_d1eaNIT6SOEWs2cVCgu4OaGAAzzFg_cw6A1z8VAhBFeyX-VBgerpVZVMijFcgvRxCglN1AVY8Ts5kORAaVCh9w2JFytcXHS4YElml_mgFAK4AAAABAOBdI8pBAWBb4TWSeJEQGRBchmv2EnJ_GKiBxdUuDtTO2ayK-iYjZdXrfxrKenbMcfcKrOZv7zccFcsICw-YqrS6TuKYzlbWUFm_5-mLNuDCQwTjDSok50r0j3vFD2I03wBB9j1NgGgDkhq8LMrRBCIMt0xRv6rz1RXdftsZ-gRklpvNCJPsw20SMBB8jVO7owExMM7HQZ289lY_z8q4hFA8_RepUItTnckfZtl0ZWxnf1JY05yAOI17w8-h80jjQfLXityWRu29nWAsdgUANwAAAQEA-CZxmBlulfdy7xc9NP2C2PH1FoGV4ClHPFor1PaqvS8PIGwJjYpN4Pq0S9o4DPPVd-WzFhg=',

      'Block1 repeated':
         'v6xsVVBD4pOtHHfzLsKBVHscJ7Q4kv_KqOKH3X_Fx1IFAFEAAAABAAZsrNtMucZUIr2UFJF3Y9R2FtBAqbm_YLotMSzgyBAAABRnUeng3ADKX8ZIicklSvESgyOeUPCFnOoBhpY-g10PWujfV7mwWWJZdMylaext9jLzwDxOLnu6u4cxcgbt1Ga1Vn5F0qDCyO0Xp9W1mAUAMAAAAAEAQTScPYuFjasQGAKP6oqkR9d58Q0YgvW3zEg50a0en8vK2ShqzFWqL5E9A_mmkW32MvPAPE4ue7q7hzFyBu3UZrVWfkXSoMLI7Ren1bWYBQAwAAAAAQBBNJw9i4WNqxAYAo_qiqRH13nxDRiC9bfMSDnRrR6fy8rZKGrMVaovkT0D-aaRoC-EaP2uvjdFmFmIicLpxx-UV5OoRGembSOpAv3KxC0FAEIAAAABAIfQHzVrEBrKQq0EE2G8DSh_2RQ6eLAGB2TMsVjA8f-nPvkB0BGzNpsp8OYFY5kUDPL10Ml-KojPY1t-vhLn2xWR-mD8U-IPr9CCotdC2_v9IMMAdvlrcL40sa8_gqHEBgUAZgAAAAEAhUGhSMiKPtv7nNQToUxu4BqJ6AIRhcFxK4t54p8IflYe95Crr7woDhT4hDohnlHP-hwS_Uvl726pqfNi8aQUx9uGM7eg0fn4L8Kp8IgX_U7OuDO2djHZ94VcHQMaJHs8FaQ8oSuRvtUFSRUt3xP5mpWE0VCy0mtfERd2uInNR94usZXfBQCuAAAAAQDjgOcIgNTExQeWy90zp3lACz8xJFTHTLv9rqF5wyc3Url47EPGoYN_7fHMvR2lvkKttb32VgkvBnP3OrICY8x4LHYo0UvZgWSEFIzLtesNX27bBPW6Ugo-rohCk4KizsuoGGJN6HjpOqliBil5yQBOJhSshLlEF8d3EBVDpLL5U4A_AcahyEIjgBgGNwsZZZgpiRkPd3cIaOMj6Fo6YVpvW9Yo0g8TgLK6-HRsfx1ezcOYe_i8RTxtbknCKhW7DlyIM4fvCBlN0I4E4uoFAK4AAAABALDHX6ZrqWfuOUQ3krysDOmUiInn-JYA0YxF0gmGPNARfsooLD5t99edvH-B08FTSjlnORT4d9CKH4F5HqfMywrkpJkEwlTAIBn2JsI-OQ71wH-LJcCP_zYqTZquAI1VpU1UPWsiDwiDaXKLtu0CwWIXkA1KVO_qWkkiphqlr93V5o0hPpI4RazZxUKC7g5oYADPMWD9zDoDXPxUCEEV7Jf5UGB6ulVlUyKMVyC9HEKCU3UBVjxOzmQ5EBpUKH3DYkXK1xcdLhgSWaX-aAUArgAAAAEA4F0jykEBYFvhNZJ4kRAZEFyGa_YScn8YqIHF1S4O1M7ZrIr6JiNl1et_Gsp6dsxx9wqs5m_vNxwVywgLD5iqtLpO4pjOVtZQWb_n6Ys24MJDBOMNKiTnSvSPe8UPYjTfAEH2PU2AaAOSGrwsytEEIgy3TFG_qvPVFd1-2xn6BGSWm80Ik-zDbRIwEHyNU7ujATEwzsdBnbz2Vj_PyriEUDz9F6lQi1OdyR9m2XRlbGd_UljTnIA4jXvDz6HzSONB8teK3JZG7b2dYCx2BQA3AAABAQD4JnGYGW6V93LvFz00_YLY8fUWgZXgKUc8WivU9qq9Lw8gbAmNik3g-rRL2jgM89V35bMWGA==',

      "Block1 deleted":
         'v6xsVVBD4pOtHHfzLsKBVHscJ7Q4kv_KqOKH3X_Fx1IFAFEAAAABAAZsrNtMucZUIr2UFJF3Y9R2FtBAqbm_YLotMSzgyBAAABRnUeng3ADKX8ZIicklSvESgyOeUPCFnOoBhpY-g10PWujfV7mwWWJZdMylaeygL4Ro_a6-N0WYWYiJwunHH5RXk6hEZ6ZtI6kC_crELQUAQgAAAAEAh9AfNWsQGspCrQQTYbwNKH_ZFDp4sAYHZMyxWMDx_6c--QHQEbM2mynw5gVjmRQM8vXQyX4qiM9jW36-EufbFZH6YPxT4g-v0IKi10Lb-_0gwwB2-WtwvjSxrz-CocQGBQBmAAAAAQCFQaFIyIo-2_uc1BOhTG7gGonoAhGFwXEri3ninwh-Vh73kKuvvCgOFPiEOiGeUc_6HBL9S-Xvbqmp82LxpBTH24Yzt6DR-fgvwqnwiBf9Ts64M7Z2Mdn3hVwdAxokezwVpDyhK5G-1QVJFS3fE_malYTRULLSa18RF3a4ic1H3i6xld8FAK4AAAABAOOA5wiA1MTFB5bL3TOneUALPzEkVMdMu_2uoXnDJzdSuXjsQ8ahg3_t8cy9HaW-Qq21vfZWCS8Gc_c6sgJjzHgsdijRS9mBZIQUjMu16w1fbtsE9bpSCj6uiEKTgqLOy6gYYk3oeOk6qWIGKXnJAE4mFKyEuUQXx3cQFUOksvlTgD8BxqHIQiOAGAY3CxllmCmJGQ93dwho4yPoWjphWm9b1ijSDxOAsrr4dGx_HV7Nw5h7-LxFPG1uScIqFbsOXIgzh-8IGU3QjgTi6gUArgAAAAEAsMdfpmupZ-45RDeSvKwM6ZSIief4lgDRjEXSCYY80BF-yigsPm331528f4HTwVNKOWc5FPh30IofgXkep8zLCuSkmQTCVMAgGfYmwj45DvXAf4slwI__NipNmq4AjVWlTVQ9ayIPCINpcou27QLBYheQDUpU7-paSSKmGqWv3dXmjSE-kjhFrNnFQoLuDmhgAM8xYP3MOgNc_FQIQRXsl_lQYHq6VWVTIoxXIL0cQoJTdQFWPE7OZDkQGlQofcNiRcrXFx0uGBJZpf5oBQCuAAAAAQDgXSPKQQFgW-E1kniREBkQXIZr9hJyfxiogcXVLg7UztmsivomI2XV638aynp2zHH3Cqzmb-83HBXLCAsPmKq0uk7imM5W1lBZv-fpizbgwkME4w0qJOdK9I97xQ9iNN8AQfY9TYBoA5IavCzK0QQiDLdMUb-q89UV3X7bGfoEZJabzQiT7MNtEjAQfI1Tu6MBMTDOx0GdvPZWP8_KuIRQPP0XqVCLU53JH2bZdGVsZ39SWNOcgDiNe8PPofNI40Hy14rclkbtvZ1gLHYFADcAAAEBAPgmcZgZbpX3cu8XPTT9gtjx9RaBleApRzxaK9T2qr0vDyBsCY2KTeD6tEvaOAzz1XflsxYY',

      'Block2 repeated':
         'v6xsVVBD4pOtHHfzLsKBVHscJ7Q4kv_KqOKH3X_Fx1IFAFEAAAABAAZsrNtMucZUIr2UFJF3Y9R2FtBAqbm_YLotMSzgyBAAABRnUeng3ADKX8ZIicklSvESgyOeUPCFnOoBhpY-g10PWujfV7mwWWJZdMylaext9jLzwDxOLnu6u4cxcgbt1Ga1Vn5F0qDCyO0Xp9W1mAUAMAAAAAEAQTScPYuFjasQGAKP6oqkR9d58Q0YgvW3zEg50a0en8vK2ShqzFWqL5E9A_mmkaAvhGj9rr43RZhZiInC6ccflFeTqERnpm0jqQL9ysQtBQBCAAAAAQCH0B81axAaykKtBBNhvA0of9kUOniwBgdkzLFYwPH_pz75AdARszabKfDmBWOZFAzy9dDJfiqIz2Nbfr4S59sVoC-EaP2uvjdFmFmIicLpxx-UV5OoRGembSOpAv3KxC0FAEIAAAABAIfQHzVrEBrKQq0EE2G8DSh_2RQ6eLAGB2TMsVjA8f-nPvkB0BGzNpsp8OYFY5kUDPL10Ml-KojPY1t-vhLn2xWR-mD8U-IPr9CCotdC2_v9IMMAdvlrcL40sa8_gqHEBgUAZgAAAAEAhUGhSMiKPtv7nNQToUxu4BqJ6AIRhcFxK4t54p8IflYe95Crr7woDhT4hDohnlHP-hwS_Uvl726pqfNi8aQUx9uGM7eg0fn4L8Kp8IgX_U7OuDO2djHZ94VcHQMaJHs8FaQ8oSuRvtUFSRUt3xP5mpWE0VCy0mtfERd2uInNR94usZXfBQCuAAAAAQDjgOcIgNTExQeWy90zp3lACz8xJFTHTLv9rqF5wyc3Url47EPGoYN_7fHMvR2lvkKttb32VgkvBnP3OrICY8x4LHYo0UvZgWSEFIzLtesNX27bBPW6Ugo-rohCk4KizsuoGGJN6HjpOqliBil5yQBOJhSshLlEF8d3EBVDpLL5U4A_AcahyEIjgBgGNwsZZZgpiRkPd3cIaOMj6Fo6YVpvW9Yo0g8TgLK6-HRsfx1ezcOYe_i8RTxtbknCKhW7DlyIM4fvCBlN0I4E4uoFAK4AAAABALDHX6ZrqWfuOUQ3krysDOmUiInn-JYA0YxF0gmGPNARfsooLD5t99edvH-B08FTSjlnORT4d9CKH4F5HqfMywrkpJkEwlTAIBn2JsI-OQ71wH-LJcCP_zYqTZquAI1VpU1UPWsiDwiDaXKLtu0CwWIXkA1KVO_qWkkiphqlr93V5o0hPpI4RazZxUKC7g5oYADPMWD9zDoDXPxUCEEV7Jf5UGB6ulVlUyKMVyC9HEKCU3UBVjxOzmQ5EBpUKH3DYkXK1xcdLhgSWaX-aAUArgAAAAEA4F0jykEBYFvhNZJ4kRAZEFyGa_YScn8YqIHF1S4O1M7ZrIr6JiNl1et_Gsp6dsxx9wqs5m_vNxwVywgLD5iqtLpO4pjOVtZQWb_n6Ys24MJDBOMNKiTnSvSPe8UPYjTfAEH2PU2AaAOSGrwsytEEIgy3TFG_qvPVFd1-2xn6BGSWm80Ik-zDbRIwEHyNU7ujATEwzsdBnbz2Vj_PyriEUDz9F6lQi1OdyR9m2XRlbGd_UljTnIA4jXvDz6HzSONB8teK3JZG7b2dYCx2BQA3AAABAQD4JnGYGW6V93LvFz00_YLY8fUWgZXgKUc8WivU9qq9Lw8gbAmNik3g-rRL2jgM89V35bMWGA==',

      'Block2 deleted':
         'v6xsVVBD4pOtHHfzLsKBVHscJ7Q4kv_KqOKH3X_Fx1IFAFEAAAABAAZsrNtMucZUIr2UFJF3Y9R2FtBAqbm_YLotMSzgyBAAABRnUeng3ADKX8ZIicklSvESgyOeUPCFnOoBhpY-g10PWujfV7mwWWJZdMylaext9jLzwDxOLnu6u4cxcgbt1Ga1Vn5F0qDCyO0Xp9W1mAUAMAAAAAEAQTScPYuFjasQGAKP6oqkR9d58Q0YgvW3zEg50a0en8vK2ShqzFWqL5E9A_mmkZH6YPxT4g-v0IKi10Lb-_0gwwB2-WtwvjSxrz-CocQGBQBmAAAAAQCFQaFIyIo-2_uc1BOhTG7gGonoAhGFwXEri3ninwh-Vh73kKuvvCgOFPiEOiGeUc_6HBL9S-Xvbqmp82LxpBTH24Yzt6DR-fgvwqnwiBf9Ts64M7Z2Mdn3hVwdAxokezwVpDyhK5G-1QVJFS3fE_malYTRULLSa18RF3a4ic1H3i6xld8FAK4AAAABAOOA5wiA1MTFB5bL3TOneUALPzEkVMdMu_2uoXnDJzdSuXjsQ8ahg3_t8cy9HaW-Qq21vfZWCS8Gc_c6sgJjzHgsdijRS9mBZIQUjMu16w1fbtsE9bpSCj6uiEKTgqLOy6gYYk3oeOk6qWIGKXnJAE4mFKyEuUQXx3cQFUOksvlTgD8BxqHIQiOAGAY3CxllmCmJGQ93dwho4yPoWjphWm9b1ijSDxOAsrr4dGx_HV7Nw5h7-LxFPG1uScIqFbsOXIgzh-8IGU3QjgTi6gUArgAAAAEAsMdfpmupZ-45RDeSvKwM6ZSIief4lgDRjEXSCYY80BF-yigsPm331528f4HTwVNKOWc5FPh30IofgXkep8zLCuSkmQTCVMAgGfYmwj45DvXAf4slwI__NipNmq4AjVWlTVQ9ayIPCINpcou27QLBYheQDUpU7-paSSKmGqWv3dXmjSE-kjhFrNnFQoLuDmhgAM8xYP3MOgNc_FQIQRXsl_lQYHq6VWVTIoxXIL0cQoJTdQFWPE7OZDkQGlQofcNiRcrXFx0uGBJZpf5oBQCuAAAAAQDgXSPKQQFgW-E1kniREBkQXIZr9hJyfxiogcXVLg7UztmsivomI2XV638aynp2zHH3Cqzmb-83HBXLCAsPmKq0uk7imM5W1lBZv-fpizbgwkME4w0qJOdK9I97xQ9iNN8AQfY9TYBoA5IavCzK0QQiDLdMUb-q89UV3X7bGfoEZJabzQiT7MNtEjAQfI1Tu6MBMTDOx0GdvPZWP8_KuIRQPP0XqVCLU53JH2bZdGVsZ39SWNOcgDiNe8PPofNI40Hy14rclkbtvZ1gLHYFADcAAAEBAPgmcZgZbpX3cu8XPTT9gtjx9RaBleApRzxaK9T2qr0vDyBsCY2KTeD6tEvaOAzz1XflsxYY',

      'Block7 (last) repeated':
         'v6xsVVBD4pOtHHfzLsKBVHscJ7Q4kv_KqOKH3X_Fx1IFAFEAAAABAAZsrNtMucZUIr2UFJF3Y9R2FtBAqbm_YLotMSzgyBAAABRnUeng3ADKX8ZIicklSvESgyOeUPCFnOoBhpY-g10PWujfV7mwWWJZdMylaext9jLzwDxOLnu6u4cxcgbt1Ga1Vn5F0qDCyO0Xp9W1mAUAMAAAAAEAQTScPYuFjasQGAKP6oqkR9d58Q0YgvW3zEg50a0en8vK2ShqzFWqL5E9A_mmkaAvhGj9rr43RZhZiInC6ccflFeTqERnpm0jqQL9ysQtBQBCAAAAAQCH0B81axAaykKtBBNhvA0of9kUOniwBgdkzLFYwPH_pz75AdARszabKfDmBWOZFAzy9dDJfiqIz2Nbfr4S59sVkfpg_FPiD6_QgqLXQtv7_SDDAHb5a3C-NLGvP4KhxAYFAGYAAAABAIVBoUjIij7b-5zUE6FMbuAaiegCEYXBcSuLeeKfCH5WHveQq6-8KA4U-IQ6IZ5Rz_ocEv1L5e9uqanzYvGkFMfbhjO3oNH5-C_CqfCIF_1OzrgztnYx2feFXB0DGiR7PBWkPKErkb7VBUkVLd8T-ZqVhNFQstJrXxEXdriJzUfeLrGV3wUArgAAAAEA44DnCIDUxMUHlsvdM6d5QAs_MSRUx0y7_a6hecMnN1K5eOxDxqGDf-3xzL0dpb5CrbW99lYJLwZz9zqyAmPMeCx2KNFL2YFkhBSMy7XrDV9u2wT1ulIKPq6IQpOCos7LqBhiTeh46TqpYgYpeckATiYUrIS5RBfHdxAVQ6Sy-VOAPwHGochCI4AYBjcLGWWYKYkZD3d3CGjjI-haOmFab1vWKNIPE4Cyuvh0bH8dXs3DmHv4vEU8bW5JwioVuw5ciDOH7wgZTdCOBOLqBQCuAAAAAQCwx1-ma6ln7jlEN5K8rAzplIiJ5_iWANGMRdIJhjzQEX7KKCw-bffXnbx_gdPBU0o5ZzkU-HfQih-BeR6nzMsK5KSZBMJUwCAZ9ibCPjkO9cB_iyXAj_82Kk2argCNVaVNVD1rIg8Ig2lyi7btAsFiF5ANSlTv6lpJIqYapa_d1eaNIT6SOEWs2cVCgu4OaGAAzzFg_cw6A1z8VAhBFeyX-VBgerpVZVMijFcgvRxCglN1AVY8Ts5kORAaVCh9w2JFytcXHS4YElml_mgFAK4AAAABAOBdI8pBAWBb4TWSeJEQGRBchmv2EnJ_GKiBxdUuDtTO2ayK-iYjZdXrfxrKenbMcfcKrOZv7zccFcsICw-YqrS6TuKYzlbWUFm_5-mLNuDCQwTjDSok50r0j3vFD2I03wBB9j1NgGgDkhq8LMrRBCIMt0xRv6rz1RXdftsZ-gRklpvNCJPsw20SMBB8jVO7owExMM7HQZ289lY_z8q4hFA8_RepUItTnckfZtl0ZWxnf1JY05yAOI17w8-h80jjQfLXityWRu29nWAsdgUANwAAAQEA-CZxmBlulfdy7xc9NP2C2PH1FoGV4ClHPFor1PaqvS8PIGwJjYpN4Pq0S9o4DPPVd-WzFhh0ZWxnf1JY05yAOI17w8-h80jjQfLXityWRu29nWAsdgUANwAAAQEA-CZxmBlulfdy7xc9NP2C2PH1FoGV4ClHPFor1PaqvS8PIGwJjYpN4Pq0S9o4DPPVd-WzFhg=',

      'Block7 (last) deleted':
         'v6xsVVBD4pOtHHfzLsKBVHscJ7Q4kv_KqOKH3X_Fx1IFAFEAAAABAAZsrNtMucZUIr2UFJF3Y9R2FtBAqbm_YLotMSzgyBAAABRnUeng3ADKX8ZIicklSvESgyOeUPCFnOoBhpY-g10PWujfV7mwWWJZdMylaext9jLzwDxOLnu6u4cxcgbt1Ga1Vn5F0qDCyO0Xp9W1mAUAMAAAAAEAQTScPYuFjasQGAKP6oqkR9d58Q0YgvW3zEg50a0en8vK2ShqzFWqL5E9A_mmkaAvhGj9rr43RZhZiInC6ccflFeTqERnpm0jqQL9ysQtBQBCAAAAAQCH0B81axAaykKtBBNhvA0of9kUOniwBgdkzLFYwPH_pz75AdARszabKfDmBWOZFAzy9dDJfiqIz2Nbfr4S59sVkfpg_FPiD6_QgqLXQtv7_SDDAHb5a3C-NLGvP4KhxAYFAGYAAAABAIVBoUjIij7b-5zUE6FMbuAaiegCEYXBcSuLeeKfCH5WHveQq6-8KA4U-IQ6IZ5Rz_ocEv1L5e9uqanzYvGkFMfbhjO3oNH5-C_CqfCIF_1OzrgztnYx2feFXB0DGiR7PBWkPKErkb7VBUkVLd8T-ZqVhNFQstJrXxEXdriJzUfeLrGV3wUArgAAAAEA44DnCIDUxMUHlsvdM6d5QAs_MSRUx0y7_a6hecMnN1K5eOxDxqGDf-3xzL0dpb5CrbW99lYJLwZz9zqyAmPMeCx2KNFL2YFkhBSMy7XrDV9u2wT1ulIKPq6IQpOCos7LqBhiTeh46TqpYgYpeckATiYUrIS5RBfHdxAVQ6Sy-VOAPwHGochCI4AYBjcLGWWYKYkZD3d3CGjjI-haOmFab1vWKNIPE4Cyuvh0bH8dXs3DmHv4vEU8bW5JwioVuw5ciDOH7wgZTdCOBOLqBQCuAAAAAQCwx1-ma6ln7jlEN5K8rAzplIiJ5_iWANGMRdIJhjzQEX7KKCw-bffXnbx_gdPBU0o5ZzkU-HfQih-BeR6nzMsK5KSZBMJUwCAZ9ibCPjkO9cB_iyXAj_82Kk2argCNVaVNVD1rIg8Ig2lyi7btAsFiF5ANSlTv6lpJIqYapa_d1eaNIT6SOEWs2cVCgu4OaGAAzzFg_cw6A1z8VAhBFeyX-VBgerpVZVMijFcgvRxCglN1AVY8Ts5kORAaVCh9w2JFytcXHS4YElml_mgFAK4AAAABAOBdI8pBAWBb4TWSeJEQGRBchmv2EnJ_GKiBxdUuDtTO2ayK-iYjZdXrfxrKenbMcfcKrOZv7zccFcsICw-YqrS6TuKYzlbWUFm_5-mLNuDCQwTjDSok50r0j3vFD2I03wBB9j1NgGgDkhq8LMrRBCIMt0xRv6rz1RXdftsZ-gRklpvNCJPsw20SMBB8jVO7owExMM7HQZ289lY_z8q4hFA8_RepUItTnckfZtk=',

      'Block1-7 deleted':
         'v6xsVVBD4pOtHHfzLsKBVHscJ7Q4kv_KqOKH3X_Fx1IFAFEAAAABAAZsrNtMucZUIr2UFJF3Y9R2FtBAqbm_YLotMSzgyBAAABRnUeng3ADKX8ZIicklSvESgyOeUPCFnOoBhpY-g10PWujfV7mwWWJZdMylaew=',
   };

   const clearData = new Uint8Array([118, 101, 114, 115, 105, 111, 110, 58, 32, 34, 51, 46, 56, 34, 10, 115, 101, 114, 118, 105, 99, 101, 115, 58, 10, 32, 32, 100, 111, 99, 107, 103, 101, 58, 10, 32, 32, 32, 32, 105, 109, 97, 103, 101, 58, 32, 108, 111, 117, 105, 115, 108, 97, 109, 47, 100, 111, 99, 107, 103, 101, 58, 49, 10, 32, 32, 32, 32, 114, 101, 115, 116, 97, 114, 116, 58, 32, 117, 110, 108, 101, 115, 115, 45, 115, 116, 111, 112, 112, 101, 100, 10, 32, 32, 32, 32, 112, 111, 114, 116, 115, 58, 10, 32, 32, 32, 32, 32, 32, 45, 32, 53, 48, 48, 49, 58, 53, 48, 48, 49, 10, 32, 32, 32, 32, 118, 111, 108, 117, 109, 101, 115, 58, 10, 32, 32, 32, 32, 32, 32, 45, 32, 47, 118, 97, 114, 47, 114, 117, 110, 47, 100, 111, 99, 107, 101, 114, 46, 115, 111, 99, 107, 58, 47, 118, 97, 114, 47, 114, 117, 110, 47, 100, 111, 99, 107, 101, 114, 46, 115, 111, 99, 107, 10, 32, 32, 32, 32, 32, 32, 45, 32, 46, 47, 100, 97, 116, 97, 58, 47, 97, 112, 112, 47, 100, 97, 116, 97, 10, 32, 32, 32, 32, 32, 32, 35, 32, 83, 116, 97, 99, 107, 115, 32, 68, 105, 114, 101, 99, 116, 111, 114, 121, 10, 32, 32, 32, 32, 32, 32, 35, 32, 226, 154, 160, 239, 184, 143, 32, 82, 69, 65, 68, 32, 73, 84, 32, 67, 65, 82, 69, 70, 85, 76, 76, 89, 46, 32, 73, 102, 32, 121, 111, 117, 32, 100, 105, 100, 32, 105, 116, 32, 119, 114, 111, 110, 103, 44, 32, 121, 111, 117, 114, 32, 100, 97, 116, 97, 32, 99, 111, 117, 108, 100, 32, 101, 110, 100, 32, 117, 112, 32, 119, 114, 105, 116, 105, 110, 103, 32, 105, 110, 116, 111, 32, 97, 32, 87, 82, 79, 78, 71, 32, 80, 65, 84, 72, 46, 10, 32, 32, 32, 32, 32, 32, 35, 32, 226, 154, 160, 239, 184, 143, 32, 49, 46, 32, 70, 85, 76, 76, 32, 112, 97, 116, 104, 32, 111, 110, 108, 121, 46, 32, 78, 111, 32, 114, 101, 108, 97, 116, 105, 118, 101, 32, 112, 97, 116, 104, 32, 40, 77, 85, 83, 84, 41, 10, 32, 32, 32, 32, 32, 32, 35, 32, 226, 154, 160, 239, 184, 143, 32, 50, 46, 32, 76, 101, 102, 116, 32, 83, 116, 97, 99, 107, 115, 32, 80, 97, 116, 104, 32, 61, 61, 61, 32, 82, 105, 103, 104, 116, 32, 83, 116, 97, 99, 107, 115, 32, 80, 97, 116, 104, 32, 40, 77, 85, 83, 84, 41, 10, 32, 32, 32, 32, 32, 32, 45, 32, 47, 111, 112, 116, 47, 115, 116, 97, 99, 107, 115, 58, 47, 111, 112, 116, 47, 115, 116, 97, 99, 107, 115, 10, 32, 32, 32, 32, 101, 110, 118, 105, 114, 111, 110, 109, 101, 110, 116, 58, 10, 32, 32, 32, 32, 32, 32, 35, 32, 84, 101, 108, 108, 32, 68, 111, 99, 107, 103, 101, 32, 119, 104, 101, 114, 101, 32, 116, 111, 32, 102, 105, 110, 100, 32, 116, 104, 101, 32, 115, 116, 97, 99, 107, 115, 10, 32, 32, 32, 32, 32, 32, 45, 32, 68, 79, 67, 75, 71, 69, 95, 83, 84, 65, 67, 75, 83, 95, 68, 73, 82, 61, 47, 111, 112, 116, 47, 115, 116, 97, 99, 107, 115]);

   it("good multi block ciphertext", async function () {
      // First make sure it decrypts as expected
      let [cipherStream] = streamFromBase64(goodCt);
      let dec = await cipherSvc.decryptStream(
         async (cdinfo) => {
            expect(cdinfo.hint).toEqual('4321');
            expect(cdinfo.alg).toBe('AES-GCM');
            expect(cdinfo.ver).toBe(cc.VERSION5);
            expect(cdinfo.lp).toBe(1);
            expect(cdinfo.lpEnd).toBe(1);
            expect(cdinfo.ic).toBe(1100000);
            expect(Boolean(cdinfo.hint)).toBe(true);
            return ['asdf', undefined];
         },
         userCred,
         cipherStream
      );
      await expectAsync(
         areEqual(dec, clearData)
      ).toBeResolvedTo(true);
   });

   it("changed multi block ciphertext", async function () {

      for (const [change, ct] of Object.entries(badCts)) {
         let [cipherStream] = streamFromBase64(ct);
         await expectAsync(
            cipherSvc.decryptStream(
               async (cdinfo) => {
                  return ['asdf', undefined];
               },
               userCred,
               cipherStream
            ).then((dec) => {
               return areEqual(dec, clearData);
            })
         ).withContext(`change ${change}`).toBeRejectedWithError(Error);
      }
   });
});


describe("Benchmark execution", function () {

   let cipherSvc: CipherService;
   beforeEach(() => {
      TestBed.configureTestingModule({});
      cipherSvc = TestBed.inject(CipherService);
   });

   it("reasonable benchmark results", async function () {
      const [icount, icountMax, hashRate] = await cipherSvc.benchmark(cc.ICOUNT_MIN);
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
      cipherSvc = TestBed.inject(CipherService);
   });

   it("expected CipherInfo, all algorithms", async function () {

      for (const alg of cipherSvc.algs()) {

         const srcString = 'This is a secret 🦋';
         const [clearStream, clearData] = streamFromStr(srcString);

         const pwd = 'not good pwd';
         const hint = 'try a himt';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

         const econtext = {
            algs: [alg],
            ic: cc.ICOUNT_MIN
         };

         const cipherStream = await cipherSvc.encryptStream(
            econtext,
            async (cdinfo) => {
               expect(cdinfo.alg).toEqual(alg);
               expect(cdinfo.ic).toEqual(cc.ICOUNT_MIN);
               return [pwd, hint];
            },
            userCred,
            clearStream
         );

         const cipherInfo = await cipherSvc.getCipherStreamInfo(userCred, cipherStream);

         const expectedIVBytes = Number(cc.AlgInfo[alg]['iv_bytes']);

         expect(cipherInfo.ver).toEqual(cc.CURRENT_VERSION);
         expect(cipherInfo.alg).toEqual(alg);
         expect(cipherInfo.ic).toEqual(cc.ICOUNT_MIN);
         expect(cipherInfo.lp).toEqual(1);
         expect(cipherInfo.iv.byteLength).toEqual(expectedIVBytes);
         expect(cipherInfo.slt.byteLength).toEqual(cc.SLT_BYTES);
         expect(cipherInfo.hint).toEqual(hint);
      }
   });

   it("detect invalid userCred", async function () {

      const srcString = 'f';
      const [clearStream, clearData] = streamFromStr(srcString);

      const pwd = 'another good pwd';
      const hint = 'nope';
      const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

      const econtext = {
         algs: ['AEGIS-256'],
         ic: cc.ICOUNT_MIN
      };

      const cipherStream = await cipherSvc.encryptStream(
         econtext,
         async (cdinfo) => {
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
