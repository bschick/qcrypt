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
import { readStreamAll, base64ToBytes, getArrayBuffer, } from './utils';
import { Encipher } from './ciphers-current';


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
async function areEqual(a: Uint8Array | ReadableStream<Uint8Array>, b: Uint8Array | ReadableStream<Uint8Array>): Promise<boolean> {

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

function streamFromBytes(data: Uint8Array): [
   ReadableStream<Uint8Array>,
   Uint8Array
] {
   const blob = new Blob([getArrayBuffer(data)], { type: 'application/octet-stream' });
   return [blob.stream(), data];
}

function streamFromStr(str: string): [
   ReadableStream<Uint8Array>,
   Uint8Array
] {
   const data = new TextEncoder().encode(str);
   const blob = new Blob([data], { type: 'application/octet-stream' });
   return [blob.stream(), data];
}

function streamFromBase64(b64: string): [
   ReadableStream<Uint8Array>,
   Uint8Array
] {
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

         const cipherStream = await cipherSvc.encryptStream(econtext, async (cdinfo) => {
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
         }, userCred, clearStream);

         const decrypted = await cipherSvc.decryptStream(async (cdinfo) => {
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
         }, userCred, cipherStream);

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

         const cipherStream = await cipherSvc.encryptStream(econtext, async (cdinfo) => {
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
         }, userCred, clearStream);

         const decrypted = await cipherSvc.decryptStream(async (cdinfo) => {
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
         }, userCred, cipherStream);

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

         const cipherStream = await cipherSvc.encryptStream(econtext, async (cdinfo) => {
            expect(cdinfo.lp).toEqual(expectedEncLp);
            expect(cdinfo.lpEnd).toEqual(maxLps);
            expect(cdinfo.alg).toEqual(alg);
            expect(cdinfo.ic).toEqual(cc.ICOUNT_MIN);
            expect(cdinfo.hint).toBeFalsy();
            expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
            expectedEncLp += 1;
            return [String(cdinfo.lp), String(cdinfo.lp)];
         }, userCred, clearStream);

         let expectedDecLp = maxLps;

         const decrypted = await cipherSvc.decryptStream(async (cdinfo) => {
            expect(cdinfo.lp).toEqual(expectedDecLp);
            expect(cdinfo.lpEnd).toEqual(maxLps);
            expect(cdinfo.alg).toEqual(alg);
            expect(cdinfo.ic).toEqual(cc.ICOUNT_MIN);
            expect(cdinfo.hint).toEqual(String(cdinfo.lp));
            expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
            expectedDecLp -= 1;
            return [cdinfo.hint!, undefined];
         }, userCred, cipherStream);

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

      const cipherStream = await cipherSvc.encryptStream(econtext, async (cdinfo) => {
         expect(cdinfo.lp).toEqual(expectedEncLp);
         expect(cdinfo.lpEnd).toEqual(maxLps);
         expect(cdinfo.alg).toEqual(algKeys[cdinfo.lp - 1]);
         expect(cdinfo.ic).toEqual(cc.ICOUNT_MIN);
         expect(cdinfo.hint).toBeFalsy();
         expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
         expectedEncLp += 1;
         return [String(cdinfo.lp), String(cdinfo.lp)];
      }, userCred, clearStream);

      let expectedDecLp = maxLps;

      const decrypted = await cipherSvc.decryptStream(async (cdinfo) => {
         expect(cdinfo.lp).toEqual(expectedDecLp);
         expect(cdinfo.lpEnd).toEqual(maxLps);
         expect(cdinfo.alg).toEqual(algKeys[cdinfo.lp - 1]);
         expect(cdinfo.ic).toEqual(cc.ICOUNT_MIN);
         expect(cdinfo.hint).toEqual(String(cdinfo.lp));
         expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
         expectedDecLp -= 1;
         return [cdinfo.hint!, undefined];
      }, userCred, cipherStream);

      const resString = await readStreamAll(decrypted, true);
      expect(resString).toEqual(srcString);
   });

   it("confirm successful version decryption, multi-version", async function () {

      const vers = [
         { ver: 1,
            cts: [
               // AEG-GCM: V1
               '4FhRcUaBCS6rrfj8pmkyclbGORk-nVoo-Epq_0NZ3E0BAEE8XuQyAPODSpDZLh9fCrOSLERyCwWq9rzth9VAdxsAAQAV3pKmSTgTx99M_cAWV51Z2AFzgXyEQk-iZznhBgEsdTvIlwTdet5j7a8FqrlMlZiQRvlvLhOgAvsO0n5Pxkhxhv-lK9mLQ670gilLRTrRR-pKATz4hGMWIDCgC4ojnOMwluTtK0XosZ0dCcSy9nMgIhWP5co-LWwr-NWsY29uXFC9WZI5ZA4Ujt1BAsv-gUe7vhwFcPLkhFGgc6tIeo4ObcSm7oC7z4AjTQ9WtURpvgwoqA9ovHEMum2ViGSifXlemw304KMKGDQgsM3Fn9YacZjJO0YYMyiNi48ywQVCNkw_Fvo',
               // XChaCha: V1
               'D0WSIi0s18fTxqsg5CGOHV3boHS7yaCo9AGOmWM8G30CAKFIuXF7m1ZxGo4bL6P7SaXqw-IIv8N9ZKR44xaZKIdgys4pysPqkIRAdxsAAQAVSEeOnFNPWdrAli-fyq8dWfUK2aBmXWF7T6vt06Fl5ehzCOh9DtT4W6uckFBh7S_VFBpmeh1_VN1WWAVV-PUB8HvIRtrVAoRiZy6H-BhkOaZflJnIQpu15AkrZC5aY8e4ulwiWIrV_ep88a963_B5mme9TaVZyzeXuBbo6xFOuGsVoPybjU-DWBDKK3i2rGju62NOlthYTn3eP3e2UuT_wIt1IB30XNO3dsxmcKQAW70GwSDvlGH-KnNqoUw3BUf07PlOYaiP0YfwqxZa7Mr4FjZ-sgTZTg2yKB0Xc-LeuuRprvs',
               // AEGIS: V1
               'ZhiPRZ7YOIjWXEMBFmyZsSWwor9WNId6oPXqBgJmCxkDAMCrHZhWSw5s_dZzPc-k9R2TqHmrs-8kYl2YCxT3PblxGLL51besQyoLQsuJHYvKGUB3GwABACXwMpAj4tQpvDM0yLAUJWwWFpSPHMxwMtxvB6xUvbQQDRdzkm1rFPPYm_PfWPXh_vekCrJTjXCp22hvGCr9NhPTCxnhrPu4hpVkIaPawZ77bB6uAoXI8htcZoLrf2CuSx2-F-v7XRCNYtFfOpwLQQx1u_df4xpFZWXwz_pZafMN6dvbYniu3-x4Iwcj1RtzqOajBPrgMO143pTu9n2LlKUkeUVR3VmeJIFeXhdbUaVWo498Jeboltf7XLUGy--Ox5yVFaCcmPiYUZFe0UolFPJLPIAEHB4Smdw83LoHwwjgjedzvuyzi5SHpq03OYME87dUQBVdgIDwaxwIyJDxpbLvXP9P',
            ] },
         { ver: 4,
            cts: [
               // AEG-GCM: V4
               "4pbVthrII9ejsB0QMVxM_8eVhBcx9AniiH_jB9f0oAkEAAcBAAABAMBOfz4z4j-XjmUIjdm2maNK1HObgT-jCNiGB1fgyBAAABVTww8FCVeXexY7HYAoPkKQsx24Pqxu451SMBrhGDVScst_s7Ep8uNMVUbglWitlMEI9pmOWxAkUZYVMEFxVlka_Hbq9qBheD5YRijGqlzaRiSAz6D6Gh5eTecJ0xfQpKIe4qXgQ-1AsWbEUig4Zk1r7fpMIszUAU3qy2wbD3JAqiSszUu1pWFtgfwPLFSjZv6oO3-exZSuOCNi7G8zqpbDPsquTdyc8FX_GpG4YD_OD755seUtVT4oBKXmwcKIoM_RhgcoBiRDqOvCWurBDIjbLVRcONe2PrZgotRDwgZ2UvEYtw",
               // XChaCha: V4
               "0hCjaRFwORsn5JPafhwRy9qV1Qt6t07FBFN9_wLNVeIEABMBAAACAJwKA2CZb8-wP4QC5wpi1KOuqI2kuurdtZij3ss2J3VxW8z0AZeunm3gyBAAABV0wEHCHvwmalDVcixk-Kk3whlnehP3UQuIZ8PZlSD04D5pDnsy7PjzXZnkfqd79fOcSpa7VfSG0NAVyGGjicLxMGPcio7wE71Pn2BC1m9jklIZGbw_Szzp7l9iorLBd9KOQq5bl5bo3D6iLFsZcHYVXc9_miqHXSI9_iorXRrS0BurFpsFSPHjbiSONOYFT2mdh-MwSQDNU-0Egab0GoltvM4-vxbjFMwLeFpR7_QRVHOXqlhdQLGyGjW6UtIpDLZLE0Ym-fiBR6A7STjeYWZWnqFni7yKygy_Ojqy5EdeRjfvOA",
               // AEGIS: V4
               "9qNOjLZ9-rH4psG5tikgFRhLfhiHLQCQrROmpFPqAAkEADsBAAADAIijvSZ00lRB-Edts0p2oEYxlrL5emmsclderCvjedg0UqNiq9mwx79iufCn3rCwieDIEAAAJfCjOKlYsM_LPXZLEmj6Bq0tOClxc764eABkaL_oxK6Ynx5SDj_Pzwa-iTXT2hbgShLadz4kMcaba_baFzmbD8HjfMehHaRApQ86KZRvfkMA1E5eFp7IIe1szgx7fyT0vE5wQeZzIB_mhsomYLdW46aP0_g5e95qjP2rLBAqav_AdC2rzWLR6AwZsuA2XgRr6uNVot4OYgFeJkVVaI0uvrmQj07D84e78-UjuU66zo6KbydWLRFm2zQBkRyGn1vAFoiv7RKM9pHWPoATJYiEG6V5pxQyZGZe-_6zKCqWF5H4wZXTuHCdb5EauQjwYGCQz2GCk7ZSztl-KYmKsSowCYPjRuw",
            ] },
         { ver: 5,
            cts: [
               // AEG-GCM: V5
               "EJclA00j4FKhWMLo8zMBbT_WWDtbYo1jOJxbms2AyY4FAAcBAAEBAKi_hNzCMN2QmjCIt-NcYBDvPRpv-t45wprgBjLgyBAAABUoqck_zYTvLssZib47B_sE5nucUsko-Q7ZMkwa01AppnXeXBP2P3Ey-xHq5aeDz2E0QF4FHHTxcG1b2q6r-uDteGWqIMg-UTvIeJjTkDL-k7qmFDUx5IpQBYrtoQ_v-OFHe9YeB5LER7MXBMYkOMnoFh84gCi2pV-fnX-7hmshvMFym_zjctpk1uXsdiFUd7rJnf7S8nG5xK3FEC4b_B4F7tUmvNUqevfOZohhweC7YlUMpo0LqRC9LDOduuoTZDz2X2YmZ14dEsTuy51SvgrP_d3L-l1SK3zE6d9GGyVJLkb3GQ",
               // XChaCha: V5
               "SAJ9PKhT8wjZjBskbt4vdzg161W2KMz61C-9VKMUsagFABMBAAECADbgwlhg2FbbXs7I9uOyhtHwK3hLkNeSkE7RcghFE9tER3gZbWW4ro7gyBAAABXuVU3WRRokICOeJCnqnhmKvTQ8I0r9cu_DbFnVJuFCB604K-qQqAV84sOvNu4Dp6_b8oFbe7B97hwvy59RkJ7YVhZJbOWUgSd8SyeSxsS_8vxctfW26FuBRHGCjmCHaIzTKvhRE-A5XeWZ_E5TI9cilLmze0Gqk4Ob7c3sfB6btro-nGj5dbdQyYPST1o7IdM34F2sn8aq2no8W3q2e6IFv7t3jHpvN8hl5abkFRIAz9zBbh_U8mO36R2vimNbYwSgcawPzPSSkX83bf11qnFEu4KxJ2_JQQxWh8lGp56YhRANDQ",
               // AEGIS: V5
               "ZUDYZTXyYnJhG-9MZMD4j8ymWuNP8Oy5jr_qmISjOF0FADsBAAEDANHCkN2qd1mYu4zrsjS5AzIg9LsqLr3Dh8dJpcPkC9wK0Bwl_iFu5hpDTmyQ3P1G-eDIEAAAJbNfK1hDFINnuh3UpFAzOJnyH1fzCbjPuKFQcuZj8YfWkZV-_USgfgSqG1NLt2szc6ZMDEWoHKPPYgsRS6IH3JqrCJF8_W8RhV_1X51v9FAHE7D1VvNs5qiMiuKWN7IU9pXad18isn2leUwI0O24-8tCK7rCIX-CqGaY5y3mHEQavpoNHBD9QQKyKWNUqnWhvO39a_FtgNrtNaLx0LFLYKOpXYzFWSCbwQfeCDxXMK-J81u7z_K_OqLWTaZdjvEqaBDCqJQPapSRlgi0eh5bu94Vg9QsLKPYcFIXXjBMLOU7gNm0oRDMDok5Qu-Ln9OeWIAv1lNVS56JcYfEpOdZKYCStRc",
            ] },
         { ver: 6,
            cts: [
               // AEG-GCM: V6
               "W4_I9gz5WSiAq-G34w44eP-3Me3xjAep6B9H1dxoHe4GAAgBAAEBAHNt83V6_8a7aZR72DqhJJgk2CpmUMPnpErW7vhAQg8AABXer0YFIgg5tMSL9afCCog2shFnxcicsow1wVHIJeLF6oZapLXOo08wk4_1d25XmdtMHLulpFV52RVgYNgrwcHpMOKmaRfN1CDLEX9nPG3BSYYCm0NAGfQzUUmrlC1cBe8lSbI4RrsVD4Sa0u4IZRz6NQ3yAR2FGenrW7yjbN_GkxROShPIaNy63rsyYc6svBw4kp8YRDgxY9xG54O4EBqaNVzNk9v6YVYzepYH14EjKQGqYLbHX-LvdVoVuu4QhFMWRAfB_1u89gS9tC46NnJFX4oJo6tokXAv0aHWeEsoR1NeCg",
               // XChaCha: V6
               "u8BTh9ThKn_klfjO8eMA1Sde-FX_CYsUBWhKaRnw6xAGABQBAAECAPQAYxtzwMf5dw7Rya2biOgUbwTUE6DbVLDcNaYxIWrsWa1va-dX5g9AQg8AABU2qXFON3ZxfJrIp26aqT5QDvUkOnNy8Sw0S_QxQgKWPyS7IsSRFh09F0Zy7Ob5jQmD6rdV1_Xq_bpa3p1snuntsJkxhnzOB28o3ALSAu8HdNRFXUmYHBzlJ0b3cxUoIn1WfZhYLWIMct1B4KDv8E8lgECHOL4HLZuMy0b_uSoUWb2KtOkwAhwQkKM_6OhSTbtRiqrWvY6C7P6ZAXrlZBRVlZVf54ft6L5swqOioRWEyzgB26raOg0CsV246oiOFuvuOTsFoW9hWcb3sMnjvGtProLH9iIBhhH7yDubc4FbqEfUTA",
               // AEGIS: V6
               "pB9kP1BYfukyE6IGD6gZ-_SHCjiV0AGI1UoJHEc6a3AGADwBAAEDAALbWMdn4I92-SWsCZpRgRqwM0Hzqp9yVg8crnjUCskbYzIqgLt7dSdfN19d3pnZjUBCDwAAJV0CeJDHHvGZ-cxRpIXKnPK9Cgh42Z_tqiOx88hUFvBISL6nOIK2pTymkZcmVN9Apw3g9WZcroMG6zTVUemIigqtzdsgEZ8IdfelvCTy1ULEzEMAsXX1n_itrE-nxVe1Q_qkJyZhzBRg4jJVL9zdXON6-l4cgTm4www0Ml9-6kl9skgjRBhk9RMFpAMIQ8Wll6tyN9Pen9uk_ahDrMFSA32eLGArQNIYZIEiompoMn1jMzMSAPTLzHN-6PgRdQUhTFr_rdEyiWjRxQWrTF8Rv57eYHxCgm_6faLPR0dLwoX0BgM83dsRjor5pzu4usO84J6TCY8fDhrXSg-1nyKUSeagYZ8",
            ] },
      ];

      // userCred used for creation of the CTS above
      // b64url userCred for browser injection: xhKm2Q404pGkqfWkTyT3UodUR-99bN0wibH6si9uF8I
      const userCred = new Uint8Array([198, 18, 166, 217, 14, 52, 226, 145, 164, 169, 245, 164, 79, 36, 247, 82, 135, 84, 71, 239, 125, 108, 221, 48, 137, 177, 250, 178, 47, 110, 23, 194]);
      const [_, clearCheck] = streamFromStr('physical farm bolt correct bee nonchalant glib high able pinch left quaint strip valuable exultant disgusted curved bless geese snatch zoom fat touch boot abject wink pretty accessible foamy');
      const hintCheck = 'royal';
      const pwd = '9j5J4QnKD3D2R7Ks5gAAa';

      for (const ver of vers) {
         for (let ct of ver.cts) {
            const [cipherStream] = streamFromBase64(ct);
            const clearStream = await cipherSvc.decryptStream(async (cdinfo) => {
               expect(cdinfo.hint).toEqual(hintCheck);
               expect(cdinfo.ver).toEqual(ver.ver);
               return [pwd, undefined];
            }, userCred, cipherStream);

            // version ${ver.ver}
            await expect(areEqual(clearStream, clearCheck)).resolves.toBe(true);
         }
      }
   });

   it("confirm successful version decryption, multi-version loops", async function () {

      const vers = [
         { ver: 4,
            cts: [
               // AEG-GCM, V4, 3 LPS
               "UAOJ5M6cU9KADQ8nSJcXp8qP0oS7nb3ASMXwazWynpkEANkBAAABAPkCZdIRcEGl6M_ilpaCHAG9aVYHeKeW_PgAsczgyBAAIhGvvNZ2B7hguRfFWUFg7V-QhL6Q-FIV38VshhSFjWOOFUpvVEMm8_DFCYIuBg-ejfcn8A7Qct7NcjxjHsPllutcg1sBhz8oDnYUm96g4Yp0ME_Ep1ak3qGRrBqetlN2Nomy3gDnibp4AHFVR-Gdj94wyI8GtEuWSS_m64e6026IMo3lrOucJ8IZ8oEL_OwOccBp6StpW_s9IkvCxW-Bivka2c113H-GkDMpmdc9HPX12-FOjyglSNIeuRJ0_2r4QUebLGIUZcxoK3qAOa3u6VRGt7elCRDv_GDKoWQyIXtaBOB8h2AX3h-1RGzHTAHcDWx3O_ad4ULyjoLntka66Y_LoU6Sq2GMrvB5l8eMJkHivFkD8SVcpwKJDjyvMLvJWpJo-FL-l9jnoMe2AxSIJ28qBl9bdCb931p1NZIBHlXTikhTTOkFa820JSiXkWNxF_5csS4MX4TVrHQ5-EIN-MaRif1uQoTf5XMUtoh2gPLLGEBVc9HqtGATvS6p9_PPnrHZ2XvC0JZyReAq57zXGTMfB8O2xL-hEmMzItDVi9sidRGKdM8LDvOrApBB1IEg7ZYzmq4LnA",
               // XChaCha: V4, 3 LPS
               "z0snbVnUg6MCrAC09OyOhDXGWDZ_SrpI_SKVs9fF4IwEAP0BAAACAN3UG9BXiATI48NUlSAvXH530dx-f7NC02mqNAJWcq3_tEBKS2XKnobgyBAAIhFBAXexQmL6gjq4FQcmJDZlV9av_GZ2BmWKTpcsBjrJVl1jL8A8wddfhHbrELWGytolPHiFPB3sCkTXF7Nvwud0pA04W3qTpt1LgCR4Zqwd-QFGNAkl2_yD8Hw8vQMJu1zoi1T05wvYTSFtQu68FVYHh1Hg_BLC3qXKQdmEePWP0YDzxTKqGbp1zzXmAY4X8NtIyw7lPyOaEaL0JNulCvkLMq-7rxBL4v-OUmK4CSTYn3_tSpzaU2e2b1hcJGIM_1s5VEYpixwH4U53CRNeUhhVy1V-BYrr_Wb34eAejYIA-G08ztHz5NxBQlfS849jNif5qihO-6pQDRN_gTYZ4pv0uAQzL2A2gi-jBPqTI7ES1hkX3VYfRBgJ33-9_y-fcBIH-k4RVlbg0NZ_Gy_umTc_gRYBocIZrlXHfYyyCHGQvkUpK3pFXrggB4B4YCfMrmWGwze6iJk9A0-jFBNnFmkglwfF8ru9PeHdK-Duf-lkqx70cRyAOCiWk55EwfTaXM80zRCvef6kG77mppK_2MhvWgsqAqqyRqgv8xUUwiO658UCjaeuOuAf2m1EsOQpmqcqEueuSHRW3JNajKPRE47K4Mq1bAZ1yL-hDTLfYQ",
               // AEGIS: V4, 3 LPS
               "AqjJe0x_GChxY-Z9bt2ZSk0-PUIeKoCoLUBleSCPp5gEAHUCAAADAKz1zLmRbFugjv3u5xN4k2H6Lb_WGPeRsBX-J3n4_j8VZwA9BPGMfnH2GltYCtKqMuDIEAAiIdMVRyGeIb0OpQG1_NCGvTVzdWwTfjq9vAR9g1cfm9Q6MDxX3p2TS_EKH26O4SOqwrmilRV6Qyer4Tx7NTUpMaJIXmD_j5KOh3P_nkfZ1IAGYj_nUfDaGTaW7_fao1udKaxlTSj7M-_-mRZ18UUEvEazOwrkuYFBBcur8y-k5tKLZSfhjeODD4-rup7rSON2XOvaX_FET5S13ga-DOluX7ITb9NJphSW3_g1l7267iLrmFOmVO3XBGnenPgeUl2D4aadSHfzc0iIkLIWs8WOe54LAwAvbJFMupAC-NDCZ4_OamDb4OwLq81AXnMXN1g5fifSn6SIWArQ9oN4j42y7CWpow0UfB8ansFv5F95rpljGrLJkKg1oEetP1U2YZXreSGo0seSoEFB1KlKojI5YN9UC2GeiHpzbH0dSKhhzVShJWpDG_NRNV9M-D2feNZ2E-bhsM747euXpGymFXZIxYTksF3dzQ50tJbomvLdAGNau8wS5fFDIptwK1C9p6OwZYlPWhCPs5JhBMOTdbeGvfV2rvx-fN5BTYT0hflFe-Or2YjX_jAI1YCDqYM5TxaS9XGKhqfFNYbXyexbB3V7yx4w4QqP1_NwnTn9WEsCJhQvRhBoQPYqHAJTKiaMjcCLmXMeNDDwb_5oHCJY-LTY8n0Ifn9safDdSKLnJMCypAtgOuk1ZB0JtvX7KzNisy-Dd8iyAIpKS89Y5g1sxfpXZQ8frAJnL6-O-Dcb2QU4oW3Db22JjVL_2L2dVHCwGw",
            ] },
         { ver: 5,
            cts: [
               // AES-GCM, XChaCha, AEGIS, V5, 3 LPS
               "fr1l3aTIL4-4O5shIllF7cmgx9JZ0iZdIHQLLDc71_sFABkCAAEDAI436nhP6Y5r9CQJL4ny_B9y2tylKH2ZxSzdvN6uqxoFG8CP2YqVB0vbQ46sdRAkheDIEAAiIa7leKW-j2vN4CT31z2cAH3bm1ddjQ9KPfKXIKLds8gJVy4UPbA8mQ_SKDLARhJuReb2SqmKU_17X6_nWnScIIPBMBvoOWdul0jb2cBlioOZ968OipMLRggD74pVeegvePLzQhTQvBZiyqOyRkta7tSfiwY6Pqb8efej-T3ItJ2q-It-NQdnloZBrThoP9Lh3hJUt5OwMgFrhTMy_5wOYDI_X8t-kmnfSKt8BdQKoCG-tri0Xe2OVN9_ae2u_l4bvE9-GkTjvFCw3l_egIYjYRAmBJTWv9SnIAwXDuxonTHMiw0QO3x0AYCF9rJ1Lu2pSeLZbL8ke8XUFqfULTlOiXb4Xc13q-DWFhEYNHz2go6zBmXg3dElK94mv2f8mfZyA5psvl4Kte5BJq9G4uJdqrFkqX7Snx5i5AQhP4JISK_3xCuC0DNNAk6fG0ARjMS2zrRbfjVwyPY_vw4HcQU2JhYqsgsRauoBABy-LmH3VUvFXkdvQi_lRPBD7hVqu0ZKjh0k6ZypFR_nXo4zwoi84IAG_527NCevoxgGqBvEdVaUL8-XjcJhxkreysrCFYSTYdhA-6qbBPgkoooSMhFwZjN-qku4lqKo7KIIIeGO7HT7XbyxldZN6pm4Q82gecrAGYs",
               // AEGIS, XChaCha, AEGIS: V5, 3 LPS
               "hV1RikjDpxKuimJkPcHs0ZX95pPW6LHIllYhoMdte2YFAE0CAAEDAKvbjrnfg3VDgvnILDZKbIaUGxMp5Iv9JYYr09KEhmQGVgyB62xjoffJabxC5zz3FeDIEAAiIWrG6htNwiOOBXfZu2IUwQpMiNqQVR0GegoX-aESZ1gppQNKj-b63ucKTaybnvSeiqExW9rsGFYxOz8u5qLH15_p2qZsNO-mGpc1wylR_Ge-aXaUF9P1bZn9AAMOxX3q2dtP5ey7bA22SYe_JeQiDPBGAvfzAk3WJ5GuHPmGzc3yoHZXmMMxSm2tytvJy6fEx2TkktobNnhI9eAXBxn82xX-rmM00djST2LAZQZG_SSQByzFk5rZUGLmhomiZz-SQQdVZDY45BD-zjNqj0jSGXAr8vKKwXPsAGKIq_uK7Gr-G4uw1_kkI02yu1AQjb3Jfpc8AvkD5KJ5V1Y42CSkmf07oMmrxqJ0QSGgEIxS0Za-XNdsDKJP2YoggGnRTW__EEp15xnnqwDzPxFgvhMBdCN4z03ERPy0rqTSeSYnY35ag6OrA9cBYD6kEVMIi-VVSErsqJCDNmq0kqnM2FBMFFCCVOT8pasoRtQuzXQzaXZiovmceXsGUNeMgU38AnYgYjUtYhNonYnHw-A3LsIYvzKDtshJRh1qekNqBMdycFrkxF405nEJe6kdyiaxKajYkjlXY9xbSt-AK3_0MWNNB3Adr_HiO9IQaj7hByCqQgxbHm8aLM2oK4KtIxNEE2AWSZ8xSpBrj2naCLNg21zo9iYfHytX8a_eDvTYIi-zwoh7725S2RkqRuRUQYPhX3RPhVzqKUfq",
               // AEGIS: AES-GCM, AES-GCM V5, 3 LPS
               "5HrnYQIAB6OTA8HO27AviugsbVz_otVhIU9SUGfAKN8FAA0CAAEBAJyuTIwejjoTJAMKQ5jI6umcC7Tdy3KzFfKF4qDgyBAAIhHh4OAHh7b9A0cRZQqcwvP_Y7xOKHQzGn55oxKi0YuOXtser60NoJxoMARtP0Pe-8x9aYT5T_Ml7d87zxZXfFcMk2MfOYLPpUZO6rHKZ1IXIFbrzW_YlVTgLwUwLYM01tmr9gg17kz5D1hTKRXxJ5CWq6nu_xlXwsi8Yo44OY6Ei1hpSLF8xhw1-w6oz0DRSqUedXlo2Y1KBj7e0rLBnW1WLnnJWhwSvOOaX6Cu7qslwBRQ3w12bxGQNIJLpbcw6LriQ1Tf7iBI6vmDDpSFN4r9zvJomyB2RqO9eTa6Y4u3yDrdpBlujw8LY3c0DSA_1SSkVKinYucKhNYWtwjSD9hCE-n0qgRcHZYLZB0JlyFv3on9mIdMhRDH_4sbs6b-car5nqzXxTIaoiDu5la78Y_gWjLRk7nCTONVluVHlk3pf4tZ2pf5C9SRC1PrH5q7OVmGDWhiHIpL-9twubrjB9e2_UQa2QZsVLiMdeNpmzeiqQM5maGIVFVi9AbE8q2kq8CqeHHu2YvJuG8Q2fH2RIUb4DCT-FHvyeLPl91k1ADw4JFtrHSwMHC1fxj3ZqIRic-f6MNEoJDm5ROV9O_4V77RMX3NqpSjQyxyvOk3lmaO7au-mJYg6txDqKlSeQXoxcLV4LG2Tdhj-D4",
            ] },
         { ver: 6,
            cts: [
               // AES-GCM, XChaCha, AEGIS, V6, 3 LPS
               "4QB_HTME7CBlOtrq2oRKtOE3coA7F-rrFnHDGaztkAcGABoCAAEDANhmAzoORQG4Mfk00xuLjYaw3ShiY8tN2vzIPEdjpwbQVBaIL8GqsItRagyVmcFdwUBCDwAiIeXZuPSfuxgRb0E-W63eGZ9NZ360gPsuUU8W1dC8JkUnWsKtIgiBHSuHKV2gxXx3w0Ev8oyMrzqBEx5FERu3FTzk-bB4zmYoqhrnY6Y6F8HzeNqQSuJ4eBzmsvCY6nSb3Z0GmkUyG4xR-eFzPICOJdZGWdkWhT0penWoqM4EFnf2Upjda-R0hivSgwSwUTNhO1H26NzidOOAvMfczZVnIhVWlxCvXp9adhhQnjMPKiAVDP7zPxkMtPUlWGhGT-TESABsaa8qYBj1il2l-LRaxk22sSSpxT3VB5i32x_qcUbXrZSsHdWl0NMDb8z8Bfy-SlAhyxwK8S5XrboUp5chDixQ50qSOaiIOAaf4nP-JKFOLdw7DO7PMfRife6oXCO2OS7iVbHtFE1phEVCfys9wyLzZFbzAzB68yoH8NMMU6_p7XAiS91VDbCFtSareVvtlMeSeImC7jNhKfiHtflb8FGl6xjT_lxSTxEZvnCYe1JUJ7kd8od2w8tYWHcTaMrJ0jxHIKNB_zaRn5yZl8h4FX5N-Ex07Dfjddh16s1JWgN_nXi-lVP6utLBGxC8E_1SDTg2SMzjvTu5BkpBbw3xRf0V4jUU9n_NGMk7AP2wCYT79HiMZ3zj4Ac6Ak8h9hfIbrg",
               // AEGIS, XChaCha, AEGIS: V6, 3 LPS
               "w7OQx2Q88GDQ4ZmXN6tPkx7Yst-Veg81ujZ-_Eg4u_IGAE4CAAEDAMOP93rYo71KmzQ8o2Vi_ld3KdaGvgIqnG4dAAO1c2Yk7WLwZtROssHxCL93eiwPSkBCDwAiIfqwWUZ3l_u5DIYKlFTpurpijTfON-fY8TisKu9y2MlGw1IGCmHebVFFCmhhwmBPhMJ9nDyA5qT99EfKtyNadC1Vjr2kAXh94JiE9JEWLB298vb583GCJodLrstiU3KxlFALz4CF8Wnk0jdhSKL4L4uIhzMMul03cHaeXIQCf6N_KHTmyi6uBu8hz_iVUq8Ia2zqBACa1Iz5P2AKPIUjvX_qsARY_vFkqOgsYbNRmabSwONmjuS-fUa_mDkupH2KG6c2lbWHNs1kE7KGzGLZ21XFsNWiojnveu0zE-IHcVIK1-lymTQzN1YoKIMKdBM_mznmS5mDgRSQvXeo7qlpU4sxn3-_qP6ZoiaKzbqqKGh0_NRNjnUd8G8GzQuQfdWY4VmVHxLrm9yJcxPbVD2GBsqmIi1wNkSJW0PRbMAsLMbeHRwJJ0w0DsjodngjvAl9D66tZSa17x_XEQlslDprbcR4jfsYFe2PSAEDUT3a1HndlSsuXHsfk_ZolC86rAxTdVV9VZi8QqcHZ7nr3AR9oTz5H66QmoZcmJlUTNpfShPneF_EzXx0gGH6DjOtfrWjKD6iW2oJlpnXqMvWla60w5dYYUG43TQmoHSjb7kUqH1PtJjcsZbz4egTxrkNxvrLJGK9r7BpRk819eX5_zTlH4X3O3JsFmWK4lT6hlpW6sw69SXVzFrMxdHBJEmqF3VCk1NqUazr",
               // AEGIS: AES-GCM, AES-GCM V6, 3 LPS
               "S18WntQoRGYoTy9W4i8fuPPjKbwWUIFBbnSpBUanhLAGAA4CAAEBABMOsbaYDQFYF1taNhZq2S208_fs-vCrT2EUJkVAQg8AIhFcpOTEGHbFby411jzaT54UiYB7muuIFIgZNxIMzEyyI-Rw4ivyQiqTNv9L0NAt1K-oDAOa2OM_yN5picketRG6-4hLpgZiEhdLQEDqQ_zHIsW9VnO1JNPlZ7c_Aa4JIDMF3NqGcJnuATkDI52uDXlqpQ9qk52DB0Y37qHaHHqYyI2kBgdMdD9tWHpCNrm63fXOOSKfOE9FRxPMmZeGWzJIOhBwQ0OGAdBCUDKsrP2rADgwQcpW-5SU4oxwsWKhoMRueAlbK6KLHTVQc8LBybqUvUI3g7PGtOU0RQOkD2q15F8jGJkog8nqlNF3ZMG3Y3DM-gC45Fx5p_4k5F4B4i6FZFFYOEHJjhPV38xECb3X8mdInAZ88bhthHW-IlrPEmI9Tz1F9_qABS0tO2wEeTs96pTyDKH1Y42sL9utaBNA7Es4-_SIRUmr8aPDW6hCCpg-o2-Snecc7A-PlxHzFm10j7BB3Y5iLcaQScUzJ-ONpx4GAJzWP8tb23zAH_zeJTmwbZ0so3OTwfS07SffFIuyrdtvBWGZarCY3eTwC5URJ5RvOGs-_NWewGC3jn-UNW_yVEEl8tAFeah3db5ljunTx2DLwnIeUPAGHZpQh9bjq7c7BE1c8S4my9a3yqzLgB3ASRezSrlGZBg",
            ] },
      ];

      for (const ver of vers) {
         for (let ct of ver.cts) {
            const [cipherStream, cipherData] = streamFromBase64(ct);
            let expectedLp = 3;

            // userCred used for creation of the CTS above
            // b64url userCred for browsser injection: xhKm2Q404pGkqfWkTyT3UodUR-99bN0wibH6si9uF8I
            const userCred = new Uint8Array([198, 18, 166, 217, 14, 52, 226, 145, 164, 169, 245, 164, 79, 36, 247, 82, 135, 84, 71, 239, 125, 108, 221, 48, 137, 177, 250, 178, 47, 110, 23, 194]);
            const [_, clearCheck] = streamFromStr('physical farm bolt correct bee nonchalant glib high able pinch left quaint strip valuable exultant disgusted curved bless geese snatch zoom fat touch boot abject wink pretty accessible foamy');

            const clearStream = await cipherSvc.decryptStream(async (cdinfo) => {
               expect(cdinfo.lp).toEqual(expectedLp);
               expect(cdinfo.lpEnd).toEqual(3);
               expect(Number(cdinfo.hint)).toEqual(expectedLp);
               expect(cdinfo.ver).toEqual(ver.ver);
               expectedLp -= 1;
               return [cdinfo.hint!, undefined];
            }, userCred, cipherStream);

            // version ${ver.ver}
            await expect(areEqual(clearStream, clearCheck)).resolves.toBe(true);
         }
      }
   });

   it("detect missing terminal block indicator, multi-version", async function () {

      // base64url userCred for injection into browser for recreation:
      // Ohyqajb6nFOm2Y5lOTkIkhc3uAaF8sUrYrQ9pts2pDc=
      // manually created with missing terminal flag bit
      const vers = [
         { ver: 5,
            cipherData: new Uint8Array([225, 67, 20, 31, 134, 179, 27, 202, 138, 52, 68, 42, 197, 34, 48, 209, 76, 235, 39, 166, 101, 12, 253, 101, 237, 25, 234, 119, 91, 227, 169, 172, 5, 0, 116, 0, 0, 0, 2, 0, 53, 140, 213, 212, 134, 206, 178, 102, 222, 97, 207, 8, 252, 103, 8, 64, 25, 112, 206, 146, 159, 150, 220, 236, 162, 203, 172, 111, 119, 158, 192, 123, 81, 141, 89, 174, 126, 4, 65, 105, 64, 119, 27, 0, 0, 23, 138, 253, 130, 153, 78, 2, 31, 195, 254, 142, 102, 116, 200, 50, 125, 8, 178, 151, 113, 13, 205, 228, 10, 85, 83, 101, 57, 149, 191, 166, 4, 221, 153, 198, 0, 18, 185, 165, 203, 53, 211, 218, 24, 198, 162, 13, 99, 240, 249, 210, 255, 200, 217, 232, 10, 187, 212, 92, 204, 165, 217, 7, 202, 6, 114, 70, 200, 221])
         },
         { ver: 6,
            cipherData: new Uint8Array([132, 28, 138, 123, 147, 127, 43, 62, 165, 146, 225, 63, 193, 229, 103, 67, 52, 78, 235, 87, 222, 81, 39, 59, 221, 183, 97, 72, 255, 88, 246, 58, 6, 0, 117, 0, 0, 0, 2, 0, 34, 40, 133, 44, 12, 94, 228, 213, 26, 168, 170, 128, 158, 80, 186, 10, 199, 186, 216, 165, 74, 175, 77, 14, 167, 87, 224, 153, 52, 15, 148, 75, 171, 2, 77, 176, 158, 14, 41, 21, 64, 119, 27, 0, 0, 23, 60, 217, 5, 30, 103, 244, 158, 250, 216, 37, 3, 99, 119, 58, 27, 195, 99, 129, 80, 65, 210, 179, 102, 243, 232, 235, 177, 129, 48, 29, 127, 154, 58, 17, 16, 73, 65, 218, 12, 57, 251, 92, 205, 101, 8, 236, 63, 89, 47, 41, 190, 168, 125, 241, 136, 131, 63, 67, 146, 42, 204, 9, 202, 62, 160, 22, 123, 154])
         },

      ];
      const [_, clearData] = streamFromStr('A nice 🦫 came to say hello');
      const pwd = 'a 🌲 of course';
      const hint = '🌧️';
      const userCred = new Uint8Array([58, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98, 180, 61, 166, 219, 54, 164, 55]);

      for (const ver of vers) {
         const [cipherStream] = streamFromBytes(ver.cipherData);

         const decryptedStream = await cipherSvc.decryptStream(async (cdinfo) => {
            expect(cdinfo.hint).toEqual(hint);
            expect(cdinfo.alg).toBe('X20-PLY');
            expect(cdinfo.ver).toBe(ver.ver);
            expect(cdinfo.lp).toBe(1);
            expect(cdinfo.lpEnd).toBe(1);
            expect(cdinfo.ic).toBe(1800000);
            return [pwd, undefined];
         }, userCred, cipherStream);

         await expect(readStreamAll(decryptedStream)).rejects.toThrow(new RegExp('Missing terminal.+'));
      }
   });

   it("detect extra terminal block indicator, v6", async function () {
      const [_, clearData] = streamFromStr('A nice 🦫 came to say hello');
      const pwd = 'a 🌲 of course';
      const hint = '🌧️';
      // base64Url userCred for generated with commandline
      // Ohyqajb6nFOm2Y5lOTkIkhc3uAaF8sUrYrQ9pts2pDc=
      const userCred = new Uint8Array([58, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98, 180, 61, 166, 219, 54, 164, 55]);
      // copied from ciphers.spec.ts
      const [cipherStream] = streamFromBytes(new Uint8Array([114, 105, 149, 122, 214, 68, 66, 254, 204, 60, 108, 90, 88, 145, 24, 13, 64, 232, 184, 211, 137, 68, 207, 107, 242, 54, 26, 74, 31, 99, 61, 110, 6, 0, 108, 0, 0, 1, 2, 0, 38, 7, 93, 115, 159, 181, 216, 73, 45, 124, 29, 242, 220, 98, 213, 145, 114, 236, 39, 248, 11, 6, 42, 127, 123, 242, 217, 57, 58, 205, 0, 255, 238, 184, 227, 83, 181, 100, 188, 208, 64, 119, 27, 0, 0, 23, 154, 92, 181, 175, 144, 243, 53, 142, 153, 165, 44, 241, 86, 111, 236, 209, 43, 164, 62, 163, 196, 163, 117, 144, 20, 60, 205, 74, 135, 202, 75, 142, 62, 9, 135, 94, 49, 180, 28, 58, 209, 97, 164, 112, 49, 76, 42, 209, 140, 8, 93, 78, 168, 68, 248, 120, 26, 49, 28, 173, 242, 51, 71, 237, 8, 237, 174, 172, 162, 15, 13, 206, 208, 202, 130, 231, 36, 205, 62, 47, 252, 216, 35, 203, 182, 64, 202, 194, 87, 132, 92, 6, 0, 52, 0, 0, 1, 2, 0, 51, 173, 77, 222, 222, 129, 65, 79, 156, 158, 88, 144, 22, 46, 77, 72, 215, 184, 30, 152, 149, 40, 86, 78, 225, 236, 11, 99, 214, 240, 246, 48, 170, 7, 183, 213, 15, 213, 179, 207, 3, 190, 145, 97, 125, 81, 96, 46, 74]));

      const decryptedStream = await cipherSvc.decryptStream(async (cdinfo) => {
         expect(cdinfo.hint).toEqual(hint);
         expect(cdinfo.alg).toBe('X20-PLY');
         expect(cdinfo.ver).toBe(cc.VERSION6);
         expect(cdinfo.lp).toBe(1);
         expect(cdinfo.lpEnd).toBe(1);
         expect(cdinfo.ic).toBe(1800000);
         return [pwd, undefined];
      }, userCred, cipherStream);

      await expect(readStreamAll(decryptedStream)).rejects.toThrow(new RegExp('Extra data block.+'));
   });

   it("detect flipped terminal block indicator, v6", async function () {
      const [_, clearData] = streamFromStr('A nice 🦫 came to say hello');
      const pwd = 'a 🌲 of course';
      const hint = '🌧️';
      // base64Url userCred for generated with commandline
      // Ohyqajb6nFOm2Y5lOTkIkhc3uAaF8sUrYrQ9pts2pDc=
      const userCred = new Uint8Array([58, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98, 180, 61, 166, 219, 54, 164, 55]);
      // copied from ciphers.spec.ts
      const [cipherStream] = streamFromBytes(new Uint8Array([24, 212, 67, 36, 232, 163, 170, 119, 145, 211, 157, 196, 172, 177, 63, 167, 12, 22, 20, 81, 250, 166, 94, 226, 132, 226, 253, 243, 133, 249, 38, 46, 6, 0, 108, 0, 0, 1, 2, 0, 85, 112, 249, 39, 40, 215, 94, 63, 122, 204, 193, 102, 64, 65, 163, 82, 69, 123, 185, 109, 204, 27, 14, 222, 237, 33, 135, 94, 11, 145, 15, 204, 88, 25, 166, 108, 158, 106, 108, 144, 64, 119, 27, 0, 0, 23, 249, 240, 198, 170, 184, 70, 4, 93, 213, 139, 151, 175, 168, 83, 58, 110, 57, 141, 165, 35, 67, 130, 224, 145, 19, 200, 206, 7, 210, 27, 238, 115, 65, 227, 65, 86, 173, 49, 27, 61, 214, 163, 247, 237, 148, 168, 221, 228, 49, 197, 130, 72, 232, 83, 9, 108, 84, 44, 172, 115, 101, 0, 244, 178, 175, 216, 196, 5, 182, 210, 63, 180, 227, 122, 3, 70, 210, 255, 100, 185, 98, 226, 215, 183, 55, 131, 223, 16, 182, 177, 109, 6, 0, 52, 0, 0, 0, 2, 0, 117, 159, 80, 68, 25, 102, 215, 193, 132, 143, 200, 39, 19, 204, 47, 81, 213, 236, 77, 70, 22, 228, 220, 182, 58, 75, 143, 225, 66, 207, 162, 138, 118, 145, 133, 192, 55, 108, 217, 36, 155, 122, 39, 41, 30, 18, 66, 109, 59]));

      const decryptedStream = await cipherSvc.decryptStream(async (cdinfo) => {
         expect(cdinfo.hint).toEqual(hint);
         expect(cdinfo.alg).toBe('X20-PLY');
         expect(cdinfo.ver).toBe(cc.VERSION6);
         expect(cdinfo.lp).toBe(1);
         expect(cdinfo.lpEnd).toBe(1);
         expect(cdinfo.ic).toBe(1800000);
         return [pwd, undefined];
      }, userCred, cipherStream);

      await expect(readStreamAll(decryptedStream)).rejects.toThrow(new RegExp('Extra data block.+'));
   });

   // using  base64-url alphabet
   const b64a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
   const b64o = 'BCDEFGHIJKLMNOPQRSTUVWXYZAbcdefghijklmnopqrstuvwxyza1234567890_-';

   it("detect corrupt cipher text, all algs, multi-version", async function () {

      const vers = [
         { ver: 4,
            cts: [
               //AES-GCM
               "eVMF6PzrEgx_XjftDM_dNDQgVWEGxAMuh0tSPEzVmFgEAF4AAAABAI_U2i3D1Q2QkdYuJTW2foBDIGBT122M_RGcb5vgyBAAABQtwX__YvRYteI4K7_YuNFgWVirS-6iuULsadb2_1n4yiTbUE_PVjMCtSOqZcT9Tk254T3TdiOv0-WB",
               //X20-PLY
               "p5q5r4dV44AsP9pxwrwOK7uf90EynliXMqpQaiOczHYEAGoAAAACAMJWRiT0rS-ivexQXh-uqAZgWjQQT-vON15dSo6XwD3zs51ix2T3k8HgyBAAABTzx6m-vqvQYCQpGcaJjO-6PmqurA32TDa_Ibq2rtCsuXLAGbO-8DM6JjfJua4tNUOHZ1W1itDO7xJ9",
               //AEGIS-256
               "1Jnt7bRakMkdgo9s0DhbdA3RZgTxQjdpczG4bVqLtdsEAJIAAAADACkhdnd1jqoOrNpifLk1Cg7qUi6-j_0EBJyyTAvtSXxxZe2cMLuH14b8TGNIsFQ6L-DIEAAAJGmwNdy_5f7etj9t6Q1l9zwg1er2CcW4gk2AnVyzqZXvxZrq1heuiam-6RtQ4Wkx2NIUruYKnYah4IRKMfuRJVLYge042ICZneCwQ6Tg1cG8adP0P1nzEXcdJA"
            ] },
         { ver: 6,
            cts: [
               //AES-GCM
               "Ro-KTigP7WqbNSeCeDT5yuMjIKFelo1c4mNKAeBPX8UGAF8AAAEBALIlz9UVTEzA9igl3sNBAZLqME8lR464nfQ4wQVAQg8AABR4pIbwIfeEHFZxcDjrQNYr4zha1RIzOoJsLy9jaMEx0RnTYy4DoFaxjMHN-acKN5bm6hnP0F3ALw8d",
               //X20-PLY
               "n8cmquHjnA6hWBN3fKi7pVubV1gtSUANgVxz4tfwvloGAGsAAAECAI_iMR3xE5g7tItxHqmoU6b9jCdVK8UUXg7AeWnNHdaHeXOA95lwiYNAQg8AABQTwpzuSG6H9n4m7fSkn9h64ls4nxwO7Hja7ruNfWuI8QWaVIy1map39Pm0F-wY1HFuu9KCwM4btVyP",
               //AEGIS-256
               "0iccnvyBA-Yer_7ur626xinuNSUivimb6SMYR5zWsisGAJMAAAEDAAwVFwpbKuzARYXHcaRN3oZFZ1ypFmUaW129_vD8i6Yxt81J2uCbtCnYQpGMW68fo0BCDwAAJIGfEG6HCbani4qkMSlgiV5oJaR2H2ir7PELn8ruJDjmk07BDCSzlAcUakQXuck-KCi6ySITkfffBojZrTSuLNRhruKhvcpDZiFCJPf7shjFmdIytH0lgHnZ9Q"
            ] },
      ];

      // base64Url usercred for commandline: ZfZIlUPklSM8fFG7nWDQ2XuT5DxU1sZ0wKKykzJ3Yfs=
      const userCred = new Uint8Array([101, 246, 72, 149, 67, 228, 149, 35, 60, 124, 81, 187, 157, 96, 208, 217, 123, 147, 228, 60, 84, 214, 198, 116, 192, 162, 178, 147, 50, 119, 97, 251]);

      for (const ver of vers) {
         for (let ct of ver.cts) {
            const [_, clearData] = streamFromStr('this 🐞 is encrypted');
            const [cipherStream, cipherData] = streamFromBase64(ct);

            // First ensure we can decrypt with valid inputs
            const clear = await cipherSvc.decryptStream(async (cdinfo) => {
               expect(cdinfo.hint).toEqual("asdf");
               expect(cdinfo.ver).toEqual(ver.ver);
               return ["asdf", undefined];
            }, userCred, cipherStream);
            await expect(areEqual(clearData, clear)).resolves.toEqual(true);

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

               await expect(cipherSvc.decryptStream(async (cdinfo) => {
                  expect(cdinfo.hint).toEqual("asdf");
                  return ["asdf", undefined];
               }, userCred, corruptStream)).rejects.toThrow(Error);
            }
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

         const cipherStream = await cipherSvc.encryptStream(econtext, async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            expect(cdinfo.alg).toEqual(alg);
            expect(cdinfo.ic).toEqual(cc.ICOUNT_MIN);
            return [pwd, hint];
         }, userCred, clearStream);

         const decryptedStream = await cipherSvc.decryptStream(async (cdinfo) => {
            expect(cdinfo.hint).toEqual(hint);
            return ['the wrong pwd', undefined];
         }, userCred, cipherStream);

         // Password isn't used until stream reading starts
         await expect(readStreamAll(decryptedStream)).rejects.toThrow(DOMException);
      }
   });

   it("detect wrong password, all alogrithms, loops", async function () {

      const maxLps = 3;
      for (let badLp = 1; badLp <= maxLps; badLp++) {

         for (const alg of cipherSvc.algs()) {

            const srcString = 'This is a secret 🦆';
            const [clearStream, clearData] = streamFromStr(srcString);
            const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

            const econtext = {
               algs: Array(maxLps).fill(alg),
               ic: cc.ICOUNT_MIN
            };

            let expectedEncLp = 1;

            const cipherStream = await cipherSvc.encryptStream(econtext, async (cdinfo) => {
               expect(cdinfo.lp).toEqual(expectedEncLp);
               expect(cdinfo.lpEnd).toEqual(maxLps);
               expect(cdinfo.alg).toEqual(alg);
               expect(cdinfo.ic).toEqual(cc.ICOUNT_MIN);
               expectedEncLp += 1;
               return [String(cdinfo.lp), String(cdinfo.lp)];
            }, userCred, clearStream);

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
               const decryptedStream = await cipherSvc.decryptStream(async (cdinfo) => {
                  expect(cdinfo.lp).toEqual(expectedDecLp);
                  expect(cdinfo.lpEnd).toEqual(maxLps);
                  expect(cdinfo.hint).toEqual(String(cdinfo.lp));
                  expect(cdinfo.alg).toEqual(alg);
                  expect(cdinfo.ic).toEqual(cc.ICOUNT_MIN);
                  expectedDecLp -= 1;
                  if (cdinfo.lp == badLp) {
                     return ['wrong', undefined];
                  }
                  else {
                     return [cdinfo.hint!, undefined];
                  }
               }, userCred, cipherStream);

               await readStreamAll(decryptedStream);

            }
            catch (err) {
               expect(err).toBeInstanceOf(DOMException);
               detected = true;
            }

            expect(detected).toBe(true);
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

         const cipherStream = await cipherSvc.encryptStream(econtext, async (cdinfo) => {
            return [pwd, hint];
         }, userCred, clearStream);

         const cipherData = await readStreamAll(cipherStream);

         // change in MAC
         const corruptData = pokeValue(cipherData, 3, -1);
         const [corruptStream] = streamFromBytes(corruptData);

         await expect(cipherSvc.decryptStream(async (cdinfo) => {
            // should never execute
            expect(false, 'should not execute').toBe(true);
            return [pwd, undefined];
         }, userCred, corruptStream)).rejects.toThrow(new RegExp('.+MAC.+'));
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

         const cipherStream = await cipherSvc.encryptStream(econtext, async (cdinfo) => {
            return [pwd, hint];
         }, userCred, clearStream);

         const cipherData = await readStreamAll(cipherStream);

         // Set character in cipher text
         // past ~(MAC + VER + ALG + MAX_IV + CHUCKSZ)*4/3 characters)
         let corruptData = pokeValue(cipherData, 100, -1);
         let [corruptStream] = streamFromBytes(corruptData);

         await expect(cipherSvc.decryptStream(async (cdinfo) => {
            // should never execute
            expect(false, 'should not execute').toBe(true);
            return [pwd, undefined];
         }, userCred, corruptStream)).rejects.toThrow(new RegExp('.+MAC.+'));

         // Hit another value
         corruptData = pokeValue(cipherData, cipherData.length - 30, 4);
         [corruptStream] = streamFromBytes(corruptData);

         await expect(cipherSvc.decryptStream(async (cdinfo) => {
            // should never execute
            expect(false, 'should not execute').toBe(true);
            return [pwd, undefined];
         }, userCred, corruptStream)).rejects.toThrow(new RegExp('.+MAC.+'));
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

      let cipherStream = await cipherSvc.encryptStream(econtext, async (cdinfo) => {
         return [pwd, hint];
      }, userCred, clearStream);

      await expect(readStreamAll(cipherStream)).resolves.not.toThrow();

      // empty pwd
      [clearStream] = streamFromBytes(clearData);

      cipherStream = await cipherSvc.encryptStream(econtext, async (cdinfo) => {
         return ['', hint];
      }, userCred, clearStream);

      await expect(readStreamAll(cipherStream)).rejects.toThrow(new RegExp('Missing password.*'));


      // hint too long
      [clearStream] = streamFromBytes(clearData);

      cipherStream = await cipherSvc.encryptStream(econtext, async (cdinfo) => {
         return [pwd, 'this is too long'.repeat(8)];
      }, userCred, clearStream);

      await expect(readStreamAll(cipherStream)).rejects.toThrow(new RegExp('Hint length.+'));

      // no userCred
      [clearStream] = streamFromBytes(clearData);

      await expect(cipherSvc.encryptStream(econtext, async (cdinfo) => {
         return [pwd, hint];
      }, new Uint8Array(0), clearStream)).rejects.toThrow(new RegExp('.+userCred.*'));

      // extra long userCred
      [clearStream] = streamFromBytes(clearData);

      await expect(cipherSvc.encryptStream(econtext, async (cdinfo) => {
         return [pwd, hint];
      }, crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES + 2)), clearStream)).rejects.toThrow(new RegExp('.+userCred.*'));

      // empty clear data
      [clearStream] = streamFromBytes(new Uint8Array());

      cipherStream = await cipherSvc.encryptStream(econtext, async (cdinfo) => {
         return [pwd, hint];
      }, userCred, clearStream);

      await expect(readStreamAll(cipherStream)).rejects.toThrow(new RegExp('Missing clear.+'));

      // ic too small
      [clearStream] = streamFromBytes(clearData);

      let bcontext = {
         ...econtext,
         ic: cc.ICOUNT_MIN - 1
      };

      await expect(cipherSvc.encryptStream(bcontext, async (cdinfo) => {
         return [pwd, hint];
      }, userCred, clearStream)).rejects.toThrow(new RegExp('Invalid ic.+'));

      // ic too big
      [clearStream] = streamFromBytes(clearData);

      bcontext = {
         ...econtext,
         ic: cc.ICOUNT_MAX + 1
      };

      await expect(cipherSvc.encryptStream(bcontext, async (cdinfo) => {
         return [pwd, hint];
      }, userCred, clearStream)).rejects.toThrow(new RegExp('Invalid ic.+'));


      // invalid alg
      [clearStream] = streamFromBytes(clearData);

      bcontext = {
         ...econtext,
         algs: ['ABS-GCM']
      };

      await expect(cipherSvc.encryptStream(bcontext, async (cdinfo) => {
         return [pwd, hint];
      }, userCred, clearStream)).rejects.toThrow(new RegExp('Invalid alg.+'));

      // really invalid alg
      [clearStream] = streamFromBytes(clearData);

      bcontext = {
         ...econtext,
         algs: ['asdfadfsk']
      };

      await expect(cipherSvc.encryptStream(bcontext, async (cdinfo) => {
         return [pwd, hint];
      }, userCred, clearStream)).rejects.toThrow(new RegExp('Invalid alg.+'));

   });
});

describe("Read block size bugs check", function () {
   let cipherSvc: CipherService;
   let savedReadSize: number;

   beforeEach(() => {
      TestBed.configureTestingModule({});
      cipherSvc = TestBed.inject(CipherService);
      savedReadSize = Encipher['READ_SIZE_START'];
   });

   afterEach(() => {
      //@ts-ignore
      Encipher['READ_SIZE_START'] = savedReadSize;
   });

   it("block size read stall test", async function () {

      const hint = 'nope';
      const pwd = 'another good pwd';
      const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));
      const clearData = crypto.getRandomValues(new Uint8Array(100));

      for (const alg of cipherSvc.algs()) {
         for (const adjust of [-1, 0, 1]) {

            let [clearStream] = streamFromBytes(clearData);

            // Monkey patch to force read size to match data
            //@ts-ignore
            Encipher['READ_SIZE_START'] = clearData.byteLength + adjust;

            //@ts-ignore
            expect(clearData.byteLength + adjust).toEqual(Encipher['READ_SIZE_START']);

            const econtext = {
               algs: [alg],
               ic: cc.ICOUNT_MIN
            };

            let cipherStream = await cipherSvc.encryptStream(econtext, async (cdinfo) => {
               expect(cdinfo.alg).toEqual(alg);
               return [pwd, hint];
            }, userCred, clearStream);

            // This previously stalled
            await expect(readStreamAll(cipherStream)).resolves.not.toThrow();
         }
      }
   });


   it("block size terminator test", async function () {

      const hint = 'nope';
      const pwd = 'another good pwd';
      const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));
      const clearData = crypto.getRandomValues(new Uint8Array(100));

      for (const alg of cipherSvc.algs()) {
         for (const adjust of [-1, 0, 1]) {

            let [clearStream] = streamFromBytes(clearData);

            // Monkey patch to force read size to match data
            //@ts-ignore
            Encipher['READ_SIZE_START'] = clearData.byteLength + adjust;

            //@ts-ignore
            expect(clearData.byteLength + adjust).toEqual(Encipher['READ_SIZE_START']);

            const econtext = {
               algs: [alg],
               ic: cc.ICOUNT_MIN
            };

            let cipherStream = await cipherSvc.encryptStream(econtext, async (cdinfo) => {
               expect(cdinfo.alg).toEqual(alg);
               return [pwd, hint];
            }, userCred, clearStream);

            let dec = await cipherSvc.decryptStream(async (cdinfo) => {
               expect(cdinfo.hint).toEqual(hint);
               expect(cdinfo.alg).toEqual(alg);
               return [pwd, undefined];
            }, userCred, cipherStream);

            // This previously failed due to missing term block
            await expect(areEqual(dec, clearData)).resolves.toEqual(true);
         }
      }
   });

});


describe("Stream manipulation, multi-version", function () {

   let cipherSvc: CipherService;
   beforeEach(() => {
      TestBed.configureTestingModule({});
      cipherSvc = TestBed.inject(CipherService);
   });

   // userCred used for creation of the CTS below
   // b64url userCred for browser injection: xhKm2Q404pGkqfWkTyT3UodUR-99bN0wibH6si9uF8I
   const userCred = new Uint8Array([198, 18, 166, 217, 14, 52, 226, 145, 164, 169, 245, 164, 79, 36, 247, 82, 135, 84, 71, 239, 125, 108, 221, 48, 137, 177, 250, 178, 47, 110, 23, 194]);
   // Also replace following value in cipher.ts to create small blocks
   //const READ_SIZE_START = 1048576/1024/4;
   //const READ_SIZE_MAX = READ_SIZE_START * 41

   const vers = [
      //V5
      {
         ct: "YxDP37WZjE6JP5EBZYd113DywXGmChJgQwJ27yUZkEgFAEgBAAABAKJehRspDKhtYi8y5MvSXUNDxyqrov5RGGOs5BzgyBAAABTw7-eoyC1TGBuraNUCj00sv1OwfcpiwKyOcCZKhPdYt63ia-dg3bV9b0IOCBleMeQyCRhc61FNyKZmUp7vonh5lIbXMUKFODQqRJRhECYDUzBLuCFvfs6ojmRKXll_-unkhH9hRtFvaTR4GDWkJKI62QP992yAIPVtPjN7Y0PlxDshWrfWMKR0_-fd7cKoHmO3JXKB7i6blEupayrqtI1VRhpY1OmGkVYSQcFjlPBkXms-VCxroGk_oA2blfrocNuf0mv2-4rdL4j9ev-k0YiKDu_HkE4tuwkhJ3pdmONEIpW7KMugg3Tg6uWk4KIMYpQKI0R1M-6CYbLXWpKL71vrJ6v_qukX8nUkpiQaqaOTYX8OhFqOPhsU5ChyTmK7ChOscZ_PwjmibGRacyvou6dRDyA_sXs7wqhUe7w3CJfQaZnQAv4FAG4BAAEBAPXFxXNhZ3Gem8pWhq4W9QT8pfUpDpHNKuNcSamS6gnfE0bg9T5FDEp-B0d0LjrhUu_fstk4VOd3k_UfrHjuQ5qD-I8s4Fd9NMkjraXLh2pdAc6E8mCOhdB3pXJp7PEByohXmxfQ6wSpacnckhB4OAPSiUBASNSNNuSWQDRJHBeYIJeNKr8znow9rIRwEe7Nsc_dbmkmfsAknLZO8QR_Glpu4by16DuULi_RLtEfgjAeRzisX7WY65CqlhiQ9KbJtiVKWZXUgVAhTPv1Kyle_uCCgB4dSeZ0C9BC7F1F15QZIEogaxM8OsgpM1szhCahQQjUdj_JVWVeyQ0YKCR9Ku-WszcBdXf7v2RA6A6C30p-B7GFrT8EWod9KSYwu-jA8PMzCymt5rINNB81uOxDc3mJwfgXI0Cailb9RMiuSSvBvUQ1yOWENXhD-L6J9Dn4b6buO4RW3Jx3qrPlwn-LndPzfJgN8P19U-PBAOA=",
         slt: new Uint8Array([203, 210, 93, 67, 67, 199, 42, 171, 162, 254, 81, 24, 99, 172, 228, 28]),
         iv: new Uint8Array([162, 94, 133, 27, 41, 12, 168, 109, 98, 47, 50, 228]),
         ver: 5
      },
      //V6
      {
         ct: "QN-b9IO7eFdTfwLrSpwTJBAQa4mLYb6L1FykX04GHgMGAEkBAAABAIGEvDGIwIKtB6Q_TQBRA-R3wkRpJO-Q-1tcwjbgyBAAABRUjQsN5Nz1_aaEcmuuO7meixdbZL0eCWmNNMuu0oWp8KYFqneceUygklENjuJJ6FUT4iWlBHN5y0qMyTIg4fMQT5kT_aT66ropqfztsDBCZKC3CyFJN-t2jyHyg86OrLrI6f-XemY0YXxhf4Aqv0V97sU43IbQvmedBg8fp-Az7Hy5jPeuzNbu8AM6hLzjmh9nJwVN8TRxoACTaQ2Z3CyAPjUO8N4_Tk3vRCLo0tWkp4Fguuyxermjba9XM1TxLcBhmN4LVbid1JWax09hiDsSbfvJg9nTBptsSu30A19oGx_jVTuI1QwMp-tzrcY6yuoEdZTYctx4PRQE_3EMaqwKSxrTduP7UMR7k-_3qwsKucPiVbIeF_TkTvfWXEnLp9vNXtLchFUxskFvQOhs0RuKKuCb6fkoMYD-7vYWtPzMpbjzI8MGAG8BAAEBADZqgj3PDWTKRYhsxnUl7V-Uj01mOPZgOcetSpf8NqYdbOU8k8Ajc95Dpcym_PHhujoO98OWfRa6ZqCIajWsBzl83PUz6zpX8-DSme71w_WR28fQE4Qu3zrZwPLvoYig1fOGGhNmNHy88BzAxrRrXnrlJuvW6z3ZtD02lLyrvW28DLK75atN32WJgyVrb8N78J-w6erBvFDpu42Wfg4hYeeuvrQLAx_kBLKNCa1AGsPngFNrF76SmIbM7xgIbjcx_yhh3CGe3OfoIJ5Az7eyXqIDGr_Vw-29sx4-mSjavFaDxTSu_gcfhk9xlXmljXSJpLqyOEhA-2dEF5-OLcqOVsY9kH_cdi6YgKl5GCr-q35hd4YWMaI2V89-2js1ABfOZvx21s3WRwiSXGsGHl2IG-Lg9NdJRnikf7qTWSIa5RTMoDHA1pYk9B_mJdchu7IxiUZ-Q4Zy8PE03fSTOfHBQ0KlfW_QdkN084IitMw",
         slt: new Uint8Array([0, 81, 3, 228, 119, 194, 68, 105, 36, 239, 144, 251, 91, 92, 194, 54]),
         iv: new Uint8Array([129, 132, 188, 49, 136, 192, 130, 173, 7, 164, 63, 77]),
         ver: 6
      },
   ];

   const clearData = new Uint8Array([118, 101, 114, 115, 105, 111, 110, 58, 32, 34, 51, 46, 56, 34, 10, 115, 101, 114, 118, 105, 99, 101, 115, 58, 10, 32, 32, 100, 111, 99, 107, 103, 101, 58, 10, 32, 32, 32, 32, 105, 109, 97, 103, 101, 58, 32, 108, 111, 117, 105, 115, 108, 97, 109, 47, 100, 111, 99, 107, 103, 101, 58, 49, 10, 32, 32, 32, 32, 114, 101, 115, 116, 97, 114, 116, 58, 32, 117, 110, 108, 101, 115, 115, 45, 115, 116, 111, 112, 112, 101, 100, 10, 32, 32, 32, 32, 112, 111, 114, 116, 115, 58, 10, 32, 32, 32, 32, 32, 32, 45, 32, 53, 48, 48, 49, 58, 53, 48, 48, 49, 10, 32, 32, 32, 32, 118, 111, 108, 117, 109, 101, 115, 58, 10, 32, 32, 32, 32, 32, 32, 45, 32, 47, 118, 97, 114, 47, 114, 117, 110, 47, 100, 111, 99, 107, 101, 114, 46, 115, 111, 99, 107, 58, 47, 118, 97, 114, 47, 114, 117, 110, 47, 100, 111, 99, 107, 101, 114, 46, 115, 111, 99, 107, 10, 32, 32, 32, 32, 32, 32, 45, 32, 46, 47, 100, 97, 116, 97, 58, 47, 97, 112, 112, 47, 100, 97, 116, 97, 10, 32, 32, 32, 32, 32, 32, 35, 32, 83, 116, 97, 99, 107, 115, 32, 68, 105, 114, 101, 99, 116, 111, 114, 121, 10, 32, 32, 32, 32, 32, 32, 35, 32, 226, 154, 160, 239, 184, 143, 32, 82, 69, 65, 68, 32, 73, 84, 32, 67, 65, 82, 69, 70, 85, 76, 76, 89, 46, 32, 73, 102, 32, 121, 111, 117, 32, 100, 105, 100, 32, 105, 116, 32, 119, 114, 111, 110, 103, 44, 32, 121, 111, 117, 114, 32, 100, 97, 116, 97, 32, 99, 111, 117, 108, 100, 32, 101, 110, 100, 32, 117, 112, 32, 119, 114, 105, 116, 105, 110, 103, 32, 105, 110, 116, 111, 32, 97, 32, 87, 82, 79, 78, 71, 32, 80, 65, 84, 72, 46, 10, 32, 32, 32, 32, 32, 32, 35, 32, 226, 154, 160, 239, 184, 143, 32, 49, 46, 32, 70, 85, 76, 76, 32, 112, 97, 116, 104, 32, 111, 110, 108, 121, 46, 32, 78, 111, 32, 114, 101, 108, 97, 116, 105, 118, 101, 32, 112, 97, 116, 104, 32, 40, 77, 85, 83, 84, 41, 10, 32, 32, 32, 32, 32, 32, 35, 32, 226, 154, 160, 239, 184, 143, 32, 50, 46, 32, 76, 101, 102, 116, 32, 83, 116, 97, 99, 107, 115, 32, 80, 97, 116, 104, 32, 61, 61, 61, 32, 82, 105, 103, 104, 116, 32, 83, 116, 97, 99, 107, 115, 32, 80, 97, 116, 104, 32, 40, 77, 85, 83, 84, 41, 10, 32, 32, 32, 32, 32, 32, 45, 32, 47, 111, 112, 116, 47, 115, 116, 97, 99, 107, 115, 58, 47, 111, 112, 116, 47, 115, 116, 97, 99, 107, 115, 10, 32, 32, 32, 32, 101, 110, 118, 105, 114, 111, 110, 109, 101, 110, 116, 58, 10, 32, 32, 32, 32, 32, 32, 35, 32, 84, 101, 108, 108, 32, 68, 111, 99, 107, 103, 101, 32, 119, 104, 101, 114, 101, 32, 116, 111, 32, 102, 105, 110, 100, 32, 116, 104, 101, 32, 115, 116, 97, 99, 107, 115, 10, 32, 32, 32, 32, 32, 32, 45, 32, 68, 79, 67, 75, 71, 69, 95, 83, 84, 65, 67, 75, 83, 95, 68, 73, 82, 61, 47, 111, 112, 116, 47, 115, 116, 97, 99, 107, 115]);

   const block0MACOffset = 0;
   const block0VerOffset = block0MACOffset + cc.MAC_BYTES;
   const block0SizeOffset = block0VerOffset + cc.VER_BYTES;
   const block0FlagsOffset = block0SizeOffset + cc.PAYLOAD_SIZE_BYTES;
   const block0ADOffset = block0FlagsOffset + cc.FLAGS_BYTES;
   const block0AlgOffset = block0ADOffset;
   const block0IVOffset = block0AlgOffset + cc.ALG_BYTES;
   const block0SltOffset = block0IVOffset + Number(cc.AlgInfo['AES-GCM']['iv_bytes']);
   const block0ICOffset = block0SltOffset + cc.SLT_BYTES;
   const block0LPOffset = block0ICOffset + cc.IC_BYTES; //LP should be at 72
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

      for (const ver of vers) {
         // First make sure it decrypts as expected
         let [cipherStream, cipherData] = streamFromBase64(ver.ct);
         let dec = await cipherSvc.decryptStream(async (cdinfo) => {
            expect(cdinfo.hint).toEqual('4321');
            expect(cdinfo.alg).toBe('AES-GCM');
            expect(cdinfo.ver).toBe(ver.ver);
            expect(cdinfo.lp).toBe(1);
            expect(cdinfo.lpEnd).toBe(1);
            expect(cdinfo.ic).toBe(1100000);
            expect(cdinfo.slt).toEqual(ver.slt);
            expect(cdinfo.iv).toEqual(ver.iv);
            expect(Boolean(cdinfo.hint)).toBe(true);
            return ['asdf', undefined];
         }, userCred, cipherStream);
         await expect(areEqual(dec, clearData)).resolves.toEqual(true);

         // Modified block0 MAC
         const b0Mac = new Uint8Array(cipherData);
         b0Mac[block0MACOffset] = 255;

         let [stream] = streamFromBytes(b0Mac);
         await expect(cipherSvc.decryptStream(async (cdinfo) => { return ['asdf', undefined]; }, userCred, stream)).rejects.toThrow(new RegExp('Invalid MAC.+'));

         // Test modified block0 version
         const b0Ver = new Uint8Array(cipherData);
         b0Ver[block0VerOffset] = 22;
         [stream] = streamFromBytes(b0Ver);
         await expect(cipherSvc.decryptStream(async (cdinfo) => { return ['asdf', undefined]; }, userCred, stream)).rejects.toThrow(new RegExp('Invalid version.+'));

         // Test modified block0 size, valid size but too small
         let b0Size = new Uint8Array(cipherData);
         b0Size.set([20, 1], block0SizeOffset);
         [stream] = streamFromBytes(b0Size);
         await expect(cipherSvc.decryptStream(async (cdinfo) => { return ['asdf', undefined]; }, userCred, stream)).rejects.toThrow(new RegExp('Invalid MAC.+'));

         // Too small block0 size, invalid
         b0Size = new Uint8Array(cipherData);
         b0Size.set([0, 0], block0SizeOffset);
         [stream] = streamFromBytes(b0Size);
         await expect(cipherSvc.decryptStream(async (cdinfo) => { return ['asdf', undefined]; }, userCred, stream)).rejects.toThrow(new RegExp('Invalid payload size3.+'));

         // Test too big block0 size
         b0Size = new Uint8Array(cipherData);
         b0Size.set([255, 255, 255], block0SizeOffset);
         [stream] = streamFromBytes(b0Size);
         await expect(cipherSvc.decryptStream(async (cdinfo) => { return ['asdf', undefined]; }, userCred, stream)).rejects.toThrow(new RegExp('Cipher data length mismatch1.+'));

         // Test modified block0 flags, invalid
         let b0Flags = new Uint8Array(cipherData);
         b0Flags[block0FlagsOffset] = 6;
         [stream] = streamFromBytes(b0Flags);
         await expect(cipherSvc.decryptStream(async (cdinfo) => { return ['asdf', undefined]; }, userCred, stream)).rejects.toThrow(new RegExp('Invalid flags.+'));

         // Test modified block0 flags, early terminal (detected by MAC first because
         // early term isn't known until next block)
         b0Flags = new Uint8Array(cipherData);
         b0Flags[block0FlagsOffset] = 1;
         [stream] = streamFromBytes(b0Flags);
         await expect(cipherSvc.decryptStream(async (cdinfo) => { return ['asdf', undefined]; }, userCred, stream)).rejects.toThrow(new RegExp('Invalid MAC.+'));
      }
   });

   it("detect manipulated cipher stream header, blockN", async function () {

      for (const ver of vers) {

         // First make sure it decrypts as expected
         let [cipherStream, cipherdata] = streamFromBase64(ver.ct);
         let dec = await cipherSvc.decryptStream(async (cdinfo) => {
            expect(cdinfo.hint).toEqual('4321');
            return ['asdf', undefined];
         }, userCred, cipherStream);
         await expect(areEqual(dec, clearData)).resolves.toEqual(true);

         // Modified blockN MAC
         const bNMac = new Uint8Array(cipherdata);
         bNMac[block1MACOffset] = 255;
         let [stream] = streamFromBytes(bNMac);
         dec = await cipherSvc.decryptStream(async (cdinfo) => { return ['asdf', undefined]; }, userCred, stream);
         await expect(readStreamAll(dec)).rejects.toThrow(new RegExp('Invalid MAC.+'));

         // Modified blockN version
         const bNVer = new Uint8Array(cipherdata);
         bNVer.set([4, 1], block1VerOffset);
         [stream] = streamFromBytes(bNVer);
         dec = await cipherSvc.decryptStream(async (cdinfo) => { return ['asdf', undefined]; }, userCred, stream);
         await expect(readStreamAll(dec)).rejects.toThrow(new RegExp('Invalid version.+'));

         // Test modified blockN size, too small valid
         let bNSize = new Uint8Array(cipherdata);
         bNSize.set([20, 1], block1SizeOffset);
         [stream] = streamFromBytes(bNSize);
         dec = await cipherSvc.decryptStream(async (cdinfo) => { return ['asdf', undefined]; }, userCred, stream);
         await expect(readStreamAll(dec)).rejects.toThrow(new RegExp('Invalid MAC.+'));

         // Too small blockN size, too small invalid
         bNSize = new Uint8Array(cipherdata);
         bNSize.set([0, 0], block1SizeOffset);
         [stream] = streamFromBytes(bNSize);
         dec = await cipherSvc.decryptStream(async (cdinfo) => { return ['asdf', undefined]; }, userCred, stream);
         await expect(readStreamAll(dec)).rejects.toThrow(new RegExp('Invalid payload.+'));

         // Test too big blockN but valid
         bNSize = new Uint8Array(cipherdata);
         bNSize.set([255, 255, 255], block1SizeOffset);
         [stream] = streamFromBytes(bNSize);
         dec = await cipherSvc.decryptStream(async (cdinfo) => { return ['asdf', undefined]; }, userCred, stream);
         await expect(readStreamAll(dec)).rejects.toThrow(new RegExp('Cipher data length mismatch2.+'));

         // Test modified block0 flags, invalid
         let bNFlags = new Uint8Array(cipherdata);
         bNFlags[block1FlagsOffset] = 6;
         [stream] = streamFromBytes(bNFlags);
         dec = await cipherSvc.decryptStream(async (cdinfo) => { return ['asdf', undefined]; }, userCred, stream);
         await expect(readStreamAll(dec)).rejects.toThrow(new RegExp('Invalid flags.+'));

         // Test modified block0 flags, early terminal (detected by MAC first)
         bNFlags = new Uint8Array(cipherdata);
         bNFlags[block1FlagsOffset] = 0;
         [stream] = streamFromBytes(bNFlags);
         dec = await cipherSvc.decryptStream(async (cdinfo) => { return ['asdf', undefined]; }, userCred, stream);
         await expect(readStreamAll(dec)).rejects.toThrow(new RegExp('Invalid MAC.+'));
      }
   });


   it("detect manipulated cipher stream additional data, block0", async function () {

      for (const ver of vers) {
         // First make sure it decrypts as expected
         let [cipherStream, cipherdata] = streamFromBase64(ver.ct);
         let dec = await cipherSvc.decryptStream(async (cdinfo) => {
            expect(cdinfo.hint).toEqual('4321');
            return ['asdf', undefined];
         }, userCred, cipherStream);
         await expect(areEqual(dec, clearData)).resolves.toEqual(true);

         // Modified block0 invalid ALG
         let b0Alg = new Uint8Array(cipherdata);
         b0Alg[block0AlgOffset] = 128;
         let [stream] = streamFromBytes(b0Alg);
         await expect(cipherSvc.decryptStream(async (cdinfo) => { return ['asdf', undefined]; }, userCred, stream)).rejects.toThrow(new RegExp('Invalid alg.+'));

         // Modified block0 valid but changed ALG
         b0Alg = new Uint8Array(cipherdata);
         b0Alg[block0AlgOffset] = 2;
         [stream] = streamFromBytes(b0Alg);
         // Error will be different given different cipherdata because changing the alg
         // above changes the IV read len and therefore location of following values.
         // Therefore don't check for specific error message
         await expect(cipherSvc.decryptStream(async (cdinfo) => { return ['asdf', undefined]; }, userCred, stream)).rejects.toThrow(Error);

         // Modified block0 IV
         let b0OIV = new Uint8Array(cipherdata);
         b0OIV[block0IVOffset] = 0;
         [stream] = streamFromBytes(b0OIV);
         await expect(cipherSvc.decryptStream(async (cdinfo) => { return ['asdf', undefined]; }, userCred, stream)).rejects.toThrow(new RegExp('Invalid MAC.+'));

         // Modified block0 Salt
         let b0Slt = new Uint8Array(cipherdata);
         b0Slt[block0SltOffset] = 1;
         [stream] = streamFromBytes(b0Slt);
         await expect(cipherSvc.decryptStream(async (cdinfo) => { return ['asdf', undefined]; }, userCred, stream)).rejects.toThrow(new RegExp('Invalid MAC.+'));

         // Modified block0 invalid IC
         let b0IC = new Uint8Array(cipherdata);
         b0IC.set([0, 0, 0, 0], block0ICOffset);
         [stream] = streamFromBytes(b0IC);
         await expect(cipherSvc.decryptStream(async (cdinfo) => { return ['asdf', undefined]; }, userCred, stream)).rejects.toThrow(new RegExp('Invalid ic.+'));

         // Modified block0 valid but changed IC
         b0IC = new Uint8Array(cipherdata);
         b0IC.set([64, 119, 21, 1], block0ICOffset);
         [stream] = streamFromBytes(b0IC);
         await expect(cipherSvc.decryptStream(async (cdinfo) => { return ['asdf', undefined]; }, userCred, stream)).rejects.toThrow(new RegExp('Invalid MAC.+'));

         // Modified block0 invalid LPP
         let b0LP = new Uint8Array(cipherdata);
         b0LP[block0LPOffset] = 24; // lp > lpEnd
         [stream] = streamFromBytes(b0LP);
         await expect(cipherSvc.decryptStream(async (cdinfo) => { return ['asdf', undefined]; }, userCred, stream)).rejects.toThrow(new RegExp('Invalid lp.+'));

         // Modified block0 valid but changed LPP
         b0LP = new Uint8Array(cipherdata);
         b0LP[block0LPOffset] = 48;
         [stream] = streamFromBytes(b0LP);
         await expect(cipherSvc.decryptStream(async (cdinfo) => { return ['asdf', undefined]; }, userCred, stream)).rejects.toThrow(new RegExp('Invalid MAC.+'));

         // Modified block0 hint length
         let b0HintLen = new Uint8Array(cipherdata);
         b0HintLen[block0HintLenOffset] = 12;
         [stream] = streamFromBytes(b0HintLen);
         await expect(cipherSvc.decryptStream(async (cdinfo) => { return ['asdf', undefined]; }, userCred, stream)).rejects.toThrow(new RegExp('Invalid MAC.+'));

         // Modified block0 hint
         let b0Hint = new Uint8Array(cipherdata);
         b0Hint[block0HintOffset] = 12;
         [stream] = streamFromBytes(b0Hint);
         await expect(cipherSvc.decryptStream(async (cdinfo) => { return ['asdf', undefined]; }, userCred, stream)).rejects.toThrow(new RegExp('Invalid MAC.+'));
      }
   });

   it("detect manipulated cipher stream additional data, blockN", async function () {

      for (const ver of vers) {
         // First make sure it decrypts as expected
         let [cipherStream, cipherdata] = streamFromBase64(ver.ct);
         let dec = await cipherSvc.decryptStream(async (cdinfo) => {
            expect(cdinfo.hint).toEqual('4321');
            return ['asdf', undefined];
         }, userCred, cipherStream);
         await expect(areEqual(dec, clearData)).resolves.toEqual(true);

         // Modified blockN invalid ALG
         let bNAlg = new Uint8Array(cipherdata);
         bNAlg[block1AlgOffset] = 128;
         let [stream] = streamFromBytes(bNAlg);
         dec = await cipherSvc.decryptStream(async (cdinfo) => { return ['asdf', undefined]; }, userCred, stream);
         await expect(readStreamAll(dec)).rejects.toThrow(new RegExp('Invalid alg.+'));

         // Modified blockN valid but changed ALG
         bNAlg = new Uint8Array(cipherdata);
         bNAlg[block1AlgOffset] = 2;
         [stream] = streamFromBytes(bNAlg);
         dec = await cipherSvc.decryptStream(async (cdinfo) => { return ['asdf', undefined]; }, userCred, stream);
         // Error will be different given different cipherdata because changing the alg
         // above changes the IV read len and therefore location of following values.
         // Therefore don't check for specific error message
         await expect(readStreamAll(dec)).rejects.toThrow(Error);

         // Modified blockN IV
         let bNIV = new Uint8Array(cipherdata);
         bNIV[block1IVOffset] = 0;
         [stream] = streamFromBytes(bNIV);
         dec = await cipherSvc.decryptStream(async (cdinfo) => { return ['asdf', undefined]; }, userCred, stream);
         await expect(readStreamAll(dec)).rejects.toThrow(new RegExp('Invalid MAC.+'));
      }
   });

   it("detect manipulated cipher stream encrypted data, block0 & blockN", async function () {

      for (const ver of vers) {
         // First make sure ct decrypts as expected
         let [cipherStream, cipherdata] = streamFromBase64(ver.ct);
         let dec = await cipherSvc.decryptStream(async (cdinfo) => {
            expect(cdinfo.hint).toEqual('4321');
            return ['asdf', undefined];
         }, userCred, cipherStream);
         await expect(areEqual(dec, clearData)).resolves.toEqual(true);

         // Modified block0 encrypted data
         let b0Enc = new Uint8Array(cipherdata);
         b0Enc[block0EncOffset] = 0;
         let [stream] = streamFromBytes(b0Enc);
         // version ${ver.ver}
         await expect(cipherSvc.decryptStream(async (cdinfo) => { return ['asdf', undefined]; }, userCred, stream)).rejects.toThrow(/Invalid MAC/);

         // Modified blockN encrypted data
         let bNEnc = new Uint8Array(cipherdata);
         bNEnc[block1EncOffset] = 0;
         [stream] = streamFromBytes(bNEnc);
         dec = await cipherSvc.decryptStream(async (cdinfo) => { return ['asdf', undefined]; }, userCred, stream);
         await expect(readStreamAll(dec)).rejects.toThrow(new RegExp('Invalid MAC.+'));
      }
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

         const cipherStream = await cipherSvc.encryptStream(econtext, async (cdinfo) => {
            return [pwd, hint];
         }, userCred, clearStream);

         const cipherData = await readStreamAll(cipherStream);
         const modLen = randomInclusive(1, 10);
         const modData = crypto.getRandomValues(new Uint8Array(modLen));
         const modPos = randomInclusive(0, cipherData.byteLength - modLen);

         cipherData.set(modData, modPos);
         const [corruptStream] = streamFromBytes(cipherData);

         // alg ${alg}, modLen ${modLen}, modPos ${modPos}
         await expect(cipherSvc.decryptStream(async (cdinfo) => {
            // should never execute
            expect(false, 'should not execute').toBe(true);
            return [pwd, undefined];
         }, userCred, corruptStream)).rejects.toThrow(Error);
      }
   });

   it("detect fuzz cipher data decryption, all algorithms", async function () {

      // Test both small invalid and normal size "cipher data"
      const minValid = cc.HEADER_BYTES_6P + cc.PAYLOAD_SIZE_MIN;
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

            // alg ${alg}, fuzzLen ${fuzzLen}
            await expect(cipherSvc.decryptStream(async (cdinfo) => {
               // should never execute
               expect(false, 'should not execute').toBe(true);
               return [pwd, undefined];
            }, userCred, fuzzStream)).rejects.toThrow(Error);
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

         const cipherStream = await cipherSvc.encryptStream(econtext, async (cdinfo) => {
            return [pwd, hint];
         }, userCred, clearStream);

         const cipherData = await readStreamAll(cipherStream);
         const rmLen = randomInclusive(1, 10);

         for (let rmPos = 0; rmPos < cipherData.byteLength - rmLen; rmPos++) {

            let corruptData = new Uint8Array(cipherData.byteLength - rmLen);
            corruptData.set(cipherData.slice(0, rmPos));
            corruptData.set(cipherData.slice(rmPos + rmLen), rmPos);
            let [corruptStream] = streamFromBytes(corruptData);

            // alg ${alg}, rmLen ${rmLen}, rmPos ${rmPos}
            await expect(cipherSvc.decryptStream(async (cdinfo) => {
               // should never execute
               expect(false, 'should not execute').toBe(true);
               return [pwd, undefined];
            }, userCred, corruptStream)).rejects.toThrow(Error);
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

         const cipherStream = await cipherSvc.encryptStream(econtext, async (cdinfo) => {
            return [pwd, hint];
         }, userCred, clearStream);

         const cipherData = await readStreamAll(cipherStream);
         const addLen = randomInclusive(1, 10);
         const addData = crypto.getRandomValues(new Uint8Array(addLen));

         // make sure first byte of addData doesn't match last byte of cipherData or
         // the extra padding won't be detected until readStreamAll (see below)
         if (addData[0] === cipherData.at(-1)) {
            addData[0] = (addData[0] + 1) % 256;
         }

         for (let addPos = 0; addPos < cipherData.byteLength; addPos++) {

            let corruptData = new Uint8Array(cipherData.byteLength + addLen);
            corruptData.set(cipherData.slice(0, addPos));
            corruptData.set(addData, addPos);
            corruptData.set(cipherData.slice(addPos), addPos + addLen);
            let [corruptStream] = streamFromBytes(corruptData);

            // alg ${alg}, addLen ${addLen}, addPos ${addPos}
            await expect(cipherSvc.decryptStream(async (cdinfo) => {
               // should never execute
               expect(false, 'should not execute').toBe(true);
               return [pwd, undefined];
            }, userCred, corruptStream)).rejects.toThrow(Error);
         }

         // Appending data after block0 throws and error at stream read since
         // only block0 is validated during stream construction
         let corruptData = new Uint8Array(cipherData.byteLength + addLen);
         corruptData.set(cipherData);
         corruptData.set(addData, cipherData.byteLength);
         let [corruptStream] = streamFromBytes(corruptData);

         const corrupStream = await cipherSvc.decryptStream(async (cdinfo) => {
            return [pwd, undefined];
         }, userCred, corruptStream);

         // alg ${alg}, addLen ${addLen}
         await expect(readStreamAll(corrupStream)).rejects.toThrow(Error);
      }
   });

});

describe("Block order change and deletion detection, multi-version", function () {
   let cipherSvc: CipherService;
   beforeEach(() => {
      TestBed.configureTestingModule({});
      cipherSvc = TestBed.inject(CipherService);
   });

   // userCred used for creation of the CTS above
   // b64url userCred for commadline: xhKm2Q404pGkqfWkTyT3UodUR-99bN0wibH6si9uF8I
   const userCred = new Uint8Array([198, 18, 166, 217, 14, 52, 226, 145, 164, 169, 245, 164, 79, 36, 247, 82, 135, 84, 71, 239, 125, 108, 221, 48, 137, 177, 250, 178, 47, 110, 23, 194]);
   // Also replace following value in cipher.ts to create small blocks
   //const READ_SIZE_START = 9;
   //const READ_SIZE_MAX = READ_SIZE_START * 16

   const vers = [
      //V5
      {
         ver: 5,
         goodCt: "v6xsVVBD4pOtHHfzLsKBVHscJ7Q4kv_KqOKH3X_Fx1IFAFEAAAABAAZsrNtMucZUIr2UFJF3Y9R2FtBAqbm_YLotMSzgyBAAABRnUeng3ADKX8ZIicklSvESgyOeUPCFnOoBhpY-g10PWujfV7mwWWJZdMylaext9jLzwDxOLnu6u4cxcgbt1Ga1Vn5F0qDCyO0Xp9W1mAUAMAAAAAEAQTScPYuFjasQGAKP6oqkR9d58Q0YgvW3zEg50a0en8vK2ShqzFWqL5E9A_mmkaAvhGj9rr43RZhZiInC6ccflFeTqERnpm0jqQL9ysQtBQBCAAAAAQCH0B81axAaykKtBBNhvA0of9kUOniwBgdkzLFYwPH_pz75AdARszabKfDmBWOZFAzy9dDJfiqIz2Nbfr4S59sVkfpg_FPiD6_QgqLXQtv7_SDDAHb5a3C-NLGvP4KhxAYFAGYAAAABAIVBoUjIij7b-5zUE6FMbuAaiegCEYXBcSuLeeKfCH5WHveQq6-8KA4U-IQ6IZ5Rz_ocEv1L5e9uqanzYvGkFMfbhjO3oNH5-C_CqfCIF_1OzrgztnYx2feFXB0DGiR7PBWkPKErkb7VBUkVLd8T-ZqVhNFQstJrXxEXdriJzUfeLrGV3wUArgAAAAEA44DnCIDUxMUHlsvdM6d5QAs_MSRUx0y7_a6hecMnN1K5eOxDxqGDf-3xzL0dpb5CrbW99lYJLwZz9zqyAmPMeCx2KNFL2YFkhBSMy7XrDV9u2wT1ulIKPq6IQpOCos7LqBhiTeh46TqpYgYpeckATiYUrIS5RBfHdxAVQ6Sy-VOAPwHGochCI4AYBjcLGWWYKYkZD3d3CGjjI-haOmFab1vWKNIPE4Cyuvh0bH8dXs3DmHv4vEU8bW5JwioVuw5ciDOH7wgZTdCOBOLqBQCuAAAAAQCwx1-ma6ln7jlEN5K8rAzplIiJ5_iWANGMRdIJhjzQEX7KKCw-bffXnbx_gdPBU0o5ZzkU-HfQih-BeR6nzMsK5KSZBMJUwCAZ9ibCPjkO9cB_iyXAj_82Kk2argCNVaVNVD1rIg8Ig2lyi7btAsFiF5ANSlTv6lpJIqYapa_d1eaNIT6SOEWs2cVCgu4OaGAAzzFg_cw6A1z8VAhBFeyX-VBgerpVZVMijFcgvRxCglN1AVY8Ts5kORAaVCh9w2JFytcXHS4YElml_mgFAK4AAAABAOBdI8pBAWBb4TWSeJEQGRBchmv2EnJ_GKiBxdUuDtTO2ayK-iYjZdXrfxrKenbMcfcKrOZv7zccFcsICw-YqrS6TuKYzlbWUFm_5-mLNuDCQwTjDSok50r0j3vFD2I03wBB9j1NgGgDkhq8LMrRBCIMt0xRv6rz1RXdftsZ-gRklpvNCJPsw20SMBB8jVO7owExMM7HQZ289lY_z8q4hFA8_RepUItTnckfZtl0ZWxnf1JY05yAOI17w8-h80jjQfLXityWRu29nWAsdgUANwAAAQEA-CZxmBlulfdy7xc9NP2C2PH1FoGV4ClHPFor1PaqvS8PIGwJjYpN4Pq0S9o4DPPVd-WzFhg=",
         badCts: {
            'Block0 Block7 swap': 'dGVsZ39SWNOcgDiNe8PPofNI40Hy14rclkbtvZ1gLHYFADcAAAEBAPgmcZgZbpX3cu8XPTT9gtjx9RaBleApRzxaK9T2qr0vDyBsCY2KTeD6tEvaOAzz1XflsxYYbfYy88A8Ti57uruHMXIG7dRmtVZ-RdKgwsjtF6fVtZgFADAAAAABAEE0nD2LhY2rEBgCj-qKpEfXefENGIL1t8xIOdGtHp_LytkoasxVqi-RPQP5ppGgL4Ro_a6-N0WYWYiJwunHH5RXk6hEZ6ZtI6kC_crELQUAQgAAAAEAh9AfNWsQGspCrQQTYbwNKH_ZFDp4sAYHZMyxWMDx_6c--QHQEbM2mynw5gVjmRQM8vXQyX4qiM9jW36-EufbFZH6YPxT4g-v0IKi10Lb-_0gwwB2-WtwvjSxrz-CocQGBQBmAAAAAQCFQaFIyIo-2_uc1BOhTG7gGonoAhGFwXEri3ninwh-Vh73kKuvvCgOFPiEOiGeUc_6HBL9S-Xvbqmp82LxpBTH24Yzt6DR-fgvwqnwiBf9Ts64M7Z2Mdn3hVwdAxokezwVpDyhK5G-1QVJFS3fE_malYTRULLSa18RF3a4ic1H3i6xld8FAK4AAAABAOOA5wiA1MTFB5bL3TOneUALPzEkVMdMu_2uoXnDJzdSuXjsQ8ahg3_t8cy9HaW-Qq21vfZWCS8Gc_c6sgJjzHgsdijRS9mBZIQUjMu16w1fbtsE9bpSCj6uiEKTgqLOy6gYYk3oeOk6qWIGKXnJAE4mFKyEuUQXx3cQFUOksvlTgD8BxqHIQiOAGAY3CxllmCmJGQ93dwho4yPoWjphWm9b1ijSDxOAsrr4dGx_HV7Nw5h7-LxFPG1uScIqFbsOXIgzh-8IGU3QjgTi6gUArgAAAAEAsMdfpmupZ-45RDeSvKwM6ZSIief4lgDRjEXSCYY80BF-yigsPm331528f4HTwVNKOWc5FPh30IofgXkep8zLCuSkmQTCVMAgGfYmwj45DvXAf4slwI__NipNmq4AjVWlTVQ9ayIPCINpcou27QLBYheQDUpU7-paSSKmGqWv3dXmjSE-kjhFrNnFQoLuDmhgAM8xYP3MOgNc_FQIQRXsl_lQYHq6VWVTIoxXIL0cQoJTdQFWPE7OZDkQGlQofcNiRcrXFx0uGBJZpf5oBQCuAAAAAQDgXSPKQQFgW-E1kniREBkQXIZr9hJyfxiogcXVLg7UztmsivomI2XV638aynp2zHH3Cqzmb-83HBXLCAsPmKq0uk7imM5W1lBZv-fpizbgwkME4w0qJOdK9I97xQ9iNN8AQfY9TYBoA5IavCzK0QQiDLdMUb-q89UV3X7bGfoEZJabzQiT7MNtEjAQfI1Tu6MBMTDOx0GdvPZWP8_KuIRQPP0XqVCLU53JH2bZdGVsZ39SWNOcgDiNe8PPofNI40Hy14rclkbtvZ1gLHYFADcAAAEBAPgmcZgZbpX3cu8XPTT9gtjx9RaBleApRzxaK9T2qr0vDyBsCY2KTeD6tEvaOAzz1XflsxYYv6xsVVBD4pOtHHfzLsKBVHscJ7Q4kv_KqOKH3X_Fx1IFAFEAAAABAAZsrNtMucZUIr2UFJF3Y9R2FtBAqbm_YLotMSzgyBAAABRnUeng3ADKX8ZIicklSvESgyOeUPCFnOoBhpY-g10PWujfV7mwWWJZdMylaew=',

            'Block1 Block4 swap': 'v6xsVVBD4pOtHHfzLsKBVHscJ7Q4kv_KqOKH3X_Fx1IFAFEAAAABAAZsrNtMucZUIr2UFJF3Y9R2FtBAqbm_YLotMSzgyBAAABRnUeng3ADKX8ZIicklSvESgyOeUPCFnOoBhpY-g10PWujfV7mwWWJZdMylaewrkb7VBUkVLd8T-ZqVhNFQstJrXxEXdriJzUfeLrGV3wUArgAAAAEA44DnCIDUxMUHlsvdM6d5QAs_MSRUx0y7_a6hecMnN1K5eOxDxqGDf-3xzL0dpb5CrbW99lYJLwZz9zqyAmPMeCx2KNFL2YFkhBSMy7XrDV9u2wT1ulIKPq6IQpOCos7LqBhiTeh46TqpYgYpeckATiYUrIS5RBfHdxAVQ6Sy-VOAPwHGochCI4AYBjcLGWWYKYkZD3d3CGjjI-haOmFab1vWKNIPE4Cyuvh0bKAvhGj9rr43RZhZiInC6ccflFeTqERnpm0jqQL9ysQtBQBCAAAAAQCH0B81axAaykKtBBNhvA0of9kUOniwBgdkzLFYwPH_pz75AdARszabKfDmBWOZFAzy9dDJfiqIz2Nbfr4S59sVkfpg_FPiD6_QgqLXQtv7_SDDAHb5a3C-NLGvP4KhxAYFAGYAAAABAIVBoUjIij7b-5zUE6FMbuAaiegCEYXBcSuLeeKfCH5WHveQq6-8KA4U-IQ6IZ5Rz_ocEv1L5e9uqanzYvGkFMfbhjO3oNH5-C_CqfCIF_1OzrgztnYx2feFXB0DGiR7PBWkPKFt9jLzwDxOLnu6u4cxcgbt1Ga1Vn5F0qDCyO0Xp9W1mAUAMAAAAAEAQTScPYuFjasQGAKP6oqkR9d58Q0YgvW3zEg50a0en8vK2ShqzFWqL5E9A_mmkX8dXs3DmHv4vEU8bW5JwioVuw5ciDOH7wgZTdCOBOLqBQCuAAAAAQCwx1-ma6ln7jlEN5K8rAzplIiJ5_iWANGMRdIJhjzQEX7KKCw-bffXnbx_gdPBU0o5ZzkU-HfQih-BeR6nzMsK5KSZBMJUwCAZ9ibCPjkO9cB_iyXAj_82Kk2argCNVaVNVD1rIg8Ig2lyi7btAsFiF5ANSlTv6lpJIqYapa_d1eaNIT6SOEWs2cVCgu4OaGAAzzFg_cw6A1z8VAhBFeyX-VBgerpVZVMijFcgvRxCglN1AVY8Ts5kORAaVCh9w2JFytcXHS4YElml_mgFAK4AAAABAOBdI8pBAWBb4TWSeJEQGRBchmv2EnJ_GKiBxdUuDtTO2ayK-iYjZdXrfxrKenbMcfcKrOZv7zccFcsICw-YqrS6TuKYzlbWUFm_5-mLNuDCQwTjDSok50r0j3vFD2I03wBB9j1NgGgDkhq8LMrRBCIMt0xRv6rz1RXdftsZ-gRklpvNCJPsw20SMBB8jVO7owExMM7HQZ289lY_z8q4hFA8_RepUItTnckfZtl0ZWxnf1JY05yAOI17w8-h80jjQfLXityWRu29nWAsdgUANwAAAQEA-CZxmBlulfdy7xc9NP2C2PH1FoGV4ClHPFor1PaqvS8PIGwJjYpN4Pq0S9o4DPPVd-WzFhg=',

            'Block1 repeated': 'v6xsVVBD4pOtHHfzLsKBVHscJ7Q4kv_KqOKH3X_Fx1IFAFEAAAABAAZsrNtMucZUIr2UFJF3Y9R2FtBAqbm_YLotMSzgyBAAABRnUeng3ADKX8ZIicklSvESgyOeUPCFnOoBhpY-g10PWujfV7mwWWJZdMylaext9jLzwDxOLnu6u4cxcgbt1Ga1Vn5F0qDCyO0Xp9W1mAUAMAAAAAEAQTScPYuFjasQGAKP6oqkR9d58Q0YgvW3zEg50a0en8vK2ShqzFWqL5E9A_mmkW32MvPAPE4ue7q7hzFyBu3UZrVWfkXSoMLI7Ren1bWYBQAwAAAAAQBBNJw9i4WNqxAYAo_qiqRH13nxDRiC9bfMSDnRrR6fy8rZKGrMVaovkT0D-aaRoC-EaP2uvjdFmFmIicLpxx-UV5OoRGembSOpAv3KxC0FAEIAAAABAIfQHzVrEBrKQq0EE2G8DSh_2RQ6eLAGB2TMsVjA8f-nPvkB0BGzNpsp8OYFY5kUDPL10Ml-KojPY1t-vhLn2xWR-mD8U-IPr9CCotdC2_v9IMMAdvlrcL40sa8_gqHEBgUAZgAAAAEAhUGhSMiKPtv7nNQToUxu4BqJ6AIRhcFxK4t54p8IflYe95Crr7woDhT4hDohnlHP-hwS_Uvl726pqfNi8aQUx9uGM7eg0fn4L8Kp8IgX_U7OuDO2djHZ94VcHQMaJHs8FaQ8oSuRvtUFSRUt3xP5mpWE0VCy0mtfERd2uInNR94usZXfBQCuAAAAAQDjgOcIgNTExQeWy90zp3lACz8xJFTHTLv9rqF5wyc3Url47EPGoYN_7fHMvR2lvkKttb32VgkvBnP3OrICY8x4LHYo0UvZgWSEFIzLtesNX27bBPW6Ugo-rohCk4KizsuoGGJN6HjpOqliBil5yQBOJhSshLlEF8d3EBVDpLL5U4A_AcahyEIjgBgGNwsZZZgpiRkPd3cIaOMj6Fo6YVpvW9Yo0g8TgLK6-HRsfx1ezcOYe_i8RTxtbknCKhW7DlyIM4fvCBlN0I4E4uoFAK4AAAABALDHX6ZrqWfuOUQ3krysDOmUiInn-JYA0YxF0gmGPNARfsooLD5t99edvH-B08FTSjlnORT4d9CKH4F5HqfMywrkpJkEwlTAIBn2JsI-OQ71wH-LJcCP_zYqTZquAI1VpU1UPWsiDwiDaXKLtu0CwWIXkA1KVO_qWkkiphqlr93V5o0hPpI4RazZxUKC7g5oYADPMWD9zDoDXPxUCEEV7Jf5UGB6ulVlUyKMVyC9HEKCU3UBVjxOzmQ5EBpUKH3DYkXK1xcdLhgSWaX-aAUArgAAAAEA4F0jykEBYFvhNZJ4kRAZEFyGa_YScn8YqIHF1S4O1M7ZrIr6JiNl1et_Gsp6dsxx9wqs5m_vNxwVywgLD5iqtLpO4pjOVtZQWb_n6Ys24MJDBOMNKiTnSvSPe8UPYjTfAEH2PU2AaAOSGrwsytEEIgy3TFG_qvPVFd1-2xn6BGSWm80Ik-zDbRIwEHyNU7ujATEwzsdBnbz2Vj_PyriEUDz9F6lQi1OdyR9m2XRlbGd_UljTnIA4jXvDz6HzSONB8teK3JZG7b2dYCx2BQA3AAABAQD4JnGYGW6V93LvFz00_YLY8fUWgZXgKUc8WivU9qq9Lw8gbAmNik3g-rRL2jgM89V35bMWGA==',

            "Block1 deleted": 'v6xsVVBD4pOtHHfzLsKBVHscJ7Q4kv_KqOKH3X_Fx1IFAFEAAAABAAZsrNtMucZUIr2UFJF3Y9R2FtBAqbm_YLotMSzgyBAAABRnUeng3ADKX8ZIicklSvESgyOeUPCFnOoBhpY-g10PWujfV7mwWWJZdMylaeygL4Ro_a6-N0WYWYiJwunHH5RXk6hEZ6ZtI6kC_crELQUAQgAAAAEAh9AfNWsQGspCrQQTYbwNKH_ZFDp4sAYHZMyxWMDx_6c--QHQEbM2mynw5gVjmRQM8vXQyX4qiM9jW36-EufbFZH6YPxT4g-v0IKi10Lb-_0gwwB2-WtwvjSxrz-CocQGBQBmAAAAAQCFQaFIyIo-2_uc1BOhTG7gGonoAhGFwXEri3ninwh-Vh73kKuvvCgOFPiEOiGeUc_6HBL9S-Xvbqmp82LxpBTH24Yzt6DR-fgvwqnwiBf9Ts64M7Z2Mdn3hVwdAxokezwVpDyhK5G-1QVJFS3fE_malYTRULLSa18RF3a4ic1H3i6xld8FAK4AAAABAOOA5wiA1MTFB5bL3TOneUALPzEkVMdMu_2uoXnDJzdSuXjsQ8ahg3_t8cy9HaW-Qq21vfZWCS8Gc_c6sgJjzHgsdijRS9mBZIQUjMu16w1fbtsE9bpSCj6uiEKTgqLOy6gYYk3oeOk6qWIGKXnJAE4mFKyEuUQXx3cQFUOksvlTgD8BxqHIQiOAGAY3CxllmCmJGQ93dwho4yPoWjphWm9b1ijSDxOAsrr4dGx_HV7Nw5h7-LxFPG1uScIqFbsOXIgzh-8IGU3QjgTi6gUArgAAAAEAsMdfpmupZ-45RDeSvKwM6ZSIief4lgDRjEXSCYY80BF-yigsPm331528f4HTwVNKOWc5FPh30IofgXkep8zLCuSkmQTCVMAgGfYmwj45DvXAf4slwI__NipNmq4AjVWlTVQ9ayIPCINpcou27QLBYheQDUpU7-paSSKmGqWv3dXmjSE-kjhFrNnFQoLuDmhgAM8xYP3MOgNc_FQIQRXsl_lQYHq6VWVTIoxXIL0cQoJTdQFWPE7OZDkQGlQofcNiRcrXFx0uGBJZpf5oBQCuAAAAAQDgXSPKQQFgW-E1kniREBkQXIZr9hJyfxiogcXVLg7UztmsivomI2XV638aynp2zHH3Cqzmb-83HBXLCAsPmKq0uk7imM5W1lBZv-fpizbgwkME4w0qJOdK9I97xQ9iNN8AQfY9TYBoA5IavCzK0QQiDLdMUb-q89UV3X7bGfoEZJabzQiT7MNtEjAQfI1Tu6MBMTDOx0GdvPZWP8_KuIRQPP0XqVCLU53JH2bZdGVsZ39SWNOcgDiNe8PPofNI40Hy14rclkbtvZ1gLHYFADcAAAEBAPgmcZgZbpX3cu8XPTT9gtjx9RaBleApRzxaK9T2qr0vDyBsCY2KTeD6tEvaOAzz1XflsxYY',

            'Block2 repeated': 'v6xsVVBD4pOtHHfzLsKBVHscJ7Q4kv_KqOKH3X_Fx1IFAFEAAAABAAZsrNtMucZUIr2UFJF3Y9R2FtBAqbm_YLotMSzgyBAAABRnUeng3ADKX8ZIicklSvESgyOeUPCFnOoBhpY-g10PWujfV7mwWWJZdMylaext9jLzwDxOLnu6u4cxcgbt1Ga1Vn5F0qDCyO0Xp9W1mAUAMAAAAAEAQTScPYuFjasQGAKP6oqkR9d58Q0YgvW3zEg50a0en8vK2ShqzFWqL5E9A_mmkaAvhGj9rr43RZhZiInC6ccflFeTqERnpm0jqQL9ysQtBQBCAAAAAQCH0B81axAaykKtBBNhvA0of9kUOniwBgdkzLFYwPH_pz75AdARszabKfDmBWOZFAzy9dDJfiqIz2Nbfr4S59sVoC-EaP2uvjdFmFmIicLpxx-UV5OoRGembSOpAv3KxC0FAEIAAAABAIfQHzVrEBrKQq0EE2G8DSh_2RQ6eLAGB2TMsVjA8f-nPvkB0BGzNpsp8OYFY5kUDPL10Ml-KojPY1t-vhLn2xWR-mD8U-IPr9CCotdC2_v9IMMAdvlrcL40sa8_gqHEBgUAZgAAAAEAhUGhSMiKPtv7nNQToUxu4BqJ6AIRhcFxK4t54p8IflYe95Crr7woDhT4hDohnlHP-hwS_Uvl726pqfNi8aQUx9uGM7eg0fn4L8Kp8IgX_U7OuDO2djHZ94VcHQMaJHs8FaQ8oSuRvtUFSRUt3xP5mpWE0VCy0mtfERd2uInNR94usZXfBQCuAAAAAQDjgOcIgNTExQeWy90zp3lACz8xJFTHTLv9rqF5wyc3Url47EPGoYN_7fHMvR2lvkKttb32VgkvBnP3OrICY8x4LHYo0UvZgWSEFIzLtesNX27bBPW6Ugo-rohCk4KizsuoGGJN6HjpOqliBil5yQBOJhSshLlEF8d3EBVDpLL5U4A_AcahyEIjgBgGNwsZZZgpiRkPd3cIaOMj6Fo6YVpvW9Yo0g8TgLK6-HRsfx1ezcOYe_i8RTxtbknCKhW7DlyIM4fvCBlN0I4E4uoFAK4AAAABALDHX6ZrqWfuOUQ3krysDOmUiInn-JYA0YxF0gmGPNARfsooLD5t99edvH-B08FTSjlnORT4d9CKH4F5HqfMywrkpJkEwlTAIBn2JsI-OQ71wH-LJcCP_zYqTZquAI1VpU1UPWsiDwiDaXKLtu0CwWIXkA1KVO_qWkkiphqlr93V5o0hPpI4RazZxUKC7g5oYADPMWD9zDoDXPxUCEEV7Jf5UGB6ulVlUyKMVyC9HEKCU3UBVjxOzmQ5EBpUKH3DYkXK1xcdLhgSWaX-aAUArgAAAAEA4F0jykEBYFvhNZJ4kRAZEFyGa_YScn8YqIHF1S4O1M7ZrIr6JiNl1et_Gsp6dsxx9wqs5m_vNxwVywgLD5iqtLpO4pjOVtZQWb_n6Ys24MJDBOMNKiTnSvSPe8UPYjTfAEH2PU2AaAOSGrwsytEEIgy3TFG_qvPVFd1-2xn6BGSWm80Ik-zDbRIwEHyNU7ujATEwzsdBnbz2Vj_PyriEUDz9F6lQi1OdyR9m2XRlbGd_UljTnIA4jXvDz6HzSONB8teK3JZG7b2dYCx2BQA3AAABAQD4JnGYGW6V93LvFz00_YLY8fUWgZXgKUc8WivU9qq9Lw8gbAmNik3g-rRL2jgM89V35bMWGA==',

            'Block2 deleted': 'v6xsVVBD4pOtHHfzLsKBVHscJ7Q4kv_KqOKH3X_Fx1IFAFEAAAABAAZsrNtMucZUIr2UFJF3Y9R2FtBAqbm_YLotMSzgyBAAABRnUeng3ADKX8ZIicklSvESgyOeUPCFnOoBhpY-g10PWujfV7mwWWJZdMylaext9jLzwDxOLnu6u4cxcgbt1Ga1Vn5F0qDCyO0Xp9W1mAUAMAAAAAEAQTScPYuFjasQGAKP6oqkR9d58Q0YgvW3zEg50a0en8vK2ShqzFWqL5E9A_mmkZH6YPxT4g-v0IKi10Lb-_0gwwB2-WtwvjSxrz-CocQGBQBmAAAAAQCFQaFIyIo-2_uc1BOhTG7gGonoAhGFwXEri3ninwh-Vh73kKuvvCgOFPiEOiGeUc_6HBL9S-Xvbqmp82LxpBTH24Yzt6DR-fgvwqnwiBf9Ts64M7Z2Mdn3hVwdAxokezwVpDyhK5G-1QVJFS3fE_malYTRULLSa18RF3a4ic1H3i6xld8FAK4AAAABAOOA5wiA1MTFB5bL3TOneUALPzEkVMdMu_2uoXnDJzdSuXjsQ8ahg3_t8cy9HaW-Qq21vfZWCS8Gc_c6sgJjzHgsdijRS9mBZIQUjMu16w1fbtsE9bpSCj6uiEKTgqLOy6gYYk3oeOk6qWIGKXnJAE4mFKyEuUQXx3cQFUOksvlTgD8BxqHIQiOAGAY3CxllmCmJGQ93dwho4yPoWjphWm9b1ijSDxOAsrr4dGx_HV7Nw5h7-LxFPG1uScIqFbsOXIgzh-8IGU3QjgTi6gUArgAAAAEAsMdfpmupZ-45RDeSvKwM6ZSIief4lgDRjEXSCYY80BF-yigsPm331528f4HTwVNKOWc5FPh30IofgXkep8zLCuSkmQTCVMAgGfYmwj45DvXAf4slwI__NipNmq4AjVWlTVQ9ayIPCINpcou27QLBYheQDUpU7-paSSKmGqWv3dXmjSE-kjhFrNnFQoLuDmhgAM8xYP3MOgNc_FQIQRXsl_lQYHq6VWVTIoxXIL0cQoJTdQFWPE7OZDkQGlQofcNiRcrXFx0uGBJZpf5oBQCuAAAAAQDgXSPKQQFgW-E1kniREBkQXIZr9hJyfxiogcXVLg7UztmsivomI2XV638aynp2zHH3Cqzmb-83HBXLCAsPmKq0uk7imM5W1lBZv-fpizbgwkME4w0qJOdK9I97xQ9iNN8AQfY9TYBoA5IavCzK0QQiDLdMUb-q89UV3X7bGfoEZJabzQiT7MNtEjAQfI1Tu6MBMTDOx0GdvPZWP8_KuIRQPP0XqVCLU53JH2bZdGVsZ39SWNOcgDiNe8PPofNI40Hy14rclkbtvZ1gLHYFADcAAAEBAPgmcZgZbpX3cu8XPTT9gtjx9RaBleApRzxaK9T2qr0vDyBsCY2KTeD6tEvaOAzz1XflsxYY',

            'Block7 (last) repeated': 'v6xsVVBD4pOtHHfzLsKBVHscJ7Q4kv_KqOKH3X_Fx1IFAFEAAAABAAZsrNtMucZUIr2UFJF3Y9R2FtBAqbm_YLotMSzgyBAAABRnUeng3ADKX8ZIicklSvESgyOeUPCFnOoBhpY-g10PWujfV7mwWWJZdMylaext9jLzwDxOLnu6u4cxcgbt1Ga1Vn5F0qDCyO0Xp9W1mAUAMAAAAAEAQTScPYuFjasQGAKP6oqkR9d58Q0YgvW3zEg50a0en8vK2ShqzFWqL5E9A_mmkaAvhGj9rr43RZhZiInC6ccflFeTqERnpm0jqQL9ysQtBQBCAAAAAQCH0B81axAaykKtBBNhvA0of9kUOniwBgdkzLFYwPH_pz75AdARszabKfDmBWOZFAzy9dDJfiqIz2Nbfr4S59sVkfpg_FPiD6_QgqLXQtv7_SDDAHb5a3C-NLGvP4KhxAYFAGYAAAABAIVBoUjIij7b-5zUE6FMbuAaiegCEYXBcSuLeeKfCH5WHveQq6-8KA4U-IQ6IZ5Rz_ocEv1L5e9uqanzYvGkFMfbhjO3oNH5-C_CqfCIF_1OzrgztnYx2feFXB0DGiR7PBWkPKErkb7VBUkVLd8T-ZqVhNFQstJrXxEXdriJzUfeLrGV3wUArgAAAAEA44DnCIDUxMUHlsvdM6d5QAs_MSRUx0y7_a6hecMnN1K5eOxDxqGDf-3xzL0dpb5CrbW99lYJLwZz9zqyAmPMeCx2KNFL2YFkhBSMy7XrDV9u2wT1ulIKPq6IQpOCos7LqBhiTeh46TqpYgYpeckATiYUrIS5RBfHdxAVQ6Sy-VOAPwHGochCI4AYBjcLGWWYKYkZD3d3CGjjI-haOmFab1vWKNIPE4Cyuvh0bH8dXs3DmHv4vEU8bW5JwioVuw5ciDOH7wgZTdCOBOLqBQCuAAAAAQCwx1-ma6ln7jlEN5K8rAzplIiJ5_iWANGMRdIJhjzQEX7KKCw-bffXnbx_gdPBU0o5ZzkU-HfQih-BeR6nzMsK5KSZBMJUwCAZ9ibCPjkO9cB_iyXAj_82Kk2argCNVaVNVD1rIg8Ig2lyi7btAsFiF5ANSlTv6lpJIqYapa_d1eaNIT6SOEWs2cVCgu4OaGAAzzFg_cw6A1z8VAhBFeyX-VBgerpVZVMijFcgvRxCglN1AVY8Ts5kORAaVCh9w2JFytcXHS4YElml_mgFAK4AAAABAOBdI8pBAWBb4TWSeJEQGRBchmv2EnJ_GKiBxdUuDtTO2ayK-iYjZdXrfxrKenbMcfcKrOZv7zccFcsICw-YqrS6TuKYzlbWUFm_5-mLNuDCQwTjDSok50r0j3vFD2I03wBB9j1NgGgDkhq8LMrRBCIMt0xRv6rz1RXdftsZ-gRklpvNCJPsw20SMBB8jVO7owExMM7HQZ289lY_z8q4hFA8_RepUItTnckfZtl0ZWxnf1JY05yAOI17w8-h80jjQfLXityWRu29nWAsdgUANwAAAQEA-CZxmBlulfdy7xc9NP2C2PH1FoGV4ClHPFor1PaqvS8PIGwJjYpN4Pq0S9o4DPPVd-WzFhh0ZWxnf1JY05yAOI17w8-h80jjQfLXityWRu29nWAsdgUANwAAAQEA-CZxmBlulfdy7xc9NP2C2PH1FoGV4ClHPFor1PaqvS8PIGwJjYpN4Pq0S9o4DPPVd-WzFhg=',

            'Block7 (last) deleted': 'v6xsVVBD4pOtHHfzLsKBVHscJ7Q4kv_KqOKH3X_Fx1IFAFEAAAABAAZsrNtMucZUIr2UFJF3Y9R2FtBAqbm_YLotMSzgyBAAABRnUeng3ADKX8ZIicklSvESgyOeUPCFnOoBhpY-g10PWujfV7mwWWJZdMylaext9jLzwDxOLnu6u4cxcgbt1Ga1Vn5F0qDCyO0Xp9W1mAUAMAAAAAEAQTScPYuFjasQGAKP6oqkR9d58Q0YgvW3zEg50a0en8vK2ShqzFWqL5E9A_mmkaAvhGj9rr43RZhZiInC6ccflFeTqERnpm0jqQL9ysQtBQBCAAAAAQCH0B81axAaykKtBBNhvA0of9kUOniwBgdkzLFYwPH_pz75AdARszabKfDmBWOZFAzy9dDJfiqIz2Nbfr4S59sVkfpg_FPiD6_QgqLXQtv7_SDDAHb5a3C-NLGvP4KhxAYFAGYAAAABAIVBoUjIij7b-5zUE6FMbuAaiegCEYXBcSuLeeKfCH5WHveQq6-8KA4U-IQ6IZ5Rz_ocEv1L5e9uqanzYvGkFMfbhjO3oNH5-C_CqfCIF_1OzrgztnYx2feFXB0DGiR7PBWkPKErkb7VBUkVLd8T-ZqVhNFQstJrXxEXdriJzUfeLrGV3wUArgAAAAEA44DnCIDUxMUHlsvdM6d5QAs_MSRUx0y7_a6hecMnN1K5eOxDxqGDf-3xzL0dpb5CrbW99lYJLwZz9zqyAmPMeCx2KNFL2YFkhBSMy7XrDV9u2wT1ulIKPq6IQpOCos7LqBhiTeh46TqpYgYpeckATiYUrIS5RBfHdxAVQ6Sy-VOAPwHGochCI4AYBjcLGWWYKYkZD3d3CGjjI-haOmFab1vWKNIPE4Cyuvh0bH8dXs3DmHv4vEU8bW5JwioVuw5ciDOH7wgZTdCOBOLqBQCuAAAAAQCwx1-ma6ln7jlEN5K8rAzplIiJ5_iWANGMRdIJhjzQEX7KKCw-bffXnbx_gdPBU0o5ZzkU-HfQih-BeR6nzMsK5KSZBMJUwCAZ9ibCPjkO9cB_iyXAj_82Kk2argCNVaVNVD1rIg8Ig2lyi7btAsFiF5ANSlTv6lpJIqYapa_d1eaNIT6SOEWs2cVCgu4OaGAAzzFg_cw6A1z8VAhBFeyX-VBgerpVZVMijFcgvRxCglN1AVY8Ts5kORAaVCh9w2JFytcXHS4YElml_mgFAK4AAAABAOBdI8pBAWBb4TWSeJEQGRBchmv2EnJ_GKiBxdUuDtTO2ayK-iYjZdXrfxrKenbMcfcKrOZv7zccFcsICw-YqrS6TuKYzlbWUFm_5-mLNuDCQwTjDSok50r0j3vFD2I03wBB9j1NgGgDkhq8LMrRBCIMt0xRv6rz1RXdftsZ-gRklpvNCJPsw20SMBB8jVO7owExMM7HQZ289lY_z8q4hFA8_RepUItTnckfZtk=',

            'Block1 Block7 deleted': 'v6xsVVBD4pOtHHfzLsKBVHscJ7Q4kv_KqOKH3X_Fx1IFAFEAAAABAAZsrNtMucZUIr2UFJF3Y9R2FtBAqbm_YLotMSzgyBAAABRnUeng3ADKX8ZIicklSvESgyOeUPCFnOoBhpY-g10PWujfV7mwWWJZdMylaew=',
         }
      },
      {
         ver: 6,
         goodCt: "145SfB4dIqbmYy-bH1rnh1pyFN8T1EyEyFCMFtguBkAGAFIAAAABADHsHML87chQYK_58RxCa0lVLRW9ueVEO55SH6vgyBAAABRO3eqnNV_xNxBnsX-r7KYWgn5F-xMiA5lTNfDYw7tOoCgtF_qddOXjyHisEb0b8z5ZdoouvyB9aG3QlCbc9XTBfAN4yPYcxrzdASguAgYAMQAAAAEAl0vO23m4DaUuLlCchOsXoKnl4bYKmhmX_ydWm2p95AwKZcdXuNcSgBMD17fjfQxogLpTAVw46IYT6Yade9GaEZeK-H4_IWcRVVloHAjiBgBDAAAAAQCkAj9mmn0ml0CccOOHETPlyrQ0qPr2vtFzCrvt-SAx_VfWK3UP7bsmKruWrF9fXPaHjlhEl9b3BzLgWFRhEI1tccFm2H62Twhok-txX_Tzma2f-1wEacpdfUYuiGgYpgIGAGcAAAABAOjptoow8I9KMVohLYUE7yt4Bvt23UzOw_nrRXVseI-n_TJ1i3jBtcdWk1hfrvWlw-2PoJZyH2oFJi2vn0Ulo_TxtGOAxKV6bPz28qxg4AenSlhmenw8N6AuS-QkSe71LDKczPAYp90W6ZiO06uOk9Dgv3ftONRWM9yuN7Kt0IqnKR5FRwYArwAAAAEAcUDPBJ_iL9JmZB8vrg4cNOJQ0zniAhWDhetArzNGPK9jJ1XPpvt7eZUyCCIvMbMFJL9sCMMNyQ6GpQbu3Yb5ykCA7UjRKDyjZaHvMifXl1DtJX8D7tkilUD9CxFG5JDiZP5WSVbK9vufZZXYmO0Rb55-XDrEwAkFGv_Z7baL3CCvFBApV8pgJFP4Y6BgzoF3X1Twah0_lpB8amihm74KoQmIR-PzuCZwRYdIcbnSCPRcEQDEAJteYV1mNHZZ4RjAebx4UKfaNFzpS3bRBgCvAAAAAQBi_iVR4Q8bxXY2--aZBV6HpYFK8iHV2R5wynUcAjctCSonwJJkv0_LZ14vFpgDak70e6exgvIfAkLb_vpjfDN8B_xKWKcuBNLvg1XwVHwEkXu0OW_a2T6FJLwVN9yYMd7TrCEqjx-Ey77eGlvie66gfdsAfqsfM_bA_rmstmDdEWZN0oKZQ4dhEuuinf61NL6R2zuH_AOm-rqgSYuHnZSZrVkmFCvmWDPsthBVH_ndo_8jdaFw-0H6fTScHXdxi4ByWbFikOScO7Og4UsGAK8AAAABAKMxDRKY02yKwaHyj5hGCyjjzls4u_KJbhq_kyU1LapORWJ8PrLU7ngWKZVV7nDbLbiGr7618KJTO9QTypg-mpqZLxKshTQh1T9y7OcIi41phr-OgQtmfLNsTq-poL9KA8j4JKQOE7BbgKWuGuD2106SJueQ0j-OdQq8FmZF3wvI_GH3jKlxnc-TsZYNz297pBBEx1X87YWHlaEG6IYsuMxTZUmuOXrZ4EAXWa2fNQwontou1_P0uGJW-zOp_0B_66xoXQZzWxBZDYXMHwYAOAAAAQEAQRiF8kaVmi2xqbQV1__kKXlpRGQvNsAWpDpH20Q-1_GWz1vSBPm5Q3OEPzO4jYh7NNy3GqI",
         badCts: {
            'Block0 Block7 swap': 'nzUMKJ7aLtfz9LhiVvszqf9Af-usaF0Gc1sQWQ2FzB8GADgAAAEBAEEYhfJGlZotsam0Fdf_5Cl5aURkLzbAFqQ6R9tEPtfxls9b0gT5uUNzhD8zuI2IezTctxqiG_M-WXaKLr8gfWht0JQm3PV0wXwDeMj2HMa83QEoLgIGADEAAAABAJdLztt5uA2lLi5QnITrF6Cp5eG2CpoZl_8nVptqfeQMCmXHV7jXEoATA9e3430MaIC6UwFcOOiGE-mGnXvRmhGXivh-PyFnEVVZaBwI4gYAQwAAAAEApAI_Zpp9JpdAnHDjhxEz5cq0NKj69r7Rcwq77fkgMf1X1it1D-27Jiq7lqxfX1z2h45YRJfW9wcy4FhUYRCNbXHBZth-tk8IaJPrcV_085mtn_tcBGnKXX1GLohoGKYCBgBnAAAAAQDo6baKMPCPSjFaIS2FBO8reAb7dt1MzsP560V1bHiPp_0ydYt4wbXHVpNYX671pcPtj6CWch9qBSYtr59FJaP08bRjgMSlemz89vKsYOAHp0pYZnp8PDegLkvkJEnu9SwynMzwGKfdFumYjtOrjpPQ4L937TjUVjPcrjeyrdCKpykeRUcGAK8AAAABAHFAzwSf4i_SZmQfL64OHDTiUNM54gIVg4XrQK8zRjyvYydVz6b7e3mVMggiLzGzBSS_bAjDDckOhqUG7t2G-cpAgO1I0Sg8o2Wh7zIn15dQ7SV_A-7ZIpVA_QsRRuSQ4mT-VklWyvb7n2WV2JjtEW-eflw6xMAJBRr_2e22i9wgrxQQKVfKYCRT-GOgYM6Bd19U8GodP5aQfGpooZu-CqEJiEfj87gmcEWHSHG50gj0XBEAxACbXmFdZjR2WeEYwHm8eFCn2jRc6Ut20QYArwAAAAEAYv4lUeEPG8V2NvvmmQVeh6WBSvIh1dkecMp1HAI3LQkqJ8CSZL9Py2deLxaYA2pO9HunsYLyHwJC2_76Y3wzfAf8SlinLgTS74NV8FR8BJF7tDlv2tk-hSS8FTfcmDHe06whKo8fhMu-3hpb4nuuoH3bAH6rHzP2wP65rLZg3RFmTdKCmUOHYRLrop3-tTS-kds7h_wDpvq6oEmLh52Uma1ZJhQr5lgz7LYQVR_53aP_I3WhcPtB-n00nB13cYuAclmxYpDknDuzoOFLBgCvAAAAAQCjMQ0SmNNsisGh8o-YRgso485bOLvyiW4av5MlNS2qTkVifD6y1O54FimVVe5w2y24hq--tfCiUzvUE8qYPpqamS8SrIU0IdU_cuznCIuNaYa_joELZnyzbE6vqaC_SgPI-CSkDhOwW4Clrhrg9tdOkibnkNI_jnUKvBZmRd8LyPxh94ypcZ3Pk7GWDc9ve6QQRMdV_O2Fh5WhBuiGLLjMU2VJrjl62eBAF1mt145SfB4dIqbmYy-bH1rnh1pyFN8T1EyEyFCMFtguBkAGAFIAAAABADHsHML87chQYK_58RxCa0lVLRW9ueVEO55SH6vgyBAAABRO3eqnNV_xNxBnsX-r7KYWgn5F-xMiA5lTNfDYw7tOoCgtF_qddOXjyHisEb0',

            'Block1 Block7 swap': '145SfB4dIqbmYy-bH1rnh1pyFN8T1EyEyFCMFtguBkAGAFIAAAABADHsHML87chQYK_58RxCa0lVLRW9ueVEO55SH6vgyBAAABRO3eqnNV_xNxBnsX-r7KYWgn5F-xMiA5lTNfDYw7tOoCgtF_qddOXjyHisEb2fNQwontou1_P0uGJW-zOp_0B_66xoXQZzWxBZDYXMHwYAOAAAAQEAQRiF8kaVmi2xqbQV1__kKXlpRGQvNsAWpDpH20Q-1_GWz1vSBPm5Q3OEPzO4jYh7NNy3GqIMaIC6UwFcOOiGE-mGnXvRmhGXivh-PyFnEVVZaBwI4gYAQwAAAAEApAI_Zpp9JpdAnHDjhxEz5cq0NKj69r7Rcwq77fkgMf1X1it1D-27Jiq7lqxfX1z2h45YRJfW9wcy4FhUYRCNbXHBZth-tk8IaJPrcV_085mtn_tcBGnKXX1GLohoGKYCBgBnAAAAAQDo6baKMPCPSjFaIS2FBO8reAb7dt1MzsP560V1bHiPp_0ydYt4wbXHVpNYX671pcPtj6CWch9qBSYtr59FJaP08bRjgMSlemz89vKsYOAHp0pYZnp8PDegLkvkJEnu9SwynMzwGKfdFumYjtOrjpPQ4L937TjUVjPcrjeyrdCKpykeRUcGAK8AAAABAHFAzwSf4i_SZmQfL64OHDTiUNM54gIVg4XrQK8zRjyvYydVz6b7e3mVMggiLzGzBSS_bAjDDckOhqUG7t2G-cpAgO1I0Sg8o2Wh7zIn15dQ7SV_A-7ZIpVA_QsRRuSQ4mT-VklWyvb7n2WV2JjtEW-eflw6xMAJBRr_2e22i9wgrxQQKVfKYCRT-GOgYM6Bd19U8GodP5aQfGpooZu-CqEJiEfj87gmcEWHSHG50gj0XBEAxACbXmFdZjR2WeEYwHm8eFCn2jRc6Ut20QYArwAAAAEAYv4lUeEPG8V2NvvmmQVeh6WBSvIh1dkecMp1HAI3LQkqJ8CSZL9Py2deLxaYA2pO9HunsYLyHwJC2_76Y3wzfAf8SlinLgTS74NV8FR8BJF7tDlv2tk-hSS8FTfcmDHe06whKo8fhMu-3hpb4nuuoH3bAH6rHzP2wP65rLZg3RFmTdKCmUOHYRLrop3-tTS-kds7h_wDpvq6oEmLh52Uma1ZJhQr5lgz7LYQVR_53aP_I3WhcPtB-n00nB13cYuAclmxYpDknDuzoOFLBgCvAAAAAQCjMQ0SmNNsisGh8o-YRgso485bOLvyiW4av5MlNS2qTkVifD6y1O54FimVVe5w2y24hq--tfCiUzvUE8qYPpqamS8SrIU0IdU_cuznCIuNaYa_joELZnyzbE6vqaC_SgPI-CSkDhOwW4Clrhrg9tdOkibnkNI_jnUKvBZmRd8LyPxh94ypcZ3Pk7GWDc9ve6QQRMdV_O2Fh5WhBuiGLLjMU2VJrjl62eBAF1mtG_M-WXaKLr8gfWht0JQm3PV0wXwDeMj2HMa83QEoLgIGADEAAAABAJdLztt5uA2lLi5QnITrF6Cp5eG2CpoZl_8nVptqfeQMCmXHV7jXEoATA9e3430',

            'Block1 Block4 swap': '145SfB4dIqbmYy-bH1rnh1pyFN8T1EyEyFCMFtguBkAGAFIAAAABADHsHML87chQYK_58RxCa0lVLRW9ueVEO55SH6vgyBAAABRO3eqnNV_xNxBnsX-r7KYWgn5F-xMiA5lTNfDYw7tOoCgtF_qddOXjyHisEb0Yp90W6ZiO06uOk9Dgv3ftONRWM9yuN7Kt0IqnKR5FRwYArwAAAAEAcUDPBJ_iL9JmZB8vrg4cNOJQ0zniAhWDhetArzNGPK9jJ1XPpvt7eZUyCCIvMbMFJL9sCMMNyQ6GpQbu3Yb5ykCA7UjRKDyjZaHvMifXl1DtJX8D7tkilUD9CxFG5JDiZP5WSVbK9vufZZXYmO0Rb55-XDrEwAkFGv_Z7baL3CCvFBApV8pgJFP4Y6BgzoF3X1Twah0_lpB8amihm74KoQmIR-PzuCZwRYdIcQxogLpTAVw46IYT6Yade9GaEZeK-H4_IWcRVVloHAjiBgBDAAAAAQCkAj9mmn0ml0CccOOHETPlyrQ0qPr2vtFzCrvt-SAx_VfWK3UP7bsmKruWrF9fXPaHjlhEl9b3BzLgWFRhEI1tccFm2H62Twhok-txX_Tzma2f-1wEacpdfUYuiGgYpgIGAGcAAAABAOjptoow8I9KMVohLYUE7yt4Bvt23UzOw_nrRXVseI-n_TJ1i3jBtcdWk1hfrvWlw-2PoJZyH2oFJi2vn0Ulo_TxtGOAxKV6bPz28qxg4AenSlhmenw8N6AuS-QkSe71LDKczPAb8z5ZdoouvyB9aG3QlCbc9XTBfAN4yPYcxrzdASguAgYAMQAAAAEAl0vO23m4DaUuLlCchOsXoKnl4bYKmhmX_ydWm2p95AwKZcdXuNcSgBMD17fjfbnSCPRcEQDEAJteYV1mNHZZ4RjAebx4UKfaNFzpS3bRBgCvAAAAAQBi_iVR4Q8bxXY2--aZBV6HpYFK8iHV2R5wynUcAjctCSonwJJkv0_LZ14vFpgDak70e6exgvIfAkLb_vpjfDN8B_xKWKcuBNLvg1XwVHwEkXu0OW_a2T6FJLwVN9yYMd7TrCEqjx-Ey77eGlvie66gfdsAfqsfM_bA_rmstmDdEWZN0oKZQ4dhEuuinf61NL6R2zuH_AOm-rqgSYuHnZSZrVkmFCvmWDPsthBVH_ndo_8jdaFw-0H6fTScHXdxi4ByWbFikOScO7Og4UsGAK8AAAABAKMxDRKY02yKwaHyj5hGCyjjzls4u_KJbhq_kyU1LapORWJ8PrLU7ngWKZVV7nDbLbiGr7618KJTO9QTypg-mpqZLxKshTQh1T9y7OcIi41phr-OgQtmfLNsTq-poL9KA8j4JKQOE7BbgKWuGuD2106SJueQ0j-OdQq8FmZF3wvI_GH3jKlxnc-TsZYNz297pBBEx1X87YWHlaEG6IYsuMxTZUmuOXrZ4EAXWa2fNQwontou1_P0uGJW-zOp_0B_66xoXQZzWxBZDYXMHwYAOAAAAQEAQRiF8kaVmi2xqbQV1__kKXlpRGQvNsAWpDpH20Q-1_GWz1vSBPm5Q3OEPzO4jYh7NNy3GqI',

            'Block0 repeated': '145SfB4dIqbmYy-bH1rnh1pyFN8T1EyEyFCMFtguBkAGAFIAAAABADHsHML87chQYK_58RxCa0lVLRW9ueVEO55SH6vgyBAAABRO3eqnNV_xNxBnsX-r7KYWgn5F-xMiA5lTNfDYw7tOoCgtF_qddOXjyHisEb3XjlJ8Hh0ipuZjL5sfWueHWnIU3xPUTITIUIwW2C4GQAYAUgAAAAEAMewcwvztyFBgr_nxHEJrSVUtFb255UQ7nlIfq-DIEAAAFE7d6qc1X_E3EGexf6vsphaCfkX7EyIDmVM18NjDu06gKC0X-p105ePIeKwRvRvzPll2ii6_IH1obdCUJtz1dMF8A3jI9hzGvN0BKC4CBgAxAAAAAQCXS87bebgNpS4uUJyE6xegqeXhtgqaGZf_J1aban3kDAplx1e41xKAEwPXt-N9DGiAulMBXDjohhPphp170ZoRl4r4fj8hZxFVWWgcCOIGAEMAAAABAKQCP2aafSaXQJxw44cRM-XKtDSo-va-0XMKu-35IDH9V9YrdQ_tuyYqu5asX19c9oeOWESX1vcHMuBYVGEQjW1xwWbYfrZPCGiT63Ff9POZrZ_7XARpyl19Ri6IaBimAgYAZwAAAAEA6Om2ijDwj0oxWiEthQTvK3gG-3bdTM7D-etFdWx4j6f9MnWLeMG1x1aTWF-u9aXD7Y-glnIfagUmLa-fRSWj9PG0Y4DEpXps_PbyrGDgB6dKWGZ6fDw3oC5L5CRJ7vUsMpzM8Bin3RbpmI7Tq46T0OC_d-041FYz3K43sq3QiqcpHkVHBgCvAAAAAQBxQM8En-Iv0mZkHy-uDhw04lDTOeICFYOF60CvM0Y8r2MnVc-m-3t5lTIIIi8xswUkv2wIww3JDoalBu7dhvnKQIDtSNEoPKNloe8yJ9eXUO0lfwPu2SKVQP0LEUbkkOJk_lZJVsr2-59lldiY7RFvnn5cOsTACQUa_9nttovcIK8UEClXymAkU_hjoGDOgXdfVPBqHT-WkHxqaKGbvgqhCYhH4_O4JnBFh0hxudII9FwRAMQAm15hXWY0dlnhGMB5vHhQp9o0XOlLdtEGAK8AAAABAGL-JVHhDxvFdjb75pkFXoelgUryIdXZHnDKdRwCNy0JKifAkmS_T8tnXi8WmANqTvR7p7GC8h8CQtv--mN8M3wH_EpYpy4E0u-DVfBUfASRe7Q5b9rZPoUkvBU33Jgx3tOsISqPH4TLvt4aW-J7rqB92wB-qx8z9sD-uay2YN0RZk3SgplDh2ES66Kd_rU0vpHbO4f8A6b6uqBJi4edlJmtWSYUK-ZYM-y2EFUf-d2j_yN1oXD7Qfp9NJwdd3GLgHJZsWKQ5Jw7s6DhSwYArwAAAAEAozENEpjTbIrBofKPmEYLKOPOWzi78oluGr-TJTUtqk5FYnw-stTueBYplVXucNstuIavvrXwolM71BPKmD6ampkvEqyFNCHVP3Ls5wiLjWmGv46BC2Z8s2xOr6mgv0oDyPgkpA4TsFuApa4a4PbXTpIm55DSP451CrwWZkXfC8j8YfeMqXGdz5Oxlg3Pb3ukEETHVfzthYeVoQbohiy4zFNlSa45etngQBdZrZ81DCie2i7X8_S4Ylb7M6n_QH_rrGhdBnNbEFkNhcwfBgA4AAABAQBBGIXyRpWaLbGptBXX_-QpeWlEZC82wBakOkfbRD7X8ZbPW9IE-blDc4Q_M7iNiHs03Lcaog',

            'Block0 deleted': 'G_M-WXaKLr8gfWht0JQm3PV0wXwDeMj2HMa83QEoLgIGADEAAAABAJdLztt5uA2lLi5QnITrF6Cp5eG2CpoZl_8nVptqfeQMCmXHV7jXEoATA9e3430MaIC6UwFcOOiGE-mGnXvRmhGXivh-PyFnEVVZaBwI4gYAQwAAAAEApAI_Zpp9JpdAnHDjhxEz5cq0NKj69r7Rcwq77fkgMf1X1it1D-27Jiq7lqxfX1z2h45YRJfW9wcy4FhUYRCNbXHBZth-tk8IaJPrcV_085mtn_tcBGnKXX1GLohoGKYCBgBnAAAAAQDo6baKMPCPSjFaIS2FBO8reAb7dt1MzsP560V1bHiPp_0ydYt4wbXHVpNYX671pcPtj6CWch9qBSYtr59FJaP08bRjgMSlemz89vKsYOAHp0pYZnp8PDegLkvkJEnu9SwynMzwGKfdFumYjtOrjpPQ4L937TjUVjPcrjeyrdCKpykeRUcGAK8AAAABAHFAzwSf4i_SZmQfL64OHDTiUNM54gIVg4XrQK8zRjyvYydVz6b7e3mVMggiLzGzBSS_bAjDDckOhqUG7t2G-cpAgO1I0Sg8o2Wh7zIn15dQ7SV_A-7ZIpVA_QsRRuSQ4mT-VklWyvb7n2WV2JjtEW-eflw6xMAJBRr_2e22i9wgrxQQKVfKYCRT-GOgYM6Bd19U8GodP5aQfGpooZu-CqEJiEfj87gmcEWHSHG50gj0XBEAxACbXmFdZjR2WeEYwHm8eFCn2jRc6Ut20QYArwAAAAEAYv4lUeEPG8V2NvvmmQVeh6WBSvIh1dkecMp1HAI3LQkqJ8CSZL9Py2deLxaYA2pO9HunsYLyHwJC2_76Y3wzfAf8SlinLgTS74NV8FR8BJF7tDlv2tk-hSS8FTfcmDHe06whKo8fhMu-3hpb4nuuoH3bAH6rHzP2wP65rLZg3RFmTdKCmUOHYRLrop3-tTS-kds7h_wDpvq6oEmLh52Uma1ZJhQr5lgz7LYQVR_53aP_I3WhcPtB-n00nB13cYuAclmxYpDknDuzoOFLBgCvAAAAAQCjMQ0SmNNsisGh8o-YRgso485bOLvyiW4av5MlNS2qTkVifD6y1O54FimVVe5w2y24hq--tfCiUzvUE8qYPpqamS8SrIU0IdU_cuznCIuNaYa_joELZnyzbE6vqaC_SgPI-CSkDhOwW4Clrhrg9tdOkibnkNI_jnUKvBZmRd8LyPxh94ypcZ3Pk7GWDc9ve6QQRMdV_O2Fh5WhBuiGLLjMU2VJrjl62eBAF1mtnzUMKJ7aLtfz9LhiVvszqf9Af-usaF0Gc1sQWQ2FzB8GADgAAAEBAEEYhfJGlZotsam0Fdf_5Cl5aURkLzbAFqQ6R9tEPtfxls9b0gT5uUNzhD8zuI2IezTctxqi',

            'Block1 repeated': '145SfB4dIqbmYy-bH1rnh1pyFN8T1EyEyFCMFtguBkAGAFIAAAABADHsHML87chQYK_58RxCa0lVLRW9ueVEO55SH6vgyBAAABRO3eqnNV_xNxBnsX-r7KYWgn5F-xMiA5lTNfDYw7tOoCgtF_qddOXjyHisEb0b8z5ZdoouvyB9aG3QlCbc9XTBfAN4yPYcxrzdASguAgYAMQAAAAEAl0vO23m4DaUuLlCchOsXoKnl4bYKmhmX_ydWm2p95AwKZcdXuNcSgBMD17fjfRvzPll2ii6_IH1obdCUJtz1dMF8A3jI9hzGvN0BKC4CBgAxAAAAAQCXS87bebgNpS4uUJyE6xegqeXhtgqaGZf_J1aban3kDAplx1e41xKAEwPXt-N9DGiAulMBXDjohhPphp170ZoRl4r4fj8hZxFVWWgcCOIGAEMAAAABAKQCP2aafSaXQJxw44cRM-XKtDSo-va-0XMKu-35IDH9V9YrdQ_tuyYqu5asX19c9oeOWESX1vcHMuBYVGEQjW1xwWbYfrZPCGiT63Ff9POZrZ_7XARpyl19Ri6IaBimAgYAZwAAAAEA6Om2ijDwj0oxWiEthQTvK3gG-3bdTM7D-etFdWx4j6f9MnWLeMG1x1aTWF-u9aXD7Y-glnIfagUmLa-fRSWj9PG0Y4DEpXps_PbyrGDgB6dKWGZ6fDw3oC5L5CRJ7vUsMpzM8Bin3RbpmI7Tq46T0OC_d-041FYz3K43sq3QiqcpHkVHBgCvAAAAAQBxQM8En-Iv0mZkHy-uDhw04lDTOeICFYOF60CvM0Y8r2MnVc-m-3t5lTIIIi8xswUkv2wIww3JDoalBu7dhvnKQIDtSNEoPKNloe8yJ9eXUO0lfwPu2SKVQP0LEUbkkOJk_lZJVsr2-59lldiY7RFvnn5cOsTACQUa_9nttovcIK8UEClXymAkU_hjoGDOgXdfVPBqHT-WkHxqaKGbvgqhCYhH4_O4JnBFh0hxudII9FwRAMQAm15hXWY0dlnhGMB5vHhQp9o0XOlLdtEGAK8AAAABAGL-JVHhDxvFdjb75pkFXoelgUryIdXZHnDKdRwCNy0JKifAkmS_T8tnXi8WmANqTvR7p7GC8h8CQtv--mN8M3wH_EpYpy4E0u-DVfBUfASRe7Q5b9rZPoUkvBU33Jgx3tOsISqPH4TLvt4aW-J7rqB92wB-qx8z9sD-uay2YN0RZk3SgplDh2ES66Kd_rU0vpHbO4f8A6b6uqBJi4edlJmtWSYUK-ZYM-y2EFUf-d2j_yN1oXD7Qfp9NJwdd3GLgHJZsWKQ5Jw7s6DhSwYArwAAAAEAozENEpjTbIrBofKPmEYLKOPOWzi78oluGr-TJTUtqk5FYnw-stTueBYplVXucNstuIavvrXwolM71BPKmD6ampkvEqyFNCHVP3Ls5wiLjWmGv46BC2Z8s2xOr6mgv0oDyPgkpA4TsFuApa4a4PbXTpIm55DSP451CrwWZkXfC8j8YfeMqXGdz5Oxlg3Pb3ukEETHVfzthYeVoQbohiy4zFNlSa45etngQBdZrZ81DCie2i7X8_S4Ylb7M6n_QH_rrGhdBnNbEFkNhcwfBgA4AAABAQBBGIXyRpWaLbGptBXX_-QpeWlEZC82wBakOkfbRD7X8ZbPW9IE-blDc4Q_M7iNiHs03Lcaog',

            "Block1 deleted": '145SfB4dIqbmYy-bH1rnh1pyFN8T1EyEyFCMFtguBkAGAFIAAAABADHsHML87chQYK_58RxCa0lVLRW9ueVEO55SH6vgyBAAABRO3eqnNV_xNxBnsX-r7KYWgn5F-xMiA5lTNfDYw7tOoCgtF_qddOXjyHisEb0MaIC6UwFcOOiGE-mGnXvRmhGXivh-PyFnEVVZaBwI4gYAQwAAAAEApAI_Zpp9JpdAnHDjhxEz5cq0NKj69r7Rcwq77fkgMf1X1it1D-27Jiq7lqxfX1z2h45YRJfW9wcy4FhUYRCNbXHBZth-tk8IaJPrcV_085mtn_tcBGnKXX1GLohoGKYCBgBnAAAAAQDo6baKMPCPSjFaIS2FBO8reAb7dt1MzsP560V1bHiPp_0ydYt4wbXHVpNYX671pcPtj6CWch9qBSYtr59FJaP08bRjgMSlemz89vKsYOAHp0pYZnp8PDegLkvkJEnu9SwynMzwGKfdFumYjtOrjpPQ4L937TjUVjPcrjeyrdCKpykeRUcGAK8AAAABAHFAzwSf4i_SZmQfL64OHDTiUNM54gIVg4XrQK8zRjyvYydVz6b7e3mVMggiLzGzBSS_bAjDDckOhqUG7t2G-cpAgO1I0Sg8o2Wh7zIn15dQ7SV_A-7ZIpVA_QsRRuSQ4mT-VklWyvb7n2WV2JjtEW-eflw6xMAJBRr_2e22i9wgrxQQKVfKYCRT-GOgYM6Bd19U8GodP5aQfGpooZu-CqEJiEfj87gmcEWHSHG50gj0XBEAxACbXmFdZjR2WeEYwHm8eFCn2jRc6Ut20QYArwAAAAEAYv4lUeEPG8V2NvvmmQVeh6WBSvIh1dkecMp1HAI3LQkqJ8CSZL9Py2deLxaYA2pO9HunsYLyHwJC2_76Y3wzfAf8SlinLgTS74NV8FR8BJF7tDlv2tk-hSS8FTfcmDHe06whKo8fhMu-3hpb4nuuoH3bAH6rHzP2wP65rLZg3RFmTdKCmUOHYRLrop3-tTS-kds7h_wDpvq6oEmLh52Uma1ZJhQr5lgz7LYQVR_53aP_I3WhcPtB-n00nB13cYuAclmxYpDknDuzoOFLBgCvAAAAAQCjMQ0SmNNsisGh8o-YRgso485bOLvyiW4av5MlNS2qTkVifD6y1O54FimVVe5w2y24hq--tfCiUzvUE8qYPpqamS8SrIU0IdU_cuznCIuNaYa_joELZnyzbE6vqaC_SgPI-CSkDhOwW4Clrhrg9tdOkibnkNI_jnUKvBZmRd8LyPxh94ypcZ3Pk7GWDc9ve6QQRMdV_O2Fh5WhBuiGLLjMU2VJrjl62eBAF1mtnzUMKJ7aLtfz9LhiVvszqf9Af-usaF0Gc1sQWQ2FzB8GADgAAAEBAEEYhfJGlZotsam0Fdf_5Cl5aURkLzbAFqQ6R9tEPtfxls9b0gT5uUNzhD8zuI2IezTctxqi',

            'Block2 repeated': '145SfB4dIqbmYy-bH1rnh1pyFN8T1EyEyFCMFtguBkAGAFIAAAABADHsHML87chQYK_58RxCa0lVLRW9ueVEO55SH6vgyBAAABRO3eqnNV_xNxBnsX-r7KYWgn5F-xMiA5lTNfDYw7tOoCgtF_qddOXjyHisEb0b8z5ZdoouvyB9aG3QlCbc9XTBfAN4yPYcxrzdASguAgYAMQAAAAEAl0vO23m4DaUuLlCchOsXoKnl4bYKmhmX_ydWm2p95AwKZcdXuNcSgBMD17fjfQxogLpTAVw46IYT6Yade9GaEZeK-H4_IWcRVVloHAjiBgBDAAAAAQCkAj9mmn0ml0CccOOHETPlyrQ0qPr2vtFzCrvt-SAx_VfWK3UP7bsmKruWrF9fXPaHjlhEl9b3BzLgWFRhEI1tDGiAulMBXDjohhPphp170ZoRl4r4fj8hZxFVWWgcCOIGAEMAAAABAKQCP2aafSaXQJxw44cRM-XKtDSo-va-0XMKu-35IDH9V9YrdQ_tuyYqu5asX19c9oeOWESX1vcHMuBYVGEQjW1xwWbYfrZPCGiT63Ff9POZrZ_7XARpyl19Ri6IaBimAgYAZwAAAAEA6Om2ijDwj0oxWiEthQTvK3gG-3bdTM7D-etFdWx4j6f9MnWLeMG1x1aTWF-u9aXD7Y-glnIfagUmLa-fRSWj9PG0Y4DEpXps_PbyrGDgB6dKWGZ6fDw3oC5L5CRJ7vUsMpzM8Bin3RbpmI7Tq46T0OC_d-041FYz3K43sq3QiqcpHkVHBgCvAAAAAQBxQM8En-Iv0mZkHy-uDhw04lDTOeICFYOF60CvM0Y8r2MnVc-m-3t5lTIIIi8xswUkv2wIww3JDoalBu7dhvnKQIDtSNEoPKNloe8yJ9eXUO0lfwPu2SKVQP0LEUbkkOJk_lZJVsr2-59lldiY7RFvnn5cOsTACQUa_9nttovcIK8UEClXymAkU_hjoGDOgXdfVPBqHT-WkHxqaKGbvgqhCYhH4_O4JnBFh0hxudII9FwRAMQAm15hXWY0dlnhGMB5vHhQp9o0XOlLdtEGAK8AAAABAGL-JVHhDxvFdjb75pkFXoelgUryIdXZHnDKdRwCNy0JKifAkmS_T8tnXi8WmANqTvR7p7GC8h8CQtv--mN8M3wH_EpYpy4E0u-DVfBUfASRe7Q5b9rZPoUkvBU33Jgx3tOsISqPH4TLvt4aW-J7rqB92wB-qx8z9sD-uay2YN0RZk3SgplDh2ES66Kd_rU0vpHbO4f8A6b6uqBJi4edlJmtWSYUK-ZYM-y2EFUf-d2j_yN1oXD7Qfp9NJwdd3GLgHJZsWKQ5Jw7s6DhSwYArwAAAAEAozENEpjTbIrBofKPmEYLKOPOWzi78oluGr-TJTUtqk5FYnw-stTueBYplVXucNstuIavvrXwolM71BPKmD6ampkvEqyFNCHVP3Ls5wiLjWmGv46BC2Z8s2xOr6mgv0oDyPgkpA4TsFuApa4a4PbXTpIm55DSP451CrwWZkXfC8j8YfeMqXGdz5Oxlg3Pb3ukEETHVfzthYeVoQbohiy4zFNlSa45etngQBdZrZ81DCie2i7X8_S4Ylb7M6n_QH_rrGhdBnNbEFkNhcwfBgA4AAABAQBBGIXyRpWaLbGptBXX_-QpeWlEZC82wBakOkfbRD7X8ZbPW9IE-blDc4Q_M7iNiHs03Lcaog',

            'Block2 deleted': '145SfB4dIqbmYy-bH1rnh1pyFN8T1EyEyFCMFtguBkAGAFIAAAABADHsHML87chQYK_58RxCa0lVLRW9ueVEO55SH6vgyBAAABRO3eqnNV_xNxBnsX-r7KYWgn5F-xMiA5lTNfDYw7tOoCgtF_qddOXjyHisEb0b8z5ZdoouvyB9aG3QlCbc9XTBfAN4yPYcxrzdASguAgYAMQAAAAEAl0vO23m4DaUuLlCchOsXoKnl4bYKmhmX_ydWm2p95AwKZcdXuNcSgBMD17fjfXHBZth-tk8IaJPrcV_085mtn_tcBGnKXX1GLohoGKYCBgBnAAAAAQDo6baKMPCPSjFaIS2FBO8reAb7dt1MzsP560V1bHiPp_0ydYt4wbXHVpNYX671pcPtj6CWch9qBSYtr59FJaP08bRjgMSlemz89vKsYOAHp0pYZnp8PDegLkvkJEnu9SwynMzwGKfdFumYjtOrjpPQ4L937TjUVjPcrjeyrdCKpykeRUcGAK8AAAABAHFAzwSf4i_SZmQfL64OHDTiUNM54gIVg4XrQK8zRjyvYydVz6b7e3mVMggiLzGzBSS_bAjDDckOhqUG7t2G-cpAgO1I0Sg8o2Wh7zIn15dQ7SV_A-7ZIpVA_QsRRuSQ4mT-VklWyvb7n2WV2JjtEW-eflw6xMAJBRr_2e22i9wgrxQQKVfKYCRT-GOgYM6Bd19U8GodP5aQfGpooZu-CqEJiEfj87gmcEWHSHG50gj0XBEAxACbXmFdZjR2WeEYwHm8eFCn2jRc6Ut20QYArwAAAAEAYv4lUeEPG8V2NvvmmQVeh6WBSvIh1dkecMp1HAI3LQkqJ8CSZL9Py2deLxaYA2pO9HunsYLyHwJC2_76Y3wzfAf8SlinLgTS74NV8FR8BJF7tDlv2tk-hSS8FTfcmDHe06whKo8fhMu-3hpb4nuuoH3bAH6rHzP2wP65rLZg3RFmTdKCmUOHYRLrop3-tTS-kds7h_wDpvq6oEmLh52Uma1ZJhQr5lgz7LYQVR_53aP_I3WhcPtB-n00nB13cYuAclmxYpDknDuzoOFLBgCvAAAAAQCjMQ0SmNNsisGh8o-YRgso485bOLvyiW4av5MlNS2qTkVifD6y1O54FimVVe5w2y24hq--tfCiUzvUE8qYPpqamS8SrIU0IdU_cuznCIuNaYa_joELZnyzbE6vqaC_SgPI-CSkDhOwW4Clrhrg9tdOkibnkNI_jnUKvBZmRd8LyPxh94ypcZ3Pk7GWDc9ve6QQRMdV_O2Fh5WhBuiGLLjMU2VJrjl62eBAF1mtnzUMKJ7aLtfz9LhiVvszqf9Af-usaF0Gc1sQWQ2FzB8GADgAAAEBAEEYhfJGlZotsam0Fdf_5Cl5aURkLzbAFqQ6R9tEPtfxls9b0gT5uUNzhD8zuI2IezTctxqi',

            'Block7 (last) repeated': '145SfB4dIqbmYy-bH1rnh1pyFN8T1EyEyFCMFtguBkAGAFIAAAABADHsHML87chQYK_58RxCa0lVLRW9ueVEO55SH6vgyBAAABRO3eqnNV_xNxBnsX-r7KYWgn5F-xMiA5lTNfDYw7tOoCgtF_qddOXjyHisEb0b8z5ZdoouvyB9aG3QlCbc9XTBfAN4yPYcxrzdASguAgYAMQAAAAEAl0vO23m4DaUuLlCchOsXoKnl4bYKmhmX_ydWm2p95AwKZcdXuNcSgBMD17fjfQxogLpTAVw46IYT6Yade9GaEZeK-H4_IWcRVVloHAjiBgBDAAAAAQCkAj9mmn0ml0CccOOHETPlyrQ0qPr2vtFzCrvt-SAx_VfWK3UP7bsmKruWrF9fXPaHjlhEl9b3BzLgWFRhEI1tccFm2H62Twhok-txX_Tzma2f-1wEacpdfUYuiGgYpgIGAGcAAAABAOjptoow8I9KMVohLYUE7yt4Bvt23UzOw_nrRXVseI-n_TJ1i3jBtcdWk1hfrvWlw-2PoJZyH2oFJi2vn0Ulo_TxtGOAxKV6bPz28qxg4AenSlhmenw8N6AuS-QkSe71LDKczPAYp90W6ZiO06uOk9Dgv3ftONRWM9yuN7Kt0IqnKR5FRwYArwAAAAEAcUDPBJ_iL9JmZB8vrg4cNOJQ0zniAhWDhetArzNGPK9jJ1XPpvt7eZUyCCIvMbMFJL9sCMMNyQ6GpQbu3Yb5ykCA7UjRKDyjZaHvMifXl1DtJX8D7tkilUD9CxFG5JDiZP5WSVbK9vufZZXYmO0Rb55-XDrEwAkFGv_Z7baL3CCvFBApV8pgJFP4Y6BgzoF3X1Twah0_lpB8amihm74KoQmIR-PzuCZwRYdIcbnSCPRcEQDEAJteYV1mNHZZ4RjAebx4UKfaNFzpS3bRBgCvAAAAAQBi_iVR4Q8bxXY2--aZBV6HpYFK8iHV2R5wynUcAjctCSonwJJkv0_LZ14vFpgDak70e6exgvIfAkLb_vpjfDN8B_xKWKcuBNLvg1XwVHwEkXu0OW_a2T6FJLwVN9yYMd7TrCEqjx-Ey77eGlvie66gfdsAfqsfM_bA_rmstmDdEWZN0oKZQ4dhEuuinf61NL6R2zuH_AOm-rqgSYuHnZSZrVkmFCvmWDPsthBVH_ndo_8jdaFw-0H6fTScHXdxi4ByWbFikOScO7Og4UsGAK8AAAABAKMxDRKY02yKwaHyj5hGCyjjzls4u_KJbhq_kyU1LapORWJ8PrLU7ngWKZVV7nDbLbiGr7618KJTO9QTypg-mpqZLxKshTQh1T9y7OcIi41phr-OgQtmfLNsTq-poL9KA8j4JKQOE7BbgKWuGuD2106SJueQ0j-OdQq8FmZF3wvI_GH3jKlxnc-TsZYNz297pBBEx1X87YWHlaEG6IYsuMxTZUmuOXrZ4EAXWa2fNQwontou1_P0uGJW-zOp_0B_66xoXQZzWxBZDYXMHwYAOAAAAQEAQRiF8kaVmi2xqbQV1__kKXlpRGQvNsAWpDpH20Q-1_GWz1vSBPm5Q3OEPzO4jYh7NNy3GqKfNQwontou1_P0uGJW-zOp_0B_66xoXQZzWxBZDYXMHwYAOAAAAQEAQRiF8kaVmi2xqbQV1__kKXlpRGQvNsAWpDpH20Q-1_GWz1vSBPm5Q3OEPzO4jYh7NNy3GqI',

            'Block7 (last) deleted': '145SfB4dIqbmYy-bH1rnh1pyFN8T1EyEyFCMFtguBkAGAFIAAAABADHsHML87chQYK_58RxCa0lVLRW9ueVEO55SH6vgyBAAABRO3eqnNV_xNxBnsX-r7KYWgn5F-xMiA5lTNfDYw7tOoCgtF_qddOXjyHisEb0b8z5ZdoouvyB9aG3QlCbc9XTBfAN4yPYcxrzdASguAgYAMQAAAAEAl0vO23m4DaUuLlCchOsXoKnl4bYKmhmX_ydWm2p95AwKZcdXuNcSgBMD17fjfQxogLpTAVw46IYT6Yade9GaEZeK-H4_IWcRVVloHAjiBgBDAAAAAQCkAj9mmn0ml0CccOOHETPlyrQ0qPr2vtFzCrvt-SAx_VfWK3UP7bsmKruWrF9fXPaHjlhEl9b3BzLgWFRhEI1tccFm2H62Twhok-txX_Tzma2f-1wEacpdfUYuiGgYpgIGAGcAAAABAOjptoow8I9KMVohLYUE7yt4Bvt23UzOw_nrRXVseI-n_TJ1i3jBtcdWk1hfrvWlw-2PoJZyH2oFJi2vn0Ulo_TxtGOAxKV6bPz28qxg4AenSlhmenw8N6AuS-QkSe71LDKczPAYp90W6ZiO06uOk9Dgv3ftONRWM9yuN7Kt0IqnKR5FRwYArwAAAAEAcUDPBJ_iL9JmZB8vrg4cNOJQ0zniAhWDhetArzNGPK9jJ1XPpvt7eZUyCCIvMbMFJL9sCMMNyQ6GpQbu3Yb5ykCA7UjRKDyjZaHvMifXl1DtJX8D7tkilUD9CxFG5JDiZP5WSVbK9vufZZXYmO0Rb55-XDrEwAkFGv_Z7baL3CCvFBApV8pgJFP4Y6BgzoF3X1Twah0_lpB8amihm74KoQmIR-PzuCZwRYdIcbnSCPRcEQDEAJteYV1mNHZZ4RjAebx4UKfaNFzpS3bRBgCvAAAAAQBi_iVR4Q8bxXY2--aZBV6HpYFK8iHV2R5wynUcAjctCSonwJJkv0_LZ14vFpgDak70e6exgvIfAkLb_vpjfDN8B_xKWKcuBNLvg1XwVHwEkXu0OW_a2T6FJLwVN9yYMd7TrCEqjx-Ey77eGlvie66gfdsAfqsfM_bA_rmstmDdEWZN0oKZQ4dhEuuinf61NL6R2zuH_AOm-rqgSYuHnZSZrVkmFCvmWDPsthBVH_ndo_8jdaFw-0H6fTScHXdxi4ByWbFikOScO7Og4UsGAK8AAAABAKMxDRKY02yKwaHyj5hGCyjjzls4u_KJbhq_kyU1LapORWJ8PrLU7ngWKZVV7nDbLbiGr7618KJTO9QTypg-mpqZLxKshTQh1T9y7OcIi41phr-OgQtmfLNsTq-poL9KA8j4JKQOE7BbgKWuGuD2106SJueQ0j-OdQq8FmZF3wvI_GH3jKlxnc-TsZYNz297pBBEx1X87YWHlaEG6IYsuMxTZUmuOXrZ4EAXWa0',

            'Block1 Block7 deleted': '145SfB4dIqbmYy-bH1rnh1pyFN8T1EyEyFCMFtguBkAGAFIAAAABADHsHML87chQYK_58RxCa0lVLRW9ueVEO55SH6vgyBAAABRO3eqnNV_xNxBnsX-r7KYWgn5F-xMiA5lTNfDYw7tOoCgtF_qddOXjyHisEb0MaIC6UwFcOOiGE-mGnXvRmhGXivh-PyFnEVVZaBwI4gYAQwAAAAEApAI_Zpp9JpdAnHDjhxEz5cq0NKj69r7Rcwq77fkgMf1X1it1D-27Jiq7lqxfX1z2h45YRJfW9wcy4FhUYRCNbXHBZth-tk8IaJPrcV_085mtn_tcBGnKXX1GLohoGKYCBgBnAAAAAQDo6baKMPCPSjFaIS2FBO8reAb7dt1MzsP560V1bHiPp_0ydYt4wbXHVpNYX671pcPtj6CWch9qBSYtr59FJaP08bRjgMSlemz89vKsYOAHp0pYZnp8PDegLkvkJEnu9SwynMzwGKfdFumYjtOrjpPQ4L937TjUVjPcrjeyrdCKpykeRUcGAK8AAAABAHFAzwSf4i_SZmQfL64OHDTiUNM54gIVg4XrQK8zRjyvYydVz6b7e3mVMggiLzGzBSS_bAjDDckOhqUG7t2G-cpAgO1I0Sg8o2Wh7zIn15dQ7SV_A-7ZIpVA_QsRRuSQ4mT-VklWyvb7n2WV2JjtEW-eflw6xMAJBRr_2e22i9wgrxQQKVfKYCRT-GOgYM6Bd19U8GodP5aQfGpooZu-CqEJiEfj87gmcEWHSHG50gj0XBEAxACbXmFdZjR2WeEYwHm8eFCn2jRc6Ut20QYArwAAAAEAYv4lUeEPG8V2NvvmmQVeh6WBSvIh1dkecMp1HAI3LQkqJ8CSZL9Py2deLxaYA2pO9HunsYLyHwJC2_76Y3wzfAf8SlinLgTS74NV8FR8BJF7tDlv2tk-hSS8FTfcmDHe06whKo8fhMu-3hpb4nuuoH3bAH6rHzP2wP65rLZg3RFmTdKCmUOHYRLrop3-tTS-kds7h_wDpvq6oEmLh52Uma1ZJhQr5lgz7LYQVR_53aP_I3WhcPtB-n00nB13cYuAclmxYpDknDuzoOFLBgCvAAAAAQCjMQ0SmNNsisGh8o-YRgso485bOLvyiW4av5MlNS2qTkVifD6y1O54FimVVe5w2y24hq--tfCiUzvUE8qYPpqamS8SrIU0IdU_cuznCIuNaYa_joELZnyzbE6vqaC_SgPI-CSkDhOwW4Clrhrg9tdOkibnkNI_jnUKvBZmRd8LyPxh94ypcZ3Pk7GWDc9ve6QQRMdV_O2Fh5WhBuiGLLjMU2VJrjl62eBAF1mt',

            'All Term': // accomplished with cmdline code hack (so macs are valid)
            'Gj8LJHitylJ4aVAkkSi1U1m4p-YoXONCOeamFCQbsY8GAFIAAAEBABE3_KB_Dqut_HwspmtRghT_YZ3NN0W-I4CNycjgyBAAABRBs_JlRZdmQiGo7-mEvgH-U-gN5QqP9a_ypYLPYjR0vDUzKmRulgjphyjMxKB2CnZk3CAA4j2o8BBh__OlfCcRXUds7AAzMnrqcImCGwYAMQAAAQEAR_GnJtWuRNBwsduFt11xVHEtBHmfdRCpSMXSbBPRxU8_qwmNHafh2F7bgTY39wdWZoxNZAtMDnhy1BwYpeslwb7dladP1OGFd2GzkUAtBgBDAAABAQCA_Br3aygBwCOF_0gsLX_S7q-9Lrk1IYKXT6gGJ2A9oB52VhiAD76dOnc1bYyeKi3iE8Rs9JRy_jkcp1WvM3R1yjh4XJ_QRmmWnl1xyFP0P8uaH4xu0G1GMyJrc_ZyB94GAGcAAAEBAPfxMbSg-KvMam2Mhkr5Hn_ACH6GX-0k2slg7uUsKELb7COjpxrGJrCuVVb2i3Y-gffCDlQ6GUmPoasRFU_Kmb6UQV5hNnwI7-mbKL8twvBsiplzl3IddqOMT6O5Si6rOmhAHINSa9IRy7UgchtreGzjBjgjc8vViInfw6BihF7r05AVaQYArwAAAQEAXhTRCseFwbouAxpSGQ4dgTlv7qAWOCDGt_DpL99ghxNxPaOZQgCAMIM0xmbZI3stQEfbUhdNWAn6zYoj4cQcfBiYdRfKj4AkWpzKQF8H38e5NgoilJ7bFEaqIeLuJItrE4JBKUr8HXklJPyuCjXKEsQpJ_goSsAqfvlOnZvh4CRq2LQ07s3qBLxhouZ4rXLrx4j8uxPg1Ghz82lOxPcRp4MdHvqLfwg9h9osUInMJI-wNa4CIl_af8GFTreyXA4bQdHTOzS3aTtqnL-_BgCvAAABAQCly24SzO2UtPsMOCEklLhpj-t_EvX3fgZkHGzG-h6JMCevq9YK3WmLjg0Fy8InTz0pqXjzcJUz-foMtkul4JDWj6nllSD9aTKTsj6SIhK6_ettdrvljxi5AdiYE_iCFtyF6MIReWOmLnFFizIKNO1WYu8n9Jli0Be1IzxOU5WawkN_VM-8iA2-MEN5pJxwlRK2f9TGsqS0P5d6xKcGryH7dX-NMwN2ywZHRuPe6GY5DKlLXsEIw0kJmb--07VokAXouCwbzkFydZW6wekGAK8AAAEBABmE5-OFM3LcqrBjJzXAZzhKgOG6GBQYFC_mKndl07saC3IfJXDenX-x2IzsBD_HcoyMMZm2ig1ObGqaZ5SqijRbAyTt13-3HoZoE6DTAF3MiW0p_0-SAniNkcSDX_bqT_NDjsKLI4AtY3rXOv_AhT3X8Aorpy1c41v89899yFDuXa0R2aZiEndgDJ1ifUGqEXkpQgASz25uJ6gJwjqlsi8AjVXIhKx0ZeNqQiEfIBu4Mm8S6SV-sIGpZe1jryCPoRbObZkMxKUhcHpHOAYAOAAAAQEA12z4tjJz4fKYHWjq4e0nyKcEjAhjBeDWhD-qE523OX5NcEXfAfqf7oj6q0wcN5PKgKzsi6I',

            'No Term': // accomplished with cmdline code hack (so macs are valid)
            'DBSj10kBKZ85UUBqgW05vS8wXkFlJCXMF37GwEpWAyIGAFIAAAABAGDNsxpQxcJfSTqljJ3_gQF59Dbw9Fo--1coQtXgyBAAABS7tNDYzTpFw-K7GQ3f46fD_kqiW4sdg0Gqo8NgaohCHvc9CAK_lKIEWltbdW0OQkHeofnoJfvquDZEPcThNI6stiALDeP865vVsJ3ozQYAMQAAAAEASFE_HU_e4zvofNC3y2YJc_TDtgTl2NkWbMh_Yj4Dz6fjgeRuVJjqk8R2mcLDiucVINP1sa0C8exDYYgIBhhyJNZKbAF4vGcts76qYN5NBgBDAAAAAQDG5uS6qlBCA10PZ5TchRsg_50IVg3H64ASIZbdkfYlIalDmnKx2_lkFkt9LkEODBfLNoCg3280ixQ2mwae3M4V0XMLGdznAYrgMnXet7ZiEtToldVzGv0m-6d29pz4umYGAGcAAAABAPqd0fors414KtU1ViEKmqkeGgHcyjEoJ4DIRH742xXTxh4nOhoFm19PvDVNeAVQIdbSCDa-s4IqdCzLgUQK-Yx8DM0YOdUBolZxJQOb-5OoVhfVmm99yiggklZPtzT1bfCaXQvKM7Xw2wAIrw1xMTkRltH8lH5yaz3Xb8elQbKYTIpFvgYArwAAAAEApmzfDJvug6b2EaDTKr61O-JGsSrEboPHwsxX9LSUcCh0eBIQ1MLG1v2owMbgK2jQy8bEOhM4rRrpiZ1TzDd0cKyhelLFCDUsOtBJO6uOknPb9YOBwcna2B9UMj8lrZb9My9ChfjofXDk_b-uRhZbIqnGFhhNTYSwkZ2dyuYleIiD1GQPoP4MYJ4XnUs3nEg392FXgTKjGlRzwwbSsIQpbWn94zN4KLQ_ziCkOwF-HDDKf8wD3WevkbFImsYM6RZbvDGt5Eei9_fvyyprBgCvAAAAAQAD-ci_1XMFjh67-ziFnGkaCeq5wfh_kwFybPRzU2HSutmX6e6jkEQrUwSfEkYvavlpMNQKFjL10aVvC1JNbI7CCx6FE2sog2ZL5lfPtRGPhbu8_BnMvS_zAG9uvvTqMneXUrvii79uhT8MY7dCuLCBCtVMtyzmQFRsXFMcVMrKEKXQH3Voi_TkLNPr7MtJGzegKQcm1y6sX3VEkPapdqkG636zmCE4tFDIptJBDgJ8uXP5no0c-CtHepqL1jcKkeIgZVt8bCK4b9-8OtcGAK8AAAABALEZNnMJXsYobGKOn8U63Wtho1muI87OKzMI_BZDDFiUQZduletcTCNjsm4iZinPpFGtGrOuS8oSbxrcnkZgJA6_RhpuN63lEOX9NAv-T5wiz8sJbWVWm59xtZ6pcR7tuyVK444Nl89f2ZeHEp_DuCWdFo-AZhUBqp7lL3_H42AABHS_iHcMU5dT3ZvVmZbiazVFCgIlpo-biDihT1XR9uuWtPZlNUE80YACm3sxSvSZ7bZZkWsgACouG3HweAeG_gILIhm6O0XwP9gUMwYAOAAAAAEAmB0NrkLBUxOT-kUrJwTlORQ62fdJKCePOjPUNnBawoupsH5c34r2leStBcHeJkokVev3OWg',
         }
      }
   ];

   const clearData = new Uint8Array([118, 101, 114, 115, 105, 111, 110, 58, 32, 34, 51, 46, 56, 34, 10, 115, 101, 114, 118, 105, 99, 101, 115, 58, 10, 32, 32, 100, 111, 99, 107, 103, 101, 58, 10, 32, 32, 32, 32, 105, 109, 97, 103, 101, 58, 32, 108, 111, 117, 105, 115, 108, 97, 109, 47, 100, 111, 99, 107, 103, 101, 58, 49, 10, 32, 32, 32, 32, 114, 101, 115, 116, 97, 114, 116, 58, 32, 117, 110, 108, 101, 115, 115, 45, 115, 116, 111, 112, 112, 101, 100, 10, 32, 32, 32, 32, 112, 111, 114, 116, 115, 58, 10, 32, 32, 32, 32, 32, 32, 45, 32, 53, 48, 48, 49, 58, 53, 48, 48, 49, 10, 32, 32, 32, 32, 118, 111, 108, 117, 109, 101, 115, 58, 10, 32, 32, 32, 32, 32, 32, 45, 32, 47, 118, 97, 114, 47, 114, 117, 110, 47, 100, 111, 99, 107, 101, 114, 46, 115, 111, 99, 107, 58, 47, 118, 97, 114, 47, 114, 117, 110, 47, 100, 111, 99, 107, 101, 114, 46, 115, 111, 99, 107, 10, 32, 32, 32, 32, 32, 32, 45, 32, 46, 47, 100, 97, 116, 97, 58, 47, 97, 112, 112, 47, 100, 97, 116, 97, 10, 32, 32, 32, 32, 32, 32, 35, 32, 83, 116, 97, 99, 107, 115, 32, 68, 105, 114, 101, 99, 116, 111, 114, 121, 10, 32, 32, 32, 32, 32, 32, 35, 32, 226, 154, 160, 239, 184, 143, 32, 82, 69, 65, 68, 32, 73, 84, 32, 67, 65, 82, 69, 70, 85, 76, 76, 89, 46, 32, 73, 102, 32, 121, 111, 117, 32, 100, 105, 100, 32, 105, 116, 32, 119, 114, 111, 110, 103, 44, 32, 121, 111, 117, 114, 32, 100, 97, 116, 97, 32, 99, 111, 117, 108, 100, 32, 101, 110, 100, 32, 117, 112, 32, 119, 114, 105, 116, 105, 110, 103, 32, 105, 110, 116, 111, 32, 97, 32, 87, 82, 79, 78, 71, 32, 80, 65, 84, 72, 46, 10, 32, 32, 32, 32, 32, 32, 35, 32, 226, 154, 160, 239, 184, 143, 32, 49, 46, 32, 70, 85, 76, 76, 32, 112, 97, 116, 104, 32, 111, 110, 108, 121, 46, 32, 78, 111, 32, 114, 101, 108, 97, 116, 105, 118, 101, 32, 112, 97, 116, 104, 32, 40, 77, 85, 83, 84, 41, 10, 32, 32, 32, 32, 32, 32, 35, 32, 226, 154, 160, 239, 184, 143, 32, 50, 46, 32, 76, 101, 102, 116, 32, 83, 116, 97, 99, 107, 115, 32, 80, 97, 116, 104, 32, 61, 61, 61, 32, 82, 105, 103, 104, 116, 32, 83, 116, 97, 99, 107, 115, 32, 80, 97, 116, 104, 32, 40, 77, 85, 83, 84, 41, 10, 32, 32, 32, 32, 32, 32, 45, 32, 47, 111, 112, 116, 47, 115, 116, 97, 99, 107, 115, 58, 47, 111, 112, 116, 47, 115, 116, 97, 99, 107, 115, 10, 32, 32, 32, 32, 101, 110, 118, 105, 114, 111, 110, 109, 101, 110, 116, 58, 10, 32, 32, 32, 32, 32, 32, 35, 32, 84, 101, 108, 108, 32, 68, 111, 99, 107, 103, 101, 32, 119, 104, 101, 114, 101, 32, 116, 111, 32, 102, 105, 110, 100, 32, 116, 104, 101, 32, 115, 116, 97, 99, 107, 115, 10, 32, 32, 32, 32, 32, 32, 45, 32, 68, 79, 67, 75, 71, 69, 95, 83, 84, 65, 67, 75, 83, 95, 68, 73, 82, 61, 47, 111, 112, 116, 47, 115, 116, 97, 99, 107, 115]);

   it("good multi block ciphertext", async function () {
      for (const ver of vers) {
         // First make sure it decrypts as expected
         let [cipherStream] = streamFromBase64(ver.goodCt);
         let dec = await cipherSvc.decryptStream(async (cdinfo) => {
            expect(cdinfo.hint).toEqual('4321');
            expect(cdinfo.alg).toBe('AES-GCM');
            expect(cdinfo.ver).toBe(ver.ver);
            expect(cdinfo.lp).toBe(1);
            expect(cdinfo.lpEnd).toBe(1);
            expect(cdinfo.ic).toBe(1100000);
            expect(Boolean(cdinfo.hint)).toBe(true);
            return ['asdf', undefined];
         }, userCred, cipherStream);
         await expect(areEqual(dec, clearData)).resolves.toEqual(true);
      }
   });

   it("changed multi block ciphertext", async function () {

      for (const ver of vers) {
         for (const [change, ct] of Object.entries(ver.badCts)) {
            let [cipherStream] = streamFromBase64(ct);
            // version ${ver.ver} change ${change}
            await expect(cipherSvc.decryptStream(async (cdinfo) => {
               return ['asdf', undefined];
            }, userCred, cipherStream).then((dec) => {
               return areEqual(dec, clearData);
            })).rejects.toThrow(Error);
         }
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
      expect(cipherSvc.validateAlg('AES_GCM')).toBe(false);
      expect(cipherSvc.validateAlg('')).toBe(false);
      expect(cipherSvc.validateAlg('f2f33flin2o23f2j3f90j2')).toBe(false);
   });

   it("should be valid algs", async function () {
      expect(cipherSvc.validateAlg('AES-GCM')).toBe(true);
      expect(cipherSvc.validateAlg('X20-PLY')).toBe(true);
      expect(cipherSvc.validateAlg('AEGIS-256')).toBe(true);
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

         const cipherStream = await cipherSvc.encryptStream(econtext, async (cdinfo) => {
            expect(cdinfo.alg).toEqual(alg);
            expect(cdinfo.ic).toEqual(cc.ICOUNT_MIN);
            return [pwd, hint];
         }, userCred, clearStream);

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

      const cipherStream = await cipherSvc.encryptStream(econtext, async (cdinfo) => {
         return [pwd, hint];
      }, userCred, clearStream);

      // Valid, but doesn't match orignal userCred
      let problemUserCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));
      await expect(cipherSvc.getCipherStreamInfo(problemUserCred, cipherStream)).rejects.toThrow(new RegExp('.+MAC.+'));

      // Missing one byte of userCred
      problemUserCred = userCred.slice(0, userCred.byteLength - 1);
      await expect(cipherSvc.getCipherStreamInfo(problemUserCred, cipherStream)).rejects.toThrow(new RegExp('Invalid userCred length.+'));

      // One bytes extra userCred
      problemUserCred = new Uint8Array(cc.USERCRED_BYTES + 1);
      problemUserCred.set(userCred);
      problemUserCred.set([0], userCred.byteLength);
      await expect(cipherSvc.getCipherStreamInfo(problemUserCred, cipherStream)).rejects.toThrow(new RegExp('Invalid userCred length.+'));
   });

});


// Python helper function to recreate values
// from base64 import urlsafe_b64decode as b64d
/*
def b64Tou8a(b64str):
   padds = (4 - len(b64str) % 4) % 4
   b64str = b64str + '=' * padds
   ba = b64d(b64str);
   ia = [int(v) for v in ba]
   print(f'new Uint8Array({ia});')

def hexTou8a(hstr):
   ta = hstr.split()
   ia = [int(v, 16) for v in ta]
   print(f'new Uint8Array({ia});')
*/
