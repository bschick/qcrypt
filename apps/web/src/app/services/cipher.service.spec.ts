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
import * as cc from '@qcrypt/crypto/consts';
import { CipherService } from './cipher.service';
import {
   readStreamAll,
   base64ToBytes,
   bytesToBase64,
   cryptoReady,
   getArrayBuffer,
   getRandom,
   bytesToNum,
   Encipher,
   Ciphers,
   type EContext,
   PWDKeyProvider,
   concatArrays,
} from '@qcrypt/crypto';

describe('CipherService', () => {
   let cipherSvc: CipherService;
   beforeEach(async () => {
      await cryptoReady();
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
   b: Uint8Array | ReadableStream<Uint8Array>,
): Promise<boolean> {
   if (a instanceof ReadableStream) {
      a = await readStreamAll(a);
   }
   if (b instanceof ReadableStream) {
      b = await readStreamAll(b);
   }

   if (a.byteLength !== b.byteLength) {
      return false;
   }

   for (let i = 0; i < a.byteLength; ++i) {
      if (a[i] !== b[i]) {
         return false;
      }
   }
   return true;
}

// Faster than .toEqual, resulting in few timeouts
function isEqualArray(a: Uint8Array, b: Uint8Array): boolean {
   if (a.length !== b.length) {
      return false;
   }
   for (let i = 0; i < a.length; ++i) {
      if (a[i] !== b[i]) {
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

describe('Stream encryption and decryption', () => {
   let cipherSvc: CipherService;
   beforeEach(async () => {
      await cryptoReady();
      TestBed.configureTestingModule({});
      cipherSvc = TestBed.inject(CipherService);
   });

   it('successful round trip, all algorithms, no pwd hint', async () => {
      for (const alg of Ciphers.algs()) {
         const srcString = 'This is a secret 🦆';
         const [clearStream, _clearData] = streamFromStr(srcString);
         const pwd = 'a good pwd';
         const userCred = getRandom(cc.USERCRED_BYTES);

         const econtext: EContext = {
            algs: [alg],
            ic: cc.ICOUNT_MIN,
         };

         const makeKP = () => {
            const kp = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
               expect(cdinfo.alg).toEqual(alg);
               expect(cdinfo.slt.byteLength).toEqual(cc.SLT_BYTES);
               expect(cdinfo.ic).toEqual(cc.ICOUNT_MIN);
               expect(cdinfo.lp).toEqual(1);
               expect(cdinfo.lpEnd).toEqual(1);
               expect(cdinfo.hint).toBeFalsy();
               expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
               return [pwd, undefined];
            });
            return kp;
         };

         const encKeyProvider = makeKP();
         const cipherStream = await cipherSvc.encryptStream(clearStream, encKeyProvider, econtext);

         const decKeyProvider = makeKP();
         const decrypted = await cipherSvc.decryptStream(cipherStream, decKeyProvider);

         const resString = await readStreamAll(decrypted, true);
         expect(resString).toEqual(srcString);
      }
   });

   it('successful round trip, all algorithms', async () => {
      for (const alg of Ciphers.algs()) {
         const srcString = 'This is a secret 🦆';
         const [clearStream, _clearData] = streamFromStr(srcString);
         const pwd = 'a good pwd';
         const hint = 'not really';
         const userCred = getRandom(cc.USERCRED_BYTES);

         const econtext: EContext = {
            algs: [alg],
            ic: cc.ICOUNT_MIN,
         };

         // Counted because assertions inside a provider that is never asked for a password
         // would silently pass
         let encPwdCount = 0;
         const encKeyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
            encPwdCount += 1;
            expect(cdinfo.alg).toEqual(alg);
            expect(cdinfo.slt.byteLength).toEqual(cc.SLT_BYTES);
            expect(cdinfo.ic).toEqual(cc.ICOUNT_MIN);
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            expect(cdinfo.hint).toBeFalsy();
            expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
            return [pwd, hint];
         });
         // Short clear text fits in block0, so no terminal block is appended
         let encDoneCount = 0;
         const cipherStream = await cipherSvc.encryptStream(
            clearStream,
            encKeyProvider,
            econtext,
            (ver, multiBlock) => {
               encDoneCount += 1;
               expect(ver).toEqual(cc.CURRENT_VERSION);
               expect(multiBlock).toBe(false);
            },
         );

         let decPwdCount = 0;
         const decKeyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
            decPwdCount += 1;
            expect(cdinfo.alg).toEqual(alg);
            expect(cdinfo.slt.byteLength).toEqual(cc.SLT_BYTES);
            expect(cdinfo.ic).toEqual(cc.ICOUNT_MIN);
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            expect(cdinfo.hint).toEqual(hint);
            expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
            return [pwd, undefined];
         });
         let decDoneCount = 0;
         const decrypted = await cipherSvc.decryptStream(cipherStream, decKeyProvider, (ver, multiBlock) => {
            decDoneCount += 1;
            expect(ver).toEqual(cc.CURRENT_VERSION);
            expect(multiBlock).toBe(false);
         });

         const resString = await readStreamAll(decrypted, true);
         expect(resString).toEqual(srcString);
         expect(encDoneCount).toBe(1);
         expect(decDoneCount).toBe(1);
         expect(encPwdCount).toBe(1);
         expect(decPwdCount).toBe(1);
      }
   });

   it('successful round trip, all algorithms, loops', async () => {
      const maxLps = 3;
      for (const alg of Ciphers.algs()) {
         const srcString = 'This is a secret 🦆';
         const [clearStream, _clearData] = streamFromStr(srcString);
         const userCred = getRandom(cc.USERCRED_BYTES);

         const econtext: EContext = {
            algs: Array(maxLps).fill(alg),
            ic: cc.ICOUNT_MIN,
         };

         let expectedEncLp = 1;

         const encKeyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
            expect(cdinfo.lp).toEqual(expectedEncLp);
            expect(cdinfo.lpEnd).toEqual(maxLps);
            expect(cdinfo.alg).toEqual(alg);
            expect(cdinfo.ic).toEqual(cc.ICOUNT_MIN);
            expect(cdinfo.hint).toBeFalsy();
            expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
            expectedEncLp += 1;
            return [String(cdinfo.lp), String(cdinfo.lp)];
         });
         // Only the outermost loop describes the stored bytes, so onDone fires exactly once
         let encDoneCount = 0;
         const cipherStream = await cipherSvc.encryptStream(
            clearStream,
            encKeyProvider,
            econtext,
            (ver, multiBlock) => {
               encDoneCount += 1;
               expect(ver).toEqual(cc.CURRENT_VERSION);
               expect(multiBlock).toBe(false);
            },
         );

         let expectedDecLp = maxLps;

         const decKeyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
            expect(cdinfo.lp).toEqual(expectedDecLp);
            expect(cdinfo.lpEnd).toEqual(maxLps);
            expect(cdinfo.alg).toEqual(alg);
            expect(cdinfo.ic).toEqual(cc.ICOUNT_MIN);
            expect(cdinfo.hint).toEqual(String(cdinfo.lp));
            expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
            expectedDecLp -= 1;
            return [cdinfo.hint!, undefined];
         });
         let decDoneCount = 0;
         const decrypted = await cipherSvc.decryptStream(cipherStream, decKeyProvider, (ver, multiBlock) => {
            decDoneCount += 1;
            expect(ver).toEqual(cc.CURRENT_VERSION);
            expect(multiBlock).toBe(false);
         });

         const resString = await readStreamAll(decrypted, true);
         expect(resString).toEqual(srcString);
         expect(encDoneCount).toBe(1);
         expect(decDoneCount).toBe(1);
         // Both providers step one loop per call, so reaching the far end proves every loop asked
         expect(expectedEncLp).toBe(maxLps + 1);
         expect(expectedDecLp).toBe(0);
      }
   });

   it('successful round trip, mixed algorithms, loops', async () => {
      const algKeys = Ciphers.algs();
      const maxLps = algKeys.length;

      const srcString = 'This is a secret 🦆';
      const [clearStream] = streamFromStr(srcString);
      const userCred = getRandom(cc.USERCRED_BYTES);

      const econtext: EContext = {
         algs: algKeys,
         ic: cc.ICOUNT_MIN,
      };

      let expectedEncLp = 1;

      const encKeyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
         expect(cdinfo.lp).toEqual(expectedEncLp);
         expect(cdinfo.lpEnd).toEqual(maxLps);
         expect(cdinfo.alg).toEqual(algKeys[cdinfo.lp - 1]);
         expect(cdinfo.ic).toEqual(cc.ICOUNT_MIN);
         expect(cdinfo.hint).toBeFalsy();
         expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
         expectedEncLp += 1;
         return [String(cdinfo.lp), String(cdinfo.lp)];
      });
      const cipherStream = await cipherSvc.encryptStream(clearStream, encKeyProvider, econtext);

      let expectedDecLp = maxLps;

      const decKeyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
         expect(cdinfo.lp).toEqual(expectedDecLp);
         expect(cdinfo.lpEnd).toEqual(maxLps);
         expect(cdinfo.alg).toEqual(algKeys[cdinfo.lp - 1]);
         expect(cdinfo.ic).toEqual(cc.ICOUNT_MIN);
         expect(cdinfo.hint).toEqual(String(cdinfo.lp));
         expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
         expectedDecLp -= 1;
         return [cdinfo.hint!, undefined];
      });
      const decrypted = await cipherSvc.decryptStream(cipherStream, decKeyProvider);

      const resString = await readStreamAll(decrypted, true);
      expect(resString).toEqual(srcString);
   });

   it('successful round trip, lpEnd=LP_MAX', { timeout: 60000 }, async () => {
      const algs: cc.CipherAlgs[] = Array(cc.LP_MAX).fill('AES-GCM');
      const srcString = 'This is a secret 🦆';
      const [clearStream] = streamFromStr(srcString);
      const userCred = getRandom(cc.USERCRED_BYTES);

      const econtext: EContext = {
         algs,
         ic: cc.ICOUNT_MIN,
      };

      const encKeyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
         expect(cdinfo.lpEnd).toEqual(cc.LP_MAX);
         return [String(cdinfo.lp), String(cdinfo.lp)];
      });
      const cipherStream = await cipherSvc.encryptStream(clearStream, encKeyProvider, econtext);

      const decKeyProvider = new PWDKeyProvider(userCred, async (cdinfo) => {
         expect(cdinfo.lpEnd).toEqual(cc.LP_MAX);
         return [cdinfo.hint!, undefined];
      });
      const decrypted = await cipherSvc.decryptStream(cipherStream, decKeyProvider);

      const resString = await readStreamAll(decrypted, true);
      expect(resString).toEqual(srcString);
   });

   it('confirm successful version decryption, multi-version', async () => {
      const vers = [
         //v1
         {
            ver: 1,
            cts: [
               // AEG-GCM: V1
               '4FhRcUaBCS6rrfj8pmkyclbGORk-nVoo-Epq_0NZ3E0BAEE8XuQyAPODSpDZLh9fCrOSLERyCwWq9rzth9VAdxsAAQAV3pKmSTgTx99M_cAWV51Z2AFzgXyEQk-iZznhBgEsdTvIlwTdet5j7a8FqrlMlZiQRvlvLhOgAvsO0n5Pxkhxhv-lK9mLQ670gilLRTrRR-pKATz4hGMWIDCgC4ojnOMwluTtK0XosZ0dCcSy9nMgIhWP5co-LWwr-NWsY29uXFC9WZI5ZA4Ujt1BAsv-gUe7vhwFcPLkhFGgc6tIeo4ObcSm7oC7z4AjTQ9WtURpvgwoqA9ovHEMum2ViGSifXlemw304KMKGDQgsM3Fn9YacZjJO0YYMyiNi48ywQVCNkw_Fvo',
               // XChaCha: V1
               'D0WSIi0s18fTxqsg5CGOHV3boHS7yaCo9AGOmWM8G30CAKFIuXF7m1ZxGo4bL6P7SaXqw-IIv8N9ZKR44xaZKIdgys4pysPqkIRAdxsAAQAVSEeOnFNPWdrAli-fyq8dWfUK2aBmXWF7T6vt06Fl5ehzCOh9DtT4W6uckFBh7S_VFBpmeh1_VN1WWAVV-PUB8HvIRtrVAoRiZy6H-BhkOaZflJnIQpu15AkrZC5aY8e4ulwiWIrV_ep88a963_B5mme9TaVZyzeXuBbo6xFOuGsVoPybjU-DWBDKK3i2rGju62NOlthYTn3eP3e2UuT_wIt1IB30XNO3dsxmcKQAW70GwSDvlGH-KnNqoUw3BUf07PlOYaiP0YfwqxZa7Mr4FjZ-sgTZTg2yKB0Xc-LeuuRprvs',
               // AEGIS: V1
               'ZhiPRZ7YOIjWXEMBFmyZsSWwor9WNId6oPXqBgJmCxkDAMCrHZhWSw5s_dZzPc-k9R2TqHmrs-8kYl2YCxT3PblxGLL51besQyoLQsuJHYvKGUB3GwABACXwMpAj4tQpvDM0yLAUJWwWFpSPHMxwMtxvB6xUvbQQDRdzkm1rFPPYm_PfWPXh_vekCrJTjXCp22hvGCr9NhPTCxnhrPu4hpVkIaPawZ77bB6uAoXI8htcZoLrf2CuSx2-F-v7XRCNYtFfOpwLQQx1u_df4xpFZWXwz_pZafMN6dvbYniu3-x4Iwcj1RtzqOajBPrgMO143pTu9n2LlKUkeUVR3VmeJIFeXhdbUaVWo498Jeboltf7XLUGy--Ox5yVFaCcmPiYUZFe0UolFPJLPIAEHB4Smdw83LoHwwjgjedzvuyzi5SHpq03OYME87dUQBVdgIDwaxwIyJDxpbLvXP9P',
            ],
         },
         //v4
         {
            ver: 4,
            cts: [
               // AEG-GCM: V4
               '4pbVthrII9ejsB0QMVxM_8eVhBcx9AniiH_jB9f0oAkEAAcBAAABAMBOfz4z4j-XjmUIjdm2maNK1HObgT-jCNiGB1fgyBAAABVTww8FCVeXexY7HYAoPkKQsx24Pqxu451SMBrhGDVScst_s7Ep8uNMVUbglWitlMEI9pmOWxAkUZYVMEFxVlka_Hbq9qBheD5YRijGqlzaRiSAz6D6Gh5eTecJ0xfQpKIe4qXgQ-1AsWbEUig4Zk1r7fpMIszUAU3qy2wbD3JAqiSszUu1pWFtgfwPLFSjZv6oO3-exZSuOCNi7G8zqpbDPsquTdyc8FX_GpG4YD_OD755seUtVT4oBKXmwcKIoM_RhgcoBiRDqOvCWurBDIjbLVRcONe2PrZgotRDwgZ2UvEYtw',
               // XChaCha: V4
               '0hCjaRFwORsn5JPafhwRy9qV1Qt6t07FBFN9_wLNVeIEABMBAAACAJwKA2CZb8-wP4QC5wpi1KOuqI2kuurdtZij3ss2J3VxW8z0AZeunm3gyBAAABV0wEHCHvwmalDVcixk-Kk3whlnehP3UQuIZ8PZlSD04D5pDnsy7PjzXZnkfqd79fOcSpa7VfSG0NAVyGGjicLxMGPcio7wE71Pn2BC1m9jklIZGbw_Szzp7l9iorLBd9KOQq5bl5bo3D6iLFsZcHYVXc9_miqHXSI9_iorXRrS0BurFpsFSPHjbiSONOYFT2mdh-MwSQDNU-0Egab0GoltvM4-vxbjFMwLeFpR7_QRVHOXqlhdQLGyGjW6UtIpDLZLE0Ym-fiBR6A7STjeYWZWnqFni7yKygy_Ojqy5EdeRjfvOA',
               // AEGIS: V4
               '9qNOjLZ9-rH4psG5tikgFRhLfhiHLQCQrROmpFPqAAkEADsBAAADAIijvSZ00lRB-Edts0p2oEYxlrL5emmsclderCvjedg0UqNiq9mwx79iufCn3rCwieDIEAAAJfCjOKlYsM_LPXZLEmj6Bq0tOClxc764eABkaL_oxK6Ynx5SDj_Pzwa-iTXT2hbgShLadz4kMcaba_baFzmbD8HjfMehHaRApQ86KZRvfkMA1E5eFp7IIe1szgx7fyT0vE5wQeZzIB_mhsomYLdW46aP0_g5e95qjP2rLBAqav_AdC2rzWLR6AwZsuA2XgRr6uNVot4OYgFeJkVVaI0uvrmQj07D84e78-UjuU66zo6KbydWLRFm2zQBkRyGn1vAFoiv7RKM9pHWPoATJYiEG6V5pxQyZGZe-_6zKCqWF5H4wZXTuHCdb5EauQjwYGCQz2GCk7ZSztl-KYmKsSowCYPjRuw',
            ],
         },
         //v5
         {
            ver: 5,
            cts: [
               // AEG-GCM: V5
               'EJclA00j4FKhWMLo8zMBbT_WWDtbYo1jOJxbms2AyY4FAAcBAAEBAKi_hNzCMN2QmjCIt-NcYBDvPRpv-t45wprgBjLgyBAAABUoqck_zYTvLssZib47B_sE5nucUsko-Q7ZMkwa01AppnXeXBP2P3Ey-xHq5aeDz2E0QF4FHHTxcG1b2q6r-uDteGWqIMg-UTvIeJjTkDL-k7qmFDUx5IpQBYrtoQ_v-OFHe9YeB5LER7MXBMYkOMnoFh84gCi2pV-fnX-7hmshvMFym_zjctpk1uXsdiFUd7rJnf7S8nG5xK3FEC4b_B4F7tUmvNUqevfOZohhweC7YlUMpo0LqRC9LDOduuoTZDz2X2YmZ14dEsTuy51SvgrP_d3L-l1SK3zE6d9GGyVJLkb3GQ',
               // XChaCha: V5
               'SAJ9PKhT8wjZjBskbt4vdzg161W2KMz61C-9VKMUsagFABMBAAECADbgwlhg2FbbXs7I9uOyhtHwK3hLkNeSkE7RcghFE9tER3gZbWW4ro7gyBAAABXuVU3WRRokICOeJCnqnhmKvTQ8I0r9cu_DbFnVJuFCB604K-qQqAV84sOvNu4Dp6_b8oFbe7B97hwvy59RkJ7YVhZJbOWUgSd8SyeSxsS_8vxctfW26FuBRHGCjmCHaIzTKvhRE-A5XeWZ_E5TI9cilLmze0Gqk4Ob7c3sfB6btro-nGj5dbdQyYPST1o7IdM34F2sn8aq2no8W3q2e6IFv7t3jHpvN8hl5abkFRIAz9zBbh_U8mO36R2vimNbYwSgcawPzPSSkX83bf11qnFEu4KxJ2_JQQxWh8lGp56YhRANDQ',
               // AEGIS: V5
               'ZUDYZTXyYnJhG-9MZMD4j8ymWuNP8Oy5jr_qmISjOF0FADsBAAEDANHCkN2qd1mYu4zrsjS5AzIg9LsqLr3Dh8dJpcPkC9wK0Bwl_iFu5hpDTmyQ3P1G-eDIEAAAJbNfK1hDFINnuh3UpFAzOJnyH1fzCbjPuKFQcuZj8YfWkZV-_USgfgSqG1NLt2szc6ZMDEWoHKPPYgsRS6IH3JqrCJF8_W8RhV_1X51v9FAHE7D1VvNs5qiMiuKWN7IU9pXad18isn2leUwI0O24-8tCK7rCIX-CqGaY5y3mHEQavpoNHBD9QQKyKWNUqnWhvO39a_FtgNrtNaLx0LFLYKOpXYzFWSCbwQfeCDxXMK-J81u7z_K_OqLWTaZdjvEqaBDCqJQPapSRlgi0eh5bu94Vg9QsLKPYcFIXXjBMLOU7gNm0oRDMDok5Qu-Ln9OeWIAv1lNVS56JcYfEpOdZKYCStRc',
            ],
         },
         //v6
         {
            ver: 6,
            cts: [
               // AEG-GCM: V6
               'W4_I9gz5WSiAq-G34w44eP-3Me3xjAep6B9H1dxoHe4GAAgBAAEBAHNt83V6_8a7aZR72DqhJJgk2CpmUMPnpErW7vhAQg8AABXer0YFIgg5tMSL9afCCog2shFnxcicsow1wVHIJeLF6oZapLXOo08wk4_1d25XmdtMHLulpFV52RVgYNgrwcHpMOKmaRfN1CDLEX9nPG3BSYYCm0NAGfQzUUmrlC1cBe8lSbI4RrsVD4Sa0u4IZRz6NQ3yAR2FGenrW7yjbN_GkxROShPIaNy63rsyYc6svBw4kp8YRDgxY9xG54O4EBqaNVzNk9v6YVYzepYH14EjKQGqYLbHX-LvdVoVuu4QhFMWRAfB_1u89gS9tC46NnJFX4oJo6tokXAv0aHWeEsoR1NeCg',
               // XChaCha: V6
               'u8BTh9ThKn_klfjO8eMA1Sde-FX_CYsUBWhKaRnw6xAGABQBAAECAPQAYxtzwMf5dw7Rya2biOgUbwTUE6DbVLDcNaYxIWrsWa1va-dX5g9AQg8AABU2qXFON3ZxfJrIp26aqT5QDvUkOnNy8Sw0S_QxQgKWPyS7IsSRFh09F0Zy7Ob5jQmD6rdV1_Xq_bpa3p1snuntsJkxhnzOB28o3ALSAu8HdNRFXUmYHBzlJ0b3cxUoIn1WfZhYLWIMct1B4KDv8E8lgECHOL4HLZuMy0b_uSoUWb2KtOkwAhwQkKM_6OhSTbtRiqrWvY6C7P6ZAXrlZBRVlZVf54ft6L5swqOioRWEyzgB26raOg0CsV246oiOFuvuOTsFoW9hWcb3sMnjvGtProLH9iIBhhH7yDubc4FbqEfUTA',
               // AEGIS: V6
               'pB9kP1BYfukyE6IGD6gZ-_SHCjiV0AGI1UoJHEc6a3AGADwBAAEDAALbWMdn4I92-SWsCZpRgRqwM0Hzqp9yVg8crnjUCskbYzIqgLt7dSdfN19d3pnZjUBCDwAAJV0CeJDHHvGZ-cxRpIXKnPK9Cgh42Z_tqiOx88hUFvBISL6nOIK2pTymkZcmVN9Apw3g9WZcroMG6zTVUemIigqtzdsgEZ8IdfelvCTy1ULEzEMAsXX1n_itrE-nxVe1Q_qkJyZhzBRg4jJVL9zdXON6-l4cgTm4www0Ml9-6kl9skgjRBhk9RMFpAMIQ8Wll6tyN9Pen9uk_ahDrMFSA32eLGArQNIYZIEiompoMn1jMzMSAPTLzHN-6PgRdQUhTFr_rdEyiWjRxQWrTF8Rv57eYHxCgm_6faLPR0dLwoX0BgM83dsRjor5pzu4usO84J6TCY8fDhrXSg-1nyKUSeagYZ8',
            ],
         },
         //v7 — generated by: pnpm vectors:ciphersvc
         {
            ver: 7,
            cts: [
               // AES-GCM: V7
               'kfjJSyac3riFUTYCZ5J3Iv_HClAaUIdRSJ6MbsC5nioHAAgBAAEBALywjAWkU-nMoEfBG_CO2Ft9mnySzCJPtA6sbpugaAYAABV-cIJ_3ZT0RK2Ur9pGmGzDjj_-y7GWgNXmDVCBX71jP2jPlP1peZL8YSNADjHsQsoS0dVQwyF3cnYJEB7nV2Zz1NtrloNB3WOze2w2tZI8QAASJ9bB0Cl93_Hoc41uHBSAw_ujJ-ksgiAiv25TXry1IDsOoCRmIWXPK-0Qc5YsCiaUigUR4RCInSoFys62Zkw4nt67WbhtXxR8duWsGR__129wMfiLXs0BxRYLDYhUXj0d9GCk4cZQZqUbUt1Fq8TCqvca6Ou7Xw3Ojz1iV5F1PkrOFPFJBaD0EJgCeL3LwTZz3w',
               // X20-PLY: V7
               '8JcLwOLGiqb4_dVWGf4BEdwOwRkZRcNO563Xf_c2VTgHABQBAAECAJ5-fCbzWPc2pA5PApHnba1IRnD3A15ap_4Ay8SKOo3e0cIE6nEV8bigaAYAABWXIzEBoL8FkwLHoIhOFxicA-AWZUllYTuwmltBJu_wQ22ayA2oU2pSj00VppmIlHgYwtFSdtC5tkBGSe0n062yzfG20lDMcUlZshx7zqWX29YFXRJkyS0hgs7NJU8IS1_3785kLGUEoJjSfITBeOY1E6ez9LHiubBHLDUIpjE7jBEkqwi_Zi5Go2-dt3cmZRSagsuixPqHb1u047aQ0brD9a5yZbBGk4ta2rVWGLp7M8KtXwgKQ2z-AKy9vo46TxfQKYsrUi3jfW8_yCN6rw4-lQK5sjk9DRedIIhHci-YAN3Iag',
               // AEGIS-256: V7
               '2VKNPB8BkDzFbCHnaX647KRIY4jNuxkP1VkCRacdtMwHADwBAAEDAJSdoVYGumnCjfLun6YC5R7MUqvN-WnUeFwjYuxjJydHEBl46FrZP0Zs1KyFgW1SaqBoBgAAJTv8UTMQERSpBq1YHCHlbc12CinhoM1l16mbdqAUhZpOw2rl1OgKp_sWAuG5uLEbiR2m_zGiYxN9NqzA-wotX55RzdyVxcZrdtdOJnoCm_TX8663KFdO8jKMRjqfCCMjwjS8We2WpZrrvGbHiTOQCjvOQxdHBIODcOgtaexNsAeYU86PYRFgiZRMBkzZAUfKu8O5wjTMlBXRFXRV3-65-oAZo8ow-WYjtZDqTVdTXp8arihJf6bteFy43SNTxJLBlRpvNXjj-81yGpBNHShomwNLs5-DNvhzMEYILI2MjpWuB-hjUD7R84JQe_UJTp219Ys4twY7qQTK7gmu0cfJkEBZJVU',
            ],
         },
         //v8 — generated by: pnpm vectors:ciphersvc
         {
            ver: 8,
            cts: [
               // AES-GCM: V8
               '6lWlpoYligg1LX8nzcF4Tid30EQLn4-opPsVqJUvIXUIACkBAAEBAK5z5gLtYbaWhGVkgOeOFs5RhnoCY_L4Pi2MU5KgaAYAABXFNK560WDdURPSsJTfIAfU6BnKe7wg7x6q0G0tcBynvXKDX3pT3TdBmkh93cSAOyha9wG9u4pQMPnMKWhudmzVqk3-eZ8uaCJ_Sld9BwKz1M1UYD6gjzRBrTLy8Fg-j6VxhG4GnmBSQndvJQ4MPD0eZJAZHt56CJ9YIu-aZkz5wAhkW_1dn72dJvwpi4MPi-6OMFRv59o9BrJ9MQnfJRBqTHpbnQjoL_2mzArBEueuwETVXRNBp5k1i28s0Kbb20ORRP64kmN7RnpckVULnSWKeowQJcFumwECcrA8KH2PZlEOMF307ZORg-HJKejTj_l8dQZS5X5yfepQAwtnjwnhkdzFWQ',
               // X20-PLY: V8
               '9GmRyMVZNdp2LUsfon6tQyntO618GmZ8pMnwySA3Wv0IADUBAAECADUTbIawRRCB1qZSd_0z_wZoCyk4qv0H9lmFvWs9I1Ndq-0J43r8u16gaAYAABWr7PEERPGVGE7d6gk6zry4oLVgjVkgRWUe_jI0caH60SFdPStXl4pUkQ8g25Lt5iuCWFjT0CUs5pOME6b_4kj-k6u3UuoSEguuysRhwQrDi8h8Hgp7P8MVj46gYEaOrnVXCMjwNjG-BzNhSzkBxuOc9DCXdW3iWVsj2zvp2ThfNGTIhCXa9sph_cYiFdY0ALbp-L2X_BTaoGaecsm_vTYp-i9-RiP5I7xG2HuSZSo0oUGot2-LJ0DQ7cM5IgWdkKONpi0g_AhZPrNk0hWZtkWDh759FIUCdqVZSCEl2mSnDe75LtgIXWTojbSRVowxkZ2wiFNjgKVhtl1j0HNNZxyRre9BEg',
               // AEGIS-256: V8
               'xx73NNmdkpZ5gMEkzt_bowxCJoNQc8wVzcaUFhGvpkcIAF0BAAEDALvC9BMqIryoUNJNfySf3xAfWhhzvOndlyWJK-1WIyZ60Lz8WAT3d7PJa3yzxnB4xqBoBgAAJTnNUNPUD4RQgHmUyWa-_qehs0FhCs4r648-dQXa7LSrLeaWjXcgf7ikuOW8FxzSGIhwDTbBP79lgNE5s3tjSqnWOekXGuhidH3vEsrINqn0xhjUMRa2LIQ7FYGsiA6gfb3hwexRjLvhjbJ2XOnHFYe9tjJ5xdTDFevi_MGs8Ja7b8-fBVgkZ7Ss-YOySquBjiyRzvOneikj7YMzWDlRHH1dGotp9c3FFnUZjHDhOKfLB5EId1BjgfMJ-RFffTGJsXRGlykMMMQ21m-MFSSiSRvp7wBZQi_EkZworgAU0LWr3tWbIZa5K9Ztt9dR3LCm52AgG478dKLTo20C2YpGA_XZF8kg3upvkv0BUgs9pWolJHa1Qfu54qHgjwLwO9Tog_vo6eY',
            ],
         },
      ];

      const userCred = new Uint8Array([
         198, 18, 166, 217, 14, 52, 226, 145, 164, 169, 245, 164, 79, 36, 247, 82, 135, 84, 71, 239, 125, 108, 221, 48,
         137, 177, 250, 178, 47, 110, 23, 194,
      ]);
      const [_, clearCheck] = streamFromStr(
         'physical farm bolt correct bee nonchalant glib high able pinch left quaint strip valuable exultant disgusted curved bless geese snatch zoom fat touch boot abject wink pretty accessible foamy',
      );
      const hintCheck = 'royal';
      const pwd = '9j5J4QnKD3D2R7Ks5gAAa';

      for (const ver of vers) {
         for (const ct of ver.cts) {
            const [cipherStream] = streamFromBase64(ct);
            const decKeyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
               expect(cdinfo.hint).toEqual(hintCheck);
               expect(cdinfo.ver).toEqual(ver.ver);
               return [pwd, undefined];
            });
            let decDoneCount = 0;
            const clearStream = await cipherSvc.decryptStream(cipherStream, decKeyProvider, (doneVer, multiBlock) => {
               decDoneCount += 1;
               expect(doneVer).toEqual(ver.ver);
               expect(multiBlock).toBe(false);
            });

            // version ${ver.ver}
            await expect(areEqual(clearStream, clearCheck)).resolves.toBe(true);
            expect(decDoneCount).toBe(1);
         }
      }
   });

   it('confirm successful version decryption, multi-version loops', { timeout: 45000 }, async () => {
      const vers = [
         //v4
         {
            ver: 4,
            cts: [
               // AEG-GCM, V4, 3 LPS
               'UAOJ5M6cU9KADQ8nSJcXp8qP0oS7nb3ASMXwazWynpkEANkBAAABAPkCZdIRcEGl6M_ilpaCHAG9aVYHeKeW_PgAsczgyBAAIhGvvNZ2B7hguRfFWUFg7V-QhL6Q-FIV38VshhSFjWOOFUpvVEMm8_DFCYIuBg-ejfcn8A7Qct7NcjxjHsPllutcg1sBhz8oDnYUm96g4Yp0ME_Ep1ak3qGRrBqetlN2Nomy3gDnibp4AHFVR-Gdj94wyI8GtEuWSS_m64e6026IMo3lrOucJ8IZ8oEL_OwOccBp6StpW_s9IkvCxW-Bivka2c113H-GkDMpmdc9HPX12-FOjyglSNIeuRJ0_2r4QUebLGIUZcxoK3qAOa3u6VRGt7elCRDv_GDKoWQyIXtaBOB8h2AX3h-1RGzHTAHcDWx3O_ad4ULyjoLntka66Y_LoU6Sq2GMrvB5l8eMJkHivFkD8SVcpwKJDjyvMLvJWpJo-FL-l9jnoMe2AxSIJ28qBl9bdCb931p1NZIBHlXTikhTTOkFa820JSiXkWNxF_5csS4MX4TVrHQ5-EIN-MaRif1uQoTf5XMUtoh2gPLLGEBVc9HqtGATvS6p9_PPnrHZ2XvC0JZyReAq57zXGTMfB8O2xL-hEmMzItDVi9sidRGKdM8LDvOrApBB1IEg7ZYzmq4LnA',
               // XChaCha: V4, 3 LPS
               'z0snbVnUg6MCrAC09OyOhDXGWDZ_SrpI_SKVs9fF4IwEAP0BAAACAN3UG9BXiATI48NUlSAvXH530dx-f7NC02mqNAJWcq3_tEBKS2XKnobgyBAAIhFBAXexQmL6gjq4FQcmJDZlV9av_GZ2BmWKTpcsBjrJVl1jL8A8wddfhHbrELWGytolPHiFPB3sCkTXF7Nvwud0pA04W3qTpt1LgCR4Zqwd-QFGNAkl2_yD8Hw8vQMJu1zoi1T05wvYTSFtQu68FVYHh1Hg_BLC3qXKQdmEePWP0YDzxTKqGbp1zzXmAY4X8NtIyw7lPyOaEaL0JNulCvkLMq-7rxBL4v-OUmK4CSTYn3_tSpzaU2e2b1hcJGIM_1s5VEYpixwH4U53CRNeUhhVy1V-BYrr_Wb34eAejYIA-G08ztHz5NxBQlfS849jNif5qihO-6pQDRN_gTYZ4pv0uAQzL2A2gi-jBPqTI7ES1hkX3VYfRBgJ33-9_y-fcBIH-k4RVlbg0NZ_Gy_umTc_gRYBocIZrlXHfYyyCHGQvkUpK3pFXrggB4B4YCfMrmWGwze6iJk9A0-jFBNnFmkglwfF8ru9PeHdK-Duf-lkqx70cRyAOCiWk55EwfTaXM80zRCvef6kG77mppK_2MhvWgsqAqqyRqgv8xUUwiO658UCjaeuOuAf2m1EsOQpmqcqEueuSHRW3JNajKPRE47K4Mq1bAZ1yL-hDTLfYQ',
               // AEGIS: V4, 3 LPS
               'AqjJe0x_GChxY-Z9bt2ZSk0-PUIeKoCoLUBleSCPp5gEAHUCAAADAKz1zLmRbFugjv3u5xN4k2H6Lb_WGPeRsBX-J3n4_j8VZwA9BPGMfnH2GltYCtKqMuDIEAAiIdMVRyGeIb0OpQG1_NCGvTVzdWwTfjq9vAR9g1cfm9Q6MDxX3p2TS_EKH26O4SOqwrmilRV6Qyer4Tx7NTUpMaJIXmD_j5KOh3P_nkfZ1IAGYj_nUfDaGTaW7_fao1udKaxlTSj7M-_-mRZ18UUEvEazOwrkuYFBBcur8y-k5tKLZSfhjeODD4-rup7rSON2XOvaX_FET5S13ga-DOluX7ITb9NJphSW3_g1l7267iLrmFOmVO3XBGnenPgeUl2D4aadSHfzc0iIkLIWs8WOe54LAwAvbJFMupAC-NDCZ4_OamDb4OwLq81AXnMXN1g5fifSn6SIWArQ9oN4j42y7CWpow0UfB8ansFv5F95rpljGrLJkKg1oEetP1U2YZXreSGo0seSoEFB1KlKojI5YN9UC2GeiHpzbH0dSKhhzVShJWpDG_NRNV9M-D2feNZ2E-bhsM747euXpGymFXZIxYTksF3dzQ50tJbomvLdAGNau8wS5fFDIptwK1C9p6OwZYlPWhCPs5JhBMOTdbeGvfV2rvx-fN5BTYT0hflFe-Or2YjX_jAI1YCDqYM5TxaS9XGKhqfFNYbXyexbB3V7yx4w4QqP1_NwnTn9WEsCJhQvRhBoQPYqHAJTKiaMjcCLmXMeNDDwb_5oHCJY-LTY8n0Ifn9safDdSKLnJMCypAtgOuk1ZB0JtvX7KzNisy-Dd8iyAIpKS89Y5g1sxfpXZQ8frAJnL6-O-Dcb2QU4oW3Db22JjVL_2L2dVHCwGw',
            ],
         },
         //v5
         {
            ver: 5,
            cts: [
               // AES-GCM, X20-PLY, AEGIS-256, V5, 3 LPS
               'fr1l3aTIL4-4O5shIllF7cmgx9JZ0iZdIHQLLDc71_sFABkCAAEDAI436nhP6Y5r9CQJL4ny_B9y2tylKH2ZxSzdvN6uqxoFG8CP2YqVB0vbQ46sdRAkheDIEAAiIa7leKW-j2vN4CT31z2cAH3bm1ddjQ9KPfKXIKLds8gJVy4UPbA8mQ_SKDLARhJuReb2SqmKU_17X6_nWnScIIPBMBvoOWdul0jb2cBlioOZ968OipMLRggD74pVeegvePLzQhTQvBZiyqOyRkta7tSfiwY6Pqb8efej-T3ItJ2q-It-NQdnloZBrThoP9Lh3hJUt5OwMgFrhTMy_5wOYDI_X8t-kmnfSKt8BdQKoCG-tri0Xe2OVN9_ae2u_l4bvE9-GkTjvFCw3l_egIYjYRAmBJTWv9SnIAwXDuxonTHMiw0QO3x0AYCF9rJ1Lu2pSeLZbL8ke8XUFqfULTlOiXb4Xc13q-DWFhEYNHz2go6zBmXg3dElK94mv2f8mfZyA5psvl4Kte5BJq9G4uJdqrFkqX7Snx5i5AQhP4JISK_3xCuC0DNNAk6fG0ARjMS2zrRbfjVwyPY_vw4HcQU2JhYqsgsRauoBABy-LmH3VUvFXkdvQi_lRPBD7hVqu0ZKjh0k6ZypFR_nXo4zwoi84IAG_527NCevoxgGqBvEdVaUL8-XjcJhxkreysrCFYSTYdhA-6qbBPgkoooSMhFwZjN-qku4lqKo7KIIIeGO7HT7XbyxldZN6pm4Q82gecrAGYs',
               // AEGIS-256, X20-PLY, AEGIS-256: V5, 3 LPS
               'hV1RikjDpxKuimJkPcHs0ZX95pPW6LHIllYhoMdte2YFAE0CAAEDAKvbjrnfg3VDgvnILDZKbIaUGxMp5Iv9JYYr09KEhmQGVgyB62xjoffJabxC5zz3FeDIEAAiIWrG6htNwiOOBXfZu2IUwQpMiNqQVR0GegoX-aESZ1gppQNKj-b63ucKTaybnvSeiqExW9rsGFYxOz8u5qLH15_p2qZsNO-mGpc1wylR_Ge-aXaUF9P1bZn9AAMOxX3q2dtP5ey7bA22SYe_JeQiDPBGAvfzAk3WJ5GuHPmGzc3yoHZXmMMxSm2tytvJy6fEx2TkktobNnhI9eAXBxn82xX-rmM00djST2LAZQZG_SSQByzFk5rZUGLmhomiZz-SQQdVZDY45BD-zjNqj0jSGXAr8vKKwXPsAGKIq_uK7Gr-G4uw1_kkI02yu1AQjb3Jfpc8AvkD5KJ5V1Y42CSkmf07oMmrxqJ0QSGgEIxS0Za-XNdsDKJP2YoggGnRTW__EEp15xnnqwDzPxFgvhMBdCN4z03ERPy0rqTSeSYnY35ag6OrA9cBYD6kEVMIi-VVSErsqJCDNmq0kqnM2FBMFFCCVOT8pasoRtQuzXQzaXZiovmceXsGUNeMgU38AnYgYjUtYhNonYnHw-A3LsIYvzKDtshJRh1qekNqBMdycFrkxF405nEJe6kdyiaxKajYkjlXY9xbSt-AK3_0MWNNB3Adr_HiO9IQaj7hByCqQgxbHm8aLM2oK4KtIxNEE2AWSZ8xSpBrj2naCLNg21zo9iYfHytX8a_eDvTYIi-zwoh7725S2RkqRuRUQYPhX3RPhVzqKUfq',
               // AEGIS-256: AES-GCM, AES-GCM V5, 3 LPS
               '5HrnYQIAB6OTA8HO27AviugsbVz_otVhIU9SUGfAKN8FAA0CAAEBAJyuTIwejjoTJAMKQ5jI6umcC7Tdy3KzFfKF4qDgyBAAIhHh4OAHh7b9A0cRZQqcwvP_Y7xOKHQzGn55oxKi0YuOXtser60NoJxoMARtP0Pe-8x9aYT5T_Ml7d87zxZXfFcMk2MfOYLPpUZO6rHKZ1IXIFbrzW_YlVTgLwUwLYM01tmr9gg17kz5D1hTKRXxJ5CWq6nu_xlXwsi8Yo44OY6Ei1hpSLF8xhw1-w6oz0DRSqUedXlo2Y1KBj7e0rLBnW1WLnnJWhwSvOOaX6Cu7qslwBRQ3w12bxGQNIJLpbcw6LriQ1Tf7iBI6vmDDpSFN4r9zvJomyB2RqO9eTa6Y4u3yDrdpBlujw8LY3c0DSA_1SSkVKinYucKhNYWtwjSD9hCE-n0qgRcHZYLZB0JlyFv3on9mIdMhRDH_4sbs6b-car5nqzXxTIaoiDu5la78Y_gWjLRk7nCTONVluVHlk3pf4tZ2pf5C9SRC1PrH5q7OVmGDWhiHIpL-9twubrjB9e2_UQa2QZsVLiMdeNpmzeiqQM5maGIVFVi9AbE8q2kq8CqeHHu2YvJuG8Q2fH2RIUb4DCT-FHvyeLPl91k1ADw4JFtrHSwMHC1fxj3ZqIRic-f6MNEoJDm5ROV9O_4V77RMX3NqpSjQyxyvOk3lmaO7au-mJYg6txDqKlSeQXoxcLV4LG2Tdhj-D4',
            ],
         },
         //v6
         {
            ver: 6,
            cts: [
               // AES-GCM, X20-PLY, AEGIS-256, V6, 3 LPS
               '4QB_HTME7CBlOtrq2oRKtOE3coA7F-rrFnHDGaztkAcGABoCAAEDANhmAzoORQG4Mfk00xuLjYaw3ShiY8tN2vzIPEdjpwbQVBaIL8GqsItRagyVmcFdwUBCDwAiIeXZuPSfuxgRb0E-W63eGZ9NZ360gPsuUU8W1dC8JkUnWsKtIgiBHSuHKV2gxXx3w0Ev8oyMrzqBEx5FERu3FTzk-bB4zmYoqhrnY6Y6F8HzeNqQSuJ4eBzmsvCY6nSb3Z0GmkUyG4xR-eFzPICOJdZGWdkWhT0penWoqM4EFnf2Upjda-R0hivSgwSwUTNhO1H26NzidOOAvMfczZVnIhVWlxCvXp9adhhQnjMPKiAVDP7zPxkMtPUlWGhGT-TESABsaa8qYBj1il2l-LRaxk22sSSpxT3VB5i32x_qcUbXrZSsHdWl0NMDb8z8Bfy-SlAhyxwK8S5XrboUp5chDixQ50qSOaiIOAaf4nP-JKFOLdw7DO7PMfRife6oXCO2OS7iVbHtFE1phEVCfys9wyLzZFbzAzB68yoH8NMMU6_p7XAiS91VDbCFtSareVvtlMeSeImC7jNhKfiHtflb8FGl6xjT_lxSTxEZvnCYe1JUJ7kd8od2w8tYWHcTaMrJ0jxHIKNB_zaRn5yZl8h4FX5N-Ex07Dfjddh16s1JWgN_nXi-lVP6utLBGxC8E_1SDTg2SMzjvTu5BkpBbw3xRf0V4jUU9n_NGMk7AP2wCYT79HiMZ3zj4Ac6Ak8h9hfIbrg=',
               // AEGIS-256, X20-PLY, AEGIS-256: V6, 3 LPS
               'w7OQx2Q88GDQ4ZmXN6tPkx7Yst-Veg81ujZ-_Eg4u_IGAE4CAAEDAMOP93rYo71KmzQ8o2Vi_ld3KdaGvgIqnG4dAAO1c2Yk7WLwZtROssHxCL93eiwPSkBCDwAiIfqwWUZ3l_u5DIYKlFTpurpijTfON-fY8TisKu9y2MlGw1IGCmHebVFFCmhhwmBPhMJ9nDyA5qT99EfKtyNadC1Vjr2kAXh94JiE9JEWLB298vb583GCJodLrstiU3KxlFALz4CF8Wnk0jdhSKL4L4uIhzMMul03cHaeXIQCf6N_KHTmyi6uBu8hz_iVUq8Ia2zqBACa1Iz5P2AKPIUjvX_qsARY_vFkqOgsYbNRmabSwONmjuS-fUa_mDkupH2KG6c2lbWHNs1kE7KGzGLZ21XFsNWiojnveu0zE-IHcVIK1-lymTQzN1YoKIMKdBM_mznmS5mDgRSQvXeo7qlpU4sxn3-_qP6ZoiaKzbqqKGh0_NRNjnUd8G8GzQuQfdWY4VmVHxLrm9yJcxPbVD2GBsqmIi1wNkSJW0PRbMAsLMbeHRwJJ0w0DsjodngjvAl9D66tZSa17x_XEQlslDprbcR4jfsYFe2PSAEDUT3a1HndlSsuXHsfk_ZolC86rAxTdVV9VZi8QqcHZ7nr3AR9oTz5H66QmoZcmJlUTNpfShPneF_EzXx0gGH6DjOtfrWjKD6iW2oJlpnXqMvWla60w5dYYUG43TQmoHSjb7kUqH1PtJjcsZbz4egTxrkNxvrLJGK9r7BpRk819eX5_zTlH4X3O3JsFmWK4lT6hlpW6sw69SXVzFrMxdHBJEmqF3VCk1NqUazr',
               // AEGIS-256: AES-GCM, AES-GCM V6, 3 LPS
               'S18WntQoRGYoTy9W4i8fuPPjKbwWUIFBbnSpBUanhLAGAA4CAAEBABMOsbaYDQFYF1taNhZq2S208_fs-vCrT2EUJkVAQg8AIhFcpOTEGHbFby411jzaT54UiYB7muuIFIgZNxIMzEyyI-Rw4ivyQiqTNv9L0NAt1K-oDAOa2OM_yN5picketRG6-4hLpgZiEhdLQEDqQ_zHIsW9VnO1JNPlZ7c_Aa4JIDMF3NqGcJnuATkDI52uDXlqpQ9qk52DB0Y37qHaHHqYyI2kBgdMdD9tWHpCNrm63fXOOSKfOE9FRxPMmZeGWzJIOhBwQ0OGAdBCUDKsrP2rADgwQcpW-5SU4oxwsWKhoMRueAlbK6KLHTVQc8LBybqUvUI3g7PGtOU0RQOkD2q15F8jGJkog8nqlNF3ZMG3Y3DM-gC45Fx5p_4k5F4B4i6FZFFYOEHJjhPV38xECb3X8mdInAZ88bhthHW-IlrPEmI9Tz1F9_qABS0tO2wEeTs96pTyDKH1Y42sL9utaBNA7Es4-_SIRUmr8aPDW6hCCpg-o2-Snecc7A-PlxHzFm10j7BB3Y5iLcaQScUzJ-ONpx4GAJzWP8tb23zAH_zeJTmwbZ0so3OTwfS07SffFIuyrdtvBWGZarCY3eTwC5URJ5RvOGs-_NWewGC3jn-UNW_yVEEl8tAFeah3db5ljunTx2DLwnIeUPAGHZpQh9bjq7c7BE1c8S4my9a3yqzLgB3ASRezSrlGZBg',
            ],
         },
         //v7 — generated by: pnpm vectors:ciphersvc
         {
            ver: 7,
            cts: [
               // AES-GCM, X20-PLY, AEGIS-256, V7, 3 LPS
               'bW5YYg-qHhoZhi0MhNHFmDStdNfvAQ2pSe_484BI0qcHABoCAAEDAOmEJZgGdSHGPau13MHYmbqFLv3YekzXFZ4jtzr3_5Se8iLjsiFkYhpB5NXXOwdbmKBoBgAiIa_kkcWHPO9tMB5UPCw4f-E-MyeWQdnT7HFHl9k5uh8GaokTduqfb1vFJyZQnu3VLHJL0Dv00xBAQCJZ6TQAXHOzphtYFr_0yhShai5_IEomxkHaoqpQUC9TrIFwQxxAmpNssGnSuCltC401D6QXdAJswKEE4qfg7sCecQ6PqfULNcDl6HQt-wumqEFTQcjFqtLeRw8aRXQJRPk-TIG6V6zZTcCLelMPyJ65v4YSQT5je1DcVLELHGsOpKNgwyVXOcpN8vW1-vTXDOeDZiwtgSleZHzkDPRGFyf19nV0Bh1rA0mRI2CS_sPhrAMSz5leMxw-MOiJs2XU5oDL_dYmxZpl-D55ibfz-idkN43IlUe3ucHBwekSKuibgJelrTiK7K1Q3ug66OzgS16ooq0I4utBoQnFfliKuF9J6juSBRhBWWERoFXV1tcE3rqB16rJSMM63g_Hgh0WaxAhTJsaPg4QPAIAPZza6FxB17gAL-CXsWVN4CMaE53uEcmeC1mZAxcJJZOvchfaWnwh0IrNJicYBKm64I7p3DK7D28bGwlaErtnZRFPA8AUiUqLbT-SDdmZgy7nyksvvjX0qJmVPpBLyv8NbzZBI34AMf5zA7MabDotrozUd9xj14tEnT3KZIY',
               // AEGIS-256, X20-PLY, AEGIS-256, V7, 3 LPS
               'Wq1VyEMSONIxufoMNQoenS2v55URpcsm67HODCcTyjgHAE4CAAEDALs-g733sIwHUTuKCnpUtxAxP_Q6T3s9JIhNAzz6--cCBtTLv7g-p3FvJPYl47Uwy6BoBgAiIeSvz_ynIv_S6f0ukxo7JUrJ1Ox-raj8mE1eBnH_NPPvOQlQ_BSLN6lhtsjxl96mbZY1nvooJNyr2731uV9wPsxw8Tch0kz-h8ilV5h62JGQ-wSd4z39LKVUqnRtRDA2zyb2NpG30OLdXaf85W27qocrXhA-iNBT86211HIedk_pameXibYR94ZxVTrah3H4I6v3oGEqIjC78TId93kclC0kTqcJfznek905zOQeARLB35mOzx18MxlmzvLKjsCb4upTAwtDBe7cBok5KcOXxtfGYj4jLNVAaWOUqYRU61ZVnRC-0mvUnd4j2K7cyO8yS0svu0TKlyV9ifWnCyZ2ykYvwag3Yunfp530gpntTDEUci0pFdEF9SmJyNjeMMwx2HJOyl8TeNNvdm71T4jLJmIvASrx_EB57pJvUamq5MlePl7hNIJyoprvuf_Qr1MBLhrxLXeL6hsFwNccKwPl1VyXphvGySKABgUc6AObArDMQd1zwijynj71H-XQmyjJz3NmqwgFBdVmYqB60NYO1-7c18VqfwZQLJNfN2PRuz1KCtT_vsugD9liiVS4Gbc4sT_p5GIs2KHD9mfvlnMA4Xv2-O5i9aTtEPhLxZQcI5eo0RebXIbcbQ6JO39To1uwi-XHJ3XH5uhLZh69D1ABtx0xdZmcdR0P5cmZVk-p5xQh3N72aAedqWRuVz4J0Yx4nv7m3ypZ',
               // AEGIS-256, AES-GCM, AES-GCM, V7, 3 LPS
               'bohW5wF_wYRrdONEPgP5qx7XMCvPz-SOPf-YQOMlPP4HAA4CAAEBAIWx8SmclCi1j2jipWgqTV-K9KIyM7uvwalFr2CgaAYAIhHUvIztBIjPG7f1UPgcRQoFN_lAcEZYhWsQBCrlYVUlRDgC1mQEIw-dMJGD1fMzlUVQZI1VeM4zuPXm_nntdTOGOcCZMYw_j2xs3ocNEIgqPmVi8lsQk7KMw-w5JL69iu7vjvkdsNY8W25QWTnMRn5r8XtannAY7qlK-kyDzhsIME0zQuLXhFvLfUP6gJFuYebCW8-bJNRgXq7gP16xNcahkWh_lOhF9cNFXZhiBe2DhQaZ-CMu6pjH4Wlb8nWQYhybqrIOYNt15wDScU0nZg3ITvdtzBpJ6fonXsTjQiXHV2oxsjPaWZLr4CB8gqKEpYUc8RsYePosqMaqS2kx4XSRAcn90EKBIe5oRWuExEPWobl5bffl48zU4Ol4wHB8VPrcW68vAoRz1TGsL3jEd-snRXTeH8oehBySKJxqbcEcd6hMcODe_ot83ql0m2z2YNvzm1CId2sjzRwL2NsveOgw3EsmiPzRdVvVReigZn69253NjSbDEWsIWsb9hTkhNEql5sUv49EJ0tQIXj6OszoUdivcrrthobVMLAjgPnc3CPwrdh_3a4o6xoeiOQ-VcKs-SRRqfOfEwbSaSPLjduoMcrZ7BFD4nAkOWDzNSQakoBDYG3_HFcHThL6kBc3bmVnQLLQa43-9uic',
            ],
         },
         //v8 — generated by: pnpm vectors:ciphersvc
         {
            ver: 8,
            cts: [
               // AES-GCM, X20-PLY, AEGIS-256, V8, 3 LPS
               'JLdbhR76xffY-UVX5VUDF-Eo7IFKk00CPv9Fni9z2wAIAH0CAAEDAHutGGQmBsOQI8XMdTkbeWIS7ur8TLg9uTNWUFm5R-D4EUlWhjh35g3rY9aasEL_y6BoBgAiITYHvFyRtGihdep_1fkio8LnL5FglxijE4hSzkuXIQ7NBiDFY_HewYckMZtCsq6DxCCopdGV7lCMuw2SASRD2hDWp8aps-gMmDs9zJY6qtHOEh-xyBqNGai3RwQlj6zQn-cHeK5kPr2k5iWSpyEh-RbdA7enHWAvkRgn5ZtQAUqnVJEg9vaPjxMW4XoZTpIx0Uku4FZrD4RYXjg-o91CmEEvyvaNq1m80AnUOeMiWMCzBTXwkEY55MqXFRGrb5ObhiHO-h5iRVVz5HYOYw61sz2-fyCmOAiLW80XhGQ8F8du8ag5uqzu9oEyvrShnLuQWPqS_Er6daraPBPNMjk0Ywv0Kbb1d4aEAaNf0aHQN7TQ_Jygtu48A8-2crnOTP0QyCSzOfO3I0wOfJ25RE_NrL0s6PRB6oVt7lChmp3EHM-zMGjgesSFq-oyB9EKf1Gtj50-GYgyBzhA7bRI71VGjwOcLCxNb-c_j8ZdKsKwahMzZKdPthc6AzfFdmZitkl5J7cM--EhuvPkoUKkhHtqnWAEvH7tMtJXfXBrjDbeeJzo_1dG2Utir2z1wBQ9V7DD5U_JRTxY22VCFs_CVJjDpMnDC9-rSgCgCDP-YvzjafIyo_bIPKWurMWpmmQmpScHyTBbinqN6DAouxcFl6ah2RQrRdeMX0GPR_ee3w_x7llg4h7eUJjcWN_aVaBhdrK6PM2_idtLZoIYhdvU5pYZCVSqM-9T_EssCOEnRO8_k5e9SeiXfbGdM-EqeWn--UP777roba8',
               // AEGIS-256, X20-PLY, AEGIS-256, V8, 3 LPS
               'A2wW2j4vX4oHlVH-1L53SuCuG53HsQJxNZLIyGV7zoUIALECAAEDALb2-dGk7raPZ9So6MDXXW0EqRdbSTmt6o0S9UcjH8NFjbm_cq4Cx_IXov3N1sv5hqBoBgAiIZAxhDHe8w_zpp-6JeRV5GiMAL-4T0e82oOcXi63Sq0LHyCmkTxd8Y0ke6nNUnTmfD0nOjO4gVmcC_aDxFTUTfo0CFYLpQ01iWXBpJCedE2KDuLFBpy_Fwrhzli4HFtMpS2Kw6A43TNH0vsVzH32AS1WBaRdupECR0fJ3DsX1ndw3_mM19lwge6lVp9qVeFCwA2rAfhfduJ3-IHbIMTLz81JyIB0iqwAO85P7wrQEQ3Vo2VaQ7s3BZEpIEusBUWJSZJBKDdvI3HLxipTHOhQSAFMZcsYKERvf8EecgkBWYy-TG-U-A8sVVuotVcb2BTNJqGoI3cRxNTPXfbhImXPnDhPJhPWxTPL8vSG8ROaDKyOIhF1aSxAZ9JEInztBtVvTyywQMSZW1XAs6l1lCsSoXCbOqAybLfhZ5w2D_RdKV9Myfwb_h-fhB0I_TN6yVVm7YXHlLKH2wK75gkrJVGqjbe221zKqBVkGuoRg4ISxnRqIAYkRBgiD9GD-fPU2TRiJZWS4z2Do3wPSRaGAOYYJq2RHQDjOOg2ecJjxNnVaksayTRTiQ924smoapd40Z21sxQTzhz8L-dlxLxuIPnaP9Qh43IR4zHhKVPyE7pTY6TRZgSKimgbUbUcNA_8JXgvBdpYiLa1KBtUNxr20XPw5mRWE8x0s_jjglEDloRBgkdPCc-4NptOZ3or7uUf_nnviD7SmQTnjrn4ZjraTwrU8VHEbYRPasqV9bP2yvGmkVjbqE6GANadS1s8-Y15yKw1oHhuwnk-5muY2fhyrHk1T6bDQI5EzXevZtVMQN732TyUECHK9MGumuTxB17xWRi2gAm5o3N7oFIN',
               // AEGIS-256, AES-GCM, AES-GCM, V8, 3 LPS
               'q87Vi68zWVEJZtCl_PWaxSdZvwwPy3GRKeGJpKzjF9MIAHECAAEBAHCJR9ssMKnmOxPwmfJb_bJ48wHPTMc9BJPKVECgaAYAIhEpwLj3Vjg1WBzHgon2KrJGJCAXbHf-rBQvO8NdG6RbfC70Z1wdhpnGh4zF3OVac3-X8JH9y2lOy5MccXE9rvy_5nFJMCeBD7VQ3uKn3UfyzPPYLdDlt7aSHP17fLSU0jFUWgvkJ5V4RQNVruLvhVviKps3ZIorfXxdKonC7KnJ0RiPzj-QkGEIrRyBOmhM5Rxu24AJTrXHJZPPieoRtOR-mAgdfMoU3P3NiIP5J-gN01-sO_yQTqpDoQB-krLU4B-Fw13j147B71ZijsxRf2lLY0kO7xTsQuAo_ZpCjz91P66pfi_0iKoAfQ7lPU6XWLOcZgb80afIKM4QUnrj6KyHID4Xe5ox82RR_sBia5VJxD-CxP2zmDO6Bk7iInVlG8NYxcq0XQm-zmDr3YxwxA_bX2Mj1Y6G-WchmXbo6ZZxgYF4EOkGjtfpG-oNBx-XoXeC718YBTGfcDxGyl3HctX5F7oD5yr2MNdvtabETUrHAlYpBeh_cqFE_o8HclDGLb8oDbl-5737qGz-Ev0XQu14-5Sooj8glLmUZtjT9OqE4C7YenqzZNfKWB62D6AQhtNmSOhM82uLsr-ssmtvoWlo3JXiEHQUrvokxUKuEuINMNuw7EgBx5K32ufOk2Qn7s6ykmos56R8VibKmrSkSn7pT14KGpAW0I1hrSpg9Jm0pXUMAVxAgiFw2RQ4RxKgwHLc1fpBNNnc9UJIBoDRGXYbxRqgpU4exqiEJYcyQCVUIlr2jabNLdRT-KFzpR4uIsHkTltbCJgBp2-_zbg',
            ],
         },
      ];

      for (const ver of vers) {
         for (const ct of ver.cts) {
            const [cipherStream, _cipherData] = streamFromBase64(ct);
            let expectedLp = 3;

            const userCred = new Uint8Array([
               198, 18, 166, 217, 14, 52, 226, 145, 164, 169, 245, 164, 79, 36, 247, 82, 135, 84, 71, 239, 125, 108,
               221, 48, 137, 177, 250, 178, 47, 110, 23, 194,
            ]);
            const [_, clearCheck] = streamFromStr(
               'physical farm bolt correct bee nonchalant glib high able pinch left quaint strip valuable exultant disgusted curved bless geese snatch zoom fat touch boot abject wink pretty accessible foamy',
            );

            const decKeyProvider = new PWDKeyProvider(userCred, async (cdinfo) => {
               expect(cdinfo.lp).toEqual(expectedLp);
               expect(cdinfo.lpEnd).toEqual(3);
               expect(Number(cdinfo.hint)).toEqual(expectedLp);
               expect(cdinfo.ver).toEqual(ver.ver);
               expectedLp -= 1;
               return [cdinfo.hint!, undefined];
            });
            const clearStream = await cipherSvc.decryptStream(cipherStream, decKeyProvider);

            // version ${ver.ver}
            await expect(areEqual(clearStream, clearCheck)).resolves.toBe(true);
         }
      }
   });

   it('detect missing terminal block indicator, multi-version', async () => {
      const vers = [
         //v5
         {
            ver: 5,
            cipherData: new Uint8Array([
               225, 67, 20, 31, 134, 179, 27, 202, 138, 52, 68, 42, 197, 34, 48, 209, 76, 235, 39, 166, 101, 12, 253,
               101, 237, 25, 234, 119, 91, 227, 169, 172, 5, 0, 116, 0, 0, 0, 2, 0, 53, 140, 213, 212, 134, 206, 178,
               102, 222, 97, 207, 8, 252, 103, 8, 64, 25, 112, 206, 146, 159, 150, 220, 236, 162, 203, 172, 111, 119,
               158, 192, 123, 81, 141, 89, 174, 126, 4, 65, 105, 64, 119, 27, 0, 0, 23, 138, 253, 130, 153, 78, 2, 31,
               195, 254, 142, 102, 116, 200, 50, 125, 8, 178, 151, 113, 13, 205, 228, 10, 85, 83, 101, 57, 149, 191,
               166, 4, 221, 153, 198, 0, 18, 185, 165, 203, 53, 211, 218, 24, 198, 162, 13, 99, 240, 249, 210, 255, 200,
               217, 232, 10, 187, 212, 92, 204, 165, 217, 7, 202, 6, 114, 70, 200, 221,
            ]),
         },
         //v6
         {
            ver: 6,
            cipherData: new Uint8Array([
               132, 28, 138, 123, 147, 127, 43, 62, 165, 146, 225, 63, 193, 229, 103, 67, 52, 78, 235, 87, 222, 81, 39,
               59, 221, 183, 97, 72, 255, 88, 246, 58, 6, 0, 117, 0, 0, 0, 2, 0, 34, 40, 133, 44, 12, 94, 228, 213, 26,
               168, 170, 128, 158, 80, 186, 10, 199, 186, 216, 165, 74, 175, 77, 14, 167, 87, 224, 153, 52, 15, 148, 75,
               171, 2, 77, 176, 158, 14, 41, 21, 64, 119, 27, 0, 0, 23, 60, 217, 5, 30, 103, 244, 158, 250, 216, 37, 3,
               99, 119, 58, 27, 195, 99, 129, 80, 65, 210, 179, 102, 243, 232, 235, 177, 129, 48, 29, 127, 154, 58, 17,
               16, 73, 65, 218, 12, 57, 251, 92, 205, 101, 8, 236, 63, 89, 47, 41, 190, 168, 125, 241, 136, 131, 63, 67,
               146, 42, 204, 9, 202, 62, 160, 22, 123, 154,
            ]),
         },
         //v7 — generated by: pnpm vectors:ciphersvc
         {
            ver: 7,
            cipherData: new Uint8Array([
               79, 252, 1, 70, 255, 173, 33, 62, 69, 12, 56, 208, 111, 160, 34, 51, 73, 165, 126, 255, 166, 1, 226, 90,
               154, 140, 166, 205, 39, 174, 251, 196, 7, 0, 108, 0, 0, 0, 2, 0, 175, 37, 7, 252, 150, 127, 144, 16, 50,
               60, 255, 100, 98, 175, 51, 28, 41, 149, 29, 150, 132, 174, 174, 213, 119, 32, 192, 136, 102, 225, 252,
               97, 220, 187, 118, 49, 202, 64, 34, 80, 64, 119, 27, 0, 0, 23, 153, 109, 4, 106, 43, 224, 182, 133, 69,
               188, 184, 56, 206, 91, 13, 13, 85, 246, 232, 60, 40, 74, 21, 192, 144, 50, 27, 37, 58, 97, 149, 234, 158,
               39, 71, 225, 244, 234, 180, 165, 202, 133, 69, 7, 47, 220, 87, 176, 6, 36, 97, 3, 42, 235, 31, 245, 103,
               25, 187, 251, 216, 212, 181, 112, 93, 218, 229, 105, 22, 214, 73, 205, 96, 159, 101, 203, 86, 181, 212,
               19, 221, 42, 70, 84, 41, 124, 239, 151, 64, 167, 4, 7, 0, 52, 0, 0, 0, 2, 0, 20, 79, 147, 9, 57, 234, 62,
               8, 176, 149, 216, 130, 119, 102, 124, 111, 112, 6, 55, 104, 136, 244, 31, 65, 113, 163, 15, 24, 151, 219,
               171, 197, 148, 130, 18, 82, 3, 85, 92, 63, 174, 119, 68, 223, 44, 244, 113, 124, 178,
            ]),
         },
         //v8 — generated by: pnpm vectors:ciphersvc
         {
            ver: 8,
            cipherData: new Uint8Array([
               225, 53, 238, 252, 52, 76, 78, 218, 18, 182, 76, 86, 13, 163, 251, 119, 125, 240, 202, 126, 101, 106, 79,
               153, 143, 135, 92, 146, 173, 16, 138, 112, 8, 0, 141, 0, 0, 0, 2, 0, 92, 22, 35, 136, 124, 105, 1, 33,
               137, 84, 239, 203, 58, 226, 129, 118, 79, 35, 210, 153, 251, 127, 198, 158, 217, 189, 30, 48, 37, 99,
               112, 68, 110, 198, 18, 229, 4, 37, 130, 149, 64, 119, 27, 0, 0, 23, 202, 211, 26, 140, 27, 208, 209, 144,
               245, 253, 250, 194, 149, 143, 177, 81, 66, 201, 116, 197, 217, 191, 144, 32, 96, 176, 83, 54, 65, 158,
               52, 48, 61, 235, 91, 144, 63, 125, 193, 26, 98, 115, 28, 235, 172, 1, 166, 59, 9, 5, 25, 250, 166, 56,
               34, 70, 207, 67, 26, 62, 103, 74, 109, 193, 205, 238, 207, 221, 181, 134, 24, 41, 30, 65, 171, 136, 243,
               189, 161, 1, 238, 31, 212, 244, 155, 141, 6, 174, 74, 133, 126, 154, 245, 60, 169, 230, 179, 142, 24,
               255, 42, 242, 49, 7, 200, 34, 69, 7, 234, 0, 199, 120, 4, 132, 60, 109, 247, 145, 232, 67, 222, 126, 106,
               126, 8, 0, 52, 0, 0, 0, 2, 0, 128, 184, 54, 151, 99, 122, 84, 39, 55, 205, 187, 250, 118, 174, 49, 95, 3,
               226, 66, 199, 68, 222, 254, 77, 126, 247, 100, 116, 205, 203, 17, 180, 217, 175, 205, 43, 136, 20, 31,
               146, 117, 71, 120, 236, 66, 37, 176, 184, 251,
            ]),
         },
      ];
      const [_, _clearData] = streamFromStr('A nice 🦫 came to say hello');
      const pwd = 'a 🌲 of course';
      const hint = '🌧️';
      const userCred = new Uint8Array([
         58, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98,
         180, 61, 166, 219, 54, 164, 55,
      ]);

      for (const ver of vers) {
         const [cipherStream] = streamFromBytes(ver.cipherData);

         const decKeyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
            expect(cdinfo.hint).toEqual(hint);
            expect(cdinfo.alg).toBe('X20-PLY');
            expect(cdinfo.ver).toBe(ver.ver);
            expect(cdinfo.lp).toBe(1);
            expect(cdinfo.lpEnd).toBe(1);
            expect(cdinfo.ic).toBe(1800000);
            return [pwd, undefined];
         });
         const decryptedStream = await cipherSvc.decryptStream(cipherStream, decKeyProvider);

         await expect(readStreamAll(decryptedStream)).rejects.toThrow(/Missing terminal.+/);
      }
   });

   it('detect extra terminal block indicator, multi-version', async () => {
      const vers = [
         //v6
         {
            ver: 6,
            cipherData: new Uint8Array([
               114, 105, 149, 122, 214, 68, 66, 254, 204, 60, 108, 90, 88, 145, 24, 13, 64, 232, 184, 211, 137, 68, 207,
               107, 242, 54, 26, 74, 31, 99, 61, 110, 6, 0, 108, 0, 0, 1, 2, 0, 38, 7, 93, 115, 159, 181, 216, 73, 45,
               124, 29, 242, 220, 98, 213, 145, 114, 236, 39, 248, 11, 6, 42, 127, 123, 242, 217, 57, 58, 205, 0, 255,
               238, 184, 227, 83, 181, 100, 188, 208, 64, 119, 27, 0, 0, 23, 154, 92, 181, 175, 144, 243, 53, 142, 153,
               165, 44, 241, 86, 111, 236, 209, 43, 164, 62, 163, 196, 163, 117, 144, 20, 60, 205, 74, 135, 202, 75,
               142, 62, 9, 135, 94, 49, 180, 28, 58, 209, 97, 164, 112, 49, 76, 42, 209, 140, 8, 93, 78, 168, 68, 248,
               120, 26, 49, 28, 173, 242, 51, 71, 237, 8, 237, 174, 172, 162, 15, 13, 206, 208, 202, 130, 231, 36, 205,
               62, 47, 252, 216, 35, 203, 182, 64, 202, 194, 87, 132, 92, 6, 0, 52, 0, 0, 1, 2, 0, 51, 173, 77, 222,
               222, 129, 65, 79, 156, 158, 88, 144, 22, 46, 77, 72, 215, 184, 30, 152, 149, 40, 86, 78, 225, 236, 11,
               99, 214, 240, 246, 48, 170, 7, 183, 213, 15, 213, 179, 207, 3, 190, 145, 97, 125, 81, 96, 46, 74,
            ]),
         },
         //v7 — generated by: pnpm vectors:ciphersvc
         {
            ver: 7,
            cipherData: new Uint8Array([
               247, 208, 167, 25, 54, 41, 232, 58, 113, 25, 173, 91, 14, 86, 176, 255, 56, 61, 113, 52, 35, 113, 123,
               124, 0, 145, 116, 79, 75, 64, 102, 45, 7, 0, 108, 0, 0, 1, 2, 0, 63, 9, 78, 140, 84, 245, 51, 189, 147,
               34, 228, 224, 84, 93, 109, 28, 243, 158, 146, 54, 74, 24, 178, 250, 209, 80, 249, 51, 50, 227, 238, 172,
               247, 92, 212, 178, 49, 123, 191, 53, 64, 119, 27, 0, 0, 23, 3, 182, 170, 156, 227, 140, 3, 164, 98, 29,
               206, 88, 192, 96, 61, 236, 182, 246, 17, 28, 214, 223, 23, 255, 130, 236, 115, 24, 7, 242, 151, 28, 103,
               27, 112, 24, 158, 29, 172, 180, 65, 235, 112, 67, 254, 177, 163, 117, 124, 147, 40, 166, 8, 203, 215,
               160, 171, 150, 171, 249, 53, 209, 100, 132, 85, 61, 151, 234, 82, 5, 165, 80, 206, 189, 175, 172, 195,
               168, 176, 171, 83, 191, 103, 63, 239, 75, 152, 21, 74, 102, 20, 7, 0, 52, 0, 0, 1, 2, 0, 243, 141, 41,
               17, 107, 90, 186, 17, 127, 153, 142, 253, 213, 23, 109, 96, 57, 149, 56, 94, 111, 237, 15, 159, 232, 213,
               222, 97, 93, 5, 64, 184, 158, 61, 216, 138, 174, 205, 129, 176, 228, 155, 245, 208, 154, 72, 148, 28, 60,
            ]),
         },
         //v8 — generated by: pnpm vectors:ciphersvc
         {
            ver: 8,
            cipherData: new Uint8Array([
               187, 248, 166, 219, 149, 97, 92, 96, 137, 56, 230, 252, 141, 220, 162, 40, 76, 13, 181, 227, 123, 201,
               45, 110, 68, 3, 106, 187, 64, 177, 68, 39, 8, 0, 141, 0, 0, 1, 2, 0, 4, 164, 180, 105, 211, 186, 149,
               182, 27, 170, 30, 44, 225, 34, 86, 212, 108, 161, 101, 67, 208, 14, 70, 200, 24, 139, 224, 212, 90, 79,
               250, 73, 153, 48, 240, 16, 158, 148, 206, 53, 64, 119, 27, 0, 0, 23, 25, 226, 168, 104, 152, 233, 129,
               20, 242, 9, 87, 171, 16, 12, 233, 89, 235, 207, 11, 249, 80, 87, 255, 32, 154, 251, 18, 78, 185, 247, 44,
               88, 44, 241, 234, 56, 63, 162, 133, 135, 94, 27, 193, 93, 40, 226, 149, 50, 246, 190, 104, 135, 174, 242,
               23, 107, 102, 7, 81, 190, 4, 243, 15, 221, 89, 51, 170, 194, 197, 2, 225, 41, 211, 91, 66, 187, 68, 47,
               131, 218, 98, 38, 55, 101, 214, 228, 105, 139, 233, 185, 181, 52, 10, 102, 182, 96, 194, 240, 179, 155,
               45, 171, 86, 140, 25, 96, 106, 237, 48, 216, 69, 186, 7, 141, 230, 73, 68, 28, 171, 121, 19, 9, 58, 180,
               8, 0, 52, 0, 0, 1, 2, 0, 157, 243, 20, 225, 195, 204, 68, 192, 139, 185, 100, 91, 52, 231, 157, 207, 11,
               153, 88, 200, 155, 69, 51, 179, 176, 212, 217, 91, 40, 198, 56, 35, 135, 66, 26, 254, 83, 141, 225, 184,
               12, 53, 81, 7, 197, 167, 101, 122, 210,
            ]),
         },
      ];
      const pwd = 'a 🌲 of course';
      const hint = '🌧️';
      const userCred = new Uint8Array([
         58, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98,
         180, 61, 166, 219, 54, 164, 55,
      ]);

      for (const ver of vers) {
         const [cipherStream] = streamFromBytes(ver.cipherData);

         const decKeyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
            expect(cdinfo.hint).toEqual(hint);
            expect(cdinfo.alg).toBe('X20-PLY');
            expect(cdinfo.ver).toBe(ver.ver);
            expect(cdinfo.lp).toBe(1);
            expect(cdinfo.lpEnd).toBe(1);
            expect(cdinfo.ic).toBe(1800000);
            return [pwd, undefined];
         });
         const decryptedStream = await cipherSvc.decryptStream(cipherStream, decKeyProvider);

         await expect(readStreamAll(decryptedStream)).rejects.toThrow(/Extra data block.+/);
      }
   });

   it('detect flipped terminal block indicator, multi-version', async () => {
      const vers = [
         //v6
         {
            ver: 6,
            cipherData: new Uint8Array([
               24, 212, 67, 36, 232, 163, 170, 119, 145, 211, 157, 196, 172, 177, 63, 167, 12, 22, 20, 81, 250, 166, 94,
               226, 132, 226, 253, 243, 133, 249, 38, 46, 6, 0, 108, 0, 0, 1, 2, 0, 85, 112, 249, 39, 40, 215, 94, 63,
               122, 204, 193, 102, 64, 65, 163, 82, 69, 123, 185, 109, 204, 27, 14, 222, 237, 33, 135, 94, 11, 145, 15,
               204, 88, 25, 166, 108, 158, 106, 108, 144, 64, 119, 27, 0, 0, 23, 249, 240, 198, 170, 184, 70, 4, 93,
               213, 139, 151, 175, 168, 83, 58, 110, 57, 141, 165, 35, 67, 130, 224, 145, 19, 200, 206, 7, 210, 27, 238,
               115, 65, 227, 65, 86, 173, 49, 27, 61, 214, 163, 247, 237, 148, 168, 221, 228, 49, 197, 130, 72, 232, 83,
               9, 108, 84, 44, 172, 115, 101, 0, 244, 178, 175, 216, 196, 5, 182, 210, 63, 180, 227, 122, 3, 70, 210,
               255, 100, 185, 98, 226, 215, 183, 55, 131, 223, 16, 182, 177, 109, 6, 0, 52, 0, 0, 0, 2, 0, 117, 159, 80,
               68, 25, 102, 215, 193, 132, 143, 200, 39, 19, 204, 47, 81, 213, 236, 77, 70, 22, 228, 220, 182, 58, 75,
               143, 225, 66, 207, 162, 138, 118, 145, 133, 192, 55, 108, 217, 36, 155, 122, 39, 41, 30, 18, 66, 109, 59,
            ]),
         },
         //v7 — generated by: pnpm vectors:ciphersvc
         {
            ver: 7,
            cipherData: new Uint8Array([
               38, 134, 51, 140, 122, 77, 1, 120, 252, 79, 208, 197, 95, 114, 188, 183, 36, 76, 94, 24, 37, 35, 242, 97,
               31, 14, 253, 40, 203, 231, 86, 165, 7, 0, 108, 0, 0, 1, 2, 0, 120, 154, 40, 45, 26, 121, 6, 27, 35, 197,
               227, 45, 227, 48, 209, 80, 117, 117, 44, 48, 225, 178, 31, 61, 180, 69, 198, 85, 95, 72, 210, 170, 231,
               68, 211, 128, 121, 6, 80, 33, 64, 119, 27, 0, 0, 23, 24, 149, 209, 196, 169, 182, 205, 158, 113, 129, 30,
               188, 43, 34, 217, 209, 118, 192, 93, 92, 200, 186, 227, 118, 245, 18, 35, 175, 50, 144, 168, 239, 139,
               165, 97, 219, 53, 253, 134, 127, 254, 18, 125, 239, 68, 5, 211, 29, 5, 31, 59, 8, 205, 255, 236, 63, 37,
               91, 130, 202, 108, 36, 138, 43, 157, 31, 71, 250, 228, 96, 129, 128, 174, 129, 153, 223, 201, 212, 63,
               12, 168, 206, 131, 0, 70, 201, 249, 42, 146, 155, 57, 7, 0, 52, 0, 0, 0, 2, 0, 245, 104, 23, 133, 118,
               51, 159, 231, 105, 138, 97, 70, 34, 219, 17, 226, 171, 123, 235, 156, 171, 166, 72, 65, 83, 129, 191,
               255, 210, 239, 150, 139, 19, 150, 43, 176, 195, 32, 91, 220, 2, 156, 93, 65, 6, 96, 83, 86, 27,
            ]),
         },
         //v8 — generated by: pnpm vectors:ciphersvc
         {
            ver: 8,
            cipherData: new Uint8Array([
               41, 153, 116, 131, 34, 70, 101, 48, 117, 145, 226, 86, 247, 223, 58, 95, 71, 115, 167, 90, 82, 232, 236,
               207, 164, 163, 102, 183, 13, 251, 55, 120, 8, 0, 141, 0, 0, 1, 2, 0, 115, 146, 75, 34, 108, 24, 175, 99,
               99, 108, 237, 230, 87, 70, 41, 102, 71, 64, 172, 202, 215, 204, 157, 95, 31, 55, 170, 108, 246, 65, 190,
               28, 121, 20, 156, 17, 42, 53, 230, 200, 64, 119, 27, 0, 0, 23, 139, 18, 253, 148, 185, 72, 86, 182, 42,
               171, 51, 87, 20, 160, 93, 11, 20, 192, 106, 245, 246, 154, 60, 32, 19, 66, 122, 192, 132, 60, 253, 235,
               24, 9, 59, 163, 90, 54, 92, 62, 101, 245, 107, 137, 82, 148, 45, 156, 74, 4, 21, 243, 4, 232, 233, 86,
               187, 106, 184, 177, 247, 112, 150, 187, 62, 2, 238, 107, 44, 40, 152, 54, 41, 23, 171, 26, 206, 145, 74,
               67, 65, 244, 2, 46, 50, 3, 42, 172, 211, 10, 229, 96, 180, 108, 61, 103, 15, 188, 121, 120, 47, 26, 70,
               112, 157, 223, 167, 255, 140, 162, 97, 114, 204, 187, 113, 174, 127, 165, 201, 194, 194, 173, 223, 13, 8,
               0, 52, 0, 0, 0, 2, 0, 164, 236, 241, 206, 127, 143, 191, 49, 174, 226, 218, 51, 142, 193, 175, 101, 120,
               149, 47, 199, 102, 37, 198, 147, 168, 200, 68, 239, 197, 14, 66, 14, 29, 183, 66, 179, 8, 0, 30, 186, 25,
               34, 118, 214, 221, 67, 120, 128, 20,
            ]),
         },
      ];
      const pwd = 'a 🌲 of course';
      const hint = '🌧️';
      const userCred = new Uint8Array([
         58, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98,
         180, 61, 166, 219, 54, 164, 55,
      ]);

      for (const ver of vers) {
         const [cipherStream] = streamFromBytes(ver.cipherData);

         const decKeyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
            expect(cdinfo.hint).toEqual(hint);
            expect(cdinfo.alg).toBe('X20-PLY');
            expect(cdinfo.ver).toBe(ver.ver);
            expect(cdinfo.lp).toBe(1);
            expect(cdinfo.lpEnd).toBe(1);
            expect(cdinfo.ic).toBe(1800000);
            return [pwd, undefined];
         });
         const decryptedStream = await cipherSvc.decryptStream(cipherStream, decKeyProvider);

         await expect(readStreamAll(decryptedStream)).rejects.toThrow(/Extra data block.+/);
      }
   });

   // using  base64-url alphabet
   const b64a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
   const b64o = 'BCDEFGHIJKLMNOPQRSTUVWXYZAbcdefghijklmnopqrstuvwxyza1234567890_-';

   it('detect corrupt cipher text, all algs, multi-version', async () => {
      const vers = [
         //v4
         {
            ver: 4,
            cts: [
               //AES-GCM
               'eVMF6PzrEgx_XjftDM_dNDQgVWEGxAMuh0tSPEzVmFgEAF4AAAABAI_U2i3D1Q2QkdYuJTW2foBDIGBT122M_RGcb5vgyBAAABQtwX__YvRYteI4K7_YuNFgWVirS-6iuULsadb2_1n4yiTbUE_PVjMCtSOqZcT9Tk254T3TdiOv0-WB',
               //X20-PLY
               'p5q5r4dV44AsP9pxwrwOK7uf90EynliXMqpQaiOczHYEAGoAAAACAMJWRiT0rS-ivexQXh-uqAZgWjQQT-vON15dSo6XwD3zs51ix2T3k8HgyBAAABTzx6m-vqvQYCQpGcaJjO-6PmqurA32TDa_Ibq2rtCsuXLAGbO-8DM6JjfJua4tNUOHZ1W1itDO7xJ9',
               //AEGIS-256
               '1Jnt7bRakMkdgo9s0DhbdA3RZgTxQjdpczG4bVqLtdsEAJIAAAADACkhdnd1jqoOrNpifLk1Cg7qUi6-j_0EBJyyTAvtSXxxZe2cMLuH14b8TGNIsFQ6L-DIEAAAJGmwNdy_5f7etj9t6Q1l9zwg1er2CcW4gk2AnVyzqZXvxZrq1heuiam-6RtQ4Wkx2NIUruYKnYah4IRKMfuRJVLYge042ICZneCwQ6Tg1cG8adP0P1nzEXcdJA',
            ],
         },
         //v6
         {
            ver: 6,
            cts: [
               //AES-GCM
               'Ro-KTigP7WqbNSeCeDT5yuMjIKFelo1c4mNKAeBPX8UGAF8AAAEBALIlz9UVTEzA9igl3sNBAZLqME8lR464nfQ4wQVAQg8AABR4pIbwIfeEHFZxcDjrQNYr4zha1RIzOoJsLy9jaMEx0RnTYy4DoFaxjMHN-acKN5bm6hnP0F3ALw8d',
               //X20-PLY
               'n8cmquHjnA6hWBN3fKi7pVubV1gtSUANgVxz4tfwvloGAGsAAAECAI_iMR3xE5g7tItxHqmoU6b9jCdVK8UUXg7AeWnNHdaHeXOA95lwiYNAQg8AABQTwpzuSG6H9n4m7fSkn9h64ls4nxwO7Hja7ruNfWuI8QWaVIy1map39Pm0F-wY1HFuu9KCwM4btVyP',
               //AEGIS-256
               '0iccnvyBA-Yer_7ur626xinuNSUivimb6SMYR5zWsisGAJMAAAEDAAwVFwpbKuzARYXHcaRN3oZFZ1ypFmUaW129_vD8i6Yxt81J2uCbtCnYQpGMW68fo0BCDwAAJIGfEG6HCbani4qkMSlgiV5oJaR2H2ir7PELn8ruJDjmk07BDCSzlAcUakQXuck-KCi6ySITkfffBojZrTSuLNRhruKhvcpDZiFCJPf7shjFmdIytH0lgHnZ9Q',
            ],
         },
         //v7 — generated by: pnpm vectors:ciphersvc
         {
            ver: 7,
            cts: [
               //AES-GCM
               'Fv-K91yKPdzpibV35WnE2-vDjGD7VSx9GrY67mtUm2wHAF8AAAEBAOKaGUxcN0Mitpp69NKXyKkUQh6gS-5OKILnxR3gyBAAABQjUqHLoClZSuiStaVs8l8r3jDtirfRGKZva-BXtKAJrBrM70EPbE85DytaTXqL66EtuYanpG0Y-ZKk',
               //X20-PLY
               'WROThcgDtkcLWXH1A2kgrigrQsaLmfDQj1vKM3rqOG8HAGsAAAECAPjjpvQTllWVVhcnPGL5X35Qx0L51ZYyDoGdD_3XsyBO0zOqBCYEpkPgyBAAABSFw9vQ5hfitgDogip4fpfJA7TPQu7VDRw3YGFdI7R2wQFD3SSzKgAG1pkKUsZpm8TxLgJ1ARp_wwZk',
               //AEGIS-256
               'WyO10aAUREegNRT5ld1_65EdVTvsDgu6ENINimrj9MEHAJMAAAEDAKi4QmKvgmVxdiNAFat-AGKQ2tqJZVclOB8SltBVj3mLAGulmaXuiQTZyQmnKw5eZuDIEAAAJPi_OXcaLoTMApdnHKon8kTcbFiBiwaEK92N8STM-6jdJPlGbdoOz8L1PLtMTYtndBKU5L_xSyZoESoIOd_vfTaP494uVHeJspcPqhxlt8NLSQpyp55arXGqhw',
            ],
         },
         //v8 — generated by: pnpm vectors:ciphersvc
         {
            ver: 8,
            cts: [
               //AES-GCM
               'y5qgE21td3TH9MrpET9hAJ0s2n_LgYFy0wJM76HxbjsIAIAAAAEBALhSl6R3DCJuRWRFeyYxU_axJ0_ru7wC9JOWGVHgyBAAABRUpMXD9JBc8qpJ12rl2CA4wHaL4iAPadO1jChZQy9NNdKNFpwNlI13YrlYNSPDD6sWBF6znHn8Mh_PjFY6xvLU7WVFAoctybxlW53_r7urg8AF3UswsSOo2Yhj',
               //X20-PLY
               'NbfxGL_PAmlifiI7WrugA5OKDJzIi7yb_VAfza8vOPkIAIwAAAECAO0WAZgyGZESlSdo4k_wutRrMyWlbaGlacDdnbeL0sIR7WrlgKOtsq7gyBAAABST8_PFM5uU13ZtPlms1Mk2fm_NgiAuz6X5yYU5TnXGaLa6aB4jImovvrDn281feEZMltVNyhVdEFB1Xsjnw5Gui_a3SGZuVcnzQlqLMzbuMaXb7SoVtbpMiMGO',
               //AEGIS-256
               'DAUo84JYyeNilqlABRrOAOnShfAI8CS_io886aRTxTEIALQAAAEDAPLegzFdtfjJRYber23cSAswW0LdgKGpBBYvZfjOXzwwGfc6Nj7X1dEKU2kSc7UAw-DIEAAAJHsKEgyYeqB5p1bsi2oujfz4dySkoUll4ah7MwGc9wa23Nr9oCBqK0auwB2RZNKzOo-fhaAV_T3GAMcT4FmrZHV0tdW4y9FVH8DQxelTXy1mECtnvum78K98PczrOXP1Tcb8pSI1y2BhyoIrbxIXsHaAFexEZV_15dLq4w',
            ],
         },
      ];

      const userCred = new Uint8Array([
         101, 246, 72, 149, 67, 228, 149, 35, 60, 124, 81, 187, 157, 96, 208, 217, 123, 147, 228, 60, 84, 214, 198, 116,
         192, 162, 178, 147, 50, 119, 97, 251,
      ]);

      for (const ver of vers) {
         for (const ct of ver.cts) {
            const [_, clearData] = streamFromStr('this 🐞 is encrypted');
            const [cipherStream, _cipherData] = streamFromBase64(ct);

            // First ensure we can decrypt with valid inputs
            const decKeyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
               expect(cdinfo.hint).toEqual('asdf');
               expect(cdinfo.ver).toEqual(ver.ver);
               return ['asdf', undefined];
            });
            const clear = await cipherSvc.decryptStream(cipherStream, decKeyProvider);
            await expect(areEqual(clearData, clear)).resolves.toEqual(true);

            let skipCount = 0;

            // Tweak one character at a time using b64o offsets (will remain a valid b64 string)
            for (let i = 0; i < ct.length; ++i) {
               const pos = b64a.indexOf(ct[i]);
               const corruptCt = setCharAt(ct, i, b64o[pos]);

               const [corruptStream] = streamFromBase64(corruptCt);

               // Multiple b64 strings can produce the same result, so skip those
               const orig = base64ToBytes(ct);
               const bad = base64ToBytes(corruptCt);
               if (isEqualArray(orig, bad)) {
                  ++skipCount;
                  expect(skipCount).toBeLessThan(10);
                  continue;
               }

               const badKeyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
                  expect(cdinfo.hint).toEqual('asdf');
                  return ['asdf', undefined];
               });
               await expect(cipherSvc.decryptStream(corruptStream, badKeyProvider)).rejects.toThrow(Error);
            }
         }
      }
   });

   it('detect wrong password, all alogrithms', async () => {
      for (const alg of Ciphers.algs()) {
         const [clearStream] = streamFromStr('This is a secret 🦄');
         const pwd = 'the correct pwd';
         const hint = '';
         const userCred = getRandom(cc.USERCRED_BYTES);

         const econtext: EContext = {
            algs: [alg],
            ic: cc.ICOUNT_MIN,
         };

         const encKeyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            expect(cdinfo.alg).toEqual(alg);
            expect(cdinfo.ic).toEqual(cc.ICOUNT_MIN);
            return [pwd, hint];
         });
         const cipherStream = await cipherSvc.encryptStream(clearStream, encKeyProvider, econtext);

         const decKeyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
            expect(cdinfo.hint).toEqual(hint);
            return ['the wrong pwd', undefined];
         });
         const decryptedStream = await cipherSvc.decryptStream(cipherStream, decKeyProvider);

         // Password isn't used until stream reading starts, and the wrong one is caught by
         // the stored key commitment before the AEAD sees it
         await expect(readStreamAll(decryptedStream)).rejects.toThrow(/key commitment/);
      }
   });

   it('detect wrong password, all alogrithms, loops', async () => {
      const maxLps = 3;
      for (let badLp = 1; badLp <= maxLps; badLp++) {
         for (const alg of Ciphers.algs()) {
            const srcString = 'This is a secret 🦆';
            const [clearStream, _clearData] = streamFromStr(srcString);
            const userCred = getRandom(cc.USERCRED_BYTES);

            const econtext: EContext = {
               algs: Array(maxLps).fill(alg),
               ic: cc.ICOUNT_MIN,
            };

            let expectedEncLp = 1;

            const encKeyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
               expect(cdinfo.lp).toEqual(expectedEncLp);
               expect(cdinfo.lpEnd).toEqual(maxLps);
               expect(cdinfo.alg).toEqual(alg);
               expect(cdinfo.ic).toEqual(cc.ICOUNT_MIN);
               expectedEncLp += 1;
               return [String(cdinfo.lp), String(cdinfo.lp)];
            });
            const cipherStream = await cipherSvc.encryptStream(clearStream, encKeyProvider, econtext);

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
               const decKeyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
                  expect(cdinfo.lp).toEqual(expectedDecLp);
                  expect(cdinfo.lpEnd).toEqual(maxLps);
                  expect(cdinfo.hint).toEqual(String(cdinfo.lp));
                  expect(cdinfo.alg).toEqual(alg);
                  expect(cdinfo.ic).toEqual(cc.ICOUNT_MIN);
                  expectedDecLp -= 1;
                  if (cdinfo.lp === badLp) {
                     return ['wrong', undefined];
                  } else {
                     return [cdinfo.hint!, undefined];
                  }
               });
               const decryptedStream = await cipherSvc.decryptStream(cipherStream, decKeyProvider);

               await readStreamAll(decryptedStream);
            } catch (err) {
               // Either the key commitment or the AEAD may object, depending on the loop
               expect(err).toBeInstanceOf(Error);
               detected = true;
            }

            expect(detected).toBe(true);
         }
      }
   });

   it('detect corrupted MAC sig, all algorithms', async () => {
      for (const alg of Ciphers.algs()) {
         const [clearStream, _clearData] = streamFromStr('asefwlefj4oh09f jw90fu w09fu 9');

         const pwd = 'another good pwd';
         const hint = 'nope';
         const userCred = getRandom(cc.USERCRED_BYTES);

         const econtext: EContext = {
            algs: [alg],
            ic: cc.ICOUNT_MIN,
         };

         const encKeyProvider = new PWDKeyProvider(userCred.slice(0), async (_cdinfo) => {
            return [pwd, hint];
         });
         const cipherStream = await cipherSvc.encryptStream(clearStream, encKeyProvider, econtext);

         const cipherData = await readStreamAll(cipherStream);

         // change in MAC
         const corruptData = pokeValue(cipherData, 3, -1);
         const [corruptStream] = streamFromBytes(corruptData);

         const decKeyProvider = new PWDKeyProvider(userCred.slice(0), async (_cdinfo) => {
            // should never execute
            expect(false, 'should not execute').toBe(true);
            return [pwd, undefined];
         });
         await expect(cipherSvc.decryptStream(corruptStream, decKeyProvider)).rejects.toThrow(/.+MAC.+/);
      }
   });

   it('detect crafted bad cipher text, all algorithms', async () => {
      for (const alg of Ciphers.algs()) {
         const [clearStream, _clearData] = streamFromStr('asdfh3roij 02f23kff 8u 3r90');

         const pwd = 'another good pwd';
         const hint = 'nope';
         const userCred = getRandom(cc.USERCRED_BYTES);

         const econtext: EContext = {
            algs: [alg],
            ic: cc.ICOUNT_MIN,
         };

         const encKeyProvider = new PWDKeyProvider(userCred.slice(0), async (_cdinfo) => {
            return [pwd, hint];
         });
         const cipherStream = await cipherSvc.encryptStream(clearStream, encKeyProvider, econtext);

         const cipherData = await readStreamAll(cipherStream);

         // Set character in cipher text
         // past ~(MAC + VER + ALG + MAX_IV + CHUCKSZ)*4/3 characters)
         let corruptData = pokeValue(cipherData, 100, -1);
         let [corruptStream] = streamFromBytes(corruptData);

         const decKeyProvider1 = new PWDKeyProvider(userCred.slice(0), async (_cdinfo) => {
            // should never execute
            expect(false, 'should not execute').toBe(true);
            return [pwd, undefined];
         });
         await expect(cipherSvc.decryptStream(corruptStream, decKeyProvider1)).rejects.toThrow(/.+MAC.+/);

         // Hit another value
         corruptData = pokeValue(cipherData, cipherData.length - 30, 4);
         [corruptStream] = streamFromBytes(corruptData);

         const decKeyProvider2 = new PWDKeyProvider(userCred.slice(0), async (_cdinfo) => {
            // should never execute
            expect(false, 'should not execute').toBe(true);
            return [pwd, undefined];
         });
         await expect(cipherSvc.decryptStream(corruptStream, decKeyProvider2)).rejects.toThrow(/.+MAC.+/);
      }
   });

   it('detect encryption argument errors', async () => {
      let [clearStream, clearData] = streamFromStr('()*Hskdfo892hj3f09');

      const hint = 'nope';
      const pwd = 'another good pwd';
      const userCred = getRandom(cc.USERCRED_BYTES);

      const econtext: EContext = {
         algs: ['AES-GCM'],
         ic: cc.ICOUNT_MIN,
      };

      const encKeyProvider = new PWDKeyProvider(userCred.slice(0), async (_cdinfo) => {
         return [pwd, hint];
      });
      let cipherStream = await cipherSvc.encryptStream(clearStream, encKeyProvider, econtext);

      await expect(readStreamAll(cipherStream)).resolves.not.toThrow();

      // empty pwd
      [clearStream] = streamFromBytes(clearData);

      const emptyPwdKeyProvider = new PWDKeyProvider(userCred.slice(0), async (_cdinfo) => {
         return ['', hint];
      });
      cipherStream = await cipherSvc.encryptStream(clearStream, emptyPwdKeyProvider, econtext);

      await expect(readStreamAll(cipherStream)).rejects.toThrow(/Missing password.*/);

      // hint too long
      [clearStream] = streamFromBytes(clearData);

      const longHintKeyProvider = new PWDKeyProvider(userCred.slice(0), async (_cdinfo) => {
         return [pwd, 'this is too long'.repeat(8)];
      });
      cipherStream = await cipherSvc.encryptStream(clearStream, longHintKeyProvider, econtext);

      await expect(readStreamAll(cipherStream)).rejects.toThrow(/Hint length.+/);

      // no userCred
      [clearStream] = streamFromBytes(clearData);

      await expect(
         (async () => {
            const noUcKeyProvider = new PWDKeyProvider(new Uint8Array(0), async (_cdinfo) => {
               return [pwd, hint];
            });
            return cipherSvc.encryptStream(clearStream, noUcKeyProvider, econtext);
         })(),
      ).rejects.toThrow(/.+userCred.*/);

      // extra long userCred
      [clearStream] = streamFromBytes(clearData);

      await expect(
         (async () => {
            const longUcKeyProvider = new PWDKeyProvider(getRandom(cc.USERCRED_BYTES + 2), async (_cdinfo) => {
               return [pwd, hint];
            });
            return cipherSvc.encryptStream(clearStream, longUcKeyProvider, econtext);
         })(),
      ).rejects.toThrow(/.+userCred.*/);

      // empty clear data
      [clearStream] = streamFromBytes(new Uint8Array());

      const emptyClearKeyProvider = new PWDKeyProvider(userCred.slice(0), async (_cdinfo) => {
         return [pwd, hint];
      });
      cipherStream = await cipherSvc.encryptStream(clearStream, emptyClearKeyProvider, econtext);

      await expect(readStreamAll(cipherStream)).rejects.toThrow(/Missing clear.+/);

      // ic too small
      [clearStream] = streamFromBytes(clearData);

      let bcontext: EContext = {
         ...econtext,
         ic: cc.ICOUNT_MIN - 1,
      };

      const smallIcKeyProvider = new PWDKeyProvider(userCred.slice(0), async (_cdinfo) => {
         return [pwd, hint];
      });
      await expect(cipherSvc.encryptStream(clearStream, smallIcKeyProvider, bcontext)).rejects.toThrow(/Invalid ic.+/);

      // ic too big
      [clearStream] = streamFromBytes(clearData);

      bcontext = {
         ...econtext,
         ic: cc.ICOUNT_MAX + 1,
      };

      const bigIcKeyProvider = new PWDKeyProvider(userCred.slice(0), async (_cdinfo) => {
         return [pwd, hint];
      });
      await expect(cipherSvc.encryptStream(clearStream, bigIcKeyProvider, bcontext)).rejects.toThrow(/Invalid ic.+/);

      // invalid alg
      [clearStream] = streamFromBytes(clearData);

      bcontext = {
         ...econtext,
         algs: ['ABS-GCM'] as any,
      };

      const badAlgKeyProvider = new PWDKeyProvider(userCred.slice(0), async (_cdinfo) => {
         return [pwd, hint];
      });
      await expect(cipherSvc.encryptStream(clearStream, badAlgKeyProvider, bcontext)).rejects.toThrow(
         /Unsupported cipher mode.+/,
      );

      // really invalid alg
      [clearStream] = streamFromBytes(clearData);

      bcontext = {
         ...econtext,
         algs: ['asdfadfsk'] as any,
      };

      const badAlg2KeyProvider = new PWDKeyProvider(userCred.slice(0), async (_cdinfo) => {
         return [pwd, hint];
      });
      await expect(cipherSvc.encryptStream(clearStream, badAlg2KeyProvider, bcontext)).rejects.toThrow(
         /Unsupported cipher mode.+/,
      );
   });

   it('hint length validation', async () => {
      const srcString = 'This is a secret 🦆';
      const pwd = 'a good pwd';
      const userCred = getRandom(cc.USERCRED_BYTES);
      const econtext: EContext = {
         algs: ['AES-GCM'],
         ic: cc.ICOUNT_MIN,
      };

      // hint max len success
      const exactHint = 'a'.repeat(cc.HINT_MAX_LEN);
      let [clearStream] = streamFromStr(srcString);
      const exactKeyProvider = new PWDKeyProvider(userCred.slice(0), [pwd, exactHint]);
      const exactCipherStream = await cipherSvc.encryptStream(clearStream, exactKeyProvider, econtext);

      const exactDecKeyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
         expect(cdinfo.hint).toEqual(exactHint);
         return [pwd, undefined];
      });
      const exactDecrypted = await cipherSvc.decryptStream(exactCipherStream, exactDecKeyProvider);
      expect(await readStreamAll(exactDecrypted, true)).toEqual(srcString);

      // hint len > max failes
      const overHint = 'a'.repeat(cc.HINT_MAX_LEN + 1);
      [clearStream] = streamFromStr(srcString);
      const overKeyProvider = new PWDKeyProvider(userCred, [pwd, overHint]);
      const overCipherStream = await cipherSvc.encryptStream(clearStream, overKeyProvider, econtext);
      await expect(readStreamAll(overCipherStream)).rejects.toThrow(/Hint length.+/);
   });

   it('multibyte UTF-8 hint under limit succeeds', async () => {
      const srcString = 'This is a secret 🦆';
      const pwd = 'a good pwd';
      const userCred = getRandom(cc.USERCRED_BYTES);
      const econtext: EContext = {
         algs: ['AES-GCM'],
         ic: cc.ICOUNT_MIN,
      };

      const hint = '🌧️'.repeat(30);
      expect(hint.length).toBeLessThanOrEqual(cc.HINT_MAX_LEN);

      const [clearStream] = streamFromStr(srcString);
      const encKeyProvider = new PWDKeyProvider(userCred.slice(0), [pwd, hint]);
      const cipherStream = await cipherSvc.encryptStream(clearStream, encKeyProvider, econtext);

      const decKeyProvider = new PWDKeyProvider(userCred, async (cdinfo) => {
         expect(cdinfo.hint).toEqual(hint);
         return [pwd, undefined];
      });
      const decrypted = await cipherSvc.decryptStream(cipherStream, decKeyProvider);
      expect(await readStreamAll(decrypted, true)).toEqual(srcString);
   });

   /// hint should be cleanly truncated at a codepoint boundary
   it('UTF-8 hint overflows byte limit is cleanly truncated', async () => {
      const srcString = 'This is a secret 🦆';
      const pwd = 'a good pwd';
      const userCred = getRandom(cc.USERCRED_BYTES);
      const econtext: EContext = {
         algs: ['AES-GCM'],
         ic: cc.ICOUNT_MIN,
      };

      // 'は' is 3 UTF-8 bytes. HINT_MAX_LEN of them passes the
      // length check but overflows the AEAD plaintext budget.
      const hint = 'は'.repeat(cc.HINT_MAX_LEN);
      const truncatedCharCount = Math.floor((cc.ENCRYPTED_HINT_MAX_BYTES - cc.AUTH_TAG_MAX_BYTES) / 3);
      const expectedHint = 'は'.repeat(truncatedCharCount);

      const [clearStream] = streamFromStr(srcString);
      const encKeyProvider = new PWDKeyProvider(userCred.slice(0), [pwd, hint]);
      const cipherStream = await cipherSvc.encryptStream(clearStream, encKeyProvider, econtext);

      const decKeyProvider = new PWDKeyProvider(userCred, async (cdinfo) => {
         expect(cdinfo.hint).toEqual(expectedHint);
         return [pwd, undefined];
      });
      const decrypted = await cipherSvc.decryptStream(cipherStream, decKeyProvider);
      expect(await readStreamAll(decrypted, true)).toEqual(srcString);
   });

   it('each encryption gets a different init vector and salt', async () => {
      const srcString = 'This is a secret 🦆';
      const pwd = 'a good pwd';
      const userCred = getRandom(cc.USERCRED_BYTES);

      for (const alg of Ciphers.algs()) {
         const econtext: EContext = {
            algs: [alg],
            ic: cc.ICOUNT_MIN,
         };

         const ivOffset = cc.MAC_BYTES + cc.VER_BYTES + cc.PAYLOAD_SIZE_BYTES + cc.FLAGS_BYTES + cc.ALG_BYTES;
         const ivLen = Number(Ciphers.algIVByteLength(alg));
         const sltOffset = ivOffset + ivLen;

         const [clearStream1] = streamFromStr(srcString);
         const kp1 = new PWDKeyProvider(userCred.slice(0), [pwd, undefined]);
         const cipher1 = await readStreamAll(await cipherSvc.encryptStream(clearStream1, kp1, econtext));

         const [clearStream2] = streamFromStr(srcString);
         const kp2 = new PWDKeyProvider(userCred.slice(0), [pwd, undefined]);
         const cipher2 = await readStreamAll(await cipherSvc.encryptStream(clearStream2, kp2, econtext));

         const iv1 = cipher1.slice(ivOffset, ivOffset + ivLen);
         const iv2 = cipher2.slice(ivOffset, ivOffset + ivLen);
         const slt1 = cipher1.slice(sltOffset, sltOffset + cc.SLT_BYTES);
         const slt2 = cipher2.slice(sltOffset, sltOffset + cc.SLT_BYTES);

         expect(iv1).not.toEqual(iv2);
         expect(slt1).not.toEqual(slt2);
      }
   });
});

describe('Stream encryption and decryption with customAd', () => {
   let cipherSvc: CipherService;
   beforeEach(async () => {
      await cryptoReady();
      TestBed.configureTestingModule({});
      cipherSvc = TestBed.inject(CipherService);
   });

   it('successful round trip, all algorithms, no pwd hint, with customAd', async () => {
      for (const alg of Ciphers.algs()) {
         const srcString = 'This is a secret 🦆';
         const [clearStream, _clearData] = streamFromStr(srcString);
         const pwd = 'a good pwd';
         const userCred = getRandom(cc.USERCRED_BYTES);
         const customAd = bytesToBase64(getRandom(16));

         const econtext: EContext = {
            algs: [alg],
            ic: cc.ICOUNT_MIN,
         };

         const encKeyProvider = new PWDKeyProvider(
            userCred.slice(0),
            async (cdinfo) => {
               expect(cdinfo.alg).toEqual(alg);
               expect(cdinfo.slt.byteLength).toEqual(cc.SLT_BYTES);
               expect(cdinfo.ic).toEqual(cc.ICOUNT_MIN);
               expect(cdinfo.lp).toEqual(1);
               expect(cdinfo.lpEnd).toEqual(1);
               expect(cdinfo.hint).toBeFalsy();
               expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
               return [pwd, undefined];
            },
            customAd,
         );
         const cipherStream = await cipherSvc.encryptStream(clearStream, encKeyProvider, econtext);

         const decKeyProvider = new PWDKeyProvider(
            userCred.slice(0),
            async (cdinfo) => {
               expect(cdinfo.alg).toEqual(alg);
               expect(cdinfo.slt.byteLength).toEqual(cc.SLT_BYTES);
               expect(cdinfo.ic).toEqual(cc.ICOUNT_MIN);
               expect(cdinfo.lp).toEqual(1);
               expect(cdinfo.lpEnd).toEqual(1);
               expect(cdinfo.hint).toBeFalsy();
               expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
               return [pwd, undefined];
            },
            customAd,
         );
         const decrypted = await cipherSvc.decryptStream(cipherStream, decKeyProvider);

         const resString = await readStreamAll(decrypted, true);
         expect(resString).toEqual(srcString);
      }
   });

   it('successful round trip, all algorithms, with customAd', async () => {
      for (const alg of Ciphers.algs()) {
         const srcString = 'This is a secret 🦆';
         const [clearStream, _clearData] = streamFromStr(srcString);
         const pwd = 'a good pwd';
         const hint = 'not really';
         const userCred = getRandom(cc.USERCRED_BYTES);
         const customAd = getRandom(1);

         const econtext: EContext = {
            algs: [alg],
            ic: cc.ICOUNT_MIN,
         };

         const encKeyProvider = new PWDKeyProvider(
            userCred.slice(0),
            async (cdinfo) => {
               expect(cdinfo.alg).toEqual(alg);
               expect(cdinfo.slt.byteLength).toEqual(cc.SLT_BYTES);
               expect(cdinfo.ic).toEqual(cc.ICOUNT_MIN);
               expect(cdinfo.lp).toEqual(1);
               expect(cdinfo.lpEnd).toEqual(1);
               expect(cdinfo.hint).toBeFalsy();
               expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
               return [pwd, hint];
            },
            customAd,
         );
         const cipherStream = await cipherSvc.encryptStream(clearStream, encKeyProvider, econtext);

         const decKeyProvider = new PWDKeyProvider(
            userCred.slice(0),
            async (cdinfo) => {
               expect(cdinfo.alg).toEqual(alg);
               expect(cdinfo.slt.byteLength).toEqual(cc.SLT_BYTES);
               expect(cdinfo.ic).toEqual(cc.ICOUNT_MIN);
               expect(cdinfo.lp).toEqual(1);
               expect(cdinfo.lpEnd).toEqual(1);
               expect(cdinfo.hint).toEqual(hint);
               expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
               return [pwd, undefined];
            },
            customAd,
         );
         const decrypted = await cipherSvc.decryptStream(cipherStream, decKeyProvider);

         const resString = await readStreamAll(decrypted, true);
         expect(resString).toEqual(srcString);
      }
   });

   it('successful cipherdatainfo, all algorithms, with customAd', async () => {
      for (const alg of Ciphers.algs()) {
         const srcString = 'This is a secret 🦆';
         const [clearStream, _clearData] = streamFromStr(srcString);
         const pwd = 'a good pwd';
         const hint = 'not really';
         const userCred = getRandom(cc.USERCRED_BYTES);
         const customAd = getRandom(1);

         const econtext: EContext = {
            algs: [alg],
            ic: cc.ICOUNT_MIN,
         };

         const encKeyProvider = new PWDKeyProvider(
            userCred.slice(0),
            async (cdinfo) => {
               expect(cdinfo.alg).toEqual(alg);
               expect(cdinfo.slt.byteLength).toEqual(cc.SLT_BYTES);
               expect(cdinfo.ic).toEqual(cc.ICOUNT_MIN);
               expect(cdinfo.lp).toEqual(1);
               expect(cdinfo.lpEnd).toEqual(1);
               expect(cdinfo.hint).toBeFalsy();
               expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
               return [pwd, hint];
            },
            customAd,
         );
         const cipherStream = await cipherSvc.encryptStream(clearStream, encKeyProvider, econtext);

         const infoKeyProvider = new PWDKeyProvider(userCred.slice(0), undefined, customAd);
         const cipherInfo = await cipherSvc.getCipherStreamInfo(cipherStream, infoKeyProvider);
         expect(cipherInfo.ver).toEqual(cc.CURRENT_VERSION);
         expect(cipherInfo.alg).toEqual(alg);
         expect(cipherInfo.ic).toEqual(cc.ICOUNT_MIN);
         expect(cipherInfo.lp).toEqual(1);
         expect(cipherInfo.slt.byteLength).toEqual(cc.SLT_BYTES);
         expect(cipherInfo.hint).toEqual(hint);
      }
   });

   it('failed round trip, all algorithms, missing customAd', async () => {
      for (const alg of Ciphers.algs()) {
         const srcString = 'This is a secret 🦆';
         const [clearStream, _clearData] = streamFromStr(srcString);
         const pwd = 'a good pwd';
         const hint = 'not really';
         const userCred = getRandom(cc.USERCRED_BYTES);
         const customAd = getRandom(1);

         const econtext: EContext = {
            algs: [alg],
            ic: cc.ICOUNT_MIN,
         };

         const encKeyProvider = new PWDKeyProvider(
            userCred.slice(0),
            async (cdinfo) => {
               expect(cdinfo.alg).toEqual(alg);
               expect(cdinfo.slt.byteLength).toEqual(cc.SLT_BYTES);
               expect(cdinfo.ic).toEqual(cc.ICOUNT_MIN);
               expect(cdinfo.lp).toEqual(1);
               expect(cdinfo.lpEnd).toEqual(1);
               expect(cdinfo.hint).toBeFalsy();
               expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
               return [pwd, hint];
            },
            customAd,
         );
         const cipherStream = await cipherSvc.encryptStream(clearStream, encKeyProvider, econtext);

         const decKeyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
            expect(cdinfo.alg).toEqual(alg);
            expect(cdinfo.slt.byteLength).toEqual(cc.SLT_BYTES);
            expect(cdinfo.ic).toEqual(cc.ICOUNT_MIN);
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            expect(cdinfo.hint).toEqual(hint);
            expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
            return [pwd, undefined];
         });
         await expect(cipherSvc.decryptStream(cipherStream, decKeyProvider)).rejects.toThrow(/Invalid MAC/);
      }
   });

   it('failed round trip, all algorithms, added customAd', async () => {
      for (const alg of Ciphers.algs()) {
         const srcString = 'This is a secret 🦆';
         const [clearStream, _clearData] = streamFromStr(srcString);
         const pwd = 'a good pwd';
         const hint = 'not really';
         const userCred = getRandom(cc.USERCRED_BYTES);
         const customAd = getRandom(14);

         const econtext: EContext = {
            algs: [alg],
            ic: cc.ICOUNT_MIN,
         };

         const encKeyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
            expect(cdinfo.alg).toEqual(alg);
            expect(cdinfo.slt.byteLength).toEqual(cc.SLT_BYTES);
            expect(cdinfo.ic).toEqual(cc.ICOUNT_MIN);
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            expect(cdinfo.hint).toBeFalsy();
            expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
            return [pwd, hint];
         });
         const cipherStream = await cipherSvc.encryptStream(clearStream, encKeyProvider, econtext);

         const decKeyProvider = new PWDKeyProvider(
            userCred.slice(0),
            async (cdinfo) => {
               expect(cdinfo.alg).toEqual(alg);
               expect(cdinfo.slt.byteLength).toEqual(cc.SLT_BYTES);
               expect(cdinfo.ic).toEqual(cc.ICOUNT_MIN);
               expect(cdinfo.lp).toEqual(1);
               expect(cdinfo.lpEnd).toEqual(1);
               expect(cdinfo.hint).toEqual(hint);
               expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
               return [pwd, undefined];
            },
            customAd,
         );
         await expect(cipherSvc.decryptStream(cipherStream, decKeyProvider)).rejects.toThrow(/Invalid MAC/);
      }
   });

   it('failed round trip, all algorithms, wrong customAd', async () => {
      for (const alg of Ciphers.algs()) {
         const srcString = 'This is a secret 🦆';
         const [clearStream, _clearData] = streamFromStr(srcString);
         const pwd = 'a good pwd';
         const hint = 'not really';
         const userCred = getRandom(cc.USERCRED_BYTES);
         const customAd = getRandom(1);

         const econtext: EContext = {
            algs: [alg],
            ic: cc.ICOUNT_MIN,
         };

         const encKeyProvider = new PWDKeyProvider(
            userCred.slice(0),
            async (cdinfo) => {
               expect(cdinfo.alg).toEqual(alg);
               expect(cdinfo.slt.byteLength).toEqual(cc.SLT_BYTES);
               expect(cdinfo.ic).toEqual(cc.ICOUNT_MIN);
               expect(cdinfo.lp).toEqual(1);
               expect(cdinfo.lpEnd).toEqual(1);
               expect(cdinfo.hint).toBeFalsy();
               expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
               return [pwd, hint];
            },
            customAd,
         );
         const cipherStream = await cipherSvc.encryptStream(clearStream, encKeyProvider, econtext);

         const decKeyProvider = new PWDKeyProvider(
            userCred.slice(0),
            async (cdinfo) => {
               expect(cdinfo.alg).toEqual(alg);
               expect(cdinfo.slt.byteLength).toEqual(cc.SLT_BYTES);
               expect(cdinfo.ic).toEqual(cc.ICOUNT_MIN);
               expect(cdinfo.lp).toEqual(1);
               expect(cdinfo.lpEnd).toEqual(1);
               expect(cdinfo.hint).toEqual(hint);
               expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
               return [pwd, undefined];
            },
            new Uint8Array(0),
         );
         await expect(cipherSvc.decryptStream(cipherStream, decKeyProvider)).rejects.toThrow(/Invalid MAC/);
      }
   });

   it('successful round trip, mixed algorithms, loops, with customAd', async () => {
      const algKeys = Ciphers.algs();
      const maxLps = algKeys.length;

      const srcString = 'This is a secret 🦆';
      const [clearStream] = streamFromStr(srcString);
      const userCred = getRandom(cc.USERCRED_BYTES);
      const customAd = getRandom(16);

      const econtext: EContext = {
         algs: algKeys,
         ic: cc.ICOUNT_MIN,
      };

      let expectedEncLp = 1;

      const encKeyProvider = new PWDKeyProvider(
         userCred.slice(0),
         async (cdinfo) => {
            expect(cdinfo.lp).toEqual(expectedEncLp);
            expect(cdinfo.lpEnd).toEqual(maxLps);
            expect(cdinfo.alg).toEqual(algKeys[cdinfo.lp - 1]);
            expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
            expectedEncLp += 1;
            return [String(cdinfo.lp), String(cdinfo.lp)];
         },
         customAd,
      );
      const cipherStream = await cipherSvc.encryptStream(clearStream, encKeyProvider, econtext);

      let expectedDecLp = maxLps;

      const decKeyProvider = new PWDKeyProvider(
         userCred.slice(0),
         async (cdinfo) => {
            expect(cdinfo.lp).toEqual(expectedDecLp);
            expect(cdinfo.lpEnd).toEqual(maxLps);
            expect(cdinfo.alg).toEqual(algKeys[cdinfo.lp - 1]);
            expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
            expectedDecLp -= 1;
            return [cdinfo.hint!, undefined];
         },
         customAd,
      );
      const decrypted = await cipherSvc.decryptStream(cipherStream, decKeyProvider);

      const resString = await readStreamAll(decrypted, true);
      expect(resString).toEqual(srcString);
   });

   it('failed round trip, mixed algorithms, loops, missing customAd', async () => {
      const algKeys = Ciphers.algs();
      const srcString = 'This is a secret 🦆';
      const [clearStream] = streamFromStr(srcString);
      const userCred = getRandom(cc.USERCRED_BYTES);
      const customAd = getRandom(16);

      const econtext: EContext = {
         algs: algKeys,
         ic: cc.ICOUNT_MIN,
      };

      const encKeyProvider = new PWDKeyProvider(
         userCred.slice(0),
         async (cdinfo) => {
            return [String(cdinfo.lp), String(cdinfo.lp)];
         },
         customAd,
      );
      const cipherStream = await cipherSvc.encryptStream(clearStream, encKeyProvider, econtext);

      const decKeyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
         return [cdinfo.hint!, undefined];
      });
      await expect(cipherSvc.decryptStream(cipherStream, decKeyProvider)).rejects.toThrow(/Invalid MAC/);
   });

   it('failed round trip, mixed algorithms, loops, wrong customAd', async () => {
      const algKeys = Ciphers.algs();
      const srcString = 'This is a secret 🦆';
      const [clearStream] = streamFromStr(srcString);
      const userCred = getRandom(cc.USERCRED_BYTES);
      const customAd = getRandom(16);
      const wrongCustomAd = getRandom(16);

      const econtext: EContext = {
         algs: algKeys,
         ic: cc.ICOUNT_MIN,
      };

      const encKeyProvider = new PWDKeyProvider(
         userCred.slice(0),
         async (cdinfo) => {
            return [String(cdinfo.lp), String(cdinfo.lp)];
         },
         customAd,
      );
      const cipherStream = await cipherSvc.encryptStream(clearStream, encKeyProvider, econtext);

      const decKeyProvider = new PWDKeyProvider(
         userCred.slice(0),
         async (cdinfo) => {
            return [cdinfo.hint!, undefined];
         },
         wrongCustomAd,
      );
      await expect(cipherSvc.decryptStream(cipherStream, decKeyProvider)).rejects.toThrow(/Invalid MAC/);
   });
});

describe('Read block size bugs check', () => {
   let cipherSvc: CipherService;
   let savedReadSize: number;

   beforeEach(() => {
      TestBed.configureTestingModule({});
      cipherSvc = TestBed.inject(CipherService);
      savedReadSize = Encipher['READ_SIZE_START'];
   });

   afterEach(() => {
      //@ts-expect-error
      Encipher['READ_SIZE_START'] = savedReadSize;
   });

   it('block size read stall test', async () => {
      const hint = 'nope';
      const pwd = 'another good pwd';
      const userCred = getRandom(cc.USERCRED_BYTES);
      const clearData = getRandom(100);

      for (const alg of Ciphers.algs()) {
         for (const adjust of [-1, 0, 1]) {
            const [clearStream] = streamFromBytes(clearData);

            // Monkey patch to force read size to match data
            //@ts-expect-error
            Encipher['READ_SIZE_START'] = clearData.byteLength + adjust;

            expect(clearData.byteLength + adjust).toEqual(Encipher['READ_SIZE_START']);

            const econtext: EContext = {
               algs: [alg],
               ic: cc.ICOUNT_MIN,
            };

            const encKeyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
               expect(cdinfo.alg).toEqual(alg);
               return [pwd, hint];
            });
            const cipherStream = await cipherSvc.encryptStream(clearStream, encKeyProvider, econtext);

            // This previously stalled
            await expect(readStreamAll(cipherStream)).resolves.not.toThrow();
         }
      }
   });

   it('block size terminator test', async () => {
      const hint = 'nope';
      const pwd = 'another good pwd';
      const userCred = getRandom(cc.USERCRED_BYTES);
      const clearData = getRandom(100);

      for (const alg of Ciphers.algs()) {
         for (const adjust of [-1, 0, 1]) {
            const [clearStream] = streamFromBytes(clearData);

            // Monkey patch to force read size to match data
            //@ts-expect-error
            Encipher['READ_SIZE_START'] = clearData.byteLength + adjust;

            expect(clearData.byteLength + adjust).toEqual(Encipher['READ_SIZE_START']);

            const econtext: EContext = {
               algs: [alg],
               ic: cc.ICOUNT_MIN,
            };

            // Only a read larger than the clear text lets block0 terminate the document
            const expectMulti = adjust < 1;

            const encKeyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
               expect(cdinfo.alg).toEqual(alg);
               return [pwd, hint];
            });
            let encDoneCount = 0;
            const cipherStream = await cipherSvc.encryptStream(
               clearStream,
               encKeyProvider,
               econtext,
               (ver, multiBlock) => {
                  encDoneCount += 1;
                  expect(ver).toEqual(cc.CURRENT_VERSION);
                  expect(multiBlock).toBe(expectMulti);
               },
            );

            const decKeyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
               expect(cdinfo.hint).toEqual(hint);
               expect(cdinfo.alg).toEqual(alg);
               return [pwd, undefined];
            });
            let decDoneCount = 0;
            const dec = await cipherSvc.decryptStream(cipherStream, decKeyProvider, (ver, multiBlock) => {
               decDoneCount += 1;
               expect(ver).toEqual(cc.CURRENT_VERSION);
               expect(multiBlock).toBe(expectMulti);
            });

            // This previously failed due to missing term block
            await expect(areEqual(dec, clearData)).resolves.toEqual(true);
            expect(encDoneCount).toBe(1);
            expect(decDoneCount).toBe(1);
         }
      }
   });
});

describe('Stream manipulation, multi-version', () => {
   let cipherSvc: CipherService;
   beforeEach(async () => {
      await cryptoReady();
      TestBed.configureTestingModule({});
      cipherSvc = TestBed.inject(CipherService);
   });

   const userCred = new Uint8Array([
      198, 18, 166, 217, 14, 52, 226, 145, 164, 169, 245, 164, 79, 36, 247, 82, 135, 84, 71, 239, 125, 108, 221, 48,
      137, 177, 250, 178, 47, 110, 23, 194,
   ]);

   const vers = [
      //v5
      {
         ct: 'YxDP37WZjE6JP5EBZYd113DywXGmChJgQwJ27yUZkEgFAEgBAAABAKJehRspDKhtYi8y5MvSXUNDxyqrov5RGGOs5BzgyBAAABTw7-eoyC1TGBuraNUCj00sv1OwfcpiwKyOcCZKhPdYt63ia-dg3bV9b0IOCBleMeQyCRhc61FNyKZmUp7vonh5lIbXMUKFODQqRJRhECYDUzBLuCFvfs6ojmRKXll_-unkhH9hRtFvaTR4GDWkJKI62QP992yAIPVtPjN7Y0PlxDshWrfWMKR0_-fd7cKoHmO3JXKB7i6blEupayrqtI1VRhpY1OmGkVYSQcFjlPBkXms-VCxroGk_oA2blfrocNuf0mv2-4rdL4j9ev-k0YiKDu_HkE4tuwkhJ3pdmONEIpW7KMugg3Tg6uWk4KIMYpQKI0R1M-6CYbLXWpKL71vrJ6v_qukX8nUkpiQaqaOTYX8OhFqOPhsU5ChyTmK7ChOscZ_PwjmibGRacyvou6dRDyA_sXs7wqhUe7w3CJfQaZnQAv4FAG4BAAEBAPXFxXNhZ3Gem8pWhq4W9QT8pfUpDpHNKuNcSamS6gnfE0bg9T5FDEp-B0d0LjrhUu_fstk4VOd3k_UfrHjuQ5qD-I8s4Fd9NMkjraXLh2pdAc6E8mCOhdB3pXJp7PEByohXmxfQ6wSpacnckhB4OAPSiUBASNSNNuSWQDRJHBeYIJeNKr8znow9rIRwEe7Nsc_dbmkmfsAknLZO8QR_Glpu4by16DuULi_RLtEfgjAeRzisX7WY65CqlhiQ9KbJtiVKWZXUgVAhTPv1Kyle_uCCgB4dSeZ0C9BC7F1F15QZIEogaxM8OsgpM1szhCahQQjUdj_JVWVeyQ0YKCR9Ku-WszcBdXf7v2RA6A6C30p-B7GFrT8EWod9KSYwu-jA8PMzCymt5rINNB81uOxDc3mJwfgXI0Cailb9RMiuSSvBvUQ1yOWENXhD-L6J9Dn4b6buO4RW3Jx3qrPlwn-LndPzfJgN8P19U-PBAOA=',
         slt: new Uint8Array([203, 210, 93, 67, 67, 199, 42, 171, 162, 254, 81, 24, 99, 172, 228, 28]),
         iv: new Uint8Array([162, 94, 133, 27, 41, 12, 168, 109, 98, 47, 50, 228]),
         ver: 5,
      },
      //v6
      {
         ct: 'QN-b9IO7eFdTfwLrSpwTJBAQa4mLYb6L1FykX04GHgMGAEkBAAABAIGEvDGIwIKtB6Q_TQBRA-R3wkRpJO-Q-1tcwjbgyBAAABRUjQsN5Nz1_aaEcmuuO7meixdbZL0eCWmNNMuu0oWp8KYFqneceUygklENjuJJ6FUT4iWlBHN5y0qMyTIg4fMQT5kT_aT66ropqfztsDBCZKC3CyFJN-t2jyHyg86OrLrI6f-XemY0YXxhf4Aqv0V97sU43IbQvmedBg8fp-Az7Hy5jPeuzNbu8AM6hLzjmh9nJwVN8TRxoACTaQ2Z3CyAPjUO8N4_Tk3vRCLo0tWkp4Fguuyxermjba9XM1TxLcBhmN4LVbid1JWax09hiDsSbfvJg9nTBptsSu30A19oGx_jVTuI1QwMp-tzrcY6yuoEdZTYctx4PRQE_3EMaqwKSxrTduP7UMR7k-_3qwsKucPiVbIeF_TkTvfWXEnLp9vNXtLchFUxskFvQOhs0RuKKuCb6fkoMYD-7vYWtPzMpbjzI8MGAG8BAAEBADZqgj3PDWTKRYhsxnUl7V-Uj01mOPZgOcetSpf8NqYdbOU8k8Ajc95Dpcym_PHhujoO98OWfRa6ZqCIajWsBzl83PUz6zpX8-DSme71w_WR28fQE4Qu3zrZwPLvoYig1fOGGhNmNHy88BzAxrRrXnrlJuvW6z3ZtD02lLyrvW28DLK75atN32WJgyVrb8N78J-w6erBvFDpu42Wfg4hYeeuvrQLAx_kBLKNCa1AGsPngFNrF76SmIbM7xgIbjcx_yhh3CGe3OfoIJ5Az7eyXqIDGr_Vw-29sx4-mSjavFaDxTSu_gcfhk9xlXmljXSJpLqyOEhA-2dEF5-OLcqOVsY9kH_cdi6YgKl5GCr-q35hd4YWMaI2V89-2js1ABfOZvx21s3WRwiSXGsGHl2IG-Lg9NdJRnikf7qTWSIa5RTMoDHA1pYk9B_mJdchu7IxiUZ-Q4Zy8PE03fSTOfHBQ0KlfW_QdkN084IitMw',
         slt: new Uint8Array([0, 81, 3, 228, 119, 194, 68, 105, 36, 239, 144, 251, 91, 92, 194, 54]),
         iv: new Uint8Array([129, 132, 188, 49, 136, 192, 130, 173, 7, 164, 63, 77]),
         ver: 6,
      },
      //v7 — generated by: pnpm vectors:ciphersvc
      {
         ct: 'dFnwD29KHNA9azLLZswlQDbide2RUoD27RyBs5CSj-UHAEkBAAABAI8Alls2_0KLG6mSxbgaMi3KNUDjVPWKgNdhocfgyBAAABTvULrOcHClNQk0KC3FhWpVhVmSvKB_NUnS2JzfrcNY-VdeToerNZvD0ETbIgMfPP0rzmKchsfJeAc7P5XUIx5vVHkrnYdiW-2vp2mSKogd2ShXmsZmRIZ9XAaeYWZiidKMicBi2TxYzr2w3RU9JyB5b2stJSIMYJsJprwWCKdmipeMIlTqRG6diwrvskvI7r5JByeeV_kaxWr9-3DdznPJk-3MiBUK7tvVxMG0Hzv09KlsI778dZCUwn-BxzPGcLQ4NTHENzsQ8iLz2WPAO3-ruuZ4r7u114N_6clx2qsvb0WDvOxJnt3kuAkBtj9jtwOg8rbxHNDfyA5R5alhBDvWUCk9DoIHkt1zVd-7ip-kmPAvuq9Nuiq6QJ2oAs8RrybiSgBxaClIsn2iS4E0zEuOwZz3FGK2kbd6YDnK2nIQlqhM64wHAG8BAAEBAOr9nAZIpiTqrstvJ2WqRmdXcCLP1CKk4i75c4H8RlSX82gtUTAv9Yxr5AVY8s3xsoFaEg_Rfyl1nJgOADTgNuit2JMqIP5U-5X4PIWg4yHx7ZLxYMVVpuHT0uHgeIzEXrzrDT_jp3YOL0j7VG_Hk2eBDcrOuxJxgjKkI5aQuyImF1CDdwDDhNFkNhe7Wg7VwJYX-UZ8hiK3kk0CvaRTQ3wNUWfA1yrd1ZRABGzKufRjWFdU5ManvN6Oyxn3njTzVaGD_bXJYl8l0ZswPMpncN2AgkJyPH92M40Vs8nqJUCfwFXhKHu5-rLHqFt1d_6UGGKNZqau5z-fhnA_uKHfoeuk7_JHOSVnz7mTBwFjHOvecmA_4VXwlbcTEbdML5ZtKB93_VaHmbrn5a1lyrJ99AHVgaK9lHFI2uz8uNIU5mibVBqGEWA9JgIwP1oURmS29prqEIJRRfvmjEAGtujbm_JwY9NUAjVGufmaRr8',
         slt: new Uint8Array([184, 26, 50, 45, 202, 53, 64, 227, 84, 245, 138, 128, 215, 97, 161, 199]),
         iv: new Uint8Array([143, 0, 150, 91, 54, 255, 66, 139, 27, 169, 146, 197]),
         ver: 7,
      },
      //v8 — generated by: pnpm vectors:ciphersvc
      {
         ct: 'wypgDhCWPnSPfXfscQHc-PBqeFJDsc9VIEkqlaqd39EIAGoBAAABAANY2gG8NUh3oep6-cE-ZxgU9YHQK1Ei1gdYlZ7gyBAAABRLzGe_w12PFM2_Beu42Y62UCS-RiCxIKSvK7EFZhdvuXwoFXnD3RAyIgj4QlYCmwBRaAJbrmpNdz93RvkWTQUkCNg0isDJZI7_TAIQh1URrgBpn4HhQJg0Oh3bw3RtAftfPdVJch5itdiaah_hzpq7ZhvdxNdsLV6LMYp5_oek6eB0zuxbPWyy45qCiR6Vtk4MqJBh8C3WIqaT_ir66emkQ7EvvMS8_968iwejs9smGZdu8QcePTDW9jwMkHPtJFcQNaWQClYGj2ArW5laAjLm4d3AxjFCJHq3zj-fhLX9laodA_GUftnIMHyGuXFioHxRUHxCsQWw4Y1qcdkfxSNe688mdcFTrMuV-hzcN01patcKLjETlcOWVNp59IGLHvA8Yvzkvbz3N7CL1adbjAmlJvHqK_04SyQ5vFXp9RsKERcDHvGkExgjwJMJ5C2R_wliMxbIe1C4zZrC-ngt84KdfEvkoZkIAG8BAAEBAMLMmm_suluPuFwqVrOzgTNab0eDVG3wcy63-1Uc5yVCOGleiHAlX4FiD5XT6cDDsvbaBlywoGioqdA2-M41z20jSp9ds4qbG1ai7nygJjt1oY9Gdjpogm51fL0MY3J7y4pBJrjPZ3cMQMcG-yPi8sNL8OrPzFlF0_u5IBDSeBS5WmukZ142soauczcXZa7M9q5hfSBHpkpAW80xqkXtz5swUHTtyUmmRkyMsGcvaa3Tf0lMlAle_vcXPhBPvRYCjgpb4bgEorCxWIrL8hzHsH1yawTQhKihz1AvN0jj7QzcxPzrnafxTEnfQyK0lNCHIe3KIH2w05pfME3EEk1B9EVTwkAHWvSMn6pWIsnxQFGQ6NiWe37znhXJBdnQHwow1FKjo4oqvMoZQVyj8jnmxB0rp0Hx99ZtyU-R4ml7LMZEyhrQlYpB_Io4qkXrSYrosBxGT5SFn9oOoUAPAF5y-6MGrPf3u1U8bgqUeMM',
         slt: new Uint8Array([193, 62, 103, 24, 20, 245, 129, 208, 43, 81, 34, 214, 7, 88, 149, 158]),
         iv: new Uint8Array([3, 88, 218, 1, 188, 53, 72, 119, 161, 234, 122, 249]),
         ver: 8,
      },
   ];

   const clearData = new Uint8Array([
      118, 101, 114, 115, 105, 111, 110, 58, 32, 34, 51, 46, 56, 34, 10, 115, 101, 114, 118, 105, 99, 101, 115, 58, 10,
      32, 32, 100, 111, 99, 107, 103, 101, 58, 10, 32, 32, 32, 32, 105, 109, 97, 103, 101, 58, 32, 108, 111, 117, 105,
      115, 108, 97, 109, 47, 100, 111, 99, 107, 103, 101, 58, 49, 10, 32, 32, 32, 32, 114, 101, 115, 116, 97, 114, 116,
      58, 32, 117, 110, 108, 101, 115, 115, 45, 115, 116, 111, 112, 112, 101, 100, 10, 32, 32, 32, 32, 112, 111, 114,
      116, 115, 58, 10, 32, 32, 32, 32, 32, 32, 45, 32, 53, 48, 48, 49, 58, 53, 48, 48, 49, 10, 32, 32, 32, 32, 118,
      111, 108, 117, 109, 101, 115, 58, 10, 32, 32, 32, 32, 32, 32, 45, 32, 47, 118, 97, 114, 47, 114, 117, 110, 47,
      100, 111, 99, 107, 101, 114, 46, 115, 111, 99, 107, 58, 47, 118, 97, 114, 47, 114, 117, 110, 47, 100, 111, 99,
      107, 101, 114, 46, 115, 111, 99, 107, 10, 32, 32, 32, 32, 32, 32, 45, 32, 46, 47, 100, 97, 116, 97, 58, 47, 97,
      112, 112, 47, 100, 97, 116, 97, 10, 32, 32, 32, 32, 32, 32, 35, 32, 83, 116, 97, 99, 107, 115, 32, 68, 105, 114,
      101, 99, 116, 111, 114, 121, 10, 32, 32, 32, 32, 32, 32, 35, 32, 226, 154, 160, 239, 184, 143, 32, 82, 69, 65, 68,
      32, 73, 84, 32, 67, 65, 82, 69, 70, 85, 76, 76, 89, 46, 32, 73, 102, 32, 121, 111, 117, 32, 100, 105, 100, 32,
      105, 116, 32, 119, 114, 111, 110, 103, 44, 32, 121, 111, 117, 114, 32, 100, 97, 116, 97, 32, 99, 111, 117, 108,
      100, 32, 101, 110, 100, 32, 117, 112, 32, 119, 114, 105, 116, 105, 110, 103, 32, 105, 110, 116, 111, 32, 97, 32,
      87, 82, 79, 78, 71, 32, 80, 65, 84, 72, 46, 10, 32, 32, 32, 32, 32, 32, 35, 32, 226, 154, 160, 239, 184, 143, 32,
      49, 46, 32, 70, 85, 76, 76, 32, 112, 97, 116, 104, 32, 111, 110, 108, 121, 46, 32, 78, 111, 32, 114, 101, 108, 97,
      116, 105, 118, 101, 32, 112, 97, 116, 104, 32, 40, 77, 85, 83, 84, 41, 10, 32, 32, 32, 32, 32, 32, 35, 32, 226,
      154, 160, 239, 184, 143, 32, 50, 46, 32, 76, 101, 102, 116, 32, 83, 116, 97, 99, 107, 115, 32, 80, 97, 116, 104,
      32, 61, 61, 61, 32, 82, 105, 103, 104, 116, 32, 83, 116, 97, 99, 107, 115, 32, 80, 97, 116, 104, 32, 40, 77, 85,
      83, 84, 41, 10, 32, 32, 32, 32, 32, 32, 45, 32, 47, 111, 112, 116, 47, 115, 116, 97, 99, 107, 115, 58, 47, 111,
      112, 116, 47, 115, 116, 97, 99, 107, 115, 10, 32, 32, 32, 32, 101, 110, 118, 105, 114, 111, 110, 109, 101, 110,
      116, 58, 10, 32, 32, 32, 32, 32, 32, 35, 32, 84, 101, 108, 108, 32, 68, 111, 99, 107, 103, 101, 32, 119, 104, 101,
      114, 101, 32, 116, 111, 32, 102, 105, 110, 100, 32, 116, 104, 101, 32, 115, 116, 97, 99, 107, 115, 10, 32, 32, 32,
      32, 32, 32, 45, 32, 68, 79, 67, 75, 71, 69, 95, 83, 84, 65, 67, 75, 83, 95, 68, 73, 82, 61, 47, 111, 112, 116, 47,
      115, 116, 97, 99, 107, 115,
   ]);

   // The commitment trails the hint, whose encrypted length varies, so read it from the data
   function block0Offsets(cipherdata: Uint8Array) {
      const mac = 0;
      const ver = mac + cc.MAC_BYTES;
      const size = ver + cc.VER_BYTES;
      const flags = size + cc.PAYLOAD_SIZE_BYTES;
      const ad = flags + cc.FLAGS_BYTES;
      const alg = ad;
      const iv = alg + cc.ALG_BYTES;
      const algName = Ciphers.algName(bytesToNum(cipherdata.subarray(alg, alg + cc.ALG_BYTES)));
      const slt = iv + Ciphers.algIVByteLength(algName);
      const ic = slt + cc.SLT_BYTES;
      const lp = ic + cc.IC_BYTES;
      const hintLen = lp + cc.LPP_BYTES;
      const hint = hintLen + cc.HINT_LEN_BYTES;
      const commitLen = hint + cipherdata[hintLen];
      const commit = commitLen + cc.COMMIT_LEN_BYTES;
      const enc = mac + 190; // in the middle of enc data
      return { mac, ver, size, flags, ad, alg, iv, slt, ic, lp, hintLen, hint, commitLen, commit, enc };
   }

   // block0's length grew in v8, so read where block1 starts from block0's declared payload
   // size rather than pinning it per version
   function block1Offsets(cipherdata: Uint8Array) {
      const b0 = block0Offsets(cipherdata);
      const blockVer = bytesToNum(cipherdata.subarray(b0.ver, b0.ver + cc.VER_BYTES));
      const payloadSize = bytesToNum(cipherdata.subarray(b0.size, b0.size + cc.PAYLOAD_SIZE_BYTES));
      // Before v6 the flags byte sat in the header rather than the additional data
      const mac = (blockVer < cc.VERSION6 ? cc.HEADER_BYTES_OLD : cc.HEADER_BYTES_6P) + payloadSize;
      const ver = mac + cc.MAC_BYTES;
      const size = ver + cc.VER_BYTES;
      const flags = size + cc.PAYLOAD_SIZE_BYTES;
      const alg = flags + cc.FLAGS_BYTES;
      const iv = alg + cc.ALG_BYTES;
      const enc = mac + 190; // in the middle of enc data
      return { mac, ver, size, flags, alg, iv, enc };
   }

   it('detect manipulated cipher stream header, block0', async () => {
      for (const ver of vers) {
         // First make sure it decrypts as expected
         const [cipherStream, cipherData] = streamFromBase64(ver.ct);
         const decKeyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
            expect(cdinfo.hint).toEqual('4321');
            expect(cdinfo.alg).toBe('AES-GCM');
            expect(cdinfo.ver).toBe(ver.ver);
            expect(cdinfo.lp).toBe(1);
            expect(cdinfo.lpEnd).toBe(1);
            expect(cdinfo.ic).toBe(1100000);
            expect(cdinfo.slt).toEqual(ver.slt);
            expect(Boolean(cdinfo.hint)).toBe(true);
            return ['asdf', undefined];
         });
         const dec = await cipherSvc.decryptStream(cipherStream, decKeyProvider);
         await expect(areEqual(dec, clearData)).resolves.toEqual(true);

         const b0Offsets = block0Offsets(cipherData);

         // Modified block0 MAC
         const b0Mac = new Uint8Array(cipherData);
         b0Mac[b0Offsets.mac] = 255;

         let [stream] = streamFromBytes(b0Mac);
         await expect(
            cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf', undefined])),
         ).rejects.toThrow(/Invalid MAC.+/);

         // Test modified block0 version
         const b0Ver = new Uint8Array(cipherData);
         b0Ver[b0Offsets.ver] = 22;
         [stream] = streamFromBytes(b0Ver);
         await expect(
            cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf', undefined])),
         ).rejects.toThrow(/Invalid version.+/);

         // Test modified block0 size, valid size but too small
         let b0Size = new Uint8Array(cipherData);
         b0Size.set([20, 1], b0Offsets.size);
         [stream] = streamFromBytes(b0Size);
         await expect(
            cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf', undefined])),
         ).rejects.toThrow(/Invalid MAC.+/);

         // Too small block0 size, invalid
         b0Size = new Uint8Array(cipherData);
         b0Size.set([0, 0], b0Offsets.size);
         [stream] = streamFromBytes(b0Size);
         await expect(
            cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf', undefined])),
         ).rejects.toThrow(/Invalid payload size3.+/);

         // Test too big block0 size
         b0Size = new Uint8Array(cipherData);
         b0Size.set([255, 255, 255], b0Offsets.size);
         [stream] = streamFromBytes(b0Size);
         await expect(
            cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf', undefined])),
         ).rejects.toThrow(/Cipher data length mismatch1.+/);

         // Boundary: PAYLOAD_SIZE_MIN - 1 fails the size check
         b0Size = new Uint8Array(cipherData);
         b0Size.set([cc.PAYLOAD_SIZE_MIN - 1, 0, 0], b0Offsets.size);
         [stream] = streamFromBytes(b0Size);
         await expect(
            cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf', undefined])),
         ).rejects.toThrow(/Invalid payload size3.+/);

         b0Size = new Uint8Array(cipherData);
         b0Size.set([cc.PAYLOAD_SIZE_MIN, 0, 0], b0Offsets.size);
         [stream] = streamFromBytes(b0Size);
         await expect(
            cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf', undefined])),
         ).rejects.toThrow(/Invalid.+/);

         // Test modified block0 flags, invalid
         let b0Flags = new Uint8Array(cipherData);
         b0Flags[b0Offsets.flags] = 6;
         [stream] = streamFromBytes(b0Flags);
         await expect(
            cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf', undefined])),
         ).rejects.toThrow(/Invalid flags.+/);

         // Test modified block0 flags, early terminal (detected by MAC first because
         // early term isn't known until next block)
         b0Flags = new Uint8Array(cipherData);
         b0Flags[b0Offsets.flags] = 1;
         [stream] = streamFromBytes(b0Flags);
         await expect(
            cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf', undefined])),
         ).rejects.toThrow(/Invalid MAC.+/);
      }
   });

   it('detect manipulated cipher stream header, blockN', async () => {
      for (const ver of vers) {
         // First make sure it decrypts as expected
         const [cipherStream, cipherdata] = streamFromBase64(ver.ct);
         let dec = await cipherSvc.decryptStream(
            cipherStream,
            new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
               expect(cdinfo.hint).toEqual('4321');
               return ['asdf', undefined];
            }),
         );
         await expect(areEqual(dec, clearData)).resolves.toEqual(true);

         const b1Offsets = block1Offsets(cipherdata);

         // Modified blockN MAC
         const bNMac = new Uint8Array(cipherdata);
         bNMac[b1Offsets.mac] = 255;
         let [stream] = streamFromBytes(bNMac);
         dec = await cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf', undefined]));
         await expect(readStreamAll(dec)).rejects.toThrow(/Invalid MAC.+/);

         // Modified blockN version
         const bNVer = new Uint8Array(cipherdata);
         bNVer.set([4, 1], b1Offsets.ver);
         [stream] = streamFromBytes(bNVer);
         dec = await cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf', undefined]));
         await expect(readStreamAll(dec)).rejects.toThrow(/Invalid version.+/);

         // Test modified blockN size, too small valid
         let bNSize = new Uint8Array(cipherdata);
         bNSize.set([20, 1], b1Offsets.size);
         [stream] = streamFromBytes(bNSize);
         dec = await cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf', undefined]));
         await expect(readStreamAll(dec)).rejects.toThrow(/Invalid MAC.+/);

         // Too small blockN size, too small invalid
         bNSize = new Uint8Array(cipherdata);
         bNSize.set([0, 0], b1Offsets.size);
         [stream] = streamFromBytes(bNSize);
         dec = await cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf', undefined]));
         await expect(readStreamAll(dec)).rejects.toThrow(/Invalid payload.+/);

         // Test too big blockN but valid
         bNSize = new Uint8Array(cipherdata);
         bNSize.set([255, 255, 255], b1Offsets.size);
         [stream] = streamFromBytes(bNSize);
         dec = await cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf', undefined]));
         await expect(readStreamAll(dec)).rejects.toThrow(/Cipher data length mismatch2.+/);

         // Test modified block0 flags, invalid
         let bNFlags = new Uint8Array(cipherdata);
         bNFlags[b1Offsets.flags] = 6;
         [stream] = streamFromBytes(bNFlags);
         dec = await cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf', undefined]));
         await expect(readStreamAll(dec)).rejects.toThrow(/Invalid flags.+/);

         // Test modified block0 flags, early terminal (detected by MAC first)
         bNFlags = new Uint8Array(cipherdata);
         bNFlags[b1Offsets.flags] = 0;
         [stream] = streamFromBytes(bNFlags);
         dec = await cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf', undefined]));
         await expect(readStreamAll(dec)).rejects.toThrow(/Invalid MAC.+/);
      }
   });

   it('detect manipulated cipher stream additional data, block0', async () => {
      for (const ver of vers) {
         // First make sure it decrypts as expected
         const [cipherStream, cipherdata] = streamFromBase64(ver.ct);
         const dec = await cipherSvc.decryptStream(
            cipherStream,
            new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
               expect(cdinfo.hint).toEqual('4321');
               return ['asdf', undefined];
            }),
         );
         await expect(areEqual(dec, clearData)).resolves.toEqual(true);

         const b0Offsets = block0Offsets(cipherdata);

         // Modified block0 invalid ALG
         let b0Alg = new Uint8Array(cipherdata);
         b0Alg[b0Offsets.alg] = 128;
         let [stream] = streamFromBytes(b0Alg);
         await expect(
            cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf', undefined])),
         ).rejects.toThrow(/Unsupported cipher mode.+/);

         // Modified block0 valid but changed ALG
         b0Alg = new Uint8Array(cipherdata);
         b0Alg[b0Offsets.alg] = 2;
         [stream] = streamFromBytes(b0Alg);
         // Error will be different given different cipherdata because changing the alg
         // above changes the IV read len and therefore location of following values.
         // Therefore don't check for specific error message
         await expect(
            cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf', undefined])),
         ).rejects.toThrow(Error);

         // Modified block0 IV
         const b0OIV = new Uint8Array(cipherdata);
         b0OIV[b0Offsets.iv] = 0;
         [stream] = streamFromBytes(b0OIV);
         await expect(
            cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf', undefined])),
         ).rejects.toThrow(/Invalid MAC.+/);

         // Modified block0 Salt
         const b0Slt = new Uint8Array(cipherdata);
         b0Slt[b0Offsets.slt] = 1;
         [stream] = streamFromBytes(b0Slt);
         await expect(
            cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf', undefined])),
         ).rejects.toThrow(/Invalid MAC.+/);

         // Modified block0 invalid IC
         let b0IC = new Uint8Array(cipherdata);
         b0IC.set([0, 0, 0, 0], b0Offsets.ic);
         [stream] = streamFromBytes(b0IC);
         await expect(
            cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf', undefined])),
         ).rejects.toThrow(/Invalid MAC.+/);

         // Modified block0 valid but changed IC
         b0IC = new Uint8Array(cipherdata);
         b0IC.set([64, 119, 21, 1], b0Offsets.ic);
         [stream] = streamFromBytes(b0IC);
         await expect(
            cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf', undefined])),
         ).rejects.toThrow(/Invalid MAC.+/);

         // Modified block0 IC
         b0IC = new Uint8Array(cipherdata);
         b0IC.set([255, 255, 255, 255], b0Offsets.ic);
         [stream] = streamFromBytes(b0IC);
         await expect(
            cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf', undefined])),
         ).rejects.toThrow(/Invalid ic.+/);

         // Modified block0 invalid LPP
         let b0LP = new Uint8Array(cipherdata);
         b0LP[b0Offsets.lp] = 24; // lp > lpEnd
         [stream] = streamFromBytes(b0LP);
         await expect(
            cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf', undefined])),
         ).rejects.toThrow(/Invalid lp.+/);

         // Modified block0 valid but changed LPP
         b0LP = new Uint8Array(cipherdata);
         b0LP[b0Offsets.lp] = 48;
         [stream] = streamFromBytes(b0LP);
         await expect(
            cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf', undefined])),
         ).rejects.toThrow(/Invalid MAC.+/);

         // From v8 the commitment trails the hint, so a bad hint length also displaces the
         // field the parser reads next and it may object before the MAC is checked
         const badHintLen = /Invalid MAC.+|Invalid commit length.+/;

         // Modified block0 hint length under
         let b0HintLen = new Uint8Array(cipherdata);
         b0HintLen[b0Offsets.hintLen] = 2;
         [stream] = streamFromBytes(b0HintLen);
         await expect(
            cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf', undefined])),
         ).rejects.toThrow(badHintLen);

         // Modified block0 hint length over
         b0HintLen = new Uint8Array(cipherdata);
         b0HintLen[b0Offsets.hintLen] = 250;
         [stream] = streamFromBytes(b0HintLen);
         await expect(
            cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf', undefined])),
         ).rejects.toThrow(badHintLen);

         // Modified block0 hint
         const b0Hint = new Uint8Array(cipherdata);
         b0Hint[b0Offsets.hint] = 12;
         [stream] = streamFromBytes(b0Hint);
         await expect(
            cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf', undefined])),
         ).rejects.toThrow(/Invalid MAC.+/);
      }
   });

   it('detect manipulated key commitment on block0', async () => {
      const [clearStream] = streamFromBytes(clearData);
      const econtext: EContext = {
         algs: ['AES-GCM'],
         ic: cc.ICOUNT_MIN,
      };

      const encKeyProvider = new PWDKeyProvider(userCred.slice(0), ['asdf', '4321']);
      const cipherStream = await cipherSvc.encryptStream(clearStream, encKeyProvider, econtext);
      const cipherdata = await readStreamAll(cipherStream);

      const b0Offsets = block0Offsets(cipherdata);
      const commitLenOffset = b0Offsets.commitLen;
      const commitOffset = b0Offsets.commit;

      // Rewriting the length with the value already expected there is only harmless
      // if commitLenOffset really points at the commitment length
      const b0Control = new Uint8Array(cipherdata);
      b0Control[commitLenOffset] = cc.COMMIT_BYTES;
      let [stream] = streamFromBytes(b0Control);
      const dec = await cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf', undefined]));
      await expect(areEqual(dec, clearData)).resolves.toEqual(true);

      // Modified block0 key commitment
      const b0Commit = new Uint8Array(cipherdata);
      b0Commit[commitOffset] ^= 0x01;
      [stream] = streamFromBytes(b0Commit);
      await expect(
         cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf', undefined])),
      ).rejects.toThrow(/Invalid MAC.+/);

      // Modified block0 key commitment length
      const b0CommitLen = new Uint8Array(cipherdata);
      b0CommitLen[commitLenOffset] = 0;
      [stream] = streamFromBytes(b0CommitLen);
      await expect(
         cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf', undefined])),
      ).rejects.toThrow(/Invalid MAC.+/);

      // Invalid block0 key commitment length
      const b0BadCommitLen = new Uint8Array(cipherdata);
      b0BadCommitLen[commitLenOffset] = 31;
      [stream] = streamFromBytes(b0BadCommitLen);
      await expect(
         cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf', undefined])),
      ).rejects.toThrow(/Invalid commit length.+/);
   });

   // Small plaintext keeps the payload short so the tampered hintLen overruns it.
   it('detect hintLen overrun on block0', async () => {
      const pwd = 'asdf';
      const hint = 'h';
      const userCredHere = getRandom(cc.USERCRED_BYTES);
      const [clearStream] = streamFromStr('short');
      const econtext: EContext = {
         algs: ['AES-GCM'],
         ic: cc.ICOUNT_MIN,
      };

      const encKeyProvider = new PWDKeyProvider(userCredHere.slice(0), [pwd, hint]);
      const cipherStream = await cipherSvc.encryptStream(clearStream, encKeyProvider, econtext);
      const cipherdata = await readStreamAll(cipherStream);

      const b0Offsets = block0Offsets(cipherdata);
      const tampered = new Uint8Array(cipherdata);
      tampered[b0Offsets.hintLen] = 250;
      const [stream] = streamFromBytes(tampered);

      await expect(cipherSvc.decryptStream(stream, new PWDKeyProvider(userCredHere, [pwd, undefined]))).rejects.toThrow(
         /Invalid hint.+/,
      );
   });

   it('detect manipulated cipher stream additional data, blockN', async () => {
      for (const ver of vers) {
         // First make sure it decrypts as expected
         const [cipherStream, cipherdata] = streamFromBase64(ver.ct);
         let dec = await cipherSvc.decryptStream(
            cipherStream,
            new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
               expect(cdinfo.hint).toEqual('4321');
               return ['asdf', undefined];
            }),
         );
         await expect(areEqual(dec, clearData)).resolves.toEqual(true);

         const b1Offsets = block1Offsets(cipherdata);

         // Modified blockN invalid ALG
         let bNAlg = new Uint8Array(cipherdata);
         bNAlg[b1Offsets.alg] = 128;
         let [stream] = streamFromBytes(bNAlg);
         dec = await cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf', undefined]));
         await expect(readStreamAll(dec)).rejects.toThrow(/Unsupported cipher mode.+/);

         // Modified blockN valid but changed ALG
         bNAlg = new Uint8Array(cipherdata);
         bNAlg[b1Offsets.alg] = 2;
         [stream] = streamFromBytes(bNAlg);
         dec = await cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf', undefined]));
         // Error will be different given different cipherdata because changing the alg
         // above changes the IV read len and therefore location of following values.
         // Therefore don't check for specific error message
         await expect(readStreamAll(dec)).rejects.toThrow(Error);

         // Modified blockN IV
         const bNIV = new Uint8Array(cipherdata);
         bNIV[b1Offsets.iv] = 0;
         [stream] = streamFromBytes(bNIV);
         dec = await cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf', undefined]));
         await expect(readStreamAll(dec)).rejects.toThrow(/Invalid MAC.+/);
      }
   });

   it('detect manipulated cipher stream encrypted data, block0 & blockN', async () => {
      for (const ver of vers) {
         // First make sure ct decrypts as expected
         const [cipherStream, cipherdata] = streamFromBase64(ver.ct);
         let dec = await cipherSvc.decryptStream(
            cipherStream,
            new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
               expect(cdinfo.hint).toEqual('4321');
               return ['asdf', undefined];
            }),
         );
         await expect(areEqual(dec, clearData)).resolves.toEqual(true);

         const b0Offsets = block0Offsets(cipherdata);
         const b1Offsets = block1Offsets(cipherdata);

         // Modified block0 encrypted data
         const b0Enc = new Uint8Array(cipherdata);
         b0Enc[b0Offsets.enc] = 0;
         let [stream] = streamFromBytes(b0Enc);
         // version ${ver.ver}
         await expect(
            cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf', undefined])),
         ).rejects.toThrow(/Invalid MAC/);

         // Modified blockN encrypted data
         const bNEnc = new Uint8Array(cipherdata);
         bNEnc[b1Offsets.enc] = 0;
         [stream] = streamFromBytes(bNEnc);
         dec = await cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf', undefined]));
         await expect(readStreamAll(dec)).rejects.toThrow(/Invalid MAC.+/);
      }
   });

   it('detect random changed bytes, all algorithms', async () => {
      const [_, clearData] = streamFromBytes(getRandom(14));

      for (const alg of Ciphers.algs()) {
         const [clearStream] = streamFromBytes(clearData);

         const pwd = 'another good pwd';
         const hint = 'nope';
         const userCred = getRandom(cc.USERCRED_BYTES);

         const econtext: EContext = {
            algs: [alg],
            ic: cc.ICOUNT_MIN,
         };

         const encKeyProvider = new PWDKeyProvider(userCred.slice(0), async (_cdinfo) => {
            return [pwd, hint];
         });
         const cipherStream = await cipherSvc.encryptStream(clearStream, encKeyProvider, econtext);

         const cipherData = await readStreamAll(cipherStream);
         const modLen = randomInclusive(1, 10);
         const modData = getRandom(modLen);
         const modPos = randomInclusive(0, cipherData.byteLength - modLen);

         for (let i = 0; i < modLen; i++) {
            if (modData[i] === cipherData[modPos + i]) {
               modData[i] = (modData[i] + 1) % 256;
            }
         }

         cipherData.set(modData, modPos);
         const [corruptStream] = streamFromBytes(cipherData);

         // alg ${alg}, modLen ${modLen}, modPos ${modPos}
         const decKeyProvider = new PWDKeyProvider(userCred.slice(0), async (_cdinfo) => {
            // should never execute
            expect(false, 'should not execute').toBe(true);
            return [pwd, undefined];
         });
         await expect(cipherSvc.decryptStream(corruptStream, decKeyProvider)).rejects.toThrow(Error);
      }
   });

   it('detect fuzz cipher data decryption, all algorithms', async () => {
      // Test both small invalid and normal size "cipher data"
      const minValid = cc.HEADER_BYTES_6P + cc.PAYLOAD_SIZE_MIN;
      const ranges = [
         [0, minValid - 1],
         [minValid, minValid + 51],
      ];

      for (const range of ranges) {
         for (const _alg of Ciphers.algs()) {
            const fuzzLen = randomInclusive(range[0], range[1]);
            const [fuzzStream, _fuzzData] = streamFromBytes(getRandom(fuzzLen));

            const pwd = 'another good pwd';
            const userCred = getRandom(cc.USERCRED_BYTES);

            // alg ${alg}, fuzzLen ${fuzzLen}
            const decKeyProvider = new PWDKeyProvider(userCred, async (_cdinfo) => {
               // should never execute
               expect(false, 'should not execute').toBe(true);
               return [pwd, undefined];
            });
            await expect(cipherSvc.decryptStream(fuzzStream, decKeyProvider)).rejects.toThrow(Error);
         }
      }
   });

   it('detect removed bytes, all algorithms', async () => {
      for (const alg of Ciphers.algs()) {
         const [clearStream, _clearData] = streamFromBytes(new Uint8Array(20));

         const pwd = 'another good pwd';
         const hint = 'nope';
         const userCred = getRandom(cc.USERCRED_BYTES);

         const econtext: EContext = {
            algs: [alg],
            ic: cc.ICOUNT_MIN,
         };

         const encKeyProvider = new PWDKeyProvider(userCred.slice(0), async (_cdinfo) => {
            return [pwd, hint];
         });
         const cipherStream = await cipherSvc.encryptStream(clearStream, encKeyProvider, econtext);

         const cipherData = await readStreamAll(cipherStream);
         const rmLen = randomInclusive(1, 10);

         for (let rmPos = 0; rmPos < cipherData.byteLength - rmLen; rmPos++) {
            const corruptData = concatArrays([cipherData.slice(0, rmPos), cipherData.slice(rmPos + rmLen)]);
            const [corruptStream] = streamFromBytes(corruptData);

            // alg ${alg}, rmLen ${rmLen}, rmPos ${rmPos}
            const decKeyProvider = new PWDKeyProvider(userCred.slice(0), async (_cdinfo) => {
               // should never execute
               expect(false, 'should not execute').toBe(true);
               return [pwd, undefined];
            });
            await expect(cipherSvc.decryptStream(corruptStream, decKeyProvider)).rejects.toThrow(Error);
         }
      }
   });

   it('detect added bytes, all algorithms', async () => {
      for (const alg of Ciphers.algs()) {
         const [clearStream, _clearData] = streamFromBytes(new Uint8Array(20));

         const pwd = 'another good pwd';
         const hint = 'nope';
         const userCred = getRandom(cc.USERCRED_BYTES);

         const econtext: EContext = {
            algs: [alg],
            ic: cc.ICOUNT_MIN,
         };

         const encKeyProvider = new PWDKeyProvider(userCred.slice(0), async (_cdinfo) => {
            return [pwd, hint];
         });
         const cipherStream = await cipherSvc.encryptStream(clearStream, encKeyProvider, econtext);

         const cipherData = await readStreamAll(cipherStream);
         const addLen = randomInclusive(1, 10);
         const addData = getRandom(addLen);

         // make sure first byte of addData doesn't match last byte of cipherData or
         // the extra padding won't be detected until readStreamAll (see below)
         if (addData[0] === cipherData.at(-1)) {
            addData[0] = (addData[0] + 1) % 256;
         }

         for (let addPos = 0; addPos < cipherData.byteLength; addPos++) {
            const corruptData = concatArrays([cipherData.slice(0, addPos), addData, cipherData.slice(addPos)]);
            const [corruptStream] = streamFromBytes(corruptData);

            // alg ${alg}, addLen ${addLen}, addPos ${addPos}
            const decKeyProvider = new PWDKeyProvider(userCred.slice(0), async (_cdinfo) => {
               // should never execute
               expect(false, 'should not execute').toBe(true);
               return [pwd, undefined];
            });
            await expect(cipherSvc.decryptStream(corruptStream, decKeyProvider)).rejects.toThrow(Error);
         }

         // Appending data after block0 throws and error at stream read since
         // only block0 is validated during stream construction
         const corruptData = concatArrays([cipherData, addData]);
         const [corruptStream] = streamFromBytes(corruptData);

         const corruptKeyProvider = new PWDKeyProvider(userCred.slice(0), async (_cdinfo) => {
            return [pwd, undefined];
         });
         const corrupStream = await cipherSvc.decryptStream(corruptStream, corruptKeyProvider);

         // alg ${alg}, addLen ${addLen}
         await expect(readStreamAll(corrupStream)).rejects.toThrow(Error);
      }
   });
});

describe('Block order change and deletion detection, multi-version', () => {
   let cipherSvc: CipherService;
   beforeEach(async () => {
      await cryptoReady();
      TestBed.configureTestingModule({});
      cipherSvc = TestBed.inject(CipherService);
   });

   const userCred = new Uint8Array([
      198, 18, 166, 217, 14, 52, 226, 145, 164, 169, 245, 164, 79, 36, 247, 82, 135, 84, 71, 239, 125, 108, 221, 48,
      137, 177, 250, 178, 47, 110, 23, 194,
   ]);

   const vers = [
      //v5
      {
         ver: 5,
         goodCt:
            'v6xsVVBD4pOtHHfzLsKBVHscJ7Q4kv_KqOKH3X_Fx1IFAFEAAAABAAZsrNtMucZUIr2UFJF3Y9R2FtBAqbm_YLotMSzgyBAAABRnUeng3ADKX8ZIicklSvESgyOeUPCFnOoBhpY-g10PWujfV7mwWWJZdMylaext9jLzwDxOLnu6u4cxcgbt1Ga1Vn5F0qDCyO0Xp9W1mAUAMAAAAAEAQTScPYuFjasQGAKP6oqkR9d58Q0YgvW3zEg50a0en8vK2ShqzFWqL5E9A_mmkaAvhGj9rr43RZhZiInC6ccflFeTqERnpm0jqQL9ysQtBQBCAAAAAQCH0B81axAaykKtBBNhvA0of9kUOniwBgdkzLFYwPH_pz75AdARszabKfDmBWOZFAzy9dDJfiqIz2Nbfr4S59sVkfpg_FPiD6_QgqLXQtv7_SDDAHb5a3C-NLGvP4KhxAYFAGYAAAABAIVBoUjIij7b-5zUE6FMbuAaiegCEYXBcSuLeeKfCH5WHveQq6-8KA4U-IQ6IZ5Rz_ocEv1L5e9uqanzYvGkFMfbhjO3oNH5-C_CqfCIF_1OzrgztnYx2feFXB0DGiR7PBWkPKErkb7VBUkVLd8T-ZqVhNFQstJrXxEXdriJzUfeLrGV3wUArgAAAAEA44DnCIDUxMUHlsvdM6d5QAs_MSRUx0y7_a6hecMnN1K5eOxDxqGDf-3xzL0dpb5CrbW99lYJLwZz9zqyAmPMeCx2KNFL2YFkhBSMy7XrDV9u2wT1ulIKPq6IQpOCos7LqBhiTeh46TqpYgYpeckATiYUrIS5RBfHdxAVQ6Sy-VOAPwHGochCI4AYBjcLGWWYKYkZD3d3CGjjI-haOmFab1vWKNIPE4Cyuvh0bH8dXs3DmHv4vEU8bW5JwioVuw5ciDOH7wgZTdCOBOLqBQCuAAAAAQCwx1-ma6ln7jlEN5K8rAzplIiJ5_iWANGMRdIJhjzQEX7KKCw-bffXnbx_gdPBU0o5ZzkU-HfQih-BeR6nzMsK5KSZBMJUwCAZ9ibCPjkO9cB_iyXAj_82Kk2argCNVaVNVD1rIg8Ig2lyi7btAsFiF5ANSlTv6lpJIqYapa_d1eaNIT6SOEWs2cVCgu4OaGAAzzFg_cw6A1z8VAhBFeyX-VBgerpVZVMijFcgvRxCglN1AVY8Ts5kORAaVCh9w2JFytcXHS4YElml_mgFAK4AAAABAOBdI8pBAWBb4TWSeJEQGRBchmv2EnJ_GKiBxdUuDtTO2ayK-iYjZdXrfxrKenbMcfcKrOZv7zccFcsICw-YqrS6TuKYzlbWUFm_5-mLNuDCQwTjDSok50r0j3vFD2I03wBB9j1NgGgDkhq8LMrRBCIMt0xRv6rz1RXdftsZ-gRklpvNCJPsw20SMBB8jVO7owExMM7HQZ289lY_z8q4hFA8_RepUItTnckfZtl0ZWxnf1JY05yAOI17w8-h80jjQfLXityWRu29nWAsdgUANwAAAQEA-CZxmBlulfdy7xc9NP2C2PH1FoGV4ClHPFor1PaqvS8PIGwJjYpN4Pq0S9o4DPPVd-WzFhg=',
         badCts: {
            'Block0 Block7 swap':
               'dGVsZ39SWNOcgDiNe8PPofNI40Hy14rclkbtvZ1gLHYFADcAAAEBAPgmcZgZbpX3cu8XPTT9gtjx9RaBleApRzxaK9T2qr0vDyBsCY2KTeD6tEvaOAzz1XflsxYYbfYy88A8Ti57uruHMXIG7dRmtVZ-RdKgwsjtF6fVtZgFADAAAAABAEE0nD2LhY2rEBgCj-qKpEfXefENGIL1t8xIOdGtHp_LytkoasxVqi-RPQP5ppGgL4Ro_a6-N0WYWYiJwunHH5RXk6hEZ6ZtI6kC_crELQUAQgAAAAEAh9AfNWsQGspCrQQTYbwNKH_ZFDp4sAYHZMyxWMDx_6c--QHQEbM2mynw5gVjmRQM8vXQyX4qiM9jW36-EufbFZH6YPxT4g-v0IKi10Lb-_0gwwB2-WtwvjSxrz-CocQGBQBmAAAAAQCFQaFIyIo-2_uc1BOhTG7gGonoAhGFwXEri3ninwh-Vh73kKuvvCgOFPiEOiGeUc_6HBL9S-Xvbqmp82LxpBTH24Yzt6DR-fgvwqnwiBf9Ts64M7Z2Mdn3hVwdAxokezwVpDyhK5G-1QVJFS3fE_malYTRULLSa18RF3a4ic1H3i6xld8FAK4AAAABAOOA5wiA1MTFB5bL3TOneUALPzEkVMdMu_2uoXnDJzdSuXjsQ8ahg3_t8cy9HaW-Qq21vfZWCS8Gc_c6sgJjzHgsdijRS9mBZIQUjMu16w1fbtsE9bpSCj6uiEKTgqLOy6gYYk3oeOk6qWIGKXnJAE4mFKyEuUQXx3cQFUOksvlTgD8BxqHIQiOAGAY3CxllmCmJGQ93dwho4yPoWjphWm9b1ijSDxOAsrr4dGx_HV7Nw5h7-LxFPG1uScIqFbsOXIgzh-8IGU3QjgTi6gUArgAAAAEAsMdfpmupZ-45RDeSvKwM6ZSIief4lgDRjEXSCYY80BF-yigsPm331528f4HTwVNKOWc5FPh30IofgXkep8zLCuSkmQTCVMAgGfYmwj45DvXAf4slwI__NipNmq4AjVWlTVQ9ayIPCINpcou27QLBYheQDUpU7-paSSKmGqWv3dXmjSE-kjhFrNnFQoLuDmhgAM8xYP3MOgNc_FQIQRXsl_lQYHq6VWVTIoxXIL0cQoJTdQFWPE7OZDkQGlQofcNiRcrXFx0uGBJZpf5oBQCuAAAAAQDgXSPKQQFgW-E1kniREBkQXIZr9hJyfxiogcXVLg7UztmsivomI2XV638aynp2zHH3Cqzmb-83HBXLCAsPmKq0uk7imM5W1lBZv-fpizbgwkME4w0qJOdK9I97xQ9iNN8AQfY9TYBoA5IavCzK0QQiDLdMUb-q89UV3X7bGfoEZJabzQiT7MNtEjAQfI1Tu6MBMTDOx0GdvPZWP8_KuIRQPP0XqVCLU53JH2bZdGVsZ39SWNOcgDiNe8PPofNI40Hy14rclkbtvZ1gLHYFADcAAAEBAPgmcZgZbpX3cu8XPTT9gtjx9RaBleApRzxaK9T2qr0vDyBsCY2KTeD6tEvaOAzz1XflsxYYv6xsVVBD4pOtHHfzLsKBVHscJ7Q4kv_KqOKH3X_Fx1IFAFEAAAABAAZsrNtMucZUIr2UFJF3Y9R2FtBAqbm_YLotMSzgyBAAABRnUeng3ADKX8ZIicklSvESgyOeUPCFnOoBhpY-g10PWujfV7mwWWJZdMylaew=',
            'Block1 Block4 swap':
               'v6xsVVBD4pOtHHfzLsKBVHscJ7Q4kv_KqOKH3X_Fx1IFAFEAAAABAAZsrNtMucZUIr2UFJF3Y9R2FtBAqbm_YLotMSzgyBAAABRnUeng3ADKX8ZIicklSvESgyOeUPCFnOoBhpY-g10PWujfV7mwWWJZdMylaewrkb7VBUkVLd8T-ZqVhNFQstJrXxEXdriJzUfeLrGV3wUArgAAAAEA44DnCIDUxMUHlsvdM6d5QAs_MSRUx0y7_a6hecMnN1K5eOxDxqGDf-3xzL0dpb5CrbW99lYJLwZz9zqyAmPMeCx2KNFL2YFkhBSMy7XrDV9u2wT1ulIKPq6IQpOCos7LqBhiTeh46TqpYgYpeckATiYUrIS5RBfHdxAVQ6Sy-VOAPwHGochCI4AYBjcLGWWYKYkZD3d3CGjjI-haOmFab1vWKNIPE4Cyuvh0bKAvhGj9rr43RZhZiInC6ccflFeTqERnpm0jqQL9ysQtBQBCAAAAAQCH0B81axAaykKtBBNhvA0of9kUOniwBgdkzLFYwPH_pz75AdARszabKfDmBWOZFAzy9dDJfiqIz2Nbfr4S59sVkfpg_FPiD6_QgqLXQtv7_SDDAHb5a3C-NLGvP4KhxAYFAGYAAAABAIVBoUjIij7b-5zUE6FMbuAaiegCEYXBcSuLeeKfCH5WHveQq6-8KA4U-IQ6IZ5Rz_ocEv1L5e9uqanzYvGkFMfbhjO3oNH5-C_CqfCIF_1OzrgztnYx2feFXB0DGiR7PBWkPKFt9jLzwDxOLnu6u4cxcgbt1Ga1Vn5F0qDCyO0Xp9W1mAUAMAAAAAEAQTScPYuFjasQGAKP6oqkR9d58Q0YgvW3zEg50a0en8vK2ShqzFWqL5E9A_mmkX8dXs3DmHv4vEU8bW5JwioVuw5ciDOH7wgZTdCOBOLqBQCuAAAAAQCwx1-ma6ln7jlEN5K8rAzplIiJ5_iWANGMRdIJhjzQEX7KKCw-bffXnbx_gdPBU0o5ZzkU-HfQih-BeR6nzMsK5KSZBMJUwCAZ9ibCPjkO9cB_iyXAj_82Kk2argCNVaVNVD1rIg8Ig2lyi7btAsFiF5ANSlTv6lpJIqYapa_d1eaNIT6SOEWs2cVCgu4OaGAAzzFg_cw6A1z8VAhBFeyX-VBgerpVZVMijFcgvRxCglN1AVY8Ts5kORAaVCh9w2JFytcXHS4YElml_mgFAK4AAAABAOBdI8pBAWBb4TWSeJEQGRBchmv2EnJ_GKiBxdUuDtTO2ayK-iYjZdXrfxrKenbMcfcKrOZv7zccFcsICw-YqrS6TuKYzlbWUFm_5-mLNuDCQwTjDSok50r0j3vFD2I03wBB9j1NgGgDkhq8LMrRBCIMt0xRv6rz1RXdftsZ-gRklpvNCJPsw20SMBB8jVO7owExMM7HQZ289lY_z8q4hFA8_RepUItTnckfZtl0ZWxnf1JY05yAOI17w8-h80jjQfLXityWRu29nWAsdgUANwAAAQEA-CZxmBlulfdy7xc9NP2C2PH1FoGV4ClHPFor1PaqvS8PIGwJjYpN4Pq0S9o4DPPVd-WzFhg=',
            'Block1 repeated':
               'v6xsVVBD4pOtHHfzLsKBVHscJ7Q4kv_KqOKH3X_Fx1IFAFEAAAABAAZsrNtMucZUIr2UFJF3Y9R2FtBAqbm_YLotMSzgyBAAABRnUeng3ADKX8ZIicklSvESgyOeUPCFnOoBhpY-g10PWujfV7mwWWJZdMylaext9jLzwDxOLnu6u4cxcgbt1Ga1Vn5F0qDCyO0Xp9W1mAUAMAAAAAEAQTScPYuFjasQGAKP6oqkR9d58Q0YgvW3zEg50a0en8vK2ShqzFWqL5E9A_mmkW32MvPAPE4ue7q7hzFyBu3UZrVWfkXSoMLI7Ren1bWYBQAwAAAAAQBBNJw9i4WNqxAYAo_qiqRH13nxDRiC9bfMSDnRrR6fy8rZKGrMVaovkT0D-aaRoC-EaP2uvjdFmFmIicLpxx-UV5OoRGembSOpAv3KxC0FAEIAAAABAIfQHzVrEBrKQq0EE2G8DSh_2RQ6eLAGB2TMsVjA8f-nPvkB0BGzNpsp8OYFY5kUDPL10Ml-KojPY1t-vhLn2xWR-mD8U-IPr9CCotdC2_v9IMMAdvlrcL40sa8_gqHEBgUAZgAAAAEAhUGhSMiKPtv7nNQToUxu4BqJ6AIRhcFxK4t54p8IflYe95Crr7woDhT4hDohnlHP-hwS_Uvl726pqfNi8aQUx9uGM7eg0fn4L8Kp8IgX_U7OuDO2djHZ94VcHQMaJHs8FaQ8oSuRvtUFSRUt3xP5mpWE0VCy0mtfERd2uInNR94usZXfBQCuAAAAAQDjgOcIgNTExQeWy90zp3lACz8xJFTHTLv9rqF5wyc3Url47EPGoYN_7fHMvR2lvkKttb32VgkvBnP3OrICY8x4LHYo0UvZgWSEFIzLtesNX27bBPW6Ugo-rohCk4KizsuoGGJN6HjpOqliBil5yQBOJhSshLlEF8d3EBVDpLL5U4A_AcahyEIjgBgGNwsZZZgpiRkPd3cIaOMj6Fo6YVpvW9Yo0g8TgLK6-HRsfx1ezcOYe_i8RTxtbknCKhW7DlyIM4fvCBlN0I4E4uoFAK4AAAABALDHX6ZrqWfuOUQ3krysDOmUiInn-JYA0YxF0gmGPNARfsooLD5t99edvH-B08FTSjlnORT4d9CKH4F5HqfMywrkpJkEwlTAIBn2JsI-OQ71wH-LJcCP_zYqTZquAI1VpU1UPWsiDwiDaXKLtu0CwWIXkA1KVO_qWkkiphqlr93V5o0hPpI4RazZxUKC7g5oYADPMWD9zDoDXPxUCEEV7Jf5UGB6ulVlUyKMVyC9HEKCU3UBVjxOzmQ5EBpUKH3DYkXK1xcdLhgSWaX-aAUArgAAAAEA4F0jykEBYFvhNZJ4kRAZEFyGa_YScn8YqIHF1S4O1M7ZrIr6JiNl1et_Gsp6dsxx9wqs5m_vNxwVywgLD5iqtLpO4pjOVtZQWb_n6Ys24MJDBOMNKiTnSvSPe8UPYjTfAEH2PU2AaAOSGrwsytEEIgy3TFG_qvPVFd1-2xn6BGSWm80Ik-zDbRIwEHyNU7ujATEwzsdBnbz2Vj_PyriEUDz9F6lQi1OdyR9m2XRlbGd_UljTnIA4jXvDz6HzSONB8teK3JZG7b2dYCx2BQA3AAABAQD4JnGYGW6V93LvFz00_YLY8fUWgZXgKUc8WivU9qq9Lw8gbAmNik3g-rRL2jgM89V35bMWGA==',
            'Block1 deleted':
               'v6xsVVBD4pOtHHfzLsKBVHscJ7Q4kv_KqOKH3X_Fx1IFAFEAAAABAAZsrNtMucZUIr2UFJF3Y9R2FtBAqbm_YLotMSzgyBAAABRnUeng3ADKX8ZIicklSvESgyOeUPCFnOoBhpY-g10PWujfV7mwWWJZdMylaeygL4Ro_a6-N0WYWYiJwunHH5RXk6hEZ6ZtI6kC_crELQUAQgAAAAEAh9AfNWsQGspCrQQTYbwNKH_ZFDp4sAYHZMyxWMDx_6c--QHQEbM2mynw5gVjmRQM8vXQyX4qiM9jW36-EufbFZH6YPxT4g-v0IKi10Lb-_0gwwB2-WtwvjSxrz-CocQGBQBmAAAAAQCFQaFIyIo-2_uc1BOhTG7gGonoAhGFwXEri3ninwh-Vh73kKuvvCgOFPiEOiGeUc_6HBL9S-Xvbqmp82LxpBTH24Yzt6DR-fgvwqnwiBf9Ts64M7Z2Mdn3hVwdAxokezwVpDyhK5G-1QVJFS3fE_malYTRULLSa18RF3a4ic1H3i6xld8FAK4AAAABAOOA5wiA1MTFB5bL3TOneUALPzEkVMdMu_2uoXnDJzdSuXjsQ8ahg3_t8cy9HaW-Qq21vfZWCS8Gc_c6sgJjzHgsdijRS9mBZIQUjMu16w1fbtsE9bpSCj6uiEKTgqLOy6gYYk3oeOk6qWIGKXnJAE4mFKyEuUQXx3cQFUOksvlTgD8BxqHIQiOAGAY3CxllmCmJGQ93dwho4yPoWjphWm9b1ijSDxOAsrr4dGx_HV7Nw5h7-LxFPG1uScIqFbsOXIgzh-8IGU3QjgTi6gUArgAAAAEAsMdfpmupZ-45RDeSvKwM6ZSIief4lgDRjEXSCYY80BF-yigsPm331528f4HTwVNKOWc5FPh30IofgXkep8zLCuSkmQTCVMAgGfYmwj45DvXAf4slwI__NipNmq4AjVWlTVQ9ayIPCINpcou27QLBYheQDUpU7-paSSKmGqWv3dXmjSE-kjhFrNnFQoLuDmhgAM8xYP3MOgNc_FQIQRXsl_lQYHq6VWVTIoxXIL0cQoJTdQFWPE7OZDkQGlQofcNiRcrXFx0uGBJZpf5oBQCuAAAAAQDgXSPKQQFgW-E1kniREBkQXIZr9hJyfxiogcXVLg7UztmsivomI2XV638aynp2zHH3Cqzmb-83HBXLCAsPmKq0uk7imM5W1lBZv-fpizbgwkME4w0qJOdK9I97xQ9iNN8AQfY9TYBoA5IavCzK0QQiDLdMUb-q89UV3X7bGfoEZJabzQiT7MNtEjAQfI1Tu6MBMTDOx0GdvPZWP8_KuIRQPP0XqVCLU53JH2bZdGVsZ39SWNOcgDiNe8PPofNI40Hy14rclkbtvZ1gLHYFADcAAAEBAPgmcZgZbpX3cu8XPTT9gtjx9RaBleApRzxaK9T2qr0vDyBsCY2KTeD6tEvaOAzz1XflsxYY',
            'Block2 repeated':
               'v6xsVVBD4pOtHHfzLsKBVHscJ7Q4kv_KqOKH3X_Fx1IFAFEAAAABAAZsrNtMucZUIr2UFJF3Y9R2FtBAqbm_YLotMSzgyBAAABRnUeng3ADKX8ZIicklSvESgyOeUPCFnOoBhpY-g10PWujfV7mwWWJZdMylaext9jLzwDxOLnu6u4cxcgbt1Ga1Vn5F0qDCyO0Xp9W1mAUAMAAAAAEAQTScPYuFjasQGAKP6oqkR9d58Q0YgvW3zEg50a0en8vK2ShqzFWqL5E9A_mmkaAvhGj9rr43RZhZiInC6ccflFeTqERnpm0jqQL9ysQtBQBCAAAAAQCH0B81axAaykKtBBNhvA0of9kUOniwBgdkzLFYwPH_pz75AdARszabKfDmBWOZFAzy9dDJfiqIz2Nbfr4S59sVoC-EaP2uvjdFmFmIicLpxx-UV5OoRGembSOpAv3KxC0FAEIAAAABAIfQHzVrEBrKQq0EE2G8DSh_2RQ6eLAGB2TMsVjA8f-nPvkB0BGzNpsp8OYFY5kUDPL10Ml-KojPY1t-vhLn2xWR-mD8U-IPr9CCotdC2_v9IMMAdvlrcL40sa8_gqHEBgUAZgAAAAEAhUGhSMiKPtv7nNQToUxu4BqJ6AIRhcFxK4t54p8IflYe95Crr7woDhT4hDohnlHP-hwS_Uvl726pqfNi8aQUx9uGM7eg0fn4L8Kp8IgX_U7OuDO2djHZ94VcHQMaJHs8FaQ8oSuRvtUFSRUt3xP5mpWE0VCy0mtfERd2uInNR94usZXfBQCuAAAAAQDjgOcIgNTExQeWy90zp3lACz8xJFTHTLv9rqF5wyc3Url47EPGoYN_7fHMvR2lvkKttb32VgkvBnP3OrICY8x4LHYo0UvZgWSEFIzLtesNX27bBPW6Ugo-rohCk4KizsuoGGJN6HjpOqliBil5yQBOJhSshLlEF8d3EBVDpLL5U4A_AcahyEIjgBgGNwsZZZgpiRkPd3cIaOMj6Fo6YVpvW9Yo0g8TgLK6-HRsfx1ezcOYe_i8RTxtbknCKhW7DlyIM4fvCBlN0I4E4uoFAK4AAAABALDHX6ZrqWfuOUQ3krysDOmUiInn-JYA0YxF0gmGPNARfsooLD5t99edvH-B08FTSjlnORT4d9CKH4F5HqfMywrkpJkEwlTAIBn2JsI-OQ71wH-LJcCP_zYqTZquAI1VpU1UPWsiDwiDaXKLtu0CwWIXkA1KVO_qWkkiphqlr93V5o0hPpI4RazZxUKC7g5oYADPMWD9zDoDXPxUCEEV7Jf5UGB6ulVlUyKMVyC9HEKCU3UBVjxOzmQ5EBpUKH3DYkXK1xcdLhgSWaX-aAUArgAAAAEA4F0jykEBYFvhNZJ4kRAZEFyGa_YScn8YqIHF1S4O1M7ZrIr6JiNl1et_Gsp6dsxx9wqs5m_vNxwVywgLD5iqtLpO4pjOVtZQWb_n6Ys24MJDBOMNKiTnSvSPe8UPYjTfAEH2PU2AaAOSGrwsytEEIgy3TFG_qvPVFd1-2xn6BGSWm80Ik-zDbRIwEHyNU7ujATEwzsdBnbz2Vj_PyriEUDz9F6lQi1OdyR9m2XRlbGd_UljTnIA4jXvDz6HzSONB8teK3JZG7b2dYCx2BQA3AAABAQD4JnGYGW6V93LvFz00_YLY8fUWgZXgKUc8WivU9qq9Lw8gbAmNik3g-rRL2jgM89V35bMWGA==',
            'Block2 deleted':
               'v6xsVVBD4pOtHHfzLsKBVHscJ7Q4kv_KqOKH3X_Fx1IFAFEAAAABAAZsrNtMucZUIr2UFJF3Y9R2FtBAqbm_YLotMSzgyBAAABRnUeng3ADKX8ZIicklSvESgyOeUPCFnOoBhpY-g10PWujfV7mwWWJZdMylaext9jLzwDxOLnu6u4cxcgbt1Ga1Vn5F0qDCyO0Xp9W1mAUAMAAAAAEAQTScPYuFjasQGAKP6oqkR9d58Q0YgvW3zEg50a0en8vK2ShqzFWqL5E9A_mmkZH6YPxT4g-v0IKi10Lb-_0gwwB2-WtwvjSxrz-CocQGBQBmAAAAAQCFQaFIyIo-2_uc1BOhTG7gGonoAhGFwXEri3ninwh-Vh73kKuvvCgOFPiEOiGeUc_6HBL9S-Xvbqmp82LxpBTH24Yzt6DR-fgvwqnwiBf9Ts64M7Z2Mdn3hVwdAxokezwVpDyhK5G-1QVJFS3fE_malYTRULLSa18RF3a4ic1H3i6xld8FAK4AAAABAOOA5wiA1MTFB5bL3TOneUALPzEkVMdMu_2uoXnDJzdSuXjsQ8ahg3_t8cy9HaW-Qq21vfZWCS8Gc_c6sgJjzHgsdijRS9mBZIQUjMu16w1fbtsE9bpSCj6uiEKTgqLOy6gYYk3oeOk6qWIGKXnJAE4mFKyEuUQXx3cQFUOksvlTgD8BxqHIQiOAGAY3CxllmCmJGQ93dwho4yPoWjphWm9b1ijSDxOAsrr4dGx_HV7Nw5h7-LxFPG1uScIqFbsOXIgzh-8IGU3QjgTi6gUArgAAAAEAsMdfpmupZ-45RDeSvKwM6ZSIief4lgDRjEXSCYY80BF-yigsPm331528f4HTwVNKOWc5FPh30IofgXkep8zLCuSkmQTCVMAgGfYmwj45DvXAf4slwI__NipNmq4AjVWlTVQ9ayIPCINpcou27QLBYheQDUpU7-paSSKmGqWv3dXmjSE-kjhFrNnFQoLuDmhgAM8xYP3MOgNc_FQIQRXsl_lQYHq6VWVTIoxXIL0cQoJTdQFWPE7OZDkQGlQofcNiRcrXFx0uGBJZpf5oBQCuAAAAAQDgXSPKQQFgW-E1kniREBkQXIZr9hJyfxiogcXVLg7UztmsivomI2XV638aynp2zHH3Cqzmb-83HBXLCAsPmKq0uk7imM5W1lBZv-fpizbgwkME4w0qJOdK9I97xQ9iNN8AQfY9TYBoA5IavCzK0QQiDLdMUb-q89UV3X7bGfoEZJabzQiT7MNtEjAQfI1Tu6MBMTDOx0GdvPZWP8_KuIRQPP0XqVCLU53JH2bZdGVsZ39SWNOcgDiNe8PPofNI40Hy14rclkbtvZ1gLHYFADcAAAEBAPgmcZgZbpX3cu8XPTT9gtjx9RaBleApRzxaK9T2qr0vDyBsCY2KTeD6tEvaOAzz1XflsxYY',
            'Block7 (last) repeated':
               'v6xsVVBD4pOtHHfzLsKBVHscJ7Q4kv_KqOKH3X_Fx1IFAFEAAAABAAZsrNtMucZUIr2UFJF3Y9R2FtBAqbm_YLotMSzgyBAAABRnUeng3ADKX8ZIicklSvESgyOeUPCFnOoBhpY-g10PWujfV7mwWWJZdMylaext9jLzwDxOLnu6u4cxcgbt1Ga1Vn5F0qDCyO0Xp9W1mAUAMAAAAAEAQTScPYuFjasQGAKP6oqkR9d58Q0YgvW3zEg50a0en8vK2ShqzFWqL5E9A_mmkaAvhGj9rr43RZhZiInC6ccflFeTqERnpm0jqQL9ysQtBQBCAAAAAQCH0B81axAaykKtBBNhvA0of9kUOniwBgdkzLFYwPH_pz75AdARszabKfDmBWOZFAzy9dDJfiqIz2Nbfr4S59sVkfpg_FPiD6_QgqLXQtv7_SDDAHb5a3C-NLGvP4KhxAYFAGYAAAABAIVBoUjIij7b-5zUE6FMbuAaiegCEYXBcSuLeeKfCH5WHveQq6-8KA4U-IQ6IZ5Rz_ocEv1L5e9uqanzYvGkFMfbhjO3oNH5-C_CqfCIF_1OzrgztnYx2feFXB0DGiR7PBWkPKErkb7VBUkVLd8T-ZqVhNFQstJrXxEXdriJzUfeLrGV3wUArgAAAAEA44DnCIDUxMUHlsvdM6d5QAs_MSRUx0y7_a6hecMnN1K5eOxDxqGDf-3xzL0dpb5CrbW99lYJLwZz9zqyAmPMeCx2KNFL2YFkhBSMy7XrDV9u2wT1ulIKPq6IQpOCos7LqBhiTeh46TqpYgYpeckATiYUrIS5RBfHdxAVQ6Sy-VOAPwHGochCI4AYBjcLGWWYKYkZD3d3CGjjI-haOmFab1vWKNIPE4Cyuvh0bH8dXs3DmHv4vEU8bW5JwioVuw5ciDOH7wgZTdCOBOLqBQCuAAAAAQCwx1-ma6ln7jlEN5K8rAzplIiJ5_iWANGMRdIJhjzQEX7KKCw-bffXnbx_gdPBU0o5ZzkU-HfQih-BeR6nzMsK5KSZBMJUwCAZ9ibCPjkO9cB_iyXAj_82Kk2argCNVaVNVD1rIg8Ig2lyi7btAsFiF5ANSlTv6lpJIqYapa_d1eaNIT6SOEWs2cVCgu4OaGAAzzFg_cw6A1z8VAhBFeyX-VBgerpVZVMijFcgvRxCglN1AVY8Ts5kORAaVCh9w2JFytcXHS4YElml_mgFAK4AAAABAOBdI8pBAWBb4TWSeJEQGRBchmv2EnJ_GKiBxdUuDtTO2ayK-iYjZdXrfxrKenbMcfcKrOZv7zccFcsICw-YqrS6TuKYzlbWUFm_5-mLNuDCQwTjDSok50r0j3vFD2I03wBB9j1NgGgDkhq8LMrRBCIMt0xRv6rz1RXdftsZ-gRklpvNCJPsw20SMBB8jVO7owExMM7HQZ289lY_z8q4hFA8_RepUItTnckfZtl0ZWxnf1JY05yAOI17w8-h80jjQfLXityWRu29nWAsdgUANwAAAQEA-CZxmBlulfdy7xc9NP2C2PH1FoGV4ClHPFor1PaqvS8PIGwJjYpN4Pq0S9o4DPPVd-WzFhh0ZWxnf1JY05yAOI17w8-h80jjQfLXityWRu29nWAsdgUANwAAAQEA-CZxmBlulfdy7xc9NP2C2PH1FoGV4ClHPFor1PaqvS8PIGwJjYpN4Pq0S9o4DPPVd-WzFhg=',
            'Block7 (last) deleted':
               'v6xsVVBD4pOtHHfzLsKBVHscJ7Q4kv_KqOKH3X_Fx1IFAFEAAAABAAZsrNtMucZUIr2UFJF3Y9R2FtBAqbm_YLotMSzgyBAAABRnUeng3ADKX8ZIicklSvESgyOeUPCFnOoBhpY-g10PWujfV7mwWWJZdMylaext9jLzwDxOLnu6u4cxcgbt1Ga1Vn5F0qDCyO0Xp9W1mAUAMAAAAAEAQTScPYuFjasQGAKP6oqkR9d58Q0YgvW3zEg50a0en8vK2ShqzFWqL5E9A_mmkaAvhGj9rr43RZhZiInC6ccflFeTqERnpm0jqQL9ysQtBQBCAAAAAQCH0B81axAaykKtBBNhvA0of9kUOniwBgdkzLFYwPH_pz75AdARszabKfDmBWOZFAzy9dDJfiqIz2Nbfr4S59sVkfpg_FPiD6_QgqLXQtv7_SDDAHb5a3C-NLGvP4KhxAYFAGYAAAABAIVBoUjIij7b-5zUE6FMbuAaiegCEYXBcSuLeeKfCH5WHveQq6-8KA4U-IQ6IZ5Rz_ocEv1L5e9uqanzYvGkFMfbhjO3oNH5-C_CqfCIF_1OzrgztnYx2feFXB0DGiR7PBWkPKErkb7VBUkVLd8T-ZqVhNFQstJrXxEXdriJzUfeLrGV3wUArgAAAAEA44DnCIDUxMUHlsvdM6d5QAs_MSRUx0y7_a6hecMnN1K5eOxDxqGDf-3xzL0dpb5CrbW99lYJLwZz9zqyAmPMeCx2KNFL2YFkhBSMy7XrDV9u2wT1ulIKPq6IQpOCos7LqBhiTeh46TqpYgYpeckATiYUrIS5RBfHdxAVQ6Sy-VOAPwHGochCI4AYBjcLGWWYKYkZD3d3CGjjI-haOmFab1vWKNIPE4Cyuvh0bH8dXs3DmHv4vEU8bW5JwioVuw5ciDOH7wgZTdCOBOLqBQCuAAAAAQCwx1-ma6ln7jlEN5K8rAzplIiJ5_iWANGMRdIJhjzQEX7KKCw-bffXnbx_gdPBU0o5ZzkU-HfQih-BeR6nzMsK5KSZBMJUwCAZ9ibCPjkO9cB_iyXAj_82Kk2argCNVaVNVD1rIg8Ig2lyi7btAsFiF5ANSlTv6lpJIqYapa_d1eaNIT6SOEWs2cVCgu4OaGAAzzFg_cw6A1z8VAhBFeyX-VBgerpVZVMijFcgvRxCglN1AVY8Ts5kORAaVCh9w2JFytcXHS4YElml_mgFAK4AAAABAOBdI8pBAWBb4TWSeJEQGRBchmv2EnJ_GKiBxdUuDtTO2ayK-iYjZdXrfxrKenbMcfcKrOZv7zccFcsICw-YqrS6TuKYzlbWUFm_5-mLNuDCQwTjDSok50r0j3vFD2I03wBB9j1NgGgDkhq8LMrRBCIMt0xRv6rz1RXdftsZ-gRklpvNCJPsw20SMBB8jVO7owExMM7HQZ289lY_z8q4hFA8_RepUItTnckfZtk=',
            'Block1 Block7 deleted':
               'v6xsVVBD4pOtHHfzLsKBVHscJ7Q4kv_KqOKH3X_Fx1IFAFEAAAABAAZsrNtMucZUIr2UFJF3Y9R2FtBAqbm_YLotMSzgyBAAABRnUeng3ADKX8ZIicklSvESgyOeUPCFnOoBhpY-g10PWujfV7mwWWJZdMylaew=',
         },
      },
      //v6
      {
         ver: 6,
         goodCt:
            '145SfB4dIqbmYy-bH1rnh1pyFN8T1EyEyFCMFtguBkAGAFIAAAABADHsHML87chQYK_58RxCa0lVLRW9ueVEO55SH6vgyBAAABRO3eqnNV_xNxBnsX-r7KYWgn5F-xMiA5lTNfDYw7tOoCgtF_qddOXjyHisEb0b8z5ZdoouvyB9aG3QlCbc9XTBfAN4yPYcxrzdASguAgYAMQAAAAEAl0vO23m4DaUuLlCchOsXoKnl4bYKmhmX_ydWm2p95AwKZcdXuNcSgBMD17fjfQxogLpTAVw46IYT6Yade9GaEZeK-H4_IWcRVVloHAjiBgBDAAAAAQCkAj9mmn0ml0CccOOHETPlyrQ0qPr2vtFzCrvt-SAx_VfWK3UP7bsmKruWrF9fXPaHjlhEl9b3BzLgWFRhEI1tccFm2H62Twhok-txX_Tzma2f-1wEacpdfUYuiGgYpgIGAGcAAAABAOjptoow8I9KMVohLYUE7yt4Bvt23UzOw_nrRXVseI-n_TJ1i3jBtcdWk1hfrvWlw-2PoJZyH2oFJi2vn0Ulo_TxtGOAxKV6bPz28qxg4AenSlhmenw8N6AuS-QkSe71LDKczPAYp90W6ZiO06uOk9Dgv3ftONRWM9yuN7Kt0IqnKR5FRwYArwAAAAEAcUDPBJ_iL9JmZB8vrg4cNOJQ0zniAhWDhetArzNGPK9jJ1XPpvt7eZUyCCIvMbMFJL9sCMMNyQ6GpQbu3Yb5ykCA7UjRKDyjZaHvMifXl1DtJX8D7tkilUD9CxFG5JDiZP5WSVbK9vufZZXYmO0Rb55-XDrEwAkFGv_Z7baL3CCvFBApV8pgJFP4Y6BgzoF3X1Twah0_lpB8amihm74KoQmIR-PzuCZwRYdIcbnSCPRcEQDEAJteYV1mNHZZ4RjAebx4UKfaNFzpS3bRBgCvAAAAAQBi_iVR4Q8bxXY2--aZBV6HpYFK8iHV2R5wynUcAjctCSonwJJkv0_LZ14vFpgDak70e6exgvIfAkLb_vpjfDN8B_xKWKcuBNLvg1XwVHwEkXu0OW_a2T6FJLwVN9yYMd7TrCEqjx-Ey77eGlvie66gfdsAfqsfM_bA_rmstmDdEWZN0oKZQ4dhEuuinf61NL6R2zuH_AOm-rqgSYuHnZSZrVkmFCvmWDPsthBVH_ndo_8jdaFw-0H6fTScHXdxi4ByWbFikOScO7Og4UsGAK8AAAABAKMxDRKY02yKwaHyj5hGCyjjzls4u_KJbhq_kyU1LapORWJ8PrLU7ngWKZVV7nDbLbiGr7618KJTO9QTypg-mpqZLxKshTQh1T9y7OcIi41phr-OgQtmfLNsTq-poL9KA8j4JKQOE7BbgKWuGuD2106SJueQ0j-OdQq8FmZF3wvI_GH3jKlxnc-TsZYNz297pBBEx1X87YWHlaEG6IYsuMxTZUmuOXrZ4EAXWa2fNQwontou1_P0uGJW-zOp_0B_66xoXQZzWxBZDYXMHwYAOAAAAQEAQRiF8kaVmi2xqbQV1__kKXlpRGQvNsAWpDpH20Q-1_GWz1vSBPm5Q3OEPzO4jYh7NNy3GqI=',
         badCts: {
            '1. Block0 Block7 swap':
               'nzUMKJ7aLtfz9LhiVvszqf9Af-usaF0Gc1sQWQ2FzB8GADgAAAEBAEEYhfJGlZotsam0Fdf_5Cl5aURkLzbAFqQ6R9tEPtfxls9b0gT5uUNzhD8zuI2IezTctxqiG_M-WXaKLr8gfWht0JQm3PV0wXwDeMj2HMa83QEoLgIGADEAAAABAJdLztt5uA2lLi5QnITrF6Cp5eG2CpoZl_8nVptqfeQMCmXHV7jXEoATA9e3430MaIC6UwFcOOiGE-mGnXvRmhGXivh-PyFnEVVZaBwI4gYAQwAAAAEApAI_Zpp9JpdAnHDjhxEz5cq0NKj69r7Rcwq77fkgMf1X1it1D-27Jiq7lqxfX1z2h45YRJfW9wcy4FhUYRCNbXHBZth-tk8IaJPrcV_085mtn_tcBGnKXX1GLohoGKYCBgBnAAAAAQDo6baKMPCPSjFaIS2FBO8reAb7dt1MzsP560V1bHiPp_0ydYt4wbXHVpNYX671pcPtj6CWch9qBSYtr59FJaP08bRjgMSlemz89vKsYOAHp0pYZnp8PDegLkvkJEnu9SwynMzwGKfdFumYjtOrjpPQ4L937TjUVjPcrjeyrdCKpykeRUcGAK8AAAABAHFAzwSf4i_SZmQfL64OHDTiUNM54gIVg4XrQK8zRjyvYydVz6b7e3mVMggiLzGzBSS_bAjDDckOhqUG7t2G-cpAgO1I0Sg8o2Wh7zIn15dQ7SV_A-7ZIpVA_QsRRuSQ4mT-VklWyvb7n2WV2JjtEW-eflw6xMAJBRr_2e22i9wgrxQQKVfKYCRT-GOgYM6Bd19U8GodP5aQfGpooZu-CqEJiEfj87gmcEWHSHG50gj0XBEAxACbXmFdZjR2WeEYwHm8eFCn2jRc6Ut20QYArwAAAAEAYv4lUeEPG8V2NvvmmQVeh6WBSvIh1dkecMp1HAI3LQkqJ8CSZL9Py2deLxaYA2pO9HunsYLyHwJC2_76Y3wzfAf8SlinLgTS74NV8FR8BJF7tDlv2tk-hSS8FTfcmDHe06whKo8fhMu-3hpb4nuuoH3bAH6rHzP2wP65rLZg3RFmTdKCmUOHYRLrop3-tTS-kds7h_wDpvq6oEmLh52Uma1ZJhQr5lgz7LYQVR_53aP_I3WhcPtB-n00nB13cYuAclmxYpDknDuzoOFLBgCvAAAAAQCjMQ0SmNNsisGh8o-YRgso485bOLvyiW4av5MlNS2qTkVifD6y1O54FimVVe5w2y24hq--tfCiUzvUE8qYPpqamS8SrIU0IdU_cuznCIuNaYa_joELZnyzbE6vqaC_SgPI-CSkDhOwW4Clrhrg9tdOkibnkNI_jnUKvBZmRd8LyPxh94ypcZ3Pk7GWDc9ve6QQRMdV_O2Fh5WhBuiGLLjMU2VJrjl62eBAF1mt145SfB4dIqbmYy-bH1rnh1pyFN8T1EyEyFCMFtguBkAGAFIAAAABADHsHML87chQYK_58RxCa0lVLRW9ueVEO55SH6vgyBAAABRO3eqnNV_xNxBnsX-r7KYWgn5F-xMiA5lTNfDYw7tOoCgtF_qddOXjyHisEb0',
            '2. Block1 Block7 swap':
               '145SfB4dIqbmYy-bH1rnh1pyFN8T1EyEyFCMFtguBkAGAFIAAAABADHsHML87chQYK_58RxCa0lVLRW9ueVEO55SH6vgyBAAABRO3eqnNV_xNxBnsX-r7KYWgn5F-xMiA5lTNfDYw7tOoCgtF_qddOXjyHisEb2fNQwontou1_P0uGJW-zOp_0B_66xoXQZzWxBZDYXMHwYAOAAAAQEAQRiF8kaVmi2xqbQV1__kKXlpRGQvNsAWpDpH20Q-1_GWz1vSBPm5Q3OEPzO4jYh7NNy3GqIMaIC6UwFcOOiGE-mGnXvRmhGXivh-PyFnEVVZaBwI4gYAQwAAAAEApAI_Zpp9JpdAnHDjhxEz5cq0NKj69r7Rcwq77fkgMf1X1it1D-27Jiq7lqxfX1z2h45YRJfW9wcy4FhUYRCNbXHBZth-tk8IaJPrcV_085mtn_tcBGnKXX1GLohoGKYCBgBnAAAAAQDo6baKMPCPSjFaIS2FBO8reAb7dt1MzsP560V1bHiPp_0ydYt4wbXHVpNYX671pcPtj6CWch9qBSYtr59FJaP08bRjgMSlemz89vKsYOAHp0pYZnp8PDegLkvkJEnu9SwynMzwGKfdFumYjtOrjpPQ4L937TjUVjPcrjeyrdCKpykeRUcGAK8AAAABAHFAzwSf4i_SZmQfL64OHDTiUNM54gIVg4XrQK8zRjyvYydVz6b7e3mVMggiLzGzBSS_bAjDDckOhqUG7t2G-cpAgO1I0Sg8o2Wh7zIn15dQ7SV_A-7ZIpVA_QsRRuSQ4mT-VklWyvb7n2WV2JjtEW-eflw6xMAJBRr_2e22i9wgrxQQKVfKYCRT-GOgYM6Bd19U8GodP5aQfGpooZu-CqEJiEfj87gmcEWHSHG50gj0XBEAxACbXmFdZjR2WeEYwHm8eFCn2jRc6Ut20QYArwAAAAEAYv4lUeEPG8V2NvvmmQVeh6WBSvIh1dkecMp1HAI3LQkqJ8CSZL9Py2deLxaYA2pO9HunsYLyHwJC2_76Y3wzfAf8SlinLgTS74NV8FR8BJF7tDlv2tk-hSS8FTfcmDHe06whKo8fhMu-3hpb4nuuoH3bAH6rHzP2wP65rLZg3RFmTdKCmUOHYRLrop3-tTS-kds7h_wDpvq6oEmLh52Uma1ZJhQr5lgz7LYQVR_53aP_I3WhcPtB-n00nB13cYuAclmxYpDknDuzoOFLBgCvAAAAAQCjMQ0SmNNsisGh8o-YRgso485bOLvyiW4av5MlNS2qTkVifD6y1O54FimVVe5w2y24hq--tfCiUzvUE8qYPpqamS8SrIU0IdU_cuznCIuNaYa_joELZnyzbE6vqaC_SgPI-CSkDhOwW4Clrhrg9tdOkibnkNI_jnUKvBZmRd8LyPxh94ypcZ3Pk7GWDc9ve6QQRMdV_O2Fh5WhBuiGLLjMU2VJrjl62eBAF1mtG_M-WXaKLr8gfWht0JQm3PV0wXwDeMj2HMa83QEoLgIGADEAAAABAJdLztt5uA2lLi5QnITrF6Cp5eG2CpoZl_8nVptqfeQMCmXHV7jXEoATA9e3430',
            '3. Block1 Block4 swap':
               '145SfB4dIqbmYy-bH1rnh1pyFN8T1EyEyFCMFtguBkAGAFIAAAABADHsHML87chQYK_58RxCa0lVLRW9ueVEO55SH6vgyBAAABRO3eqnNV_xNxBnsX-r7KYWgn5F-xMiA5lTNfDYw7tOoCgtF_qddOXjyHisEb0Yp90W6ZiO06uOk9Dgv3ftONRWM9yuN7Kt0IqnKR5FRwYArwAAAAEAcUDPBJ_iL9JmZB8vrg4cNOJQ0zniAhWDhetArzNGPK9jJ1XPpvt7eZUyCCIvMbMFJL9sCMMNyQ6GpQbu3Yb5ykCA7UjRKDyjZaHvMifXl1DtJX8D7tkilUD9CxFG5JDiZP5WSVbK9vufZZXYmO0Rb55-XDrEwAkFGv_Z7baL3CCvFBApV8pgJFP4Y6BgzoF3X1Twah0_lpB8amihm74KoQmIR-PzuCZwRYdIcQxogLpTAVw46IYT6Yade9GaEZeK-H4_IWcRVVloHAjiBgBDAAAAAQCkAj9mmn0ml0CccOOHETPlyrQ0qPr2vtFzCrvt-SAx_VfWK3UP7bsmKruWrF9fXPaHjlhEl9b3BzLgWFRhEI1tccFm2H62Twhok-txX_Tzma2f-1wEacpdfUYuiGgYpgIGAGcAAAABAOjptoow8I9KMVohLYUE7yt4Bvt23UzOw_nrRXVseI-n_TJ1i3jBtcdWk1hfrvWlw-2PoJZyH2oFJi2vn0Ulo_TxtGOAxKV6bPz28qxg4AenSlhmenw8N6AuS-QkSe71LDKczPAb8z5ZdoouvyB9aG3QlCbc9XTBfAN4yPYcxrzdASguAgYAMQAAAAEAl0vO23m4DaUuLlCchOsXoKnl4bYKmhmX_ydWm2p95AwKZcdXuNcSgBMD17fjfbnSCPRcEQDEAJteYV1mNHZZ4RjAebx4UKfaNFzpS3bRBgCvAAAAAQBi_iVR4Q8bxXY2--aZBV6HpYFK8iHV2R5wynUcAjctCSonwJJkv0_LZ14vFpgDak70e6exgvIfAkLb_vpjfDN8B_xKWKcuBNLvg1XwVHwEkXu0OW_a2T6FJLwVN9yYMd7TrCEqjx-Ey77eGlvie66gfdsAfqsfM_bA_rmstmDdEWZN0oKZQ4dhEuuinf61NL6R2zuH_AOm-rqgSYuHnZSZrVkmFCvmWDPsthBVH_ndo_8jdaFw-0H6fTScHXdxi4ByWbFikOScO7Og4UsGAK8AAAABAKMxDRKY02yKwaHyj5hGCyjjzls4u_KJbhq_kyU1LapORWJ8PrLU7ngWKZVV7nDbLbiGr7618KJTO9QTypg-mpqZLxKshTQh1T9y7OcIi41phr-OgQtmfLNsTq-poL9KA8j4JKQOE7BbgKWuGuD2106SJueQ0j-OdQq8FmZF3wvI_GH3jKlxnc-TsZYNz297pBBEx1X87YWHlaEG6IYsuMxTZUmuOXrZ4EAXWa2fNQwontou1_P0uGJW-zOp_0B_66xoXQZzWxBZDYXMHwYAOAAAAQEAQRiF8kaVmi2xqbQV1__kKXlpRGQvNsAWpDpH20Q-1_GWz1vSBPm5Q3OEPzO4jYh7NNy3GqI',
            '4. Block0 repeated':
               '145SfB4dIqbmYy-bH1rnh1pyFN8T1EyEyFCMFtguBkAGAFIAAAABADHsHML87chQYK_58RxCa0lVLRW9ueVEO55SH6vgyBAAABRO3eqnNV_xNxBnsX-r7KYWgn5F-xMiA5lTNfDYw7tOoCgtF_qddOXjyHisEb3XjlJ8Hh0ipuZjL5sfWueHWnIU3xPUTITIUIwW2C4GQAYAUgAAAAEAMewcwvztyFBgr_nxHEJrSVUtFb255UQ7nlIfq-DIEAAAFE7d6qc1X_E3EGexf6vsphaCfkX7EyIDmVM18NjDu06gKC0X-p105ePIeKwRvRvzPll2ii6_IH1obdCUJtz1dMF8A3jI9hzGvN0BKC4CBgAxAAAAAQCXS87bebgNpS4uUJyE6xegqeXhtgqaGZf_J1aban3kDAplx1e41xKAEwPXt-N9DGiAulMBXDjohhPphp170ZoRl4r4fj8hZxFVWWgcCOIGAEMAAAABAKQCP2aafSaXQJxw44cRM-XKtDSo-va-0XMKu-35IDH9V9YrdQ_tuyYqu5asX19c9oeOWESX1vcHMuBYVGEQjW1xwWbYfrZPCGiT63Ff9POZrZ_7XARpyl19Ri6IaBimAgYAZwAAAAEA6Om2ijDwj0oxWiEthQTvK3gG-3bdTM7D-etFdWx4j6f9MnWLeMG1x1aTWF-u9aXD7Y-glnIfagUmLa-fRSWj9PG0Y4DEpXps_PbyrGDgB6dKWGZ6fDw3oC5L5CRJ7vUsMpzM8Bin3RbpmI7Tq46T0OC_d-041FYz3K43sq3QiqcpHkVHBgCvAAAAAQBxQM8En-Iv0mZkHy-uDhw04lDTOeICFYOF60CvM0Y8r2MnVc-m-3t5lTIIIi8xswUkv2wIww3JDoalBu7dhvnKQIDtSNEoPKNloe8yJ9eXUO0lfwPu2SKVQP0LEUbkkOJk_lZJVsr2-59lldiY7RFvnn5cOsTACQUa_9nttovcIK8UEClXymAkU_hjoGDOgXdfVPBqHT-WkHxqaKGbvgqhCYhH4_O4JnBFh0hxudII9FwRAMQAm15hXWY0dlnhGMB5vHhQp9o0XOlLdtEGAK8AAAABAGL-JVHhDxvFdjb75pkFXoelgUryIdXZHnDKdRwCNy0JKifAkmS_T8tnXi8WmANqTvR7p7GC8h8CQtv--mN8M3wH_EpYpy4E0u-DVfBUfASRe7Q5b9rZPoUkvBU33Jgx3tOsISqPH4TLvt4aW-J7rqB92wB-qx8z9sD-uay2YN0RZk3SgplDh2ES66Kd_rU0vpHbO4f8A6b6uqBJi4edlJmtWSYUK-ZYM-y2EFUf-d2j_yN1oXD7Qfp9NJwdd3GLgHJZsWKQ5Jw7s6DhSwYArwAAAAEAozENEpjTbIrBofKPmEYLKOPOWzi78oluGr-TJTUtqk5FYnw-stTueBYplVXucNstuIavvrXwolM71BPKmD6ampkvEqyFNCHVP3Ls5wiLjWmGv46BC2Z8s2xOr6mgv0oDyPgkpA4TsFuApa4a4PbXTpIm55DSP451CrwWZkXfC8j8YfeMqXGdz5Oxlg3Pb3ukEETHVfzthYeVoQbohiy4zFNlSa45etngQBdZrZ81DCie2i7X8_S4Ylb7M6n_QH_rrGhdBnNbEFkNhcwfBgA4AAABAQBBGIXyRpWaLbGptBXX_-QpeWlEZC82wBakOkfbRD7X8ZbPW9IE-blDc4Q_M7iNiHs03Lcaog',
            '5. Block0 deleted':
               'G_M-WXaKLr8gfWht0JQm3PV0wXwDeMj2HMa83QEoLgIGADEAAAABAJdLztt5uA2lLi5QnITrF6Cp5eG2CpoZl_8nVptqfeQMCmXHV7jXEoATA9e3430MaIC6UwFcOOiGE-mGnXvRmhGXivh-PyFnEVVZaBwI4gYAQwAAAAEApAI_Zpp9JpdAnHDjhxEz5cq0NKj69r7Rcwq77fkgMf1X1it1D-27Jiq7lqxfX1z2h45YRJfW9wcy4FhUYRCNbXHBZth-tk8IaJPrcV_085mtn_tcBGnKXX1GLohoGKYCBgBnAAAAAQDo6baKMPCPSjFaIS2FBO8reAb7dt1MzsP560V1bHiPp_0ydYt4wbXHVpNYX671pcPtj6CWch9qBSYtr59FJaP08bRjgMSlemz89vKsYOAHp0pYZnp8PDegLkvkJEnu9SwynMzwGKfdFumYjtOrjpPQ4L937TjUVjPcrjeyrdCKpykeRUcGAK8AAAABAHFAzwSf4i_SZmQfL64OHDTiUNM54gIVg4XrQK8zRjyvYydVz6b7e3mVMggiLzGzBSS_bAjDDckOhqUG7t2G-cpAgO1I0Sg8o2Wh7zIn15dQ7SV_A-7ZIpVA_QsRRuSQ4mT-VklWyvb7n2WV2JjtEW-eflw6xMAJBRr_2e22i9wgrxQQKVfKYCRT-GOgYM6Bd19U8GodP5aQfGpooZu-CqEJiEfj87gmcEWHSHG50gj0XBEAxACbXmFdZjR2WeEYwHm8eFCn2jRc6Ut20QYArwAAAAEAYv4lUeEPG8V2NvvmmQVeh6WBSvIh1dkecMp1HAI3LQkqJ8CSZL9Py2deLxaYA2pO9HunsYLyHwJC2_76Y3wzfAf8SlinLgTS74NV8FR8BJF7tDlv2tk-hSS8FTfcmDHe06whKo8fhMu-3hpb4nuuoH3bAH6rHzP2wP65rLZg3RFmTdKCmUOHYRLrop3-tTS-kds7h_wDpvq6oEmLh52Uma1ZJhQr5lgz7LYQVR_53aP_I3WhcPtB-n00nB13cYuAclmxYpDknDuzoOFLBgCvAAAAAQCjMQ0SmNNsisGh8o-YRgso485bOLvyiW4av5MlNS2qTkVifD6y1O54FimVVe5w2y24hq--tfCiUzvUE8qYPpqamS8SrIU0IdU_cuznCIuNaYa_joELZnyzbE6vqaC_SgPI-CSkDhOwW4Clrhrg9tdOkibnkNI_jnUKvBZmRd8LyPxh94ypcZ3Pk7GWDc9ve6QQRMdV_O2Fh5WhBuiGLLjMU2VJrjl62eBAF1mtnzUMKJ7aLtfz9LhiVvszqf9Af-usaF0Gc1sQWQ2FzB8GADgAAAEBAEEYhfJGlZotsam0Fdf_5Cl5aURkLzbAFqQ6R9tEPtfxls9b0gT5uUNzhD8zuI2IezTctxqi',
            '6. Block1 repeated':
               '145SfB4dIqbmYy-bH1rnh1pyFN8T1EyEyFCMFtguBkAGAFIAAAABADHsHML87chQYK_58RxCa0lVLRW9ueVEO55SH6vgyBAAABRO3eqnNV_xNxBnsX-r7KYWgn5F-xMiA5lTNfDYw7tOoCgtF_qddOXjyHisEb0b8z5ZdoouvyB9aG3QlCbc9XTBfAN4yPYcxrzdASguAgYAMQAAAAEAl0vO23m4DaUuLlCchOsXoKnl4bYKmhmX_ydWm2p95AwKZcdXuNcSgBMD17fjfRvzPll2ii6_IH1obdCUJtz1dMF8A3jI9hzGvN0BKC4CBgAxAAAAAQCXS87bebgNpS4uUJyE6xegqeXhtgqaGZf_J1aban3kDAplx1e41xKAEwPXt-N9DGiAulMBXDjohhPphp170ZoRl4r4fj8hZxFVWWgcCOIGAEMAAAABAKQCP2aafSaXQJxw44cRM-XKtDSo-va-0XMKu-35IDH9V9YrdQ_tuyYqu5asX19c9oeOWESX1vcHMuBYVGEQjW1xwWbYfrZPCGiT63Ff9POZrZ_7XARpyl19Ri6IaBimAgYAZwAAAAEA6Om2ijDwj0oxWiEthQTvK3gG-3bdTM7D-etFdWx4j6f9MnWLeMG1x1aTWF-u9aXD7Y-glnIfagUmLa-fRSWj9PG0Y4DEpXps_PbyrGDgB6dKWGZ6fDw3oC5L5CRJ7vUsMpzM8Bin3RbpmI7Tq46T0OC_d-041FYz3K43sq3QiqcpHkVHBgCvAAAAAQBxQM8En-Iv0mZkHy-uDhw04lDTOeICFYOF60CvM0Y8r2MnVc-m-3t5lTIIIi8xswUkv2wIww3JDoalBu7dhvnKQIDtSNEoPKNloe8yJ9eXUO0lfwPu2SKVQP0LEUbkkOJk_lZJVsr2-59lldiY7RFvnn5cOsTACQUa_9nttovcIK8UEClXymAkU_hjoGDOgXdfVPBqHT-WkHxqaKGbvgqhCYhH4_O4JnBFh0hxudII9FwRAMQAm15hXWY0dlnhGMB5vHhQp9o0XOlLdtEGAK8AAAABAGL-JVHhDxvFdjb75pkFXoelgUryIdXZHnDKdRwCNy0JKifAkmS_T8tnXi8WmANqTvR7p7GC8h8CQtv--mN8M3wH_EpYpy4E0u-DVfBUfASRe7Q5b9rZPoUkvBU33Jgx3tOsISqPH4TLvt4aW-J7rqB92wB-qx8z9sD-uay2YN0RZk3SgplDh2ES66Kd_rU0vpHbO4f8A6b6uqBJi4edlJmtWSYUK-ZYM-y2EFUf-d2j_yN1oXD7Qfp9NJwdd3GLgHJZsWKQ5Jw7s6DhSwYArwAAAAEAozENEpjTbIrBofKPmEYLKOPOWzi78oluGr-TJTUtqk5FYnw-stTueBYplVXucNstuIavvrXwolM71BPKmD6ampkvEqyFNCHVP3Ls5wiLjWmGv46BC2Z8s2xOr6mgv0oDyPgkpA4TsFuApa4a4PbXTpIm55DSP451CrwWZkXfC8j8YfeMqXGdz5Oxlg3Pb3ukEETHVfzthYeVoQbohiy4zFNlSa45etngQBdZrZ81DCie2i7X8_S4Ylb7M6n_QH_rrGhdBnNbEFkNhcwfBgA4AAABAQBBGIXyRpWaLbGptBXX_-QpeWlEZC82wBakOkfbRD7X8ZbPW9IE-blDc4Q_M7iNiHs03Lcaog',
            '7. Block1 deleted':
               '145SfB4dIqbmYy-bH1rnh1pyFN8T1EyEyFCMFtguBkAGAFIAAAABADHsHML87chQYK_58RxCa0lVLRW9ueVEO55SH6vgyBAAABRO3eqnNV_xNxBnsX-r7KYWgn5F-xMiA5lTNfDYw7tOoCgtF_qddOXjyHisEb0MaIC6UwFcOOiGE-mGnXvRmhGXivh-PyFnEVVZaBwI4gYAQwAAAAEApAI_Zpp9JpdAnHDjhxEz5cq0NKj69r7Rcwq77fkgMf1X1it1D-27Jiq7lqxfX1z2h45YRJfW9wcy4FhUYRCNbXHBZth-tk8IaJPrcV_085mtn_tcBGnKXX1GLohoGKYCBgBnAAAAAQDo6baKMPCPSjFaIS2FBO8reAb7dt1MzsP560V1bHiPp_0ydYt4wbXHVpNYX671pcPtj6CWch9qBSYtr59FJaP08bRjgMSlemz89vKsYOAHp0pYZnp8PDegLkvkJEnu9SwynMzwGKfdFumYjtOrjpPQ4L937TjUVjPcrjeyrdCKpykeRUcGAK8AAAABAHFAzwSf4i_SZmQfL64OHDTiUNM54gIVg4XrQK8zRjyvYydVz6b7e3mVMggiLzGzBSS_bAjDDckOhqUG7t2G-cpAgO1I0Sg8o2Wh7zIn15dQ7SV_A-7ZIpVA_QsRRuSQ4mT-VklWyvb7n2WV2JjtEW-eflw6xMAJBRr_2e22i9wgrxQQKVfKYCRT-GOgYM6Bd19U8GodP5aQfGpooZu-CqEJiEfj87gmcEWHSHG50gj0XBEAxACbXmFdZjR2WeEYwHm8eFCn2jRc6Ut20QYArwAAAAEAYv4lUeEPG8V2NvvmmQVeh6WBSvIh1dkecMp1HAI3LQkqJ8CSZL9Py2deLxaYA2pO9HunsYLyHwJC2_76Y3wzfAf8SlinLgTS74NV8FR8BJF7tDlv2tk-hSS8FTfcmDHe06whKo8fhMu-3hpb4nuuoH3bAH6rHzP2wP65rLZg3RFmTdKCmUOHYRLrop3-tTS-kds7h_wDpvq6oEmLh52Uma1ZJhQr5lgz7LYQVR_53aP_I3WhcPtB-n00nB13cYuAclmxYpDknDuzoOFLBgCvAAAAAQCjMQ0SmNNsisGh8o-YRgso485bOLvyiW4av5MlNS2qTkVifD6y1O54FimVVe5w2y24hq--tfCiUzvUE8qYPpqamS8SrIU0IdU_cuznCIuNaYa_joELZnyzbE6vqaC_SgPI-CSkDhOwW4Clrhrg9tdOkibnkNI_jnUKvBZmRd8LyPxh94ypcZ3Pk7GWDc9ve6QQRMdV_O2Fh5WhBuiGLLjMU2VJrjl62eBAF1mtnzUMKJ7aLtfz9LhiVvszqf9Af-usaF0Gc1sQWQ2FzB8GADgAAAEBAEEYhfJGlZotsam0Fdf_5Cl5aURkLzbAFqQ6R9tEPtfxls9b0gT5uUNzhD8zuI2IezTctxqi',
            '8. Block2 repeated':
               '145SfB4dIqbmYy-bH1rnh1pyFN8T1EyEyFCMFtguBkAGAFIAAAABADHsHML87chQYK_58RxCa0lVLRW9ueVEO55SH6vgyBAAABRO3eqnNV_xNxBnsX-r7KYWgn5F-xMiA5lTNfDYw7tOoCgtF_qddOXjyHisEb0b8z5ZdoouvyB9aG3QlCbc9XTBfAN4yPYcxrzdASguAgYAMQAAAAEAl0vO23m4DaUuLlCchOsXoKnl4bYKmhmX_ydWm2p95AwKZcdXuNcSgBMD17fjfQxogLpTAVw46IYT6Yade9GaEZeK-H4_IWcRVVloHAjiBgBDAAAAAQCkAj9mmn0ml0CccOOHETPlyrQ0qPr2vtFzCrvt-SAx_VfWK3UP7bsmKruWrF9fXPaHjlhEl9b3BzLgWFRhEI1tDGiAulMBXDjohhPphp170ZoRl4r4fj8hZxFVWWgcCOIGAEMAAAABAKQCP2aafSaXQJxw44cRM-XKtDSo-va-0XMKu-35IDH9V9YrdQ_tuyYqu5asX19c9oeOWESX1vcHMuBYVGEQjW1xwWbYfrZPCGiT63Ff9POZrZ_7XARpyl19Ri6IaBimAgYAZwAAAAEA6Om2ijDwj0oxWiEthQTvK3gG-3bdTM7D-etFdWx4j6f9MnWLeMG1x1aTWF-u9aXD7Y-glnIfagUmLa-fRSWj9PG0Y4DEpXps_PbyrGDgB6dKWGZ6fDw3oC5L5CRJ7vUsMpzM8Bin3RbpmI7Tq46T0OC_d-041FYz3K43sq3QiqcpHkVHBgCvAAAAAQBxQM8En-Iv0mZkHy-uDhw04lDTOeICFYOF60CvM0Y8r2MnVc-m-3t5lTIIIi8xswUkv2wIww3JDoalBu7dhvnKQIDtSNEoPKNloe8yJ9eXUO0lfwPu2SKVQP0LEUbkkOJk_lZJVsr2-59lldiY7RFvnn5cOsTACQUa_9nttovcIK8UEClXymAkU_hjoGDOgXdfVPBqHT-WkHxqaKGbvgqhCYhH4_O4JnBFh0hxudII9FwRAMQAm15hXWY0dlnhGMB5vHhQp9o0XOlLdtEGAK8AAAABAGL-JVHhDxvFdjb75pkFXoelgUryIdXZHnDKdRwCNy0JKifAkmS_T8tnXi8WmANqTvR7p7GC8h8CQtv--mN8M3wH_EpYpy4E0u-DVfBUfASRe7Q5b9rZPoUkvBU33Jgx3tOsISqPH4TLvt4aW-J7rqB92wB-qx8z9sD-uay2YN0RZk3SgplDh2ES66Kd_rU0vpHbO4f8A6b6uqBJi4edlJmtWSYUK-ZYM-y2EFUf-d2j_yN1oXD7Qfp9NJwdd3GLgHJZsWKQ5Jw7s6DhSwYArwAAAAEAozENEpjTbIrBofKPmEYLKOPOWzi78oluGr-TJTUtqk5FYnw-stTueBYplVXucNstuIavvrXwolM71BPKmD6ampkvEqyFNCHVP3Ls5wiLjWmGv46BC2Z8s2xOr6mgv0oDyPgkpA4TsFuApa4a4PbXTpIm55DSP451CrwWZkXfC8j8YfeMqXGdz5Oxlg3Pb3ukEETHVfzthYeVoQbohiy4zFNlSa45etngQBdZrZ81DCie2i7X8_S4Ylb7M6n_QH_rrGhdBnNbEFkNhcwfBgA4AAABAQBBGIXyRpWaLbGptBXX_-QpeWlEZC82wBakOkfbRD7X8ZbPW9IE-blDc4Q_M7iNiHs03Lcaog',
            '9. Block2 deleted':
               '145SfB4dIqbmYy-bH1rnh1pyFN8T1EyEyFCMFtguBkAGAFIAAAABADHsHML87chQYK_58RxCa0lVLRW9ueVEO55SH6vgyBAAABRO3eqnNV_xNxBnsX-r7KYWgn5F-xMiA5lTNfDYw7tOoCgtF_qddOXjyHisEb0b8z5ZdoouvyB9aG3QlCbc9XTBfAN4yPYcxrzdASguAgYAMQAAAAEAl0vO23m4DaUuLlCchOsXoKnl4bYKmhmX_ydWm2p95AwKZcdXuNcSgBMD17fjfXHBZth-tk8IaJPrcV_085mtn_tcBGnKXX1GLohoGKYCBgBnAAAAAQDo6baKMPCPSjFaIS2FBO8reAb7dt1MzsP560V1bHiPp_0ydYt4wbXHVpNYX671pcPtj6CWch9qBSYtr59FJaP08bRjgMSlemz89vKsYOAHp0pYZnp8PDegLkvkJEnu9SwynMzwGKfdFumYjtOrjpPQ4L937TjUVjPcrjeyrdCKpykeRUcGAK8AAAABAHFAzwSf4i_SZmQfL64OHDTiUNM54gIVg4XrQK8zRjyvYydVz6b7e3mVMggiLzGzBSS_bAjDDckOhqUG7t2G-cpAgO1I0Sg8o2Wh7zIn15dQ7SV_A-7ZIpVA_QsRRuSQ4mT-VklWyvb7n2WV2JjtEW-eflw6xMAJBRr_2e22i9wgrxQQKVfKYCRT-GOgYM6Bd19U8GodP5aQfGpooZu-CqEJiEfj87gmcEWHSHG50gj0XBEAxACbXmFdZjR2WeEYwHm8eFCn2jRc6Ut20QYArwAAAAEAYv4lUeEPG8V2NvvmmQVeh6WBSvIh1dkecMp1HAI3LQkqJ8CSZL9Py2deLxaYA2pO9HunsYLyHwJC2_76Y3wzfAf8SlinLgTS74NV8FR8BJF7tDlv2tk-hSS8FTfcmDHe06whKo8fhMu-3hpb4nuuoH3bAH6rHzP2wP65rLZg3RFmTdKCmUOHYRLrop3-tTS-kds7h_wDpvq6oEmLh52Uma1ZJhQr5lgz7LYQVR_53aP_I3WhcPtB-n00nB13cYuAclmxYpDknDuzoOFLBgCvAAAAAQCjMQ0SmNNsisGh8o-YRgso485bOLvyiW4av5MlNS2qTkVifD6y1O54FimVVe5w2y24hq--tfCiUzvUE8qYPpqamS8SrIU0IdU_cuznCIuNaYa_joELZnyzbE6vqaC_SgPI-CSkDhOwW4Clrhrg9tdOkibnkNI_jnUKvBZmRd8LyPxh94ypcZ3Pk7GWDc9ve6QQRMdV_O2Fh5WhBuiGLLjMU2VJrjl62eBAF1mtnzUMKJ7aLtfz9LhiVvszqf9Af-usaF0Gc1sQWQ2FzB8GADgAAAEBAEEYhfJGlZotsam0Fdf_5Cl5aURkLzbAFqQ6R9tEPtfxls9b0gT5uUNzhD8zuI2IezTctxqi',
            '10. Block7 (last) repeated':
               '145SfB4dIqbmYy-bH1rnh1pyFN8T1EyEyFCMFtguBkAGAFIAAAABADHsHML87chQYK_58RxCa0lVLRW9ueVEO55SH6vgyBAAABRO3eqnNV_xNxBnsX-r7KYWgn5F-xMiA5lTNfDYw7tOoCgtF_qddOXjyHisEb0b8z5ZdoouvyB9aG3QlCbc9XTBfAN4yPYcxrzdASguAgYAMQAAAAEAl0vO23m4DaUuLlCchOsXoKnl4bYKmhmX_ydWm2p95AwKZcdXuNcSgBMD17fjfQxogLpTAVw46IYT6Yade9GaEZeK-H4_IWcRVVloHAjiBgBDAAAAAQCkAj9mmn0ml0CccOOHETPlyrQ0qPr2vtFzCrvt-SAx_VfWK3UP7bsmKruWrF9fXPaHjlhEl9b3BzLgWFRhEI1tccFm2H62Twhok-txX_Tzma2f-1wEacpdfUYuiGgYpgIGAGcAAAABAOjptoow8I9KMVohLYUE7yt4Bvt23UzOw_nrRXVseI-n_TJ1i3jBtcdWk1hfrvWlw-2PoJZyH2oFJi2vn0Ulo_TxtGOAxKV6bPz28qxg4AenSlhmenw8N6AuS-QkSe71LDKczPAYp90W6ZiO06uOk9Dgv3ftONRWM9yuN7Kt0IqnKR5FRwYArwAAAAEAcUDPBJ_iL9JmZB8vrg4cNOJQ0zniAhWDhetArzNGPK9jJ1XPpvt7eZUyCCIvMbMFJL9sCMMNyQ6GpQbu3Yb5ykCA7UjRKDyjZaHvMifXl1DtJX8D7tkilUD9CxFG5JDiZP5WSVbK9vufZZXYmO0Rb55-XDrEwAkFGv_Z7baL3CCvFBApV8pgJFP4Y6BgzoF3X1Twah0_lpB8amihm74KoQmIR-PzuCZwRYdIcbnSCPRcEQDEAJteYV1mNHZZ4RjAebx4UKfaNFzpS3bRBgCvAAAAAQBi_iVR4Q8bxXY2--aZBV6HpYFK8iHV2R5wynUcAjctCSonwJJkv0_LZ14vFpgDak70e6exgvIfAkLb_vpjfDN8B_xKWKcuBNLvg1XwVHwEkXu0OW_a2T6FJLwVN9yYMd7TrCEqjx-Ey77eGlvie66gfdsAfqsfM_bA_rmstmDdEWZN0oKZQ4dhEuuinf61NL6R2zuH_AOm-rqgSYuHnZSZrVkmFCvmWDPsthBVH_ndo_8jdaFw-0H6fTScHXdxi4ByWbFikOScO7Og4UsGAK8AAAABAKMxDRKY02yKwaHyj5hGCyjjzls4u_KJbhq_kyU1LapORWJ8PrLU7ngWKZVV7nDbLbiGr7618KJTO9QTypg-mpqZLxKshTQh1T9y7OcIi41phr-OgQtmfLNsTq-poL9KA8j4JKQOE7BbgKWuGuD2106SJueQ0j-OdQq8FmZF3wvI_GH3jKlxnc-TsZYNz297pBBEx1X87YWHlaEG6IYsuMxTZUmuOXrZ4EAXWa2fNQwontou1_P0uGJW-zOp_0B_66xoXQZzWxBZDYXMHwYAOAAAAQEAQRiF8kaVmi2xqbQV1__kKXlpRGQvNsAWpDpH20Q-1_GWz1vSBPm5Q3OEPzO4jYh7NNy3GqKfNQwontou1_P0uGJW-zOp_0B_66xoXQZzWxBZDYXMHwYAOAAAAQEAQRiF8kaVmi2xqbQV1__kKXlpRGQvNsAWpDpH20Q-1_GWz1vSBPm5Q3OEPzO4jYh7NNy3GqI',
            '11. Block7 (last) deleted':
               '145SfB4dIqbmYy-bH1rnh1pyFN8T1EyEyFCMFtguBkAGAFIAAAABADHsHML87chQYK_58RxCa0lVLRW9ueVEO55SH6vgyBAAABRO3eqnNV_xNxBnsX-r7KYWgn5F-xMiA5lTNfDYw7tOoCgtF_qddOXjyHisEb0b8z5ZdoouvyB9aG3QlCbc9XTBfAN4yPYcxrzdASguAgYAMQAAAAEAl0vO23m4DaUuLlCchOsXoKnl4bYKmhmX_ydWm2p95AwKZcdXuNcSgBMD17fjfQxogLpTAVw46IYT6Yade9GaEZeK-H4_IWcRVVloHAjiBgBDAAAAAQCkAj9mmn0ml0CccOOHETPlyrQ0qPr2vtFzCrvt-SAx_VfWK3UP7bsmKruWrF9fXPaHjlhEl9b3BzLgWFRhEI1tccFm2H62Twhok-txX_Tzma2f-1wEacpdfUYuiGgYpgIGAGcAAAABAOjptoow8I9KMVohLYUE7yt4Bvt23UzOw_nrRXVseI-n_TJ1i3jBtcdWk1hfrvWlw-2PoJZyH2oFJi2vn0Ulo_TxtGOAxKV6bPz28qxg4AenSlhmenw8N6AuS-QkSe71LDKczPAYp90W6ZiO06uOk9Dgv3ftONRWM9yuN7Kt0IqnKR5FRwYArwAAAAEAcUDPBJ_iL9JmZB8vrg4cNOJQ0zniAhWDhetArzNGPK9jJ1XPpvt7eZUyCCIvMbMFJL9sCMMNyQ6GpQbu3Yb5ykCA7UjRKDyjZaHvMifXl1DtJX8D7tkilUD9CxFG5JDiZP5WSVbK9vufZZXYmO0Rb55-XDrEwAkFGv_Z7baL3CCvFBApV8pgJFP4Y6BgzoF3X1Twah0_lpB8amihm74KoQmIR-PzuCZwRYdIcbnSCPRcEQDEAJteYV1mNHZZ4RjAebx4UKfaNFzpS3bRBgCvAAAAAQBi_iVR4Q8bxXY2--aZBV6HpYFK8iHV2R5wynUcAjctCSonwJJkv0_LZ14vFpgDak70e6exgvIfAkLb_vpjfDN8B_xKWKcuBNLvg1XwVHwEkXu0OW_a2T6FJLwVN9yYMd7TrCEqjx-Ey77eGlvie66gfdsAfqsfM_bA_rmstmDdEWZN0oKZQ4dhEuuinf61NL6R2zuH_AOm-rqgSYuHnZSZrVkmFCvmWDPsthBVH_ndo_8jdaFw-0H6fTScHXdxi4ByWbFikOScO7Og4UsGAK8AAAABAKMxDRKY02yKwaHyj5hGCyjjzls4u_KJbhq_kyU1LapORWJ8PrLU7ngWKZVV7nDbLbiGr7618KJTO9QTypg-mpqZLxKshTQh1T9y7OcIi41phr-OgQtmfLNsTq-poL9KA8j4JKQOE7BbgKWuGuD2106SJueQ0j-OdQq8FmZF3wvI_GH3jKlxnc-TsZYNz297pBBEx1X87YWHlaEG6IYsuMxTZUmuOXrZ4EAXWa0',
            '12. Block1 Block7 deleted':
               '145SfB4dIqbmYy-bH1rnh1pyFN8T1EyEyFCMFtguBkAGAFIAAAABADHsHML87chQYK_58RxCa0lVLRW9ueVEO55SH6vgyBAAABRO3eqnNV_xNxBnsX-r7KYWgn5F-xMiA5lTNfDYw7tOoCgtF_qddOXjyHisEb0MaIC6UwFcOOiGE-mGnXvRmhGXivh-PyFnEVVZaBwI4gYAQwAAAAEApAI_Zpp9JpdAnHDjhxEz5cq0NKj69r7Rcwq77fkgMf1X1it1D-27Jiq7lqxfX1z2h45YRJfW9wcy4FhUYRCNbXHBZth-tk8IaJPrcV_085mtn_tcBGnKXX1GLohoGKYCBgBnAAAAAQDo6baKMPCPSjFaIS2FBO8reAb7dt1MzsP560V1bHiPp_0ydYt4wbXHVpNYX671pcPtj6CWch9qBSYtr59FJaP08bRjgMSlemz89vKsYOAHp0pYZnp8PDegLkvkJEnu9SwynMzwGKfdFumYjtOrjpPQ4L937TjUVjPcrjeyrdCKpykeRUcGAK8AAAABAHFAzwSf4i_SZmQfL64OHDTiUNM54gIVg4XrQK8zRjyvYydVz6b7e3mVMggiLzGzBSS_bAjDDckOhqUG7t2G-cpAgO1I0Sg8o2Wh7zIn15dQ7SV_A-7ZIpVA_QsRRuSQ4mT-VklWyvb7n2WV2JjtEW-eflw6xMAJBRr_2e22i9wgrxQQKVfKYCRT-GOgYM6Bd19U8GodP5aQfGpooZu-CqEJiEfj87gmcEWHSHG50gj0XBEAxACbXmFdZjR2WeEYwHm8eFCn2jRc6Ut20QYArwAAAAEAYv4lUeEPG8V2NvvmmQVeh6WBSvIh1dkecMp1HAI3LQkqJ8CSZL9Py2deLxaYA2pO9HunsYLyHwJC2_76Y3wzfAf8SlinLgTS74NV8FR8BJF7tDlv2tk-hSS8FTfcmDHe06whKo8fhMu-3hpb4nuuoH3bAH6rHzP2wP65rLZg3RFmTdKCmUOHYRLrop3-tTS-kds7h_wDpvq6oEmLh52Uma1ZJhQr5lgz7LYQVR_53aP_I3WhcPtB-n00nB13cYuAclmxYpDknDuzoOFLBgCvAAAAAQCjMQ0SmNNsisGh8o-YRgso485bOLvyiW4av5MlNS2qTkVifD6y1O54FimVVe5w2y24hq--tfCiUzvUE8qYPpqamS8SrIU0IdU_cuznCIuNaYa_joELZnyzbE6vqaC_SgPI-CSkDhOwW4Clrhrg9tdOkibnkNI_jnUKvBZmRd8LyPxh94ypcZ3Pk7GWDc9ve6QQRMdV_O2Fh5WhBuiGLLjMU2VJrjl62eBAF1mt',
            '13. All Term':
               'Gj8LJHitylJ4aVAkkSi1U1m4p-YoXONCOeamFCQbsY8GAFIAAAEBABE3_KB_Dqut_HwspmtRghT_YZ3NN0W-I4CNycjgyBAAABRBs_JlRZdmQiGo7-mEvgH-U-gN5QqP9a_ypYLPYjR0vDUzKmRulgjphyjMxKB2CnZk3CAA4j2o8BBh__OlfCcRXUds7AAzMnrqcImCGwYAMQAAAQEAR_GnJtWuRNBwsduFt11xVHEtBHmfdRCpSMXSbBPRxU8_qwmNHafh2F7bgTY39wdWZoxNZAtMDnhy1BwYpeslwb7dladP1OGFd2GzkUAtBgBDAAABAQCA_Br3aygBwCOF_0gsLX_S7q-9Lrk1IYKXT6gGJ2A9oB52VhiAD76dOnc1bYyeKi3iE8Rs9JRy_jkcp1WvM3R1yjh4XJ_QRmmWnl1xyFP0P8uaH4xu0G1GMyJrc_ZyB94GAGcAAAEBAPfxMbSg-KvMam2Mhkr5Hn_ACH6GX-0k2slg7uUsKELb7COjpxrGJrCuVVb2i3Y-gffCDlQ6GUmPoasRFU_Kmb6UQV5hNnwI7-mbKL8twvBsiplzl3IddqOMT6O5Si6rOmhAHINSa9IRy7UgchtreGzjBjgjc8vViInfw6BihF7r05AVaQYArwAAAQEAXhTRCseFwbouAxpSGQ4dgTlv7qAWOCDGt_DpL99ghxNxPaOZQgCAMIM0xmbZI3stQEfbUhdNWAn6zYoj4cQcfBiYdRfKj4AkWpzKQF8H38e5NgoilJ7bFEaqIeLuJItrE4JBKUr8HXklJPyuCjXKEsQpJ_goSsAqfvlOnZvh4CRq2LQ07s3qBLxhouZ4rXLrx4j8uxPg1Ghz82lOxPcRp4MdHvqLfwg9h9osUInMJI-wNa4CIl_af8GFTreyXA4bQdHTOzS3aTtqnL-_BgCvAAABAQCly24SzO2UtPsMOCEklLhpj-t_EvX3fgZkHGzG-h6JMCevq9YK3WmLjg0Fy8InTz0pqXjzcJUz-foMtkul4JDWj6nllSD9aTKTsj6SIhK6_ettdrvljxi5AdiYE_iCFtyF6MIReWOmLnFFizIKNO1WYu8n9Jli0Be1IzxOU5WawkN_VM-8iA2-MEN5pJxwlRK2f9TGsqS0P5d6xKcGryH7dX-NMwN2ywZHRuPe6GY5DKlLXsEIw0kJmb--07VokAXouCwbzkFydZW6wekGAK8AAAEBABmE5-OFM3LcqrBjJzXAZzhKgOG6GBQYFC_mKndl07saC3IfJXDenX-x2IzsBD_HcoyMMZm2ig1ObGqaZ5SqijRbAyTt13-3HoZoE6DTAF3MiW0p_0-SAniNkcSDX_bqT_NDjsKLI4AtY3rXOv_AhT3X8Aorpy1c41v89899yFDuXa0R2aZiEndgDJ1ifUGqEXkpQgASz25uJ6gJwjqlsi8AjVXIhKx0ZeNqQiEfIBu4Mm8S6SV-sIGpZe1jryCPoRbObZkMxKUhcHpHOAYAOAAAAQEA12z4tjJz4fKYHWjq4e0nyKcEjAhjBeDWhD-qE523OX5NcEXfAfqf7oj6q0wcN5PKgKzsi6I',
            '14. No Term':
               'DBSj10kBKZ85UUBqgW05vS8wXkFlJCXMF37GwEpWAyIGAFIAAAABAGDNsxpQxcJfSTqljJ3_gQF59Dbw9Fo--1coQtXgyBAAABS7tNDYzTpFw-K7GQ3f46fD_kqiW4sdg0Gqo8NgaohCHvc9CAK_lKIEWltbdW0OQkHeofnoJfvquDZEPcThNI6stiALDeP865vVsJ3ozQYAMQAAAAEASFE_HU_e4zvofNC3y2YJc_TDtgTl2NkWbMh_Yj4Dz6fjgeRuVJjqk8R2mcLDiucVINP1sa0C8exDYYgIBhhyJNZKbAF4vGcts76qYN5NBgBDAAAAAQDG5uS6qlBCA10PZ5TchRsg_50IVg3H64ASIZbdkfYlIalDmnKx2_lkFkt9LkEODBfLNoCg3280ixQ2mwae3M4V0XMLGdznAYrgMnXet7ZiEtToldVzGv0m-6d29pz4umYGAGcAAAABAPqd0fors414KtU1ViEKmqkeGgHcyjEoJ4DIRH742xXTxh4nOhoFm19PvDVNeAVQIdbSCDa-s4IqdCzLgUQK-Yx8DM0YOdUBolZxJQOb-5OoVhfVmm99yiggklZPtzT1bfCaXQvKM7Xw2wAIrw1xMTkRltH8lH5yaz3Xb8elQbKYTIpFvgYArwAAAAEApmzfDJvug6b2EaDTKr61O-JGsSrEboPHwsxX9LSUcCh0eBIQ1MLG1v2owMbgK2jQy8bEOhM4rRrpiZ1TzDd0cKyhelLFCDUsOtBJO6uOknPb9YOBwcna2B9UMj8lrZb9My9ChfjofXDk_b-uRhZbIqnGFhhNTYSwkZ2dyuYleIiD1GQPoP4MYJ4XnUs3nEg392FXgTKjGlRzwwbSsIQpbWn94zN4KLQ_ziCkOwF-HDDKf8wD3WevkbFImsYM6RZbvDGt5Eei9_fvyyprBgCvAAAAAQAD-ci_1XMFjh67-ziFnGkaCeq5wfh_kwFybPRzU2HSutmX6e6jkEQrUwSfEkYvavlpMNQKFjL10aVvC1JNbI7CCx6FE2sog2ZL5lfPtRGPhbu8_BnMvS_zAG9uvvTqMneXUrvii79uhT8MY7dCuLCBCtVMtyzmQFRsXFMcVMrKEKXQH3Voi_TkLNPr7MtJGzegKQcm1y6sX3VEkPapdqkG636zmCE4tFDIptJBDgJ8uXP5no0c-CtHepqL1jcKkeIgZVt8bCK4b9-8OtcGAK8AAAABALEZNnMJXsYobGKOn8U63Wtho1muI87OKzMI_BZDDFiUQZduletcTCNjsm4iZinPpFGtGrOuS8oSbxrcnkZgJA6_RhpuN63lEOX9NAv-T5wiz8sJbWVWm59xtZ6pcR7tuyVK444Nl89f2ZeHEp_DuCWdFo-AZhUBqp7lL3_H42AABHS_iHcMU5dT3ZvVmZbiazVFCgIlpo-biDihT1XR9uuWtPZlNUE80YACm3sxSvSZ7bZZkWsgACouG3HweAeG_gILIhm6O0XwP9gUMwYAOAAAAAEAmB0NrkLBUxOT-kUrJwTlORQ62fdJKCePOjPUNnBawoupsH5c34r2leStBcHeJkokVev3OWg',
         },
      },
      //v7 — generated by: pnpm vectors:ciphersvc
      {
         ver: 7,
         goodCt:
            '2d4lCLWsO_9astzam2P4CYD1TH7IlvhtsvGOCanH3sgHAFIAAAABAF4zrCqkH7RIDn2V8wUkgcGiFTEcYkp6VvOTlX_gyBAAABTlp4yEbvl3YY_sMYeUeUlSL3VkO4dgiwvYKP4iK-9fB-8o3ukq8CYpiN3L6lH2VBqseyvabrr4C5R4j8tso6w-VxdAX-rwdHk6VA6_awcAMQAAAAEASN9jeLe2WjsGNcmYjc3rnc84ctK6A-u-Gl_G_Bxpd9_gPY6EI1bANbRk-Sf2JutKSvpL4Bp8qQANGgnUeAtvWjo54tEaeEHmDQJx6or5BwBDAAAAAQDu9TB55TLYwE_Dl7tDJRSPB43nw61KXjniPq7Y2m_8DUlI65csxNV6ps_7oRBJIA7WjJme2NVn9KmMhRs0H358aRx9W00iSKpOufN024kutdsqjx9eXGEeJ8AlGuwsn8EHAGcAAAABAKZpzt2wpu7j_wI-W_fJxIbZ4NfzuJIaaIAOqaOhskJf3WbG_UXosN_-ej4JWfVJ4_bj7bxiK3GVuoMXWPcavqxL936rueWaVHisL0fdf9PO_zIMyd2iq6RJkbeSgmij9N2GWAmqctdr8dKjRqfYDTASiWD6Wr1egoOt2ZPyhGClMsRyRQcArwAAAAEArRxWcELyP8OeFFYA4HWPYZ1GNz-epKaOnnkx9tQQYaFAfUYBCE6VZzCstK921-kLRQQQSa4dO4lBA6arLmjAao4UbDGDA8KviZln3W7gw90PVy2lZNB1euBr_XLSeRRuEUrN34aXOktaOjdrqespQ6Lsh8qJk3ZaPNKPx7ZdW6e4ERecmGvEMraOse1JEG3-OxdpRBubNUauElXHTYmbTO3ofsrPAiPXi4Gk5ppbCddwUSmuotZFpX-2gn6cDZU4Wa7TKYTA3bhUpkf9BwCvAAAAAQDMhHxuo-wNe_Hqcyr0x4TacADp8t6Tc0csH9b70TovUvT5xSRb8EbVZOwjBZ9H3oBoCV3EDiuPJqT9ekdDvmT_vK29eoLzxxQACN3xhd5dusVn4-s3MsgzpSkfFoG7I-0laNxICaSStFtiYF6IMN-NRO0g1jYeCV-kqm8HtttX_FNjcjIj-pW5holFC30rwiS8_VUoxfm8KPvkLbX5Q0RpnjJM5JGRr6CTdKlUPo29XnIWJIeQgQq3yGH3z4cu6_enerD9yaaBaLvoH1IHAK8AAAABAJ8ImRTmgMApS7fYt4Upee33CJWlsmDW_ZWvUmcLmhtn7LQKfLP59oYBUZS27_3BpJP4iZnfNGDZRrbXFzotcPhgHOYHjkYpEoTCIjTOYzs_edWORvKCPpgfrkH86TwjyKM_tZGSLsuHgpdyBHRxw7BHMhntnWHQxNbsL05d3WOfVrDxvvo4vjI7xYYG2GNy-HFSBmTJJ_oR6SeMNibpkVZpVy7s-tFRATHnFfuUKgetXdyP9Vut5pOXX0lhlEWc252IFrBQL47HXmS7sgcAOAAAAQEAkMuqlF81Jc6RLzlOBksLODHh2o3W7MhRezzmsHpNzPlv8w3IUQ2PhWxoNIcdp1N_bPIA9w0',
         badCts: {
            '1. Block0 Block7 swap':
               'lCoHrV3cj_VbreaTl19JYZRFnNudiBawUC-Ox15ku7IHADgAAAEBAJDLqpRfNSXOkS85TgZLCzgx4dqN1uzIUXs85rB6Tcz5b_MNyFENj4VsaDSHHadTf2zyAPcN9lQarHsr2m66-AuUeI_LbKOsPlcXQF_q8HR5OlQOv2sHADEAAAABAEjfY3i3tlo7BjXJmI3N653POHLSugPrvhpfxvwcaXff4D2OhCNWwDW0ZPkn9ibrSkr6S-AafKkADRoJ1HgLb1o6OeLRGnhB5g0CceqK-QcAQwAAAAEA7vUweeUy2MBPw5e7QyUUjweN58OtSl454j6u2Npv_A1JSOuXLMTVeqbP-6EQSSAO1oyZntjVZ_SpjIUbNB9-fGkcfVtNIkiqTrnzdNuJLrXbKo8fXlxhHifAJRrsLJ_BBwBnAAAAAQCmac7dsKbu4_8CPlv3ycSG2eDX87iSGmiADqmjobJCX91mxv1F6LDf_no-CVn1SeP24-28YitxlbqDF1j3Gr6sS_d-q7nlmlR4rC9H3X_Tzv8yDMndoqukSZG3koJoo_TdhlgJqnLXa_HSo0an2A0wEolg-lq9XoKDrdmT8oRgpTLEckUHAK8AAAABAK0cVnBC8j_DnhRWAOB1j2GdRjc_nqSmjp55MfbUEGGhQH1GAQhOlWcwrLSvdtfpC0UEEEmuHTuJQQOmqy5owGqOFGwxgwPCr4mZZ91u4MPdD1ctpWTQdXrga_1y0nkUbhFKzd-GlzpLWjo3a6nrKUOi7IfKiZN2WjzSj8e2XVunuBEXnJhrxDK2jrHtSRBt_jsXaUQbmzVGrhJVx02Jm0zt6H7KzwIj14uBpOaaWwnXcFEprqLWRaV_toJ-nA2VOFmu0ymEwN24VKZH_QcArwAAAAEAzIR8bqPsDXvx6nMq9MeE2nAA6fLek3NHLB_W-9E6L1L0-cUkW_BG1WTsIwWfR96AaAldxA4rjyak_XpHQ75k_7ytvXqC88cUAAjd8YXeXbrFZ-PrNzLIM6UpHxaBuyPtJWjcSAmkkrRbYmBeiDDfjUTtINY2HglfpKpvB7bbV_xTY3IyI_qVuYaJRQt9K8IkvP1VKMX5vCj75C21-UNEaZ4yTOSRka-gk3SpVD6NvV5yFiSHkIEKt8hh98-HLuv3p3qw_cmmgWi76B9SBwCvAAAAAQCfCJkU5oDAKUu32LeFKXnt9wiVpbJg1v2Vr1JnC5obZ-y0Cnyz-faGAVGUtu_9waST-ImZ3zRg2Ua21xc6LXD4YBzmB45GKRKEwiI0zmM7P3nVjkbygj6YH65B_Ok8I8ijP7WRki7Lh4KXcgR0ccOwRzIZ7Z1h0MTW7C9OXd1jn1aw8b76OL4yO8WGBthjcvhxUgZkySf6EeknjDYm6ZFWaVcu7PrRUQEx5xX72d4lCLWsO_9astzam2P4CYD1TH7IlvhtsvGOCanH3sgHAFIAAAABAF4zrCqkH7RIDn2V8wUkgcGiFTEcYkp6VvOTlX_gyBAAABTlp4yEbvl3YY_sMYeUeUlSL3VkO4dgiwvYKP4iK-9fB-8o3ukq8CYpiN3L6lE',
            '2. Block1 Block7 swap':
               '2d4lCLWsO_9astzam2P4CYD1TH7IlvhtsvGOCanH3sgHAFIAAAABAF4zrCqkH7RIDn2V8wUkgcGiFTEcYkp6VvOTlX_gyBAAABTlp4yEbvl3YY_sMYeUeUlSL3VkO4dgiwvYKP4iK-9fB-8o3ukq8CYpiN3L6lGUKgetXdyP9Vut5pOXX0lhlEWc252IFrBQL47HXmS7sgcAOAAAAQEAkMuqlF81Jc6RLzlOBksLODHh2o3W7MhRezzmsHpNzPlv8w3IUQ2PhWxoNIcdp1N_bPIA9w3rSkr6S-AafKkADRoJ1HgLb1o6OeLRGnhB5g0CceqK-QcAQwAAAAEA7vUweeUy2MBPw5e7QyUUjweN58OtSl454j6u2Npv_A1JSOuXLMTVeqbP-6EQSSAO1oyZntjVZ_SpjIUbNB9-fGkcfVtNIkiqTrnzdNuJLrXbKo8fXlxhHifAJRrsLJ_BBwBnAAAAAQCmac7dsKbu4_8CPlv3ycSG2eDX87iSGmiADqmjobJCX91mxv1F6LDf_no-CVn1SeP24-28YitxlbqDF1j3Gr6sS_d-q7nlmlR4rC9H3X_Tzv8yDMndoqukSZG3koJoo_TdhlgJqnLXa_HSo0an2A0wEolg-lq9XoKDrdmT8oRgpTLEckUHAK8AAAABAK0cVnBC8j_DnhRWAOB1j2GdRjc_nqSmjp55MfbUEGGhQH1GAQhOlWcwrLSvdtfpC0UEEEmuHTuJQQOmqy5owGqOFGwxgwPCr4mZZ91u4MPdD1ctpWTQdXrga_1y0nkUbhFKzd-GlzpLWjo3a6nrKUOi7IfKiZN2WjzSj8e2XVunuBEXnJhrxDK2jrHtSRBt_jsXaUQbmzVGrhJVx02Jm0zt6H7KzwIj14uBpOaaWwnXcFEprqLWRaV_toJ-nA2VOFmu0ymEwN24VKZH_QcArwAAAAEAzIR8bqPsDXvx6nMq9MeE2nAA6fLek3NHLB_W-9E6L1L0-cUkW_BG1WTsIwWfR96AaAldxA4rjyak_XpHQ75k_7ytvXqC88cUAAjd8YXeXbrFZ-PrNzLIM6UpHxaBuyPtJWjcSAmkkrRbYmBeiDDfjUTtINY2HglfpKpvB7bbV_xTY3IyI_qVuYaJRQt9K8IkvP1VKMX5vCj75C21-UNEaZ4yTOSRka-gk3SpVD6NvV5yFiSHkIEKt8hh98-HLuv3p3qw_cmmgWi76B9SBwCvAAAAAQCfCJkU5oDAKUu32LeFKXnt9wiVpbJg1v2Vr1JnC5obZ-y0Cnyz-faGAVGUtu_9waST-ImZ3zRg2Ua21xc6LXD4YBzmB45GKRKEwiI0zmM7P3nVjkbygj6YH65B_Ok8I8ijP7WRki7Lh4KXcgR0ccOwRzIZ7Z1h0MTW7C9OXd1jn1aw8b76OL4yO8WGBthjcvhxUgZkySf6EeknjDYm6ZFWaVcu7PrRUQEx5xX79lQarHsr2m66-AuUeI_LbKOsPlcXQF_q8HR5OlQOv2sHADEAAAABAEjfY3i3tlo7BjXJmI3N653POHLSugPrvhpfxvwcaXff4D2OhCNWwDW0ZPkn9iY',
            '3. Block1 Block4 swap':
               '2d4lCLWsO_9astzam2P4CYD1TH7IlvhtsvGOCanH3sgHAFIAAAABAF4zrCqkH7RIDn2V8wUkgcGiFTEcYkp6VvOTlX_gyBAAABTlp4yEbvl3YY_sMYeUeUlSL3VkO4dgiwvYKP4iK-9fB-8o3ukq8CYpiN3L6lGqctdr8dKjRqfYDTASiWD6Wr1egoOt2ZPyhGClMsRyRQcArwAAAAEArRxWcELyP8OeFFYA4HWPYZ1GNz-epKaOnnkx9tQQYaFAfUYBCE6VZzCstK921-kLRQQQSa4dO4lBA6arLmjAao4UbDGDA8KviZln3W7gw90PVy2lZNB1euBr_XLSeRRuEUrN34aXOktaOjdrqespQ6Lsh8qJk3ZaPNKPx7ZdW6e4ERecmGvEMraOse1JEG3-OxdpRBubNUauElXHTYmbTO3ofsrPAiPXi4Gk5utKSvpL4Bp8qQANGgnUeAtvWjo54tEaeEHmDQJx6or5BwBDAAAAAQDu9TB55TLYwE_Dl7tDJRSPB43nw61KXjniPq7Y2m_8DUlI65csxNV6ps_7oRBJIA7WjJme2NVn9KmMhRs0H358aRx9W00iSKpOufN024kutdsqjx9eXGEeJ8AlGuwsn8EHAGcAAAABAKZpzt2wpu7j_wI-W_fJxIbZ4NfzuJIaaIAOqaOhskJf3WbG_UXosN_-ej4JWfVJ4_bj7bxiK3GVuoMXWPcavqxL936rueWaVHisL0fdf9PO_zIMyd2iq6RJkbeSgmij9N2GWAn2VBqseyvabrr4C5R4j8tso6w-VxdAX-rwdHk6VA6_awcAMQAAAAEASN9jeLe2WjsGNcmYjc3rnc84ctK6A-u-Gl_G_Bxpd9_gPY6EI1bANbRk-Sf2JppbCddwUSmuotZFpX-2gn6cDZU4Wa7TKYTA3bhUpkf9BwCvAAAAAQDMhHxuo-wNe_Hqcyr0x4TacADp8t6Tc0csH9b70TovUvT5xSRb8EbVZOwjBZ9H3oBoCV3EDiuPJqT9ekdDvmT_vK29eoLzxxQACN3xhd5dusVn4-s3MsgzpSkfFoG7I-0laNxICaSStFtiYF6IMN-NRO0g1jYeCV-kqm8HtttX_FNjcjIj-pW5holFC30rwiS8_VUoxfm8KPvkLbX5Q0RpnjJM5JGRr6CTdKlUPo29XnIWJIeQgQq3yGH3z4cu6_enerD9yaaBaLvoH1IHAK8AAAABAJ8ImRTmgMApS7fYt4Upee33CJWlsmDW_ZWvUmcLmhtn7LQKfLP59oYBUZS27_3BpJP4iZnfNGDZRrbXFzotcPhgHOYHjkYpEoTCIjTOYzs_edWORvKCPpgfrkH86TwjyKM_tZGSLsuHgpdyBHRxw7BHMhntnWHQxNbsL05d3WOfVrDxvvo4vjI7xYYG2GNy-HFSBmTJJ_oR6SeMNibpkVZpVy7s-tFRATHnFfuUKgetXdyP9Vut5pOXX0lhlEWc252IFrBQL47HXmS7sgcAOAAAAQEAkMuqlF81Jc6RLzlOBksLODHh2o3W7MhRezzmsHpNzPlv8w3IUQ2PhWxoNIcdp1N_bPIA9w0',
            '4. Block0 repeated':
               '2d4lCLWsO_9astzam2P4CYD1TH7IlvhtsvGOCanH3sgHAFIAAAABAF4zrCqkH7RIDn2V8wUkgcGiFTEcYkp6VvOTlX_gyBAAABTlp4yEbvl3YY_sMYeUeUlSL3VkO4dgiwvYKP4iK-9fB-8o3ukq8CYpiN3L6lHZ3iUItaw7_1qy3NqbY_gJgPVMfsiW-G2y8Y4JqcfeyAcAUgAAAAEAXjOsKqQftEgOfZXzBSSBwaIVMRxiSnpW85OVf-DIEAAAFOWnjIRu-Xdhj-wxh5R5SVIvdWQ7h2CLC9go_iIr718H7yje6SrwJimI3cvqUfZUGqx7K9puuvgLlHiPy2yjrD5XF0Bf6vB0eTpUDr9rBwAxAAAAAQBI32N4t7ZaOwY1yZiNzeudzzhy0roD674aX8b8HGl33-A9joQjVsA1tGT5J_Ym60pK-kvgGnypAA0aCdR4C29aOjni0Rp4QeYNAnHqivkHAEMAAAABAO71MHnlMtjAT8OXu0MlFI8HjefDrUpeOeI-rtjab_wNSUjrlyzE1Xqmz_uhEEkgDtaMmZ7Y1Wf0qYyFGzQffnxpHH1bTSJIqk6583TbiS612yqPH15cYR4nwCUa7CyfwQcAZwAAAAEApmnO3bCm7uP_Aj5b98nEhtng1_O4khpogA6po6GyQl_dZsb9Reiw3_56PglZ9Unj9uPtvGIrcZW6gxdY9xq-rEv3fqu55ZpUeKwvR91_087_MgzJ3aKrpEmRt5KCaKP03YZYCapy12vx0qNGp9gNMBKJYPpavV6Cg63Zk_KEYKUyxHJFBwCvAAAAAQCtHFZwQvI_w54UVgDgdY9hnUY3P56kpo6eeTH21BBhoUB9RgEITpVnMKy0r3bX6QtFBBBJrh07iUEDpqsuaMBqjhRsMYMDwq-JmWfdbuDD3Q9XLaVk0HV64Gv9ctJ5FG4RSs3fhpc6S1o6N2up6ylDouyHyomTdlo80o_Htl1bp7gRF5yYa8Qyto6x7UkQbf47F2lEG5s1Rq4SVcdNiZtM7eh-ys8CI9eLgaTmmlsJ13BRKa6i1kWlf7aCfpwNlThZrtMphMDduFSmR_0HAK8AAAABAMyEfG6j7A178epzKvTHhNpwAOny3pNzRywf1vvROi9S9PnFJFvwRtVk7CMFn0fegGgJXcQOK48mpP16R0O-ZP-8rb16gvPHFAAI3fGF3l26xWfj6zcyyDOlKR8Wgbsj7SVo3EgJpJK0W2JgXogw341E7SDWNh4JX6Sqbwe221f8U2NyMiP6lbmGiUULfSvCJLz9VSjF-bwo--QttflDRGmeMkzkkZGvoJN0qVQ-jb1echYkh5CBCrfIYffPhy7r96d6sP3JpoFou-gfUgcArwAAAAEAnwiZFOaAwClLt9i3hSl57fcIlaWyYNb9la9SZwuaG2fstAp8s_n2hgFRlLbv_cGkk_iJmd80YNlGttcXOi1w-GAc5geORikShMIiNM5jOz951Y5G8oI-mB-uQfzpPCPIoz-1kZIuy4eCl3IEdHHDsEcyGe2dYdDE1uwvTl3dY59WsPG--ji-MjvFhgbYY3L4cVIGZMkn-hHpJ4w2JumRVmlXLuz60VEBMecV-5QqB61d3I_1W63mk5dfSWGURZzbnYgWsFAvjsdeZLuyBwA4AAABAQCQy6qUXzUlzpEvOU4GSws4MeHajdbsyFF7POawek3M-W_zDchRDY-FbGg0hx2nU39s8gD3DQ',
            '5. Block0 deleted':
               '9lQarHsr2m66-AuUeI_LbKOsPlcXQF_q8HR5OlQOv2sHADEAAAABAEjfY3i3tlo7BjXJmI3N653POHLSugPrvhpfxvwcaXff4D2OhCNWwDW0ZPkn9ibrSkr6S-AafKkADRoJ1HgLb1o6OeLRGnhB5g0CceqK-QcAQwAAAAEA7vUweeUy2MBPw5e7QyUUjweN58OtSl454j6u2Npv_A1JSOuXLMTVeqbP-6EQSSAO1oyZntjVZ_SpjIUbNB9-fGkcfVtNIkiqTrnzdNuJLrXbKo8fXlxhHifAJRrsLJ_BBwBnAAAAAQCmac7dsKbu4_8CPlv3ycSG2eDX87iSGmiADqmjobJCX91mxv1F6LDf_no-CVn1SeP24-28YitxlbqDF1j3Gr6sS_d-q7nlmlR4rC9H3X_Tzv8yDMndoqukSZG3koJoo_TdhlgJqnLXa_HSo0an2A0wEolg-lq9XoKDrdmT8oRgpTLEckUHAK8AAAABAK0cVnBC8j_DnhRWAOB1j2GdRjc_nqSmjp55MfbUEGGhQH1GAQhOlWcwrLSvdtfpC0UEEEmuHTuJQQOmqy5owGqOFGwxgwPCr4mZZ91u4MPdD1ctpWTQdXrga_1y0nkUbhFKzd-GlzpLWjo3a6nrKUOi7IfKiZN2WjzSj8e2XVunuBEXnJhrxDK2jrHtSRBt_jsXaUQbmzVGrhJVx02Jm0zt6H7KzwIj14uBpOaaWwnXcFEprqLWRaV_toJ-nA2VOFmu0ymEwN24VKZH_QcArwAAAAEAzIR8bqPsDXvx6nMq9MeE2nAA6fLek3NHLB_W-9E6L1L0-cUkW_BG1WTsIwWfR96AaAldxA4rjyak_XpHQ75k_7ytvXqC88cUAAjd8YXeXbrFZ-PrNzLIM6UpHxaBuyPtJWjcSAmkkrRbYmBeiDDfjUTtINY2HglfpKpvB7bbV_xTY3IyI_qVuYaJRQt9K8IkvP1VKMX5vCj75C21-UNEaZ4yTOSRka-gk3SpVD6NvV5yFiSHkIEKt8hh98-HLuv3p3qw_cmmgWi76B9SBwCvAAAAAQCfCJkU5oDAKUu32LeFKXnt9wiVpbJg1v2Vr1JnC5obZ-y0Cnyz-faGAVGUtu_9waST-ImZ3zRg2Ua21xc6LXD4YBzmB45GKRKEwiI0zmM7P3nVjkbygj6YH65B_Ok8I8ijP7WRki7Lh4KXcgR0ccOwRzIZ7Z1h0MTW7C9OXd1jn1aw8b76OL4yO8WGBthjcvhxUgZkySf6EeknjDYm6ZFWaVcu7PrRUQEx5xX7lCoHrV3cj_VbreaTl19JYZRFnNudiBawUC-Ox15ku7IHADgAAAEBAJDLqpRfNSXOkS85TgZLCzgx4dqN1uzIUXs85rB6Tcz5b_MNyFENj4VsaDSHHadTf2zyAPcN',
            '6. Block1 repeated':
               '2d4lCLWsO_9astzam2P4CYD1TH7IlvhtsvGOCanH3sgHAFIAAAABAF4zrCqkH7RIDn2V8wUkgcGiFTEcYkp6VvOTlX_gyBAAABTlp4yEbvl3YY_sMYeUeUlSL3VkO4dgiwvYKP4iK-9fB-8o3ukq8CYpiN3L6lH2VBqseyvabrr4C5R4j8tso6w-VxdAX-rwdHk6VA6_awcAMQAAAAEASN9jeLe2WjsGNcmYjc3rnc84ctK6A-u-Gl_G_Bxpd9_gPY6EI1bANbRk-Sf2JvZUGqx7K9puuvgLlHiPy2yjrD5XF0Bf6vB0eTpUDr9rBwAxAAAAAQBI32N4t7ZaOwY1yZiNzeudzzhy0roD674aX8b8HGl33-A9joQjVsA1tGT5J_Ym60pK-kvgGnypAA0aCdR4C29aOjni0Rp4QeYNAnHqivkHAEMAAAABAO71MHnlMtjAT8OXu0MlFI8HjefDrUpeOeI-rtjab_wNSUjrlyzE1Xqmz_uhEEkgDtaMmZ7Y1Wf0qYyFGzQffnxpHH1bTSJIqk6583TbiS612yqPH15cYR4nwCUa7CyfwQcAZwAAAAEApmnO3bCm7uP_Aj5b98nEhtng1_O4khpogA6po6GyQl_dZsb9Reiw3_56PglZ9Unj9uPtvGIrcZW6gxdY9xq-rEv3fqu55ZpUeKwvR91_087_MgzJ3aKrpEmRt5KCaKP03YZYCapy12vx0qNGp9gNMBKJYPpavV6Cg63Zk_KEYKUyxHJFBwCvAAAAAQCtHFZwQvI_w54UVgDgdY9hnUY3P56kpo6eeTH21BBhoUB9RgEITpVnMKy0r3bX6QtFBBBJrh07iUEDpqsuaMBqjhRsMYMDwq-JmWfdbuDD3Q9XLaVk0HV64Gv9ctJ5FG4RSs3fhpc6S1o6N2up6ylDouyHyomTdlo80o_Htl1bp7gRF5yYa8Qyto6x7UkQbf47F2lEG5s1Rq4SVcdNiZtM7eh-ys8CI9eLgaTmmlsJ13BRKa6i1kWlf7aCfpwNlThZrtMphMDduFSmR_0HAK8AAAABAMyEfG6j7A178epzKvTHhNpwAOny3pNzRywf1vvROi9S9PnFJFvwRtVk7CMFn0fegGgJXcQOK48mpP16R0O-ZP-8rb16gvPHFAAI3fGF3l26xWfj6zcyyDOlKR8Wgbsj7SVo3EgJpJK0W2JgXogw341E7SDWNh4JX6Sqbwe221f8U2NyMiP6lbmGiUULfSvCJLz9VSjF-bwo--QttflDRGmeMkzkkZGvoJN0qVQ-jb1echYkh5CBCrfIYffPhy7r96d6sP3JpoFou-gfUgcArwAAAAEAnwiZFOaAwClLt9i3hSl57fcIlaWyYNb9la9SZwuaG2fstAp8s_n2hgFRlLbv_cGkk_iJmd80YNlGttcXOi1w-GAc5geORikShMIiNM5jOz951Y5G8oI-mB-uQfzpPCPIoz-1kZIuy4eCl3IEdHHDsEcyGe2dYdDE1uwvTl3dY59WsPG--ji-MjvFhgbYY3L4cVIGZMkn-hHpJ4w2JumRVmlXLuz60VEBMecV-5QqB61d3I_1W63mk5dfSWGURZzbnYgWsFAvjsdeZLuyBwA4AAABAQCQy6qUXzUlzpEvOU4GSws4MeHajdbsyFF7POawek3M-W_zDchRDY-FbGg0hx2nU39s8gD3DQ',
            '7. Block1 deleted':
               '2d4lCLWsO_9astzam2P4CYD1TH7IlvhtsvGOCanH3sgHAFIAAAABAF4zrCqkH7RIDn2V8wUkgcGiFTEcYkp6VvOTlX_gyBAAABTlp4yEbvl3YY_sMYeUeUlSL3VkO4dgiwvYKP4iK-9fB-8o3ukq8CYpiN3L6lHrSkr6S-AafKkADRoJ1HgLb1o6OeLRGnhB5g0CceqK-QcAQwAAAAEA7vUweeUy2MBPw5e7QyUUjweN58OtSl454j6u2Npv_A1JSOuXLMTVeqbP-6EQSSAO1oyZntjVZ_SpjIUbNB9-fGkcfVtNIkiqTrnzdNuJLrXbKo8fXlxhHifAJRrsLJ_BBwBnAAAAAQCmac7dsKbu4_8CPlv3ycSG2eDX87iSGmiADqmjobJCX91mxv1F6LDf_no-CVn1SeP24-28YitxlbqDF1j3Gr6sS_d-q7nlmlR4rC9H3X_Tzv8yDMndoqukSZG3koJoo_TdhlgJqnLXa_HSo0an2A0wEolg-lq9XoKDrdmT8oRgpTLEckUHAK8AAAABAK0cVnBC8j_DnhRWAOB1j2GdRjc_nqSmjp55MfbUEGGhQH1GAQhOlWcwrLSvdtfpC0UEEEmuHTuJQQOmqy5owGqOFGwxgwPCr4mZZ91u4MPdD1ctpWTQdXrga_1y0nkUbhFKzd-GlzpLWjo3a6nrKUOi7IfKiZN2WjzSj8e2XVunuBEXnJhrxDK2jrHtSRBt_jsXaUQbmzVGrhJVx02Jm0zt6H7KzwIj14uBpOaaWwnXcFEprqLWRaV_toJ-nA2VOFmu0ymEwN24VKZH_QcArwAAAAEAzIR8bqPsDXvx6nMq9MeE2nAA6fLek3NHLB_W-9E6L1L0-cUkW_BG1WTsIwWfR96AaAldxA4rjyak_XpHQ75k_7ytvXqC88cUAAjd8YXeXbrFZ-PrNzLIM6UpHxaBuyPtJWjcSAmkkrRbYmBeiDDfjUTtINY2HglfpKpvB7bbV_xTY3IyI_qVuYaJRQt9K8IkvP1VKMX5vCj75C21-UNEaZ4yTOSRka-gk3SpVD6NvV5yFiSHkIEKt8hh98-HLuv3p3qw_cmmgWi76B9SBwCvAAAAAQCfCJkU5oDAKUu32LeFKXnt9wiVpbJg1v2Vr1JnC5obZ-y0Cnyz-faGAVGUtu_9waST-ImZ3zRg2Ua21xc6LXD4YBzmB45GKRKEwiI0zmM7P3nVjkbygj6YH65B_Ok8I8ijP7WRki7Lh4KXcgR0ccOwRzIZ7Z1h0MTW7C9OXd1jn1aw8b76OL4yO8WGBthjcvhxUgZkySf6EeknjDYm6ZFWaVcu7PrRUQEx5xX7lCoHrV3cj_VbreaTl19JYZRFnNudiBawUC-Ox15ku7IHADgAAAEBAJDLqpRfNSXOkS85TgZLCzgx4dqN1uzIUXs85rB6Tcz5b_MNyFENj4VsaDSHHadTf2zyAPcN',
            '8. Block2 repeated':
               '2d4lCLWsO_9astzam2P4CYD1TH7IlvhtsvGOCanH3sgHAFIAAAABAF4zrCqkH7RIDn2V8wUkgcGiFTEcYkp6VvOTlX_gyBAAABTlp4yEbvl3YY_sMYeUeUlSL3VkO4dgiwvYKP4iK-9fB-8o3ukq8CYpiN3L6lH2VBqseyvabrr4C5R4j8tso6w-VxdAX-rwdHk6VA6_awcAMQAAAAEASN9jeLe2WjsGNcmYjc3rnc84ctK6A-u-Gl_G_Bxpd9_gPY6EI1bANbRk-Sf2JutKSvpL4Bp8qQANGgnUeAtvWjo54tEaeEHmDQJx6or5BwBDAAAAAQDu9TB55TLYwE_Dl7tDJRSPB43nw61KXjniPq7Y2m_8DUlI65csxNV6ps_7oRBJIA7WjJme2NVn9KmMhRs0H35860pK-kvgGnypAA0aCdR4C29aOjni0Rp4QeYNAnHqivkHAEMAAAABAO71MHnlMtjAT8OXu0MlFI8HjefDrUpeOeI-rtjab_wNSUjrlyzE1Xqmz_uhEEkgDtaMmZ7Y1Wf0qYyFGzQffnxpHH1bTSJIqk6583TbiS612yqPH15cYR4nwCUa7CyfwQcAZwAAAAEApmnO3bCm7uP_Aj5b98nEhtng1_O4khpogA6po6GyQl_dZsb9Reiw3_56PglZ9Unj9uPtvGIrcZW6gxdY9xq-rEv3fqu55ZpUeKwvR91_087_MgzJ3aKrpEmRt5KCaKP03YZYCapy12vx0qNGp9gNMBKJYPpavV6Cg63Zk_KEYKUyxHJFBwCvAAAAAQCtHFZwQvI_w54UVgDgdY9hnUY3P56kpo6eeTH21BBhoUB9RgEITpVnMKy0r3bX6QtFBBBJrh07iUEDpqsuaMBqjhRsMYMDwq-JmWfdbuDD3Q9XLaVk0HV64Gv9ctJ5FG4RSs3fhpc6S1o6N2up6ylDouyHyomTdlo80o_Htl1bp7gRF5yYa8Qyto6x7UkQbf47F2lEG5s1Rq4SVcdNiZtM7eh-ys8CI9eLgaTmmlsJ13BRKa6i1kWlf7aCfpwNlThZrtMphMDduFSmR_0HAK8AAAABAMyEfG6j7A178epzKvTHhNpwAOny3pNzRywf1vvROi9S9PnFJFvwRtVk7CMFn0fegGgJXcQOK48mpP16R0O-ZP-8rb16gvPHFAAI3fGF3l26xWfj6zcyyDOlKR8Wgbsj7SVo3EgJpJK0W2JgXogw341E7SDWNh4JX6Sqbwe221f8U2NyMiP6lbmGiUULfSvCJLz9VSjF-bwo--QttflDRGmeMkzkkZGvoJN0qVQ-jb1echYkh5CBCrfIYffPhy7r96d6sP3JpoFou-gfUgcArwAAAAEAnwiZFOaAwClLt9i3hSl57fcIlaWyYNb9la9SZwuaG2fstAp8s_n2hgFRlLbv_cGkk_iJmd80YNlGttcXOi1w-GAc5geORikShMIiNM5jOz951Y5G8oI-mB-uQfzpPCPIoz-1kZIuy4eCl3IEdHHDsEcyGe2dYdDE1uwvTl3dY59WsPG--ji-MjvFhgbYY3L4cVIGZMkn-hHpJ4w2JumRVmlXLuz60VEBMecV-5QqB61d3I_1W63mk5dfSWGURZzbnYgWsFAvjsdeZLuyBwA4AAABAQCQy6qUXzUlzpEvOU4GSws4MeHajdbsyFF7POawek3M-W_zDchRDY-FbGg0hx2nU39s8gD3DQ',
            '9. Block2 deleted':
               '2d4lCLWsO_9astzam2P4CYD1TH7IlvhtsvGOCanH3sgHAFIAAAABAF4zrCqkH7RIDn2V8wUkgcGiFTEcYkp6VvOTlX_gyBAAABTlp4yEbvl3YY_sMYeUeUlSL3VkO4dgiwvYKP4iK-9fB-8o3ukq8CYpiN3L6lH2VBqseyvabrr4C5R4j8tso6w-VxdAX-rwdHk6VA6_awcAMQAAAAEASN9jeLe2WjsGNcmYjc3rnc84ctK6A-u-Gl_G_Bxpd9_gPY6EI1bANbRk-Sf2JmkcfVtNIkiqTrnzdNuJLrXbKo8fXlxhHifAJRrsLJ_BBwBnAAAAAQCmac7dsKbu4_8CPlv3ycSG2eDX87iSGmiADqmjobJCX91mxv1F6LDf_no-CVn1SeP24-28YitxlbqDF1j3Gr6sS_d-q7nlmlR4rC9H3X_Tzv8yDMndoqukSZG3koJoo_TdhlgJqnLXa_HSo0an2A0wEolg-lq9XoKDrdmT8oRgpTLEckUHAK8AAAABAK0cVnBC8j_DnhRWAOB1j2GdRjc_nqSmjp55MfbUEGGhQH1GAQhOlWcwrLSvdtfpC0UEEEmuHTuJQQOmqy5owGqOFGwxgwPCr4mZZ91u4MPdD1ctpWTQdXrga_1y0nkUbhFKzd-GlzpLWjo3a6nrKUOi7IfKiZN2WjzSj8e2XVunuBEXnJhrxDK2jrHtSRBt_jsXaUQbmzVGrhJVx02Jm0zt6H7KzwIj14uBpOaaWwnXcFEprqLWRaV_toJ-nA2VOFmu0ymEwN24VKZH_QcArwAAAAEAzIR8bqPsDXvx6nMq9MeE2nAA6fLek3NHLB_W-9E6L1L0-cUkW_BG1WTsIwWfR96AaAldxA4rjyak_XpHQ75k_7ytvXqC88cUAAjd8YXeXbrFZ-PrNzLIM6UpHxaBuyPtJWjcSAmkkrRbYmBeiDDfjUTtINY2HglfpKpvB7bbV_xTY3IyI_qVuYaJRQt9K8IkvP1VKMX5vCj75C21-UNEaZ4yTOSRka-gk3SpVD6NvV5yFiSHkIEKt8hh98-HLuv3p3qw_cmmgWi76B9SBwCvAAAAAQCfCJkU5oDAKUu32LeFKXnt9wiVpbJg1v2Vr1JnC5obZ-y0Cnyz-faGAVGUtu_9waST-ImZ3zRg2Ua21xc6LXD4YBzmB45GKRKEwiI0zmM7P3nVjkbygj6YH65B_Ok8I8ijP7WRki7Lh4KXcgR0ccOwRzIZ7Z1h0MTW7C9OXd1jn1aw8b76OL4yO8WGBthjcvhxUgZkySf6EeknjDYm6ZFWaVcu7PrRUQEx5xX7lCoHrV3cj_VbreaTl19JYZRFnNudiBawUC-Ox15ku7IHADgAAAEBAJDLqpRfNSXOkS85TgZLCzgx4dqN1uzIUXs85rB6Tcz5b_MNyFENj4VsaDSHHadTf2zyAPcN',
            '10. Block7 (last) repeated':
               '2d4lCLWsO_9astzam2P4CYD1TH7IlvhtsvGOCanH3sgHAFIAAAABAF4zrCqkH7RIDn2V8wUkgcGiFTEcYkp6VvOTlX_gyBAAABTlp4yEbvl3YY_sMYeUeUlSL3VkO4dgiwvYKP4iK-9fB-8o3ukq8CYpiN3L6lH2VBqseyvabrr4C5R4j8tso6w-VxdAX-rwdHk6VA6_awcAMQAAAAEASN9jeLe2WjsGNcmYjc3rnc84ctK6A-u-Gl_G_Bxpd9_gPY6EI1bANbRk-Sf2JutKSvpL4Bp8qQANGgnUeAtvWjo54tEaeEHmDQJx6or5BwBDAAAAAQDu9TB55TLYwE_Dl7tDJRSPB43nw61KXjniPq7Y2m_8DUlI65csxNV6ps_7oRBJIA7WjJme2NVn9KmMhRs0H358aRx9W00iSKpOufN024kutdsqjx9eXGEeJ8AlGuwsn8EHAGcAAAABAKZpzt2wpu7j_wI-W_fJxIbZ4NfzuJIaaIAOqaOhskJf3WbG_UXosN_-ej4JWfVJ4_bj7bxiK3GVuoMXWPcavqxL936rueWaVHisL0fdf9PO_zIMyd2iq6RJkbeSgmij9N2GWAmqctdr8dKjRqfYDTASiWD6Wr1egoOt2ZPyhGClMsRyRQcArwAAAAEArRxWcELyP8OeFFYA4HWPYZ1GNz-epKaOnnkx9tQQYaFAfUYBCE6VZzCstK921-kLRQQQSa4dO4lBA6arLmjAao4UbDGDA8KviZln3W7gw90PVy2lZNB1euBr_XLSeRRuEUrN34aXOktaOjdrqespQ6Lsh8qJk3ZaPNKPx7ZdW6e4ERecmGvEMraOse1JEG3-OxdpRBubNUauElXHTYmbTO3ofsrPAiPXi4Gk5ppbCddwUSmuotZFpX-2gn6cDZU4Wa7TKYTA3bhUpkf9BwCvAAAAAQDMhHxuo-wNe_Hqcyr0x4TacADp8t6Tc0csH9b70TovUvT5xSRb8EbVZOwjBZ9H3oBoCV3EDiuPJqT9ekdDvmT_vK29eoLzxxQACN3xhd5dusVn4-s3MsgzpSkfFoG7I-0laNxICaSStFtiYF6IMN-NRO0g1jYeCV-kqm8HtttX_FNjcjIj-pW5holFC30rwiS8_VUoxfm8KPvkLbX5Q0RpnjJM5JGRr6CTdKlUPo29XnIWJIeQgQq3yGH3z4cu6_enerD9yaaBaLvoH1IHAK8AAAABAJ8ImRTmgMApS7fYt4Upee33CJWlsmDW_ZWvUmcLmhtn7LQKfLP59oYBUZS27_3BpJP4iZnfNGDZRrbXFzotcPhgHOYHjkYpEoTCIjTOYzs_edWORvKCPpgfrkH86TwjyKM_tZGSLsuHgpdyBHRxw7BHMhntnWHQxNbsL05d3WOfVrDxvvo4vjI7xYYG2GNy-HFSBmTJJ_oR6SeMNibpkVZpVy7s-tFRATHnFfuUKgetXdyP9Vut5pOXX0lhlEWc252IFrBQL47HXmS7sgcAOAAAAQEAkMuqlF81Jc6RLzlOBksLODHh2o3W7MhRezzmsHpNzPlv8w3IUQ2PhWxoNIcdp1N_bPIA9w2UKgetXdyP9Vut5pOXX0lhlEWc252IFrBQL47HXmS7sgcAOAAAAQEAkMuqlF81Jc6RLzlOBksLODHh2o3W7MhRezzmsHpNzPlv8w3IUQ2PhWxoNIcdp1N_bPIA9w0',
            '11. Block7 (last) deleted':
               '2d4lCLWsO_9astzam2P4CYD1TH7IlvhtsvGOCanH3sgHAFIAAAABAF4zrCqkH7RIDn2V8wUkgcGiFTEcYkp6VvOTlX_gyBAAABTlp4yEbvl3YY_sMYeUeUlSL3VkO4dgiwvYKP4iK-9fB-8o3ukq8CYpiN3L6lH2VBqseyvabrr4C5R4j8tso6w-VxdAX-rwdHk6VA6_awcAMQAAAAEASN9jeLe2WjsGNcmYjc3rnc84ctK6A-u-Gl_G_Bxpd9_gPY6EI1bANbRk-Sf2JutKSvpL4Bp8qQANGgnUeAtvWjo54tEaeEHmDQJx6or5BwBDAAAAAQDu9TB55TLYwE_Dl7tDJRSPB43nw61KXjniPq7Y2m_8DUlI65csxNV6ps_7oRBJIA7WjJme2NVn9KmMhRs0H358aRx9W00iSKpOufN024kutdsqjx9eXGEeJ8AlGuwsn8EHAGcAAAABAKZpzt2wpu7j_wI-W_fJxIbZ4NfzuJIaaIAOqaOhskJf3WbG_UXosN_-ej4JWfVJ4_bj7bxiK3GVuoMXWPcavqxL936rueWaVHisL0fdf9PO_zIMyd2iq6RJkbeSgmij9N2GWAmqctdr8dKjRqfYDTASiWD6Wr1egoOt2ZPyhGClMsRyRQcArwAAAAEArRxWcELyP8OeFFYA4HWPYZ1GNz-epKaOnnkx9tQQYaFAfUYBCE6VZzCstK921-kLRQQQSa4dO4lBA6arLmjAao4UbDGDA8KviZln3W7gw90PVy2lZNB1euBr_XLSeRRuEUrN34aXOktaOjdrqespQ6Lsh8qJk3ZaPNKPx7ZdW6e4ERecmGvEMraOse1JEG3-OxdpRBubNUauElXHTYmbTO3ofsrPAiPXi4Gk5ppbCddwUSmuotZFpX-2gn6cDZU4Wa7TKYTA3bhUpkf9BwCvAAAAAQDMhHxuo-wNe_Hqcyr0x4TacADp8t6Tc0csH9b70TovUvT5xSRb8EbVZOwjBZ9H3oBoCV3EDiuPJqT9ekdDvmT_vK29eoLzxxQACN3xhd5dusVn4-s3MsgzpSkfFoG7I-0laNxICaSStFtiYF6IMN-NRO0g1jYeCV-kqm8HtttX_FNjcjIj-pW5holFC30rwiS8_VUoxfm8KPvkLbX5Q0RpnjJM5JGRr6CTdKlUPo29XnIWJIeQgQq3yGH3z4cu6_enerD9yaaBaLvoH1IHAK8AAAABAJ8ImRTmgMApS7fYt4Upee33CJWlsmDW_ZWvUmcLmhtn7LQKfLP59oYBUZS27_3BpJP4iZnfNGDZRrbXFzotcPhgHOYHjkYpEoTCIjTOYzs_edWORvKCPpgfrkH86TwjyKM_tZGSLsuHgpdyBHRxw7BHMhntnWHQxNbsL05d3WOfVrDxvvo4vjI7xYYG2GNy-HFSBmTJJ_oR6SeMNibpkVZpVy7s-tFRATHnFfs',
            '12. Block1 Block7 deleted':
               '2d4lCLWsO_9astzam2P4CYD1TH7IlvhtsvGOCanH3sgHAFIAAAABAF4zrCqkH7RIDn2V8wUkgcGiFTEcYkp6VvOTlX_gyBAAABTlp4yEbvl3YY_sMYeUeUlSL3VkO4dgiwvYKP4iK-9fB-8o3ukq8CYpiN3L6lHrSkr6S-AafKkADRoJ1HgLb1o6OeLRGnhB5g0CceqK-QcAQwAAAAEA7vUweeUy2MBPw5e7QyUUjweN58OtSl454j6u2Npv_A1JSOuXLMTVeqbP-6EQSSAO1oyZntjVZ_SpjIUbNB9-fGkcfVtNIkiqTrnzdNuJLrXbKo8fXlxhHifAJRrsLJ_BBwBnAAAAAQCmac7dsKbu4_8CPlv3ycSG2eDX87iSGmiADqmjobJCX91mxv1F6LDf_no-CVn1SeP24-28YitxlbqDF1j3Gr6sS_d-q7nlmlR4rC9H3X_Tzv8yDMndoqukSZG3koJoo_TdhlgJqnLXa_HSo0an2A0wEolg-lq9XoKDrdmT8oRgpTLEckUHAK8AAAABAK0cVnBC8j_DnhRWAOB1j2GdRjc_nqSmjp55MfbUEGGhQH1GAQhOlWcwrLSvdtfpC0UEEEmuHTuJQQOmqy5owGqOFGwxgwPCr4mZZ91u4MPdD1ctpWTQdXrga_1y0nkUbhFKzd-GlzpLWjo3a6nrKUOi7IfKiZN2WjzSj8e2XVunuBEXnJhrxDK2jrHtSRBt_jsXaUQbmzVGrhJVx02Jm0zt6H7KzwIj14uBpOaaWwnXcFEprqLWRaV_toJ-nA2VOFmu0ymEwN24VKZH_QcArwAAAAEAzIR8bqPsDXvx6nMq9MeE2nAA6fLek3NHLB_W-9E6L1L0-cUkW_BG1WTsIwWfR96AaAldxA4rjyak_XpHQ75k_7ytvXqC88cUAAjd8YXeXbrFZ-PrNzLIM6UpHxaBuyPtJWjcSAmkkrRbYmBeiDDfjUTtINY2HglfpKpvB7bbV_xTY3IyI_qVuYaJRQt9K8IkvP1VKMX5vCj75C21-UNEaZ4yTOSRka-gk3SpVD6NvV5yFiSHkIEKt8hh98-HLuv3p3qw_cmmgWi76B9SBwCvAAAAAQCfCJkU5oDAKUu32LeFKXnt9wiVpbJg1v2Vr1JnC5obZ-y0Cnyz-faGAVGUtu_9waST-ImZ3zRg2Ua21xc6LXD4YBzmB45GKRKEwiI0zmM7P3nVjkbygj6YH65B_Ok8I8ijP7WRki7Lh4KXcgR0ccOwRzIZ7Z1h0MTW7C9OXd1jn1aw8b76OL4yO8WGBthjcvhxUgZkySf6EeknjDYm6ZFWaVcu7PrRUQEx5xX7',
            '13. All Term':
               'zpiIZklzA6RWnwn6HxsfIkN6z2YtOsePo9-qZzw816UHAFIAAAEBAGMilUR63r3bEe83MbNGl0PmkAmPibWGCu8NlevgyBAAABQvcQ6RhWv-A4FcjAepLbq0lfiYYjbFIF_NcS55rpgRTimPcx1yWejGYnk1DhPS1e064WxpYONYGB8LAXF8p40fGI8kQQHtCQEwvhavjQcAMQAAAQEA_0DhE2tya_IKZ5nO9Pq8SBzjShmFXn6OGd7MQQiuL6k-1lqblKQpnT096eM-58N4Ft9J9jlwB6XTJ5WqrD22zfMahMQmseGLpC9tcltbBwBDAAABAQCV7Emh-0NdfOIgV8s4iKXiJsYLiIlDUiXDL23Jns_P_iEd314p5RkasUWTEKU26DLyXKBSBPd0F8GRyEm7C8XsWaWIVXVvYjNPv1c_M72I5DWjaRLdQ7pln7D2-OOC6v8HAGcAAAEBAGaFsoMf-HX7fghoqeQrQ6QnEFiFm0ZXsrmUJfxpaRxl_Ogm_dBINEfnzN9ljI1fLnw5zA-3yqJigbvl8zvkRuWsUUl0e6zlr4NaH-Rp67D1CVy3f_kQMrZOrJA9BYAXCWO74ZdVl9zivjT6tNOr_h5YqyCs30ihd9BCBl8-xgXcCEd6pgcArwAAAQEAtkmRrXT4DpH8gYijKo-FE1tgk4FBjqVbD1GjO_r92sjUbGeJmFAMA1jtH9f1Twk-Etg5dQeGbQl7M89zAg97kqkZ1Xnipj6dlbbx88wVYTVgU2AHNAXu2Q1RCdtGqUM2T-GxS4QLRzdyBN_F24fCU7McPQLx8QjrSxNDdIdAU8yqnRPogBkA3B883h-jom9glwBM_vDAcQEg3eeRQ9hWb1pj0EoJYp18X8-ZwcpbkBKz1z40e0fRuxaKeXmD6rWdqZoHiR_lad0Pqzd0BwCvAAABAQDxil1cljnWDQkcOL6559HpA0Cq8ITkc6Bab7VfHVInkJYR6sHbodF-5exhzDEVdonRZ6idOSv_vvT5Ej5t4DQyRVDNS8SzvXndZQwGOQvMQZZldjGKWvK6d2y5Wb2jXixWj0Wo75IlqUHQyjexQvA2z1cNSonEGtIs3ISQyyXaakOjAxHavgB8S-QK7qzw7AzlDINnfrbyX4pIIyfrAV-JbzyFfxwLyppoT9DiQOVlyHokpO5EJMqrZ_2ssafrxvNYTUns4TUfyPUJqYIHAK8AAAEBAFZcFHLI7cN1HEShESijeDg8t3xCjXJKNQlDLV1S8hfmJkxu8u9AZX6UsuRkWtiRxfOqLccxRfa4O8NM0LcsBfCdjX5_P0hQMFSpffX7AONUNb5ksGeAKp7ybVE_FU1Rumfi7-yP_tnpOaxyHcRyQr13mdSUiwAsSBD1aiLICAKdV59ayWqnG4SyTj3e-khEfzoSnJvGfhmOWbAFDDLXXUILaEiRH1hLJyBSntxCVbLeES28nOUjOS1V53KUuCm9sWZU1KTZrD5gIf6rngcAOAAAAQEA1iceQurYvvBiOItVQqmdP0-1QYPrWnc0qFLkzerUeI6HfJF3gfw_cQmt1sohK2pGey7G86Q',
            '14. No Term':
               'um9RcvgpupjPTd9G3n6KzglAYTLhgsPaVmPjfCAFOQEHAFIAAAABABtiE0CpERAC6IeCRrKS3rS7tPfZLxuYLpYZLWXgyBAAABTww0ZoTp349Hiz7hCyDkLsK4Q1S8LLIKYcnvzGlwxRQY3aU-iChor4W7cAIkjM5-aYndu1Gc8wz8f_GdrJHss765Wh5JlPFhP_WmMV4wcAMQAAAAEAzuCntdnuhBuWK_v33oTDjRUU8f9nSbyYE2OmQL3YR4bAVOc35TLm_oD4aNsBt9SJjcRwF57zavSpn3bava-q6cSnfSGelZvqJ09JV7CcBwBDAAAAAQB5L926gvwMJsENlTjFGaAzw2NXCLNhpPvf0CjTeKhhwX01Gk8DynNRDOH9awFB3X7kfOSRC8Sm9bREKKvUNgorDC6YimAratrlfrcapw5jQJTV9CxbW4tPQ_sEblsWglMHAGcAAAABAKXvG3PvQDeyPUv5iHOfgOVT4d26-VJxx7cbKUDbL0B-2QivDHy4mUd7GWb77nh_q69P-BwhyVrafcdSPNjCIbgW3MDwCwpCHceO0QWAZH4hXPw-rzgdut9RXoB0F_pNoSo0ZxpaG9fprrA6PIapFbb3HVFvzAcZez8VR5PsW-AoDlXAIgcArwAAAAEA-WGvyWChZJuzjHaS0EuHhll78KbERUpEB_hKdeYf4HDttVuw8vL8gYq3gpdCzs3-ny7LGygPmfK0eeQ6BsBMA_ZVZoLwClyY2v0MdGgDEfT39-gPyZOa8FKYFbp6vqH8TH_-ban2cTB1Dj3zRbfhOa7LnhqneG1Tfw107MuRgRDGLHIDLLitJNQnJANH38keUYJEQGHCbBi47s-k2J8Asr8SoGQZw8U-g941AQO92iir0qrJCGxcxhUfdCOfUDdwM_y7yxOmZ9kJJZ4tBwCvAAAAAQDhkbjGfJ-iM53YKoD-B7hLxd2feR4QxDP3JJGE3GbxDlSI_sPIioqHONUCVMvWXkfJ5SZeUudpXl7STKthdipLG_6Now6UefHSYdy2ZyGdvKNPJxUtxVUNfJ4ba27Rhn5VVnWfUqUYkOwO8vYC09fpteAjFsyN32g84z6B6iGAs5UpfWVMUN3yO_P2ir1u4sa4Vy9DSPDdSaltuDxO8X7VUHwxg1okpw6IDboPhUV0f48NBwmHfZqNlSq2cuqxwR4UrGUivsNfVk1qGUwHAK8AAAABAAsxtebwF1tl2y2CcoLx1rMa30D_b4OICPMX5Vgsspd7w5BHffnK6vF29l5dn37rbhqe-i4d3-03clKTGswGBDEYqHAzw-3-Z1g8EdpVPIgvPkUFCO13I1N9oVw427cyO-og8pbOVEDK6FKHujHDaN6b-AOOGYhh2Bl1KAOeVwAF88-uzA1auD50l9Awttj-apRCYvDteZ_gjtIxjMXJBE4WAF_zVJiTa9ayizItRGdiQqGYKtN8R6CJPc-NDRaf0jHm_ksXv6VyRg01JQcAOAAAAAEAPm9NAHz915c7Eqi7aZMYaQV7NPRMnD7QOhossuVZybaxvRrPOM-w_-niY5BqLCQWWVb2eWc',
         },
      },
      //v8 — generated by: pnpm vectors:ciphersvc
      {
         ver: 8,
         goodCt:
            'Ta3XqzSSntJoSTE2Ru10N_ot-V8mlwPqWnT9APiNky4IAHMAAAABAKlcxHh4Bwsd1ORWi20jL-hyNBOd5K5aEl9ITw_gyBAAABSKelh_NJBNkl0qTUZgUggKyy_UySBiRO1eIZ0gW6A1q0HOnj5EeH5m0XTASebpCIY2ZGHL8J523j-vlARIlwxSK5nsWojei6xbrH4kiQngb2UkUCjR0AaiKAN3oRhXzZYBhEOszYUb0v-XXgvErQgAMQAAAAEAUHycvyyQVxLjTvmceTj7QVwuAxrjS9rqUdyu0ULQgMOAUIFE3pmk0G5s3CNL_GdbR6LMgQNO4hBUF-0zcCXiRQuNx5exW7M_BCv1UxscCABDAAAAAQCHRzWQPhTWzc74vbjcOTCpW-Nd7XezI-E-1or2Hii-y3FuCOj12TSauLqo_DggQT8NWS48xIZaKPOiCm1_rlw_NF9RWtW9qEEMqNHVwYwUtUyJj-j2yd51jqRZWYLzoHwIAGcAAAABAPeHmsn1w6djcci1ZIRFVmae0qdqR56qPr6sKuxGZS5oq0ya-nS_YQq5kVwsHtA41HRllgmK3XX5xTA650_6CWBd9xpbTARsr1HZQNTpHl4MU8_ZkLIR-PoF8GdsWPPWxW2uYdBfIz6V6WqM1_ImjZb6JUp9m5UaAWQy83mFvcWYaN6dYwgArwAAAAEAta331j-Vc9tTmPCBSBbqpMGWUhB0HYUaMboIj2OX_xFls4dMlsvVQZJv-Id6kbmlVuJq7t7BM2Z0bS_vnokjUF52c2m86FvOVvj7EZtlGdTHy5a7DbnPl5aaSHRuQRw_HczzTP3QMPYbRPYsX7xt5kPp5M7BYO3L--G-8XB6_qvMay02Rju86uX81lfppfnvaWwYJ9FYOUWvGctBq7jcUwXf94t27JseO3BbIyvgiuxmfLFShL-RfAAWJ3YjJmRBuMmqPMJvxlHTyFH5CACvAAAAAQDcKwS12arGvrzmZBWesDef-jcVkeoQKd7LYEghzli3Sdv1gbGU-FlYHBj3lc0hes71XZ5HeYeEXkNEOK3LgHhmmOQDulvkOV6i-YpdX9P0VqUAOWhTX4vinLVuUbLLf_GVEOIPRp5r4xYgJIujx1ZpLDbm1ZSiCLwibYPV1COthUBFpO_UPL1XzN9HVxDdirzW3ocpRA9NhzD1N787TpyYVvaWLAsB8uAKPsuylO0CbNFmwQy8inwpL3VC98Sf4KMfq6F3B_NIbPHNzI8IAK8AAAABABXQbyQK3C3HDNBaEPCvJwiispJR9VZ4UoUPYkx_vhGwaYCsZJWYq5nXCl4w_20HebHbdezhqoF9ixN8eFn-5Os72a2oMSgRnRzgrM7mRQJhySLX41XrcJl_Nazl9v3DODMNokL8NWB9gbbcdG9hV52gsn02dVukhkjx6pZj3j-DXt2LtScb06ND-Md-mBxGGkxjxFEh99Wfbic6VBlcYiKGfLACNMI2eZgOzQqtsA2goyJnyuGilC1s_fQfWm7Psw0UNTNFSItCHcKCVggAOAAAAQEAejWDVrOwhFyW4TbInm2SM98DfNac11tXhvZDwA7t9bRxhMkWwrbBae9gB9rdFz1QiKjXouw',
         badCts: {
            '1. Block0 Block7 swap':
               'rbANoKMiZ8rhopQtbP30H1puz7MNFDUzRUiLQh3CglYIADgAAAEBAHo1g1azsIRcluE2yJ5tkjPfA3zWnNdbV4b2Q8AO7fW0cYTJFsK2wWnvYAfa3Rc9UIio16Ls4G9lJFAo0dAGoigDd6EYV82WAYRDrM2FG9L_l14LxK0IADEAAAABAFB8nL8skFcS4075nHk4-0FcLgMa40va6lHcrtFC0IDDgFCBRN6ZpNBubNwjS_xnW0eizIEDTuIQVBftM3Al4kULjceXsVuzPwQr9VMbHAgAQwAAAAEAh0c1kD4U1s3O-L243DkwqVvjXe13syPhPtaK9h4ovstxbgjo9dk0mri6qPw4IEE_DVkuPMSGWijzogptf65cPzRfUVrVvahBDKjR1cGMFLVMiY_o9snedY6kWVmC86B8CABnAAAAAQD3h5rJ9cOnY3HItWSERVZmntKnakeeqj6-rCrsRmUuaKtMmvp0v2EKuZFcLB7QONR0ZZYJit11-cUwOudP-glgXfcaW0wEbK9R2UDU6R5eDFPP2ZCyEfj6BfBnbFjz1sVtrmHQXyM-lelqjNfyJo2W-iVKfZuVGgFkMvN5hb3FmGjenWMIAK8AAAABALWt99Y_lXPbU5jwgUgW6qTBllIQdB2FGjG6CI9jl_8RZbOHTJbL1UGSb_iHepG5pVbiau7ewTNmdG0v756JI1BednNpvOhbzlb4-xGbZRnUx8uWuw25z5eWmkh0bkEcPx3M80z90DD2G0T2LF-8beZD6eTOwWDty_vhvvFwev6rzGstNkY7vOrl_NZX6aX572lsGCfRWDlFrxnLQau43FMF3_eLduybHjtwWyMr4IrsZnyxUoS_kXwAFid2IyZkQbjJqjzCb8ZR08hR-QgArwAAAAEA3CsEtdmqxr685mQVnrA3n_o3FZHqECney2BIIc5Yt0nb9YGxlPhZWBwY95XNIXrO9V2eR3mHhF5DRDity4B4ZpjkA7pb5DleovmKXV_T9FalADloU1-L4py1blGyy3_xlRDiD0aea-MWICSLo8dWaSw25tWUogi8Im2D1dQjrYVARaTv1Dy9V8zfR1cQ3Yq81t6HKUQPTYcw9Te_O06cmFb2liwLAfLgCj7LspTtAmzRZsEMvIp8KS91QvfEn-CjH6uhdwfzSGzxzcyPCACvAAAAAQAV0G8kCtwtxwzQWhDwrycIorKSUfVWeFKFD2JMf74RsGmArGSVmKuZ1wpeMP9tB3mx23Xs4aqBfYsTfHhZ_uTrO9mtqDEoEZ0c4KzO5kUCYcki1-NV63CZfzWs5fb9wzgzDaJC_DVgfYG23HRvYVedoLJ9NnVbpIZI8eqWY94_g17di7UnG9OjQ_jHfpgcRhpMY8RRIffVn24nOlQZXGIihnywAjTCNnmYDs0KTa3XqzSSntJoSTE2Ru10N_ot-V8mlwPqWnT9APiNky4IAHMAAAABAKlcxHh4Bwsd1ORWi20jL-hyNBOd5K5aEl9ITw_gyBAAABSKelh_NJBNkl0qTUZgUggKyy_UySBiRO1eIZ0gW6A1q0HOnj5EeH5m0XTASebpCIY2ZGHL8J523j-vlARIlwxSK5nsWojei6xbrH4kiQk',
            '2. Block1 Block7 swap':
               'Ta3XqzSSntJoSTE2Ru10N_ot-V8mlwPqWnT9APiNky4IAHMAAAABAKlcxHh4Bwsd1ORWi20jL-hyNBOd5K5aEl9ITw_gyBAAABSKelh_NJBNkl0qTUZgUggKyy_UySBiRO1eIZ0gW6A1q0HOnj5EeH5m0XTASebpCIY2ZGHL8J523j-vlARIlwxSK5nsWojei6xbrH4kiQmtsA2goyJnyuGilC1s_fQfWm7Psw0UNTNFSItCHcKCVggAOAAAAQEAejWDVrOwhFyW4TbInm2SM98DfNac11tXhvZDwA7t9bRxhMkWwrbBae9gB9rdFz1QiKjXouxnW0eizIEDTuIQVBftM3Al4kULjceXsVuzPwQr9VMbHAgAQwAAAAEAh0c1kD4U1s3O-L243DkwqVvjXe13syPhPtaK9h4ovstxbgjo9dk0mri6qPw4IEE_DVkuPMSGWijzogptf65cPzRfUVrVvahBDKjR1cGMFLVMiY_o9snedY6kWVmC86B8CABnAAAAAQD3h5rJ9cOnY3HItWSERVZmntKnakeeqj6-rCrsRmUuaKtMmvp0v2EKuZFcLB7QONR0ZZYJit11-cUwOudP-glgXfcaW0wEbK9R2UDU6R5eDFPP2ZCyEfj6BfBnbFjz1sVtrmHQXyM-lelqjNfyJo2W-iVKfZuVGgFkMvN5hb3FmGjenWMIAK8AAAABALWt99Y_lXPbU5jwgUgW6qTBllIQdB2FGjG6CI9jl_8RZbOHTJbL1UGSb_iHepG5pVbiau7ewTNmdG0v756JI1BednNpvOhbzlb4-xGbZRnUx8uWuw25z5eWmkh0bkEcPx3M80z90DD2G0T2LF-8beZD6eTOwWDty_vhvvFwev6rzGstNkY7vOrl_NZX6aX572lsGCfRWDlFrxnLQau43FMF3_eLduybHjtwWyMr4IrsZnyxUoS_kXwAFid2IyZkQbjJqjzCb8ZR08hR-QgArwAAAAEA3CsEtdmqxr685mQVnrA3n_o3FZHqECney2BIIc5Yt0nb9YGxlPhZWBwY95XNIXrO9V2eR3mHhF5DRDity4B4ZpjkA7pb5DleovmKXV_T9FalADloU1-L4py1blGyy3_xlRDiD0aea-MWICSLo8dWaSw25tWUogi8Im2D1dQjrYVARaTv1Dy9V8zfR1cQ3Yq81t6HKUQPTYcw9Te_O06cmFb2liwLAfLgCj7LspTtAmzRZsEMvIp8KS91QvfEn-CjH6uhdwfzSGzxzcyPCACvAAAAAQAV0G8kCtwtxwzQWhDwrycIorKSUfVWeFKFD2JMf74RsGmArGSVmKuZ1wpeMP9tB3mx23Xs4aqBfYsTfHhZ_uTrO9mtqDEoEZ0c4KzO5kUCYcki1-NV63CZfzWs5fb9wzgzDaJC_DVgfYG23HRvYVedoLJ9NnVbpIZI8eqWY94_g17di7UnG9OjQ_jHfpgcRhpMY8RRIffVn24nOlQZXGIihnywAjTCNnmYDs0K4G9lJFAo0dAGoigDd6EYV82WAYRDrM2FG9L_l14LxK0IADEAAAABAFB8nL8skFcS4075nHk4-0FcLgMa40va6lHcrtFC0IDDgFCBRN6ZpNBubNwjS_w',
            '3. Block1 Block4 swap':
               'Ta3XqzSSntJoSTE2Ru10N_ot-V8mlwPqWnT9APiNky4IAHMAAAABAKlcxHh4Bwsd1ORWi20jL-hyNBOd5K5aEl9ITw_gyBAAABSKelh_NJBNkl0qTUZgUggKyy_UySBiRO1eIZ0gW6A1q0HOnj5EeH5m0XTASebpCIY2ZGHL8J523j-vlARIlwxSK5nsWojei6xbrH4kiQlfIz6V6WqM1_ImjZb6JUp9m5UaAWQy83mFvcWYaN6dYwgArwAAAAEAta331j-Vc9tTmPCBSBbqpMGWUhB0HYUaMboIj2OX_xFls4dMlsvVQZJv-Id6kbmlVuJq7t7BM2Z0bS_vnokjUF52c2m86FvOVvj7EZtlGdTHy5a7DbnPl5aaSHRuQRw_HczzTP3QMPYbRPYsX7xt5kPp5M7BYO3L--G-8XB6_qvMay02Rju86uX81lfppfnvaWwYJ9FYOUWvGctBq7jcUwXf94t27JseO3BbI2dbR6LMgQNO4hBUF-0zcCXiRQuNx5exW7M_BCv1UxscCABDAAAAAQCHRzWQPhTWzc74vbjcOTCpW-Nd7XezI-E-1or2Hii-y3FuCOj12TSauLqo_DggQT8NWS48xIZaKPOiCm1_rlw_NF9RWtW9qEEMqNHVwYwUtUyJj-j2yd51jqRZWYLzoHwIAGcAAAABAPeHmsn1w6djcci1ZIRFVmae0qdqR56qPr6sKuxGZS5oq0ya-nS_YQq5kVwsHtA41HRllgmK3XX5xTA650_6CWBd9xpbTARsr1HZQNTpHl4MU8_ZkLIR-PoF8GdsWPPWxW2uYdDgb2UkUCjR0AaiKAN3oRhXzZYBhEOszYUb0v-XXgvErQgAMQAAAAEAUHycvyyQVxLjTvmceTj7QVwuAxrjS9rqUdyu0ULQgMOAUIFE3pmk0G5s3CNL_CvgiuxmfLFShL-RfAAWJ3YjJmRBuMmqPMJvxlHTyFH5CACvAAAAAQDcKwS12arGvrzmZBWesDef-jcVkeoQKd7LYEghzli3Sdv1gbGU-FlYHBj3lc0hes71XZ5HeYeEXkNEOK3LgHhmmOQDulvkOV6i-YpdX9P0VqUAOWhTX4vinLVuUbLLf_GVEOIPRp5r4xYgJIujx1ZpLDbm1ZSiCLwibYPV1COthUBFpO_UPL1XzN9HVxDdirzW3ocpRA9NhzD1N787TpyYVvaWLAsB8uAKPsuylO0CbNFmwQy8inwpL3VC98Sf4KMfq6F3B_NIbPHNzI8IAK8AAAABABXQbyQK3C3HDNBaEPCvJwiispJR9VZ4UoUPYkx_vhGwaYCsZJWYq5nXCl4w_20HebHbdezhqoF9ixN8eFn-5Os72a2oMSgRnRzgrM7mRQJhySLX41XrcJl_Nazl9v3DODMNokL8NWB9gbbcdG9hV52gsn02dVukhkjx6pZj3j-DXt2LtScb06ND-Md-mBxGGkxjxFEh99Wfbic6VBlcYiKGfLACNMI2eZgOzQqtsA2goyJnyuGilC1s_fQfWm7Psw0UNTNFSItCHcKCVggAOAAAAQEAejWDVrOwhFyW4TbInm2SM98DfNac11tXhvZDwA7t9bRxhMkWwrbBae9gB9rdFz1QiKjXouw',
            '4. Block0 repeated':
               'Ta3XqzSSntJoSTE2Ru10N_ot-V8mlwPqWnT9APiNky4IAHMAAAABAKlcxHh4Bwsd1ORWi20jL-hyNBOd5K5aEl9ITw_gyBAAABSKelh_NJBNkl0qTUZgUggKyy_UySBiRO1eIZ0gW6A1q0HOnj5EeH5m0XTASebpCIY2ZGHL8J523j-vlARIlwxSK5nsWojei6xbrH4kiQlNrderNJKe0mhJMTZG7XQ3-i35XyaXA-padP0A-I2TLggAcwAAAAEAqVzEeHgHCx3U5FaLbSMv6HI0E53krloSX0hPD-DIEAAAFIp6WH80kE2SXSpNRmBSCArLL9TJIGJE7V4hnSBboDWrQc6ePkR4fmbRdMBJ5ukIhjZkYcvwnnbeP6-UBEiXDFIrmexaiN6LrFusfiSJCeBvZSRQKNHQBqIoA3ehGFfNlgGEQ6zNhRvS_5deC8StCAAxAAAAAQBQfJy_LJBXEuNO-Zx5OPtBXC4DGuNL2upR3K7RQtCAw4BQgUTemaTQbmzcI0v8Z1tHosyBA07iEFQX7TNwJeJFC43Hl7Fbsz8EK_VTGxwIAEMAAAABAIdHNZA-FNbNzvi9uNw5MKlb413td7Mj4T7WivYeKL7LcW4I6PXZNJq4uqj8OCBBPw1ZLjzEhloo86IKbX-uXD80X1Fa1b2oQQyo0dXBjBS1TImP6PbJ3nWOpFlZgvOgfAgAZwAAAAEA94eayfXDp2NxyLVkhEVWZp7Sp2pHnqo-vqwq7EZlLmirTJr6dL9hCrmRXCwe0DjUdGWWCYrddfnFMDrnT_oJYF33GltMBGyvUdlA1OkeXgxTz9mQshH4-gXwZ2xY89bFba5h0F8jPpXpaozX8iaNlvolSn2blRoBZDLzeYW9xZho3p1jCACvAAAAAQC1rffWP5Vz21OY8IFIFuqkwZZSEHQdhRoxugiPY5f_EWWzh0yWy9VBkm_4h3qRuaVW4mru3sEzZnRtL--eiSNQXnZzabzoW85W-PsRm2UZ1MfLlrsNuc-XlppIdG5BHD8dzPNM_dAw9htE9ixfvG3mQ-nkzsFg7cv74b7xcHr-q8xrLTZGO7zq5fzWV-ml-e9pbBgn0Vg5Ra8Zy0GruNxTBd_3i3bsmx47cFsjK-CK7GZ8sVKEv5F8ABYndiMmZEG4yao8wm_GUdPIUfkIAK8AAAABANwrBLXZqsa-vOZkFZ6wN5_6NxWR6hAp3stgSCHOWLdJ2_WBsZT4WVgcGPeVzSF6zvVdnkd5h4ReQ0Q4rcuAeGaY5AO6W-Q5XqL5il1f0_RWpQA5aFNfi-KctW5Rsst_8ZUQ4g9GnmvjFiAki6PHVmksNubVlKIIvCJtg9XUI62FQEWk79Q8vVfM30dXEN2KvNbehylED02HMPU3vztOnJhW9pYsCwHy4Ao-y7KU7QJs0WbBDLyKfCkvdUL3xJ_gox-roXcH80hs8c3MjwgArwAAAAEAFdBvJArcLccM0FoQ8K8nCKKyklH1VnhShQ9iTH--EbBpgKxklZirmdcKXjD_bQd5sdt17OGqgX2LE3x4Wf7k6zvZragxKBGdHOCszuZFAmHJItfjVetwmX81rOX2_cM4Mw2iQvw1YH2Bttx0b2FXnaCyfTZ1W6SGSPHqlmPeP4Ne3Yu1JxvTo0P4x36YHEYaTGPEUSH31Z9uJzpUGVxiIoZ8sAI0wjZ5mA7NCq2wDaCjImfK4aKULWz99B9abs-zDRQ1M0VIi0IdwoJWCAA4AAABAQB6NYNWs7CEXJbhNsiebZIz3wN81pzXW1eG9kPADu31tHGEyRbCtsFp72AH2t0XPVCIqNei7A',
            '5. Block0 deleted':
               '4G9lJFAo0dAGoigDd6EYV82WAYRDrM2FG9L_l14LxK0IADEAAAABAFB8nL8skFcS4075nHk4-0FcLgMa40va6lHcrtFC0IDDgFCBRN6ZpNBubNwjS_xnW0eizIEDTuIQVBftM3Al4kULjceXsVuzPwQr9VMbHAgAQwAAAAEAh0c1kD4U1s3O-L243DkwqVvjXe13syPhPtaK9h4ovstxbgjo9dk0mri6qPw4IEE_DVkuPMSGWijzogptf65cPzRfUVrVvahBDKjR1cGMFLVMiY_o9snedY6kWVmC86B8CABnAAAAAQD3h5rJ9cOnY3HItWSERVZmntKnakeeqj6-rCrsRmUuaKtMmvp0v2EKuZFcLB7QONR0ZZYJit11-cUwOudP-glgXfcaW0wEbK9R2UDU6R5eDFPP2ZCyEfj6BfBnbFjz1sVtrmHQXyM-lelqjNfyJo2W-iVKfZuVGgFkMvN5hb3FmGjenWMIAK8AAAABALWt99Y_lXPbU5jwgUgW6qTBllIQdB2FGjG6CI9jl_8RZbOHTJbL1UGSb_iHepG5pVbiau7ewTNmdG0v756JI1BednNpvOhbzlb4-xGbZRnUx8uWuw25z5eWmkh0bkEcPx3M80z90DD2G0T2LF-8beZD6eTOwWDty_vhvvFwev6rzGstNkY7vOrl_NZX6aX572lsGCfRWDlFrxnLQau43FMF3_eLduybHjtwWyMr4IrsZnyxUoS_kXwAFid2IyZkQbjJqjzCb8ZR08hR-QgArwAAAAEA3CsEtdmqxr685mQVnrA3n_o3FZHqECney2BIIc5Yt0nb9YGxlPhZWBwY95XNIXrO9V2eR3mHhF5DRDity4B4ZpjkA7pb5DleovmKXV_T9FalADloU1-L4py1blGyy3_xlRDiD0aea-MWICSLo8dWaSw25tWUogi8Im2D1dQjrYVARaTv1Dy9V8zfR1cQ3Yq81t6HKUQPTYcw9Te_O06cmFb2liwLAfLgCj7LspTtAmzRZsEMvIp8KS91QvfEn-CjH6uhdwfzSGzxzcyPCACvAAAAAQAV0G8kCtwtxwzQWhDwrycIorKSUfVWeFKFD2JMf74RsGmArGSVmKuZ1wpeMP9tB3mx23Xs4aqBfYsTfHhZ_uTrO9mtqDEoEZ0c4KzO5kUCYcki1-NV63CZfzWs5fb9wzgzDaJC_DVgfYG23HRvYVedoLJ9NnVbpIZI8eqWY94_g17di7UnG9OjQ_jHfpgcRhpMY8RRIffVn24nOlQZXGIihnywAjTCNnmYDs0KrbANoKMiZ8rhopQtbP30H1puz7MNFDUzRUiLQh3CglYIADgAAAEBAHo1g1azsIRcluE2yJ5tkjPfA3zWnNdbV4b2Q8AO7fW0cYTJFsK2wWnvYAfa3Rc9UIio16Ls',
            '6. Block1 repeated':
               'Ta3XqzSSntJoSTE2Ru10N_ot-V8mlwPqWnT9APiNky4IAHMAAAABAKlcxHh4Bwsd1ORWi20jL-hyNBOd5K5aEl9ITw_gyBAAABSKelh_NJBNkl0qTUZgUggKyy_UySBiRO1eIZ0gW6A1q0HOnj5EeH5m0XTASebpCIY2ZGHL8J523j-vlARIlwxSK5nsWojei6xbrH4kiQngb2UkUCjR0AaiKAN3oRhXzZYBhEOszYUb0v-XXgvErQgAMQAAAAEAUHycvyyQVxLjTvmceTj7QVwuAxrjS9rqUdyu0ULQgMOAUIFE3pmk0G5s3CNL_OBvZSRQKNHQBqIoA3ehGFfNlgGEQ6zNhRvS_5deC8StCAAxAAAAAQBQfJy_LJBXEuNO-Zx5OPtBXC4DGuNL2upR3K7RQtCAw4BQgUTemaTQbmzcI0v8Z1tHosyBA07iEFQX7TNwJeJFC43Hl7Fbsz8EK_VTGxwIAEMAAAABAIdHNZA-FNbNzvi9uNw5MKlb413td7Mj4T7WivYeKL7LcW4I6PXZNJq4uqj8OCBBPw1ZLjzEhloo86IKbX-uXD80X1Fa1b2oQQyo0dXBjBS1TImP6PbJ3nWOpFlZgvOgfAgAZwAAAAEA94eayfXDp2NxyLVkhEVWZp7Sp2pHnqo-vqwq7EZlLmirTJr6dL9hCrmRXCwe0DjUdGWWCYrddfnFMDrnT_oJYF33GltMBGyvUdlA1OkeXgxTz9mQshH4-gXwZ2xY89bFba5h0F8jPpXpaozX8iaNlvolSn2blRoBZDLzeYW9xZho3p1jCACvAAAAAQC1rffWP5Vz21OY8IFIFuqkwZZSEHQdhRoxugiPY5f_EWWzh0yWy9VBkm_4h3qRuaVW4mru3sEzZnRtL--eiSNQXnZzabzoW85W-PsRm2UZ1MfLlrsNuc-XlppIdG5BHD8dzPNM_dAw9htE9ixfvG3mQ-nkzsFg7cv74b7xcHr-q8xrLTZGO7zq5fzWV-ml-e9pbBgn0Vg5Ra8Zy0GruNxTBd_3i3bsmx47cFsjK-CK7GZ8sVKEv5F8ABYndiMmZEG4yao8wm_GUdPIUfkIAK8AAAABANwrBLXZqsa-vOZkFZ6wN5_6NxWR6hAp3stgSCHOWLdJ2_WBsZT4WVgcGPeVzSF6zvVdnkd5h4ReQ0Q4rcuAeGaY5AO6W-Q5XqL5il1f0_RWpQA5aFNfi-KctW5Rsst_8ZUQ4g9GnmvjFiAki6PHVmksNubVlKIIvCJtg9XUI62FQEWk79Q8vVfM30dXEN2KvNbehylED02HMPU3vztOnJhW9pYsCwHy4Ao-y7KU7QJs0WbBDLyKfCkvdUL3xJ_gox-roXcH80hs8c3MjwgArwAAAAEAFdBvJArcLccM0FoQ8K8nCKKyklH1VnhShQ9iTH--EbBpgKxklZirmdcKXjD_bQd5sdt17OGqgX2LE3x4Wf7k6zvZragxKBGdHOCszuZFAmHJItfjVetwmX81rOX2_cM4Mw2iQvw1YH2Bttx0b2FXnaCyfTZ1W6SGSPHqlmPeP4Ne3Yu1JxvTo0P4x36YHEYaTGPEUSH31Z9uJzpUGVxiIoZ8sAI0wjZ5mA7NCq2wDaCjImfK4aKULWz99B9abs-zDRQ1M0VIi0IdwoJWCAA4AAABAQB6NYNWs7CEXJbhNsiebZIz3wN81pzXW1eG9kPADu31tHGEyRbCtsFp72AH2t0XPVCIqNei7A',
            '7. Block1 deleted':
               'Ta3XqzSSntJoSTE2Ru10N_ot-V8mlwPqWnT9APiNky4IAHMAAAABAKlcxHh4Bwsd1ORWi20jL-hyNBOd5K5aEl9ITw_gyBAAABSKelh_NJBNkl0qTUZgUggKyy_UySBiRO1eIZ0gW6A1q0HOnj5EeH5m0XTASebpCIY2ZGHL8J523j-vlARIlwxSK5nsWojei6xbrH4kiQlnW0eizIEDTuIQVBftM3Al4kULjceXsVuzPwQr9VMbHAgAQwAAAAEAh0c1kD4U1s3O-L243DkwqVvjXe13syPhPtaK9h4ovstxbgjo9dk0mri6qPw4IEE_DVkuPMSGWijzogptf65cPzRfUVrVvahBDKjR1cGMFLVMiY_o9snedY6kWVmC86B8CABnAAAAAQD3h5rJ9cOnY3HItWSERVZmntKnakeeqj6-rCrsRmUuaKtMmvp0v2EKuZFcLB7QONR0ZZYJit11-cUwOudP-glgXfcaW0wEbK9R2UDU6R5eDFPP2ZCyEfj6BfBnbFjz1sVtrmHQXyM-lelqjNfyJo2W-iVKfZuVGgFkMvN5hb3FmGjenWMIAK8AAAABALWt99Y_lXPbU5jwgUgW6qTBllIQdB2FGjG6CI9jl_8RZbOHTJbL1UGSb_iHepG5pVbiau7ewTNmdG0v756JI1BednNpvOhbzlb4-xGbZRnUx8uWuw25z5eWmkh0bkEcPx3M80z90DD2G0T2LF-8beZD6eTOwWDty_vhvvFwev6rzGstNkY7vOrl_NZX6aX572lsGCfRWDlFrxnLQau43FMF3_eLduybHjtwWyMr4IrsZnyxUoS_kXwAFid2IyZkQbjJqjzCb8ZR08hR-QgArwAAAAEA3CsEtdmqxr685mQVnrA3n_o3FZHqECney2BIIc5Yt0nb9YGxlPhZWBwY95XNIXrO9V2eR3mHhF5DRDity4B4ZpjkA7pb5DleovmKXV_T9FalADloU1-L4py1blGyy3_xlRDiD0aea-MWICSLo8dWaSw25tWUogi8Im2D1dQjrYVARaTv1Dy9V8zfR1cQ3Yq81t6HKUQPTYcw9Te_O06cmFb2liwLAfLgCj7LspTtAmzRZsEMvIp8KS91QvfEn-CjH6uhdwfzSGzxzcyPCACvAAAAAQAV0G8kCtwtxwzQWhDwrycIorKSUfVWeFKFD2JMf74RsGmArGSVmKuZ1wpeMP9tB3mx23Xs4aqBfYsTfHhZ_uTrO9mtqDEoEZ0c4KzO5kUCYcki1-NV63CZfzWs5fb9wzgzDaJC_DVgfYG23HRvYVedoLJ9NnVbpIZI8eqWY94_g17di7UnG9OjQ_jHfpgcRhpMY8RRIffVn24nOlQZXGIihnywAjTCNnmYDs0KrbANoKMiZ8rhopQtbP30H1puz7MNFDUzRUiLQh3CglYIADgAAAEBAHo1g1azsIRcluE2yJ5tkjPfA3zWnNdbV4b2Q8AO7fW0cYTJFsK2wWnvYAfa3Rc9UIio16Ls',
            '8. Block2 repeated':
               'Ta3XqzSSntJoSTE2Ru10N_ot-V8mlwPqWnT9APiNky4IAHMAAAABAKlcxHh4Bwsd1ORWi20jL-hyNBOd5K5aEl9ITw_gyBAAABSKelh_NJBNkl0qTUZgUggKyy_UySBiRO1eIZ0gW6A1q0HOnj5EeH5m0XTASebpCIY2ZGHL8J523j-vlARIlwxSK5nsWojei6xbrH4kiQngb2UkUCjR0AaiKAN3oRhXzZYBhEOszYUb0v-XXgvErQgAMQAAAAEAUHycvyyQVxLjTvmceTj7QVwuAxrjS9rqUdyu0ULQgMOAUIFE3pmk0G5s3CNL_GdbR6LMgQNO4hBUF-0zcCXiRQuNx5exW7M_BCv1UxscCABDAAAAAQCHRzWQPhTWzc74vbjcOTCpW-Nd7XezI-E-1or2Hii-y3FuCOj12TSauLqo_DggQT8NWS48xIZaKPOiCm1_rlw_Z1tHosyBA07iEFQX7TNwJeJFC43Hl7Fbsz8EK_VTGxwIAEMAAAABAIdHNZA-FNbNzvi9uNw5MKlb413td7Mj4T7WivYeKL7LcW4I6PXZNJq4uqj8OCBBPw1ZLjzEhloo86IKbX-uXD80X1Fa1b2oQQyo0dXBjBS1TImP6PbJ3nWOpFlZgvOgfAgAZwAAAAEA94eayfXDp2NxyLVkhEVWZp7Sp2pHnqo-vqwq7EZlLmirTJr6dL9hCrmRXCwe0DjUdGWWCYrddfnFMDrnT_oJYF33GltMBGyvUdlA1OkeXgxTz9mQshH4-gXwZ2xY89bFba5h0F8jPpXpaozX8iaNlvolSn2blRoBZDLzeYW9xZho3p1jCACvAAAAAQC1rffWP5Vz21OY8IFIFuqkwZZSEHQdhRoxugiPY5f_EWWzh0yWy9VBkm_4h3qRuaVW4mru3sEzZnRtL--eiSNQXnZzabzoW85W-PsRm2UZ1MfLlrsNuc-XlppIdG5BHD8dzPNM_dAw9htE9ixfvG3mQ-nkzsFg7cv74b7xcHr-q8xrLTZGO7zq5fzWV-ml-e9pbBgn0Vg5Ra8Zy0GruNxTBd_3i3bsmx47cFsjK-CK7GZ8sVKEv5F8ABYndiMmZEG4yao8wm_GUdPIUfkIAK8AAAABANwrBLXZqsa-vOZkFZ6wN5_6NxWR6hAp3stgSCHOWLdJ2_WBsZT4WVgcGPeVzSF6zvVdnkd5h4ReQ0Q4rcuAeGaY5AO6W-Q5XqL5il1f0_RWpQA5aFNfi-KctW5Rsst_8ZUQ4g9GnmvjFiAki6PHVmksNubVlKIIvCJtg9XUI62FQEWk79Q8vVfM30dXEN2KvNbehylED02HMPU3vztOnJhW9pYsCwHy4Ao-y7KU7QJs0WbBDLyKfCkvdUL3xJ_gox-roXcH80hs8c3MjwgArwAAAAEAFdBvJArcLccM0FoQ8K8nCKKyklH1VnhShQ9iTH--EbBpgKxklZirmdcKXjD_bQd5sdt17OGqgX2LE3x4Wf7k6zvZragxKBGdHOCszuZFAmHJItfjVetwmX81rOX2_cM4Mw2iQvw1YH2Bttx0b2FXnaCyfTZ1W6SGSPHqlmPeP4Ne3Yu1JxvTo0P4x36YHEYaTGPEUSH31Z9uJzpUGVxiIoZ8sAI0wjZ5mA7NCq2wDaCjImfK4aKULWz99B9abs-zDRQ1M0VIi0IdwoJWCAA4AAABAQB6NYNWs7CEXJbhNsiebZIz3wN81pzXW1eG9kPADu31tHGEyRbCtsFp72AH2t0XPVCIqNei7A',
            '9. Block2 deleted':
               'Ta3XqzSSntJoSTE2Ru10N_ot-V8mlwPqWnT9APiNky4IAHMAAAABAKlcxHh4Bwsd1ORWi20jL-hyNBOd5K5aEl9ITw_gyBAAABSKelh_NJBNkl0qTUZgUggKyy_UySBiRO1eIZ0gW6A1q0HOnj5EeH5m0XTASebpCIY2ZGHL8J523j-vlARIlwxSK5nsWojei6xbrH4kiQngb2UkUCjR0AaiKAN3oRhXzZYBhEOszYUb0v-XXgvErQgAMQAAAAEAUHycvyyQVxLjTvmceTj7QVwuAxrjS9rqUdyu0ULQgMOAUIFE3pmk0G5s3CNL_DRfUVrVvahBDKjR1cGMFLVMiY_o9snedY6kWVmC86B8CABnAAAAAQD3h5rJ9cOnY3HItWSERVZmntKnakeeqj6-rCrsRmUuaKtMmvp0v2EKuZFcLB7QONR0ZZYJit11-cUwOudP-glgXfcaW0wEbK9R2UDU6R5eDFPP2ZCyEfj6BfBnbFjz1sVtrmHQXyM-lelqjNfyJo2W-iVKfZuVGgFkMvN5hb3FmGjenWMIAK8AAAABALWt99Y_lXPbU5jwgUgW6qTBllIQdB2FGjG6CI9jl_8RZbOHTJbL1UGSb_iHepG5pVbiau7ewTNmdG0v756JI1BednNpvOhbzlb4-xGbZRnUx8uWuw25z5eWmkh0bkEcPx3M80z90DD2G0T2LF-8beZD6eTOwWDty_vhvvFwev6rzGstNkY7vOrl_NZX6aX572lsGCfRWDlFrxnLQau43FMF3_eLduybHjtwWyMr4IrsZnyxUoS_kXwAFid2IyZkQbjJqjzCb8ZR08hR-QgArwAAAAEA3CsEtdmqxr685mQVnrA3n_o3FZHqECney2BIIc5Yt0nb9YGxlPhZWBwY95XNIXrO9V2eR3mHhF5DRDity4B4ZpjkA7pb5DleovmKXV_T9FalADloU1-L4py1blGyy3_xlRDiD0aea-MWICSLo8dWaSw25tWUogi8Im2D1dQjrYVARaTv1Dy9V8zfR1cQ3Yq81t6HKUQPTYcw9Te_O06cmFb2liwLAfLgCj7LspTtAmzRZsEMvIp8KS91QvfEn-CjH6uhdwfzSGzxzcyPCACvAAAAAQAV0G8kCtwtxwzQWhDwrycIorKSUfVWeFKFD2JMf74RsGmArGSVmKuZ1wpeMP9tB3mx23Xs4aqBfYsTfHhZ_uTrO9mtqDEoEZ0c4KzO5kUCYcki1-NV63CZfzWs5fb9wzgzDaJC_DVgfYG23HRvYVedoLJ9NnVbpIZI8eqWY94_g17di7UnG9OjQ_jHfpgcRhpMY8RRIffVn24nOlQZXGIihnywAjTCNnmYDs0KrbANoKMiZ8rhopQtbP30H1puz7MNFDUzRUiLQh3CglYIADgAAAEBAHo1g1azsIRcluE2yJ5tkjPfA3zWnNdbV4b2Q8AO7fW0cYTJFsK2wWnvYAfa3Rc9UIio16Ls',
            '10. Block7 (last) repeated':
               'Ta3XqzSSntJoSTE2Ru10N_ot-V8mlwPqWnT9APiNky4IAHMAAAABAKlcxHh4Bwsd1ORWi20jL-hyNBOd5K5aEl9ITw_gyBAAABSKelh_NJBNkl0qTUZgUggKyy_UySBiRO1eIZ0gW6A1q0HOnj5EeH5m0XTASebpCIY2ZGHL8J523j-vlARIlwxSK5nsWojei6xbrH4kiQngb2UkUCjR0AaiKAN3oRhXzZYBhEOszYUb0v-XXgvErQgAMQAAAAEAUHycvyyQVxLjTvmceTj7QVwuAxrjS9rqUdyu0ULQgMOAUIFE3pmk0G5s3CNL_GdbR6LMgQNO4hBUF-0zcCXiRQuNx5exW7M_BCv1UxscCABDAAAAAQCHRzWQPhTWzc74vbjcOTCpW-Nd7XezI-E-1or2Hii-y3FuCOj12TSauLqo_DggQT8NWS48xIZaKPOiCm1_rlw_NF9RWtW9qEEMqNHVwYwUtUyJj-j2yd51jqRZWYLzoHwIAGcAAAABAPeHmsn1w6djcci1ZIRFVmae0qdqR56qPr6sKuxGZS5oq0ya-nS_YQq5kVwsHtA41HRllgmK3XX5xTA650_6CWBd9xpbTARsr1HZQNTpHl4MU8_ZkLIR-PoF8GdsWPPWxW2uYdBfIz6V6WqM1_ImjZb6JUp9m5UaAWQy83mFvcWYaN6dYwgArwAAAAEAta331j-Vc9tTmPCBSBbqpMGWUhB0HYUaMboIj2OX_xFls4dMlsvVQZJv-Id6kbmlVuJq7t7BM2Z0bS_vnokjUF52c2m86FvOVvj7EZtlGdTHy5a7DbnPl5aaSHRuQRw_HczzTP3QMPYbRPYsX7xt5kPp5M7BYO3L--G-8XB6_qvMay02Rju86uX81lfppfnvaWwYJ9FYOUWvGctBq7jcUwXf94t27JseO3BbIyvgiuxmfLFShL-RfAAWJ3YjJmRBuMmqPMJvxlHTyFH5CACvAAAAAQDcKwS12arGvrzmZBWesDef-jcVkeoQKd7LYEghzli3Sdv1gbGU-FlYHBj3lc0hes71XZ5HeYeEXkNEOK3LgHhmmOQDulvkOV6i-YpdX9P0VqUAOWhTX4vinLVuUbLLf_GVEOIPRp5r4xYgJIujx1ZpLDbm1ZSiCLwibYPV1COthUBFpO_UPL1XzN9HVxDdirzW3ocpRA9NhzD1N787TpyYVvaWLAsB8uAKPsuylO0CbNFmwQy8inwpL3VC98Sf4KMfq6F3B_NIbPHNzI8IAK8AAAABABXQbyQK3C3HDNBaEPCvJwiispJR9VZ4UoUPYkx_vhGwaYCsZJWYq5nXCl4w_20HebHbdezhqoF9ixN8eFn-5Os72a2oMSgRnRzgrM7mRQJhySLX41XrcJl_Nazl9v3DODMNokL8NWB9gbbcdG9hV52gsn02dVukhkjx6pZj3j-DXt2LtScb06ND-Md-mBxGGkxjxFEh99Wfbic6VBlcYiKGfLACNMI2eZgOzQqtsA2goyJnyuGilC1s_fQfWm7Psw0UNTNFSItCHcKCVggAOAAAAQEAejWDVrOwhFyW4TbInm2SM98DfNac11tXhvZDwA7t9bRxhMkWwrbBae9gB9rdFz1QiKjXouytsA2goyJnyuGilC1s_fQfWm7Psw0UNTNFSItCHcKCVggAOAAAAQEAejWDVrOwhFyW4TbInm2SM98DfNac11tXhvZDwA7t9bRxhMkWwrbBae9gB9rdFz1QiKjXouw',
            '11. Block7 (last) deleted':
               'Ta3XqzSSntJoSTE2Ru10N_ot-V8mlwPqWnT9APiNky4IAHMAAAABAKlcxHh4Bwsd1ORWi20jL-hyNBOd5K5aEl9ITw_gyBAAABSKelh_NJBNkl0qTUZgUggKyy_UySBiRO1eIZ0gW6A1q0HOnj5EeH5m0XTASebpCIY2ZGHL8J523j-vlARIlwxSK5nsWojei6xbrH4kiQngb2UkUCjR0AaiKAN3oRhXzZYBhEOszYUb0v-XXgvErQgAMQAAAAEAUHycvyyQVxLjTvmceTj7QVwuAxrjS9rqUdyu0ULQgMOAUIFE3pmk0G5s3CNL_GdbR6LMgQNO4hBUF-0zcCXiRQuNx5exW7M_BCv1UxscCABDAAAAAQCHRzWQPhTWzc74vbjcOTCpW-Nd7XezI-E-1or2Hii-y3FuCOj12TSauLqo_DggQT8NWS48xIZaKPOiCm1_rlw_NF9RWtW9qEEMqNHVwYwUtUyJj-j2yd51jqRZWYLzoHwIAGcAAAABAPeHmsn1w6djcci1ZIRFVmae0qdqR56qPr6sKuxGZS5oq0ya-nS_YQq5kVwsHtA41HRllgmK3XX5xTA650_6CWBd9xpbTARsr1HZQNTpHl4MU8_ZkLIR-PoF8GdsWPPWxW2uYdBfIz6V6WqM1_ImjZb6JUp9m5UaAWQy83mFvcWYaN6dYwgArwAAAAEAta331j-Vc9tTmPCBSBbqpMGWUhB0HYUaMboIj2OX_xFls4dMlsvVQZJv-Id6kbmlVuJq7t7BM2Z0bS_vnokjUF52c2m86FvOVvj7EZtlGdTHy5a7DbnPl5aaSHRuQRw_HczzTP3QMPYbRPYsX7xt5kPp5M7BYO3L--G-8XB6_qvMay02Rju86uX81lfppfnvaWwYJ9FYOUWvGctBq7jcUwXf94t27JseO3BbIyvgiuxmfLFShL-RfAAWJ3YjJmRBuMmqPMJvxlHTyFH5CACvAAAAAQDcKwS12arGvrzmZBWesDef-jcVkeoQKd7LYEghzli3Sdv1gbGU-FlYHBj3lc0hes71XZ5HeYeEXkNEOK3LgHhmmOQDulvkOV6i-YpdX9P0VqUAOWhTX4vinLVuUbLLf_GVEOIPRp5r4xYgJIujx1ZpLDbm1ZSiCLwibYPV1COthUBFpO_UPL1XzN9HVxDdirzW3ocpRA9NhzD1N787TpyYVvaWLAsB8uAKPsuylO0CbNFmwQy8inwpL3VC98Sf4KMfq6F3B_NIbPHNzI8IAK8AAAABABXQbyQK3C3HDNBaEPCvJwiispJR9VZ4UoUPYkx_vhGwaYCsZJWYq5nXCl4w_20HebHbdezhqoF9ixN8eFn-5Os72a2oMSgRnRzgrM7mRQJhySLX41XrcJl_Nazl9v3DODMNokL8NWB9gbbcdG9hV52gsn02dVukhkjx6pZj3j-DXt2LtScb06ND-Md-mBxGGkxjxFEh99Wfbic6VBlcYiKGfLACNMI2eZgOzQo',
            '12. Block1 Block7 deleted':
               'Ta3XqzSSntJoSTE2Ru10N_ot-V8mlwPqWnT9APiNky4IAHMAAAABAKlcxHh4Bwsd1ORWi20jL-hyNBOd5K5aEl9ITw_gyBAAABSKelh_NJBNkl0qTUZgUggKyy_UySBiRO1eIZ0gW6A1q0HOnj5EeH5m0XTASebpCIY2ZGHL8J523j-vlARIlwxSK5nsWojei6xbrH4kiQlnW0eizIEDTuIQVBftM3Al4kULjceXsVuzPwQr9VMbHAgAQwAAAAEAh0c1kD4U1s3O-L243DkwqVvjXe13syPhPtaK9h4ovstxbgjo9dk0mri6qPw4IEE_DVkuPMSGWijzogptf65cPzRfUVrVvahBDKjR1cGMFLVMiY_o9snedY6kWVmC86B8CABnAAAAAQD3h5rJ9cOnY3HItWSERVZmntKnakeeqj6-rCrsRmUuaKtMmvp0v2EKuZFcLB7QONR0ZZYJit11-cUwOudP-glgXfcaW0wEbK9R2UDU6R5eDFPP2ZCyEfj6BfBnbFjz1sVtrmHQXyM-lelqjNfyJo2W-iVKfZuVGgFkMvN5hb3FmGjenWMIAK8AAAABALWt99Y_lXPbU5jwgUgW6qTBllIQdB2FGjG6CI9jl_8RZbOHTJbL1UGSb_iHepG5pVbiau7ewTNmdG0v756JI1BednNpvOhbzlb4-xGbZRnUx8uWuw25z5eWmkh0bkEcPx3M80z90DD2G0T2LF-8beZD6eTOwWDty_vhvvFwev6rzGstNkY7vOrl_NZX6aX572lsGCfRWDlFrxnLQau43FMF3_eLduybHjtwWyMr4IrsZnyxUoS_kXwAFid2IyZkQbjJqjzCb8ZR08hR-QgArwAAAAEA3CsEtdmqxr685mQVnrA3n_o3FZHqECney2BIIc5Yt0nb9YGxlPhZWBwY95XNIXrO9V2eR3mHhF5DRDity4B4ZpjkA7pb5DleovmKXV_T9FalADloU1-L4py1blGyy3_xlRDiD0aea-MWICSLo8dWaSw25tWUogi8Im2D1dQjrYVARaTv1Dy9V8zfR1cQ3Yq81t6HKUQPTYcw9Te_O06cmFb2liwLAfLgCj7LspTtAmzRZsEMvIp8KS91QvfEn-CjH6uhdwfzSGzxzcyPCACvAAAAAQAV0G8kCtwtxwzQWhDwrycIorKSUfVWeFKFD2JMf74RsGmArGSVmKuZ1wpeMP9tB3mx23Xs4aqBfYsTfHhZ_uTrO9mtqDEoEZ0c4KzO5kUCYcki1-NV63CZfzWs5fb9wzgzDaJC_DVgfYG23HRvYVedoLJ9NnVbpIZI8eqWY94_g17di7UnG9OjQ_jHfpgcRhpMY8RRIffVn24nOlQZXGIihnywAjTCNnmYDs0K',
            '13. All Term':
               'PyJXJATmMVX82T3nQBlPDmL9YwwytO7ftQBWKZAeobcIAHMAAAEBAAUP63dxfnL4m1RarDIyq9bJfdjQyZTZZhwYJMzgyBAAABQ5atP2TU6Pe87sfli28K0RQnBRwSBzULIw60aDaX5YAes0TyFC4tQwAPR786hOUExkq8aJbf685w8txKOvZ4HnD0gvAwpNO_gavBJcQSt3T_RSLLyQywLDWmWt4G80bOqMEiuYl8OJu9uIjq5HDAgAMQAAAQEATGv5gafd2xbrofgWl6c7Is-Jk3sxDOa-mNdFxA9M8dN9IXWD1UP5Md5LrQicAppizAbfa9OqVVx7senax2JudWHYxaA0nDpucY4fUVRkCABDAAABAQAuIUAGC_B9ln0ACCHFjLj2jfopmBbIexqVRf9uLEEAwRwoIqh26WM5UtmVwgy-2vqWXGRLvZicrh-tfGPeY-pCkMixkY3qBVJSKk_PUMcoXci2fyPcTH-MVRBxLtcrkbkIAGcAAAEBAIcGt0RIryBtzeDcm2VLly_Zt6v4z0CbtFfyQd32kEE1yCfFoN-vh93GdNQRaGhBN9XfBopMh83hu_nPytUn1LkFmHg61_4QXbzZf77H1B40zjyetg9ArOYMhwVCW1n4PVP7AYwgBkqZ7PFr-qgi6e6VIU6_X6L0KObdNUYupPBy5PhkOAgArwAAAQEA0_LgxhKQtp3JbwTQuKesBDVdjwEvgFXjy_rb52kK0azr4UOrsilm1ZvArlukppo1jrq1U1ME0LZNnh-K6y_CcYAQ_n8Zzqu9ceaA-14O49ODNKzJA3jJEGaUHgcHvJD1YMckXuKz6k-Bc_RGO48rKwS7Rn81aUODXWTtmKjjiuEX2R-or5iwbuSdO_sdpGn8Hl6spuuc3MutDVmNrQHbR-PCK_zwDKZ0lUMYQy0HZLGUSlr3jiOqXC9Ux5hW-LivycjUNfr3zCIBtr0wCACvAAABAQAxpUCWSd4vj7sB4aFTbZjHkeZzV0nFgv7X8vvr9HqitIGYSRJ32jDQ5MRUbT6MzVBv7fYjpVVmzWUpMaiN7m7VCp0M7cb1YbOOdFgz42yGEPuLxei-gDJgWS5aBw-bfTScyYl8gcIoRBW-xxyYldSFA3H4pn1eE_C5e17kD208QqVP7VkB_kPK3EpN4yWU5-y4FYMxPTCtzBqDVV_paLKFFCpQz5InEFvGpoA3-fbroBSQUNhK0vB1P9iXvG7qSCxqE39C4eBm8_X-LuQIAK8AAAEBAPZnpZ4K9Mdux0ULr-f3KyX9OIJ8k5jCmvYaDkLVLs1jaJO9oMIUD5VDnJ4xXpf_CIJwhQM5giF1tVVXW30fKHMO9OQsZxPoGl8SGBL-tqYeC0KQ4Kiu8vbA1J93kCKsoVZtGVqxBXLV2JeS4_tpZbyHOqAOjzbo7pgtZnHvKBPOS9TyPkdg1P3FHY5mItZ8g8p67qJuB7GJjuL-7623z3bSlrqSyjVCpMcDWG6QGvVftKUAsJ0QWDr--q4hJlfHAhYF4IXOCbN7PvpF3AgAOAAAAQEAHLXEWIKPlWs6q10elK7Q6aKEZRCpmjGLQxFAoRLLVmGWEeTD8hVcO5cDWrMp26QrZ3tQCa4',
            '14. No Term':
               'KY6WmcUBkWYcUBQJ_r0m2YM0J1K-0rN598ZlpU4LefwIAHMAAAABABfxTyYCeGPV_vo8roQc-WhfsNC42bgS1OUpDS7gyBAAABQAPI4hSh6b12MmA7FVLYT_hOXLUSBoRlKQrFHKLkh8oRQPMVMgCo-4Z4G84xknLPqpTuoOUyBv121mryPAvZVHbkKjB7P1an68pcG-oIkOp3GjqCedbD3B4PxUmUWwcjOhW3z4yHBhIqMyGQyK9AgAMQAAAAEAe3keg7sECm9jYVEyG49w5fiYnyGVKXhrCOCtbb3ALUt5U0i4dCkINiH6HeuKY8GZbyMSFHRwATa2ZkOC3VDVm5GY1bcKMaV1jOD2wgm3CABDAAAAAQD47iVFSgx6hoxeul_wRotapjdG8JDW1WvQfOG0oHl-m_aahMNtjp8I0JrpYOEBSpq0aofiBy87kQFOuctUnyomi4fYWSoGRq7asKfXpft4l80b_I9nPanR23rG0w_RumMIAGcAAAABAIWFQU4hEnaBJHTFqnKwDhUyUqep02fioBcr1Pc8C1LtDDWmlvdO7ji-vyRQSQP6sBw-V7WfN4pAcurcHmdWm0pZu-ZoLIQgHl1zSxpYR0diaKnNu16XklQp2jHaUNw_yhTP8Nnj_-q5iCmrdMlD6ZAMJELLazFEb15m53PVhT4CC6256QgArwAAAAEAxrKX6jZpJeP6VWjgjdbwRyB6ckuKgg58VBF--prrSRrpPlU5Ya8WFLQzl3LF23ss_EX6Hu2je7BbgkijD4DjHoSh3pmnZJTQwXL8lUFErjtq6ah6hi88bmjitQR9mwlr6EhT4D-ztojB_17zvzCbn_KM-tr4I4q31aEb2-zv-mlEzYsFxi_MUW4LDgN5C6HijopKUjI-i7YUAl2C9HZz3T25NcpR1nN_5181B1_W-PG5ym6KWLuTy7Ds32f9utJotCwxKYD9-cdLDnTWCACvAAAAAQA1vPt81dpOw6pCrvKOjTFE7B7-pGQx0uOL1Aems9Leh34WuRp_w0TFSQB_V501cOXTcPmMrfJE6fKlf8ygN6BngMIVbeeKai3s2k3uClP96ZRvgrjhM9zqrjbMhNz5kXA1T45BMC0jC3XXbtOG8FVTEColSVE61SDOqbpHmiFqO88xLhaMEIIS3BPokJEm0VENsOv6X5y9Pk35ah2uH9GnQnOWBA67qqLsexUzF0k7d0GNl9HOmPs6qXw1QLZzdKoYfn8gWq6Jf376FqkIAK8AAAABAGMazPNuhjG6Ltn2LsntkXZkdin8J6ITvRDEud3Lb8qFuEyh05imFHFHoDmH6Pw0w5_2KNe9XAGORsv-5_ZFnanbwsO7NM2zcl-nMVdCOL-cTuWxd_gB1Pq7MUz7zlb1jYAimGgy_Ssg_0jgF0NMIr8f5Ibd-LHDcbvFAWmKq-3cwRZjjm1C3JL96PC7BIdYTqtNKnyQm_vD8c7wIHMbmcznPdWGe3c_hcmwAgjJw_NuYLYylNoJ7BrFE6qWyQsJMZcYxWCrfG0GhnFKPQgAOAAAAAEATlJPKsxzH7J5H1n7KqjfMTQdQmWRa43yrOgh4Tjxm5t3ogNFAaZ0dCSpERxF2R5OMnFHNzc',
         },
      },
   ];

   const clearData = new Uint8Array([
      118, 101, 114, 115, 105, 111, 110, 58, 32, 34, 51, 46, 56, 34, 10, 115, 101, 114, 118, 105, 99, 101, 115, 58, 10,
      32, 32, 100, 111, 99, 107, 103, 101, 58, 10, 32, 32, 32, 32, 105, 109, 97, 103, 101, 58, 32, 108, 111, 117, 105,
      115, 108, 97, 109, 47, 100, 111, 99, 107, 103, 101, 58, 49, 10, 32, 32, 32, 32, 114, 101, 115, 116, 97, 114, 116,
      58, 32, 117, 110, 108, 101, 115, 115, 45, 115, 116, 111, 112, 112, 101, 100, 10, 32, 32, 32, 32, 112, 111, 114,
      116, 115, 58, 10, 32, 32, 32, 32, 32, 32, 45, 32, 53, 48, 48, 49, 58, 53, 48, 48, 49, 10, 32, 32, 32, 32, 118,
      111, 108, 117, 109, 101, 115, 58, 10, 32, 32, 32, 32, 32, 32, 45, 32, 47, 118, 97, 114, 47, 114, 117, 110, 47,
      100, 111, 99, 107, 101, 114, 46, 115, 111, 99, 107, 58, 47, 118, 97, 114, 47, 114, 117, 110, 47, 100, 111, 99,
      107, 101, 114, 46, 115, 111, 99, 107, 10, 32, 32, 32, 32, 32, 32, 45, 32, 46, 47, 100, 97, 116, 97, 58, 47, 97,
      112, 112, 47, 100, 97, 116, 97, 10, 32, 32, 32, 32, 32, 32, 35, 32, 83, 116, 97, 99, 107, 115, 32, 68, 105, 114,
      101, 99, 116, 111, 114, 121, 10, 32, 32, 32, 32, 32, 32, 35, 32, 226, 154, 160, 239, 184, 143, 32, 82, 69, 65, 68,
      32, 73, 84, 32, 67, 65, 82, 69, 70, 85, 76, 76, 89, 46, 32, 73, 102, 32, 121, 111, 117, 32, 100, 105, 100, 32,
      105, 116, 32, 119, 114, 111, 110, 103, 44, 32, 121, 111, 117, 114, 32, 100, 97, 116, 97, 32, 99, 111, 117, 108,
      100, 32, 101, 110, 100, 32, 117, 112, 32, 119, 114, 105, 116, 105, 110, 103, 32, 105, 110, 116, 111, 32, 97, 32,
      87, 82, 79, 78, 71, 32, 80, 65, 84, 72, 46, 10, 32, 32, 32, 32, 32, 32, 35, 32, 226, 154, 160, 239, 184, 143, 32,
      49, 46, 32, 70, 85, 76, 76, 32, 112, 97, 116, 104, 32, 111, 110, 108, 121, 46, 32, 78, 111, 32, 114, 101, 108, 97,
      116, 105, 118, 101, 32, 112, 97, 116, 104, 32, 40, 77, 85, 83, 84, 41, 10, 32, 32, 32, 32, 32, 32, 35, 32, 226,
      154, 160, 239, 184, 143, 32, 50, 46, 32, 76, 101, 102, 116, 32, 83, 116, 97, 99, 107, 115, 32, 80, 97, 116, 104,
      32, 61, 61, 61, 32, 82, 105, 103, 104, 116, 32, 83, 116, 97, 99, 107, 115, 32, 80, 97, 116, 104, 32, 40, 77, 85,
      83, 84, 41, 10, 32, 32, 32, 32, 32, 32, 45, 32, 47, 111, 112, 116, 47, 115, 116, 97, 99, 107, 115, 58, 47, 111,
      112, 116, 47, 115, 116, 97, 99, 107, 115, 10, 32, 32, 32, 32, 101, 110, 118, 105, 114, 111, 110, 109, 101, 110,
      116, 58, 10, 32, 32, 32, 32, 32, 32, 35, 32, 84, 101, 108, 108, 32, 68, 111, 99, 107, 103, 101, 32, 119, 104, 101,
      114, 101, 32, 116, 111, 32, 102, 105, 110, 100, 32, 116, 104, 101, 32, 115, 116, 97, 99, 107, 115, 10, 32, 32, 32,
      32, 32, 32, 45, 32, 68, 79, 67, 75, 71, 69, 95, 83, 84, 65, 67, 75, 83, 95, 68, 73, 82, 61, 47, 111, 112, 116, 47,
      115, 116, 97, 99, 107, 115,
   ]);

   it('good multi block ciphertext', async () => {
      for (const ver of vers) {
         // First make sure it decrypts as expected
         const [cipherStream] = streamFromBase64(ver.goodCt);
         const decKeyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
            expect(cdinfo.hint).toEqual('4321');
            expect(cdinfo.alg).toBe('AES-GCM');
            expect(cdinfo.ver).toBe(ver.ver);
            expect(cdinfo.lp).toBe(1);
            expect(cdinfo.lpEnd).toBe(1);
            expect(cdinfo.ic).toBe(1100000);
            expect(Boolean(cdinfo.hint)).toBe(true);
            return ['asdf', undefined];
         });
         let decDoneCount = 0;
         const dec = await cipherSvc.decryptStream(cipherStream, decKeyProvider, (doneVer, multiBlock) => {
            decDoneCount += 1;
            expect(doneVer).toBe(ver.ver);
            expect(multiBlock).toBe(true);
         });
         await expect(areEqual(dec, clearData)).resolves.toEqual(true);
         expect(decDoneCount).toBe(1);
      }
   });

   it('changed multi block ciphertext', async () => {
      for (const ver of vers) {
         for (const [_change, ct] of Object.entries(ver.badCts)) {
            const [cipherStream] = streamFromBase64(ct);
            const decKeyProvider = new PWDKeyProvider(userCred.slice(0), async (_cdinfo) => {
               return ['asdf', undefined];
            });
            await expect(
               cipherSvc.decryptStream(cipherStream, decKeyProvider).then((dec) => {
                  return areEqual(dec, clearData);
               }),
            ).rejects.toThrow(Error);
         }
      }
   });
});

describe('Benchmark execution', () => {
   let cipherSvc: CipherService;
   beforeEach(async () => {
      await cryptoReady();
      TestBed.configureTestingModule({});
      cipherSvc = TestBed.inject(CipherService);
   });

   it('reasonable benchmark results', async () => {
      const [icount, icountMax, hashRate] = await cipherSvc.benchmark(cc.ICOUNT_MIN);
      expect(icount).toBeGreaterThanOrEqual(cc.ICOUNT_DEFAULT);
      expect(icount).toBeLessThanOrEqual(cc.ICOUNT_MAX);
      expect(icountMax).toBeGreaterThanOrEqual(icount);
      expect(icountMax).toBeLessThanOrEqual(cc.ICOUNT_MAX);
      expect(hashRate).toBeGreaterThanOrEqual(1);
      expect(hashRate).toBeLessThanOrEqual(100000);
   });
});

describe('Cipher alg validate', () => {
   let _cipherSvc: CipherService;
   beforeEach(async () => {
      await cryptoReady();
      TestBed.configureTestingModule({});
      _cipherSvc = TestBed.inject(CipherService);
   });

   it('detect invalid alg', async () => {
      expect(Ciphers.isValidAlg('AES_GCM')).toBe(false);
      expect(Ciphers.isValidAlg('')).toBe(false);
      expect(Ciphers.isValidAlg('f2f33flin2o23f2j3f90j2')).toBe(false);
   });

   it('should be valid algs', async () => {
      expect(Ciphers.isValidAlg('AES-GCM')).toBe(true);
      expect(Ciphers.isValidAlg('X20-PLY')).toBe(true);
      expect(Ciphers.isValidAlg('AEGIS-256')).toBe(true);
   });
});

describe('Get cipherinfo from cipher text', () => {
   let cipherSvc: CipherService;
   beforeEach(async () => {
      await cryptoReady();
      TestBed.configureTestingModule({});
      cipherSvc = TestBed.inject(CipherService);
   });

   it('expected CipherInfo, all algorithms', async () => {
      for (const alg of Ciphers.algs()) {
         const srcString = 'This is a secret 🦋';
         const [clearStream, _clearData] = streamFromStr(srcString);

         const pwd = 'not good pwd';
         const hint = 'try a himt';
         const userCred = getRandom(cc.USERCRED_BYTES);

         const econtext: EContext = {
            algs: [alg],
            ic: cc.ICOUNT_MIN,
         };

         const encKeyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
            expect(cdinfo.alg).toEqual(alg);
            expect(cdinfo.ic).toEqual(cc.ICOUNT_MIN);
            return [pwd, hint];
         });
         const cipherStream = await cipherSvc.encryptStream(clearStream, encKeyProvider, econtext);

         const infoKeyProvider = new PWDKeyProvider(userCred.slice(0));
         const cipherInfo = await cipherSvc.getCipherStreamInfo(cipherStream, infoKeyProvider);
         expect(cipherInfo.ver).toEqual(cc.CURRENT_VERSION);
         expect(cipherInfo.alg).toEqual(alg);
         expect(cipherInfo.ic).toEqual(cc.ICOUNT_MIN);
         expect(cipherInfo.lp).toEqual(1);
         expect(cipherInfo.slt.byteLength).toEqual(cc.SLT_BYTES);
         expect(cipherInfo.hint).toEqual(hint);
      }
   });

   it('detect invalid userCred', async () => {
      const srcString = 'f';
      const [clearStream, _clearData] = streamFromStr(srcString);

      const pwd = 'another good pwd';
      const hint = 'nope';
      const userCred = getRandom(cc.USERCRED_BYTES);

      const econtext: EContext = {
         algs: ['AEGIS-256'],
         ic: cc.ICOUNT_MIN,
      };

      const encKeyProvider = new PWDKeyProvider(userCred.slice(0), async (_cdinfo) => {
         return [pwd, hint];
      });
      const cipherStream = await cipherSvc.encryptStream(clearStream, encKeyProvider, econtext);

      // Valid, but doesn't match orignal userCred
      let problemUserCred = getRandom(cc.USERCRED_BYTES);
      await expect(cipherSvc.getCipherStreamInfo(cipherStream, new PWDKeyProvider(problemUserCred))).rejects.toThrow(
         /.+MAC.+/,
      );

      // Missing one byte of userCred
      problemUserCred = userCred.slice(0, userCred.byteLength - 1);
      await expect(
         (async () => {
            return cipherSvc.getCipherStreamInfo(cipherStream, new PWDKeyProvider(problemUserCred));
         })(),
      ).rejects.toThrow(/Invalid userCred length.+/);

      // One bytes extra userCred
      problemUserCred = new Uint8Array(cc.USERCRED_BYTES + 1);
      problemUserCred.set(userCred);
      problemUserCred.set([0], userCred.byteLength);
      await expect(
         (async () => {
            return cipherSvc.getCipherStreamInfo(cipherStream, new PWDKeyProvider(problemUserCred));
         })(),
      ).rejects.toThrow(/Invalid userCred length.+/);
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
