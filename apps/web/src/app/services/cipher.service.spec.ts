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
   MasterKeyKeyProvider,
   concatArrays,
   getStreamDecipher,
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

// Each block is self delimiting, so the payload size in its header gives the next offset
function splitBlocks(bytes: Uint8Array, ver: number): Uint8Array[] {
   const headerBytes = ver < cc.VERSION6 ? cc.HEADER_BYTES_OLD : cc.HEADER_BYTES_6P;
   const blocks: Uint8Array[] = [];
   let offset = 0;
   while (offset < bytes.byteLength) {
      const sizeStart = offset + cc.MAC_BYTES + cc.VER_BYTES;
      const size = bytesToNum(bytes.subarray(sizeStart, sizeStart + cc.PAYLOAD_SIZE_BYTES));
      const end = offset + headerBytes + size;
      blocks.push(bytes.subarray(offset, end));
      offset = end;
   }
   return blocks;
}

// Long enough that the manipulation and block-order vectors split into 8 blocks
const clearData = new Uint8Array([
   118, 101, 114, 115, 105, 111, 110, 58, 32, 34, 51, 46, 56, 34, 10, 115, 101, 114, 118, 105, 99, 101, 115, 58, 10, 32,
   32, 100, 111, 99, 107, 103, 101, 58, 10, 32, 32, 32, 32, 105, 109, 97, 103, 101, 58, 32, 108, 111, 117, 105, 115,
   108, 97, 109, 47, 100, 111, 99, 107, 103, 101, 58, 49, 10, 32, 32, 32, 32, 114, 101, 115, 116, 97, 114, 116, 58, 32,
   117, 110, 108, 101, 115, 115, 45, 115, 116, 111, 112, 112, 101, 100, 10, 32, 32, 32, 32, 112, 111, 114, 116, 115, 58,
   10, 32, 32, 32, 32, 32, 32, 45, 32, 53, 48, 48, 49, 58, 53, 48, 48, 49, 10, 32, 32, 32, 32, 118, 111, 108, 117, 109,
   101, 115, 58, 10, 32, 32, 32, 32, 32, 32, 45, 32, 47, 118, 97, 114, 47, 114, 117, 110, 47, 100, 111, 99, 107, 101,
   114, 46, 115, 111, 99, 107, 58, 47, 118, 97, 114, 47, 114, 117, 110, 47, 100, 111, 99, 107, 101, 114, 46, 115, 111,
   99, 107, 10, 32, 32, 32, 32, 32, 32, 45, 32, 46, 47, 100, 97, 116, 97, 58, 47, 97, 112, 112, 47, 100, 97, 116, 97,
   10, 32, 32, 32, 32, 32, 32, 35, 32, 83, 116, 97, 99, 107, 115, 32, 68, 105, 114, 101, 99, 116, 111, 114, 121, 10, 32,
   32, 32, 32, 32, 32, 35, 32, 226, 154, 160, 239, 184, 143, 32, 82, 69, 65, 68, 32, 73, 84, 32, 67, 65, 82, 69, 70, 85,
   76, 76, 89, 46, 32, 73, 102, 32, 121, 111, 117, 32, 100, 105, 100, 32, 105, 116, 32, 119, 114, 111, 110, 103, 44, 32,
   121, 111, 117, 114, 32, 100, 97, 116, 97, 32, 99, 111, 117, 108, 100, 32, 101, 110, 100, 32, 117, 112, 32, 119, 114,
   105, 116, 105, 110, 103, 32, 105, 110, 116, 111, 32, 97, 32, 87, 82, 79, 78, 71, 32, 80, 65, 84, 72, 46, 10, 32, 32,
   32, 32, 32, 32, 35, 32, 226, 154, 160, 239, 184, 143, 32, 49, 46, 32, 70, 85, 76, 76, 32, 112, 97, 116, 104, 32, 111,
   110, 108, 121, 46, 32, 78, 111, 32, 114, 101, 108, 97, 116, 105, 118, 101, 32, 112, 97, 116, 104, 32, 40, 77, 85, 83,
   84, 41, 10, 32, 32, 32, 32, 32, 32, 35, 32, 226, 154, 160, 239, 184, 143, 32, 50, 46, 32, 76, 101, 102, 116, 32, 83,
   116, 97, 99, 107, 115, 32, 80, 97, 116, 104, 32, 61, 61, 61, 32, 82, 105, 103, 104, 116, 32, 83, 116, 97, 99, 107,
   115, 32, 80, 97, 116, 104, 32, 40, 77, 85, 83, 84, 41, 10, 32, 32, 32, 32, 32, 32, 45, 32, 47, 111, 112, 116, 47,
   115, 116, 97, 99, 107, 115, 58, 47, 111, 112, 116, 47, 115, 116, 97, 99, 107, 115, 10, 32, 32, 32, 32, 101, 110, 118,
   105, 114, 111, 110, 109, 101, 110, 116, 58, 10, 32, 32, 32, 32, 32, 32, 35, 32, 84, 101, 108, 108, 32, 68, 111, 99,
   107, 103, 101, 32, 119, 104, 101, 114, 101, 32, 116, 111, 32, 102, 105, 110, 100, 32, 116, 104, 101, 32, 115, 116,
   97, 99, 107, 115, 10, 32, 32, 32, 32, 32, 32, 45, 32, 68, 79, 67, 75, 71, 69, 95, 83, 84, 65, 67, 75, 83, 95, 68, 73,
   82, 61, 47, 111, 112, 116, 47, 115, 116, 97, 99, 107, 115,
]);

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
               return [pwd];
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
            return [pwd];
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
            return [cdinfo.hint!];
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
         return [cdinfo.hint!];
      });
      const decrypted = await cipherSvc.decryptStream(cipherStream, decKeyProvider);

      const resString = await readStreamAll(decrypted, true);
      expect(resString).toEqual(srcString);
   });

   it('detect a stripped outer loop layer', async () => {
      const algKeys = Ciphers.algs();
      const srcString = 'This is a secret 🦆';
      const [clearStream] = streamFromStr(srcString);
      const userCred = getRandom(cc.USERCRED_BYTES);

      const econtext: EContext = {
         algs: algKeys,
         ic: cc.ICOUNT_MIN,
      };

      const encKeyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
         return [String(cdinfo.lp), String(cdinfo.lp)];
      });
      const cipherData = await readStreamAll(await cipherSvc.encryptStream(clearStream, encKeyProvider, econtext));

      // Loop layers nest, so decrypting the outer block yields the entire layer within
      const [outerStream] = streamFromBytes(cipherData);
      const peelKeyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
         return [cdinfo.hint!];
      });
      const inner = await (await getStreamDecipher(outerStream, peelKeyProvider)).decryptBlock();

      // Control: the inner layer is a well formed ciphertext that decrypts as a stand-alone block
      const [controlStream] = streamFromBytes(inner);
      const controlKeyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
         return [cdinfo.hint!];
      });
      const controlDecipher = await getStreamDecipher(controlStream, controlKeyProvider);
      await expect(controlDecipher.decryptBlock()).resolves.not.toHaveLength(0);

      // Stream decryption understands nesting and should reject a stream with a missing layer
      const [innerStream] = streamFromBytes(inner);
      const strippedKeyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
         return [cdinfo.hint!];
      });
      await expect(cipherSvc.decryptStream(innerStream, strippedKeyProvider)).rejects.toThrow(/Invalid loop/);
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
         return [cdinfo.hint!];
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
         // BEGIN GENERATED: v8:singleLoopMultiVersion
         //v8 — generated by: pnpm vectors:ciphersvc
         {
            ver: 8,
            cts: [
               // AES-GCM: V8
               'n0pCTAbp9K9dRFvWhr-lnNo_oa9LHoBJc1-nD2auJmMIADQBAAEBAHPr6gc0l0C4Vnn47FuBczZ0lI7bUIuZ77Pqca6gaAYAACDewzVJDVRGi3F4qGIqECLs7qTJoFaWi6sg7Av07BbgOyBpXKrbulg78n221ccFkGPhbjywEf0cGuKHjNaULLbP6AseF8V8Qv7W1IC6HWE5TtREmOnMmfOfqK1-cOvzKN8PIzLObX5A2ruOYpzCN9kvDxVGRh_rAD5tWeqsztn-eSX1zlN5d9VwqQ2ftgcohaX9N9ZSiqhueVWUOv-F9CAkh9U3882h28loyLf3C_snRIpdkCKyHEjyGupYMA6BM20SdgzcMfXKxhjLoPcl7rPP8f8Rmjui8ePrOgM_MXsWHWr3bTGiRKGJa_kY3KwRKGuR8Rz_SAx-7gfzdS98OIZ2-LMkR6NE5R3BqGN8oUxF',
               // X20-PLY: V8
               'I0_GLW7Avj-OnpAbWikCf3QFCeUVnsEMC4at7T8ReFYIAEABAAECAMzzj6rX-4_NcQl7kS_lBN5A5OK3bbEVKzrgcxK7oHKxoO2HDOjEY9WgaAYAACBEY6UouAZsIZV0jnk-p_yOe8rUlHINc2NlE6Y1T5HFJyAdIG_SLulnuBbrqAytJfze2imms_t9dvDtMDGGdez2H6FKOvbR8B4HQO-ibwVoWbNZfrw-bbHJoRqQa0emA3en8DFUlDQSZLIDdcsmfVWGTYU7L8lv8v_AqwouKq8fofFDRE3-GNEmlGf6N0lnlNAkNZQ6ha6FS8kPi4seLu6ngz_kEqUUWK73NsyrdWwqRQjiJfT7wjdkjOOiFA4_YQJTQO_hMOxFhwlISpLxPBEhsjktPwhzBUHBZVa25yiOG0mToGLzqeNjuiTelvZA_ugFZFQfiD2Fujx3qt9y1Jl5BQz6ZYXoS1eXaA3WAM4g',
               // AEGIS-256: V8
               'VlxGGSTfZhW4MO9CiTS3vMgpv7m2ckJVffGroMzlWEwIAGgBAAEDABczPYip05enRzyTZUJpn5XH56VbNiwg1IjIGnTTOlhOFIAYU5_WsQbPVnsnOUVbm6BoBgAAMKd70qW2sHecvj-hqnPcRJoXOeD81XP71PnfYkBWNOWvET5dH0QK4vxZtpZcEI4d8CAfS712E30rFZ_l4HYWj-VEjvfU1JoO4C6JS6ipSWbwVjVZWKz__sGyMpYqUAKzFGJs5Dck2ir9fBwoojPVxKG5ccroUI2-dS2HDeP1CtsfSO3ciQBEfBFlfIp0TZvY7StOHLMll1bMnO7Wj6STvY5CS5avDMJ3logN4gtTsCA8hEcEqvYhAZUsh1e1MOmP_VVdWB2xRWImY6h8BFXEfwR2YScO4FCHJJwpXKQbSKgD2gbt_0AisivZlL7K1B2FmVJlQlghofNdcxeCyBvlh_lCl2kLGTf2akM2KCI6mrW5BHgk3YRJo1-xLlEF359cZgLYtqcuan9wAwhpXqDWxQ',
            ],
         },
         // END GENERATED: v8:singleLoopMultiVersion
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
               return [pwd];
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
         // BEGIN GENERATED: v8:multiVersionLoops
         //v8 — generated by: pnpm vectors:ciphersvc
         {
            ver: 8,
            cts: [
               // AES-GCM, X20-PLY, AEGIS-256, V8, 3 LPS
               'Sh9VcHvblVbA-ZHrT3TjTx62ECD7-_Mc6FS9tTR66i4IAKoCAAEDAJM5680S5Pth2uOkEdsEAyGk7MFh2tv0VapFJX89ba652pYCyey_1O2oJaf_m3IwYKBoBgAiMHhnnXN8nJl02j8qLRvnU-TSLMA6Zmw0b6uWe2ekm7BSk4WBsQutEw7Hge53PVFdCyBkJhptFlBgASfQ4lgXYSlLqwiu-nEMjEeA_PmkgqK1T-7fmQvFgDDj5-K_tOsLoohl2N4v9espMf6zN3UmsjX34wunvnQXFwpdpuEXDRo3t5C-czP8B3Tj6P4oNaj5wRYrPeI4uE-AtQZn0p17oDZOpjsMEA9uRXlJ7wyRg-sGd0xfvV_a4bqu6gnrAjRZD442uGe7Ro1dwoGOyfygHUog1guPZDluVinF0BwTTuP05GJdGJkl3c-eg1854zdy3jswdDxgYeJ42MJszqDmvrsd0M-JM1cq0svjIzsd2Cn2zl_SINDHxtGXK4YjCM8_xst6S40JLL1bkIECkUMJltbzWnCVh9z04-qQC4bs8-NHcRpIZK0iuHpfyGqwhBq4mRfs_UgdhcGhIYN5yTIwLM7kg5Q7ePFaTggupktFkv7JC02rfQroAKa5RSVc9SqJtlf_494VqMK_cM6Z8y3lbRatHid7mztRnIsE4pWSbjatjU84pQqg9-4oz62ZZADFseViRGZr29r7eebbE2FaDoMNrrsdAd7n7eKIr6VhfsMG2oh_k0X3PKV63sh2-uzGHLgL5kID09ryyixABj8q6hVDm5HEKXwcsaIRXnzze1uIY5ztRaXZmWjnlVxySw3JUztlR0LDpjmaB0frN4f3L0Y6Vyjr06AkpFC1EnqOqw5NNlWJAqPNwp62-VvPvgZeO3EXKOvYZQSaBBnIhyj_2Wy5Es-0vY2FTywrV2NbUrnQKD1s4U2qRK-4tOMRU6YTeV8',
               // AEGIS-256, X20-PLY, AEGIS-256, V8, 3 LPS
               'Qnfzid3rDybCh3kQ2FCQ2KvW2wyC_QOCeYlWmSeWQogIAN4CAAEDADw9jPz6pGgHlE-pOtI-YYx9BdcMQWBFCcl7YBBD7BK-o_KEn2Q-rsPWez4d1rtCYKBoBgAiMPvilfcb0E1fT5TJ6lWQgX_SpnhBcXswzE6KNmDWLiMlm4CEOeLYHAKr9Bi23gmpfyAu4UL1eaBNMExwGmmh1S6I1zYCsZ4VifEh1L30SPqVxLGU0hwlv1VKFNCrwxmzJPeQxSiPav9aO-OdnPwYppVQVrHzWtoh4ZvKVFuqajLy5Crjty67PVQnGC9jau5E8kXk3eyhsIMcgGkQFc9LQ2F_nxS9hL0Mbt8JoMfPwG0GejcNweMkUrCNndTUTK4fTKDhmuiYWR11iT9Wt22ZSp4aO2zqmSbsQn-QocTGbl9nS2ifoZEA0smO1u6h6zseoL-taG1mpJ8JQE0xCC_ZVjd_pYWAGxWyI6RjQCrJDC-D4GZanJZvyJXUqKsEprzW_wo2cdslJTWtJcBtvi_nlz3yrNiC_8YYU88TFYMDqCNQ7P5MgZJ_ViWvp9ZrowTiRULiGjKenDrZC4TGczJb6FdUkIroD1YdBVRV_M0K8AElx8jzxvzmX6gznkdmj822bZpCLa-mkP4n4lQzVo9Gvtd5kAtEobrtgZCMwcGO6MGz8GpZlma2uF8SqxMph9X9q7g_YuHtNkArM-XEltxC5AOXpz8w3EGDqJLmzH9LNLVT5rXmAHlOnjjXmINcfurA3l7D5oOABUZYzRk8PXNXUZa0NoV54D0s1P9tvw_PohuJyKp46Vd6ojqIW_Rp-42mC1sIA__1fUjxlDzTkipSGMls8P2mtF7ZeYrmXgm32nEhS5168POajayO4oXrwbenVIHsX5b506d4Fxb4ZEYl3M7RfwzuC6ZA0uZKca1_-Hd9uIkotwLFUqBOtGfxbMoyv2ic3jTdwKod8bLZFWaqbNbKRal8vNch8hKMbzp11LM7l54iRUBmyB8bzZykatumTLWY6GBr',
               // AEGIS-256, AES-GCM, AES-GCM, V8, 3 LPS
               'lwPRP_sXRlTa6GSSdpUY3qgU5BwdfxMqIyepH16G5WYIAJ4CAAEBAN_RQsd3f21MFvzuSvsa1xCLpybmW0RFcbinl1OgaAYAIiApkQ_J2X2hIT1koESQtzuiSrPh3Y3ktarnUwqIaiLO3CBdnfuSCBU7cUofef1LtZME1L_lYgZtYIkTyNoJ8J--61sxU7GihRpRIeMHOmEWB1p5k0KR-xv1eFRRHcd-WcMQK5ciCxIbefni3R8ZD8tS4jmcIpFn1-x0xEd4bX1gnNgApefzbM8lsQxnyrHXx0z-VRDO4O_5efZ9K784GIb7ZWmqMdQsdkniB2ZxEJOLMHK2MLRv-BfTGynkN-JYiT71Sx6UZhTkTsYvMuv3UJXOHeB-dQfNddOgJVnUSnkEOjotgLG2niWLHt3Xv_A7ZPEgde-NLrB8ScjaQjN0xwvVLsZWjscrUpiMA4pabGVdD54AZ_9fOaSqyxgURH02TOHlpKVdNTm8LFlXSfJ6KV2JsHx7NgI8_h1gb4cERw_qCNxqQF53dpuhLqJOzeNTPREhNm1Gd5kKS6AuOGvyjDkvchZLyWJ7-jEN2PXm3_ieAIhaLAbSwp5UiVD21VPnBwDMFysQW_AEWj9_tCNptrG6597RIF9QH9jHptGN757rnDnUmPe3y-INd8kYzkyGUM607WGYpJRKc0txhF8uPNvnPIXSGXzkgmHmSLzUGI1lBcjiqatA-Y9RwzyzXCpWvBsIP7ivDaecTO63oXMbDmtHEJUR0dUt_4IyU9POoMy2BobFibHrZ6MijgCOTof_CpyKDWCl7wYMPdGdteErIQhMs5oJ18QFwVdNiBd5pUJ5DAQBkoUvlzSCL_f6A0RKgqFEZqpqV57v6VKbmBUO7bhDYac1dNukMofVZgLwcTpHm3ge4_D4cf9M-pm9WiQTPY7SxUhKmj8Mo6I',
            ],
         },
         // END GENERATED: v8:multiVersionLoops
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
               return [cdinfo.hint!];
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
         // BEGIN GENERATED: v8:missingTerminal
         //v8 — generated by: pnpm vectors:ciphersvc
         {
            ver: 8,
            cipherData: new Uint8Array([
               56, 101, 244, 200, 117, 199, 158, 128, 68, 140, 223, 24, 84, 36, 7, 243, 161, 38, 152, 216, 58, 61, 76,
               2, 251, 171, 127, 70, 19, 19, 150, 132, 8, 0, 150, 0, 0, 0, 2, 0, 209, 183, 81, 144, 204, 246, 57, 192,
               142, 171, 29, 41, 198, 143, 223, 237, 205, 93, 43, 189, 126, 219, 42, 31, 163, 54, 212, 105, 75, 30, 246,
               164, 230, 226, 103, 182, 210, 217, 216, 235, 64, 119, 27, 0, 0, 32, 96, 193, 6, 20, 85, 115, 204, 70,
               224, 205, 49, 90, 94, 33, 160, 30, 227, 215, 92, 85, 216, 46, 251, 191, 208, 244, 233, 120, 51, 234, 76,
               60, 32, 73, 170, 173, 46, 93, 194, 102, 103, 49, 78, 146, 69, 195, 191, 33, 219, 192, 109, 11, 230, 173,
               248, 244, 233, 135, 180, 72, 44, 162, 15, 37, 249, 136, 43, 51, 184, 129, 106, 89, 171, 246, 115, 249,
               217, 107, 245, 207, 110, 146, 200, 192, 232, 150, 183, 127, 168, 220, 120, 9, 237, 57, 191, 25, 97, 251,
               200, 127, 50, 72, 240, 177, 151, 56, 125, 100, 168, 105, 38, 212, 90, 7, 50, 193, 209, 5, 169, 106, 60,
               189, 218, 122, 176, 204, 171, 131, 150, 100, 56, 4, 152, 8, 0, 52, 0, 0, 0, 2, 0, 65, 141, 141, 152, 3,
               0, 150, 49, 3, 39, 28, 97, 121, 137, 10, 15, 45, 56, 77, 173, 202, 218, 250, 239, 236, 106, 106, 158,
               147, 82, 1, 38, 173, 197, 12, 220, 0, 113, 54, 71, 139, 134, 119, 18, 48, 216, 4, 75, 50,
            ]),
         },
         // END GENERATED: v8:missingTerminal
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
            return [pwd];
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
         // BEGIN GENERATED: v8:extraTerminal
         //v8 — generated by: pnpm vectors:ciphersvc
         {
            ver: 8,
            cipherData: new Uint8Array([
               45, 203, 180, 137, 151, 160, 233, 235, 138, 181, 201, 216, 34, 74, 99, 166, 238, 92, 77, 141, 43, 25,
               205, 146, 66, 110, 116, 120, 97, 59, 241, 255, 8, 0, 150, 0, 0, 1, 2, 0, 86, 158, 31, 52, 249, 112, 133,
               136, 195, 227, 216, 56, 92, 49, 141, 24, 150, 35, 197, 33, 152, 204, 211, 113, 202, 254, 33, 129, 57,
               156, 102, 93, 1, 42, 58, 35, 152, 168, 75, 92, 64, 119, 27, 0, 0, 32, 108, 202, 221, 221, 148, 164, 225,
               0, 103, 9, 188, 84, 148, 121, 204, 186, 212, 141, 193, 204, 223, 182, 158, 177, 80, 238, 58, 232, 152,
               49, 139, 121, 32, 28, 93, 111, 15, 181, 155, 202, 200, 184, 116, 249, 124, 45, 14, 220, 164, 91, 55, 72,
               127, 184, 80, 222, 182, 147, 61, 97, 183, 215, 80, 213, 202, 198, 1, 90, 246, 214, 82, 227, 68, 228, 43,
               106, 251, 214, 15, 159, 151, 179, 64, 192, 32, 113, 217, 122, 100, 163, 39, 223, 57, 206, 247, 229, 156,
               251, 193, 97, 36, 44, 56, 43, 180, 120, 115, 48, 22, 1, 89, 3, 68, 250, 151, 70, 156, 69, 118, 252, 8,
               235, 38, 249, 60, 251, 200, 138, 215, 92, 102, 87, 111, 8, 0, 52, 0, 0, 1, 2, 0, 250, 151, 51, 123, 13,
               140, 161, 53, 191, 16, 206, 133, 242, 87, 69, 46, 73, 110, 4, 229, 207, 221, 125, 108, 240, 35, 216, 223,
               240, 180, 191, 141, 155, 177, 10, 18, 180, 246, 24, 12, 14, 1, 142, 197, 105, 50, 243, 8, 128,
            ]),
         },
         // END GENERATED: v8:extraTerminal
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
            return [pwd];
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
         // BEGIN GENERATED: v8:flippedTerminal
         //v8 — generated by: pnpm vectors:ciphersvc
         {
            ver: 8,
            cipherData: new Uint8Array([
               56, 156, 0, 205, 131, 99, 189, 189, 62, 229, 55, 13, 110, 92, 254, 170, 244, 67, 148, 244, 244, 180, 88,
               121, 98, 192, 5, 207, 73, 134, 199, 8, 8, 0, 150, 0, 0, 1, 2, 0, 240, 233, 228, 116, 176, 184, 77, 110,
               54, 254, 152, 65, 87, 86, 123, 215, 152, 18, 235, 64, 216, 181, 50, 208, 208, 61, 235, 66, 223, 114, 219,
               123, 148, 241, 168, 22, 182, 11, 53, 182, 64, 119, 27, 0, 0, 32, 62, 27, 164, 249, 206, 111, 202, 237,
               220, 157, 188, 172, 210, 232, 160, 175, 226, 214, 55, 110, 6, 68, 87, 247, 86, 85, 179, 44, 180, 168,
               111, 215, 32, 157, 9, 42, 78, 40, 17, 125, 147, 101, 10, 54, 229, 153, 86, 179, 127, 153, 176, 170, 50,
               182, 138, 210, 33, 234, 220, 97, 233, 96, 33, 103, 226, 100, 102, 199, 181, 181, 29, 118, 163, 197, 229,
               17, 93, 155, 92, 216, 154, 55, 167, 27, 22, 51, 189, 229, 151, 127, 5, 210, 224, 68, 227, 26, 119, 41,
               166, 11, 216, 114, 104, 165, 187, 212, 171, 217, 171, 40, 54, 142, 123, 208, 190, 21, 130, 59, 94, 23,
               178, 238, 70, 90, 79, 143, 218, 73, 141, 182, 24, 199, 48, 8, 0, 52, 0, 0, 0, 2, 0, 99, 195, 5, 189, 176,
               89, 248, 105, 193, 82, 44, 78, 126, 205, 105, 133, 220, 223, 253, 216, 223, 190, 128, 93, 246, 83, 167,
               46, 163, 96, 232, 18, 130, 247, 135, 141, 143, 86, 28, 14, 174, 73, 74, 156, 9, 8, 18, 63, 230,
            ]),
         },
         // END GENERATED: v8:flippedTerminal
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
            return [pwd];
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
         // BEGIN GENERATED: v8:corruptCipherText
         //v8 — generated by: pnpm vectors:ciphersvc
         {
            ver: 8,
            cts: [
               //AES-GCM
               '_M4tfZejuqcq1wUjICJKHhEgqUHe2j-PiSWb2EcQRdsIAIwAAAEBAFM0Xm9Vr5Xwrqn6e5frQdWl5GndDrSPl0CAzT_gyBAAACAgfzy4gEv-s-jbwz0yBPknC_g85uIC8593BBuuRtHynSAY--P5KFII1XBPK8_eO1_aj979kVyUfgghQMThjmvdSTa7KwSeoUc_RwxIkrf7QGaWT2uCLwqeab6dHqk8SSz3MLli-F5S',
               //X20-PLY
               '-Fh0NRxo1wQjfhFGPO8YGbBAc7nwcVSWfkEvI-uPDr4IAJgAAAECAMpVodV1uY00Hlc6CqwPUDGFOkQP8mbkdXGEVwu3VWi9YST9gonrMuDgyBAAACB_YFM9Sf6fD7lWHrUsCtiElAczFgJjPnXZAx48TKavtiA1sH0dSsPcZ2Wwbx4A_-_xxWGngGYIFA74RPv6ge6QKq774Q-sLITKjj362Q4sgq0IIorz2VcQNdeg-ETEbctxXxwkiVqj',
               //AEGIS-256
               'cMcFiDXoUyFlsOnc6fUyp8-t4vAQxY0ceMPrpHYQliwIAMAAAAEDAJld7O3n-QNFLj6u01WI3iIMVnH8waZDzslo4gYTf7ZLUx9xCvP2l-lybtQd5eBnzuDIEAAAMHhL0kn7NKC9CeD7L_Xn5IKZPOoN3KCLrb5okQDpt1NUwP0iL9qy92yy9lkcqGDR4yDcOJdDQIaP8QGp1vCw1v7sovxJEPjl8Oe2R9bhw0JWfgg6WpPTE2gndcD1h43DkGYf_BsTr0MlBIjh6AGkUetWDPWAV7RJXg1bFcoA_0AaGa-STWIg1w',
            ],
         },
         // END GENERATED: v8:corruptCipherText
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
               return ['asdf'];
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
                  return ['asdf'];
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
            return ['the wrong pwd'];
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
                     return ['wrong'];
                  } else {
                     return [cdinfo.hint!];
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
            return [pwd];
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
            return [pwd];
         });
         await expect(cipherSvc.decryptStream(corruptStream, decKeyProvider1)).rejects.toThrow(/.+MAC.+/);

         // Hit another value
         corruptData = pokeValue(cipherData, cipherData.length - 30, 4);
         [corruptStream] = streamFromBytes(corruptData);

         const decKeyProvider2 = new PWDKeyProvider(userCred.slice(0), async (_cdinfo) => {
            // should never execute
            expect(false, 'should not execute').toBe(true);
            return [pwd];
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
         return [pwd];
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
         return [pwd];
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
         return [pwd];
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
         const kp1 = new PWDKeyProvider(userCred.slice(0), [pwd]);
         const cipher1 = await readStreamAll(await cipherSvc.encryptStream(clearStream1, kp1, econtext));

         const [clearStream2] = streamFromStr(srcString);
         const kp2 = new PWDKeyProvider(userCred.slice(0), [pwd]);
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

describe('Stream encryption and decryption with extraKeyMaterial', () => {
   let cipherSvc: CipherService;
   beforeEach(async () => {
      await cryptoReady();
      TestBed.configureTestingModule({});
      cipherSvc = TestBed.inject(CipherService);
   });

   it('successful round trip, all algorithms, no pwd hint, with extraKeyMaterial', async () => {
      for (const alg of Ciphers.algs()) {
         const srcString = 'This is a secret 🦆';
         const [clearStream, _clearData] = streamFromStr(srcString);
         const pwd = 'a good pwd';
         const userCred = getRandom(cc.USERCRED_BYTES);
         const extraKeyMaterial = bytesToBase64(getRandom(16));

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
               return [pwd];
            },
            extraKeyMaterial,
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
               return [pwd];
            },
            extraKeyMaterial,
         );
         const decrypted = await cipherSvc.decryptStream(cipherStream, decKeyProvider);

         const resString = await readStreamAll(decrypted, true);
         expect(resString).toEqual(srcString);
      }
   });

   it('successful round trip, all algorithms, with extraKeyMaterial', async () => {
      for (const alg of Ciphers.algs()) {
         const srcString = 'This is a secret 🦆';
         const [clearStream, _clearData] = streamFromStr(srcString);
         const pwd = 'a good pwd';
         const hint = 'not really';
         const userCred = getRandom(cc.USERCRED_BYTES);
         const extraKeyMaterial = getRandom(1);

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
            extraKeyMaterial,
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
               return [pwd];
            },
            extraKeyMaterial,
         );
         const decrypted = await cipherSvc.decryptStream(cipherStream, decKeyProvider);

         const resString = await readStreamAll(decrypted, true);
         expect(resString).toEqual(srcString);
      }
   });

   it('successful cipherdatainfo, all algorithms, with extraKeyMaterial', async () => {
      for (const alg of Ciphers.algs()) {
         const srcString = 'This is a secret 🦆';
         const [clearStream, _clearData] = streamFromStr(srcString);
         const pwd = 'a good pwd';
         const hint = 'not really';
         const userCred = getRandom(cc.USERCRED_BYTES);
         const extraKeyMaterial = getRandom(1);

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
            extraKeyMaterial,
         );
         const cipherStream = await cipherSvc.encryptStream(clearStream, encKeyProvider, econtext);

         const infoKeyProvider = new PWDKeyProvider(userCred.slice(0), undefined, extraKeyMaterial);
         const cipherInfo = await cipherSvc.getCipherStreamInfo(cipherStream, infoKeyProvider);
         expect(cipherInfo.ver).toEqual(cc.CURRENT_VERSION);
         expect(cipherInfo.alg).toEqual(alg);
         expect(cipherInfo.ic).toEqual(cc.ICOUNT_MIN);
         expect(cipherInfo.lp).toEqual(1);
         expect(cipherInfo.slt.byteLength).toEqual(cc.SLT_BYTES);
         expect(cipherInfo.hint).toEqual(hint);
      }
   });

   it('failed round trip, all algorithms, missing extraKeyMaterial', async () => {
      for (const alg of Ciphers.algs()) {
         const srcString = 'This is a secret 🦆';
         const [clearStream, _clearData] = streamFromStr(srcString);
         const pwd = 'a good pwd';
         const hint = 'not really';
         const userCred = getRandom(cc.USERCRED_BYTES);
         const extraKeyMaterial = getRandom(1);

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
            extraKeyMaterial,
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
            return [pwd];
         });
         await expect(cipherSvc.decryptStream(cipherStream, decKeyProvider)).rejects.toThrow(/Invalid MAC/);
      }
   });

   it('failed round trip, all algorithms, added extraKeyMaterial', async () => {
      for (const alg of Ciphers.algs()) {
         const srcString = 'This is a secret 🦆';
         const [clearStream, _clearData] = streamFromStr(srcString);
         const pwd = 'a good pwd';
         const hint = 'not really';
         const userCred = getRandom(cc.USERCRED_BYTES);
         const extraKeyMaterial = getRandom(14);

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
               return [pwd];
            },
            extraKeyMaterial,
         );
         await expect(cipherSvc.decryptStream(cipherStream, decKeyProvider)).rejects.toThrow(/Invalid MAC/);
      }
   });

   it('failed round trip, all algorithms, wrong extraKeyMaterial', async () => {
      for (const alg of Ciphers.algs()) {
         const srcString = 'This is a secret 🦆';
         const [clearStream, _clearData] = streamFromStr(srcString);
         const pwd = 'a good pwd';
         const hint = 'not really';
         const userCred = getRandom(cc.USERCRED_BYTES);
         const extraKeyMaterial = getRandom(1);

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
            extraKeyMaterial,
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
               return [pwd];
            },
            new Uint8Array(0),
         );
         await expect(cipherSvc.decryptStream(cipherStream, decKeyProvider)).rejects.toThrow(/Invalid MAC/);
      }
   });

   it('successful round trip, mixed algorithms, loops, with extraKeyMaterial', async () => {
      const algKeys = Ciphers.algs();
      const maxLps = algKeys.length;

      const srcString = 'This is a secret 🦆';
      const [clearStream] = streamFromStr(srcString);
      const userCred = getRandom(cc.USERCRED_BYTES);
      const extraKeyMaterial = getRandom(16);

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
         extraKeyMaterial,
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
            return [cdinfo.hint!];
         },
         extraKeyMaterial,
      );
      const decrypted = await cipherSvc.decryptStream(cipherStream, decKeyProvider);

      const resString = await readStreamAll(decrypted, true);
      expect(resString).toEqual(srcString);
   });

   it('failed round trip, mixed algorithms, loops, missing extraKeyMaterial', async () => {
      const algKeys = Ciphers.algs();
      const srcString = 'This is a secret 🦆';
      const [clearStream] = streamFromStr(srcString);
      const userCred = getRandom(cc.USERCRED_BYTES);
      const extraKeyMaterial = getRandom(16);

      const econtext: EContext = {
         algs: algKeys,
         ic: cc.ICOUNT_MIN,
      };

      const encKeyProvider = new PWDKeyProvider(
         userCred.slice(0),
         async (cdinfo) => {
            return [String(cdinfo.lp), String(cdinfo.lp)];
         },
         extraKeyMaterial,
      );
      const cipherStream = await cipherSvc.encryptStream(clearStream, encKeyProvider, econtext);

      const decKeyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
         return [cdinfo.hint!];
      });
      await expect(cipherSvc.decryptStream(cipherStream, decKeyProvider)).rejects.toThrow(/Invalid MAC/);
   });

   it('failed round trip, mixed algorithms, loops, wrong extraKeyMaterial', async () => {
      const algKeys = Ciphers.algs();
      const srcString = 'This is a secret 🦆';
      const [clearStream] = streamFromStr(srcString);
      const userCred = getRandom(cc.USERCRED_BYTES);
      const extraKeyMaterial = getRandom(16);
      const wrongExtraKeyMaterial = getRandom(16);

      const econtext: EContext = {
         algs: algKeys,
         ic: cc.ICOUNT_MIN,
      };

      const encKeyProvider = new PWDKeyProvider(
         userCred.slice(0),
         async (cdinfo) => {
            return [String(cdinfo.lp), String(cdinfo.lp)];
         },
         extraKeyMaterial,
      );
      const cipherStream = await cipherSvc.encryptStream(clearStream, encKeyProvider, econtext);

      const decKeyProvider = new PWDKeyProvider(
         userCred.slice(0),
         async (cdinfo) => {
            return [cdinfo.hint!];
         },
         wrongExtraKeyMaterial,
      );
      await expect(cipherSvc.decryptStream(cipherStream, decKeyProvider)).rejects.toThrow(/Invalid MAC/);
   });
});

describe('Stream encryption and decryption with MasterKeyKeyProvider', () => {
   let cipherSvc: CipherService;
   beforeEach(async () => {
      await cryptoReady();
      TestBed.configureTestingModule({});
      cipherSvc = TestBed.inject(CipherService);
   });

   it('successful round trip, all algorithms, no extraKeyMaterial', async () => {
      for (const alg of Ciphers.algs()) {
         const srcString = 'This is a secret 🦆';
         const [clearStream, _clearData] = streamFromStr(srcString);
         const masterKey = getRandom(cc.KEY_BYTES);

         const econtext: EContext = {
            algs: [alg],
         };

         const encKeyProvider = new MasterKeyKeyProvider(masterKey.slice(0));
         const cipherStream = await cipherSvc.encryptStream(clearStream, encKeyProvider, econtext);

         const decKeyProvider = new MasterKeyKeyProvider(masterKey.slice(0));
         const decrypted = await cipherSvc.decryptStream(cipherStream, decKeyProvider);

         const resString = await readStreamAll(decrypted, true);
         expect(resString).toEqual(srcString);
      }
   });

   it('successful round trip, all algorithms, with extraKeyMaterial', async () => {
      for (const alg of Ciphers.algs()) {
         const srcString = 'This is a secret 🦆';
         const [clearStream, _clearData] = streamFromStr(srcString);
         const masterKey = getRandom(cc.KEY_BYTES);
         const extraKeyMaterial = getRandom(16);

         const econtext: EContext = {
            algs: [alg],
         };

         const encKeyProvider = new MasterKeyKeyProvider(masterKey.slice(0), extraKeyMaterial);
         const cipherStream = await cipherSvc.encryptStream(clearStream, encKeyProvider, econtext);

         const decKeyProvider = new MasterKeyKeyProvider(masterKey.slice(0), extraKeyMaterial);
         const decrypted = await cipherSvc.decryptStream(cipherStream, decKeyProvider);

         const resString = await readStreamAll(decrypted, true);
         expect(resString).toEqual(srcString);
      }
   });

   // The authenticator and PRF paths pass a base64 userId rather than bytes
   it('successful round trip, all algorithms, base64 extraKeyMaterial', async () => {
      for (const alg of Ciphers.algs()) {
         const srcString = 'This is a secret 🦆';
         const [clearStream, _clearData] = streamFromStr(srcString);
         const masterKey = getRandom(cc.KEY_BYTES);
         const extraKeyMaterial = bytesToBase64(getRandom(16));

         const econtext: EContext = {
            algs: [alg],
         };

         const encKeyProvider = new MasterKeyKeyProvider(masterKey.slice(0), extraKeyMaterial);
         const cipherStream = await cipherSvc.encryptStream(clearStream, encKeyProvider, econtext);

         const decKeyProvider = new MasterKeyKeyProvider(masterKey.slice(0), base64ToBytes(extraKeyMaterial));
         const decrypted = await cipherSvc.decryptStream(cipherStream, decKeyProvider);

         const resString = await readStreamAll(decrypted, true);
         expect(resString).toEqual(srcString);
      }
   });

   it('successful cipherdatainfo, all algorithms, with extraKeyMaterial', async () => {
      for (const alg of Ciphers.algs()) {
         const srcString = 'This is a secret 🦆';
         const [clearStream, _clearData] = streamFromStr(srcString);
         const masterKey = getRandom(cc.KEY_BYTES);
         const extraKeyMaterial = getRandom(1);

         const econtext: EContext = {
            algs: [alg],
         };

         const encKeyProvider = new MasterKeyKeyProvider(masterKey.slice(0), extraKeyMaterial);
         const cipherStream = await cipherSvc.encryptStream(clearStream, encKeyProvider, econtext);

         const infoKeyProvider = new MasterKeyKeyProvider(masterKey.slice(0), extraKeyMaterial);
         const cipherInfo = await cipherSvc.getCipherStreamInfo(cipherStream, infoKeyProvider);
         expect(cipherInfo.ver).toEqual(cc.CURRENT_VERSION);
         expect(cipherInfo.alg).toEqual(alg);
         expect(cipherInfo.ic).toBeFalsy();
         expect(cipherInfo.lp).toEqual(1);
         expect(cipherInfo.slt.byteLength).toEqual(cc.SLT_BYTES);
         expect(cipherInfo.hint).toBeFalsy();
      }
   });

   it('failed round trip, all algorithms, missing extraKeyMaterial', async () => {
      for (const alg of Ciphers.algs()) {
         const srcString = 'This is a secret 🦆';
         const [clearStream, _clearData] = streamFromStr(srcString);
         const masterKey = getRandom(cc.KEY_BYTES);
         const extraKeyMaterial = getRandom(16);

         const econtext: EContext = {
            algs: [alg],
         };

         const encKeyProvider = new MasterKeyKeyProvider(masterKey.slice(0), extraKeyMaterial);
         const cipherStream = await cipherSvc.encryptStream(clearStream, encKeyProvider, econtext);

         const decKeyProvider = new MasterKeyKeyProvider(masterKey.slice(0));
         await expect(cipherSvc.decryptStream(cipherStream, decKeyProvider)).rejects.toThrow(/Invalid MAC/);
      }
   });

   it('failed round trip, all algorithms, added extraKeyMaterial', async () => {
      for (const alg of Ciphers.algs()) {
         const srcString = 'This is a secret 🦆';
         const [clearStream, _clearData] = streamFromStr(srcString);
         const masterKey = getRandom(cc.KEY_BYTES);

         const econtext: EContext = {
            algs: [alg],
         };

         const encKeyProvider = new MasterKeyKeyProvider(masterKey.slice(0));
         const cipherStream = await cipherSvc.encryptStream(clearStream, encKeyProvider, econtext);

         const decKeyProvider = new MasterKeyKeyProvider(masterKey.slice(0), getRandom(16));
         await expect(cipherSvc.decryptStream(cipherStream, decKeyProvider)).rejects.toThrow(/Invalid MAC/);
      }
   });

   it('failed round trip, all algorithms, wrong extraKeyMaterial', async () => {
      for (const alg of Ciphers.algs()) {
         const srcString = 'This is a secret 🦆';
         const [clearStream, _clearData] = streamFromStr(srcString);
         const masterKey = getRandom(cc.KEY_BYTES);
         const extraKeyMaterial = getRandom(16);
         const wrongExtraKeyMaterial = getRandom(16);

         const econtext: EContext = {
            algs: [alg],
         };

         const encKeyProvider = new MasterKeyKeyProvider(masterKey.slice(0), extraKeyMaterial);
         const cipherStream = await cipherSvc.encryptStream(clearStream, encKeyProvider, econtext);

         const decKeyProvider = new MasterKeyKeyProvider(masterKey.slice(0), wrongExtraKeyMaterial);
         await expect(cipherSvc.decryptStream(cipherStream, decKeyProvider)).rejects.toThrow(/Invalid MAC/);
      }
   });

   it('failed round trip, all algorithms, wrong master key', async () => {
      for (const alg of Ciphers.algs()) {
         const srcString = 'This is a secret 🦆';
         const [clearStream, _clearData] = streamFromStr(srcString);
         const masterKey = getRandom(cc.KEY_BYTES);
         const extraKeyMaterial = getRandom(16);

         const econtext: EContext = {
            algs: [alg],
         };

         const encKeyProvider = new MasterKeyKeyProvider(masterKey.slice(0), extraKeyMaterial);
         const cipherStream = await cipherSvc.encryptStream(clearStream, encKeyProvider, econtext);

         const decKeyProvider = new MasterKeyKeyProvider(getRandom(cc.KEY_BYTES), extraKeyMaterial);
         await expect(cipherSvc.decryptStream(cipherStream, decKeyProvider)).rejects.toThrow(/Invalid MAC/);
      }
   });

   it('successful round trip, mixed algorithms, loops, with extraKeyMaterial', async () => {
      const algKeys = Ciphers.algs();
      const srcString = 'This is a secret 🦆';
      const [clearStream] = streamFromStr(srcString);
      const masterKey = getRandom(cc.KEY_BYTES);
      const extraKeyMaterial = getRandom(16);

      const econtext: EContext = {
         algs: algKeys,
      };

      const encKeyProvider = new MasterKeyKeyProvider(masterKey.slice(0), extraKeyMaterial);
      const cipherData = await readStreamAll(await cipherSvc.encryptStream(clearStream, encKeyProvider, econtext));

      // The outermost loop is what got stored, so it reports the last algorithm
      const infoKeyProvider = new MasterKeyKeyProvider(masterKey.slice(0), extraKeyMaterial);
      const [infoStream] = streamFromBytes(cipherData);
      const cipherInfo = await cipherSvc.getCipherStreamInfo(infoStream, infoKeyProvider);
      expect(cipherInfo.lp).toEqual(algKeys.length);
      expect(cipherInfo.lpEnd).toEqual(algKeys.length);
      expect(cipherInfo.alg).toEqual(algKeys[algKeys.length - 1]);
      expect(cipherInfo.ver).toEqual(cc.CURRENT_VERSION);

      const decKeyProvider = new MasterKeyKeyProvider(masterKey.slice(0), extraKeyMaterial);
      const [decStream] = streamFromBytes(cipherData);
      const decrypted = await cipherSvc.decryptStream(decStream, decKeyProvider);

      const resString = await readStreamAll(decrypted, true);
      expect(resString).toEqual(srcString);
   });

   it('failed round trip, mixed algorithms, loops, wrong extraKeyMaterial', async () => {
      const algKeys = Ciphers.algs();
      const srcString = 'This is a secret 🦆';
      const [clearStream] = streamFromStr(srcString);
      const masterKey = getRandom(cc.KEY_BYTES);
      const extraKeyMaterial = getRandom(16);
      const wrongExtraKeyMaterial = getRandom(16);

      const econtext: EContext = {
         algs: algKeys,
      };

      const encKeyProvider = new MasterKeyKeyProvider(masterKey.slice(0), extraKeyMaterial);
      const cipherStream = await cipherSvc.encryptStream(clearStream, encKeyProvider, econtext);

      const decKeyProvider = new MasterKeyKeyProvider(masterKey.slice(0), wrongExtraKeyMaterial);
      await expect(cipherSvc.decryptStream(cipherStream, decKeyProvider)).rejects.toThrow(/Invalid MAC/);
   });

   it('detect encryption argument errors', async () => {
      const srcString = 'This is a secret 🦆';
      const masterKey = getRandom(cc.KEY_BYTES);
      const extraKeyMaterial = getRandom(16);

      // Prove the arguments are otherwise valid
      const [goodStream] = streamFromStr(srcString);
      const goodKeyProvider = new MasterKeyKeyProvider(masterKey.slice(0), extraKeyMaterial);
      let cipherStream = await cipherSvc.encryptStream(goodStream, goodKeyProvider, { algs: ['X20-PLY'] });

      const decKeyProvider = new MasterKeyKeyProvider(masterKey.slice(0), extraKeyMaterial);
      const decrypted = await cipherSvc.decryptStream(cipherStream, decKeyProvider);
      await expect(readStreamAll(decrypted, true)).resolves.toEqual(srcString);

      // Master keys are not password stretched, so an iteration count is meaningless
      const [icStream] = streamFromStr(srcString);
      const icKeyProvider = new MasterKeyKeyProvider(masterKey.slice(0), extraKeyMaterial);
      cipherStream = await cipherSvc.encryptStream(icStream, icKeyProvider, {
         algs: ['X20-PLY'],
         ic: cc.ICOUNT_MIN,
      });

      await expect(readStreamAll(cipherStream)).rejects.toThrow(/not used by masterkey/);

      expect(() => new MasterKeyKeyProvider(getRandom(cc.KEY_BYTES - 1), extraKeyMaterial)).toThrow(
         /Invalid masterKey length/,
      );
      expect(() => new MasterKeyKeyProvider(new Uint8Array(cc.KEY_BYTES), extraKeyMaterial)).toThrow(/all zero bytes/);
      expect(() => new MasterKeyKeyProvider(masterKey.slice(0), getRandom(cc.EXTRA_BYTES_MAX + 1))).toThrow(
         /Extra key material too long/,
      );
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
               return [pwd];
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
      // BEGIN GENERATED: v8:streamManipulation
      //v8 — generated by: pnpm vectors:ciphersvc
      {
         ver: 8,
         ct: 'srpUsm4F4Q7yci8N3S4Fj33CKqKV8mFswwA9At2vodEIAHYBAAABACik1tEe_0x55PWLUrA5-aPmPmOEs8QJpCjUaVHgyBAAACB_VupvpyZ6CKYMijh08a68_lrZ5acx3ujS3HAMSMeqqSBlPPAT5UNtQzj6nvvEBzZkw6eh-VT7cccbaQE7NEeRU6Eu5WlZ1b4_5RLKk793BfeETkk-Y8K3PsQZD88xqttWHT-fdkmGe07dB_oxsGIQDl7LGDkl7WoCpsfSv8qy-q0yhA-y95biTvPFcfBoBC30_4qWALD86OIsGysX_IpIMjWwM0uQzEzoYlFelD3DgenbSrfD3VYKK_U0TOENtsc1a7P2n45BF01LQSoN-YldSInkzxCS6zKjFcwU_o3MnerbJttT2y5x5af8KDRT9tKuSVgMF1EXcaCHeG4OjbpaCm3fiGqTQPRbalb9YLrXl9BF1o59exRF_k5DUAXoOZfxi4W5cjfCtqddfBMH6SJQzdh0nxclKqllcaCFM05OqrAA-dHD51tmExuserOK6IUGIa_CL5yBEhHkc1qfTaeG9tLPUkm-AJieLg8fpRks-cwIAG8BAAEBAB091VVOZtWRJ50shJndefqohxnKjkswa56q0ev2g6r2dIY7hHEudvrvyvA8vc2HsaXiNZL3Wqe_rHhIqYBvx_xgTmKwTV0emwoYvADG53CndEbooz21y6XFEJp4d373EAem1ieFBGmWgc5qRsjH-cCvF-8dZ6YfwHpYm14rJcJrpkz0nLD-6MnV_sWFQSsgXyvFs6YMrCexAQes85DUlDCOhIykZjaMkdmyzBn95Kaxsf9-GURgYH4UspS9lOQH62qntFnv1IEFbk2obrIS_ucRe0FH6ZsYgJY4tLI92dlEyUyvKwr6yRGtJJJ4kYImWmCONpzzoNhE5EyeUuym2JEZSp6qZxG4L_Rt3u7yel_83j7YBciZl4l9VQ0sLNLOHCFqLSzL4INrQoZn1DzrJ9FsMhWcGpxI0jHn941yhUcsoIx8C_eEnA8E65WL9GKFFw4TmFJdc88JhE7wpt0xgN2VSOnMyxehDltCtio',
         slt: new Uint8Array([176, 57, 249, 163, 230, 62, 99, 132, 179, 196, 9, 164, 40, 212, 105, 81]),
         iv: new Uint8Array([40, 164, 214, 209, 30, 255, 76, 121, 228, 245, 139, 82]),
      },
      // END GENERATED: v8:streamManipulation
   ];

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
            return ['asdf'];
         });
         const dec = await cipherSvc.decryptStream(cipherStream, decKeyProvider);
         await expect(areEqual(dec, clearData)).resolves.toEqual(true);

         const b0Offsets = block0Offsets(cipherData);

         // Modified block0 MAC
         const b0Mac = new Uint8Array(cipherData);
         b0Mac[b0Offsets.mac] = 255;

         let [stream] = streamFromBytes(b0Mac);
         await expect(cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf']))).rejects.toThrow(
            /Invalid MAC.+/,
         );

         // Test modified block0 version
         const b0Ver = new Uint8Array(cipherData);
         b0Ver[b0Offsets.ver] = 22;
         [stream] = streamFromBytes(b0Ver);
         await expect(cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf']))).rejects.toThrow(
            /Invalid version.+/,
         );

         // Test modified block0 size, valid size but too small
         let b0Size = new Uint8Array(cipherData);
         b0Size.set([20, 1], b0Offsets.size);
         [stream] = streamFromBytes(b0Size);
         await expect(cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf']))).rejects.toThrow(
            /Invalid MAC.+/,
         );

         // Too small block0 size, invalid
         b0Size = new Uint8Array(cipherData);
         b0Size.set([0, 0], b0Offsets.size);
         [stream] = streamFromBytes(b0Size);
         await expect(cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf']))).rejects.toThrow(
            /Invalid payload size3.+/,
         );

         // Test too big block0 size
         b0Size = new Uint8Array(cipherData);
         b0Size.set([255, 255, 255], b0Offsets.size);
         [stream] = streamFromBytes(b0Size);
         await expect(cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf']))).rejects.toThrow(
            /Cipher data length mismatch1.+/,
         );

         // Boundary: PAYLOAD_SIZE_MIN - 1 fails the size check
         b0Size = new Uint8Array(cipherData);
         b0Size.set([cc.PAYLOAD_SIZE_MIN - 1, 0, 0], b0Offsets.size);
         [stream] = streamFromBytes(b0Size);
         await expect(cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf']))).rejects.toThrow(
            /Invalid payload size3.+/,
         );

         b0Size = new Uint8Array(cipherData);
         b0Size.set([cc.PAYLOAD_SIZE_MIN, 0, 0], b0Offsets.size);
         [stream] = streamFromBytes(b0Size);
         await expect(cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf']))).rejects.toThrow(
            /Invalid.+/,
         );

         // Test modified block0 flags, invalid
         let b0Flags = new Uint8Array(cipherData);
         b0Flags[b0Offsets.flags] = 6;
         [stream] = streamFromBytes(b0Flags);
         await expect(cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf']))).rejects.toThrow(
            /Invalid flags.+/,
         );

         // Test modified block0 flags, early terminal (detected by MAC first because
         // early term isn't known until next block)
         b0Flags = new Uint8Array(cipherData);
         b0Flags[b0Offsets.flags] = 1;
         [stream] = streamFromBytes(b0Flags);
         await expect(cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf']))).rejects.toThrow(
            /Invalid MAC.+/,
         );
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
               return ['asdf'];
            }),
         );
         await expect(areEqual(dec, clearData)).resolves.toEqual(true);

         const b1Offsets = block1Offsets(cipherdata);

         // Modified blockN MAC
         const bNMac = new Uint8Array(cipherdata);
         bNMac[b1Offsets.mac] = 255;
         let [stream] = streamFromBytes(bNMac);
         dec = await cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf']));
         await expect(readStreamAll(dec)).rejects.toThrow(/Invalid MAC.+/);

         // Modified blockN version
         const bNVer = new Uint8Array(cipherdata);
         bNVer.set([4, 1], b1Offsets.ver);
         [stream] = streamFromBytes(bNVer);
         dec = await cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf']));
         await expect(readStreamAll(dec)).rejects.toThrow(/Invalid version.+/);

         // Test modified blockN size, too small valid
         let bNSize = new Uint8Array(cipherdata);
         bNSize.set([20, 1], b1Offsets.size);
         [stream] = streamFromBytes(bNSize);
         dec = await cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf']));
         await expect(readStreamAll(dec)).rejects.toThrow(/Invalid MAC.+/);

         // Too small blockN size, too small invalid
         bNSize = new Uint8Array(cipherdata);
         bNSize.set([0, 0], b1Offsets.size);
         [stream] = streamFromBytes(bNSize);
         dec = await cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf']));
         await expect(readStreamAll(dec)).rejects.toThrow(/Invalid payload.+/);

         // Test too big blockN but valid
         bNSize = new Uint8Array(cipherdata);
         bNSize.set([255, 255, 255], b1Offsets.size);
         [stream] = streamFromBytes(bNSize);
         dec = await cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf']));
         await expect(readStreamAll(dec)).rejects.toThrow(/Cipher data length mismatch2.+/);

         // Test modified block0 flags, invalid
         let bNFlags = new Uint8Array(cipherdata);
         bNFlags[b1Offsets.flags] = 6;
         [stream] = streamFromBytes(bNFlags);
         dec = await cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf']));
         await expect(readStreamAll(dec)).rejects.toThrow(/Invalid flags.+/);

         // Test modified block0 flags, early terminal (detected by MAC first)
         bNFlags = new Uint8Array(cipherdata);
         bNFlags[b1Offsets.flags] = 0;
         [stream] = streamFromBytes(bNFlags);
         dec = await cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf']));
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
               return ['asdf'];
            }),
         );
         await expect(areEqual(dec, clearData)).resolves.toEqual(true);

         const b0Offsets = block0Offsets(cipherdata);

         // Modified block0 invalid ALG
         let b0Alg = new Uint8Array(cipherdata);
         b0Alg[b0Offsets.alg] = 128;
         let [stream] = streamFromBytes(b0Alg);
         await expect(cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf']))).rejects.toThrow(
            /Unsupported cipher mode.+/,
         );

         // Modified block0 valid but changed ALG
         b0Alg = new Uint8Array(cipherdata);
         b0Alg[b0Offsets.alg] = 2;
         [stream] = streamFromBytes(b0Alg);
         // Error will be different given different cipherdata because changing the alg
         // above changes the IV read len and therefore location of following values.
         // Therefore don't check for specific error message
         await expect(cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf']))).rejects.toThrow(
            Error,
         );

         // Modified block0 IV
         const b0OIV = new Uint8Array(cipherdata);
         b0OIV[b0Offsets.iv] = 0;
         [stream] = streamFromBytes(b0OIV);
         await expect(cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf']))).rejects.toThrow(
            /Invalid MAC.+/,
         );

         // Modified block0 Salt
         const b0Slt = new Uint8Array(cipherdata);
         b0Slt[b0Offsets.slt] = 1;
         [stream] = streamFromBytes(b0Slt);
         await expect(cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf']))).rejects.toThrow(
            /Invalid MAC.+/,
         );

         // Modified block0 invalid IC
         let b0IC = new Uint8Array(cipherdata);
         b0IC.set([0, 0, 0, 0], b0Offsets.ic);
         [stream] = streamFromBytes(b0IC);
         await expect(cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf']))).rejects.toThrow(
            /Invalid MAC.+/,
         );

         // Modified block0 valid but changed IC
         b0IC = new Uint8Array(cipherdata);
         b0IC.set([64, 119, 21, 1], b0Offsets.ic);
         [stream] = streamFromBytes(b0IC);
         await expect(cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf']))).rejects.toThrow(
            /Invalid MAC.+/,
         );

         // Modified block0 IC
         b0IC = new Uint8Array(cipherdata);
         b0IC.set([255, 255, 255, 255], b0Offsets.ic);
         [stream] = streamFromBytes(b0IC);
         await expect(cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf']))).rejects.toThrow(
            /Invalid ic.+/,
         );

         // Modified block0 invalid LPP
         let b0LP = new Uint8Array(cipherdata);
         b0LP[b0Offsets.lp] = 24; // lp > lpEnd
         [stream] = streamFromBytes(b0LP);
         await expect(cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf']))).rejects.toThrow(
            /Invalid lp.+/,
         );

         // Modified block0 valid but changed LPP
         b0LP = new Uint8Array(cipherdata);
         b0LP[b0Offsets.lp] = 48;
         [stream] = streamFromBytes(b0LP);
         await expect(cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf']))).rejects.toThrow(
            /Invalid MAC.+/,
         );

         // From v8 the commitment trails the hint, so a bad hint length also displaces the
         // field the parser reads next and it may object before the MAC is checked
         const badHintLen = /Invalid MAC.+|Invalid commit length.+/;

         // Modified block0 hint length under
         let b0HintLen = new Uint8Array(cipherdata);
         b0HintLen[b0Offsets.hintLen] = 2;
         [stream] = streamFromBytes(b0HintLen);
         await expect(cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf']))).rejects.toThrow(
            badHintLen,
         );

         // Modified block0 hint length over
         b0HintLen = new Uint8Array(cipherdata);
         b0HintLen[b0Offsets.hintLen] = 250;
         [stream] = streamFromBytes(b0HintLen);
         await expect(cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf']))).rejects.toThrow(
            badHintLen,
         );

         // Modified block0 hint
         const b0Hint = new Uint8Array(cipherdata);
         b0Hint[b0Offsets.hint] = 12;
         [stream] = streamFromBytes(b0Hint);
         await expect(cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf']))).rejects.toThrow(
            /Invalid MAC.+/,
         );
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
      const dec = await cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf']));
      await expect(areEqual(dec, clearData)).resolves.toEqual(true);

      // Modified block0 key commitment
      const b0Commit = new Uint8Array(cipherdata);
      b0Commit[commitOffset] ^= 0x01;
      [stream] = streamFromBytes(b0Commit);
      await expect(cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf']))).rejects.toThrow(
         /Invalid MAC.+/,
      );

      // Modified block0 key commitment length
      const b0CommitLen = new Uint8Array(cipherdata);
      b0CommitLen[commitLenOffset] = 0;
      [stream] = streamFromBytes(b0CommitLen);
      await expect(cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf']))).rejects.toThrow(
         /Invalid MAC.+/,
      );

      // Invalid block0 key commitment length
      const b0BadCommitLen = new Uint8Array(cipherdata);
      b0BadCommitLen[commitLenOffset] = 31;
      [stream] = streamFromBytes(b0BadCommitLen);
      await expect(cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf']))).rejects.toThrow(
         /Invalid commit length.+/,
      );
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

      await expect(cipherSvc.decryptStream(stream, new PWDKeyProvider(userCredHere, [pwd]))).rejects.toThrow(
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
               return ['asdf'];
            }),
         );
         await expect(areEqual(dec, clearData)).resolves.toEqual(true);

         const b1Offsets = block1Offsets(cipherdata);

         // Modified blockN invalid ALG
         let bNAlg = new Uint8Array(cipherdata);
         bNAlg[b1Offsets.alg] = 128;
         let [stream] = streamFromBytes(bNAlg);
         dec = await cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf']));
         await expect(readStreamAll(dec)).rejects.toThrow(/Unsupported cipher mode.+/);

         // Modified blockN valid but changed ALG
         bNAlg = new Uint8Array(cipherdata);
         bNAlg[b1Offsets.alg] = 2;
         [stream] = streamFromBytes(bNAlg);
         dec = await cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf']));
         // Error will be different given different cipherdata because changing the alg
         // above changes the IV read len and therefore location of following values.
         // Therefore don't check for specific error message
         await expect(readStreamAll(dec)).rejects.toThrow(Error);

         // Modified blockN IV
         const bNIV = new Uint8Array(cipherdata);
         bNIV[b1Offsets.iv] = 0;
         [stream] = streamFromBytes(bNIV);
         dec = await cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf']));
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
               return ['asdf'];
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
         await expect(cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf']))).rejects.toThrow(
            /Invalid MAC/,
         );

         // Modified blockN encrypted data
         const bNEnc = new Uint8Array(cipherdata);
         bNEnc[b1Offsets.enc] = 0;
         [stream] = streamFromBytes(bNEnc);
         dec = await cipherSvc.decryptStream(stream, new PWDKeyProvider(userCred.slice(0), ['asdf']));
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
            return [pwd];
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
               return [pwd];
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
               return [pwd];
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
               return [pwd];
            });
            await expect(cipherSvc.decryptStream(corruptStream, decKeyProvider)).rejects.toThrow(Error);
         }

         // Appending data after block0 throws and error at stream read since
         // only block0 is validated during stream construction
         const corruptData = concatArrays([cipherData, addData]);
         const [corruptStream] = streamFromBytes(corruptData);

         const corruptKeyProvider = new PWDKeyProvider(userCred.slice(0), async (_cdinfo) => {
            return [pwd];
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
      // BEGIN GENERATED: v8:blockOrder
      //v8 — generated by: pnpm vectors:ciphersvc
      {
         ver: 8,
         goodCt:
            'RrwDC_oLoaZeWhltiIxbuMOjQBUqo-nUCqQdiroJG08IAH8AAAABAOLhq7u9y5XDxCEZuauGPW8TmNjNc3_hf0CX50LgyBAAACCxUxpNySSr6c7D6a0JHaa18Xko87Ez1hQHErgGP1g69SDSDFIg-LXa-Kq0BGhbfkpNW7wdkFE9XKqdkVojPBXiWcZVI28fNNeoFFix1CAmA36KNCm-2xHI9hsBUvzJVrmd-zf27kXJA12d4VYBnPQSwwfRFfUc5r_g7AgAMQAAAAEAUY2MRL7tOdQTBpcZlXx4cjK4wWNG3v4rnH8G6jOSXQGYmoQiLphb8UdkL83sjDpklXljS62xaLs8av7Zere3A_xPdvtUuyZdLjs9H3AqCABDAAAAAQBOcYFLpLlFQ6_rI3XV8rnFBAEk7FhyXqYkwgPP0uDJdm67D_lS_9o44Vcn43uvVA8dLGHjBMdyHV3UCTnpCojizHY1mPXIUINjrmfXN0USjFe1ulDDN9p620H0BB_dDrAIAGcAAAABAIS_CMW4wRSS8u2tq8oame462MGfkfqpkbiM2yH6buPEGifkOUjzF5fl4-w8dhB3tKLkpeT9eqyXmmn0bR33eVcqJew_EuEr4Gtg6AvdGCrM-kGzQhYBxAWKYP8fjcJ4DAzg270oyov-2dpggZgNmsCnCsC-_SoecirJRUQuRS0IUSYZZggArwAAAAEA2qxJ4IjFOkJreUlSw5DM6lEy1p3jEoG1MYdVpLid5SQV2blsdlBc8lW_YVGyf0p6gzJECxQoKPPrCKazmmQkD1LnqDMIhOEgIM70RLkCzsoKApFkDH0hGGI9IMqM-lH5s1p5iaPlYo1R38Zq04jX8hWny0pFo5o2VaOkjsDuwhXNIYdAhbcGFsbB5C2_lMs5seOqmLhVJCaMNJ3eDRnqCyDCodafWh67XfVyYR6qugtZMoiLSSg3YzDAQ8KzWAfgQJWUYEcAbm729X2kCACvAAAAAQDUo5jryeOWtj5p5rPVr0aXytuvV5z18gprl4NlacO4yfzJnIn6CKknh8ERddvMTn913O6q3kVT6cNwRVbfGp-Y-OiosSW11DLUd7xVXyOUPhMqO4pyBK2mxtUbF-1I54VDF6eBXKEROBiPLXihJ1NhfhEkeR-Kja5U6LDa_tFHFRmPjX8ivxymlgez7q31vbOpk3kpSRmeXUQCMTMcam4oS48q7WwszDF4bVaHdg8Ytrs0vTRKKKJ6rF4iNNhIHaTXHgOddRlKd2oftL4IAK8AAAABAMIo8zBXRwINpyKoHfGIEKrwziELu8MXyc5enlbdsvBEunK91aO0jyiY8PCDbtpiZ_VddMTheVQryE_jS1CLcxGy8MT1VYjMraGmjMLR3dzovJEsf0KPDTjZixowJJgteBmDiJaVMJKvzXwxNg7_hEd57cdJG1fnmTow6IQzGqJQHydwVQy3ZTLwUvH-g6r_cQowe-iFogq3qpJQJ0A8Ry2uzr5p-NlwuQrE3QyIrOWsAsSHaNVoW8vtqlbpoH2gwYyb1zPj00msFFpaAwgAOAAAAQEA2BoOqy60wjpSrURNa0hepJA0s49dliZoJecXtEtUSesrU9jIUb0Gm9fm6yHW09z3zZ0UOk8',
         badCts: {
            '1. Block0 Block7 swap':
               'iKzlrALEh2jVaFvL7apW6aB9oMGMm9cz49NJrBRaWgMIADgAAAEBANgaDqsutMI6Uq1ETWtIXqSQNLOPXZYmaCXnF7RLVEnrK1PYyFG9BpvX5ush1tPc982dFDpPAVL8yVa5nfs39u5FyQNdneFWAZz0EsMH0RX1HOa_4OwIADEAAAABAFGNjES-7TnUEwaXGZV8eHIyuMFjRt7-K5x_Buozkl0BmJqEIi6YW_FHZC_N7Iw6ZJV5Y0utsWi7PGr-2Xq3twP8T3b7VLsmXS47PR9wKggAQwAAAAEATnGBS6S5RUOv6yN11fK5xQQBJOxYcl6mJMIDz9LgyXZuuw_5Uv_aOOFXJ-N7r1QPHSxh4wTHch1d1Ak56QqI4sx2NZj1yFCDY65n1zdFEoxXtbpQwzfaettB9AQf3Q6wCABnAAAAAQCEvwjFuMEUkvLtravKGpnuOtjBn5H6qZG4jNsh-m7jxBon5DlI8xeX5ePsPHYQd7Si5KXk_Xqsl5pp9G0d93lXKiXsPxLhK-BrYOgL3RgqzPpBs0IWAcQFimD_H43CeAwM4Nu9KMqL_tnaYIGYDZrApwrAvv0qHnIqyUVELkUtCFEmGWYIAK8AAAABANqsSeCIxTpCa3lJUsOQzOpRMtad4xKBtTGHVaS4neUkFdm5bHZQXPJVv2FRsn9KeoMyRAsUKCjz6wims5pkJA9S56gzCIThICDO9ES5As7KCgKRZAx9IRhiPSDKjPpR-bNaeYmj5WKNUd_GatOI1_IVp8tKRaOaNlWjpI7A7sIVzSGHQIW3BhbGweQtv5TLObHjqpi4VSQmjDSd3g0Z6gsgwqHWn1oeu131cmEeqroLWTKIi0koN2MwwEPCs1gH4ECVlGBHAG5u9vV9pAgArwAAAAEA1KOY68njlrY-aeaz1a9Gl8rbr1ec9fIKa5eDZWnDuMn8yZyJ-gipJ4fBEXXbzE5_ddzuqt5FU-nDcEVW3xqfmPjoqLEltdQy1He8VV8jlD4TKjuKcgStpsbVGxftSOeFQxengVyhETgYjy14oSdTYX4RJHkfio2uVOiw2v7RRxUZj41_Ir8cppYHs-6t9b2zqZN5KUkZnl1EAjEzHGpuKEuPKu1sLMwxeG1Wh3YPGLa7NL00SiiieqxeIjTYSB2k1x4DnXUZSndqH7S-CACvAAAAAQDCKPMwV0cCDaciqB3xiBCq8M4hC7vDF8nOXp5W3bLwRLpyvdWjtI8omPDwg27aYmf1XXTE4XlUK8hP40tQi3MRsvDE9VWIzK2hpozC0d3c6LyRLH9Cjw042YsaMCSYLXgZg4iWlTCSr818MTYO_4RHee3HSRtX55k6MOiEMxqiUB8ncFUMt2Uy8FLx_oOq_3EKMHvohaIKt6qSUCdAPEctrs6-afjZcLkKxN0MRrwDC_oLoaZeWhltiIxbuMOjQBUqo-nUCqQdiroJG08IAH8AAAABAOLhq7u9y5XDxCEZuauGPW8TmNjNc3_hf0CX50LgyBAAACCxUxpNySSr6c7D6a0JHaa18Xko87Ez1hQHErgGP1g69SDSDFIg-LXa-Kq0BGhbfkpNW7wdkFE9XKqdkVojPBXiWcZVI28fNNeoFFix1CAmA36KNCm-2xHI9hs',
            '2. Block1 Block7 swap':
               'RrwDC_oLoaZeWhltiIxbuMOjQBUqo-nUCqQdiroJG08IAH8AAAABAOLhq7u9y5XDxCEZuauGPW8TmNjNc3_hf0CX50LgyBAAACCxUxpNySSr6c7D6a0JHaa18Xko87Ez1hQHErgGP1g69SDSDFIg-LXa-Kq0BGhbfkpNW7wdkFE9XKqdkVojPBXiWcZVI28fNNeoFFix1CAmA36KNCm-2xHI9huIrOWsAsSHaNVoW8vtqlbpoH2gwYyb1zPj00msFFpaAwgAOAAAAQEA2BoOqy60wjpSrURNa0hepJA0s49dliZoJecXtEtUSesrU9jIUb0Gm9fm6yHW09z3zZ0UOk86ZJV5Y0utsWi7PGr-2Xq3twP8T3b7VLsmXS47PR9wKggAQwAAAAEATnGBS6S5RUOv6yN11fK5xQQBJOxYcl6mJMIDz9LgyXZuuw_5Uv_aOOFXJ-N7r1QPHSxh4wTHch1d1Ak56QqI4sx2NZj1yFCDY65n1zdFEoxXtbpQwzfaettB9AQf3Q6wCABnAAAAAQCEvwjFuMEUkvLtravKGpnuOtjBn5H6qZG4jNsh-m7jxBon5DlI8xeX5ePsPHYQd7Si5KXk_Xqsl5pp9G0d93lXKiXsPxLhK-BrYOgL3RgqzPpBs0IWAcQFimD_H43CeAwM4Nu9KMqL_tnaYIGYDZrApwrAvv0qHnIqyUVELkUtCFEmGWYIAK8AAAABANqsSeCIxTpCa3lJUsOQzOpRMtad4xKBtTGHVaS4neUkFdm5bHZQXPJVv2FRsn9KeoMyRAsUKCjz6wims5pkJA9S56gzCIThICDO9ES5As7KCgKRZAx9IRhiPSDKjPpR-bNaeYmj5WKNUd_GatOI1_IVp8tKRaOaNlWjpI7A7sIVzSGHQIW3BhbGweQtv5TLObHjqpi4VSQmjDSd3g0Z6gsgwqHWn1oeu131cmEeqroLWTKIi0koN2MwwEPCs1gH4ECVlGBHAG5u9vV9pAgArwAAAAEA1KOY68njlrY-aeaz1a9Gl8rbr1ec9fIKa5eDZWnDuMn8yZyJ-gipJ4fBEXXbzE5_ddzuqt5FU-nDcEVW3xqfmPjoqLEltdQy1He8VV8jlD4TKjuKcgStpsbVGxftSOeFQxengVyhETgYjy14oSdTYX4RJHkfio2uVOiw2v7RRxUZj41_Ir8cppYHs-6t9b2zqZN5KUkZnl1EAjEzHGpuKEuPKu1sLMwxeG1Wh3YPGLa7NL00SiiieqxeIjTYSB2k1x4DnXUZSndqH7S-CACvAAAAAQDCKPMwV0cCDaciqB3xiBCq8M4hC7vDF8nOXp5W3bLwRLpyvdWjtI8omPDwg27aYmf1XXTE4XlUK8hP40tQi3MRsvDE9VWIzK2hpozC0d3c6LyRLH9Cjw042YsaMCSYLXgZg4iWlTCSr818MTYO_4RHee3HSRtX55k6MOiEMxqiUB8ncFUMt2Uy8FLx_oOq_3EKMHvohaIKt6qSUCdAPEctrs6-afjZcLkKxN0MAVL8yVa5nfs39u5FyQNdneFWAZz0EsMH0RX1HOa_4OwIADEAAAABAFGNjES-7TnUEwaXGZV8eHIyuMFjRt7-K5x_Buozkl0BmJqEIi6YW_FHZC_N7Iw',
            '3. Block1 Block4 swap':
               'RrwDC_oLoaZeWhltiIxbuMOjQBUqo-nUCqQdiroJG08IAH8AAAABAOLhq7u9y5XDxCEZuauGPW8TmNjNc3_hf0CX50LgyBAAACCxUxpNySSr6c7D6a0JHaa18Xko87Ez1hQHErgGP1g69SDSDFIg-LXa-Kq0BGhbfkpNW7wdkFE9XKqdkVojPBXiWcZVI28fNNeoFFix1CAmA36KNCm-2xHI9hsoyov-2dpggZgNmsCnCsC-_SoecirJRUQuRS0IUSYZZggArwAAAAEA2qxJ4IjFOkJreUlSw5DM6lEy1p3jEoG1MYdVpLid5SQV2blsdlBc8lW_YVGyf0p6gzJECxQoKPPrCKazmmQkD1LnqDMIhOEgIM70RLkCzsoKApFkDH0hGGI9IMqM-lH5s1p5iaPlYo1R38Zq04jX8hWny0pFo5o2VaOkjsDuwhXNIYdAhbcGFsbB5C2_lMs5seOqmLhVJCaMNJ3eDRnqCyDCodafWh67XfVyYTpklXljS62xaLs8av7Zere3A_xPdvtUuyZdLjs9H3AqCABDAAAAAQBOcYFLpLlFQ6_rI3XV8rnFBAEk7FhyXqYkwgPP0uDJdm67D_lS_9o44Vcn43uvVA8dLGHjBMdyHV3UCTnpCojizHY1mPXIUINjrmfXN0USjFe1ulDDN9p620H0BB_dDrAIAGcAAAABAIS_CMW4wRSS8u2tq8oame462MGfkfqpkbiM2yH6buPEGifkOUjzF5fl4-w8dhB3tKLkpeT9eqyXmmn0bR33eVcqJew_EuEr4Gtg6AvdGCrM-kGzQhYBxAWKYP8fjcJ4DAzg270BUvzJVrmd-zf27kXJA12d4VYBnPQSwwfRFfUc5r_g7AgAMQAAAAEAUY2MRL7tOdQTBpcZlXx4cjK4wWNG3v4rnH8G6jOSXQGYmoQiLphb8UdkL83sjB6qugtZMoiLSSg3YzDAQ8KzWAfgQJWUYEcAbm729X2kCACvAAAAAQDUo5jryeOWtj5p5rPVr0aXytuvV5z18gprl4NlacO4yfzJnIn6CKknh8ERddvMTn913O6q3kVT6cNwRVbfGp-Y-OiosSW11DLUd7xVXyOUPhMqO4pyBK2mxtUbF-1I54VDF6eBXKEROBiPLXihJ1NhfhEkeR-Kja5U6LDa_tFHFRmPjX8ivxymlgez7q31vbOpk3kpSRmeXUQCMTMcam4oS48q7WwszDF4bVaHdg8Ytrs0vTRKKKJ6rF4iNNhIHaTXHgOddRlKd2oftL4IAK8AAAABAMIo8zBXRwINpyKoHfGIEKrwziELu8MXyc5enlbdsvBEunK91aO0jyiY8PCDbtpiZ_VddMTheVQryE_jS1CLcxGy8MT1VYjMraGmjMLR3dzovJEsf0KPDTjZixowJJgteBmDiJaVMJKvzXwxNg7_hEd57cdJG1fnmTow6IQzGqJQHydwVQy3ZTLwUvH-g6r_cQowe-iFogq3qpJQJ0A8Ry2uzr5p-NlwuQrE3QyIrOWsAsSHaNVoW8vtqlbpoH2gwYyb1zPj00msFFpaAwgAOAAAAQEA2BoOqy60wjpSrURNa0hepJA0s49dliZoJecXtEtUSesrU9jIUb0Gm9fm6yHW09z3zZ0UOk8',
            '4. Block0 repeated':
               'RrwDC_oLoaZeWhltiIxbuMOjQBUqo-nUCqQdiroJG08IAH8AAAABAOLhq7u9y5XDxCEZuauGPW8TmNjNc3_hf0CX50LgyBAAACCxUxpNySSr6c7D6a0JHaa18Xko87Ez1hQHErgGP1g69SDSDFIg-LXa-Kq0BGhbfkpNW7wdkFE9XKqdkVojPBXiWcZVI28fNNeoFFix1CAmA36KNCm-2xHI9htGvAML-guhpl5aGW2IjFu4w6NAFSqj6dQKpB2KugkbTwgAfwAAAAEA4uGru73LlcPEIRm5q4Y9bxOY2M1zf-F_QJfnQuDIEAAAILFTGk3JJKvpzsPprQkdprXxeSjzsTPWFAcSuAY_WDr1INIMUiD4tdr4qrQEaFt-Sk1bvB2QUT1cqp2RWiM8FeJZxlUjbx8016gUWLHUICYDfoo0Kb7bEcj2GwFS_MlWuZ37N_buRckDXZ3hVgGc9BLDB9EV9Rzmv-DsCAAxAAAAAQBRjYxEvu051BMGlxmVfHhyMrjBY0be_iucfwbqM5JdAZiahCIumFvxR2QvzeyMOmSVeWNLrbFouzxq_tl6t7cD_E92-1S7Jl0uOz0fcCoIAEMAAAABAE5xgUukuUVDr-sjddXyucUEASTsWHJepiTCA8_S4Ml2brsP-VL_2jjhVyfje69UDx0sYeMEx3IdXdQJOekKiOLMdjWY9chQg2OuZ9c3RRKMV7W6UMM32nrbQfQEH90OsAgAZwAAAAEAhL8IxbjBFJLy7a2ryhqZ7jrYwZ-R-qmRuIzbIfpu48QaJ-Q5SPMXl-Xj7Dx2EHe0ouSl5P16rJeaafRtHfd5Vyol7D8S4Svga2DoC90YKsz6QbNCFgHEBYpg_x-NwngMDODbvSjKi_7Z2mCBmA2awKcKwL79Kh5yKslFRC5FLQhRJhlmCACvAAAAAQDarEngiMU6Qmt5SVLDkMzqUTLWneMSgbUxh1WkuJ3lJBXZuWx2UFzyVb9hUbJ_SnqDMkQLFCgo8-sIprOaZCQPUueoMwiE4SAgzvREuQLOygoCkWQMfSEYYj0gyoz6UfmzWnmJo-VijVHfxmrTiNfyFafLSkWjmjZVo6SOwO7CFc0hh0CFtwYWxsHkLb-Uyzmx46qYuFUkJow0nd4NGeoLIMKh1p9aHrtd9XJhHqq6C1kyiItJKDdjMMBDwrNYB-BAlZRgRwBubvb1faQIAK8AAAABANSjmOvJ45a2Pmnms9WvRpfK269XnPXyCmuXg2Vpw7jJ_MmcifoIqSeHwRF128xOf3Xc7qreRVPpw3BFVt8an5j46KixJbXUMtR3vFVfI5Q-Eyo7inIErabG1RsX7UjnhUMXp4FcoRE4GI8teKEnU2F-ESR5H4qNrlTosNr-0UcVGY-NfyK_HKaWB7PurfW9s6mTeSlJGZ5dRAIxMxxqbihLjyrtbCzMMXhtVod2Dxi2uzS9NEooonqsXiI02EgdpNceA511GUp3ah-0vggArwAAAAEAwijzMFdHAg2nIqgd8YgQqvDOIQu7wxfJzl6eVt2y8ES6cr3Vo7SPKJjw8INu2mJn9V10xOF5VCvIT-NLUItzEbLwxPVViMytoaaMwtHd3Oi8kSx_Qo8NONmLGjAkmC14GYOIlpUwkq_NfDE2Dv-ER3ntx0kbV-eZOjDohDMaolAfJ3BVDLdlMvBS8f6Dqv9xCjB76IWiCreqklAnQDxHLa7Ovmn42XC5CsTdDIis5awCxIdo1Whby-2qVumgfaDBjJvXM-PTSawUWloDCAA4AAABAQDYGg6rLrTCOlKtRE1rSF6kkDSzj12WJmgl5xe0S1RJ6ytT2MhRvQab1-brIdbT3PfNnRQ6Tw',
            '5. Block0 deleted':
               'AVL8yVa5nfs39u5FyQNdneFWAZz0EsMH0RX1HOa_4OwIADEAAAABAFGNjES-7TnUEwaXGZV8eHIyuMFjRt7-K5x_Buozkl0BmJqEIi6YW_FHZC_N7Iw6ZJV5Y0utsWi7PGr-2Xq3twP8T3b7VLsmXS47PR9wKggAQwAAAAEATnGBS6S5RUOv6yN11fK5xQQBJOxYcl6mJMIDz9LgyXZuuw_5Uv_aOOFXJ-N7r1QPHSxh4wTHch1d1Ak56QqI4sx2NZj1yFCDY65n1zdFEoxXtbpQwzfaettB9AQf3Q6wCABnAAAAAQCEvwjFuMEUkvLtravKGpnuOtjBn5H6qZG4jNsh-m7jxBon5DlI8xeX5ePsPHYQd7Si5KXk_Xqsl5pp9G0d93lXKiXsPxLhK-BrYOgL3RgqzPpBs0IWAcQFimD_H43CeAwM4Nu9KMqL_tnaYIGYDZrApwrAvv0qHnIqyUVELkUtCFEmGWYIAK8AAAABANqsSeCIxTpCa3lJUsOQzOpRMtad4xKBtTGHVaS4neUkFdm5bHZQXPJVv2FRsn9KeoMyRAsUKCjz6wims5pkJA9S56gzCIThICDO9ES5As7KCgKRZAx9IRhiPSDKjPpR-bNaeYmj5WKNUd_GatOI1_IVp8tKRaOaNlWjpI7A7sIVzSGHQIW3BhbGweQtv5TLObHjqpi4VSQmjDSd3g0Z6gsgwqHWn1oeu131cmEeqroLWTKIi0koN2MwwEPCs1gH4ECVlGBHAG5u9vV9pAgArwAAAAEA1KOY68njlrY-aeaz1a9Gl8rbr1ec9fIKa5eDZWnDuMn8yZyJ-gipJ4fBEXXbzE5_ddzuqt5FU-nDcEVW3xqfmPjoqLEltdQy1He8VV8jlD4TKjuKcgStpsbVGxftSOeFQxengVyhETgYjy14oSdTYX4RJHkfio2uVOiw2v7RRxUZj41_Ir8cppYHs-6t9b2zqZN5KUkZnl1EAjEzHGpuKEuPKu1sLMwxeG1Wh3YPGLa7NL00SiiieqxeIjTYSB2k1x4DnXUZSndqH7S-CACvAAAAAQDCKPMwV0cCDaciqB3xiBCq8M4hC7vDF8nOXp5W3bLwRLpyvdWjtI8omPDwg27aYmf1XXTE4XlUK8hP40tQi3MRsvDE9VWIzK2hpozC0d3c6LyRLH9Cjw042YsaMCSYLXgZg4iWlTCSr818MTYO_4RHee3HSRtX55k6MOiEMxqiUB8ncFUMt2Uy8FLx_oOq_3EKMHvohaIKt6qSUCdAPEctrs6-afjZcLkKxN0MiKzlrALEh2jVaFvL7apW6aB9oMGMm9cz49NJrBRaWgMIADgAAAEBANgaDqsutMI6Uq1ETWtIXqSQNLOPXZYmaCXnF7RLVEnrK1PYyFG9BpvX5ush1tPc982dFDpP',
            '6. Block1 repeated':
               'RrwDC_oLoaZeWhltiIxbuMOjQBUqo-nUCqQdiroJG08IAH8AAAABAOLhq7u9y5XDxCEZuauGPW8TmNjNc3_hf0CX50LgyBAAACCxUxpNySSr6c7D6a0JHaa18Xko87Ez1hQHErgGP1g69SDSDFIg-LXa-Kq0BGhbfkpNW7wdkFE9XKqdkVojPBXiWcZVI28fNNeoFFix1CAmA36KNCm-2xHI9hsBUvzJVrmd-zf27kXJA12d4VYBnPQSwwfRFfUc5r_g7AgAMQAAAAEAUY2MRL7tOdQTBpcZlXx4cjK4wWNG3v4rnH8G6jOSXQGYmoQiLphb8UdkL83sjAFS_MlWuZ37N_buRckDXZ3hVgGc9BLDB9EV9Rzmv-DsCAAxAAAAAQBRjYxEvu051BMGlxmVfHhyMrjBY0be_iucfwbqM5JdAZiahCIumFvxR2QvzeyMOmSVeWNLrbFouzxq_tl6t7cD_E92-1S7Jl0uOz0fcCoIAEMAAAABAE5xgUukuUVDr-sjddXyucUEASTsWHJepiTCA8_S4Ml2brsP-VL_2jjhVyfje69UDx0sYeMEx3IdXdQJOekKiOLMdjWY9chQg2OuZ9c3RRKMV7W6UMM32nrbQfQEH90OsAgAZwAAAAEAhL8IxbjBFJLy7a2ryhqZ7jrYwZ-R-qmRuIzbIfpu48QaJ-Q5SPMXl-Xj7Dx2EHe0ouSl5P16rJeaafRtHfd5Vyol7D8S4Svga2DoC90YKsz6QbNCFgHEBYpg_x-NwngMDODbvSjKi_7Z2mCBmA2awKcKwL79Kh5yKslFRC5FLQhRJhlmCACvAAAAAQDarEngiMU6Qmt5SVLDkMzqUTLWneMSgbUxh1WkuJ3lJBXZuWx2UFzyVb9hUbJ_SnqDMkQLFCgo8-sIprOaZCQPUueoMwiE4SAgzvREuQLOygoCkWQMfSEYYj0gyoz6UfmzWnmJo-VijVHfxmrTiNfyFafLSkWjmjZVo6SOwO7CFc0hh0CFtwYWxsHkLb-Uyzmx46qYuFUkJow0nd4NGeoLIMKh1p9aHrtd9XJhHqq6C1kyiItJKDdjMMBDwrNYB-BAlZRgRwBubvb1faQIAK8AAAABANSjmOvJ45a2Pmnms9WvRpfK269XnPXyCmuXg2Vpw7jJ_MmcifoIqSeHwRF128xOf3Xc7qreRVPpw3BFVt8an5j46KixJbXUMtR3vFVfI5Q-Eyo7inIErabG1RsX7UjnhUMXp4FcoRE4GI8teKEnU2F-ESR5H4qNrlTosNr-0UcVGY-NfyK_HKaWB7PurfW9s6mTeSlJGZ5dRAIxMxxqbihLjyrtbCzMMXhtVod2Dxi2uzS9NEooonqsXiI02EgdpNceA511GUp3ah-0vggArwAAAAEAwijzMFdHAg2nIqgd8YgQqvDOIQu7wxfJzl6eVt2y8ES6cr3Vo7SPKJjw8INu2mJn9V10xOF5VCvIT-NLUItzEbLwxPVViMytoaaMwtHd3Oi8kSx_Qo8NONmLGjAkmC14GYOIlpUwkq_NfDE2Dv-ER3ntx0kbV-eZOjDohDMaolAfJ3BVDLdlMvBS8f6Dqv9xCjB76IWiCreqklAnQDxHLa7Ovmn42XC5CsTdDIis5awCxIdo1Whby-2qVumgfaDBjJvXM-PTSawUWloDCAA4AAABAQDYGg6rLrTCOlKtRE1rSF6kkDSzj12WJmgl5xe0S1RJ6ytT2MhRvQab1-brIdbT3PfNnRQ6Tw',
            '7. Block1 deleted':
               'RrwDC_oLoaZeWhltiIxbuMOjQBUqo-nUCqQdiroJG08IAH8AAAABAOLhq7u9y5XDxCEZuauGPW8TmNjNc3_hf0CX50LgyBAAACCxUxpNySSr6c7D6a0JHaa18Xko87Ez1hQHErgGP1g69SDSDFIg-LXa-Kq0BGhbfkpNW7wdkFE9XKqdkVojPBXiWcZVI28fNNeoFFix1CAmA36KNCm-2xHI9hs6ZJV5Y0utsWi7PGr-2Xq3twP8T3b7VLsmXS47PR9wKggAQwAAAAEATnGBS6S5RUOv6yN11fK5xQQBJOxYcl6mJMIDz9LgyXZuuw_5Uv_aOOFXJ-N7r1QPHSxh4wTHch1d1Ak56QqI4sx2NZj1yFCDY65n1zdFEoxXtbpQwzfaettB9AQf3Q6wCABnAAAAAQCEvwjFuMEUkvLtravKGpnuOtjBn5H6qZG4jNsh-m7jxBon5DlI8xeX5ePsPHYQd7Si5KXk_Xqsl5pp9G0d93lXKiXsPxLhK-BrYOgL3RgqzPpBs0IWAcQFimD_H43CeAwM4Nu9KMqL_tnaYIGYDZrApwrAvv0qHnIqyUVELkUtCFEmGWYIAK8AAAABANqsSeCIxTpCa3lJUsOQzOpRMtad4xKBtTGHVaS4neUkFdm5bHZQXPJVv2FRsn9KeoMyRAsUKCjz6wims5pkJA9S56gzCIThICDO9ES5As7KCgKRZAx9IRhiPSDKjPpR-bNaeYmj5WKNUd_GatOI1_IVp8tKRaOaNlWjpI7A7sIVzSGHQIW3BhbGweQtv5TLObHjqpi4VSQmjDSd3g0Z6gsgwqHWn1oeu131cmEeqroLWTKIi0koN2MwwEPCs1gH4ECVlGBHAG5u9vV9pAgArwAAAAEA1KOY68njlrY-aeaz1a9Gl8rbr1ec9fIKa5eDZWnDuMn8yZyJ-gipJ4fBEXXbzE5_ddzuqt5FU-nDcEVW3xqfmPjoqLEltdQy1He8VV8jlD4TKjuKcgStpsbVGxftSOeFQxengVyhETgYjy14oSdTYX4RJHkfio2uVOiw2v7RRxUZj41_Ir8cppYHs-6t9b2zqZN5KUkZnl1EAjEzHGpuKEuPKu1sLMwxeG1Wh3YPGLa7NL00SiiieqxeIjTYSB2k1x4DnXUZSndqH7S-CACvAAAAAQDCKPMwV0cCDaciqB3xiBCq8M4hC7vDF8nOXp5W3bLwRLpyvdWjtI8omPDwg27aYmf1XXTE4XlUK8hP40tQi3MRsvDE9VWIzK2hpozC0d3c6LyRLH9Cjw042YsaMCSYLXgZg4iWlTCSr818MTYO_4RHee3HSRtX55k6MOiEMxqiUB8ncFUMt2Uy8FLx_oOq_3EKMHvohaIKt6qSUCdAPEctrs6-afjZcLkKxN0MiKzlrALEh2jVaFvL7apW6aB9oMGMm9cz49NJrBRaWgMIADgAAAEBANgaDqsutMI6Uq1ETWtIXqSQNLOPXZYmaCXnF7RLVEnrK1PYyFG9BpvX5ush1tPc982dFDpP',
            '8. Block2 repeated':
               'RrwDC_oLoaZeWhltiIxbuMOjQBUqo-nUCqQdiroJG08IAH8AAAABAOLhq7u9y5XDxCEZuauGPW8TmNjNc3_hf0CX50LgyBAAACCxUxpNySSr6c7D6a0JHaa18Xko87Ez1hQHErgGP1g69SDSDFIg-LXa-Kq0BGhbfkpNW7wdkFE9XKqdkVojPBXiWcZVI28fNNeoFFix1CAmA36KNCm-2xHI9hsBUvzJVrmd-zf27kXJA12d4VYBnPQSwwfRFfUc5r_g7AgAMQAAAAEAUY2MRL7tOdQTBpcZlXx4cjK4wWNG3v4rnH8G6jOSXQGYmoQiLphb8UdkL83sjDpklXljS62xaLs8av7Zere3A_xPdvtUuyZdLjs9H3AqCABDAAAAAQBOcYFLpLlFQ6_rI3XV8rnFBAEk7FhyXqYkwgPP0uDJdm67D_lS_9o44Vcn43uvVA8dLGHjBMdyHV3UCTnpCojiOmSVeWNLrbFouzxq_tl6t7cD_E92-1S7Jl0uOz0fcCoIAEMAAAABAE5xgUukuUVDr-sjddXyucUEASTsWHJepiTCA8_S4Ml2brsP-VL_2jjhVyfje69UDx0sYeMEx3IdXdQJOekKiOLMdjWY9chQg2OuZ9c3RRKMV7W6UMM32nrbQfQEH90OsAgAZwAAAAEAhL8IxbjBFJLy7a2ryhqZ7jrYwZ-R-qmRuIzbIfpu48QaJ-Q5SPMXl-Xj7Dx2EHe0ouSl5P16rJeaafRtHfd5Vyol7D8S4Svga2DoC90YKsz6QbNCFgHEBYpg_x-NwngMDODbvSjKi_7Z2mCBmA2awKcKwL79Kh5yKslFRC5FLQhRJhlmCACvAAAAAQDarEngiMU6Qmt5SVLDkMzqUTLWneMSgbUxh1WkuJ3lJBXZuWx2UFzyVb9hUbJ_SnqDMkQLFCgo8-sIprOaZCQPUueoMwiE4SAgzvREuQLOygoCkWQMfSEYYj0gyoz6UfmzWnmJo-VijVHfxmrTiNfyFafLSkWjmjZVo6SOwO7CFc0hh0CFtwYWxsHkLb-Uyzmx46qYuFUkJow0nd4NGeoLIMKh1p9aHrtd9XJhHqq6C1kyiItJKDdjMMBDwrNYB-BAlZRgRwBubvb1faQIAK8AAAABANSjmOvJ45a2Pmnms9WvRpfK269XnPXyCmuXg2Vpw7jJ_MmcifoIqSeHwRF128xOf3Xc7qreRVPpw3BFVt8an5j46KixJbXUMtR3vFVfI5Q-Eyo7inIErabG1RsX7UjnhUMXp4FcoRE4GI8teKEnU2F-ESR5H4qNrlTosNr-0UcVGY-NfyK_HKaWB7PurfW9s6mTeSlJGZ5dRAIxMxxqbihLjyrtbCzMMXhtVod2Dxi2uzS9NEooonqsXiI02EgdpNceA511GUp3ah-0vggArwAAAAEAwijzMFdHAg2nIqgd8YgQqvDOIQu7wxfJzl6eVt2y8ES6cr3Vo7SPKJjw8INu2mJn9V10xOF5VCvIT-NLUItzEbLwxPVViMytoaaMwtHd3Oi8kSx_Qo8NONmLGjAkmC14GYOIlpUwkq_NfDE2Dv-ER3ntx0kbV-eZOjDohDMaolAfJ3BVDLdlMvBS8f6Dqv9xCjB76IWiCreqklAnQDxHLa7Ovmn42XC5CsTdDIis5awCxIdo1Whby-2qVumgfaDBjJvXM-PTSawUWloDCAA4AAABAQDYGg6rLrTCOlKtRE1rSF6kkDSzj12WJmgl5xe0S1RJ6ytT2MhRvQab1-brIdbT3PfNnRQ6Tw',
            '9. Block2 deleted':
               'RrwDC_oLoaZeWhltiIxbuMOjQBUqo-nUCqQdiroJG08IAH8AAAABAOLhq7u9y5XDxCEZuauGPW8TmNjNc3_hf0CX50LgyBAAACCxUxpNySSr6c7D6a0JHaa18Xko87Ez1hQHErgGP1g69SDSDFIg-LXa-Kq0BGhbfkpNW7wdkFE9XKqdkVojPBXiWcZVI28fNNeoFFix1CAmA36KNCm-2xHI9hsBUvzJVrmd-zf27kXJA12d4VYBnPQSwwfRFfUc5r_g7AgAMQAAAAEAUY2MRL7tOdQTBpcZlXx4cjK4wWNG3v4rnH8G6jOSXQGYmoQiLphb8UdkL83sjMx2NZj1yFCDY65n1zdFEoxXtbpQwzfaettB9AQf3Q6wCABnAAAAAQCEvwjFuMEUkvLtravKGpnuOtjBn5H6qZG4jNsh-m7jxBon5DlI8xeX5ePsPHYQd7Si5KXk_Xqsl5pp9G0d93lXKiXsPxLhK-BrYOgL3RgqzPpBs0IWAcQFimD_H43CeAwM4Nu9KMqL_tnaYIGYDZrApwrAvv0qHnIqyUVELkUtCFEmGWYIAK8AAAABANqsSeCIxTpCa3lJUsOQzOpRMtad4xKBtTGHVaS4neUkFdm5bHZQXPJVv2FRsn9KeoMyRAsUKCjz6wims5pkJA9S56gzCIThICDO9ES5As7KCgKRZAx9IRhiPSDKjPpR-bNaeYmj5WKNUd_GatOI1_IVp8tKRaOaNlWjpI7A7sIVzSGHQIW3BhbGweQtv5TLObHjqpi4VSQmjDSd3g0Z6gsgwqHWn1oeu131cmEeqroLWTKIi0koN2MwwEPCs1gH4ECVlGBHAG5u9vV9pAgArwAAAAEA1KOY68njlrY-aeaz1a9Gl8rbr1ec9fIKa5eDZWnDuMn8yZyJ-gipJ4fBEXXbzE5_ddzuqt5FU-nDcEVW3xqfmPjoqLEltdQy1He8VV8jlD4TKjuKcgStpsbVGxftSOeFQxengVyhETgYjy14oSdTYX4RJHkfio2uVOiw2v7RRxUZj41_Ir8cppYHs-6t9b2zqZN5KUkZnl1EAjEzHGpuKEuPKu1sLMwxeG1Wh3YPGLa7NL00SiiieqxeIjTYSB2k1x4DnXUZSndqH7S-CACvAAAAAQDCKPMwV0cCDaciqB3xiBCq8M4hC7vDF8nOXp5W3bLwRLpyvdWjtI8omPDwg27aYmf1XXTE4XlUK8hP40tQi3MRsvDE9VWIzK2hpozC0d3c6LyRLH9Cjw042YsaMCSYLXgZg4iWlTCSr818MTYO_4RHee3HSRtX55k6MOiEMxqiUB8ncFUMt2Uy8FLx_oOq_3EKMHvohaIKt6qSUCdAPEctrs6-afjZcLkKxN0MiKzlrALEh2jVaFvL7apW6aB9oMGMm9cz49NJrBRaWgMIADgAAAEBANgaDqsutMI6Uq1ETWtIXqSQNLOPXZYmaCXnF7RLVEnrK1PYyFG9BpvX5ush1tPc982dFDpP',
            '10. Block7 (last) repeated':
               'RrwDC_oLoaZeWhltiIxbuMOjQBUqo-nUCqQdiroJG08IAH8AAAABAOLhq7u9y5XDxCEZuauGPW8TmNjNc3_hf0CX50LgyBAAACCxUxpNySSr6c7D6a0JHaa18Xko87Ez1hQHErgGP1g69SDSDFIg-LXa-Kq0BGhbfkpNW7wdkFE9XKqdkVojPBXiWcZVI28fNNeoFFix1CAmA36KNCm-2xHI9hsBUvzJVrmd-zf27kXJA12d4VYBnPQSwwfRFfUc5r_g7AgAMQAAAAEAUY2MRL7tOdQTBpcZlXx4cjK4wWNG3v4rnH8G6jOSXQGYmoQiLphb8UdkL83sjDpklXljS62xaLs8av7Zere3A_xPdvtUuyZdLjs9H3AqCABDAAAAAQBOcYFLpLlFQ6_rI3XV8rnFBAEk7FhyXqYkwgPP0uDJdm67D_lS_9o44Vcn43uvVA8dLGHjBMdyHV3UCTnpCojizHY1mPXIUINjrmfXN0USjFe1ulDDN9p620H0BB_dDrAIAGcAAAABAIS_CMW4wRSS8u2tq8oame462MGfkfqpkbiM2yH6buPEGifkOUjzF5fl4-w8dhB3tKLkpeT9eqyXmmn0bR33eVcqJew_EuEr4Gtg6AvdGCrM-kGzQhYBxAWKYP8fjcJ4DAzg270oyov-2dpggZgNmsCnCsC-_SoecirJRUQuRS0IUSYZZggArwAAAAEA2qxJ4IjFOkJreUlSw5DM6lEy1p3jEoG1MYdVpLid5SQV2blsdlBc8lW_YVGyf0p6gzJECxQoKPPrCKazmmQkD1LnqDMIhOEgIM70RLkCzsoKApFkDH0hGGI9IMqM-lH5s1p5iaPlYo1R38Zq04jX8hWny0pFo5o2VaOkjsDuwhXNIYdAhbcGFsbB5C2_lMs5seOqmLhVJCaMNJ3eDRnqCyDCodafWh67XfVyYR6qugtZMoiLSSg3YzDAQ8KzWAfgQJWUYEcAbm729X2kCACvAAAAAQDUo5jryeOWtj5p5rPVr0aXytuvV5z18gprl4NlacO4yfzJnIn6CKknh8ERddvMTn913O6q3kVT6cNwRVbfGp-Y-OiosSW11DLUd7xVXyOUPhMqO4pyBK2mxtUbF-1I54VDF6eBXKEROBiPLXihJ1NhfhEkeR-Kja5U6LDa_tFHFRmPjX8ivxymlgez7q31vbOpk3kpSRmeXUQCMTMcam4oS48q7WwszDF4bVaHdg8Ytrs0vTRKKKJ6rF4iNNhIHaTXHgOddRlKd2oftL4IAK8AAAABAMIo8zBXRwINpyKoHfGIEKrwziELu8MXyc5enlbdsvBEunK91aO0jyiY8PCDbtpiZ_VddMTheVQryE_jS1CLcxGy8MT1VYjMraGmjMLR3dzovJEsf0KPDTjZixowJJgteBmDiJaVMJKvzXwxNg7_hEd57cdJG1fnmTow6IQzGqJQHydwVQy3ZTLwUvH-g6r_cQowe-iFogq3qpJQJ0A8Ry2uzr5p-NlwuQrE3QyIrOWsAsSHaNVoW8vtqlbpoH2gwYyb1zPj00msFFpaAwgAOAAAAQEA2BoOqy60wjpSrURNa0hepJA0s49dliZoJecXtEtUSesrU9jIUb0Gm9fm6yHW09z3zZ0UOk-IrOWsAsSHaNVoW8vtqlbpoH2gwYyb1zPj00msFFpaAwgAOAAAAQEA2BoOqy60wjpSrURNa0hepJA0s49dliZoJecXtEtUSesrU9jIUb0Gm9fm6yHW09z3zZ0UOk8',
            '11. Block7 (last) deleted':
               'RrwDC_oLoaZeWhltiIxbuMOjQBUqo-nUCqQdiroJG08IAH8AAAABAOLhq7u9y5XDxCEZuauGPW8TmNjNc3_hf0CX50LgyBAAACCxUxpNySSr6c7D6a0JHaa18Xko87Ez1hQHErgGP1g69SDSDFIg-LXa-Kq0BGhbfkpNW7wdkFE9XKqdkVojPBXiWcZVI28fNNeoFFix1CAmA36KNCm-2xHI9hsBUvzJVrmd-zf27kXJA12d4VYBnPQSwwfRFfUc5r_g7AgAMQAAAAEAUY2MRL7tOdQTBpcZlXx4cjK4wWNG3v4rnH8G6jOSXQGYmoQiLphb8UdkL83sjDpklXljS62xaLs8av7Zere3A_xPdvtUuyZdLjs9H3AqCABDAAAAAQBOcYFLpLlFQ6_rI3XV8rnFBAEk7FhyXqYkwgPP0uDJdm67D_lS_9o44Vcn43uvVA8dLGHjBMdyHV3UCTnpCojizHY1mPXIUINjrmfXN0USjFe1ulDDN9p620H0BB_dDrAIAGcAAAABAIS_CMW4wRSS8u2tq8oame462MGfkfqpkbiM2yH6buPEGifkOUjzF5fl4-w8dhB3tKLkpeT9eqyXmmn0bR33eVcqJew_EuEr4Gtg6AvdGCrM-kGzQhYBxAWKYP8fjcJ4DAzg270oyov-2dpggZgNmsCnCsC-_SoecirJRUQuRS0IUSYZZggArwAAAAEA2qxJ4IjFOkJreUlSw5DM6lEy1p3jEoG1MYdVpLid5SQV2blsdlBc8lW_YVGyf0p6gzJECxQoKPPrCKazmmQkD1LnqDMIhOEgIM70RLkCzsoKApFkDH0hGGI9IMqM-lH5s1p5iaPlYo1R38Zq04jX8hWny0pFo5o2VaOkjsDuwhXNIYdAhbcGFsbB5C2_lMs5seOqmLhVJCaMNJ3eDRnqCyDCodafWh67XfVyYR6qugtZMoiLSSg3YzDAQ8KzWAfgQJWUYEcAbm729X2kCACvAAAAAQDUo5jryeOWtj5p5rPVr0aXytuvV5z18gprl4NlacO4yfzJnIn6CKknh8ERddvMTn913O6q3kVT6cNwRVbfGp-Y-OiosSW11DLUd7xVXyOUPhMqO4pyBK2mxtUbF-1I54VDF6eBXKEROBiPLXihJ1NhfhEkeR-Kja5U6LDa_tFHFRmPjX8ivxymlgez7q31vbOpk3kpSRmeXUQCMTMcam4oS48q7WwszDF4bVaHdg8Ytrs0vTRKKKJ6rF4iNNhIHaTXHgOddRlKd2oftL4IAK8AAAABAMIo8zBXRwINpyKoHfGIEKrwziELu8MXyc5enlbdsvBEunK91aO0jyiY8PCDbtpiZ_VddMTheVQryE_jS1CLcxGy8MT1VYjMraGmjMLR3dzovJEsf0KPDTjZixowJJgteBmDiJaVMJKvzXwxNg7_hEd57cdJG1fnmTow6IQzGqJQHydwVQy3ZTLwUvH-g6r_cQowe-iFogq3qpJQJ0A8Ry2uzr5p-NlwuQrE3Qw',
            '12. Block1 Block7 deleted':
               'RrwDC_oLoaZeWhltiIxbuMOjQBUqo-nUCqQdiroJG08IAH8AAAABAOLhq7u9y5XDxCEZuauGPW8TmNjNc3_hf0CX50LgyBAAACCxUxpNySSr6c7D6a0JHaa18Xko87Ez1hQHErgGP1g69SDSDFIg-LXa-Kq0BGhbfkpNW7wdkFE9XKqdkVojPBXiWcZVI28fNNeoFFix1CAmA36KNCm-2xHI9hs6ZJV5Y0utsWi7PGr-2Xq3twP8T3b7VLsmXS47PR9wKggAQwAAAAEATnGBS6S5RUOv6yN11fK5xQQBJOxYcl6mJMIDz9LgyXZuuw_5Uv_aOOFXJ-N7r1QPHSxh4wTHch1d1Ak56QqI4sx2NZj1yFCDY65n1zdFEoxXtbpQwzfaettB9AQf3Q6wCABnAAAAAQCEvwjFuMEUkvLtravKGpnuOtjBn5H6qZG4jNsh-m7jxBon5DlI8xeX5ePsPHYQd7Si5KXk_Xqsl5pp9G0d93lXKiXsPxLhK-BrYOgL3RgqzPpBs0IWAcQFimD_H43CeAwM4Nu9KMqL_tnaYIGYDZrApwrAvv0qHnIqyUVELkUtCFEmGWYIAK8AAAABANqsSeCIxTpCa3lJUsOQzOpRMtad4xKBtTGHVaS4neUkFdm5bHZQXPJVv2FRsn9KeoMyRAsUKCjz6wims5pkJA9S56gzCIThICDO9ES5As7KCgKRZAx9IRhiPSDKjPpR-bNaeYmj5WKNUd_GatOI1_IVp8tKRaOaNlWjpI7A7sIVzSGHQIW3BhbGweQtv5TLObHjqpi4VSQmjDSd3g0Z6gsgwqHWn1oeu131cmEeqroLWTKIi0koN2MwwEPCs1gH4ECVlGBHAG5u9vV9pAgArwAAAAEA1KOY68njlrY-aeaz1a9Gl8rbr1ec9fIKa5eDZWnDuMn8yZyJ-gipJ4fBEXXbzE5_ddzuqt5FU-nDcEVW3xqfmPjoqLEltdQy1He8VV8jlD4TKjuKcgStpsbVGxftSOeFQxengVyhETgYjy14oSdTYX4RJHkfio2uVOiw2v7RRxUZj41_Ir8cppYHs-6t9b2zqZN5KUkZnl1EAjEzHGpuKEuPKu1sLMwxeG1Wh3YPGLa7NL00SiiieqxeIjTYSB2k1x4DnXUZSndqH7S-CACvAAAAAQDCKPMwV0cCDaciqB3xiBCq8M4hC7vDF8nOXp5W3bLwRLpyvdWjtI8omPDwg27aYmf1XXTE4XlUK8hP40tQi3MRsvDE9VWIzK2hpozC0d3c6LyRLH9Cjw042YsaMCSYLXgZg4iWlTCSr818MTYO_4RHee3HSRtX55k6MOiEMxqiUB8ncFUMt2Uy8FLx_oOq_3EKMHvohaIKt6qSUCdAPEctrs6-afjZcLkKxN0M',
            '13. All Term':
               'Eic21uka6cJdxlpc2Z4UzxtKMA2CdZ97-GtfSWQj2ooIAH8AAAEBACRezYjjg5urc8IxCaEGF1nALn-t-IM8bs34jebgyBAAACBzzkBgDXN2LtLGYyTRn4B8JqU--Mf2s0NdbtGdSikXdCCzv3XzSnKTzPtLCf9tPB25AjczY68zOj50cpvNWc9kyjTFFAOPrTjBEZ36u2S3iCN2rTueltHi6uQ1-yPyZyQwx7yBEb6hB6jF-Rsh6E3QmB4s5QPQp828xwgAMQAAAQEAiY5CRqNN1Nv6zcWhaNCIiOrp967Kdyx6lNcKlAu6V0YhOyRcBki2BHzvDASo6iJX5ceSAC_gmhQriHsaP22ct5EugdFXujQntaUUvjFBCABDAAABAQAb4OsTiIphrdPoBMqc_LyOh9p_5nQ-LfPc9uUhObvE76UcPSNpVD4cntyujZ9CmEGi8fupRdWez0eXTLEYt-gvel1fKuhxJOJOK6GTJa0XhrF1taKtyPzTO1DxFSr54wYIAGcAAAEBAIYh2dzmPxsDUk6IN4vLlKnYvHMlWeGTLXtXigxjClqhrALSZV2BZ-DSd66HN8cAWm3T_HpzUtPof5tkTE_hgWU_xL9gY93lS3rQFxWpb1RH65lpjJ4eNtRPe9r1GXRkJ2WWJYeyrbr3e9dcKzhUwzaX2mFOayB4y8qrlRbC8Mr9RuiGbwgArwAAAQEAGcXDBAFGs0pQVJASBVW0Ie1f0Cl2Np6ucD-XP1kB4wAvb-AXQKEYXeZ3mmU4UHchQH5jV6ldjOPOAk31tRhMyWVp8XUUGDjHumbNeOZ64VPk4loj5-d5kab7saahXTJRE3b3bs__fB-24WAeAkQqwENSmWi72Y9Gza6Oqa8tLX5J0Wdnigs69UBaMQsrlKpASWINm-LrmEDBYRITTR-bMRJsbnuzcuAST6PtSYem67oB1y18vmZ5-4caOdhMt0DwOi84xpIdKHGVLe2VCACvAAABAQD_tOzr2T8L1pd5B5xM1whH5BTIxR0y0O2il1FPjv9mHpjGflyOUr0KH9WWCYgNMsucOi_tpqoYF1iMPYa-p7eg09RUr2Y6X0l5p2Cj0YCcI0tePaeONgMeFWrjSncS-oVIwO9whdgcr8imexolz0onMne4RpyaW2CzD1mwQcusFDmgxvEPM_n9_8vq3M89ZUDW7kbnyG06Q9AFQ_zqGwrGleTRIatuPop2hTCslPbmBL0aS3Oqckx0z2TbGWju454Ms7aLr-RENvrns0sIAK8AAAEBAOeZOQx823Coy3laj9X0qDuo0bZ1uNSEGWm5Pj0Kdegq54A6fbeo2yJpUeWLtZ1W93rPduilqAQngku2MlZsvWRWTY5J1N-2HYSncer3_ocPZK1kSP89bes3Cji6jr6IFFD1QwgTCNRPCwZosGA68zGm_Sfs2_Nu-LPgmLbtQgbdhPqyAFO9LqFM_f-qIsUb9te81Y8n2FyFIhFe8b25YoFrtQBuJpFWnCl6_pa_6G70Bh7runNnKUleR4KR18Xz0UxID1fBmOSpgc-fyQgAOAAAAQEAhmww6jA0aytHcS5gFDdeHhhWBc3XnHvvVZasGi02eSInpPi2ybvFYIu_pX8glpXNIC28KkM',
            '14. No Term':
               'H11O0rVtUE2K95ECYk2CQ5CCORzXBXM5UAEdwN9SWqcIAH8AAAABAL5KW7niD2vbfZwurEQO3oWuVS-LuD-6ZOmKy9fgyBAAACDhb-2m0iSQoMczjP9nUF3zsT8ff_yilu12IUIyxZijICB_tlamqZ_hhvOi8NKRaRcKZpBXmTx1qy7_mgIYssEVsMguMYT0518jImvpJPQx-ZUfi8QQMG0_0nR9j4Ivp455c6ievFX1Oui_tD1hhYo41bztuwsnZwEdOQgAMQAAAAEATaOti0-LiNNzy7qfoBaMqxAt39opfHbD-W9G3BmNJM0yFja_xo37F3kOeNNQ4LRuFTvr5sbyfGL6uiM0UhsWC88Xd-m4JleoDLkuujxPCABDAAAAAQDB3HUVaoShp-j_aK2tSbUbfORtddsAo9oVBV5NYZvhSujwag0FA7sM6ncktt-8biWHC63_UoOc89z1jEIvUgWtU3rx7IwBmnE-VBOrRcqe0xidRjy4dxfwmBD0ab1auhkIAGcAAAABABaY5LNub2NWp0ANNddpd2QIUx9uPPbUyVoxbVfungkSm3CkW2_e5kRgNfHiSvQdlLp51UFasMsPjt1lE-UXIi8KbNKWb9e3C9AlxIkBYft6ycZaW390ly4Ca-t0WAeyiVGVr3Xl8RRTn_jMM640rrraSO0n2feMtJxdItBF-B72o4lYrggArwAAAAEAbxY3GrmOOK7x7PKxu2WgFO1jWZJQUIhF0sOX9iNybhCDUPl64hsfHdKspba4e-aBiTzPr0TYE-8oJ7rp2mY4yAO1F9aDjj_l2OPLIj5o2H0Uw1_E21Mtf0RkjkzRo_J5BAtUtQttJOwLPsfkVj8DkLs0zYqkijVrRjO75PX2nqY2wNOpY3btJtD4ocmjRZ9dXnjpukaakwwK4QxUZB5Aapt2VVHf4nY4utJ3NebCS8ZCrAivfAT_DQ27XIhlQKXztuOTqnNYJms1sLviCACvAAAAAQD8VAqzpz-LUYPD_bKZ_-0x9vFbdgjJ7SdJK5_FSpt5nb5YperX03Y4qboZph8h6mbVniAZ0rFN_QftM2Y2eHj7gmnoknLQJolEVK3Ez5prJAUCHd_jUopfexgm4kBn621s-nZjq_7dN7WKdRSX0r8mWoNKud4AuzM0VeF79B8dZHK0E6qoJmunIlD7WuDWrksAWPArgO7_0tLcVXQcCx-VWonGj48Wcd3G2BRGj6syN0TfIGP7MlwC7io3-9Gruze8BGWAVsxSufPRyosIAK8AAAABAKpdEnL5yKZiwM5krBKNA4FKfB7tSJ7y8e1BRA-a5cZbCT27Dmzb2xZzkD6kUGn1fHhHWdg2QD_rrO0stCP2c9KR43J2045rVGJ-w__XAUt9paVuOe-b3Rtspyt9JY77NxEZstIF1bHR1bsSeV2Xn8PTE8S40uWwyMQEMbIm_nkeJP8dUni5_Wezjng62fYArqu7sSA3fTxHR-JBpjURK8IN3LMaAbVTkWbqRmS9nlc_7SYF61d_8VOo7djT2PXtBVu22cQIyETJK-oESwgAOAAAAAEApDbAEa_BdVBTzGrq572efaqVq_tjl4d0oazRyHae9TYtOCHiCM1Y-ur_nWCMYX9dz04RHic',
         },
      },
      // END GENERATED: v8:blockOrder
   ];

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
            return ['asdf'];
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

   it('block reorder vectors are built from the blocks of the good ciphertext', () => {
      for (const ver of vers) {
         const goodBytes = base64ToBytes(ver.goodCt);
         const goodBlocks = splitBlocks(goodBytes, ver.ver);

         // Splitter control, so a wrong block boundary cannot make the checks below pass
         expect(concatArrays(goodBlocks)).toEqual(goodBytes);
         expect(goodBlocks.length).toBeGreaterThan(1);

         for (const [change, ct] of Object.entries(ver.badCts)) {
            // The term vectors rewrite flag bytes rather than moving whole blocks
            if (!change.includes('Term')) {
               for (const block of splitBlocks(base64ToBytes(ct), ver.ver)) {
                  expect(goodBlocks.some((good) => isEqualArray(good, block))).toBe(true);
               }
            }
         }
      }
   });

   it('changed multi block ciphertext', async () => {
      for (const ver of vers) {
         for (const [_change, ct] of Object.entries(ver.badCts)) {
            const [cipherStream] = streamFromBase64(ct);
            const decKeyProvider = new PWDKeyProvider(userCred.slice(0), async (_cdinfo) => {
               return ['asdf'];
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

describe('Block order change and deletion detection, MasterKeyKeyProvider, multi-version', () => {
   let cipherSvc: CipherService;
   beforeEach(async () => {
      await cryptoReady();
      TestBed.configureTestingModule({});
      cipherSvc = TestBed.inject(CipherService);
   });

   const masterKey = base64ToBytes('TWFzdGVyS2V5Rml4ZWRTZWVkVmFsdWUwMTIzNDU2Nzg=');
   const extraKeyMaterial = base64ToBytes('RXh0cmFLZXlNYXQ=');

   const vers = [
      //v7 — generated by apps/web/scripts/gen_v7_master_blockorder.ts in a v7.5.0 checkout
      {
         ver: 7,
         goodCt:
            'cDlM27NSsDXF6XKlfohskx7o9STsSjkUeCFxxi6qnwkHAD4AAAABAMPL8m4oCSoUOu-IpP_oqZFKxj9_2tvRxlKIYCMAAAAAAAADiFlD4q7qZdh76NHxxsJCg6n51ihAW3pAWwNYc88nzkYRY2donofyDtNIpI7GaJEFeRq2waVFmw8HADEAAAABAKKOtewqQladEB8rXW_WHOaM0r_4h-YHXH28FmbmTInxImFbC3HurfaoUOaTasaci7-V4tNFWz8l8Wr5RHHtrwkgPpkyzzrEOdSV2SaVcQcAQwAAAAEAi4mPEiGwTF3398M-caMk46qSdzjUUMrhzX8uuykYVkUE5M3zpSwAMgisCGwCitlf7ImF10bUzR92il9hDn3jY7Q71lV-GjvHlj4SnranQZejtjliz767vsNYB2HSqvrVBwBnAAAAAQD-J8ToqNp-6nuZA0r29x9Hrdvw_nuh-JB8t-_agIgXTHCTO2qllwOQexXJ_Y96Lrslk_PgnDxzYFg9dRaRcMKqa8bwPRP83eopmfJT1k4fJ7IMKG2n2wKt8Ih9tzBVG5JMvgPwnOGIqWPCuqxOwxYfRNUkMGlzCf5J6Yre4uAKAMYqtUIHAK8AAAABABfibMO0sj-xYp_B-Fd6Pl4ZNKx2pKuD0oYqXQXW2KePPpvMeWFy4RrAlfK0S4H4sZlA16abGVNPrfWLWOEmQFufEDwxJq447h_Sj_bYwDhYbEKISZxauLmeF6wYh3iDStnUR-Y6Y0MKrnZ55ZEQ_6bnZae1wcYWTQEO2MRQqB24wEOZWqBiQENG0MiMsvQ9uzvmMiwDEOItUq13dcX7n20WFhSg_CdHusjNPgYC1kn2AuKYi8gN7A48HV0zKP4pxY8adhcoDhEzz3jp8wcArwAAAAEA6ceUMmoCT4-zJtDPXWNpIIjwbWQae74_EeuLZA6bnwGSqSXQrCO6e0a2uv95jsHZxBPGr1xb5lOUzUPxypTVMX5hvOFgdXXDXDDh_HPrP64HSKHc6tOKS6S_qu6hUdUTACIwku-VYNdyLJwYlQ5SD8KNVCE9GhmBkPt1XB8XeOPcK3qgSvhl1pgbQ0LEnJc1O-O5PdtnD_MT2Q8mE5WAzplCNafkWNlefRtYjYH_En_Rs3mNL-gMj8K4j3H7Wcd2iVXF28jHKa6rYqN-BwCvAAAAAQAwYzm8Lrsr7ehYcxdy4-JLerdFXl0f5TDLHrBSapC5IRF2tu6WoyxDpC4yV4yBwPTSga69fPvPmLN88JF4ucD-7kNT5xf0NCNJqwLIDJFnbdz98ewskuy55qK_YE4Fn811R7NmbzFBaHdwA_gkll5lkummxFx6qNnoUiBejUexd-BuMRgmU8XWaM4fnPLKk0iTbgqbcv-W78uTBcn3Cwy78z4BQMTHRLJUqbT11K07Ffe4y6ZTG-LlmiTaKRLBt9u7G8dKlNQ_IIZC4PwHADgAAAEBAFGe6iumO8KLoXkZWjMPOmqDLB-oC8gMPMU91fk0QxQYz1_XuEjq1Qkt_fIdCJ4D5_ytNA1e',
         badCts: {
            '1. Block0 Block7 swap':
               '1K07Ffe4y6ZTG-LlmiTaKRLBt9u7G8dKlNQ_IIZC4PwHADgAAAEBAFGe6iumO8KLoXkZWjMPOmqDLB-oC8gMPMU91fk0QxQYz1_XuEjq1Qkt_fIdCJ4D5_ytNA1eWwNYc88nzkYRY2donofyDtNIpI7GaJEFeRq2waVFmw8HADEAAAABAKKOtewqQladEB8rXW_WHOaM0r_4h-YHXH28FmbmTInxImFbC3HurfaoUOaTasaci7-V4tNFWz8l8Wr5RHHtrwkgPpkyzzrEOdSV2SaVcQcAQwAAAAEAi4mPEiGwTF3398M-caMk46qSdzjUUMrhzX8uuykYVkUE5M3zpSwAMgisCGwCitlf7ImF10bUzR92il9hDn3jY7Q71lV-GjvHlj4SnranQZejtjliz767vsNYB2HSqvrVBwBnAAAAAQD-J8ToqNp-6nuZA0r29x9Hrdvw_nuh-JB8t-_agIgXTHCTO2qllwOQexXJ_Y96Lrslk_PgnDxzYFg9dRaRcMKqa8bwPRP83eopmfJT1k4fJ7IMKG2n2wKt8Ih9tzBVG5JMvgPwnOGIqWPCuqxOwxYfRNUkMGlzCf5J6Yre4uAKAMYqtUIHAK8AAAABABfibMO0sj-xYp_B-Fd6Pl4ZNKx2pKuD0oYqXQXW2KePPpvMeWFy4RrAlfK0S4H4sZlA16abGVNPrfWLWOEmQFufEDwxJq447h_Sj_bYwDhYbEKISZxauLmeF6wYh3iDStnUR-Y6Y0MKrnZ55ZEQ_6bnZae1wcYWTQEO2MRQqB24wEOZWqBiQENG0MiMsvQ9uzvmMiwDEOItUq13dcX7n20WFhSg_CdHusjNPgYC1kn2AuKYi8gN7A48HV0zKP4pxY8adhcoDhEzz3jp8wcArwAAAAEA6ceUMmoCT4-zJtDPXWNpIIjwbWQae74_EeuLZA6bnwGSqSXQrCO6e0a2uv95jsHZxBPGr1xb5lOUzUPxypTVMX5hvOFgdXXDXDDh_HPrP64HSKHc6tOKS6S_qu6hUdUTACIwku-VYNdyLJwYlQ5SD8KNVCE9GhmBkPt1XB8XeOPcK3qgSvhl1pgbQ0LEnJc1O-O5PdtnD_MT2Q8mE5WAzplCNafkWNlefRtYjYH_En_Rs3mNL-gMj8K4j3H7Wcd2iVXF28jHKa6rYqN-BwCvAAAAAQAwYzm8Lrsr7ehYcxdy4-JLerdFXl0f5TDLHrBSapC5IRF2tu6WoyxDpC4yV4yBwPTSga69fPvPmLN88JF4ucD-7kNT5xf0NCNJqwLIDJFnbdz98ewskuy55qK_YE4Fn811R7NmbzFBaHdwA_gkll5lkummxFx6qNnoUiBejUexd-BuMRgmU8XWaM4fnPLKk0iTbgqbcv-W78uTBcn3Cwy78z4BQMTHRLJUqbT1cDlM27NSsDXF6XKlfohskx7o9STsSjkUeCFxxi6qnwkHAD4AAAABAMPL8m4oCSoUOu-IpP_oqZFKxj9_2tvRxlKIYCMAAAAAAAADiFlD4q7qZdh76NHxxsJCg6n51ihAW3pA',
            '2. Block1 Block7 swap':
               'cDlM27NSsDXF6XKlfohskx7o9STsSjkUeCFxxi6qnwkHAD4AAAABAMPL8m4oCSoUOu-IpP_oqZFKxj9_2tvRxlKIYCMAAAAAAAADiFlD4q7qZdh76NHxxsJCg6n51ihAW3pA1K07Ffe4y6ZTG-LlmiTaKRLBt9u7G8dKlNQ_IIZC4PwHADgAAAEBAFGe6iumO8KLoXkZWjMPOmqDLB-oC8gMPMU91fk0QxQYz1_XuEjq1Qkt_fIdCJ4D5_ytNA1enIu_leLTRVs_JfFq-URx7a8JID6ZMs86xDnUldkmlXEHAEMAAAABAIuJjxIhsExd9_fDPnGjJOOqknc41FDK4c1_LrspGFZFBOTN86UsADIIrAhsAorZX-yJhddG1M0fdopfYQ5942O0O9ZVfho7x5Y-Ep62p0GXo7Y5Ys--u77DWAdh0qr61QcAZwAAAAEA_ifE6Kjafup7mQNK9vcfR63b8P57ofiQfLfv2oCIF0xwkztqpZcDkHsVyf2Pei67JZPz4Jw8c2BYPXUWkXDCqmvG8D0T_N3qKZnyU9ZOHyeyDChtp9sCrfCIfbcwVRuSTL4D8JzhiKljwrqsTsMWH0TVJDBpcwn-SemK3uLgCgDGKrVCBwCvAAAAAQAX4mzDtLI_sWKfwfhXej5eGTSsdqSrg9KGKl0F1tinjz6bzHlhcuEawJXytEuB-LGZQNemmxlTT631i1jhJkBbnxA8MSauOO4f0o_22MA4WGxCiEmcWri5nhesGId4g0rZ1EfmOmNDCq52eeWREP-m52WntcHGFk0BDtjEUKgduMBDmVqgYkBDRtDIjLL0Pbs75jIsAxDiLVKtd3XF-59tFhYUoPwnR7rIzT4GAtZJ9gLimIvIDewOPB1dMyj-KcWPGnYXKA4RM8946fMHAK8AAAABAOnHlDJqAk-PsybQz11jaSCI8G1kGnu-PxHri2QOm58Bkqkl0KwjuntGtrr_eY7B2cQTxq9cW-ZTlM1D8cqU1TF-YbzhYHV1w1ww4fxz6z-uB0ih3OrTikukv6ruoVHVEwAiMJLvlWDXciycGJUOUg_CjVQhPRoZgZD7dVwfF3jj3Ct6oEr4ZdaYG0NCxJyXNTvjuT3bZw_zE9kPJhOVgM6ZQjWn5FjZXn0bWI2B_xJ_0bN5jS_oDI_CuI9x-1nHdolVxdvIxymuq2KjfgcArwAAAAEAMGM5vC67K-3oWHMXcuPiS3q3RV5dH-Uwyx6wUmqQuSERdrbulqMsQ6QuMleMgcD00oGuvXz7z5izfPCReLnA_u5DU-cX9DQjSasCyAyRZ23c_fHsLJLsueaiv2BOBZ_NdUezZm8xQWh3cAP4JJZeZZLppsRceqjZ6FIgXo1HsXfgbjEYJlPF1mjOH5zyypNIk24Km3L_lu_LkwXJ9wsMu_M-AUDEx0SyVKm09VsDWHPPJ85GEWNnaJ6H8g7TSKSOxmiRBXkatsGlRZsPBwAxAAAAAQCijrXsKkJWnRAfK11v1hzmjNK_-IfmB1x9vBZm5kyJ8SJhWwtx7q32qFDmk2rG',
            '3. Block1 Block4 swap':
               'cDlM27NSsDXF6XKlfohskx7o9STsSjkUeCFxxi6qnwkHAD4AAAABAMPL8m4oCSoUOu-IpP_oqZFKxj9_2tvRxlKIYCMAAAAAAAADiFlD4q7qZdh76NHxxsJCg6n51ihAW3pAnOGIqWPCuqxOwxYfRNUkMGlzCf5J6Yre4uAKAMYqtUIHAK8AAAABABfibMO0sj-xYp_B-Fd6Pl4ZNKx2pKuD0oYqXQXW2KePPpvMeWFy4RrAlfK0S4H4sZlA16abGVNPrfWLWOEmQFufEDwxJq447h_Sj_bYwDhYbEKISZxauLmeF6wYh3iDStnUR-Y6Y0MKrnZ55ZEQ_6bnZae1wcYWTQEO2MRQqB24wEOZWqBiQENG0MiMsvQ9uzvmMiwDEOItUq13dcX7n20WFhSg_CdHusjNPgaci7-V4tNFWz8l8Wr5RHHtrwkgPpkyzzrEOdSV2SaVcQcAQwAAAAEAi4mPEiGwTF3398M-caMk46qSdzjUUMrhzX8uuykYVkUE5M3zpSwAMgisCGwCitlf7ImF10bUzR92il9hDn3jY7Q71lV-GjvHlj4SnranQZejtjliz767vsNYB2HSqvrVBwBnAAAAAQD-J8ToqNp-6nuZA0r29x9Hrdvw_nuh-JB8t-_agIgXTHCTO2qllwOQexXJ_Y96Lrslk_PgnDxzYFg9dRaRcMKqa8bwPRP83eopmfJT1k4fJ7IMKG2n2wKt8Ih9tzBVG5JMvgPwWwNYc88nzkYRY2donofyDtNIpI7GaJEFeRq2waVFmw8HADEAAAABAKKOtewqQladEB8rXW_WHOaM0r_4h-YHXH28FmbmTInxImFbC3HurfaoUOaTasYC1kn2AuKYi8gN7A48HV0zKP4pxY8adhcoDhEzz3jp8wcArwAAAAEA6ceUMmoCT4-zJtDPXWNpIIjwbWQae74_EeuLZA6bnwGSqSXQrCO6e0a2uv95jsHZxBPGr1xb5lOUzUPxypTVMX5hvOFgdXXDXDDh_HPrP64HSKHc6tOKS6S_qu6hUdUTACIwku-VYNdyLJwYlQ5SD8KNVCE9GhmBkPt1XB8XeOPcK3qgSvhl1pgbQ0LEnJc1O-O5PdtnD_MT2Q8mE5WAzplCNafkWNlefRtYjYH_En_Rs3mNL-gMj8K4j3H7Wcd2iVXF28jHKa6rYqN-BwCvAAAAAQAwYzm8Lrsr7ehYcxdy4-JLerdFXl0f5TDLHrBSapC5IRF2tu6WoyxDpC4yV4yBwPTSga69fPvPmLN88JF4ucD-7kNT5xf0NCNJqwLIDJFnbdz98ewskuy55qK_YE4Fn811R7NmbzFBaHdwA_gkll5lkummxFx6qNnoUiBejUexd-BuMRgmU8XWaM4fnPLKk0iTbgqbcv-W78uTBcn3Cwy78z4BQMTHRLJUqbT11K07Ffe4y6ZTG-LlmiTaKRLBt9u7G8dKlNQ_IIZC4PwHADgAAAEBAFGe6iumO8KLoXkZWjMPOmqDLB-oC8gMPMU91fk0QxQYz1_XuEjq1Qkt_fIdCJ4D5_ytNA1e',
            '4. Block0 repeated':
               'cDlM27NSsDXF6XKlfohskx7o9STsSjkUeCFxxi6qnwkHAD4AAAABAMPL8m4oCSoUOu-IpP_oqZFKxj9_2tvRxlKIYCMAAAAAAAADiFlD4q7qZdh76NHxxsJCg6n51ihAW3pAcDlM27NSsDXF6XKlfohskx7o9STsSjkUeCFxxi6qnwkHAD4AAAABAMPL8m4oCSoUOu-IpP_oqZFKxj9_2tvRxlKIYCMAAAAAAAADiFlD4q7qZdh76NHxxsJCg6n51ihAW3pAWwNYc88nzkYRY2donofyDtNIpI7GaJEFeRq2waVFmw8HADEAAAABAKKOtewqQladEB8rXW_WHOaM0r_4h-YHXH28FmbmTInxImFbC3HurfaoUOaTasaci7-V4tNFWz8l8Wr5RHHtrwkgPpkyzzrEOdSV2SaVcQcAQwAAAAEAi4mPEiGwTF3398M-caMk46qSdzjUUMrhzX8uuykYVkUE5M3zpSwAMgisCGwCitlf7ImF10bUzR92il9hDn3jY7Q71lV-GjvHlj4SnranQZejtjliz767vsNYB2HSqvrVBwBnAAAAAQD-J8ToqNp-6nuZA0r29x9Hrdvw_nuh-JB8t-_agIgXTHCTO2qllwOQexXJ_Y96Lrslk_PgnDxzYFg9dRaRcMKqa8bwPRP83eopmfJT1k4fJ7IMKG2n2wKt8Ih9tzBVG5JMvgPwnOGIqWPCuqxOwxYfRNUkMGlzCf5J6Yre4uAKAMYqtUIHAK8AAAABABfibMO0sj-xYp_B-Fd6Pl4ZNKx2pKuD0oYqXQXW2KePPpvMeWFy4RrAlfK0S4H4sZlA16abGVNPrfWLWOEmQFufEDwxJq447h_Sj_bYwDhYbEKISZxauLmeF6wYh3iDStnUR-Y6Y0MKrnZ55ZEQ_6bnZae1wcYWTQEO2MRQqB24wEOZWqBiQENG0MiMsvQ9uzvmMiwDEOItUq13dcX7n20WFhSg_CdHusjNPgYC1kn2AuKYi8gN7A48HV0zKP4pxY8adhcoDhEzz3jp8wcArwAAAAEA6ceUMmoCT4-zJtDPXWNpIIjwbWQae74_EeuLZA6bnwGSqSXQrCO6e0a2uv95jsHZxBPGr1xb5lOUzUPxypTVMX5hvOFgdXXDXDDh_HPrP64HSKHc6tOKS6S_qu6hUdUTACIwku-VYNdyLJwYlQ5SD8KNVCE9GhmBkPt1XB8XeOPcK3qgSvhl1pgbQ0LEnJc1O-O5PdtnD_MT2Q8mE5WAzplCNafkWNlefRtYjYH_En_Rs3mNL-gMj8K4j3H7Wcd2iVXF28jHKa6rYqN-BwCvAAAAAQAwYzm8Lrsr7ehYcxdy4-JLerdFXl0f5TDLHrBSapC5IRF2tu6WoyxDpC4yV4yBwPTSga69fPvPmLN88JF4ucD-7kNT5xf0NCNJqwLIDJFnbdz98ewskuy55qK_YE4Fn811R7NmbzFBaHdwA_gkll5lkummxFx6qNnoUiBejUexd-BuMRgmU8XWaM4fnPLKk0iTbgqbcv-W78uTBcn3Cwy78z4BQMTHRLJUqbT11K07Ffe4y6ZTG-LlmiTaKRLBt9u7G8dKlNQ_IIZC4PwHADgAAAEBAFGe6iumO8KLoXkZWjMPOmqDLB-oC8gMPMU91fk0QxQYz1_XuEjq1Qkt_fIdCJ4D5_ytNA1e',
            '5. Block0 deleted':
               'WwNYc88nzkYRY2donofyDtNIpI7GaJEFeRq2waVFmw8HADEAAAABAKKOtewqQladEB8rXW_WHOaM0r_4h-YHXH28FmbmTInxImFbC3HurfaoUOaTasaci7-V4tNFWz8l8Wr5RHHtrwkgPpkyzzrEOdSV2SaVcQcAQwAAAAEAi4mPEiGwTF3398M-caMk46qSdzjUUMrhzX8uuykYVkUE5M3zpSwAMgisCGwCitlf7ImF10bUzR92il9hDn3jY7Q71lV-GjvHlj4SnranQZejtjliz767vsNYB2HSqvrVBwBnAAAAAQD-J8ToqNp-6nuZA0r29x9Hrdvw_nuh-JB8t-_agIgXTHCTO2qllwOQexXJ_Y96Lrslk_PgnDxzYFg9dRaRcMKqa8bwPRP83eopmfJT1k4fJ7IMKG2n2wKt8Ih9tzBVG5JMvgPwnOGIqWPCuqxOwxYfRNUkMGlzCf5J6Yre4uAKAMYqtUIHAK8AAAABABfibMO0sj-xYp_B-Fd6Pl4ZNKx2pKuD0oYqXQXW2KePPpvMeWFy4RrAlfK0S4H4sZlA16abGVNPrfWLWOEmQFufEDwxJq447h_Sj_bYwDhYbEKISZxauLmeF6wYh3iDStnUR-Y6Y0MKrnZ55ZEQ_6bnZae1wcYWTQEO2MRQqB24wEOZWqBiQENG0MiMsvQ9uzvmMiwDEOItUq13dcX7n20WFhSg_CdHusjNPgYC1kn2AuKYi8gN7A48HV0zKP4pxY8adhcoDhEzz3jp8wcArwAAAAEA6ceUMmoCT4-zJtDPXWNpIIjwbWQae74_EeuLZA6bnwGSqSXQrCO6e0a2uv95jsHZxBPGr1xb5lOUzUPxypTVMX5hvOFgdXXDXDDh_HPrP64HSKHc6tOKS6S_qu6hUdUTACIwku-VYNdyLJwYlQ5SD8KNVCE9GhmBkPt1XB8XeOPcK3qgSvhl1pgbQ0LEnJc1O-O5PdtnD_MT2Q8mE5WAzplCNafkWNlefRtYjYH_En_Rs3mNL-gMj8K4j3H7Wcd2iVXF28jHKa6rYqN-BwCvAAAAAQAwYzm8Lrsr7ehYcxdy4-JLerdFXl0f5TDLHrBSapC5IRF2tu6WoyxDpC4yV4yBwPTSga69fPvPmLN88JF4ucD-7kNT5xf0NCNJqwLIDJFnbdz98ewskuy55qK_YE4Fn811R7NmbzFBaHdwA_gkll5lkummxFx6qNnoUiBejUexd-BuMRgmU8XWaM4fnPLKk0iTbgqbcv-W78uTBcn3Cwy78z4BQMTHRLJUqbT11K07Ffe4y6ZTG-LlmiTaKRLBt9u7G8dKlNQ_IIZC4PwHADgAAAEBAFGe6iumO8KLoXkZWjMPOmqDLB-oC8gMPMU91fk0QxQYz1_XuEjq1Qkt_fIdCJ4D5_ytNA1e',
            '6. Block1 repeated':
               'cDlM27NSsDXF6XKlfohskx7o9STsSjkUeCFxxi6qnwkHAD4AAAABAMPL8m4oCSoUOu-IpP_oqZFKxj9_2tvRxlKIYCMAAAAAAAADiFlD4q7qZdh76NHxxsJCg6n51ihAW3pAWwNYc88nzkYRY2donofyDtNIpI7GaJEFeRq2waVFmw8HADEAAAABAKKOtewqQladEB8rXW_WHOaM0r_4h-YHXH28FmbmTInxImFbC3HurfaoUOaTasZbA1hzzyfORhFjZ2ieh_IO00ikjsZokQV5GrbBpUWbDwcAMQAAAAEAoo617CpCVp0QHytdb9Yc5ozSv_iH5gdcfbwWZuZMifEiYVsLce6t9qhQ5pNqxpyLv5Xi00VbPyXxavlEce2vCSA-mTLPOsQ51JXZJpVxBwBDAAAAAQCLiY8SIbBMXff3wz5xoyTjqpJ3ONRQyuHNfy67KRhWRQTkzfOlLAAyCKwIbAKK2V_siYXXRtTNH3aKX2EOfeNjtDvWVX4aO8eWPhKetqdBl6O2OWLPvru-w1gHYdKq-tUHAGcAAAABAP4nxOio2n7qe5kDSvb3H0et2_D-e6H4kHy379qAiBdMcJM7aqWXA5B7Fcn9j3ouuyWT8-CcPHNgWD11FpFwwqprxvA9E_zd6imZ8lPWTh8nsgwobafbAq3wiH23MFUbkky-A_Cc4YipY8K6rE7DFh9E1SQwaXMJ_knpit7i4AoAxiq1QgcArwAAAAEAF-Jsw7SyP7Fin8H4V3o-Xhk0rHakq4PShipdBdbYp48-m8x5YXLhGsCV8rRLgfixmUDXppsZU0-t9YtY4SZAW58QPDEmrjjuH9KP9tjAOFhsQohJnFq4uZ4XrBiHeINK2dRH5jpjQwqudnnlkRD_pudlp7XBxhZNAQ7YxFCoHbjAQ5laoGJAQ0bQyIyy9D27O-YyLAMQ4i1SrXd1xfufbRYWFKD8J0e6yM0-BgLWSfYC4piLyA3sDjwdXTMo_inFjxp2FygOETPPeOnzBwCvAAAAAQDpx5QyagJPj7Mm0M9dY2kgiPBtZBp7vj8R64tkDpufAZKpJdCsI7p7Rra6_3mOwdnEE8avXFvmU5TNQ_HKlNUxfmG84WB1dcNcMOH8c-s_rgdIodzq04pLpL-q7qFR1RMAIjCS75Vg13IsnBiVDlIPwo1UIT0aGYGQ-3VcHxd449wreqBK-GXWmBtDQsSclzU747k922cP8xPZDyYTlYDOmUI1p-RY2V59G1iNgf8Sf9GzeY0v6AyPwriPcftZx3aJVcXbyMcprqtio34HAK8AAAABADBjObwuuyvt6FhzF3Lj4kt6t0VeXR_lMMsesFJqkLkhEXa27pajLEOkLjJXjIHA9NKBrr18-8-Ys3zwkXi5wP7uQ1PnF_Q0I0mrAsgMkWdt3P3x7CyS7Lnmor9gTgWfzXVHs2ZvMUFod3AD-CSWXmWS6abEXHqo2ehSIF6NR7F34G4xGCZTxdZozh-c8sqTSJNuCpty_5bvy5MFyfcLDLvzPgFAxMdEslSptPXUrTsV97jLplMb4uWaJNopEsG327sbx0qU1D8ghkLg_AcAOAAAAQEAUZ7qK6Y7wouheRlaMw86aoMsH6gLyAw8xT3V-TRDFBjPX9e4SOrVCS398h0IngPn_K00DV4',
            '7. Block1 deleted':
               'cDlM27NSsDXF6XKlfohskx7o9STsSjkUeCFxxi6qnwkHAD4AAAABAMPL8m4oCSoUOu-IpP_oqZFKxj9_2tvRxlKIYCMAAAAAAAADiFlD4q7qZdh76NHxxsJCg6n51ihAW3pAnIu_leLTRVs_JfFq-URx7a8JID6ZMs86xDnUldkmlXEHAEMAAAABAIuJjxIhsExd9_fDPnGjJOOqknc41FDK4c1_LrspGFZFBOTN86UsADIIrAhsAorZX-yJhddG1M0fdopfYQ5942O0O9ZVfho7x5Y-Ep62p0GXo7Y5Ys--u77DWAdh0qr61QcAZwAAAAEA_ifE6Kjafup7mQNK9vcfR63b8P57ofiQfLfv2oCIF0xwkztqpZcDkHsVyf2Pei67JZPz4Jw8c2BYPXUWkXDCqmvG8D0T_N3qKZnyU9ZOHyeyDChtp9sCrfCIfbcwVRuSTL4D8JzhiKljwrqsTsMWH0TVJDBpcwn-SemK3uLgCgDGKrVCBwCvAAAAAQAX4mzDtLI_sWKfwfhXej5eGTSsdqSrg9KGKl0F1tinjz6bzHlhcuEawJXytEuB-LGZQNemmxlTT631i1jhJkBbnxA8MSauOO4f0o_22MA4WGxCiEmcWri5nhesGId4g0rZ1EfmOmNDCq52eeWREP-m52WntcHGFk0BDtjEUKgduMBDmVqgYkBDRtDIjLL0Pbs75jIsAxDiLVKtd3XF-59tFhYUoPwnR7rIzT4GAtZJ9gLimIvIDewOPB1dMyj-KcWPGnYXKA4RM8946fMHAK8AAAABAOnHlDJqAk-PsybQz11jaSCI8G1kGnu-PxHri2QOm58Bkqkl0KwjuntGtrr_eY7B2cQTxq9cW-ZTlM1D8cqU1TF-YbzhYHV1w1ww4fxz6z-uB0ih3OrTikukv6ruoVHVEwAiMJLvlWDXciycGJUOUg_CjVQhPRoZgZD7dVwfF3jj3Ct6oEr4ZdaYG0NCxJyXNTvjuT3bZw_zE9kPJhOVgM6ZQjWn5FjZXn0bWI2B_xJ_0bN5jS_oDI_CuI9x-1nHdolVxdvIxymuq2KjfgcArwAAAAEAMGM5vC67K-3oWHMXcuPiS3q3RV5dH-Uwyx6wUmqQuSERdrbulqMsQ6QuMleMgcD00oGuvXz7z5izfPCReLnA_u5DU-cX9DQjSasCyAyRZ23c_fHsLJLsueaiv2BOBZ_NdUezZm8xQWh3cAP4JJZeZZLppsRceqjZ6FIgXo1HsXfgbjEYJlPF1mjOH5zyypNIk24Km3L_lu_LkwXJ9wsMu_M-AUDEx0SyVKm09dStOxX3uMumUxvi5Zok2ikSwbfbuxvHSpTUPyCGQuD8BwA4AAABAQBRnuorpjvCi6F5GVozDzpqgywfqAvIDDzFPdX5NEMUGM9f17hI6tUJLf3yHQieA-f8rTQNXg',
            '8. Block2 repeated':
               'cDlM27NSsDXF6XKlfohskx7o9STsSjkUeCFxxi6qnwkHAD4AAAABAMPL8m4oCSoUOu-IpP_oqZFKxj9_2tvRxlKIYCMAAAAAAAADiFlD4q7qZdh76NHxxsJCg6n51ihAW3pAWwNYc88nzkYRY2donofyDtNIpI7GaJEFeRq2waVFmw8HADEAAAABAKKOtewqQladEB8rXW_WHOaM0r_4h-YHXH28FmbmTInxImFbC3HurfaoUOaTasaci7-V4tNFWz8l8Wr5RHHtrwkgPpkyzzrEOdSV2SaVcQcAQwAAAAEAi4mPEiGwTF3398M-caMk46qSdzjUUMrhzX8uuykYVkUE5M3zpSwAMgisCGwCitlf7ImF10bUzR92il9hDn3jY5yLv5Xi00VbPyXxavlEce2vCSA-mTLPOsQ51JXZJpVxBwBDAAAAAQCLiY8SIbBMXff3wz5xoyTjqpJ3ONRQyuHNfy67KRhWRQTkzfOlLAAyCKwIbAKK2V_siYXXRtTNH3aKX2EOfeNjtDvWVX4aO8eWPhKetqdBl6O2OWLPvru-w1gHYdKq-tUHAGcAAAABAP4nxOio2n7qe5kDSvb3H0et2_D-e6H4kHy379qAiBdMcJM7aqWXA5B7Fcn9j3ouuyWT8-CcPHNgWD11FpFwwqprxvA9E_zd6imZ8lPWTh8nsgwobafbAq3wiH23MFUbkky-A_Cc4YipY8K6rE7DFh9E1SQwaXMJ_knpit7i4AoAxiq1QgcArwAAAAEAF-Jsw7SyP7Fin8H4V3o-Xhk0rHakq4PShipdBdbYp48-m8x5YXLhGsCV8rRLgfixmUDXppsZU0-t9YtY4SZAW58QPDEmrjjuH9KP9tjAOFhsQohJnFq4uZ4XrBiHeINK2dRH5jpjQwqudnnlkRD_pudlp7XBxhZNAQ7YxFCoHbjAQ5laoGJAQ0bQyIyy9D27O-YyLAMQ4i1SrXd1xfufbRYWFKD8J0e6yM0-BgLWSfYC4piLyA3sDjwdXTMo_inFjxp2FygOETPPeOnzBwCvAAAAAQDpx5QyagJPj7Mm0M9dY2kgiPBtZBp7vj8R64tkDpufAZKpJdCsI7p7Rra6_3mOwdnEE8avXFvmU5TNQ_HKlNUxfmG84WB1dcNcMOH8c-s_rgdIodzq04pLpL-q7qFR1RMAIjCS75Vg13IsnBiVDlIPwo1UIT0aGYGQ-3VcHxd449wreqBK-GXWmBtDQsSclzU747k922cP8xPZDyYTlYDOmUI1p-RY2V59G1iNgf8Sf9GzeY0v6AyPwriPcftZx3aJVcXbyMcprqtio34HAK8AAAABADBjObwuuyvt6FhzF3Lj4kt6t0VeXR_lMMsesFJqkLkhEXa27pajLEOkLjJXjIHA9NKBrr18-8-Ys3zwkXi5wP7uQ1PnF_Q0I0mrAsgMkWdt3P3x7CyS7Lnmor9gTgWfzXVHs2ZvMUFod3AD-CSWXmWS6abEXHqo2ehSIF6NR7F34G4xGCZTxdZozh-c8sqTSJNuCpty_5bvy5MFyfcLDLvzPgFAxMdEslSptPXUrTsV97jLplMb4uWaJNopEsG327sbx0qU1D8ghkLg_AcAOAAAAQEAUZ7qK6Y7wouheRlaMw86aoMsH6gLyAw8xT3V-TRDFBjPX9e4SOrVCS398h0IngPn_K00DV4',
            '9. Block2 deleted':
               'cDlM27NSsDXF6XKlfohskx7o9STsSjkUeCFxxi6qnwkHAD4AAAABAMPL8m4oCSoUOu-IpP_oqZFKxj9_2tvRxlKIYCMAAAAAAAADiFlD4q7qZdh76NHxxsJCg6n51ihAW3pAWwNYc88nzkYRY2donofyDtNIpI7GaJEFeRq2waVFmw8HADEAAAABAKKOtewqQladEB8rXW_WHOaM0r_4h-YHXH28FmbmTInxImFbC3HurfaoUOaTasa0O9ZVfho7x5Y-Ep62p0GXo7Y5Ys--u77DWAdh0qr61QcAZwAAAAEA_ifE6Kjafup7mQNK9vcfR63b8P57ofiQfLfv2oCIF0xwkztqpZcDkHsVyf2Pei67JZPz4Jw8c2BYPXUWkXDCqmvG8D0T_N3qKZnyU9ZOHyeyDChtp9sCrfCIfbcwVRuSTL4D8JzhiKljwrqsTsMWH0TVJDBpcwn-SemK3uLgCgDGKrVCBwCvAAAAAQAX4mzDtLI_sWKfwfhXej5eGTSsdqSrg9KGKl0F1tinjz6bzHlhcuEawJXytEuB-LGZQNemmxlTT631i1jhJkBbnxA8MSauOO4f0o_22MA4WGxCiEmcWri5nhesGId4g0rZ1EfmOmNDCq52eeWREP-m52WntcHGFk0BDtjEUKgduMBDmVqgYkBDRtDIjLL0Pbs75jIsAxDiLVKtd3XF-59tFhYUoPwnR7rIzT4GAtZJ9gLimIvIDewOPB1dMyj-KcWPGnYXKA4RM8946fMHAK8AAAABAOnHlDJqAk-PsybQz11jaSCI8G1kGnu-PxHri2QOm58Bkqkl0KwjuntGtrr_eY7B2cQTxq9cW-ZTlM1D8cqU1TF-YbzhYHV1w1ww4fxz6z-uB0ih3OrTikukv6ruoVHVEwAiMJLvlWDXciycGJUOUg_CjVQhPRoZgZD7dVwfF3jj3Ct6oEr4ZdaYG0NCxJyXNTvjuT3bZw_zE9kPJhOVgM6ZQjWn5FjZXn0bWI2B_xJ_0bN5jS_oDI_CuI9x-1nHdolVxdvIxymuq2KjfgcArwAAAAEAMGM5vC67K-3oWHMXcuPiS3q3RV5dH-Uwyx6wUmqQuSERdrbulqMsQ6QuMleMgcD00oGuvXz7z5izfPCReLnA_u5DU-cX9DQjSasCyAyRZ23c_fHsLJLsueaiv2BOBZ_NdUezZm8xQWh3cAP4JJZeZZLppsRceqjZ6FIgXo1HsXfgbjEYJlPF1mjOH5zyypNIk24Km3L_lu_LkwXJ9wsMu_M-AUDEx0SyVKm09dStOxX3uMumUxvi5Zok2ikSwbfbuxvHSpTUPyCGQuD8BwA4AAABAQBRnuorpjvCi6F5GVozDzpqgywfqAvIDDzFPdX5NEMUGM9f17hI6tUJLf3yHQieA-f8rTQNXg',
            '10. Block7 (last) repeated':
               'cDlM27NSsDXF6XKlfohskx7o9STsSjkUeCFxxi6qnwkHAD4AAAABAMPL8m4oCSoUOu-IpP_oqZFKxj9_2tvRxlKIYCMAAAAAAAADiFlD4q7qZdh76NHxxsJCg6n51ihAW3pAWwNYc88nzkYRY2donofyDtNIpI7GaJEFeRq2waVFmw8HADEAAAABAKKOtewqQladEB8rXW_WHOaM0r_4h-YHXH28FmbmTInxImFbC3HurfaoUOaTasaci7-V4tNFWz8l8Wr5RHHtrwkgPpkyzzrEOdSV2SaVcQcAQwAAAAEAi4mPEiGwTF3398M-caMk46qSdzjUUMrhzX8uuykYVkUE5M3zpSwAMgisCGwCitlf7ImF10bUzR92il9hDn3jY7Q71lV-GjvHlj4SnranQZejtjliz767vsNYB2HSqvrVBwBnAAAAAQD-J8ToqNp-6nuZA0r29x9Hrdvw_nuh-JB8t-_agIgXTHCTO2qllwOQexXJ_Y96Lrslk_PgnDxzYFg9dRaRcMKqa8bwPRP83eopmfJT1k4fJ7IMKG2n2wKt8Ih9tzBVG5JMvgPwnOGIqWPCuqxOwxYfRNUkMGlzCf5J6Yre4uAKAMYqtUIHAK8AAAABABfibMO0sj-xYp_B-Fd6Pl4ZNKx2pKuD0oYqXQXW2KePPpvMeWFy4RrAlfK0S4H4sZlA16abGVNPrfWLWOEmQFufEDwxJq447h_Sj_bYwDhYbEKISZxauLmeF6wYh3iDStnUR-Y6Y0MKrnZ55ZEQ_6bnZae1wcYWTQEO2MRQqB24wEOZWqBiQENG0MiMsvQ9uzvmMiwDEOItUq13dcX7n20WFhSg_CdHusjNPgYC1kn2AuKYi8gN7A48HV0zKP4pxY8adhcoDhEzz3jp8wcArwAAAAEA6ceUMmoCT4-zJtDPXWNpIIjwbWQae74_EeuLZA6bnwGSqSXQrCO6e0a2uv95jsHZxBPGr1xb5lOUzUPxypTVMX5hvOFgdXXDXDDh_HPrP64HSKHc6tOKS6S_qu6hUdUTACIwku-VYNdyLJwYlQ5SD8KNVCE9GhmBkPt1XB8XeOPcK3qgSvhl1pgbQ0LEnJc1O-O5PdtnD_MT2Q8mE5WAzplCNafkWNlefRtYjYH_En_Rs3mNL-gMj8K4j3H7Wcd2iVXF28jHKa6rYqN-BwCvAAAAAQAwYzm8Lrsr7ehYcxdy4-JLerdFXl0f5TDLHrBSapC5IRF2tu6WoyxDpC4yV4yBwPTSga69fPvPmLN88JF4ucD-7kNT5xf0NCNJqwLIDJFnbdz98ewskuy55qK_YE4Fn811R7NmbzFBaHdwA_gkll5lkummxFx6qNnoUiBejUexd-BuMRgmU8XWaM4fnPLKk0iTbgqbcv-W78uTBcn3Cwy78z4BQMTHRLJUqbT11K07Ffe4y6ZTG-LlmiTaKRLBt9u7G8dKlNQ_IIZC4PwHADgAAAEBAFGe6iumO8KLoXkZWjMPOmqDLB-oC8gMPMU91fk0QxQYz1_XuEjq1Qkt_fIdCJ4D5_ytNA1e1K07Ffe4y6ZTG-LlmiTaKRLBt9u7G8dKlNQ_IIZC4PwHADgAAAEBAFGe6iumO8KLoXkZWjMPOmqDLB-oC8gMPMU91fk0QxQYz1_XuEjq1Qkt_fIdCJ4D5_ytNA1e',
            '11. Block7 (last) deleted':
               'cDlM27NSsDXF6XKlfohskx7o9STsSjkUeCFxxi6qnwkHAD4AAAABAMPL8m4oCSoUOu-IpP_oqZFKxj9_2tvRxlKIYCMAAAAAAAADiFlD4q7qZdh76NHxxsJCg6n51ihAW3pAWwNYc88nzkYRY2donofyDtNIpI7GaJEFeRq2waVFmw8HADEAAAABAKKOtewqQladEB8rXW_WHOaM0r_4h-YHXH28FmbmTInxImFbC3HurfaoUOaTasaci7-V4tNFWz8l8Wr5RHHtrwkgPpkyzzrEOdSV2SaVcQcAQwAAAAEAi4mPEiGwTF3398M-caMk46qSdzjUUMrhzX8uuykYVkUE5M3zpSwAMgisCGwCitlf7ImF10bUzR92il9hDn3jY7Q71lV-GjvHlj4SnranQZejtjliz767vsNYB2HSqvrVBwBnAAAAAQD-J8ToqNp-6nuZA0r29x9Hrdvw_nuh-JB8t-_agIgXTHCTO2qllwOQexXJ_Y96Lrslk_PgnDxzYFg9dRaRcMKqa8bwPRP83eopmfJT1k4fJ7IMKG2n2wKt8Ih9tzBVG5JMvgPwnOGIqWPCuqxOwxYfRNUkMGlzCf5J6Yre4uAKAMYqtUIHAK8AAAABABfibMO0sj-xYp_B-Fd6Pl4ZNKx2pKuD0oYqXQXW2KePPpvMeWFy4RrAlfK0S4H4sZlA16abGVNPrfWLWOEmQFufEDwxJq447h_Sj_bYwDhYbEKISZxauLmeF6wYh3iDStnUR-Y6Y0MKrnZ55ZEQ_6bnZae1wcYWTQEO2MRQqB24wEOZWqBiQENG0MiMsvQ9uzvmMiwDEOItUq13dcX7n20WFhSg_CdHusjNPgYC1kn2AuKYi8gN7A48HV0zKP4pxY8adhcoDhEzz3jp8wcArwAAAAEA6ceUMmoCT4-zJtDPXWNpIIjwbWQae74_EeuLZA6bnwGSqSXQrCO6e0a2uv95jsHZxBPGr1xb5lOUzUPxypTVMX5hvOFgdXXDXDDh_HPrP64HSKHc6tOKS6S_qu6hUdUTACIwku-VYNdyLJwYlQ5SD8KNVCE9GhmBkPt1XB8XeOPcK3qgSvhl1pgbQ0LEnJc1O-O5PdtnD_MT2Q8mE5WAzplCNafkWNlefRtYjYH_En_Rs3mNL-gMj8K4j3H7Wcd2iVXF28jHKa6rYqN-BwCvAAAAAQAwYzm8Lrsr7ehYcxdy4-JLerdFXl0f5TDLHrBSapC5IRF2tu6WoyxDpC4yV4yBwPTSga69fPvPmLN88JF4ucD-7kNT5xf0NCNJqwLIDJFnbdz98ewskuy55qK_YE4Fn811R7NmbzFBaHdwA_gkll5lkummxFx6qNnoUiBejUexd-BuMRgmU8XWaM4fnPLKk0iTbgqbcv-W78uTBcn3Cwy78z4BQMTHRLJUqbT1',
            '12. Block1 Block7 deleted':
               'cDlM27NSsDXF6XKlfohskx7o9STsSjkUeCFxxi6qnwkHAD4AAAABAMPL8m4oCSoUOu-IpP_oqZFKxj9_2tvRxlKIYCMAAAAAAAADiFlD4q7qZdh76NHxxsJCg6n51ihAW3pAnIu_leLTRVs_JfFq-URx7a8JID6ZMs86xDnUldkmlXEHAEMAAAABAIuJjxIhsExd9_fDPnGjJOOqknc41FDK4c1_LrspGFZFBOTN86UsADIIrAhsAorZX-yJhddG1M0fdopfYQ5942O0O9ZVfho7x5Y-Ep62p0GXo7Y5Ys--u77DWAdh0qr61QcAZwAAAAEA_ifE6Kjafup7mQNK9vcfR63b8P57ofiQfLfv2oCIF0xwkztqpZcDkHsVyf2Pei67JZPz4Jw8c2BYPXUWkXDCqmvG8D0T_N3qKZnyU9ZOHyeyDChtp9sCrfCIfbcwVRuSTL4D8JzhiKljwrqsTsMWH0TVJDBpcwn-SemK3uLgCgDGKrVCBwCvAAAAAQAX4mzDtLI_sWKfwfhXej5eGTSsdqSrg9KGKl0F1tinjz6bzHlhcuEawJXytEuB-LGZQNemmxlTT631i1jhJkBbnxA8MSauOO4f0o_22MA4WGxCiEmcWri5nhesGId4g0rZ1EfmOmNDCq52eeWREP-m52WntcHGFk0BDtjEUKgduMBDmVqgYkBDRtDIjLL0Pbs75jIsAxDiLVKtd3XF-59tFhYUoPwnR7rIzT4GAtZJ9gLimIvIDewOPB1dMyj-KcWPGnYXKA4RM8946fMHAK8AAAABAOnHlDJqAk-PsybQz11jaSCI8G1kGnu-PxHri2QOm58Bkqkl0KwjuntGtrr_eY7B2cQTxq9cW-ZTlM1D8cqU1TF-YbzhYHV1w1ww4fxz6z-uB0ih3OrTikukv6ruoVHVEwAiMJLvlWDXciycGJUOUg_CjVQhPRoZgZD7dVwfF3jj3Ct6oEr4ZdaYG0NCxJyXNTvjuT3bZw_zE9kPJhOVgM6ZQjWn5FjZXn0bWI2B_xJ_0bN5jS_oDI_CuI9x-1nHdolVxdvIxymuq2KjfgcArwAAAAEAMGM5vC67K-3oWHMXcuPiS3q3RV5dH-Uwyx6wUmqQuSERdrbulqMsQ6QuMleMgcD00oGuvXz7z5izfPCReLnA_u5DU-cX9DQjSasCyAyRZ23c_fHsLJLsueaiv2BOBZ_NdUezZm8xQWh3cAP4JJZeZZLppsRceqjZ6FIgXo1HsXfgbjEYJlPF1mjOH5zyypNIk24Km3L_lu_LkwXJ9wsMu_M-AUDEx0SyVKm09Q',
            '13. All Term':
               'Pl99GfIf4oQ7ul4BYFGNW4qOhconaucJH10f7yFTOZsHAD4AAAEBANw9bX5NlxV9nG0fDwyOqELY3X3KtQJgL-8hOmsAAAAAAADWi-mE__9IeMxpkKvpr3naVXgTGNvb52oG9EHWx9VoGsYvgezPkr-0y4C_Qlm4wyqqOOrA-5O_ycEHADEAAAEBADGF8TflKw6ltrjSNU1fMWJoPICtR55Y8LyVSSERHhnEzU_uPGoYbbLKiK3jahPrD5l9AEx0mVxbFnW9akS-cnqAosloYNm7sfVxNMki6wcAQwAAAQEAhOv6HFhY8gp9RI-9ZDoAq3Q1bf9PNe1ujJL1sjCbJ0ihPcfGDlIsppo4XwUbXGMiAK_emMcOplThSYkHDbWQJqwEvupb4-oNR9_MAtT-KrTSRTDcQoP0JJQf6uYVDZKDBwBnAAABAQBU3cqq57qwvXE8r49ce4IZzHaDjWUmckKCPouvkObBRedmJnyYaWiMz22MW0AjluaLa8XkTpHV_zviI14xs6L8ob6Dpot-Kmzvq5UAMBvc7kt-bBbjI2DEkK9gzU6EL58zO4_n4Hxa_pJmCm_jUSSfWsOb6ozOFgbzVpNPPq0Cej2M8XwHAK8AAAEBAHaLhLZIsVHXUQR97g1uoQzNAWlqMgArUi1WdcOsXEApBOaM64xewklfX4BjGNbnZnTgA4PpnYR6u6mzEJw0XLGq8CG6j6Hvx-DWf_05fXB2LrNpre_sX8oi00TbzM-ikziponXg4TnXD5N6KzLykQEUHZpzaEOHhFGe4dA4xmmxn7Dm_APWaOJb0aHMOlZzxLsTyZJ2JNyzcE4zxavE0QVp0iygaHiY_83tjvFNyzkfQ-75aDFO8BVoU843Cr6uQnNNlniiI5rlT-C4swcArwAAAQEAu_nWL9j3ELtWaNjBQ5pXGIr0RbNpJ8HjO2J4643gqWcd3MRCe3B9TKCbzoma2HgsWR8K1KFc7UllwaVxCBzcnErqltxN8p1jtUhf5Dz3nAURfSbNu3nk3MhRAO9bwda4tyxNmg6h5EwAlpcF0yTU0FwL7Ye1bIoYq9kJkvr68h39fmjvdQm83ZCnjALsmjmxldA5PDvjR-iNLKeGakiEa-sN7THnghVVLpHKQMctt4wvQGGZe0WL375LG84kb-GA__P_IQnoUcJZLsHGBwCvAAABAQCJzBRbzZS5DeUvZIBeFcQZiIxGcJ67baKb63xGgJjkEeDFvqRNTrANfFCgaO-8MAIBRajUyW8rHjDduY15gPkbP_sJCPzlSUqzVc_V2h7bBxhmK5otXhzrpOneesi9i5e-HdYZ6TT3L4AquacWtJ_ufMkW77itzh9qHNLVVNYi-Mdqlu1Bit_o4dn6P-1-RyJCYvyqmY4XMoX9av7ZY4cQmW-qk94Hmgood2O83AJS4kuKNoZKQvbzkaF0Zd2RQrHlqt8r-MytlCerSZQHADgAAAEBAOOvDNvzjjAyBgKGD9DhAIL6UdM4vt2serGIvgspsCIjWp1lRRD2exvFNexOMsLKVPJmdwfM',
            '14. No Term':
               'M1QgDX4RZ8yb47kZd3V71PTL7FE0pZ2P3iGbsQKEgFMHAD4AAAABAC-Xh4MUR94MkzdFbO70NGqgbzTSQETRR_PxmjEAAAAAAAAq_dy8eL2eTZ6rXc21qfL1v2qjGgjZZq0luU5Xz9M1Q0LU3fcjk7d8pt_1VySs6EjdED2watvVCxYHADEAAAABANiSsTidCe7ojt13PPVWG0snHfIcN9J5PoJXkv0sK1DCWp_k8bjaxjQtTseZiH14qhFXIxxP0QQEJs16tOSj0OtfnowCLngEKNX_f7a4BAcAQwAAAAEAykqQozHBSi2vtDqGh0fIfpIx7zgXL8nET1zPYapp9kVjLwaa1S5TU-TfFH0sMQ3GMsLp_b81OhoPadxEQTD0UrVSmJ-JN6SuZV1M-tJE0X2BZySzkk7IVNfgRLxoQutWBwBnAAAAAQDJol1iC9CSvnbKk7aapCvu6rJQ7JAVCntZ3d6mxAtBuLadentlPxV7Q0d84dFyJtwKRcpUxl0dNafps3hD8ocmV-E_2yHZqzd60l5_w-3W9LoNQSzEpd-fRmr_0fQPjLLPB7e6iQpcdy8TkygCdbHY3UnJciR5d08qiWQWmX-EQ9FFpnkHAK8AAAABAJrjbp0SlipDEgS_IgUiXWt0cWkAYpe0G_lZcM56G_O1FETDswiX4jhbyviVisuSKa_jhEiVf6ClmPj9hWDIbWMH9dXKAlFS8WQ4StUz08fPBMbzV3qvntHRcVsNQSNHr4vsXeF6WVkWhfmytFhghtFEQBpbCMuHR1uZhpoD9FeSTgR9EOiwWUfS7RcejIq-wCPNSNpOKgFXbUymtEIVGHUSJFLr8W7Pvbm5SVOwo5CqoPONMZL_p07ZidJkAch5MP58Dl8ssvGUOhaZ6QcArwAAAAEA0luDmc1KckessxYP_Fz6UPrYusJj6sHSIJCEdCxj6nHR0gchvBdCKNf1GhZip1ZDLomZd0NTf9YwtofxUXKmj6X4ICx-OhMqFjzXVooD-TSoM0wI-v1f76OYVdiWatnXTDUeAFIAYu5WH_AIHyWbe0-DZ8T1vGffR0tSBq9nF8F0zXTxYjaVdgkGzLrl6a8RQ9t5zUD9TBrvxCFXOHemuW4wYxboWJK24G8HuiIcswNDkpC9IBevBUJl6kmFIWpBD_SUUulnMiuJBvdqBwCvAAAAAQBV3wL74k5ViKEXh0v2lUBvXFqByngLOujLB7_Q2l09MHt6ofVsXwksABj04p1Tg0XOlHw3pP0rsFADbPRJ2VxUFAsQmauOs3ugwNdWKkPpOPHgpgmXHE64Vbqsgvok8tgrXZp0WyNDQOe71Qet9KapDV0DWTJp_X34PlZSFAizd_f9znJ9zr-SZojaM0xuVmDQUW_oo5GwOD2C15s2BBE0B6Bn-REpDqEt48fsgTEKaafPHK_JCEacsjXxrHiobz_g_a8fqHkHsbQqbZcHADgAAAABAI6ZrrtVqX4B2hD61nwqBgRrelSxLDBi_yAD2Hi8SHtps9NbMXL4Sm-kOipkRICyucsRwpMN',
         },
      },

      // BEGIN GENERATED: v8:blockOrderMaster
      //v8 — generated by: pnpm vectors:ciphersvc
      {
         ver: 8,
         goodCt:
            'u8KB6jsBD7RqHv6lL7hSJRV2jUkislgTfFwOnZcUXeEIAD8AAAABAGk01JsVguGy1M7NC1OucFCIn1mDPW9NF9fG28EAAAAAAAAA_73nwB7qi2-Rw0nn6NbQRcyJYFRTnTC9wNyJqR--e9SgPjeSPOr0UxL7k8zT8S559IuXbWYg4a1vCAAxAAAAAQCRezltP-mD8k3YBuscU20bwRx4e4BXAGsFiGEtewu1OHPIhO1TLaemuNA47Nmy5r4p4v5bweBgOiuLICGwct-OryvSYH2Oq18g_Hk2oF8IAEMAAAABACXCvYTnZ0VTnlNxPa6rkw40VPBm7xqqrhs7L5Vz4edsEX4qC67AVA_91meysInCfAzZxgY2eGsUFwnVNx8sau2-ww9yN94GJioBqCODX2XtpazJclg_VZzTgrt4Xl7FOQgAZwAAAAEACQ9LPB_-tbTrOoYeBEl3mb4Jw-nZ-qHWduLj4Pgw-vTIRn8uYtOT7L3QvoGfClG2Z2gSV4O_-0EB7LgDqvtmaPXrUuJrUuMymwVobFonaXe6vmVnhKTryX87JRYjZqnLLYvCMyMKUyYt1SgQm8xhdGNuiH22R-DEeZwUbkIqV-tvEw0VCACvAAAAAQCM921Jl6q6xdJMaV6ybtLkpnL6ZCarYvPLql9WDeKUr-BZ6TrxVINfr5UjjTrRvhUpDWBKf-sJXxpM3CK2c9cZYPePAHudJjmMnuntBZCMH5iN-16iB24_pF92nAybATfdcjvBAAzCFklM8nUwu-2iV4P7gRSB5CM1QKeYFz2NL89sTfrpjmCxTWv7pfHhMgi2fM6WTTy3e2vKJEVG3xRpwFBN-ruCtmFS1hueoWUjShtDhiYk-x_3GZK3UWd-nr9SASEhEmrSXFc30xsIAK8AAAABAK4_MbHfhhRZdyA_FKXju1cvjJJScNQf7KOND3twaIYwUNSSWq8h6gfZFoZxwSa_YXaxMyaQzAvtGZYknv5BVGdkY7tO6KS7yJlMs4KmtCkdKYz3WM1niEwLhXNebB_UkrQanMdLtEl-zZD5FVlZ1ohFXopzZ6VSGSMU3NrmJ32Xfl9tLo4enhWhzzRdho_sT5J02PQcL0f-LitbcX9AVUOaGWcgpHxb2L86SO0NAj8innovN7I4d1nU6YiOJIyVKPWl17GkuEhVO7gG9wgArwAAAAEAgoQtC2fEGFpK3eZ5J9Kv7tXaadtovejLe0ALbFyS5GxSKbi3bvYDKwVBRIPitoOUhFup2fidxiQfBWimgnJW8UvHhDEg0enHp6SR080cqFKSyjTSXT5f_BCS6Zh7XQ8FIYJVSgmuFH2LcncCIk6aFP5ZFrZJMgu7BkOYz1FXe_bHF013pyseJFZvn4QOphOarPJaS4SrPl73Ixfk67dImm3Sb1iZC58TCyY9MUQGJajdfbumAWBmHAhRC38uFh5xaumuEG_BgaZAcULVCAA4AAABAQADuUGeR6DW0_mgwgOCgw8CYdnYyjL2mRWOpoYuTS8jLiZd6CNzRlu9Ly2fBCRv67u-GsMb6w',
         badCts: {
            '1. Block0 Block7 swap':
               'RAYlqN19u6YBYGYcCFELfy4WHnFq6a4Qb8GBpkBxQtUIADgAAAEBAAO5QZ5HoNbT-aDCA4KDDwJh2djKMvaZFY6mhi5NLyMuJl3oI3NGW70vLZ8EJG_ru74awxvr3ImpH7571KA-N5I86vRTEvuTzNPxLnn0i5dtZiDhrW8IADEAAAABAJF7OW0_6YPyTdgG6xxTbRvBHHh7gFcAawWIYS17C7U4c8iE7VMtp6a40Djs2bLmvini_lvB4GA6K4sgIbBy346vK9JgfY6rXyD8eTagXwgAQwAAAAEAJcK9hOdnRVOeU3E9rquTDjRU8GbvGqquGzsvlXPh52wRfioLrsBUD_3WZ7KwicJ8DNnGBjZ4axQXCdU3Hyxq7b7DD3I33gYmKgGoI4NfZe2lrMlyWD9VnNOCu3heXsU5CABnAAAAAQAJD0s8H_61tOs6hh4ESXeZvgnD6dn6odZ24uPg-DD69MhGfy5i05PsvdC-gZ8KUbZnaBJXg7_7QQHsuAOq-2Zo9etS4mtS4zKbBWhsWidpd7q-ZWeEpOvJfzslFiNmqcsti8IzIwpTJi3VKBCbzGF0Y26IfbZH4MR5nBRuQipX628TDRUIAK8AAAABAIz3bUmXqrrF0kxpXrJu0uSmcvpkJqti88uqX1YN4pSv4FnpOvFUg1-vlSONOtG-FSkNYEp_6wlfGkzcIrZz1xlg948Ae50mOYye6e0FkIwfmI37XqIHbj-kX3acDJsBN91yO8EADMIWSUzydTC77aJXg_uBFIHkIzVAp5gXPY0vz2xN-umOYLFNa_ul8eEyCLZ8zpZNPLd7a8okRUbfFGnAUE36u4K2YVLWG56hZSNKG0OGJiT7H_cZkrdRZ36ev1IBISESatJcVzfTGwgArwAAAAEArj8xsd-GFFl3ID8UpeO7Vy-MklJw1B_so40Pe3BohjBQ1JJaryHqB9kWhnHBJr9hdrEzJpDMC-0ZliSe_kFUZ2Rju07opLvImUyzgqa0KR0pjPdYzWeITAuFc15sH9SStBqcx0u0SX7NkPkVWVnWiEVeinNnpVIZIxTc2uYnfZd-X20ujh6eFaHPNF2Gj-xPknTY9BwvR_4uK1txf0BVQ5oZZyCkfFvYvzpI7Q0CPyKeei83sjh3WdTpiI4kjJUo9aXXsaS4SFU7uAb3CACvAAAAAQCChC0LZ8QYWkrd5nkn0q_u1dpp22i96Mt7QAtsXJLkbFIpuLdu9gMrBUFEg-K2g5SEW6nZ-J3GJB8FaKaCclbxS8eEMSDR6cenpJHTzRyoUpLKNNJdPl_8EJLpmHtdDwUhglVKCa4UfYtydwIiTpoU_lkWtkkyC7sGQ5jPUVd79scXTXenKx4kVm-fhA6mE5qs8lpLhKs-XvcjF-Trt0iabdJvWJkLnxMLJj0xu8KB6jsBD7RqHv6lL7hSJRV2jUkislgTfFwOnZcUXeEIAD8AAAABAGk01JsVguGy1M7NC1OucFCIn1mDPW9NF9fG28EAAAAAAAAA_73nwB7qi2-Rw0nn6NbQRcyJYFRTnTC9wA',
            '2. Block1 Block7 swap':
               'u8KB6jsBD7RqHv6lL7hSJRV2jUkislgTfFwOnZcUXeEIAD8AAAABAGk01JsVguGy1M7NC1OucFCIn1mDPW9NF9fG28EAAAAAAAAA_73nwB7qi2-Rw0nn6NbQRcyJYFRTnTC9wEQGJajdfbumAWBmHAhRC38uFh5xaumuEG_BgaZAcULVCAA4AAABAQADuUGeR6DW0_mgwgOCgw8CYdnYyjL2mRWOpoYuTS8jLiZd6CNzRlu9Ly2fBCRv67u-GsMb6-a-KeL-W8HgYDoriyAhsHLfjq8r0mB9jqtfIPx5NqBfCABDAAAAAQAlwr2E52dFU55TcT2uq5MONFTwZu8aqq4bOy-Vc-HnbBF-KguuwFQP_dZnsrCJwnwM2cYGNnhrFBcJ1TcfLGrtvsMPcjfeBiYqAagjg19l7aWsyXJYP1Wc04K7eF5exTkIAGcAAAABAAkPSzwf_rW06zqGHgRJd5m-CcPp2fqh1nbi4-D4MPr0yEZ_LmLTk-y90L6BnwpRtmdoEleDv_tBAey4A6r7Zmj161Lia1LjMpsFaGxaJ2l3ur5lZ4Sk68l_OyUWI2apyy2LwjMjClMmLdUoEJvMYXRjboh9tkfgxHmcFG5CKlfrbxMNFQgArwAAAAEAjPdtSZequsXSTGlesm7S5KZy-mQmq2Lzy6pfVg3ilK_gWek68VSDX6-VI4060b4VKQ1gSn_rCV8aTNwitnPXGWD3jwB7nSY5jJ7p7QWQjB-YjfteogduP6RfdpwMmwE33XI7wQAMwhZJTPJ1MLvtoleD-4EUgeQjNUCnmBc9jS_PbE366Y5gsU1r-6Xx4TIItnzOlk08t3tryiRFRt8UacBQTfq7grZhUtYbnqFlI0obQ4YmJPsf9xmSt1Fnfp6_UgEhIRJq0lxXN9MbCACvAAAAAQCuPzGx34YUWXcgPxSl47tXL4ySUnDUH-yjjQ97cGiGMFDUklqvIeoH2RaGccEmv2F2sTMmkMwL7RmWJJ7-QVRnZGO7Tuiku8iZTLOCprQpHSmM91jNZ4hMC4VzXmwf1JK0GpzHS7RJfs2Q-RVZWdaIRV6Kc2elUhkjFNza5id9l35fbS6OHp4Voc80XYaP7E-SdNj0HC9H_i4rW3F_QFVDmhlnIKR8W9i_OkjtDQI_Ip56LzeyOHdZ1OmIjiSMlSj1pdexpLhIVTu4BvcIAK8AAAABAIKELQtnxBhaSt3meSfSr-7V2mnbaL3oy3tAC2xckuRsUim4t272AysFQUSD4raDlIRbqdn4ncYkHwVopoJyVvFLx4QxINHpx6ekkdPNHKhSkso00l0-X_wQkumYe10PBSGCVUoJrhR9i3J3AiJOmhT-WRa2STILuwZDmM9RV3v2xxdNd6crHiRWb5-EDqYTmqzyWkuEqz5e9yMX5Ou3SJpt0m9YmQufEwsmPTHciakfvnvUoD43kjzq9FMS-5PM0_EuefSLl21mIOGtbwgAMQAAAAEAkXs5bT_pg_JN2AbrHFNtG8EceHuAVwBrBYhhLXsLtThzyITtUy2nprjQOOzZsg',
            '3. Block1 Block4 swap':
               'u8KB6jsBD7RqHv6lL7hSJRV2jUkislgTfFwOnZcUXeEIAD8AAAABAGk01JsVguGy1M7NC1OucFCIn1mDPW9NF9fG28EAAAAAAAAA_73nwB7qi2-Rw0nn6NbQRcyJYFRTnTC9wCMKUyYt1SgQm8xhdGNuiH22R-DEeZwUbkIqV-tvEw0VCACvAAAAAQCM921Jl6q6xdJMaV6ybtLkpnL6ZCarYvPLql9WDeKUr-BZ6TrxVINfr5UjjTrRvhUpDWBKf-sJXxpM3CK2c9cZYPePAHudJjmMnuntBZCMH5iN-16iB24_pF92nAybATfdcjvBAAzCFklM8nUwu-2iV4P7gRSB5CM1QKeYFz2NL89sTfrpjmCxTWv7pfHhMgi2fM6WTTy3e2vKJEVG3xRpwFBN-ruCtmFS1hue5r4p4v5bweBgOiuLICGwct-OryvSYH2Oq18g_Hk2oF8IAEMAAAABACXCvYTnZ0VTnlNxPa6rkw40VPBm7xqqrhs7L5Vz4edsEX4qC67AVA_91meysInCfAzZxgY2eGsUFwnVNx8sau2-ww9yN94GJioBqCODX2XtpazJclg_VZzTgrt4Xl7FOQgAZwAAAAEACQ9LPB_-tbTrOoYeBEl3mb4Jw-nZ-qHWduLj4Pgw-vTIRn8uYtOT7L3QvoGfClG2Z2gSV4O_-0EB7LgDqvtmaPXrUuJrUuMymwVobFonaXe6vmVnhKTryX87JRYjZqnLLYvCM9yJqR--e9SgPjeSPOr0UxL7k8zT8S559IuXbWYg4a1vCAAxAAAAAQCRezltP-mD8k3YBuscU20bwRx4e4BXAGsFiGEtewu1OHPIhO1TLaemuNA47NmyoWUjShtDhiYk-x_3GZK3UWd-nr9SASEhEmrSXFc30xsIAK8AAAABAK4_MbHfhhRZdyA_FKXju1cvjJJScNQf7KOND3twaIYwUNSSWq8h6gfZFoZxwSa_YXaxMyaQzAvtGZYknv5BVGdkY7tO6KS7yJlMs4KmtCkdKYz3WM1niEwLhXNebB_UkrQanMdLtEl-zZD5FVlZ1ohFXopzZ6VSGSMU3NrmJ32Xfl9tLo4enhWhzzRdho_sT5J02PQcL0f-LitbcX9AVUOaGWcgpHxb2L86SO0NAj8innovN7I4d1nU6YiOJIyVKPWl17GkuEhVO7gG9wgArwAAAAEAgoQtC2fEGFpK3eZ5J9Kv7tXaadtovejLe0ALbFyS5GxSKbi3bvYDKwVBRIPitoOUhFup2fidxiQfBWimgnJW8UvHhDEg0enHp6SR080cqFKSyjTSXT5f_BCS6Zh7XQ8FIYJVSgmuFH2LcncCIk6aFP5ZFrZJMgu7BkOYz1FXe_bHF013pyseJFZvn4QOphOarPJaS4SrPl73Ixfk67dImm3Sb1iZC58TCyY9MUQGJajdfbumAWBmHAhRC38uFh5xaumuEG_BgaZAcULVCAA4AAABAQADuUGeR6DW0_mgwgOCgw8CYdnYyjL2mRWOpoYuTS8jLiZd6CNzRlu9Ly2fBCRv67u-GsMb6w',
            '4. Block0 repeated':
               'u8KB6jsBD7RqHv6lL7hSJRV2jUkislgTfFwOnZcUXeEIAD8AAAABAGk01JsVguGy1M7NC1OucFCIn1mDPW9NF9fG28EAAAAAAAAA_73nwB7qi2-Rw0nn6NbQRcyJYFRTnTC9wLvCgeo7AQ-0ah7-pS-4UiUVdo1JIrJYE3xcDp2XFF3hCAA_AAAAAQBpNNSbFYLhstTOzQtTrnBQiJ9Zgz1vTRfXxtvBAAAAAAAAAP-958Ae6otvkcNJ5-jW0EXMiWBUU50wvcDciakfvnvUoD43kjzq9FMS-5PM0_EuefSLl21mIOGtbwgAMQAAAAEAkXs5bT_pg_JN2AbrHFNtG8EceHuAVwBrBYhhLXsLtThzyITtUy2nprjQOOzZsua-KeL-W8HgYDoriyAhsHLfjq8r0mB9jqtfIPx5NqBfCABDAAAAAQAlwr2E52dFU55TcT2uq5MONFTwZu8aqq4bOy-Vc-HnbBF-KguuwFQP_dZnsrCJwnwM2cYGNnhrFBcJ1TcfLGrtvsMPcjfeBiYqAagjg19l7aWsyXJYP1Wc04K7eF5exTkIAGcAAAABAAkPSzwf_rW06zqGHgRJd5m-CcPp2fqh1nbi4-D4MPr0yEZ_LmLTk-y90L6BnwpRtmdoEleDv_tBAey4A6r7Zmj161Lia1LjMpsFaGxaJ2l3ur5lZ4Sk68l_OyUWI2apyy2LwjMjClMmLdUoEJvMYXRjboh9tkfgxHmcFG5CKlfrbxMNFQgArwAAAAEAjPdtSZequsXSTGlesm7S5KZy-mQmq2Lzy6pfVg3ilK_gWek68VSDX6-VI4060b4VKQ1gSn_rCV8aTNwitnPXGWD3jwB7nSY5jJ7p7QWQjB-YjfteogduP6RfdpwMmwE33XI7wQAMwhZJTPJ1MLvtoleD-4EUgeQjNUCnmBc9jS_PbE366Y5gsU1r-6Xx4TIItnzOlk08t3tryiRFRt8UacBQTfq7grZhUtYbnqFlI0obQ4YmJPsf9xmSt1Fnfp6_UgEhIRJq0lxXN9MbCACvAAAAAQCuPzGx34YUWXcgPxSl47tXL4ySUnDUH-yjjQ97cGiGMFDUklqvIeoH2RaGccEmv2F2sTMmkMwL7RmWJJ7-QVRnZGO7Tuiku8iZTLOCprQpHSmM91jNZ4hMC4VzXmwf1JK0GpzHS7RJfs2Q-RVZWdaIRV6Kc2elUhkjFNza5id9l35fbS6OHp4Voc80XYaP7E-SdNj0HC9H_i4rW3F_QFVDmhlnIKR8W9i_OkjtDQI_Ip56LzeyOHdZ1OmIjiSMlSj1pdexpLhIVTu4BvcIAK8AAAABAIKELQtnxBhaSt3meSfSr-7V2mnbaL3oy3tAC2xckuRsUim4t272AysFQUSD4raDlIRbqdn4ncYkHwVopoJyVvFLx4QxINHpx6ekkdPNHKhSkso00l0-X_wQkumYe10PBSGCVUoJrhR9i3J3AiJOmhT-WRa2STILuwZDmM9RV3v2xxdNd6crHiRWb5-EDqYTmqzyWkuEqz5e9yMX5Ou3SJpt0m9YmQufEwsmPTFEBiWo3X27pgFgZhwIUQt_LhYecWrprhBvwYGmQHFC1QgAOAAAAQEAA7lBnkeg1tP5oMIDgoMPAmHZ2Moy9pkVjqaGLk0vIy4mXegjc0ZbvS8tnwQkb-u7vhrDG-s',
            '5. Block0 deleted':
               '3ImpH7571KA-N5I86vRTEvuTzNPxLnn0i5dtZiDhrW8IADEAAAABAJF7OW0_6YPyTdgG6xxTbRvBHHh7gFcAawWIYS17C7U4c8iE7VMtp6a40Djs2bLmvini_lvB4GA6K4sgIbBy346vK9JgfY6rXyD8eTagXwgAQwAAAAEAJcK9hOdnRVOeU3E9rquTDjRU8GbvGqquGzsvlXPh52wRfioLrsBUD_3WZ7KwicJ8DNnGBjZ4axQXCdU3Hyxq7b7DD3I33gYmKgGoI4NfZe2lrMlyWD9VnNOCu3heXsU5CABnAAAAAQAJD0s8H_61tOs6hh4ESXeZvgnD6dn6odZ24uPg-DD69MhGfy5i05PsvdC-gZ8KUbZnaBJXg7_7QQHsuAOq-2Zo9etS4mtS4zKbBWhsWidpd7q-ZWeEpOvJfzslFiNmqcsti8IzIwpTJi3VKBCbzGF0Y26IfbZH4MR5nBRuQipX628TDRUIAK8AAAABAIz3bUmXqrrF0kxpXrJu0uSmcvpkJqti88uqX1YN4pSv4FnpOvFUg1-vlSONOtG-FSkNYEp_6wlfGkzcIrZz1xlg948Ae50mOYye6e0FkIwfmI37XqIHbj-kX3acDJsBN91yO8EADMIWSUzydTC77aJXg_uBFIHkIzVAp5gXPY0vz2xN-umOYLFNa_ul8eEyCLZ8zpZNPLd7a8okRUbfFGnAUE36u4K2YVLWG56hZSNKG0OGJiT7H_cZkrdRZ36ev1IBISESatJcVzfTGwgArwAAAAEArj8xsd-GFFl3ID8UpeO7Vy-MklJw1B_so40Pe3BohjBQ1JJaryHqB9kWhnHBJr9hdrEzJpDMC-0ZliSe_kFUZ2Rju07opLvImUyzgqa0KR0pjPdYzWeITAuFc15sH9SStBqcx0u0SX7NkPkVWVnWiEVeinNnpVIZIxTc2uYnfZd-X20ujh6eFaHPNF2Gj-xPknTY9BwvR_4uK1txf0BVQ5oZZyCkfFvYvzpI7Q0CPyKeei83sjh3WdTpiI4kjJUo9aXXsaS4SFU7uAb3CACvAAAAAQCChC0LZ8QYWkrd5nkn0q_u1dpp22i96Mt7QAtsXJLkbFIpuLdu9gMrBUFEg-K2g5SEW6nZ-J3GJB8FaKaCclbxS8eEMSDR6cenpJHTzRyoUpLKNNJdPl_8EJLpmHtdDwUhglVKCa4UfYtydwIiTpoU_lkWtkkyC7sGQ5jPUVd79scXTXenKx4kVm-fhA6mE5qs8lpLhKs-XvcjF-Trt0iabdJvWJkLnxMLJj0xRAYlqN19u6YBYGYcCFELfy4WHnFq6a4Qb8GBpkBxQtUIADgAAAEBAAO5QZ5HoNbT-aDCA4KDDwJh2djKMvaZFY6mhi5NLyMuJl3oI3NGW70vLZ8EJG_ru74awxvr',
            '6. Block1 repeated':
               'u8KB6jsBD7RqHv6lL7hSJRV2jUkislgTfFwOnZcUXeEIAD8AAAABAGk01JsVguGy1M7NC1OucFCIn1mDPW9NF9fG28EAAAAAAAAA_73nwB7qi2-Rw0nn6NbQRcyJYFRTnTC9wNyJqR--e9SgPjeSPOr0UxL7k8zT8S559IuXbWYg4a1vCAAxAAAAAQCRezltP-mD8k3YBuscU20bwRx4e4BXAGsFiGEtewu1OHPIhO1TLaemuNA47Nmy3ImpH7571KA-N5I86vRTEvuTzNPxLnn0i5dtZiDhrW8IADEAAAABAJF7OW0_6YPyTdgG6xxTbRvBHHh7gFcAawWIYS17C7U4c8iE7VMtp6a40Djs2bLmvini_lvB4GA6K4sgIbBy346vK9JgfY6rXyD8eTagXwgAQwAAAAEAJcK9hOdnRVOeU3E9rquTDjRU8GbvGqquGzsvlXPh52wRfioLrsBUD_3WZ7KwicJ8DNnGBjZ4axQXCdU3Hyxq7b7DD3I33gYmKgGoI4NfZe2lrMlyWD9VnNOCu3heXsU5CABnAAAAAQAJD0s8H_61tOs6hh4ESXeZvgnD6dn6odZ24uPg-DD69MhGfy5i05PsvdC-gZ8KUbZnaBJXg7_7QQHsuAOq-2Zo9etS4mtS4zKbBWhsWidpd7q-ZWeEpOvJfzslFiNmqcsti8IzIwpTJi3VKBCbzGF0Y26IfbZH4MR5nBRuQipX628TDRUIAK8AAAABAIz3bUmXqrrF0kxpXrJu0uSmcvpkJqti88uqX1YN4pSv4FnpOvFUg1-vlSONOtG-FSkNYEp_6wlfGkzcIrZz1xlg948Ae50mOYye6e0FkIwfmI37XqIHbj-kX3acDJsBN91yO8EADMIWSUzydTC77aJXg_uBFIHkIzVAp5gXPY0vz2xN-umOYLFNa_ul8eEyCLZ8zpZNPLd7a8okRUbfFGnAUE36u4K2YVLWG56hZSNKG0OGJiT7H_cZkrdRZ36ev1IBISESatJcVzfTGwgArwAAAAEArj8xsd-GFFl3ID8UpeO7Vy-MklJw1B_so40Pe3BohjBQ1JJaryHqB9kWhnHBJr9hdrEzJpDMC-0ZliSe_kFUZ2Rju07opLvImUyzgqa0KR0pjPdYzWeITAuFc15sH9SStBqcx0u0SX7NkPkVWVnWiEVeinNnpVIZIxTc2uYnfZd-X20ujh6eFaHPNF2Gj-xPknTY9BwvR_4uK1txf0BVQ5oZZyCkfFvYvzpI7Q0CPyKeei83sjh3WdTpiI4kjJUo9aXXsaS4SFU7uAb3CACvAAAAAQCChC0LZ8QYWkrd5nkn0q_u1dpp22i96Mt7QAtsXJLkbFIpuLdu9gMrBUFEg-K2g5SEW6nZ-J3GJB8FaKaCclbxS8eEMSDR6cenpJHTzRyoUpLKNNJdPl_8EJLpmHtdDwUhglVKCa4UfYtydwIiTpoU_lkWtkkyC7sGQ5jPUVd79scXTXenKx4kVm-fhA6mE5qs8lpLhKs-XvcjF-Trt0iabdJvWJkLnxMLJj0xRAYlqN19u6YBYGYcCFELfy4WHnFq6a4Qb8GBpkBxQtUIADgAAAEBAAO5QZ5HoNbT-aDCA4KDDwJh2djKMvaZFY6mhi5NLyMuJl3oI3NGW70vLZ8EJG_ru74awxvr',
            '7. Block1 deleted':
               'u8KB6jsBD7RqHv6lL7hSJRV2jUkislgTfFwOnZcUXeEIAD8AAAABAGk01JsVguGy1M7NC1OucFCIn1mDPW9NF9fG28EAAAAAAAAA_73nwB7qi2-Rw0nn6NbQRcyJYFRTnTC9wOa-KeL-W8HgYDoriyAhsHLfjq8r0mB9jqtfIPx5NqBfCABDAAAAAQAlwr2E52dFU55TcT2uq5MONFTwZu8aqq4bOy-Vc-HnbBF-KguuwFQP_dZnsrCJwnwM2cYGNnhrFBcJ1TcfLGrtvsMPcjfeBiYqAagjg19l7aWsyXJYP1Wc04K7eF5exTkIAGcAAAABAAkPSzwf_rW06zqGHgRJd5m-CcPp2fqh1nbi4-D4MPr0yEZ_LmLTk-y90L6BnwpRtmdoEleDv_tBAey4A6r7Zmj161Lia1LjMpsFaGxaJ2l3ur5lZ4Sk68l_OyUWI2apyy2LwjMjClMmLdUoEJvMYXRjboh9tkfgxHmcFG5CKlfrbxMNFQgArwAAAAEAjPdtSZequsXSTGlesm7S5KZy-mQmq2Lzy6pfVg3ilK_gWek68VSDX6-VI4060b4VKQ1gSn_rCV8aTNwitnPXGWD3jwB7nSY5jJ7p7QWQjB-YjfteogduP6RfdpwMmwE33XI7wQAMwhZJTPJ1MLvtoleD-4EUgeQjNUCnmBc9jS_PbE366Y5gsU1r-6Xx4TIItnzOlk08t3tryiRFRt8UacBQTfq7grZhUtYbnqFlI0obQ4YmJPsf9xmSt1Fnfp6_UgEhIRJq0lxXN9MbCACvAAAAAQCuPzGx34YUWXcgPxSl47tXL4ySUnDUH-yjjQ97cGiGMFDUklqvIeoH2RaGccEmv2F2sTMmkMwL7RmWJJ7-QVRnZGO7Tuiku8iZTLOCprQpHSmM91jNZ4hMC4VzXmwf1JK0GpzHS7RJfs2Q-RVZWdaIRV6Kc2elUhkjFNza5id9l35fbS6OHp4Voc80XYaP7E-SdNj0HC9H_i4rW3F_QFVDmhlnIKR8W9i_OkjtDQI_Ip56LzeyOHdZ1OmIjiSMlSj1pdexpLhIVTu4BvcIAK8AAAABAIKELQtnxBhaSt3meSfSr-7V2mnbaL3oy3tAC2xckuRsUim4t272AysFQUSD4raDlIRbqdn4ncYkHwVopoJyVvFLx4QxINHpx6ekkdPNHKhSkso00l0-X_wQkumYe10PBSGCVUoJrhR9i3J3AiJOmhT-WRa2STILuwZDmM9RV3v2xxdNd6crHiRWb5-EDqYTmqzyWkuEqz5e9yMX5Ou3SJpt0m9YmQufEwsmPTFEBiWo3X27pgFgZhwIUQt_LhYecWrprhBvwYGmQHFC1QgAOAAAAQEAA7lBnkeg1tP5oMIDgoMPAmHZ2Moy9pkVjqaGLk0vIy4mXegjc0ZbvS8tnwQkb-u7vhrDG-s',
            '8. Block2 repeated':
               'u8KB6jsBD7RqHv6lL7hSJRV2jUkislgTfFwOnZcUXeEIAD8AAAABAGk01JsVguGy1M7NC1OucFCIn1mDPW9NF9fG28EAAAAAAAAA_73nwB7qi2-Rw0nn6NbQRcyJYFRTnTC9wNyJqR--e9SgPjeSPOr0UxL7k8zT8S559IuXbWYg4a1vCAAxAAAAAQCRezltP-mD8k3YBuscU20bwRx4e4BXAGsFiGEtewu1OHPIhO1TLaemuNA47Nmy5r4p4v5bweBgOiuLICGwct-OryvSYH2Oq18g_Hk2oF8IAEMAAAABACXCvYTnZ0VTnlNxPa6rkw40VPBm7xqqrhs7L5Vz4edsEX4qC67AVA_91meysInCfAzZxgY2eGsUFwnVNx8sau3mvini_lvB4GA6K4sgIbBy346vK9JgfY6rXyD8eTagXwgAQwAAAAEAJcK9hOdnRVOeU3E9rquTDjRU8GbvGqquGzsvlXPh52wRfioLrsBUD_3WZ7KwicJ8DNnGBjZ4axQXCdU3Hyxq7b7DD3I33gYmKgGoI4NfZe2lrMlyWD9VnNOCu3heXsU5CABnAAAAAQAJD0s8H_61tOs6hh4ESXeZvgnD6dn6odZ24uPg-DD69MhGfy5i05PsvdC-gZ8KUbZnaBJXg7_7QQHsuAOq-2Zo9etS4mtS4zKbBWhsWidpd7q-ZWeEpOvJfzslFiNmqcsti8IzIwpTJi3VKBCbzGF0Y26IfbZH4MR5nBRuQipX628TDRUIAK8AAAABAIz3bUmXqrrF0kxpXrJu0uSmcvpkJqti88uqX1YN4pSv4FnpOvFUg1-vlSONOtG-FSkNYEp_6wlfGkzcIrZz1xlg948Ae50mOYye6e0FkIwfmI37XqIHbj-kX3acDJsBN91yO8EADMIWSUzydTC77aJXg_uBFIHkIzVAp5gXPY0vz2xN-umOYLFNa_ul8eEyCLZ8zpZNPLd7a8okRUbfFGnAUE36u4K2YVLWG56hZSNKG0OGJiT7H_cZkrdRZ36ev1IBISESatJcVzfTGwgArwAAAAEArj8xsd-GFFl3ID8UpeO7Vy-MklJw1B_so40Pe3BohjBQ1JJaryHqB9kWhnHBJr9hdrEzJpDMC-0ZliSe_kFUZ2Rju07opLvImUyzgqa0KR0pjPdYzWeITAuFc15sH9SStBqcx0u0SX7NkPkVWVnWiEVeinNnpVIZIxTc2uYnfZd-X20ujh6eFaHPNF2Gj-xPknTY9BwvR_4uK1txf0BVQ5oZZyCkfFvYvzpI7Q0CPyKeei83sjh3WdTpiI4kjJUo9aXXsaS4SFU7uAb3CACvAAAAAQCChC0LZ8QYWkrd5nkn0q_u1dpp22i96Mt7QAtsXJLkbFIpuLdu9gMrBUFEg-K2g5SEW6nZ-J3GJB8FaKaCclbxS8eEMSDR6cenpJHTzRyoUpLKNNJdPl_8EJLpmHtdDwUhglVKCa4UfYtydwIiTpoU_lkWtkkyC7sGQ5jPUVd79scXTXenKx4kVm-fhA6mE5qs8lpLhKs-XvcjF-Trt0iabdJvWJkLnxMLJj0xRAYlqN19u6YBYGYcCFELfy4WHnFq6a4Qb8GBpkBxQtUIADgAAAEBAAO5QZ5HoNbT-aDCA4KDDwJh2djKMvaZFY6mhi5NLyMuJl3oI3NGW70vLZ8EJG_ru74awxvr',
            '9. Block2 deleted':
               'u8KB6jsBD7RqHv6lL7hSJRV2jUkislgTfFwOnZcUXeEIAD8AAAABAGk01JsVguGy1M7NC1OucFCIn1mDPW9NF9fG28EAAAAAAAAA_73nwB7qi2-Rw0nn6NbQRcyJYFRTnTC9wNyJqR--e9SgPjeSPOr0UxL7k8zT8S559IuXbWYg4a1vCAAxAAAAAQCRezltP-mD8k3YBuscU20bwRx4e4BXAGsFiGEtewu1OHPIhO1TLaemuNA47NmyvsMPcjfeBiYqAagjg19l7aWsyXJYP1Wc04K7eF5exTkIAGcAAAABAAkPSzwf_rW06zqGHgRJd5m-CcPp2fqh1nbi4-D4MPr0yEZ_LmLTk-y90L6BnwpRtmdoEleDv_tBAey4A6r7Zmj161Lia1LjMpsFaGxaJ2l3ur5lZ4Sk68l_OyUWI2apyy2LwjMjClMmLdUoEJvMYXRjboh9tkfgxHmcFG5CKlfrbxMNFQgArwAAAAEAjPdtSZequsXSTGlesm7S5KZy-mQmq2Lzy6pfVg3ilK_gWek68VSDX6-VI4060b4VKQ1gSn_rCV8aTNwitnPXGWD3jwB7nSY5jJ7p7QWQjB-YjfteogduP6RfdpwMmwE33XI7wQAMwhZJTPJ1MLvtoleD-4EUgeQjNUCnmBc9jS_PbE366Y5gsU1r-6Xx4TIItnzOlk08t3tryiRFRt8UacBQTfq7grZhUtYbnqFlI0obQ4YmJPsf9xmSt1Fnfp6_UgEhIRJq0lxXN9MbCACvAAAAAQCuPzGx34YUWXcgPxSl47tXL4ySUnDUH-yjjQ97cGiGMFDUklqvIeoH2RaGccEmv2F2sTMmkMwL7RmWJJ7-QVRnZGO7Tuiku8iZTLOCprQpHSmM91jNZ4hMC4VzXmwf1JK0GpzHS7RJfs2Q-RVZWdaIRV6Kc2elUhkjFNza5id9l35fbS6OHp4Voc80XYaP7E-SdNj0HC9H_i4rW3F_QFVDmhlnIKR8W9i_OkjtDQI_Ip56LzeyOHdZ1OmIjiSMlSj1pdexpLhIVTu4BvcIAK8AAAABAIKELQtnxBhaSt3meSfSr-7V2mnbaL3oy3tAC2xckuRsUim4t272AysFQUSD4raDlIRbqdn4ncYkHwVopoJyVvFLx4QxINHpx6ekkdPNHKhSkso00l0-X_wQkumYe10PBSGCVUoJrhR9i3J3AiJOmhT-WRa2STILuwZDmM9RV3v2xxdNd6crHiRWb5-EDqYTmqzyWkuEqz5e9yMX5Ou3SJpt0m9YmQufEwsmPTFEBiWo3X27pgFgZhwIUQt_LhYecWrprhBvwYGmQHFC1QgAOAAAAQEAA7lBnkeg1tP5oMIDgoMPAmHZ2Moy9pkVjqaGLk0vIy4mXegjc0ZbvS8tnwQkb-u7vhrDG-s',
            '10. Block7 (last) repeated':
               'u8KB6jsBD7RqHv6lL7hSJRV2jUkislgTfFwOnZcUXeEIAD8AAAABAGk01JsVguGy1M7NC1OucFCIn1mDPW9NF9fG28EAAAAAAAAA_73nwB7qi2-Rw0nn6NbQRcyJYFRTnTC9wNyJqR--e9SgPjeSPOr0UxL7k8zT8S559IuXbWYg4a1vCAAxAAAAAQCRezltP-mD8k3YBuscU20bwRx4e4BXAGsFiGEtewu1OHPIhO1TLaemuNA47Nmy5r4p4v5bweBgOiuLICGwct-OryvSYH2Oq18g_Hk2oF8IAEMAAAABACXCvYTnZ0VTnlNxPa6rkw40VPBm7xqqrhs7L5Vz4edsEX4qC67AVA_91meysInCfAzZxgY2eGsUFwnVNx8sau2-ww9yN94GJioBqCODX2XtpazJclg_VZzTgrt4Xl7FOQgAZwAAAAEACQ9LPB_-tbTrOoYeBEl3mb4Jw-nZ-qHWduLj4Pgw-vTIRn8uYtOT7L3QvoGfClG2Z2gSV4O_-0EB7LgDqvtmaPXrUuJrUuMymwVobFonaXe6vmVnhKTryX87JRYjZqnLLYvCMyMKUyYt1SgQm8xhdGNuiH22R-DEeZwUbkIqV-tvEw0VCACvAAAAAQCM921Jl6q6xdJMaV6ybtLkpnL6ZCarYvPLql9WDeKUr-BZ6TrxVINfr5UjjTrRvhUpDWBKf-sJXxpM3CK2c9cZYPePAHudJjmMnuntBZCMH5iN-16iB24_pF92nAybATfdcjvBAAzCFklM8nUwu-2iV4P7gRSB5CM1QKeYFz2NL89sTfrpjmCxTWv7pfHhMgi2fM6WTTy3e2vKJEVG3xRpwFBN-ruCtmFS1hueoWUjShtDhiYk-x_3GZK3UWd-nr9SASEhEmrSXFc30xsIAK8AAAABAK4_MbHfhhRZdyA_FKXju1cvjJJScNQf7KOND3twaIYwUNSSWq8h6gfZFoZxwSa_YXaxMyaQzAvtGZYknv5BVGdkY7tO6KS7yJlMs4KmtCkdKYz3WM1niEwLhXNebB_UkrQanMdLtEl-zZD5FVlZ1ohFXopzZ6VSGSMU3NrmJ32Xfl9tLo4enhWhzzRdho_sT5J02PQcL0f-LitbcX9AVUOaGWcgpHxb2L86SO0NAj8innovN7I4d1nU6YiOJIyVKPWl17GkuEhVO7gG9wgArwAAAAEAgoQtC2fEGFpK3eZ5J9Kv7tXaadtovejLe0ALbFyS5GxSKbi3bvYDKwVBRIPitoOUhFup2fidxiQfBWimgnJW8UvHhDEg0enHp6SR080cqFKSyjTSXT5f_BCS6Zh7XQ8FIYJVSgmuFH2LcncCIk6aFP5ZFrZJMgu7BkOYz1FXe_bHF013pyseJFZvn4QOphOarPJaS4SrPl73Ixfk67dImm3Sb1iZC58TCyY9MUQGJajdfbumAWBmHAhRC38uFh5xaumuEG_BgaZAcULVCAA4AAABAQADuUGeR6DW0_mgwgOCgw8CYdnYyjL2mRWOpoYuTS8jLiZd6CNzRlu9Ly2fBCRv67u-GsMb60QGJajdfbumAWBmHAhRC38uFh5xaumuEG_BgaZAcULVCAA4AAABAQADuUGeR6DW0_mgwgOCgw8CYdnYyjL2mRWOpoYuTS8jLiZd6CNzRlu9Ly2fBCRv67u-GsMb6w',
            '11. Block7 (last) deleted':
               'u8KB6jsBD7RqHv6lL7hSJRV2jUkislgTfFwOnZcUXeEIAD8AAAABAGk01JsVguGy1M7NC1OucFCIn1mDPW9NF9fG28EAAAAAAAAA_73nwB7qi2-Rw0nn6NbQRcyJYFRTnTC9wNyJqR--e9SgPjeSPOr0UxL7k8zT8S559IuXbWYg4a1vCAAxAAAAAQCRezltP-mD8k3YBuscU20bwRx4e4BXAGsFiGEtewu1OHPIhO1TLaemuNA47Nmy5r4p4v5bweBgOiuLICGwct-OryvSYH2Oq18g_Hk2oF8IAEMAAAABACXCvYTnZ0VTnlNxPa6rkw40VPBm7xqqrhs7L5Vz4edsEX4qC67AVA_91meysInCfAzZxgY2eGsUFwnVNx8sau2-ww9yN94GJioBqCODX2XtpazJclg_VZzTgrt4Xl7FOQgAZwAAAAEACQ9LPB_-tbTrOoYeBEl3mb4Jw-nZ-qHWduLj4Pgw-vTIRn8uYtOT7L3QvoGfClG2Z2gSV4O_-0EB7LgDqvtmaPXrUuJrUuMymwVobFonaXe6vmVnhKTryX87JRYjZqnLLYvCMyMKUyYt1SgQm8xhdGNuiH22R-DEeZwUbkIqV-tvEw0VCACvAAAAAQCM921Jl6q6xdJMaV6ybtLkpnL6ZCarYvPLql9WDeKUr-BZ6TrxVINfr5UjjTrRvhUpDWBKf-sJXxpM3CK2c9cZYPePAHudJjmMnuntBZCMH5iN-16iB24_pF92nAybATfdcjvBAAzCFklM8nUwu-2iV4P7gRSB5CM1QKeYFz2NL89sTfrpjmCxTWv7pfHhMgi2fM6WTTy3e2vKJEVG3xRpwFBN-ruCtmFS1hueoWUjShtDhiYk-x_3GZK3UWd-nr9SASEhEmrSXFc30xsIAK8AAAABAK4_MbHfhhRZdyA_FKXju1cvjJJScNQf7KOND3twaIYwUNSSWq8h6gfZFoZxwSa_YXaxMyaQzAvtGZYknv5BVGdkY7tO6KS7yJlMs4KmtCkdKYz3WM1niEwLhXNebB_UkrQanMdLtEl-zZD5FVlZ1ohFXopzZ6VSGSMU3NrmJ32Xfl9tLo4enhWhzzRdho_sT5J02PQcL0f-LitbcX9AVUOaGWcgpHxb2L86SO0NAj8innovN7I4d1nU6YiOJIyVKPWl17GkuEhVO7gG9wgArwAAAAEAgoQtC2fEGFpK3eZ5J9Kv7tXaadtovejLe0ALbFyS5GxSKbi3bvYDKwVBRIPitoOUhFup2fidxiQfBWimgnJW8UvHhDEg0enHp6SR080cqFKSyjTSXT5f_BCS6Zh7XQ8FIYJVSgmuFH2LcncCIk6aFP5ZFrZJMgu7BkOYz1FXe_bHF013pyseJFZvn4QOphOarPJaS4SrPl73Ixfk67dImm3Sb1iZC58TCyY9MQ',
            '12. Block1 Block7 deleted':
               'u8KB6jsBD7RqHv6lL7hSJRV2jUkislgTfFwOnZcUXeEIAD8AAAABAGk01JsVguGy1M7NC1OucFCIn1mDPW9NF9fG28EAAAAAAAAA_73nwB7qi2-Rw0nn6NbQRcyJYFRTnTC9wOa-KeL-W8HgYDoriyAhsHLfjq8r0mB9jqtfIPx5NqBfCABDAAAAAQAlwr2E52dFU55TcT2uq5MONFTwZu8aqq4bOy-Vc-HnbBF-KguuwFQP_dZnsrCJwnwM2cYGNnhrFBcJ1TcfLGrtvsMPcjfeBiYqAagjg19l7aWsyXJYP1Wc04K7eF5exTkIAGcAAAABAAkPSzwf_rW06zqGHgRJd5m-CcPp2fqh1nbi4-D4MPr0yEZ_LmLTk-y90L6BnwpRtmdoEleDv_tBAey4A6r7Zmj161Lia1LjMpsFaGxaJ2l3ur5lZ4Sk68l_OyUWI2apyy2LwjMjClMmLdUoEJvMYXRjboh9tkfgxHmcFG5CKlfrbxMNFQgArwAAAAEAjPdtSZequsXSTGlesm7S5KZy-mQmq2Lzy6pfVg3ilK_gWek68VSDX6-VI4060b4VKQ1gSn_rCV8aTNwitnPXGWD3jwB7nSY5jJ7p7QWQjB-YjfteogduP6RfdpwMmwE33XI7wQAMwhZJTPJ1MLvtoleD-4EUgeQjNUCnmBc9jS_PbE366Y5gsU1r-6Xx4TIItnzOlk08t3tryiRFRt8UacBQTfq7grZhUtYbnqFlI0obQ4YmJPsf9xmSt1Fnfp6_UgEhIRJq0lxXN9MbCACvAAAAAQCuPzGx34YUWXcgPxSl47tXL4ySUnDUH-yjjQ97cGiGMFDUklqvIeoH2RaGccEmv2F2sTMmkMwL7RmWJJ7-QVRnZGO7Tuiku8iZTLOCprQpHSmM91jNZ4hMC4VzXmwf1JK0GpzHS7RJfs2Q-RVZWdaIRV6Kc2elUhkjFNza5id9l35fbS6OHp4Voc80XYaP7E-SdNj0HC9H_i4rW3F_QFVDmhlnIKR8W9i_OkjtDQI_Ip56LzeyOHdZ1OmIjiSMlSj1pdexpLhIVTu4BvcIAK8AAAABAIKELQtnxBhaSt3meSfSr-7V2mnbaL3oy3tAC2xckuRsUim4t272AysFQUSD4raDlIRbqdn4ncYkHwVopoJyVvFLx4QxINHpx6ekkdPNHKhSkso00l0-X_wQkumYe10PBSGCVUoJrhR9i3J3AiJOmhT-WRa2STILuwZDmM9RV3v2xxdNd6crHiRWb5-EDqYTmqzyWkuEqz5e9yMX5Ou3SJpt0m9YmQufEwsmPTE',
            '13. All Term':
               'V-WJig9SFPljzmMFBltEhgU8bR-9G2JFtO1xUZwO2_0IAD8AAAEBAMjMY1g96UYGON2CXcdC-_1La1tBpzbNkICsI70AAAAAAAAAaE-Y9sUp-0IftlII7BRa-5zFmx1M_OgBVFrhcRFM4yDRJYqtYzMAd2alyVbF0igno23qa-Q_XnhOCAAxAAABAQC99H-SQjp4OgaUl8_xzwduQyYQOqEOXIt90YFVMmhWM2JFCRwVM9EtkNlxMvOJxldcHJkbZJ014thuxFNACgMXF-m9yvdiKaalivY5u-cIAEMAAAEBABelCz07Crcm1Yfc_bvE8wVr6pwerwfIqPHvvhEYeBWVSFoRKCxSgZXqJhxqDrlmiAxMQ8-4av4liDtQymCmxIJUxWvp6eHQ-04EtAEx24-NjzxuCv-tl7WhydFhnlFMyAgAZwAAAQEAmEvkx6JqQFc8OnFFAuVoLdGrRTZkilkrgkL2xjXxDAnq_gTyFAgWW88KMz8wuDGa4KMBYiGH39kThC2ZcwujbFCIlSTJTJU_zhI4iQveL04fyraV1s9WsC_Lf8AAmv-uEVAi92iMvRefmHs-LovUDpDjIBiuC7I2SXWdlLT06TtOgYW-CACvAAABAQAt9XQvtnT4Y-U3RDCf0oQRHpjTm0We8bnKTNtUSadXgdBDNGGIbk1El-L9qAkpW6NUt64r3PmSIO3vdh8C8AyIXGAOcb736-qHO4VioWQ2fOtfHNr3iA9mQ05P7zeB46qS_wpxFv_g_0slk6fgT5aT51a6dCBvQNd4pQJ6Mj8rFuwaIcnm85LNfvpKOLjwSqt-xvee3MJUZTbe2KnWiv1S52DTytNq2mfDNfKael4nAjnKU6SjPgVV_f6NztXBQf0GynCi_bFGdr50ogcIAK8AAAEBADJZaxOp_G3wdU9k3Iimiy505abjIC_j0s5q7k6CjEQRyR1tEwROSu8Z_u8HIQoNEouU0s8CY8eYjYZ5VKWfDbqGe0sPc9LW9TgzLYHy6vEosLUhi8Qh4E8u6bk8EXZqljmnq5ecAnFBm8GzO3-3gPV-GTS9cclOXSWPvcgfgwT7G_aLjt-ryUU_6IxRkGRgLnLylaXxzRfrlSLUcVV6ojM4oEb-de6nLunrlnlNYmVMW0Oythnz0RIoPgXDQn0EPiVjJjblNavjGclPDggArwAAAQEAjVbA9fZ42BI5rQsXfyaFnGzVhyk7ij3HAXcyZRDWyrKnI5NKCoURccALg4KbKVh7GjiGw6bdqYF-i4LSDcDOLYDoHb-m9gnVK2h5acRa5-PqQwZ3zp-UmH_nY0Rknlgh1lPgVeGe22q2mNs5gQrw22Eynicm-r_GEPUdK1IOmL6kqEdxcI8XaQpJqGM6R2icmkY2OdgFxYG37wZLeUXtlabpX5fcSr1pxKtohvXIOwGuV4lJJNFjL_CBmK05gt4k3M_9ctjGQ_m1YqXTCAA4AAABAQCrxbCzbk0WMrPD4n9ad0BNWZLiOSEWn9iIUTXROLI9-OF-3FeG_VxhAigQT54CWpruc6vpGw',
            '14. No Term':
               'yMx2OPPgDHRPviXDLv1gnnCelVcUcpeVNW-Prs9STBUIAD8AAAABAE4n1Rnhz9Skq5TOFK0F3vjn_znIfUnQwlH_uHIAAAAAAAAAHBaJdIiGQAcoJoBXb5L2oQOqtLp5-4E2jrfE4GzIWNSTHCxm58gzheZlHbpfclxyudxc_nnMQD7tCAAxAAAAAQDQBOCUDtKnqO2LNSZBGnd3HE8iCKPHrDPonXo_qToxG-ghL7TmC-LLXE7hmBJCPx1le0K8fHiWmoKC9u3LsleFqaBnialX3hJPOtqC6TgIAEMAAAABAHxrbU6FaK-8q-Be3V8VdrYbaVmYQSA8czL3ukrYFbinumFy-FmJT0JxkPGtggKzz7HDfjcJ1hcmkXht-DHobpF_cYb8-6MFMxOoVh3pQHsKs2JQ4lrIGWPuoGXmp2ET0wgAZwAAAAEA06XG550wWhgnWGu0NkOItCgERt5zY4oV2nAT7cj8ZKExxoSPKwikFaB0IbqBqSsVOZww2x5DtzwnYHetb6C2yhoxKf6-paPxVcGiKoL715gw9Dn97zrTzuAkEMDnsPIaQvDXJ8NIvcNGf7QoKuy6WXmNwKPXitK8E7SAqk3FSfXmTnonCACvAAAAAQC5LLNudFBjLjxzx81sHzQiqR0XqIF4uTj5d-HL0FlZRwcZXzewcoBjufguB-tkLhq5cHmTrmgbUVIFculvO8oRWawoWa5_Vjc8hUAUFoYnduJWH2gYttSJMJd8SXLUaUvCS3ynIXcpvQk2OGTVEQ0K54w_l-6iP73ciF4GsVO8PKDDN0W4PazzF34F2AcZDAC-n5QFntBZyMiGhwS3Q0cIrkNfIvYiJ7dPkET-KoTJD0aLVIGm05u-PHC9sbnSCxO1BaPtLyYJEBCe7N0IAK8AAAABAG8oww7Gfo822C0k4mFfd-OFIVMq8F41z8HpRIOY10kNiUKHOivY1J_8WDrfhSX-YT-lxU8kr1MkVtVuNb1PajJaufhgR-FmgwiPNJ0zC__ijTzXwGEJnChJPDfLs2iwZnPDOCfYj80CU8sXJfSYZtzrrVCrfY0JIrKC2JbQ3NzFJ2J-h0LMt0IkAFVXSZE9kCVRWK5WEDa_MeGTx8nwZxRbMEgMgeqW5D2CAvIsi-NjgkzzuY19Bq8wyidK9pkahkeMdR0R3RhBgp7lLQgArwAAAAEA3LaRGmGx5mQX3qHmFA5tWIztXT60MwYAYHN0AbPpro4w8YtR2EdKIs3ZmzcixC7QN6oWI5GOnTc7Er368BaExY_U4Onp_XY70yQ7eI0tprU8YuerKlvz25V842NG7CRt1FXSkVyq62lQ4FkyO4ncfOcO2WizSwypeyeghwinJrssYdw4JFD-DKvtEw0ezybmGoEtrQbAvbBI-2nx5FPRrxnfw_cfxGaQ3MS6u4YElsUh9nKnDBJTUVs4SL1hfNsHMY7xn-je8RD6B1-aCAA4AAAAAQA6XdDAMxtZfUeHFM9rxoRJeUEbqUwNN70UvVKYKqKbaQ-BzVlNWuN3Z_hr2PNmNX-sFe5WtQ',
         },
      },
      // END GENERATED: v8:blockOrderMaster
   ];

   it('good multi block ciphertext', async () => {
      for (const ver of vers) {
         // First make sure it decrypts as expected
         const [cipherStream] = streamFromBase64(ver.goodCt);
         const decKeyProvider = new MasterKeyKeyProvider(masterKey.slice(0), extraKeyMaterial);
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

   it('block reorder vectors are built from the blocks of the good ciphertext', () => {
      for (const ver of vers) {
         const goodBytes = base64ToBytes(ver.goodCt);
         const goodBlocks = splitBlocks(goodBytes, ver.ver);

         // Splitter control, so a wrong block boundary cannot make the checks below pass
         expect(concatArrays(goodBlocks)).toEqual(goodBytes);
         expect(goodBlocks.length).toBeGreaterThan(1);

         for (const [change, ct] of Object.entries(ver.badCts)) {
            // The term vectors rewrite flag bytes rather than moving whole blocks
            if (!change.includes('Term')) {
               for (const block of splitBlocks(base64ToBytes(ct), ver.ver)) {
                  expect(goodBlocks.some((good) => isEqualArray(good, block))).toBe(true);
               }
            }
         }
      }
   });

   it('changed multi block ciphertext', async () => {
      for (const ver of vers) {
         for (const [_change, ct] of Object.entries(ver.badCts)) {
            const [cipherStream] = streamFromBase64(ct);
            const decKeyProvider = new MasterKeyKeyProvider(masterKey.slice(0), extraKeyMaterial);
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
