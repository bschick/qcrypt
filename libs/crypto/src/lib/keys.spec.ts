/* MIT License

Copyright (c) 2025-2026 Brad Schick

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
import { cryptoReady } from './sodium';
import * as cc from './cipher.consts';
import { PWDKeyProvider } from './keys';
import { PWDKeyProviderOld } from './keys-old';
import { Ciphers } from './ciphers';
import { getRandom } from './utils';
import { isEqualArray } from './utils.spec';

describe("Key generation", function () {
   beforeEach(async () => {
      await cryptoReady();
   });

   it("successful and not equivalent key generation", async function () {

      for (const alg of Ciphers.algs()) {
         const pwd = 'not a good pwd';
         const ic = cc.ICOUNT_MIN;
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

         const randomArray = getRandom(48);
         const slt = randomArray.slice(0, cc.SLT_BYTES);
         const iv = randomArray.slice(cc.SLT_BYTES, cc.SLT_BYTES + 12);

         const keyProvider = new PWDKeyProvider(userCred, [pwd, undefined]);
         keyProvider.setCipherDataInfo({
            ver: cc.CURRENT_VERSION,
            alg,
            ic,
            slt,
            lp: 1,
            lpEnd: 1
         });
         const ek = await keyProvider.getCipherKey(false);
         const sk = await keyProvider.getSigningKey();
         const [hk, hIV] = await keyProvider.getHintCipherKeyAndIV(iv);

         expect(ek.byteLength).toBe(32);
         expect(sk.byteLength).toBe(32);
         expect(hk.byteLength).toBe(32);

         expect(isEqualArray(ek, sk)).toBe(false);
         expect(isEqualArray(ek, hk)).toBe(false);
         expect(isEqualArray(sk, hk)).toBe(false);

         expect(isEqualArray(ek, userCred)).toBe(false);
         expect(isEqualArray(sk, userCred)).toBe(false);
         expect(isEqualArray(hk, userCred)).toBe(false);
      }
   });

   it("traditional keys should match expected values", async function () {

      const expected: Record<number, Record<cc.CipherAlgs, Record<string, Uint8Array>>> = {
         [cc.VERSION5]: {
            'AES-GCM': {
               ek: new Uint8Array([158, 221, 13, 155, 167, 216, 81, 115, 151, 193, 225, 53, 187, 156, 175, 196, 85, 234, 233, 199, 86, 45, 149, 120, 1, 57, 14, 102, 147, 123, 7, 150]),
               sk: new Uint8Array([238, 127, 13, 239, 238, 127, 177, 22, 231, 87, 89, 23, 88, 52, 42, 22, 6, 170, 172, 112, 111, 101, 147, 204, 238, 28, 203, 159, 118, 54, 139, 151]),
               hk: new Uint8Array([253, 30, 237, 129, 147, 186, 235, 65, 217, 78, 219, 38, 163, 12, 23, 248, 3, 118, 123, 120, 237, 0, 56, 103, 67, 76, 88, 126, 153, 83, 238, 85]),
               hIV: new Uint8Array([46, 22, 226, 86, 89, 132, 143, 185, 198, 129, 242, 241, 183, 195, 191, 229, 162, 127, 162, 148, 75, 16, 28, 140]),
            },
            'X20-PLY': {
               ek: new Uint8Array([158, 221, 13, 155, 167, 216, 81, 115, 151, 193, 225, 53, 187, 156, 175, 196, 85, 234, 233, 199, 86, 45, 149, 120, 1, 57, 14, 102, 147, 123, 7, 150]),
               sk: new Uint8Array([238, 127, 13, 239, 238, 127, 177, 22, 231, 87, 89, 23, 88, 52, 42, 22, 6, 170, 172, 112, 111, 101, 147, 204, 238, 28, 203, 159, 118, 54, 139, 151]),
               hk: new Uint8Array([253, 30, 237, 129, 147, 186, 235, 65, 217, 78, 219, 38, 163, 12, 23, 248, 3, 118, 123, 120, 237, 0, 56, 103, 67, 76, 88, 126, 153, 83, 238, 85]),
               hIV: new Uint8Array([46, 22, 226, 86, 89, 132, 143, 185, 198, 129, 242, 241, 183, 195, 191, 229, 162, 127, 162, 148, 75, 16, 28, 140]),
            },
            'AEGIS-256': {
               ek: new Uint8Array([158, 221, 13, 155, 167, 216, 81, 115, 151, 193, 225, 53, 187, 156, 175, 196, 85, 234, 233, 199, 86, 45, 149, 120, 1, 57, 14, 102, 147, 123, 7, 150]),
               sk: new Uint8Array([238, 127, 13, 239, 238, 127, 177, 22, 231, 87, 89, 23, 88, 52, 42, 22, 6, 170, 172, 112, 111, 101, 147, 204, 238, 28, 203, 159, 118, 54, 139, 151]),
               hk: new Uint8Array([253, 30, 237, 129, 147, 186, 235, 65, 217, 78, 219, 38, 163, 12, 23, 248, 3, 118, 123, 120, 237, 0, 56, 103, 67, 76, 88, 126, 153, 83, 238, 85]),
               hIV: new Uint8Array([46, 22, 226, 86, 89, 132, 143, 185, 198, 129, 242, 241, 183, 195, 191, 229, 162, 127, 162, 148, 75, 16, 28, 140]),
            }
         },
         [cc.VERSION6]: {
            'AES-GCM': {
               ek: new Uint8Array([158, 221, 13, 155, 167, 216, 81, 115, 151, 193, 225, 53, 187, 156, 175, 196, 85, 234, 233, 199, 86, 45, 149, 120, 1, 57, 14, 102, 147, 123, 7, 150]),
               sk: new Uint8Array([172, 133, 166, 39, 233, 237, 204, 73, 234, 53, 191, 16, 169, 71, 164, 71, 36, 51, 18, 87, 19, 33, 25, 50, 224, 33, 120, 21, 233, 20, 154, 79]),
               hk: new Uint8Array([34, 121, 121, 4, 207, 55, 202, 73, 83, 4, 58, 102, 135, 111, 186, 242, 3, 187, 239, 108, 251, 245, 3, 245, 3, 77, 228, 197, 101, 4, 16, 94]),
               hIV: new Uint8Array([46, 22, 226, 86, 89, 132, 143, 185, 198, 129, 242, 241, 183, 195, 191, 229, 162, 127, 162, 148, 75, 16, 28, 140]),
               bk: new Uint8Array([192, 104, 75, 166, 230, 145, 51, 60, 135, 138, 96, 200, 191, 249, 197, 149, 134, 168, 133, 169, 65, 94, 40, 46, 229, 162, 180, 28, 232, 61, 3, 227]),
            },
            'X20-PLY': {
               ek: new Uint8Array([158, 221, 13, 155, 167, 216, 81, 115, 151, 193, 225, 53, 187, 156, 175, 196, 85, 234, 233, 199, 86, 45, 149, 120, 1, 57, 14, 102, 147, 123, 7, 150]),
               sk: new Uint8Array([172, 133, 166, 39, 233, 237, 204, 73, 234, 53, 191, 16, 169, 71, 164, 71, 36, 51, 18, 87, 19, 33, 25, 50, 224, 33, 120, 21, 233, 20, 154, 79]),
               hk: new Uint8Array([34, 121, 121, 4, 207, 55, 202, 73, 83, 4, 58, 102, 135, 111, 186, 242, 3, 187, 239, 108, 251, 245, 3, 245, 3, 77, 228, 197, 101, 4, 16, 94]),
               hIV: new Uint8Array([46, 22, 226, 86, 89, 132, 143, 185, 198, 129, 242, 241, 183, 195, 191, 229, 162, 127, 162, 148, 75, 16, 28, 140]),
               bk: new Uint8Array([192, 104, 75, 166, 230, 145, 51, 60, 135, 138, 96, 200, 191, 249, 197, 149, 134, 168, 133, 169, 65, 94, 40, 46, 229, 162, 180, 28, 232, 61, 3, 227]),
            },
            'AEGIS-256': {
               ek: new Uint8Array([158, 221, 13, 155, 167, 216, 81, 115, 151, 193, 225, 53, 187, 156, 175, 196, 85, 234, 233, 199, 86, 45, 149, 120, 1, 57, 14, 102, 147, 123, 7, 150]),
               sk: new Uint8Array([172, 133, 166, 39, 233, 237, 204, 73, 234, 53, 191, 16, 169, 71, 164, 71, 36, 51, 18, 87, 19, 33, 25, 50, 224, 33, 120, 21, 233, 20, 154, 79]),
               hk: new Uint8Array([34, 121, 121, 4, 207, 55, 202, 73, 83, 4, 58, 102, 135, 111, 186, 242, 3, 187, 239, 108, 251, 245, 3, 245, 3, 77, 228, 197, 101, 4, 16, 94]),
               hIV: new Uint8Array([46, 22, 226, 86, 89, 132, 143, 185, 198, 129, 242, 241, 183, 195, 191, 229, 162, 127, 162, 148, 75, 16, 28, 140]),
               bk: new Uint8Array([192, 104, 75, 166, 230, 145, 51, 60, 135, 138, 96, 200, 191, 249, 197, 149, 134, 168, 133, 169, 65, 94, 40, 46, 229, 162, 180, 28, 232, 61, 3, 227]),
            }
         },
         [cc.VERSION7]: {
            'AES-GCM': {
               ek: new Uint8Array([57, 195, 65, 44, 111, 159, 65, 176, 164, 31, 186, 181, 12, 102, 241, 180, 55, 157, 229, 119, 213, 239, 11, 196, 252, 61, 138, 193, 111, 134, 194, 19]),
               sk: new Uint8Array([12, 11, 234, 82, 207, 215, 131, 80, 38, 32, 132, 108, 3, 142, 171, 167, 122, 64, 206, 141, 38, 119, 244, 14, 84, 157, 79, 143, 230, 193, 123, 152]),
               hk: new Uint8Array([186, 23, 116, 170, 237, 110, 92, 251, 20, 233, 24, 0, 10, 15, 167, 201, 128, 120, 73, 71, 132, 103, 171, 49, 154, 150, 49, 100, 201, 201, 137, 45]),
               hIV: new Uint8Array([209, 157, 68, 198, 140, 129, 200, 180, 195, 7, 203, 152, 159, 48, 27, 169, 238, 3, 71, 245, 252, 45, 165, 23]),
               bk: new Uint8Array([61, 239, 241, 139, 152, 53, 154, 62, 208, 244, 179, 18, 227, 158, 36, 2, 232, 115, 124, 108, 178, 71, 129, 26, 70, 118, 223, 30, 16, 47, 151, 170]),
            },
            'X20-PLY': {
               ek: new Uint8Array([57, 195, 65, 44, 111, 159, 65, 176, 164, 31, 186, 181, 12, 102, 241, 180, 55, 157, 229, 119, 213, 239, 11, 196, 252, 61, 138, 193, 111, 134, 194, 19]),
               sk: new Uint8Array([12, 11, 234, 82, 207, 215, 131, 80, 38, 32, 132, 108, 3, 142, 171, 167, 122, 64, 206, 141, 38, 119, 244, 14, 84, 157, 79, 143, 230, 193, 123, 152]),
               hk: new Uint8Array([186, 23, 116, 170, 237, 110, 92, 251, 20, 233, 24, 0, 10, 15, 167, 201, 128, 120, 73, 71, 132, 103, 171, 49, 154, 150, 49, 100, 201, 201, 137, 45]),
               hIV: new Uint8Array([209, 157, 68, 198, 140, 129, 200, 180, 195, 7, 203, 152, 159, 48, 27, 169, 238, 3, 71, 245, 252, 45, 165, 23]),
               bk: new Uint8Array([61, 239, 241, 139, 152, 53, 154, 62, 208, 244, 179, 18, 227, 158, 36, 2, 232, 115, 124, 108, 178, 71, 129, 26, 70, 118, 223, 30, 16, 47, 151, 170]),
            },
            'AEGIS-256': {
               ek: new Uint8Array([57, 195, 65, 44, 111, 159, 65, 176, 164, 31, 186, 181, 12, 102, 241, 180, 55, 157, 229, 119, 213, 239, 11, 196, 252, 61, 138, 193, 111, 134, 194, 19]),
               sk: new Uint8Array([12, 11, 234, 82, 207, 215, 131, 80, 38, 32, 132, 108, 3, 142, 171, 167, 122, 64, 206, 141, 38, 119, 244, 14, 84, 157, 79, 143, 230, 193, 123, 152]),
               hk: new Uint8Array([186, 23, 116, 170, 237, 110, 92, 251, 20, 233, 24, 0, 10, 15, 167, 201, 128, 120, 73, 71, 132, 103, 171, 49, 154, 150, 49, 100, 201, 201, 137, 45]),
               hIV: new Uint8Array([209, 157, 68, 198, 140, 129, 200, 180, 195, 7, 203, 152, 159, 48, 27, 169, 238, 3, 71, 245, 252, 45, 165, 23]),
               bk: new Uint8Array([61, 239, 241, 139, 152, 53, 154, 62, 208, 244, 179, 18, 227, 158, 36, 2, 232, 115, 124, 108, 178, 71, 129, 26, 70, 118, 223, 30, 16, 47, 151, 170]),
            }
         }
      };

      for (const alg of Ciphers.algs()) {
         for (let ver of Object.keys(expected).map(Number)) {
            const pwd = 'a good pwd';
            const ic = cc.ICOUNT_MIN;
            const userCred = new Uint8Array([214, 245, 252, 122, 133, 39, 76, 162, 64, 201, 143, 217, 237, 57, 18, 207, 199, 153, 20, 28, 162, 9, 236, 66, 100, 103, 152, 159, 226, 50, 225, 129]);
            const slt = new Uint8Array([160, 202, 135, 230, 125, 174, 49, 189, 171, 56, 203, 1, 237, 233, 27, 76]);
            const iv = new Uint8Array([46, 22, 226, 86, 89, 132, 143, 185, 198, 129, 242, 241, 183, 195, 191, 229, 162, 127, 162, 148, 75, 16, 28, 140]);

            let ek: Uint8Array;
            let sk: Uint8Array;
            let hk: Uint8Array;
            let hIV: Uint8Array;
            let bk: Uint8Array | undefined;

            if (ver >= cc.VERSION6) {
               const keyProvider = new PWDKeyProvider(userCred, [pwd, undefined]);
               keyProvider.setCipherDataInfo({
                  ver: ver,
                  alg,
                  ic,
                  slt,
                  lp: 1,
                  lpEnd: 1
               });
               ek = await keyProvider.getCipherKey(false);
               sk = await keyProvider.getSigningKey();
               [hk, hIV] = await keyProvider.getHintCipherKeyAndIV(iv);
               await expect(keyProvider.getBlockCipherKey(0)).rejects.toThrow(/Invalid block number: 0/);
               bk = await keyProvider.getBlockCipherKey(1);
            } else {
               const keyProviderOld = new PWDKeyProviderOld(userCred, [pwd, undefined]);
               keyProviderOld.setCipherDataInfo({
                  ver: ver,
                  alg,
                  ic,
                  slt,
                  lp: 1,
                  lpEnd: 1
               });
               ek = await keyProviderOld.getCipherKey(false);
               sk = await keyProviderOld.getSigningKey();
               [hk, hIV] = await keyProviderOld.getHintCipherKeyAndIV(iv);
            }

            expect(isEqualArray(ek, expected[ver][alg]['ek'])).toBe(true);
            expect(isEqualArray(sk, expected[ver][alg]['sk'])).toBe(true);
            expect(isEqualArray(hk, expected[ver][alg]['hk'])).toBe(true);
            expect(isEqualArray(hIV, expected[ver][alg]['hIV'])).toBe(true);
            if (bk) {
               expect(isEqualArray(bk, expected[ver][alg]['bk'])).toBe(true);
            }

            expect(isEqualArray(ek, userCred)).toBe(false);
            expect(isEqualArray(sk, userCred)).toBe(false);
            expect(isEqualArray(hk, userCred)).toBe(false);
            expect(isEqualArray(hIV, userCred)).toBe(false);
            if (bk) {
               expect(isEqualArray(bk, userCred)).toBe(false);
            }
         }
      }
   });
});

