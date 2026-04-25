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

   it("pqc keys should match expected values", async function () {
      const expected: {
         [kv: number]: {
            [k1: string]: {
               [k2: string]: Uint8Array;
            };
         };
      } = {
         [cc.VERSION7]: {
            'KEM': {
               secret: new Uint8Array([169, 92, 54, 65, 120, 111, 51, 6, 25, 82, 78, 212, 16, 156, 134, 66, 203, 61, 47, 5, 125, 91, 19, 114, 150, 172, 95, 39, 101, 4, 144, 18]),
               public: new Uint8Array([44, 88, 13, 103, 122, 78, 8, 195, 145, 106, 101, 136, 115, 44, 113, 31, 48, 111, 106, 244, 33, 251, 131, 19, 219, 160, 183, 172, 247, 78, 74, 38, 47, 83, 179, 75, 219, 68, 18, 117, 11, 4, 67, 169, 62, 172, 138, 173, 194, 58, 168, 22, 67, 11, 21, 208, 154, 95, 204, 46, 49,
                  7, 154, 217, 113, 88, 170, 179, 186, 56, 42, 53, 230, 81, 150, 4, 64, 89, 253, 97, 138, 224, 184, 148, 48, 96, 156, 24, 186, 8, 211, 215, 41, 187, 22, 106, 25, 5, 42, 134, 83, 45, 85, 53, 77, 186, 208, 104, 33, 49, 134, 45, 209, 70, 214, 34, 16, 42, 71, 90, 245, 203, 33, 131, 200, 56, 241,
                  193, 142, 15, 226, 38, 210, 50, 200, 22, 100, 75, 179, 0, 129, 153, 81, 92, 221, 235, 3, 199, 83, 154, 205, 228, 128, 98, 212, 87, 247, 3, 76, 78, 56, 143, 94, 211, 24, 42, 69, 11, 97, 34, 168, 222, 163, 106, 233, 112, 191, 12, 198, 1, 142, 67, 136, 86, 113, 81, 97, 114, 199, 62, 73, 139, 184,
                  40, 86, 94, 240, 193, 178, 72, 178, 20, 161, 10, 60, 227, 183, 246, 197, 146, 148, 18, 200, 108, 103, 100, 17, 115, 14, 217, 88, 49, 157, 6, 149, 82, 146, 125, 154, 59, 32, 121, 168, 126, 9, 92, 109, 236, 170, 205, 181, 156, 138, 112, 40, 94, 132, 75, 14, 41, 74, 115, 175, 118, 185, 238, 21,
                  26, 203, 169, 9, 68, 91, 42, 178, 92, 62, 70, 113, 100, 94, 9, 96, 142, 129, 179, 175, 104, 17, 76, 168, 177, 46, 226, 6, 205, 183, 189, 219, 135, 96, 56, 216, 53, 137, 211, 80, 89, 11, 103, 3, 44, 28, 168, 233, 8, 222, 119, 174, 75, 137, 162, 90, 245, 155, 223, 225, 179, 200, 86, 27, 98, 103,
                  145, 118, 133, 96, 205, 212, 36, 58, 219, 202, 100, 139, 107, 237, 32, 12, 27, 59, 67, 110, 164, 37, 142, 204, 187, 111, 131, 206, 71, 226, 21, 101, 70, 65, 142, 16, 43, 209, 240, 37, 32, 59, 205, 194, 21, 126, 31, 252, 43, 245, 16, 160, 95, 58, 184, 57, 49, 46, 254, 154, 112, 33, 178, 197, 94,
                  21, 8, 221, 136, 92, 132, 219, 145, 87, 134, 167, 133, 4, 72, 78, 128, 141, 181, 180, 161, 36, 154, 8, 104, 244, 38, 66, 120, 51, 240, 165, 141, 20, 69, 55, 90, 6, 13, 133, 25, 32, 122, 98, 11, 103, 116, 186, 144, 215, 185, 162, 117, 178, 164, 40, 145, 87, 70, 65, 37, 5, 100, 230, 200, 174, 10,
                  42, 29, 147, 218, 87, 209, 34, 69, 246, 160, 164, 235, 151, 140, 45, 89, 22, 213, 9, 189, 82, 246, 139, 149, 192, 167, 181, 96, 54, 163, 195, 10, 5, 91, 119, 78, 38, 169, 248, 87, 155, 20, 102, 96, 106, 201, 139, 74, 36, 92, 203, 53, 61, 156, 53, 112, 240, 25, 178, 14, 216, 68, 128, 28, 165, 29,
                  250, 198, 193, 39, 125, 109, 135, 116, 23, 227, 145, 33, 130, 166, 192, 241, 2, 154, 193, 141, 31, 84, 48, 213, 220, 87, 57, 224, 145, 36, 84, 200, 138, 235, 80, 67, 124, 184, 222, 73, 56, 130, 163, 61, 101, 32, 199, 49, 148, 188, 104, 156, 122, 86, 208, 132, 199, 99, 184, 77, 225, 3, 247, 247,
                  141, 134, 92, 13, 205, 25, 177, 143, 73, 34, 115, 140, 20, 220, 188, 60, 165, 148, 202, 163, 9, 65, 183, 119, 46, 77, 213, 120, 20, 130, 5, 190, 42, 58, 250, 168, 49, 73, 99, 13, 30, 48, 36, 145, 140, 87, 238, 74, 136, 117, 27, 80, 226, 216, 58, 253, 20, 153, 150, 181, 76, 16, 49, 6, 7, 226, 11,
                  18, 248, 78, 55, 183, 27, 192, 203, 41, 32, 243, 143, 65, 102, 52, 84, 170, 171, 152, 51, 83, 13, 180, 48, 96, 249, 115, 44, 178, 72, 70, 11, 103, 237, 233, 36, 61, 59, 38, 247, 168, 82, 170, 82, 190, 105, 60, 31, 186, 66, 141, 105, 11, 53, 75, 82, 198, 135, 144, 58, 113, 242, 112, 131, 215, 9,
                  218, 133, 22, 104, 166, 99, 202, 131, 113, 201, 183, 70, 29, 83, 134, 63, 73, 62, 183, 247, 162, 168, 224, 101, 135, 212, 90, 24, 251, 62, 100, 37, 114, 203, 99, 64, 80, 91, 112, 206, 160, 64, 223, 43, 52, 241, 202, 15, 164, 170, 31, 216, 231, 139, 58, 130, 7, 140, 147, 161, 195, 40, 111, 19, 91,
                  110, 18, 139, 196, 230, 171, 173, 54, 85, 149, 128, 132, 2, 5, 146, 112, 20, 211, 41, 162, 4, 57, 22, 146, 152, 248, 108, 34, 207, 72, 141, 17, 153, 105, 200, 208, 76, 181, 49, 109, 167, 197, 97, 154, 185, 192, 180,103, 163, 0, 156, 137, 119, 54, 117, 47, 87, 201, 77, 25, 23, 166, 133, 117, 62,
                  235, 106, 178, 0, 76, 39, 44, 57, 27, 35, 152, 118, 161, 61, 188, 214, 57, 224, 28, 124, 35, 227, 98, 219, 241, 97, 226, 75, 21, 5, 105, 174, 22, 87, 22, 82, 107, 125, 8, 224, 131, 186, 244, 91, 220, 132, 17, 115, 148, 147, 229, 120, 69, 230, 37, 203, 14, 246, 56, 190, 100, 122, 178, 165, 121,
                  198, 184, 24, 30, 70, 63, 117, 129, 207, 239, 213, 204, 198, 18, 95, 182, 135, 22, 152, 146, 122, 130, 132, 87, 60, 195, 129, 116, 133, 52, 83, 6, 111, 119, 43, 138, 169, 91, 126, 16, 66, 88, 29, 16, 149, 111, 122, 180, 171, 107, 177, 52, 246, 160, 53, 99, 112, 101, 75, 27, 42, 176, 205, 230,
                  131, 147, 201, 116, 159, 128, 178, 18, 106, 147, 44, 93, 121, 154, 104, 22, 195, 171, 17, 111, 219, 80, 133, 96, 152, 114, 180, 176, 157, 83, 177, 129, 39, 67, 150, 115, 140, 207, 249, 134, 33, 17, 182, 201, 126, 204, 137, 12, 86, 111, 49, 22, 140, 83, 151, 160, 81, 99, 188, 110, 51, 110, 182,
                  172, 177, 183, 41, 72, 167, 137, 187, 184, 176, 141, 6, 131, 196, 255, 65, 51, 131, 187, 52, 110, 107, 137, 133, 113, 84, 0, 101, 99, 124, 92, 155, 53, 37, 3, 123, 39, 16, 36, 122, 91, 172, 188, 54, 66, 171, 89, 239, 136, 137, 191, 73, 152, 231, 28, 164, 179, 140, 27, 5, 167, 155, 250, 185, 33,
                  158, 70, 186, 117, 193, 79, 50, 88, 145, 225, 112, 115, 186, 18, 47, 171, 35, 31, 49, 58, 6, 101, 36, 181, 7, 180, 3, 146, 208, 89, 162, 99, 93, 176, 123, 49, 193, 151, 9, 196, 188, 84, 198, 8, 206, 189, 192, 1, 84, 99, 249, 175, 4, 77, 68, 191, 45, 248, 83, 130, 26, 42, 117, 51, 196, 10, 32, 115,
                  230, 11, 122, 137, 145, 116, 3, 80, 215, 114, 191, 143, 222, 232, 205, 47, 73, 105, 211, 80, 101, 132, 79, 143, 135, 105, 250, 25, 140, 17, 84, 26, 105, 153, 210, 30, 2, 9, 245, 70, 50, 216, 4, 23]),
            }
         }
      };

      for (let ver of Object.keys(expected).map(Number)) {
         const pwd = 'a good pwd';
         const ic = cc.ICOUNT_MIN;
         const userCred = new Uint8Array([214, 245, 252, 122, 133, 39, 76, 162, 64, 201, 143, 217, 237, 57, 18, 207, 199, 153, 20, 28, 162, 9, 236, 66, 100, 103, 152, 159, 226, 50, 225, 129]);
         const slt = new Uint8Array([160, 202, 135, 230, 125, 174, 49, 189, 171, 56, 203, 1, 237, 233, 27, 76]);

         const keyProvider = new PWDKeyProvider(userCred, [pwd, undefined]);
         keyProvider.setCipherDataInfo({
            ver: ver,
            alg: 'AES-GCM',
            ic,
            slt,
            lp: 1,
            lpEnd: 1
         });

         const { secretKey, publicKey } = await keyProvider.getKEMKeys(true);
         // fs.writeFileSync('keys-output.txt', `secret: new Uint8Array([${Array.from(secretKey).join(', ')}]),\npublic: new Uint8Array([${Array.from(publicKey).join(', ')}]),\n`, { flag: 'a' });

         expect(isEqualArray(secretKey, expected[ver]['KEM']['secret'])).toBe(true);
         expect(isEqualArray(publicKey, expected[ver]['KEM']['public'])).toBe(true);

         expect(isEqualArray(secretKey, userCred)).toBe(false);
         expect(isEqualArray(publicKey, userCred)).toBe(false);
      }
   });
});

