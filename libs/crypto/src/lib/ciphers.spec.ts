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
import {
   BYOBStreamReader,
   streamDecipher, latestEncipher,
   EncipherV7,
   Ciphers
} from '../index';
import type { CipherDataBlock } from '../index';
import { PWDKeyProvider } from './keys';
import {
   isEqualArray,
   streamFromBytes,
   streamFromStr,
   areEqual,
   streamFromBase64Url
} from './utils.spec';


function streamFromCipherBlock(cdBlocks: CipherDataBlock[]): [
   ReadableStream<Uint8Array>,
   Uint8Array
] {

   let bytes = 0;
   for (let cdBlock of cdBlocks) {
      for (let part of cdBlock.parts) {
         bytes += part.byteLength;
      }
   }

   let pos = 0;
   const cipherData = new Uint8Array(bytes);
   for (let cdBlock of cdBlocks) {
      for (let part of cdBlock.parts) {
         cipherData.set(part, pos);
         pos += part.byteLength;
      }
   }

   return streamFromBytes(cipherData);
}

describe("Encryption and decryption", function () {
   beforeEach(async () => {
      await cryptoReady();
   });

   async function signAndRepack(
      encipher: EncipherV7,
      block: CipherDataBlock,
      keyProvider: PWDKeyProvider
   ): Promise<Uint8Array> {

      // cheating... parts[1] is _additionalData, parts[2] is encryptedData
      // and set _keyProvider to the one with potentially wrong userCred, reset _lastMac
      encipher['_keyProvider'] = keyProvider;
      encipher['_lastMac'] = new Uint8Array([0]);
      const headerData = await encipher._createHeader(block.parts[2], block.parts[1]);

      const output = new Uint8Array(headerData.byteLength +
         block.parts[1].byteLength +
         block.parts[2].byteLength);

      output.set(headerData);
      output.set(block.parts[1], headerData.byteLength);
      output.set(block.parts[2], headerData.byteLength + block.parts[1].byteLength);

      return output;
   }

   // More complex test to ensure that having the wrong usercred causes
   // decryption to fail. We test this by extracting and not changing original
   // CipherData from "Alice's" original encrypted data that was encrypted with
   // Alice's userCredA. We then creating a new valid MAC signature with "Bob's"
   // userCredB signature attached to the front of the Alice's CipherData
   // (and encypted txt).

   // In the wild if the MAC signature was swapped with someone else's
   // valid signature Quick Crypt would report the error to Alice at signature
   // validation time because it would use Alice's userCredA not Bob's userCredB to
   // test.

   // But what could happen is that an evil site might closely mimicked
   // Quick Crypt, and if Alice was tricked into going there, it would
   // not tell Alice about the MAC signature failure. So what this test
   // validates is that even with a replaced MAC signature
   // (which is equivalent to an ignored MAC signature), the clear
   // text can still not be retrived. This test tries to ensures that
   // even having tricked Alice into entering her PWD at the evil website,
   // the ciphertext still cannot be decrypted because the
   // evil site does not have access to Alice's userCredA which is
   // combined with her password to generate the cipher key.

   it("decryption should fail with replaced valid signature", async function () {

      for (const alg of Ciphers.algs()) {

         const [clearStream, clearData] = streamFromStr('This is a secret 🐓');
         const pwd = 'a good pwd';
         const userCredA = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));
         const userCredB = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));
         const slt = crypto.getRandomValues(new Uint8Array(cc.SLT_BYTES));

         const keyProvider = new PWDKeyProvider(userCredA, [pwd, undefined]);
         keyProvider.setCipherDataInfo({
            ver: cc.CURRENT_VERSION,
            alg,
            ic: cc.ICOUNT_MIN,
            slt,
            lp: 1,
            lpEnd: 1
         });

         const reader = new BYOBStreamReader(clearStream);
         const encipher = new EncipherV7(keyProvider, reader);
         const cipherBlock = await encipher.encryptBlock0();

         // Create fresh key providers with same salt. Original gets purged after encrypt
         const keyProviderA = new PWDKeyProvider(userCredA, [pwd, undefined]);
         keyProviderA.setCipherDataInfo({
            ver: cc.CURRENT_VERSION,
            alg,
            ic: cc.ICOUNT_MIN,
            slt,
            lp: 1,
            lpEnd: 1
         });
         const keyProviderB = new PWDKeyProvider(userCredB, [pwd, undefined]);
         keyProviderB.setCipherDataInfo({
            ver: cc.CURRENT_VERSION,
            alg,
            ic: cc.ICOUNT_MIN,
            slt,
            lp: 1,
            lpEnd: 1
         });

         // Sign and repack with both the original (correct) values to help ensure the
         // code for repacking is valid and then with a new signature to be sure
         // the replacment is detected.
         let [cipherstreamA, cipherDataA] = streamFromBytes(await signAndRepack(encipher, cipherBlock, keyProviderA));
         let [cipherstreamB, cipherDataB] = streamFromBytes(await signAndRepack(encipher, cipherBlock, keyProviderB));

         // These should fail because using the wrong userCred for each
         let decipherA = await streamDecipher(userCredB, cipherstreamA, [pwd, undefined]);
         let decipherB = await streamDecipher(userCredA, cipherstreamB, [pwd, undefined]);

         await expect(decipherA._decodeBlock0()).rejects.toThrow(/MAC/);
         await expect(decipherB._decodeBlock0()).rejects.toThrow(/MAC/);

         // Reaload streams, then test with correct matching userCreds
         [cipherstreamA] = streamFromBytes(cipherDataA);
         [cipherstreamB] = streamFromBytes(cipherDataB);
         decipherA = await streamDecipher(userCredA, cipherstreamA, [pwd, undefined]);
         decipherB = await streamDecipher(userCredB, cipherstreamB, [pwd, undefined]);

         // Both should succeed since the re-signed signatures are now valid for each
         // userCred. But while decrypting, we should fail on B because that userCred wasn't
         // used for encrpytion. Also, these would fail if there was an encrypted hint unless
         // that was also replaced
         await expect(decipherA._decodeBlock0()).resolves.not.toThrow();
         await expect(decipherB._decodeBlock0()).resolves.not.toThrow();

         // should succeed since we repacked with correct userCredA (ensure logic is valid)
         await expect(decipherA.decryptBlock0()).resolves.toEqual(clearData);

         // The big moment... perhaps should have better validation that the decryption
         // failed, but not much else returns DOMException from cipher.service. Note that
         // this is using the correct PWD because we assume the evil site has tricked
         // Alice into providing it and just doesn't have userCred since site cannot retrieve
         await expect(decipherB.decryptBlock0()).rejects.toThrow(DOMException);
      }
   });

   it("round trip block0, all algorithms", async function () {

      for (const alg of Ciphers.algs()) {

         const [clearStream, clearData] = streamFromStr('This is a secret 🦆');
         const pwd = 'a good pwd';
         const hint = 'not really';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

         const latest = latestEncipher(userCred, alg, cc.ICOUNT_MIN, 1, 1, clearStream,
            async (cdinfo) => {
               expect(cdinfo.alg).toEqual(alg);
               expect(cdinfo.slt.byteLength).toEqual(cc.SLT_BYTES);
               expect(cdinfo.ic).toBe(cc.ICOUNT_MIN);
               expect(cdinfo.lp).toEqual(1);
               expect(cdinfo.lpEnd).toEqual(1);
               expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
               return [pwd, hint];
         });
         const block0 = await latest.encryptBlock0();

         const [cipherStream] = streamFromCipherBlock([block0]);
         const decipher = await streamDecipher(userCred, cipherStream,
            async (cdinfo) => {
               expect(cdinfo.alg).toEqual(alg);
               expect(cdinfo.slt.byteLength).toEqual(cc.SLT_BYTES);
               expect(cdinfo.ic).toBe(cc.ICOUNT_MIN);
               expect(cdinfo.hint).toEqual(hint);
               expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
               return [pwd, undefined];
         });

         const decrypted = await decipher.decryptBlock0();
         await expect(areEqual(decrypted, clearData)).resolves.toEqual(true);
      }
   });

   it("concurrent getCipherDataInfo and decryptBlock0 share one decode", async function () {

      // This tests _decodeBlock0 serialization by calling getCipherDataInfo() and
      // decryptBlock0() without awaiting between calls.
      for (const alg of Ciphers.algs()) {

         const [clearStream, clearData] = streamFromStr('This is a secret 🦆');
         const pwd = 'a good pwd';
         const hint = 'not really';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

         const latest = latestEncipher(userCred, alg, cc.ICOUNT_MIN, 1, 1, clearStream,
            async () => [pwd, hint],
         );
         const block0 = await latest.encryptBlock0();

         // Happy path: kick off both without awaiting first.
         const [cipherStream] = streamFromCipherBlock([block0]);
         const decipher = await streamDecipher(userCred, cipherStream,
            async () => [pwd, undefined],
         );

         const cdInfoPromise = decipher.getCipherDataInfo();
         const decryptPromise = decipher.decryptBlock0();

         const cdInfo = await cdInfoPromise;
         expect(cdInfo.alg).toEqual(alg);
         expect(cdInfo.hint).toEqual(hint);
         expect(cdInfo.ver).toEqual(cc.CURRENT_VERSION);

         const decrypted = await decryptPromise;
         await expect(areEqual(decrypted, clearData)).resolves.toEqual(true);

         // Failure-propagation path: tamper userCred so MAC fails. Both
         // concurrent callers should see the same exception
         const [tamperedStream] = streamFromCipherBlock([block0]);
         const wrongUserCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));
         const badDecipher = await streamDecipher(wrongUserCred, tamperedStream,
            async () => [pwd, undefined],
         );

         const badCdInfoPromise = badDecipher.getCipherDataInfo();
         const badDecryptPromise = badDecipher.decryptBlock0();
         await expect(badCdInfoPromise).rejects.toThrow(/MAC/);
         await expect(badDecryptPromise).rejects.toThrow(/MAC/);
      }
   });


   it("round trip blockN, all algorithms", async function () {

      for (const alg of Ciphers.algs()) {

         let [clearStream, clearData] = streamFromStr('This is a secret 🦀');
         const pwd = 'a not good pwd';
         const hint = 'sorta';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

         let latest = latestEncipher(userCred, alg, cc.ICOUNT_MIN, 1, 1, clearStream, async (cdinfo) => {
            return [pwd, hint];
         });
         const readStart = 12;
         //@ts-ignore force multiple blocks
         latest['_readTarget'] = readStart;

         await expect(latest.encryptBlockN()).rejects.toThrow(/Encipher invalid state/);

         // once invalidated, it stays that way...
         await expect(latest.encryptBlock0()).rejects.toThrow(new RegExp('Encipher invalid state.+'));

         [clearStream, clearData] = streamFromStr('This is a secret 🦀');
         latest = latestEncipher(userCred, alg, cc.ICOUNT_MIN, 1, 1, clearStream, async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, hint];
         });
         //@ts-ignore force multiple blocks
         latest['_readTarget'] = readStart;

         const block0 = await latest.encryptBlock0();
         const blockN = await latest.encryptBlockN();

         let [cipherStream] = streamFromCipherBlock([block0, blockN]);
         let decipher = await streamDecipher(userCred, cipherStream, async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, undefined];
         });

         let decb0 = await decipher.decryptBlock0();
         await expect(areEqual(decb0, clearData.slice(0, readStart))).resolves.toEqual(true);

         const decb1 = await decipher.decryptBlockN();
         await expect(areEqual(decb1, clearData.slice(readStart))).resolves.toEqual(true);

         // Try again, but copy block0 head to block N
         const badBlockN = {
            ...blockN
         };
         badBlockN.parts[0] = block0.parts[0];

         [cipherStream] = streamFromCipherBlock([block0, badBlockN]);
         decipher = await streamDecipher(userCred, cipherStream, async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, undefined];
         });

         decb0 = await decipher.decryptBlock0();
         await expect(areEqual(decb0, clearData.slice(0, readStart))).resolves.toEqual(true);
         await expect(decipher.decryptBlockN()).rejects.toThrow(/Cipher data length mismatch2/);
      }
   });
});

describe("Decryption known values", function () {
   beforeEach(async () => {
      await cryptoReady();
   });

   // base64url userCred for use in commandline for recreation:
   // Ohyqajb6nFOm2Y5lOTkIkhc3uAaF8sUrYrQ9pts2pDc=
   const userCred = new Uint8Array([58, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98, 180, 61, 166, 219, 54, 164, 55]);

   it("correct cipherdata info and decryption, v4", async function () {
      const [_, clearData] = streamFromStr('A nice 🦫 came to say hello');
      const pwd = 'a 🌲 of course';
      const hint = '🌧️';
      const [cipherStream] = streamFromBytes(new Uint8Array([117, 163, 250, 117, 59, 97, 3, 10, 139, 12, 55, 161, 115, 52, 28, 105, 246, 126, 220, 0, 129, 151, 165, 136, 46, 97, 163, 160, 91, 9, 189, 218, 4, 0, 116, 0, 0, 0, 2, 0, 16, 242, 98, 46, 102, 223, 79, 227, 209, 73, 22, 207, 92, 80, 75, 125, 125, 234, 18, 21, 88, 64, 43, 68, 25, 193, 133, 31, 159, 156, 8, 184, 10, 164, 33, 46, 20, 159, 218, 222, 64, 119, 27, 0, 0, 23, 5, 135, 172, 203, 4, 101, 163, 155, 133, 221, 40, 227, 91, 222, 227, 213, 97, 77, 24, 117, 60, 188, 27, 153, 253, 134, 10, 112, 75, 76, 146, 132, 123, 217, 7, 171, 211, 24, 206, 186, 248, 244, 119, 18, 165, 195, 59, 160, 76, 31, 90, 80, 53, 19, 39, 143, 99, 141, 109, 68, 72, 63, 121, 199, 96, 95, 157, 81]));

      const decipher = await streamDecipher(userCred, cipherStream, async (cdinfo) => {
         expect(cdinfo.hint).toEqual(hint);
         expect(cdinfo.lp).toEqual(1);
         expect(cdinfo.lpEnd).toEqual(1);
         expect(cdinfo.alg).toBe('X20-PLY');
         expect(cdinfo.ic).toBe(1800000);
         expect(cdinfo.ver).toEqual(cc.VERSION4);
         expect(isEqualArray(cdinfo.slt, new Uint8Array([25, 193, 133, 31, 159, 156, 8, 184, 10, 164, 33, 46, 20, 159, 218, 222]))).toBe(true);
         return [pwd, undefined];
      });
      const cdInfo = await decipher.getCipherDataInfo();

      expect(cdInfo.alg).toEqual('X20-PLY');
      expect(cdInfo.ic).toEqual(1800000);
      expect(isEqualArray(cdInfo.slt, new Uint8Array([25, 193, 133, 31, 159, 156, 8, 184, 10, 164, 33, 46, 20, 159, 218, 222]))).toBe(true);
      expect(cdInfo.ver).toEqual(cc.VERSION4);
      expect(cdInfo.hint).toEqual(hint);

      await expect(decipher.decryptBlock0()).resolves.toEqual(clearData);
   });

   it("correct cipherdata info and decryption, v5", async function () {
      const [_, clearData] = streamFromStr('A nice 🦫 came to say hello');
      const pwd = 'a 🌲 of course';
      const hint = '🌧️';
      const [cipherStream] = streamFromBytes(new Uint8Array([166, 123, 188, 183, 212, 97, 47, 147, 59, 39, 78, 222, 101, 74, 221, 53, 27, 11, 194, 67, 156, 235, 116, 104, 65, 64, 76, 166, 29, 220, 71, 179, 5, 0, 116, 0, 0, 1, 2, 0, 121, 78, 37, 8, 192, 196, 110, 22, 164, 106, 59, 161, 122, 165, 176, 147, 49, 43, 41, 250, 163, 111, 218, 4, 174, 61, 6, 169, 145, 216, 66, 166, 139, 82, 19, 207, 29, 75, 105, 149, 64, 119, 27, 0, 0, 23, 93, 92, 56, 163, 242, 71, 208, 3, 190, 44, 140, 222, 149, 159, 152, 193, 162, 44, 177, 93, 197, 119, 131, 88, 92, 53, 108, 167, 253, 64, 216, 200, 121, 212, 193, 153, 180, 39, 92, 35, 142, 6, 240, 115, 51, 211, 198, 63, 12, 126, 128, 206, 178, 114, 65, 37, 246, 197, 19, 79, 58, 96, 56, 86, 172, 162, 217, 70]));

      const decipher = await streamDecipher(userCred, cipherStream, async (cdinfo) => {
         expect(cdinfo.hint).toEqual(hint);
         expect(cdinfo.lp).toEqual(1);
         expect(cdinfo.lpEnd).toEqual(1);
         expect(cdinfo.alg).toBe('X20-PLY');
         expect(cdinfo.ic).toBe(1800000);
         expect(cdinfo.hint).toEqual(hint);
         expect(cdinfo.ver).toEqual(cc.VERSION5);
         expect(isEqualArray(cdinfo.slt, new Uint8Array([174, 61, 6, 169, 145, 216, 66, 166, 139, 82, 19, 207, 29, 75, 105, 149]))).toBe(true);
         return [pwd, undefined];
      });
      const cdInfo = await decipher.getCipherDataInfo();

      expect(cdInfo.alg).toEqual('X20-PLY');
      expect(cdInfo.ic).toEqual(1800000);
      expect(isEqualArray(cdInfo.slt, new Uint8Array([174, 61, 6, 169, 145, 216, 66, 166, 139, 82, 19, 207, 29, 75, 105, 149]))).toBe(true);
      expect(cdInfo.ver).toEqual(cc.VERSION5);
      expect(cdInfo.hint).toEqual(hint);

      await expect(decipher.decryptBlock0()).resolves.toEqual(clearData);
      await expect(decipher.decryptBlockN()).resolves.toEqual(new Uint8Array(0));
   });

   it("correct cipherdata info and decryption, multi version", async function () {
      const [_, clearData] = streamFromStr('A nice 🦫 came to say hello');
      const pwd = 'a 🌲 of course';
      const hint = '🌧️';

      // NOTE: this cipherStream can be created by:
      //   * set ciphers-current: READ_SIZE_START = 20; READ_SIZE_MAX = Encipher.READ_SIZE_START * 16;
      //   * run ./apps/web/scripts/ciphers_tests.sh
      const vers = [
         //v6
         {  ver: 6,
            cts: {
               'AES-GCM': 'F4qYlclmVWQD5IayN_Ub_3pQ7N91gNZzLGi8Iu_sIbkGAGAAAAABAMrZN-Xbi9Kvdpcl2k5pFxC_07E33BkQ-QlqxchAdxsAABfm9OTNhim0krfh9ZLGyi7yDGB-oB4gScok1BFuD5UcpZEj44VRQWVD8kCX-fD_t4VRbXXcgYiz1TOGFz5nsobA3jkhROi53GPsJiSiW18yy3A73-eETAgZjQfeBgAoAAABAQD1T3bCnKPA38DHIMBWWXsv7H2fFBJ9DjIPimYghk6CJdS5IXME',
               'X20-PLY': 'PkeGHkLso1abo-aBE93x_e69rJb6OrW-STBAAwDxbRQGAGwAAAACANIwjwvIQLygUdSpdbfKw83iAo126tZL0VgOnatOaYIfOXGuBj5hEGhAdxsAABfIUjubZ9H30GHKKissSmSWyblIHejAG_IPbxEjFyiOrgndOJuISt5vqJhmTJlRWoc_1683Ku3T0MkHtw24Je54qsYzl4TKzwqvSvMhL56c2g2hIVF6TuB4Cr97BgA0AAABAgAT-DRYec2-zEvMw50PxYgwmdvcJoHH01QMlf_4rV01LzigH2KFr9VaKQASTWU7310c',
               'AEGIS-256': 'XRa5nS7wJ8DLF6HWZyP2MWfeAS4PyHUYzkd67AaMUfYGAJQAAAADAJey272VOwM55vXW_P2rEudCgPSRwGB5nAjF7gmnc5AA46rTvby4Wv_R6l6eH0UNQUB3GwAAJ_K3cZg5LpRqUy83VmoXe1KwPHh3wkGbEes_qRTu7vrNvz_saJVP0ajB6xDxZYs5RhHb9yl2GWxtkLpqkhN6N2pxtAKF2a_LjknVWeIRN_jxn-LqzwkuI-Lz4Pm0OeGEwl7bfOvP8qftV8UztFNlwmGxOA_nIu_KmWG6CwYATAAAAQMA_n0RaJelAb_JLnaUUtlQrgBaG7_wcwL4lplkWi3V_Uo3V9pkIHvDj6Jvgy58blIx5yGQHa96GTx_0U3_0w38vAaiupLQGf4Ibw',
            }
         },
         //v7
         {  ver: 7,
            cts: {
               'AES-GCM': 'f54Kbfvskz0fSmqLMKu5meoa98Pjd7acb842dogLb5oHAGAAAAABAMad0LlIngQIQmfHf5UlOBpI22Gqs_yc9ONnRUpAdxsAABdlMKpBc7lTiu1ubTTqtyXg1w_gpoPBTqraECeUbj-J_rOkysOSg_0bj6tkWQ8K7QEe9YtthrNyIueZz7SjNZTyyqYssKkhLcgwA_M6r3yWfnnTukXCQCoo9tYaBwAoAAABAQCFQZFWQYSA2CBs8ljZzqqjUiFqKCS7uw6RE0e8S2LEiPuIHJwB',
               'X20-PLY': 'AZwRvYONTmUiGmy1FD_E_W-KIMwISoTV1928-TQsWDkHAGwAAAACAGWfXMaHOiKMdRhrASFEp6IBNAiA77MvWrl14TQBYKzViy1hGaH7x1lAdxsAABdYtEAsyZ70RPsXSHo91g5W2RE2mGtid91BdMw4p_pnhYXVjdU50bJdrfp8iQa-KzC5CrfpwopR_hufqd1klSAXe0jqCNoMKq9lV_dZmbkgyp-P3OidXHXTPiZnBwA0AAABAgBdgykbdEQtRtnwwo46Jd0X8fxc0ZR5SahASYPMaMkvZmDD1erhR8LHVF4rMtZoOvvc',
               'AEGIS-256': '7V_KLO_W6Dn3z_Nm8ApEvpuCStCCrI9DotqOK4NlL3YHAJQAAAADAGQBbVBjySD_E4d9VA1ALhL291hssjA9dXCUPaxKiOi0VsaLhpx2DAYSG0YOEDtIEkB3GwAAJ3oAD7PgLd1p_WcJgtbVhwfU1oEuVaKWWphOpDzc2u6aoWKxZlIqEIrtWExNZu4vTi2-Y4IT5RoBtsIvQ00Y_VVK6hGRVHxhbeDGPgMuybUanllaCCurgP4JSo0SASwEnImEQpHYraWRqSEXO80Y5FszBdMODnIyrJwWPgcATAAAAQMAcoz6mX1p-OtwhmpbsQnq8sDZRmzcByWMsv0-k_4FRJ4FvHYt-ZxL7f9GHTc9glJRufqaapbSmr5aX5x0a_ioF4jijYiOSAmKDA',
            },
         }
      ];

      const userCred = new Uint8Array([58, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98, 180, 61, 166, 219, 54, 164, 55]);
      for (const { ver, cts } of vers) {
         for (const [alg, cipherTxt] of Object.entries(cts)) {
            const [cipherStream] = streamFromBase64Url(cipherTxt);

            const decipher = await streamDecipher(userCred, cipherStream, async (cdinfo) => {
               expect(cdinfo.hint).toEqual(hint);
               expect(cdinfo.lp).toEqual(1);
               expect(cdinfo.lpEnd).toEqual(1);
               expect(cdinfo.alg).toBe(alg);
               expect(cdinfo.ic).toBe(1800000);
               expect(cdinfo.hint).toEqual(hint);
               expect(cdinfo.ver).toEqual(ver);
               expect(cdinfo.slt.byteLength).toEqual(cc.SLT_BYTES);
               return [pwd, undefined];
            });
            const cdInfo = await decipher.getCipherDataInfo();

            expect(cdInfo.alg).toEqual(alg);
            expect(cdInfo.ic).toEqual(1800000);
            expect(cdInfo.ver).toEqual(ver);
            expect(cdInfo.hint).toEqual(hint);
            expect(cdInfo.slt.byteLength).toEqual(cc.SLT_BYTES);

            await expect(decipher.decryptBlock0()).resolves.toEqual(clearData.subarray(0, 20));
            await expect(decipher.decryptBlockN()).resolves.toEqual(clearData.subarray(20));
         }
      }
   });

   it("missing terminal block indicator, v5", async function () {
      const [_, clearData] = streamFromStr('A nice 🦫 came to say hello');
      const pwd = 'a 🌲 of course';
      const hint = '🌧️';
      const [cipherStream] = streamFromBytes(new Uint8Array([225, 67, 20, 31, 134, 179, 27, 202, 138, 52, 68, 42, 197, 34, 48, 209, 76, 235, 39, 166, 101, 12, 253, 101, 237, 25, 234, 119, 91, 227, 169, 172, 5, 0, 116, 0, 0, 0, 2, 0, 53, 140, 213, 212, 134, 206, 178, 102, 222, 97, 207, 8, 252, 103, 8, 64, 25, 112, 206, 146, 159, 150, 220, 236, 162, 203, 172, 111, 119, 158, 192, 123, 81, 141, 89, 174, 126, 4, 65, 105, 64, 119, 27, 0, 0, 23, 138, 253, 130, 153, 78, 2, 31, 195, 254, 142, 102, 116, 200, 50, 125, 8, 178, 151, 113, 13, 205, 228, 10, 85, 83, 101, 57, 149, 191, 166, 4, 221, 153, 198, 0, 18, 185, 165, 203, 53, 211, 218, 24, 198, 162, 13, 99, 240, 249, 210, 255, 200, 217, 232, 10, 187, 212, 92, 204, 165, 217, 7, 202, 6, 114, 70, 200, 221]));

      const decipher = await streamDecipher(userCred, cipherStream, async (cdinfo) => {
         expect(cdinfo.hint).toEqual(hint);
         expect(cdinfo.lp).toEqual(1);
         expect(cdinfo.lpEnd).toEqual(1);
         expect(cdinfo.alg).toBe('X20-PLY');
         expect(cdinfo.ic).toBe(1800000);
         expect(cdinfo.ver).toEqual(cc.VERSION5);
         expect(isEqualArray(cdinfo.slt, new Uint8Array([162, 203, 172, 111, 119, 158, 192, 123, 81, 141, 89, 174, 126, 4, 65, 105]))).toBe(true);
         return [pwd, undefined];
      });
      const cdInfo = await decipher.getCipherDataInfo();

      expect(cdInfo.alg).toEqual('X20-PLY');
      expect(cdInfo.ic).toEqual(1800000);
      expect(isEqualArray(cdInfo.slt, new Uint8Array([162, 203, 172, 111, 119, 158, 192, 123, 81, 141, 89, 174, 126, 4, 65, 105]))).toBe(true);
      expect(cdInfo.ver).toEqual(cc.VERSION5);
      expect(cdInfo.hint).toEqual(hint);

      // Although the cipherData for block0 above is missing the "terminal block" indicator,
      // that isn't detected until we hit the end of the file (below in blockN)
      await expect(decipher.decryptBlock0()).resolves.toEqual(clearData);
      await expect(decipher.decryptBlockN()).rejects.toThrow(/Missing terminal/);
   });

   it("missing terminal block indicator, multi version", async function () {
      const [_, clearData] = streamFromStr('A nice 🦫 came to say hello');
      const pwd = 'a 🌲 of course';
      const hint = '🌧️';

      // NOTE: this cipherStream can be created by:
      //   * set ciphers-current: READ_SIZE_START = 20; READ_SIZE_MAX = Encipher.READ_SIZE_START * 16;
      //   * manually set ciphers-current term:false in two places (search for term:) and rebuilding the cli
      //   * run ./apps/web/scripts/ciphers_tests.sh
      const vers = [
         //v6
         {  ver: 6,
            cts: {
               'AES-GCM': 'KIjAs5WAVq58nEVKZrLwqxgxMuZEtvfOzncNnPLZFMcGAGAAAAABADO2r-khoqGTJepwHcoQaJ_q7wIJVkeMwp4VJVNAdxsAABcUS4eu-pzXZVWsPBJTZFwQd8xCGb6JRPEAaHyNCtmH0s5zVBpgO0gqfD8TPHXqW-FQ0pHbAzmElgnjDdRYMM_TLrsuHVRsLtf-ddyjjeXv6LeeeX1ExbtaDaE9BgAoAAAAAQBdvvgBoMusZZO0E3CRS2zBfPNvOwLY-2hDMwgOQGpzWDRFQGGb',
               'X20-PLY': 'rPEwFYLr_WH3sIydgcLU29KNbXWSLtGKHCtFc5NdlKMGAGwAAAACAGKwcuUJZj8OVEdc4SyAMGHmDvaPBFvYq7j44fhHwsjA5GCauj6rMn1AdxsAABd_YgNSnyvPvbuXChCV7yAXv9E--ZrhXyOANRq8mr1R1BbmaEhY4oNzuaLqxfr2gFTvtjLBgZxOfhev1kA6HVx9SHdB6VnaOHyFX3v7zSQPnyo-TBRHCMOOaDtxBgA0AAAAAgDujN-I-TOuUWw7VFOdcx0NMpK6vc8rOqzmWFA_sfZRMpFrn8oN92L8utlAdTjjuFfT',
               'AEGIS-256': 'O8Y_5AfBakBc9UXPWLcgTtAsxopVkVmrzhEVlsgnhpAGAJQAAAADANAGQIgVn8JS4_-OekbG5INtC9sO-XnbCWVr9qSyAU5wteE2cI38YN6Je9KfMO8i_UB3GwAAJ5AtkgTlpq4a2LhCcWhE8X46S_FVF7wcvaTJ9rg4oz5xizPExQortEWXsMWCQFsVxjRqvcg2Co50wk3nPFdtdT7pFUuU-xA2k-GWcM7J49nvyhmS1o7TVrpvds4GTh4IYCTcu80eYh4Kq0KSSX2ipreuoVom5kBvA_F7RQYATAAAAAMASOhuM8YNbVyhW4SedzlAKRLXww9Is1ocJJOR3eQSVqZcspLI0RjCxG7lJ0rveEVf4pO0TvOKx9BLnoq3Xy65PrVzvmHSfm1lsA',
            }
         },
         //v7
         {  ver: 7,
            cts: {
               'AES-GCM': '6RA2trl6fUk79HunesjBIc5QzCZHVmLP8LycF9nSlMYHAGAAAAABAG89sHG8QqsNCmFhD4dzxokWvimyPabHADr9l_tAdxsAABc8EqnWkomp5aaWElBAgGRjELah1-pGKCb1RcEUTDjTIO9eYbwBFVLdBBGIfxJ4cuuITGBRT19GvXYXrxB42YokPVuQ7j25s-vqLnKNxs0b71KnMMPemwM_YMptBwAoAAAAAQBP4fGvmDZNvxnArsrJ2GIM-JYVMLkrt-2WJgiAdjTbHiablssV',
               'X20-PLY': 'XJywoA5hCWvKKuUeafFGFdKr5fVIsSTPwlMPFEnqQIsHAGwAAAACAD7dwujhdRKAz1CxnBVRCAMv3U-0yymOvfdCfs6lixJA7qt3EQWpqdVAdxsAABf_vYUapnFjfO4UPkzUuWE7drM7IiJuHQhS7g04ZQqXxFO2LFZsmoAkbFsvruQhvawrBHnmuQUZsXM5eiakgPWPH-Pt956x8ISTNDR6KuvTknW96pqOca5uKRFMBwA0AAAAAgClljvvVjtEb9GFux4vpVecg6uVKuLWMB8pKS1mWLI-WqOtvGENGnmT4gPpppf2uK72',
               'AEGIS-256': 'zxpeZ6-Z83Ekdj9qTlYASx1wD_0tLAVK0VEoMWhdO10HAJQAAAADAO2xoAUh7Klhh8f7jEWdRy7rFI78CYG4cxAbbeRuEwkKaRxofiiJ1aqZqHOjfBCUCUB3GwAAJzuPgU-AEr1CALn5F-Kgqme360HrCl78A47On3P_nLnSTIUqHvAQwnYpWvXoTVRBarnUzSqBXMmTO5D7h6I26k7kbx8eHRNbxD5SCvjBPKZt6hTufhdo8dRUWZXQwaQzOX_u3_DaOovUUCvKcdaQAwiixy-j5fYxbE6L-wcATAAAAAMAFVFvmLZLgigXe9LZxWe1XBJZ-FWckKeC8ovR6swdbTv0WcxTF22Zr_cylCFWcVmLGXp54tUQtTVsRdqywh9fZ-Knml99gdiR2g',
            },
         }
      ];

      for (const { ver, cts } of vers) {
         for (const [alg, cipherTxt] of Object.entries(cts)) {
            const [cipherStream] = streamFromBase64Url(cipherTxt);

            const decipher = await streamDecipher(userCred, cipherStream, async (cdinfo) => {
               expect(cdinfo.hint).toEqual(hint);
               expect(cdinfo.lp).toEqual(1);
               expect(cdinfo.lpEnd).toEqual(1);
               expect(cdinfo.alg).toBe(alg);
               expect(cdinfo.ic).toBe(1800000);
               expect(cdinfo.ver).toEqual(ver);
               expect(cdinfo.slt.byteLength).toEqual(cc.SLT_BYTES);
               return [pwd, undefined];
            });
            const cdInfo = await decipher.getCipherDataInfo();

            expect(cdInfo.alg).toEqual(alg);
            expect(cdInfo.ic).toEqual(1800000);
            expect(cdInfo.slt.byteLength).toEqual(cc.SLT_BYTES);
            expect(cdInfo.ver).toEqual(ver);
            expect(cdInfo.hint).toEqual(hint);

            // Although the cipherData for block1 is missing the "terminal block" indicator,
            // that isn't detected until we hit the end of the file and try to read another block
            await expect(decipher.decryptBlock0()).resolves.toEqual(clearData.subarray(0, 20));
            await expect(decipher.decryptBlockN()).resolves.toEqual(clearData.subarray(20));
            await expect(decipher.decryptBlockN()).rejects.toThrow(/Missing terminal/);
         }
      }
   });

   it("extra terminal block indicator, multi version", async function () {
      const [_, clearData] = streamFromStr('A nice 🦫 came to say hello');
      const pwd = 'a 🌲 of course';
      const hint = '🌧️';

      // NOTE: this cipherStream can be created by:
      //   * set ciphers-current: READ_SIZE_START = 20; READ_SIZE_MAX = Encipher.READ_SIZE_START * 16;
      //   * manually set ciphers-current term:true in two places (search for term:) and rebuilding the cli
      //   * run ./apps/web/scripts/ciphers_tests.sh
      const vers = [
         //v6
         {  ver: 6,
            cts: {
               'AES-GCM': 'mxQYSs5jS2yLP9UoVPL5Umg7_aVQ0Kohu9sM6u0AWjUGAGAAAAEBADUjCDDpJymFQGrtlpcLXrv-FayLZ8GrNTn1MtRAdxsAABe8NtaKQ2wbkt7ZdPI2NkArzYT-r1fUJujQQVU3scbYxSZBhqfp8rljM-WWfdSx20UeVViyBdonxlrdCz99LJDBxGnluk0tTGs3pU8paRrXUs7jui8pUHP7QvW8BgAoAAABAQAzT5VH4MLNFnuxVW7a-ZjEvcRzQBPRd3-cfCFf8R4v7dR95Hx5',
               'X20-PLY': '4oGG7bf2iwqs1Ljsc85yIYK9Tekk4AO1rupAqeobkfQGAGwAAAECACU7WFzBfSFXioJOUtFt9cwt2nmYyx_vbvduORUE-6KnHykmq0kotERAdxsAABfCS4X16NT1XKJs1_2LwbhN0qMedP46qVvJ8Bwy2Nx_15r-_Dai_Xtr4ozjU232a4hUv1_PIKVTEu8VU4F2DUNSz8SlVg5yLI8MSQxKcJGAt84v854geBjlAJvWBgA0AAABAgA7ZDI86mqgxANzrbFkdrqovb6cC9W07QSzcRXHUqokonBGpHMPInYj0K4vlp2s11p4',
               'AEGIS-256': 'BCBMTk_hVOi0MGzUZCkxWbC7ABcKigcsyhDLC3vz9QwGAJQAAAEDAGvAtgrTFpTgoiUU65LY8CHoD43gXSr64jim1HL7_fosH_NnlBh7CS6KSvVNoRYCekB3GwAAJ7jfBXuOoOdXFFvfJxF1rUP2pctiszIRA5dA4VtlKBATAeM3WlArwwxE0bg09nDxEBxGJTU1cunJtv-PTDBf65ELq6EtzUV89Nf2I-p1O2unHboiALilVfc0tJVUnh8YLUK0V72BCi3shY17jGgObiTMBBYtlh8KTLmCQAYATAAAAQMAekEOxoUB-qEhhqOPS1flXIygThAgFLJGWecj9hHGfMcwh-D8Rcmy6o7LU_VdFNULC-TORjXevyeClQAfSPnSH0578riwrIqoQA',
            }
         },
         //v7
         {  ver: 7,
            cts: {
               'AES-GCM': 'F3v_Pi6wH46zJFgyiyhI8DXAYKpO57dUnsxtOqfaNrkHAGAAAAEBAODZZ0Gwv0CCxoV7MZePzXvhluwX6nGziHmKQslAdxsAABe0zKtIKF4d50iBWVAty99DTnTFA1jdcSSE1Jh1WFNv_dKPg-djalFfCfIAnKUqux2eo2XHd8TAwza6V-wbFM54rfgARJaMbTArEnn8n9x-Qkk5iyhy-nL3OChvBwAoAAABAQB0ZNFh6fRfq85nh4t_1ezBFfPF9pqcdVhqZWJyCYNgejRwSQ9T',
               'X20-PLY': 'FaREI6wP_wPw1ByYBoxPa-YQTXdL2iAtgEljYb7pOnMHAGwAAAECACVsYFkEdmCTuMTTEC85RHOFJqk4e0Kj19WJZQXjFSwV3p-F_l23PcBAdxsAABc2fpd4zH47GXApu5WgXmuXzUXNwjXEtv0gbmVYboDAIqn8-WIEBhJGNKuvLUfXHoIiObQcQoSttKowEi5Hl_qODW_d8FjaH9Sf0wnnbuGF8pJhGTIwDksS_6P7BwA0AAABAgD7PFO6b61Ug3UfmiXKrj-MZENvjqGBBASgBxiSpAgPZ0tbuECBNa8WM6Glv94Dlukx',
               'AEGIS-256': 'uac6SPBDTpFsCr__H6fH6HA2deh5UT1Wuz6J9knxN6cHAJQAAAEDAFC36W0e0eNbwepQhIqbNTEClc47gLXZOQEbV1oIUEPd1_SihYM3bG51REU5oTqrQEB3GwAAJ-ECNPzfIclvvH9lfdT2_9aMwQFWc4pZa0sX8CEhAl5ulY3OYWkVVh_NzITu1Oot6BhvOnWwTcycogO9mNDDentQ0O3xtPJP4krZJUPtxgW0tLzxCN5snzPlX67clO6VpUI8ETrbX5yuw_2eDTErML4gmju8imum991UwgcATAAAAQMAvkSKYNBGevjW50PohhMMc-fhfuYP9xdJS0EGvIPs0AuRYLntmB6bdSkT33R-mF3AyBAQZpHBMqY8zEBq1cX3BbtPiHfp9BoR8g',
            },
         }
      ];

      for (const { ver, cts } of vers) {
         for (const [alg, cipherTxt] of Object.entries(cts)) {
            const [cipherStream] = streamFromBase64Url(cipherTxt);

            const decipher = await streamDecipher(userCred, cipherStream, async (cdinfo) => {
               expect(cdinfo.hint).toEqual(hint);
               expect(cdinfo.lp).toEqual(1);
               expect(cdinfo.lpEnd).toEqual(1);
               expect(cdinfo.alg).toBe(alg);
               expect(cdinfo.ic).toBe(1800000);
               expect(cdinfo.ver).toEqual(ver);
               expect(cdinfo.slt.byteLength).toEqual(cc.SLT_BYTES);
               return [pwd, undefined];
            });
            const cdInfo = await decipher.getCipherDataInfo();

            expect(cdInfo.alg).toEqual(alg);
            expect(cdInfo.ic).toEqual(1800000);
            expect(cdInfo.slt.byteLength).toEqual(cc.SLT_BYTES);
            expect(cdInfo.ver).toEqual(ver);
            expect(cdInfo.hint).toEqual(hint);

            await expect(decipher.decryptBlock0()).resolves.toEqual(clearData.subarray(0, 20));
            await expect(decipher.decryptBlockN()).rejects.toThrow(/Extra data block/);
         }
      }
   });

   it("flipped terminal block indicator, multi version", async function () {
      const [_, clearData] = streamFromStr('A nice 🦫 came to say hello');
      const pwd = 'a 🌲 of course';
      const hint = '🌧️';

      // NOTE: this cipherStream can be created by:
      //   * set ciphers-current: READ_SIZE_START = 20; READ_SIZE_MAX = Encipher.READ_SIZE_START * 16;
      //   * manually set ciphers-current term:true then false in two places (search for term:) and rebuilding the cli
      //   * run ./apps/web/scripts/ciphers_tests.sh
      const vers = [
         //v6
         {  ver: 6,
            cts: {
               'AES-GCM': 'zL-JSCGd1aRZUnPt9TYI8TxqyK2GOqXc1PPfgZ_moFcGAGAAAAEBAPnRpCPk1D7tTfVKhZxcBk83-vdpkFimVg_prmRAdxsAABeoHcob5QcQ7PGB4ZDscl-M2H1bCwnDvnciwPUCtwS_CJuOi-GXSHohqkthBR7Ep8FBnPVv4IfiXZ47LyDMTUBHrfnu7h1uXFBc6HhmjKVqPDzZxvDgSQiGtbZiBgAoAAAAAQCYbD7O11e8YfHzbrAic5RRZRI4G8zn6ZAqn2a-nbjkihLHoM8c',
               'X20-PLY': 'bP3w_P0Y9OoqnmwmWQRa9_pCnQyJgq7FWvSNyQQJXXYGAGwAAAECAPdKsJxFPHOxKLdM5ly8HUikZOiXDIKmfJUKqA6ZQzuQLcyks8wHVU9AdxsAABcHrl_B4pkZTPTqgTLTyMN-GiFJGLBgLidfafyJ9OI3zM-CM7Bt4VqxqZzx2HlPB96z0XJKIWYA0_E0UjxBGNmAT3Dlm_cecMIcDTjphcy_Yb0QfCT3-wIoOml3BgA0AAAAAgDL0Bcr0EpFvqc9nVANaFwv6LOPykWvtq_QFhg4-dj-GXp3w4kYQsEklQc2OOHEAF7Q',
               'AEGIS-256': 'z_wjYRYc3RAXYpAaXvU2V3BCWYno0y6Kh0pVcUjZl3kGAJQAAAEDAGcCoTiOwDrN12pPfW5eUpz5g45AFyspWIwlZMXN1ioRp4_dUdl3IhjK_Wqlb3CePkB3GwAAJ7o9Tijp5eLpL6N_0V-ruVh61s6GmtRq8j5FE3LS6D5K-Y9uH9BZ1GI8UMkGNsAfnfMArB8cj4R7lRVo1HjqOX4j15b3FEU3ROwMWmNl7Zp77CN4023BH7JzlPzen7M_DyMsa7qiBrVF8GV-6f577Sv6xpFsUVweZRED_wYATAAAAAMAQ7fPqOQtec-v1wNMzhL5V5s8XNQ194ef7xLIn4oNjZF6FWKLsvQ65lt0psTKmu-f2e3qcU93LwWx7qs3JZDI1KFhB-kvb0vQQQ',
            }
         },
         //v7
         {  ver: 7,
            cts: {
               'AES-GCM': 'r2XtsTt5znYG3JRp89J6EtMmcV_yeuucyb2HxhaoML4HAGAAAAEBANT_KOEL6JpCLoa4ThqWw7_N4oAww7Rs2O_rtgFAdxsAABehiGogOpkUkw57qV3bN3mRtX7j9jVCW86XnKbtebLj62c0KkT8wOflclxQfO3fk1HDmofGzGXGaDj6qpQV3NKqhRchM-xVR5KQvbI7Dq0aKk6DgM7jU-ugX9w4BwAoAAAAAQA3S43iFIVmrxzuDavRCNCgF9NMtzPeeRLefHmHZ84RgPaQMoHB',
               'X20-PLY': 'qUmQI6Yb4w7bnoWqvHzCSNAIUAyEkpB4fTBdZG1y2UcHAGwAAAECAFMazLZ3rkgn-1I6jKvWh_VqCcxwh78hF51rNFrgBPXPhMmyGtw3swNAdxsAABfJKJOPB6vJEXvDajGtT6880FlKcRa3bJmkDAErmkt8BSCfr3aO5GtGbZ_2bwIcSzuUnlVU9bLjYO732LHiy7GnJtqLlMcCseAuqoA63mJnqP5QarD-gbq8f5_3BwA0AAAAAgD3yFXS0Av9DtGNNcvtDYFvqCq_8Hwju4P5B1P8ZIknZmYADRVUNF9wMXFQrPG6v2DU',
               'AEGIS-256': 'cWFcmdpN77SH9vVP2HN_6MTqpeC_VKqVox97CkZkXcAHAJQAAAEDALfnYSqMy3StceLZoBTbRNhRzhc9ZxYxASRynSHbwlRkJo_OCNZPjWBAN5A36mcaO0B3GwAAJ1IhFFKx70J6wo3Mk_qnF0Swnq7qFJsMcysry0pACwze3k-_DY6nhrox_BV9m6hzb1oGB6fPChp1tYYQJsDq6HdlwgNZsZYhuGylt2AGkvBWU9751-t4q4GjK3hQKFDJKhToaIfR_fMmLnFc8Re1_6gM0GZtNPbyUEDHHgcATAAAAAMApYpNppo4FzPkLYv8T-ev2JHrMI3BaMTrKw70cHXpWZ0j4ZfQWw10uCXL4utvnI7f9f9Qu-yi6g_Vaq4byirzoNNEVUwsQ2Cupw',
            },
         }
      ];

      for (const { ver, cts } of vers) {
         for (const [alg, cipherTxt] of Object.entries(cts)) {
            const [cipherStream] = streamFromBase64Url(cipherTxt);

            const decipher = await streamDecipher(userCred, cipherStream, async (cdinfo) => {
               expect(cdinfo.hint).toEqual(hint);
               expect(cdinfo.lp).toEqual(1);
               expect(cdinfo.lpEnd).toEqual(1);
               expect(cdinfo.alg).toBe(alg);
               expect(cdinfo.ic).toBe(1800000);
               expect(cdinfo.ver).toEqual(ver);
               expect(cdinfo.slt.byteLength).toEqual(cc.SLT_BYTES);
               return [pwd, undefined];
            });
            const cdInfo = await decipher.getCipherDataInfo();

            expect(cdInfo.alg).toEqual(alg);
            expect(cdInfo.ic).toEqual(1800000);
            expect(cdInfo.slt.byteLength).toEqual(cc.SLT_BYTES);
            expect(cdInfo.ver).toEqual(ver);
            expect(cdInfo.hint).toEqual(hint);

            await expect(decipher.decryptBlock0()).resolves.toEqual(clearData.subarray(0, 20));
            await expect(decipher.decryptBlockN()).rejects.toThrow(/Extra data block/);
         }
      }
   });

   it("bad pwd to cipherdata info and decrypt, v4", async function () {
      const [_, clearData] = streamFromStr('A nice 🦫 came to say hello');
      const pwdGood = 'a 🌲 of course';
      const pwdBad = 'a 🌵 of course';
      const userCredBad = new Uint8Array([0, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98, 180, 61, 166, 219, 54, 164, 55]);

      // copied from "correct cipherdata info and decryption" spec above
      const userCredGood = new Uint8Array([58, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98, 180, 61, 166, 219, 54, 164, 55]);

      let [cipherStream, cipherData] = streamFromBytes(new Uint8Array([117, 163, 250, 117, 59, 97, 3, 10, 139, 12, 55, 161, 115, 52, 28, 105, 246, 126, 220, 0, 129, 151, 165, 136, 46, 97, 163, 160, 91, 9, 189, 218, 4, 0, 116, 0, 0, 0, 2, 0, 16, 242, 98, 46, 102, 223, 79, 227, 209, 73, 22, 207, 92, 80, 75, 125, 125, 234, 18, 21, 88, 64, 43, 68, 25, 193, 133, 31, 159, 156, 8, 184, 10, 164, 33, 46, 20, 159, 218, 222, 64, 119, 27, 0, 0, 23, 5, 135, 172, 203, 4, 101, 163, 155, 133, 221, 40, 227, 91, 222, 227, 213, 97, 77, 24, 117, 60, 188, 27, 153, 253, 134, 10, 112, 75, 76, 146, 132, 123, 217, 7, 171, 211, 24, 206, 186, 248, 244, 119, 18, 165, 195, 59, 160, 76, 31, 90, 80, 53, 19, 39, 143, 99, 141, 109, 68, 72, 63, 121, 199, 96, 95, 157, 81]));
      let decipher = await streamDecipher(userCredGood, cipherStream, async (cdinfo) => {
         expect(cdinfo.alg).toBe('X20-PLY');
         expect(cdinfo.ic).toBe(1800000);
         expect(cdinfo.hint).toBeTruthy();
         expect(cdinfo.ver).toEqual(cc.VERSION4);
         return [pwdGood, undefined];
      });

      // First make sure the good values are actually good
      await expect(decipher.decryptBlock0()).resolves.toEqual(clearData);

      // Ensure bad password fails
      [cipherStream] = streamFromBytes(cipherData);
      decipher = await streamDecipher(userCredGood, cipherStream, async () => {
         return [pwdBad, undefined];
      });

      await expect(decipher.decryptBlock0()).rejects.toThrow(DOMException);

      // Test wrong userCred
      [cipherStream] = streamFromBytes(cipherData);
      decipher = await streamDecipher(userCredBad, cipherStream, undefined);

      await expect(decipher.getCipherDataInfo()).rejects.toThrow(/Invalid MAC/);

      // decipher now in invalid state from prevous getCipherDataInfo call
      await expect(decipher.decryptBlock0()).rejects.toThrow(new RegExp('Decipher invalid.+'));

      // Test wrong userCred with block decrypt first (error msg is different)
      [cipherStream] = streamFromBytes(cipherData);
      decipher = await streamDecipher(userCredBad, cipherStream, async () => {
         return [pwdGood, undefined];
      });

      await expect(decipher.decryptBlock0()).rejects.toThrow(new RegExp('Invalid MAC.+'));
   });

   it("bad pwd to cipherdata info and decrypt, v5", async function () {
      const [_, clearData] = streamFromStr('A nice 🦫 came to say hello');
      const pwdGood = 'a 🌲 of course';
      const pwdBad = 'a 🌵 of course';
      const userCredBad = new Uint8Array([0, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98, 180, 61, 166, 219, 54, 164, 55]);

      // copied from "correct cipherdata info and decryption" spec above
      const userCredGood = new Uint8Array([58, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98, 180, 61, 166, 219, 54, 164, 55]);

      let [cipherStream, cipherData] = streamFromBytes(new Uint8Array([166, 123, 188, 183, 212, 97, 47, 147, 59, 39, 78, 222, 101, 74, 221, 53, 27, 11, 194, 67, 156, 235, 116, 104, 65, 64, 76, 166, 29, 220, 71, 179, 5, 0, 116, 0, 0, 1, 2, 0, 121, 78, 37, 8, 192, 196, 110, 22, 164, 106, 59, 161, 122, 165, 176, 147, 49, 43, 41, 250, 163, 111, 218, 4, 174, 61, 6, 169, 145, 216, 66, 166, 139, 82, 19, 207, 29, 75, 105, 149, 64, 119, 27, 0, 0, 23, 93, 92, 56, 163, 242, 71, 208, 3, 190, 44, 140, 222, 149, 159, 152, 193, 162, 44, 177, 93, 197, 119, 131, 88, 92, 53, 108, 167, 253, 64, 216, 200, 121, 212, 193, 153, 180, 39, 92, 35, 142, 6, 240, 115, 51, 211, 198, 63, 12, 126, 128, 206, 178, 114, 65, 37, 246, 197, 19, 79, 58, 96, 56, 86, 172, 162, 217, 70]));
      let decipher = await streamDecipher(userCredGood, cipherStream, async (cdinfo) => {
         expect(cdinfo.alg).toBe('X20-PLY');
         expect(cdinfo.ic).toBe(1800000);
         expect(cdinfo.hint).toBeTruthy();
         expect(cdinfo.ver).toEqual(cc.VERSION5);
         return [pwdGood, undefined];
      });

      // First make sure the good values are actually good
      await expect(decipher.decryptBlock0()).resolves.toEqual(clearData);

      // Ensure bad password fails
      [cipherStream] = streamFromBytes(cipherData);
      decipher = await streamDecipher(userCredGood, cipherStream, async () => {
         return [pwdBad, undefined];
      });

      await expect(decipher.decryptBlock0()).rejects.toThrow(DOMException);

      // Test wrong userCred
      [cipherStream] = streamFromBytes(cipherData);
      decipher = await streamDecipher(userCredBad, cipherStream, undefined);

      await expect(decipher.getCipherDataInfo()).rejects.toThrow(/MAC/);

      // Does not get MAC error because the decipher instance is now in a
      // bad state and will remain so... forever...
      await expect(decipher.decryptBlock0()).rejects.toThrow(new RegExp('Decipher invalid state.+'));
   });

   it("bad pwd to cipherdata info and decrypt, multi version", async function () {
      const [_, clearData] = streamFromStr('A nice 🦫 came to say hello');
      const pwdGood = 'a 🌲 of course';
      const pwdBad = 'a 🌵 of course';
      const userCredBad = new Uint8Array([0, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98, 180, 61, 166, 219, 54, 164, 55]);

      // NOTE: this cipherStream can be created by:
      //   * set ciphers-current: READ_SIZE_START = 20; READ_SIZE_MAX = Encipher.READ_SIZE_START * 16;
      //   * run ./apps/web/scripts/ciphers_tests.sh
      const vers = [
         //v6
         {  ver: 6,
            cts: {
               'AES-GCM': 'F4qYlclmVWQD5IayN_Ub_3pQ7N91gNZzLGi8Iu_sIbkGAGAAAAABAMrZN-Xbi9Kvdpcl2k5pFxC_07E33BkQ-QlqxchAdxsAABfm9OTNhim0krfh9ZLGyi7yDGB-oB4gScok1BFuD5UcpZEj44VRQWVD8kCX-fD_t4VRbXXcgYiz1TOGFz5nsobA3jkhROi53GPsJiSiW18yy3A73-eETAgZjQfeBgAoAAABAQD1T3bCnKPA38DHIMBWWXsv7H2fFBJ9DjIPimYghk6CJdS5IXME',
               'X20-PLY': 'PkeGHkLso1abo-aBE93x_e69rJb6OrW-STBAAwDxbRQGAGwAAAACANIwjwvIQLygUdSpdbfKw83iAo126tZL0VgOnatOaYIfOXGuBj5hEGhAdxsAABfIUjubZ9H30GHKKissSmSWyblIHejAG_IPbxEjFyiOrgndOJuISt5vqJhmTJlRWoc_1683Ku3T0MkHtw24Je54qsYzl4TKzwqvSvMhL56c2g2hIVF6TuB4Cr97BgA0AAABAgAT-DRYec2-zEvMw50PxYgwmdvcJoHH01QMlf_4rV01LzigH2KFr9VaKQASTWU7310c',
               'AEGIS-256': 'XRa5nS7wJ8DLF6HWZyP2MWfeAS4PyHUYzkd67AaMUfYGAJQAAAADAJey272VOwM55vXW_P2rEudCgPSRwGB5nAjF7gmnc5AA46rTvby4Wv_R6l6eH0UNQUB3GwAAJ_K3cZg5LpRqUy83VmoXe1KwPHh3wkGbEes_qRTu7vrNvz_saJVP0ajB6xDxZYs5RhHb9yl2GWxtkLpqkhN6N2pxtAKF2a_LjknVWeIRN_jxn-LqzwkuI-Lz4Pm0OeGEwl7bfOvP8qftV8UztFNlwmGxOA_nIu_KmWG6CwYATAAAAQMA_n0RaJelAb_JLnaUUtlQrgBaG7_wcwL4lplkWi3V_Uo3V9pkIHvDj6Jvgy58blIx5yGQHa96GTx_0U3_0w38vAaiupLQGf4Ibw',
            }
         },
         //v7
         {  ver: 7,
            cts: {
               'AES-GCM': 'f54Kbfvskz0fSmqLMKu5meoa98Pjd7acb842dogLb5oHAGAAAAABAMad0LlIngQIQmfHf5UlOBpI22Gqs_yc9ONnRUpAdxsAABdlMKpBc7lTiu1ubTTqtyXg1w_gpoPBTqraECeUbj-J_rOkysOSg_0bj6tkWQ8K7QEe9YtthrNyIueZz7SjNZTyyqYssKkhLcgwA_M6r3yWfnnTukXCQCoo9tYaBwAoAAABAQCFQZFWQYSA2CBs8ljZzqqjUiFqKCS7uw6RE0e8S2LEiPuIHJwB',
               'X20-PLY': 'AZwRvYONTmUiGmy1FD_E_W-KIMwISoTV1928-TQsWDkHAGwAAAACAGWfXMaHOiKMdRhrASFEp6IBNAiA77MvWrl14TQBYKzViy1hGaH7x1lAdxsAABdYtEAsyZ70RPsXSHo91g5W2RE2mGtid91BdMw4p_pnhYXVjdU50bJdrfp8iQa-KzC5CrfpwopR_hufqd1klSAXe0jqCNoMKq9lV_dZmbkgyp-P3OidXHXTPiZnBwA0AAABAgBdgykbdEQtRtnwwo46Jd0X8fxc0ZR5SahASYPMaMkvZmDD1erhR8LHVF4rMtZoOvvc',
               'AEGIS-256': '7V_KLO_W6Dn3z_Nm8ApEvpuCStCCrI9DotqOK4NlL3YHAJQAAAADAGQBbVBjySD_E4d9VA1ALhL291hssjA9dXCUPaxKiOi0VsaLhpx2DAYSG0YOEDtIEkB3GwAAJ3oAD7PgLd1p_WcJgtbVhwfU1oEuVaKWWphOpDzc2u6aoWKxZlIqEIrtWExNZu4vTi2-Y4IT5RoBtsIvQ00Y_VVK6hGRVHxhbeDGPgMuybUanllaCCurgP4JSo0SASwEnImEQpHYraWRqSEXO80Y5FszBdMODnIyrJwWPgcATAAAAQMAcoz6mX1p-OtwhmpbsQnq8sDZRmzcByWMsv0-k_4FRJ4FvHYt-ZxL7f9GHTc9glJRufqaapbSmr5aX5x0a_ioF4jijYiOSAmKDA',
            },
         }
      ];

      for (const { ver, cts } of vers) {
         for (const [alg, cipherTxt] of Object.entries(cts)) {
            let [cipherStream, cipherData] = streamFromBase64Url(cipherTxt);
             // First make sure the good values are actually good
             let decipher = await streamDecipher(userCred, cipherStream, async (cdinfo) => {
               expect(cdinfo.alg).toBe(alg);
               expect(cdinfo.ic).toBe(1800000);
               expect(cdinfo.hint).toBeTruthy();
               expect(cdinfo.ver).toEqual(ver);
               return [pwdGood, undefined];
            });
            await expect(decipher.decryptBlock0()).resolves.toEqual(clearData.slice(0,20));

            // Ensure bad password fails
            [cipherStream] = streamFromBytes(cipherData);
            decipher = await streamDecipher(userCred, cipherStream, async () => {
               return [pwdBad, undefined];
            });
            await expect(decipher.decryptBlock0()).rejects.toThrow(DOMException);

            // Test wrong userCred
            [cipherStream] = streamFromBytes(cipherData);
            decipher = await streamDecipher(userCredBad, cipherStream, async () => {
               return [pwdGood, undefined];
            });
            await expect(decipher.getCipherDataInfo()).rejects.toThrow(/MAC/);

            // Does not get MAC error because the decipher instance is now in a
            // bad state and will remain so... forever...
            await expect(decipher.decryptBlock0()).rejects.toThrow(new RegExp('Decipher invalid state.+'));
         }
      }
   });

});

describe("Custom AD encryption and decryption", function () {
   beforeEach(async () => {
      await cryptoReady();
   });

   it("round trip block0, all algorithms with customAd", async function () {
      for (const alg of Ciphers.algs()) {
         const [clearStream, clearData] = streamFromStr('This is a secret 🦆');
         const pwd = 'a good pwd';
         const hint = 'not really';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));
         const customAd = crypto.getRandomValues(new Uint8Array(52));

         const latest = latestEncipher(userCred, alg, cc.ICOUNT_MIN, 1, 1, clearStream,
            async (cdinfo) => {
               expect(cdinfo.alg).toEqual(alg);
               expect(cdinfo.slt.byteLength).toEqual(cc.SLT_BYTES);
               expect(cdinfo.ic).toBe(cc.ICOUNT_MIN);
               expect(cdinfo.lp).toEqual(1);
               expect(cdinfo.lpEnd).toEqual(1);
               expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
               return [pwd, hint];
            },
            customAd
         );
         const block0 = await latest.encryptBlock0();

         const [cipherStream] = streamFromCipherBlock([block0]);
         const decipher = await streamDecipher(userCred, cipherStream,
            async (cdinfo) => {
               expect(cdinfo.alg).toEqual(alg);
               expect(cdinfo.slt.byteLength).toEqual(cc.SLT_BYTES);
               expect(cdinfo.ic).toBe(cc.ICOUNT_MIN);
               expect(cdinfo.hint).toEqual(hint);
               expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
               return [pwd, undefined];
            },
            customAd
         );

         const decrypted = await decipher.decryptBlock0();
         await expect(areEqual(decrypted, clearData)).resolves.toEqual(true);
      }
   });

   it("round trip blockN, all algorithms with customAd", async function () {

      for (const alg of Ciphers.algs()) {
         let [clearStream, clearData] = streamFromStr('This is a secret 🦀');
         const pwd = 'a not good pwd';
         const hint = 'sorta';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));
         const customAd = crypto.getRandomValues(new Uint8Array(223));

         const latest = latestEncipher(userCred, alg, cc.ICOUNT_MIN, 1, 1, clearStream, async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, hint];
         }, customAd);

         const readStart = 12;
         //@ts-ignore force multiple blocks
         latest['_readTarget'] = readStart;

         const block0 = await latest.encryptBlock0();
         const blockN = await latest.encryptBlockN();

         let [cipherStream] = streamFromCipherBlock([block0, blockN]);
         let decipher = await streamDecipher(userCred, cipherStream, async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, undefined];
         }, customAd);

         let decb0 = await decipher.decryptBlock0();
         await expect(areEqual(decb0, clearData.slice(0, readStart))).resolves.toEqual(true);

         const decb1 = await decipher.decryptBlockN();
         await expect(areEqual(decb1, clearData.slice(readStart))).resolves.toEqual(true);
      }
   });

   it("round trip block0, all algorithms missing customAd", async function () {
      for (const alg of Ciphers.algs()) {
         const [clearStream, clearData] = streamFromStr('This is a secret 🦆');
         const pwd = 'a good pwd';
         const hint = 'not really';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));
         const customAd = crypto.getRandomValues(new Uint8Array(52));

         const latest = latestEncipher(userCred, alg, cc.ICOUNT_MIN, 1, 1, clearStream,
            async (cdinfo) => {
               expect(cdinfo.alg).toEqual(alg);
               expect(cdinfo.slt.byteLength).toEqual(cc.SLT_BYTES);
               expect(cdinfo.ic).toBe(cc.ICOUNT_MIN);
               expect(cdinfo.lp).toEqual(1);
               expect(cdinfo.lpEnd).toEqual(1);
               expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
               return [pwd, hint];
            },
            customAd
         );
         const block0 = await latest.encryptBlock0();

         const [cipherStream] = streamFromCipherBlock([block0]);
         const decipher = await streamDecipher(userCred, cipherStream,
            async (cdinfo) => {
               expect(cdinfo.alg).toEqual(alg);
               expect(cdinfo.slt.byteLength).toEqual(cc.SLT_BYTES);
               expect(cdinfo.ic).toBe(cc.ICOUNT_MIN);
               expect(cdinfo.hint).toEqual(hint);
               expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
               return [pwd, undefined];
            }
         );

         await expect(decipher.decryptBlock0()).rejects.toThrow(DOMException);
      }
   });

   it("round trip block0, all algorithms added customAd", async function () {
      for (const alg of Ciphers.algs()) {
         const [clearStream, clearData] = streamFromStr('This is a secret 🦆');
         const pwd = 'a good pwd';
         const hint = 'not really';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));
         const customAd = crypto.getRandomValues(new Uint8Array(52));

         const latest = latestEncipher(userCred, alg, cc.ICOUNT_MIN, 1, 1, clearStream,
            async (cdinfo) => {
               expect(cdinfo.alg).toEqual(alg);
               expect(cdinfo.slt.byteLength).toEqual(cc.SLT_BYTES);
               expect(cdinfo.ic).toBe(cc.ICOUNT_MIN);
               expect(cdinfo.lp).toEqual(1);
               expect(cdinfo.lpEnd).toEqual(1);
               expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
               return [pwd, hint];
            },
         );
         const block0 = await latest.encryptBlock0();

         const [cipherStream] = streamFromCipherBlock([block0]);
         const decipher = await streamDecipher(userCred, cipherStream,
            async (cdinfo) => {
               expect(cdinfo.alg).toEqual(alg);
               expect(cdinfo.slt.byteLength).toEqual(cc.SLT_BYTES);
               expect(cdinfo.ic).toBe(cc.ICOUNT_MIN);
               expect(cdinfo.hint).toEqual(hint);
               expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
               return [pwd, undefined];
            },
            customAd
         );

         await expect(decipher.decryptBlock0()).rejects.toThrow(DOMException);
      }
   });

   it("round trip block0, all algorithms changed customAd", async function () {
      for (const alg of Ciphers.algs()) {
         const [clearStream, clearData] = streamFromStr('This is a secret 🦆');
         const pwd = 'a good pwd';
         const hint = 'not really';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));
         const customAd = crypto.getRandomValues(new Uint8Array(52));

         const latest = latestEncipher(userCred, alg, cc.ICOUNT_MIN, 1, 1, clearStream,
            async (cdinfo) => {
               expect(cdinfo.alg).toEqual(alg);
               expect(cdinfo.slt.byteLength).toEqual(cc.SLT_BYTES);
               expect(cdinfo.ic).toBe(cc.ICOUNT_MIN);
               expect(cdinfo.lp).toEqual(1);
               expect(cdinfo.lpEnd).toEqual(1);
               expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
               return [pwd, hint];
            },
            customAd
         );
         const block0 = await latest.encryptBlock0();

         // modify customAd so it doesn't match what was used for encryption
         customAd[2] ^= 1;
         const [cipherStream] = streamFromCipherBlock([block0]);
         const decipher = await streamDecipher(userCred, cipherStream,
            async (cdinfo) => {
               expect(cdinfo.alg).toEqual(alg);
               expect(cdinfo.slt.byteLength).toEqual(cc.SLT_BYTES);
               expect(cdinfo.ic).toBe(cc.ICOUNT_MIN);
               expect(cdinfo.hint).toEqual(hint);
               expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
               return [pwd, undefined];
            },
            customAd
         );

         await expect(decipher.decryptBlock0()).rejects.toThrow(DOMException);
      }
   });

   it("round trip blockN, all algorithms missing customAd", async function () {

      for (const alg of Ciphers.algs()) {
         let [clearStream, clearData] = streamFromStr('This is a secret 🦀');
         const pwd = 'a not good pwd';
         const hint = 'sorta';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));
         const customAd = crypto.getRandomValues(new Uint8Array(123));

         const latest = latestEncipher(userCred, alg, cc.ICOUNT_MIN, 1, 1, clearStream, async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, hint];
         }, customAd);

         const readStart = 12;
         //@ts-ignore force multiple blocks
         latest['_readTarget'] = readStart;

         const block0 = await latest.encryptBlock0();
         const blockN = await latest.encryptBlockN();

         let [cipherStream] = streamFromCipherBlock([block0, blockN]);
         let decipher = await streamDecipher(userCred, cipherStream, async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, undefined];
         });

         await expect(decipher.decryptBlock0()).rejects.toThrow(DOMException);
         await expect(decipher.decryptBlockN()).rejects.toThrow(/Decipher invalid state/);
      }
   });


   it("round trip blockN, all algorithms added customAd", async function () {

      for (const alg of Ciphers.algs()) {
         let [clearStream, clearData] = streamFromStr('This is a secret 🦀');
         const pwd = 'a not good pwd';
         const hint = 'sorta';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));
         const customAd = crypto.getRandomValues(new Uint8Array(123));

         const latest = latestEncipher(userCred, alg, cc.ICOUNT_MIN, 1, 1, clearStream, async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, hint];
         });

         const readStart = 12;
         //@ts-ignore force multiple blocks
         latest['_readTarget'] = readStart;

         const block0 = await latest.encryptBlock0();
         const blockN = await latest.encryptBlockN();

         let [cipherStream] = streamFromCipherBlock([block0, blockN]);
         let decipher = await streamDecipher(userCred, cipherStream, async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, undefined];
         }, customAd);

         await expect(decipher.decryptBlock0()).rejects.toThrow(DOMException);
         await expect(decipher.decryptBlockN()).rejects.toThrow(/Decipher invalid state/);
      }
   });

   it("round trip blockN, all algorithms added customAd", async function () {

      for (const alg of Ciphers.algs()) {
         let [clearStream, clearData] = streamFromStr('This is a secret 🦀');
         const pwd = 'a not good pwd';
         const hint = 'sorta';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));
         const customAd = crypto.getRandomValues(new Uint8Array(123));

         const latest = latestEncipher(userCred, alg, cc.ICOUNT_MIN, 1, 1, clearStream, async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, hint];
         }, customAd);

         const readStart = 12;
         //@ts-ignore force multiple blocks
         latest['_readTarget'] = readStart;

         const block0 = await latest.encryptBlock0();
         const blockN = await latest.encryptBlockN();

         // modify customAd so it doesn't match what was used for encryption
         customAd[customAd.length - 1] ^= 1;
         let [cipherStream] = streamFromCipherBlock([block0, blockN]);
         let decipher = await streamDecipher(userCred, cipherStream, async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, undefined];
         }, customAd);

         await expect(decipher.decryptBlock0()).rejects.toThrow(DOMException);
         await expect(decipher.decryptBlockN()).rejects.toThrow(/Decipher invalid state/);
      }
   });});


describe("Detect changed cipher data", function () {
   beforeEach(async () => {
      await cryptoReady();
   });

   it("detect changed headerData", async function () {

      for (const alg of Ciphers.algs()) {
         const [clearStream, clearData] = streamFromStr('This is a secret 🦆');
         const pwd = 'a good pwd';
         const hint = 'not really';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

         const latest = latestEncipher(
            userCred,
            alg,
            cc.ICOUNT_MIN,
            1, // lp
            1, // lpEnd
            clearStream,
            async (cdinfo) => {
               expect(cdinfo.lp).toEqual(1);
               expect(cdinfo.lpEnd).toEqual(1);
               expect(cdinfo.alg).toBe(alg);
               expect(cdinfo.ic).toBe(cc.ICOUNT_MIN);
               return [pwd, hint];
            }
         );

         const block0 = await latest.encryptBlock0();

         const savedHeader = new Uint8Array(block0.parts[0]);

         // set byte in MAC
         block0.parts[0][12] = block0.parts[0][12] == 123 ? 124 : 123;
         let [cipherStream] = streamFromCipherBlock([block0]);
         let decipher = await streamDecipher(userCred, cipherStream, async () => {
            return [pwd, undefined];
         });

         await expect(decipher.decryptBlock0()).rejects.toThrow(/Invalid MAC.+/);

         block0.parts[0] = new Uint8Array(savedHeader);
         [cipherStream] = streamFromCipherBlock([block0]);
         decipher = await streamDecipher(userCred, cipherStream, async () => {
            return [pwd, undefined];
         });

         await expect(decipher.decryptBlock0()).resolves.toEqual(clearData);

         // set version
         block0.parts[0][33] = block0.parts[0][33] == 43 ? 45 : 43;
         [cipherStream] = streamFromCipherBlock([block0]);

         await expect(streamDecipher(userCred, cipherStream, undefined)).rejects.toThrow(/Invalid version/);

         // set length
         block0.parts[0] = new Uint8Array(savedHeader);
         block0.parts[0][36] = block0.parts[0][36] == 43 ? 45 : 43;
         [cipherStream] = streamFromCipherBlock([block0]);
         decipher = await streamDecipher(userCred, cipherStream, async () => {
            return [pwd, undefined];
         });

         await expect(decipher.decryptBlock0()).rejects.toThrow(/Cipher data length mismatch+/);
      }
   });

   it("detect changed additionalData", async function () {

      for (const alg of Ciphers.algs()) {
         const [clearStream, clearData] = streamFromStr('This is a secret 🦆');
         const pwd = 'a good pwd';
         const hint = 'not really';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

         const latest = latestEncipher(
            userCred,
            alg,
            cc.ICOUNT_MIN,
            1, // lp
            1, // lpEnd
            clearStream,
            async (cdinfo) => {
               expect(cdinfo.alg).toBe(alg);
               expect(cdinfo.ic).toBe(cc.ICOUNT_MIN);
               return [pwd, hint];
            }
         );
         const block0 = await latest.encryptBlock0();

         const savedAD = new Uint8Array(block0.parts[1]);

         block0.parts[1][12] = block0.parts[1][12] == 123 ? 124 : 123;
         let [cipherStream] = streamFromCipherBlock([block0]);
         let decipher = await streamDecipher(userCred, cipherStream, async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, undefined];
         });

         await expect(decipher.decryptBlock0()).rejects.toThrow(new RegExp('.+MAC.+'));

         // Confirm we're back to good state
         block0.parts[1] = new Uint8Array(savedAD);
         [cipherStream] = streamFromCipherBlock([block0]);
         decipher = await streamDecipher(userCred, cipherStream, async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, undefined];
         });

         await expect(decipher.decryptBlock0()).resolves.toEqual(clearData);

         // set byte near end
         const back = block0.parts[1].byteLength - 4;
         block0.parts[1][back] = block0.parts[1][back] == 43 ? 45 : 43;
         [cipherStream] = streamFromCipherBlock([block0]);
         decipher = await streamDecipher(userCred, cipherStream, async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, undefined];
         });

         await expect(decipher.decryptBlock0()).rejects.toThrow(new RegExp('.+MAC.+'));
      }
   });

   it("detect changed encryptedData", async function () {

      for (const alg of Ciphers.algs()) {
         const [clearStream] = streamFromStr('This is a secret 🦆');
         const pwd = 'a good pwd';
         const hint = 'not really';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

         const latest = latestEncipher(
            userCred,
            alg,
            cc.ICOUNT_MIN,
            1, // lp
            1, // lpEnd
            clearStream,
            async (cdinfo) => {
               expect(cdinfo.alg).toBe(alg);
               expect(cdinfo.ic).toBe(cc.ICOUNT_MIN);
               return [pwd, hint];
            }
         );
         const block0 = await latest.encryptBlock0();

         block0.parts[2][12] = block0.parts[2][12] == 123 ? 124 : 123;
         let [cipherStream] = streamFromCipherBlock([block0]);
         let decipher = await streamDecipher(userCred, cipherStream, async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, undefined];
         });

         await expect(decipher.decryptBlock0()).rejects.toThrow(new RegExp('.+MAC.+'));
      }
   });

   it("does not detect changed headerData, skip MAC verify", async function () {

      for (const alg of Ciphers.algs()) {
         const [clearStream, clearData] = streamFromStr('This is a secret 🦆');
         const pwd = 'a good pwd';
         const hint = 'not really';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

         const latest = latestEncipher(
            userCred,
            alg,
            cc.ICOUNT_MIN,
            1, // lp
            1, // lpEnd
            clearStream,
            async (cdinfo) => {
               expect(cdinfo.lp).toEqual(1);
               expect(cdinfo.lpEnd).toEqual(1);
               expect(cdinfo.alg).toBe(alg);
               expect(cdinfo.ic).toBe(cc.ICOUNT_MIN);
               return [pwd, hint];
            }
         );
         const block0 = await latest.encryptBlock0();

         // set byte in MAC
         block0.parts[0][12] = block0.parts[0][12] == 123 ? 124 : 123;
         let [cipherStream] = streamFromCipherBlock([block0]);
         let decipher = await streamDecipher(userCred, cipherStream, async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, undefined];
         });

         // Monkey patch to skip MAC validation
         //@ts-ignore
         decipher['_verifyMAC'] = (): Promise<boolean> => {
            return Promise.resolve(true);
         };

         // This should succeed even though the MAC has been changed (because
         // MAC was not tested due to monkey patch)
         await expect(decipher.decryptBlock0()).resolves.toEqual(clearData);
      }
   });

   it("detect changed additionalData, skip MAC verify", async function () {

      for (const alg of Ciphers.algs()) {
         const [clearStream, clearData] = streamFromStr('This is a secret 🦆');
         const pwd = 'a good pwd';
         const hint = 'not really';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

         const latest = latestEncipher(
            userCred,
            alg,
            cc.ICOUNT_MIN,
            1, // lp
            1, // lpEnd
            clearStream,
            async (cdinfo) => {
               expect(cdinfo.alg).toBe(alg);
               expect(cdinfo.ic).toBe(cc.ICOUNT_MIN);
               return [pwd, hint];
            }
         );
         const block0 = await latest.encryptBlock0();

         // set byte in additional data
         block0.parts[1][12] = block0.parts[1][12] == 123 ? 124 : 123;
         let [cipherStream] = streamFromCipherBlock([block0]);
         let decipher = await streamDecipher(userCred, cipherStream, async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, undefined];
         });

         // Monkey patch to skip MAC validation
         //@ts-ignore
         decipher['_verifyMAC'] = (): Promise<boolean> => {
            return Promise.resolve(true);
         };

         // This should fail (even though MAC check wass skipped) because
         // AD check is part of all encryption algorithms. Note that this
         // should fail with DOMException rather than Error with MAC in message
         await expect(decipher.decryptBlock0()).rejects.toThrow(DOMException);
      }
   });

   it("detect changed encryptedData, skip MAC verify", async function () {

      for (const alg of Ciphers.algs()) {
         const [clearStream, clearData] = streamFromStr('This is a secret 🦆');
         const pwd = 'a good pwd';
         const hint = 'not really';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

         const latest = latestEncipher(
            userCred,
            alg,
            cc.ICOUNT_MIN,
            1, // lp
            1, // lpEnd
            clearStream,
            async (cdinfo) => {
               expect(cdinfo.alg).toBe(alg);
               expect(cdinfo.ic).toBe(cc.ICOUNT_MIN);
               return [pwd, hint];
            }
         );
         const block0 = await latest.encryptBlock0();

         // set byte in encrypted data
         block0.parts[2][12] = block0.parts[2][12] == 123 ? 124 : 123;
         let [cipherStream] = streamFromCipherBlock([block0]);
         let decipher = await streamDecipher(userCred, cipherStream, async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, undefined];
         });

         // Monkey patch to skip MAC validation
         //@ts-ignore
         decipher['_verifyMAC'] = (): Promise<boolean> => {
            return Promise.resolve(true);
         };

         // This should fail (even though MAC check is skipped) because
         // encrypted data was modified. Note that this should
         // fail with DOMException rather than Error with MAC in message
         await expect(decipher.decryptBlock0()).rejects.toThrow(DOMException);
      }
   });
});

describe("Detect block order changes", function () {
   beforeEach(async () => {
      await cryptoReady();
   });

   const pwd = 'a not good pwd';
   const hint = 'sorta';
   const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));
   const clearStr = 'This is a secret 🦀 with extra wording for more blocks';

   async function get_blocks(alg: cc.CipherAlgs): Promise<[
      CipherDataBlock,
      CipherDataBlock,
      CipherDataBlock
   ]> {
      const [clearStream] = streamFromStr(clearStr);

      const latest = latestEncipher(
         userCred,
         alg,
         cc.ICOUNT_MIN,
         1, // lp
         1, // lpEnd
         clearStream,
         async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, hint];
         }
      );
      const readStart = 11;
      //@ts-ignore force multiple blocks
      latest['_readTarget'] = readStart;

      const block0 = await latest.encryptBlock0();
      const block1 = await latest.encryptBlockN();
      const block2 = await latest.encryptBlockN();

      return [block0, block1, block2];
   }

   it("block order good, all algorithms", async function () {

      const clearData = new TextEncoder().encode(clearStr);

      for (const alg of Ciphers.algs()) {

         const [block0, block1, block2] = await get_blocks(alg);

         // First make sure we can decrypt in the proper order
         let [cipherStream] = streamFromCipherBlock([block0, block1, block2]);
         let decipher = await streamDecipher(userCred, cipherStream, async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, undefined];
         });

         const decb0 = await decipher.decryptBlock0();
         const decb1 = await decipher.decryptBlockN();
         const decb2 = await decipher.decryptBlockN();

         let [decrypted] = streamFromBytes([decb0, decb1, decb2]);

         await expect(areEqual(decrypted, clearData)).resolves.toEqual(true);
      }
   });

   it("blockN bad order detected, all algorithms", async function () {

      const clearData = new TextEncoder().encode(clearStr);

      for (const alg of Ciphers.algs()) {

         const [block0, block1, block2] = await get_blocks(alg);

         // Order of block N+ changed
         let [cipherStream] = streamFromCipherBlock([block0, block2, block1]);
         let decipher = await streamDecipher(userCred, cipherStream, async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, undefined];
         });

         const decb0 = await decipher.decryptBlock0();

         const partial = new TextDecoder().decode(decb0);
         expect(clearStr.startsWith(partial)).toBe(true);

         // In V4 this worked, but should fail in V5
         await expect(decipher.decryptBlockN()).rejects.toThrow(/Invalid MAC/);
      }
   });

   it("block0 bad order detected, all algorithms", async function () {

      const clearData = new TextEncoder().encode(clearStr);

      for (const alg of Ciphers.algs()) {

         const [block0, block1, block2] = await get_blocks(alg);

         let [cipherStream] = streamFromCipherBlock([block1, block0, block2]);
         let decipher = await streamDecipher(userCred, cipherStream, async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, undefined];
         });

         // Will fail in V4 and later because block0 format or MAC is invalid.
         // Failure detection can happen at different spots while data is unpacked
         // since random values may look valid. MAC will alsways be
         // invalid if we get that far.
         await expect(decipher.decryptBlock0()).rejects.toThrow(new RegExp('Invalid.+'));

      }
   });
});


// Python helper function to recreate values
/*
from base64 import urlsafe_b64decode as b64d
from base64 import urlsafe_b64encode as b64e
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

def b64ToHexStr(b64str):
   ba = b64d(b64str);
   return ' '.join(f'{b:02x}' for b in ba)

def uint8AToHexStr(ua):
   return ' '.join(f'{b:02x}' for b in ua)

def uint8AToB64Str(ua):
   ba = bytes(ua)
   return b64e(ba)
   */
