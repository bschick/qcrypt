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
   getStreamDecipher, getLatestEncipher,
   EncipherV7,
   Ciphers,
   concatArrays,
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
   const parts = cdBlocks.flatMap(block => block.parts);
   return streamFromBytes(concatArrays(parts));
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
      return concatArrays([headerData, block.parts[1], block.parts[2]]);
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

         const makeKP = (userCred: Uint8Array<ArrayBuffer>, encrypting: boolean): PWDKeyProvider => {
            const kp = new PWDKeyProvider(userCred.slice(0), [pwd, undefined]);
            encrypting && kp.setCipherDataInfo({
               ver: cc.CURRENT_VERSION,
               alg,
               ic: cc.ICOUNT_MIN,
               slt,
               lp: 1,
               lpEnd: 1
            });
            return kp;
         };

         const reader = new BYOBStreamReader(clearStream);
         const encipher = new EncipherV7(makeKP(userCredA, true), reader);
         const cipherBlock = await encipher.encryptBlock0();

         // Sign and repack with both the original (correct) values to help ensure the
         // code for repacking is valid and then with a new signature to be sure
         // the replacment is detected. Each signAndRepack uses a fresh keyProvider
         // because the encipher purges its keyProvider after encryptBlock0.
         let [cipherstreamA, cipherDataA] = streamFromBytes(await signAndRepack(encipher, cipherBlock, makeKP(userCredA, true)));
         let [cipherstreamB, cipherDataB] = streamFromBytes(await signAndRepack(encipher, cipherBlock, makeKP(userCredB, true)));

         // These should fail because using the wrong keyProvider/userCred for each.
         // A fresh keyProvider is needed per decipher call since errorState purges it.
         let decipherA = await getStreamDecipher(cipherstreamA, makeKP(userCredB, false));
         let decipherB = await getStreamDecipher(cipherstreamB, makeKP(userCredA, false));

         await expect(decipherA._decodeBlock0()).rejects.toThrow(/MAC/);
         await expect(decipherB._decodeBlock0()).rejects.toThrow(/MAC/);

         // Reaload streams, then test with correct matching keyProvider/userCred
         [cipherstreamA] = streamFromBytes(cipherDataA);
         [cipherstreamB] = streamFromBytes(cipherDataB);
         decipherA = await getStreamDecipher(cipherstreamA, makeKP(userCredA, false));
         decipherB = await getStreamDecipher(cipherstreamB, makeKP(userCredB, false));

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

         const encKeyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
            expect(cdinfo.alg).toEqual(alg);
            expect(cdinfo.slt.byteLength).toEqual(cc.SLT_BYTES);
            expect(cdinfo.ic).toBe(cc.ICOUNT_MIN);
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
            return [pwd, hint];
         });
         const latest = getLatestEncipher(clearStream, encKeyProvider, alg, 1, 1, cc.ICOUNT_MIN);
         const block0 = await latest.encryptBlock0();

         const [cipherStream] = streamFromCipherBlock([block0]);
         const decKeyProvider = new PWDKeyProvider(userCred, async (cdinfo) => {
            expect(cdinfo.alg).toEqual(alg);
            expect(cdinfo.slt.byteLength).toEqual(cc.SLT_BYTES);
            expect(cdinfo.ic).toBe(cc.ICOUNT_MIN);
            expect(cdinfo.hint).toEqual(hint);
            expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
            return [pwd, undefined];
         });
         const decipher = await getStreamDecipher(cipherStream, decKeyProvider);

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

         const encKeyProvider = new PWDKeyProvider(userCred.slice(0), [pwd, hint]);
         const latest = getLatestEncipher(clearStream, encKeyProvider, alg, 1, 1, cc.ICOUNT_MIN);
         const block0 = await latest.encryptBlock0();

         // Happy path: kick off both without awaiting first.
         const [cipherStream] = streamFromCipherBlock([block0]);
         const decKeyProvider = new PWDKeyProvider(userCred.slice(0), [pwd, undefined]);
         const decipher = await getStreamDecipher(cipherStream, decKeyProvider);

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
         const wrongKeyProvider = new PWDKeyProvider(wrongUserCred, [pwd, undefined]);
         const badDecipher = await getStreamDecipher(tamperedStream, wrongKeyProvider);

         const badCdInfoPromise = badDecipher.getCipherDataInfo();
         const badDecryptPromise = badDecipher.decryptBlock0();
         await expect(badCdInfoPromise).rejects.toThrow(/MAC/);
         await expect(badDecryptPromise).rejects.toThrow(/MAC/);
      }
   });

   it("getCipherDataInfo is safe to call concurrently after first decode", async function () {

      for (const alg of Ciphers.algs()) {

         const [clearStream] = streamFromStr('This is a secret 🦆');
         const pwd = 'a good pwd';
         const hint = 'not really';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

         const encKeyProvider = new PWDKeyProvider(userCred.slice(0), [pwd, hint]);
         const encipher = getLatestEncipher(clearStream, encKeyProvider, alg, 1, 1, cc.ICOUNT_MIN);
         const block0 = await encipher.encryptBlock0();

         const [cipherStream] = streamFromCipherBlock([block0]);
         const decKeyProvider = new PWDKeyProvider(userCred.slice(0), [pwd, undefined]);
         const decipher = await getStreamDecipher(cipherStream, decKeyProvider);

         await decipher._decodeBlock0();

         // After the first decode finishes, repeated reads must keep returning
         // the same info without needed to re-read the cipher stream
         const [firstCdInfo, secondCdInfo] = await Promise.all([
            decipher.getCipherDataInfo(),
            decipher.getCipherDataInfo(),
         ]);
         expect(firstCdInfo.alg).toEqual(alg);
         expect(secondCdInfo).toEqual(firstCdInfo);
      }
   });


   it("round trip blockN, all algorithms", async function () {

      for (const alg of Ciphers.algs()) {

         let [clearStream, clearData] = streamFromStr('This is a secret 🦀');
         const pwd = 'a not good pwd';
         const hint = 'sorta';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

         const readStart = 12;
         let encKeyProvider = new PWDKeyProvider(userCred.slice(0), [pwd, hint]);
         let latest = getLatestEncipher(clearStream, encKeyProvider, alg, 1, 1, cc.ICOUNT_MIN, { startSize: readStart });

         await expect(latest.encryptBlockN()).rejects.toThrow(/Encipher invalid state/);

         // once invalidated, it stays that way...
         await expect(latest.encryptBlock0()).rejects.toThrow(new RegExp('Encipher invalid state.+'));

         [clearStream, clearData] = streamFromStr('This is a secret 🦀');
         encKeyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, hint];
         });
         latest = getLatestEncipher(clearStream, encKeyProvider, alg, 1, 1, cc.ICOUNT_MIN, { startSize: readStart });

         const block0 = await latest.encryptBlock0();
         const blockN = await latest.encryptBlockN();

         const makeDecKP = () => new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, undefined];
         });

         let [cipherStream] = streamFromCipherBlock([block0, blockN]);
         let decipher = await getStreamDecipher(cipherStream, makeDecKP());

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
         decipher = await getStreamDecipher(cipherStream, makeDecKP());

         decb0 = await decipher.decryptBlock0();
         await expect(areEqual(decb0, clearData.slice(0, readStart))).resolves.toEqual(true);
         await expect(decipher.decryptBlockN()).rejects.toThrow(/Cipher data length mismatch2/);
      }
   });
});

describe("Decryption known values", function () {

   const userCredBytes = [58, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98, 180, 61, 166, 219, 54, 164, 55];
   let userCred: Uint8Array<ArrayBuffer>;

   beforeEach(async () => {
      await cryptoReady();
      userCred = new Uint8Array(userCredBytes);
   });

   it("correct cipherdata info and decryption, v4", async function () {
      const [_, clearData] = streamFromStr('A nice 🦫 came to say hello');
      const pwd = 'a 🌲 of course';
      const hint = '🌧️';
      const [cipherStream] = streamFromBytes(new Uint8Array([117, 163, 250, 117, 59, 97, 3, 10, 139, 12, 55, 161, 115, 52, 28, 105, 246, 126, 220, 0, 129, 151, 165, 136, 46, 97, 163, 160, 91, 9, 189, 218, 4, 0, 116, 0, 0, 0, 2, 0, 16, 242, 98, 46, 102, 223, 79, 227, 209, 73, 22, 207, 92, 80, 75, 125, 125, 234, 18, 21, 88, 64, 43, 68, 25, 193, 133, 31, 159, 156, 8, 184, 10, 164, 33, 46, 20, 159, 218, 222, 64, 119, 27, 0, 0, 23, 5, 135, 172, 203, 4, 101, 163, 155, 133, 221, 40, 227, 91, 222, 227, 213, 97, 77, 24, 117, 60, 188, 27, 153, 253, 134, 10, 112, 75, 76, 146, 132, 123, 217, 7, 171, 211, 24, 206, 186, 248, 244, 119, 18, 165, 195, 59, 160, 76, 31, 90, 80, 53, 19, 39, 143, 99, 141, 109, 68, 72, 63, 121, 199, 96, 95, 157, 81]));

      const keyProvider = new PWDKeyProvider(userCred, async (cdinfo) => {
         expect(cdinfo.hint).toEqual(hint);
         expect(cdinfo.lp).toEqual(1);
         expect(cdinfo.lpEnd).toEqual(1);
         expect(cdinfo.alg).toBe('X20-PLY');
         expect(cdinfo.ic).toBe(1800000);
         expect(cdinfo.ver).toEqual(cc.VERSION4);
         expect(isEqualArray(cdinfo.slt, new Uint8Array([25, 193, 133, 31, 159, 156, 8, 184, 10, 164, 33, 46, 20, 159, 218, 222]))).toBe(true);
         return [pwd, undefined];
      });
      const decipher = await getStreamDecipher(cipherStream, keyProvider);
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

      const keyProvider = new PWDKeyProvider(userCred, async (cdinfo) => {
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
      const decipher = await getStreamDecipher(cipherStream, keyProvider);
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

      const vers = [
         //v6
         {  ver: 6,
            cts: {
               'AES-GCM': 'F4qYlclmVWQD5IayN_Ub_3pQ7N91gNZzLGi8Iu_sIbkGAGAAAAABAMrZN-Xbi9Kvdpcl2k5pFxC_07E33BkQ-QlqxchAdxsAABfm9OTNhim0krfh9ZLGyi7yDGB-oB4gScok1BFuD5UcpZEj44VRQWVD8kCX-fD_t4VRbXXcgYiz1TOGFz5nsobA3jkhROi53GPsJiSiW18yy3A73-eETAgZjQfeBgAoAAABAQD1T3bCnKPA38DHIMBWWXsv7H2fFBJ9DjIPimYghk6CJdS5IXME',
               'X20-PLY': 'PkeGHkLso1abo-aBE93x_e69rJb6OrW-STBAAwDxbRQGAGwAAAACANIwjwvIQLygUdSpdbfKw83iAo126tZL0VgOnatOaYIfOXGuBj5hEGhAdxsAABfIUjubZ9H30GHKKissSmSWyblIHejAG_IPbxEjFyiOrgndOJuISt5vqJhmTJlRWoc_1683Ku3T0MkHtw24Je54qsYzl4TKzwqvSvMhL56c2g2hIVF6TuB4Cr97BgA0AAABAgAT-DRYec2-zEvMw50PxYgwmdvcJoHH01QMlf_4rV01LzigH2KFr9VaKQASTWU7310c',
               'AEGIS-256': 'XRa5nS7wJ8DLF6HWZyP2MWfeAS4PyHUYzkd67AaMUfYGAJQAAAADAJey272VOwM55vXW_P2rEudCgPSRwGB5nAjF7gmnc5AA46rTvby4Wv_R6l6eH0UNQUB3GwAAJ_K3cZg5LpRqUy83VmoXe1KwPHh3wkGbEes_qRTu7vrNvz_saJVP0ajB6xDxZYs5RhHb9yl2GWxtkLpqkhN6N2pxtAKF2a_LjknVWeIRN_jxn-LqzwkuI-Lz4Pm0OeGEwl7bfOvP8qftV8UztFNlwmGxOA_nIu_KmWG6CwYATAAAAQMA_n0RaJelAb_JLnaUUtlQrgBaG7_wcwL4lplkWi3V_Uo3V9pkIHvDj6Jvgy58blIx5yGQHa96GTx_0U3_0w38vAaiupLQGf4Ibw',
            }
         },
         //v7 — generated by: pnpm vectors:ciphers
         {  ver: 7,
            cts: {
               'AES-GCM': 'QI9tSYHZBMLcVOtkCebgv99cI5xIukDZHIdhtZgiyNMHAGAAAAABANUrjAgeq9s842izFMDZ4ap07SqhUfqiRnTetVZAdxsAABdmM5hNf1AVwZFQYHpYwQCTKkQO3yU4VGiL81pGCtL5iuUIt90D9Mz9Em_tes2sd4P8BqP1MDbknWADX8uywaweOxudJkbRr0lwiwjfA1ol5KRc_SVn2MS6W2sPBwAoAAABAQA-d2q1Kg5a2v9qOS4KleoOjWepviDWD3fpNiX1UYrl9hIbeb6n',
               'X20-PLY': 'dcUCsZKjBS5_DjFhzYJJEVoYIqT2rrGQCmvcWvdQKXsHAGwAAAACAKbm1DdR9t4r3VtbK9jES7Msl_ER8iEYTPsIfugU0DTGa2pjlJ5dxzBAdxsAABcFehrXDPcAPu0fTUo3qrw6GQd01woo0nk__v_xmajhDZd0M6AZf0epFCuutkikzSzyUpj3ydcMaxwv3tcbCQ-qEdSJMF8IplNOIzzukxU2wNxuJuIsv2atiRv6BwA0AAABAgDuUwXaIMsX6afoalQdi3Roh1h2YXeIDzGQ9yp-pxlZn3hlnkaIsDNWUg-Sc4jfQriD',
               'AEGIS-256': 'V_69lDNanPv_RLgSMAOmOJqPlUAprBgUayTScleDa84HAJQAAAADAFt5Zy6A_SjkMIo9mZUqIWNL382vdK3AKnuyoqkJySAOric2ywhh_QDRQkPqtuaHykB3GwAAJymZMFNnDz8ipaaXLdYpNZjzNNtsA7jvxhzE_xMr-NWe42wQ6i1YAc_u8PQ2lg5DixiiDeIMegKWYZyJxtXquOzkvTncR9K4IosEaalF59qNTZmJ1mnNe4BvCybtI4Xw856cjN7ecfEOLiomsLksqW-LxJOmGT89b4zcwQcATAAAAQMAvdMCxfOqOTrY83pUuAKqrAWf4jxBpXl1qSADjMKJNt_fDes4MHzJdQGZ1ZjbhrlNinzxXLDqUMBxAc8zBsol1kF0JUVr4y0TbQ',
            },
         }
      ];

      const userCred = new Uint8Array([58, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98, 180, 61, 166, 219, 54, 164, 55]);
      for (const { ver, cts } of vers) {
         for (const [alg, cipherTxt] of Object.entries(cts)) {
            const [cipherStream] = streamFromBase64Url(cipherTxt);

            const keyProvider = new PWDKeyProvider(userCred, async (cdinfo) => {
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
            const decipher = await getStreamDecipher(cipherStream, keyProvider);
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

      const keyProvider = new PWDKeyProvider(userCred, async (cdinfo) => {
         expect(cdinfo.hint).toEqual(hint);
         expect(cdinfo.lp).toEqual(1);
         expect(cdinfo.lpEnd).toEqual(1);
         expect(cdinfo.alg).toBe('X20-PLY');
         expect(cdinfo.ic).toBe(1800000);
         expect(cdinfo.ver).toEqual(cc.VERSION5);
         expect(isEqualArray(cdinfo.slt, new Uint8Array([162, 203, 172, 111, 119, 158, 192, 123, 81, 141, 89, 174, 126, 4, 65, 105]))).toBe(true);
         return [pwd, undefined];
      });
      const decipher = await getStreamDecipher(cipherStream, keyProvider);
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

      const vers = [
         //v6
         {  ver: 6,
            cts: {
               'AES-GCM': 'KIjAs5WAVq58nEVKZrLwqxgxMuZEtvfOzncNnPLZFMcGAGAAAAABADO2r-khoqGTJepwHcoQaJ_q7wIJVkeMwp4VJVNAdxsAABcUS4eu-pzXZVWsPBJTZFwQd8xCGb6JRPEAaHyNCtmH0s5zVBpgO0gqfD8TPHXqW-FQ0pHbAzmElgnjDdRYMM_TLrsuHVRsLtf-ddyjjeXv6LeeeX1ExbtaDaE9BgAoAAAAAQBdvvgBoMusZZO0E3CRS2zBfPNvOwLY-2hDMwgOQGpzWDRFQGGb',
               'X20-PLY': 'rPEwFYLr_WH3sIydgcLU29KNbXWSLtGKHCtFc5NdlKMGAGwAAAACAGKwcuUJZj8OVEdc4SyAMGHmDvaPBFvYq7j44fhHwsjA5GCauj6rMn1AdxsAABd_YgNSnyvPvbuXChCV7yAXv9E--ZrhXyOANRq8mr1R1BbmaEhY4oNzuaLqxfr2gFTvtjLBgZxOfhev1kA6HVx9SHdB6VnaOHyFX3v7zSQPnyo-TBRHCMOOaDtxBgA0AAAAAgDujN-I-TOuUWw7VFOdcx0NMpK6vc8rOqzmWFA_sfZRMpFrn8oN92L8utlAdTjjuFfT',
               'AEGIS-256': 'O8Y_5AfBakBc9UXPWLcgTtAsxopVkVmrzhEVlsgnhpAGAJQAAAADANAGQIgVn8JS4_-OekbG5INtC9sO-XnbCWVr9qSyAU5wteE2cI38YN6Je9KfMO8i_UB3GwAAJ5AtkgTlpq4a2LhCcWhE8X46S_FVF7wcvaTJ9rg4oz5xizPExQortEWXsMWCQFsVxjRqvcg2Co50wk3nPFdtdT7pFUuU-xA2k-GWcM7J49nvyhmS1o7TVrpvds4GTh4IYCTcu80eYh4Kq0KSSX2ipreuoVom5kBvA_F7RQYATAAAAAMASOhuM8YNbVyhW4SedzlAKRLXww9Is1ocJJOR3eQSVqZcspLI0RjCxG7lJ0rveEVf4pO0TvOKx9BLnoq3Xy65PrVzvmHSfm1lsA',
            }
         },
         //v7 — generated by: pnpm vectors:ciphers
         {  ver: 7,
            cts: {
               'AES-GCM': 'NTmNSxaqnPekDoPRJwNFe0QGTDN6uRDtnJxBtG3nu-oHAGAAAAABAKsclFmOck7H76jxVzq8gosi38_DgPb83hQjop1AdxsAABcTvGW7sEFiQaVqihhup64SaqBGek6HYAr8WJOrc-235NyhmBf2yJI8Em0LW0iV60pxUrrB77zsiyDWOyA438c0JfygX9mK1mtwK6RdPH3T1AjywtJDVzUqqUXOBwAoAAAAAQDMqzY-yTEuh-xGW4SmRCs0lM-fdlLx_tRjIHAdC46JdVQAHdYe',
               'X20-PLY': 'UGUaYdaLrFzez0ogh5pxmk8nyejLz_U-zgRNiUjUbTwHAGwAAAACAJuJOa4tyqNUcNz1NVAeVcy_f5mf15HM2HwXcMv5VoSkZZfotdJlKURAdxsAABcCfyBFnL0jyYPeTuXwELlEuvCuTNtpIKRHQ6XmjWJ-zaksD5QsEttobXYuoElccKaWBS-93wiJBIjXj9U6oUNwqqKIXXLQMA0HT1S6LPXWiOcUCg8_MsFfqshABwA0AAAAAgCBzy7FaeXPe7qrtZtuE64AtJqsNMeoMmbZQTD5n4Tp0zrRWI16lkmYPV5NBIGsVKcR',
               'AEGIS-256': 'jJFZJGtaYvN0D4xP0XO1Kfup_HRhSB8c4Z7VSVVZUtYHAJQAAAADAL9tc2PAu1A0VuatkDXM6StTxtGYNcPUnmh8gwXe_S5huzf8iZMz4XPBT9D89Qd3xEB3GwAAJyUV-ONQJDk29qVTdwnjK8fXex6iq1J8T8xkmfh8AzkMywnc58py3BPbexDG2h3QT5AHL7We5aP-y77aXhunKDk3P_o5g8fgqcCPSMzGPiUzle3WNrbsh7N35ObpVjrFXsZmOHF9HIGPqb3fzcfRCP42cz7GdtAiLnbbowcATAAAAAMAJJqMtBPHh9yo97IPkCIiaQbckH_8Mz0JR4J4SQjbV7ElH40E_OMG02j4q2UqNKILLUPlvaVXm99o1tOu27_bjQnoyhj7nmcr6w',
            },
         }
      ];

      for (const { ver, cts } of vers) {
         for (const [alg, cipherTxt] of Object.entries(cts)) {
            const [cipherStream] = streamFromBase64Url(cipherTxt);

            const keyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
               expect(cdinfo.hint).toEqual(hint);
               expect(cdinfo.lp).toEqual(1);
               expect(cdinfo.lpEnd).toEqual(1);
               expect(cdinfo.alg).toBe(alg);
               expect(cdinfo.ic).toBe(1800000);
               expect(cdinfo.ver).toEqual(ver);
               expect(cdinfo.slt.byteLength).toEqual(cc.SLT_BYTES);
               return [pwd, undefined];
            });
            const decipher = await getStreamDecipher(cipherStream, keyProvider);
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

      const vers = [
         //v6
         {  ver: 6,
            cts: {
               'AES-GCM': 'mxQYSs5jS2yLP9UoVPL5Umg7_aVQ0Kohu9sM6u0AWjUGAGAAAAEBADUjCDDpJymFQGrtlpcLXrv-FayLZ8GrNTn1MtRAdxsAABe8NtaKQ2wbkt7ZdPI2NkArzYT-r1fUJujQQVU3scbYxSZBhqfp8rljM-WWfdSx20UeVViyBdonxlrdCz99LJDBxGnluk0tTGs3pU8paRrXUs7jui8pUHP7QvW8BgAoAAABAQAzT5VH4MLNFnuxVW7a-ZjEvcRzQBPRd3-cfCFf8R4v7dR95Hx5',
               'X20-PLY': '4oGG7bf2iwqs1Ljsc85yIYK9Tekk4AO1rupAqeobkfQGAGwAAAECACU7WFzBfSFXioJOUtFt9cwt2nmYyx_vbvduORUE-6KnHykmq0kotERAdxsAABfCS4X16NT1XKJs1_2LwbhN0qMedP46qVvJ8Bwy2Nx_15r-_Dai_Xtr4ozjU232a4hUv1_PIKVTEu8VU4F2DUNSz8SlVg5yLI8MSQxKcJGAt84v854geBjlAJvWBgA0AAABAgA7ZDI86mqgxANzrbFkdrqovb6cC9W07QSzcRXHUqokonBGpHMPInYj0K4vlp2s11p4',
               'AEGIS-256': 'BCBMTk_hVOi0MGzUZCkxWbC7ABcKigcsyhDLC3vz9QwGAJQAAAEDAGvAtgrTFpTgoiUU65LY8CHoD43gXSr64jim1HL7_fosH_NnlBh7CS6KSvVNoRYCekB3GwAAJ7jfBXuOoOdXFFvfJxF1rUP2pctiszIRA5dA4VtlKBATAeM3WlArwwxE0bg09nDxEBxGJTU1cunJtv-PTDBf65ELq6EtzUV89Nf2I-p1O2unHboiALilVfc0tJVUnh8YLUK0V72BCi3shY17jGgObiTMBBYtlh8KTLmCQAYATAAAAQMAekEOxoUB-qEhhqOPS1flXIygThAgFLJGWecj9hHGfMcwh-D8Rcmy6o7LU_VdFNULC-TORjXevyeClQAfSPnSH0578riwrIqoQA',
            }
         },
         //v7 — generated by: pnpm vectors:ciphers
         {  ver: 7,
            cts: {
               'AES-GCM': 'VTCtjbUfA-4Y_37Cj8n6BOJ48DXXoTol-Unv4f_2Kc8HAGAAAAEBAOgh6nz0W6FBABfw60gLq3fs7a_jLUK-8-sq7DZAdxsAABfUmJXyHuemAga9Ta00L8Bwb5_z8remjg7Qctc5ls3JdpTMxPolNRQjHTnVy9fQYQdy3MGOX36Vi6aLkykd-RtW5ABQG01DQ9MIsH0YO6cTTQe63DOOF5NOnfrEBwAoAAABAQDrCoVLRl4DfRZn2Wi5Nl4DzSGp6hrqIOYhTtWC-179Aaiol1-W',
               'X20-PLY': 'mCjRjkoq7DsYjM6yoxprfHliqtEiGfcJXCvH_xMw1PQHAGwAAAECAFDW82ljhW5yRUJwXsV_zHit9xa9xWY33M3uYvoqjedFex6iesZOd0FAdxsAABchUlNqAETTZhE3aXp_EDWB9rGyOcKX8Cftu8KUY74fsNhiOj8uGJmeyQwVo-65gaUIZjDBeIgtINsH2LJA_00uRHdbB24KS6JrALPtTjoJbeNAMB-4D_CbTQUVBwA0AAABAgDyapJ4lVBz72TgUWb8iGwUIN4FnRakjIbhsgA0ZdI3jxNr7BnOHySU7qIq0lkl_LeO',
               'AEGIS-256': 'Z6pIEKsxJG-pvql5TD-7Wr7XPhuq8KLQS-jt6-SmR0IHAJQAAAEDAAx2-rTb8qJDFBRa7hzFBzE8IrhPKIs2WrsIpwOhCLadx9V0XzPvSBret917o2-apEB3GwAAJ9qI0xdH3KzwATPtNjXOAxlKMyPdLIz5hAfx1P-5x47kzgHBx2Y8b6adw3KF2_yaJlV-7M-aGQw_I397f7UnIMWidSx7tJvI0FutCa3mHSyFZbkr0kd3YC6A5i9lao9QVfjAf0uv4dXrudmBVxIgjE2_lj-r_kKZt5AOnAcATAAAAQMAaBZetnv6Du9VT2-z_ag-R4Ap4bDElXs-ezLFP_bv1XtmM8MZ8EotR64HLVbdwp4jbseWNNU62rsJehGOVJFXgulGBbo8O33AaQ',
            },
         }
      ];

      for (const { ver, cts } of vers) {
         for (const [alg, cipherTxt] of Object.entries(cts)) {
            const [cipherStream] = streamFromBase64Url(cipherTxt);

            const keyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
               expect(cdinfo.hint).toEqual(hint);
               expect(cdinfo.lp).toEqual(1);
               expect(cdinfo.lpEnd).toEqual(1);
               expect(cdinfo.alg).toBe(alg);
               expect(cdinfo.ic).toBe(1800000);
               expect(cdinfo.ver).toEqual(ver);
               expect(cdinfo.slt.byteLength).toEqual(cc.SLT_BYTES);
               return [pwd, undefined];
            });
            const decipher = await getStreamDecipher(cipherStream, keyProvider);
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

      const vers = [
         //v6
         {  ver: 6,
            cts: {
               'AES-GCM': 'zL-JSCGd1aRZUnPt9TYI8TxqyK2GOqXc1PPfgZ_moFcGAGAAAAEBAPnRpCPk1D7tTfVKhZxcBk83-vdpkFimVg_prmRAdxsAABeoHcob5QcQ7PGB4ZDscl-M2H1bCwnDvnciwPUCtwS_CJuOi-GXSHohqkthBR7Ep8FBnPVv4IfiXZ47LyDMTUBHrfnu7h1uXFBc6HhmjKVqPDzZxvDgSQiGtbZiBgAoAAAAAQCYbD7O11e8YfHzbrAic5RRZRI4G8zn6ZAqn2a-nbjkihLHoM8c',
               'X20-PLY': 'bP3w_P0Y9OoqnmwmWQRa9_pCnQyJgq7FWvSNyQQJXXYGAGwAAAECAPdKsJxFPHOxKLdM5ly8HUikZOiXDIKmfJUKqA6ZQzuQLcyks8wHVU9AdxsAABcHrl_B4pkZTPTqgTLTyMN-GiFJGLBgLidfafyJ9OI3zM-CM7Bt4VqxqZzx2HlPB96z0XJKIWYA0_E0UjxBGNmAT3Dlm_cecMIcDTjphcy_Yb0QfCT3-wIoOml3BgA0AAAAAgDL0Bcr0EpFvqc9nVANaFwv6LOPykWvtq_QFhg4-dj-GXp3w4kYQsEklQc2OOHEAF7Q',
               'AEGIS-256': 'z_wjYRYc3RAXYpAaXvU2V3BCWYno0y6Kh0pVcUjZl3kGAJQAAAEDAGcCoTiOwDrN12pPfW5eUpz5g45AFyspWIwlZMXN1ioRp4_dUdl3IhjK_Wqlb3CePkB3GwAAJ7o9Tijp5eLpL6N_0V-ruVh61s6GmtRq8j5FE3LS6D5K-Y9uH9BZ1GI8UMkGNsAfnfMArB8cj4R7lRVo1HjqOX4j15b3FEU3ROwMWmNl7Zp77CN4023BH7JzlPzen7M_DyMsa7qiBrVF8GV-6f577Sv6xpFsUVweZRED_wYATAAAAAMAQ7fPqOQtec-v1wNMzhL5V5s8XNQ194ef7xLIn4oNjZF6FWKLsvQ65lt0psTKmu-f2e3qcU93LwWx7qs3JZDI1KFhB-kvb0vQQQ',
            }
         },
         //v7 — generated by: pnpm vectors:ciphers
         {  ver: 7,
            cts: {
               'AES-GCM': 'ICMTbZv-mEZS1-pmXzPgLb2ds9rdjZXYGservrKAOVAHAGAAAAEBADKaM2ItChwxcp2fNARPzM6DEoclz5SzEjZm7JhAdxsAABemOv8L4_auczq3tFEurVIH1B_glDDHl37ZhhLyL0RbUhQ3Wk7b7nKjNkIToU-Xz3Cf8hpI83HRflkK2-GpVkku5wgP9Qw0abHiHWYIP2W8bdjIq6sbbHqrMf61BwAoAAAAAQCTtsH_Cb26AsKpGCoMV4q5JQeCzZFqaV8rinh-IvzcyR-GDavH',
               'X20-PLY': 'IJvaSenlyiln9rxdoAD8bry76Ao2b8CHaBsDBOlBRn0HAGwAAAECANKL91b9x5ZWSm_gvz4-le2Qq6epuZEPAWxh0W_EFusp-NauYbgkbfJAdxsAABdkjkDYn45FN82MgQyzTkZMq4ELXyGHYyBw4CRikrd0drXqLw-hHMY_EIO1T6QyqjVeSlmWXywYwZvvKvOr8cV8SfKNq7d3lJdVPygL68-sgW4oGCZniVX_caxKBwA0AAAAAgBLFlNxigbcAyLjgGqZtc3YIzBv95YAhxQpSxbUXDW5TC3JWrEZgtHRAE8XFAkc5p0e',
               'AEGIS-256': 'kkFn5bpWh2H9Zdu7vc4SibT13oI2u4vu5qlyjHvz6f4HAJQAAAEDAOSDZE_adfTq_XmBCOopqJSWbmJyVy1Qc6_TJObtYKGoZqUwEGXaVxVAgJbKWeD8e0B3GwAAJ06qNQGNNwpryfr4b-sc7jd4hK6mbe075h3rGfGGsDEYOBXwg8knKAnrWcwL8Hn_FcRICagcvSkIIQhwucE6Wi7CMXNM9Qdnq055xab0Yx-W42gCD9j4Cw64RROgvC64mobHzprXSuyC7Isml1TfEE6wIY3_OwXDCsl5QgcATAAAAAMAK0TiORRe380FGuzOFzG7gCl7gxKorbnAFI_LAIl16M6umL69FKcdKmIS9hcknIcMbM0YoviDMj-nrWceiHJjJ3Gv7SPFXEtufQ',
            },
         }
      ];

      for (const { ver, cts } of vers) {
         for (const [alg, cipherTxt] of Object.entries(cts)) {
            const [cipherStream] = streamFromBase64Url(cipherTxt);

            const keyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
               expect(cdinfo.hint).toEqual(hint);
               expect(cdinfo.lp).toEqual(1);
               expect(cdinfo.lpEnd).toEqual(1);
               expect(cdinfo.alg).toBe(alg);
               expect(cdinfo.ic).toBe(1800000);
               expect(cdinfo.ver).toEqual(ver);
               expect(cdinfo.slt.byteLength).toEqual(cc.SLT_BYTES);
               return [pwd, undefined];
            });
            const decipher = await getStreamDecipher(cipherStream, keyProvider);
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
      let keyProvider = new PWDKeyProvider(userCredGood.slice(0), async (cdinfo) => {
         expect(cdinfo.alg).toBe('X20-PLY');
         expect(cdinfo.ic).toBe(1800000);
         expect(cdinfo.hint).toBeTruthy();
         expect(cdinfo.ver).toEqual(cc.VERSION4);
         return [pwdGood, undefined];
      });
      let decipher = await getStreamDecipher(cipherStream, keyProvider);

      // First make sure the good values are actually good
      await expect(decipher.decryptBlock0()).resolves.toEqual(clearData);

      // Ensure bad password fails
      [cipherStream] = streamFromBytes(cipherData);
      keyProvider = new PWDKeyProvider(userCredGood.slice(0), [pwdBad, undefined]);
      decipher = await getStreamDecipher(cipherStream, keyProvider);

      await expect(decipher.decryptBlock0()).rejects.toThrow(DOMException);

      // Test wrong userCred
      [cipherStream] = streamFromBytes(cipherData);
      keyProvider = new PWDKeyProvider(userCredBad.slice(0), undefined);
      decipher = await getStreamDecipher(cipherStream, keyProvider);

      await expect(decipher.getCipherDataInfo()).rejects.toThrow(/Invalid MAC/);

      // decipher now in invalid state from prevous getCipherDataInfo call
      await expect(decipher.decryptBlock0()).rejects.toThrow(new RegExp('Decipher invalid.+'));

      // Test wrong userCred with block decrypt first (error msg is different)
      [cipherStream] = streamFromBytes(cipherData);
      keyProvider = new PWDKeyProvider(userCredBad.slice(0), [pwdGood, undefined]);
      decipher = await getStreamDecipher(cipherStream, keyProvider);

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
      let keyProvider = new PWDKeyProvider(userCredGood, async (cdinfo) => {
         expect(cdinfo.alg).toBe('X20-PLY');
         expect(cdinfo.ic).toBe(1800000);
         expect(cdinfo.hint).toBeTruthy();
         expect(cdinfo.ver).toEqual(cc.VERSION5);
         return [pwdGood, undefined];
      });
      let decipher = await getStreamDecipher(cipherStream, keyProvider);

      // First make sure the good values are actually good
      await expect(decipher.decryptBlock0()).resolves.toEqual(clearData);

      // Ensure bad password fails
      [cipherStream] = streamFromBytes(cipherData);
      keyProvider = new PWDKeyProvider(userCredGood, [pwdBad, undefined]);
      decipher = await getStreamDecipher(cipherStream, keyProvider);

      await expect(decipher.decryptBlock0()).rejects.toThrow(DOMException);

      // Test wrong userCred
      [cipherStream] = streamFromBytes(cipherData);
      keyProvider = new PWDKeyProvider(userCredBad, undefined);
      decipher = await getStreamDecipher(cipherStream, keyProvider);

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

      const vers = [
         //v6
         {  ver: 6,
            cts: {
               'AES-GCM': 'F4qYlclmVWQD5IayN_Ub_3pQ7N91gNZzLGi8Iu_sIbkGAGAAAAABAMrZN-Xbi9Kvdpcl2k5pFxC_07E33BkQ-QlqxchAdxsAABfm9OTNhim0krfh9ZLGyi7yDGB-oB4gScok1BFuD5UcpZEj44VRQWVD8kCX-fD_t4VRbXXcgYiz1TOGFz5nsobA3jkhROi53GPsJiSiW18yy3A73-eETAgZjQfeBgAoAAABAQD1T3bCnKPA38DHIMBWWXsv7H2fFBJ9DjIPimYghk6CJdS5IXME',
               'X20-PLY': 'PkeGHkLso1abo-aBE93x_e69rJb6OrW-STBAAwDxbRQGAGwAAAACANIwjwvIQLygUdSpdbfKw83iAo126tZL0VgOnatOaYIfOXGuBj5hEGhAdxsAABfIUjubZ9H30GHKKissSmSWyblIHejAG_IPbxEjFyiOrgndOJuISt5vqJhmTJlRWoc_1683Ku3T0MkHtw24Je54qsYzl4TKzwqvSvMhL56c2g2hIVF6TuB4Cr97BgA0AAABAgAT-DRYec2-zEvMw50PxYgwmdvcJoHH01QMlf_4rV01LzigH2KFr9VaKQASTWU7310c',
               'AEGIS-256': 'XRa5nS7wJ8DLF6HWZyP2MWfeAS4PyHUYzkd67AaMUfYGAJQAAAADAJey272VOwM55vXW_P2rEudCgPSRwGB5nAjF7gmnc5AA46rTvby4Wv_R6l6eH0UNQUB3GwAAJ_K3cZg5LpRqUy83VmoXe1KwPHh3wkGbEes_qRTu7vrNvz_saJVP0ajB6xDxZYs5RhHb9yl2GWxtkLpqkhN6N2pxtAKF2a_LjknVWeIRN_jxn-LqzwkuI-Lz4Pm0OeGEwl7bfOvP8qftV8UztFNlwmGxOA_nIu_KmWG6CwYATAAAAQMA_n0RaJelAb_JLnaUUtlQrgBaG7_wcwL4lplkWi3V_Uo3V9pkIHvDj6Jvgy58blIx5yGQHa96GTx_0U3_0w38vAaiupLQGf4Ibw',
            }
         },
         //v7 — generated by: pnpm vectors:ciphers
         {  ver: 7,
            cts: {
               'AES-GCM': '4HqaA_x0NfL-Lf5Na8y6hL-riHK3KyJdFE2SEhwx5LYHAGAAAAABAPysHkdL0M4zcysF2og_ge5wsMwKT_xAuMXGrBxAdxsAABe6Z3m9EvN6Y_sxYrElDyN-6PvyIoShWg6tPvimnho4H99MxYZgbLIcrBX8zC9dpUgBGWKratN9-Fa50tZKXDJ3qO3ABIiOAVA0xPFD1XdQtlLo415xQhTRlFZEBwAoAAABAQC75YGxqP9hDNbA8i6guGLiU3HCFjeaphHkd96Ua7IV2XHfqfU8',
               'X20-PLY': 'STL1yvGUQsZ6fch9ZF1EeDhm6Hy4mVXnsCxb92-KlG4HAGwAAAACACRL5HqJgFlW-9pzMeoLPwTkV9zlhPQmhGcdeNSg1IosOyT5vie1waBAdxsAABeQyA19trqyQq1TPajNoT2ANyfeHy-RHf22aKmmad_iKz4na77KerqvuOs-2HG02pTAwFgAiFq28NXb1p0ls98l73bdWRE8XUGCRsiO5Sw8SSt0HsOdpMZ2NRhkBwA0AAABAgAmYrJ3dIibkQvtcLGNMAnJf_kaNeLoO2SqXHNhZVb5Z-S2Osa7ELbim_QuupRqq6Dk',
               'AEGIS-256': 'bGHlPFIsJywbOgUndKGIIsifY3BQA19u46baaSScykEHAJQAAAADAGTaDfFs-4ZU0QWQd6XUJmkqnpsHNecSyO41OmJIjmVklHUwfvTKK_42cnKuVJeOE0B3GwAAJ0p2jphORQO78U7BwslRPiw9hAalYreWxAxesoTZZjr3GGqI_vPRdJfTaS5xemfNiJqmtBgZglc9CViYpnbQQvxA5emMmJ7rOX3RsUhpA-DVe2A6YeMv8hFGrih3sG_z65nG6dAgmD9X0EZqZ07lw_fua9fgy5gm4acDAgcATAAAAQMAkmSgZwBhr94ilIxrYT25tMzbh8v8O6YK1xf4g3dmoArIyqgravttSr_r8FyQyojSo8qfMojQTPp2UDhdmxBrB_IIHcaNCTx-OQ',
            },
         }
      ];

      for (const { ver, cts } of vers) {
         for (const [alg, cipherTxt] of Object.entries(cts)) {
            let [cipherStream, cipherData] = streamFromBase64Url(cipherTxt);
            // First make sure the good values are actually good
            let keyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
               expect(cdinfo.alg).toBe(alg);
               expect(cdinfo.ic).toBe(1800000);
               expect(cdinfo.hint).toBeTruthy();
               expect(cdinfo.ver).toEqual(ver);
               return [pwdGood, undefined];
            });
            let decipher = await getStreamDecipher(cipherStream, keyProvider);
            await expect(decipher.decryptBlock0()).resolves.toEqual(clearData.slice(0,20));

            // Ensure bad password fails
            [cipherStream] = streamFromBytes(cipherData);
            keyProvider = new PWDKeyProvider(userCred.slice(0), [pwdBad, undefined]);
            decipher = await getStreamDecipher(cipherStream, keyProvider);
            await expect(decipher.decryptBlock0()).rejects.toThrow(DOMException);

            // Test wrong userCred
            [cipherStream] = streamFromBytes(cipherData);
            keyProvider = new PWDKeyProvider(userCredBad.slice(0), [pwdGood, undefined]);
            decipher = await getStreamDecipher(cipherStream, keyProvider);
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

         const encKeyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
            expect(cdinfo.alg).toEqual(alg);
            expect(cdinfo.slt.byteLength).toEqual(cc.SLT_BYTES);
            expect(cdinfo.ic).toBe(cc.ICOUNT_MIN);
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
            return [pwd, hint];
         }, customAd);
         const latest = getLatestEncipher(clearStream, encKeyProvider, alg, 1, 1, cc.ICOUNT_MIN);
         const block0 = await latest.encryptBlock0();

         const [cipherStream] = streamFromCipherBlock([block0]);
         const decKeyProvider = new PWDKeyProvider(userCred, async (cdinfo) => {
            expect(cdinfo.alg).toEqual(alg);
            expect(cdinfo.slt.byteLength).toEqual(cc.SLT_BYTES);
            expect(cdinfo.ic).toBe(cc.ICOUNT_MIN);
            expect(cdinfo.hint).toEqual(hint);
            expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
            return [pwd, undefined];
         }, customAd);
         const decipher = await getStreamDecipher(cipherStream, decKeyProvider);

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

         const readStart = 12;
         const encKeyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, hint];
         }, customAd);
         const latest = getLatestEncipher(clearStream, encKeyProvider, alg, 1, 1, cc.ICOUNT_MIN, { startSize: readStart });

         const block0 = await latest.encryptBlock0();
         const blockN = await latest.encryptBlockN();

         let [cipherStream] = streamFromCipherBlock([block0, blockN]);
         const decKeyProvider = new PWDKeyProvider(userCred, async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, undefined];
         }, customAd);
         let decipher = await getStreamDecipher(cipherStream, decKeyProvider);

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

         const encKeyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
            expect(cdinfo.alg).toEqual(alg);
            expect(cdinfo.slt.byteLength).toEqual(cc.SLT_BYTES);
            expect(cdinfo.ic).toBe(cc.ICOUNT_MIN);
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
            return [pwd, hint];
         }, customAd);
         const latest = getLatestEncipher(clearStream, encKeyProvider, alg, 1, 1, cc.ICOUNT_MIN);
         const block0 = await latest.encryptBlock0();

         const [cipherStream] = streamFromCipherBlock([block0]);
         const decKeyProvider = new PWDKeyProvider(userCred, async (cdinfo) => {
            expect(cdinfo.alg).toEqual(alg);
            expect(cdinfo.slt.byteLength).toEqual(cc.SLT_BYTES);
            expect(cdinfo.ic).toBe(cc.ICOUNT_MIN);
            expect(cdinfo.hint).toEqual(hint);
            expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
            return [pwd, undefined];
         });
         const decipher = await getStreamDecipher(cipherStream, decKeyProvider);

         await expect(decipher.decryptBlock0()).rejects.toThrow(/Invalid MAC/);
      }
   });

   it("round trip block0, all algorithms added customAd", async function () {
      for (const alg of Ciphers.algs()) {
         const [clearStream, clearData] = streamFromStr('This is a secret 🦆');
         const pwd = 'a good pwd';
         const hint = 'not really';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));
         const customAd = crypto.getRandomValues(new Uint8Array(52));

         const encKeyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
            expect(cdinfo.alg).toEqual(alg);
            expect(cdinfo.slt.byteLength).toEqual(cc.SLT_BYTES);
            expect(cdinfo.ic).toBe(cc.ICOUNT_MIN);
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
            return [pwd, hint];
         });
         const latest = getLatestEncipher(clearStream, encKeyProvider, alg, 1, 1, cc.ICOUNT_MIN);
         const block0 = await latest.encryptBlock0();

         const [cipherStream] = streamFromCipherBlock([block0]);
         const decKeyProvider = new PWDKeyProvider(userCred, async (cdinfo) => {
            expect(cdinfo.alg).toEqual(alg);
            expect(cdinfo.slt.byteLength).toEqual(cc.SLT_BYTES);
            expect(cdinfo.ic).toBe(cc.ICOUNT_MIN);
            expect(cdinfo.hint).toEqual(hint);
            expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
            return [pwd, undefined];
         }, customAd);
         const decipher = await getStreamDecipher(cipherStream, decKeyProvider);

         await expect(decipher.decryptBlock0()).rejects.toThrow(/Invalid MAC/);
      }
   });

   it("round trip block0, all algorithms changed customAd", async function () {
      for (const alg of Ciphers.algs()) {
         const [clearStream, clearData] = streamFromStr('This is a secret 🦆');
         const pwd = 'a good pwd';
         const hint = 'not really';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));
         const customAd = crypto.getRandomValues(new Uint8Array(52));

         const encKeyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
            expect(cdinfo.alg).toEqual(alg);
            expect(cdinfo.slt.byteLength).toEqual(cc.SLT_BYTES);
            expect(cdinfo.ic).toBe(cc.ICOUNT_MIN);
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
            return [pwd, hint];
         }, customAd);
         const latest = getLatestEncipher(clearStream, encKeyProvider, alg, 1, 1, cc.ICOUNT_MIN);
         const block0 = await latest.encryptBlock0();

         // modify customAd so it doesn't match what was used for encryption
         customAd[2] ^= 1;
         const [cipherStream] = streamFromCipherBlock([block0]);
         const decKeyProvider = new PWDKeyProvider(userCred, async (cdinfo) => {
            expect(cdinfo.alg).toEqual(alg);
            expect(cdinfo.slt.byteLength).toEqual(cc.SLT_BYTES);
            expect(cdinfo.ic).toBe(cc.ICOUNT_MIN);
            expect(cdinfo.hint).toEqual(hint);
            expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
            return [pwd, undefined];
         }, customAd);
         const decipher = await getStreamDecipher(cipherStream, decKeyProvider);

         await expect(decipher.decryptBlock0()).rejects.toThrow(/Invalid MAC/);
      }
   });

   it("round trip blockN, all algorithms missing customAd", async function () {

      for (const alg of Ciphers.algs()) {
         let [clearStream, clearData] = streamFromStr('This is a secret 🦀');
         const pwd = 'a not good pwd';
         const hint = 'sorta';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));
         const customAd = crypto.getRandomValues(new Uint8Array(123));

         const encKeyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, hint];
         }, customAd);
         const latest = getLatestEncipher(clearStream, encKeyProvider, alg, 1, 1, cc.ICOUNT_MIN, { startSize: 12 });

         const block0 = await latest.encryptBlock0();
         const blockN = await latest.encryptBlockN();

         let [cipherStream] = streamFromCipherBlock([block0, blockN]);
         const decKeyProvider = new PWDKeyProvider(userCred, async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, undefined];
         });
         let decipher = await getStreamDecipher(cipherStream, decKeyProvider);

         await expect(decipher.decryptBlock0()).rejects.toThrow(/Invalid MAC/);
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

         const encKeyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, hint];
         });
         const latest = getLatestEncipher(clearStream, encKeyProvider, alg, 1, 1, cc.ICOUNT_MIN, { startSize: 12 });

         const block0 = await latest.encryptBlock0();
         const blockN = await latest.encryptBlockN();

         let [cipherStream] = streamFromCipherBlock([block0, blockN]);
         const decKeyProvider = new PWDKeyProvider(userCred, async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, undefined];
         }, customAd);
         let decipher = await getStreamDecipher(cipherStream, decKeyProvider);

         await expect(decipher.decryptBlock0()).rejects.toThrow(/Invalid MAC/);
         await expect(decipher.decryptBlockN()).rejects.toThrow(/Decipher invalid state/);
      }
   });

   it("round trip blockN, all algorithms tampered customAd", async function () {

      for (const alg of Ciphers.algs()) {
         let [clearStream, clearData] = streamFromStr('This is a secret 🦀');
         const pwd = 'a not good pwd';
         const hint = 'sorta';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));
         const customAd = crypto.getRandomValues(new Uint8Array(123));

         const encKeyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, hint];
         }, customAd);
         const latest = getLatestEncipher(
            clearStream, encKeyProvider, alg, 1, 1, cc.ICOUNT_MIN,
            { startSize: 12 }
         );

         const block0 = await latest.encryptBlock0();
         const blockN = await latest.encryptBlockN();

         // modify customAd so it doesn't match what was used for encryption
         customAd[customAd.length - 1] ^= 1;
         let [cipherStream] = streamFromCipherBlock([block0, blockN]);
         const decKeyProvider = new PWDKeyProvider(userCred, async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, undefined];
         }, customAd);
         let decipher = await getStreamDecipher(cipherStream, decKeyProvider);

         await expect(decipher.decryptBlock0()).rejects.toThrow(/Invalid MAC/);
         await expect(decipher.decryptBlockN()).rejects.toThrow(/Decipher invalid state/);
      }
   });
});


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

         const encKeyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            expect(cdinfo.alg).toBe(alg);
            expect(cdinfo.ic).toBe(cc.ICOUNT_MIN);
            return [pwd, hint];
         });
         const latest = getLatestEncipher(clearStream, encKeyProvider, alg, 1, 1, cc.ICOUNT_MIN);

         const block0 = await latest.encryptBlock0();

         const savedHeader = new Uint8Array(block0.parts[0]);

         const makeDecKP = () => new PWDKeyProvider(userCred.slice(0), [pwd, undefined]);

         // set byte in MAC
         block0.parts[0][12] = block0.parts[0][12] == 123 ? 124 : 123;
         let [cipherStream] = streamFromCipherBlock([block0]);
         let decipher = await getStreamDecipher(cipherStream, makeDecKP());

         await expect(decipher.decryptBlock0()).rejects.toThrow(/Invalid MAC.+/);

         block0.parts[0] = new Uint8Array(savedHeader);
         [cipherStream] = streamFromCipherBlock([block0]);
         decipher = await getStreamDecipher(cipherStream, makeDecKP());

         await expect(decipher.decryptBlock0()).resolves.toEqual(clearData);

         // set version
         block0.parts[0][33] = block0.parts[0][33] == 43 ? 45 : 43;
         [cipherStream] = streamFromCipherBlock([block0]);

         await expect(getStreamDecipher(cipherStream, new PWDKeyProvider(userCred.slice(0), undefined))).rejects.toThrow(/Invalid version/);

         // set length
         block0.parts[0] = new Uint8Array(savedHeader);
         block0.parts[0][36] = block0.parts[0][36] == 43 ? 45 : 43;
         [cipherStream] = streamFromCipherBlock([block0]);
         decipher = await getStreamDecipher(cipherStream, makeDecKP());

         await expect(decipher.decryptBlock0()).rejects.toThrow(/Cipher data length mismatch+/);
      }
   });

   it("detect changed additionalData", async function () {

      for (const alg of Ciphers.algs()) {
         const [clearStream, clearData] = streamFromStr('This is a secret 🦆');
         const pwd = 'a good pwd';
         const hint = 'not really';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

         const encKeyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
            expect(cdinfo.alg).toBe(alg);
            expect(cdinfo.ic).toBe(cc.ICOUNT_MIN);
            return [pwd, hint];
         });
         const latest = getLatestEncipher(clearStream, encKeyProvider, alg, 1, 1, cc.ICOUNT_MIN);
         const block0 = await latest.encryptBlock0();

         const savedAD = new Uint8Array(block0.parts[1]);

         const makeDecKP = () => new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, undefined];
         });

         block0.parts[1][12] = block0.parts[1][12] == 123 ? 124 : 123;
         let [cipherStream] = streamFromCipherBlock([block0]);
         let decipher = await getStreamDecipher(cipherStream, makeDecKP());

         await expect(decipher.decryptBlock0()).rejects.toThrow(new RegExp('.+MAC.+'));

         // Confirm we're back to good state
         block0.parts[1] = new Uint8Array(savedAD);
         [cipherStream] = streamFromCipherBlock([block0]);
         decipher = await getStreamDecipher(cipherStream, makeDecKP());

         await expect(decipher.decryptBlock0()).resolves.toEqual(clearData);

         // set byte near end
         const back = block0.parts[1].byteLength - 4;
         block0.parts[1][back] = block0.parts[1][back] == 43 ? 45 : 43;
         [cipherStream] = streamFromCipherBlock([block0]);
         decipher = await getStreamDecipher(cipherStream, makeDecKP());

         await expect(decipher.decryptBlock0()).rejects.toThrow(new RegExp('.+MAC.+'));
      }
   });

   it("detect changed encryptedData", async function () {

      for (const alg of Ciphers.algs()) {
         const [clearStream] = streamFromStr('This is a secret 🦆');
         const pwd = 'a good pwd';
         const hint = 'not really';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

         const encKeyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
            expect(cdinfo.alg).toBe(alg);
            expect(cdinfo.ic).toBe(cc.ICOUNT_MIN);
            return [pwd, hint];
         });
         const latest = getLatestEncipher(clearStream, encKeyProvider, alg, 1, 1, cc.ICOUNT_MIN);
         const block0 = await latest.encryptBlock0();

         block0.parts[2][12] = block0.parts[2][12] == 123 ? 124 : 123;
         let [cipherStream] = streamFromCipherBlock([block0]);
         const decKeyProvider = new PWDKeyProvider(userCred, async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, undefined];
         });
         let decipher = await getStreamDecipher(cipherStream, decKeyProvider);

         await expect(decipher.decryptBlock0()).rejects.toThrow(new RegExp('.+MAC.+'));
      }
   });

   it("does not detect changed headerData, skip MAC verify", async function () {

      for (const alg of Ciphers.algs()) {
         const [clearStream, clearData] = streamFromStr('This is a secret 🦆');
         const pwd = 'a good pwd';
         const hint = 'not really';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

         const encKeyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            expect(cdinfo.alg).toBe(alg);
            expect(cdinfo.ic).toBe(cc.ICOUNT_MIN);
            return [pwd, hint];
         });
         const latest = getLatestEncipher(clearStream, encKeyProvider, alg, 1, 1, cc.ICOUNT_MIN);
         const block0 = await latest.encryptBlock0();

         // set byte in MAC
         block0.parts[0][12] = block0.parts[0][12] == 123 ? 124 : 123;
         let [cipherStream] = streamFromCipherBlock([block0]);
         const decKeyProvider = new PWDKeyProvider(userCred, async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, undefined];
         });
         let decipher = await getStreamDecipher(cipherStream, decKeyProvider);

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

         const encKeyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
            expect(cdinfo.alg).toBe(alg);
            expect(cdinfo.ic).toBe(cc.ICOUNT_MIN);
            return [pwd, hint];
         });
         const latest = getLatestEncipher(clearStream, encKeyProvider, alg, 1, 1, cc.ICOUNT_MIN);
         const block0 = await latest.encryptBlock0();

         // set byte in additional data
         block0.parts[1][12] = block0.parts[1][12] == 123 ? 124 : 123;
         let [cipherStream] = streamFromCipherBlock([block0]);
         const decKeyProvider = new PWDKeyProvider(userCred, async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, undefined];
         });
         let decipher = await getStreamDecipher(cipherStream, decKeyProvider);

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

         const encKeyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
            expect(cdinfo.alg).toBe(alg);
            expect(cdinfo.ic).toBe(cc.ICOUNT_MIN);
            return [pwd, hint];
         });
         const latest = getLatestEncipher(clearStream, encKeyProvider, alg, 1, 1, cc.ICOUNT_MIN);
         const block0 = await latest.encryptBlock0();

         // set byte in encrypted data
         block0.parts[2][12] = block0.parts[2][12] == 123 ? 124 : 123;
         let [cipherStream] = streamFromCipherBlock([block0]);
         const decKeyProvider = new PWDKeyProvider(userCred, async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, undefined];
         });
         let decipher = await getStreamDecipher(cipherStream, decKeyProvider);

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

   const pwd = 'a not good pwd';
   const hint = 'sorta';
   let userCred: Uint8Array<ArrayBuffer>;
   const clearStr = 'This is a secret 🦀 with extra wording for more blocks';

   beforeEach(async () => {
      await cryptoReady();
      userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));
   });

   async function get_blocks(alg: cc.CipherAlgs): Promise<[
      CipherDataBlock,
      CipherDataBlock,
      CipherDataBlock
   ]> {
      const [clearStream] = streamFromStr(clearStr);

      const encKeyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
         expect(cdinfo.lp).toEqual(1);
         expect(cdinfo.lpEnd).toEqual(1);
         return [pwd, hint];
      });
      const latest = getLatestEncipher(
         clearStream, encKeyProvider, alg, 1, 1, cc.ICOUNT_MIN,
         { startSize: 12 }
      );

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
         const decKeyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, undefined];
         });
         let decipher = await getStreamDecipher(cipherStream, decKeyProvider);

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
         const decKeyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, undefined];
         });
         let decipher = await getStreamDecipher(cipherStream, decKeyProvider);

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
         const decKeyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, undefined];
         });
         let decipher = await getStreamDecipher(cipherStream, decKeyProvider);

         // Will fail in V4 and later because block0 format or MAC is invalid.
         // Failure detection can happen at different spots while data is unpacked
         // since random values may look valid. MAC will alsways be
         // invalid if we get that far.
         await expect(decipher.decryptBlock0()).rejects.toThrow(new RegExp('Invalid.+'));

      }
   });
});


describe("Inter-block MAC chaining", function () {

   const pwd = 'a not good pwd';
   const clearStr = 'This is a secret 🦀 with extra wording for more blocks';

   beforeEach(async () => {
      await cryptoReady();
   });

   // Encrypts clearStr with explicit slt so two encryptions produce identical
   // signing keys but different per-block IVs and MACs.
   async function encryptThreeBlocks(
      alg: cc.CipherAlgs,
      userCred: Uint8Array<ArrayBuffer>,
      slt: Uint8Array<ArrayBuffer>
   ): Promise<[CipherDataBlock, CipherDataBlock, CipherDataBlock]> {
      const [clearStream] = streamFromStr(clearStr);
      const keyProvider = new PWDKeyProvider(userCred.slice(0), [pwd, undefined]);
      keyProvider.setCipherDataInfo({
         ver: cc.CURRENT_VERSION,
         alg,
         ic: cc.ICOUNT_MIN,
         slt,
         lp: 1,
         lpEnd: 1,
      });

      const reader = new BYOBStreamReader(clearStream);
      const encipher = new EncipherV7(keyProvider, reader, { startSize: 12 });
      const block0 = await encipher.encryptBlock0();
      const block1 = await encipher.encryptBlockN();
      const block2 = await encipher.encryptBlockN();

      return [block0, block1, block2];
   }

   // Validates the splice test approach before it's used to assert failures.
   it("extract and concat round-trip succeeds, all algorithms", async function () {
      const clearData = new TextEncoder().encode(clearStr);
      for (const alg of Ciphers.algs()) {
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));
         const slt = crypto.getRandomValues(new Uint8Array(cc.SLT_BYTES));

         const blocks = await encryptThreeBlocks(alg, userCred, slt);
         const cipherBytes = concatArrays(blocks.flatMap(block => block.parts));
         const [cipherStream] = streamFromBytes(cipherBytes);

         const decKeyProvider = new PWDKeyProvider(userCred, [pwd, undefined]);
         const decipher = await getStreamDecipher(cipherStream, decKeyProvider);
         const decBlock0 = await decipher.decryptBlock0();
         const decBlock1 = await decipher.decryptBlockN();
         const decBlock2 = await decipher.decryptBlockN();

         const [decrypted] = streamFromBytes([decBlock0, decBlock1, decBlock2]);
         await expect(areEqual(decrypted, clearData)).resolves.toEqual(true);
      }
   });

   // Verifies MAC chain detects swapped blocks even with the same signing key
   // (derviced from matching userCred + slt + alg + lp + ver)
   it("block spliced from a parallel stream fails MAC, all algorithms", async function () {
      for (const alg of Ciphers.algs()) {
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));
         const slt = crypto.getRandomValues(new Uint8Array(cc.SLT_BYTES));

         const [a0, , a2] = await encryptThreeBlocks(alg, userCred, slt);
         const [, b1] = await encryptThreeBlocks(alg, userCred, slt);

         // Splice: A's block0, B's block1, A's block2.
         const spliced = concatArrays([a0, b1, a2].flatMap(block => block.parts));
         const [cipherStream] = streamFromBytes(spliced);

         const decKeyProvider = new PWDKeyProvider(userCred, [pwd, undefined]);
         const decipher = await getStreamDecipher(cipherStream, decKeyProvider);
         await expect(decipher.decryptBlock0()).resolves.not.toThrow();
         await expect(decipher.decryptBlockN()).rejects.toThrow(/Invalid MAC/);
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
