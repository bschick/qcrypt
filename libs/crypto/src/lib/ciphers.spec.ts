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
   EncipherV67,
   Ciphers
} from '../index';
import type { CipherDataBlock } from '../index';
import { PWDKeyProvider } from './keys';
import {
   isEqualArray,
   streamFromBytes,
   streamFromStr,
   areEqual
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
      encipher: EncipherV67,
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
         const encipher = new EncipherV67(keyProvider, reader);
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

   it("correct cipherdata info and decryption, v4", async function () {
      const [_, clearData] = streamFromStr('A nice 🦫 came to say hello');
      const pwd = 'a 🌲 of course';
      const hint = '🌧️';
      // base64url userCred for use in commandline for recreation (see Python helper function):
      // Ohyqajb6nFOm2Y5lOTkIkhc3uAaF8sUrYrQ9pts2pDc=
      const userCred = new Uint8Array([58, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98, 180, 61, 166, 219, 54, 164, 55]);
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
      // base64url userCred for use in commandline for recreation (see Python helper function):
      // Ohyqajb6nFOm2Y5lOTkIkhc3uAaF8sUrYrQ9pts2pDc=
      const userCred = new Uint8Array([58, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98, 180, 61, 166, 219, 54, 164, 55]);
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

   it("correct cipherdata info and decryption, v6", async function () {
      const [_, clearData] = streamFromStr('A nice 🦫 came to say hello');
      const pwd = 'a 🌲 of course';
      const hint = '🌧️';
      // base64url userCred for use in commandline for recreation (see Python helper function):
      // Ohyqajb6nFOm2Y5lOTkIkhc3uAaF8sUrYrQ9pts2pDc=
      const userCred = new Uint8Array([58, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98, 180, 61, 166, 219, 54, 164, 55]);
      const [cipherStream] = streamFromBytes(new Uint8Array([6, 96, 26, 215, 92, 226, 157, 130, 104, 27, 37, 39, 156, 244, 118, 186, 163, 217, 181, 220, 148, 183, 115, 69, 212, 144, 69, 184, 232, 175, 121, 248, 6, 0, 117, 0, 0, 1, 2, 0, 182, 155, 226, 214, 133, 101, 225, 193, 160, 76, 50, 50, 81, 174, 29, 73, 153, 121, 174, 60, 118, 42, 201, 149, 164, 52, 159, 208, 233, 162, 104, 60, 88, 170, 241, 87, 39, 144, 27, 9, 64, 119, 27, 0, 0, 23, 39, 229, 13, 184, 77, 68, 136, 183, 209, 252, 108, 46, 43, 205, 134, 87, 252, 6, 137, 0, 87, 185, 232, 81, 118, 182, 118, 213, 206, 208, 109, 156, 228, 114, 188, 28, 150, 5, 239, 220, 247, 53, 192, 38, 56, 0, 190, 42, 95, 177, 83, 44, 31, 173, 51, 32, 94, 177, 93, 144, 3, 149, 167, 10, 114, 79, 141, 182]));

      const decipher = await streamDecipher(userCred, cipherStream, async (cdinfo) => {
         expect(cdinfo.hint).toEqual(hint);
         expect(cdinfo.lp).toEqual(1);
         expect(cdinfo.lpEnd).toEqual(1);
         expect(cdinfo.alg).toBe('X20-PLY');
         expect(cdinfo.ic).toBe(1800000);
         expect(cdinfo.hint).toEqual(hint);
         expect(cdinfo.ver).toEqual(cc.VERSION6);
         expect(isEqualArray(cdinfo.slt, new Uint8Array([164, 52, 159, 208, 233, 162, 104, 60, 88, 170, 241, 87, 39, 144, 27, 9]))).toBe(true);
         return [pwd, undefined];
      });
      const cdInfo = await decipher.getCipherDataInfo();

      expect(cdInfo.alg).toEqual('X20-PLY');
      expect(cdInfo.ic).toEqual(1800000);
      expect(isEqualArray(cdInfo.slt, new Uint8Array([164, 52, 159, 208, 233, 162, 104, 60, 88, 170, 241, 87, 39, 144, 27, 9]))).toBe(true);
      expect(cdInfo.ver).toEqual(cc.VERSION6);
      expect(cdInfo.hint).toEqual(hint);

      await expect(decipher.decryptBlock0()).resolves.toEqual(clearData);
      await expect(decipher.decryptBlockN()).resolves.toEqual(new Uint8Array(0));
   });

   it("correct cipherdata info and decryption, v7", async function () {
      const [_, clearData] = streamFromStr('A nice 🦫 came to say hello');
      const pwd = 'a 🌲 of course';
      const hint = '🌧️';
      // base64url userCred for use in commandline for recreation (see Python helper function):
      // Ohyqajb6nFOm2Y5lOTkIkhc3uAaF8sUrYrQ9pts2pDc=
      const userCred = new Uint8Array([58, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98, 180, 61, 166, 219, 54, 164, 55]);
      const [cipherStream] = streamFromBytes(new Uint8Array([75, 67, 72, 3, 80, 226, 101, 28, 192, 33, 232, 133, 179, 116, 165, 149, 149, 31, 16, 55, 162, 227, 219, 153, 35, 191, 195, 75, 50, 198, 116, 34, 7, 0, 117, 0, 0, 1, 2, 0, 140, 23, 135, 49, 78, 230, 82, 168, 169, 154, 46, 151, 64, 243, 65, 230, 55, 137, 114, 161, 78, 128, 24, 99, 137, 230, 0, 23, 255, 99, 255, 2, 129, 199, 168, 215, 49, 94, 57, 29, 64, 119, 27, 0, 0, 23, 2, 144, 63, 30, 135, 104, 68, 170, 207, 177, 20, 115, 242, 67, 168, 221, 173, 68, 23, 119, 49, 252, 245, 56, 167, 186, 205, 231, 167, 164, 142, 181, 208, 124, 219, 18, 217, 57, 28, 44, 101, 21, 174, 27, 65, 48, 40, 254, 174, 79, 154, 220, 163, 100, 7, 32, 228, 161, 22, 194, 47, 32, 178, 71, 137, 29, 22, 162]));

      const decipher = await streamDecipher(userCred, cipherStream, async (cdinfo) => {
         expect(cdinfo.hint).toEqual(hint);
         expect(cdinfo.lp).toEqual(1);
         expect(cdinfo.lpEnd).toEqual(1);
         expect(cdinfo.alg).toBe('X20-PLY');
         expect(cdinfo.ic).toBe(1800000);
         expect(cdinfo.hint).toEqual(hint);
         expect(cdinfo.ver).toEqual(cc.VERSION7);
         expect(cdinfo.slt.byteLength).toEqual(cc.SLT_BYTES);
         return [pwd, undefined];
      });
      const cdInfo = await decipher.getCipherDataInfo();

      expect(cdInfo.alg).toEqual('X20-PLY');
      expect(cdInfo.ic).toEqual(1800000);
      expect(cdInfo.ver).toEqual(cc.VERSION7);
      expect(cdInfo.hint).toEqual(hint);
      expect(cdInfo.slt.byteLength).toEqual(cc.SLT_BYTES);

      await expect(decipher.decryptBlock0()).resolves.toEqual(clearData);
      await expect(decipher.decryptBlockN()).resolves.toEqual(new Uint8Array(0));
   });

   it("missing terminal block indicator, v5", async function () {
      const [_, clearData] = streamFromStr('A nice 🦫 came to say hello');
      const pwd = 'a 🌲 of course';
      const hint = '🌧️';
      // base64url userCred for use in commandline for recreation (see Python helper function):
      // Ohyqajb6nFOm2Y5lOTkIkhc3uAaF8sUrYrQ9pts2pDc=
      const userCred = new Uint8Array([58, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98, 180, 61, 166, 219, 54, 164, 55]);
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


   it("missing terminal block indicator, v6", async function () {
      const [_, clearData] = streamFromStr('A nice 🦫 came to say hello');
      const pwd = 'a 🌲 of course';
      const hint = '🌧️';
      // base64url userCred for use in commandline for recreation (see Python helper function):
      // Ohyqajb6nFOm2Y5lOTkIkhc3uAaF8sUrYrQ9pts2pDc=
      // creating the proper cipherdata requires a hacked/rebuilt cmdline that always sets flags to 0 (search chipers-current for "term:")
      const userCred = new Uint8Array([58, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98, 180, 61, 166, 219, 54, 164, 55]);
      const [cipherStream] = streamFromBytes(new Uint8Array([132, 28, 138, 123, 147, 127, 43, 62, 165, 146, 225, 63, 193, 229, 103, 67, 52, 78, 235, 87, 222, 81, 39, 59, 221, 183, 97, 72, 255, 88, 246, 58, 6, 0, 117, 0, 0, 0, 2, 0, 34, 40, 133, 44, 12, 94, 228, 213, 26, 168, 170, 128, 158, 80, 186, 10, 199, 186, 216, 165, 74, 175, 77, 14, 167, 87, 224, 153, 52, 15, 148, 75, 171, 2, 77, 176, 158, 14, 41, 21, 64, 119, 27, 0, 0, 23, 60, 217, 5, 30, 103, 244, 158, 250, 216, 37, 3, 99, 119, 58, 27, 195, 99, 129, 80, 65, 210, 179, 102, 243, 232, 235, 177, 129, 48, 29, 127, 154, 58, 17, 16, 73, 65, 218, 12, 57, 251, 92, 205, 101, 8, 236, 63, 89, 47, 41, 190, 168, 125, 241, 136, 131, 63, 67, 146, 42, 204, 9, 202, 62, 160, 22, 123, 154]));

      const decipher = await streamDecipher(userCred, cipherStream, async (cdinfo) => {
         expect(cdinfo.hint).toEqual(hint);
         expect(cdinfo.lp).toEqual(1);
         expect(cdinfo.lpEnd).toEqual(1);
         expect(cdinfo.alg).toBe('X20-PLY');
         expect(cdinfo.ic).toBe(1800000);
         expect(cdinfo.ver).toEqual(cc.VERSION6);
         expect(isEqualArray(cdinfo.slt, new Uint8Array([167, 87, 224, 153, 52, 15, 148, 75, 171, 2, 77, 176, 158, 14, 41, 21]))).toBe(true);
         return [pwd, undefined];
      });
      const cdInfo = await decipher.getCipherDataInfo();

      expect(cdInfo.alg).toEqual('X20-PLY');
      expect(cdInfo.ic).toEqual(1800000);
      expect(isEqualArray(cdInfo.slt, new Uint8Array([167, 87, 224, 153, 52, 15, 148, 75, 171, 2, 77, 176, 158, 14, 41, 21]))).toBe(true);
      expect(cdInfo.ver).toEqual(cc.VERSION6);
      expect(cdInfo.hint).toEqual(hint);

      // Although the cipherData for block0 above is missing the "terminal block" indicator,
      // that isn't detected until we hit the end of the file (below in blockN)
      await expect(decipher.decryptBlock0()).resolves.toEqual(clearData);
      await expect(decipher.decryptBlockN()).rejects.toThrow(/Missing terminal/);
   });

   it("missing terminal block indicator, v7", async function () {
      const [_, clearData] = streamFromStr('A nice 🦫 came to say hello');
      const pwd = 'a 🌲 of course';
      const hint = '🌧️';
      // base64url userCred for use in commandline for recreation (see Python helper function):
      // Ohyqajb6nFOm2Y5lOTkIkhc3uAaF8sUrYrQ9pts2pDc=
      // creating the proper cipherdata requires a hacked/rebuilt cmdline that always sets flags to 0 (search chipers-current for "term:")
      const userCred = new Uint8Array([58, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98, 180, 61, 166, 219, 54, 164, 55]);
      const [cipherStream] = streamFromBytes(new Uint8Array([209, 240, 80, 168, 179, 48, 240, 241, 10, 5, 106, 71, 60, 33, 6, 88, 2, 92, 9, 113, 97, 17, 227, 74, 229, 187, 126, 159, 89, 136, 76, 115, 7, 0, 117, 0, 0, 0, 2, 0, 144, 192, 88, 15, 25, 183, 62, 200, 83, 148, 77, 165, 57, 32, 233, 121, 39, 211, 4, 73, 10, 209, 123, 122, 156, 2, 132, 58, 152, 234, 145, 172, 183, 45, 158, 85, 84, 119, 238, 37, 64, 119, 27, 0, 0, 23, 190, 80, 107, 244, 46, 134, 188, 170, 53, 63, 39, 49, 202, 61, 68, 143, 96, 230, 197, 94, 157, 167, 104, 56, 174, 34, 181, 45, 146, 117, 232, 180, 176, 141, 190, 86, 146, 145, 127, 108, 204, 132, 53, 163, 30, 5, 236, 163, 206, 126, 147, 74, 102, 178, 77, 146, 92, 86, 29, 1, 117, 147, 145, 154, 201, 120, 3, 141]));

      const decipher = await streamDecipher(userCred, cipherStream, async (cdinfo) => {
         expect(cdinfo.hint).toEqual(hint);
         expect(cdinfo.lp).toEqual(1);
         expect(cdinfo.lpEnd).toEqual(1);
         expect(cdinfo.alg).toBe('X20-PLY');
         expect(cdinfo.ic).toBe(1800000);
         expect(cdinfo.ver).toEqual(cc.VERSION7);
         expect(cdinfo.slt.byteLength).toEqual(cc.SLT_BYTES);
         return [pwd, undefined];
      });
      const cdInfo = await decipher.getCipherDataInfo();

      expect(cdInfo.alg).toEqual('X20-PLY');
      expect(cdInfo.ic).toEqual(1800000);
      expect(cdInfo.slt.byteLength).toEqual(cc.SLT_BYTES);
      expect(cdInfo.ver).toEqual(cc.VERSION7);
      expect(cdInfo.hint).toEqual(hint);

      // Although the cipherData for block0 above is missing the "terminal block" indicator,
      // that isn't detected until we hit the end of the file (below in blockN)
      await expect(decipher.decryptBlock0()).resolves.toEqual(clearData);
      await expect(decipher.decryptBlockN()).rejects.toThrow(/Missing terminal/);
   });

   it("extra terminal block indicator, v6", async function () {
      const [_, clearData] = streamFromStr('A nice 🦫 came to say hello');
      const pwd = 'a 🌲 of course';
      const hint = '🌧️';
      // base64url userCred for use in commandline for recreation (see Python helper function):
      // Ohyqajb6nFOm2Y5lOTkIkhc3uAaF8sUrYrQ9pts2pDc=
      // creating the proper cipherdata requires a hacked/rebuilt cmdline that always sets flags to 1 (search chipers-current for "term:") and READ_SIZE_START to 20
      const userCred = new Uint8Array([58, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98, 180, 61, 166, 219, 54, 164, 55]);
      const [cipherStream] = streamFromBytes(new Uint8Array([114, 105, 149, 122, 214, 68, 66, 254, 204, 60, 108, 90, 88, 145, 24, 13, 64, 232, 184, 211, 137, 68, 207, 107, 242, 54, 26, 74, 31, 99, 61, 110, 6, 0, 108, 0, 0, 1, 2, 0, 38, 7, 93, 115, 159, 181, 216, 73, 45, 124, 29, 242, 220, 98, 213, 145, 114, 236, 39, 248, 11, 6, 42, 127, 123, 242, 217, 57, 58, 205, 0, 255, 238, 184, 227, 83, 181, 100, 188, 208, 64, 119, 27, 0, 0, 23, 154, 92, 181, 175, 144, 243, 53, 142, 153, 165, 44, 241, 86, 111, 236, 209, 43, 164, 62, 163, 196, 163, 117, 144, 20, 60, 205, 74, 135, 202, 75, 142, 62, 9, 135, 94, 49, 180, 28, 58, 209, 97, 164, 112, 49, 76, 42, 209, 140, 8, 93, 78, 168, 68, 248, 120, 26, 49, 28, 173, 242, 51, 71, 237, 8, 237, 174, 172, 162, 15, 13, 206, 208, 202, 130, 231, 36, 205, 62, 47, 252, 216, 35, 203, 182, 64, 202, 194, 87, 132, 92, 6, 0, 52, 0, 0, 1, 2, 0, 51, 173, 77, 222, 222, 129, 65, 79, 156, 158, 88, 144, 22, 46, 77, 72, 215, 184, 30, 152, 149, 40, 86, 78, 225, 236, 11, 99, 214, 240, 246, 48, 170, 7, 183, 213, 15, 213, 179, 207, 3, 190, 145, 97, 125, 81, 96, 46, 74]));

      const decipher = await streamDecipher(userCred, cipherStream, async (cdinfo) => {
         expect(cdinfo.hint).toEqual(hint);
         expect(cdinfo.lp).toEqual(1);
         expect(cdinfo.lpEnd).toEqual(1);
         expect(cdinfo.alg).toBe('X20-PLY');
         expect(cdinfo.ic).toBe(1800000);
         expect(cdinfo.ver).toEqual(cc.VERSION6);
         expect(isEqualArray(cdinfo.slt, new Uint8Array([123, 242, 217, 57, 58, 205, 0, 255, 238, 184, 227, 83, 181, 100, 188, 208]))).toBe(true);
         return [pwd, undefined];
      });
      const cdInfo = await decipher.getCipherDataInfo();

      expect(cdInfo.alg).toEqual('X20-PLY');
      expect(cdInfo.ic).toEqual(1800000);
      expect(isEqualArray(cdInfo.slt, new Uint8Array([123, 242, 217, 57, 58, 205, 0, 255, 238, 184, 227, 83, 181, 100, 188, 208]))).toBe(true);
      expect(cdInfo.ver).toEqual(cc.VERSION6);
      expect(cdInfo.hint).toEqual(hint);

      await expect(decipher.decryptBlock0()).resolves.toEqual(clearData.slice(0, 20));
      await expect(decipher.decryptBlockN()).rejects.toThrow(/Extra data block/);
   });

   it("extra terminal block indicator, v7", async function () {
      const [_, clearData] = streamFromStr('A nice 🦫 came to say hello');
      const pwd = 'a 🌲 of course';
      const hint = '🌧️';
      // base64url userCred for use in commandline for recreation (see Python helper function):
      // Ohyqajb6nFOm2Y5lOTkIkhc3uAaF8sUrYrQ9pts2pDc=
      // creating the proper cipherdata requires a hacked/rebuilt cmdline that always sets flags to 1 (search chipers-current for "term:") and READ_SIZE_START to 20
      const userCred = new Uint8Array([58, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98, 180, 61, 166, 219, 54, 164, 55]);
      const [cipherStream] = streamFromBytes(new Uint8Array([71, 26, 9, 62, 172, 47, 214, 150, 172, 219, 175, 2, 130, 150, 83, 10, 50, 117, 51, 110, 216, 166, 180, 128, 2, 198, 40, 167, 14, 175, 179, 212, 7, 0, 108, 0, 0, 1, 2, 0, 157, 224, 179, 10, 66, 233, 196, 45, 242, 174, 198, 127, 240, 213, 132, 79, 248, 187, 196, 215, 158, 253, 179, 7, 50, 15, 185, 66, 17, 69, 99, 111, 166, 161, 171, 245, 57, 4, 39, 37, 64, 119, 27, 0, 0, 23, 42, 234, 155, 172, 178, 126, 198, 56, 245, 128, 224, 166, 219, 229, 232, 44, 129, 255, 56, 211, 234, 164, 68, 130, 13, 85, 146, 244, 19, 163, 38, 30, 211, 39, 126, 116, 209, 233, 150, 73, 94, 178, 228, 51, 112, 50, 90, 10, 205, 28, 18, 62, 8, 58, 154, 220, 161, 162, 134, 63, 131, 73, 164, 93, 34, 56, 195, 196, 109, 219, 60, 151, 173, 171, 240, 127, 32, 153, 203, 140, 36, 90, 14, 175, 224, 111, 212, 109, 98, 172, 211, 7, 0, 52, 0, 0, 1, 2, 0, 12, 217, 34, 57, 87, 125, 55, 51, 12, 121, 39, 53, 140, 18, 44, 213, 198, 131, 191, 124, 49, 61, 10, 108, 165, 137, 86, 33, 125, 14, 197, 207, 74, 157, 221, 39, 125, 88, 122, 36, 36, 112, 111, 39, 183, 209, 161, 91, 45]));

      const decipher = await streamDecipher(userCred, cipherStream, async (cdinfo) => {
         expect(cdinfo.hint).toEqual(hint);
         expect(cdinfo.lp).toEqual(1);
         expect(cdinfo.lpEnd).toEqual(1);
         expect(cdinfo.alg).toBe('X20-PLY');
         expect(cdinfo.ic).toBe(1800000);
         expect(cdinfo.ver).toEqual(cc.VERSION7);
         expect(cdinfo.slt.byteLength).toEqual(cc.SLT_BYTES);
         return [pwd, undefined];
      });
      const cdInfo = await decipher.getCipherDataInfo();

      expect(cdInfo.alg).toEqual('X20-PLY');
      expect(cdInfo.ic).toEqual(1800000);
      expect(cdInfo.slt.byteLength).toEqual(cc.SLT_BYTES);
      expect(cdInfo.ver).toEqual(cc.VERSION7);
      expect(cdInfo.hint).toEqual(hint);

      await expect(decipher.decryptBlock0()).resolves.toEqual(clearData.slice(0, 20));
      await expect(decipher.decryptBlockN()).rejects.toThrow(/Extra data block/);
   });


   it("flipped terminal block indicator, v6", async function () {
      const [_, clearData] = streamFromStr('A nice 🦫 came to say hello');
      const pwd = 'a 🌲 of course';
      const hint = '🌧️';
      // base64url userCred for use in commandline for recreation (see Python helper function):
      // Ohyqajb6nFOm2Y5lOTkIkhc3uAaF8sUrYrQ9pts2pDc=
      // creating the proper cipherdata requires a hacked/rebuilt cmdline that flips flags to 1 then 0 (search chipers-current for "term:") and READ_SIZE_START to 20
      const userCred = new Uint8Array([58, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98, 180, 61, 166, 219, 54, 164, 55]);
      const [cipherStream] = streamFromBytes(new Uint8Array([24, 212, 67, 36, 232, 163, 170, 119, 145, 211, 157, 196, 172, 177, 63, 167, 12, 22, 20, 81, 250, 166, 94, 226, 132, 226, 253, 243, 133, 249, 38, 46, 6, 0, 108, 0, 0, 1, 2, 0, 85, 112, 249, 39, 40, 215, 94, 63, 122, 204, 193, 102, 64, 65, 163, 82, 69, 123, 185, 109, 204, 27, 14, 222, 237, 33, 135, 94, 11, 145, 15, 204, 88, 25, 166, 108, 158, 106, 108, 144, 64, 119, 27, 0, 0, 23, 249, 240, 198, 170, 184, 70, 4, 93, 213, 139, 151, 175, 168, 83, 58, 110, 57, 141, 165, 35, 67, 130, 224, 145, 19, 200, 206, 7, 210, 27, 238, 115, 65, 227, 65, 86, 173, 49, 27, 61, 214, 163, 247, 237, 148, 168, 221, 228, 49, 197, 130, 72, 232, 83, 9, 108, 84, 44, 172, 115, 101, 0, 244, 178, 175, 216, 196, 5, 182, 210, 63, 180, 227, 122, 3, 70, 210, 255, 100, 185, 98, 226, 215, 183, 55, 131, 223, 16, 182, 177, 109, 6, 0, 52, 0, 0, 0, 2, 0, 117, 159, 80, 68, 25, 102, 215, 193, 132, 143, 200, 39, 19, 204, 47, 81, 213, 236, 77, 70, 22, 228, 220, 182, 58, 75, 143, 225, 66, 207, 162, 138, 118, 145, 133, 192, 55, 108, 217, 36, 155, 122, 39, 41, 30, 18, 66, 109, 59]));

      const decipher = await streamDecipher(userCred, cipherStream, async (cdinfo) => {
         expect(cdinfo.hint).toEqual(hint);
         expect(cdinfo.lp).toEqual(1);
         expect(cdinfo.lpEnd).toEqual(1);
         expect(cdinfo.alg).toBe('X20-PLY');
         expect(cdinfo.ic).toBe(1800000);
         expect(cdinfo.ver).toEqual(cc.VERSION6);
         expect(isEqualArray(cdinfo.slt, new Uint8Array([237, 33, 135, 94, 11, 145, 15, 204, 88, 25, 166, 108, 158, 106, 108, 144]))).toBe(true);
         return [pwd, undefined];
      });
      const cdInfo = await decipher.getCipherDataInfo();

      expect(cdInfo.alg).toEqual('X20-PLY');
      expect(cdInfo.ic).toEqual(1800000);
      expect(isEqualArray(cdInfo.slt, new Uint8Array([237, 33, 135, 94, 11, 145, 15, 204, 88, 25, 166, 108, 158, 106, 108, 144]))).toBe(true);
      expect(cdInfo.ver).toEqual(cc.VERSION6);
      expect(cdInfo.hint).toEqual(hint);

      await expect(decipher.decryptBlock0()).resolves.toEqual(clearData.slice(0, 20));
      await expect(decipher.decryptBlockN()).rejects.toThrow(/Extra data block/);
   });

   it("flipped terminal block indicator, v7", async function () {
      const [_, clearData] = streamFromStr('A nice 🦫 came to say hello');
      const pwd = 'a 🌲 of course';
      const hint = '🌧️';
      // base64url userCred for use in commandline for recreation (see Python helper function):
      // Ohyqajb6nFOm2Y5lOTkIkhc3uAaF8sUrYrQ9pts2pDc=
      // creating the proper cipherdata requires a hacked/rebuilt cmdline that flips flags to 1 then 0 (search chipers-current for "term:") and READ_SIZE_START to 20
      const userCred = new Uint8Array([58, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98, 180, 61, 166, 219, 54, 164, 55]);
      const [cipherStream] = streamFromBytes(new Uint8Array([141, 83, 66, 190, 110, 251, 166, 187, 71, 125, 210, 226, 11, 78, 119, 209, 171, 159, 122, 214, 106, 240, 112, 186, 25, 93, 103, 22, 128, 132, 199, 19, 7, 0, 108, 0, 0, 1, 2, 0, 92, 74, 84, 65, 34, 10, 243, 84, 13, 1, 22, 55, 87, 6, 78, 255, 133, 159, 128, 106, 169, 207, 197, 14, 195, 35, 113, 147, 9, 242, 219, 186, 12, 247, 169, 72, 114, 97, 143, 202, 64, 119, 27, 0, 0, 23, 196, 177, 88, 75, 80, 138, 135, 239, 81, 171, 126, 216, 3, 124, 104, 97, 223, 40, 148, 244, 182, 147, 109, 194, 25, 51, 238, 225, 217, 186, 208, 91, 201, 96, 184, 13, 207, 83, 154, 30, 3, 237, 79, 100, 5, 216, 16, 133, 58, 175, 88, 105, 209, 42, 54, 220, 29, 215, 160, 150, 43, 146, 208, 138, 223, 135, 87, 159, 161, 42, 181, 134, 173, 114, 113, 94, 158, 62, 40, 27, 88, 105, 104, 214, 211, 146, 172, 108, 91, 143, 23, 7, 0, 52, 0, 0, 0, 2, 0, 4, 10, 91, 77, 71, 138, 179, 153, 144, 43, 138, 95, 179, 37, 198, 58, 190, 126, 108, 132, 52, 150, 105, 106, 22, 50, 47, 219, 39, 104, 157, 223, 104, 25, 17, 192, 153, 144, 202, 69, 80, 240, 2, 82, 216, 83, 183, 175, 15]));

      const decipher = await streamDecipher(userCred, cipherStream, async (cdinfo) => {
         expect(cdinfo.hint).toEqual(hint);
         expect(cdinfo.lp).toEqual(1);
         expect(cdinfo.lpEnd).toEqual(1);
         expect(cdinfo.alg).toBe('X20-PLY');
         expect(cdinfo.ic).toBe(1800000);
         expect(cdinfo.ver).toEqual(cc.VERSION7);
         expect(cdinfo.slt.byteLength).toEqual(cc.SLT_BYTES);
         return [pwd, undefined];
      });
      const cdInfo = await decipher.getCipherDataInfo();

      expect(cdInfo.alg).toEqual('X20-PLY');
      expect(cdInfo.ic).toEqual(1800000);
      expect(cdInfo.slt.byteLength).toEqual(cc.SLT_BYTES);
      expect(cdInfo.ver).toEqual(cc.VERSION7);
      expect(cdInfo.hint).toEqual(hint);

      await expect(decipher.decryptBlock0()).resolves.toEqual(clearData.slice(0, 20));
      await expect(decipher.decryptBlockN()).rejects.toThrow(/Extra data block/);
   });

   it("bad input to cipherdata info and decrypt, v4", async function () {
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

   it("bad input to cipherdata info and decrypt, v5", async function () {
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

   it("bad input to cipherdata info and decrypt, v6", async function () {
      const [_, clearData] = streamFromStr('A nice 🦫 came to say hello');
      const pwdGood = 'a 🌲 of course';
      const pwdBad = 'a 🌵 of course';
      const userCredBad = new Uint8Array([0, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98, 180, 61, 166, 219, 54, 164, 55]);

      // copied from "correct cipherdata info and decryption" spec above
      const userCredGood = new Uint8Array([58, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98, 180, 61, 166, 219, 54, 164, 55]);
      let [cipherStream, cipherData] = streamFromBytes(new Uint8Array([6, 96, 26, 215, 92, 226, 157, 130, 104, 27, 37, 39, 156, 244, 118, 186, 163, 217, 181, 220, 148, 183, 115, 69, 212, 144, 69, 184, 232, 175, 121, 248, 6, 0, 117, 0, 0, 1, 2, 0, 182, 155, 226, 214, 133, 101, 225, 193, 160, 76, 50, 50, 81, 174, 29, 73, 153, 121, 174, 60, 118, 42, 201, 149, 164, 52, 159, 208, 233, 162, 104, 60, 88, 170, 241, 87, 39, 144, 27, 9, 64, 119, 27, 0, 0, 23, 39, 229, 13, 184, 77, 68, 136, 183, 209, 252, 108, 46, 43, 205, 134, 87, 252, 6, 137, 0, 87, 185, 232, 81, 118, 182, 118, 213, 206, 208, 109, 156, 228, 114, 188, 28, 150, 5, 239, 220, 247, 53, 192, 38, 56, 0, 190, 42, 95, 177, 83, 44, 31, 173, 51, 32, 94, 177, 93, 144, 3, 149, 167, 10, 114, 79, 141, 182]));
      let decipher = await streamDecipher(userCredGood, cipherStream, async (cdinfo) => {
         expect(cdinfo.alg).toBe('X20-PLY');
         expect(cdinfo.ic).toBe(1800000);
         expect(cdinfo.hint).toBeTruthy();
         expect(cdinfo.ver).toEqual(cc.VERSION6);
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

   it("bad input to cipherdata info and decrypt, v7", async function () {
      const [_, clearData] = streamFromStr('A nice 🦫 came to say hello');
      const pwdGood = 'a 🌲 of course';
      const pwdBad = 'a 🌵 of course';
      const userCredBad = new Uint8Array([0, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98, 180, 61, 166, 219, 54, 164, 55]);

      // copied from "correct cipherdata info and decryption, v7" spec above
      const userCredGood = new Uint8Array([58, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98, 180, 61, 166, 219, 54, 164, 55]);
      let [cipherStream, cipherData] = streamFromBytes(new Uint8Array([75, 67, 72, 3, 80, 226, 101, 28, 192, 33, 232, 133, 179, 116, 165, 149, 149, 31, 16, 55, 162, 227, 219, 153, 35, 191, 195, 75, 50, 198, 116, 34, 7, 0, 117, 0, 0, 1, 2, 0, 140, 23, 135, 49, 78, 230, 82, 168, 169, 154, 46, 151, 64, 243, 65, 230, 55, 137, 114, 161, 78, 128, 24, 99, 137, 230, 0, 23, 255, 99, 255, 2, 129, 199, 168, 215, 49, 94, 57, 29, 64, 119, 27, 0, 0, 23, 2, 144, 63, 30, 135, 104, 68, 170, 207, 177, 20, 115, 242, 67, 168, 221, 173, 68, 23, 119, 49, 252, 245, 56, 167, 186, 205, 231, 167, 164, 142, 181, 208, 124, 219, 18, 217, 57, 28, 44, 101, 21, 174, 27, 65, 48, 40, 254, 174, 79, 154, 220, 163, 100, 7, 32, 228, 161, 22, 194, 47, 32, 178, 71, 137, 29, 22, 162]));
      let decipher = await streamDecipher(userCredGood, cipherStream, async (cdinfo) => {
         expect(cdinfo.alg).toBe('X20-PLY');
         expect(cdinfo.ic).toBe(1800000);
         expect(cdinfo.hint).toBeTruthy();
         expect(cdinfo.ver).toEqual(cc.VERSION7);
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
