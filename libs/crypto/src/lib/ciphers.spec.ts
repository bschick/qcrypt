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
import { cryptoReady } from './crypto';
import * as cc from './cipher.consts';
import {
   BYOBStreamReader,
   getStreamDecipher,
   getLatestEncipher,
   EncipherV8,
   Ciphers,
   concatArrays,
   getRandom,
   numToBytes,
   bytesToNum,
   base64ToBytes,
   CipherState,
} from '../index';
import type { CipherDataBlock, KeyProvider } from '../index';
import { MasterKeyKeyProvider, PWDKeyProvider } from './keys';
import { isEqualArray, streamFromBytes, streamFromStr, areEqual, streamFromBase64Url } from './test-helpers';

// Field offsets within block0's additional data, walked from the data itself so that adding
// or reordering fields cannot leave these pointing at the wrong bytes
function fileADOffsets(fileAD: Uint8Array) {
   const flags = 0;
   const alg = flags + cc.FLAGS_BYTES;
   const iv = alg + cc.ALG_BYTES;
   const algName = Ciphers.algName(bytesToNum(fileAD.subarray(alg, alg + cc.ALG_BYTES)));
   const slt = iv + Ciphers.algIVByteLength(algName);
   const ic = slt + cc.SLT_BYTES;
   const lp = ic + cc.IC_BYTES;
   const hintLen = lp + cc.LPP_BYTES;
   const hint = hintLen + cc.HINT_LEN_BYTES;
   const commitLen = hint + fileAD[hintLen];
   const commit = commitLen + cc.COMMIT_LEN_BYTES;
   return { flags, alg, iv, slt, ic, lp, hintLen, hint, commitLen, commit };
}

function streamFromCipherBlock(cdBlocks: CipherDataBlock[]): [ReadableStream<Uint8Array>, Uint8Array] {
   const parts = cdBlocks.flatMap((block) => block.parts);
   return streamFromBytes(concatArrays(parts));
}

describe('Encryption and decryption', () => {
   beforeEach(async () => {
      await cryptoReady();
   });

   async function signAndRepack(
      encipher: EncipherV8,
      block: CipherDataBlock,
      keyProvider: PWDKeyProvider,
      restampCommitment: boolean = true,
   ): Promise<Uint8Array> {
      // cheating... parts[1] is _additionalData, parts[2] is encryptedData
      // and set _keyProvider to the one with potentially wrong userCred, reset _lastMac
      encipher['_keyProvider'] = keyProvider;
      encipher['_lastMac'] = new Uint8Array([0]);

      // Restamp the stored key commitment for this userCred so the block stays internally
      // consistent, leaving the AEAD as the thing under test rather than the commitment gate
      const fileAD = block.parts[1].slice(0);
      if (restampCommitment && keyProvider.supportsCommitment) {
         await keyProvider.getCipherKey(true);
         const keyCommitment = await keyProvider.getKeyCommitment();
         fileAD.set(keyCommitment, fileADOffsets(fileAD).commit);
      }

      const headerData = await encipher._createHeader(block.parts[2], fileAD);
      return concatArrays([headerData, fileAD, block.parts[2]]);
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

   it('decryption should fail with replaced valid signature and additionalData', async () => {
      for (const alg of Ciphers.algs()) {
         const [clearStream, clearData] = streamFromStr('This is a secret 🐓');
         const pwd = 'a good pwd';
         const userCredA = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));
         const userCredB = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));
         const slt = crypto.getRandomValues(new Uint8Array(cc.SLT_BYTES));

         const makeKP = (userCred: Uint8Array<ArrayBuffer>, encrypting: boolean): PWDKeyProvider => {
            const kp = new PWDKeyProvider(userCred.slice(0), [pwd, undefined]);
            encrypting &&
               kp.setCipherDataInfo({
                  ver: cc.CURRENT_VERSION,
                  alg,
                  ic: cc.ICOUNT_MIN,
                  slt,
                  lp: 1,
                  lpEnd: 1,
               });
            return kp;
         };

         const reader = new BYOBStreamReader(clearStream);
         const encipher = new EncipherV8(makeKP(userCredA, true), reader);
         const cipherBlock = await encipher.encryptBlock0();

         // Sign and repack with both the original (correct) values to help ensure the
         // code for repacking is valid and then with a new signature to be sure
         // the replacment is detected. Each signAndRepack uses a fresh keyProvider
         // because the encipher purges its keyProvider after encryptBlock0.
         let [cipherstreamA, cipherDataA] = streamFromBytes(
            await signAndRepack(encipher, cipherBlock, makeKP(userCredA, true)),
         );
         let [cipherstreamB, cipherDataB] = streamFromBytes(
            await signAndRepack(encipher, cipherBlock, makeKP(userCredB, true)),
         );

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

   // Same evil site as above, but leaving Alice's key commitment in place so the mismatch
   // is caught before the AEAD is reached
   it('decryption should fail when stored key commitment does not match the cipher key', async () => {
      for (const alg of Ciphers.algs()) {
         const [clearStream, clearData] = streamFromStr('This is a secret 🐈');
         const pwd = 'a good pwd';
         const userCredA = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));
         const userCredB = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));
         const slt = crypto.getRandomValues(new Uint8Array(cc.SLT_BYTES));

         const makeKP = (userCred: Uint8Array<ArrayBuffer>, encrypting: boolean): PWDKeyProvider => {
            const kp = new PWDKeyProvider(userCred.slice(0), [pwd, undefined]);
            encrypting &&
               kp.setCipherDataInfo({
                  ver: cc.CURRENT_VERSION,
                  alg,
                  ic: cc.ICOUNT_MIN,
                  slt,
                  lp: 1,
                  lpEnd: 1,
               });
            return kp;
         };

         const reader = new BYOBStreamReader(clearStream);
         const encipher = new EncipherV8(makeKP(userCredA, true), reader);
         const cipherBlock = await encipher.encryptBlock0();

         // Control keeps the original commitment too, so userCred is the only difference
         const [goodStream] = streamFromBytes(
            await signAndRepack(encipher, cipherBlock, makeKP(userCredA, true), false),
         );
         const goodDecipher = await getStreamDecipher(goodStream, makeKP(userCredA, false));
         await expect(goodDecipher.decryptBlock0()).resolves.toEqual(clearData);

         const [badStream] = streamFromBytes(
            await signAndRepack(encipher, cipherBlock, makeKP(userCredB, true), false),
         );
         const badDecipher = await getStreamDecipher(badStream, makeKP(userCredB, false));
         await expect(badDecipher.decryptBlock0()).rejects.toThrow(/key commitment/);
      }
   });

   // A tampering party who has gained access to userCred can rebuild the outer MAC
   // chain. This test drops a block, sets the term flag, and rebuilds the MAC to verify
   // that the AEAD still detects it because the flag lives in the additional data
   it('truncation should fail even when the outer MAC is rebuilt', async () => {
      for (const alg of Ciphers.algs()) {
         // 192 bytes splits into a 64 byte block0 and a terminal 128 byte block1
         const clearData = getRandom(192);
         const [clearStream] = streamFromBytes(clearData);
         const pwd = 'a good pwd';
         const userCred = getRandom(cc.USERCRED_BYTES);

         const encKeyProvider = new PWDKeyProvider(userCred.slice(0), [pwd, undefined]);
         const encipher = getLatestEncipher(clearStream, encKeyProvider, alg, 1, 1, cc.ICOUNT_MIN, {
            startSize: 64,
            maxSize: 128,
         });

         // Read the generated salt before encrypting because the encipher then purges it
         const slt = encKeyProvider.getCipherDataInfo().slt.slice(0);
         const block0 = await encipher.encryptBlock();
         await encipher.encryptBlock();

         const makeKP = (encrypting: boolean): PWDKeyProvider => {
            const kp = new PWDKeyProvider(userCred.slice(0), [pwd, undefined]);
            encrypting &&
               kp.setCipherDataInfo({ ver: cc.CURRENT_VERSION, alg, ic: cc.ICOUNT_MIN, slt, lp: 1, lpEnd: 1 });
            return kp;
         };

         // Rebuilds block0's MAC over additionalData the caller may have edited
         async function reforge(fileAD: Uint8Array): Promise<Uint8Array> {
            const [emptyStream] = streamFromBytes(new Uint8Array(0));
            const reforger = new EncipherV8(makeKP(true), new BYOBStreamReader(emptyStream));
            const headerData = await reforger._createHeader(block0.parts[2], fileAD);
            return concatArrays([headerData, fileAD, block0.parts[2]]);
         }

         // Control, so a failure below cannot be blamed on the repacking itself
         let [cipherStream] = streamFromBytes(await reforge(block0.parts[1]));
         const controlDec = await getStreamDecipher(cipherStream, makeKP(false));
         await expect(controlDec.decryptBlock0()).resolves.toEqual(clearData.subarray(0, 64));

         // Dropping block1 alone is caught by the terminal flag and needs no forging
         [cipherStream] = streamFromBytes(concatArrays(block0.parts));
         const plainDec = await getStreamDecipher(cipherStream, makeKP(false));
         await expect(plainDec.decryptBlock0()).resolves.toEqual(clearData.subarray(0, 64));
         await expect(plainDec.decryptBlockN()).rejects.toThrow(/terminal/);

         // Marking block0 terminal with a correctly rebuilt MAC leaves only the AEAD to object
         const tamperedAD = block0.parts[1].slice(0);
         tamperedAD[0] = 1;
         [cipherStream] = streamFromBytes(await reforge(tamperedAD));
         const forgedDec = await getStreamDecipher(cipherStream, makeKP(false));
         await expect(forgedDec.decryptBlock0()).rejects.toThrow(DOMException);
      }
   });

   // Same tampering party editing the commit length rather than the commitment value
   it('missing or wrong length key commitment should fail even when the outer MAC is rebuilt', async () => {
      for (const alg of Ciphers.algs()) {
         const clearData = getRandom(64);
         const [clearStream] = streamFromBytes(clearData);
         const pwd = 'a good pwd';
         const userCred = getRandom(cc.USERCRED_BYTES);

         const encKeyProvider = new PWDKeyProvider(userCred.slice(0), [pwd, undefined]);
         const encipher = getLatestEncipher(clearStream, encKeyProvider, alg, 1, 1, cc.ICOUNT_MIN);

         // Read the generated salt before encrypting because the encipher then purges it
         const slt = encKeyProvider.getCipherDataInfo().slt.slice(0);
         const block0 = await encipher.encryptBlock();

         const makeKP = (encrypting: boolean): PWDKeyProvider => {
            const kp = new PWDKeyProvider(userCred.slice(0), [pwd, undefined]);
            encrypting &&
               kp.setCipherDataInfo({ ver: cc.CURRENT_VERSION, alg, ic: cc.ICOUNT_MIN, slt, lp: 1, lpEnd: 1 });
            return kp;
         };

         // Rebuilds block0's MAC over additionalData the caller may have edited
         async function reforge(fileAD: Uint8Array): Promise<Uint8Array> {
            const [emptyStream] = streamFromBytes(new Uint8Array(0));
            const reforger = new EncipherV8(makeKP(true), new BYOBStreamReader(emptyStream));
            const headerData = await reforger._createHeader(block0.parts[2], fileAD);
            return concatArrays([headerData, fileAD, block0.parts[2]]);
         }

         // Only the length changes, so the rebuilt MAC still covers the same bytes
         function withCommitLen(commitLen: number): Uint8Array {
            const fileAD = block0.parts[1].slice(0);
            fileAD[fileADOffsets(fileAD).commitLen] = commitLen;
            return fileAD;
         }

         // Control, so a failure below is isolated to the commit length change
         let [cipherStream] = streamFromBytes(await reforge(withCommitLen(cc.COMMIT_BYTES)));
         const controlDec = await getStreamDecipher(cipherStream, makeKP(false));
         await expect(controlDec.decryptBlock0()).resolves.toEqual(clearData);

         [cipherStream] = streamFromBytes(await reforge(withCommitLen(0)));
         const missingDec = await getStreamDecipher(cipherStream, makeKP(false));
         await expect(missingDec.decryptBlock0()).rejects.toThrow(/key commitment presence/);

         [cipherStream] = streamFromBytes(await reforge(withCommitLen(cc.COMMIT_BYTES - 1)));
         const wrongLenDec = await getStreamDecipher(cipherStream, makeKP(false));
         await expect(wrongLenDec.decryptBlock0()).rejects.toThrow(/Invalid commit length/);
      }
   });

   // Similar tampering party who has gained access to userCred can rebuild MAC
   it('altered key commitment should fail even when the outer MAC is rebuilt', async () => {
      for (const alg of Ciphers.algs()) {
         const clearData = getRandom(64);
         const [clearStream] = streamFromBytes(clearData);
         const pwd = 'a good pwd';
         const userCred = getRandom(cc.USERCRED_BYTES);

         const encKeyProvider = new PWDKeyProvider(userCred.slice(0), [pwd, undefined]);
         const encipher = getLatestEncipher(clearStream, encKeyProvider, alg, 1, 1, cc.ICOUNT_MIN);

         // Read the generated salt before encrypting because the encipher then purges it
         const slt = encKeyProvider.getCipherDataInfo().slt.slice(0);
         const block0 = await encipher.encryptBlock();

         const makeKP = (encrypting: boolean): PWDKeyProvider => {
            const kp = new PWDKeyProvider(userCred.slice(0), [pwd, undefined]);
            encrypting &&
               kp.setCipherDataInfo({ ver: cc.CURRENT_VERSION, alg, ic: cc.ICOUNT_MIN, slt, lp: 1, lpEnd: 1 });
            return kp;
         };

         // Rebuilds block0's MAC over additionalData the caller may have edited
         async function reforge(fileAD: Uint8Array): Promise<Uint8Array> {
            const [emptyStream] = streamFromBytes(new Uint8Array(0));
            const reforger = new EncipherV8(makeKP(true), new BYOBStreamReader(emptyStream));
            const headerData = await reforger._createHeader(block0.parts[2], fileAD);
            return concatArrays([headerData, fileAD, block0.parts[2]]);
         }

         // Control, so a failure below is isolated to the commit key change
         let [cipherStream] = streamFromBytes(await reforge(block0.parts[1]));
         const controlDec = await getStreamDecipher(cipherStream, makeKP(false));
         await expect(controlDec.decryptBlock0()).resolves.toEqual(clearData);

         const tamperedAD = block0.parts[1].slice(0);
         tamperedAD[fileADOffsets(tamperedAD).commit] ^= 0x01;
         [cipherStream] = streamFromBytes(await reforge(tamperedAD));
         const forgedDec = await getStreamDecipher(cipherStream, makeKP(false));
         await expect(forgedDec.decryptBlock0()).rejects.toThrow(/key commitment/);
      }
   });

   it('added key commitment should be detected in MasterKeyKeyProvider', async () => {
      for (const alg of Ciphers.algs()) {
         const clearData = getRandom(64);
         const [clearStream] = streamFromBytes(clearData);
         const masterKey = getRandom(cc.KEY_BYTES);

         const encKeyProvider = new MasterKeyKeyProvider(masterKey.slice(0));
         const encipher = getLatestEncipher(clearStream, encKeyProvider, alg, 1, 1, 0);

         // Read the generated salt before encrypting because the encipher then purges it
         const slt = encKeyProvider.getCipherDataInfo().slt.slice(0);
         const block0 = await encipher.encryptBlock();

         const makeKP = (encrypting: boolean): MasterKeyKeyProvider => {
            const kp = new MasterKeyKeyProvider(masterKey.slice(0));
            encrypting && kp.setCipherDataInfo({ ver: cc.CURRENT_VERSION, alg, ic: 0, slt, lp: 1, lpEnd: 1 });
            return kp;
         };

         // Rebuilds block0's MAC over additionalData the caller may have edited
         async function reforge(fileAD: Uint8Array): Promise<Uint8Array> {
            const [emptyStream] = streamFromBytes(new Uint8Array(0));
            const reforger = new EncipherV8(makeKP(true), new BYOBStreamReader(emptyStream));
            const headerData = await reforger._createHeader(block0.parts[2], fileAD);
            return concatArrays([headerData, fileAD, block0.parts[2]]);
         }

         // Control, so a failure below is isolated to the added commitment
         let [cipherStream] = streamFromBytes(await reforge(block0.parts[1]));
         const controlDec = await getStreamDecipher(cipherStream, makeKP(false));
         await expect(controlDec.decryptBlock0()).resolves.toEqual(clearData);

         // The commitment is the last additional data field, so appending is the whole edit
         const fileAD = block0.parts[1].slice(0);
         fileAD[fileADOffsets(fileAD).commitLen] = cc.COMMIT_BYTES;
         [cipherStream] = streamFromBytes(await reforge(concatArrays([fileAD, getRandom(cc.COMMIT_BYTES)])));
         const addedDec = await getStreamDecipher(cipherStream, makeKP(false));
         await expect(addedDec.decryptBlock0()).rejects.toThrow(/key commitment presence/);
      }
   });

   // Similar tampering party who has gained access to userCred can rebuild MAC
   it('swapped blockN algorithm should fail even when its MAC is rebuilt', async () => {
      for (const alg of Ciphers.algs()) {
         // Enough plaintext to produce a block1
         const [clearStream, clearData] = streamFromStr('x'.repeat(2048));
         const pwd = 'a good pwd';
         const userCred = getRandom(cc.USERCRED_BYTES);

         const encKeyProvider = new PWDKeyProvider(userCred.slice(0), [pwd, undefined]);
         const encipher = getLatestEncipher(clearStream, encKeyProvider, alg, 1, 1, cc.ICOUNT_MIN, {
            startSize: 64,
            maxSize: 256,
         });

         // Read the generated salt before encrypting because the encipher then purges it
         const slt = encKeyProvider.getCipherDataInfo().slt.slice(0);
         const block0 = await encipher.encryptBlock();
         const block1 = await encipher.encryptBlock();

         const makeKP = (encrypting: boolean): PWDKeyProvider => {
            const kp = new PWDKeyProvider(userCred.slice(0), [pwd, undefined]);
            encrypting &&
               kp.setCipherDataInfo({ ver: cc.CURRENT_VERSION, alg, ic: cc.ICOUNT_MIN, slt, lp: 1, lpEnd: 1 });
            return kp;
         };

         function block1WithAlg(algName: cc.CipherAlgs): Uint8Array {
            const blockNAD = block1.parts[1].slice(0);
            blockNAD.set(numToBytes(Ciphers.algId(algName), cc.ALG_BYTES), cc.FLAGS_BYTES);
            return blockNAD;
         }

         async function reforge(blockNAD: Uint8Array): Promise<Uint8Array> {
            const [emptyStream] = streamFromBytes(new Uint8Array(0));
            const reforger = new EncipherV8(makeKP(true), new BYOBStreamReader(emptyStream));
            reforger['_lastMac'] = block0.parts[0].slice(0, cc.MAC_BYTES);
            const headerN = await reforger._createHeader(block1.parts[2], blockNAD);
            return concatArrays([...block0.parts, headerN, blockNAD, block1.parts[2]]);
         }

         // Control. Write the original algorithm back through the same path so a failure
         // below is isolated to the Alg change
         let [cipherStream] = streamFromBytes(await reforge(block1WithAlg(alg)));
         const controlDec = await getStreamDecipher(cipherStream, makeKP(false));
         await expect(controlDec.decryptBlock0()).resolves.toEqual(clearData.subarray(0, 64));
         await expect(controlDec.decryptBlockN()).resolves.toEqual(clearData.subarray(64, 64 + 128));

         const swapped = Ciphers.algs().find((other) => other !== alg) as cc.CipherAlgs;
         [cipherStream] = streamFromBytes(await reforge(block1WithAlg(swapped)));
         const forgedDec = await getStreamDecipher(cipherStream, makeKP(false));
         await expect(forgedDec.decryptBlock0()).resolves.toEqual(clearData.subarray(0, 64));
         await expect(forgedDec.decryptBlockN()).rejects.toThrow(/Invalid block algorithm/);
      }
   });

   it('round trip block0, all algorithms', async () => {
      for (const alg of Ciphers.algs()) {
         const [clearStream, clearData] = streamFromStr('This is a secret 🦆');
         const pwd = 'a good pwd';
         const hint = 'not really';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

         // Counted because assertions inside a provider that is never asked for a password
         // would silently pass
         let encPwdCount = 0;
         const encKeyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
            encPwdCount += 1;
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
         let decPwdCount = 0;
         const decKeyProvider = new PWDKeyProvider(userCred, async (cdinfo) => {
            decPwdCount += 1;
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
         expect(encPwdCount).toBe(1);
         expect(decPwdCount).toBe(1);
      }
   });

   it('concurrent getCipherDataInfo and decryptBlock0 share one decode', async () => {
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

   it('getCipherDataInfo is safe to call concurrently after first decode', async () => {
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

   async function roundTripBlockN(makeKP: () => KeyProvider, ic: number) {
      for (const alg of Ciphers.algs()) {
         let [clearStream, clearData] = streamFromStr('This is a secret 🦀');

         const readStart = 12;
         let encKeyProvider = makeKP();
         let latest = getLatestEncipher(clearStream, encKeyProvider, alg, 1, 1, ic, {
            startSize: readStart,
         });

         await expect(latest.encryptBlockN()).rejects.toThrow(/Encipher invalid state/);

         // once invalidated, it stays that way...
         await expect(latest.encryptBlock0()).rejects.toThrow(/Encipher invalid state.+/);

         [clearStream] = streamFromBytes(clearData);
         encKeyProvider = makeKP();
         latest = getLatestEncipher(clearStream, encKeyProvider, alg, 1, 1, ic, { startSize: readStart });

         const block0 = await latest.encryptBlock0();
         const blockN = await latest.encryptBlockN();

         let [cipherStream] = streamFromCipherBlock([block0, blockN]);
         let decipher = await getStreamDecipher(cipherStream, makeKP());

         let decb0 = await decipher.decryptBlock0();
         await expect(areEqual(decb0, clearData.slice(0, readStart))).resolves.toEqual(true);

         const decb1 = await decipher.decryptBlockN();
         await expect(areEqual(decb1, clearData.slice(readStart))).resolves.toEqual(true);

         // Try with block0 head copied to block N
         const badBlockN = {
            ...blockN,
         };
         badBlockN.parts[0] = block0.parts[0];

         [cipherStream] = streamFromCipherBlock([block0, badBlockN]);
         decipher = await getStreamDecipher(cipherStream, makeKP());

         decb0 = await decipher.decryptBlock0();
         await expect(areEqual(decb0, clearData.slice(0, readStart))).resolves.toEqual(true);
         await expect(decipher.decryptBlockN()).rejects.toThrow(/Cipher data length mismatch2/);
      }
   }

   it('round trip blockN, all algorithms, PWDKeyProvider', async () => {
      const pwd = 'a not good pwd';
      const hint = 'sorta';
      const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

      const makePwdKP = () => {
         let counter = 0;
         return new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
            counter += 1;
            expect(counter).toEqual(1);
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, hint];
         });
      };

      roundTripBlockN(makePwdKP, cc.ICOUNT_MIN);
   });

   it('round trip blockN, all algorithms, PWDKeyProvider with custom AD', async () => {
      const pwd = 'a not good pwd';
      const hint = 'sorta';
      const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));
      const extraKeyMaterial = getRandom(10);

      const makePwdKP = () => {
         let counter = 0;
         return new PWDKeyProvider(
            userCred.slice(0),
            async (cdinfo) => {
               counter += 1;
               expect(counter).toEqual(1);
               expect(cdinfo.lp).toEqual(1);
               expect(cdinfo.lpEnd).toEqual(1);
               return [pwd, hint];
            },
            extraKeyMaterial,
         );
      };

      roundTripBlockN(makePwdKP, cc.ICOUNT_MIN);
   });

   it('round trip blockN, all algorithms, MasterKeyKeyProvider', async () => {
      const masterKey = crypto.getRandomValues(new Uint8Array(cc.KEY_BYTES));

      const makeMasterKP = () => {
         return new MasterKeyKeyProvider(masterKey.slice(0));
      };

      roundTripBlockN(makeMasterKP, 0);
   });

   it('round trip blockN, all algorithms, MasterKeyKeyProvider with custom AD', async () => {
      const masterKey = crypto.getRandomValues(new Uint8Array(cc.KEY_BYTES));

      const makeMasterKP = () => {
         return new MasterKeyKeyProvider(masterKey.slice(0), 'some-user-id');
      };

      roundTripBlockN(makeMasterKP, 0);
   });

   it('custom AD is bound even though it is absent from the ciphertext', async () => {
      const userCred = getRandom(cc.USERCRED_BYTES);
      const masterKey = getRandom(cc.KEY_BYTES);
      const adOne = getRandom(10);
      const adTwo = getRandom(10);

      const providers = [
         {
            ic: cc.ICOUNT_MIN,
            make: (extraKeyMaterial: Uint8Array<ArrayBuffer>) =>
               new PWDKeyProvider(userCred.slice(0), ['a good pwd', undefined], extraKeyMaterial),
         },
         {
            ic: 0,
            make: (extraKeyMaterial: Uint8Array<ArrayBuffer>) =>
               new MasterKeyKeyProvider(masterKey.slice(0), extraKeyMaterial),
         },
      ];

      for (const alg of Ciphers.algs()) {
         for (const { ic, make } of providers) {
            const [clearStream, clearData] = streamFromStr('A block0 secret 🦫');
            const encipher = getLatestEncipher(clearStream, make(adOne), alg, 1, 1, ic);
            const cipherBytes = concatArrays((await encipher.encryptBlock()).parts);

            let [cipherStream] = streamFromBytes(cipherBytes);
            const sameDec = await getStreamDecipher(cipherStream, make(adOne));
            await expect(sameDec.decryptBlock0()).resolves.toEqual(clearData);

            [cipherStream] = streamFromBytes(cipherBytes);
            const otherDec = await getStreamDecipher(cipherStream, make(adTwo));
            await expect(otherDec.decryptBlock0()).rejects.toThrow(/Invalid MAC/);
         }
      }
   });
});

describe('Decryption known values', () => {
   const userCredBytes = [
      58, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98,
      180, 61, 166, 219, 54, 164, 55,
   ];
   let userCred: Uint8Array<ArrayBuffer>;

   beforeEach(async () => {
      await cryptoReady();
      userCred = new Uint8Array(userCredBytes);
   });

   it('correct cipherdata info and decryption, v4', async () => {
      const [_, clearData] = streamFromStr('A nice 🦫 came to say hello');
      const pwd = 'a 🌲 of course';
      const hint = '🌧️';
      const [cipherStream] = streamFromBytes(
         new Uint8Array([
            117, 163, 250, 117, 59, 97, 3, 10, 139, 12, 55, 161, 115, 52, 28, 105, 246, 126, 220, 0, 129, 151, 165, 136,
            46, 97, 163, 160, 91, 9, 189, 218, 4, 0, 116, 0, 0, 0, 2, 0, 16, 242, 98, 46, 102, 223, 79, 227, 209, 73,
            22, 207, 92, 80, 75, 125, 125, 234, 18, 21, 88, 64, 43, 68, 25, 193, 133, 31, 159, 156, 8, 184, 10, 164, 33,
            46, 20, 159, 218, 222, 64, 119, 27, 0, 0, 23, 5, 135, 172, 203, 4, 101, 163, 155, 133, 221, 40, 227, 91,
            222, 227, 213, 97, 77, 24, 117, 60, 188, 27, 153, 253, 134, 10, 112, 75, 76, 146, 132, 123, 217, 7, 171,
            211, 24, 206, 186, 248, 244, 119, 18, 165, 195, 59, 160, 76, 31, 90, 80, 53, 19, 39, 143, 99, 141, 109, 68,
            72, 63, 121, 199, 96, 95, 157, 81,
         ]),
      );

      const keyProvider = new PWDKeyProvider(userCred, async (cdinfo) => {
         expect(cdinfo.hint).toEqual(hint);
         expect(cdinfo.lp).toEqual(1);
         expect(cdinfo.lpEnd).toEqual(1);
         expect(cdinfo.alg).toBe('X20-PLY');
         expect(cdinfo.ic).toBe(1800000);
         expect(cdinfo.ver).toEqual(cc.VERSION4);
         expect(
            isEqualArray(
               cdinfo.slt,
               new Uint8Array([25, 193, 133, 31, 159, 156, 8, 184, 10, 164, 33, 46, 20, 159, 218, 222]),
            ),
         ).toBe(true);
         return [pwd, undefined];
      });
      const decipher = await getStreamDecipher(cipherStream, keyProvider);
      const cdInfo = await decipher.getCipherDataInfo();

      expect(cdInfo.alg).toEqual('X20-PLY');
      expect(cdInfo.ic).toEqual(1800000);
      expect(
         isEqualArray(
            cdInfo.slt,
            new Uint8Array([25, 193, 133, 31, 159, 156, 8, 184, 10, 164, 33, 46, 20, 159, 218, 222]),
         ),
      ).toBe(true);
      expect(cdInfo.ver).toEqual(cc.VERSION4);
      expect(cdInfo.hint).toEqual(hint);

      await expect(decipher.decryptBlock0()).resolves.toEqual(clearData);
   });

   it('correct cipherdata info and decryption, v5', async () => {
      const [_, clearData] = streamFromStr('A nice 🦫 came to say hello');
      const pwd = 'a 🌲 of course';
      const hint = '🌧️';
      const [cipherStream] = streamFromBytes(
         new Uint8Array([
            166, 123, 188, 183, 212, 97, 47, 147, 59, 39, 78, 222, 101, 74, 221, 53, 27, 11, 194, 67, 156, 235, 116,
            104, 65, 64, 76, 166, 29, 220, 71, 179, 5, 0, 116, 0, 0, 1, 2, 0, 121, 78, 37, 8, 192, 196, 110, 22, 164,
            106, 59, 161, 122, 165, 176, 147, 49, 43, 41, 250, 163, 111, 218, 4, 174, 61, 6, 169, 145, 216, 66, 166,
            139, 82, 19, 207, 29, 75, 105, 149, 64, 119, 27, 0, 0, 23, 93, 92, 56, 163, 242, 71, 208, 3, 190, 44, 140,
            222, 149, 159, 152, 193, 162, 44, 177, 93, 197, 119, 131, 88, 92, 53, 108, 167, 253, 64, 216, 200, 121, 212,
            193, 153, 180, 39, 92, 35, 142, 6, 240, 115, 51, 211, 198, 63, 12, 126, 128, 206, 178, 114, 65, 37, 246,
            197, 19, 79, 58, 96, 56, 86, 172, 162, 217, 70,
         ]),
      );

      const keyProvider = new PWDKeyProvider(userCred, async (cdinfo) => {
         expect(cdinfo.hint).toEqual(hint);
         expect(cdinfo.lp).toEqual(1);
         expect(cdinfo.lpEnd).toEqual(1);
         expect(cdinfo.alg).toBe('X20-PLY');
         expect(cdinfo.ic).toBe(1800000);
         expect(cdinfo.hint).toEqual(hint);
         expect(cdinfo.ver).toEqual(cc.VERSION5);
         expect(
            isEqualArray(
               cdinfo.slt,
               new Uint8Array([174, 61, 6, 169, 145, 216, 66, 166, 139, 82, 19, 207, 29, 75, 105, 149]),
            ),
         ).toBe(true);
         return [pwd, undefined];
      });
      const decipher = await getStreamDecipher(cipherStream, keyProvider);
      const cdInfo = await decipher.getCipherDataInfo();

      expect(cdInfo.alg).toEqual('X20-PLY');
      expect(cdInfo.ic).toEqual(1800000);
      expect(
         isEqualArray(
            cdInfo.slt,
            new Uint8Array([174, 61, 6, 169, 145, 216, 66, 166, 139, 82, 19, 207, 29, 75, 105, 149]),
         ),
      ).toBe(true);
      expect(cdInfo.ver).toEqual(cc.VERSION5);
      expect(cdInfo.hint).toEqual(hint);

      await expect(decipher.decryptBlock0()).resolves.toEqual(clearData);
      await expect(decipher.decryptBlockN()).resolves.toEqual(new Uint8Array(0));
   });

   it('correct cipherdata info and decryption, multi version', async () => {
      const [_, clearData] = streamFromStr('A nice 🦫 came to say hello');
      const pwd = 'a 🌲 of course';
      const hint = '🌧️';

      const vers = [
         //v6
         {
            ver: 6,
            cts: {
               'AES-GCM':
                  'F4qYlclmVWQD5IayN_Ub_3pQ7N91gNZzLGi8Iu_sIbkGAGAAAAABAMrZN-Xbi9Kvdpcl2k5pFxC_07E33BkQ-QlqxchAdxsAABfm9OTNhim0krfh9ZLGyi7yDGB-oB4gScok1BFuD5UcpZEj44VRQWVD8kCX-fD_t4VRbXXcgYiz1TOGFz5nsobA3jkhROi53GPsJiSiW18yy3A73-eETAgZjQfeBgAoAAABAQD1T3bCnKPA38DHIMBWWXsv7H2fFBJ9DjIPimYghk6CJdS5IXME',
               'X20-PLY':
                  'PkeGHkLso1abo-aBE93x_e69rJb6OrW-STBAAwDxbRQGAGwAAAACANIwjwvIQLygUdSpdbfKw83iAo126tZL0VgOnatOaYIfOXGuBj5hEGhAdxsAABfIUjubZ9H30GHKKissSmSWyblIHejAG_IPbxEjFyiOrgndOJuISt5vqJhmTJlRWoc_1683Ku3T0MkHtw24Je54qsYzl4TKzwqvSvMhL56c2g2hIVF6TuB4Cr97BgA0AAABAgAT-DRYec2-zEvMw50PxYgwmdvcJoHH01QMlf_4rV01LzigH2KFr9VaKQASTWU7310c',
               'AEGIS-256':
                  'XRa5nS7wJ8DLF6HWZyP2MWfeAS4PyHUYzkd67AaMUfYGAJQAAAADAJey272VOwM55vXW_P2rEudCgPSRwGB5nAjF7gmnc5AA46rTvby4Wv_R6l6eH0UNQUB3GwAAJ_K3cZg5LpRqUy83VmoXe1KwPHh3wkGbEes_qRTu7vrNvz_saJVP0ajB6xDxZYs5RhHb9yl2GWxtkLpqkhN6N2pxtAKF2a_LjknVWeIRN_jxn-LqzwkuI-Lz4Pm0OeGEwl7bfOvP8qftV8UztFNlwmGxOA_nIu_KmWG6CwYATAAAAQMA_n0RaJelAb_JLnaUUtlQrgBaG7_wcwL4lplkWi3V_Uo3V9pkIHvDj6Jvgy58blIx5yGQHa96GTx_0U3_0w38vAaiupLQGf4Ibw',
            },
         },
         //v7 — generated by: pnpm vectors:ciphers
         {
            ver: 7,
            cts: {
               'AES-GCM':
                  '3RtQ2aZ5ixzjgr6DxGkFY9fQ4es0i7BN7viHs_NRhycHAGAAAAABAGwl6yWJLE3HurXPIzhqSuMdlqWn8PhayXAOsk9AdxsAABdqM5RNpIpWZjynqxlrwxERvouymkdAfqt4YsnJet-edPValHzd0CS-VQaDblCREU6lf-OpdrGXDnVAQAw13xv30PnNmetOg9p7ZvbBnl-I6tI0U0dq09j4rl0VBwAoAAABAQBSW9DbcNEsLbXctETgJGeNHjr8PcSiMjq0LzYptoKf95oJq3Z5',
               'X20-PLY':
                  'RYLHRk8poPlrnc4T23oBLnvFMWOn4NmTZMOu64rgOsMHAGwAAAACAFQN9gQhN3bD5gsRVaVB_Cb2krlV1DmP8oVYBsSaVhh0yDZ5Ja2LC29AdxsAABftzQHFMLcr3uhEk2mll1flYGPsZ7m_Y98zCaGFxpCKK-iqBTPa5GfT9itn0Tt4fWxuuTfOtHQKzit3R3Ep6VZZWZEwSgByQy_5J_UA-bTMlolsmZZN0oUP41DlBwA0AAABAgAqF_8F2bLMxCDyhvb4KnlhkhvfIKIG4JzcRZ3r1z_1ZLxaV0RynaB3c15f3utPezlA',
               'AEGIS-256':
                  'Ikd9XNQvhtfo5NCNgq2yKi-g_NQt4cH6aPQ3c8HyzU0HAJQAAAADAAsJ-GygmL4nz-wJHtnp-Mn-kow1As8sqUmLnkIvyohj1S87gLhGP_2I6_BkR-cFvkB3GwAAJ3MCMWiB_UDWR5eiPJ_eOxe0nQHHkctrcPFKZxy9wX4r-AEEKroXsN2kX6oggAqkqjqWW5aRSQsCh6jkoi8HjKoWIbsTXxGTJFKPff6jH62XBD6x7Vv7NO5c3UvcvvtFwdfl4VkOok6C90xXyqhfcm0BCUiZ46eJeCIIjgcATAAAAQMACQnEdmejMsWyUPAJ8Y7m4isdeoRkIJea71myATpKuvQCMkS0WOHoIzrisYTdJXd7s4jH_t5JYtmhPgmBuR7TNLiOPC4RWq1FEw',
            },
         },
         //v8 — generated by: pnpm vectors:ciphers
         {
            ver: 8,
            cts: {
               'AES-GCM':
                  '5WTNC-lyNSsFrD9EE0KiS5KAgMr1c0-0yOTo34khxLgIAIEAAAABAJ9wWZr8QqzldpU6CUpaiJo7jouUDUFL1rXRHGRAdxsAABe1uuPmeC1MIENW_vqnqTaLo81crRnOliAIelajjp5Cqad55TOheTO7VtiZvSoD7ZEvVb3XO7YrBlfXMl3UZm1Ch0F6Jcqbdxowow3kEwKck28P7jrvA3yaUAt1a1CB4-hMdbr_m0yhII-fTO0vPulI26-8vG78KdddSWdVCAAoAAABAQAAPVWORMFgh5WUovu0ztlWMyQy-1Go05xdNHu3j4pbOb8VzVti',
               'X20-PLY':
                  'WsAK62TEy04ffWXQs2TDQphagL5NobAJRHOwXUJcYXQIAI0AAAACADDqx5KoAGLhWWsJmg48Hqt9wj2YxscvYbxXxPMjHUIY9JUV5DUjb4xAdxsAABdDh-rYbdurKmnd5pk6X7RXYpVcNbeUKCBwogeg8S5jD_1l_XPa4oygsQP6i3TCBkUljRgFeQdf0DXmf5Tog8yNfWd8MoFgHd1hzkskwLvZSIKZdLAza2Mp-nDjqqvHvf2HyoG2r3CH2WLlmbvai4mCz1WiFtk8U_YG3Z2RCAA0AAABAgAemEikVE2ivh7L9YM9Z-eyKZqK_EK3Afkh6GQ-GFZOMWwRDGd34C8PDjtgg6s-TYV4',
               'AEGIS-256':
                  'PPZPaCDDZlnFgTlgD2rOHzZf9BTmEEXRidCSH49d-NIIALUAAAADABqRb2N_ZklBBTfyhQKKElNjBaP9UdqLYrJ8YH23aGEn6BErjzPtnz8WnN-sNDOKPEB3GwAAJzv7onjozssZX3S8XfNhQbGW3HpmyQ7Zfbci9HGFAVqTfT3kltZpfiDowa8gZTLbmnicy15WJYBPSM-mdpzmmBTKQ3MPjPR_f4PNNDcAoV4LkO-AoTLDRIT0Wja26U498_-lvR9iWK5ZFc-SR2YGGd5BPmrgGRce36G9OOv3m0A8LoC9uxm6M0TqCBMkxh26D9qzZ35OUO1pcfhp-ggATAAAAQMAMgVkIQnh6kzeuR4p6P2FMDoKqy5IEVVnfKWquziUcOHnc7h3HFH1Js1dHssBF66GwjdKkCCwk4QuizFqFa0TrpyghgIg_954xw',
            },
         },
      ];

      const userCred = new Uint8Array([
         58, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98,
         180, 61, 166, 219, 54, 164, 55,
      ]);
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

   it('missing terminal block indicator, v5', async () => {
      const [_, clearData] = streamFromStr('A nice 🦫 came to say hello');
      const pwd = 'a 🌲 of course';
      const hint = '🌧️';
      const [cipherStream] = streamFromBytes(
         new Uint8Array([
            225, 67, 20, 31, 134, 179, 27, 202, 138, 52, 68, 42, 197, 34, 48, 209, 76, 235, 39, 166, 101, 12, 253, 101,
            237, 25, 234, 119, 91, 227, 169, 172, 5, 0, 116, 0, 0, 0, 2, 0, 53, 140, 213, 212, 134, 206, 178, 102, 222,
            97, 207, 8, 252, 103, 8, 64, 25, 112, 206, 146, 159, 150, 220, 236, 162, 203, 172, 111, 119, 158, 192, 123,
            81, 141, 89, 174, 126, 4, 65, 105, 64, 119, 27, 0, 0, 23, 138, 253, 130, 153, 78, 2, 31, 195, 254, 142, 102,
            116, 200, 50, 125, 8, 178, 151, 113, 13, 205, 228, 10, 85, 83, 101, 57, 149, 191, 166, 4, 221, 153, 198, 0,
            18, 185, 165, 203, 53, 211, 218, 24, 198, 162, 13, 99, 240, 249, 210, 255, 200, 217, 232, 10, 187, 212, 92,
            204, 165, 217, 7, 202, 6, 114, 70, 200, 221,
         ]),
      );

      const keyProvider = new PWDKeyProvider(userCred, async (cdinfo) => {
         expect(cdinfo.hint).toEqual(hint);
         expect(cdinfo.lp).toEqual(1);
         expect(cdinfo.lpEnd).toEqual(1);
         expect(cdinfo.alg).toBe('X20-PLY');
         expect(cdinfo.ic).toBe(1800000);
         expect(cdinfo.ver).toEqual(cc.VERSION5);
         expect(
            isEqualArray(
               cdinfo.slt,
               new Uint8Array([162, 203, 172, 111, 119, 158, 192, 123, 81, 141, 89, 174, 126, 4, 65, 105]),
            ),
         ).toBe(true);
         return [pwd, undefined];
      });
      const decipher = await getStreamDecipher(cipherStream, keyProvider);
      const cdInfo = await decipher.getCipherDataInfo();

      expect(cdInfo.alg).toEqual('X20-PLY');
      expect(cdInfo.ic).toEqual(1800000);
      expect(
         isEqualArray(
            cdInfo.slt,
            new Uint8Array([162, 203, 172, 111, 119, 158, 192, 123, 81, 141, 89, 174, 126, 4, 65, 105]),
         ),
      ).toBe(true);
      expect(cdInfo.ver).toEqual(cc.VERSION5);
      expect(cdInfo.hint).toEqual(hint);

      // Although the cipherData for block0 above is missing the "terminal block" indicator,
      // that isn't detected until we hit the end of the file (below in blockN)
      await expect(decipher.decryptBlock0()).resolves.toEqual(clearData);
      await expect(decipher.decryptBlockN()).rejects.toThrow(/Missing terminal/);
   });

   it('missing terminal block indicator, multi version', async () => {
      const [_, clearData] = streamFromStr('A nice 🦫 came to say hello');
      const pwd = 'a 🌲 of course';
      const hint = '🌧️';

      const vers = [
         //v6
         {
            ver: 6,
            cts: {
               'AES-GCM':
                  'KIjAs5WAVq58nEVKZrLwqxgxMuZEtvfOzncNnPLZFMcGAGAAAAABADO2r-khoqGTJepwHcoQaJ_q7wIJVkeMwp4VJVNAdxsAABcUS4eu-pzXZVWsPBJTZFwQd8xCGb6JRPEAaHyNCtmH0s5zVBpgO0gqfD8TPHXqW-FQ0pHbAzmElgnjDdRYMM_TLrsuHVRsLtf-ddyjjeXv6LeeeX1ExbtaDaE9BgAoAAAAAQBdvvgBoMusZZO0E3CRS2zBfPNvOwLY-2hDMwgOQGpzWDRFQGGb',
               'X20-PLY':
                  'rPEwFYLr_WH3sIydgcLU29KNbXWSLtGKHCtFc5NdlKMGAGwAAAACAGKwcuUJZj8OVEdc4SyAMGHmDvaPBFvYq7j44fhHwsjA5GCauj6rMn1AdxsAABd_YgNSnyvPvbuXChCV7yAXv9E--ZrhXyOANRq8mr1R1BbmaEhY4oNzuaLqxfr2gFTvtjLBgZxOfhev1kA6HVx9SHdB6VnaOHyFX3v7zSQPnyo-TBRHCMOOaDtxBgA0AAAAAgDujN-I-TOuUWw7VFOdcx0NMpK6vc8rOqzmWFA_sfZRMpFrn8oN92L8utlAdTjjuFfT',
               'AEGIS-256':
                  'O8Y_5AfBakBc9UXPWLcgTtAsxopVkVmrzhEVlsgnhpAGAJQAAAADANAGQIgVn8JS4_-OekbG5INtC9sO-XnbCWVr9qSyAU5wteE2cI38YN6Je9KfMO8i_UB3GwAAJ5AtkgTlpq4a2LhCcWhE8X46S_FVF7wcvaTJ9rg4oz5xizPExQortEWXsMWCQFsVxjRqvcg2Co50wk3nPFdtdT7pFUuU-xA2k-GWcM7J49nvyhmS1o7TVrpvds4GTh4IYCTcu80eYh4Kq0KSSX2ipreuoVom5kBvA_F7RQYATAAAAAMASOhuM8YNbVyhW4SedzlAKRLXww9Is1ocJJOR3eQSVqZcspLI0RjCxG7lJ0rveEVf4pO0TvOKx9BLnoq3Xy65PrVzvmHSfm1lsA',
            },
         },
         //v7 — generated by: pnpm vectors:ciphers
         {
            ver: 7,
            cts: {
               'AES-GCM':
                  '4ytOyJUYfbj5X-KM1gCLpTLvgYRnDt2QXKVTP3yhAtEHAGAAAAABAPBmsbddTk3TGbnWGnJ9Yyt-9l4IJ7uz6sDm6lpAdxsAABeA51_DKPKxYjshFSRgYnTSeP34yeKJQTpzJjXrJqyAlpB2D7RjbukvWXRpF_blhH5cIEi_3Zge_y7y0x7SUlqYUAMrqmJfFc-2mgys6n-9MiesqJg57jDdWu2vBwAoAAAAAQBJIk0q45_dbXD3aI1Is8OZ-kYzdj72Lt7oTE-epJDFloyCA6DH',
               'X20-PLY':
                  'lg6RdE-QKb65Gp8zWPV95sJ5Gv4gQcvGmez2e8qXz14HAGwAAAACAMTRHGqXQhOTSjQ4hMjXtkLbgVAAQayhWQan60anPVpUg4Et0SoNk7xAdxsAABeZ5hr8qI3tFKo5l5Qzxr176xTTZvzeZRv4RiwTAXNGM9eik7sZuLBNTX7n0X3106SBpDdyZGhXizW9S8lxzzz5zBCSFHqFEeq906lNvP8hhFgcRMZOjpKzPuQKBwA0AAAAAgDd1Wv5AVT7D1arcJrYJvhYH32T-1euWuQxInG0tMaPXxbTL8sdulkHgh3YIg0IP9wn',
               'AEGIS-256':
                  'Z7wOOHsbrWHxuEVocLmZQCUjv4Bhnj-nwuYd3rtKPDQHAJQAAAADAENBfTMqkJRnF7O94Ia0mryEZ7d824e4cUm4cQ0bsbimjC2ibZlqjzdFWMVappX3z0B3GwAAJ5XIi_WF8lrpab5_Icli2jTRX82Zjr5W-7XGYWF6C0sK9CAwEMCyAcUhjzBYApBwf34g0VopUo041cAa1n1w9MNYwUMKT6_NbrsmoTNlR7-JO241DIbV3S1RKf--q4BH4ndbD4ZUNFT9QFUL8u3-YwgZ2Xp9W5Dds3S30gcATAAAAAMAD4GqlRwMH25MNOqk1yCEKAzllVZ_NUlWtWtJ-kuvntxu3ilO54biyrWOB1mV-DKqP_ryHJqX8bEBtbCaGqdpt4LQliThSkiT4Q',
            },
         },
         //v8 — generated by: pnpm vectors:ciphers
         {
            ver: 8,
            cts: {
               'AES-GCM':
                  'eTrk1SjeOlvvs6v4Hu6XtCauiKY_3a_7kWaQVrGt5P4IAIEAAAABAIrFc5cld8ia5ZUXfFYjJWBkNws_JTnLZWJ9BehAdxsAABfVGVM9DociwGarxRaifKpVGgCWuevhNCC_XZFBWkGFHRv9GKUsRth5EepIi2p9nsSZu-hPsxgw7BJ1ymmkGiO3Lh7o2alCAoATPtLDIRQz1hh_yp-wyxRVugY9fZld1uqC3IChaH2DMvAMRREQyCOO67fmkegAE_4W2YnJCAAoAAAAAQDWEOtP-e8l5Jptwid1DXwlV_dLm69TQ9wOdT-0mzQ4P4eXSnva',
               'X20-PLY':
                  'utUQY9649SkDvEzgdUUJUrHx8nB6b7fOlhvdyXdbVbIIAI0AAAACAJu29Qv6r_Pm0OAC8RpMyf4GF8XIQQv5JtxfbTz8c1m981AL0mU9EKJAdxsAABc_5f0X-BIW0xTpkBjPntdh0QpOfx4AeiBPPvjTBM64LQBwXa1B4H8F6msS1Cw2398-RBkvfJ1CxIghkgAQbBV9NCWN9m54waptKg-RBGIhW9yxv7TmXsH9Usr0pa4tuDgvemAiLTwlxCmu6kiAWzZrRe25UyHHk48D1iuuCAA0AAAAAgB9YcUcUWihdnndBqhyfxum_A1c8CCKMC2dhZVyTZMaDPYR7PatDg-OeiTkYZNibB_U',
               'AEGIS-256':
                  'kIs1fdZyAc3LsYc8L-2o75mBL1QvoyZZNuHc3e1RjxUIALUAAAADANh1rqRqftpVdltmd3-lD-0WNcJAjbByW0flt2dEtgXgF5s7KtVNYQ-QX0PU5xsDiUB3GwAAJ-cK8Refq2nlz2knf9Fj-RQdX1oyXVZBpIbb5bJk-3W4-stnWtm_2iCQiC5l_QCrTeoNgVfKx0-logaBhcZKkAdpcbxCqvpbBqJGI9DloN6oPWwcWJcL8TUUZ1UVqYyFobeK2GOd-VdeX-YBCc2APGdNM9rxDeCMfAuWmgTlTf9tWS1Ynj2SMwN1YobABTqAhL7XF9SlgXOVzmiRRQgATAAAAAMA3aHWotS426M_JgHHlobRi1wOv5-bH41uGagtxctPE-Dvty9pFW8CqZ6QxNitgdndP5WZTYIhpdIXL-hIikWw71Tc0ZZXTjkdxQ',
            },
         },
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

   it('extra terminal block indicator, multi version', async () => {
      const [_, clearData] = streamFromStr('A nice 🦫 came to say hello');
      const pwd = 'a 🌲 of course';
      const hint = '🌧️';

      const vers = [
         //v6
         {
            ver: 6,
            cts: {
               'AES-GCM':
                  'mxQYSs5jS2yLP9UoVPL5Umg7_aVQ0Kohu9sM6u0AWjUGAGAAAAEBADUjCDDpJymFQGrtlpcLXrv-FayLZ8GrNTn1MtRAdxsAABe8NtaKQ2wbkt7ZdPI2NkArzYT-r1fUJujQQVU3scbYxSZBhqfp8rljM-WWfdSx20UeVViyBdonxlrdCz99LJDBxGnluk0tTGs3pU8paRrXUs7jui8pUHP7QvW8BgAoAAABAQAzT5VH4MLNFnuxVW7a-ZjEvcRzQBPRd3-cfCFf8R4v7dR95Hx5',
               'X20-PLY':
                  '4oGG7bf2iwqs1Ljsc85yIYK9Tekk4AO1rupAqeobkfQGAGwAAAECACU7WFzBfSFXioJOUtFt9cwt2nmYyx_vbvduORUE-6KnHykmq0kotERAdxsAABfCS4X16NT1XKJs1_2LwbhN0qMedP46qVvJ8Bwy2Nx_15r-_Dai_Xtr4ozjU232a4hUv1_PIKVTEu8VU4F2DUNSz8SlVg5yLI8MSQxKcJGAt84v854geBjlAJvWBgA0AAABAgA7ZDI86mqgxANzrbFkdrqovb6cC9W07QSzcRXHUqokonBGpHMPInYj0K4vlp2s11p4',
               'AEGIS-256':
                  'BCBMTk_hVOi0MGzUZCkxWbC7ABcKigcsyhDLC3vz9QwGAJQAAAEDAGvAtgrTFpTgoiUU65LY8CHoD43gXSr64jim1HL7_fosH_NnlBh7CS6KSvVNoRYCekB3GwAAJ7jfBXuOoOdXFFvfJxF1rUP2pctiszIRA5dA4VtlKBATAeM3WlArwwxE0bg09nDxEBxGJTU1cunJtv-PTDBf65ELq6EtzUV89Nf2I-p1O2unHboiALilVfc0tJVUnh8YLUK0V72BCi3shY17jGgObiTMBBYtlh8KTLmCQAYATAAAAQMAekEOxoUB-qEhhqOPS1flXIygThAgFLJGWecj9hHGfMcwh-D8Rcmy6o7LU_VdFNULC-TORjXevyeClQAfSPnSH0578riwrIqoQA',
            },
         },
         //v7 — generated by: pnpm vectors:ciphers
         {
            ver: 7,
            cts: {
               'AES-GCM':
                  'zSEorQFuLCxjYL1qPQgpGHf5JbpLVV6u363w3yszjx8HAGAAAAEBACTxNU4enr6vCcA6-Rtp2E5MszgtgeV3xY7cqdBAdxsAABcVxifi57tjuvstLC8zWehVlMVRyCD35tR_Jev3vMo-nQEkxjGaQa_yFhbEGccht8vaWROI99vEwTfZbrS_Id6BAk9qI41Uk62FH4CWukOVBf4fIEt0XHGgSuurBwAoAAABAQDZwQWm7NikoXR48TuY__Vj-bY4Zm1IioyrUNp4uQ5a_6BqiFMj',
               'X20-PLY':
                  'SXjlsoTcruJVMG9GBSNq7lrscEb975x2zek_fAK-lEUHAGwAAAECALAZFlI5Neq_QSu2c6SuJCDzkIJ2sV7xqOMiokXH3x1lNEkGjuWWaKpAdxsAABcKdTSjzjkLdHMmLDRwMtMiLOmBweEfY6C5fKyI3rN-sW54c0UCjdlOLIgvQM1a5prxljMzpmcLBhNx4TQKAenOEwf_vSwcUYTAw11gJdTHUq_vBzESJAlzNJESBwA0AAABAgBNDofAUNfbUBn4utbV8wx7hepbrOn0UDX23CR-5ySLOKQhke8Pk6Bx3s9DEVhbSpPb',
               'AEGIS-256':
                  'o9c6sk_m1Xfm3xdYbSwQi50oYq4acFVjeZFJ15B5Q6kHAJQAAAEDAHeGF6QGO4ZugN20lDIaTZuTy-dYR1L4LGHdo3jn3LP92H2_0motVm3FwTurpBovYkB3GwAAJ2gWjSvLF0kDgVbu063jbNJ5S46PRUrg1eiCVWF2o-fEhodlg7yDTVFfbMIPR_9hbUHbsUENF9HL3asSg6w2KL45Yp0rDHPN8BO-G34L9XIvYU1k7-vVb70fq3os8LpYKBmdhoqeYvQLtH1YAxh3-9_p_5tqDy275YoHhAcATAAAAQMAMBgnTlyeUBBw8_spEhh84TUtezZO4S3W2KZMNm02bgfIKL02ZMFEiNz_FsMeC3HDaKKjO7a_pVLQhFAxywLG2KAQYN2fQo9uNw',
            },
         },
         //v8 — generated by: pnpm vectors:ciphers
         {
            ver: 8,
            cts: {
               'AES-GCM':
                  'pUwFtH2ZNX6Rk1wemXtwD1oV569w3Yjgl-9EciGJq5YIAIEAAAEBAJ1w3Kz4NSXD22b0xfaDLj2JI9NNOSIeaqA0V-5AdxsAABe9l86FCe9Pmnc1u45iEob28MW5mxv7VSBzlK2cvUxDItcn0mSTPSYk4uSB6DKnIeOL0fQqesF6X_QMf-cQnKyrQxEV_1LmJr9nZMnQaRlOXcVYFdw4FJ5RSfNkIjHU2MLgepx9uuXDw9DeUN0qesVkWuhn2aVg_G-j4TM0CAAoAAABAQCIwtOdBSLCRx9jjTzDGqvcczBcWzEZf-5EdTyIfMXkHKIh7Gi6',
               'X20-PLY':
                  'yvZcJgv1_QL7YHFNOpO8FEG2c2Bf9qZudQrNnO7Sx6EIAI0AAAECAGZdj2QwtInQmI4TYkPmpQFoRb9NRDQaS3-DyOJCnxHI5PgGKmvzGV5AdxsAABflQ4fTYAHz7s9u_QuGOuHZZEh3ZgQWAiCsLgPzLx-EI-rr6GTocVEvIIyTqGWtHPCv4B8YJhMxgnY9fAJiNihx8IMTstT4qp9QQGh0sfDQQhfop3JA2kIT7ShlOpnB1nc2bbzl4zDJx96YF00_pzAku85v1NjfQ92wplaTCAA0AAABAgAJnX5drJx3kVmQvEt2votP4loCmHU1Ao_jLqWEKCDIL1Li0XAJmCFh9BiMAf8HjuGP',
               'AEGIS-256':
                  'ojJuRkE72yqz3iMPi91rlF4vi9H0So3UrJHft1sLbCYIALUAAAEDACyLEkhfQ7dgjcBxewa-wwsc88wgk-c6aE0ydH2pzcwBgcCK_WZmqwhllAdm3aRV5UB3GwAAJw4AQYZ-B8Dvjlhz8segHJu4BzxCmAoW-lRgPqXqXqJF1ZCP2kzWpiD1Ua3ySf-Lxgq__Wgz1i_GZw6WgUMdVr3JjUc3IQDwIl1mo9U5GQKmLlS0NqpJ7EYqaJrmom_yGz9soaOF6ZwIPWziyUJUZnNWqjZp3tCyx9Bm2iJ1N1DXUZ13If0K4w0Hpd9JvBXcsjEW9F2DoeSYV9bfNwgATAAAAQMALR6AHhEHHufTa5SfD5PGMd3_47Bg-iLa_5NAbTur0wM-sEx0mjrf8NYxGyoP6VKKu-AV8O_5YBQqLxeXmRoDry7_mhhX0DQExA',
            },
         },
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

   it('flipped terminal block indicator, multi version', async () => {
      const [_, clearData] = streamFromStr('A nice 🦫 came to say hello');
      const pwd = 'a 🌲 of course';
      const hint = '🌧️';

      const vers = [
         //v6
         {
            ver: 6,
            cts: {
               'AES-GCM':
                  'zL-JSCGd1aRZUnPt9TYI8TxqyK2GOqXc1PPfgZ_moFcGAGAAAAEBAPnRpCPk1D7tTfVKhZxcBk83-vdpkFimVg_prmRAdxsAABeoHcob5QcQ7PGB4ZDscl-M2H1bCwnDvnciwPUCtwS_CJuOi-GXSHohqkthBR7Ep8FBnPVv4IfiXZ47LyDMTUBHrfnu7h1uXFBc6HhmjKVqPDzZxvDgSQiGtbZiBgAoAAAAAQCYbD7O11e8YfHzbrAic5RRZRI4G8zn6ZAqn2a-nbjkihLHoM8c',
               'X20-PLY':
                  'bP3w_P0Y9OoqnmwmWQRa9_pCnQyJgq7FWvSNyQQJXXYGAGwAAAECAPdKsJxFPHOxKLdM5ly8HUikZOiXDIKmfJUKqA6ZQzuQLcyks8wHVU9AdxsAABcHrl_B4pkZTPTqgTLTyMN-GiFJGLBgLidfafyJ9OI3zM-CM7Bt4VqxqZzx2HlPB96z0XJKIWYA0_E0UjxBGNmAT3Dlm_cecMIcDTjphcy_Yb0QfCT3-wIoOml3BgA0AAAAAgDL0Bcr0EpFvqc9nVANaFwv6LOPykWvtq_QFhg4-dj-GXp3w4kYQsEklQc2OOHEAF7Q',
               'AEGIS-256':
                  'z_wjYRYc3RAXYpAaXvU2V3BCWYno0y6Kh0pVcUjZl3kGAJQAAAEDAGcCoTiOwDrN12pPfW5eUpz5g45AFyspWIwlZMXN1ioRp4_dUdl3IhjK_Wqlb3CePkB3GwAAJ7o9Tijp5eLpL6N_0V-ruVh61s6GmtRq8j5FE3LS6D5K-Y9uH9BZ1GI8UMkGNsAfnfMArB8cj4R7lRVo1HjqOX4j15b3FEU3ROwMWmNl7Zp77CN4023BH7JzlPzen7M_DyMsa7qiBrVF8GV-6f577Sv6xpFsUVweZRED_wYATAAAAAMAQ7fPqOQtec-v1wNMzhL5V5s8XNQ194ef7xLIn4oNjZF6FWKLsvQ65lt0psTKmu-f2e3qcU93LwWx7qs3JZDI1KFhB-kvb0vQQQ',
            },
         },
         //v7 — generated by: pnpm vectors:ciphers
         {
            ver: 7,
            cts: {
               'AES-GCM':
                  'GpdHJCHuwS2s3KpYFEZpCMdj8xFncn_BOfbKgRpFIHMHAGAAAAEBAER0ZdNjoxQRkiLbLJYy78tLzlb1kJjnm0HFQGpAdxsAABfQOfDj80dozj0AUvxnqL2Bu4R_uQYsGt5SJo5EpZxyQ-zfq0i5B8cSg6pvs85VBS4FQR1trMqEwnX9lzGI54egP3TiY3mlEMTvrMj4ZNUDkOE91mjNMsl1kBi2BwAoAAAAAQAykYi3nUaRAg7ghX2_rniJTj7YBkWOQLA_9V_NJXA7Lwp8-XJ2',
               'X20-PLY':
                  'Jkvrz4C15BdDg_9oBm6pgFm56ecs4tee0d6te7Et_OgHAGwAAAECAGvIJZrf-on48Ndm2CN-uJa8kIeHrhsyhFuRhifhka1rAcKDkmcgVeNAdxsAABfI3LxJrftbz0f0w2A5UWgqFTrrtWgPePX9yqZ8cOz1f2Mni6kZvZ6uEAsmEdJaEq-M8Nxl0RuQViecT1RnsjYarTkaoMQwoZAHtFPQm0eyNq_Zns2WAZOezfy6BwA0AAAAAgARg5FWhE4U40cpfXt7FSK1g8rEyzEgNMcsysXq4UyxNBkXt0r9euUJLCCp0RPUQUvJ',
               'AEGIS-256':
                  'Q_foMbKP8JJnzmfmEiJN7_U29v2gm6S4uWvVAhJrT9wHAJQAAAEDAKUqQR3gDPXvwfLTiktkSi2bkHCAaLGQ0-7ExX1zKZlYSa7VdWxa_N4Of5HsGxOFekB3GwAAJ_egRknJkeWIuesGWjr9HW41u9P5n1k1oaCs_tWXe8csWxq_PXOI486X8-6cuWB4-72YidIx2-3mEv_BjruEXvbhXloPXa5m7g17uY8RfnrXxYIqnOaTpaXt6tJvfs5FZXU4Q2DDMc3Vw4cFVVz_S9aDfSJVX2BFgYhzrgcATAAAAAMAM5V16GUy2nF86DgwI801GgcPg1oobQ2me8MVclqcEBD8geH7XPEnuHeR3NE8papsGfdp2OdK0Y0KoE6620ZJD_-fNPN3yGkRhQ',
            },
         },
         //v8 — generated by: pnpm vectors:ciphers
         {
            ver: 8,
            cts: {
               'AES-GCM':
                  'ARimbkiBV4dgciApyw1wPJZSITioZM_S1_eQGKEjOcYIAIEAAAEBAEdGgKuYDnZt99zSVm7PYGFd6KeqOkufLz8NOxpAdxsAABf03-vLbNx_eZsyd9O8Uhj5b0wbIV0QXyAJFYEprzy8HGR2vKE15SBGQzLJkqqZOU57q-oHpJLFzXYtkqxOTn4BBd2_y5P8jO8Gsy7MrzVQy3_jkvt4tYJoxtSHC5DOODO8UpzuTx_A_nlQoDsk27cXqVVcSbmKe7LOW_fFCAAoAAAAAQCosF6oHNosAumrs1LhxAekOcTTO-WFlEBYT1Sduvuf0Nq3hF2X',
               'X20-PLY':
                  'yAtwEyLMG77F8J1F6XRfZ9LdRhZJYtWJsjG0B7a53_AIAI0AAAECAFfYK4tSs85B-ddxUupS3fpQFUydiSTnqyIbQDFkVM-iceLUB1exiY9AdxsAABeEb3Uu-yG3OmbXsTDbfuZYQ__7QUP_gSBFhRWx-arx782kwsk79CQHim55plgkqW2wu-q1sEcbfQOdoQpGcQSXkeHT3x1_95i8_GmEvr27N9tHRBdcLgmMuKml44aQ0UEPEIX0L9M8XxnxgnuVz6ZS-w4IMI-YoinKfOHnCAA0AAAAAgAoVJg1rh00cZwMy2IUAXVAeBZttWgD0IyNUH9e0hVXuKTaO5yCmagpTwmkuCkKSVhl',
               'AEGIS-256':
                  'aTgxgI4rrWR9Lul5VjiutIZnFAnhhOw15u-n3WKdkMAIALUAAAEDAKItraXUWeaORBDcLOWEzbpuIsvxbTtyRY3o0ZQTjcNs3xhO5z8gQEvqt1Rlkw8bYkB3GwAAJ7e37nJ4PmAAT2u8JkS3obtr81-a5W3nuG_156TYu-_E9rmfMIi9DiC0PPapNMsNXK7qHZUOPf6JBcVcC5Qc5_XuQyoo12cHh3esj2wZvi19FNC_u6HgM0P2sccMbeFSHYuu7pOK0DCssKJjtBMEMlzeox1s0nNsEw3d0sPghtDz73mFQqsYUN-Oqpj7DdDlB0aU4lmcBrdHJxdl1AgATAAAAAMAMKdeBvgL7gXJMf4jalTtKuHSNMeIaHfXBA6W4at6Fn-cnucIYL_0fUZlirtPF0oyPU0DuOw1u9olGfk3mrPjMT_Tkk_A2ZXk_Q',
            },
         },
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

   it('bad pwd to cipherdata info and decrypt, v4', async () => {
      const [_, clearData] = streamFromStr('A nice 🦫 came to say hello');
      const pwdGood = 'a 🌲 of course';
      const pwdBad = 'a 🌵 of course';
      const userCredBad = new Uint8Array([
         0, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98,
         180, 61, 166, 219, 54, 164, 55,
      ]);

      // copied from "correct cipherdata info and decryption" spec above
      const userCredGood = new Uint8Array([
         58, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98,
         180, 61, 166, 219, 54, 164, 55,
      ]);

      let [cipherStream, cipherData] = streamFromBytes(
         new Uint8Array([
            117, 163, 250, 117, 59, 97, 3, 10, 139, 12, 55, 161, 115, 52, 28, 105, 246, 126, 220, 0, 129, 151, 165, 136,
            46, 97, 163, 160, 91, 9, 189, 218, 4, 0, 116, 0, 0, 0, 2, 0, 16, 242, 98, 46, 102, 223, 79, 227, 209, 73,
            22, 207, 92, 80, 75, 125, 125, 234, 18, 21, 88, 64, 43, 68, 25, 193, 133, 31, 159, 156, 8, 184, 10, 164, 33,
            46, 20, 159, 218, 222, 64, 119, 27, 0, 0, 23, 5, 135, 172, 203, 4, 101, 163, 155, 133, 221, 40, 227, 91,
            222, 227, 213, 97, 77, 24, 117, 60, 188, 27, 153, 253, 134, 10, 112, 75, 76, 146, 132, 123, 217, 7, 171,
            211, 24, 206, 186, 248, 244, 119, 18, 165, 195, 59, 160, 76, 31, 90, 80, 53, 19, 39, 143, 99, 141, 109, 68,
            72, 63, 121, 199, 96, 95, 157, 81,
         ]),
      );
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
      await expect(decipher.decryptBlock0()).rejects.toThrow(/Decipher invalid.+/);

      // Test wrong userCred with block decrypt first (error msg is different)
      [cipherStream] = streamFromBytes(cipherData);
      keyProvider = new PWDKeyProvider(userCredBad.slice(0), [pwdGood, undefined]);
      decipher = await getStreamDecipher(cipherStream, keyProvider);

      await expect(decipher.decryptBlock0()).rejects.toThrow(/Invalid MAC.+/);
   });

   it('bad pwd to cipherdata info and decrypt, v5', async () => {
      const [_, clearData] = streamFromStr('A nice 🦫 came to say hello');
      const pwdGood = 'a 🌲 of course';
      const pwdBad = 'a 🌵 of course';
      const userCredBad = new Uint8Array([
         0, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98,
         180, 61, 166, 219, 54, 164, 55,
      ]);

      // copied from "correct cipherdata info and decryption" spec above
      const userCredGood = new Uint8Array([
         58, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98,
         180, 61, 166, 219, 54, 164, 55,
      ]);

      let [cipherStream, cipherData] = streamFromBytes(
         new Uint8Array([
            166, 123, 188, 183, 212, 97, 47, 147, 59, 39, 78, 222, 101, 74, 221, 53, 27, 11, 194, 67, 156, 235, 116,
            104, 65, 64, 76, 166, 29, 220, 71, 179, 5, 0, 116, 0, 0, 1, 2, 0, 121, 78, 37, 8, 192, 196, 110, 22, 164,
            106, 59, 161, 122, 165, 176, 147, 49, 43, 41, 250, 163, 111, 218, 4, 174, 61, 6, 169, 145, 216, 66, 166,
            139, 82, 19, 207, 29, 75, 105, 149, 64, 119, 27, 0, 0, 23, 93, 92, 56, 163, 242, 71, 208, 3, 190, 44, 140,
            222, 149, 159, 152, 193, 162, 44, 177, 93, 197, 119, 131, 88, 92, 53, 108, 167, 253, 64, 216, 200, 121, 212,
            193, 153, 180, 39, 92, 35, 142, 6, 240, 115, 51, 211, 198, 63, 12, 126, 128, 206, 178, 114, 65, 37, 246,
            197, 19, 79, 58, 96, 56, 86, 172, 162, 217, 70,
         ]),
      );
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
      await expect(decipher.decryptBlock0()).rejects.toThrow(/Decipher invalid state.+/);
   });

   it('bad pwd to cipherdata info and decrypt, multi version', async () => {
      const [_, clearData] = streamFromStr('A nice 🦫 came to say hello');
      const pwdGood = 'a 🌲 of course';
      const pwdBad = 'a 🌵 of course';
      const userCredBad = new Uint8Array([
         0, 28, 170, 106, 54, 250, 156, 83, 166, 217, 142, 101, 57, 57, 8, 146, 23, 55, 184, 6, 133, 242, 197, 43, 98,
         180, 61, 166, 219, 54, 164, 55,
      ]);

      const vers = [
         //v6
         {
            ver: 6,
            cts: {
               'AES-GCM':
                  'F4qYlclmVWQD5IayN_Ub_3pQ7N91gNZzLGi8Iu_sIbkGAGAAAAABAMrZN-Xbi9Kvdpcl2k5pFxC_07E33BkQ-QlqxchAdxsAABfm9OTNhim0krfh9ZLGyi7yDGB-oB4gScok1BFuD5UcpZEj44VRQWVD8kCX-fD_t4VRbXXcgYiz1TOGFz5nsobA3jkhROi53GPsJiSiW18yy3A73-eETAgZjQfeBgAoAAABAQD1T3bCnKPA38DHIMBWWXsv7H2fFBJ9DjIPimYghk6CJdS5IXME',
               'X20-PLY':
                  'PkeGHkLso1abo-aBE93x_e69rJb6OrW-STBAAwDxbRQGAGwAAAACANIwjwvIQLygUdSpdbfKw83iAo126tZL0VgOnatOaYIfOXGuBj5hEGhAdxsAABfIUjubZ9H30GHKKissSmSWyblIHejAG_IPbxEjFyiOrgndOJuISt5vqJhmTJlRWoc_1683Ku3T0MkHtw24Je54qsYzl4TKzwqvSvMhL56c2g2hIVF6TuB4Cr97BgA0AAABAgAT-DRYec2-zEvMw50PxYgwmdvcJoHH01QMlf_4rV01LzigH2KFr9VaKQASTWU7310c',
               'AEGIS-256':
                  'XRa5nS7wJ8DLF6HWZyP2MWfeAS4PyHUYzkd67AaMUfYGAJQAAAADAJey272VOwM55vXW_P2rEudCgPSRwGB5nAjF7gmnc5AA46rTvby4Wv_R6l6eH0UNQUB3GwAAJ_K3cZg5LpRqUy83VmoXe1KwPHh3wkGbEes_qRTu7vrNvz_saJVP0ajB6xDxZYs5RhHb9yl2GWxtkLpqkhN6N2pxtAKF2a_LjknVWeIRN_jxn-LqzwkuI-Lz4Pm0OeGEwl7bfOvP8qftV8UztFNlwmGxOA_nIu_KmWG6CwYATAAAAQMA_n0RaJelAb_JLnaUUtlQrgBaG7_wcwL4lplkWi3V_Uo3V9pkIHvDj6Jvgy58blIx5yGQHa96GTx_0U3_0w38vAaiupLQGf4Ibw',
            },
         },
         //v7 — generated by: pnpm vectors:ciphers
         {
            ver: 7,
            cts: {
               'AES-GCM':
                  '3RtQ2aZ5ixzjgr6DxGkFY9fQ4es0i7BN7viHs_NRhycHAGAAAAABAGwl6yWJLE3HurXPIzhqSuMdlqWn8PhayXAOsk9AdxsAABdqM5RNpIpWZjynqxlrwxERvouymkdAfqt4YsnJet-edPValHzd0CS-VQaDblCREU6lf-OpdrGXDnVAQAw13xv30PnNmetOg9p7ZvbBnl-I6tI0U0dq09j4rl0VBwAoAAABAQBSW9DbcNEsLbXctETgJGeNHjr8PcSiMjq0LzYptoKf95oJq3Z5',
               'X20-PLY':
                  'RYLHRk8poPlrnc4T23oBLnvFMWOn4NmTZMOu64rgOsMHAGwAAAACAFQN9gQhN3bD5gsRVaVB_Cb2krlV1DmP8oVYBsSaVhh0yDZ5Ja2LC29AdxsAABftzQHFMLcr3uhEk2mll1flYGPsZ7m_Y98zCaGFxpCKK-iqBTPa5GfT9itn0Tt4fWxuuTfOtHQKzit3R3Ep6VZZWZEwSgByQy_5J_UA-bTMlolsmZZN0oUP41DlBwA0AAABAgAqF_8F2bLMxCDyhvb4KnlhkhvfIKIG4JzcRZ3r1z_1ZLxaV0RynaB3c15f3utPezlA',
               'AEGIS-256':
                  'Ikd9XNQvhtfo5NCNgq2yKi-g_NQt4cH6aPQ3c8HyzU0HAJQAAAADAAsJ-GygmL4nz-wJHtnp-Mn-kow1As8sqUmLnkIvyohj1S87gLhGP_2I6_BkR-cFvkB3GwAAJ3MCMWiB_UDWR5eiPJ_eOxe0nQHHkctrcPFKZxy9wX4r-AEEKroXsN2kX6oggAqkqjqWW5aRSQsCh6jkoi8HjKoWIbsTXxGTJFKPff6jH62XBD6x7Vv7NO5c3UvcvvtFwdfl4VkOok6C90xXyqhfcm0BCUiZ46eJeCIIjgcATAAAAQMACQnEdmejMsWyUPAJ8Y7m4isdeoRkIJea71myATpKuvQCMkS0WOHoIzrisYTdJXd7s4jH_t5JYtmhPgmBuR7TNLiOPC4RWq1FEw',
            },
         },
         //v8 — generated by: pnpm vectors:ciphers
         {
            ver: 8,
            cts: {
               'AES-GCM':
                  '5WTNC-lyNSsFrD9EE0KiS5KAgMr1c0-0yOTo34khxLgIAIEAAAABAJ9wWZr8QqzldpU6CUpaiJo7jouUDUFL1rXRHGRAdxsAABe1uuPmeC1MIENW_vqnqTaLo81crRnOliAIelajjp5Cqad55TOheTO7VtiZvSoD7ZEvVb3XO7YrBlfXMl3UZm1Ch0F6Jcqbdxowow3kEwKck28P7jrvA3yaUAt1a1CB4-hMdbr_m0yhII-fTO0vPulI26-8vG78KdddSWdVCAAoAAABAQAAPVWORMFgh5WUovu0ztlWMyQy-1Go05xdNHu3j4pbOb8VzVti',
               'X20-PLY':
                  'WsAK62TEy04ffWXQs2TDQphagL5NobAJRHOwXUJcYXQIAI0AAAACADDqx5KoAGLhWWsJmg48Hqt9wj2YxscvYbxXxPMjHUIY9JUV5DUjb4xAdxsAABdDh-rYbdurKmnd5pk6X7RXYpVcNbeUKCBwogeg8S5jD_1l_XPa4oygsQP6i3TCBkUljRgFeQdf0DXmf5Tog8yNfWd8MoFgHd1hzkskwLvZSIKZdLAza2Mp-nDjqqvHvf2HyoG2r3CH2WLlmbvai4mCz1WiFtk8U_YG3Z2RCAA0AAABAgAemEikVE2ivh7L9YM9Z-eyKZqK_EK3Afkh6GQ-GFZOMWwRDGd34C8PDjtgg6s-TYV4',
               'AEGIS-256':
                  'PPZPaCDDZlnFgTlgD2rOHzZf9BTmEEXRidCSH49d-NIIALUAAAADABqRb2N_ZklBBTfyhQKKElNjBaP9UdqLYrJ8YH23aGEn6BErjzPtnz8WnN-sNDOKPEB3GwAAJzv7onjozssZX3S8XfNhQbGW3HpmyQ7Zfbci9HGFAVqTfT3kltZpfiDowa8gZTLbmnicy15WJYBPSM-mdpzmmBTKQ3MPjPR_f4PNNDcAoV4LkO-AoTLDRIT0Wja26U498_-lvR9iWK5ZFc-SR2YGGd5BPmrgGRce36G9OOv3m0A8LoC9uxm6M0TqCBMkxh26D9qzZ35OUO1pcfhp-ggATAAAAQMAMgVkIQnh6kzeuR4p6P2FMDoKqy5IEVVnfKWquziUcOHnc7h3HFH1Js1dHssBF66GwjdKkCCwk4QuizFqFa0TrpyghgIg_954xw',
            },
         },
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
            await expect(decipher.decryptBlock0()).resolves.toEqual(clearData.slice(0, 20));

            // Ensure bad password fails. From v8 the stored key commitment rejects the
            // wrong cipher key before the AEAD is reached
            [cipherStream] = streamFromBytes(cipherData);
            keyProvider = new PWDKeyProvider(userCred.slice(0), [pwdBad, undefined]);
            decipher = await getStreamDecipher(cipherStream, keyProvider);
            await expect(decipher.decryptBlock0()).rejects.toThrow(
               ver >= cc.VERSION8 ? /key commitment/ : DOMException,
            );

            // Test wrong userCred
            [cipherStream] = streamFromBytes(cipherData);
            keyProvider = new PWDKeyProvider(userCredBad.slice(0), [pwdGood, undefined]);
            decipher = await getStreamDecipher(cipherStream, keyProvider);
            await expect(decipher.getCipherDataInfo()).rejects.toThrow(/MAC/);

            // Does not get MAC error because the decipher instance is now in a
            // bad state and will remain so... forever...
            await expect(decipher.decryptBlock0()).rejects.toThrow(/Decipher invalid state.+/);
         }
      }
   });
});

describe('Custom AD encryption and decryption', () => {
   beforeEach(async () => {
      await cryptoReady();
   });

   it('round trip block0, all algorithms with extraKeyMaterial', async () => {
      for (const alg of Ciphers.algs()) {
         const [clearStream, clearData] = streamFromStr('This is a secret 🦆');
         const pwd = 'a good pwd';
         const hint = 'not really';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));
         const extraKeyMaterial = crypto.getRandomValues(new Uint8Array(52));

         const encKeyProvider = new PWDKeyProvider(
            userCred.slice(0),
            async (cdinfo) => {
               expect(cdinfo.alg).toEqual(alg);
               expect(cdinfo.slt.byteLength).toEqual(cc.SLT_BYTES);
               expect(cdinfo.ic).toBe(cc.ICOUNT_MIN);
               expect(cdinfo.lp).toEqual(1);
               expect(cdinfo.lpEnd).toEqual(1);
               expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
               return [pwd, hint];
            },
            extraKeyMaterial,
         );
         const latest = getLatestEncipher(clearStream, encKeyProvider, alg, 1, 1, cc.ICOUNT_MIN);
         const block0 = await latest.encryptBlock0();

         const [cipherStream] = streamFromCipherBlock([block0]);
         const decKeyProvider = new PWDKeyProvider(
            userCred,
            async (cdinfo) => {
               expect(cdinfo.alg).toEqual(alg);
               expect(cdinfo.slt.byteLength).toEqual(cc.SLT_BYTES);
               expect(cdinfo.ic).toBe(cc.ICOUNT_MIN);
               expect(cdinfo.hint).toEqual(hint);
               expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
               return [pwd, undefined];
            },
            extraKeyMaterial,
         );
         const decipher = await getStreamDecipher(cipherStream, decKeyProvider);

         const decrypted = await decipher.decryptBlock0();
         await expect(areEqual(decrypted, clearData)).resolves.toEqual(true);
      }
   });

   it('round trip blockN, all algorithms with extraKeyMaterial', async () => {
      for (const alg of Ciphers.algs()) {
         const [clearStream, clearData] = streamFromStr('This is a secret 🦀');
         const pwd = 'a not good pwd';
         const hint = 'sorta';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));
         const extraKeyMaterial = crypto.getRandomValues(new Uint8Array(223));

         const readStart = 12;
         const encKeyProvider = new PWDKeyProvider(
            userCred.slice(0),
            async (cdinfo) => {
               expect(cdinfo.lp).toEqual(1);
               expect(cdinfo.lpEnd).toEqual(1);
               return [pwd, hint];
            },
            extraKeyMaterial,
         );
         const latest = getLatestEncipher(clearStream, encKeyProvider, alg, 1, 1, cc.ICOUNT_MIN, {
            startSize: readStart,
         });

         const block0 = await latest.encryptBlock0();
         const blockN = await latest.encryptBlockN();

         const [cipherStream] = streamFromCipherBlock([block0, blockN]);
         const decKeyProvider = new PWDKeyProvider(
            userCred,
            async (cdinfo) => {
               expect(cdinfo.lp).toEqual(1);
               expect(cdinfo.lpEnd).toEqual(1);
               return [pwd, undefined];
            },
            extraKeyMaterial,
         );
         const decipher = await getStreamDecipher(cipherStream, decKeyProvider);

         const decb0 = await decipher.decryptBlock0();
         await expect(areEqual(decb0, clearData.slice(0, readStart))).resolves.toEqual(true);

         const decb1 = await decipher.decryptBlockN();
         await expect(areEqual(decb1, clearData.slice(readStart))).resolves.toEqual(true);
      }
   });

   it('round trip block0, all algorithms missing extraKeyMaterial', async () => {
      for (const alg of Ciphers.algs()) {
         const [clearStream, _clearData] = streamFromStr('This is a secret 🦆');
         const pwd = 'a good pwd';
         const hint = 'not really';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));
         const extraKeyMaterial = crypto.getRandomValues(new Uint8Array(52));

         const encKeyProvider = new PWDKeyProvider(
            userCred.slice(0),
            async (cdinfo) => {
               expect(cdinfo.alg).toEqual(alg);
               expect(cdinfo.slt.byteLength).toEqual(cc.SLT_BYTES);
               expect(cdinfo.ic).toBe(cc.ICOUNT_MIN);
               expect(cdinfo.lp).toEqual(1);
               expect(cdinfo.lpEnd).toEqual(1);
               expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
               return [pwd, hint];
            },
            extraKeyMaterial,
         );
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

   it('round trip block0, all algorithms added extraKeyMaterial', async () => {
      for (const alg of Ciphers.algs()) {
         const [clearStream, _clearData] = streamFromStr('This is a secret 🦆');
         const pwd = 'a good pwd';
         const hint = 'not really';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));
         const extraKeyMaterial = crypto.getRandomValues(new Uint8Array(52));

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
         const decKeyProvider = new PWDKeyProvider(
            userCred,
            async (cdinfo) => {
               expect(cdinfo.alg).toEqual(alg);
               expect(cdinfo.slt.byteLength).toEqual(cc.SLT_BYTES);
               expect(cdinfo.ic).toBe(cc.ICOUNT_MIN);
               expect(cdinfo.hint).toEqual(hint);
               expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
               return [pwd, undefined];
            },
            extraKeyMaterial,
         );
         const decipher = await getStreamDecipher(cipherStream, decKeyProvider);

         await expect(decipher.decryptBlock0()).rejects.toThrow(/Invalid MAC/);
      }
   });

   it('round trip block0, all algorithms changed extraKeyMaterial', async () => {
      for (const alg of Ciphers.algs()) {
         const [clearStream, _clearData] = streamFromStr('This is a secret 🦆');
         const pwd = 'a good pwd';
         const hint = 'not really';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));
         const extraKeyMaterial = crypto.getRandomValues(new Uint8Array(52));

         const encKeyProvider = new PWDKeyProvider(
            userCred.slice(0),
            async (cdinfo) => {
               expect(cdinfo.alg).toEqual(alg);
               expect(cdinfo.slt.byteLength).toEqual(cc.SLT_BYTES);
               expect(cdinfo.ic).toBe(cc.ICOUNT_MIN);
               expect(cdinfo.lp).toEqual(1);
               expect(cdinfo.lpEnd).toEqual(1);
               expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
               return [pwd, hint];
            },
            extraKeyMaterial,
         );
         const latest = getLatestEncipher(clearStream, encKeyProvider, alg, 1, 1, cc.ICOUNT_MIN);
         const block0 = await latest.encryptBlock0();

         // modify extraKeyMaterial so it doesn't match what was used for encryption
         extraKeyMaterial[2] ^= 1;
         const [cipherStream] = streamFromCipherBlock([block0]);
         const decKeyProvider = new PWDKeyProvider(
            userCred,
            async (cdinfo) => {
               expect(cdinfo.alg).toEqual(alg);
               expect(cdinfo.slt.byteLength).toEqual(cc.SLT_BYTES);
               expect(cdinfo.ic).toBe(cc.ICOUNT_MIN);
               expect(cdinfo.hint).toEqual(hint);
               expect(cdinfo.ver).toEqual(cc.CURRENT_VERSION);
               return [pwd, undefined];
            },
            extraKeyMaterial,
         );
         const decipher = await getStreamDecipher(cipherStream, decKeyProvider);

         await expect(decipher.decryptBlock0()).rejects.toThrow(/Invalid MAC/);
      }
   });

   it('round trip blockN, all algorithms missing extraKeyMaterial', async () => {
      for (const alg of Ciphers.algs()) {
         const [clearStream, _clearData] = streamFromStr('This is a secret 🦀');
         const pwd = 'a not good pwd';
         const hint = 'sorta';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));
         const extraKeyMaterial = crypto.getRandomValues(new Uint8Array(123));

         const encKeyProvider = new PWDKeyProvider(
            userCred.slice(0),
            async (cdinfo) => {
               expect(cdinfo.lp).toEqual(1);
               expect(cdinfo.lpEnd).toEqual(1);
               return [pwd, hint];
            },
            extraKeyMaterial,
         );
         const latest = getLatestEncipher(clearStream, encKeyProvider, alg, 1, 1, cc.ICOUNT_MIN, { startSize: 12 });

         const block0 = await latest.encryptBlock0();
         const blockN = await latest.encryptBlockN();

         const [cipherStream] = streamFromCipherBlock([block0, blockN]);
         const decKeyProvider = new PWDKeyProvider(userCred, async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, undefined];
         });
         const decipher = await getStreamDecipher(cipherStream, decKeyProvider);

         await expect(decipher.decryptBlock0()).rejects.toThrow(/Invalid MAC/);
         await expect(decipher.decryptBlockN()).rejects.toThrow(/Decipher invalid state/);
      }
   });

   it('round trip blockN, all algorithms added extraKeyMaterial', async () => {
      for (const alg of Ciphers.algs()) {
         const [clearStream, _clearData] = streamFromStr('This is a secret 🦀');
         const pwd = 'a not good pwd';
         const hint = 'sorta';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));
         const extraKeyMaterial = crypto.getRandomValues(new Uint8Array(123));

         const encKeyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, hint];
         });
         const latest = getLatestEncipher(clearStream, encKeyProvider, alg, 1, 1, cc.ICOUNT_MIN, { startSize: 12 });

         const block0 = await latest.encryptBlock0();
         const blockN = await latest.encryptBlockN();

         const [cipherStream] = streamFromCipherBlock([block0, blockN]);
         const decKeyProvider = new PWDKeyProvider(
            userCred,
            async (cdinfo) => {
               expect(cdinfo.lp).toEqual(1);
               expect(cdinfo.lpEnd).toEqual(1);
               return [pwd, undefined];
            },
            extraKeyMaterial,
         );
         const decipher = await getStreamDecipher(cipherStream, decKeyProvider);

         await expect(decipher.decryptBlock0()).rejects.toThrow(/Invalid MAC/);
         await expect(decipher.decryptBlockN()).rejects.toThrow(/Decipher invalid state/);
      }
   });

   it('round trip blockN, all algorithms tampered extraKeyMaterial', async () => {
      for (const alg of Ciphers.algs()) {
         const [clearStream, _clearData] = streamFromStr('This is a secret 🦀');
         const pwd = 'a not good pwd';
         const hint = 'sorta';
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));
         const extraKeyMaterial = crypto.getRandomValues(new Uint8Array(123));

         const encKeyProvider = new PWDKeyProvider(
            userCred.slice(0),
            async (cdinfo) => {
               expect(cdinfo.lp).toEqual(1);
               expect(cdinfo.lpEnd).toEqual(1);
               return [pwd, hint];
            },
            extraKeyMaterial,
         );
         const latest = getLatestEncipher(clearStream, encKeyProvider, alg, 1, 1, cc.ICOUNT_MIN, { startSize: 12 });

         const block0 = await latest.encryptBlock0();
         const blockN = await latest.encryptBlockN();

         // modify extraKeyMaterial so it doesn't match what was used for encryption
         extraKeyMaterial[extraKeyMaterial.length - 1] ^= 1;
         const [cipherStream] = streamFromCipherBlock([block0, blockN]);
         const decKeyProvider = new PWDKeyProvider(
            userCred,
            async (cdinfo) => {
               expect(cdinfo.lp).toEqual(1);
               expect(cdinfo.lpEnd).toEqual(1);
               return [pwd, undefined];
            },
            extraKeyMaterial,
         );
         const decipher = await getStreamDecipher(cipherStream, decKeyProvider);

         await expect(decipher.decryptBlock0()).rejects.toThrow(/Invalid MAC/);
         await expect(decipher.decryptBlockN()).rejects.toThrow(/Decipher invalid state/);
      }
   });
});

describe('Detect changed cipher data', () => {
   beforeEach(async () => {
      await cryptoReady();
   });

   it('detect changed headerData', async () => {
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
         block0.parts[0][12] = block0.parts[0][12] === 123 ? 124 : 123;
         let [cipherStream] = streamFromCipherBlock([block0]);
         let decipher = await getStreamDecipher(cipherStream, makeDecKP());

         await expect(decipher.decryptBlock0()).rejects.toThrow(/Invalid MAC.+/);

         block0.parts[0] = new Uint8Array(savedHeader);
         [cipherStream] = streamFromCipherBlock([block0]);
         decipher = await getStreamDecipher(cipherStream, makeDecKP());

         await expect(decipher.decryptBlock0()).resolves.toEqual(clearData);

         // set version
         block0.parts[0][33] = block0.parts[0][33] === 43 ? 45 : 43;
         [cipherStream] = streamFromCipherBlock([block0]);

         await expect(
            getStreamDecipher(cipherStream, new PWDKeyProvider(userCred.slice(0), undefined)),
         ).rejects.toThrow(/Invalid version/);

         // set length
         block0.parts[0] = new Uint8Array(savedHeader);
         block0.parts[0][36] = block0.parts[0][36] === 43 ? 45 : 43;
         [cipherStream] = streamFromCipherBlock([block0]);
         decipher = await getStreamDecipher(cipherStream, makeDecKP());

         await expect(decipher.decryptBlock0()).rejects.toThrow(/Cipher data length mismatch+/);
      }
   });

   it('detect changed additionalData', async () => {
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

         const makeDecKP = () =>
            new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
               expect(cdinfo.lp).toEqual(1);
               expect(cdinfo.lpEnd).toEqual(1);
               return [pwd, undefined];
            });

         block0.parts[1][12] = block0.parts[1][12] === 123 ? 124 : 123;
         let [cipherStream] = streamFromCipherBlock([block0]);
         let decipher = await getStreamDecipher(cipherStream, makeDecKP());

         await expect(decipher.decryptBlock0()).rejects.toThrow(/.+MAC.+/);

         // Confirm we're back to good state
         block0.parts[1] = new Uint8Array(savedAD);
         [cipherStream] = streamFromCipherBlock([block0]);
         decipher = await getStreamDecipher(cipherStream, makeDecKP());

         await expect(decipher.decryptBlock0()).resolves.toEqual(clearData);

         // set byte near end
         const back = block0.parts[1].byteLength - 4;
         block0.parts[1][back] = block0.parts[1][back] === 43 ? 45 : 43;
         [cipherStream] = streamFromCipherBlock([block0]);
         decipher = await getStreamDecipher(cipherStream, makeDecKP());

         await expect(decipher.decryptBlock0()).rejects.toThrow(/.+MAC.+/);
      }
   });

   it('detect changed encryptedData', async () => {
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

         block0.parts[2][12] = block0.parts[2][12] === 123 ? 124 : 123;
         const [cipherStream] = streamFromCipherBlock([block0]);
         const decKeyProvider = new PWDKeyProvider(userCred, async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, undefined];
         });
         const decipher = await getStreamDecipher(cipherStream, decKeyProvider);

         await expect(decipher.decryptBlock0()).rejects.toThrow(/.+MAC.+/);
      }
   });

   it('does not detect changed headerData, skip MAC verify', async () => {
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
         block0.parts[0][12] = block0.parts[0][12] === 123 ? 124 : 123;
         const [cipherStream] = streamFromCipherBlock([block0]);
         const decKeyProvider = new PWDKeyProvider(userCred, async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, undefined];
         });
         const decipher = await getStreamDecipher(cipherStream, decKeyProvider);

         // Monkey patch to skip MAC validation
         //@ts-expect-error
         decipher['_verifyMAC'] = (): Promise<boolean> => {
            return Promise.resolve(true);
         };

         // This should succeed even though the MAC has been changed (because
         // MAC was not tested due to monkey patch)
         await expect(decipher.decryptBlock0()).resolves.toEqual(clearData);
      }
   });

   it('detect changed additionalData, skip MAC verify', async () => {
      for (const alg of Ciphers.algs()) {
         const [clearStream, _clearData] = streamFromStr('This is a secret 🦆');
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
         block0.parts[1][12] = block0.parts[1][12] === 123 ? 124 : 123;
         const [cipherStream] = streamFromCipherBlock([block0]);
         const decKeyProvider = new PWDKeyProvider(userCred, async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, undefined];
         });
         const decipher = await getStreamDecipher(cipherStream, decKeyProvider);

         // Monkey patch to skip MAC validation
         //@ts-expect-error
         decipher['_verifyMAC'] = (): Promise<boolean> => {
            return Promise.resolve(true);
         };

         // This should fail (even though MAC check wass skipped) because
         // AD check is part of all encryption algorithms. Note that this
         // should fail with DOMException rather than Error with MAC in message
         await expect(decipher.decryptBlock0()).rejects.toThrow(DOMException);
      }
   });

   it('detect changed encryptedData, skip MAC verify', async () => {
      for (const alg of Ciphers.algs()) {
         const [clearStream, _clearData] = streamFromStr('This is a secret 🦆');
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
         block0.parts[2][12] = block0.parts[2][12] === 123 ? 124 : 123;
         const [cipherStream] = streamFromCipherBlock([block0]);
         const decKeyProvider = new PWDKeyProvider(userCred, async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, undefined];
         });
         const decipher = await getStreamDecipher(cipherStream, decKeyProvider);

         // Monkey patch to skip MAC validation
         //@ts-expect-error
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

describe('Detect block order changes', () => {
   const pwd = 'a not good pwd';
   const hint = 'sorta';
   let userCred: Uint8Array<ArrayBuffer>;
   const clearStr = 'This is a secret 🦀 with extra wording for more blocks';

   beforeEach(async () => {
      await cryptoReady();
      userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));
   });

   async function get_blocks(alg: cc.CipherAlgs): Promise<[CipherDataBlock, CipherDataBlock, CipherDataBlock]> {
      const [clearStream] = streamFromStr(clearStr);

      const encKeyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
         expect(cdinfo.lp).toEqual(1);
         expect(cdinfo.lpEnd).toEqual(1);
         return [pwd, hint];
      });
      const latest = getLatestEncipher(clearStream, encKeyProvider, alg, 1, 1, cc.ICOUNT_MIN, { startSize: 12 });

      const block0 = await latest.encryptBlock0();
      const block1 = await latest.encryptBlockN();
      const block2 = await latest.encryptBlockN();

      return [block0, block1, block2];
   }

   it('block order good, all algorithms', async () => {
      const clearData = new TextEncoder().encode(clearStr);

      for (const alg of Ciphers.algs()) {
         const [block0, block1, block2] = await get_blocks(alg);

         // First make sure we can decrypt in the proper order
         const [cipherStream] = streamFromCipherBlock([block0, block1, block2]);
         const decKeyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, undefined];
         });
         const decipher = await getStreamDecipher(cipherStream, decKeyProvider);

         const decb0 = await decipher.decryptBlock0();
         const decb1 = await decipher.decryptBlockN();
         const decb2 = await decipher.decryptBlockN();

         const [decrypted] = streamFromBytes([decb0, decb1, decb2]);

         await expect(areEqual(decrypted, clearData)).resolves.toEqual(true);
      }
   });

   it('blockN bad order detected, all algorithms', async () => {
      const _clearData = new TextEncoder().encode(clearStr);

      for (const alg of Ciphers.algs()) {
         const [block0, block1, block2] = await get_blocks(alg);

         // Order of block N+ changed
         const [cipherStream] = streamFromCipherBlock([block0, block2, block1]);
         const decKeyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, undefined];
         });
         const decipher = await getStreamDecipher(cipherStream, decKeyProvider);

         const decb0 = await decipher.decryptBlock0();

         const partial = new TextDecoder().decode(decb0);
         expect(clearStr.startsWith(partial)).toBe(true);

         // In V4 this worked, but should fail in V5
         await expect(decipher.decryptBlockN()).rejects.toThrow(/Invalid MAC/);
      }
   });

   it('block0 bad order detected, all algorithms', async () => {
      const _clearData = new TextEncoder().encode(clearStr);

      for (const alg of Ciphers.algs()) {
         const [block0, block1, block2] = await get_blocks(alg);

         const [cipherStream] = streamFromCipherBlock([block1, block0, block2]);
         const decKeyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
            expect(cdinfo.lp).toEqual(1);
            expect(cdinfo.lpEnd).toEqual(1);
            return [pwd, undefined];
         });
         const decipher = await getStreamDecipher(cipherStream, decKeyProvider);

         // Will fail in V4 and later because block0 format or MAC is invalid.
         // Failure detection can happen at different spots while data is unpacked
         // since random values may look valid. MAC will alsways be
         // invalid if we get that far.
         await expect(decipher.decryptBlock0()).rejects.toThrow(/Invalid.+/);
      }
   });
});

describe('Inter-block MAC chaining', () => {
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
      slt: Uint8Array<ArrayBuffer>,
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
      const encipher = new EncipherV8(keyProvider, reader, { startSize: 12 });
      const block0 = await encipher.encryptBlock0();
      const block1 = await encipher.encryptBlockN();
      const block2 = await encipher.encryptBlockN();

      return [block0, block1, block2];
   }

   // Validates the splice test approach before it's used to assert failures.
   it('extract and concat round-trip succeeds, all algorithms', async () => {
      const clearData = new TextEncoder().encode(clearStr);
      for (const alg of Ciphers.algs()) {
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));
         const slt = crypto.getRandomValues(new Uint8Array(cc.SLT_BYTES));

         const blocks = await encryptThreeBlocks(alg, userCred, slt);
         const cipherBytes = concatArrays(blocks.flatMap((block) => block.parts));
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
   it('block spliced from a parallel stream fails MAC, all algorithms', async () => {
      for (const alg of Ciphers.algs()) {
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));
         const slt = crypto.getRandomValues(new Uint8Array(cc.SLT_BYTES));

         const [a0, , a2] = await encryptThreeBlocks(alg, userCred, slt);
         const [, b1] = await encryptThreeBlocks(alg, userCred, slt);

         // Splice: A's block0, B's block1, A's block2.
         const spliced = concatArrays([a0, b1, a2].flatMap((block) => block.parts));
         const [cipherStream] = streamFromBytes(spliced);

         const decKeyProvider = new PWDKeyProvider(userCred, [pwd, undefined]);
         const decipher = await getStreamDecipher(cipherStream, decKeyProvider);
         await expect(decipher.decryptBlock0()).resolves.not.toThrow();
         await expect(decipher.decryptBlockN()).rejects.toThrow(/Invalid MAC/);
      }
   });
});

describe('Key commitment', () => {
   beforeEach(async () => {
      await cryptoReady();
   });

   const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));

   function normalKeyProvider(): PWDKeyProvider {
      const keyProvider = new PWDKeyProvider(userCred.slice(0), ['a good pwd', undefined]);
      return keyProvider;
   }

   // Wraps a KeyProvider to tamper with the key commitment
   function tamperingKeyProvider(baseKeyProvider: PWDKeyProvider): PWDKeyProvider {
      const origGetKeyCommitment = baseKeyProvider.getKeyCommitment.bind(baseKeyProvider);
      baseKeyProvider.getKeyCommitment = async () => {
         const keyCommitment = await origGetKeyCommitment();
         const tamperedCommitment = keyCommitment.slice(0);
         tamperedCommitment[3] ^= 0x01;
         return tamperedCommitment;
      };
      return baseKeyProvider;
   }

   it('block0 decryption fails when commitment is tampered', async () => {
      for (const alg of Ciphers.algs()) {
         const [clearStream, clearData] = streamFromStr('A block0 secret 🦫');

         const encKeyProvider = normalKeyProvider();
         const encipher = getLatestEncipher(clearStream, encKeyProvider, alg, 1, 1, cc.ICOUNT_MIN);
         const block0 = await encipher.encryptBlock();
         const cipherBytes = concatArrays(block0.parts);

         // Control should succeeed
         let [cipherStream] = streamFromBytes(cipherBytes);
         const controlDec = await getStreamDecipher(cipherStream, normalKeyProvider());
         await expect(controlDec.decryptBlock0()).resolves.toEqual(clearData);

         [cipherStream] = streamFromBytes(cipherBytes);
         const tamperedDec = await getStreamDecipher(cipherStream, tamperingKeyProvider(normalKeyProvider()));
         await expect(tamperedDec.decryptBlock0()).rejects.toThrow(/key commitment/);
      }
   });

   // Later blocks carry no commitment of their own. Their keys derive from the root cipher
   // key, so a mismatch stops the stream at block0 and no later block is ever reached.
   it('multi-block decryption stops at block0 when commitment is tampered', async () => {
      for (const alg of Ciphers.algs()) {
         // Enough plaintext to produce a block1
         const plaintext = 'x'.repeat(2048);
         const [clearStream, clearData] = streamFromStr(plaintext);

         const encKeyProvider = normalKeyProvider();
         const encipher = getLatestEncipher(clearStream, encKeyProvider, alg, 1, 1, cc.ICOUNT_MIN, {
            startSize: 64,
            maxSize: 256,
         });
         const block0 = await encipher.encryptBlock();
         const block1 = await encipher.encryptBlock();
         const cipherBytes = concatArrays([block0, block1].flatMap((block) => block.parts));

         // Control should succeeed
         let [cipherStream] = streamFromBytes(cipherBytes);
         const controlDec = await getStreamDecipher(cipherStream, normalKeyProvider());
         await expect(controlDec.decryptBlock0()).resolves.toEqual(clearData.subarray(0, 64));
         await expect(controlDec.decryptBlockN()).resolves.toEqual(clearData.subarray(64, 64 + 128));

         [cipherStream] = streamFromBytes(cipherBytes);
         const tamperedDec = await getStreamDecipher(cipherStream, tamperingKeyProvider(normalKeyProvider()));
         await expect(tamperedDec.decryptBlock0()).rejects.toThrow(/key commitment/);

         // The stream is dead, so block1 is unreachable rather than merely undetected
         await expect(tamperedDec.decryptBlockN()).rejects.toThrow();
      }
   });
});

describe('Cipher internal state validation', () => {
   beforeEach(async () => {
      await cryptoReady();
   });

   it('less than one block of cleartext state check', async () => {
      for (const alg of Ciphers.algs()) {
         const readStart = 25;

         const [clearStream, clearData] = streamFromBytes(getRandom(readStart - 5));
         const pwd = 'a not good pwd';
         const userCred = getRandom(cc.USERCRED_BYTES);

         const encKeyProvider = new PWDKeyProvider(userCred.slice(0), [pwd, undefined]);
         const latest = getLatestEncipher(clearStream, encKeyProvider, alg, 1, 1, cc.ICOUNT_MIN, {
            startSize: readStart,
         });

         //@ts-expect-error
         expect(latest._state).toBe(CipherState.Initialized);

         const block0 = await latest.encryptBlock0();

         //@ts-expect-error
         expect(latest._state).toBe(CipherState.Finished);
         expect(latest.multiBlock).toBe(false);

         const decKeyProvider = new PWDKeyProvider(userCred.slice(0), [pwd, undefined]);

         const [cipherStream] = streamFromCipherBlock([block0]);
         const decipher = await getStreamDecipher(cipherStream, decKeyProvider);

         //@ts-expect-error
         expect(decipher._state).toBe(CipherState.Initialized);

         const decb0 = await decipher.decryptBlock0();
         await expect(areEqual(decb0, clearData)).resolves.toEqual(true);

         // Even though there are no more blocks, decryption doesn't detect until you read past the end
         //@ts-expect-error
         expect(decipher._state).toBe(CipherState.Block0Done);
         expect(() => decipher.multiBlock).toThrow(/not finished/);

         const decb1 = await decipher.decryptBlockN();
         await expect(areEqual(decb1, new Uint8Array(0))).resolves.toEqual(true);

         //@ts-expect-error
         expect(decipher._state).toBe(CipherState.Finished);
         expect(decipher.multiBlock).toBe(false);
      }
   });

   it('exactly one block of cleartext state check', async () => {
      for (const alg of Ciphers.algs()) {
         const readStart = 25;

         const [clearStream, clearData] = streamFromBytes(getRandom(readStart));
         const pwd = 'a not good pwd';
         const userCred = getRandom(cc.USERCRED_BYTES);

         const encKeyProvider = new PWDKeyProvider(userCred.slice(0), [pwd, undefined]);
         const latest = getLatestEncipher(clearStream, encKeyProvider, alg, 1, 1, cc.ICOUNT_MIN, {
            startSize: readStart,
         });

         //@ts-expect-error
         expect(latest._state).toBe(CipherState.Initialized);

         const block0 = await latest.encryptBlock0();

         // Exactly 1 block of cleartext results in two blocks due to terminal block addition
         //@ts-expect-error
         expect(latest._state).toBe(CipherState.Block0Done);

         const blockN = await latest.encryptBlockN();
         //@ts-expect-error
         expect(latest._state).toBe(CipherState.Finished);
         expect(latest.multiBlock).toBe(true);

         const decKeyProvider = new PWDKeyProvider(userCred.slice(0), [pwd, undefined]);

         const [cipherStream] = streamFromCipherBlock([block0, blockN]);
         const decipher = await getStreamDecipher(cipherStream, decKeyProvider);

         //@ts-expect-error
         expect(decipher._state).toBe(CipherState.Initialized);

         const decb0 = await decipher.decryptBlock0();
         await expect(areEqual(decb0, clearData)).resolves.toEqual(true);

         //@ts-expect-error
         expect(decipher._state).toBe(CipherState.Block0Done);
         expect(() => decipher.multiBlock).toThrow(/not finished/);

         const decb1 = await decipher.decryptBlockN();
         await expect(areEqual(decb1, new Uint8Array(0))).resolves.toEqual(true);

         //@ts-expect-error
         expect(decipher._state).toBe(CipherState.Finished);
         // The terminal block carries no clear text, but it is still a second block
         expect(decipher.multiBlock).toBe(true);
      }
   });

   it('greater than one block of cleartext state check', async () => {
      for (const alg of Ciphers.algs()) {
         const readStart = 25;

         const [clearStream, clearData] = streamFromBytes(getRandom(readStart + 5));
         const pwd = 'a not good pwd';
         const userCred = getRandom(cc.USERCRED_BYTES);

         const encKeyProvider = new PWDKeyProvider(userCred.slice(0), [pwd, undefined]);
         const latest = getLatestEncipher(clearStream, encKeyProvider, alg, 1, 1, cc.ICOUNT_MIN, {
            startSize: readStart,
         });

         //@ts-expect-error
         expect(latest._state).toBe(CipherState.Initialized);

         const block0 = await latest.encryptBlock0();

         //@ts-expect-error
         expect(latest._state).toBe(CipherState.Block0Done);

         const blockN = await latest.encryptBlockN();
         //@ts-expect-error
         expect(latest._state).toBe(CipherState.Finished);
         expect(latest.multiBlock).toBe(true);

         const decKeyProvider = new PWDKeyProvider(userCred.slice(0), [pwd, undefined]);

         const [cipherStream] = streamFromCipherBlock([block0, blockN]);
         const decipher = await getStreamDecipher(cipherStream, decKeyProvider);

         //@ts-expect-error
         expect(decipher._state).toBe(CipherState.Initialized);

         const decb0 = await decipher.decryptBlock0();
         await expect(areEqual(decb0, clearData.slice(0, readStart))).resolves.toEqual(true);

         //@ts-expect-error
         expect(decipher._state).toBe(CipherState.Block0Done);
         expect(() => decipher.multiBlock).toThrow(/not finished/);

         const decb1 = await decipher.decryptBlockN();
         await expect(areEqual(decb1, clearData.slice(readStart))).resolves.toEqual(true);

         // Even though there are no more blocks, decryption doesn't detect until you read past the end
         //@ts-expect-error
         expect(decipher._state).toBe(CipherState.Block0Done);

         const decb2 = await decipher.decryptBlockN();
         await expect(areEqual(decb2, new Uint8Array(0))).resolves.toEqual(true);

         //@ts-expect-error
         expect(decipher._state).toBe(CipherState.Finished);
         expect(decipher.multiBlock).toBe(true);
      }
   });
});

describe('Decryption known values, key providers and extra key material', () => {
   const pwd = 'a 🌲 of course';
   const hint = '🌧️';
   const userCred = base64ToBytes('Ohyqajb6nFOm2Y5lOTkIkhc3uAaF8sUrYrQ9pts2pDc=');
   const masterKey = base64ToBytes('TWFzdGVyS2V5Rml4ZWRTZWVkVmFsdWUwMTIzNDU2Nzg=');
   const extra = base64ToBytes('RXh0cmFLZXlNYXQ=');
   const otherExtra = base64ToBytes('T3RoZXJLZXlNYXQ=');

   beforeEach(async () => {
      await cryptoReady();
   });

   const vers = [
      //v7 — generated by apps/web/scripts/gen_v7_extra_vectors.ts run in a v7.5.0 checkout
      {
         ver: 7,
         pwdNoExtra: {
            'AES-GCM':
               'O716fvu8Nxuma64B8_5zDkzWZ8D_1IAMdn5YHCm7pqkHAGAAAAABAMJ8IP4mUxmggtd263Es2LGWzAcSSc3INCClW4FAdxsAABedVaBXEX41uQZpXFAIi7B93ueUhmbfTx194wsFjl47xNOGd7Cw0GL1UmZ2Vgz1-pmXifidlOrzkYI2oyGO1ccOcXR3QkQvQaa8_iaYL_pgCQSSwqmTEoLnd258BwAoAAABAQD3c7ZeHM0kVR1o_HLfGThSZE4agnYyVxThIrXFGd8hYR5jM9kG',
            'X20-PLY':
               '7mNqOdjmoZfUIlxtcrDsAKCRy_JltzQmQ74gQUvzhSAHAGwAAAACAA5u2MCwdI-r_SQ0bXFCuJ9ioVpiyHW0SQqXF58erTdKUguc2Y8ZUylAdxsAABfoPgEVY5TLSSA0qvHp0bmsbew2-Evmoc4nnRcCjSIXNK97_GudvEz9sPknkHToE7rYG5IVlFPlBUStzKJ5qlzXCL8GBR7JnhUmgWDWxppbKI13coxecu3sxAPfBwA0AAABAgASjp3UwYIX9AVM-eKFzhm3Hc12_e2ZEwATjlEWRUnSnrWf1ENguUhUXTBRyKQT1_Qp',
            'AEGIS-256':
               'bTJEz6FGTf81DW3JE94FivcYXIhg2199Y3eDsJ5w16UHAJQAAAADAPm9BlLKdrOlEOi_pUE-S37zk6Uqdv08cBaOvmre2BPa0MNjENOYpVOETlAwT5A8zkB3GwAAJ63Zwkmy6JJnfF_eldZlvoLxTjHW-PuG0GKRqxkNhoNbWEW9Ns1E4rccI7a6ZYL01G3QysQ8fZdXJoD4g8pw-7E1alFcaI0cE1G8TeAM0ge_BaiBUWw73Vut_5XUQgX4p5LrqzefhxxD0wRhxyG0pB9uj8auIYsCXDeWtAcATAAAAQMAD6BLONVIHIn-W1yMcm4zO6LaCRWWwmi8_7zPdb0-zCmqAcbpsCmyJfnH9go6qfZivxsbTCbktRPAg6dCgCzEElxQAMFuPgN7qQ',
         },
         pwdWithExtra: {
            'AES-GCM':
               '9MBxuzZj40C_HCt410lh5n_5T9qfiq_AN6DadQmHAikHAGAAAAABAJWvJUcGPntOqD8o-KLFkb7Ozzp3vCmNz02gn3VAdxsAABeR4kVHxhHvouQh564mGQBWMQ0lixltvmk9lQw1yorBIoeSyhl-EGDGnZabM5jzXRhLprsAVucVE2EAJSdgAOUSiIL-Pv3-cIS3zbK6V9y00MCfov_rLTn3AKmrBwAoAAABAQBgZhXERDKwDbEQ3JmvncrtyVXaIQMFk9ljz0I-e8_gKqgWvvJR',
            'X20-PLY':
               'Woy9euml-I58AkopMcDYW4Sw_d_rMpVfPqoiVCbhKW4HAGwAAAACAI0Ru9F1o_lZGcEh_XjNbXrhitRydT6C-r9CTel3ntc00C5y5Y0lDS5AdxsAABdxkSz7_NeV8i2CERllMSL7--9J_VEVqavm1iMMxbnmkHN50SqazCWt2CjyLzUmZ_JWk4t6hCbzI6InFCwwxGPxA5Eeo6FEEvY69pvUofDaLNB0rl-blyBK6QrrBwA0AAABAgDIuD8AFIp81FDBe_NuQ_M8c6WUjhCKgQ3VBhQCKnaOFd8Bvt3X2LJBYWZub5fOUXyw',
            'AEGIS-256':
               'xG2AE7bJ_NHx_oA8hM0Lo367FYGhSewvFofWnIhlHZ8HAJQAAAADAA0SA0NiHJy0CJcEhpBLJPgM1m_93-VzSYajvQ2JB_3FZy-ziZASPgGbNrl0lGipEUB3GwAAJwAnFfWXNNIbstXcW7r98biGLHYcoUjaHDMoGgP0bkOx28TD1fDjRlNfujDltRTAxMRr-gi6eN1aaoPa7ojzxK-RoT4bKZToeHSq5cBQ7uzo-oerDjzxBpUvXWKRF46IMhbqMz1T8ZNO8v53JkmZvwFjM_hRCdsldqn6QgcATAAAAQMAy3yugSeesloA8H9jM0Wc6MTwu6_vV_3RDs1JmpAJobTLbAlwbP4UNSHTtIwN-QW5CpfaC9YC9uFuC6-yNQ9bU4yDuTPBRY5vUA',
         },
         masterNoExtra: {
            'AES-GCM':
               'ARB0BgorsspAviyT28QXQ1CE0cQsoNgs-P8D3ASMh-QHAEkAAAABAJXX-2oMFl2O5U-Pbublz9uSwwhMgV1CoigoqdsAAAAAAACkacI5WVSSm7u6jKSJ5nzq-f367VwxH70aJsDjpmNHuhJ1vTE8HOx4dJcwK41q0Be_bF6Wws1P-tHqSXxDk3syBx0DngcAKAAAAQEAnnwBy17QgZus1I24O9sMSEkXnywVeQzeRjgQY6Z3l5JAoSVDnA',
            'X20-PLY':
               'E9Y7AZgB3UsqyrGk9zB_yke8AhVxj09dJ06mQRkrdyUHAFUAAAACAKW4HNq1bpiLxG8Emx6cd85BHilUZqp9P4ySA7JMmOURmoHAPp6qq-QAAAAAAACCTCkxcJRs6VvbrgBUnwvHKmzEy9N2OA6GtoyBCd3u7fFqC2w8BKKkTfHFv_yHgdqGdDNhIhgN1XVSCkf2xG6v6CQ5AgcANAAAAQIA4UnaftCg2TK8DrqtLhqt2NQgEpsO1MDsyxJzU6mI5kUpfljo9Hb56Y6vx6BSFPtvEw',
            'AEGIS-256':
               'XbfSaP1AyXGr6OkKtcNdOfchELrL7hFZcdZdmpkhzuEHAG0AAAADAMfUHOTKt8pEDJU8uZAlZGmJqqqhevkPkCXgDktwgA3sQ8fssyqaUQ_PUzAEQEad2QAAAAAAAERDj8HWrOX6qO7lUUOe-EGqAtc41Od_oiPvjeSlKkJBBJxzWrGwGxS9Zrz3fHHxH7cs4ICScDToZ-kkGMCmdY14_Hl7PQISq7qGMaTm_eD60IMhdwcATAAAAQMAgN0bLVb2bdKs5rfale7maIUKkmHqE-XV3iacVlWhVHIH-jgFUO5HEiYpPtAC66N4fLj9jIrxIxOy9Ivl49CIJwAHtEJRKKD3GA',
         },
         masterWithExtra: {
            'AES-GCM':
               'dIrH-Who2ZLUnl5vhYjgdeIkzJyxrIRNiHXdajJpLgUHAEkAAAABABE57zjmQLHDDBc_rzWy0JUc9Dg78ET-y_Ip_vwAAAAAAADj65RBsYoXfxMbc-KoEfHwHMy_pVTbugOQXpqrr8_Zt81g-qwA12hpTTQP5y1xdCkRyyVX-RWr8axhPlDAuBcmNYo0_gcAKAAAAQEAmq9E1GXUGDzIWYBF3Ru8D62YzYTdHbuSRTDlb8hWSNNV5a-ZIQ',
            'X20-PLY':
               'cP3TL_MfS4gDXL6chvkyX9h-LdwSHb1290FgD8owItAHAFUAAAACAKIVZCL5CKy7_a4YqDxYYdNqdRSRZKQq-mmNGDffSJKwV80pkJ5ANZMAAAAAAAAMoYhn0_wTx1m0guDpqYV_fXeV9cCtEp1Z4YpabG-rK6TFqm3lCTbRZofPRZUoriQ3EU3X1hUVljjrz_D1mU8MoLbR7AcANAAAAQIAPcNP1HtwleMSPuBMzz9UlDnRm8UkwMeIND5a6Z-OKshE811N31cN-qTgCl-I3Lznlg',
            'AEGIS-256':
               'DthZtnDc1JmB_60tau_hoUe5EhdG0g_OIOaqfv94MZUHAG0AAAADAFWZbUWv4W9RWQFylghbGMJk_cSm3GSEZf_yVflyUKEuwVmaYrg-qmAxhx1jQ46w4AAAAAAAALUv8i6Cvrkp75YDdIhy3oSKdAlr6mHUekN0jTDee4Z9kdfDRbPIaPUUUWZeSLAUCpEdu1ZnTEff-uefA2-6EvPd3hgKAOvINFJFOgbQbR3j9dyF0QcATAAAAQMAgqoY4QAxgbvUt1z_8HH5mIgQ5jK6iRLjSacfitQImI64K2_fB3ALDL07K392zfiEYmoQ3STaYgk9X0fGP4_Iy-bKGQa29jXPhw',
         },
      },
      //v8 — generated by: pnpm vectors:ciphers
      {
         ver: 8,
         pwdNoExtra: {
            'AES-GCM':
               'doyc0666_82JCCE67vP6SY7YF_JB7f0DsQrYwed8IkMIAIEAAAABAAbtiljfFnU6lhSm7oZ9sDHPZWI9RO8ii_UI6U5AdxsAABfIf2Z2MRcdjWrN7k4LxYOEvDx34Ug2uCBY9axMhJ5pFZvb-EkGnyE8AuCEHZEeR6rUnxjMRToZxXGFmSm5gL3YEoZ4OuTZUKogPowxUYgSHLtWcWyOaoV13r-D7SA-tAyPuE4ldb7tXEW-rzzIG24NPAsQ6wpu_JeB-1vlCAAoAAABAQCnB42LvHlzvoHs8Ah4OXE4MYuUMsBiPHyXQWUS5vdpv3ycU9wN',
            'X20-PLY':
               'RCg6ndEsaa2i8ctUOnQY-uKm0lTyXaAUCHHVk0qrMUsIAI0AAAACAJ4YpyZAsidykmFcfS6EKJzZ2nWXX1O4VCxXifj9OosbhJLVNbkx2j5AdxsAABdFAuQia2KtsLzYbFGi5qUY2rPKhFUe3CBjAnpWPgj3SJxDl24-iAJwzhoAizLE1EUFrYDhw0_rQKBQ-WDzZvG3jU03_bP6GNci199sRG9PwAFL8OfoBeSJbXS1HRrlI_aY0SrueNc5IwnFKkQskF_D19G8yKOysRWwmL1PCAA0AAABAgBw0Cn-FU2nlGC-XzqawpDrMOPX2aqkqPsR6FBgycS0gYWI6u2H2bF5fsabkJ7pVtJN',
            'AEGIS-256':
               '-KkkYHrSgEcRssiIQ6SKpNvOyzX83lhLdqsBeA3hP0YIALUAAAADANZu4mn5d6rPfBDRwa5hEW6Az_wjDLAqa9yN0YniIqOmNmPZu-UqwG770I5DUK-nTkB3GwAAJ7Z7fvmsoCn4MQvN7qgryPJsviJQmT_SSK_9jKfwZuzpsMfOTA_AqCB4ujYni2pwHjFf4N8imfMc8TNZP0wbNG34M4qwiV1SwufIJ7Fpc9cadnnCKHV31y0L5WqgbIiBT0r-Xw2H9RHzf_fzt642rJBwF8NieTx9OQsh9_zfSbqXgunuK0hZ9GnXIOo8b4Cqa7ezI7kTurclyOVLDQgATAAAAQMAsFFGbxzgVZy9V4zyA36yhVSDCXyAUoauh79g8fNu7GB4hDQhitrcKBOvL41lW8o_acFhkRjHh-hax6UNYv_qi0aPZ7fdZ1v6Ng',
         },
         pwdWithExtra: {
            'AES-GCM':
               'aRdNSgrnMSiJJmx6BDHYOvrMfiDBngKQqBDmz4pbbkgIAIEAAAABAOIKk8nbaL_M9bJlFp_9Obik5LCHNWkFj61-vfVAdxsAABfbngdCdriADPwREk3ozdnfur43i5zM7yBQg5z4hDEiKh_Fll6qG7a6qN7YxUnPb2IPXAEU6uoZCj3fYzxYz-D4fURlOpmDenxZ2UUD1mLE4kVGJ3VHvjXLEwSYyiXLrtdP5boEiKAC2pUFBHWYnOgsILEc2wTW2NZYt5b9CAAoAAABAQAsXjo244SWwkiPaxiyNEpVzfoQWkxzYrzX5MotxbHujazugtJt',
            'X20-PLY':
               'jyJhScsguHXeD9xCoS7hAryz7hDtimcJ7corHhXW0FoIAI0AAAACAL9glHKQhf_nMFdRg8ZL1PaICTBoJqCZj4UdvbgeVGFXbzmuIQetRhpAdxsAABf2vmI6WPa2KeWKtAsCzCwdhAusk93GuyDqjk7vqsrBiroL1VfpNBb00LuL9pkRvuyjFYIF3p2GqppSers8pVuHhHPRbYRxKhIkUlXVCr7lkYaK7M8QqLalDjyXFnbCNod5DydPUKkCIEnQaoopja6b3AeBQuU5f2Evy4biCAA0AAABAgAHOAx7zHr2n4M3KPpn4flLNuqDMe84pCbFlO0vPOMpwWrHDyFofiL-nuPGjW1U-0eX',
            'AEGIS-256':
               'B5qqkzVF89xcC7hLpGIqV3N_6xJgkwYUvMmUisiULDMIALUAAAADABiqIFQGFZO9_Cinc9tUXIK_zI8C9XGjFvHYPtmYmVfPUxL4cBhnKRkXw9-mMSf4XUB3GwAAJ-rj78AnXgKiOy3huyCq2iaSTHXq1AovQ_jwrd71NktfN6-m4HX9FiBv33RA3lSrrx6Ed6UtjLUN980s7T-n4RJYa6aJ02tgl06NHoBrVxGi2_MulKFNwmJ79uVww1XwOJPLRCwFOUXwxy7SW4qJWPiXyAlDen2-LKE_9T8PCcqKRrtZ2uNOOYAWMcm7_h9RKi3NMvKOoDs4iUW1bAgATAAAAQMAJ5UPblkK1nNPZWwl9jMI9Qm6v-f2236kyP9wBJW9QC66Hb6ayFUW6FQlKrX8eGkfRnfS-QTvWhU8yL5ryneanakrFatiPXaVRw',
         },
         masterNoExtra: {
            'AES-GCM':
               'XVvxUZv-NECGRd5fLJrE8PzXdmCC99mxAZI9x9xSQ8QIAEoAAAABAAPagG9Xcewf7XoSwG_dEKDNAY2eJVkmqs4625oAAAAAAAAAZzuVRDSqva2GIXioD10_SU8IzdXSWEfFHSZPWG2Jng6VK4X82vqA19nnrrN_ugIjRrYkmhvmdC0k4fCruc0YsE3G1NYIACgAAAEBACEprSWmqhf58ek8Vy1Oy6ut0QK7f1rRhczH50f4r-RMpJBVg4Y',
            'X20-PLY':
               'GDWstZL4_0AiDPJ9vPeeffgLDaRbI2R9k7JfStOLTWQIAFYAAAACAMsasQ0w4mvyVVhUcVKx6l4QGmO4tcbhzBqrCKENtwB3j7c_KjmFGAIAAAAAAAAAE_MAghdWEMqtfQifgnr6TiceN3eSkuFWerq8SheVn68tQKFrl8mXXGsUz9ZKLcNV5N41v3tzTBQecubEiHU3dO4Q9z4IADQAAAECAJgvAzLcJw7kFGNY0exGGsO_1OAyNTMLtbYEmxTjar_oy6dLHBt2l14UVijsDOlYO_Y',
            'AEGIS-256':
               '5sqpZfAvs8ZXCYmjc7CpgLGxDQB09rpiR2CkHG9zqLMIAG4AAAADAJg-vtneJCdhbD2qTa-SmKDdLGpCQ2XpvhLb83zALRrGP7y6N0U6USS5HTGECucHGwAAAAAAAAAY7_zLuOfg2ArcTk3v18QJLSgTQTaES48XHWVlhOAfCCrqneQNsj9yDa2snb0IcXzE-kq8AGNtoCsORvZSQ8oFabwA4Tq6EiZyA1b2hd-gy3rM_mgIAEwAAAEDAE4ElB9jwwcT_F65m2nB3OJyE-WbDEHQg7LqR5GB5GWI7Fh80yJx7-S6I1HSX3avc8sgIbVlNWpp2ZRO1RoFAEa0slB0kYcUsPs',
         },
         masterWithExtra: {
            'AES-GCM':
               '-pEiZCRaVu_IhDn-Yuj4JxA2VNtw-Y3aTpl9unIV06oIAEoAAAABANBaGUzAHzeR72X28ctWz95RJzoN3tEAje3ckHgAAAAAAAAAEt4B3nogmlzx0RZKhFJdUhP5ibshBJ0cm9CKKIwjeY2PUI3-XY6FzS7DqO-e4vKtsRzxwwCAXwn8J6VwWzAKNYgg2V0IACgAAAEBALxhiqSwUWxP0Rq7NOQy7rnHcv9KJlrmyDwSS6e57U_PzzgAGWM',
            'X20-PLY':
               'yYK6eClJyahmWmthE44-ejqW_b1CvT_BNq6ftkC0pHkIAFYAAAACAOZiWD8KnNlFY22yYtodpm2yH7Mh9lyhysT1FDPwmHByqBbeElwcL84AAAAAAAAAbHGwH9TU8xIjgnD-xcB11aZpDBQkc8WQhzplFKKNk5LF1Lu6Y4GKEnwk0Ogzq3yUXC9MyYGPi_oGKFaXEVqA0MsyJNYIADQAAAECAPa9PCB0vGNJjzrxIR7g716lHUvlJcZzhasPlZnjKyj_PK9gk-A4W-IDw2ZbVrg6HNQ',
            'AEGIS-256':
               'BIF7h31BmBPDy6PeTBplJ6Ifc5_GeiwEDHxYOOzfqvMIAG4AAAADABRaeRL9MSwIEWNjFEIly-G9TXbCGVhpNlxHUnooXcfBrQIT6iMexFlEpn4A00MhrQAAAAAAAAAGCZOnZHMR_2Jcts8ER8AKfBvzz82Z7Bh3-pl1jkhBSLJSDkU_SkaW9ctEFBWmZOoabarVkYufXgR7Y8LpGlcwZzvPV0aa7TlqvTpl-l-jlCz4wC8IAEwAAAEDALpc63EdLl2Q4vA2wetShhe1W9u5pCsaTVK1Amdx5tO3T32I_aYUQZ5xL4m8ecFL93WRWEuoSokObWKvoSgU99GZmy68QTejFlo',
         },
      },
   ];

   it('PWDKeyProvider without extra key material, multi version', async () => {
      const [_, clearData] = streamFromStr('A nice 🦫 came to say hello');

      for (const { ver, pwdNoExtra } of vers) {
         for (const [alg, cipherTxt] of Object.entries(pwdNoExtra)) {
            let [cipherStream, cipherData] = streamFromBase64Url(cipherTxt);
            let keyProvider = new PWDKeyProvider(userCred.slice(0), async (cdinfo) => {
               expect(cdinfo.alg).toBe(alg);
               expect(cdinfo.ic).toBe(1800000);
               expect(cdinfo.hint).toEqual(hint);
               expect(cdinfo.ver).toEqual(ver);
               return [pwd, undefined];
            });
            let decipher = await getStreamDecipher(cipherStream, keyProvider);
            await expect(decipher.decryptBlock0()).resolves.toEqual(clearData.subarray(0, 20));
            await expect(decipher.decryptBlockN()).resolves.toEqual(clearData.subarray(20));

            // Extra key material reaches the signing key, so offering some where the
            // ciphertext was built without any fails at the MAC
            [cipherStream] = streamFromBytes(cipherData);
            keyProvider = new PWDKeyProvider(userCred.slice(0), [pwd, undefined], otherExtra.slice(0));
            decipher = await getStreamDecipher(cipherStream, keyProvider);
            await expect(decipher.getCipherDataInfo()).rejects.toThrow(/MAC/);
         }
      }
   });

   it('PWDKeyProvider with extra key material, multi version', async () => {
      const [_, clearData] = streamFromStr('A nice 🦫 came to say hello');

      for (const { ver, pwdWithExtra } of vers) {
         for (const [alg, cipherTxt] of Object.entries(pwdWithExtra)) {
            let [cipherStream, cipherData] = streamFromBase64Url(cipherTxt);
            let keyProvider = new PWDKeyProvider(
               userCred.slice(0),
               async (cdinfo) => {
                  expect(cdinfo.alg).toBe(alg);
                  expect(cdinfo.ic).toBe(1800000);
                  expect(cdinfo.hint).toEqual(hint);
                  expect(cdinfo.ver).toEqual(ver);
                  return [pwd, undefined];
               },
               extra.slice(0),
            );
            let decipher = await getStreamDecipher(cipherStream, keyProvider);
            await expect(decipher.decryptBlock0()).resolves.toEqual(clearData.subarray(0, 20));
            await expect(decipher.decryptBlockN()).resolves.toEqual(clearData.subarray(20));

            [cipherStream] = streamFromBytes(cipherData);
            keyProvider = new PWDKeyProvider(userCred.slice(0), [pwd, undefined], otherExtra.slice(0));
            decipher = await getStreamDecipher(cipherStream, keyProvider);
            await expect(decipher.getCipherDataInfo()).rejects.toThrow(/MAC/);

            [cipherStream] = streamFromBytes(cipherData);
            keyProvider = new PWDKeyProvider(userCred.slice(0), [pwd, undefined]);
            decipher = await getStreamDecipher(cipherStream, keyProvider);
            await expect(decipher.getCipherDataInfo()).rejects.toThrow(/MAC/);
         }
      }
   });

   it('MasterKeyKeyProvider without extra key material, multi version', async () => {
      const [_, clearData] = streamFromStr('A nice 🦫 came to say hello');

      for (const { ver, masterNoExtra } of vers) {
         for (const [alg, cipherTxt] of Object.entries(masterNoExtra)) {
            let [cipherStream, cipherData] = streamFromBase64Url(cipherTxt);
            let keyProvider = new MasterKeyKeyProvider(masterKey.slice(0));
            let decipher = await getStreamDecipher(cipherStream, keyProvider);
            const cdInfo = await decipher.getCipherDataInfo();

            expect(cdInfo.alg).toEqual(alg);
            expect(cdInfo.ver).toEqual(ver);
            await expect(decipher.decryptBlock0()).resolves.toEqual(clearData.subarray(0, 20));
            await expect(decipher.decryptBlockN()).resolves.toEqual(clearData.subarray(20));

            [cipherStream] = streamFromBytes(cipherData);
            keyProvider = new MasterKeyKeyProvider(masterKey.slice(0), otherExtra.slice(0));
            decipher = await getStreamDecipher(cipherStream, keyProvider);
            await expect(decipher.getCipherDataInfo()).rejects.toThrow(/MAC/);
         }
      }
   });

   it('MasterKeyKeyProvider with extra key material, multi version', async () => {
      const [_, clearData] = streamFromStr('A nice 🦫 came to say hello');

      for (const { ver, masterWithExtra } of vers) {
         for (const [alg, cipherTxt] of Object.entries(masterWithExtra)) {
            let [cipherStream, cipherData] = streamFromBase64Url(cipherTxt);
            let keyProvider = new MasterKeyKeyProvider(masterKey.slice(0), extra.slice(0));
            let decipher = await getStreamDecipher(cipherStream, keyProvider);
            const cdInfo = await decipher.getCipherDataInfo();

            expect(cdInfo.alg).toEqual(alg);
            expect(cdInfo.ver).toEqual(ver);
            await expect(decipher.decryptBlock0()).resolves.toEqual(clearData.subarray(0, 20));
            await expect(decipher.decryptBlockN()).resolves.toEqual(clearData.subarray(20));

            [cipherStream] = streamFromBytes(cipherData);
            keyProvider = new MasterKeyKeyProvider(masterKey.slice(0), otherExtra.slice(0));
            decipher = await getStreamDecipher(cipherStream, keyProvider);
            await expect(decipher.getCipherDataInfo()).rejects.toThrow(/MAC/);

            [cipherStream] = streamFromBytes(cipherData);
            keyProvider = new MasterKeyKeyProvider(masterKey.slice(0));
            decipher = await getStreamDecipher(cipherStream, keyProvider);
            await expect(decipher.getCipherDataInfo()).rejects.toThrow(/MAC/);
         }
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
