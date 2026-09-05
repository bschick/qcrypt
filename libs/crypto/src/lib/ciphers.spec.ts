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
            const kp = new PWDKeyProvider(userCred.slice(0), [pwd]);
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
            const kp = new PWDKeyProvider(userCred.slice(0), [pwd]);
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

         const encKeyProvider = new PWDKeyProvider(userCred.slice(0), [pwd]);
         const encipher = getLatestEncipher(clearStream, encKeyProvider, alg, 1, 1, cc.ICOUNT_MIN, {
            startSize: 64,
            maxSize: 128,
         });

         // Read the generated salt before encrypting because the encipher then purges it
         const slt = encKeyProvider.getCipherDataInfo().slt.slice(0);
         const block0 = await encipher.encryptBlock();
         await encipher.encryptBlock();

         const makeKP = (encrypting: boolean): PWDKeyProvider => {
            const kp = new PWDKeyProvider(userCred.slice(0), [pwd]);
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

         const encKeyProvider = new PWDKeyProvider(userCred.slice(0), [pwd]);
         const encipher = getLatestEncipher(clearStream, encKeyProvider, alg, 1, 1, cc.ICOUNT_MIN);

         // Read the generated salt before encrypting because the encipher then purges it
         const slt = encKeyProvider.getCipherDataInfo().slt.slice(0);
         const block0 = await encipher.encryptBlock();

         const makeKP = (encrypting: boolean): PWDKeyProvider => {
            const kp = new PWDKeyProvider(userCred.slice(0), [pwd]);
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

         const encKeyProvider = new PWDKeyProvider(userCred.slice(0), [pwd]);
         const encipher = getLatestEncipher(clearStream, encKeyProvider, alg, 1, 1, cc.ICOUNT_MIN);

         // Read the generated salt before encrypting because the encipher then purges it
         const slt = encKeyProvider.getCipherDataInfo().slt.slice(0);
         const block0 = await encipher.encryptBlock();

         const makeKP = (encrypting: boolean): PWDKeyProvider => {
            const kp = new PWDKeyProvider(userCred.slice(0), [pwd]);
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

   it('pads hints so a range of lengths share one encrypted length', async () => {
      for (const alg of Ciphers.algs()) {
         const encryptedHintLen = async (hintBytes: number): Promise<number> => {
            const [clearStream] = streamFromBytes(getRandom(64));
            const keyProvider = new PWDKeyProvider(getRandom(cc.USERCRED_BYTES), ['a good pwd', 'a'.repeat(hintBytes)]);
            const encipher = getLatestEncipher(clearStream, keyProvider, alg, 1, 1, cc.ICOUNT_MIN);
            const fileAD = (await encipher.encryptBlock()).parts[1];
            return fileAD[fileADOffsets(fileAD).hintLen];
         };

         await expect(encryptedHintLen(0)).resolves.toEqual(0);

         const shortest = await encryptedHintLen(1);
         for (const hintBytes of [2, cc.HINT_LEN_MODULUS - 1, cc.HINT_LEN_MODULUS]) {
            await expect(encryptedHintLen(hintBytes)).resolves.toEqual(shortest);
         }
         await expect(encryptedHintLen(cc.HINT_LEN_MODULUS + 1)).resolves.toBeGreaterThan(shortest);
      }
   });

   it('round trips hints whose padding could be confused with content', async () => {
      for (const alg of Ciphers.algs()) {
         for (const hint of ['a', 'trailing space   ', '🌧️🦫', 'x'.repeat(cc.HINT_LEN_MODULUS)]) {
            const clearData = getRandom(64);
            const [clearStream] = streamFromBytes(clearData);
            const userCred = getRandom(cc.USERCRED_BYTES);

            const encipher = getLatestEncipher(
               clearStream,
               new PWDKeyProvider(userCred.slice(0), ['a good pwd', hint]),
               alg,
               1,
               1,
               cc.ICOUNT_MIN,
            );
            const [cipherStream] = streamFromBytes(concatArrays((await encipher.encryptBlock()).parts));

            const decKeyProvider = new PWDKeyProvider(userCred.slice(0), async (cdInfo) => {
               expect(cdInfo.hint).toEqual(hint);
               return ['a good pwd'];
            });
            const decipher = await getStreamDecipher(cipherStream, decKeyProvider);
            await expect(decipher.decryptBlock0()).resolves.toEqual(clearData);
         }
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

         const encKeyProvider = new PWDKeyProvider(userCred.slice(0), [pwd]);
         const encipher = getLatestEncipher(clearStream, encKeyProvider, alg, 1, 1, cc.ICOUNT_MIN, {
            startSize: 64,
            maxSize: 256,
         });

         // Read the generated salt before encrypting because the encipher then purges it
         const slt = encKeyProvider.getCipherDataInfo().slt.slice(0);
         const block0 = await encipher.encryptBlock();
         const block1 = await encipher.encryptBlock();

         const makeKP = (encrypting: boolean): PWDKeyProvider => {
            const kp = new PWDKeyProvider(userCred.slice(0), [pwd]);
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
            return [pwd];
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
         const decKeyProvider = new PWDKeyProvider(userCred.slice(0), [pwd]);
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
         const wrongKeyProvider = new PWDKeyProvider(wrongUserCred, [pwd]);
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
         const decKeyProvider = new PWDKeyProvider(userCred.slice(0), [pwd]);
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
               new PWDKeyProvider(userCred.slice(0), ['a good pwd'], extraKeyMaterial),
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
         return [pwd];
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
         return [pwd];
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
         // BEGIN GENERATED: v8:correctDecryption
         //v8 — generated by: pnpm vectors:ciphers
         {
            ver: 8,
            cts: {
               'AES-GCM':
                  'r5MIpa5wieJPvklOihZv6taZAFrDxwdcGPGMZY0NVw8IAIoAAAABABhhZu6SIUALDEh37o3DMh2-8426HwEaWyQOaglAdxsAACB7IAauDExTmsiULMOGivao7EIHKhvWTX1TE8zEQ_FgfSB9YJnHWuXRT78AsrjyaUJcds8KoayekDq9VnppgCwGoznfDvxBQhukb1ouSZ7P6b6XX-dw8RQY7oR0pxB5EmQ3k3TYawGytn3LyEHd1UVxpLOzr5_oGOoRT0OFQX7VoYwydrjkCAAoAAABAQBaHdBC-EmzIMVykuy7ZVAxkQRTcXuy5BsNwmYdAy-5D13Coz-Y',
               'X20-PLY':
                  'Q7VFMd3uux1hGhw1F1n2NWHaMBGDQ235sGGeWUc8tDwIAJYAAAACAA-pDBTYG8XH9PRU7-A3cBEBqF_gx1h6klMyvV-JWNpFwpvhazgyb99AdxsAACD62lCM4wR96BPIrgd2Posd7mxc_8ik6DYAbVu0-DS5_yBFFd1_JbWYJ11cAbwt2qCLrY6xb3JXwymbBS2lPLMlJkCdGMepFiBiAbKnOfIP3FV78-D2stVTJkb685wSgrn_knbh7lybIg86BMc3KF3ry_2LI29S0Zag9MefY9yXLURhs1sxCAA0AAABAgCuYiTrkcnq9SQZcMzrP7T6pR-E9Tlfa8tjGwruBVB62f1OqkUoEOp8ZCpChOXtKgsI',
               'AEGIS-256':
                  'aS3zM3fJEHe6EOL5IugoKtM1AkYAaWfnRgLflaMTaTsIAL4AAAADAA7DfeZAQfqGG08Lgf767EdvEowUcv-UAyN0_TW30QbR73I4BcpNZrBTruwMpZuTU0B3GwAAMGwSOtlgT3WyxQ776vrGA-ApWwjrmpeXS4Tu3wY53zRy0WoghCjCqLD308tFsA5K8SA8UrV9ilQxGITQkfFvb6nVNaC2YhguWOGQ3sOAnpOpHMxwE53yYbk_xSCh2Wa8JOYZY9FO9g9N6mkeKyn7L9FcicUS5dmWrlAMQJew3DmiuWN5nNRJYBG1UsYleEJkd2oFSOPWwgP0vwiwPFao-DH2zfmlbAgATAAAAQMAy-ztnlTL3VxdUfbK3lF_jh9MmGqllT6zlzU4Frz6Xk2nBbYhSxhuGCIEyy3n_s7X7kJzY0vv7QY5p4Qiz6U_gq9kz4W7MYpHtw',
            },
         },
         // END GENERATED: v8:correctDecryption
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
               return [pwd];
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
         return [pwd];
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
         // BEGIN GENERATED: v8:missingTerminal
         //v8 — generated by: pnpm vectors:ciphers
         {
            ver: 8,
            cts: {
               'AES-GCM':
                  'zzYpeEktmqAEinAO4pfXtoYkZQXJHuqh5DlFfQ9cVdkIAIoAAAABAL-oikVZBtoHlS3ks1kotrkZIz7FsvjZwx1kHaBAdxsAACCPoFdZoO--kQKTG9rPGQu3MeAvZqzv4KMFIXEFNG6rSiBC9CxPohC10A0qlqn1VA9-5CDuJs3iTpn5D34gdeG3QfA61HvjboK-3XftJTxH8aceSnAGIhc9vx8o8Cq-GiDLr-NPY5FhjznU4pr2N_Cvn2Eqyya3TL27XSWf6Bqcqm1CHYAoCAAoAAAAAQBSX6W1ZBztiQE-3eQ6I4nrFoSUlur2JtanXaS8hSyyZAj0OWyB',
               'X20-PLY':
                  '64W9Y8mqsQmHgNHLQrC62SKq8WbFAMwGpxAvxUuGR9kIAJYAAAACAMbHwifkSPqPB7Btwow0NPGO9IxlIxbqwO2WerGHGd01GNXn05F3u5NAdxsAACBFjGK7clEtwMf5-HMMsFWOy3cI6TZAVHgxnJHREyMPUyB3_LTg9HvKr8TahEZY7LjohZ8vMDNitRgTDElY48b18nys_HqyxItl6pWZdZE0k1Zd5REcISn8CLWdqeyh6eVuOdYRoGR-kmP63gbCqAPMari57JUd49eqBbOnL1fCRyZ10r6hCAA0AAAAAgCykzg1FCDr-y1_VBOu8I0br070-6-OBRohqDJGHsU8UFJgWt3bKMz3DF7OL-sXBhfp',
               'AEGIS-256':
                  'FslXEWhVvNp-fAcD9TbHFg50cHwFOQrpvsoM73mzNMYIAL4AAAADAKJ2CO8yrr2kth3v9mw8vjjqTIiZRbMb9KYzDVOVCpKor9zDDw4ORV7-MB66FGA7gEB3GwAAMPMjpbE_Qqn99pjdFnTTpU4F7Re3shZA6QIgyR-8-AS5w1hv6_f9Dl8jKvAHlP7HtiBDvnXs7VP7fHeD3NZmGTIU4EO7hF0f1Tvu1DY7-ceYXCf4aScKEDGbv-UfON3OrGeiHVAgRGguu5yv3JKndFXlaEfbYLjlA2nSF92cLNkWAc-VUDUbn8UyCGrYlYEaVHtxtm3ooxjgTl_SLcILQuUfzQLw8wgATAAAAAMAzBP587_7P7VhBIuwGOM5J1Uk6PoO9meUYIb6_lMuxnbNRH7zCH9XIBLHkefrObvcywfgJRIPUVNXIOYx0zjoZU3Ay_9iKybLPg',
            },
         },
         // END GENERATED: v8:missingTerminal
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
               return [pwd];
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
         // BEGIN GENERATED: v8:extraTerminal
         //v8 — generated by: pnpm vectors:ciphers
         {
            ver: 8,
            cts: {
               'AES-GCM':
                  'MPgaSfMZQpF_SRke6pJrKuqPt5w6y7UfU1W7jh05gRgIAIoAAAEBAO6NBrFy1Du8osHKKHJLdS8LGT5jEcHIm2_QVLlAdxsAACDpkPkxkKl7GNREzkXlVwhaPOkia51XJEViSlM0hHfXAyBJTn9c4wwd4v7VqGNPYqCvzNWWK8fuQPpJVb7adYfrTd--FboSi3jjwoammUTpKHD4l18xp_6zKrBXGVOi8VvjLebGQT9wPtPtWXNQ7Ey7p3qMJ1ZiEeNWG-bIYJ4zdv-oVImbCAAoAAABAQCE1EDEhtij60RGqAod7NcWxr_FI1dIxT0q6V2A-TUOxSf3eBrR',
               'X20-PLY':
                  'rKcqfl6VfNDSXZ5JQKix06ddvGArzSDj64MUo2yuNIgIAJYAAAECACLE0Bh5MC4ryN8qS-sxTniWCUHGsV6CqooM6WIkls7CJ0VgE9uj_JNAdxsAACBiYwfby7Gc0BSfCntHO3yBfSGau8d9kuYwy4nsowxagCAEF-BallL0YVtgTmzJgkyQEpx05TGxqfGFW-A6TwmWvvIebTOvUmrn12fDwQunAVHu3p8EdhqLbks1XYQP_zYWNr47YtcoV_27unPor6tFs_hzJaVcCa1oUd9bbV6yliEJeTAECAA0AAABAgBLOgm1fSvL4bwFsT4lzIBFprjMSIEMWKF3JDusAmoAA6__ta24i0Ga1ypfswZuJkUc',
               'AEGIS-256':
                  'VBTerVcmk-UkqCJm2neFpQHebiiG1XFFftTiZPkSVAIIAL4AAAEDAJe2cr_X63gicE11Z2fDGjNBLbgPpWR_8K32dtTF8KGXNBlBU9SxkTv4R3Whg9K9qkB3GwAAMBtpRAFXRJYa3f_dGWYhDmZ3ZufKauVFrRAQSxTILXtgVCrGFuQHUTV4Chx6iZxNmCCebBq6g606H3hKjXOWXXaZX7MnnBnOX5jXeZGEic_H-Q0cnb140JEVwoa1Gqyp28QlzfNGULnnsyRNI5e4KATFS1HKNUZrkhqpENoWEMCmZ_bU3DayrGg0eaxwYjvMLLZ6lk8QJSl5lyLe8to3mPdDjtyHIwgATAAAAQMA-bXSqohzZ7p7mNvdK2jbIx3u2ratBRXpCSRoG_8I5f-M3eUr_jk741VJJkGdbECpRvOmMNU6tpeUAGHXdhYzRBuf750EmPxAXg',
            },
         },
         // END GENERATED: v8:extraTerminal
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
               return [pwd];
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
         // BEGIN GENERATED: v8:flippedTerminal
         //v8 — generated by: pnpm vectors:ciphers
         {
            ver: 8,
            cts: {
               'AES-GCM':
                  'L08tHkddbPBovsLlYvsyo0dTv3Wrl5Zhjy9xhtuT9F4IAIoAAAEBAONfU9CIN_vGxfm9ahxYcdPs-gSh6pZTpIw-zeFAdxsAACCAWoO_0H2w89wmho6xOVkJAot31pMN740TizVsDr26mCCwR6W43xs3Zx4to66g9VKHFbV4inHbko6h1Zg4ocf5PyT_M-Yxs3oTMYL2M8letPFUPuhb3N0o7r7OUTfRS0UoOXCJk5iSYjfPSTDQAIvmUloSYzGh3-4ukHXKalzKuPM5La2ACAAoAAAAAQBQYuTwWo91g4hzf4WUMI2uKsM6FqkFNqXJZy-V_C--F22kZer8',
               'X20-PLY':
                  'KkgGYon51G-dif2SoWOwf_eAtHnoKykhmsaX--HtS6kIAJYAAAECAKP5CEOEq9bOnFtLzRhHVcAbYPsU-2MiCXDPOo4U6v2XgD_P_u9ZOrJAdxsAACA6CJ2R2N8i2GzD6Fj3FN44Adr0pwQ49XQW6Gx5QdH9qiDQ24TtWeNnGtn1TkoWMJ0-PMxbWIwxh8vroYC07VFStt8Z1F_sBnK4CtYQ5guDJwEkCGRHXBhzqHeE07LRxDMd9mPDXi8XwAUsQC2D5oCiEdghDZP6GKsTYovVhEkQdcu_dcfPCAA0AAAAAgDsQPLoHS5JzkkSj80mA8NTw1E-Ba6bONSBEHdA2tXMoLnXqjrGFIgMJnbAR9jNRfuH',
               'AEGIS-256':
                  'cwC-zOzIRI57xAd8ULzUEWfGcczNMtshGhz0kfY4PnsIAL4AAAEDAHvYsjc9Vm-0x4xsCCckL62RmMtuuBHFge3mcD_U8i8I1YrvWiOS1IFP1e5P5Vg3p0B3GwAAMMK_ctQN0Jwwc1eUxcXaS8yt_blkNGIykItar9xhZtOmZ2L69AtTCZB9wDMVafmHnyAfgngIqsI-VUp_hiN6DH32VWrk8Dhn3ZALWqnvYi-AX4Zwige4VTUU8KO2IEIvu0RgKnV09jEY2QcB8TIi3Gcm7Lqa5w1UyFvDmuAdQ_ywwA9R8oL0o9bM-UdTRQHkwaNoeegGdN0h_nl8KrC4UKJ__9fMIAgATAAAAAMAV_SIsTYOznY7Nn7QAZs5kjp0ed0Jv6FZzGJh7Nzm3swE9EcxJBZxjduxbNWdreE7d7eGeVs78piwoPS6aPoohqcU02-8X_RKXA',
            },
         },
         // END GENERATED: v8:flippedTerminal
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
               return [pwd];
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
         return [pwdGood];
      });
      let decipher = await getStreamDecipher(cipherStream, keyProvider);

      // First make sure the good values are actually good
      await expect(decipher.decryptBlock0()).resolves.toEqual(clearData);

      // Ensure bad password fails
      [cipherStream] = streamFromBytes(cipherData);
      keyProvider = new PWDKeyProvider(userCredGood.slice(0), [pwdBad]);
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
      keyProvider = new PWDKeyProvider(userCredBad.slice(0), [pwdGood]);
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
         return [pwdGood];
      });
      let decipher = await getStreamDecipher(cipherStream, keyProvider);

      // First make sure the good values are actually good
      await expect(decipher.decryptBlock0()).resolves.toEqual(clearData);

      // Ensure bad password fails
      [cipherStream] = streamFromBytes(cipherData);
      keyProvider = new PWDKeyProvider(userCredGood, [pwdBad]);
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
         // BEGIN GENERATED: v8:badPwd
         //v8 — generated by: pnpm vectors:ciphers
         {
            ver: 8,
            cts: {
               'AES-GCM':
                  'okE3nkgv3PaIXJDNs9JDvmApRTnNo7HEDfhn9m0sjdkIAIoAAAABAN0QgPBRcmBohWp-A7lM5d9qZv7B8M1PWS8xibJAdxsAACBUleh1Oe3EuKbmRbRwomTEaPwZuQm4qOxE41-SDSh6eSCARtCRIIVYxO91wf6NeTttIUKxejWBQtnbcYJSr5t3gj4VNWGcMrvL002gPnoNljsxvOJQT_5rEgVf6GZgwxqrNXsADCD8yQFdwEt82wmGP3eIDZY7NH_i0ksdXhYLYlZv7AwkCAAoAAABAQCKjswAG-h8RiJ6TomoBFRxG0xRMIHb4yyJMuuutGRFTnKUCGhA',
               'X20-PLY':
                  'UKaFcULm2htI8wCdiSUMRUMP3YJpfWNI9abpBX7oSksIAJYAAAACAHtk8R_Liuw3OFuMk_-qwmnrjfq3GrDwBOfGkgsepx6--m_PsCgXboBAdxsAACA_rIphz8fmZsiGBJAKpHQzr6uDApQOdB6uFP43mrjafSAo3V5MQwp8FZC3DNR7XxQKLQhezlS6VE3Bc_yfehgMqQsRCsgtY8qjL2tc4XdZLA-tqgksl4nCo1XoZYgiozpp4sdqkFqGROSdB0HuG2FR_ZaqhJphfJp13uVB9TBeH0OwryBdCAA0AAABAgB2sW9yR5n7nWTTyeRVsYdFsZJu_RrAgf0_UffJx_X-Zr9gbZiYppfFLZi4r8qK8xOX',
               'AEGIS-256':
                  '7i5CXnW9ziNBvSVEVWN2DRvmIeh2Jn7EI6YxV_rK6nUIAL4AAAADAJ0WO9eA95MDOdKpf0xPvDCzAEG5riAhCnVDm82VlmIFoMZc4FaUs5SuOXH3WGlfwkB3GwAAMFodb9uvH2lk5qYzDY3T8hXgnJLVufdcxFP9m1XR87UCEI9LzDV7B8BiBlMSxRcjmSDmUWx2xn7Pmpelxed8u94iGZioDw1NUXYUm47GIm79C_34heCekQqK4bpmiTV8Byyh-e8fii-471ldgsN689hxLTZ42pqJsFd8dpJ-0l7HL04jwgPqZJfTX4SuRC70NHr7aZb5otJ7cpKkZK10Mzny-XKHLQgATAAAAQMAXzqG1JAXPj7-zLmiPEwsAVgprZmVEelWsfYWNRTPUTdRaNs3gjLsGpt1aLJ1yuDakHCHvH_w3EK98BLPBFGhZ2RHtpGI3MZpoA',
            },
         },
         // END GENERATED: v8:badPwd
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
               return [pwdGood];
            });
            let decipher = await getStreamDecipher(cipherStream, keyProvider);
            await expect(decipher.decryptBlock0()).resolves.toEqual(clearData.slice(0, 20));

            // Ensure bad password fails. From v8 the stored key commitment rejects the
            // wrong cipher key before the AEAD is reached
            [cipherStream] = streamFromBytes(cipherData);
            keyProvider = new PWDKeyProvider(userCred.slice(0), [pwdBad]);
            decipher = await getStreamDecipher(cipherStream, keyProvider);
            await expect(decipher.decryptBlock0()).rejects.toThrow(
               ver >= cc.VERSION8 ? /key commitment/ : DOMException,
            );

            // Test wrong userCred
            [cipherStream] = streamFromBytes(cipherData);
            keyProvider = new PWDKeyProvider(userCredBad.slice(0), [pwdGood]);
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
               return [pwd];
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
               return [pwd];
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
            return [pwd];
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
               return [pwd];
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
               return [pwd];
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
            return [pwd];
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
               return [pwd];
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
               return [pwd];
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

         const makeDecKP = () => new PWDKeyProvider(userCred.slice(0), [pwd]);

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
               return [pwd];
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
            return [pwd];
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
            return [pwd];
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
            return [pwd];
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
            return [pwd];
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
            return [pwd];
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
            return [pwd];
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
            return [pwd];
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
      const keyProvider = new PWDKeyProvider(userCred.slice(0), [pwd]);
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

         const decKeyProvider = new PWDKeyProvider(userCred, [pwd]);
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

         const decKeyProvider = new PWDKeyProvider(userCred, [pwd]);
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
      const keyProvider = new PWDKeyProvider(userCred.slice(0), ['a good pwd']);
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

         const encKeyProvider = new PWDKeyProvider(userCred.slice(0), [pwd]);
         const latest = getLatestEncipher(clearStream, encKeyProvider, alg, 1, 1, cc.ICOUNT_MIN, {
            startSize: readStart,
         });

         //@ts-expect-error
         expect(latest._state).toBe(CipherState.Initialized);

         const block0 = await latest.encryptBlock0();

         //@ts-expect-error
         expect(latest._state).toBe(CipherState.Finished);
         expect(latest.multiBlock).toBe(false);

         const decKeyProvider = new PWDKeyProvider(userCred.slice(0), [pwd]);

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

         const encKeyProvider = new PWDKeyProvider(userCred.slice(0), [pwd]);
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

         const decKeyProvider = new PWDKeyProvider(userCred.slice(0), [pwd]);

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

         const encKeyProvider = new PWDKeyProvider(userCred.slice(0), [pwd]);
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

         const decKeyProvider = new PWDKeyProvider(userCred.slice(0), [pwd]);

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
      // BEGIN GENERATED: v8:providers
      //v8 — generated by: pnpm vectors:ciphers
      {
         ver: 8,
         pwdNoExtra: {
            'AES-GCM':
               'HZJ_P3bsDsBRxK-hv1JQRIsvj5-RqwR4VesU0sIc2DMIAIoAAAABAH0DAuxa-B62bvQcY-cdPJrBjix8CFDEDHSUANVAdxsAACBrQgViAECya6Fx_UpRrdcH46NfEkNUyb4BigpLnP0u8yARZ0cn1tbDNf2RuFZyu5O0olE3YcPnV0oF5-3UgW2w_UehCvZMbWNKJQNImB_jZK4_J-yQx2Bf3yti1BBYBIZ3UsRUD_digrwkp0Yw84aJBdsIPtR116mhMPY-X_6ytDejF4aNCAAoAAABAQDAd8pvS-JhTs6t45egadqD5lpREXvPOojOIdiranYlqSu6EuSc',
            'X20-PLY':
               'q-MNVLWvt8afUB11S-RLaKaUE6RXZhq8mPhPO8PZ1z8IAJYAAAACAGvBPOLJ6pPXJlnp_PcDlJzD3cZ0J1Z-nvE3vosi5W-uWXK2L-Fyrq9AdxsAACAWRps479n4EczM3c78UTJzkm-wXcSAZjB6gMIpoEW8sCAfbwIFqDHdqTb_0T33U-uxQpRWgrRnKX-j38XK2_VB08IobZ8BJbggqUy9yvFiswRdW5g6tJSCVLpOLc71HP4XE-5ynXLgvIZVthRznDeXtQRlth1kM8OqAHDnNtBzNGXuEFVwCAA0AAABAgAflyclOtB-DrvIkr5z5aPoBZrrApJF41FBnCff8jS77lDtxJEtJCIiuJFuO3HbJCmf',
            'AEGIS-256':
               'cWB6xy2TbH80AhyYP15jEPOgio_mgFYa-R-hrp9wESsIAL4AAAADAJPOWQVLdRv4MJgowc4vGnKkCswIDSqIklbxFcCgMINouq-BrMi-9dYgidKwCBPxwkB3GwAAMCh1Dl-WhDvSS_Fyoi-VP1pD9wLrJphzN4RJQ-lFMhHe7njVqClluxIWO-Bp8HSgHyCjW0XtqLZLOl1owOUrTVV_0OAp9YmxD5RtA0nh26aAY2l7Fp2M4jfQLWgiEKklWwqYQdClLXVI7hzLlNh82vMwjaaOk3G2J1F6dmnTFCwjjFK_j4EfWV-a2viRvT9EIPs24oqu2q_CVXX7y2aWQB3fGGfmTggATAAAAQMAsZonMER0z6dI6Owgpm_CSYg4IfEYD-g-n9_gP0YQGeUBMudPyV3-ZVCQ0KPgPTThv3JPmP8raGJ9vH8-jO3gSsvRCTEa68WKUw',
         },
         pwdWithExtra: {
            'AES-GCM':
               'K5FkGUAgwZ1wVGNKSPgFknlsnEEQ6IicIutUovbsT_MIAIoAAAABAI7GoT2eNCstbT6qDE3cN-ge-IYZL7KFSlZsgBpAdxsAACBrLBKJmIK0R5VmssA7U_vmmzT8KlcOLNHkzSPeq6ks9SDH9tpCF0s90fRjmMwO_lFotPexuQgZ8sT4wsiVhWrw2EOZvwIfgivWmhkV9VZJPQLZZXgnVFYjX5bgARd9AM4E5AxIGaPo8y8kCBRQJ4O8_63Y01MAO9XlDoNIlNFb-GKqUV89CAAoAAABAQB32YF_DQSizM2kgsxgs406Q2QvIZkxZ5nqNrDn0UdZCLNxC8UZ',
            'X20-PLY':
               'KU0T1UJcBjpbSe064dS5K5GqzNpDI4Rm9iqMRnfAI68IAJYAAAACABmeKS7MY42v6wjIKF1RIPBNu-MBh6RKzQ7cSC9vjdwyZbn-KsLKlG9AdxsAACBq47I2asv1aa2QmDseODqvKwaKfDRrkCk99SgtUvt3miB0B52oVFiKe-Eb5cMhGDB3F-p7DpsLlfraIy6C5wNbqeZydvRfoWDNQ0GttubGzNSXo8ZSChcUN6U_NcHwZAmtXv4Q6gg9MeW2LgVUW1DxyN12-odUOQFKuvYZWY1w7pFSmhx1CAA0AAABAgDzpT-k0ba83sOa02S2XEuW0rbSpn39ZnqyDqwaU7oVe1OW_phS4R0aNIVy08Ai-02s',
            'AEGIS-256':
               '9GPQCxHeK_ZIPn75DZsmouRQfPoiTEKUNY2harv248kIAL4AAAADAHfW8TH58flJtzjABFw1Vp2iBMiP7rjrq0Mu1_6d4QNHQqCwaYJKt_BUsp3V-AYxyUB3GwAAMDVdy69J9bWH_uZeSEwBhHfkBGa-a2ZYRrhrwjyyDkgiINzXDtvZtgLLOZSqEnGNiCCQLCzbEyqnVzvFde6i3iiBpR0KhfbiaX1C8eWgxWWrAd70oqfF0SEGnUsn420eXV15HtOy2RifKvOdhVT-5KAbfxu9BUNfXbu4DrcaHB-qBim5UUEaS1zKOs-6Nd2zji_Jne-STRdQZwJMtVYO7GoPbP8J2ggATAAAAQMAcVlRUcVJTqVlfRyr79f-tnXhk2YFsvmF-nmb47LsOQ2p_Q7d2a1AyRSdoCSCbACh5Wawv0SvS1IkN2ncncvG7gVI6i3B7vCvVw',
         },
         masterNoExtra: {
            'AES-GCM':
               'jkDy7TsVWpRFyUjxuOahdO6RscIsIw0tgUV6qE1ARXcIAEoAAAABAPOMuXEtacYF2OKBh6Dp5afSXS5kvd2WaqTmA3oAAAAAAAAAirXNyLUSC_Y697CrnvK1043bPkYvMDTU-DpoNzR3RdPRFsqQOk5pqoKJuyRO9YY3vyQtYaLDFpOHpnQ97Xxm8Dv6uNEIACgAAAEBAOTMWFnXJaSLDxtaF-4NuI_iiJlGGX8ifLVzXsWaXEGlm1tGteg',
            'X20-PLY':
               'LRvyzBTDhhRWO9nC_CGJ96breOqAQ5d8fTqalfR3yg8IAFYAAAACAH-k_7CufTY5gu7KVImXOaJjFifVL7IFz9HS6dNMwgYIGhhRPsDQeSQAAAAAAAAANLNW7hgAiFxY1zRXGfXf2aScURi-NP8rRawQ7-fZ5yf2Sto_AaPmAY9RkAOmoxb8fL1pV4sGQABiYJWPGE28MfiRup0IADQAAAECAL0hlciBuNfPiimHWviDBVBiC-GmR3c3qwbwbEyM15kOBLwKQcnHkbkJFe6OIeC4PlU',
            'AEGIS-256':
               'Fs4z3XgmePN3is73RLrRNR4DZ80BR8833VBleviM1EwIAG4AAAADAE3wQBU4tRtGUZuvp7lrtlBaQzW-Xlnbd7Ctt_tgD0V-4EJOiqoK7GSaD4AJ5-0UIwAAAAAAAAArMtKMWpUl34jZmcA3te7qxwABXKQXZ7tkv-IwdqnQRTtr88HjYRZnLPA_CJtx2h1JjtCDS2YHYnqGvkOJR7UriTpe14v7Amlg4y_KR_lLTa8k1I4IAEwAAAEDAPo-zhif22NzKw6k7CBwVNQErs1w2J4EFCWtEnhOamxmTn0zPuueVadeyGzHl0yExpgCMVh_YA4m-EM_2sbwemWNR22HipEehPU',
         },
         masterWithExtra: {
            'AES-GCM':
               'UI6OKerIbg66qerElkg1H382h98haXy-HViDjrAVDEsIAEoAAAABAK_VWuF9ucjq_KsOABZiCslnls4Qw-ZZk8JVCXcAAAAAAAAAU0YleXqROcr1eZ0xEBsGBUeYWWceJPA4_1O_GKfg8j6U0G-zc_pi14zY5kBVqtyfokVWxMqSI3Ir3SDqiv6FA9g0VhcIACgAAAEBAOftn-7GLV1FrzIM5k7uiTKurJJnqiDOZSWKu9WRhrMVWhig97Q',
            'X20-PLY':
               'UkeNIB80ddnjvZFA6hEGHhz3o3k1UzpYfRIkkU0rCkwIAFYAAAACAPSY0CR_Mamu8h-08eK56F1EOSXQOEE4pis0BDxkF2x7I1xvcoEYY4kAAAAAAAAAdZcAqPh6SPIPXowiCyNwdtwmwuIL5gHvy2isJkhKxD4Ku7CPY5tiZwWUDFuvVPuxCLDHYh_LuhkbuDrPHvu-10jTWmIIADQAAAECAOzIrZjfvJMuBp0SWEPioHxxV7FzRRz99yEZ2Z_hjxFpOL4XbRDd_mOyXXjoxxLCONw',
            'AEGIS-256':
               'QnXD3ricAoFA5ifRa8rnTovATadnfoj0ra577dxOCwsIAG4AAAADALFTEXRtSheVHJT3UjIpXJ8W9NPmU_6Y4P82O_PQ_x3Yspj0JM2J1VC7cY_3AoDQZAAAAAAAAAB2RjEZ9f1w-ns90gFPLkr4Y_hzXS0x7f2Bah95ivX9SIM-IRrT7rFjwXZHnwrjmXLoFZqbyzxDGa_IHkkBD3d5W5Tu85kh4DZodt6H7gqT5XRwHOgIAEwAAAEDAPmX3hUNmTuty-b065TF-4BdbiudUzU83l2x-3ATnCbK88khjDHfNao7mJwsSXuQsxU_IUhiurBlaT46zlLom1I_JXHVvT2wxgs',
         },
      },
      // END GENERATED: v8:providers
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
               return [pwd];
            });
            let decipher = await getStreamDecipher(cipherStream, keyProvider);
            await expect(decipher.decryptBlock0()).resolves.toEqual(clearData.subarray(0, 20));
            await expect(decipher.decryptBlockN()).resolves.toEqual(clearData.subarray(20));

            // Extra key material reaches the signing key, so offering some where the
            // ciphertext was built without any fails at the MAC
            [cipherStream] = streamFromBytes(cipherData);
            keyProvider = new PWDKeyProvider(userCred.slice(0), [pwd], otherExtra.slice(0));
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
                  return [pwd];
               },
               extra.slice(0),
            );
            let decipher = await getStreamDecipher(cipherStream, keyProvider);
            await expect(decipher.decryptBlock0()).resolves.toEqual(clearData.subarray(0, 20));
            await expect(decipher.decryptBlockN()).resolves.toEqual(clearData.subarray(20));

            [cipherStream] = streamFromBytes(cipherData);
            keyProvider = new PWDKeyProvider(userCred.slice(0), [pwd], otherExtra.slice(0));
            decipher = await getStreamDecipher(cipherStream, keyProvider);
            await expect(decipher.getCipherDataInfo()).rejects.toThrow(/MAC/);

            [cipherStream] = streamFromBytes(cipherData);
            keyProvider = new PWDKeyProvider(userCred.slice(0), [pwd]);
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
