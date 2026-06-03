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
import { KeyProvider, MasterKeyKeyProvider, PWDKeyProvider } from './keys';
import { Ciphers } from './ciphers';
import { getRandom } from './utils';
import { isEqualArray } from './utils.spec';

const KEY_NAMES = ['ek', 'sk', 'hk', 'hIV', 'bk', 'commit'] as const;
type AllDerivedKeys = Record<typeof KEY_NAMES[number], Uint8Array>;

async function deriveAllKeys(
   keyProvider: KeyProvider,
   baseIV: Uint8Array<ArrayBuffer>,
   alg: cc.CipherAlgs
): Promise<AllDerivedKeys> {
   const ek = (await keyProvider.getCipherKey(false)).slice(0);
   const sk = (await keyProvider.getSigningKey()).slice(0);
   const [hkRef, hIVRef] = await keyProvider.getHintCipherKeyAndIV(
      baseIV.slice(0, Ciphers.algIVByteLength(alg))
   );
   const hk = hkRef.slice(0);
   const hIV = hIVRef.slice(0);
   const bk = (await keyProvider.getBlockCipherKey(1)).slice(0);
   const commit = (await keyProvider.getKeyCommitment()).slice(0);
   keyProvider.purge();
   return { ek, sk, hk, hIV, bk, commit };
}

describe("Key generation", function () {
   beforeEach(async () => {
      await cryptoReady();
   });

   async function testKeyGenSuccessAndOveralp(
      keyProvider: KeyProvider,
      iv: Uint8Array<ArrayBuffer>,
      notEq: Uint8Array<ArrayBuffer>
   ) {
      const ek = await keyProvider.getCipherKey(false);
      const sk = await keyProvider.getSigningKey();
      const bk = await keyProvider.getBlockCipherKey(1);
      const [hk, hIV] = await keyProvider.getHintCipherKeyAndIV(iv);

      expect(ek.byteLength).toBe(cc.KEY_BYTES);
      expect(sk.byteLength).toBe(cc.KEY_BYTES);
      expect(hk.byteLength).toBe(cc.KEY_BYTES);
      expect(bk.byteLength).toBe(cc.KEY_BYTES);
      expect(hIV.byteLength).toBe(Ciphers.algIVByteLength(keyProvider.getCipherDataInfo().alg));

      expect([sk,hk,hIV].includes(ek)).toBe(false);
      expect([ek,hk,hIV].includes(sk)).toBe(false);
      expect([ek,sk,hIV].includes(bk)).toBe(false);
      expect([ek,sk,hIV].includes(hk)).toBe(false);
      expect([ek,sk,hk].includes(hIV)).toBe(false);

      expect(isEqualArray(ek, notEq)).toBe(false);
      expect(isEqualArray(sk, notEq)).toBe(false);
      expect(isEqualArray(bk, notEq)).toBe(false);
      expect(isEqualArray(hk, notEq)).toBe(false);
      expect(isEqualArray(hIV, notEq)).toBe(false);
   }

   async function testKeyGenStable(
      keyProvider: KeyProvider,
      iv: Uint8Array<ArrayBuffer>
   ) {
      const eks: Uint8Array[] = [];
      const sks: Uint8Array[] = [];
      const bks: Uint8Array[] = [];
      const hks: Uint8Array[] = [];
      const hIVs: Uint8Array[] = [];

      for (let i = 0; i < 5; i++) {
         eks.push(await keyProvider.getCipherKey(false));
         sks.push(await keyProvider.getSigningKey());
         bks.push(await keyProvider.getBlockCipherKey(1));
         hks.push((await keyProvider.getHintCipherKeyAndIV(iv))[0]);
         hIVs.push((await keyProvider.getHintCipherKeyAndIV(iv))[1]);

         expect(eks[i].byteLength).toBe(cc.KEY_BYTES);
         expect(sks[i].byteLength).toBe(cc.KEY_BYTES);
         expect(bks[i].byteLength).toBe(cc.KEY_BYTES);
         expect(hks[i].byteLength).toBe(cc.KEY_BYTES);
         expect(hIVs[i].byteLength).toBe(Ciphers.algIVByteLength(keyProvider.getCipherDataInfo().alg));

         expect(isEqualArray(eks[i], eks[0])).toBe(true);
         expect(isEqualArray(sks[i], sks[0])).toBe(true);
         expect(isEqualArray(bks[i], bks[0])).toBe(true);
         expect(isEqualArray(hks[i], hks[0])).toBe(true);
         expect(isEqualArray(hIVs[i], hIVs[0])).toBe(true);
      }
   }

   async function testNotUsuableAfterPurge(
      keyProvider: KeyProvider,
      iv: Uint8Array<ArrayBuffer>
   ) {
      await keyProvider.getCipherKey(false);
      await keyProvider.getSigningKey();
      await keyProvider.getBlockCipherKey(1);
      await keyProvider.getHintCipherKeyAndIV(iv);

      keyProvider.purge();

      await expect(keyProvider.getCipherKey(false)).rejects.toThrow();
      await expect(keyProvider.getSigningKey()).rejects.toThrow();
      await expect(keyProvider.getBlockCipherKey(1)).rejects.toThrow();
      await expect(keyProvider.getHintCipherKeyAndIV(iv)).rejects.toThrow();
   }

   it("PWDKeyProvider successful and not equivalent key generation", async function () {
      for (const alg of Ciphers.algs()) {
         const pwd = 'not a good pwd';
         const ic = cc.ICOUNT_MIN;
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));
         const randomArray = getRandom(48);
         const slt = randomArray.slice(0, cc.SLT_BYTES);
         const iv = randomArray.slice(cc.SLT_BYTES, cc.SLT_BYTES + Ciphers.algIVByteLength(alg));

         const keyProvider = new PWDKeyProvider(userCred, [pwd, undefined]);
         keyProvider.setCipherDataInfo({
            ver: cc.CURRENT_VERSION,
            alg,
            ic,
            slt,
            lp: 1,
            lpEnd: 1
         });

         await testKeyGenSuccessAndOveralp(keyProvider, iv, userCred);
         keyProvider.purge();
      }
   });


   it("PWDKeyProvider key are stable", async function () {
      for (const alg of Ciphers.algs()) {
         const pwd = 'not a good pwd';
         const ic = cc.ICOUNT_MIN;
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));
         const randomArray = getRandom(48);
         const slt = randomArray.slice(0, cc.SLT_BYTES);
         const iv = randomArray.slice(cc.SLT_BYTES, cc.SLT_BYTES + Ciphers.algIVByteLength(alg));

         const keyProvider = new PWDKeyProvider(userCred, [pwd, undefined]);
         keyProvider.setCipherDataInfo({
            ver: cc.CURRENT_VERSION,
            alg,
            ic,
            slt,
            lp: 1,
            lpEnd: 1
         });

         await testKeyGenStable(keyProvider, iv);
         keyProvider.purge();
      }
   });

   it("PWDKeyProvider unsuable after purge", async function () {
      for (const alg of Ciphers.algs()) {
         const pwd = 'not a good pwd';
         const ic = cc.ICOUNT_MIN;
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));
         const randomArray = getRandom(48);
         const slt = randomArray.slice(0, cc.SLT_BYTES);
         const iv = randomArray.slice(cc.SLT_BYTES, cc.SLT_BYTES + Ciphers.algIVByteLength(alg));

         const keyProvider = new PWDKeyProvider(userCred, [pwd, undefined]);
         keyProvider.setCipherDataInfo({
            ver: cc.CURRENT_VERSION,
            alg,
            ic,
            slt,
            lp: 1,
            lpEnd: 1
         });

         await testNotUsuableAfterPurge(keyProvider, iv);
      }
   });

   it("PWDKeyProvider clone after purge throws", function () {
      const userCred = getRandom(cc.USERCRED_BYTES);
      const keyProvider = new PWDKeyProvider(userCred, ['a pwd', undefined]);
      keyProvider.purge();

      expect(() => keyProvider.clone()).toThrow(/Cannot clone a purged keyProvider/);
   });

   it("PWDKeyProvider clone derives same keys after original is purged", async function () {
      const userCred = getRandom(cc.USERCRED_BYTES);
      const slt = getRandom(cc.SLT_BYTES);
      const cdInfo = {
         ver: cc.CURRENT_VERSION,
         alg: 'AES-GCM' as cc.CipherAlgs,
         ic: cc.ICOUNT_MIN,
         slt,
         lp: 1,
         lpEnd: 1,
      };

      const original = new PWDKeyProvider(userCred, ['a pwd', undefined]);
      original.setCipherDataInfo(cdInfo);
      const originalKey = (await original.getSigningKey()).slice(0);

      const clone = original.clone();
      original.purge();

      clone.setCipherDataInfo(cdInfo);
      const cloneKey = (await clone.getSigningKey()).slice(0);
      clone.purge();

      expect(isEqualArray(cloneKey, originalKey)).toBe(true);
   });

   it("PWDKeyProvider unsuable without cipherdatainfo", async function () {
      for (const alg of Ciphers.algs()) {
         const pwd = 'not a good pwd';
         const ic = cc.ICOUNT_MIN;
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));
         const randomArray = getRandom(48);
         const slt = randomArray.slice(0, cc.SLT_BYTES);
         const iv = randomArray.slice(cc.SLT_BYTES, cc.SLT_BYTES + Ciphers.algIVByteLength(alg));

         const keyProvider = new PWDKeyProvider(userCred, [pwd, undefined]);
         expect(() => keyProvider.getCipherDataInfo()).toThrow();
         expect(() => keyProvider.setHint("abc")).toThrow();
         await expect(keyProvider.getCipherKey(false)).rejects.toThrow();
         await expect(keyProvider.getSigningKey()).rejects.toThrow();
         await expect(keyProvider.getBlockCipherKey(1)).rejects.toThrow();
         await expect(keyProvider.getHintCipherKeyAndIV(iv)).rejects.toThrow();
         keyProvider.purge();
      }
   });

   it("PWDKeyProvider setCipherDataInfo rejects second call", function () {
      const userCred = getRandom(cc.USERCRED_BYTES);
      const slt = getRandom(cc.SLT_BYTES);
      const keyProvider = new PWDKeyProvider(userCred, ['a pwd', undefined]);

      keyProvider.setCipherDataInfo({
         ver: cc.CURRENT_VERSION,
         alg: 'AES-GCM',
         ic: cc.ICOUNT_MIN,
         slt,
         lp: 1,
         lpEnd: 1,
      });

      expect(() => keyProvider.setCipherDataInfo({
         ver: cc.CURRENT_VERSION,
         alg: 'X20-PLY',
         ic: cc.ICOUNT_MIN,
         slt,
         lp: 1,
         lpEnd: 1,
      })).toThrow(/CipherDataInfo can only be set once/);

      keyProvider.purge();
   });

   it("PWDKeyProvider setCipherDataInfo validates lp/lpEnd bounds", async function () {
      const userCred = getRandom(cc.USERCRED_BYTES);
      const slt = getRandom(cc.SLT_BYTES);
      const baseInfo = {
         ver: cc.CURRENT_VERSION,
         alg: 'AES-GCM' as cc.CipherAlgs,
         ic: cc.ICOUNT_MIN,
         slt,
      };

      // lp = 0 (below min)
      let keyProvider = new PWDKeyProvider(getRandom(cc.USERCRED_BYTES), ['a pwd', undefined]);
      expect(() => keyProvider.setCipherDataInfo({ ...baseInfo, lp: 0, lpEnd: 1 })).toThrow(/Invalid lp/);
      keyProvider.purge();

      // lp > lpEnd
      keyProvider = new PWDKeyProvider(getRandom(cc.USERCRED_BYTES), ['a pwd', undefined]);
      expect(() => keyProvider.setCipherDataInfo({ ...baseInfo, lp: 2, lpEnd: 1 })).toThrow(/Invalid lp/);
      keyProvider.purge();

      // lpEnd = 0 (below min)
      keyProvider = new PWDKeyProvider(getRandom(cc.USERCRED_BYTES), ['a pwd', undefined]);
      expect(() => keyProvider.setCipherDataInfo({ ...baseInfo, lp: 1, lpEnd: 0 })).toThrow(/Invalid lpEnd/);
      keyProvider.purge();

      // lpEnd > LP_MAX
      keyProvider = new PWDKeyProvider(getRandom(cc.USERCRED_BYTES), ['a pwd', undefined]);
      expect(() => keyProvider.setCipherDataInfo({ ...baseInfo, lp: 1, lpEnd: cc.LP_MAX + 1 })).toThrow(/Invalid lpEnd/);
      keyProvider.purge();

      // lp = lpEnd = LP_MAX (boundary success)
      keyProvider = new PWDKeyProvider(userCred, ['a pwd', undefined]);
      keyProvider.setCipherDataInfo({ ...baseInfo, lp: cc.LP_MAX, lpEnd: cc.LP_MAX });
      const key = (await keyProvider.getSigningKey()).slice(0);
      expect(key.byteLength).toBe(cc.KEY_BYTES);
      keyProvider.purge();
   });

   it("PWDKeyProvider rejects unknown versions", async function () {
      const slt = getRandom(cc.SLT_BYTES);
      const baseInfo = {
         alg: 'AES-GCM' as cc.CipherAlgs,
         ic: cc.ICOUNT_MIN,
         slt,
         lp: 1,
         lpEnd: 1,
      };

      let keyProvider = new PWDKeyProvider(getRandom(cc.USERCRED_BYTES), ['a pwd', undefined]);
      keyProvider.setCipherDataInfo({ ...baseInfo, ver: 0 });
      await expect(keyProvider.getCipherKey(false)).rejects.toThrow(/Invalid version/);
      keyProvider.purge();

      keyProvider = new PWDKeyProvider(getRandom(cc.USERCRED_BYTES), ['a pwd', undefined]);
      keyProvider.setCipherDataInfo({ ...baseInfo, ver: 3 });
      await expect(keyProvider.getCipherKey(false)).rejects.toThrow(/Invalid version/);
      keyProvider.purge();

      keyProvider = new PWDKeyProvider(getRandom(cc.USERCRED_BYTES), ['a pwd', undefined]);
      keyProvider.setCipherDataInfo({ ...baseInfo, ver: cc.CURRENT_VERSION + 1 });
      await expect(keyProvider.getCipherKey(false)).rejects.toThrow(/Invalid version/);
      keyProvider.purge();
   });

   it("setCipherDataInfo validates ic bounds", function () {
      const slt = getRandom(cc.SLT_BYTES);
      const baseInfo = {
         ver: cc.CURRENT_VERSION,
         alg: 'AES-GCM' as cc.CipherAlgs,
         slt,
         lp: 1,
         lpEnd: 1,
      };

      let keyProvider = new PWDKeyProvider(getRandom(cc.USERCRED_BYTES), ['a pwd', undefined]);
      expect(() => keyProvider.setCipherDataInfo({ ...baseInfo, ic: cc.ICOUNT_MIN - 1 })).toThrow(/Invalid ic/);
      keyProvider.purge();

      keyProvider = new PWDKeyProvider(getRandom(cc.USERCRED_BYTES), ['a pwd', undefined]);
      expect(() => keyProvider.setCipherDataInfo({ ...baseInfo, ic: cc.ICOUNT_MAX + 1 })).toThrow(/Invalid ic/);
      keyProvider.purge();

      // Boundary success: exactly ICOUNT_MAX is accepted.
      keyProvider = new PWDKeyProvider(getRandom(cc.USERCRED_BYTES), ['a pwd', undefined]);
      keyProvider.setCipherDataInfo({ ...baseInfo, ic: cc.ICOUNT_MAX });
      keyProvider.purge();
   });

   it("MasterKeyKeyProvider successful and not equivalent key generation", async function () {

      for (const alg of Ciphers.algs()) {
         const master = crypto.getRandomValues(new Uint8Array(cc.KEY_BYTES));
         const randomArray = getRandom(48);
         const slt = randomArray.slice(0, cc.SLT_BYTES);
         const iv = randomArray.slice(cc.SLT_BYTES, cc.SLT_BYTES + Ciphers.algIVByteLength(alg));

         const keyProvider = new MasterKeyKeyProvider(master);
         keyProvider.setCipherDataInfo({
            ver: cc.CURRENT_VERSION,
            alg,
            ic: 0,
            slt,
            lp: 1,
            lpEnd: 1
         });

         await testKeyGenSuccessAndOveralp(keyProvider, iv, master);
         keyProvider.purge();
      }
   });

   it("MasterKeyKeyProvider key are stable", async function () {

      for (const alg of Ciphers.algs()) {
         const master = crypto.getRandomValues(new Uint8Array(cc.KEY_BYTES));
         const randomArray = getRandom(48);
         const slt = randomArray.slice(0, cc.SLT_BYTES);
         const iv = randomArray.slice(cc.SLT_BYTES, cc.SLT_BYTES + Ciphers.algIVByteLength(alg));

         const keyProvider = new MasterKeyKeyProvider(master);
         keyProvider.setCipherDataInfo({
            ver: cc.CURRENT_VERSION,
            alg,
            ic: 0,
            slt,
            lp: 1,
            lpEnd: 1
         });

         await testKeyGenStable(keyProvider, iv);
         keyProvider.purge();

      }
   });

   it("MasterKeyKeyProvider unsuable without cipherdatainfo", async function () {
      for (const alg of Ciphers.algs()) {
         const master = crypto.getRandomValues(new Uint8Array(cc.KEY_BYTES));
         const randomArray = getRandom(48);
         const iv = randomArray.slice(cc.SLT_BYTES, cc.SLT_BYTES + Ciphers.algIVByteLength(alg));

         const keyProvider = new MasterKeyKeyProvider(master);
         expect(() => keyProvider.getCipherDataInfo()).toThrow();
         expect(() => keyProvider.setHint("abc")).toThrow();
         await expect(keyProvider.getCipherKey(false)).rejects.toThrow();
         await expect(keyProvider.getSigningKey()).rejects.toThrow();
         await expect(keyProvider.getBlockCipherKey(1)).rejects.toThrow();
         await expect(keyProvider.getHintCipherKeyAndIV(iv)).rejects.toThrow();
         keyProvider.purge();
      }
   });

   it("MasterKeyKeyProvider setCipherDataInfo rejects second call", function () {
      const master = getRandom(cc.KEY_BYTES);
      const slt = getRandom(cc.SLT_BYTES);
      const keyProvider = new MasterKeyKeyProvider(master);

      keyProvider.setCipherDataInfo({
         ver: cc.CURRENT_VERSION,
         alg: 'AES-GCM',
         ic: 0,
         slt,
         lp: 1,
         lpEnd: 1,
      });

      expect(() => keyProvider.setCipherDataInfo({
         ver: cc.CURRENT_VERSION,
         alg: 'X20-PLY',
         ic: 0,
         slt,
         lp: 1,
         lpEnd: 1,
      })).toThrow(/CipherDataInfo can only be set once/);

      keyProvider.purge();
   });

   it("MasterKeyKeyProvider setCipherDataInfo validates lp/lpEnd bounds", async function () {
      const slt = getRandom(cc.SLT_BYTES);
      const baseInfo = {
         ver: cc.CURRENT_VERSION,
         alg: 'AES-GCM' as cc.CipherAlgs,
         ic: 0,
         slt,
      };

      // lp = 0 (below min)
      let keyProvider = new MasterKeyKeyProvider(getRandom(cc.KEY_BYTES));
      expect(() => keyProvider.setCipherDataInfo({ ...baseInfo, lp: 0, lpEnd: 1 })).toThrow(/Invalid lp/);
      keyProvider.purge();

      // lp > lpEnd
      keyProvider = new MasterKeyKeyProvider(getRandom(cc.KEY_BYTES));
      expect(() => keyProvider.setCipherDataInfo({ ...baseInfo, lp: 2, lpEnd: 1 })).toThrow(/Invalid lp/);
      keyProvider.purge();

      // lpEnd = 0 (below min)
      keyProvider = new MasterKeyKeyProvider(getRandom(cc.KEY_BYTES));
      expect(() => keyProvider.setCipherDataInfo({ ...baseInfo, lp: 1, lpEnd: 0 })).toThrow(/Invalid lpEnd/);
      keyProvider.purge();

      // lpEnd > LP_MAX
      keyProvider = new MasterKeyKeyProvider(getRandom(cc.KEY_BYTES));
      expect(() => keyProvider.setCipherDataInfo({ ...baseInfo, lp: 1, lpEnd: cc.LP_MAX + 1 })).toThrow(/Invalid lpEnd/);
      keyProvider.purge();

      // lp = lpEnd = LP_MAX (boundary success)
      keyProvider = new MasterKeyKeyProvider(getRandom(cc.KEY_BYTES));
      keyProvider.setCipherDataInfo({ ...baseInfo, lp: cc.LP_MAX, lpEnd: cc.LP_MAX });
      const key = (await keyProvider.getSigningKey()).slice(0);
      expect(key.byteLength).toBe(cc.KEY_BYTES);
      keyProvider.purge();
   });

   it("MasterKeyKeyProvider rejects unknown versions", async function () {
      const slt = getRandom(cc.SLT_BYTES);
      const baseInfo = {
         alg: 'AES-GCM' as cc.CipherAlgs,
         ic: 0,
         slt,
         lp: 1,
         lpEnd: 1,
      };

      let keyProvider = new MasterKeyKeyProvider(getRandom(cc.KEY_BYTES));
      keyProvider.setCipherDataInfo({ ...baseInfo, ver: 0 });
      await expect(keyProvider.getSigningKey()).rejects.toThrow(/Invalid version/);
      keyProvider.purge();

      keyProvider = new MasterKeyKeyProvider(getRandom(cc.KEY_BYTES));
      keyProvider.setCipherDataInfo({ ...baseInfo, ver: cc.VERSION6 });
      await expect(keyProvider.getSigningKey()).rejects.toThrow(/Invalid version/);
      keyProvider.purge();

      keyProvider = new MasterKeyKeyProvider(getRandom(cc.KEY_BYTES));
      keyProvider.setCipherDataInfo({ ...baseInfo, ver: cc.CURRENT_VERSION + 1 });
      await expect(keyProvider.getSigningKey()).rejects.toThrow(/Invalid version/);
      keyProvider.purge();
   });

   it("MasterKeyKeyProvider rejects invalid masterKey", function () {
      expect(() => new MasterKeyKeyProvider(new Uint8Array(0))).toThrow(/Invalid masterKey length/);
      expect(() => new MasterKeyKeyProvider(getRandom(cc.KEY_BYTES - 1))).toThrow(/Invalid masterKey length/);
      expect(() => new MasterKeyKeyProvider(getRandom(cc.KEY_BYTES + 1))).toThrow(/Invalid masterKey length/);
      expect(() => new MasterKeyKeyProvider(new Uint8Array(cc.KEY_BYTES))).toThrow(/Invalid masterKey: all zero bytes/);
   });

   it("MasterKeyKeyProvider unsuable after purge", async function () {
      for (const alg of Ciphers.algs()) {
         const master = crypto.getRandomValues(new Uint8Array(cc.KEY_BYTES));
         const randomArray = getRandom(48);
         const slt = randomArray.slice(0, cc.SLT_BYTES);
         const iv = randomArray.slice(cc.SLT_BYTES, cc.SLT_BYTES + Ciphers.algIVByteLength(alg));

         const keyProvider = new MasterKeyKeyProvider(master);
         keyProvider.setCipherDataInfo({
            ver: cc.CURRENT_VERSION,
            alg,
            ic: 0,
            slt,
            lp: 1,
            lpEnd: 1
         });

         await testNotUsuableAfterPurge(keyProvider, iv);
      }
   });

   it("MasterKeyKeyProvider clone after purge throws", function () {
      const master = getRandom(cc.KEY_BYTES);
      const keyProvider = new MasterKeyKeyProvider(master);
      keyProvider.purge();

      expect(() => keyProvider.clone()).toThrow(/Cannot clone a purged keyProvider/);
   });

   it("MasterKeyKeyProvider clone derives same keys after original is purged", async function () {
      const master = getRandom(cc.KEY_BYTES);
      const slt = getRandom(cc.SLT_BYTES);
      const cdInfo = {
         ver: cc.CURRENT_VERSION,
         alg: 'AES-GCM' as cc.CipherAlgs,
         ic: 0,
         slt,
         lp: 1,
         lpEnd: 1,
      };

      const original = new MasterKeyKeyProvider(master);
      original.setCipherDataInfo(cdInfo);
      const originalKey = (await original.getSigningKey()).slice(0);

      const clone = original.clone();
      original.purge();

      clone.setCipherDataInfo(cdInfo);
      const cloneKey = (await clone.getSigningKey()).slice(0);
      clone.purge();

      expect(isEqualArray(cloneKey, originalKey)).toBe(true);
   });


   it("PWDKeyProvider keys match expected values", async function () {

      const expected:  [number, Record<cc.CipherAlgs, Record<string, Uint8Array<ArrayBuffer>>>][] = [
         [cc.VERSION4, {
            'AES-GCM': {
               ek: new Uint8Array([158, 221, 13, 155, 167, 216, 81, 115, 151, 193, 225, 53, 187, 156, 175, 196, 85, 234, 233, 199, 86, 45, 149, 120, 1, 57, 14, 102, 147, 123, 7, 150]),
               sk: new Uint8Array([238, 127, 13, 239, 238, 127, 177, 22, 231, 87, 89, 23, 88, 52, 42, 22, 6, 170, 172, 112, 111, 101, 147, 204, 238, 28, 203, 159, 118, 54, 139, 151]),
               hk: new Uint8Array([253, 30, 237, 129, 147, 186, 235, 65, 217, 78, 219, 38, 163, 12, 23, 248, 3, 118, 123, 120, 237, 0, 56, 103, 67, 76, 88, 126, 153, 83, 238, 85]),
               hIV: new Uint8Array([46, 22, 226, 86, 89, 132, 143, 185, 198, 129, 242, 241]),
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
               hIV: new Uint8Array([46, 22, 226, 86, 89, 132, 143, 185, 198, 129, 242, 241, 183, 195, 191, 229, 162, 127, 162, 148, 75, 16, 28, 140, 53, 215, 85, 89, 158, 248, 52, 175]),
            }
         }],
         [cc.VERSION5, {
            'AES-GCM': {
               ek: new Uint8Array([158, 221, 13, 155, 167, 216, 81, 115, 151, 193, 225, 53, 187, 156, 175, 196, 85, 234, 233, 199, 86, 45, 149, 120, 1, 57, 14, 102, 147, 123, 7, 150]),
               sk: new Uint8Array([238, 127, 13, 239, 238, 127, 177, 22, 231, 87, 89, 23, 88, 52, 42, 22, 6, 170, 172, 112, 111, 101, 147, 204, 238, 28, 203, 159, 118, 54, 139, 151]),
               hk: new Uint8Array([253, 30, 237, 129, 147, 186, 235, 65, 217, 78, 219, 38, 163, 12, 23, 248, 3, 118, 123, 120, 237, 0, 56, 103, 67, 76, 88, 126, 153, 83, 238, 85]),
               hIV: new Uint8Array([46, 22, 226, 86, 89, 132, 143, 185, 198, 129, 242, 241]),
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
               hIV: new Uint8Array([46, 22, 226, 86, 89, 132, 143, 185, 198, 129, 242, 241, 183, 195, 191, 229, 162, 127, 162, 148, 75, 16, 28, 140, 53, 215, 85, 89, 158, 248, 52, 175]),
            }
         }],
         [cc.VERSION6, {
            'AES-GCM': {
               ek: new Uint8Array([158, 221, 13, 155, 167, 216, 81, 115, 151, 193, 225, 53, 187, 156, 175, 196, 85, 234, 233, 199, 86, 45, 149, 120, 1, 57, 14, 102, 147, 123, 7, 150]),
               sk: new Uint8Array([172, 133, 166, 39, 233, 237, 204, 73, 234, 53, 191, 16, 169, 71, 164, 71, 36, 51, 18, 87, 19, 33, 25, 50, 224, 33, 120, 21, 233, 20, 154, 79]),
               hk: new Uint8Array([34, 121, 121, 4, 207, 55, 202, 73, 83, 4, 58, 102, 135, 111, 186, 242, 3, 187, 239, 108, 251, 245, 3, 245, 3, 77, 228, 197, 101, 4, 16, 94]),
               hIV: new Uint8Array([46, 22, 226, 86, 89, 132, 143, 185, 198, 129, 242, 241]),
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
               hIV: new Uint8Array([46, 22, 226, 86, 89, 132, 143, 185, 198, 129, 242, 241, 183, 195, 191, 229, 162, 127, 162, 148, 75, 16, 28, 140, 53, 215, 85, 89, 158, 248, 52, 175]),
               bk: new Uint8Array([192, 104, 75, 166, 230, 145, 51, 60, 135, 138, 96, 200, 191, 249, 197, 149, 134, 168, 133, 169, 65, 94, 40, 46, 229, 162, 180, 28, 232, 61, 3, 227]),
            }
         }],
         // generated by: pnpm vectors:keys
         [cc.VERSION7, {
            'AES-GCM': {
               ek: new Uint8Array([116, 242, 61, 10, 108, 97, 209, 124, 228, 61, 197, 29, 51, 181, 35, 99, 249, 55, 21, 36, 31, 115, 170, 7, 7, 61, 219, 85, 163, 160, 24, 168]),
               sk: new Uint8Array([163, 148, 226, 77, 124, 112, 100, 108, 128, 224, 74, 73, 171, 218, 24, 13, 98, 66, 35, 34, 75, 207, 135, 22, 39, 62, 113, 121, 18, 165, 254, 28]),
               hk: new Uint8Array([14, 159, 104, 237, 222, 85, 138, 34, 126, 157, 81, 139, 98, 171, 77, 10, 127, 148, 230, 254, 125, 30, 46, 228, 203, 147, 134, 141, 164, 10, 81, 105]),
               hIV: new Uint8Array([158, 97, 138, 184, 44, 70, 219, 110, 186, 127, 51, 99]),
               bk: new Uint8Array([61, 57, 107, 74, 35, 118, 132, 160, 207, 182, 124, 180, 165, 163, 55, 151, 178, 51, 9, 5, 116, 67, 15, 142, 183, 207, 224, 150, 32, 215, 8, 248]),
               commit: new Uint8Array([77, 154, 216, 123, 90, 142, 38, 0, 114, 14, 150, 236, 96, 163, 55, 190, 160, 107, 23, 55, 247, 33, 185, 214, 56, 30, 219, 91, 142, 191, 14, 106]),
            },
            'X20-PLY': {
               ek: new Uint8Array([151, 104, 43, 112, 157, 41, 222, 172, 99, 235, 77, 192, 78, 45, 125, 119, 155, 97, 155, 224, 132, 165, 10, 245, 166, 169, 255, 126, 226, 151, 228, 243]),
               sk: new Uint8Array([108, 91, 159, 253, 3, 33, 237, 112, 173, 212, 215, 133, 101, 236, 7, 155, 103, 141, 79, 64, 21, 81, 26, 205, 230, 87, 185, 83, 55, 85, 249, 239]),
               hk: new Uint8Array([91, 199, 210, 194, 45, 236, 239, 162, 119, 252, 31, 117, 65, 227, 20, 215, 231, 19, 233, 167, 52, 92, 220, 100, 36, 118, 122, 91, 14, 87, 164, 154]),
               hIV: new Uint8Array([28, 76, 162, 179, 150, 28, 137, 55, 242, 29, 42, 1, 236, 107, 209, 167, 183, 111, 247, 144, 196, 97, 54, 20]),
               bk: new Uint8Array([148, 165, 235, 202, 182, 161, 188, 67, 80, 48, 111, 82, 92, 161, 207, 212, 127, 134, 9, 255, 30, 163, 149, 208, 212, 249, 147, 209, 127, 37, 130, 56]),
               commit: new Uint8Array([45, 191, 194, 209, 53, 35, 180, 104, 130, 97, 112, 75, 143, 223, 192, 166, 119, 165, 219, 109, 77, 131, 51, 175, 180, 241, 157, 55, 148, 170, 90, 15]),
            },
            'AEGIS-256': {
               ek: new Uint8Array([19, 188, 48, 103, 209, 12, 52, 137, 155, 117, 18, 67, 70, 112, 1, 71, 50, 252, 45, 26, 177, 199, 123, 80, 230, 35, 252, 202, 242, 167, 57, 11]),
               sk: new Uint8Array([189, 127, 169, 232, 173, 233, 238, 65, 214, 23, 142, 49, 82, 97, 214, 114, 234, 91, 110, 232, 241, 73, 156, 158, 2, 71, 231, 169, 170, 186, 205, 244]),
               hk: new Uint8Array([227, 167, 244, 172, 42, 64, 64, 76, 8, 86, 73, 187, 220, 48, 229, 75, 117, 207, 41, 13, 167, 31, 227, 6, 31, 192, 0, 121, 59, 85, 152, 93]),
               hIV: new Uint8Array([133, 34, 227, 194, 43, 92, 130, 203, 33, 207, 226, 139, 183, 122, 0, 76, 169, 59, 73, 11, 114, 149, 212, 176, 86, 242, 245, 99, 164, 140, 17, 182]),
               bk: new Uint8Array([20, 164, 54, 117, 155, 116, 35, 191, 210, 69, 54, 161, 240, 120, 40, 26, 192, 30, 136, 108, 111, 212, 89, 137, 18, 24, 97, 36, 160, 110, 66, 107]),
               commit: new Uint8Array([45, 179, 120, 212, 44, 215, 88, 239, 118, 245, 139, 56, 153, 241, 79, 96, 2, 103, 172, 145, 223, 192, 113, 244, 174, 167, 80, 221, 248, 24, 136, 27]),
            }
         }],

         // generated by: pnpm vectors:keys
         [cc.VERSION7, {
            'AES-GCM': {
               customAd: new Uint8Array([120, 190, 112, 41, 122, 140, 204, 6, 253, 18]),
               ek: new Uint8Array([254, 57, 68, 32, 174, 22, 216, 5, 68, 114, 63, 121, 50, 178, 236, 181, 166, 226, 132, 131, 64, 195, 139, 103, 82, 12, 131, 30, 155, 73, 48, 171]),
               sk: new Uint8Array([126, 50, 182, 156, 181, 156, 25, 223, 201, 133, 54, 157, 205, 248, 58, 217, 140, 70, 138, 144, 125, 194, 129, 61, 170, 21, 220, 71, 182, 14, 241, 190]),
               hk: new Uint8Array([136, 115, 155, 174, 209, 123, 13, 65, 26, 227, 183, 174, 49, 205, 123, 224, 133, 43, 145, 142, 33, 182, 132, 255, 129, 221, 101, 228, 84, 38, 141, 124]),
               hIV: new Uint8Array([0, 39, 72, 109, 192, 71, 88, 214, 114, 43, 73, 90]),
               bk: new Uint8Array([234, 196, 137, 208, 116, 105, 34, 95, 206, 229, 53, 52, 136, 96, 42, 94, 167, 70, 97, 12, 28, 166, 131, 85, 188, 123, 124, 28, 7, 65, 111, 238]),
               commit: new Uint8Array([131, 29, 40, 43, 143, 181, 129, 177, 10, 164, 150, 2, 70, 34, 88, 21, 12, 141, 235, 233, 164, 40, 138, 63, 61, 47, 150, 109, 71, 198, 254, 168]),
            },
            'X20-PLY': {
               customAd: new Uint8Array([120, 190, 112, 41, 122, 140, 204, 6, 253, 18]),
               ek: new Uint8Array([214, 16, 97, 74, 248, 18, 228, 247, 137, 139, 165, 39, 178, 202, 71, 208, 9, 231, 86, 55, 7, 75, 61, 214, 115, 197, 119, 145, 51, 91, 166, 41]),
               sk: new Uint8Array([9, 235, 189, 10, 101, 2, 26, 112, 109, 246, 151, 81, 153, 141, 65, 230, 49, 21, 26, 239, 20, 191, 246, 57, 157, 54, 40, 85, 217, 114, 75, 129]),
               hk: new Uint8Array([99, 90, 22, 36, 151, 128, 108, 55, 166, 83, 112, 208, 14, 165, 105, 9, 222, 177, 193, 220, 238, 176, 200, 48, 16, 208, 42, 181, 28, 136, 74, 59]),
               hIV: new Uint8Array([16, 184, 236, 32, 200, 140, 28, 28, 129, 178, 253, 194, 208, 20, 101, 87, 143, 167, 142, 28, 58, 180, 202, 31]),
               bk: new Uint8Array([184, 122, 197, 228, 83, 178, 105, 201, 91, 81, 19, 96, 182, 46, 19, 191, 144, 131, 184, 237, 155, 182, 158, 53, 213, 152, 88, 210, 169, 130, 221, 232]),
               commit: new Uint8Array([234, 255, 111, 180, 53, 47, 237, 148, 253, 221, 99, 35, 107, 191, 54, 242, 170, 94, 200, 196, 50, 37, 84, 127, 126, 146, 0, 58, 112, 77, 137, 36]),
            },
            'AEGIS-256': {
               customAd: new Uint8Array([120, 190, 112, 41, 122, 140, 204, 6, 253, 18]),
               ek: new Uint8Array([235, 73, 183, 169, 184, 191, 201, 229, 211, 241, 189, 43, 42, 230, 10, 91, 12, 34, 171, 146, 189, 245, 152, 3, 71, 20, 255, 192, 48, 32, 160, 135]),
               sk: new Uint8Array([111, 119, 142, 83, 177, 9, 77, 51, 200, 32, 67, 179, 102, 37, 175, 206, 194, 51, 54, 215, 59, 141, 244, 19, 154, 2, 162, 29, 105, 71, 89, 44]),
               hk: new Uint8Array([2, 137, 191, 34, 190, 9, 124, 25, 73, 149, 145, 110, 60, 97, 59, 146, 161, 202, 7, 27, 124, 215, 156, 149, 223, 212, 220, 118, 171, 88, 39, 191]),
               hIV: new Uint8Array([236, 88, 168, 140, 198, 68, 124, 100, 211, 209, 58, 249, 94, 222, 127, 255, 242, 116, 219, 47, 239, 87, 68, 130, 28, 239, 211, 58, 217, 144, 143, 205]),
               bk: new Uint8Array([200, 210, 75, 8, 126, 197, 119, 121, 136, 27, 57, 145, 242, 203, 239, 239, 117, 217, 194, 15, 242, 140, 14, 85, 145, 12, 13, 234, 238, 199, 144, 131]),
               commit: new Uint8Array([88, 26, 173, 27, 85, 17, 59, 173, 120, 40, 136, 210, 182, 176, 221, 40, 97, 9, 56, 178, 211, 228, 252, 10, 177, 128, 124, 51, 127, 193, 80, 53]),
            }
         }]
      ];

      for (const [ver, algsExpected] of expected) {
         for (const alg of Ciphers.algs()) {
            const algExpected = algsExpected[alg];
            expect(algExpected).toBeDefined();

            const pwd = 'a good pwd';
            const ic = cc.ICOUNT_MIN;
            const userCred = new Uint8Array([214, 245, 252, 122, 133, 39, 76, 162, 64, 201, 143, 217, 237, 57, 18, 207, 199, 153, 20, 28, 162, 9, 236, 66, 100, 103, 152, 159, 226, 50, 225, 129]);
            const slt = new Uint8Array([160, 202, 135, 230, 125, 174, 49, 189, 171, 56, 203, 1, 237, 233, 27, 76]);
            const iv = new Uint8Array([46, 22, 226, 86, 89, 132, 143, 185, 198, 129, 242, 241, 183, 195, 191, 229, 162, 127, 162, 148, 75, 16, 28, 140, 53, 215, 85, 89, 158, 248, 52, 175]);

            const keyProvider = new PWDKeyProvider(userCred, [pwd, undefined], algExpected.customAd);
            keyProvider.setCipherDataInfo({
               ver: ver,
               alg,
               ic,
               slt,
               lp: 1,
               lpEnd: 1
            });

            const ek = await keyProvider.getCipherKey(false);
            const sk = await keyProvider.getSigningKey();
            const [hk, hIV] = await keyProvider.getHintCipherKeyAndIV(iv.slice(0, Ciphers.algIVByteLength(alg)));
            await expect(keyProvider.getBlockCipherKey(0)).rejects.toThrow(/Invalid block number: 0/);
            const bk = ver >= cc.VERSION6 ? await keyProvider.getBlockCipherKey(1) : undefined;
            const commit = keyProvider.supportsCommitment ? await keyProvider.getKeyCommitment() : undefined;

            expect(isEqualArray(ek, algExpected.ek)).toBe(true);
            expect(isEqualArray(sk, algExpected.sk)).toBe(true);
            expect(isEqualArray(hk, algExpected.hk)).toBe(true);
            expect(isEqualArray(hIV, algExpected.hIV)).toBe(true);
            if (bk) {
               expect(isEqualArray(bk, algExpected.bk)).toBe(true);
            }
            if (commit) {
               expect(isEqualArray(commit, algExpected.commit)).toBe(true);
            }

            expect(isEqualArray(ek, userCred)).toBe(false);
            expect(isEqualArray(sk, userCred)).toBe(false);
            expect(isEqualArray(hk, userCred)).toBe(false);
            expect(isEqualArray(hIV, userCred)).toBe(false);
            if (bk) {
               expect(isEqualArray(bk, userCred)).toBe(false);
            }
            if (commit) {
               expect(isEqualArray(commit, userCred)).toBe(false);
            }
         }
      }
   });

   it("PWDKeyProvider getBlockCipherKey block number range", async function () {
      const slt = getRandom(cc.SLT_BYTES);
      const baseInfo = {
         ver: cc.CURRENT_VERSION,
         alg: 'AES-GCM' as cc.CipherAlgs,
         ic: cc.ICOUNT_MIN,
         slt,
         lp: 1,
         lpEnd: 1,
      };

      // Called before getCipherKey
      let keyProvider = new PWDKeyProvider(getRandom(cc.USERCRED_BYTES), ['a pwd', undefined]);
      keyProvider.setCipherDataInfo(baseInfo);
      await expect(keyProvider.getBlockCipherKey(1)).rejects.toThrow(/getCipherKey/);
      keyProvider.purge();

      keyProvider = new PWDKeyProvider(getRandom(cc.USERCRED_BYTES), ['a pwd', undefined]);
      keyProvider.setCipherDataInfo(baseInfo);
      await keyProvider.getCipherKey(false);

      await expect(keyProvider.getBlockCipherKey(-1)).rejects.toThrow(/Invalid block number/);
      await expect(keyProvider.getBlockCipherKey(0)).rejects.toThrow(/Invalid block number/);
      await expect(keyProvider.getBlockCipherKey(cc.BLOCKS_MAX + 1)).rejects.toThrow(/Invalid block number/);

      const largeBk = (await keyProvider.getBlockCipherKey(cc.BLOCKS_MAX));
      expect(largeBk.byteLength).toBe(cc.KEY_BYTES);
      keyProvider.purge();
   });

   it("PWDKeyProvider getBlockCipherKey enforces version", async function () {
      const slt = getRandom(cc.SLT_BYTES);
      const keyProvider = new PWDKeyProvider(getRandom(cc.USERCRED_BYTES), ['a pwd', undefined]);
      keyProvider.setCipherDataInfo({
         ver: cc.VERSION4,
         alg: 'AES-GCM',
         ic: cc.ICOUNT_MIN,
         slt,
         lp: 1,
         lpEnd: 1,
      });
      await keyProvider.getCipherKey(false);
      await expect(keyProvider.getBlockCipherKey(1)).rejects.toThrow(/Block cipher keys not supported/);
      keyProvider.purge();
   });

   it("MasterKeyKeyProvider getBlockCipherKey block number range", async function () {
      const slt = getRandom(cc.SLT_BYTES);
      const baseInfo = {
         ver: cc.CURRENT_VERSION,
         alg: 'AES-GCM' as cc.CipherAlgs,
         ic: 0,
         slt,
         lp: 1,
         lpEnd: 1,
      };

      // Called before getCipherKey
      let keyProvider = new MasterKeyKeyProvider(getRandom(cc.KEY_BYTES));
      keyProvider.setCipherDataInfo(baseInfo);
      await expect(keyProvider.getBlockCipherKey(1)).rejects.toThrow(/getCipherKey/);
      keyProvider.purge();

      keyProvider = new MasterKeyKeyProvider(getRandom(cc.KEY_BYTES));
      keyProvider.setCipherDataInfo(baseInfo);
      await keyProvider.getCipherKey(false);

      await expect(keyProvider.getBlockCipherKey(-1)).rejects.toThrow(/Invalid block number/);
      await expect(keyProvider.getBlockCipherKey(0)).rejects.toThrow(/Invalid block number/);
      await expect(keyProvider.getBlockCipherKey(cc.BLOCKS_MAX + 1)).rejects.toThrow(/Invalid block number/);

      const largeBk = (await keyProvider.getBlockCipherKey(cc.BLOCKS_MAX));
      expect(largeBk.byteLength).toBe(cc.KEY_BYTES);
      keyProvider.purge();
   });

   it("MasterKeyKeyProvider keys match expected values", async function () {

      // generated by: pnpm vectors:keys
      const expected:  [number, Record<cc.CipherAlgs, Record<string, Uint8Array<ArrayBuffer>>>][] = [
         [cc.VERSION7, {
            'AES-GCM': {
               ek: new Uint8Array([25, 129, 11, 96, 135, 33, 63, 217, 43, 12, 118, 167, 202, 183, 106, 149, 187, 161, 97, 89, 108, 10, 137, 90, 196, 127, 77, 148, 25, 75, 158, 72]),
               sk: new Uint8Array([110, 9, 12, 164, 246, 119, 116, 215, 233, 250, 105, 189, 226, 46, 48, 111, 53, 146, 1, 174, 176, 250, 228, 59, 76, 194, 83, 60, 57, 17, 235, 183]),
               hk: new Uint8Array([75, 233, 122, 79, 182, 152, 112, 212, 91, 189, 225, 190, 76, 54, 190, 102, 17, 186, 165, 214, 69, 190, 3, 137, 73, 80, 162, 22, 104, 169, 53, 118]),
               hIV: new Uint8Array([6, 172, 134, 98, 183, 253, 128, 188, 13, 97, 111, 81]),
               bk: new Uint8Array([13, 93, 49, 8, 209, 104, 26, 47, 249, 114, 126, 206, 191, 118, 177, 96, 224, 48, 22, 90, 164, 139, 222, 89, 126, 84, 138, 27, 187, 220, 87, 89]),
               commit: new Uint8Array([224, 81, 234, 9, 44, 181, 208, 151, 228, 161, 23, 68, 252, 120, 156, 182, 144, 181, 111, 75, 230, 148, 179, 81, 70, 165, 40, 205, 174, 7, 173, 3]),
            },
            'X20-PLY': {
               ek: new Uint8Array([47, 200, 68, 171, 123, 192, 12, 3, 72, 76, 206, 187, 112, 134, 28, 138, 118, 254, 214, 9, 58, 159, 132, 13, 246, 6, 25, 189, 136, 27, 172, 38]),
               sk: new Uint8Array([139, 60, 86, 241, 1, 168, 19, 135, 3, 153, 33, 106, 24, 176, 100, 83, 190, 219, 133, 151, 142, 179, 33, 119, 75, 183, 33, 181, 146, 252, 129, 238]),
               hk: new Uint8Array([117, 255, 53, 125, 151, 101, 143, 79, 167, 113, 143, 143, 241, 210, 32, 72, 48, 125, 200, 166, 64, 50, 144, 203, 69, 20, 152, 197, 56, 185, 80, 199]),
               hIV: new Uint8Array([218, 227, 148, 190, 235, 92, 131, 150, 70, 55, 70, 227, 76, 136, 136, 206, 13, 32, 236, 248, 229, 46, 159, 201]),
               bk: new Uint8Array([202, 1, 233, 57, 83, 94, 188, 96, 217, 166, 49, 229, 76, 183, 46, 12, 110, 151, 152, 27, 91, 88, 58, 242, 246, 75, 101, 214, 47, 180, 189, 117]),
               commit: new Uint8Array([47, 120, 69, 120, 229, 144, 241, 59, 138, 247, 198, 85, 111, 184, 200, 245, 31, 115, 55, 255, 93, 110, 201, 31, 239, 13, 223, 26, 49, 235, 117, 156]),
            },
            'AEGIS-256': {
               ek: new Uint8Array([95, 116, 198, 245, 2, 214, 147, 10, 88, 79, 2, 125, 213, 6, 93, 192, 3, 211, 246, 22, 55, 149, 137, 121, 163, 131, 81, 149, 155, 156, 111, 8]),
               sk: new Uint8Array([34, 79, 216, 66, 110, 252, 78, 127, 203, 61, 9, 109, 155, 190, 103, 112, 115, 227, 88, 57, 79, 143, 245, 159, 161, 201, 146, 128, 183, 70, 68, 242]),
               hk: new Uint8Array([108, 163, 10, 153, 128, 142, 16, 241, 125, 197, 75, 229, 89, 210, 87, 187, 145, 248, 125, 139, 88, 174, 139, 159, 178, 177, 151, 231, 241, 83, 147, 181]),
               hIV: new Uint8Array([163, 206, 50, 53, 126, 162, 225, 104, 13, 75, 141, 218, 55, 126, 20, 91, 110, 252, 197, 109, 246, 201, 185, 189, 94, 65, 189, 240, 44, 151, 35, 84]),
               bk: new Uint8Array([165, 4, 182, 231, 7, 1, 91, 158, 82, 74, 197, 67, 135, 164, 242, 218, 1, 159, 28, 187, 192, 87, 146, 97, 81, 143, 61, 78, 99, 212, 16, 172]),
               commit: new Uint8Array([222, 209, 2, 95, 0, 57, 254, 148, 51, 177, 56, 63, 53, 146, 242, 17, 60, 16, 44, 150, 95, 33, 134, 34, 73, 144, 41, 75, 117, 129, 0, 219]),
            }
         }],
         [cc.VERSION7, {
            'AES-GCM': {
               customAd: new Uint8Array([120, 190, 112, 41, 122, 140, 204, 6, 253, 18]),
               ek: new Uint8Array([62, 43, 242, 215, 21, 141, 122, 13, 2, 38, 243, 254, 112, 200, 114, 92, 59, 80, 209, 207, 157, 127, 132, 17, 80, 61, 240, 220, 149, 88, 170, 16]),
               sk: new Uint8Array([209, 56, 236, 89, 220, 203, 165, 253, 32, 160, 210, 53, 220, 128, 14, 68, 197, 175, 146, 228, 20, 152, 87, 54, 106, 34, 231, 231, 106, 250, 70, 228]),
               hk: new Uint8Array([118, 52, 25, 8, 249, 215, 77, 139, 225, 231, 17, 183, 42, 184, 141, 41, 69, 89, 112, 146, 26, 90, 182, 1, 88, 18, 106, 155, 24, 30, 134, 98]),
               hIV: new Uint8Array([93, 210, 168, 79, 69, 155, 53, 55, 4, 151, 150, 82]),
               bk: new Uint8Array([174, 156, 65, 21, 147, 3, 148, 239, 97, 217, 216, 244, 174, 204, 221, 199, 172, 32, 144, 144, 219, 11, 166, 147, 5, 151, 209, 213, 26, 145, 88, 51]),
               commit: new Uint8Array([227, 73, 243, 13, 96, 140, 75, 83, 188, 178, 164, 186, 100, 115, 138, 249, 4, 16, 27, 152, 166, 95, 146, 171, 42, 253, 162, 34, 64, 173, 37, 226]),
            },
            'X20-PLY': {
               customAd: new Uint8Array([120, 190, 112, 41, 122, 140, 204, 6, 253, 18]),
               ek: new Uint8Array([157, 147, 112, 209, 3, 40, 65, 66, 67, 89, 106, 123, 251, 202, 215, 13, 68, 220, 209, 45, 56, 197, 88, 38, 190, 0, 91, 51, 88, 214, 113, 26]),
               sk: new Uint8Array([249, 14, 233, 174, 146, 161, 86, 217, 253, 35, 214, 231, 164, 101, 249, 169, 133, 33, 21, 58, 191, 195, 89, 182, 245, 174, 48, 42, 254, 192, 206, 54]),
               hk: new Uint8Array([90, 2, 146, 127, 213, 234, 202, 181, 133, 213, 133, 0, 88, 241, 203, 170, 175, 125, 252, 25, 196, 139, 48, 197, 202, 146, 221, 139, 241, 59, 151, 105]),
               hIV: new Uint8Array([43, 249, 167, 241, 45, 108, 151, 45, 207, 180, 166, 171, 18, 172, 103, 58, 12, 180, 40, 124, 114, 119, 122, 226]),
               bk: new Uint8Array([201, 171, 30, 45, 106, 18, 219, 107, 106, 223, 159, 107, 13, 120, 190, 97, 44, 234, 216, 122, 136, 194, 236, 94, 136, 10, 27, 12, 3, 244, 223, 158]),
               commit: new Uint8Array([3, 67, 93, 221, 110, 13, 198, 0, 176, 97, 83, 132, 66, 41, 218, 215, 144, 54, 0, 233, 236, 102, 227, 187, 160, 104, 121, 166, 169, 186, 30, 95]),
            },
            'AEGIS-256': {
               customAd: new Uint8Array([120, 190, 112, 41, 122, 140, 204, 6, 253, 18]),
               ek: new Uint8Array([115, 173, 169, 134, 46, 62, 56, 41, 73, 181, 183, 176, 225, 186, 38, 91, 245, 119, 231, 71, 130, 21, 108, 106, 128, 166, 89, 87, 198, 61, 87, 192]),
               sk: new Uint8Array([144, 248, 50, 96, 159, 123, 1, 69, 238, 133, 67, 105, 44, 65, 176, 132, 137, 71, 224, 164, 19, 132, 216, 195, 53, 69, 216, 121, 93, 44, 221, 21]),
               hk: new Uint8Array([143, 27, 241, 195, 93, 150, 106, 186, 95, 37, 85, 26, 222, 120, 73, 92, 221, 73, 223, 252, 216, 35, 80, 241, 28, 195, 116, 199, 203, 157, 194, 82]),
               hIV: new Uint8Array([119, 117, 163, 175, 98, 141, 56, 219, 217, 204, 129, 121, 24, 67, 69, 107, 88, 236, 94, 21, 224, 199, 181, 250, 149, 167, 226, 250, 1, 184, 94, 176]),
               bk: new Uint8Array([24, 136, 144, 244, 195, 210, 250, 38, 63, 197, 58, 11, 199, 197, 251, 8, 229, 54, 250, 194, 31, 103, 13, 177, 249, 88, 84, 181, 115, 73, 242, 171]),
               commit: new Uint8Array([108, 202, 108, 21, 9, 113, 198, 9, 66, 19, 109, 234, 247, 151, 188, 118, 110, 53, 120, 90, 138, 57, 103, 246, 198, 67, 72, 221, 137, 144, 237, 103]),
            }
         }]
      ];

      for (const [ver, algsExpected] of expected) {
         for (const alg of Ciphers.algs()) {
            const algExpected = algsExpected[alg];
            expect(algExpected).toBeDefined();

            const slt = new Uint8Array([247, 229, 145, 155, 90, 26, 149, 132, 44, 75, 197, 178, 187, 88, 41, 244]);
            const iv = new Uint8Array([110, 248, 21, 150, 142, 146, 67, 223, 194, 230, 44, 28, 247, 71, 109, 61, 53, 215, 85, 89, 158, 248, 52, 175,53, 215, 169, 223, 219, 248, 52, 175]);
            const master = new Uint8Array([88, 164, 150, 177, 85, 43, 43, 25, 42, 250, 120, 190, 112, 26, 41, 122, 140, 204, 6, 253, 225, 220, 237, 10, 80, 64, 148, 152, 204, 30, 231, 18]);

            const keyProvider = new MasterKeyKeyProvider(master, algExpected.customAd);
            keyProvider.setCipherDataInfo({
               ver: ver,
               alg,
               ic: 0,
               slt,
               lp: 1,
               lpEnd: 1
            });
            let ek = await keyProvider.getCipherKey(false);
            let sk = await keyProvider.getSigningKey();
            let [hk, hIV] = await keyProvider.getHintCipherKeyAndIV(iv.slice(0, Ciphers.algIVByteLength(alg)));
            await expect(keyProvider.getBlockCipherKey(0)).rejects.toThrow(/Invalid block number: 0/);
            let bk = await keyProvider.getBlockCipherKey(1);
            let commit = await keyProvider.getKeyCommitment();

            expect(isEqualArray(ek, algExpected.ek)).toBe(true);
            expect(isEqualArray(sk, algExpected.sk)).toBe(true);
            expect(isEqualArray(hk, algExpected.hk)).toBe(true);
            expect(isEqualArray(hIV, algExpected.hIV)).toBe(true);
            expect(isEqualArray(bk, algExpected.bk)).toBe(true);
            expect(isEqualArray(commit, algExpected.commit)).toBe(true);

            expect(isEqualArray(ek, master)).toBe(false);
            expect(isEqualArray(sk, master)).toBe(false);
            expect(isEqualArray(hk, master)).toBe(false);
            expect(isEqualArray(hIV, master)).toBe(false);
            expect(isEqualArray(bk, master)).toBe(false);
            expect(isEqualArray(commit, master)).toBe(false);
         }
      }
   });

   it("PWDKeyProvider keys match expected values, multi-loop with customAd", async function () {

      // generated by: pnpm vectors:keys
      const expected: [number, number, Record<cc.CipherAlgs, Record<string, Uint8Array<ArrayBuffer>>>][] = [
         [cc.VERSION7, 1, {
            'AES-GCM': {
               ek: new Uint8Array([254, 57, 68, 32, 174, 22, 216, 5, 68, 114, 63, 121, 50, 178, 236, 181, 166, 226, 132, 131, 64, 195, 139, 103, 82, 12, 131, 30, 155, 73, 48, 171]),
               sk: new Uint8Array([126, 50, 182, 156, 181, 156, 25, 223, 201, 133, 54, 157, 205, 248, 58, 217, 140, 70, 138, 144, 125, 194, 129, 61, 170, 21, 220, 71, 182, 14, 241, 190]),
               hk: new Uint8Array([136, 115, 155, 174, 209, 123, 13, 65, 26, 227, 183, 174, 49, 205, 123, 224, 133, 43, 145, 142, 33, 182, 132, 255, 129, 221, 101, 228, 84, 38, 141, 124]),
               hIV: new Uint8Array([0, 39, 72, 109, 192, 71, 88, 214, 114, 43, 73, 90]),
               bk: new Uint8Array([234, 196, 137, 208, 116, 105, 34, 95, 206, 229, 53, 52, 136, 96, 42, 94, 167, 70, 97, 12, 28, 166, 131, 85, 188, 123, 124, 28, 7, 65, 111, 238]),
               commit: new Uint8Array([131, 29, 40, 43, 143, 181, 129, 177, 10, 164, 150, 2, 70, 34, 88, 21, 12, 141, 235, 233, 164, 40, 138, 63, 61, 47, 150, 109, 71, 198, 254, 168]),
            },
            'X20-PLY': {
               ek: new Uint8Array([214, 16, 97, 74, 248, 18, 228, 247, 137, 139, 165, 39, 178, 202, 71, 208, 9, 231, 86, 55, 7, 75, 61, 214, 115, 197, 119, 145, 51, 91, 166, 41]),
               sk: new Uint8Array([9, 235, 189, 10, 101, 2, 26, 112, 109, 246, 151, 81, 153, 141, 65, 230, 49, 21, 26, 239, 20, 191, 246, 57, 157, 54, 40, 85, 217, 114, 75, 129]),
               hk: new Uint8Array([99, 90, 22, 36, 151, 128, 108, 55, 166, 83, 112, 208, 14, 165, 105, 9, 222, 177, 193, 220, 238, 176, 200, 48, 16, 208, 42, 181, 28, 136, 74, 59]),
               hIV: new Uint8Array([16, 184, 236, 32, 200, 140, 28, 28, 129, 178, 253, 194, 208, 20, 101, 87, 143, 167, 142, 28, 58, 180, 202, 31]),
               bk: new Uint8Array([184, 122, 197, 228, 83, 178, 105, 201, 91, 81, 19, 96, 182, 46, 19, 191, 144, 131, 184, 237, 155, 182, 158, 53, 213, 152, 88, 210, 169, 130, 221, 232]),
               commit: new Uint8Array([234, 255, 111, 180, 53, 47, 237, 148, 253, 221, 99, 35, 107, 191, 54, 242, 170, 94, 200, 196, 50, 37, 84, 127, 126, 146, 0, 58, 112, 77, 137, 36]),
            },
            'AEGIS-256': {
               ek: new Uint8Array([235, 73, 183, 169, 184, 191, 201, 229, 211, 241, 189, 43, 42, 230, 10, 91, 12, 34, 171, 146, 189, 245, 152, 3, 71, 20, 255, 192, 48, 32, 160, 135]),
               sk: new Uint8Array([111, 119, 142, 83, 177, 9, 77, 51, 200, 32, 67, 179, 102, 37, 175, 206, 194, 51, 54, 215, 59, 141, 244, 19, 154, 2, 162, 29, 105, 71, 89, 44]),
               hk: new Uint8Array([2, 137, 191, 34, 190, 9, 124, 25, 73, 149, 145, 110, 60, 97, 59, 146, 161, 202, 7, 27, 124, 215, 156, 149, 223, 212, 220, 118, 171, 88, 39, 191]),
               hIV: new Uint8Array([236, 88, 168, 140, 198, 68, 124, 100, 211, 209, 58, 249, 94, 222, 127, 255, 242, 116, 219, 47, 239, 87, 68, 130, 28, 239, 211, 58, 217, 144, 143, 205]),
               bk: new Uint8Array([200, 210, 75, 8, 126, 197, 119, 121, 136, 27, 57, 145, 242, 203, 239, 239, 117, 217, 194, 15, 242, 140, 14, 85, 145, 12, 13, 234, 238, 199, 144, 131]),
               commit: new Uint8Array([88, 26, 173, 27, 85, 17, 59, 173, 120, 40, 136, 210, 182, 176, 221, 40, 97, 9, 56, 178, 211, 228, 252, 10, 177, 128, 124, 51, 127, 193, 80, 53]),
            }
         }],
         [cc.VERSION7, 2, {
            'AES-GCM': {
               ek: new Uint8Array([66, 206, 240, 128, 213, 23, 28, 69, 62, 156, 185, 1, 204, 151, 11, 101, 106, 128, 203, 128, 16, 32, 191, 147, 77, 95, 105, 107, 153, 246, 193, 114]),
               sk: new Uint8Array([62, 192, 10, 112, 253, 229, 200, 243, 71, 210, 43, 235, 9, 69, 229, 76, 157, 152, 103, 209, 110, 4, 111, 210, 183, 3, 248, 52, 152, 79, 169, 54]),
               hk: new Uint8Array([69, 25, 18, 228, 148, 55, 133, 235, 44, 11, 125, 171, 207, 153, 9, 220, 71, 177, 236, 197, 157, 227, 204, 76, 189, 223, 179, 172, 180, 36, 222, 128]),
               hIV: new Uint8Array([90, 98, 87, 24, 158, 71, 67, 116, 130, 112, 213, 139]),
               bk: new Uint8Array([255, 205, 87, 41, 223, 246, 27, 32, 47, 23, 200, 232, 140, 102, 127, 253, 54, 61, 222, 239, 57, 166, 31, 75, 168, 85, 179, 199, 123, 242, 45, 7]),
               commit: new Uint8Array([205, 147, 18, 47, 112, 203, 91, 178, 35, 11, 209, 47, 236, 114, 190, 139, 148, 206, 0, 250, 248, 7, 83, 240, 27, 235, 228, 142, 174, 113, 116, 34]),
            },
            'X20-PLY': {
               ek: new Uint8Array([154, 109, 219, 233, 90, 111, 177, 221, 193, 214, 32, 186, 226, 201, 0, 36, 46, 144, 167, 245, 129, 94, 243, 101, 30, 182, 116, 121, 187, 239, 99, 98]),
               sk: new Uint8Array([244, 209, 138, 94, 155, 26, 68, 83, 204, 97, 99, 63, 61, 26, 8, 254, 111, 73, 173, 8, 154, 197, 38, 158, 66, 14, 66, 193, 170, 4, 35, 178]),
               hk: new Uint8Array([106, 45, 252, 201, 243, 204, 197, 233, 135, 42, 215, 3, 58, 169, 214, 52, 61, 152, 120, 36, 105, 58, 243, 29, 130, 99, 247, 107, 53, 190, 228, 170]),
               hIV: new Uint8Array([250, 67, 134, 148, 150, 123, 249, 26, 62, 8, 195, 119, 166, 163, 248, 209, 119, 12, 148, 188, 30, 38, 141, 54]),
               bk: new Uint8Array([204, 117, 220, 75, 83, 188, 116, 217, 149, 166, 27, 251, 17, 150, 1, 14, 70, 211, 16, 186, 14, 146, 137, 6, 255, 71, 240, 163, 104, 87, 154, 29]),
               commit: new Uint8Array([192, 78, 162, 114, 91, 56, 46, 93, 121, 117, 231, 100, 115, 14, 219, 76, 112, 57, 232, 20, 226, 46, 128, 69, 156, 6, 75, 166, 189, 232, 219, 194]),
            },
            'AEGIS-256': {
               ek: new Uint8Array([33, 74, 135, 189, 151, 233, 117, 150, 42, 164, 78, 220, 2, 79, 13, 170, 36, 95, 3, 152, 68, 90, 142, 8, 87, 195, 222, 22, 62, 245, 17, 166]),
               sk: new Uint8Array([95, 213, 244, 251, 109, 115, 20, 28, 139, 255, 216, 137, 183, 95, 225, 115, 55, 74, 125, 102, 93, 181, 97, 54, 226, 194, 198, 213, 159, 230, 101, 7]),
               hk: new Uint8Array([137, 34, 91, 133, 176, 18, 125, 243, 153, 146, 133, 98, 38, 199, 249, 3, 143, 225, 54, 217, 139, 26, 116, 81, 196, 202, 67, 135, 28, 165, 17, 157]),
               hIV: new Uint8Array([227, 174, 52, 237, 228, 83, 101, 193, 132, 251, 19, 230, 160, 31, 127, 57, 149, 252, 101, 235, 122, 172, 46, 179, 171, 119, 3, 59, 82, 39, 230, 210]),
               bk: new Uint8Array([227, 83, 152, 120, 153, 239, 248, 215, 159, 176, 185, 176, 99, 234, 188, 201, 165, 150, 233, 222, 168, 218, 163, 211, 232, 118, 103, 118, 234, 186, 101, 81]),
               commit: new Uint8Array([29, 206, 22, 83, 233, 26, 208, 107, 205, 130, 44, 64, 231, 253, 43, 143, 168, 61, 37, 38, 175, 160, 27, 128, 151, 135, 209, 8, 23, 60, 198, 157]),
            }
         }],
      ];

      const lpEnd = 2;
      const customAd = new Uint8Array([120, 190, 112, 41, 122, 140, 204, 6, 253, 18]);
      const userCred = new Uint8Array([214, 245, 252, 122, 133, 39, 76, 162, 64, 201, 143, 217, 237, 57, 18, 207, 199, 153, 20, 28, 162, 9, 236, 66, 100, 103, 152, 159, 226, 50, 225, 129]);
      const slt = new Uint8Array([160, 202, 135, 230, 125, 174, 49, 189, 171, 56, 203, 1, 237, 233, 27, 76]);
      const iv = new Uint8Array([46, 22, 226, 86, 89, 132, 143, 185, 198, 129, 242, 241, 183, 195, 191, 229, 162, 127, 162, 148, 75, 16, 28, 140, 53, 215, 85, 89, 158, 248, 52, 175]);
      const pwd = 'a good pwd';

      for (const [ver, lp, algsExpected] of expected) {
         for (const alg of Ciphers.algs()) {
            const algExpected = algsExpected[alg];
            const keyProvider = new PWDKeyProvider(userCred, [pwd, undefined], customAd);
            keyProvider.setCipherDataInfo({
               ver,
               alg,
               ic: cc.ICOUNT_MIN,
               slt,
               lp,
               lpEnd,
            });

            const ek = await keyProvider.getCipherKey(false);
            const sk = await keyProvider.getSigningKey();
            const [hk, hIV] = await keyProvider.getHintCipherKeyAndIV(iv.slice(0, Ciphers.algIVByteLength(alg)));
            const bk = await keyProvider.getBlockCipherKey(1);
            const commit = await keyProvider.getKeyCommitment();

            expect(isEqualArray(ek, algExpected.ek)).toBe(true);
            expect(isEqualArray(sk, algExpected.sk)).toBe(true);
            expect(isEqualArray(hk, algExpected.hk)).toBe(true);
            expect(isEqualArray(hIV, algExpected.hIV)).toBe(true);
            expect(isEqualArray(bk, algExpected.bk)).toBe(true);
            expect(isEqualArray(commit, algExpected.commit)).toBe(true);
         }
      }
   });

   it("MasterKeyKeyProvider keys match expected values, multi-loop with customAd", async function () {

      // generated by: pnpm vectors:keys
      const expected: [number, number, Record<cc.CipherAlgs, Record<string, Uint8Array<ArrayBuffer>>>][] = [
         [cc.VERSION7, 1, {
            'AES-GCM': {
               ek: new Uint8Array([62, 43, 242, 215, 21, 141, 122, 13, 2, 38, 243, 254, 112, 200, 114, 92, 59, 80, 209, 207, 157, 127, 132, 17, 80, 61, 240, 220, 149, 88, 170, 16]),
               sk: new Uint8Array([209, 56, 236, 89, 220, 203, 165, 253, 32, 160, 210, 53, 220, 128, 14, 68, 197, 175, 146, 228, 20, 152, 87, 54, 106, 34, 231, 231, 106, 250, 70, 228]),
               hk: new Uint8Array([118, 52, 25, 8, 249, 215, 77, 139, 225, 231, 17, 183, 42, 184, 141, 41, 69, 89, 112, 146, 26, 90, 182, 1, 88, 18, 106, 155, 24, 30, 134, 98]),
               hIV: new Uint8Array([93, 210, 168, 79, 69, 155, 53, 55, 4, 151, 150, 82]),
               bk: new Uint8Array([174, 156, 65, 21, 147, 3, 148, 239, 97, 217, 216, 244, 174, 204, 221, 199, 172, 32, 144, 144, 219, 11, 166, 147, 5, 151, 209, 213, 26, 145, 88, 51]),
               commit: new Uint8Array([227, 73, 243, 13, 96, 140, 75, 83, 188, 178, 164, 186, 100, 115, 138, 249, 4, 16, 27, 152, 166, 95, 146, 171, 42, 253, 162, 34, 64, 173, 37, 226]),
            },
            'X20-PLY': {
               ek: new Uint8Array([157, 147, 112, 209, 3, 40, 65, 66, 67, 89, 106, 123, 251, 202, 215, 13, 68, 220, 209, 45, 56, 197, 88, 38, 190, 0, 91, 51, 88, 214, 113, 26]),
               sk: new Uint8Array([249, 14, 233, 174, 146, 161, 86, 217, 253, 35, 214, 231, 164, 101, 249, 169, 133, 33, 21, 58, 191, 195, 89, 182, 245, 174, 48, 42, 254, 192, 206, 54]),
               hk: new Uint8Array([90, 2, 146, 127, 213, 234, 202, 181, 133, 213, 133, 0, 88, 241, 203, 170, 175, 125, 252, 25, 196, 139, 48, 197, 202, 146, 221, 139, 241, 59, 151, 105]),
               hIV: new Uint8Array([43, 249, 167, 241, 45, 108, 151, 45, 207, 180, 166, 171, 18, 172, 103, 58, 12, 180, 40, 124, 114, 119, 122, 226]),
               bk: new Uint8Array([201, 171, 30, 45, 106, 18, 219, 107, 106, 223, 159, 107, 13, 120, 190, 97, 44, 234, 216, 122, 136, 194, 236, 94, 136, 10, 27, 12, 3, 244, 223, 158]),
               commit: new Uint8Array([3, 67, 93, 221, 110, 13, 198, 0, 176, 97, 83, 132, 66, 41, 218, 215, 144, 54, 0, 233, 236, 102, 227, 187, 160, 104, 121, 166, 169, 186, 30, 95]),
            },
            'AEGIS-256': {
               ek: new Uint8Array([115, 173, 169, 134, 46, 62, 56, 41, 73, 181, 183, 176, 225, 186, 38, 91, 245, 119, 231, 71, 130, 21, 108, 106, 128, 166, 89, 87, 198, 61, 87, 192]),
               sk: new Uint8Array([144, 248, 50, 96, 159, 123, 1, 69, 238, 133, 67, 105, 44, 65, 176, 132, 137, 71, 224, 164, 19, 132, 216, 195, 53, 69, 216, 121, 93, 44, 221, 21]),
               hk: new Uint8Array([143, 27, 241, 195, 93, 150, 106, 186, 95, 37, 85, 26, 222, 120, 73, 92, 221, 73, 223, 252, 216, 35, 80, 241, 28, 195, 116, 199, 203, 157, 194, 82]),
               hIV: new Uint8Array([119, 117, 163, 175, 98, 141, 56, 219, 217, 204, 129, 121, 24, 67, 69, 107, 88, 236, 94, 21, 224, 199, 181, 250, 149, 167, 226, 250, 1, 184, 94, 176]),
               bk: new Uint8Array([24, 136, 144, 244, 195, 210, 250, 38, 63, 197, 58, 11, 199, 197, 251, 8, 229, 54, 250, 194, 31, 103, 13, 177, 249, 88, 84, 181, 115, 73, 242, 171]),
               commit: new Uint8Array([108, 202, 108, 21, 9, 113, 198, 9, 66, 19, 109, 234, 247, 151, 188, 118, 110, 53, 120, 90, 138, 57, 103, 246, 198, 67, 72, 221, 137, 144, 237, 103]),
            }
         }],
         [cc.VERSION7, 2, {
            'AES-GCM': {
               ek: new Uint8Array([172, 45, 162, 96, 158, 190, 214, 221, 177, 245, 79, 138, 170, 38, 17, 132, 71, 147, 40, 98, 194, 226, 93, 11, 17, 244, 65, 9, 92, 21, 35, 254]),
               sk: new Uint8Array([78, 25, 69, 77, 190, 43, 0, 214, 138, 18, 9, 37, 126, 194, 133, 119, 124, 188, 187, 43, 52, 94, 249, 91, 209, 125, 219, 189, 54, 149, 117, 73]),
               hk: new Uint8Array([195, 145, 6, 179, 122, 136, 53, 228, 29, 178, 147, 238, 183, 75, 249, 43, 187, 63, 179, 36, 52, 252, 1, 24, 114, 4, 54, 130, 235, 25, 115, 18]),
               hIV: new Uint8Array([213, 54, 206, 110, 202, 234, 225, 42, 162, 32, 91, 196]),
               bk: new Uint8Array([166, 208, 141, 250, 39, 76, 240, 69, 219, 93, 176, 180, 200, 158, 123, 12, 83, 221, 75, 203, 42, 88, 184, 58, 240, 219, 223, 132, 204, 4, 10, 16]),
               commit: new Uint8Array([227, 128, 147, 207, 106, 204, 84, 168, 140, 72, 211, 255, 105, 205, 201, 221, 95, 217, 240, 142, 76, 190, 171, 51, 139, 83, 255, 81, 156, 255, 53, 201]),
            },
            'X20-PLY': {
               ek: new Uint8Array([86, 14, 79, 152, 62, 235, 61, 35, 91, 35, 168, 85, 111, 42, 68, 57, 9, 212, 151, 119, 104, 86, 201, 102, 253, 38, 232, 54, 90, 80, 163, 241]),
               sk: new Uint8Array([81, 2, 7, 205, 204, 164, 40, 169, 10, 189, 1, 102, 31, 222, 140, 160, 150, 225, 80, 14, 229, 142, 144, 15, 137, 129, 151, 234, 15, 80, 20, 101]),
               hk: new Uint8Array([119, 188, 112, 55, 251, 57, 217, 98, 156, 0, 30, 71, 250, 1, 205, 245, 32, 174, 81, 20, 85, 196, 35, 226, 226, 192, 217, 247, 159, 194, 209, 113]),
               hIV: new Uint8Array([116, 64, 176, 21, 57, 73, 253, 186, 250, 72, 32, 176, 126, 106, 107, 236, 205, 80, 45, 245, 26, 19, 112, 169]),
               bk: new Uint8Array([23, 122, 6, 147, 44, 218, 36, 236, 20, 172, 188, 48, 211, 178, 104, 57, 45, 90, 31, 61, 159, 171, 255, 157, 199, 188, 129, 28, 61, 51, 36, 250]),
               commit: new Uint8Array([227, 86, 55, 254, 90, 192, 129, 137, 76, 69, 186, 114, 255, 57, 181, 189, 3, 203, 19, 253, 146, 215, 132, 208, 79, 119, 77, 181, 143, 62, 68, 148]),
            },
            'AEGIS-256': {
               ek: new Uint8Array([200, 76, 42, 9, 63, 102, 66, 39, 58, 22, 98, 21, 114, 198, 85, 50, 26, 101, 167, 127, 94, 7, 143, 93, 81, 79, 165, 232, 138, 72, 55, 41]),
               sk: new Uint8Array([236, 154, 41, 18, 104, 255, 218, 69, 51, 223, 250, 217, 187, 130, 93, 91, 51, 85, 196, 221, 147, 197, 4, 233, 88, 78, 198, 219, 56, 223, 213, 89]),
               hk: new Uint8Array([156, 175, 209, 3, 184, 195, 14, 97, 3, 162, 242, 233, 66, 219, 163, 246, 57, 159, 193, 53, 248, 212, 216, 205, 26, 79, 155, 216, 156, 5, 31, 117]),
               hIV: new Uint8Array([192, 33, 207, 36, 84, 19, 196, 175, 42, 53, 17, 134, 124, 203, 83, 55, 171, 53, 140, 178, 189, 165, 19, 164, 7, 81, 252, 225, 17, 204, 184, 201]),
               bk: new Uint8Array([212, 210, 45, 101, 26, 86, 169, 202, 171, 84, 2, 74, 123, 55, 120, 123, 148, 194, 203, 250, 43, 156, 213, 158, 247, 65, 47, 17, 235, 42, 244, 122]),
               commit: new Uint8Array([158, 67, 66, 247, 17, 243, 83, 240, 133, 59, 193, 61, 21, 11, 189, 205, 181, 145, 58, 153, 213, 32, 178, 64, 203, 248, 125, 132, 57, 246, 145, 239]),
            }
         }],
      ];

      const lpEnd = 2;
      const customAd = new Uint8Array([120, 190, 112, 41, 122, 140, 204, 6, 253, 18]);
      const master = new Uint8Array([88, 164, 150, 177, 85, 43, 43, 25, 42, 250, 120, 190, 112, 26, 41, 122, 140, 204, 6, 253, 225, 220, 237, 10, 80, 64, 148, 152, 204, 30, 231, 18]);
      const slt = new Uint8Array([247, 229, 145, 155, 90, 26, 149, 132, 44, 75, 197, 178, 187, 88, 41, 244]);
      const iv = new Uint8Array([110, 248, 21, 150, 142, 146, 67, 223, 194, 230, 44, 28, 247, 71, 109, 61, 53, 215, 85, 89, 158, 248, 52, 175, 53, 215, 169, 223, 219, 248, 52, 175]);

      for (const [ver, lp, algsExpected] of expected) {
         for (const alg of Ciphers.algs()) {
            const algExpected = algsExpected[alg];
            const keyProvider = new MasterKeyKeyProvider(master, customAd);
            keyProvider.setCipherDataInfo({
               ver,
               alg,
               ic: 0,
               slt,
               lp,
               lpEnd,
            });

            const ek = await keyProvider.getCipherKey(false);
            const sk = await keyProvider.getSigningKey();
            const [hk, hIV] = await keyProvider.getHintCipherKeyAndIV(iv.slice(0, Ciphers.algIVByteLength(alg)));
            const bk = await keyProvider.getBlockCipherKey(1);
            const commit = await keyProvider.getKeyCommitment();

            expect(isEqualArray(ek, algExpected.ek)).toBe(true);
            expect(isEqualArray(sk, algExpected.sk)).toBe(true);
            expect(isEqualArray(hk, algExpected.hk)).toBe(true);
            expect(isEqualArray(hIV, algExpected.hIV)).toBe(true);
            expect(isEqualArray(bk, algExpected.bk)).toBe(true);
            expect(isEqualArray(commit, algExpected.commit)).toBe(true);
         }
      }
   });

   it("PWDKeyProvider supportsCommitment per version", async function () {
      const userCred = getRandom(cc.USERCRED_BYTES);
      const slt = getRandom(cc.SLT_BYTES);
      const base = { alg: 'AES-GCM' as cc.CipherAlgs, ic: cc.ICOUNT_MIN, slt, lp: 1, lpEnd: 1 };

      const v4 = new PWDKeyProvider(userCred.slice(0), ['p', undefined]);
      v4.setCipherDataInfo({ ...base, ver: cc.VERSION4 });
      await v4.getCipherKey(false);
      expect(v4.supportsCommitment).toBe(false);
      await expect(v4.getKeyCommitment()).rejects.toThrow(/Key commitments not supported/);
      v4.purge();

      const v6 = new PWDKeyProvider(userCred.slice(0), ['p', undefined]);
      v6.setCipherDataInfo({ ...base, ver: cc.VERSION6 });
      await v6.getCipherKey(false);
      expect(v6.supportsCommitment).toBe(false);
      await expect(v6.getKeyCommitment()).rejects.toThrow(/Key commitments not supported/);
      v6.purge();

      const v7 = new PWDKeyProvider(userCred.slice(0), ['p', undefined]);
      v7.setCipherDataInfo({ ...base, ver: cc.CURRENT_VERSION });
      await v7.getCipherKey(false);
      expect(v7.supportsCommitment).toBe(true);
      const commit = await v7.getKeyCommitment();
      expect(commit.byteLength).toBe(cc.KEY_BYTES);
      v7.purge();
   });

   it("MasterKeyKeyProvider supportsCommitment succeeds", async function () {
      const master = getRandom(cc.KEY_BYTES);
      const slt = getRandom(cc.SLT_BYTES);
      const keyProvider = new MasterKeyKeyProvider(master);
      keyProvider.setCipherDataInfo({ ver: cc.CURRENT_VERSION, alg: 'AES-GCM', ic: 0, slt, lp: 1, lpEnd: 1 });
      await keyProvider.getCipherKey(false);
      expect(keyProvider.supportsCommitment).toBe(true);
      const commit = await keyProvider.getKeyCommitment();
      expect(commit.byteLength).toBe(cc.KEY_BYTES);
      keyProvider.purge();
   });

   it("getKeyCommitment requires getCipherKey to have been called", async function () {
      const slt = getRandom(cc.SLT_BYTES);
      const pwdProvider = new PWDKeyProvider(getRandom(cc.USERCRED_BYTES), ['p', undefined]);
      pwdProvider.setCipherDataInfo({ ver: cc.CURRENT_VERSION, alg: 'AES-GCM', ic: cc.ICOUNT_MIN, slt, lp: 1, lpEnd: 1 });
      await expect(pwdProvider.getKeyCommitment()).rejects.toThrow(/Cipher key must be generated/);
      pwdProvider.purge();

      const masterProvider = new MasterKeyKeyProvider(getRandom(cc.KEY_BYTES));
      masterProvider.setCipherDataInfo({ ver: cc.CURRENT_VERSION, alg: 'AES-GCM', ic: 0, slt, lp: 1, lpEnd: 1 });
      await expect(masterProvider.getKeyCommitment()).rejects.toThrow(/Cipher key must be generated/);
      masterProvider.purge();
   });

   it("derived keys change with cipher info (alg, lp, slt, customAd)", async function () {
      const userCred = getRandom(cc.USERCRED_BYTES);
      const master = getRandom(cc.KEY_BYTES);
      const customAd = getRandom(16);
      const baseSlt = getRandom(cc.SLT_BYTES);
      const otherSlt = getRandom(cc.SLT_BYTES);
      const baseIV = getRandom(32);

      const providers = [
         {
            ic: cc.ICOUNT_MIN,
            make: (extraAd?: Uint8Array<ArrayBuffer>) => new PWDKeyProvider(userCred.slice(0), ['pwd-A', undefined], extraAd),
         },
         {
            ic: 0,
            make: (extraAd?: Uint8Array<ArrayBuffer>) => new MasterKeyKeyProvider(master.slice(0), extraAd),
         },
      ];

      async function derive(
         provider: typeof providers[number],
         alg: cc.CipherAlgs,
         lp: number,
         slt: Uint8Array<ArrayBuffer>,
         extraAd: Uint8Array<ArrayBuffer> | undefined
      ): Promise<AllDerivedKeys> {
         const keyProvider = provider.make(extraAd);
         keyProvider.setCipherDataInfo({ ver: cc.CURRENT_VERSION, alg, ic: provider.ic, slt: slt.slice(0), lp, lpEnd: 6 });
         return deriveAllKeys(keyProvider, baseIV, alg);
      }

      for (const provider of providers) {
         const baseline = await derive(provider, 'AES-GCM', 1, baseSlt, undefined);
         const sameInputs = await derive(provider, 'AES-GCM', 1, baseSlt, undefined);
         const diffAlg = await derive(provider, 'X20-PLY', 1, baseSlt, undefined);
         const diffLp = await derive(provider, 'AES-GCM', 2, baseSlt, undefined);
         const diffSlt = await derive(provider, 'AES-GCM', 1, otherSlt, undefined);
         const withCustomAd = await derive(provider, 'AES-GCM', 1, baseSlt, customAd);

         for (const name of KEY_NAMES) {
            expect(isEqualArray(baseline[name], sameInputs[name])).toBe(true);
            expect(isEqualArray(baseline[name], diffAlg[name])).toBe(false);
            expect(isEqualArray(baseline[name], diffLp[name])).toBe(false);
            expect(isEqualArray(baseline[name], diffSlt[name])).toBe(false);
            expect(isEqualArray(baseline[name], withCustomAd[name])).toBe(false);
         }
      }
   });

   it("PWDKeyProvider derived keys change with pwd and userCred", async function () {
      const userCred = getRandom(cc.USERCRED_BYTES);
      const otherCred = getRandom(cc.USERCRED_BYTES);
      const slt = getRandom(cc.SLT_BYTES);
      const baseIV = getRandom(32);
      const alg: cc.CipherAlgs = 'AES-GCM';

      async function derive(cred: Uint8Array<ArrayBuffer>, pwd: string): Promise<AllDerivedKeys> {
         const keyProvider = new PWDKeyProvider(cred.slice(0), [pwd, undefined]);
         keyProvider.setCipherDataInfo({ ver: cc.CURRENT_VERSION, alg, ic: cc.ICOUNT_MIN, slt, lp: 1, lpEnd: 1 });
         return deriveAllKeys(keyProvider, baseIV, alg);
      }

      const baseline = await derive(userCred, 'pwd-A');

      // Changing pwd only changes ek (PBKDF2 input), and the keys derived from
      // ek (bk, commit). sk and hk come from userCred, hIV from baseIV.
      const diffPwd = await derive(userCred, 'pwd-B');
      expect(isEqualArray(baseline.ek, diffPwd.ek)).toBe(false);
      expect(isEqualArray(baseline.bk, diffPwd.bk)).toBe(false);
      expect(isEqualArray(baseline.commit, diffPwd.commit)).toBe(false);
      expect(isEqualArray(baseline.sk, diffPwd.sk)).toBe(true);
      expect(isEqualArray(baseline.hk, diffPwd.hk)).toBe(true);
      expect(isEqualArray(baseline.hIV, diffPwd.hIV)).toBe(true);

      // Changing userCred changes ek, sk, hk, and the keys derived from ek
      // (bk, commit). Only hIV (derived from baseIV) stays the same.
      const diffCred = await derive(otherCred, 'pwd-A');
      expect(isEqualArray(baseline.ek, diffCred.ek)).toBe(false);
      expect(isEqualArray(baseline.sk, diffCred.sk)).toBe(false);
      expect(isEqualArray(baseline.hk, diffCred.hk)).toBe(false);
      expect(isEqualArray(baseline.bk, diffCred.bk)).toBe(false);
      expect(isEqualArray(baseline.commit, diffCred.commit)).toBe(false);
      expect(isEqualArray(baseline.hIV, diffCred.hIV)).toBe(true);
   });

   it("MasterKeyKeyProvider derived keys change with masterKey", async function () {
      const master = getRandom(cc.KEY_BYTES);
      const otherMaster = getRandom(cc.KEY_BYTES);
      const slt = getRandom(cc.SLT_BYTES);
      const baseIV = getRandom(32);
      const alg: cc.CipherAlgs = 'AES-GCM';

      async function derive(masterKey: Uint8Array<ArrayBuffer>): Promise<AllDerivedKeys> {
         const keyProvider = new MasterKeyKeyProvider(masterKey.slice(0));
         keyProvider.setCipherDataInfo({ ver: cc.CURRENT_VERSION, alg, ic: 0, slt, lp: 1, lpEnd: 1 });
         return deriveAllKeys(keyProvider, baseIV, alg);
      }

      // Changing masterKey changes ek, sk, hk, and the keys derived from ek
      // (bk, commit). Only hIV (derived from baseIV) stays the same.
      const baseline = await derive(master);
      const diffMaster = await derive(otherMaster);

      expect(isEqualArray(baseline.ek, diffMaster.ek)).toBe(false);
      expect(isEqualArray(baseline.sk, diffMaster.sk)).toBe(false);
      expect(isEqualArray(baseline.hk, diffMaster.hk)).toBe(false);
      expect(isEqualArray(baseline.bk, diffMaster.bk)).toBe(false);
      expect(isEqualArray(baseline.commit, diffMaster.commit)).toBe(false);
      expect(isEqualArray(baseline.hIV, diffMaster.hIV)).toBe(true);
   });

   it("getKeyCommitment is stable across other key derivations", async function () {
      const slt = getRandom(cc.SLT_BYTES);
      const providers = [
         {
            ic: cc.ICOUNT_MIN,
            make: () => new PWDKeyProvider(getRandom(cc.USERCRED_BYTES), ['p', undefined]),
         },
         {
            ic: 0,
            make: () => new MasterKeyKeyProvider(getRandom(cc.KEY_BYTES)),
         },
      ];

      for (const provider of providers) {
         const keyProvider = provider.make();
         keyProvider.setCipherDataInfo({ ver: cc.CURRENT_VERSION, alg: 'AES-GCM', ic: provider.ic, slt, lp: 1, lpEnd: 1 });
         await keyProvider.getCipherKey(false);
         const first = (await keyProvider.getKeyCommitment());

         // Interleave unrelated derivations that mutate internal state
         await keyProvider.getSigningKey();
         await keyProvider.getBlockCipherKey(1);
         await keyProvider.getBlockCipherKey(2);
         await keyProvider.getHintCipherKeyAndIV(getRandom(12));

         const second = (await keyProvider.getKeyCommitment());
         expect(first.every((byte) => byte === 0)).toBe(false);
         expect(isEqualArray(first, second)).toBe(true);
         keyProvider.purge();
      }
   });

   it("purge zeroes the commitment key", async function () {
      const slt = getRandom(cc.SLT_BYTES);
      const providers = [
         {
            ic: cc.ICOUNT_MIN,
            make: () => new PWDKeyProvider(getRandom(cc.USERCRED_BYTES), ['p', undefined]),
         },
         {
            ic: 0,
            make: () => new MasterKeyKeyProvider(getRandom(cc.KEY_BYTES)),
         },
      ];

      for (const provider of providers) {
         const keyProvider = provider.make();
         keyProvider.setCipherDataInfo({ ver: cc.CURRENT_VERSION, alg: 'AES-GCM', ic: provider.ic, slt, lp: 1, lpEnd: 1 });
         await keyProvider.getCipherKey(false);
         const commit = await keyProvider.getKeyCommitment();
         expect(commit.some((byte) => byte !== 0)).toBe(true);
         keyProvider.purge();
         // Same backing buffer; purge wipes it in place
         expect(commit.every((byte) => byte === 0)).toBe(true);
      }
   });

});

