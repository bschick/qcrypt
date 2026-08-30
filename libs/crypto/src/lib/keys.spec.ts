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
import { type KeyProvider, MasterKeyKeyProvider, PWDKeyProvider } from './keys';
import { Ciphers } from './ciphers';
import { getRandom } from './utils';
import { isEqualArray } from './utils.spec';

const KEY_NAMES = ['ek', 'sk', 'hk', 'hIV', 'bk', 'commit'] as const;
type AllDerivedKeys = Record<(typeof KEY_NAMES)[number], Uint8Array>;

async function deriveAllKeys(
   keyProvider: KeyProvider,
   baseIV: Uint8Array<ArrayBuffer>,
   alg: cc.CipherAlgs,
): Promise<AllDerivedKeys> {
   const ek = (await keyProvider.getCipherKey(false)).slice(0);
   const sk = (await keyProvider.getSigningKey()).slice(0);
   const [hkRef, hIVRef] = await keyProvider.getHintCipherKeyAndIV(baseIV.slice(0, Ciphers.algIVByteLength(alg)));
   const hk = hkRef.slice(0);
   const hIV = hIVRef.slice(0);
   const bk = (await keyProvider.getBlockCipherKey(1)).slice(0);
   const commit = (await keyProvider.getKeyCommitment()).slice(0);
   keyProvider.purge();
   return { ek, sk, hk, hIV, bk, commit };
}

describe('Key generation', () => {
   beforeEach(async () => {
      await cryptoReady();
   });

   async function testKeyGenSuccessAndOveralp(
      keyProvider: KeyProvider,
      iv: Uint8Array<ArrayBuffer>,
      notEq: Uint8Array<ArrayBuffer>,
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

      expect([sk, hk, hIV].includes(ek)).toBe(false);
      expect([ek, hk, hIV].includes(sk)).toBe(false);
      expect([ek, sk, hIV].includes(bk)).toBe(false);
      expect([ek, sk, hIV].includes(hk)).toBe(false);
      expect([ek, sk, hk].includes(hIV)).toBe(false);

      expect(isEqualArray(ek, notEq)).toBe(false);
      expect(isEqualArray(sk, notEq)).toBe(false);
      expect(isEqualArray(bk, notEq)).toBe(false);
      expect(isEqualArray(hk, notEq)).toBe(false);
      expect(isEqualArray(hIV, notEq)).toBe(false);
   }

   async function testKeyGenStable(keyProvider: KeyProvider, iv: Uint8Array<ArrayBuffer>) {
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

   async function testNotUsuableAfterPurge(keyProvider: KeyProvider, iv: Uint8Array<ArrayBuffer>) {
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

   it('PWDKeyProvider successful and not equivalent key generation', async () => {
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
            lpEnd: 1,
         });

         await testKeyGenSuccessAndOveralp(keyProvider, iv, userCred);
         keyProvider.purge();
      }
   });

   it('PWDKeyProvider key are stable', async () => {
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
            lpEnd: 1,
         });

         await testKeyGenStable(keyProvider, iv);
         keyProvider.purge();
      }
   });

   it('PWDKeyProvider unsuable after purge', async () => {
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
            lpEnd: 1,
         });

         await testNotUsuableAfterPurge(keyProvider, iv);
      }
   });

   it('PWDKeyProvider clone after purge throws', () => {
      const userCred = getRandom(cc.USERCRED_BYTES);
      const keyProvider = new PWDKeyProvider(userCred, ['a pwd', undefined]);
      keyProvider.purge();

      expect(() => keyProvider.clone()).toThrow(/Cannot clone a purged keyProvider/);
   });

   it('PWDKeyProvider clone derives same keys after original is purged', async () => {
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

   it('PWDKeyProvider unsuable without cipherdatainfo', async () => {
      for (const alg of Ciphers.algs()) {
         const pwd = 'not a good pwd';
         const _ic = cc.ICOUNT_MIN;
         const userCred = crypto.getRandomValues(new Uint8Array(cc.USERCRED_BYTES));
         const randomArray = getRandom(48);
         const _slt = randomArray.slice(0, cc.SLT_BYTES);
         const iv = randomArray.slice(cc.SLT_BYTES, cc.SLT_BYTES + Ciphers.algIVByteLength(alg));

         const keyProvider = new PWDKeyProvider(userCred, [pwd, undefined]);
         expect(() => keyProvider.getCipherDataInfo()).toThrow();
         expect(() => keyProvider.setHint('abc')).toThrow();
         await expect(keyProvider.getCipherKey(false)).rejects.toThrow();
         await expect(keyProvider.getSigningKey()).rejects.toThrow();
         await expect(keyProvider.getBlockCipherKey(1)).rejects.toThrow();
         await expect(keyProvider.getHintCipherKeyAndIV(iv)).rejects.toThrow();
         keyProvider.purge();
      }
   });

   it('PWDKeyProvider setCipherDataInfo rejects second call', () => {
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

      expect(() =>
         keyProvider.setCipherDataInfo({
            ver: cc.CURRENT_VERSION,
            alg: 'X20-PLY',
            ic: cc.ICOUNT_MIN,
            slt,
            lp: 1,
            lpEnd: 1,
         }),
      ).toThrow(/CipherDataInfo can only be set once/);

      keyProvider.purge();
   });

   it('PWDKeyProvider setCipherDataInfo validates lp/lpEnd bounds', async () => {
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
      expect(() => keyProvider.setCipherDataInfo({ ...baseInfo, lp: 1, lpEnd: cc.LP_MAX + 1 })).toThrow(
         /Invalid lpEnd/,
      );
      keyProvider.purge();

      // lp = lpEnd = LP_MAX (boundary success)
      keyProvider = new PWDKeyProvider(userCred, ['a pwd', undefined]);
      keyProvider.setCipherDataInfo({ ...baseInfo, lp: cc.LP_MAX, lpEnd: cc.LP_MAX });
      const key = (await keyProvider.getSigningKey()).slice(0);
      expect(key.byteLength).toBe(cc.KEY_BYTES);
      keyProvider.purge();
   });

   it('PWDKeyProvider rejects unknown versions', async () => {
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

   it('setCipherDataInfo validates ic bounds', () => {
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

   it('MasterKeyKeyProvider successful and not equivalent key generation', async () => {
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
            lpEnd: 1,
         });

         await testKeyGenSuccessAndOveralp(keyProvider, iv, master);
         keyProvider.purge();
      }
   });

   it('MasterKeyKeyProvider key are stable', async () => {
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
            lpEnd: 1,
         });

         await testKeyGenStable(keyProvider, iv);
         keyProvider.purge();
      }
   });

   it('MasterKeyKeyProvider unsuable without cipherdatainfo', async () => {
      for (const alg of Ciphers.algs()) {
         const master = crypto.getRandomValues(new Uint8Array(cc.KEY_BYTES));
         const randomArray = getRandom(48);
         const iv = randomArray.slice(cc.SLT_BYTES, cc.SLT_BYTES + Ciphers.algIVByteLength(alg));

         const keyProvider = new MasterKeyKeyProvider(master);
         expect(() => keyProvider.getCipherDataInfo()).toThrow();
         expect(() => keyProvider.setHint('abc')).toThrow();
         await expect(keyProvider.getCipherKey(false)).rejects.toThrow();
         await expect(keyProvider.getSigningKey()).rejects.toThrow();
         await expect(keyProvider.getBlockCipherKey(1)).rejects.toThrow();
         await expect(keyProvider.getHintCipherKeyAndIV(iv)).rejects.toThrow();
         keyProvider.purge();
      }
   });

   it('MasterKeyKeyProvider setCipherDataInfo rejects second call', () => {
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

      expect(() =>
         keyProvider.setCipherDataInfo({
            ver: cc.CURRENT_VERSION,
            alg: 'X20-PLY',
            ic: 0,
            slt,
            lp: 1,
            lpEnd: 1,
         }),
      ).toThrow(/CipherDataInfo can only be set once/);

      keyProvider.purge();
   });

   it('MasterKeyKeyProvider setCipherDataInfo validates lp/lpEnd bounds', async () => {
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
      expect(() => keyProvider.setCipherDataInfo({ ...baseInfo, lp: 1, lpEnd: cc.LP_MAX + 1 })).toThrow(
         /Invalid lpEnd/,
      );
      keyProvider.purge();

      // lp = lpEnd = LP_MAX (boundary success)
      keyProvider = new MasterKeyKeyProvider(getRandom(cc.KEY_BYTES));
      keyProvider.setCipherDataInfo({ ...baseInfo, lp: cc.LP_MAX, lpEnd: cc.LP_MAX });
      const key = (await keyProvider.getSigningKey()).slice(0);
      expect(key.byteLength).toBe(cc.KEY_BYTES);
      keyProvider.purge();
   });

   it('MasterKeyKeyProvider rejects unknown versions', async () => {
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

   it('MasterKeyKeyProvider rejects invalid masterKey', () => {
      expect(() => new MasterKeyKeyProvider(new Uint8Array(0))).toThrow(/Invalid masterKey length/);
      expect(() => new MasterKeyKeyProvider(getRandom(cc.KEY_BYTES - 1))).toThrow(/Invalid masterKey length/);
      expect(() => new MasterKeyKeyProvider(getRandom(cc.KEY_BYTES + 1))).toThrow(/Invalid masterKey length/);
      expect(() => new MasterKeyKeyProvider(new Uint8Array(cc.KEY_BYTES))).toThrow(/Invalid masterKey: all zero bytes/);
   });

   it('MasterKeyKeyProvider unsuable after purge', async () => {
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
            lpEnd: 1,
         });

         await testNotUsuableAfterPurge(keyProvider, iv);
      }
   });

   it('MasterKeyKeyProvider clone after purge throws', () => {
      const master = getRandom(cc.KEY_BYTES);
      const keyProvider = new MasterKeyKeyProvider(master);
      keyProvider.purge();

      expect(() => keyProvider.clone()).toThrow(/Cannot clone a purged keyProvider/);
   });

   it('MasterKeyKeyProvider clone derives same keys after original is purged', async () => {
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

   it('PWDKeyProvider keys match expected values', async () => {
      const expected: [number, Record<cc.CipherAlgs, Record<string, Uint8Array<ArrayBuffer>>>][] = [
         [
            cc.VERSION4,
            {
               'AES-GCM': {
                  ek: new Uint8Array([
                     158, 221, 13, 155, 167, 216, 81, 115, 151, 193, 225, 53, 187, 156, 175, 196, 85, 234, 233, 199, 86,
                     45, 149, 120, 1, 57, 14, 102, 147, 123, 7, 150,
                  ]),
                  sk: new Uint8Array([
                     238, 127, 13, 239, 238, 127, 177, 22, 231, 87, 89, 23, 88, 52, 42, 22, 6, 170, 172, 112, 111, 101,
                     147, 204, 238, 28, 203, 159, 118, 54, 139, 151,
                  ]),
                  hk: new Uint8Array([
                     253, 30, 237, 129, 147, 186, 235, 65, 217, 78, 219, 38, 163, 12, 23, 248, 3, 118, 123, 120, 237, 0,
                     56, 103, 67, 76, 88, 126, 153, 83, 238, 85,
                  ]),
                  hIV: new Uint8Array([46, 22, 226, 86, 89, 132, 143, 185, 198, 129, 242, 241]),
               },
               'X20-PLY': {
                  ek: new Uint8Array([
                     158, 221, 13, 155, 167, 216, 81, 115, 151, 193, 225, 53, 187, 156, 175, 196, 85, 234, 233, 199, 86,
                     45, 149, 120, 1, 57, 14, 102, 147, 123, 7, 150,
                  ]),
                  sk: new Uint8Array([
                     238, 127, 13, 239, 238, 127, 177, 22, 231, 87, 89, 23, 88, 52, 42, 22, 6, 170, 172, 112, 111, 101,
                     147, 204, 238, 28, 203, 159, 118, 54, 139, 151,
                  ]),
                  hk: new Uint8Array([
                     253, 30, 237, 129, 147, 186, 235, 65, 217, 78, 219, 38, 163, 12, 23, 248, 3, 118, 123, 120, 237, 0,
                     56, 103, 67, 76, 88, 126, 153, 83, 238, 85,
                  ]),
                  hIV: new Uint8Array([
                     46, 22, 226, 86, 89, 132, 143, 185, 198, 129, 242, 241, 183, 195, 191, 229, 162, 127, 162, 148, 75,
                     16, 28, 140,
                  ]),
               },
               'AEGIS-256': {
                  ek: new Uint8Array([
                     158, 221, 13, 155, 167, 216, 81, 115, 151, 193, 225, 53, 187, 156, 175, 196, 85, 234, 233, 199, 86,
                     45, 149, 120, 1, 57, 14, 102, 147, 123, 7, 150,
                  ]),
                  sk: new Uint8Array([
                     238, 127, 13, 239, 238, 127, 177, 22, 231, 87, 89, 23, 88, 52, 42, 22, 6, 170, 172, 112, 111, 101,
                     147, 204, 238, 28, 203, 159, 118, 54, 139, 151,
                  ]),
                  hk: new Uint8Array([
                     253, 30, 237, 129, 147, 186, 235, 65, 217, 78, 219, 38, 163, 12, 23, 248, 3, 118, 123, 120, 237, 0,
                     56, 103, 67, 76, 88, 126, 153, 83, 238, 85,
                  ]),
                  hIV: new Uint8Array([
                     46, 22, 226, 86, 89, 132, 143, 185, 198, 129, 242, 241, 183, 195, 191, 229, 162, 127, 162, 148, 75,
                     16, 28, 140, 53, 215, 85, 89, 158, 248, 52, 175,
                  ]),
               },
            },
         ],
         [
            cc.VERSION5,
            {
               'AES-GCM': {
                  ek: new Uint8Array([
                     158, 221, 13, 155, 167, 216, 81, 115, 151, 193, 225, 53, 187, 156, 175, 196, 85, 234, 233, 199, 86,
                     45, 149, 120, 1, 57, 14, 102, 147, 123, 7, 150,
                  ]),
                  sk: new Uint8Array([
                     238, 127, 13, 239, 238, 127, 177, 22, 231, 87, 89, 23, 88, 52, 42, 22, 6, 170, 172, 112, 111, 101,
                     147, 204, 238, 28, 203, 159, 118, 54, 139, 151,
                  ]),
                  hk: new Uint8Array([
                     253, 30, 237, 129, 147, 186, 235, 65, 217, 78, 219, 38, 163, 12, 23, 248, 3, 118, 123, 120, 237, 0,
                     56, 103, 67, 76, 88, 126, 153, 83, 238, 85,
                  ]),
                  hIV: new Uint8Array([46, 22, 226, 86, 89, 132, 143, 185, 198, 129, 242, 241]),
               },
               'X20-PLY': {
                  ek: new Uint8Array([
                     158, 221, 13, 155, 167, 216, 81, 115, 151, 193, 225, 53, 187, 156, 175, 196, 85, 234, 233, 199, 86,
                     45, 149, 120, 1, 57, 14, 102, 147, 123, 7, 150,
                  ]),
                  sk: new Uint8Array([
                     238, 127, 13, 239, 238, 127, 177, 22, 231, 87, 89, 23, 88, 52, 42, 22, 6, 170, 172, 112, 111, 101,
                     147, 204, 238, 28, 203, 159, 118, 54, 139, 151,
                  ]),
                  hk: new Uint8Array([
                     253, 30, 237, 129, 147, 186, 235, 65, 217, 78, 219, 38, 163, 12, 23, 248, 3, 118, 123, 120, 237, 0,
                     56, 103, 67, 76, 88, 126, 153, 83, 238, 85,
                  ]),
                  hIV: new Uint8Array([
                     46, 22, 226, 86, 89, 132, 143, 185, 198, 129, 242, 241, 183, 195, 191, 229, 162, 127, 162, 148, 75,
                     16, 28, 140,
                  ]),
               },
               'AEGIS-256': {
                  ek: new Uint8Array([
                     158, 221, 13, 155, 167, 216, 81, 115, 151, 193, 225, 53, 187, 156, 175, 196, 85, 234, 233, 199, 86,
                     45, 149, 120, 1, 57, 14, 102, 147, 123, 7, 150,
                  ]),
                  sk: new Uint8Array([
                     238, 127, 13, 239, 238, 127, 177, 22, 231, 87, 89, 23, 88, 52, 42, 22, 6, 170, 172, 112, 111, 101,
                     147, 204, 238, 28, 203, 159, 118, 54, 139, 151,
                  ]),
                  hk: new Uint8Array([
                     253, 30, 237, 129, 147, 186, 235, 65, 217, 78, 219, 38, 163, 12, 23, 248, 3, 118, 123, 120, 237, 0,
                     56, 103, 67, 76, 88, 126, 153, 83, 238, 85,
                  ]),
                  hIV: new Uint8Array([
                     46, 22, 226, 86, 89, 132, 143, 185, 198, 129, 242, 241, 183, 195, 191, 229, 162, 127, 162, 148, 75,
                     16, 28, 140, 53, 215, 85, 89, 158, 248, 52, 175,
                  ]),
               },
            },
         ],
         [
            cc.VERSION6,
            {
               'AES-GCM': {
                  ek: new Uint8Array([
                     158, 221, 13, 155, 167, 216, 81, 115, 151, 193, 225, 53, 187, 156, 175, 196, 85, 234, 233, 199, 86,
                     45, 149, 120, 1, 57, 14, 102, 147, 123, 7, 150,
                  ]),
                  sk: new Uint8Array([
                     172, 133, 166, 39, 233, 237, 204, 73, 234, 53, 191, 16, 169, 71, 164, 71, 36, 51, 18, 87, 19, 33,
                     25, 50, 224, 33, 120, 21, 233, 20, 154, 79,
                  ]),
                  hk: new Uint8Array([
                     34, 121, 121, 4, 207, 55, 202, 73, 83, 4, 58, 102, 135, 111, 186, 242, 3, 187, 239, 108, 251, 245,
                     3, 245, 3, 77, 228, 197, 101, 4, 16, 94,
                  ]),
                  hIV: new Uint8Array([46, 22, 226, 86, 89, 132, 143, 185, 198, 129, 242, 241]),
                  bk: new Uint8Array([
                     192, 104, 75, 166, 230, 145, 51, 60, 135, 138, 96, 200, 191, 249, 197, 149, 134, 168, 133, 169, 65,
                     94, 40, 46, 229, 162, 180, 28, 232, 61, 3, 227,
                  ]),
               },
               'X20-PLY': {
                  ek: new Uint8Array([
                     158, 221, 13, 155, 167, 216, 81, 115, 151, 193, 225, 53, 187, 156, 175, 196, 85, 234, 233, 199, 86,
                     45, 149, 120, 1, 57, 14, 102, 147, 123, 7, 150,
                  ]),
                  sk: new Uint8Array([
                     172, 133, 166, 39, 233, 237, 204, 73, 234, 53, 191, 16, 169, 71, 164, 71, 36, 51, 18, 87, 19, 33,
                     25, 50, 224, 33, 120, 21, 233, 20, 154, 79,
                  ]),
                  hk: new Uint8Array([
                     34, 121, 121, 4, 207, 55, 202, 73, 83, 4, 58, 102, 135, 111, 186, 242, 3, 187, 239, 108, 251, 245,
                     3, 245, 3, 77, 228, 197, 101, 4, 16, 94,
                  ]),
                  hIV: new Uint8Array([
                     46, 22, 226, 86, 89, 132, 143, 185, 198, 129, 242, 241, 183, 195, 191, 229, 162, 127, 162, 148, 75,
                     16, 28, 140,
                  ]),
                  bk: new Uint8Array([
                     192, 104, 75, 166, 230, 145, 51, 60, 135, 138, 96, 200, 191, 249, 197, 149, 134, 168, 133, 169, 65,
                     94, 40, 46, 229, 162, 180, 28, 232, 61, 3, 227,
                  ]),
               },
               'AEGIS-256': {
                  ek: new Uint8Array([
                     158, 221, 13, 155, 167, 216, 81, 115, 151, 193, 225, 53, 187, 156, 175, 196, 85, 234, 233, 199, 86,
                     45, 149, 120, 1, 57, 14, 102, 147, 123, 7, 150,
                  ]),
                  sk: new Uint8Array([
                     172, 133, 166, 39, 233, 237, 204, 73, 234, 53, 191, 16, 169, 71, 164, 71, 36, 51, 18, 87, 19, 33,
                     25, 50, 224, 33, 120, 21, 233, 20, 154, 79,
                  ]),
                  hk: new Uint8Array([
                     34, 121, 121, 4, 207, 55, 202, 73, 83, 4, 58, 102, 135, 111, 186, 242, 3, 187, 239, 108, 251, 245,
                     3, 245, 3, 77, 228, 197, 101, 4, 16, 94,
                  ]),
                  hIV: new Uint8Array([
                     46, 22, 226, 86, 89, 132, 143, 185, 198, 129, 242, 241, 183, 195, 191, 229, 162, 127, 162, 148, 75,
                     16, 28, 140, 53, 215, 85, 89, 158, 248, 52, 175,
                  ]),
                  bk: new Uint8Array([
                     192, 104, 75, 166, 230, 145, 51, 60, 135, 138, 96, 200, 191, 249, 197, 149, 134, 168, 133, 169, 65,
                     94, 40, 46, 229, 162, 180, 28, 232, 61, 3, 227,
                  ]),
               },
            },
         ],
         // generated by: pnpm vectors:keys
         [
            cc.VERSION7,
            {
               'AES-GCM': {
                  ek: new Uint8Array([
                     116, 242, 61, 10, 108, 97, 209, 124, 228, 61, 197, 29, 51, 181, 35, 99, 249, 55, 21, 36, 31, 115,
                     170, 7, 7, 61, 219, 85, 163, 160, 24, 168,
                  ]),
                  sk: new Uint8Array([
                     163, 148, 226, 77, 124, 112, 100, 108, 128, 224, 74, 73, 171, 218, 24, 13, 98, 66, 35, 34, 75, 207,
                     135, 22, 39, 62, 113, 121, 18, 165, 254, 28,
                  ]),
                  hk: new Uint8Array([
                     14, 159, 104, 237, 222, 85, 138, 34, 126, 157, 81, 139, 98, 171, 77, 10, 127, 148, 230, 254, 125,
                     30, 46, 228, 203, 147, 134, 141, 164, 10, 81, 105,
                  ]),
                  hIV: new Uint8Array([158, 97, 138, 184, 44, 70, 219, 110, 186, 127, 51, 99]),
                  bk: new Uint8Array([
                     61, 57, 107, 74, 35, 118, 132, 160, 207, 182, 124, 180, 165, 163, 55, 151, 178, 51, 9, 5, 116, 67,
                     15, 142, 183, 207, 224, 150, 32, 215, 8, 248,
                  ]),
                  commit: new Uint8Array([
                     77, 154, 216, 123, 90, 142, 38, 0, 114, 14, 150, 236, 96, 163, 55, 190, 160, 107, 23, 55, 247, 33,
                     185, 214, 56, 30, 219, 91, 142, 191, 14, 106,
                  ]),
               },
               'X20-PLY': {
                  ek: new Uint8Array([
                     151, 104, 43, 112, 157, 41, 222, 172, 99, 235, 77, 192, 78, 45, 125, 119, 155, 97, 155, 224, 132,
                     165, 10, 245, 166, 169, 255, 126, 226, 151, 228, 243,
                  ]),
                  sk: new Uint8Array([
                     108, 91, 159, 253, 3, 33, 237, 112, 173, 212, 215, 133, 101, 236, 7, 155, 103, 141, 79, 64, 21, 81,
                     26, 205, 230, 87, 185, 83, 55, 85, 249, 239,
                  ]),
                  hk: new Uint8Array([
                     91, 199, 210, 194, 45, 236, 239, 162, 119, 252, 31, 117, 65, 227, 20, 215, 231, 19, 233, 167, 52,
                     92, 220, 100, 36, 118, 122, 91, 14, 87, 164, 154,
                  ]),
                  hIV: new Uint8Array([
                     28, 76, 162, 179, 150, 28, 137, 55, 242, 29, 42, 1, 236, 107, 209, 167, 183, 111, 247, 144, 196,
                     97, 54, 20,
                  ]),
                  bk: new Uint8Array([
                     148, 165, 235, 202, 182, 161, 188, 67, 80, 48, 111, 82, 92, 161, 207, 212, 127, 134, 9, 255, 30,
                     163, 149, 208, 212, 249, 147, 209, 127, 37, 130, 56,
                  ]),
                  commit: new Uint8Array([
                     45, 191, 194, 209, 53, 35, 180, 104, 130, 97, 112, 75, 143, 223, 192, 166, 119, 165, 219, 109, 77,
                     131, 51, 175, 180, 241, 157, 55, 148, 170, 90, 15,
                  ]),
               },
               'AEGIS-256': {
                  ek: new Uint8Array([
                     19, 188, 48, 103, 209, 12, 52, 137, 155, 117, 18, 67, 70, 112, 1, 71, 50, 252, 45, 26, 177, 199,
                     123, 80, 230, 35, 252, 202, 242, 167, 57, 11,
                  ]),
                  sk: new Uint8Array([
                     189, 127, 169, 232, 173, 233, 238, 65, 214, 23, 142, 49, 82, 97, 214, 114, 234, 91, 110, 232, 241,
                     73, 156, 158, 2, 71, 231, 169, 170, 186, 205, 244,
                  ]),
                  hk: new Uint8Array([
                     227, 167, 244, 172, 42, 64, 64, 76, 8, 86, 73, 187, 220, 48, 229, 75, 117, 207, 41, 13, 167, 31,
                     227, 6, 31, 192, 0, 121, 59, 85, 152, 93,
                  ]),
                  hIV: new Uint8Array([
                     133, 34, 227, 194, 43, 92, 130, 203, 33, 207, 226, 139, 183, 122, 0, 76, 169, 59, 73, 11, 114, 149,
                     212, 176, 86, 242, 245, 99, 164, 140, 17, 182,
                  ]),
                  bk: new Uint8Array([
                     20, 164, 54, 117, 155, 116, 35, 191, 210, 69, 54, 161, 240, 120, 40, 26, 192, 30, 136, 108, 111,
                     212, 89, 137, 18, 24, 97, 36, 160, 110, 66, 107,
                  ]),
                  commit: new Uint8Array([
                     45, 179, 120, 212, 44, 215, 88, 239, 118, 245, 139, 56, 153, 241, 79, 96, 2, 103, 172, 145, 223,
                     192, 113, 244, 174, 167, 80, 221, 248, 24, 136, 27,
                  ]),
               },
            },
         ],

         // generated by: pnpm vectors:keys
         [
            cc.VERSION7,
            {
               'AES-GCM': {
                  extraKeyMaterial: new Uint8Array([120, 190, 112, 41, 122, 140, 204, 6, 253, 18]),
                  ek: new Uint8Array([
                     254, 57, 68, 32, 174, 22, 216, 5, 68, 114, 63, 121, 50, 178, 236, 181, 166, 226, 132, 131, 64, 195,
                     139, 103, 82, 12, 131, 30, 155, 73, 48, 171,
                  ]),
                  sk: new Uint8Array([
                     126, 50, 182, 156, 181, 156, 25, 223, 201, 133, 54, 157, 205, 248, 58, 217, 140, 70, 138, 144, 125,
                     194, 129, 61, 170, 21, 220, 71, 182, 14, 241, 190,
                  ]),
                  hk: new Uint8Array([
                     136, 115, 155, 174, 209, 123, 13, 65, 26, 227, 183, 174, 49, 205, 123, 224, 133, 43, 145, 142, 33,
                     182, 132, 255, 129, 221, 101, 228, 84, 38, 141, 124,
                  ]),
                  hIV: new Uint8Array([0, 39, 72, 109, 192, 71, 88, 214, 114, 43, 73, 90]),
                  bk: new Uint8Array([
                     234, 196, 137, 208, 116, 105, 34, 95, 206, 229, 53, 52, 136, 96, 42, 94, 167, 70, 97, 12, 28, 166,
                     131, 85, 188, 123, 124, 28, 7, 65, 111, 238,
                  ]),
                  commit: new Uint8Array([
                     131, 29, 40, 43, 143, 181, 129, 177, 10, 164, 150, 2, 70, 34, 88, 21, 12, 141, 235, 233, 164, 40,
                     138, 63, 61, 47, 150, 109, 71, 198, 254, 168,
                  ]),
               },
               'X20-PLY': {
                  extraKeyMaterial: new Uint8Array([120, 190, 112, 41, 122, 140, 204, 6, 253, 18]),
                  ek: new Uint8Array([
                     214, 16, 97, 74, 248, 18, 228, 247, 137, 139, 165, 39, 178, 202, 71, 208, 9, 231, 86, 55, 7, 75,
                     61, 214, 115, 197, 119, 145, 51, 91, 166, 41,
                  ]),
                  sk: new Uint8Array([
                     9, 235, 189, 10, 101, 2, 26, 112, 109, 246, 151, 81, 153, 141, 65, 230, 49, 21, 26, 239, 20, 191,
                     246, 57, 157, 54, 40, 85, 217, 114, 75, 129,
                  ]),
                  hk: new Uint8Array([
                     99, 90, 22, 36, 151, 128, 108, 55, 166, 83, 112, 208, 14, 165, 105, 9, 222, 177, 193, 220, 238,
                     176, 200, 48, 16, 208, 42, 181, 28, 136, 74, 59,
                  ]),
                  hIV: new Uint8Array([
                     16, 184, 236, 32, 200, 140, 28, 28, 129, 178, 253, 194, 208, 20, 101, 87, 143, 167, 142, 28, 58,
                     180, 202, 31,
                  ]),
                  bk: new Uint8Array([
                     184, 122, 197, 228, 83, 178, 105, 201, 91, 81, 19, 96, 182, 46, 19, 191, 144, 131, 184, 237, 155,
                     182, 158, 53, 213, 152, 88, 210, 169, 130, 221, 232,
                  ]),
                  commit: new Uint8Array([
                     234, 255, 111, 180, 53, 47, 237, 148, 253, 221, 99, 35, 107, 191, 54, 242, 170, 94, 200, 196, 50,
                     37, 84, 127, 126, 146, 0, 58, 112, 77, 137, 36,
                  ]),
               },
               'AEGIS-256': {
                  extraKeyMaterial: new Uint8Array([120, 190, 112, 41, 122, 140, 204, 6, 253, 18]),
                  ek: new Uint8Array([
                     235, 73, 183, 169, 184, 191, 201, 229, 211, 241, 189, 43, 42, 230, 10, 91, 12, 34, 171, 146, 189,
                     245, 152, 3, 71, 20, 255, 192, 48, 32, 160, 135,
                  ]),
                  sk: new Uint8Array([
                     111, 119, 142, 83, 177, 9, 77, 51, 200, 32, 67, 179, 102, 37, 175, 206, 194, 51, 54, 215, 59, 141,
                     244, 19, 154, 2, 162, 29, 105, 71, 89, 44,
                  ]),
                  hk: new Uint8Array([
                     2, 137, 191, 34, 190, 9, 124, 25, 73, 149, 145, 110, 60, 97, 59, 146, 161, 202, 7, 27, 124, 215,
                     156, 149, 223, 212, 220, 118, 171, 88, 39, 191,
                  ]),
                  hIV: new Uint8Array([
                     236, 88, 168, 140, 198, 68, 124, 100, 211, 209, 58, 249, 94, 222, 127, 255, 242, 116, 219, 47, 239,
                     87, 68, 130, 28, 239, 211, 58, 217, 144, 143, 205,
                  ]),
                  bk: new Uint8Array([
                     200, 210, 75, 8, 126, 197, 119, 121, 136, 27, 57, 145, 242, 203, 239, 239, 117, 217, 194, 15, 242,
                     140, 14, 85, 145, 12, 13, 234, 238, 199, 144, 131,
                  ]),
                  commit: new Uint8Array([
                     88, 26, 173, 27, 85, 17, 59, 173, 120, 40, 136, 210, 182, 176, 221, 40, 97, 9, 56, 178, 211, 228,
                     252, 10, 177, 128, 124, 51, 127, 193, 80, 53,
                  ]),
               },
            },
         ],
         // generated by: pnpm vectors:keys
         [
            cc.VERSION8,
            {
               'AES-GCM': {
                  ek: new Uint8Array([
                     175, 233, 148, 101, 170, 172, 53, 70, 150, 93, 166, 175, 139, 152, 107, 232, 134, 10, 173, 147,
                     186, 47, 96, 112, 70, 120, 56, 166, 146, 45, 238, 37,
                  ]),
                  sk: new Uint8Array([
                     252, 155, 134, 50, 138, 122, 136, 236, 123, 154, 141, 114, 147, 26, 215, 17, 102, 152, 246, 198,
                     222, 2, 2, 58, 244, 112, 21, 225, 162, 55, 97, 209,
                  ]),
                  hk: new Uint8Array([
                     54, 124, 30, 38, 152, 16, 237, 128, 123, 97, 123, 217, 38, 242, 190, 101, 112, 244, 142, 219, 165,
                     123, 47, 137, 49, 78, 109, 8, 87, 111, 92, 89,
                  ]),
                  hIV: new Uint8Array([224, 138, 32, 7, 229, 118, 49, 38, 83, 150, 44, 204]),
                  bk: new Uint8Array([
                     21, 32, 32, 200, 200, 105, 171, 185, 87, 167, 200, 78, 27, 191, 110, 221, 105, 155, 245, 17, 186,
                     196, 22, 123, 100, 95, 191, 167, 211, 146, 106, 31,
                  ]),
                  commit: new Uint8Array([
                     249, 205, 172, 95, 0, 230, 172, 28, 17, 8, 203, 187, 6, 60, 68, 39, 101, 95, 167, 155, 176, 92,
                     112, 165, 187, 207, 119, 225, 50, 93, 115, 163,
                  ]),
               },
               'X20-PLY': {
                  ek: new Uint8Array([
                     10, 204, 213, 226, 63, 16, 1, 89, 94, 232, 82, 134, 77, 86, 216, 149, 85, 22, 117, 103, 150, 50,
                     186, 122, 52, 127, 23, 132, 213, 49, 29, 246,
                  ]),
                  sk: new Uint8Array([
                     108, 134, 59, 195, 233, 127, 174, 112, 59, 57, 226, 135, 170, 36, 4, 209, 220, 57, 43, 191, 172,
                     186, 2, 198, 155, 169, 178, 6, 221, 108, 213, 1,
                  ]),
                  hk: new Uint8Array([
                     122, 177, 106, 245, 78, 142, 40, 128, 217, 242, 41, 198, 10, 51, 154, 230, 201, 186, 185, 38, 232,
                     22, 105, 137, 146, 6, 194, 217, 207, 39, 17, 52,
                  ]),
                  hIV: new Uint8Array([
                     97, 228, 205, 236, 66, 5, 184, 193, 174, 48, 213, 119, 117, 166, 95, 185, 121, 164, 209, 145, 173,
                     154, 70, 179,
                  ]),
                  bk: new Uint8Array([
                     228, 182, 216, 173, 171, 178, 185, 10, 43, 248, 213, 26, 197, 168, 38, 92, 125, 91, 98, 140, 23,
                     173, 240, 97, 161, 52, 167, 50, 130, 23, 186, 123,
                  ]),
                  commit: new Uint8Array([
                     183, 169, 207, 56, 250, 134, 31, 150, 18, 5, 139, 91, 63, 30, 1, 10, 239, 130, 122, 233, 26, 173,
                     63, 206, 240, 243, 151, 247, 63, 110, 95, 132,
                  ]),
               },
               'AEGIS-256': {
                  ek: new Uint8Array([
                     26, 143, 30, 0, 141, 250, 239, 60, 121, 224, 188, 130, 71, 129, 2, 209, 87, 251, 204, 13, 2, 202,
                     18, 228, 246, 213, 85, 55, 61, 64, 198, 95,
                  ]),
                  sk: new Uint8Array([
                     69, 57, 17, 114, 211, 93, 190, 64, 205, 230, 224, 94, 168, 198, 91, 198, 111, 102, 214, 170, 42,
                     136, 28, 208, 184, 124, 75, 138, 127, 228, 152, 229,
                  ]),
                  hk: new Uint8Array([
                     116, 43, 60, 230, 33, 152, 159, 17, 30, 146, 57, 13, 211, 238, 49, 135, 7, 120, 29, 118, 171, 177,
                     214, 209, 70, 131, 107, 75, 19, 106, 117, 63,
                  ]),
                  hIV: new Uint8Array([
                     236, 177, 157, 141, 157, 23, 142, 172, 190, 227, 97, 26, 64, 34, 136, 2, 243, 67, 218, 203, 112,
                     154, 0, 110, 11, 151, 199, 121, 151, 53, 168, 0,
                  ]),
                  bk: new Uint8Array([
                     16, 144, 127, 200, 212, 109, 237, 89, 251, 125, 56, 143, 142, 111, 220, 31, 193, 119, 49, 184, 235,
                     48, 233, 11, 247, 212, 223, 200, 147, 103, 123, 185,
                  ]),
                  commit: new Uint8Array([
                     125, 54, 98, 239, 175, 137, 67, 203, 100, 233, 61, 86, 227, 42, 211, 244, 22, 40, 106, 184, 35,
                     170, 56, 141, 24, 116, 150, 255, 117, 226, 205, 154,
                  ]),
               },
            },
         ],
         [
            cc.VERSION8,
            {
               'AES-GCM': {
                  extraKeyMaterial: new Uint8Array([120, 190, 112, 41, 122, 140, 204, 6, 253, 18]),
                  ek: new Uint8Array([
                     32, 117, 121, 29, 10, 105, 150, 189, 22, 119, 5, 133, 210, 115, 26, 212, 115, 103, 31, 11, 128,
                     152, 158, 74, 154, 147, 154, 91, 173, 193, 31, 17,
                  ]),
                  sk: new Uint8Array([
                     221, 174, 102, 247, 95, 187, 207, 231, 79, 218, 70, 180, 126, 13, 247, 181, 121, 104, 122, 52, 5,
                     64, 37, 149, 205, 92, 87, 82, 214, 210, 17, 208,
                  ]),
                  hk: new Uint8Array([
                     90, 194, 117, 60, 122, 242, 120, 155, 54, 183, 40, 229, 122, 41, 37, 206, 117, 37, 45, 19, 193, 66,
                     163, 37, 86, 236, 238, 1, 98, 19, 14, 169,
                  ]),
                  hIV: new Uint8Array([142, 1, 116, 106, 41, 117, 29, 165, 47, 206, 233, 237]),
                  bk: new Uint8Array([
                     153, 181, 175, 243, 245, 68, 28, 58, 178, 118, 43, 66, 113, 75, 234, 138, 16, 80, 248, 97, 71, 66,
                     170, 36, 87, 7, 90, 143, 120, 18, 187, 33,
                  ]),
                  commit: new Uint8Array([
                     33, 82, 14, 160, 185, 26, 26, 29, 192, 95, 120, 112, 255, 183, 87, 90, 21, 251, 119, 101, 136, 61,
                     154, 0, 86, 79, 120, 94, 126, 116, 144, 37,
                  ]),
               },
               'X20-PLY': {
                  extraKeyMaterial: new Uint8Array([120, 190, 112, 41, 122, 140, 204, 6, 253, 18]),
                  ek: new Uint8Array([
                     250, 53, 181, 168, 185, 113, 211, 177, 127, 234, 138, 131, 130, 49, 52, 39, 254, 65, 34, 33, 133,
                     65, 146, 64, 238, 194, 89, 96, 172, 92, 225, 122,
                  ]),
                  sk: new Uint8Array([
                     2, 44, 20, 50, 187, 190, 36, 35, 171, 186, 125, 37, 41, 10, 51, 0, 95, 78, 189, 0, 209, 91, 190,
                     88, 15, 169, 57, 113, 147, 248, 55, 76,
                  ]),
                  hk: new Uint8Array([
                     81, 169, 160, 78, 161, 251, 3, 149, 31, 146, 162, 176, 61, 8, 220, 120, 110, 217, 5, 146, 82, 164,
                     251, 185, 30, 1, 208, 241, 22, 128, 202, 216,
                  ]),
                  hIV: new Uint8Array([
                     27, 171, 3, 247, 24, 149, 31, 100, 83, 248, 177, 1, 152, 175, 203, 93, 134, 121, 183, 77, 7, 226,
                     30, 117,
                  ]),
                  bk: new Uint8Array([
                     254, 150, 127, 188, 17, 68, 69, 105, 69, 127, 85, 118, 83, 104, 165, 253, 89, 240, 26, 192, 68, 45,
                     221, 147, 1, 102, 19, 198, 74, 43, 8, 160,
                  ]),
                  commit: new Uint8Array([
                     184, 196, 186, 19, 162, 75, 166, 171, 251, 50, 119, 56, 82, 183, 172, 163, 22, 154, 160, 109, 84,
                     68, 40, 218, 193, 201, 160, 88, 218, 126, 98, 232,
                  ]),
               },
               'AEGIS-256': {
                  extraKeyMaterial: new Uint8Array([120, 190, 112, 41, 122, 140, 204, 6, 253, 18]),
                  ek: new Uint8Array([
                     92, 128, 44, 140, 241, 62, 109, 211, 51, 6, 102, 204, 120, 252, 81, 174, 110, 32, 55, 195, 205,
                     193, 17, 218, 10, 246, 173, 176, 39, 224, 209, 200,
                  ]),
                  sk: new Uint8Array([
                     27, 212, 154, 186, 188, 74, 233, 153, 206, 33, 54, 119, 181, 51, 128, 33, 67, 46, 188, 11, 111,
                     129, 86, 144, 109, 93, 235, 160, 191, 120, 157, 87,
                  ]),
                  hk: new Uint8Array([
                     150, 26, 18, 62, 5, 245, 177, 191, 55, 176, 128, 250, 53, 65, 163, 48, 6, 5, 5, 238, 205, 209, 103,
                     193, 225, 173, 121, 218, 129, 249, 227, 31,
                  ]),
                  hIV: new Uint8Array([
                     241, 203, 228, 11, 168, 162, 200, 31, 116, 212, 31, 246, 126, 54, 146, 43, 121, 172, 106, 102, 89,
                     10, 107, 88, 254, 87, 102, 66, 170, 24, 51, 5,
                  ]),
                  bk: new Uint8Array([
                     110, 50, 118, 171, 253, 246, 58, 165, 215, 72, 150, 119, 190, 102, 53, 102, 165, 91, 125, 249, 14,
                     129, 135, 200, 148, 67, 10, 151, 89, 242, 138, 114,
                  ]),
                  commit: new Uint8Array([
                     173, 120, 26, 154, 191, 127, 65, 43, 152, 90, 43, 237, 80, 90, 194, 56, 25, 130, 119, 17, 245, 245,
                     255, 74, 12, 30, 120, 33, 32, 103, 167, 36,
                  ]),
               },
            },
         ],
      ];

      for (const [ver, algsExpected] of expected) {
         for (const alg of Ciphers.algs()) {
            const algExpected = algsExpected[alg];
            expect(algExpected).toBeDefined();

            const pwd = 'a good pwd';
            const ic = cc.ICOUNT_MIN;
            const userCred = new Uint8Array([
               214, 245, 252, 122, 133, 39, 76, 162, 64, 201, 143, 217, 237, 57, 18, 207, 199, 153, 20, 28, 162, 9, 236,
               66, 100, 103, 152, 159, 226, 50, 225, 129,
            ]);
            const slt = new Uint8Array([160, 202, 135, 230, 125, 174, 49, 189, 171, 56, 203, 1, 237, 233, 27, 76]);
            const iv = new Uint8Array([
               46, 22, 226, 86, 89, 132, 143, 185, 198, 129, 242, 241, 183, 195, 191, 229, 162, 127, 162, 148, 75, 16,
               28, 140, 53, 215, 85, 89, 158, 248, 52, 175,
            ]);

            const keyProvider = new PWDKeyProvider(userCred, [pwd, undefined], algExpected.extraKeyMaterial);
            keyProvider.setCipherDataInfo({
               ver,
               alg,
               ic,
               slt,
               lp: 1,
               lpEnd: 1,
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

   it('PWDKeyProvider getBlockCipherKey block number range', async () => {
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

      const largeBk = await keyProvider.getBlockCipherKey(cc.BLOCKS_MAX);
      expect(largeBk.byteLength).toBe(cc.KEY_BYTES);
      keyProvider.purge();
   });

   it('PWDKeyProvider getBlockCipherKey enforces version', async () => {
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

   it('MasterKeyKeyProvider getBlockCipherKey block number range', async () => {
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

      const largeBk = await keyProvider.getBlockCipherKey(cc.BLOCKS_MAX);
      expect(largeBk.byteLength).toBe(cc.KEY_BYTES);
      keyProvider.purge();
   });

   it('MasterKeyKeyProvider keys match expected values', async () => {
      // generated by: pnpm vectors:keys
      const expected: [number, Record<cc.CipherAlgs, Record<string, Uint8Array<ArrayBuffer>>>][] = [
         [
            cc.VERSION7,
            {
               'AES-GCM': {
                  ek: new Uint8Array([
                     25, 129, 11, 96, 135, 33, 63, 217, 43, 12, 118, 167, 202, 183, 106, 149, 187, 161, 97, 89, 108, 10,
                     137, 90, 196, 127, 77, 148, 25, 75, 158, 72,
                  ]),
                  sk: new Uint8Array([
                     110, 9, 12, 164, 246, 119, 116, 215, 233, 250, 105, 189, 226, 46, 48, 111, 53, 146, 1, 174, 176,
                     250, 228, 59, 76, 194, 83, 60, 57, 17, 235, 183,
                  ]),
                  hk: new Uint8Array([
                     75, 233, 122, 79, 182, 152, 112, 212, 91, 189, 225, 190, 76, 54, 190, 102, 17, 186, 165, 214, 69,
                     190, 3, 137, 73, 80, 162, 22, 104, 169, 53, 118,
                  ]),
                  hIV: new Uint8Array([6, 172, 134, 98, 183, 253, 128, 188, 13, 97, 111, 81]),
                  bk: new Uint8Array([
                     13, 93, 49, 8, 209, 104, 26, 47, 249, 114, 126, 206, 191, 118, 177, 96, 224, 48, 22, 90, 164, 139,
                     222, 89, 126, 84, 138, 27, 187, 220, 87, 89,
                  ]),
                  commit: new Uint8Array([
                     224, 81, 234, 9, 44, 181, 208, 151, 228, 161, 23, 68, 252, 120, 156, 182, 144, 181, 111, 75, 230,
                     148, 179, 81, 70, 165, 40, 205, 174, 7, 173, 3,
                  ]),
               },
               'X20-PLY': {
                  ek: new Uint8Array([
                     47, 200, 68, 171, 123, 192, 12, 3, 72, 76, 206, 187, 112, 134, 28, 138, 118, 254, 214, 9, 58, 159,
                     132, 13, 246, 6, 25, 189, 136, 27, 172, 38,
                  ]),
                  sk: new Uint8Array([
                     139, 60, 86, 241, 1, 168, 19, 135, 3, 153, 33, 106, 24, 176, 100, 83, 190, 219, 133, 151, 142, 179,
                     33, 119, 75, 183, 33, 181, 146, 252, 129, 238,
                  ]),
                  hk: new Uint8Array([
                     117, 255, 53, 125, 151, 101, 143, 79, 167, 113, 143, 143, 241, 210, 32, 72, 48, 125, 200, 166, 64,
                     50, 144, 203, 69, 20, 152, 197, 56, 185, 80, 199,
                  ]),
                  hIV: new Uint8Array([
                     218, 227, 148, 190, 235, 92, 131, 150, 70, 55, 70, 227, 76, 136, 136, 206, 13, 32, 236, 248, 229,
                     46, 159, 201,
                  ]),
                  bk: new Uint8Array([
                     202, 1, 233, 57, 83, 94, 188, 96, 217, 166, 49, 229, 76, 183, 46, 12, 110, 151, 152, 27, 91, 88,
                     58, 242, 246, 75, 101, 214, 47, 180, 189, 117,
                  ]),
                  commit: new Uint8Array([
                     47, 120, 69, 120, 229, 144, 241, 59, 138, 247, 198, 85, 111, 184, 200, 245, 31, 115, 55, 255, 93,
                     110, 201, 31, 239, 13, 223, 26, 49, 235, 117, 156,
                  ]),
               },
               'AEGIS-256': {
                  ek: new Uint8Array([
                     95, 116, 198, 245, 2, 214, 147, 10, 88, 79, 2, 125, 213, 6, 93, 192, 3, 211, 246, 22, 55, 149, 137,
                     121, 163, 131, 81, 149, 155, 156, 111, 8,
                  ]),
                  sk: new Uint8Array([
                     34, 79, 216, 66, 110, 252, 78, 127, 203, 61, 9, 109, 155, 190, 103, 112, 115, 227, 88, 57, 79, 143,
                     245, 159, 161, 201, 146, 128, 183, 70, 68, 242,
                  ]),
                  hk: new Uint8Array([
                     108, 163, 10, 153, 128, 142, 16, 241, 125, 197, 75, 229, 89, 210, 87, 187, 145, 248, 125, 139, 88,
                     174, 139, 159, 178, 177, 151, 231, 241, 83, 147, 181,
                  ]),
                  hIV: new Uint8Array([
                     163, 206, 50, 53, 126, 162, 225, 104, 13, 75, 141, 218, 55, 126, 20, 91, 110, 252, 197, 109, 246,
                     201, 185, 189, 94, 65, 189, 240, 44, 151, 35, 84,
                  ]),
                  bk: new Uint8Array([
                     165, 4, 182, 231, 7, 1, 91, 158, 82, 74, 197, 67, 135, 164, 242, 218, 1, 159, 28, 187, 192, 87,
                     146, 97, 81, 143, 61, 78, 99, 212, 16, 172,
                  ]),
                  commit: new Uint8Array([
                     222, 209, 2, 95, 0, 57, 254, 148, 51, 177, 56, 63, 53, 146, 242, 17, 60, 16, 44, 150, 95, 33, 134,
                     34, 73, 144, 41, 75, 117, 129, 0, 219,
                  ]),
               },
            },
         ],
         [
            cc.VERSION7,
            {
               'AES-GCM': {
                  extraKeyMaterial: new Uint8Array([120, 190, 112, 41, 122, 140, 204, 6, 253, 18]),
                  ek: new Uint8Array([
                     62, 43, 242, 215, 21, 141, 122, 13, 2, 38, 243, 254, 112, 200, 114, 92, 59, 80, 209, 207, 157, 127,
                     132, 17, 80, 61, 240, 220, 149, 88, 170, 16,
                  ]),
                  sk: new Uint8Array([
                     209, 56, 236, 89, 220, 203, 165, 253, 32, 160, 210, 53, 220, 128, 14, 68, 197, 175, 146, 228, 20,
                     152, 87, 54, 106, 34, 231, 231, 106, 250, 70, 228,
                  ]),
                  hk: new Uint8Array([
                     118, 52, 25, 8, 249, 215, 77, 139, 225, 231, 17, 183, 42, 184, 141, 41, 69, 89, 112, 146, 26, 90,
                     182, 1, 88, 18, 106, 155, 24, 30, 134, 98,
                  ]),
                  hIV: new Uint8Array([93, 210, 168, 79, 69, 155, 53, 55, 4, 151, 150, 82]),
                  bk: new Uint8Array([
                     174, 156, 65, 21, 147, 3, 148, 239, 97, 217, 216, 244, 174, 204, 221, 199, 172, 32, 144, 144, 219,
                     11, 166, 147, 5, 151, 209, 213, 26, 145, 88, 51,
                  ]),
                  commit: new Uint8Array([
                     227, 73, 243, 13, 96, 140, 75, 83, 188, 178, 164, 186, 100, 115, 138, 249, 4, 16, 27, 152, 166, 95,
                     146, 171, 42, 253, 162, 34, 64, 173, 37, 226,
                  ]),
               },
               'X20-PLY': {
                  extraKeyMaterial: new Uint8Array([120, 190, 112, 41, 122, 140, 204, 6, 253, 18]),
                  ek: new Uint8Array([
                     157, 147, 112, 209, 3, 40, 65, 66, 67, 89, 106, 123, 251, 202, 215, 13, 68, 220, 209, 45, 56, 197,
                     88, 38, 190, 0, 91, 51, 88, 214, 113, 26,
                  ]),
                  sk: new Uint8Array([
                     249, 14, 233, 174, 146, 161, 86, 217, 253, 35, 214, 231, 164, 101, 249, 169, 133, 33, 21, 58, 191,
                     195, 89, 182, 245, 174, 48, 42, 254, 192, 206, 54,
                  ]),
                  hk: new Uint8Array([
                     90, 2, 146, 127, 213, 234, 202, 181, 133, 213, 133, 0, 88, 241, 203, 170, 175, 125, 252, 25, 196,
                     139, 48, 197, 202, 146, 221, 139, 241, 59, 151, 105,
                  ]),
                  hIV: new Uint8Array([
                     43, 249, 167, 241, 45, 108, 151, 45, 207, 180, 166, 171, 18, 172, 103, 58, 12, 180, 40, 124, 114,
                     119, 122, 226,
                  ]),
                  bk: new Uint8Array([
                     201, 171, 30, 45, 106, 18, 219, 107, 106, 223, 159, 107, 13, 120, 190, 97, 44, 234, 216, 122, 136,
                     194, 236, 94, 136, 10, 27, 12, 3, 244, 223, 158,
                  ]),
                  commit: new Uint8Array([
                     3, 67, 93, 221, 110, 13, 198, 0, 176, 97, 83, 132, 66, 41, 218, 215, 144, 54, 0, 233, 236, 102,
                     227, 187, 160, 104, 121, 166, 169, 186, 30, 95,
                  ]),
               },
               'AEGIS-256': {
                  extraKeyMaterial: new Uint8Array([120, 190, 112, 41, 122, 140, 204, 6, 253, 18]),
                  ek: new Uint8Array([
                     115, 173, 169, 134, 46, 62, 56, 41, 73, 181, 183, 176, 225, 186, 38, 91, 245, 119, 231, 71, 130,
                     21, 108, 106, 128, 166, 89, 87, 198, 61, 87, 192,
                  ]),
                  sk: new Uint8Array([
                     144, 248, 50, 96, 159, 123, 1, 69, 238, 133, 67, 105, 44, 65, 176, 132, 137, 71, 224, 164, 19, 132,
                     216, 195, 53, 69, 216, 121, 93, 44, 221, 21,
                  ]),
                  hk: new Uint8Array([
                     143, 27, 241, 195, 93, 150, 106, 186, 95, 37, 85, 26, 222, 120, 73, 92, 221, 73, 223, 252, 216, 35,
                     80, 241, 28, 195, 116, 199, 203, 157, 194, 82,
                  ]),
                  hIV: new Uint8Array([
                     119, 117, 163, 175, 98, 141, 56, 219, 217, 204, 129, 121, 24, 67, 69, 107, 88, 236, 94, 21, 224,
                     199, 181, 250, 149, 167, 226, 250, 1, 184, 94, 176,
                  ]),
                  bk: new Uint8Array([
                     24, 136, 144, 244, 195, 210, 250, 38, 63, 197, 58, 11, 199, 197, 251, 8, 229, 54, 250, 194, 31,
                     103, 13, 177, 249, 88, 84, 181, 115, 73, 242, 171,
                  ]),
                  commit: new Uint8Array([
                     108, 202, 108, 21, 9, 113, 198, 9, 66, 19, 109, 234, 247, 151, 188, 118, 110, 53, 120, 90, 138, 57,
                     103, 246, 198, 67, 72, 221, 137, 144, 237, 103,
                  ]),
               },
            },
         ],
         // generated by: pnpm vectors:keys
         [
            cc.VERSION8,
            {
               'AES-GCM': {
                  ek: new Uint8Array([
                     210, 239, 184, 194, 116, 61, 216, 119, 58, 172, 211, 10, 69, 198, 173, 34, 201, 228, 168, 59, 11,
                     184, 12, 96, 146, 172, 117, 16, 16, 88, 55, 249,
                  ]),
                  sk: new Uint8Array([
                     175, 220, 98, 250, 116, 170, 226, 156, 118, 70, 53, 40, 58, 46, 193, 36, 18, 129, 2, 107, 72, 255,
                     88, 243, 43, 242, 61, 58, 197, 162, 220, 103,
                  ]),
                  hk: new Uint8Array([
                     159, 149, 70, 195, 203, 58, 136, 197, 25, 222, 253, 219, 62, 122, 106, 21, 18, 161, 55, 244, 184,
                     159, 241, 120, 152, 49, 78, 136, 211, 23, 224, 71,
                  ]),
                  hIV: new Uint8Array([231, 67, 255, 85, 112, 73, 179, 70, 96, 234, 44, 25]),
                  bk: new Uint8Array([
                     49, 56, 52, 60, 241, 32, 201, 13, 24, 23, 58, 64, 153, 4, 152, 63, 72, 206, 204, 52, 35, 127, 207,
                     251, 250, 145, 73, 72, 59, 73, 119, 17,
                  ]),
               },
               'X20-PLY': {
                  ek: new Uint8Array([
                     23, 24, 18, 222, 111, 210, 65, 172, 2, 201, 157, 122, 42, 108, 246, 245, 152, 13, 182, 149, 92,
                     243, 196, 9, 17, 215, 50, 105, 104, 194, 22, 153,
                  ]),
                  sk: new Uint8Array([
                     83, 197, 150, 59, 233, 74, 62, 173, 51, 8, 123, 154, 38, 46, 94, 19, 4, 227, 57, 220, 99, 185, 6,
                     53, 34, 151, 36, 239, 133, 162, 164, 166,
                  ]),
                  hk: new Uint8Array([
                     178, 183, 4, 2, 54, 18, 38, 53, 15, 20, 34, 43, 146, 235, 123, 35, 122, 241, 174, 74, 47, 115, 6,
                     197, 140, 156, 163, 127, 4, 109, 199, 63,
                  ]),
                  hIV: new Uint8Array([
                     251, 163, 160, 221, 76, 240, 2, 192, 57, 32, 28, 90, 194, 33, 139, 53, 11, 165, 8, 23, 82, 188, 67,
                     242,
                  ]),
                  bk: new Uint8Array([
                     36, 206, 145, 69, 127, 41, 147, 75, 102, 81, 22, 118, 62, 45, 181, 243, 58, 52, 253, 132, 29, 27,
                     6, 222, 204, 48, 147, 251, 103, 124, 81, 230,
                  ]),
               },
               'AEGIS-256': {
                  ek: new Uint8Array([
                     99, 245, 206, 144, 91, 47, 219, 165, 140, 176, 194, 77, 192, 66, 242, 154, 129, 112, 87, 54, 39,
                     231, 6, 49, 90, 75, 255, 141, 100, 98, 227, 20,
                  ]),
                  sk: new Uint8Array([
                     20, 253, 35, 120, 160, 132, 40, 53, 212, 63, 96, 157, 211, 6, 3, 234, 85, 122, 144, 55, 52, 64, 90,
                     136, 97, 49, 36, 61, 69, 144, 119, 220,
                  ]),
                  hk: new Uint8Array([
                     6, 60, 228, 36, 18, 104, 236, 120, 151, 163, 27, 155, 228, 170, 188, 61, 221, 254, 64, 194, 178,
                     203, 56, 135, 93, 22, 246, 164, 158, 224, 5, 31,
                  ]),
                  hIV: new Uint8Array([
                     231, 163, 155, 32, 13, 22, 166, 33, 141, 104, 152, 30, 0, 89, 27, 106, 78, 178, 94, 62, 235, 63,
                     143, 10, 9, 179, 154, 2, 89, 35, 193, 54,
                  ]),
                  bk: new Uint8Array([
                     19, 40, 70, 21, 34, 5, 20, 25, 15, 5, 190, 140, 123, 147, 45, 141, 27, 150, 9, 134, 59, 83, 32, 33,
                     117, 185, 37, 40, 122, 28, 53, 48,
                  ]),
               },
            },
         ],
         [
            cc.VERSION8,
            {
               'AES-GCM': {
                  extraKeyMaterial: new Uint8Array([120, 190, 112, 41, 122, 140, 204, 6, 253, 18]),
                  ek: new Uint8Array([
                     215, 217, 146, 34, 211, 146, 67, 84, 248, 164, 95, 50, 199, 67, 40, 25, 143, 90, 221, 190, 44, 231,
                     65, 177, 203, 164, 151, 206, 127, 73, 231, 112,
                  ]),
                  sk: new Uint8Array([
                     222, 202, 209, 238, 7, 128, 74, 178, 225, 231, 91, 26, 130, 196, 36, 93, 247, 213, 152, 3, 48, 166,
                     69, 116, 94, 109, 248, 145, 127, 226, 242, 98,
                  ]),
                  hk: new Uint8Array([
                     25, 197, 73, 222, 245, 31, 205, 161, 199, 166, 97, 160, 46, 5, 77, 113, 176, 22, 184, 199, 52, 233,
                     43, 190, 55, 229, 22, 144, 230, 22, 36, 70,
                  ]),
                  hIV: new Uint8Array([4, 159, 201, 115, 152, 229, 8, 81, 83, 29, 131, 169]),
                  bk: new Uint8Array([
                     233, 251, 182, 125, 73, 88, 3, 200, 146, 139, 27, 222, 45, 133, 34, 136, 202, 89, 9, 91, 160, 11,
                     242, 133, 33, 102, 5, 168, 118, 146, 208, 2,
                  ]),
               },
               'X20-PLY': {
                  extraKeyMaterial: new Uint8Array([120, 190, 112, 41, 122, 140, 204, 6, 253, 18]),
                  ek: new Uint8Array([
                     6, 229, 20, 128, 6, 243, 13, 148, 254, 32, 236, 220, 163, 133, 15, 111, 241, 61, 41, 29, 66, 50,
                     249, 39, 254, 207, 226, 42, 27, 139, 35, 240,
                  ]),
                  sk: new Uint8Array([
                     62, 10, 107, 181, 251, 15, 26, 100, 118, 205, 154, 167, 140, 35, 182, 241, 125, 8, 231, 215, 157,
                     81, 46, 174, 2, 152, 40, 178, 118, 30, 149, 131,
                  ]),
                  hk: new Uint8Array([
                     224, 2, 156, 14, 208, 184, 186, 241, 127, 187, 151, 58, 116, 47, 219, 150, 135, 14, 113, 5, 9, 30,
                     208, 77, 62, 26, 5, 215, 18, 132, 166, 103,
                  ]),
                  hIV: new Uint8Array([
                     72, 102, 156, 233, 39, 122, 78, 6, 62, 49, 105, 99, 79, 208, 30, 69, 168, 192, 157, 110, 19, 83,
                     93, 227,
                  ]),
                  bk: new Uint8Array([
                     8, 8, 207, 14, 207, 59, 176, 85, 213, 154, 162, 42, 187, 187, 242, 141, 201, 210, 160, 161, 60, 87,
                     92, 3, 93, 215, 18, 193, 205, 61, 110, 71,
                  ]),
               },
               'AEGIS-256': {
                  extraKeyMaterial: new Uint8Array([120, 190, 112, 41, 122, 140, 204, 6, 253, 18]),
                  ek: new Uint8Array([
                     30, 236, 219, 150, 133, 94, 152, 41, 140, 204, 33, 170, 22, 79, 211, 165, 30, 79, 201, 142, 187,
                     210, 193, 32, 183, 12, 251, 5, 31, 124, 152, 43,
                  ]),
                  sk: new Uint8Array([
                     33, 87, 61, 230, 148, 145, 77, 60, 10, 50, 142, 110, 181, 75, 65, 150, 158, 195, 49, 53, 52, 133,
                     242, 222, 63, 37, 230, 13, 219, 52, 242, 90,
                  ]),
                  hk: new Uint8Array([
                     41, 19, 126, 166, 120, 44, 229, 201, 88, 59, 13, 100, 50, 33, 119, 49, 36, 170, 29, 164, 167, 161,
                     234, 175, 113, 102, 123, 72, 244, 44, 126, 194,
                  ]),
                  hIV: new Uint8Array([
                     57, 99, 49, 81, 246, 52, 156, 206, 95, 98, 248, 121, 65, 158, 0, 16, 252, 229, 76, 147, 216, 233,
                     169, 210, 196, 171, 20, 175, 49, 166, 80, 165,
                  ]),
                  bk: new Uint8Array([
                     227, 209, 235, 165, 120, 133, 4, 127, 209, 109, 69, 143, 43, 110, 5, 65, 168, 113, 177, 197, 184,
                     173, 133, 53, 80, 28, 147, 52, 130, 219, 176, 147,
                  ]),
               },
            },
         ],
      ];

      for (const [ver, algsExpected] of expected) {
         for (const alg of Ciphers.algs()) {
            const algExpected = algsExpected[alg];
            expect(algExpected).toBeDefined();

            const slt = new Uint8Array([247, 229, 145, 155, 90, 26, 149, 132, 44, 75, 197, 178, 187, 88, 41, 244]);
            const iv = new Uint8Array([
               110, 248, 21, 150, 142, 146, 67, 223, 194, 230, 44, 28, 247, 71, 109, 61, 53, 215, 85, 89, 158, 248, 52,
               175, 53, 215, 169, 223, 219, 248, 52, 175,
            ]);
            const master = new Uint8Array([
               88, 164, 150, 177, 85, 43, 43, 25, 42, 250, 120, 190, 112, 26, 41, 122, 140, 204, 6, 253, 225, 220, 237,
               10, 80, 64, 148, 152, 204, 30, 231, 18,
            ]);

            const keyProvider = new MasterKeyKeyProvider(master, algExpected.extraKeyMaterial);
            keyProvider.setCipherDataInfo({
               ver,
               alg,
               ic: 0,
               slt,
               lp: 1,
               lpEnd: 1,
            });
            const ek = await keyProvider.getCipherKey(false);
            const sk = await keyProvider.getSigningKey();
            const [hk, hIV] = await keyProvider.getHintCipherKeyAndIV(iv.slice(0, Ciphers.algIVByteLength(alg)));
            await expect(keyProvider.getBlockCipherKey(0)).rejects.toThrow(/Invalid block number: 0/);
            const bk = await keyProvider.getBlockCipherKey(1);
            expect(keyProvider.supportsCommitment).toBe(!!algExpected.commit);
            const commit = algExpected.commit ? await keyProvider.getKeyCommitment() : undefined;

            expect(isEqualArray(ek, algExpected.ek)).toBe(true);
            expect(isEqualArray(sk, algExpected.sk)).toBe(true);
            expect(isEqualArray(hk, algExpected.hk)).toBe(true);
            expect(isEqualArray(hIV, algExpected.hIV)).toBe(true);
            expect(isEqualArray(bk, algExpected.bk)).toBe(true);
            if (commit) {
               expect(isEqualArray(commit, algExpected.commit)).toBe(true);
            }

            expect(isEqualArray(ek, master)).toBe(false);
            expect(isEqualArray(sk, master)).toBe(false);
            expect(isEqualArray(hk, master)).toBe(false);
            expect(isEqualArray(hIV, master)).toBe(false);
            expect(isEqualArray(bk, master)).toBe(false);
            if (commit) {
               expect(isEqualArray(commit, master)).toBe(false);
            }
         }
      }
   });

   it('PWDKeyProvider keys match expected values, multi-loop with extraKeyMaterial', async () => {
      // generated by: pnpm vectors:keys
      const expected: [number, number, Record<cc.CipherAlgs, Record<string, Uint8Array<ArrayBuffer>>>][] = [
         [
            cc.VERSION7,
            1,
            {
               'AES-GCM': {
                  ek: new Uint8Array([
                     254, 57, 68, 32, 174, 22, 216, 5, 68, 114, 63, 121, 50, 178, 236, 181, 166, 226, 132, 131, 64, 195,
                     139, 103, 82, 12, 131, 30, 155, 73, 48, 171,
                  ]),
                  sk: new Uint8Array([
                     126, 50, 182, 156, 181, 156, 25, 223, 201, 133, 54, 157, 205, 248, 58, 217, 140, 70, 138, 144, 125,
                     194, 129, 61, 170, 21, 220, 71, 182, 14, 241, 190,
                  ]),
                  hk: new Uint8Array([
                     136, 115, 155, 174, 209, 123, 13, 65, 26, 227, 183, 174, 49, 205, 123, 224, 133, 43, 145, 142, 33,
                     182, 132, 255, 129, 221, 101, 228, 84, 38, 141, 124,
                  ]),
                  hIV: new Uint8Array([0, 39, 72, 109, 192, 71, 88, 214, 114, 43, 73, 90]),
                  bk: new Uint8Array([
                     234, 196, 137, 208, 116, 105, 34, 95, 206, 229, 53, 52, 136, 96, 42, 94, 167, 70, 97, 12, 28, 166,
                     131, 85, 188, 123, 124, 28, 7, 65, 111, 238,
                  ]),
                  commit: new Uint8Array([
                     131, 29, 40, 43, 143, 181, 129, 177, 10, 164, 150, 2, 70, 34, 88, 21, 12, 141, 235, 233, 164, 40,
                     138, 63, 61, 47, 150, 109, 71, 198, 254, 168,
                  ]),
               },
               'X20-PLY': {
                  ek: new Uint8Array([
                     214, 16, 97, 74, 248, 18, 228, 247, 137, 139, 165, 39, 178, 202, 71, 208, 9, 231, 86, 55, 7, 75,
                     61, 214, 115, 197, 119, 145, 51, 91, 166, 41,
                  ]),
                  sk: new Uint8Array([
                     9, 235, 189, 10, 101, 2, 26, 112, 109, 246, 151, 81, 153, 141, 65, 230, 49, 21, 26, 239, 20, 191,
                     246, 57, 157, 54, 40, 85, 217, 114, 75, 129,
                  ]),
                  hk: new Uint8Array([
                     99, 90, 22, 36, 151, 128, 108, 55, 166, 83, 112, 208, 14, 165, 105, 9, 222, 177, 193, 220, 238,
                     176, 200, 48, 16, 208, 42, 181, 28, 136, 74, 59,
                  ]),
                  hIV: new Uint8Array([
                     16, 184, 236, 32, 200, 140, 28, 28, 129, 178, 253, 194, 208, 20, 101, 87, 143, 167, 142, 28, 58,
                     180, 202, 31,
                  ]),
                  bk: new Uint8Array([
                     184, 122, 197, 228, 83, 178, 105, 201, 91, 81, 19, 96, 182, 46, 19, 191, 144, 131, 184, 237, 155,
                     182, 158, 53, 213, 152, 88, 210, 169, 130, 221, 232,
                  ]),
                  commit: new Uint8Array([
                     234, 255, 111, 180, 53, 47, 237, 148, 253, 221, 99, 35, 107, 191, 54, 242, 170, 94, 200, 196, 50,
                     37, 84, 127, 126, 146, 0, 58, 112, 77, 137, 36,
                  ]),
               },
               'AEGIS-256': {
                  ek: new Uint8Array([
                     235, 73, 183, 169, 184, 191, 201, 229, 211, 241, 189, 43, 42, 230, 10, 91, 12, 34, 171, 146, 189,
                     245, 152, 3, 71, 20, 255, 192, 48, 32, 160, 135,
                  ]),
                  sk: new Uint8Array([
                     111, 119, 142, 83, 177, 9, 77, 51, 200, 32, 67, 179, 102, 37, 175, 206, 194, 51, 54, 215, 59, 141,
                     244, 19, 154, 2, 162, 29, 105, 71, 89, 44,
                  ]),
                  hk: new Uint8Array([
                     2, 137, 191, 34, 190, 9, 124, 25, 73, 149, 145, 110, 60, 97, 59, 146, 161, 202, 7, 27, 124, 215,
                     156, 149, 223, 212, 220, 118, 171, 88, 39, 191,
                  ]),
                  hIV: new Uint8Array([
                     236, 88, 168, 140, 198, 68, 124, 100, 211, 209, 58, 249, 94, 222, 127, 255, 242, 116, 219, 47, 239,
                     87, 68, 130, 28, 239, 211, 58, 217, 144, 143, 205,
                  ]),
                  bk: new Uint8Array([
                     200, 210, 75, 8, 126, 197, 119, 121, 136, 27, 57, 145, 242, 203, 239, 239, 117, 217, 194, 15, 242,
                     140, 14, 85, 145, 12, 13, 234, 238, 199, 144, 131,
                  ]),
                  commit: new Uint8Array([
                     88, 26, 173, 27, 85, 17, 59, 173, 120, 40, 136, 210, 182, 176, 221, 40, 97, 9, 56, 178, 211, 228,
                     252, 10, 177, 128, 124, 51, 127, 193, 80, 53,
                  ]),
               },
            },
         ],
         [
            cc.VERSION7,
            2,
            {
               'AES-GCM': {
                  ek: new Uint8Array([
                     66, 206, 240, 128, 213, 23, 28, 69, 62, 156, 185, 1, 204, 151, 11, 101, 106, 128, 203, 128, 16, 32,
                     191, 147, 77, 95, 105, 107, 153, 246, 193, 114,
                  ]),
                  sk: new Uint8Array([
                     62, 192, 10, 112, 253, 229, 200, 243, 71, 210, 43, 235, 9, 69, 229, 76, 157, 152, 103, 209, 110, 4,
                     111, 210, 183, 3, 248, 52, 152, 79, 169, 54,
                  ]),
                  hk: new Uint8Array([
                     69, 25, 18, 228, 148, 55, 133, 235, 44, 11, 125, 171, 207, 153, 9, 220, 71, 177, 236, 197, 157,
                     227, 204, 76, 189, 223, 179, 172, 180, 36, 222, 128,
                  ]),
                  hIV: new Uint8Array([90, 98, 87, 24, 158, 71, 67, 116, 130, 112, 213, 139]),
                  bk: new Uint8Array([
                     255, 205, 87, 41, 223, 246, 27, 32, 47, 23, 200, 232, 140, 102, 127, 253, 54, 61, 222, 239, 57,
                     166, 31, 75, 168, 85, 179, 199, 123, 242, 45, 7,
                  ]),
                  commit: new Uint8Array([
                     205, 147, 18, 47, 112, 203, 91, 178, 35, 11, 209, 47, 236, 114, 190, 139, 148, 206, 0, 250, 248, 7,
                     83, 240, 27, 235, 228, 142, 174, 113, 116, 34,
                  ]),
               },
               'X20-PLY': {
                  ek: new Uint8Array([
                     154, 109, 219, 233, 90, 111, 177, 221, 193, 214, 32, 186, 226, 201, 0, 36, 46, 144, 167, 245, 129,
                     94, 243, 101, 30, 182, 116, 121, 187, 239, 99, 98,
                  ]),
                  sk: new Uint8Array([
                     244, 209, 138, 94, 155, 26, 68, 83, 204, 97, 99, 63, 61, 26, 8, 254, 111, 73, 173, 8, 154, 197, 38,
                     158, 66, 14, 66, 193, 170, 4, 35, 178,
                  ]),
                  hk: new Uint8Array([
                     106, 45, 252, 201, 243, 204, 197, 233, 135, 42, 215, 3, 58, 169, 214, 52, 61, 152, 120, 36, 105,
                     58, 243, 29, 130, 99, 247, 107, 53, 190, 228, 170,
                  ]),
                  hIV: new Uint8Array([
                     250, 67, 134, 148, 150, 123, 249, 26, 62, 8, 195, 119, 166, 163, 248, 209, 119, 12, 148, 188, 30,
                     38, 141, 54,
                  ]),
                  bk: new Uint8Array([
                     204, 117, 220, 75, 83, 188, 116, 217, 149, 166, 27, 251, 17, 150, 1, 14, 70, 211, 16, 186, 14, 146,
                     137, 6, 255, 71, 240, 163, 104, 87, 154, 29,
                  ]),
                  commit: new Uint8Array([
                     192, 78, 162, 114, 91, 56, 46, 93, 121, 117, 231, 100, 115, 14, 219, 76, 112, 57, 232, 20, 226, 46,
                     128, 69, 156, 6, 75, 166, 189, 232, 219, 194,
                  ]),
               },
               'AEGIS-256': {
                  ek: new Uint8Array([
                     33, 74, 135, 189, 151, 233, 117, 150, 42, 164, 78, 220, 2, 79, 13, 170, 36, 95, 3, 152, 68, 90,
                     142, 8, 87, 195, 222, 22, 62, 245, 17, 166,
                  ]),
                  sk: new Uint8Array([
                     95, 213, 244, 251, 109, 115, 20, 28, 139, 255, 216, 137, 183, 95, 225, 115, 55, 74, 125, 102, 93,
                     181, 97, 54, 226, 194, 198, 213, 159, 230, 101, 7,
                  ]),
                  hk: new Uint8Array([
                     137, 34, 91, 133, 176, 18, 125, 243, 153, 146, 133, 98, 38, 199, 249, 3, 143, 225, 54, 217, 139,
                     26, 116, 81, 196, 202, 67, 135, 28, 165, 17, 157,
                  ]),
                  hIV: new Uint8Array([
                     227, 174, 52, 237, 228, 83, 101, 193, 132, 251, 19, 230, 160, 31, 127, 57, 149, 252, 101, 235, 122,
                     172, 46, 179, 171, 119, 3, 59, 82, 39, 230, 210,
                  ]),
                  bk: new Uint8Array([
                     227, 83, 152, 120, 153, 239, 248, 215, 159, 176, 185, 176, 99, 234, 188, 201, 165, 150, 233, 222,
                     168, 218, 163, 211, 232, 118, 103, 118, 234, 186, 101, 81,
                  ]),
                  commit: new Uint8Array([
                     29, 206, 22, 83, 233, 26, 208, 107, 205, 130, 44, 64, 231, 253, 43, 143, 168, 61, 37, 38, 175, 160,
                     27, 128, 151, 135, 209, 8, 23, 60, 198, 157,
                  ]),
               },
            },
         ],
         // generated by: pnpm vectors:keys
         [
            cc.VERSION8,
            1,
            {
               'AES-GCM': {
                  ek: new Uint8Array([
                     32, 117, 121, 29, 10, 105, 150, 189, 22, 119, 5, 133, 210, 115, 26, 212, 115, 103, 31, 11, 128,
                     152, 158, 74, 154, 147, 154, 91, 173, 193, 31, 17,
                  ]),
                  sk: new Uint8Array([
                     221, 174, 102, 247, 95, 187, 207, 231, 79, 218, 70, 180, 126, 13, 247, 181, 121, 104, 122, 52, 5,
                     64, 37, 149, 205, 92, 87, 82, 214, 210, 17, 208,
                  ]),
                  hk: new Uint8Array([
                     90, 194, 117, 60, 122, 242, 120, 155, 54, 183, 40, 229, 122, 41, 37, 206, 117, 37, 45, 19, 193, 66,
                     163, 37, 86, 236, 238, 1, 98, 19, 14, 169,
                  ]),
                  hIV: new Uint8Array([142, 1, 116, 106, 41, 117, 29, 165, 47, 206, 233, 237]),
                  bk: new Uint8Array([
                     153, 181, 175, 243, 245, 68, 28, 58, 178, 118, 43, 66, 113, 75, 234, 138, 16, 80, 248, 97, 71, 66,
                     170, 36, 87, 7, 90, 143, 120, 18, 187, 33,
                  ]),
                  commit: new Uint8Array([
                     33, 82, 14, 160, 185, 26, 26, 29, 192, 95, 120, 112, 255, 183, 87, 90, 21, 251, 119, 101, 136, 61,
                     154, 0, 86, 79, 120, 94, 126, 116, 144, 37,
                  ]),
               },
               'X20-PLY': {
                  ek: new Uint8Array([
                     250, 53, 181, 168, 185, 113, 211, 177, 127, 234, 138, 131, 130, 49, 52, 39, 254, 65, 34, 33, 133,
                     65, 146, 64, 238, 194, 89, 96, 172, 92, 225, 122,
                  ]),
                  sk: new Uint8Array([
                     2, 44, 20, 50, 187, 190, 36, 35, 171, 186, 125, 37, 41, 10, 51, 0, 95, 78, 189, 0, 209, 91, 190,
                     88, 15, 169, 57, 113, 147, 248, 55, 76,
                  ]),
                  hk: new Uint8Array([
                     81, 169, 160, 78, 161, 251, 3, 149, 31, 146, 162, 176, 61, 8, 220, 120, 110, 217, 5, 146, 82, 164,
                     251, 185, 30, 1, 208, 241, 22, 128, 202, 216,
                  ]),
                  hIV: new Uint8Array([
                     27, 171, 3, 247, 24, 149, 31, 100, 83, 248, 177, 1, 152, 175, 203, 93, 134, 121, 183, 77, 7, 226,
                     30, 117,
                  ]),
                  bk: new Uint8Array([
                     254, 150, 127, 188, 17, 68, 69, 105, 69, 127, 85, 118, 83, 104, 165, 253, 89, 240, 26, 192, 68, 45,
                     221, 147, 1, 102, 19, 198, 74, 43, 8, 160,
                  ]),
                  commit: new Uint8Array([
                     184, 196, 186, 19, 162, 75, 166, 171, 251, 50, 119, 56, 82, 183, 172, 163, 22, 154, 160, 109, 84,
                     68, 40, 218, 193, 201, 160, 88, 218, 126, 98, 232,
                  ]),
               },
               'AEGIS-256': {
                  ek: new Uint8Array([
                     92, 128, 44, 140, 241, 62, 109, 211, 51, 6, 102, 204, 120, 252, 81, 174, 110, 32, 55, 195, 205,
                     193, 17, 218, 10, 246, 173, 176, 39, 224, 209, 200,
                  ]),
                  sk: new Uint8Array([
                     27, 212, 154, 186, 188, 74, 233, 153, 206, 33, 54, 119, 181, 51, 128, 33, 67, 46, 188, 11, 111,
                     129, 86, 144, 109, 93, 235, 160, 191, 120, 157, 87,
                  ]),
                  hk: new Uint8Array([
                     150, 26, 18, 62, 5, 245, 177, 191, 55, 176, 128, 250, 53, 65, 163, 48, 6, 5, 5, 238, 205, 209, 103,
                     193, 225, 173, 121, 218, 129, 249, 227, 31,
                  ]),
                  hIV: new Uint8Array([
                     241, 203, 228, 11, 168, 162, 200, 31, 116, 212, 31, 246, 126, 54, 146, 43, 121, 172, 106, 102, 89,
                     10, 107, 88, 254, 87, 102, 66, 170, 24, 51, 5,
                  ]),
                  bk: new Uint8Array([
                     110, 50, 118, 171, 253, 246, 58, 165, 215, 72, 150, 119, 190, 102, 53, 102, 165, 91, 125, 249, 14,
                     129, 135, 200, 148, 67, 10, 151, 89, 242, 138, 114,
                  ]),
                  commit: new Uint8Array([
                     173, 120, 26, 154, 191, 127, 65, 43, 152, 90, 43, 237, 80, 90, 194, 56, 25, 130, 119, 17, 245, 245,
                     255, 74, 12, 30, 120, 33, 32, 103, 167, 36,
                  ]),
               },
            },
         ],
         [
            cc.VERSION8,
            2,
            {
               'AES-GCM': {
                  ek: new Uint8Array([
                     27, 129, 28, 215, 62, 8, 223, 37, 141, 217, 175, 80, 48, 24, 24, 63, 113, 199, 59, 85, 236, 245,
                     25, 225, 36, 152, 176, 110, 165, 97, 134, 47,
                  ]),
                  sk: new Uint8Array([
                     48, 57, 150, 144, 40, 155, 147, 173, 88, 49, 9, 230, 171, 97, 64, 201, 222, 102, 182, 121, 44, 212,
                     147, 228, 188, 180, 187, 58, 60, 233, 59, 192,
                  ]),
                  hk: new Uint8Array([
                     82, 20, 149, 215, 96, 176, 251, 131, 177, 169, 78, 190, 247, 43, 123, 79, 107, 138, 210, 220, 79,
                     107, 70, 106, 91, 54, 1, 35, 97, 157, 144, 166,
                  ]),
                  hIV: new Uint8Array([95, 140, 151, 33, 186, 201, 230, 106, 177, 56, 56, 213]),
                  bk: new Uint8Array([
                     217, 27, 111, 85, 75, 218, 222, 165, 125, 176, 131, 204, 145, 240, 5, 81, 65, 199, 182, 232, 122,
                     237, 36, 248, 60, 100, 191, 96, 25, 18, 137, 41,
                  ]),
                  commit: new Uint8Array([
                     85, 28, 229, 253, 127, 44, 230, 158, 215, 14, 96, 172, 242, 79, 168, 62, 211, 136, 39, 205, 4, 113,
                     43, 234, 203, 153, 19, 65, 235, 255, 215, 240,
                  ]),
               },
               'X20-PLY': {
                  ek: new Uint8Array([
                     94, 167, 185, 77, 219, 112, 71, 66, 75, 117, 137, 155, 77, 120, 112, 237, 4, 21, 16, 5, 108, 170,
                     242, 56, 187, 129, 255, 101, 36, 228, 111, 143,
                  ]),
                  sk: new Uint8Array([
                     97, 223, 152, 140, 76, 136, 0, 237, 89, 158, 8, 139, 132, 216, 169, 97, 36, 213, 80, 207, 19, 212,
                     136, 55, 166, 205, 124, 213, 164, 100, 130, 134,
                  ]),
                  hk: new Uint8Array([
                     48, 128, 243, 40, 201, 102, 120, 37, 93, 92, 49, 207, 190, 152, 72, 232, 62, 60, 158, 123, 201,
                     191, 85, 50, 36, 241, 182, 165, 252, 254, 116, 57,
                  ]),
                  hIV: new Uint8Array([
                     232, 89, 24, 216, 83, 6, 32, 160, 203, 207, 140, 253, 242, 218, 13, 53, 95, 31, 170, 164, 75, 244,
                     86, 249,
                  ]),
                  bk: new Uint8Array([
                     104, 134, 187, 58, 90, 103, 155, 204, 229, 51, 244, 148, 99, 42, 29, 149, 20, 135, 15, 248, 63,
                     175, 1, 173, 0, 55, 99, 218, 77, 173, 164, 175,
                  ]),
                  commit: new Uint8Array([
                     63, 162, 129, 92, 139, 247, 191, 71, 234, 151, 207, 135, 37, 152, 229, 249, 100, 11, 12, 228, 89,
                     4, 45, 174, 43, 156, 127, 190, 199, 225, 185, 149,
                  ]),
               },
               'AEGIS-256': {
                  ek: new Uint8Array([
                     77, 60, 92, 182, 243, 180, 201, 117, 42, 148, 35, 105, 243, 29, 48, 89, 125, 193, 36, 47, 187, 219,
                     81, 156, 190, 138, 204, 112, 205, 254, 179, 235,
                  ]),
                  sk: new Uint8Array([
                     45, 242, 43, 71, 163, 244, 151, 145, 92, 238, 145, 238, 159, 61, 224, 127, 248, 172, 237, 69, 221,
                     16, 87, 194, 201, 86, 187, 213, 223, 161, 188, 111,
                  ]),
                  hk: new Uint8Array([
                     185, 39, 198, 58, 113, 218, 13, 178, 217, 32, 253, 90, 48, 181, 156, 114, 76, 170, 55, 6, 1, 159,
                     245, 218, 172, 17, 168, 122, 2, 12, 91, 13,
                  ]),
                  hIV: new Uint8Array([
                     131, 30, 145, 164, 154, 122, 121, 129, 187, 60, 4, 171, 93, 153, 74, 127, 154, 132, 217, 214, 81,
                     102, 226, 61, 7, 112, 126, 40, 205, 41, 146, 240,
                  ]),
                  bk: new Uint8Array([
                     46, 201, 255, 107, 92, 28, 16, 200, 62, 51, 215, 50, 95, 176, 149, 18, 222, 226, 182, 73, 159, 199,
                     26, 148, 156, 232, 221, 97, 91, 161, 239, 142,
                  ]),
                  commit: new Uint8Array([
                     234, 28, 110, 185, 63, 73, 51, 140, 126, 137, 49, 211, 158, 178, 196, 28, 183, 72, 200, 94, 114,
                     238, 167, 229, 229, 2, 106, 42, 43, 30, 8, 77,
                  ]),
               },
            },
         ],
      ];

      const lpEnd = 2;
      const extraKeyMaterial = new Uint8Array([120, 190, 112, 41, 122, 140, 204, 6, 253, 18]);
      const userCred = new Uint8Array([
         214, 245, 252, 122, 133, 39, 76, 162, 64, 201, 143, 217, 237, 57, 18, 207, 199, 153, 20, 28, 162, 9, 236, 66,
         100, 103, 152, 159, 226, 50, 225, 129,
      ]);
      const slt = new Uint8Array([160, 202, 135, 230, 125, 174, 49, 189, 171, 56, 203, 1, 237, 233, 27, 76]);
      const iv = new Uint8Array([
         46, 22, 226, 86, 89, 132, 143, 185, 198, 129, 242, 241, 183, 195, 191, 229, 162, 127, 162, 148, 75, 16, 28,
         140, 53, 215, 85, 89, 158, 248, 52, 175,
      ]);
      const pwd = 'a good pwd';

      for (const [ver, lp, algsExpected] of expected) {
         for (const alg of Ciphers.algs()) {
            const algExpected = algsExpected[alg];
            const keyProvider = new PWDKeyProvider(userCred, [pwd, undefined], extraKeyMaterial);
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

   it('MasterKeyKeyProvider keys match expected values, multi-loop with extraKeyMaterial', async () => {
      // generated by: pnpm vectors:keys
      const expected: [number, number, Record<cc.CipherAlgs, Record<string, Uint8Array<ArrayBuffer>>>][] = [
         [
            cc.VERSION7,
            1,
            {
               'AES-GCM': {
                  ek: new Uint8Array([
                     62, 43, 242, 215, 21, 141, 122, 13, 2, 38, 243, 254, 112, 200, 114, 92, 59, 80, 209, 207, 157, 127,
                     132, 17, 80, 61, 240, 220, 149, 88, 170, 16,
                  ]),
                  sk: new Uint8Array([
                     209, 56, 236, 89, 220, 203, 165, 253, 32, 160, 210, 53, 220, 128, 14, 68, 197, 175, 146, 228, 20,
                     152, 87, 54, 106, 34, 231, 231, 106, 250, 70, 228,
                  ]),
                  hk: new Uint8Array([
                     118, 52, 25, 8, 249, 215, 77, 139, 225, 231, 17, 183, 42, 184, 141, 41, 69, 89, 112, 146, 26, 90,
                     182, 1, 88, 18, 106, 155, 24, 30, 134, 98,
                  ]),
                  hIV: new Uint8Array([93, 210, 168, 79, 69, 155, 53, 55, 4, 151, 150, 82]),
                  bk: new Uint8Array([
                     174, 156, 65, 21, 147, 3, 148, 239, 97, 217, 216, 244, 174, 204, 221, 199, 172, 32, 144, 144, 219,
                     11, 166, 147, 5, 151, 209, 213, 26, 145, 88, 51,
                  ]),
                  commit: new Uint8Array([
                     227, 73, 243, 13, 96, 140, 75, 83, 188, 178, 164, 186, 100, 115, 138, 249, 4, 16, 27, 152, 166, 95,
                     146, 171, 42, 253, 162, 34, 64, 173, 37, 226,
                  ]),
               },
               'X20-PLY': {
                  ek: new Uint8Array([
                     157, 147, 112, 209, 3, 40, 65, 66, 67, 89, 106, 123, 251, 202, 215, 13, 68, 220, 209, 45, 56, 197,
                     88, 38, 190, 0, 91, 51, 88, 214, 113, 26,
                  ]),
                  sk: new Uint8Array([
                     249, 14, 233, 174, 146, 161, 86, 217, 253, 35, 214, 231, 164, 101, 249, 169, 133, 33, 21, 58, 191,
                     195, 89, 182, 245, 174, 48, 42, 254, 192, 206, 54,
                  ]),
                  hk: new Uint8Array([
                     90, 2, 146, 127, 213, 234, 202, 181, 133, 213, 133, 0, 88, 241, 203, 170, 175, 125, 252, 25, 196,
                     139, 48, 197, 202, 146, 221, 139, 241, 59, 151, 105,
                  ]),
                  hIV: new Uint8Array([
                     43, 249, 167, 241, 45, 108, 151, 45, 207, 180, 166, 171, 18, 172, 103, 58, 12, 180, 40, 124, 114,
                     119, 122, 226,
                  ]),
                  bk: new Uint8Array([
                     201, 171, 30, 45, 106, 18, 219, 107, 106, 223, 159, 107, 13, 120, 190, 97, 44, 234, 216, 122, 136,
                     194, 236, 94, 136, 10, 27, 12, 3, 244, 223, 158,
                  ]),
                  commit: new Uint8Array([
                     3, 67, 93, 221, 110, 13, 198, 0, 176, 97, 83, 132, 66, 41, 218, 215, 144, 54, 0, 233, 236, 102,
                     227, 187, 160, 104, 121, 166, 169, 186, 30, 95,
                  ]),
               },
               'AEGIS-256': {
                  ek: new Uint8Array([
                     115, 173, 169, 134, 46, 62, 56, 41, 73, 181, 183, 176, 225, 186, 38, 91, 245, 119, 231, 71, 130,
                     21, 108, 106, 128, 166, 89, 87, 198, 61, 87, 192,
                  ]),
                  sk: new Uint8Array([
                     144, 248, 50, 96, 159, 123, 1, 69, 238, 133, 67, 105, 44, 65, 176, 132, 137, 71, 224, 164, 19, 132,
                     216, 195, 53, 69, 216, 121, 93, 44, 221, 21,
                  ]),
                  hk: new Uint8Array([
                     143, 27, 241, 195, 93, 150, 106, 186, 95, 37, 85, 26, 222, 120, 73, 92, 221, 73, 223, 252, 216, 35,
                     80, 241, 28, 195, 116, 199, 203, 157, 194, 82,
                  ]),
                  hIV: new Uint8Array([
                     119, 117, 163, 175, 98, 141, 56, 219, 217, 204, 129, 121, 24, 67, 69, 107, 88, 236, 94, 21, 224,
                     199, 181, 250, 149, 167, 226, 250, 1, 184, 94, 176,
                  ]),
                  bk: new Uint8Array([
                     24, 136, 144, 244, 195, 210, 250, 38, 63, 197, 58, 11, 199, 197, 251, 8, 229, 54, 250, 194, 31,
                     103, 13, 177, 249, 88, 84, 181, 115, 73, 242, 171,
                  ]),
                  commit: new Uint8Array([
                     108, 202, 108, 21, 9, 113, 198, 9, 66, 19, 109, 234, 247, 151, 188, 118, 110, 53, 120, 90, 138, 57,
                     103, 246, 198, 67, 72, 221, 137, 144, 237, 103,
                  ]),
               },
            },
         ],
         [
            cc.VERSION7,
            2,
            {
               'AES-GCM': {
                  ek: new Uint8Array([
                     172, 45, 162, 96, 158, 190, 214, 221, 177, 245, 79, 138, 170, 38, 17, 132, 71, 147, 40, 98, 194,
                     226, 93, 11, 17, 244, 65, 9, 92, 21, 35, 254,
                  ]),
                  sk: new Uint8Array([
                     78, 25, 69, 77, 190, 43, 0, 214, 138, 18, 9, 37, 126, 194, 133, 119, 124, 188, 187, 43, 52, 94,
                     249, 91, 209, 125, 219, 189, 54, 149, 117, 73,
                  ]),
                  hk: new Uint8Array([
                     195, 145, 6, 179, 122, 136, 53, 228, 29, 178, 147, 238, 183, 75, 249, 43, 187, 63, 179, 36, 52,
                     252, 1, 24, 114, 4, 54, 130, 235, 25, 115, 18,
                  ]),
                  hIV: new Uint8Array([213, 54, 206, 110, 202, 234, 225, 42, 162, 32, 91, 196]),
                  bk: new Uint8Array([
                     166, 208, 141, 250, 39, 76, 240, 69, 219, 93, 176, 180, 200, 158, 123, 12, 83, 221, 75, 203, 42,
                     88, 184, 58, 240, 219, 223, 132, 204, 4, 10, 16,
                  ]),
                  commit: new Uint8Array([
                     227, 128, 147, 207, 106, 204, 84, 168, 140, 72, 211, 255, 105, 205, 201, 221, 95, 217, 240, 142,
                     76, 190, 171, 51, 139, 83, 255, 81, 156, 255, 53, 201,
                  ]),
               },
               'X20-PLY': {
                  ek: new Uint8Array([
                     86, 14, 79, 152, 62, 235, 61, 35, 91, 35, 168, 85, 111, 42, 68, 57, 9, 212, 151, 119, 104, 86, 201,
                     102, 253, 38, 232, 54, 90, 80, 163, 241,
                  ]),
                  sk: new Uint8Array([
                     81, 2, 7, 205, 204, 164, 40, 169, 10, 189, 1, 102, 31, 222, 140, 160, 150, 225, 80, 14, 229, 142,
                     144, 15, 137, 129, 151, 234, 15, 80, 20, 101,
                  ]),
                  hk: new Uint8Array([
                     119, 188, 112, 55, 251, 57, 217, 98, 156, 0, 30, 71, 250, 1, 205, 245, 32, 174, 81, 20, 85, 196,
                     35, 226, 226, 192, 217, 247, 159, 194, 209, 113,
                  ]),
                  hIV: new Uint8Array([
                     116, 64, 176, 21, 57, 73, 253, 186, 250, 72, 32, 176, 126, 106, 107, 236, 205, 80, 45, 245, 26, 19,
                     112, 169,
                  ]),
                  bk: new Uint8Array([
                     23, 122, 6, 147, 44, 218, 36, 236, 20, 172, 188, 48, 211, 178, 104, 57, 45, 90, 31, 61, 159, 171,
                     255, 157, 199, 188, 129, 28, 61, 51, 36, 250,
                  ]),
                  commit: new Uint8Array([
                     227, 86, 55, 254, 90, 192, 129, 137, 76, 69, 186, 114, 255, 57, 181, 189, 3, 203, 19, 253, 146,
                     215, 132, 208, 79, 119, 77, 181, 143, 62, 68, 148,
                  ]),
               },
               'AEGIS-256': {
                  ek: new Uint8Array([
                     200, 76, 42, 9, 63, 102, 66, 39, 58, 22, 98, 21, 114, 198, 85, 50, 26, 101, 167, 127, 94, 7, 143,
                     93, 81, 79, 165, 232, 138, 72, 55, 41,
                  ]),
                  sk: new Uint8Array([
                     236, 154, 41, 18, 104, 255, 218, 69, 51, 223, 250, 217, 187, 130, 93, 91, 51, 85, 196, 221, 147,
                     197, 4, 233, 88, 78, 198, 219, 56, 223, 213, 89,
                  ]),
                  hk: new Uint8Array([
                     156, 175, 209, 3, 184, 195, 14, 97, 3, 162, 242, 233, 66, 219, 163, 246, 57, 159, 193, 53, 248,
                     212, 216, 205, 26, 79, 155, 216, 156, 5, 31, 117,
                  ]),
                  hIV: new Uint8Array([
                     192, 33, 207, 36, 84, 19, 196, 175, 42, 53, 17, 134, 124, 203, 83, 55, 171, 53, 140, 178, 189, 165,
                     19, 164, 7, 81, 252, 225, 17, 204, 184, 201,
                  ]),
                  bk: new Uint8Array([
                     212, 210, 45, 101, 26, 86, 169, 202, 171, 84, 2, 74, 123, 55, 120, 123, 148, 194, 203, 250, 43,
                     156, 213, 158, 247, 65, 47, 17, 235, 42, 244, 122,
                  ]),
                  commit: new Uint8Array([
                     158, 67, 66, 247, 17, 243, 83, 240, 133, 59, 193, 61, 21, 11, 189, 205, 181, 145, 58, 153, 213, 32,
                     178, 64, 203, 248, 125, 132, 57, 246, 145, 239,
                  ]),
               },
            },
         ],
         // generated by: pnpm vectors:keys
         [
            cc.VERSION8,
            1,
            {
               'AES-GCM': {
                  ek: new Uint8Array([
                     215, 217, 146, 34, 211, 146, 67, 84, 248, 164, 95, 50, 199, 67, 40, 25, 143, 90, 221, 190, 44, 231,
                     65, 177, 203, 164, 151, 206, 127, 73, 231, 112,
                  ]),
                  sk: new Uint8Array([
                     222, 202, 209, 238, 7, 128, 74, 178, 225, 231, 91, 26, 130, 196, 36, 93, 247, 213, 152, 3, 48, 166,
                     69, 116, 94, 109, 248, 145, 127, 226, 242, 98,
                  ]),
                  hk: new Uint8Array([
                     25, 197, 73, 222, 245, 31, 205, 161, 199, 166, 97, 160, 46, 5, 77, 113, 176, 22, 184, 199, 52, 233,
                     43, 190, 55, 229, 22, 144, 230, 22, 36, 70,
                  ]),
                  hIV: new Uint8Array([4, 159, 201, 115, 152, 229, 8, 81, 83, 29, 131, 169]),
                  bk: new Uint8Array([
                     233, 251, 182, 125, 73, 88, 3, 200, 146, 139, 27, 222, 45, 133, 34, 136, 202, 89, 9, 91, 160, 11,
                     242, 133, 33, 102, 5, 168, 118, 146, 208, 2,
                  ]),
               },
               'X20-PLY': {
                  ek: new Uint8Array([
                     6, 229, 20, 128, 6, 243, 13, 148, 254, 32, 236, 220, 163, 133, 15, 111, 241, 61, 41, 29, 66, 50,
                     249, 39, 254, 207, 226, 42, 27, 139, 35, 240,
                  ]),
                  sk: new Uint8Array([
                     62, 10, 107, 181, 251, 15, 26, 100, 118, 205, 154, 167, 140, 35, 182, 241, 125, 8, 231, 215, 157,
                     81, 46, 174, 2, 152, 40, 178, 118, 30, 149, 131,
                  ]),
                  hk: new Uint8Array([
                     224, 2, 156, 14, 208, 184, 186, 241, 127, 187, 151, 58, 116, 47, 219, 150, 135, 14, 113, 5, 9, 30,
                     208, 77, 62, 26, 5, 215, 18, 132, 166, 103,
                  ]),
                  hIV: new Uint8Array([
                     72, 102, 156, 233, 39, 122, 78, 6, 62, 49, 105, 99, 79, 208, 30, 69, 168, 192, 157, 110, 19, 83,
                     93, 227,
                  ]),
                  bk: new Uint8Array([
                     8, 8, 207, 14, 207, 59, 176, 85, 213, 154, 162, 42, 187, 187, 242, 141, 201, 210, 160, 161, 60, 87,
                     92, 3, 93, 215, 18, 193, 205, 61, 110, 71,
                  ]),
               },
               'AEGIS-256': {
                  ek: new Uint8Array([
                     30, 236, 219, 150, 133, 94, 152, 41, 140, 204, 33, 170, 22, 79, 211, 165, 30, 79, 201, 142, 187,
                     210, 193, 32, 183, 12, 251, 5, 31, 124, 152, 43,
                  ]),
                  sk: new Uint8Array([
                     33, 87, 61, 230, 148, 145, 77, 60, 10, 50, 142, 110, 181, 75, 65, 150, 158, 195, 49, 53, 52, 133,
                     242, 222, 63, 37, 230, 13, 219, 52, 242, 90,
                  ]),
                  hk: new Uint8Array([
                     41, 19, 126, 166, 120, 44, 229, 201, 88, 59, 13, 100, 50, 33, 119, 49, 36, 170, 29, 164, 167, 161,
                     234, 175, 113, 102, 123, 72, 244, 44, 126, 194,
                  ]),
                  hIV: new Uint8Array([
                     57, 99, 49, 81, 246, 52, 156, 206, 95, 98, 248, 121, 65, 158, 0, 16, 252, 229, 76, 147, 216, 233,
                     169, 210, 196, 171, 20, 175, 49, 166, 80, 165,
                  ]),
                  bk: new Uint8Array([
                     227, 209, 235, 165, 120, 133, 4, 127, 209, 109, 69, 143, 43, 110, 5, 65, 168, 113, 177, 197, 184,
                     173, 133, 53, 80, 28, 147, 52, 130, 219, 176, 147,
                  ]),
               },
            },
         ],
         [
            cc.VERSION8,
            2,
            {
               'AES-GCM': {
                  ek: new Uint8Array([
                     224, 9, 174, 37, 125, 92, 81, 173, 79, 203, 194, 26, 162, 101, 249, 90, 123, 37, 83, 235, 21, 35,
                     154, 211, 29, 6, 49, 247, 1, 254, 47, 108,
                  ]),
                  sk: new Uint8Array([
                     107, 78, 125, 91, 218, 5, 48, 238, 232, 129, 178, 198, 18, 10, 109, 65, 215, 34, 248, 41, 133, 240,
                     172, 127, 174, 125, 112, 117, 171, 145, 126, 43,
                  ]),
                  hk: new Uint8Array([
                     131, 100, 252, 35, 187, 94, 66, 169, 191, 228, 110, 228, 71, 201, 196, 25, 126, 171, 144, 247, 34,
                     202, 5, 13, 46, 112, 51, 189, 233, 210, 140, 38,
                  ]),
                  hIV: new Uint8Array([142, 110, 237, 96, 242, 99, 118, 205, 9, 42, 248, 77]),
                  bk: new Uint8Array([
                     251, 41, 64, 22, 216, 139, 93, 229, 152, 227, 232, 92, 109, 0, 131, 102, 117, 162, 111, 39, 129,
                     43, 138, 82, 235, 195, 64, 245, 53, 17, 223, 167,
                  ]),
               },
               'X20-PLY': {
                  ek: new Uint8Array([
                     173, 58, 57, 98, 87, 88, 130, 249, 13, 54, 78, 23, 17, 186, 32, 76, 165, 240, 162, 97, 55, 106,
                     193, 244, 77, 50, 72, 189, 214, 148, 9, 4,
                  ]),
                  sk: new Uint8Array([
                     83, 63, 39, 140, 131, 155, 239, 39, 47, 253, 232, 50, 94, 116, 141, 59, 56, 204, 87, 215, 29, 209,
                     1, 4, 111, 180, 159, 9, 41, 179, 155, 189,
                  ]),
                  hk: new Uint8Array([
                     46, 118, 193, 50, 119, 49, 125, 76, 44, 108, 147, 149, 102, 226, 62, 216, 129, 7, 50, 32, 70, 76,
                     161, 68, 90, 68, 231, 125, 164, 231, 178, 108,
                  ]),
                  hIV: new Uint8Array([
                     89, 155, 212, 16, 94, 108, 245, 18, 212, 213, 129, 145, 211, 85, 236, 242, 89, 211, 210, 60, 115,
                     153, 86, 62,
                  ]),
                  bk: new Uint8Array([
                     189, 180, 232, 14, 222, 237, 40, 248, 31, 191, 94, 232, 97, 140, 67, 210, 103, 107, 186, 132, 7,
                     81, 239, 38, 226, 82, 55, 217, 89, 31, 65, 199,
                  ]),
               },
               'AEGIS-256': {
                  ek: new Uint8Array([
                     206, 124, 18, 209, 235, 206, 1, 57, 116, 185, 254, 197, 98, 67, 196, 241, 22, 247, 236, 164, 204,
                     246, 33, 189, 25, 46, 193, 82, 175, 145, 155, 150,
                  ]),
                  sk: new Uint8Array([
                     116, 88, 6, 245, 53, 4, 191, 224, 7, 66, 10, 150, 25, 224, 95, 69, 54, 6, 113, 193, 153, 165, 189,
                     186, 222, 215, 134, 20, 95, 58, 0, 1,
                  ]),
                  hk: new Uint8Array([
                     236, 107, 243, 55, 109, 81, 80, 70, 114, 155, 136, 121, 140, 79, 56, 49, 137, 97, 37, 66, 26, 157,
                     58, 244, 90, 211, 226, 66, 247, 200, 90, 12,
                  ]),
                  hIV: new Uint8Array([
                     233, 237, 143, 10, 118, 159, 27, 44, 23, 18, 239, 129, 47, 44, 106, 140, 185, 72, 120, 150, 198,
                     65, 194, 202, 41, 169, 83, 204, 203, 82, 76, 52,
                  ]),
                  bk: new Uint8Array([
                     14, 99, 182, 112, 69, 21, 176, 6, 168, 231, 191, 96, 52, 230, 148, 170, 36, 45, 131, 69, 203, 110,
                     233, 188, 71, 183, 23, 137, 58, 56, 148, 58,
                  ]),
               },
            },
         ],
      ];

      const lpEnd = 2;
      const extraKeyMaterial = new Uint8Array([120, 190, 112, 41, 122, 140, 204, 6, 253, 18]);
      const master = new Uint8Array([
         88, 164, 150, 177, 85, 43, 43, 25, 42, 250, 120, 190, 112, 26, 41, 122, 140, 204, 6, 253, 225, 220, 237, 10,
         80, 64, 148, 152, 204, 30, 231, 18,
      ]);
      const slt = new Uint8Array([247, 229, 145, 155, 90, 26, 149, 132, 44, 75, 197, 178, 187, 88, 41, 244]);
      const iv = new Uint8Array([
         110, 248, 21, 150, 142, 146, 67, 223, 194, 230, 44, 28, 247, 71, 109, 61, 53, 215, 85, 89, 158, 248, 52, 175,
         53, 215, 169, 223, 219, 248, 52, 175,
      ]);

      for (const [ver, lp, algsExpected] of expected) {
         for (const alg of Ciphers.algs()) {
            const algExpected = algsExpected[alg];
            const keyProvider = new MasterKeyKeyProvider(master, extraKeyMaterial);
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
            expect(keyProvider.supportsCommitment).toBe(!!algExpected.commit);
            const commit = algExpected.commit ? await keyProvider.getKeyCommitment() : undefined;

            expect(isEqualArray(ek, algExpected.ek)).toBe(true);
            expect(isEqualArray(sk, algExpected.sk)).toBe(true);
            expect(isEqualArray(hk, algExpected.hk)).toBe(true);
            expect(isEqualArray(hIV, algExpected.hIV)).toBe(true);
            expect(isEqualArray(bk, algExpected.bk)).toBe(true);
            if (commit) {
               expect(isEqualArray(commit, algExpected.commit)).toBe(true);
            }
         }
      }
   });

   it('PWDKeyProvider supportsCommitment per version', async () => {
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

      for (const ver of [cc.VERSION7, cc.VERSION8]) {
         const keyProvider = new PWDKeyProvider(userCred.slice(0), ['p', undefined]);
         keyProvider.setCipherDataInfo({ ...base, ver });
         await keyProvider.getCipherKey(false);
         expect(keyProvider.supportsCommitment).toBe(true);
         const commit = await keyProvider.getKeyCommitment();
         expect(commit.byteLength).toBe(cc.KEY_BYTES);
         keyProvider.purge();
      }
   });

   it('MasterKeyKeyProvider supportsCommitment per version', async () => {
      const slt = getRandom(cc.SLT_BYTES);

      const v7 = new MasterKeyKeyProvider(getRandom(cc.KEY_BYTES));
      v7.setCipherDataInfo({ ver: cc.VERSION7, alg: 'AES-GCM', ic: 0, slt, lp: 1, lpEnd: 1 });
      await v7.getCipherKey(false);
      expect(v7.supportsCommitment).toBe(true);
      const v7Commit = await v7.getKeyCommitment();
      expect(v7Commit.byteLength).toBe(cc.KEY_BYTES);
      v7.purge();

      const v8 = new MasterKeyKeyProvider(getRandom(cc.KEY_BYTES));
      v8.setCipherDataInfo({ ver: cc.VERSION8, alg: 'AES-GCM', ic: 0, slt, lp: 1, lpEnd: 1 });
      await v8.getCipherKey(false);
      expect(v8.supportsCommitment).toBe(false);
      const v8Commit = await v8.getKeyCommitment();
      expect(v8Commit.byteLength).toBe(cc.KEY_BYTES);
      v8.purge();
   });

   it('MasterKeyKeyProvider supportsCommitment requires cipherdatainfo', () => {
      const slt = getRandom(cc.SLT_BYTES);
      const ready = new MasterKeyKeyProvider(getRandom(cc.KEY_BYTES));
      ready.setCipherDataInfo({ ver: cc.CURRENT_VERSION, alg: 'AES-GCM', ic: 0, slt, lp: 1, lpEnd: 1 });
      expect(ready.supportsCommitment).toBe(false);
      ready.purge();

      const notReady = new MasterKeyKeyProvider(getRandom(cc.KEY_BYTES));
      expect(() => notReady.supportsCommitment).toThrow(/cipherDataInfo not set/);
      notReady.purge();
   });

   it('getKeyCommitment requires getCipherKey to have been called', async () => {
      const slt = getRandom(cc.SLT_BYTES);
      const pwdProvider = new PWDKeyProvider(getRandom(cc.USERCRED_BYTES), ['p', undefined]);
      pwdProvider.setCipherDataInfo({
         ver: cc.CURRENT_VERSION,
         alg: 'AES-GCM',
         ic: cc.ICOUNT_MIN,
         slt,
         lp: 1,
         lpEnd: 1,
      });
      await expect(pwdProvider.getKeyCommitment()).rejects.toThrow(/Cipher key must be generated/);
      pwdProvider.purge();

      const masterProvider = new MasterKeyKeyProvider(getRandom(cc.KEY_BYTES));
      masterProvider.setCipherDataInfo({ ver: cc.CURRENT_VERSION, alg: 'AES-GCM', ic: 0, slt, lp: 1, lpEnd: 1 });
      await expect(masterProvider.getKeyCommitment()).rejects.toThrow(/Cipher key must be generated/);
      masterProvider.purge();
   });

   it('derived keys change with cipher info (alg, lp, slt, extraKeyMaterial)', async () => {
      const userCred = getRandom(cc.USERCRED_BYTES);
      const master = getRandom(cc.KEY_BYTES);
      const extraKeyMaterial = getRandom(16);
      const baseSlt = getRandom(cc.SLT_BYTES);
      const otherSlt = getRandom(cc.SLT_BYTES);
      const baseIV = getRandom(32);

      const providers = [
         {
            ic: cc.ICOUNT_MIN,
            make: (extraAd?: Uint8Array<ArrayBuffer>) =>
               new PWDKeyProvider(userCred.slice(0), ['pwd-A', undefined], extraAd),
         },
         {
            ic: 0,
            make: (extraAd?: Uint8Array<ArrayBuffer>) => new MasterKeyKeyProvider(master.slice(0), extraAd),
         },
      ];

      async function derive(
         provider: (typeof providers)[number],
         alg: cc.CipherAlgs,
         lp: number,
         slt: Uint8Array<ArrayBuffer>,
         extraAd: Uint8Array<ArrayBuffer> | undefined,
      ): Promise<AllDerivedKeys> {
         const keyProvider = provider.make(extraAd);
         keyProvider.setCipherDataInfo({
            ver: cc.CURRENT_VERSION,
            alg,
            ic: provider.ic,
            slt: slt.slice(0),
            lp,
            lpEnd: 6,
         });
         return deriveAllKeys(keyProvider, baseIV, alg);
      }

      for (const provider of providers) {
         const baseline = await derive(provider, 'AES-GCM', 1, baseSlt, undefined);
         const sameInputs = await derive(provider, 'AES-GCM', 1, baseSlt, undefined);
         const diffAlg = await derive(provider, 'X20-PLY', 1, baseSlt, undefined);
         const diffLp = await derive(provider, 'AES-GCM', 2, baseSlt, undefined);
         const diffSlt = await derive(provider, 'AES-GCM', 1, otherSlt, undefined);
         const withExtraKeyMaterial = await derive(provider, 'AES-GCM', 1, baseSlt, extraKeyMaterial);

         for (const name of KEY_NAMES) {
            expect(isEqualArray(baseline[name], sameInputs[name])).toBe(true);
            expect(isEqualArray(baseline[name], diffAlg[name])).toBe(false);
            expect(isEqualArray(baseline[name], diffLp[name])).toBe(false);
            expect(isEqualArray(baseline[name], diffSlt[name])).toBe(false);
            expect(isEqualArray(baseline[name], withExtraKeyMaterial[name])).toBe(false);
         }
      }
   });

   it('PWDKeyProvider derived keys change with pwd and userCred', async () => {
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

   it('MasterKeyKeyProvider derived keys change with masterKey', async () => {
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

   it('getKeyCommitment is stable across other key derivations', async () => {
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
         keyProvider.setCipherDataInfo({
            ver: cc.CURRENT_VERSION,
            alg: 'AES-GCM',
            ic: provider.ic,
            slt,
            lp: 1,
            lpEnd: 1,
         });
         await keyProvider.getCipherKey(false);
         const first = await keyProvider.getKeyCommitment();

         // Interleave unrelated derivations that mutate internal state
         await keyProvider.getSigningKey();
         await keyProvider.getBlockCipherKey(1);
         await keyProvider.getBlockCipherKey(2);
         await keyProvider.getHintCipherKeyAndIV(getRandom(12));

         const second = await keyProvider.getKeyCommitment();
         expect(first.every((byte) => byte === 0)).toBe(false);
         expect(isEqualArray(first, second)).toBe(true);
         keyProvider.purge();
      }
   });

   it('purge zeroes the commitment key', async () => {
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
         keyProvider.setCipherDataInfo({
            ver: cc.CURRENT_VERSION,
            alg: 'AES-GCM',
            ic: provider.ic,
            slt,
            lp: 1,
            lpEnd: 1,
         });
         await keyProvider.getCipherKey(false);
         const commit = await keyProvider.getKeyCommitment();
         expect(commit.some((byte) => byte !== 0)).toBe(true);
         keyProvider.purge();
         // Same backing buffer; purge wipes it in place
         expect(commit.every((byte) => byte === 0)).toBe(true);
      }
   });
});
