/* MIT License

Copyright (c) 2026 Brad Schick

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
import { KeystoreService } from './keystore.service';
import * as cc from '@qcrypt/crypto/consts';
import { bytesToBase64, cryptoReady, getRandom } from '@qcrypt/crypto';

describe('KeystoreService', () => {
   let service: KeystoreService;

   beforeEach(async () => {
      await cryptoReady();
      TestBed.configureTestingModule({});
      service = TestBed.inject(KeystoreService);
   });

   afterEach(async () => {
      await service.flush();
   });

   it('should be created', () => {
      expect(service).toBeTruthy();
   });

   it('same inputs should have different outputs', async () => {
      const slot = 'test-slot-1';
      const pkId = getRandom(cc.PKID_MIN_BYTES);

      const createMaterial1 = await service.create(slot, pkId);
      const createMaterial2 = await service.create(slot, pkId);
      expect(createMaterial1.derivedKey).not.toEqual(createMaterial2.derivedKey);

      await service.delete(slot);
   });

   it('different slots should have different outputs', async () => {
      const slot1 = 'test-slot-1';
      const slot2 = 'test-slot-2';
      const pkId = getRandom(cc.PKID_MIN_BYTES);

      const createMaterial1 = await service.create(slot1, pkId);
      const getMaterial1 = await service.get(slot1, pkId);
      expect(createMaterial1).toEqual(getMaterial1);

      const createMaterial2 = await service.create(slot2, pkId);
      const getMaterial2 = await service.get(slot2, pkId);
      expect(createMaterial2).toEqual(getMaterial2);

      // the key test...
      expect(createMaterial1.derivedKey).not.toEqual(createMaterial2.derivedKey);

      await service.delete(slot1);
      await service.delete(slot2);
   });

   it('different pkIds should have different outputs', async () => {
      const slot = 'test-slot-1';

      const pkId1 = getRandom(cc.PKID_MIN_BYTES);
      const pkId2 = getRandom(cc.PKID_MIN_BYTES);

      const createMaterial1 = await service.create(slot, pkId1);
      const createMaterial2 = await service.create(slot, pkId2);
      expect(createMaterial1.derivedKey).not.toEqual(createMaterial2.derivedKey);

      await service.delete(slot);
   });

   it('create and get with same inputs should match', async () => {
      const slot = 'test-slot-2';
      const pkId = getRandom(cc.PKID_MIN_BYTES);

      const createMaterial = await service.create(slot, pkId);
      expect(createMaterial.derivedKey).toBeInstanceOf(Uint8Array);
      expect(createMaterial.derivedKey.byteLength).toEqual(cc.KEY_BYTES);

      const getMaterial = await service.get(slot, pkId);
      expect(getMaterial.derivedKey).toBeInstanceOf(Uint8Array);
      expect(getMaterial.derivedKey.byteLength).toEqual(cc.KEY_BYTES);

      expect(createMaterial).toEqual(getMaterial);
      await service.delete(slot);
   });

   it('create should incement version counter', async () => {
      const slot = 'test-version-slot';
      const pkId = getRandom(cc.PKID_MIN_BYTES);

      const first = await service.create(slot, pkId);
      expect(first.version).toBe(1);

      const second = await service.create(slot, pkId);
      expect(second.version).toBe(2);

      const third = await service.create(slot, pkId);
      expect(third.version).toBe(3);

      const got = await service.get(slot, pkId);
      expect(got.version).toBe(3);

      await service.delete(slot);
   });

   it('delete restarts version counter', async () => {
      const slot = 'test-delete-version-slot';
      const pkId = getRandom(cc.PKID_MIN_BYTES);

      await service.create(slot, pkId);
      const second = await service.create(slot, pkId);
      expect(second.version).toBe(2);

      await service.delete(slot);

      const afterDelete = await service.create(slot, pkId);
      expect(afterDelete.version).toBe(1);

      await service.delete(slot);
   });

   it('should throw if slot is too short', async () => {
      const slot = '123'; // MIN_SLOT_LEN is 4
      const pkId = new Uint8Array(cc.PKID_MIN_BYTES);
      await expect(service.create(slot, pkId)).rejects.toThrow(/Slot must be at least/);
   });

   it('should throw if pkId is too short', async () => {
      const slot = 'test-slot-3';
      const invalidPKId = getRandom(cc.PKID_MIN_BYTES - 1);
      const invalidPKIdStr = bytesToBase64(invalidPKId);

      await expect(service.create(slot, invalidPKId)).rejects.toThrow(/Credential id is < 16 bytes/);
      await expect(service.create(slot, invalidPKIdStr)).rejects.toThrow(/Credential id is < 16 bytes/);
   });

   it('get should throw if slot does not exist', async () => {
      const slot = 'non-existent-slot';
      const pkId = new Uint8Array(cc.PKID_MIN_BYTES);
      await expect(service.get(slot, pkId)).rejects.toThrow(/No key found for slot/);
   });

   it('delete should not throw if slot does not exist', async () => {
      const slot = 'non-existent-slot';
      await expect(service.delete(slot)).resolves.toBeUndefined();
   });

   it('master key should not be extractable', async () => {
      const slot = 'session-key';
      const pkId = getRandom(cc.PKID_MIN_BYTES);
      await service.create(slot, pkId);

      // Bypass private member checks by casting to any
      const srvAny = service as any;
      const db: IDBDatabase = await srvAny._db();
      const entry = await new Promise<{ masterKey: CryptoKey, version: number }>((resolve, reject) => {
         const req = db.transaction(srvAny._storeName, 'readonly').objectStore(srvAny._storeName).get(slot);
         req.onsuccess = () => resolve(req.result);
         req.onerror = () => reject(req.error);
      });

      expect(entry).toBeDefined();
      expect(entry.masterKey.extractable).toBe(false);
      await expect(crypto.subtle.exportKey('raw', entry.masterKey)).rejects.toThrow(/extractable/i);
   });

   it('flush should destroy database and prevent lookups', async () => {
      const slot = 'test-flush-slot';
      const pkId = getRandom(cc.PKID_MIN_BYTES);

      await service.create(slot, pkId);
      const beforeFlush = await service.get(slot, pkId);
      expect(beforeFlush.derivedKey).toBeDefined();

      await service.flush();
      await expect(service.get(slot, pkId)).rejects.toThrow(/No key found for slot/);
   });

   it('supports base64 string for pkId', async () => {
      const slot = 'test-base64-slot';
      const pkIdBytes = getRandom(cc.PKID_MIN_BYTES);
      const pkIdStr = bytesToBase64(pkIdBytes);

      const createMaterial = await service.create(slot, pkIdStr);
      expect(createMaterial.derivedKey).toBeInstanceOf(Uint8Array);

      const getMaterial = await service.get(slot, pkIdStr);
      expect(getMaterial.derivedKey).toBeInstanceOf(Uint8Array);
      expect(createMaterial).toEqual(getMaterial);
   });

});
