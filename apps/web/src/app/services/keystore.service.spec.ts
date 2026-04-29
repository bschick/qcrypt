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
import { bytesToBase64 } from '@qcrypt/crypto';

describe('KeystoreService', () => {
   let service: KeystoreService;

   beforeEach(() => {
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
      const credId = new Uint8Array(cc.CREDID_MIN_BYTES);
      crypto.getRandomValues(credId);

      const createMaterial1 = await service.create(slot, credId);
      const createMaterial2 = await service.create(slot, credId);
      expect(createMaterial1).not.toEqual(createMaterial2);

      await service.delete(slot);
   });

   it('different slots should have different outputs', async () => {
      const slot1 = 'test-slot-1';
      const slot2 = 'test-slot-2';
      const credId = new Uint8Array(cc.CREDID_MIN_BYTES);
      crypto.getRandomValues(credId);

      const createMaterial1 = await service.create(slot1, credId);
      const getMaterial1 = await service.get(slot1, credId);
      expect(createMaterial1).toEqual(getMaterial1);

      const createMaterial2 = await service.create(slot2, credId);
      const getMaterial2 = await service.get(slot2, credId);
      expect(createMaterial2).toEqual(getMaterial2);

      // the key test...
      expect(createMaterial1).not.toEqual(createMaterial2);

      await service.delete(slot1);
      await service.delete(slot2);
   });

   it('different credIds should have different outputs', async () => {
      const slot = 'test-slot-1';

      const credId1 = new Uint8Array(cc.CREDID_MIN_BYTES);
      crypto.getRandomValues(credId1);
      const credId2 = new Uint8Array(cc.CREDID_MIN_BYTES);
      crypto.getRandomValues(credId2);

      const createMaterial1 = await service.create(slot, credId1);
      const createMaterial2 = await service.create(slot, credId2);
      expect(createMaterial1).not.toEqual(createMaterial2);

      await service.delete(slot);
   });

   it('create and get with same inputs should match', async () => {
      const slot = 'test-slot-2';
      const credId = new Uint8Array(cc.CREDID_MIN_BYTES);
      crypto.getRandomValues(credId);

      const createMaterial = await service.create(slot, credId);
      expect(createMaterial).toBeInstanceOf(Uint8Array);
      expect(createMaterial.byteLength).toEqual(cc.KEY_BYTES);

      const getMaterial = await service.get(slot, credId);
      expect(getMaterial).toBeInstanceOf(Uint8Array);
      expect(getMaterial.byteLength).toEqual(cc.KEY_BYTES);

      expect(createMaterial).toEqual(getMaterial);
      await service.delete(slot);
   });

   it('should throw if slot is too short', async () => {
      const slot = '123'; // MIN_SLOT_LEN is 4
      const credId = new Uint8Array(cc.CREDID_MIN_BYTES);
      await expect(service.create(slot, credId)).rejects.toThrow(/Slot must be at least/);
   });

   it('should throw if credId is too short', async () => {
      const slot = 'test-slot-3';
      const invalidCredId = new Uint8Array(cc.CREDID_MIN_BYTES - 1);
      crypto.getRandomValues(invalidCredId);
      const invalidCredIdStr = bytesToBase64(invalidCredId);

      await expect(service.create(slot, invalidCredId)).rejects.toThrow(/Credential id is < 16 bytes/);
      await expect(service.create(slot, invalidCredIdStr)).rejects.toThrow(/Credential id is < 16 bytes/);
   });

   it('get should throw if slot does not exist', async () => {
      const slot = 'non-existent-slot';
      const credId = new Uint8Array(cc.CREDID_MIN_BYTES);
      await expect(service.get(slot, credId)).rejects.toThrow(/No key found for slot/);
   });

   it('delete should not throw if slot does not exist', async () => {
      const slot = 'non-existent-slot';
      await expect(service.delete(slot)).resolves.toBeUndefined();
   });

   it('master key should not be extractable', async () => {
      const slot = 'session-key';
      const credId = new Uint8Array(cc.CREDID_MIN_BYTES);
      crypto.getRandomValues(credId);
      await service.create(slot, credId);

      // Bypass private member checks by casting to any
      const srvAny = service as any;
      const db: IDBDatabase = await srvAny._db();
      const masterKey = await new Promise<CryptoKey>((resolve, reject) => {
         const req = db.transaction(srvAny._storeName, 'readonly').objectStore(srvAny._storeName).get(slot);
         req.onsuccess = () => resolve(req.result as CryptoKey);
         req.onerror = () => reject(req.error);
      });

      expect(masterKey).toBeDefined();
      expect(masterKey.extractable).toBe(false);
      await expect(crypto.subtle.exportKey('raw', masterKey)).rejects.toThrow();
   });

   it('flush should destroy database and prevent lookups', async () => {
      const slot = 'test-flush-slot';
      const credId = new Uint8Array(cc.CREDID_MIN_BYTES);
      crypto.getRandomValues(credId);

      await service.create(slot, credId);
      const beforeFlush = await service.get(slot, credId);
      expect(beforeFlush).toBeDefined();

      await service.flush();
      await expect(service.get(slot, credId)).rejects.toThrow(/No key found for slot/);
   });

   it('supports base64 string for credId', async () => {
      const slot = 'test-base64-slot';
      const credIdBytes = new Uint8Array(cc.CREDID_MIN_BYTES);
      crypto.getRandomValues(credIdBytes);
      const credIdStr = bytesToBase64(credIdBytes);

      const createMaterial = await service.create(slot, credIdStr);
      expect(createMaterial).toBeInstanceOf(Uint8Array);

      const getMaterial = await service.get(slot, credIdStr);
      expect(getMaterial).toBeInstanceOf(Uint8Array);
      expect(createMaterial).toEqual(getMaterial);
   });

});