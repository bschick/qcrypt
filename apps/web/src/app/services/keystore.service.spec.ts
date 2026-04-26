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

describe('KeystoreService', () => {
   let service: KeystoreService;

   beforeEach(() => {
      TestBed.configureTestingModule({});
      service = TestBed.inject(KeystoreService);
   });

   afterEach(async () => {
      await service.close();
   });

   it('should be created', () => {
      expect(service).toBeTruthy();
   });

   it('different slots should have different outputs', async () => {
      const slot1 = 'test-slot-1';
      const slot2 = 'test-slot-2';
      const salt = new Uint8Array(cc.SLT_BYTES);
      crypto.getRandomValues(salt);
      const userId = new Uint8Array(cc.USERID_BYTES);
      crypto.getRandomValues(userId);

      const upsertMaterial1 = await service.upsert(slot1, salt, userId);
      const getMaterial1 = await service.get(slot1, salt);
      expect(upsertMaterial1).toEqual(getMaterial1);

      const upsertMaterial2 = await service.upsert(slot2, salt, userId);
      const getMaterial2 = await service.get(slot2, salt);
      expect(upsertMaterial2).toEqual(getMaterial2);

      // the big test... should not be the same
      expect(upsertMaterial1).not.toEqual(upsertMaterial2);

      await service.delete(slot1);
      await service.delete(slot2);
   });

   it('different salts should have different outputs', async () => {
      const slot = 'test-slot-1';
      const salt1 = new Uint8Array(cc.SLT_BYTES);
      crypto.getRandomValues(salt1);
      const salt2 = new Uint8Array(cc.SLT_BYTES);
      crypto.getRandomValues(salt2);
      const userId = new Uint8Array(cc.USERID_BYTES);
      crypto.getRandomValues(userId);

      const upsertMaterial1 = await service.upsert(slot, salt1, userId);
      const upsertMaterial2 = await service.upsert(slot, salt2, userId);

      // the big test... should not be the same
      expect(upsertMaterial1).not.toEqual(upsertMaterial2);

      await service.delete(slot);
   });

   it('different userIds should have different outputs', async () => {
      const slot = 'test-slot-1';
      const salt = new Uint8Array(cc.SLT_BYTES);
      crypto.getRandomValues(salt);

      const userId1 = new Uint8Array(cc.USERID_BYTES);
      crypto.getRandomValues(userId1);
      const userId2 = new Uint8Array(cc.USERID_BYTES);
      crypto.getRandomValues(userId2);

      const upsertMaterial1 = await service.upsert(slot, salt, userId1);
      const upsertMaterial2 = await service.upsert(slot, salt, userId2);

      // the big test... should not be the same
      expect(upsertMaterial1).not.toEqual(upsertMaterial2);

      await service.delete(slot);
   });


   it('known input should produce known output', async () => {
      const slot = 'test-slot-1';
      const salt = new Uint8Array([17, 33, 6, 99, 168, 209, 111, 118, 13, 220, 186, 201, 115, 9, 99, 154]);
      const userId = new Uint8Array([79, 62, 118, 219, 222, 118, 141, 232, 170, 57, 34, 139, 163, 83, 123, 122]);
      const expectedMaterial = new Uint8Array([227, 53, 58, 164, 166, 52, 44, 247, 252, 23, 66, 169, 21, 69, 244, 85, 63, 209, 133, 38, 63, 235, 40, 89, 92, 25, 166, 146, 97, 190, 1, 60]);

      const upsertMaterial = await service.upsert(slot, salt, userId);
      expect(upsertMaterial).toEqual(expectedMaterial);

      const getMaterial = await service.get(slot, salt);
      expect(getMaterial).toEqual(expectedMaterial);

      await service.delete(slot);
   });

   it('upsert and upsert with same inputs should match', async () => {
      const slot = 'test-slot-2';
      const salt = new Uint8Array(cc.SLT_BYTES);
      crypto.getRandomValues(salt);
      const userId = new Uint8Array(cc.USERID_BYTES);
      crypto.getRandomValues(userId);

      const upsertMaterial1 = await service.upsert(slot, salt, userId);
      const upsertMaterial2 = await service.upsert(slot, salt, userId);
      expect(upsertMaterial1).toEqual(upsertMaterial2);

      await service.delete(slot);
   });

   it('upsert and get with same inputs should match', async () => {
      const slot = 'test-slot-2';
      const salt = new Uint8Array(cc.SLT_BYTES);
      crypto.getRandomValues(salt);
      const userId = new Uint8Array(cc.USERID_BYTES);
      crypto.getRandomValues(userId);

      const upsertMaterial = await service.upsert(slot, salt, userId);
      expect(upsertMaterial).toBeInstanceOf(Uint8Array);

      const getMaterial = await service.get(slot, salt);
      expect(getMaterial).toBeInstanceOf(Uint8Array);
      expect(upsertMaterial).toEqual(getMaterial);

      await service.delete(slot);
   });

   it('should throw if slot is too short', async () => {
      const slot = '123'; // MIN_SLOT_LEN is 4
      const salt = new Uint8Array(cc.SLT_BYTES);
      const userId = new Uint8Array(cc.USERID_BYTES);

      await expect(service.upsert(slot, salt, userId)).rejects.toThrow(/Slot must be at least/);
   });

   it('should throw if salt is incorrect length', async () => {
      const slot = 'test-slot-2';
      const invalidSalt = new Uint8Array(cc.SLT_BYTES - 1);
      const userId = new Uint8Array(cc.USERID_BYTES);

      await expect(service.upsert(slot, invalidSalt, userId)).rejects.toThrow(/Salt is not \d+ bytes/);
   });

   it('should throw if userId is incorrect length', async () => {
      const slot = 'test-slot-3';
      const salt = new Uint8Array(cc.SLT_BYTES);
      const invalidUserId = new Uint8Array(cc.USERID_BYTES + 1);

      await expect(service.upsert(slot, salt, invalidUserId)).rejects.toThrow(/User id is not \d+ bytes/);
   });

   it('should throw if salt is incorrect length', async () => {
      const slot = 'test-slot-4';
      const salt = new Uint8Array(cc.SLT_BYTES);
      const userId = new Uint8Array(cc.USERID_BYTES);

      await service.upsert(slot, salt, userId);
      const invalidSalt = new Uint8Array(cc.SLT_BYTES + 1);
      await expect(service.get(slot, invalidSalt)).rejects.toThrow(/Salt is not \d+ bytes/);

      await service.delete(slot);
   });

   it('get should throw if slot does not exist', async () => {
      const slot = 'non-existent-slot';
      const salt = new Uint8Array(cc.SLT_BYTES);

      await expect(service.get(slot, salt)).rejects.toThrow(/No key found for slot/);
   });

   it('delete should not throw if slot does not exist', async () => {
      const slot = 'non-existent-slot';
      await expect(service.delete(slot)).resolves.toBeUndefined();
   });

   it('master key should not be extractable', async () => {
      const slot = 'session-key';
      const salt = new Uint8Array(cc.SLT_BYTES);
      crypto.getRandomValues(salt);
      const userId = new Uint8Array(cc.USERID_BYTES);
      crypto.getRandomValues(userId);
      await service.upsert(slot, salt, userId);

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

});