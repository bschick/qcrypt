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
import { Injectable } from '@angular/core';
import * as cc from '@qcrypt/crypto/consts';
import { base64ToBytes } from '@qcrypt/crypto';

const DB_VERSION = 1;
const MIN_SLOT_LEN = 4;

@Injectable({
   providedIn: 'root',
})
export class KeystoreService {
   private _dbPromise?: Promise<IDBDatabase>;
   private _dbName: string = 'quick-crypt';
   private _storeName: string = 'keys';

   // Uses an existing key. Returned key material should
   // be used immediately and then overwritten and discarded
   async get(
      slot: string,
      salt: Uint8Array<ArrayBuffer> | string
   ): Promise<Uint8Array<ArrayBuffer>> {
      const saltBytes = typeof salt === 'string' ? base64ToBytes(salt) : salt;

      const db = await this._db();
      const masterKey = await new Promise<CryptoKey | undefined>((resolve, reject) => {
         const req = db.transaction(this._storeName, 'readonly').objectStore(this._storeName).get(slot);
         req.onsuccess = () => resolve(req.result as CryptoKey | undefined);
         req.onerror = () => reject(req.error);
      });

      if (!masterKey) {
         throw new Error('No key found for slot: ' + slot);
      }

      // Caller should overwrite the returned key immediately afer use
      return this._deriveKeyMaterial(masterKey, saltBytes);
   }

   // Either creates or replaces an existing key. Returned key material should
   // be used immediately and then overwritten and discarded
   async upsert(
      slot: string,
      salt: Uint8Array<ArrayBuffer> | string,
      userId: Uint8Array<ArrayBuffer> | string
   ): Promise<Uint8Array<ArrayBuffer>> {
      const saltBytes = typeof salt === 'string' ? base64ToBytes(salt) : salt;
      const userIdBytes = typeof userId === 'string' ? base64ToBytes(userId) : userId;

      const masterKey = await this._newMasterKey(slot, userIdBytes, saltBytes);

      // Caller should overwrite the returned key immediately afer use
      return this._deriveKeyMaterial(masterKey, saltBytes);
   }

   async delete(slot: string): Promise<void> {
      const db = await this._db();
      return new Promise<void>((resolve, reject) => {
         const tx = db.transaction(this._storeName, 'readwrite');
         tx.objectStore(this._storeName).delete(slot);
         tx.oncomplete = () => resolve();
         tx.onerror = () => reject(tx.error);
      });
   }

   // Destroys the entire database, wiping all keys and schema
   async flush(): Promise<void> {
      if (this._dbPromise) {
         const p = this._dbPromise;
         this._dbPromise = undefined;
         try {
            (await p).close();
         } catch (err) {
            console.error(err);
         }
      }

      return new Promise<void>((resolve, reject) => {
         const req = indexedDB.deleteDatabase(this._dbName);
         req.onsuccess = () => resolve();
         req.onerror = () => reject(req.error);
         req.onblocked = () => {
             console.warn("Database deletion blocked by another open connection");
             // Resolve anyway so the caller isn't permanently blocked.
             // The browser will complete the deletion when other connections close.
             resolve();
         };
      });
   }

   private async _deriveKeyMaterial(
      masterKey: CryptoKey,
      salt: Uint8Array<ArrayBuffer>
   ): Promise<Uint8Array<ArrayBuffer>> {

      if (salt.length !== cc.SLT_BYTES) {
         throw new Error('Salt is not ' + cc.SLT_BYTES + ' bytes');
      }

      const purpose = new TextEncoder().encode('qq-derived');
      const derivedBits = await crypto.subtle.deriveBits(
         {
            name: 'HKDF',
            hash: 'SHA-512',
            salt: salt,
            info: purpose,
         },
         masterKey,
         256
      );

      return new Uint8Array(derivedBits);
   }

   private async _newMasterKey(
      slot: string,
      userId: Uint8Array<ArrayBuffer>,
      salt: Uint8Array<ArrayBuffer>
   ): Promise<CryptoKey> {

      if (slot.length < MIN_SLOT_LEN) {
         throw new Error('Slot must be at least ' + MIN_SLOT_LEN + ' characters');
      }
      if (userId.byteLength !== cc.USERID_BYTES) {
         throw new Error('User id is not ' + cc.USERID_BYTES + ' bytes');
      }
      if (salt.byteLength !== cc.SLT_BYTES) {
         throw new Error('Salt is not ' + cc.SLT_BYTES + ' bytes');
      }

      const baseKey = await window.crypto.subtle.importKey(
         'raw',
         userId,
         'HKDF',
         false,
         ['deriveBits'],
      );

      // SubtleCrypto is so lame. It will not let you create a derived CryptoKey
      // for the purpose of deriving further keys. Instead you are forced to
      // momentarily expose the bits, then reimport and wipe.
      const purpose = new TextEncoder().encode(slot + 'qq-master');
      const masterBits = await crypto.subtle.deriveBits(
         {
            name: 'HKDF',
            hash: 'SHA-512',
            salt: salt,
            info: purpose,
         },
         baseKey,
         256
      );

      // Derive a new CryptoKey from the raw bits. Critical that it is not
      // exportable so that it isn't accessible to JS when at rest
      const masterKey = await crypto.subtle.importKey(
         'raw',
         masterBits,
         'HKDF',
         false,
         ['deriveBits', 'deriveKey'],
      );

      // Wipe the intermediate bits in place.
      crypto.getRandomValues(new Uint8Array(masterBits));

      const db = await this._db();
      await new Promise<void>((resolve, reject) => {
         const tx = db.transaction(this._storeName, 'readwrite');
         tx.objectStore(this._storeName).put(masterKey, slot);
         tx.oncomplete = () => resolve();
         tx.onerror = () => reject(tx.error);
      });

      return masterKey;
   }

   private async _db(): Promise<IDBDatabase> {
      if (!this._dbPromise) {
         this._dbPromise = new Promise((resolve, reject) => {
            const req = indexedDB.open(this._dbName, DB_VERSION);
            req.onupgradeneeded = () => {
               req.result.createObjectStore(this._storeName);
            };
            req.onsuccess = () => resolve(req.result);
            req.onerror = () => reject(req.error);
         });
      }
      return this._dbPromise;
   }
}
