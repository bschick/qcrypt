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
      credId: Uint8Array<ArrayBuffer> | string
   ): Promise<Uint8Array<ArrayBuffer>> {
      const credIdBytes = (typeof credId === 'string') ? base64ToBytes(credId) : credId;

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
      return this._deriveKey(masterKey, slot, credIdBytes);
   }

   // Create and replace the key in `slot`
   async create(
      slot: string,
      credId: Uint8Array<ArrayBuffer> | string
   ): Promise<Uint8Array<ArrayBuffer>> {
      const credIdBytes = (typeof credId === 'string') ? base64ToBytes(credId) : credId;

      const masterKey = await this._newMasterKey(slot);

      // Caller should overwrite the returned key immediately afer use
      return this._deriveKey(masterKey, slot, credIdBytes);
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

   private async _deriveKey(
      masterKey: CryptoKey,
      purpose: string,
      credId: Uint8Array<ArrayBuffer>
   ): Promise<Uint8Array<ArrayBuffer>> {

      if (purpose.length < MIN_SLOT_LEN) {
         throw new Error('Slot must be at least ' + MIN_SLOT_LEN + ' characters');
      }
      if (credId.byteLength < cc.CREDID_MIN_BYTES) {
         throw new Error('Credential id is < ' + cc.CREDID_MIN_BYTES + ' bytes');
      }

      const purposeBytes = new TextEncoder().encode(purpose);
      const data = new Uint8Array(purposeBytes.byteLength + credId.byteLength);
      data.set(purposeBytes);
      data.set(credId, purposeBytes.byteLength);

      const derivedBytes = await crypto.subtle.sign(
         "HMAC",
         masterKey,
         data
      );
      if (derivedBytes.byteLength !== cc.KEY_BYTES * 2) {
         throw new Error('Invalid derived key length: ' + derivedBytes.byteLength);
      }

      return new Uint8Array(derivedBytes.slice(cc.KEY_BYTES));
   }

   private async _newMasterKey(slot: string): Promise<CryptoKey> {

      if (slot.length < MIN_SLOT_LEN) {
         throw new Error('Slot must be at least ' + MIN_SLOT_LEN + ' characters');
      }

      // SubtleCrypto is lame... It will not let you generate CryptoKey for
      // the purpose of deriving further symetric keys. So we generate an HMAC
      // key and bascially rebuild a KDF from that.
      const masterKey = await crypto.subtle.generateKey(
         {
            name: "HMAC",
            hash: { name: "SHA-512" },
         },
         false,
         ["sign"]
      );

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
