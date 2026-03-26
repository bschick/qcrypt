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
import sodium from 'libsodium-wrappers';
import * as cc from './cipher.consts';
import { CipherDataInfo } from './ciphers-current';
import { ensureArrayBuffer, getArrayBuffer, getRandom48 } from './utils';

export type PWDProvider = (
   cdInfo: CipherDataInfo,
   encrypting: boolean
) => Promise<[string, string | undefined]>;

// export interface KeyProvider {
//    getCipherKey(alg: string, ic: number, pwd: string,
//       userCred: Uint8Array,
//       slt: Uint8Array
//    ): Promise<Uint8Array<ArrayBuffer>>): Promise<Uint8Array>;
//    getNextCipherKey(): Promise<Uint8Array>;
//    getSigningKey(slt: Uint8Array, ver: number): Uint8Array<ArrayBuffer>;
//    getHintKeyAndIV(iv: Uint8Array, slt: Uint8Array, ver: number): [Uint8Array<ArrayBuffer>, Uint8Array<ArrayBuffer>];
// };

export class PWDKeyProvider { //implements KeyProvider {

   // private _slt: Uint8Array;
   private _ek: Uint8Array<ArrayBuffer> | undefined = undefined;

   constructor(
      private _pwdProvider: PWDProvider,
      private _userCred: Uint8Array<ArrayBuffer>
   ) {
      // this._slt = sodium.randombytes_buf(cc.SLT_BYTES);
      if (this._userCred.byteLength != cc.USERCRED_BYTES) {
         throw new Error("Invalid userCred length of: " + this._userCred.byteLength);
      }
   }

   public purge(): void {
      this._ek = undefined;
      // Don't overwrite because this is only a reference
      this._userCred = new Uint8Array(0);

      // overwrite to clear
      if (this._ek) {
         crypto.getRandomValues(this._ek);
         this._ek = undefined;
      }
      // if (this._sk) {
      //    crypto.getRandomValues(this._sk);
      //    this._sk = undefined;
      // }
   }

   // get slt(): Uint8Array {
   //    return this._slt;
   // }

   // Exported for testing, normal callers should not need this
   async public genCipherKey(
      cdInfo: CipherDataInfo,
      encrypting: boolean
   ): Promise<Uint8Array<ArrayBuffer>> {

      const { ic, slt } = cdInfo;

      if (ic < cc.ICOUNT_MIN || ic > cc.ICOUNT_MAX) {
         throw new Error('Invalid ic of: ' + ic);
      }
      if (slt.byteLength != cc.SLT_BYTES) {
         throw new Error("Invalid slt length of: " + slt.byteLength);
      }

      const [pwd, hint] = await this._pwdProvider(
         cdInfo,
         encrypting
      );
      if (hint && hint.length > cc.HINT_MAX_LEN) {
         throw new Error('Hint length exceeds: ' + cc.HINT_MAX_LEN);
      }
      if (!pwd) {
         throw new Error('Missing password');
      }

      const pwdBytes = new TextEncoder().encode(pwd);
      const rawMaterial = new Uint8Array(pwdBytes.byteLength + this._userCred.byteLength)
      rawMaterial.set(pwdBytes);
      rawMaterial.set(this._userCred, pwdBytes.byteLength);

      const ekMaterial = await crypto.subtle.importKey(
         'raw',
         rawMaterial,
         'PBKDF2',
         false,
         ['deriveBits', 'deriveKey']
      );

      // overwrite to clear userCred and pwd
      crypto.getRandomValues(rawMaterial);
      crypto.getRandomValues(pwdBytes);

      // A bit of a hack, but subtle doesn't support other algorithms... so lie. This
      // is safe because the key is exported as bits and used in libsodium when not
      // AES-GCM. TODO: If more non-browser cipher are added, make this more generic.
      const useAlg = 'AES-GCM';

      let subtleKey: CryptoKey | undefined = await crypto.subtle.deriveKey(
         {
            name: 'PBKDF2',
            salt: getArrayBuffer(slt),
            iterations: ic,
            hash: 'SHA-512',
         },
         ekMaterial,
         { name: useAlg, length: 256 },
         true,
         ['encrypt', 'decrypt']
      );

      this._ek = new Uint8Array(await crypto.subtle.exportKey("raw", subtleKey));
      subtleKey = undefined;
      return this._ek;
   }


   private static _genDerivedKey(
      master: Uint8Array,
      slt: Uint8Array,
      purpose: string,
      instance: number,
      ver: number
   ): Uint8Array<ArrayBuffer> {

      let mixedKey: Uint8Array;

      // VERSION7 adds a salt to key derivations
      if (ver === cc.VERSION7) {
         if (purpose.length != 8) {
            throw new Error('Invalid purpose length: ' + purpose.length);
         }

         // because crypto_kdf_derive_from_key does not take a salt, we first merge salt and
         // master into a single hash.
         mixedKey = sodium.crypto_generichash(cc.KEY_BYTES, slt, master);
      } else {
         mixedKey = master;
      }

      return ensureArrayBuffer(sodium.crypto_kdf_derive_from_key(
         master.byteLength,
         instance,
         purpose.slice(0, 8),
         mixedKey
      ));
   }

}