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
import { CipherDataInfo, Ciphers } from './ciphers-current';
import { ensureArrayBuffer, getRandom, numToBytes } from './utils';

// V7 Contexts must be 8 bytes
const KDF_CTX_SIGNING_V6 = "cipherdata signing key";
const KDF_CTX_SIGNING_V7 = "Sign_Key";
const KDF_CTX_HINT_V6 = "hint encryption key";
const KDF_CTX_HINT_V7 = "Hint_Key";
const KDF_CTX_BLOCK_V6 = "block encryption key";
const KDF_CTX_BLOCK_V7 = "Blck_Key";


export type PWDProvider =
   [string, string | undefined] |
   ((
      cdInfo: CipherDataInfo,
      encrypting: boolean
   ) => Promise<[string, string | undefined]>);

export interface KeyProvider {
   // Purge also clear returned references to key, so all usage should be finished when called
   purge(): void;
   // Note that KeyProvider implementation takes ownership of passed in cdInfo
   setCipherDataInfo(cdInfo: CipherDataInfo): void;
   getCipherDataInfo(): CipherDataInfo;
   getCipherKey(encrypting: boolean): Promise<Uint8Array<ArrayBuffer>>;
   getBlockCipherKey(blockNum: number): Promise<Uint8Array<ArrayBuffer>>;
   getSigningKey(): Promise<Uint8Array<ArrayBuffer>>;
   getHintCipherKeyAndIV(baseIV: Uint8Array<ArrayBuffer>): Promise<[Uint8Array<ArrayBuffer>, Uint8Array<ArrayBuffer>]>;
};

// IMPORTANT: This class caches calculated keys, and users must:
// 1) call setCipherDataInfo() first
// 2) call purge() when immediate need for keys is complete
// 3) not overwrite or hold references to returned keys
export abstract class BasePWDKeyProvider implements KeyProvider {

   // owned values
   protected _ek: Uint8Array<ArrayBuffer> | undefined = undefined;
   protected _sk: Uint8Array<ArrayBuffer> | undefined = undefined;
   protected _hk: Uint8Array<ArrayBuffer> | undefined = undefined;
   protected _hIV: Uint8Array<ArrayBuffer> | undefined = undefined;
   protected _bks: Uint8Array<ArrayBuffer>[] = [];
   protected _hint: string | undefined = undefined;
   protected _cdInfo: CipherDataInfo | undefined = undefined;
   protected _userCred: Uint8Array<ArrayBuffer>;

   // _pwdProvider may be undefined when only hint or signing key is required
   constructor(
      userCred: Uint8Array,
      protected _pwdProvider: PWDProvider | undefined = undefined,
   ) {
      this._userCred = ensureArrayBuffer(userCred);
      if (this._userCred.byteLength != cc.USERCRED_BYTES) {
         throw new Error("Invalid userCred length of: " + this._userCred.byteLength);
      }
   }

   public setCipherDataInfo(cdInfo: CipherDataInfo) {
      if (!Ciphers.validateAlg(cdInfo.alg)) {
         throw new Error('Invalid alg type of: ' + cdInfo.alg);
      }
      if (cdInfo.ic < cc.ICOUNT_MIN || cdInfo.ic > cc.ICOUNT_MAX) {
         throw new Error('Invalid ic of: ' + cdInfo.ic);
      }
      if (cdInfo.lpEnd < 1 || cdInfo.lpEnd > cc.LP_MAX) {
         throw new Error('Invalid lpEnd: ' + cdInfo.lpEnd);
      }
      if (cdInfo.lp < 1 || cdInfo.lp > cdInfo.lpEnd) {
         throw new Error('Invalid lp: ' + cdInfo.lp);
      }
      if (cdInfo.slt.byteLength != cc.SLT_BYTES) {
         throw new Error("Invalid salt length of: " + cdInfo.slt.byteLength);
      }
      this._cdInfo = {...cdInfo};
   }

   public getCipherDataInfo(): CipherDataInfo {
      if (!this._cdInfo) {
         throw new Error('CipherDataInfo not set');
      }
      return this._cdInfo;
   }


   public purge(): void {
      // Don't overwrite because we only hold a reference
      this._userCred = new Uint8Array(0);

      // overwrite owned values to clear
      if (this._ek) {
         crypto.getRandomValues(this._ek);
         this._ek = undefined;
      }
      if (this._sk) {
         crypto.getRandomValues(this._sk);
         this._sk = undefined;
      }
      if (this._hk) {
         crypto.getRandomValues(this._hk);
         this._hk = undefined;
      }
      if (this._hIV) {
         crypto.getRandomValues(this._hIV);
         this._hIV = undefined;
      }
      if (this._cdInfo) {
         this._cdInfo.hint = undefined;
         this._cdInfo = undefined;
      }
      for (const bk of this._bks) {
         if (bk) {
            crypto.getRandomValues(bk);
         }
      }
      this._bks = [];
      if (this._hint) {
         this._hint = undefined;
      }
   }

   public async getCipherKey(
      encrypting: boolean
   ): Promise<Uint8Array<ArrayBuffer>> {
      if (!this._ek) {
         this._ek = await this._genCipherKey(encrypting);
         if (!this._ek) {
            throw new Error('Failed to generate cipher key');
         }
      }
      return this._ek;
   }

   public async getBlockCipherKey(blockNum: number): Promise<Uint8Array<ArrayBuffer>> {
      // expect blockNum >= 1
      if (blockNum < 1) {
         throw new Error('Invalid block number: ' + blockNum);
      }
      // cache block keys primarily to overwrite at purge
      if (!this._bks[blockNum - 1]) {
         this._bks[blockNum - 1] = await this._genBlockCipherKey(blockNum);
         if (!this._bks[blockNum - 1]) {
            throw new Error('Failed to generate block cipher key');
         }
      }
      return this._bks[blockNum - 1];
   }

   public async getSigningKey(): Promise<Uint8Array<ArrayBuffer>> {
      if (!this._sk) {
         this._sk = await this._genSigningKey();
         if (!this._sk) {
            throw new Error('Failed to generate signing key');
         }
      }
      return this._sk;
   }

   public async getHintCipherKeyAndIV(baseIV: Uint8Array<ArrayBuffer>): Promise<[Uint8Array<ArrayBuffer>, Uint8Array<ArrayBuffer>]> {
      // cache hint key primarily to overwrite at purge
      if (!this._hk) {
         [this._hk, this._hIV] = await this._genHintCipherKeyAndIV(baseIV);
         if (!this._hk || !this._hIV) {
            throw new Error('Failed to generate hint key and IV');
         }
      }
      return [this._hk, this._hIV!];
   }

   protected abstract _genCipherKey(encrypting: boolean): Promise<Uint8Array<ArrayBuffer>>;
   protected abstract _genSigningKey(): Promise<Uint8Array<ArrayBuffer>>;
   protected abstract _genBlockCipherKey(blockNum: number): Promise<Uint8Array<ArrayBuffer>>;
   protected abstract _genHintCipherKeyAndIV(
      baseIV: Uint8Array<ArrayBuffer>
   ): Promise<[Uint8Array<ArrayBuffer>, Uint8Array<ArrayBuffer>]>;
};


export class PWDKeyProvider extends BasePWDKeyProvider {

   // _pwdProvider may be undefined when only hint or signing key is required
   constructor(
      userCred: Uint8Array,
      pwdProvider: PWDProvider | undefined = undefined,
   ) {
      super(userCred, pwdProvider);
   }

   protected override async _genCipherKey(
      encrypting: boolean
   ): Promise<Uint8Array<ArrayBuffer>> {
      if (!this._cdInfo) {
         throw new Error('CipherDataInfo not set');
      }
      if (!this._pwdProvider) {
         throw new Error('PWDProvider not set');
      }
      if (this._cdInfo.ver !== cc.VERSION6 && this._cdInfo.ver !== cc.VERSION7) {
         throw new Error('Invalid version: ' + this._cdInfo.ver);
      }

      const [pwd, hint] = Array.isArray(this._pwdProvider)
         ? this._pwdProvider
         : await this._pwdProvider(this._cdInfo, encrypting);
      if (hint && hint.length > cc.HINT_MAX_LEN) {
         throw new Error('Hint length exceeds: ' + cc.HINT_MAX_LEN);
      }
      if (!pwd) {
         throw new Error('Missing password');
      }

      this._cdInfo.hint = hint;
      const pwdBytes = new TextEncoder().encode(pwd);
      let rawMaterial: Uint8Array<ArrayBuffer>;

      if (this._cdInfo.ver === cc.VERSION7) {
         rawMaterial = new Uint8Array(pwdBytes.byteLength + this._userCred.byteLength + cc.LPP_BYTES)
         rawMaterial.set(pwdBytes);
         rawMaterial.set(this._userCred, pwdBytes.byteLength);
         rawMaterial.set(numToBytes(this._cdInfo.lp, cc.LPP_BYTES), pwdBytes.byteLength + this._userCred.byteLength);
      } else {
         rawMaterial = new Uint8Array(pwdBytes.byteLength + this._userCred.byteLength)
         rawMaterial.set(pwdBytes);
         rawMaterial.set(this._userCred, pwdBytes.byteLength);
      }

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
            salt: this._cdInfo.slt,
            iterations: this._cdInfo.ic,
            hash: 'SHA-512',
         },
         ekMaterial,
         { name: useAlg, length: 256 },
         true,
         ['encrypt', 'decrypt']
      );

      const ek = new Uint8Array(await crypto.subtle.exportKey("raw", subtleKey));
      subtleKey = undefined;
      return ek;
   }

   protected override async _genSigningKey(): Promise<Uint8Array<ArrayBuffer>> {
      const ctx = (this._cdInfo?.ver === cc.VERSION6 ? KDF_CTX_SIGNING_V6 : KDF_CTX_SIGNING_V7);
      return this._genDerivedKey(this._userCred, ctx, 1);
   }

   protected override async _genBlockCipherKey(
      blockNum: number
   ): Promise<Uint8Array<ArrayBuffer>> {
      const ctx = (this._cdInfo?.ver === cc.VERSION6 ? KDF_CTX_BLOCK_V6 : KDF_CTX_BLOCK_V7);
      return this._genDerivedKey(this._ek!, ctx, blockNum);
   }

   protected override async _genHintCipherKeyAndIV(baseIV: Uint8Array<ArrayBuffer>): Promise<[Uint8Array<ArrayBuffer>, Uint8Array<ArrayBuffer>]> {
      if (!this._cdInfo) {
         throw new Error('Invalid state for hint key derivation');
      }

      const ctx = (this._cdInfo?.ver === cc.VERSION6 ? KDF_CTX_HINT_V6 : KDF_CTX_HINT_V7);
      return [
         this._genDerivedKey(this._userCred, ctx, 1),
         this._cdInfo?.ver === cc.VERSION6 ? baseIV : this._genDerivedKey(baseIV, ctx, 2)
      ];
   }

   private _genDerivedKey(
      master: Uint8Array,
      purpose: string,
      instance: number,
   ): Uint8Array<ArrayBuffer> {
      if (!master || master.byteLength === 0) {
         throw new Error('Invalid master key');
      }
      if (!this._cdInfo || !this._cdInfo.slt) {
         throw new Error('Invalid state for key derivation');
      }

      let mixedKey: Uint8Array;

      // VERSION7 adds a salt to key derivations
      if (this._cdInfo.ver === cc.VERSION7) {
         if (!purpose || purpose.length != 8) {
            throw new Error('Purpose must be 8 bytes');
         }
         if (this._cdInfo.slt.byteLength != cc.SLT_BYTES) {
            throw new Error('Invalid salt length of: ' + this._cdInfo.slt.byteLength);
         }

         // because crypto_kdf_derive_from_key does not take a salt, we first merge salt and
         // master into a single hash.
         mixedKey = sodium.crypto_generichash(cc.KEY_BYTES, this._cdInfo.slt, master);
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