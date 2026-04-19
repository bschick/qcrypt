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
import * as cc from './cipher.consts';
import { BasePWDKeyProvider, PWDProvider } from './keys';

// To geenrate matching keys, these must not change
const KDF_INFO_SIGNING = "cipherdata signing key";
const KDF_INFO_HINT = "hint encryption key";


export class PWDKeyProviderOld extends BasePWDKeyProvider {

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
      if (![cc.VERSION6, cc.VERSION5, cc.VERSION4, cc.VERSION1].includes(this._cdInfo.ver)) {
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
      if (!this._cdInfo) {
         throw new Error('CipherDataInfo not set');
      }

      const skMaterial = await crypto.subtle.importKey(
         'raw',
         this._userCred,
         'HKDF',
         false,
         ['deriveBits', 'deriveKey']
      );

      let subtleKey: CryptoKey | undefined = await crypto.subtle.deriveKey(
         {
            name: 'HKDF',
            salt: this._cdInfo.slt,
            hash: 'SHA-512',
            info: new TextEncoder().encode(KDF_INFO_SIGNING)
         },
         skMaterial,
         { name: 'HMAC', hash: 'SHA-256', length: 256 },
         true,
         ['sign', 'verify']
      );

      // skMaterial is not extractable, so doesn't need clear

      const exported = await crypto.subtle.exportKey("raw", subtleKey);
      subtleKey = undefined;
      return new Uint8Array(exported);
   }

   // Exported for testing and old deciphers, normal callers should not need this
   protected override async _genHintCipherKeyAndIV(baseIV: Uint8Array<ArrayBuffer>): Promise<[Uint8Array<ArrayBuffer>, Uint8Array<ArrayBuffer>]> {
      if (!this._cdInfo) {
         throw new Error('Invalid state for hint key derivation');
      }

      const hkMaterial = await crypto.subtle.importKey(
         'raw',
         this._userCred,
         'HKDF',
         false,
         ['deriveBits', 'deriveKey']
      );

      // A bit of a hack, but subtle doesn't support other algorithms... so lie. This
      // is safe because the key is exported as bits and used in libsodium when not
      // AES-GCM. TODO: If more non-browser cipher are added, make this more generic.
      const dkAlg = 'AES-GCM';

      let subtleKey: CryptoKey | undefined = await crypto.subtle.deriveKey(
         {
            name: 'HKDF',
            salt: this._cdInfo.slt,
            hash: 'SHA-512',
            info: new TextEncoder().encode(KDF_INFO_HINT)
         },
         hkMaterial,
         { name: dkAlg, length: 256 },
         true,
         ['encrypt', 'decrypt']
      );

      const exported = await crypto.subtle.exportKey("raw", subtleKey);
      subtleKey = undefined;
      return [new Uint8Array(exported), baseIV];
   }

   protected override async _genBlockCipherKey(blockNum: number): Promise<Uint8Array<ArrayBuffer>> {
      throw new Error('Block cipher keys not supported for this cipher version');
   }
}