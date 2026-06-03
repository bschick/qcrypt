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
import { getSodium } from './crypto';
import * as cc from './cipher.consts';
import { CipherDataInfo, Ciphers } from './ciphers-current';
import { ensureArrayBuffer, numToBytes, base64ToBytes, concatArrays } from './utils';

// Contexts must be 8 bytes. Old v6 CTX had a bug of passing more that was
// truncated silently by libsodium (fortunately, harmless)
const KDF_CTX_SIGNING_V6 = "cipherda";
const KDF_CTX_SIGNING_V7 = "Sign_Key";
const KDF_CTX_HINT_V6 = "hint enc";
const KDF_CTX_HINT_V7 = "Hint_Key";
const KDF_CTX_BLOCK_V6 = "block en";
const KDF_CTX_BLOCK_V7 = "Blck_Key";
const KDF_CTX_CIPHER_V7 = "Cphr_Key";
const KDF_CTX_COMMIT_V7 = "Cmit_Key";
const KDF_INFO_SIGNING_V1 = "cipherdata signing key";
const KDF_INFO_HINT_V1 = "hint encryption key";

export type PWDProvider =
   [string, string | undefined] |
   ((
      cdInfo: CipherDataInfo,
      encrypting: boolean
   ) => Promise<[string, string | undefined]>);

export interface KeyProvider {
   purge(): void;
   clone(): KeyProvider;
   setCipherDataInfo(cdInfo: CipherDataInfo): void;
   setHint(hint: string | undefined): void;
   getCipherDataInfo(): CipherDataInfo;
   getCipherKey(encrypting: boolean): Promise<Uint8Array<ArrayBuffer>>;
   getBlockCipherKey(blockNum: number): Promise<Uint8Array<ArrayBuffer>>;
   getSigningKey(): Promise<Uint8Array<ArrayBuffer>>;
   getHintCipherKeyAndIV(baseIV: Uint8Array<ArrayBuffer>): Promise<[Uint8Array<ArrayBuffer>, Uint8Array<ArrayBuffer>]>;
   getKeyCommitment(): Promise<Uint8Array<ArrayBuffer>>;
   get supportsCommitment(): boolean;
   getCustomAd(): Uint8Array<ArrayBuffer> | undefined;
};


export abstract class BaseKeyProvider implements KeyProvider {

   // owned values
   protected _ek: Uint8Array<ArrayBuffer> | undefined = undefined;
   protected _sk: Uint8Array<ArrayBuffer> | undefined = undefined;
   protected _hk: Uint8Array<ArrayBuffer> | undefined = undefined;
   protected _hIV: Uint8Array<ArrayBuffer> | undefined = undefined;
   protected _bks: Map<number, Uint8Array<ArrayBuffer>> = new Map();
   protected _commitKey: Uint8Array<ArrayBuffer> | undefined = undefined;
   protected _cdInfo: CipherDataInfo | undefined = undefined;

   // referenced values
   protected _customAd: Uint8Array<ArrayBuffer> | undefined = undefined;

   constructor(customAd: Uint8Array<ArrayBuffer> | string | undefined = undefined) {
      if (typeof customAd === 'string') {
         customAd = base64ToBytes(customAd);
      }
      if (customAd && customAd.byteLength > cc.ADDIONTAL_DATA_MAX_BYTES) {
         throw new Error('Custom AD too long: ' + customAd.byteLength + ' bytes');
      }
      this._customAd = customAd;
   }

   public getCustomAd(): Uint8Array<ArrayBuffer> | undefined {
      return this._customAd;
   }

   public setCipherDataInfo(cdInfo: CipherDataInfo) {
      if (this._cdInfo) {
         throw new Error('CipherDataInfo can only be set once');
      }
      if (!Ciphers.validateAlg(cdInfo.alg)) {
         throw new Error('Invalid alg type of: ' + cdInfo.alg);
      }
      if (cdInfo.ic !== 0 && (cdInfo.ic < cc.ICOUNT_MIN || cdInfo.ic > cc.ICOUNT_MAX)) {
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
      this._cdInfo = { ...cdInfo, hint: cdInfo.hint ?? '' };
   }

   public setHint(hint: string | undefined): void {
      if (!this._cdInfo) {
         throw new Error('CipherDataInfo not set');
      }
      if (hint && hint.length > cc.HINT_MAX_LEN) {
         throw new Error('Hint length exceeds: ' + cc.HINT_MAX_LEN);
      }
      this._cdInfo.hint = hint;
   }

   public getCipherDataInfo(): CipherDataInfo {
      if (!this._cdInfo) {
         throw new Error('CipherDataInfo not set');
      }
      return this._cdInfo;
   }


   public purge(): void {
      if (this._ek) {
         this._ek.fill(0);
         this._ek = undefined;
      }
      if (this._sk) {
         this._sk.fill(0);
         this._sk = undefined;
      }
      if (this._hk) {
         this._hk.fill(0);
         this._hk = undefined;
      }
      if (this._hIV) {
         this._hIV.fill(0);
         this._hIV = undefined;
      }
      if (this._commitKey) {
         this._commitKey.fill(0);
         this._commitKey = undefined;
      }
      if (this._cdInfo) {
         this._cdInfo.hint = undefined;
         this._cdInfo = undefined;
      }
      for (const bk of this._bks.values()) {
         bk.fill(0);
      }
      this._bks.clear();
      this._customAd = undefined;
   }

   public async getCipherKey(
      encrypting: boolean
   ): Promise<Uint8Array<ArrayBuffer>> {
      if (!this._ek) {
         this._ek = await this._genCipherKey(encrypting);
         if (!this._ek || this._ek.byteLength !== cc.KEY_BYTES) {
            throw new Error('Invalid cipher key');
         }
      }
      return this._ek;
   }

   public async getBlockCipherKey(blockNum: number): Promise<Uint8Array<ArrayBuffer>> {
      // expect blockNum >= 1
      if (blockNum < 1 || blockNum > cc.BLOCKS_MAX) {
         throw new Error('Invalid block number: ' + blockNum);
      }
      if (!this._ek) {
         throw new Error('Invalid state, getCipherKey() must be called first');
      }
      // cache block keys primarily to overwrite at purge
      let bk = this._bks.get(blockNum);
      if (!bk) {
         bk = await this._genBlockCipherKey(blockNum);
         if (!bk || bk.byteLength !== cc.KEY_BYTES) {
            throw new Error('Invalid block cipher key');
         }
         this._bks.set(blockNum, bk);
      }
      return bk;
   }

   public async getSigningKey(): Promise<Uint8Array<ArrayBuffer>> {
      if (!this._sk) {
         this._sk = await this._genSigningKey();
         if (!this._sk || this._sk.byteLength !== cc.KEY_BYTES) {
            throw new Error('Invalid signing key');
         }
      }
      return this._sk;
   }

   public async getHintCipherKeyAndIV(baseIV: Uint8Array<ArrayBuffer>): Promise<[Uint8Array<ArrayBuffer>, Uint8Array<ArrayBuffer>]> {
      if (baseIV.byteLength !== Ciphers.algIVByteLength(this._cdInfo!.alg)) {
         throw new Error('Invalid base IV length: ' + baseIV.byteLength);
      }

      // cache hint key primarily to overwrite at purge
      if (!this._hk || !this._hIV) {
         [this._hk, this._hIV] = await this._genHintCipherKeyAndIV(baseIV);
         if (!this._hk || !this._hIV || this._hk.byteLength !== cc.KEY_BYTES || this._hIV.byteLength < cc.IV_MIN_BYTES) {
            throw new Error('Invalid hint key or hint IV');
         }
      }
      return [this._hk, this._hIV];
   }

   public async getKeyCommitment(): Promise<Uint8Array<ArrayBuffer>> {
      if (!this._commitKey) {
         if (!this._ek) {
            throw new Error('Cipher key must be generated before commitment');
         }
         this._commitKey = await this._genKeyCommitment();
         if (!this._commitKey || this._commitKey.byteLength !== cc.KEY_BYTES) {
            throw new Error('Invalid commitment key');
         }
      }
      return this._commitKey;
   }

   public abstract clone(): KeyProvider;
   public abstract get supportsCommitment(): boolean;
   protected abstract _genCipherKey(encrypting: boolean): Promise<Uint8Array<ArrayBuffer>>;
   protected abstract _genSigningKey(): Promise<Uint8Array<ArrayBuffer>>;
   protected abstract _genBlockCipherKey(blockNum: number): Promise<Uint8Array<ArrayBuffer>>;
   protected abstract _genHintCipherKeyAndIV(
      baseIV: Uint8Array<ArrayBuffer>
   ): Promise<[Uint8Array<ArrayBuffer>, Uint8Array<ArrayBuffer>]>;
   protected abstract _genKeyCommitment(): Promise<Uint8Array<ArrayBuffer>>;
};


export abstract class BasePWDKeyProvider extends BaseKeyProvider {

   // owned values (wiped on purge)
   protected _userCred: Uint8Array<ArrayBuffer> | undefined;
   protected _pwdProvider: PWDProvider | undefined;

   /**
    * Takes ownership of userCred. Caller must not read or modify it after construction
    * because the buffer will be overwritten. Other values are just referenced.
    */
   constructor(
      userCred: Uint8Array<ArrayBuffer>,
      pwdProvider: PWDProvider | undefined = undefined,
      customAd: Uint8Array<ArrayBuffer> | string | undefined = undefined
   ) {
      if (userCred.byteLength != cc.USERCRED_BYTES) {
         throw new Error("Invalid userCred length of: " + userCred.byteLength);
      }
      // To detect use-after-purge or uninitialized buffers, reject all-zero values
      // and accept the exceedingly rare error from a randomly generated all-zero buffer.
      if (userCred.every(b => b === 0)) {
         throw new Error("Invalid userCred: all zero bytes");
      }
      super(customAd);
      this._userCred = userCred;
      this._pwdProvider = pwdProvider;
   }

   public override purge(): void {
      super.purge();
      if (this._userCred) {
         this._userCred.fill(0);
         this._userCred = undefined;
      }
      this._pwdProvider = undefined;
      this._customAd = undefined;
   }

   protected async _pbkdf2CipherKey(rawMaterial: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>> {
      if (!this._cdInfo || this._cdInfo.ic === undefined || !this._cdInfo.slt) {
         throw new Error('Invalid CipherDataInfo');
      }
      if (this._cdInfo.ic < cc.ICOUNT_MIN || this._cdInfo.ic > cc.ICOUNT_MAX) {
         throw new Error('Invalid ic of: ' + this._cdInfo.ic);
      }

      const ekMaterial = await crypto.subtle.importKey(
         'raw',
         rawMaterial,
         'PBKDF2',
         false,
         ['deriveBits', 'deriveKey']
      );

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
};

// IMPORTANT: This class caches derived keys, and users must:
// 1) call setCipherDataInfo() first
// 2) call purge() when the immediate need for keys is complete
// 3) not overwrite or hold references to returned keys
export class PWDKeyProvider implements KeyProvider {

   private _impl?: BasePWDKeyProvider;
   private _userCred: Uint8Array<ArrayBuffer> | undefined;
   private _customAd: Uint8Array<ArrayBuffer> | undefined;

   /**
    * Takes ownership of userCred. Caller must not read or modify it after construction
    * because the buffer will be overwritten. Other values are just referenced.
    */
   constructor(
      userCred: Uint8Array<ArrayBuffer>,
      private _pwdProvider: PWDProvider | undefined = undefined,
      customAd: Uint8Array<ArrayBuffer> | string | undefined = undefined
   ) {
      if (typeof customAd === 'string') {
         customAd = base64ToBytes(customAd);
      }
      if (customAd && customAd.byteLength > cc.ADDIONTAL_DATA_MAX_BYTES) {
         throw new Error('Custom AD too long: ' + customAd.byteLength + ' bytes');
      }
      this._customAd = customAd;

      if (userCred.byteLength != cc.USERCRED_BYTES) {
         throw new Error("Invalid userCred length of: " + userCred.byteLength);
      }
      // To detect use-after-purge or uninitialized buffers reject all-zero values,
      // and accept the exceedingly rare error from a randomly generated all-zero buffer.
      if (userCred.every(b => b === 0)) {
         throw new Error("Invalid userCred: all zero bytes");
      }
      this._userCred = userCred;
   }

   public purge(): void {
      if (this._impl) {
         this._impl.purge();
      }
      if (this._userCred) {
         this._userCred.fill(0);
         this._userCred = undefined;
      }
      this._pwdProvider = undefined;
      this._customAd = undefined;
   }

   public clone(): KeyProvider {
      if (!this._userCred) {
         throw new Error('Cannot clone a purged keyProvider');
      }
      return new PWDKeyProvider(this._userCred.slice(0), this._pwdProvider, this._customAd);
   }

   public setCipherDataInfo(cdInfo: CipherDataInfo): void {
      if (this._impl) {
         throw new Error('CipherDataInfo can only be set once');
      }
      if (!this._userCred) {
         throw new Error('Cannot use a purged keyProvider');
      }
      if (cdInfo.ver < cc.VERSION7 && this._customAd) {
         throw new Error(`customAd is only supported for V7+`);
      }

      // Impls get their own copy so facade and impls can be purged independently.
      const userCredClone = this._userCred.slice(0);
      if (cdInfo.ver >= cc.VERSION7) {
         this._impl = new PWDKeyProviderV7(userCredClone, this._pwdProvider, this._customAd);
      } else if (cdInfo.ver === cc.VERSION6) {
         this._impl = new PWDKeyProviderV6(userCredClone, this._pwdProvider);
      } else {
         this._impl = new PWDKeyProviderLegacy(userCredClone, this._pwdProvider);
      }

      this._impl.setCipherDataInfo(cdInfo);
   }

   public setHint(hint: string | undefined): void {
      if (!this._impl) {
         throw new Error('CipherDataInfo not set');
      }
      this._impl.setHint(hint);
   }

   public getCipherDataInfo(): CipherDataInfo {
      if (!this._impl) {
         throw new Error('CipherDataInfo not set');
      }
      return this._impl.getCipherDataInfo();
   }

   public async getCipherKey(encrypting: boolean): Promise<Uint8Array<ArrayBuffer>> {
      if (!this._impl) {
         throw new Error('CipherDataInfo not set');
      }
      return this._impl.getCipherKey(encrypting);
   }

   public async getBlockCipherKey(blockNum: number): Promise<Uint8Array<ArrayBuffer>> {
      if (!this._impl) {
         throw new Error('CipherDataInfo not set');
      }
      return this._impl.getBlockCipherKey(blockNum);
   }

   public async getSigningKey(): Promise<Uint8Array<ArrayBuffer>> {
      if (!this._impl) {
         throw new Error('CipherDataInfo not set');
      }
      return this._impl.getSigningKey();
   }

   public async getHintCipherKeyAndIV(baseIV: Uint8Array<ArrayBuffer>): Promise<[Uint8Array<ArrayBuffer>, Uint8Array<ArrayBuffer>]> {
      if (!this._impl) {
         throw new Error('CipherDataInfo not set');
      }
      return this._impl.getHintCipherKeyAndIV(baseIV);
   }

   public async getKeyCommitment(): Promise<Uint8Array<ArrayBuffer>> {
      if (!this._impl) {
         throw new Error('CipherDataInfo not set');
      }
      return this._impl.getKeyCommitment();
   }

   public get supportsCommitment(): boolean {
      if (!this._impl) {
         throw new Error('CipherDataInfo not set');
      }
      return this._impl.supportsCommitment;
   }

   public getCustomAd(): Uint8Array<ArrayBuffer> | undefined {
      if (!this._impl) {
         return this._customAd;
      }
      return this._impl.getCustomAd();
   }
}

// IMPORTANT: This class caches derived keys, and users must:
// 1) call setCipherDataInfo() first
// 2) call purge() when the immediate need for keys is complete
// 3) not overwrite or hold references to returned keys
export class MasterKeyKeyProvider extends BaseKeyProvider {

   // owned values (wiped on purge)
   private _masterKey: Uint8Array<ArrayBuffer> | undefined;
   private _cachedExtraContext?: Uint8Array<ArrayBuffer>[];

   /**
    * Takes ownership of masterKey. Caller must not read or modify it after construction
    * because the buffer will be overwritten. Other values are just referenced.
    */
   constructor(
      masterKey: Uint8Array<ArrayBuffer>,
      customAd: Uint8Array<ArrayBuffer> | string | undefined = undefined
   ) {
      if (masterKey.byteLength != cc.KEY_BYTES) {
         throw new Error("Invalid masterKey length of: " + masterKey.byteLength);
      }
      // To detect use-after-purge or uninitialized buffers, reject all-zero values
      // and accept the exceedingly rare error from a randomly generated all-zero buffer.
      if (masterKey.every(b => b === 0)) {
         throw new Error("Invalid masterKey: all zero bytes");
      }
      super(customAd);
      this._masterKey = masterKey;
   }

   public clone(): KeyProvider {
      if (!this._masterKey) {
         throw new Error('Cannot clone a purged keyProvider');
      }
      return new MasterKeyKeyProvider(this._masterKey.slice(0), this._customAd);
   }

   public override purge(): void {
      super.purge();
      if (this._masterKey) {
         this._masterKey.fill(0);
         this._masterKey = undefined;
      }
      this._cachedExtraContext = undefined;
      this._customAd = undefined;
   }

   public get supportsCommitment(): boolean {
      return true;
   }

   private _extraContext(): Uint8Array<ArrayBuffer>[] {
      if (!this._cdInfo) {
         throw new Error('Invalid state, cipherDataInfo not set');
      }
      if (!this._cachedExtraContext) {
         this._cachedExtraContext = [
            numToBytes(Ciphers.algId(this._cdInfo.alg), cc.ALG_BYTES),
            numToBytes(this._cdInfo.ver, cc.VER_BYTES),
            numToBytes(this._cdInfo.lp, cc.LPP_BYTES)
         ];
         if (this._customAd) {
            this._cachedExtraContext.push(this._customAd);
         }
      }

      return this._cachedExtraContext;
   }

   protected override async _genCipherKey(
      encrypting: boolean
   ): Promise<Uint8Array<ArrayBuffer>> {
      if (!this._masterKey) {
         throw new Error('Invalid state, masterKey missing');
      }
      return this._genDerivedKey(this._masterKey, KDF_CTX_CIPHER_V7, 0, this._extraContext());
   }

   protected override async _genSigningKey(): Promise<Uint8Array<ArrayBuffer>> {
      return this._genDerivedKey(this._masterKey!, KDF_CTX_SIGNING_V7, 1, this._extraContext());
   }

   protected override async _genBlockCipherKey(
      blockNum: number
   ): Promise<Uint8Array<ArrayBuffer>> {
      // No extra context for block keys because _ek was already derived from it
      return this._genDerivedKey(this._ek!, KDF_CTX_BLOCK_V7, blockNum);
   }

   protected override async _genHintCipherKeyAndIV(baseIV: Uint8Array<ArrayBuffer>): Promise<[Uint8Array<ArrayBuffer>, Uint8Array<ArrayBuffer>]> {
      if (!this._cdInfo) {
         throw new Error('Invalid state for hint key derivation');
      }

      const extraContext = this._extraContext();
      return [
         this._genDerivedKey(this._masterKey!, KDF_CTX_HINT_V7, 1, extraContext),
         this._genDerivedKey(baseIV, KDF_CTX_HINT_V7, 2, extraContext)
      ];
   }

   protected override async _genKeyCommitment(): Promise<Uint8Array<ArrayBuffer>> {
      // No extra context for commit keys because _ek was already derived from it
      return this._genDerivedKey(this._ek!, KDF_CTX_COMMIT_V7, 1);
   }

   // Returns a derived with the same byteLength as master
   private _genDerivedKey(
      master: Uint8Array<ArrayBuffer>,
      purpose: string,
      instance: number,
      extraContext: Uint8Array<ArrayBuffer>[] = []
   ): Uint8Array<ArrayBuffer> {
      if (!master || master.byteLength < cc.IV_MIN_BYTES) {
         throw new Error('Invalid master key length of: ' + master?.byteLength);
      }
      if (!this._cdInfo) {
         throw new Error('Invalid state for key derivation');
      }
      const sodium = getSodium();
      if (!purpose || purpose.length != sodium.crypto_kdf_CONTEXTBYTES) {
         throw new Error('Invalid purpose length of: ' + purpose?.length);
      }
      if (!this._cdInfo.slt || this._cdInfo.slt.byteLength != cc.SLT_BYTES) {
         throw new Error('Invalid salt length of: ' + this._cdInfo.slt?.byteLength);
      }
      if (this._cdInfo.ver < cc.VERSION7 || this._cdInfo.ver > cc.CURRENT_VERSION) {
         throw new Error('Invalid version: ' + this._cdInfo.ver);
      }
      if (this._cdInfo.ic) {
         throw new Error('Invalid ic, not used by masterkey keyprovider');
      }

      // because crypto_kdf_derive_from_key does not take a salt, we first merge salt,
      // master, and extras into a cryptographic hash.
      const state = sodium.crypto_generichash_init(master, cc.KEY_BYTES);
      sodium.crypto_generichash_update(state, this._cdInfo.slt);
      for (const extra of extraContext) {
         sodium.crypto_generichash_update(state, extra);
      }
      const mixedKey = sodium.crypto_generichash_final(state, cc.KEY_BYTES);

      const derivedKey = ensureArrayBuffer(sodium.crypto_kdf_derive_from_key(
         Math.max(master.byteLength, sodium.crypto_kdf_BYTES_MIN),
         instance,
         purpose,
         mixedKey
      ));
      return derivedKey.slice(0, master.byteLength);
   }
}

export class PWDKeyProviderV7 extends BasePWDKeyProvider {

   private _cachedExtraContext?: Uint8Array<ArrayBuffer>[];

   constructor(
      userCred: Uint8Array<ArrayBuffer>,
      pwdProvider: PWDProvider | undefined = undefined,
      customAd: Uint8Array<ArrayBuffer> | string | undefined = undefined
   ) {
      super(userCred, pwdProvider, customAd);
   }

   public clone(): KeyProvider {
      if (!this._userCred) {
         throw new Error('Cannot clone a purged keyProvider');
      }
      return new PWDKeyProviderV7(this._userCred.slice(0), this._pwdProvider, this._customAd);
   }

   public override purge(): void {
      super.purge();
      this._cachedExtraContext = undefined;
   }

   public get supportsCommitment(): boolean {
      return true;
   }

   private _extraContext(): Uint8Array<ArrayBuffer>[] {
      if (!this._cdInfo) {
         throw new Error('Invalid state, cipherDataInfo not set');
      }
      if (!this._cachedExtraContext) {
         this._cachedExtraContext = [
            numToBytes(Ciphers.algId(this._cdInfo.alg), cc.ALG_BYTES),
            numToBytes(this._cdInfo.ver, cc.VER_BYTES),
            numToBytes(this._cdInfo.lp, cc.LPP_BYTES)
         ];
         if (this._customAd) {
            this._cachedExtraContext.push(this._customAd);
         }
      }

      return this._cachedExtraContext;
   }

   protected override async _genCipherKey(encrypting: boolean): Promise<Uint8Array<ArrayBuffer>> {
      if (!this._cdInfo) {
         throw new Error('CipherDataInfo not set');
      }
      if (!this._pwdProvider) {
         throw new Error('PWDProvider not set');
      }
      if (!this._userCred) {
         throw new Error('User credential not set');
      }
      if (this._cdInfo.ver !== cc.VERSION7) {
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

      this.setHint(hint);
      const pwdBytes = new TextEncoder().encode(pwd);
      const rawMaterial = concatArrays([pwdBytes, this._userCred, ...this._extraContext()]);

      const ek = await this._pbkdf2CipherKey(rawMaterial);
      pwdBytes.fill(0);
      rawMaterial.fill(0);
      return ek;
   }

   protected override async _genSigningKey(): Promise<Uint8Array<ArrayBuffer>> {
      if (!this._userCred) {
         throw new Error('User credential not set');
      }
      return this._genDerivedKey(this._userCred, KDF_CTX_SIGNING_V7, 1, this._extraContext());
   }

   protected override async _genBlockCipherKey(blockNum: number): Promise<Uint8Array<ArrayBuffer>> {
      // No extra context for block keys because _ek was already derived from it
      return this._genDerivedKey(this._ek!, KDF_CTX_BLOCK_V7, blockNum);
   }

   protected override async _genHintCipherKeyAndIV(
      baseIV: Uint8Array<ArrayBuffer>
   ): Promise<[Uint8Array<ArrayBuffer>, Uint8Array<ArrayBuffer>]> {
      if (!this._userCred) {
         throw new Error('User credential not set');
      }

      const extraContext = this._extraContext();
      return [
         this._genDerivedKey(this._userCred, KDF_CTX_HINT_V7, 1, extraContext),
         this._genDerivedKey(baseIV, KDF_CTX_HINT_V7, 2, extraContext)
      ];
   }

   protected override async _genKeyCommitment(): Promise<Uint8Array<ArrayBuffer>> {
      // No extra context for commit keys because _ek was already derived from it
      return this._genDerivedKey(this._ek!, KDF_CTX_COMMIT_V7, 1);
   }

   private _genDerivedKey(
      master: Uint8Array<ArrayBuffer>,
      purpose: string,
      instance: number,
      extraContext: Uint8Array<ArrayBuffer>[] = []
   ): Uint8Array<ArrayBuffer> {
      if (!master || master.byteLength < cc.IV_MIN_BYTES) {
         throw new Error('Invalid master key length of: ' + master?.byteLength);
      }
      if (!this._cdInfo || !this._cdInfo.slt) {
         throw new Error('Invalid state for key derivation');
      }
      if (!purpose || purpose.length != 8) {
         throw new Error('Invalid purpose length of: ' + purpose?.length);
      }
      if (this._cdInfo.slt.byteLength != cc.SLT_BYTES) {
         throw new Error('Invalid salt length of: ' + this._cdInfo.slt.byteLength);
      }
      if (this._cdInfo.ver !== cc.VERSION7) {
         throw new Error('Invalid version: ' + this._cdInfo.ver);
      }

      // because crypto_kdf_derive_from_key does not take a salt, we first merge salt,
      // master, and extras into a cryptographic hash.
      const sodium = getSodium();
      const state = sodium.crypto_generichash_init(master, cc.KEY_BYTES);
      sodium.crypto_generichash_update(state, this._cdInfo.slt);
      for (const extra of extraContext) {
         sodium.crypto_generichash_update(state, extra);
      }
      const mixedKey = sodium.crypto_generichash_final(state, cc.KEY_BYTES);

      const derivedKey = ensureArrayBuffer(sodium.crypto_kdf_derive_from_key(
         Math.max(master.byteLength, sodium.crypto_kdf_BYTES_MIN),
         instance,
         purpose,
         mixedKey
      ));
      return derivedKey.slice(0, master.byteLength);
   }
}

export class PWDKeyProviderV6 extends BasePWDKeyProvider {
   constructor(
      userCred: Uint8Array<ArrayBuffer>,
      pwdProvider: PWDProvider | undefined = undefined
   ) {
      super(userCred, pwdProvider);
   }

   public clone(): KeyProvider {
      if (!this._userCred) {
         throw new Error('Cannot clone a purged keyProvider');
      }
      return new PWDKeyProviderV6(this._userCred.slice(0), this._pwdProvider);
   }

   public get supportsCommitment(): boolean {
      return false;
   }

   protected override async _genCipherKey(encrypting: boolean): Promise<Uint8Array<ArrayBuffer>> {
      if (!this._cdInfo) {
         throw new Error('CipherDataInfo not set');
      }
      if (!this._pwdProvider) {
         throw new Error('PWDProvider not set');
      }
      if (!this._userCred) {
         throw new Error('User credential not set');
      }
      if (this._cdInfo.ver !== cc.VERSION6) {
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

      this.setHint(hint);
      const pwdBytes = new TextEncoder().encode(pwd);
      const rawMaterial = concatArrays([pwdBytes, this._userCred]);

      const ek = await this._pbkdf2CipherKey(rawMaterial);
      pwdBytes.fill(0);
      rawMaterial.fill(0);
      return ek;
   }

   protected override async _genSigningKey(): Promise<Uint8Array<ArrayBuffer>> {
      if (!this._userCred) {
         throw new Error('User credential not set');
      }
      return this._genDerivedKey(this._userCred, KDF_CTX_SIGNING_V6, 1);
   }

   protected override async _genBlockCipherKey(blockNum: number): Promise<Uint8Array<ArrayBuffer>> {
      return this._genDerivedKey(this._ek!, KDF_CTX_BLOCK_V6, blockNum);
   }

   protected override async _genHintCipherKeyAndIV(
      baseIV: Uint8Array<ArrayBuffer>
   ): Promise<[Uint8Array<ArrayBuffer>, Uint8Array<ArrayBuffer>]> {
      if (!this._userCred) {
         throw new Error('User credential not set');
      }
      return [
         this._genDerivedKey(this._userCred, KDF_CTX_HINT_V6, 1),
         baseIV
      ];
   }

   protected override async _genKeyCommitment(): Promise<Uint8Array<ArrayBuffer>> {
      throw new Error('Key commitments not supported for this cipher version');
   }

   private _genDerivedKey(
      master: Uint8Array<ArrayBuffer>,
      purpose: string,
      instance: number,
   ): Uint8Array<ArrayBuffer> {
      if (!master || master.byteLength < cc.IV_MIN_BYTES) {
         throw new Error('Invalid master key length of: ' + master?.byteLength);
      }
      if (!this._cdInfo || !this._cdInfo.slt) {
         throw new Error('Invalid state for key derivation');
      }
      if (!purpose || purpose.length != 8) {
         throw new Error('Invalid purpose length of: ' + purpose?.length);
      }

      const sodium = getSodium();

      const derivedKey = ensureArrayBuffer(sodium.crypto_kdf_derive_from_key(
         Math.max(master.byteLength, sodium.crypto_kdf_BYTES_MIN),
         instance,
         purpose,
         master
      ));
      return derivedKey.slice(0, master.byteLength);
   }
}

export class PWDKeyProviderLegacy extends BasePWDKeyProvider {

   constructor(
      userCred: Uint8Array<ArrayBuffer>,
      pwdProvider: PWDProvider | undefined = undefined
   ) {
      super(userCred, pwdProvider);
   }

   public clone(): KeyProvider {
      if (!this._userCred) {
         throw new Error('Cannot clone a purged keyProvider');
      }
      return new PWDKeyProviderLegacy(this._userCred.slice(0), this._pwdProvider);
   }

   public get supportsCommitment(): boolean {
      return false;
   }

   protected override async _genCipherKey(encrypting: boolean): Promise<Uint8Array<ArrayBuffer>> {
      if (!this._cdInfo) {
         throw new Error('CipherDataInfo not set');
      }
      if (!this._pwdProvider) {
         throw new Error('PWDProvider not set');
      }
      if (!this._userCred) {
         throw new Error('User credential not set');
      }
      if (![cc.VERSION5, cc.VERSION4, cc.VERSION1].includes(this._cdInfo.ver)) {
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

      this.setHint(hint);
      const pwdBytes = new TextEncoder().encode(pwd);
      const rawMaterial = concatArrays([pwdBytes, this._userCred]);

      const ek = await this._pbkdf2CipherKey(rawMaterial);
      pwdBytes.fill(0);
      rawMaterial.fill(0);
      return ek;
   }

   protected override async _genSigningKey(): Promise<Uint8Array<ArrayBuffer>> {
      if (!this._cdInfo) {
         throw new Error('CipherDataInfo not set');
      }
      if (!this._userCred) {
         throw new Error('User credential not set');
      }
      if (![cc.VERSION5, cc.VERSION4, cc.VERSION1].includes(this._cdInfo.ver)) {
         throw new Error('Invalid version: ' + this._cdInfo.ver);
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
            info: new TextEncoder().encode(KDF_INFO_SIGNING_V1)
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

   protected override async _genBlockCipherKey(blockNum: number): Promise<Uint8Array<ArrayBuffer>> {
      throw new Error('Block cipher keys not supported for this cipher version');
   }

   protected override async _genHintCipherKeyAndIV(
      baseIV: Uint8Array<ArrayBuffer>
   ): Promise<[Uint8Array<ArrayBuffer>, Uint8Array<ArrayBuffer>]> {
      if (!this._cdInfo) {
         throw new Error('Invalid state for hint key derivation');
      }
      if (!this._userCred) {
         throw new Error('User credential not set');
      }
      if (![cc.VERSION5, cc.VERSION4, cc.VERSION1].includes(this._cdInfo.ver)) {
         throw new Error('Invalid version: ' + this._cdInfo.ver);
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
            info: new TextEncoder().encode(KDF_INFO_HINT_V1)
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

   protected override async _genKeyCommitment(): Promise<Uint8Array<ArrayBuffer>> {
      throw new Error('Key commitments not supported for this cipher version');
   }
}
