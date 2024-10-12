/* MIT License

Copyright (c) 2024 Brad Schick

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
import { Random48, numToBytes, bytesToNum } from './utils';
import * as cc from './cipher.consts';


export type EParams = {
   readonly alg: string;
   readonly ic: number;
   readonly trueRand: boolean;
   readonly fallbackRand: boolean;
   readonly pwd: string;
   readonly lp: number;
   readonly lpEnd: number;
   readonly userCred: Uint8Array;
   readonly hint?: string;     // limited to HINT_MAX_LEN characters
};

export type PWDProvider = (lp: number, lpEnd:number, hint?: string) => Promise<[string, string | undefined]>;

export type CipherDataBlock = {
   readonly headerData: Uint8Array; // HEADER_BYTES
   readonly additionalData: Uint8Array;
   readonly encryptedData: Uint8Array;
};

export type CipherDataInfo = {
   readonly ver: number;      // VER_BYTES
   readonly alg: string;      // ALG_BYTES
   readonly ic: number;       // IC_BYTES
   readonly lp: number;       // LP_BYTES
   readonly iv: Uint8Array;   // Variable, lookup in AlgInfo
   readonly slt: Uint8Array;  // SLT_BYTES
   readonly hint: boolean;    // limited to ENCRYPTED_HINT_MAX_BYTES bytes
};

// To geenrate matching keys, these must not change
const HKDF_INFO_SIGNING = "cipherdata signing key";
const HKDF_INFO_HINT = "hint encryption key";


export abstract class Ciphers {
   // Poke in this value to true to block random
   // downloads from random.org during testing
   public static testingFlag = false;

   // cache in case any use of true random
   protected _random48Cache: Random48;
   protected _ek?: CryptoKey;
   protected _sk?: CryptoKey;

   protected _ver?: number;
   protected _alg?: string;
   protected _iv?: Uint8Array;
   protected _slt?: Uint8Array;
   protected _ic?: number;
   protected _lp: number = 1; // Not all version support loop # so provide a default
   protected _additionalData?: Uint8Array;
   protected _encryptedHint?: Uint8Array;
   protected _encryptedData?: Uint8Array;

   protected constructor() {
      this._random48Cache = new Random48(Ciphers.testingFlag);
   }

   public static latest(): Ciphers {
      return new CiphersV4();
   }

   // Return appropriate version of Ciphers
   public static fromHeader(encoded: Uint8Array): Ciphers {
      if (encoded.byteLength < cc.MAC_BYTES + cc.VER_BYTES) {
         throw new Error('Invalid header length: ' + encoded.byteLength);
      }

      let ciphers: Ciphers;

      // This is a bit ugly, but the original CiphersV1 encoding stupidly had the
      // version in the middle of the encoding. So detect old version by the first 2 bytes
      // being < 4 (since encoded started with ALG and v1 max ALG was 3 and beyond v1
      // version is >=4). Fortunately ALG_BYTES and VER_BYTES are equal.
      const verOrAlg = bytesToNum(new Uint8Array(encoded.buffer, cc.MAC_BYTES, cc.VER_BYTES));
      if (verOrAlg == cc.VERSION4) {
         ciphers = new CiphersV4();
      } else if (verOrAlg < cc.V1_BELOW && verOrAlg > 0) {
         ciphers = new CiphersV1();
      } else {
         throw new Error('Invalid version: ' + verOrAlg);
      }

      return ciphers;
   }

   static validateAlg(alg: string): boolean {
      return Object.keys(cc.AlgInfo).includes(alg);
   }

   public async benchmark(
      testSize: number,
      targetMillis: number,
      maxMillis: number
   ): Promise<[number, number, number]> {

      const start = Date.now();
      await Ciphers._genCipherKey('AES-GCM', testSize, 'AVeryBogusPwd', crypto.getRandomValues(new Uint8Array(32)), new Uint8Array(cc.SLT_BYTES));
      const test_millis = Date.now() - start;

      const hashRate = testSize / test_millis;

      // Don't allow more then ~5 minutes of pwd hashing (rounded to millions)
      const iCountMax =
         Math.min(cc.ICOUNT_MAX,
            Math.round((maxMillis * hashRate) / 1000000) * 1000000);

      let targetICount = Math.round((hashRate * targetMillis) / 100000) * 100000;
      // Add ICOUNT_MIN to calculated target because benchmark is done during
      // page load and tends to be too low.
      const iCount = Math.max(cc.ICOUNT_DEFAULT, targetICount + cc.ICOUNT_MIN);

      console.log(
         `bench: ${testSize}i, in: ${test_millis}ms, rate: ${Math.round(hashRate)}i/ms,
        ic: ${iCount}i, icm: ${iCountMax}i`
      );

      return [iCount, iCountMax, hashRate];
   }

   public abstract encryptBlock0(
      eparams: EParams,
      input: Uint8Array,
      readyNotice?: (cdInfo: CipherDataInfo) => void
   ): Promise<CipherDataBlock>;

   public abstract encryptBlockN(
      eparams: EParams,
      input: Uint8Array,
   ): Promise<CipherDataBlock>;

   public abstract decodeHeader(encoded: Uint8Array): number;

   public abstract decryptPayloadN(
      payload: Uint8Array
   ): Promise<Uint8Array>;

   public abstract get payloadSize(): number;

   abstract _decodePayload0(
      userCred: Uint8Array,
      payload: Uint8Array
   ): Promise<void>;

   protected abstract _decodePayloadN(
      payload: Uint8Array
   ): Promise<void>;

   protected abstract _verifyMAC(): Promise<boolean>;

   static async _genCipherKey(
      alg: string,
      ic: number,
      pwd: string,
      userCred: Uint8Array,
      slt: Uint8Array
   ): Promise<CryptoKey> {

      if (!Ciphers.validateAlg(alg)) {
         throw new Error('Invalid alg type of: ' + alg);
      }
      if (ic < cc.ICOUNT_MIN || ic > cc.ICOUNT_MAX) {
         throw new Error('Invalid ic of: ' + ic);
      }
      if (slt.byteLength != cc.SLT_BYTES) {
         throw new Error("Invalid slt size of: " + slt.byteLength);
      }
      if (userCred.byteLength != cc.USERCRED_BYTES) {
         throw new Error("Invalid userCred size of: " + userCred.byteLength);
      }
      if (!pwd) {
         throw new Error('Invalid empty password');
      }
      if (ic < cc.ICOUNT_MIN || ic > cc.ICOUNT_MAX) {
         throw new Error('Invalid ic of: ' + ic);
      }

      const pwdBytes = new TextEncoder().encode(pwd);
      let rawMaterial = new Uint8Array(pwdBytes.byteLength + cc.USERCRED_BYTES)
      rawMaterial.set(pwdBytes);
      rawMaterial.set(userCred, pwdBytes.byteLength);

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

      const ek = await crypto.subtle.deriveKey(
         {
            name: 'PBKDF2',
            salt: slt,
            iterations: ic,
            hash: 'SHA-512',
         },
         ekMaterial,
         { name: useAlg, length: 256 },
         true,
         ['encrypt', 'decrypt']
      );

      return ek;
   }


   // Public for testing, normal callers should not need this
   static async _genSigningKey(
      userCred: Uint8Array,
      slt: Uint8Array
   ): Promise<CryptoKey> {

      if (slt.byteLength != cc.SLT_BYTES) {
         throw new Error("Invalid slt size of: " + slt.byteLength);
      }

      if (userCred.byteLength != cc.USERCRED_BYTES) {
         throw new Error('Invalid userCred length of: ' + userCred.byteLength);
      }
      const skMaterial = await crypto.subtle.importKey(
         'raw',
         userCred,
         'HKDF',
         false,
         ['deriveBits', 'deriveKey']
      );

      const sk = await crypto.subtle.deriveKey(
         {
            name: 'HKDF',
            salt: slt,
            hash: 'SHA-512',
            info: new TextEncoder().encode(HKDF_INFO_SIGNING)
         },
         skMaterial,
         { name: 'HMAC', hash: 'SHA-256', length: 256 },
         true,
         ['sign', 'verify']
      );

      return sk;
   }

   // Public for testing, normal callers should not need this
   static async _genHintCipherKey(
      alg: string,
      userCred: Uint8Array,
      slt: Uint8Array
   ): Promise<CryptoKey> {

      if (slt.byteLength != cc.SLT_BYTES) {
         throw new Error("Invalid slt size of: " + slt.byteLength);
      }

      if (userCred.byteLength != cc.USERCRED_BYTES) {
         throw new Error('Invalid userCred length of: ' + userCred.byteLength);
      }
      const skMaterial = await crypto.subtle.importKey(
         'raw',
         userCred,
         'HKDF',
         false,
         ['deriveBits', 'deriveKey']
      );

      // A bit of a hack, but subtle doesn't support other algorithms... so lie. This
      // is safe because the key is exported as bits and used in libsodium when not
      // AES-GCM. TODO: If more non-browser cipher are added, make this more generic.
      const useAlg = 'AES-GCM';

      const hk = await crypto.subtle.deriveKey(
         {
            name: 'HKDF',
            salt: slt,
            hash: 'SHA-512',
            info: new TextEncoder().encode(HKDF_INFO_HINT)
         },
         skMaterial,
         { name: useAlg, length: 256 },
         true,
         ['encrypt', 'decrypt']
      );

      return hk;
   }

   protected static async _doEncrypt(
      alg: string,
      key: CryptoKey,
      iv: Uint8Array,
      clear: Uint8Array,
      additionalData?: Uint8Array,
   ): Promise<Uint8Array> {

      const ivBytes = Number(cc.AlgInfo[alg]['iv_bytes']);
      if (ivBytes != iv.byteLength) {
         throw new Error('incorrect iv length of: ' + iv.byteLength);
      }

      let encryptedBytes: Uint8Array;
      if (alg == 'X20-PLY') {
         const exported = await crypto.subtle.exportKey("raw", key);
         const keyBytes = new Uint8Array(exported);

         await sodium.ready;
         try {
            encryptedBytes = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
               clear,
               additionalData ?? null,
               null,
               iv,
               keyBytes,
               "uint8array"
            );
         } catch (err) {
            console.error(err)
            // Match behavior of Web Crytpo functions that throws limited DOMException
            throw new DOMException('', 'OperationError');
         }
      } else if (alg == 'AEGIS-256') {
         const exported = await crypto.subtle.exportKey("raw", key);
         const keyBytes = new Uint8Array(exported);

         await sodium.ready;
         try {
            encryptedBytes = sodium.crypto_aead_aegis256_encrypt(
               clear,
               additionalData ?? null,
               null,
               iv,
               keyBytes,
               "uint8array"
            );
         } catch (err) {
            console.error(err)
            // Match behavior of Web Crytpo functions that throws limited DOMException
            throw new DOMException('', 'OperationError');
         }
      } else {
         const cipherBuf = await crypto.subtle.encrypt({
            name: alg,
            iv: iv,
            additionalData: additionalData ?? new ArrayBuffer(0),
            tagLength: cc.AES_GCM_TAG_BYTES * 8
         },
            key,
            clear
         );
         encryptedBytes = new Uint8Array(cipherBuf);
      }

      return encryptedBytes;
   }


   // Password is a callback because we need to extract any hint from ciphertext first.
   // We also don't want the caller (web page) to show anything  extracted from
   // ciphertext until after it has been verified with the MAC. Order
   // of operations is:
   //
   // 1. Unpack values and checks userCred based MAC
   // 2. Decrypt hint if it exists
   // 3. Callback to get the password with the hint unpacked & validated hint
   // 4. Generate cipher keys using returned pwd + userCred
   // 5. Decrypt encrypted text using cipher key and addtional data
   // 6. Return cleat text bytes
   //
   public async decryptPayload0(
      pwdProvider: PWDProvider,
      lpEnd: number,
      userCred: Uint8Array,
      payload: Uint8Array,
      readyNotice?: (cdInfo: CipherDataInfo) => void
   ): Promise<Uint8Array> {

      if (userCred.byteLength != cc.USERCRED_BYTES) {
         throw new Error('Invalid userCred length of: ' + userCred.byteLength);
      }

      // This does MAC check
      await this._decodePayload0(userCred, payload);

      if (!this._alg || !this._slt || !this._iv || !this._ic || !this._encryptedData || !this._encryptedHint) {
         throw new Error('Data not initialized');
      }

      let hint = new Uint8Array(0);
      if (this._encryptedHint!.byteLength != 0) {
         const hk = await Ciphers._genHintCipherKey(this._alg, userCred, this._slt);
         hint = await Ciphers._doDecrypt(
            this._alg,
            hk,
            this._iv,
            this._encryptedHint
         );
      }

      const [pwd] = await pwdProvider(this._lp, lpEnd, new TextDecoder().decode(hint));
      if (!pwd) {
         throw new Error('password is empty');
      }

      if (readyNotice) {
         readyNotice({
            ver: this._ver!,
            alg: this._alg,
            ic: this._ic,
            slt: this._slt,
            iv: this._iv,
            lp: this._lp,
            hint: hint.byteLength > 0
         });
      }

      this._ek = await Ciphers._genCipherKey(this._alg, this._ic, pwd, userCred, this._slt);

      const decrypted = await Ciphers._doDecrypt(
         this._alg,
         this._ek,
         this._iv,
         this._encryptedData,
         this._additionalData,
      );

      return decrypted;
   }

   public async getCipherDataInfo(
      userCred: Uint8Array,
      payload: Uint8Array,
   ): Promise<CipherDataInfo> {

      if (userCred.byteLength != cc.USERCRED_BYTES) {
         throw new Error('Invalid userCred length of: ' + userCred.byteLength);
      }

      // This does MAC check
      await this._decodePayload0(userCred, payload);

      if (!this._alg || !this._slt || !this._iv || !this._ic || !this._encryptedHint) {
         throw new Error('Data not initialized');
      }

      return {
         ver: this._ver!,
         alg: this._alg,
         ic: this._ic,
         slt: this._slt,
         lp: this._lp,
         iv: this._iv,
         hint: this._encryptedHint!.byteLength > 0
      };
   }

   protected static async _doDecrypt(
      alg: string,
      key: CryptoKey,
      iv: Uint8Array,
      encrypted: Uint8Array,
      additionalData?: Uint8Array,
   ): Promise<Uint8Array> {

      let decrypted: Uint8Array;
      if (alg == 'X20-PLY') {
         const exported = await crypto.subtle.exportKey("raw", key);
         const keyBytes = new Uint8Array(exported);

         /*         console.log('dxcha encrypted', encrypted.byteLength, encrypted);
                  console.log('dxcha additionalData', additionalData.byteLength, additionalData);
                  console.log('dxcha iv', iv.byteLength, iv);
                  console.log('dxcha keyBytes', keyBytes.byteLength, keyBytes);
         */
         await sodium.ready;
         try {
            decrypted = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
               null,
               encrypted,
               additionalData ?? null,
               iv,
               keyBytes,
               "uint8array"
            );
         } catch (err) {
            console.error(err);
            // Match behavior of Web Crytpo functions that throws limited DOMException
            throw new DOMException('', 'OperationError');
         }
      } else if (alg == 'AEGIS-256') {
         const exported = await crypto.subtle.exportKey("raw", key);
         const keyBytes = new Uint8Array(exported);

         await sodium.ready;
         try {
            decrypted = sodium.crypto_aead_aegis256_decrypt(
               null,
               encrypted,
               additionalData ?? null,
               iv,
               keyBytes,
               "uint8array"
            );
         } catch (err) {
            console.error(err);
            // Match behavior of Web Crytpo functions that throws limited DOMException
            throw new DOMException('', 'OperationError');
         }
      } else {
         const buffer = await crypto.subtle.decrypt({
            name: alg,
            iv: iv.slice(0, 12),
            additionalData: additionalData ?? new ArrayBuffer(0),
            tagLength: cc.AES_GCM_TAG_BYTES * 8
         },
            key,
            encrypted
         );
         decrypted = new Uint8Array(buffer);
      }

      return decrypted;
   }

   // Seperated out and made public for testing, normal callers should not be needed this
   public static async _createHeader(
      sk: CryptoKey,
      encryptedData: Uint8Array,
      additionalData: Uint8Array,
   ): Promise<Uint8Array> {

      const payloadBytes = encryptedData.byteLength + additionalData.byteLength;
      // Packer validates ranges as values are added
      const packer = new Packer(cc.HEADER_BYTES, cc.MAC_BYTES);
      packer.ver = cc.VERSION4;
      packer.size = payloadBytes;

      const exportedSk = await crypto.subtle.exportKey("raw", sk);
      const skData = new Uint8Array(exportedSk);

      const state = sodium.crypto_generichash_init(skData, cc.MAC_BYTES);
      sodium.crypto_generichash_update(state, new Uint8Array(packer.buffer, cc.MAC_BYTES));
      sodium.crypto_generichash_update(state, additionalData);
      sodium.crypto_generichash_update(state, encryptedData);

      const mac = sodium.crypto_generichash_final(state, cc.MAC_BYTES);
      packer.offset = 0;
      packer.mac = mac;

      return packer.detach();
   }

   public static validateEparams(eparams: EParams) {
      if (!Ciphers.validateAlg(eparams.alg)) {
         throw new Error('Invalid alg type of: ' + eparams.alg);
      }
      if (eparams.ic < cc.ICOUNT_MIN || eparams.ic > cc.ICOUNT_MAX) {
         throw new Error('Invalid ic of: ' + eparams.ic);
      }
      if (!eparams.trueRand && !eparams.fallbackRand) {
         throw new Error('Either trueRand or fallbackRand must be true');
      }
      if (eparams.hint && eparams.hint.length > cc.HINT_MAX_LEN) {
         throw new Error('Hint length exceeds ' + cc.HINT_MAX_LEN);
      }
      if (!eparams.pwd || !eparams.userCred || eparams.userCred.byteLength != cc.USERCRED_BYTES) {
         throw new Error('Invalid password or userCred');
      }
   }

   // Only useful for validating params before encoding. Decoded values are read with
   // expected sizes, so validity depends on signature validate rather than decoded lengths
   public static validateAdditionalData(
      args: {
         alg: string;
         iv: Uint8Array;
         ic?: number;
         slt?: Uint8Array;
         encryptedHint?: Uint8Array
      }) {

      if (!Ciphers.validateAlg(args.alg)) {
         throw new Error('Invalid alg: ' + args.alg);
      }

      const ivBytes = Number(cc.AlgInfo[args.alg]['iv_bytes']);
      if (args.iv.byteLength != ivBytes) {
         throw new Error('Invalid iv size: ' + args.iv.byteLength);
      }

      if (args.slt) {
         if (args.slt.byteLength != cc.SLT_BYTES) {
            throw new Error('Invalid slt len: ' + args.slt.byteLength);
         }
         // If there is a salt, ic must also be present (and valid)
         if (!args.ic) {
            throw new Error('Missing ic');
         }
      }

      if (args.ic && (args.ic < cc.ICOUNT_MIN || args.ic > cc.ICOUNT_MAX)) {
         throw new Error('Invalid ic: ' + args.ic);
      }

      if (args.encryptedHint && (args.encryptedHint.length > cc.ENCRYPTED_HINT_MAX_BYTES)) {
         throw new Error('Invalid encrypted hint length: ' + args.encryptedHint.length);
      }
   }
}


class CiphersV1 extends Ciphers {
   /* V1 CipherData Layout (it was a bit brain dead, but it wasn't written to files)
      <Document>
         MAC_BYTES
         ALG_BYTES
         IV_BYTES (variable)
         SLT_BYTES
         IC_BYTES
         VER_BYTES
         HINT_SIZE_BYTES
         HINT_BYTES (variable)
         ENC_DATA_BYTES (variable)
      </Document>
   */

   private _mac?: Uint8Array;

   override decodeHeader(
      header: Uint8Array
   ): number {

      if (this._mac) {
         throw new Error('CiphersV1 instance was reused');
      }

      // Need to treat all values an UNTRUSTED since the signature has not yet been
      // validated.

      if (header.byteLength < cc.HEADER_BYTES) {
         throw new Error('Invalid cipher data length: ' + header.byteLength);
      }

      // Need to treat all values an UNTRUSTED since the signature has not yet been
      // validated. Test each value for errors as we unpack
      let extractor = new Extractor(header);

      // Order must be invariant
      // This is actually more then HEADER_BYTES, but V1 did really have a head
      // and we know the full CipherData is provided, so cheat to simplify V4 and later.
      this._mac = extractor.mac;
      this._alg = extractor.alg;
      this._iv = extractor.iv;

      // Not that for V1 this is larger then HEADER_BYTES because we consumed the
      // entire IV. This is ok since we know the full CipherData is provided, to
      // this call and it make the overall API cleaner for newers versions
      return extractor.offset;
   }


   // For V1, this should be the entire CipherData array
   override async _decodePayload0(
      userCred: Uint8Array,
      payload: Uint8Array
   ): Promise<void> {

      if (userCred.byteLength != cc.USERCRED_BYTES) {
         throw new Error('Invalid userCred length of: ' + userCred.byteLength);
      }
      if (!this._alg || !this._iv) {
         throw new Error('CiphersV1 data not initialized');
      }


      // Need to treat all values an UNTRUSTED since the signature has not yet been
      // validated, Extractor does test each value for valid ranges as we unpack
      let extractor = new Extractor(payload);

      // Order must be invariant
      this._slt = extractor.slt;
      this._ic = extractor.ic;
      this._ver = extractor.ver;
      if (this._ver != cc.VERSION1) {
         throw new Error('Invalid version of: ' + this._ver);
      }
      this._encryptedHint = extractor.hint;
      this._encryptedData = extractor.remainder('edata');

      // repack because of the split between header and payload call
      this._additionalData = CiphersV1._encodeAdditionalData({
         alg: this._alg,
         iv: this._iv,
         ic: this._ic,
         slt: this._slt,
         encryptedHint: this._encryptedHint
      });

      this._sk = await Ciphers._genSigningKey(userCred, this._slt);

      // Avoiding the Doom Principle and verify signature before crypto operations.
      // Aka, check MAC as soon as possible after we  have the signing key and data.
      // Might be cleaner to do this elswhere, but keeping it at the lowest level
      // ensures we don't skip the step
      const validMac: boolean = await this._verifyMAC();
      if (validMac) {
         return;
      }

      throw new Error('Invalid MAC');
   }

   protected override async _verifyMAC(): Promise<boolean> {

      if (!this._additionalData || !this._sk || !this._encryptedData || !this._mac) {
         throw new Error('Invalid MAC data');
      }

      const data = new Uint8Array(this._additionalData.byteLength + this._encryptedData.byteLength);
      data.set(this._additionalData);
      data.set(this._encryptedData, this._additionalData.byteLength);

      const valid: boolean = await crypto.subtle.verify('HMAC', this._sk, this._mac, data);
      if (valid) {
         return true;
      }

      throw new Error('Invalid HMAC signature');
   }

   protected static _encodeAdditionalData(
      args: {
         alg: string;
         iv: Uint8Array;
         ic: number;
         slt: Uint8Array;
         encryptedHint: Uint8Array
      }): Uint8Array {

      Ciphers.validateAdditionalData(args);

      const maxBytes = cc.ADDIONTAL_DATA_MAX_BYTES - cc.LP_BYTES;
      // Packer validates ranges as values are added
      const packer = new Packer(maxBytes);

      packer.alg = args.alg;
      packer.iv = args.iv;
      packer.slt = args.slt;
      packer.ic = args.ic;
      packer.ver = cc.VERSION1;
      packer.hint = args.encryptedHint;

      const result = packer.trim();
      return result;
   }

   override async encryptBlock0(
      eparams: EParams,
      input: Uint8Array,
      readyNotice?: (cdInfo: CipherDataInfo) => void
   ): Promise<CipherDataBlock> {
      throw new Error('Encrypting V1 not supported');
   }

   override async encryptBlockN(
      eparams: EParams,
      input: Uint8Array,
   ): Promise<CipherDataBlock> {
      throw new Error('Encrypting V1 not supported');
   }

   public override async decryptPayloadN(
      payloadN: Uint8Array
   ): Promise<Uint8Array> {
      throw new Error('V1 only has block0');
   }

   protected override async _decodePayloadN(
      payload: Uint8Array
   ): Promise<void> {
      throw new Error('V1 only has block0');
   }

   public override get payloadSize(): number {
      throw new Error('V1 does not have a payload');
   }
}


class CiphersV4 extends Ciphers {
   /* V4 CipherData Layout (hopefully less brain dead). Tags are just notation...
    * and are not actually in the data stream. All encodings have one block0 instance
    * followed by zero or more blockN instances

      <Document>
         <Block0>
            <Header>
               MAC_BYTES
               VER_BYTES
               PAYLOAD_SIZE_BYTES
            </Header>
            <Payload>
               <Additional Data>
                  ALG_BYTES
                  IV_BYTES (variable)
                  SLT_BYTES
                  IC_BYTES
                  LP_BYTES
                  EHINT_LEN_BYTES
                  EHINT_BYTES (variable)
               </Additional Data>
               <Encrypted Data>
                  EDATA_BYTES (variable)
               </Encrypted Data>
            </Payload>
         </Block0>
         <BlockN>
            <Header>
               MAC_BYTES
               VER_BYTES
               PAYLOAD_SIZE_BYTES
            </Header>
            <Payload>
               <Additional Data>
                  ALG_BYTES
                  IV_BYTES (variable)
               </Additional Data>
               <Encrypted Data>
                  EDATA_BYTES (variable)
               </Encrypted Data>
            </Payload>
         </BlockN>
         ...
      </Document>
   */

   private _mac?: Uint8Array;
   protected _payloadSize?: number;

   public override get payloadSize(): number {
      if (!this._payloadSize) {
         throw new Error('V4 payloadsize not set');
      }
      return this._payloadSize;
   }


   // Overall order of operations for encryption
   //
   // 1. Generate new salt and iv/nonce values
   // 2. Generate keys
   // 3. Encrypt hint if it exists
   // 2. Encode cipher parameters as additional data
   // 4. Encrypt cleartext using cipher key (with addition data)
   // 5. Sign addtional data + cipher text with signing key
   // 6. Return all the parts of the cipherdata
   //
   override async encryptBlock0(
      eparams: EParams,
      input: Uint8Array,
      readyNotice?: (cdInfo: CipherDataInfo) => void
   ): Promise<CipherDataBlock> {

      Ciphers.validateEparams(eparams);
      if (this._sk || this._ek) {
         throw new Error('CiphersV4 instance encryptBlock0 should only be called once');
      }
      if (input.byteLength == 0) {
         throw new Error('No data to encrypt');
      } else if (input.byteLength > cc.CLEAR_DATA_MAX_BYTES) {
         throw new Error('Clear data too large');
      }

      // Create a new salt and IV each time a key is derviced from the password.
      // https://crypto.stackexchange.com/questions/53032/salt-for-non-stored-passwords
      const randomArray = await this._random48Cache.getRandomArray(
         eparams.trueRand,
         eparams.fallbackRand
      );

      this._alg = eparams.alg;
      this._ic = eparams.ic;
      this._lp = eparams.lp;

      // don't save this stuff... we allow changing alg and ic per block
      const ivBytes = Number(cc.AlgInfo[this._alg]['iv_bytes']);
      this._slt = randomArray.slice(0, cc.SLT_BYTES);
      this._iv = randomArray.slice(cc.SLT_BYTES, cc.SLT_BYTES + ivBytes);

      if (readyNotice) {
         readyNotice({
            ver: cc.VERSION4,
            alg: this._alg,
            ic: this._ic,
            slt: this._slt,
            lp: this._lp,
            iv: this._iv,
            hint: Boolean(eparams.hint)
         });
      }

      const hk = await Ciphers._genHintCipherKey(this._alg, eparams.userCred, this._slt);
      this._sk = await Ciphers._genSigningKey(eparams.userCred, this._slt);
      this._ek = await Ciphers._genCipherKey(this._alg, this._ic, eparams.pwd, eparams.userCred, this._slt);

      this._encryptedHint = new Uint8Array(0);
      if (eparams.hint) {
         // Since hint encoding could expand beyond 255, truncate the result to ensure fit
         // TODO: This can cause � problems with truncated unicode codepoints or graphemes,
         // could truncate hint characters and re-encode (see https://tonsky.me/blog/unicode/)
         const hintEnc = new TextEncoder()
            .encode(eparams.hint)
            .slice(0, cc.ENCRYPTED_HINT_MAX_BYTES - cc.AUTH_TAG_MAX_BYTES);

         this._encryptedHint = await Ciphers._doEncrypt(
            this._alg,
            hk,
            this._iv,
            hintEnc
         );
      }

      this._additionalData = CiphersV4._encodeAdditionalData({
         alg: this._alg,
         iv: this._iv,
         ic: this._ic,
         lp: this._lp,
         slt: this._slt,
         encryptedHint: this._encryptedHint
      });

      return this._encryptAndSign(input);
   }

   override async encryptBlockN(
      eparams: EParams,
      input: Uint8Array,
   ): Promise<CipherDataBlock> {

      Ciphers.validateEparams(eparams);
      if (!this._sk || !this._ek) {
         throw new Error('Data not initialized, encrypt block0 first');
      }
      if (input.byteLength == 0) {
         throw new Error('No data to encrypt');
      } else if (input.byteLength > cc.CLEAR_DATA_MAX_BYTES) {
         throw new Error('Clear data too large');
      }

      const randomArray = await this._random48Cache.getRandomArray(
         eparams.trueRand,
         eparams.fallbackRand
      );

      this._alg = eparams.alg
      const ivBytes = Number(cc.AlgInfo[this._alg]['iv_bytes']);
      this._iv = randomArray.slice(0, ivBytes);

      this._additionalData = CiphersV4._encodeAdditionalData({
         alg: this._alg,
         iv: this._iv
      });

      return this._encryptAndSign(input);
   }

   protected async _encryptAndSign(
      clear: Uint8Array
   ): Promise<CipherDataBlock> {

      if (!this._sk || !this._ek || !this._alg || !this._iv || !this._additionalData) {
         throw new Error('Data not initialized');
      }

      this._encryptedData = await Ciphers._doEncrypt(
         this._alg,
         this._ek,
         this._iv,
         clear,
         this._additionalData,
      );

      const headerData = await CiphersV4._createHeader(
         this._sk,
         this._encryptedData,
         this._additionalData
      );

      return {
         headerData: headerData,
         additionalData: this._additionalData,
         encryptedData: this._encryptedData
      }
   }

   protected static _encodeAdditionalData(
      args: {
         alg: string;
         iv: Uint8Array;
         ic?: number;
         slt?: Uint8Array;
         lp?: number;
         encryptedHint?: Uint8Array
      }): Uint8Array {

      Ciphers.validateAdditionalData(args);

      const maxBytes = cc.ADDIONTAL_DATA_MAX_BYTES;
      // Packer validates ranges as values are added
      const packer = new Packer(maxBytes);

      packer.alg = args.alg;
      packer.iv = args.iv;

      if (args.slt) {
         packer.slt = args.slt;
      }

      if (args.ic) {
         packer.ic = args.ic;
      }

      if (args.lp) {
         packer.lp = args.lp;
      }

      if (args.encryptedHint != undefined) {
         packer.hint = args.encryptedHint;
      }

      const result = packer.trim();
      return result;
   }

   override decodeHeader(
      header: Uint8Array
   ): number {

      // Need to treat all values an UNTRUSTED since the signature has not yet been
      // validated.

      if (header.byteLength < cc.HEADER_BYTES) {
         throw new Error('Invalid cipher data length: ' + header.byteLength);
      }

      // Need to treat all values an UNTRUSTED since the signature has not yet been
      // validated, Extractor does test each value for valid ranges as we unpack
      const extractor = new Extractor(header);

      // Order must be invariant
      this._mac = extractor.mac;
      this._ver = extractor.ver;
      if (this._ver != cc.VERSION4) {
         throw new Error('Invalid version of: ' + this._ver);
      }
      this._payloadSize = extractor.size;

      return extractor.offset;
   }

   public async decryptPayloadN(
      payload: Uint8Array,
   ): Promise<Uint8Array> {

      await this._decodePayloadN(payload);
      if (!this._alg || !this._ek || !this._iv || !this._encryptedData || !this._encryptedHint) {
         throw new Error('Data not initialized');
      }

      const decrypted = await Ciphers._doDecrypt(
         this._alg,
         this._ek,
         this._iv,
         this._encryptedData,
         this._additionalData,
      );

      return decrypted;
   }

   // Importers of CipherService should not need this function directly,
   // but it is public for unit testing. Does not allow encoding
   // with zero length encrypted text since that is not needed
   override async _decodePayload0(
      userCred: Uint8Array,
      payload: Uint8Array
   ): Promise<void> {

      if (userCred.byteLength != cc.USERCRED_BYTES) {
         throw new Error('Invalid userCred length of: ' + userCred.byteLength);
      }

      // Need to treat all values an UNTRUSTED since the signature has not yet been
      // validated, Extractor does test each value for valid ranges as we unpack
      let extractor = new Extractor(payload);

      // Order must be invariant
      this._alg = extractor.alg;
      this._iv = extractor.iv;
      this._slt = extractor.slt;
      this._ic = extractor.ic;
      this._lp = extractor.lp;
      this._encryptedHint = extractor.hint;
      this._encryptedData = extractor.remainder('edata');

      // V4 additional data is the payload minus encrypted data
      this._additionalData = new Uint8Array(
         payload.buffer,
         payload.byteOffset,
         extractor.offset - this._encryptedData.byteLength
      );

      this._sk = await Ciphers._genSigningKey(userCred, this._slt);

      // Avoiding the Doom Principle and verify signature before crypto operations.
      // Aka, check MAC as soon as possible after we  have the signing key and data.
      // Might be cleaner to do this elswhere, but keeping it at the lowest level
      // ensures we don't skip the step
      const validMac: boolean = await this._verifyMAC();
      if (validMac) {
         return;
      }

      throw new Error('Invalid MAC');
   }

   // Importers of CipherService should not need this function directly,
   // but it is public for unit testing. Does not allow encoding
   // with zero length encrypted text since that is not needed
   async _decodePayloadN(
      payload: Uint8Array
   ): Promise<void> {

      // Need to treat all values an UNTRUSTED since the signature has not yet been
      // validated, Extractor does test each value for valid ranges as we unpack
      let extractor = new Extractor(payload);

      // Order must be invariant
      this._alg = extractor.alg;
      this._iv = extractor.iv;
      this._encryptedData = extractor.remainder('edata');

      // V4 additional data is payload - encrypted data
      this._additionalData = new Uint8Array(
         payload.buffer,
         payload.byteOffset,
         extractor.offset - this._encryptedData.byteLength
      );

      // Avoiding the Doom Principle and verify signature before crypto operations.
      // Aka, check MAC as soon as possible after we  have the signing key and data.
      // Might be cleaner to do this elswhere, but keeping it at the lowest level
      // ensures we don't skip the step
      const validMac: boolean = await this._verifyMAC();
      if (validMac) {
         return;
      }

      throw new Error('Invalid MAC');
   }

   protected override async _verifyMAC(): Promise<boolean> {

      if (!this._payloadSize || !this._ver || !this._additionalData ||
         !this._sk || !this._encryptedData || !this._mac) {
         throw new Error('Data not initialized');
      }

      const encVer = numToBytes(this._ver, cc.VER_BYTES);
      const encSizeBytes = numToBytes(this._payloadSize, cc.PAYLOAD_SIZE_BYTES);

      const headerPortion = new Uint8Array(cc.VER_BYTES + cc.PAYLOAD_SIZE_BYTES);
      headerPortion.set(encVer);
      headerPortion.set(encSizeBytes, cc.VER_BYTES);

      const exportedSk = await crypto.subtle.exportKey("raw", this._sk);
      const skData = new Uint8Array(exportedSk);
      const state = sodium.crypto_generichash_init(skData, cc.MAC_BYTES);

      sodium.crypto_generichash_update(state, headerPortion);
      sodium.crypto_generichash_update(state, this._additionalData);
      sodium.crypto_generichash_update(state, this._encryptedData);

      const testMac = sodium.crypto_generichash_final(state, cc.MAC_BYTES);
      const validMac: boolean = sodium.memcmp(this._mac, testMac);
      if (validMac) {
         return true;
      }

      throw new Error('Invalid MAC signature');
   }

}


class Extractor {
   private _encoded: Uint8Array;
   private _offset: number;
   private _ivBytes?: number;

   constructor(encoded: Uint8Array, offset: number = 0) {
      this._encoded = encoded;
      this._offset = offset;
   }

   extract(what: string, len: number): Uint8Array {
      const result = new Uint8Array(this._encoded.buffer,
         this._encoded.byteOffset + this._offset, len);
      // happens if the encode data is not as long as expected
      if (result.byteLength != len) {
         throw new Error(`Invalid ${what}, length: ${result.byteLength}`);
      }

      this._offset += len;
      return result;
   }

   remainder(what: string): Uint8Array {
      const result = new Uint8Array(this._encoded.buffer,
         this._encoded.byteOffset + this._offset);
      // happens if the encode data is not as long as expected
      if (result.byteLength == 0) {
         throw new Error(`Invalid ${what}, length: 0`);
      }

      this._offset += result.byteLength;
      return result;
   }

   get offset(): number {
      return this._offset;
   }

   get mac(): Uint8Array {
      return this.extract('mac', cc.MAC_BYTES);
   }

   get alg(): string {
      const algNum = bytesToNum(this.extract('alg', cc.ALG_BYTES));
      if (algNum < 1 || algNum > Object.keys(cc.AlgInfo).length) {
         throw new Error('Invalid alg id of: ' + algNum);
      }

      let alg: string;
      for (alg in cc.AlgInfo) {
         if (cc.AlgInfo[alg]['id'] == algNum) {
            this._ivBytes = Number(cc.AlgInfo[alg]['iv_bytes']);
            break;
         }
      }
      return alg!;
   }

   get iv(): Uint8Array {
      if (!this._ivBytes) {
         throw new Error('iv length undefined, get extractor.alg first');
      }
      return this.extract('iv', this._ivBytes);
   }

   get slt(): Uint8Array {
      return this.extract('slt', cc.SLT_BYTES);
   }

   get ic(): number {
      const ic = bytesToNum(this.extract('ic', cc.IC_BYTES));
      if (ic < cc.ICOUNT_MIN || ic > cc.ICOUNT_MAX) {
         throw new Error('Invalid ic of: ' + ic);
      }
      return ic;
   }

   get lp(): number {
      const lp = bytesToNum(this.extract('lp', cc.LP_BYTES));
      if (lp < 1 || lp > cc.LP_MAX) {
         throw new Error('Invalid lp of: ' + lp);
      }
      return lp;
   }

   get ver(): number {
      const ver = bytesToNum(this.extract('ver', cc.VER_BYTES));
      if (ver != cc.VERSION1 && ver != cc.VERSION4) {
         throw new Error('Invalid version of: ' + ver);
      }
      return ver;
   }

   // Return zero length Array if no hint
   get hint(): Uint8Array {
      const hintLen = bytesToNum(this.extract('hlen', cc.HINT_LEN_BYTES));
      const encryptedHint = this.extract('hint', hintLen);
      return encryptedHint;
   }

   get size(): number {
      const payloadSize = bytesToNum(this.extract('size', cc.PAYLOAD_SIZE_BYTES));
      if (payloadSize < cc.PAYLOAD_SIZE_MIN || payloadSize > cc.PAYLOAD_SIZE_MAX) {
         throw new Error('Invalid payload size: ' + payloadSize);
      }
      return payloadSize;
   }
}


class Packer {
   private _dest?: Uint8Array;
   private _offset: number;
   private _ivBytes?: number;

   constructor(maxSize: number, offset: number = 0) {
      this._dest = new Uint8Array(maxSize);
      this._offset = offset;
   }

   pack(what: string, data: Uint8Array) {
      if (!this._dest) {
         throw new Error('Packer was detached');
      }
      this._dest.set(data, this._offset);
      this._offset += data.byteLength;

      // happens if the encode data is not as long as expected
      if (this._offset > this._dest.byteLength) {
         throw new Error(`Invalid ${what}, length: ${data.byteLength}`);
      }
   }

   get offset(): number {
      return this._offset;
   }

   set offset(value: number) {
      if (!this._dest) {
         throw new Error('Packer was detached');
      }
      if (value > this._dest.byteLength) {
         throw new Error('Invalid offset: ' + value);
      }
      this._offset = value;
   }

   get buffer(): ArrayBuffer {
      if (!this._dest) {
         throw new Error('Packer was detached');
      }
      return this._dest.buffer;
   }

   trim(): Uint8Array {
      if (!this._dest) {
         throw new Error('Packer was detached');
      }
      return new Uint8Array(this._dest.buffer, this._dest.byteOffset, this._offset);
   }

   detach(): Uint8Array {
      if (!this._dest) {
         throw new Error('Packer was detached');
      }
      const result = this._dest;
      this._dest = undefined;
      return result;
   }

   set data(data: Uint8Array) {
      this.pack('data', data);
   }

   set mac(sig: Uint8Array) {
      if (sig.byteLength != cc.MAC_BYTES) {
         throw new Error('Invalid MAC length: ' + sig.byteLength);
      }
      this.pack('mac', sig);
   }

   set alg(algName: string) {
      if (!Ciphers.validateAlg(algName)) {
         throw new Error('Invalid alg name: ' + algName);
      }
      const algInfo = cc.AlgInfo[algName];
      this._ivBytes = Number(algInfo['iv_bytes']);
      this.pack('alg', numToBytes(Number(algInfo['id']), cc.ALG_BYTES));
   }

   set iv(iVect: Uint8Array) {
      if (!this._ivBytes) {
         throw new Error('IV length undefined, set packer.alg first');
      }
      if (this._ivBytes != iVect.byteLength) {
         throw new Error('Invalid IV length: ' + iVect.byteLength);
      }
      this.pack('iv', iVect);
   }

   set slt(salt: Uint8Array) {
      if (salt.byteLength != cc.SLT_BYTES) {
         throw new Error('Invalid salt length: ' + salt.byteLength);
      }
      this.pack('slt', salt);
   }

   set ic(iCount: number) {
      if (iCount < cc.ICOUNT_MIN || iCount > cc.ICOUNT_MAX) {
         throw new Error('Invalid ic of: ' + iCount);
      }
      this.pack('ic', numToBytes(iCount, cc.IC_BYTES));
   }

   set lp(lp: number) {
      if (lp < 1 || lp > cc.LP_MAX) {
         throw new Error('Invalid lp of: ' + lp);
      }
      this.pack('lp', numToBytes(lp, cc.LP_BYTES));
   }

   set ver(version: number) {
      if (version != cc.VERSION1 && version != cc.VERSION4) {
         throw new Error('Invalid version of: ' + version);
      }
      this.pack('ver', numToBytes(version, cc.VER_BYTES));
   }

   set hint(encHint: Uint8Array) {
      if (encHint.byteLength > cc.ENCRYPTED_HINT_MAX_BYTES) {
         throw new Error('Invalid hint length: ' + encHint.byteLength);
      }
      this.pack('hlen', numToBytes(encHint.byteLength, cc.HINT_LEN_BYTES));
      this.pack('hint', encHint);
   }

   set size(payloadSize: number) {
      if (payloadSize < cc.PAYLOAD_SIZE_MIN || payloadSize > cc.PAYLOAD_SIZE_MAX) {
         throw new Error('Invalid payload size: ' + payloadSize);
      }
      this.pack('size', numToBytes(payloadSize, cc.PAYLOAD_SIZE_BYTES));
   }
}
