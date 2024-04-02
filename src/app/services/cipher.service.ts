import { Injectable } from '@angular/core';
import sodium from 'libsodium-wrappers';
import { base64URLStringToBuffer, bufferToBase64URLString } from '@simplewebauthn/browser';

const AES_GCM_TAG_BYTES = 16;
const X20_PLY_TAG_BYTES = 16; // sodium.crypto_aead_xchacha20poly1305_IETF_ABYTES, is not ready yet
const AEGIS_256_TAG_BYTES = 32; // sodium.crypto_aead_aegis256_ABYTES, is not ready yet
const MAX_AUTH_TAG_BYTES = Math.max(X20_PLY_TAG_BYTES, AES_GCM_TAG_BYTES, AEGIS_256_TAG_BYTES);

export const ICOUNT_MIN = 400000;
export const ICOUNT_DEFAULT = 800000;
export const ICOUNT_MAX = 4294000000; // limited to 4 bytes unsigned rounded to millions
export const ENCRYPTED_HINT_MAX_LEN = 255;
// needs to fit into 255 bytes encypted... this allows for all double byte + max auth tag
export const HINT_MAX_LEN = Math.trunc(ENCRYPTED_HINT_MAX_LEN / 2 - MAX_AUTH_TAG_BYTES);
export const CURRENT_VERSION = 1;

export const AlgInfo: { [key: string]: { [key: string]: string | number } } = {
   'AES-GCM': { 'id': 1, 'description': 'AES 256 GCM', 'iv_bytes': 12 },
   'X20-PLY': { 'id': 2, 'description': 'XChaCha20 Poly1305', 'iv_bytes': 24 },
   'AEGIS-256': { 'id': 3, 'description': 'AEGIS 256', 'iv_bytes': 32 },
};

export type Params = {
   readonly alg: string;      // ALG_BYTES
   readonly ic: number;       // IC_BYTES
}


export type CipherData = Params & {
   readonly iv: Uint8Array;   // Variable, lookup in AlgInfo
   readonly slt: Uint8Array;  // SLT_BYTES
   readonly encryptedHint: Uint8Array;  // limited to ENCRYPTED_HINT_MAX_LEN bytes
   readonly encryptedData: Uint8Array;
};

export type EParams = Params & {
   readonly trueRand: boolean;
   readonly fallbackRand: boolean;
   readonly pwd: string;
   readonly userCred: Uint8Array;
   readonly clear: Uint8Array;
   readonly hint?: string;     // limited to HINT_MAX_LEN characters
}

export const ALG_BYTES = 2;
export const IV_BYTES_MIN = 12;
export const SLT_BYTES = 16;
export const IC_BYTES = 4;
export const VER_BYTES = 2;
export const HMAC_BYTES = 32;
export const KEY_BYTES = 32;
export const USERCRED_BYTES = 32;

// To geenrate matching keys, these must not change
const HKDF_INFO_SIGNING = "cipherdata signing key";
const HKDF_INFO_HINT = "hint encryption key";

/* Javascript converts to signed 32 bit int when using bit shifting
   and masking, so do this instead. Count is the number of bytes
   used to pack the number.  */
export function numToBytes(num: number, count: number): Uint8Array {
   if (count < 1 || num >= Math.pow(256, count)) {
      throw new Error("Invalid arguments");
   }
   let arr = new Uint8Array(count);
   for (let i = 0; i < count; ++i) {
      arr[i] = num % 256;
      num = Math.floor(num / 256);
   }
   return arr;
}

export function bytesToNum(arr: Uint8Array): number {
   let num = 0;
   for (let i = arr.length - 1; i >= 0; --i) {
      num = num * 256 + arr[i];
   }
   return num;
}

// Returns base64Url text
export function bytesToBase64(bytes: Uint8Array): string {
   // simplewebauthn function return base64Url format
   return (bufferToBase64URLString(bytes));
}

// Accepts either base64 or base64Url text
export function base64ToBytes(b64: string): Uint8Array {
   // simplewebauthn function accepts either as input to base64ToBytes
   return new Uint8Array(base64URLStringToBuffer(b64));
}

export class Random48 {
   private trueRandCache: Promise<Response>;

   constructor() {
      this.trueRandCache = this.downloadTrueRand();
   }

   async getRandomArray(
      trueRand: boolean = true,
      fallback: boolean = true
   ): Promise<Uint8Array> {
      if (!trueRand) {
         if (!fallback) {
            throw new Error('both trueRand and fallback disabled');
         }
         return crypto.getRandomValues(new Uint8Array(48));
      } else {
         const lastCache = this.trueRandCache;
         this.trueRandCache = this.downloadTrueRand();
         return lastCache.then((response) => {
            if (!response.ok) {
               throw new Error('random.org response: ' + response.statusText);
            }
            return response.arrayBuffer();
         }).then((array) => {
            if (array.byteLength != 48) {
               throw new Error('missing bytes from random.org');
            }
            return new Uint8Array(array!);
         }).catch((err) => {
            console.error(err);
            // If pseudo random fallback is disabled, then throw error
            if (!fallback) {
               throw new Error('no connection to random.org and no fallback: ' + err.message);
            }
            return crypto.getRandomValues(new Uint8Array(48));
         });
      }
   }

   async downloadTrueRand(): Promise<Response> {
      const url = 'https://www.random.org/cgi-bin/randbyte?nbytes=' + 48;
      try {
         const p = fetch(url, {
            cache: 'no-store',
         });
         return p;
      } catch (err) {
         // According to the docs, this should not happend but it seems to sometimes
         // (perfhaps just one nodejs, but not sure)
         console.error('wtf fetch, ', err);
         return Promise.reject();
      }
   }
}


@Injectable({
   providedIn: 'root'
})
export class CipherService {

   // cache in case any use of true random
   private random48Cache = new Random48();
   private icount: number = 0;
   private icountMax: number = 0;
   private hashRate: number = 0;

   constructor() {
   }

   async benchmark(
      test_size: number
   ): Promise<[number, number, number]> {

      if (!this.icount || !this.icountMax || !this.hashRate) {
         const target_hash_millis = 500;
         const max_hash_millis = 5 * 60 * 1000; //5 minutes

         const start = Date.now();
         await this._genCipherKey('AES-GCM', test_size, 'AVeryBogusPwd', crypto.getRandomValues(new Uint8Array(32)), new Uint8Array(SLT_BYTES));
         const test_millis = Date.now() - start;

         this.hashRate = test_size / test_millis;

         // Don't allow more then ~5 minutes of pwd hashing (rounded to millions)
         this.icountMax =
            Math.min(ICOUNT_MAX,
               Math.round((max_hash_millis * this.hashRate) / 1000000) * 1000000);

         let target_icount = Math.round((this.hashRate * target_hash_millis) / 100000) * 100000;
         this.icount = Math.max(ICOUNT_DEFAULT, target_icount + 200000);

         console.log(
            `bench: ${test_size}i, in: ${test_millis}ms, rate: ${Math.round(this.hashRate)}i/ms,
        ic: ${this.icount}i, icm: ${this.icountMax}i`
         );
      }

      return [this.icount, this.icountMax, this.hashRate];
   }


   // Public for testing, normal callers should not need this
   public async _genCipherKey(
      alg: string,
      ic: number,
      pwd: string,
      userCred: Uint8Array,
      slt: Uint8Array
   ): Promise<CryptoKey> {

      if (!Object.keys(AlgInfo).includes(alg)) {
         throw new Error('Invalid alg type of: ' + alg);
      }
      if (ic < ICOUNT_MIN || ic > ICOUNT_MAX) {
         throw new Error('Invalid ic of: ' + ic);
      }
      if (slt.byteLength != SLT_BYTES) {
         throw new Error("Invalid slt size of: " + slt.byteLength);
      }
      if (userCred.byteLength != USERCRED_BYTES) {
         throw new Error("Invalid userCred size of: " + userCred.byteLength);
      }
      if (!pwd) {
         throw new Error('Invalid empty password');
      }
      if (ic < ICOUNT_MIN || ic > ICOUNT_MAX) {
         throw new Error('Invalid ic of: ' + ic);
      }

      const pwdBytes = new TextEncoder().encode(pwd);
      let rawMaterial = new Uint8Array(pwdBytes.byteLength + USERCRED_BYTES)
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
   async _genSigningKey(
      userCred: Uint8Array,
      slt: Uint8Array
   ): Promise<CryptoKey> {

      if (slt.byteLength != SLT_BYTES) {
         throw new Error("Invalid slt size of: " + slt.byteLength);
      }

      if (userCred.byteLength != USERCRED_BYTES) {
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
   async _genHintCipherKey(
      alg: string,
      userCred: Uint8Array,
      slt: Uint8Array
   ): Promise<CryptoKey> {

      if (slt.byteLength != SLT_BYTES) {
         throw new Error("Invalid slt size of: " + slt.byteLength);
      }

      if (userCred.byteLength != USERCRED_BYTES) {
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

   // Overall order of operations:
   //
   // 1. Generate new salt and iv/nonce values
   // 2. Encode cipher parameters as additional data
   // 3. Generate signing key from userCred and cipher key from pwd + userCred
   // 4. Encrypt cleartext using cipher key (with addition data)
   // 5. Sign addtional data + cipher text with signing key
   // 6. Concat and return
   //
   async encrypt(
      eparams: EParams,
      readyNotice?: (params: Params) => void
   ): Promise<string> {

      if (!Object.keys(AlgInfo).includes(eparams.alg)) {
         throw new Error('Invalid alg type of: ' + eparams.alg);
      }
      if (eparams.ic < ICOUNT_MIN || eparams.ic > ICOUNT_MAX) {
         throw new Error('Invalid ic of: ' + eparams.ic);
      }
      if (!eparams.trueRand && !eparams.fallbackRand) {
         throw new Error('Either trueRand or fallbackRand must be true');
      }
      if (eparams.hint && eparams.hint.length > HINT_MAX_LEN) {
         throw new Error('Hint length exceeds ' + HINT_MAX_LEN);
      }
      if (!eparams.pwd || !eparams.userCred || eparams.userCred.byteLength != USERCRED_BYTES) {
         throw new Error('Invalid password or userCred');
      }

      // encrpting nothing not supported
      if (eparams.clear.byteLength == 0) {
         throw new Error('No data to encrypt');
      }

      // Setup EncContext for new key derivation (and encryption)
      // Create a new salt each time a key is derviced from the password.
      // https://crypto.stackexchange.com/questions/53032/salt-for-non-stored-passwords
      const randomArray = await this.random48Cache.getRandomArray(
         eparams.trueRand,
         eparams.fallbackRand
      );

      const iv_bytes = Number(AlgInfo[eparams.alg]['iv_bytes']);
      const slt = randomArray.slice(0, SLT_BYTES);
      const iv = randomArray.slice(SLT_BYTES, SLT_BYTES + iv_bytes);

      if (readyNotice) {
         readyNotice(eparams);
      }

      const hk = await this._genHintCipherKey(eparams.alg, eparams.userCred, slt);
      const sk = await this._genSigningKey(eparams.userCred, slt);
      const ek = await this._genCipherKey(eparams.alg, eparams.ic, eparams.pwd, eparams.userCred, slt);

      let encryptedHint = new Uint8Array(0);
      if (eparams.hint) {
         // Since hint encoding could expand beyond 255, truncate the result to ensure fit
         // TODO: This can cause � problems with truncated unicode codepoints or graphemes,
         // could truncate hint characters and re-encode (see https://tonsky.me/blog/unicode/)
         const hintEnc = new TextEncoder().encode(eparams.hint).slice(0, ENCRYPTED_HINT_MAX_LEN - MAX_AUTH_TAG_BYTES);
         encryptedHint = await this._doEncrypt(
            eparams.alg,
            hk,
            iv,
            hintEnc
         );
      }

      const cipherDataForAD: CipherData = {
         alg: eparams.alg,
         ic: eparams.ic,
         iv: iv,
         slt: slt,
         encryptedHint: encryptedHint,
         encryptedData: new Uint8Array(0)
      };

      const additionalData = this._encodeCipherData(cipherDataForAD);
      const encryptedBytes = await this._doEncrypt(
         eparams.alg,
         ek,
         iv,
         eparams.clear,
         additionalData,
      );

      const encoded = this._encodeCipherData({
         ...cipherDataForAD,
         encryptedData: encryptedBytes
      });

      const hmac = await this._signCipherBytes(sk, encoded);

      let extended = new Uint8Array(hmac.byteLength + encoded.byteLength);
      extended.set(hmac);
      extended.set(encoded, hmac.byteLength);

      return bytesToBase64(extended);
   }

   async _doEncrypt(
      alg: string,
      key: CryptoKey,
      iv: Uint8Array,
      clear: Uint8Array,
      additionalData: Uint8Array = new Uint8Array(0),
   ): Promise<Uint8Array> {

      const iv_bytes = Number(AlgInfo[alg]['iv_bytes']);
      if (iv_bytes != iv.byteLength) {
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
               additionalData,
               null,
               iv,
               keyBytes,
               "uint8array"
            );
         } catch (err) {
            console.log(err)
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
               additionalData,
               null,
               iv,
               keyBytes,
               "uint8array"
            );
         } catch (err) {
            console.log(err)
            // Match behavior of Web Crytpo functions that throws limited DOMException
            throw new DOMException('', 'OperationError');
         }
      } else {
         const cipherBuf = await crypto.subtle.encrypt(
            {
               name: alg,
               iv: iv,
               additionalData: additionalData,
               tagLength: AES_GCM_TAG_BYTES * 8
            },
            key,
            clear
         );
         encryptedBytes = new Uint8Array(cipherBuf);
      }
      return encryptedBytes;
   }


   // Password is a callback because we need to extract any hint from ciphertext first.
   // We also don't want the caller (web page) to show anything from extracted from
   // ciphertext until after it has been verified again the userCred (pass-key). Order
   // of operations is:
   //
   // 1. Unpack parameters from encrypted
   // 1.1.    Unpack validated values and checks userCred based signature
   // 2. Callback to get the password with the hint unpacked & validated hint
   // 3. Encode cipher parameters as additional data
   // 4. Generate cipher keys using returned pwd + userCred
   // 5. Decrypt encrypted text using cipher key and addtional data
   // 6. Return cleat text bytes
   //
   async decrypt(
      pwdProvider: (hint: string) => Promise<string>,
      userCred: Uint8Array,
      cipherText: string,
      readyNotice?: (params: Params) => void
   ): Promise<Uint8Array> {

      // getCipherData does HMAC signature verification on CT and throws if invalid
      const cipherData = await this.getCipherData(userCred, cipherText);
      const hk = await this._genHintCipherKey(cipherData.alg, userCred, cipherData.slt);

      let hintEnc = new Uint8Array(0);
      if (cipherData.encryptedHint.byteLength != 0) {
         hintEnc = await this._doDecrypt(
            cipherData.alg,
            hk,
            cipherData.iv,
            cipherData.encryptedHint
         );
      }

      const pwd = await pwdProvider(new TextDecoder().decode(hintEnc));
      if (!pwd) {
         throw new Error('password is empty');
      }

      if (readyNotice) {
         readyNotice(cipherData);
      }
      const ek = await this._genCipherKey(cipherData.alg, cipherData.ic, pwd, userCred, cipherData.slt);

      const cipherDataForAD: CipherData = {
         ...cipherData,
         encryptedData: new Uint8Array(0)
      };
      const additionalData = this._encodeCipherData(cipherDataForAD);

      const decrypted = await this._doDecrypt(
         cipherData.alg,
         ek,
         cipherData.iv,
         cipherData.encryptedData,
         additionalData,
      );

      return decrypted;
   }

   async _doDecrypt(
      alg: string,
      key: CryptoKey,
      iv: Uint8Array,
      encrypted: Uint8Array,
      additionalData: Uint8Array = new Uint8Array(0),
   ): Promise<Uint8Array> {

      let decrypted: Uint8Array;
      if (alg == 'X20-PLY') {
         const exported = await crypto.subtle.exportKey("raw", key);
         const keyBytes = new Uint8Array(exported);

         await sodium.ready;
         try {
            decrypted = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
               null,
               encrypted,
               additionalData,
               iv,
               keyBytes,
               "uint8array"
            );
         } catch (err) {
            console.log(err);
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
               additionalData,
               iv,
               keyBytes,
               "uint8array"
            );
         } catch (err) {
            console.log(err);
            // Match behavior of Web Crytpo functions that throws limited DOMException
            throw new DOMException('', 'OperationError');
         }
      } else {
         const buffer = await crypto.subtle.decrypt(
            {
               name: alg,
               iv: iv.slice(0, 12),
               additionalData: additionalData,
               tagLength: AES_GCM_TAG_BYTES * 8
            },
            key,
            encrypted
         );
         decrypted = new Uint8Array(buffer);
      }

      return decrypted;
   }

   async getCipherData(
      userCred: Uint8Array,
      cipherText: string
   ): Promise<CipherData> {

      if (userCred.byteLength != USERCRED_BYTES) {
         throw new Error('Invalid userCred length of: ' + userCred.byteLength);
      }

      const extended = base64ToBytes(cipherText);
      const hmac = extended.slice(0, HMAC_BYTES);

      if (hmac.byteLength != HMAC_BYTES) {
         throw new Error('Invalid HMAC length of: ' + hmac.byteLength);
      }
      const encoded = extended.slice(HMAC_BYTES);

      // This is not a crypto function, just unpacking. We need to unpack to
      // get the salt used for signing key generation.
      //
      // IMPORTANT: The returned cipherData could be corrupted. Do not return
      //       this to the caller until after signature verified.
      const cipherData = this._decodeCipherData(encoded);

      const sk = await this._genSigningKey(userCred, cipherData.slt);

      // Avoiding the Doom Principle and verify signature before crypto operations.
      // Aka, check HMAC as soon as possible after we have the signing key.
      // _verifyCipherBytes should throw an exception if invalid, but the boolean
      // return is a precaution... requires an explicit true result && no exception
      const validSig = await this._verifyCipherBytes(sk, hmac, encoded);

      if (validSig) {
         return cipherData;
      }

      // Should never get here since verify throws on bad signature
      throw new Error('Invalid HMAC signature');
   }

   // public for testing, callers should not need to use this directly
   async _signCipherBytes(
      sk: CryptoKey,
      encoded: Uint8Array
   ): Promise<Uint8Array> {

      const hmac = await crypto.subtle.sign('HMAC', sk, encoded);
      if (hmac.byteLength != HMAC_BYTES) {
         throw new Error('Invalid HMAC length of: ' + hmac.byteLength);
      }

      return new Uint8Array(hmac);
   }

   // public for testing, callers should not need to use this directly
   async _verifyCipherBytes(
      sk: CryptoKey,
      hmac: Uint8Array,
      encoded: Uint8Array
   ): Promise<boolean> {

      const valid = await crypto.subtle.verify('HMAC', sk, hmac, encoded);
      if (valid) {
         return true;
      }

      throw new Error('Invalid HMAC signature');
   }

   // Importers of CipherService should not need this function directly
   // but it is public for unit testing. Allows encoding with
   // zero length encrypted text
   _encodeCipherData(cipherData: CipherData): Uint8Array {

      this.validateCipherData(cipherData);

      const algInfo = AlgInfo[cipherData.alg];

      const icEnc = numToBytes(cipherData.ic, IC_BYTES);
      const verEnc = numToBytes(CURRENT_VERSION, VER_BYTES);
      const algEnc = numToBytes(Number(algInfo['id']), ALG_BYTES);
      const hintLenEnc = numToBytes(cipherData.encryptedHint.byteLength, 1);
      const iv_bytes = Number(algInfo['iv_bytes']);

      let encoded = new Uint8Array(
         ALG_BYTES +
         iv_bytes +
         SLT_BYTES +
         IC_BYTES +
         VER_BYTES +
         1 +
         cipherData.encryptedHint.byteLength +
         cipherData.encryptedData.byteLength
      );

      let offset = 0;
      encoded.set(algEnc, offset);
      offset += ALG_BYTES;
      encoded.set(cipherData.iv, offset);
      offset += iv_bytes;
      encoded.set(cipherData.slt, offset);
      offset += SLT_BYTES;
      encoded.set(icEnc, offset);
      offset += IC_BYTES;
      encoded.set(verEnc, offset);
      offset += VER_BYTES;
      encoded.set(hintLenEnc, offset);
      offset += 1;
      encoded.set(cipherData.encryptedHint, offset);
      offset += cipherData.encryptedHint.byteLength;
      encoded.set(cipherData.encryptedData, offset);

      return encoded;
   }

   // Importers of CipherService should not need this function directly,
   // but it is public for unit testing. Does not allow encoding
   // with zero length encrypted text since that is not needed
   _decodeCipherData(encoded: Uint8Array): CipherData {

      // Need to treat all values an UNTRUSTED since the signature has not
      // been tested (slt param extracted here is required for HMAC test)

      if (encoded.byteLength < ALG_BYTES + IV_BYTES_MIN + SLT_BYTES + IC_BYTES +
         VER_BYTES + 1 + 1) {
         throw new Error('Invalid cparam lengths');
      }

      // Using validCParams isn't applicable because we're reading fixed lengths,
      // and if some data was clipped (like say IV) we cannot tell until we do
      // the signature check (or if the data is clipped so much other values are
      // missing). Also want to check for errors as we unpack

      let offset = 0;

      // ### algorithm id ###
      const algNum = bytesToNum(encoded.slice(offset, offset + ALG_BYTES));
      offset += ALG_BYTES;
      if (algNum < 1 || algNum > Object.keys(AlgInfo).length) {
         throw new Error('Invalid alg id of: ' + algNum);
      }

      let alg: string;
      let iv_bytes: number;
      for (alg in AlgInfo) {
         if (AlgInfo[alg]['id'] == algNum) {
            iv_bytes = Number(AlgInfo[alg]['iv_bytes']);
            break;
         }
      }

      // ### iv ###
      const iv = encoded.slice(offset, offset + iv_bytes!);
      offset += iv_bytes!;
      // Should never happen because of overall length check abvoe,
      // but... defense in depth in case of an oversight
      if (iv.byteLength != iv_bytes!) {
         throw new Error('Invalid iv length: ' + iv.byteLength);
      }

      // ### salt ###
      const slt = encoded.slice(offset, offset + SLT_BYTES);
      offset += SLT_BYTES;
      if (slt.byteLength != SLT_BYTES) {
         throw new Error('Invalid slt length: ' + slt.byteLength);
      }

      // ### iter count ###
      const ic = bytesToNum(encoded.slice(offset, offset + IC_BYTES));
      offset += IC_BYTES;
      if (ic < ICOUNT_MIN || ic > ICOUNT_MAX) {
         throw new Error('Invalid ic of: ' + ic);
      }

      // ### version ###
      const ver = bytesToNum(encoded.slice(offset, offset + VER_BYTES));
      offset += VER_BYTES;
      // There has only ever been 1 version at this point
      if (ver != CURRENT_VERSION) {
         throw new Error('Invalid version of: ' + ver);
      }

      // ### hint ###
      const hintLen = bytesToNum(encoded.slice(offset, offset + 1));
      offset += 1;
      const encryptedHint = encoded.slice(offset, offset + hintLen)
      offset += hintLen;
      // Can happen if the encode data was clipped and reencoded
      if (hintLen != encryptedHint.byteLength) {
         throw new Error('Invalid hint length of: ' + hintLen);
      }

      // ### encrypted data ###
      const encryptedData = encoded.slice(offset);
      // Again, can happen if the encode data was clipped and reencoded
      if (encryptedData.byteLength == 0) {
         throw new Error('Missing et data, found only: ' + encryptedData.byteLength);
      }

      return {
         alg: alg!,
         iv: iv,
         slt: slt,
         ic: ic,
         encryptedHint: encryptedHint,
         encryptedData: encryptedData,
      };
   }

   // Only useful for validatin CParmas before encoding. Decoded values are read with
   // the correct sizes, so it depends on signature validate rather than decoded lengths
   validateCipherData(cipherData: CipherData) {
      //May want to make these message more helpful...
      if (!(cipherData.alg in AlgInfo)) {
         throw new Error('Invalid alg of: ' + cipherData.alg);
      }

      const iv_bytes = Number(AlgInfo[cipherData.alg]['iv_bytes']);
      if (cipherData.iv.byteLength != iv_bytes) {
         throw new Error('Invalid iv len of: ' + cipherData.iv.byteLength);
      }
      if (cipherData.slt.byteLength != SLT_BYTES) {
         throw new Error('Invalid slt len: ' + cipherData.slt.byteLength);
      }
      if (cipherData.ic < ICOUNT_MIN || cipherData.ic > ICOUNT_MAX) {
         throw new Error('Invalid ic of: ' + cipherData.ic);
      }
      if (cipherData.encryptedHint.length > ENCRYPTED_HINT_MAX_LEN) {
         throw new Error('Invalid encrypted hint length of: ' + cipherData.encryptedHint.length);
      }
   }

}
