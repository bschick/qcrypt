import { Injectable } from '@angular/core';
import sodium from 'libsodium-wrappers';
import { base64URLStringToBuffer, bufferToBase64URLString } from '@simplewebauthn/browser';
import { readStreamFill, readStreamUntil } from './streams';

const AES_GCM_TAG_BYTES = 16;
const X20_PLY_TAG_BYTES = 16; // sodium.crypto_aead_xchacha20poly1305_IETF_ABYTES, is not ready yet
const AEGIS_256_TAG_BYTES = 32; // sodium.crypto_aead_aegis256_ABYTES, is not ready yet
const AUTH_TAG_MAX_BYTES = Math.max(X20_PLY_TAG_BYTES, AES_GCM_TAG_BYTES, AEGIS_256_TAG_BYTES);
//const AUTH_TAG_MIN_BYTES = Math.min(X20_PLY_TAG_BYTES, AES_GCM_TAG_BYTES, AEGIS_256_TAG_BYTES);

export const ICOUNT_MIN = 400000;
export const ICOUNT_DEFAULT = 800000;
export const ICOUNT_MAX = 4294000000; // limited to 4 bytes unsigned rounded to millions
export const ENCRYPTED_HINT_MAX_BYTES = 255;
export const ENCRYPTED_HINT_MIN_BYTES = 0;
export const HINT_LEN_BYTES = 1;
// needs to fit into 255 bytes encypted... this allows for all double byte + max auth tag
export const HINT_MAX_LEN = Math.trunc(ENCRYPTED_HINT_MAX_BYTES / 2 - AUTH_TAG_MAX_BYTES);

// Change version number when the encoding format changes or we add a new
// cipher algorithm
export const CURRENT_VERSION = 4;
export const V1_BELOW = 4; // leave fixed at 4

export const AlgInfo: { [key: string]: { [key: string]: string | number } } = {
   'AES-GCM': { 'id': 1, 'description': 'AES 256 GCM', 'iv_bytes': 12 },
   'X20-PLY': { 'id': 2, 'description': 'XChaCha20 Poly1305', 'iv_bytes': 24 },
   'AEGIS-256': { 'id': 3, 'description': 'AEGIS 256', 'iv_bytes': 32 },
};

export const IV_MIN_BYTES = 12;
export const IV_MAX_BYTES = 32;

const CHUNK_SIZE_START = 1048576; // 1 MiB
const CHUNK_SIZE_MAX = CHUNK_SIZE_START * 16; // Most browsers won't even read this much at once
const CHUNK_SIZE_BYTES = 3;       // max 2^24 (aka 16 MiB)

export type EParams = {
   readonly alg: string;
   readonly ic: number;
   readonly trueRand: boolean;
   readonly fallbackRand: boolean;
   readonly pwd: string;
   readonly userCred: Uint8Array;
   readonly clear: ReadableStream<Uint8Array> | string;
   readonly hint?: string;     // limited to HINT_MAX_LEN characters
}

export type Params = {
   readonly alg: string;      // ALG_BYTES
   readonly ic: number;       // IC_BYTES
}

/*export type EParams = Params & {
   readonly trueRand: boolean;
   readonly fallbackRand: boolean;
   readonly pwd: string;
   readonly userCred: Uint8Array;
   readonly clear: Uint8Array;
   readonly hint?: string;     // limited to HINT_MAX_LEN characters
}*/

export type CipherData1 = Params & {
   readonly mac: Uint8Array;     // MAC_BYTES
   readonly iv: Uint8Array;   // Variable, lookup in AlgInfo
   readonly slt: Uint8Array;  // SLT_BYTES
   readonly ver: number;      // VER_BYTES
   readonly encryptedHint: Uint8Array;  // limited to ENCRYPTED_HINT_MAX_BYTES bytes
   readonly encryptedData: Uint8Array;
   readonly additionalData: Uint8Array;
};

export const ALG_BYTES = 2;
export const SLT_BYTES = 16;
export const IC_BYTES = 4;
export const VER_BYTES = 2;
export const MAC_BYTES = 32;
export const USERCRED_BYTES = 32;

export type EncodedCipherData = {
   readonly headerData: Uint8Array;
   readonly additionalData: Uint8Array;
   readonly encryptedData: Uint8Array;
   readonly sk: CryptoKey;
   readonly ek: CryptoKey;
}

export type CipherDataHeader = {
   readonly mac: Uint8Array;     // MAC_BYTES
   readonly ver: number;         // VER_BYTES
   readonly blockSize: number;   // CHUNK_SIZE_BYTES
}
const HEADER_BYTES = MAC_BYTES + VER_BYTES + CHUNK_SIZE_BYTES;

export type CipherDataBlockN = {
   readonly alg: string;      // ALG_BYTES
   readonly iv: Uint8Array;   // Variable, lookup in AlgInfo
   readonly encryptedData: Uint8Array;
   readonly additionalData: Uint8Array;
}

export type CipherDataBlock0 = CipherDataBlockN & {
   readonly ic: number;       // IC_BYTES
   readonly slt: Uint8Array;  // SLT_BYTES
   readonly encryptedHint: Uint8Array;  // limited to ENCRYPTED_HINT_MAX_BYTES bytes
}

type verifyMACFun = (
   sk: CryptoKey,
   cipherDataHeader: CipherDataHeader,
   additionalData: Uint8Array,
   encryptedData: Uint8Array
) => Promise<boolean>;


/*
export type CipherData4Block = {
   readonly ver: number;      // VER_BYTES
   readonly alg: string;      // ALG_BYTES
   readonly iv: Uint8Array;   // Variable, lookup in AlgInfo
   readonly encryptedData: Uint8Array;
};

export type CipherData4Header = CipherData4Block & {
   readonly ic: number;       // IC_BYTES
   readonly slt: Uint8Array;  // SLT_BYTES
   readonly encryptedHint: Uint8Array;  // limited to ENCRYPTED_HINT_MAX_BYTES bytes
};
*/

function isCurrentVersion(cipherData: CipherDataHeader | CipherData1): cipherData is CipherDataHeader {
   return cipherData.ver === CURRENT_VERSION;
}

// The following is not just the size of the CipherData4Block structs,
// this is the MAX byte expansion of the output of encryption compared
// to the byte size of the input
/*
export const OVERHEAD_MAX_BYTES = MAC_BYTES + VER_BYTES + ALG_BYTES +
   IV_MAX_BYTES + AUTH_TAG_MAX_BYTES + IC_BYTES + SLT_BYTES +
   CHUNK_SIZE_BYTES + HINT_LEN_BYTES + ENCRYPTED_HINT_MAX_BYTES;
*/

/*const OVERHEAD_MIN_BYTES = MAC_BYTES + VER_BYTES + ALG_BYTES +
   IV_MIN_BYTES + AUTH_TAG_MIN_BYTES + CHUNK_SIZE_BYTES;
*/

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

/*
function base64Transformer<I, R>(
   mapper: (value: I) => R
): TransformStream<I, R> {
   return new TransformStream<I, R>({
      transform(value, controller) {
         console.log('transform: ', value);
         controller.enqueue(mapper(value));
      },
   });
}

export function toBase64Transformer(): TransformStream<Uint8Array, string> {
   return base64Transformer(bytesToBase64);
}

export function toBytesTransformer(): TransformStream<string, Uint8Array> {
   return base64Transformer(base64ToBytes);
}*/

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
      console.log(`extracted ${len} bytes of ${what} at ${this._offset}: ${result}`);

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
      console.log(`remainder ${result.byteLength} bytes of ${what} at ${this._offset}: ${result}`);

      this._offset += result.byteLength;
      return result;
   }

   get offset(): number {
      return this._offset;
   }

   get mac(): Uint8Array {
      return this.extract('mac', MAC_BYTES);
   }

   get alg(): string {
      const algNum = bytesToNum(this.extract('alg', ALG_BYTES));
      if (algNum < 1 || algNum > Object.keys(AlgInfo).length) {
         throw new Error('Invalid alg id of: ' + algNum);
      }

      let alg: string;
      for (alg in AlgInfo) {
         if (AlgInfo[alg]['id'] == algNum) {
            this._ivBytes = Number(AlgInfo[alg]['iv_bytes']);
            break;
         }
      }
      return alg!;
   }

   get iv(): Uint8Array {
      if (!this._ivBytes) {
         throw new Error('iv length unknown, get extractor.alg first');
      }
      return this.extract('iv', this._ivBytes);
   }

   get slt(): Uint8Array {
      return this.extract('slt', SLT_BYTES);
   }

   get ic(): number {
      const ic = bytesToNum(this.extract('ic', IC_BYTES));
      if (ic < ICOUNT_MIN || ic > ICOUNT_MAX) {
         throw new Error('Invalid ic of: ' + ic);
      }
      return ic;
   }

   get ver(): number {
      const ver = bytesToNum(this.extract('ver', VER_BYTES));
      if (ver != 1 && ver != CURRENT_VERSION) {
         throw new Error('Invalid version of: ' + ver);
      }
      return ver;
   }

   get hint(): Uint8Array {
      const hintLen = bytesToNum(this.extract('hlen', HINT_LEN_BYTES));
      const encryptedHint = this.extract('hint', hintLen);
      return encryptedHint;
   }

   get size(): number {
      const size = bytesToNum(this.extract('size', CHUNK_SIZE_BYTES));
      if (size < 1) {
         throw new Error('Invalid chunk size: ' + size);
      }
      return size;
   }
}


@Injectable({
   providedIn: 'root'
})
export class CipherService {

   // cache in case any use of true random
   private _random48Cache = new Random48();
   private _icount: number = 0;
   private _icountMax: number = 0;
   private _hashRate: number = 0;

   constructor() {
   }

   get hashRate(): number {
      return this._hashRate;
   }

   async benchmark(
      test_size: number
   ): Promise<[number, number, number]> {

      if (!this._icount || !this._icountMax || !this._hashRate) {
         const target_hash_millis = 500;
         const max_hash_millis = 5 * 60 * 1000; //5 minutes

         const start = Date.now();
         await this._genCipherKey('AES-GCM', test_size, 'AVeryBogusPwd', crypto.getRandomValues(new Uint8Array(32)), new Uint8Array(SLT_BYTES));
         const test_millis = Date.now() - start;

         this._hashRate = test_size / test_millis;

         // Don't allow more then ~5 minutes of pwd hashing (rounded to millions)
         this._icountMax =
            Math.min(ICOUNT_MAX,
               Math.round((max_hash_millis * this._hashRate) / 1000000) * 1000000);

         let target_icount = Math.round((this._hashRate * target_hash_millis) / 100000) * 100000;
         // Add ICOUNT_MIN to calculated target because benchmark is done during
         // page load and tends to be too low.
         this._icount = Math.max(ICOUNT_DEFAULT, target_icount + ICOUNT_MIN);

         console.log(
            `bench: ${test_size}i, in: ${test_millis}ms, rate: ${Math.round(this._hashRate)}i/ms,
        ic: ${this._icount}i, icm: ${this._icountMax}i`
         );
      }

      return [this._icount, this._icountMax, this._hashRate];
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

   async encryptString(
      eparams: EParams,
      readyNotice?: (params: Params) => void
   ): Promise<string> {
      if (!(typeof eparams.clear === 'string')) {
         throw new Error('Clear type must be string');
      }
      this._validateEparams(eparams);

      const input = new TextEncoder().encode(eparams.clear);
      const cipherData = await this._encryptBlock0(
         eparams,
         input,
         readyNotice
      );

      const output = new Uint8Array(cipherData.headerData.byteLength +
         cipherData.additionalData.byteLength +
         cipherData.encryptedData.byteLength
      );

      output.set(cipherData.headerData);
      output.set(cipherData.additionalData, cipherData.headerData.byteLength);
      output.set(cipherData.encryptedData,
         cipherData.headerData.byteLength + cipherData.additionalData.byteLength);

      return bytesToBase64(output);
   }
   /*
      async encryptStream1(
         eparams: EParams,
         readyNotice?: (params: Params) => void
      ): Promise<string> {

         if (!(eparams.clear instanceof ReadableStream)) {
            throw new Error('Clear type must be ReadableStream');
         }
         this._validateEparams(eparams);

         const reader = eparams.clear.getReader({ mode: "byob" });
         const cipherSvc = this;
         let sk: CryptoKey;
         let ek: CryptoKey;
         let totalBytesOutput = 0;
         let chunkSize = CHUNK_SIZE_START;

         console.log('encryptToBytes returning');

         // Header reading uses a smaller buffer since this is often likely the only
         // read for pasted text.
         const output = new Uint8Array(chunkSize);

         let input = new ArrayBuffer(output.byteLength - OVERHEAD_MAX_BYTES);
         let inputBytes: number;
         let bytesWritten: number;

         try {
            inputBytes = await readStreamBYOB(reader, new Uint8Array(input));
         } finally {
            reader.releaseLock();
         }

         [bytesWritten, ek, sk] = await cipherSvc._encryptHeader(
            eparams,
            new Uint8Array(input, 0, inputBytes),
            output,
            readyNotice
         );

         return bytesToBase64(new Uint8Array(output.buffer, 0, bytesWritten));
      }
   */
   encryptStream(
      eparams: EParams,
      readyNotice?: (params: Params) => void
   ): ReadableStream<Uint8Array> {

      if (!(eparams.clear instanceof ReadableStream)) {
         throw new Error('Clear type must be ReadableStream');
      }
      this._validateEparams(eparams);

      const reader = eparams.clear.getReader({ mode: "byob" });
      const cipherSvc = this;
      let sk: CryptoKey;
      let ek: CryptoKey;
      let totalBytesOutput = 0;
      let chunkSize = CHUNK_SIZE_START;

      console.log('encryptToBytes returning');

      return new ReadableStream({
         type: 'bytes',

         async start(controller) {
            console.log(`start(): ${controller.constructor.name}.byobRequest = ${controller.byobRequest}`);

            try {
               let done = false;
               let clearBuffer = new Uint8Array(chunkSize);

               [clearBuffer, done] = await readStreamUntil(reader, clearBuffer);
               console.log('start(): chunkSize, readBytes', chunkSize, clearBuffer.byteLength);

               if(clearBuffer.byteLength) {
                  const cipherData = await cipherSvc._encryptBlock0(
                     eparams,
                     clearBuffer,
                     readyNotice
                  );

                  sk = cipherData.sk;
                  ek = cipherData.ek;

                  // for debugging, but needs to happen first because they get deteached
                  totalBytesOutput += (cipherData.headerData.byteLength + cipherData.encryptedData.byteLength + cipherData.additionalData.byteLength);
                  controller.enqueue(cipherData.headerData);
                  controller.enqueue(cipherData.additionalData);
                  controller.enqueue(cipherData.encryptedData);

                  console.log('start(): total enqueued: ' + totalBytesOutput);
               }

               if(done) {
                  console.log('start(): closing');
                  controller.close();
                  reader.releaseLock();
               }
            } catch (err) {
               console.error(err);
               controller.close();
               reader.releaseLock();
               // TODO: Need a way to report error back to parent
            }
         },

         async pull(controller) {
            console.log(`pull(): ${controller.constructor.name}.byobRequest = ${controller.byobRequest}`);

            chunkSize = Math.min(chunkSize * 2, CHUNK_SIZE_MAX);

            try {
               let done = false;
               let clearBuffer = new Uint8Array(chunkSize);

               [clearBuffer, done] = await readStreamUntil(reader, clearBuffer);
               console.log('pull(): chunkSize, readBytes', chunkSize, clearBuffer.byteLength);

               if(clearBuffer.byteLength) {
                  const cipherData = await cipherSvc._encryptBlockN(
                     eparams,
                     clearBuffer,
                     ek, sk
                  );

                  // for debugging, but needs to happen first because they get deteached
                  totalBytesOutput += (cipherData.headerData.byteLength + cipherData.encryptedData.byteLength + cipherData.additionalData.byteLength);
                  controller.enqueue(cipherData.headerData);
                  controller.enqueue(cipherData.additionalData);
                  controller.enqueue(cipherData.encryptedData);

                  console.log('pull(): total enqueued: ' + totalBytesOutput);
               }

               if(done) {
                  console.log('pull(): closing');
                  controller.close();
                  reader.releaseLock();
               }
            } catch (err) {
               console.error(err);
               controller.close();
               reader.releaseLock();
               // TODO: Need a way to report error back to parent
            }
         }

      });
   }

   _validateEparams(eparams: EParams) {
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
   }

   // Overall order of operations for encryption (TODO: Update comment)
   //
   // 1. Generate new salt and iv/nonce values
   // 2. Encode cipher parameters as additional data
   // 3. Generate signing key from userCred and cipher key from pwd + userCred
   // 4. Encrypt cleartext using cipher key (with addition data)
   // 5. Sign addtional data + cipher text with signing key
   // 6. Concat and return
   //
   async _encryptBlock0(
      eparams: EParams,
      input: Uint8Array,
      readyNotice?: (params: Params) => void
   ): Promise<EncodedCipherData> {

      console.log('_encryptBlock0 input bytes: ' + input.byteLength);

      if (input.byteLength == 0) {
         throw new Error('No data to encrypt');
      }

      // Create a new salt and IV each time a key is derviced from the password.
      // https://crypto.stackexchange.com/questions/53032/salt-for-non-stored-passwords
      const randomArray = await this._random48Cache.getRandomArray(
         eparams.trueRand,
         eparams.fallbackRand
      );

      const ivBytes = Number(AlgInfo[eparams.alg]['iv_bytes']);
      const slt = randomArray.slice(0, SLT_BYTES);
      const iv = randomArray.slice(SLT_BYTES, SLT_BYTES + ivBytes);

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
         const hintEnc = new TextEncoder()
            .encode(eparams.hint)
            .slice(0, ENCRYPTED_HINT_MAX_BYTES - AUTH_TAG_MAX_BYTES);

         encryptedHint = await this._doEncrypt(
            eparams.alg,
            hk,
            iv,
            hintEnc
         );
      }

      const ad = {
         alg: eparams.alg,
         ic: eparams.ic,
         iv: iv,
         slt: slt,
         encryptedHint: encryptedHint
      };

      const additionalData = this._encodeAdditionalData(CURRENT_VERSION, ad);

      const cipherData = await this._buildCipherData(
         eparams.alg,
         ek,
         sk,
         iv,
         input,
         additionalData,
      );

      return cipherData;
   }


   async _encryptBlockN(
      eparams: EParams,
      input: Uint8Array,
      ek: CryptoKey,
      sk: CryptoKey
   ): Promise<EncodedCipherData> {

      console.log('_encryptBlockN input bytes: ' + input.byteLength);

      if (input.byteLength == 0) {
         throw new Error('No data to encrypt');
      }

      const randomArray = await this._random48Cache.getRandomArray(
         eparams.trueRand,
         eparams.fallbackRand
      );

      const ivBytes = Number(AlgInfo[eparams.alg]['iv_bytes']);
      const iv = randomArray.slice(0, ivBytes);

      const ad = {
         alg: eparams.alg,
         iv: iv
      };

      const additionalData = this._encodeAdditionalData(CURRENT_VERSION, ad);

      const cipherData = await this._buildCipherData(
         eparams.alg,
         ek,
         sk,
         iv,
         input,
         additionalData,
      );

      return cipherData;
   }

   async _buildCipherData(
      alg: string,
      ek: CryptoKey,
      sk: CryptoKey,
      iv: Uint8Array,
      clear: Uint8Array,
      additionalData: Uint8Array,
   ): Promise<EncodedCipherData> {

      const encryptedData = await this._doEncrypt(
         alg,
         ek,
         iv,
         clear,
         additionalData,
      );
      console.log('_buildCipherData encrypted bytes: ' + encryptedData.byteLength);

      const dataBytes = encryptedData.byteLength + additionalData.byteLength;
      const encDataBytes = numToBytes(dataBytes, CHUNK_SIZE_BYTES);

      const encVer = numToBytes(CURRENT_VERSION, VER_BYTES);

      // pack part of the header first to be sure we sign what we return
      const headerData = new Uint8Array(MAC_BYTES + VER_BYTES + CHUNK_SIZE_BYTES);
      headerData.set(encVer, MAC_BYTES);
      headerData.set(encDataBytes, MAC_BYTES + VER_BYTES);

      const exportedSk = await crypto.subtle.exportKey("raw", sk);
      const skData = new Uint8Array(exportedSk);
      console.log('sign sk: ' + skData);
      const state = sodium.crypto_generichash_init(skData, MAC_BYTES);

      console.log('sign header: ' + new Uint8Array(headerData.buffer, MAC_BYTES));
      sodium.crypto_generichash_update(state, new Uint8Array(headerData.buffer, MAC_BYTES));
      console.log('sign addition: ' + additionalData);
      sodium.crypto_generichash_update(state, additionalData);
      console.log('sign encdata: ' + encryptedData);
      sodium.crypto_generichash_update(state, encryptedData);

      const mac = sodium.crypto_generichash_final(state, MAC_BYTES);
      headerData.set(mac);

      return {
         headerData: headerData,
         encryptedData: encryptedData,
         additionalData: additionalData,
         sk: sk,
         ek: ek
      }
   }


   /*   async encrypt(
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

         // Create a new salt each time a key is derviced from the password.
         // https://crypto.stackexchange.com/questions/53032/salt-for-non-stored-passwords
         const randomArray = await this._random48Cache.getRandomArray(
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
            const hintEnc = new TextEncoder()
               .encode(eparams.hint)
               .slice(0, ENCRYPTED_HINT_MAX_BYTES - AUTH_TAG_MAX_BYTES);

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
   */

   async _doEncrypt(
      alg: string,
      key: CryptoKey,
      iv: Uint8Array,
      clear: Uint8Array,
      additionalData: Uint8Array = new Uint8Array(0),
   ): Promise<Uint8Array> {

      //      console.log('doencrpt clear:' + clear.byteLength);

      const ivBytes = Number(AlgInfo[alg]['iv_bytes']);
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
         const cipherBuf = await crypto.subtle.encrypt({
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
      console.log('_doEncrypt result: ', encryptedBytes);
      return encryptedBytes;
   }
/*
   async getCipherDataBlock0(
      userCred: Uint8Array,
      cipherData: Uint8Array
   ) : Promise<CipherDataBlock0> {

      const cipherDataHeader = this._decodeCipherDataHeader(cipherData);

      const ad = {
         alg: alg,
         ic: ic,
         iv: iv,
         slt: slt,
         encryptedHint: encryptedHint
      };
      const additionalData = this._encodeAdditionalData(cipherDataHeader.ver, ad);

      const valid: boolean = verifyMAC
   }
      */

   async decryptString(
      pwdProvider: (hint: string) => Promise<string>,
      userCred: Uint8Array,
      cipherText: string,
      readyNotice?: (params: Params) => void
   ): Promise<string> {

      const cipherData = base64ToBytes(cipherText);

      let decrypted: Uint8Array;
      const cipherDataHeader = await this._decodeCipherDataHeader(userCred, cipherData);
      if (isCurrentVersion(cipherDataHeader)) {
         [decrypted] = await this._decryptBlock0(
            pwdProvider,
            userCred,
            cipherDataHeader,
            new Uint8Array(cipherData.buffer, cipherData.byteLength - cipherDataHeader.blockSize),
            readyNotice
         );
      } else {
         [decrypted] = await this._decryptCipherData1(
            pwdProvider,
            userCred,
            cipherDataHeader,
            readyNotice
         );
      }

      return new TextDecoder().decode(decrypted);
   }

   /*
   async decryptStream1(
      pwdProvider: (hint: string) => Promise<string>,
      userCred: Uint8Array,
      cipherStream: ReadableStream<Uint8Array>,
      readyNotice?: (params: Params) => void
   ): Promise<string> {

      const reader = cipherStream.getReader({ mode: "byob" });
      const cipherSvc = this;
      let sk: CryptoKey;
      let ek: CryptoKey;
      let totalBytesOutput = 0;
      let chunkSize = CHUNK_SIZE_START;

      // Header reading uses a smaller buffer since this is often likely the only
      // read for pasted text.
      const output = new Uint8Array(chunkSize);

      let input = new ArrayBuffer(output.byteLength);
      let inputBytes: number;

      try {
         inputBytes = await readStreamUntil(reader, new Uint8Array(input));
      } finally {
         reader.releaseLock();
      }

      const [decrypted] = await this._decryptHeader(
         pwdProvider,
         userCred,
         new Uint8Array(input),
         readyNotice
      );

      return new TextDecoder().decode(decrypted);
   }
*/

   decryptStream(
      pwdProvider: (hint: string) => Promise<string>,
      userCred: Uint8Array,
      cipherStream: ReadableStream<Uint8Array>,
      readyNotice?: (params: Params) => void
   ): ReadableStream<Uint8Array> {

      const reader = cipherStream.getReader({ mode: "byob" });
      const cipherSvc = this;
      let sk: CryptoKey;
      let ek: CryptoKey;
      let totalBytesOutput = 0;

      console.log('decryptStream returning');

      return new ReadableStream({
         type: 'bytes',

         async start(controller) {
            console.log(`start(): ${controller.constructor.name}.byobRequest = ${controller.byobRequest}`);

            try {
               let readBytes: number;
               let headerData = new Uint8Array(HEADER_BYTES);
               [headerData] = await readStreamFill(reader, headerData);
               console.log('start(): HEADER_BYTES, readBytes, headerData', HEADER_BYTES, headerData);

               const cipherDataHeader = await cipherSvc._decodeCipherDataHeader(userCred, headerData);
               if (!isCurrentVersion(cipherDataHeader)) {
                  throw new Error('stream expects current version')
               }

               let blockData = new Uint8Array(cipherDataHeader.blockSize);
               [blockData] = await readStreamFill(reader, blockData);
               console.log('start(): blockSize, readBytes, blockData', cipherDataHeader.blockSize, blockData);

               let decrypted: Uint8Array;
               [decrypted, ek, sk] = await cipherSvc._decryptBlock0(
                  pwdProvider,
                  userCred,
                  cipherDataHeader,
                  blockData,
                  readyNotice
               );

               totalBytesOutput += decrypted.byteLength;
               controller.enqueue(decrypted);
               console.log('start(): total enqueued', totalBytesOutput);
            } catch (err) {
               console.error(err);
               controller.close();
               reader.releaseLock();
               // TODO: Need a way to report error back to parent
            }
         },

         async pull(controller) {
            console.log(`pull(): ${controller.constructor.name}.byobRequest = ${controller.byobRequest}`);

            try {
               let readBytes: number;
               let headerData = new Uint8Array(HEADER_BYTES);
               try {
                  [headerData] = await readStreamFill(reader, headerData);
                  console.log('pull(): HEADER_BYTES, readBytes, headerData', HEADER_BYTES, headerData);
               } catch(err) {
                  // don't report as an error since if the file being done
                  console.log('pull(): closing');
                  controller.close();
                  reader.releaseLock();
                  return;
               }

               const cipherDataHeader = await cipherSvc._decodeCipherDataHeader(userCred, headerData);
               if (!isCurrentVersion(cipherDataHeader)) {
                  throw new Error('stream expects current version')
               }

               let blockData = new Uint8Array(cipherDataHeader.blockSize);
               [blockData] = await readStreamFill(reader, blockData);
               console.log('pull(): blockSize, readBytes, blockData', cipherDataHeader.blockSize, blockData);

               let decrypted: Uint8Array;
               decrypted = await cipherSvc._decryptBlockN(
                  cipherDataHeader,
                  blockData,
                  ek, sk
               );

               totalBytesOutput += decrypted.byteLength;
               controller.enqueue(decrypted);
               console.log('pull(): total enqueued', totalBytesOutput);
            } catch (err) {
               console.error(err);
               controller.close();
               reader.releaseLock();
               // TODO: Need a way to report error back to parent
            }
         }

      });
   }

   /*
      async getCipherDataHeader(
         userCred: Uint8Array,
         input: Uint8Array,
      ): Promise<[CipherData4Header, CryptoKey, number]> {

         if (userCred.byteLength != USERCRED_BYTES) {
            throw new Error('Invalid userCred length of: ' + userCred.byteLength);
         }
         console.log('getCipherDataHeader', input);


         // Putting the HMAC first (ahead of version) was a mistake, but as long we the length
         // isn't changed, its not a problem. If we ever want to use a longer HMAC a simple
         // solution would be to keep the first 256bits at the start and append the rest to the
         // and of encoded cipher data
         const hmac = new Uint8Array(input.buffer, 0, MAC_BYTES);
         const data = new Uint8Array(input.buffer, MAC_BYTES);

   //      console.log('getCipherData hmac', hmac.byteLength, hmac);
     //    console.log('getCipherData data', data.byteLength, data);

         if (hmac.byteLength != MAC_BYTES) {
            throw new Error('Invalid header HMAC length of: ' + hmac.byteLength);
         }

         // This is not a crypto function, just unpacking. We need to unpack to
         // get the salt used for signing key generation.
         //
         // IMPORTANT: The returned cipherData could be corrupted. Do not return
         //       this to the caller until after signature verified.
         const [cipherData, read] = this._decodeCipherHeader(data);

         const sk = await this._genSigningKey(userCred, cipherData.slt);

         // Avoiding the Doom Principle and verify signature before crypto operations.
         // Aka, check HMAC as soon as possible after we have the signing key.
         // _verifyCipherData should throw an exception if invalid, but the boolean
         // return is a precaution... requires an explicit true result && no exception
   //      console.log(sk);
         const validSig = await this._verifyCipherData(sk, hmac, data);

         if (validSig) {
            return [cipherData, sk, read + MAC_BYTES];
         }

         // Should never get here since verify throws on bad signature
         throw new Error('Invalid header HMAC signature');
      }
   */

   async _decryptBlock0(
      pwdProvider: (hint: string) => Promise<string>,
      userCred: Uint8Array,
      cipherDataHeader: CipherDataHeader,
      blockData: Uint8Array,
      readyNotice?: (params: Params) => void
   ): Promise<[decrypted: Uint8Array, ek: CryptoKey, sk: CryptoKey]> {

      const [cipherBlock0, sk] = await this._decodeCipherDataBlock0(
         cipherDataHeader,
         userCred,
         this._verifyMAC,
         blockData);

      return this._decryptBlock0Common(
         pwdProvider,
         sk, userCred,
         cipherDataHeader,
         cipherBlock0,
         readyNotice
      );
   }

   async _decryptCipherData1(
      pwdProvider: (hint: string) => Promise<string>,
      userCred: Uint8Array,
      cipherData: CipherData1,
      readyNotice?: (params: Params) => void
   ): Promise<[decrypted: Uint8Array, ek: CryptoKey, sk: CryptoKey]> {

      const cipherDataHeader: CipherDataHeader = {
         ...cipherData,
         blockSize: 0
      };
      const cipherBlock0: CipherDataBlock0 = {
         ...cipherData,
      }

      // TODO, just for now until class resturcutre
      const sk = await this._genSigningKey(userCred, cipherData.slt);

      return this._decryptBlock0Common(
         pwdProvider,
         sk, userCred,
         cipherDataHeader,
         cipherBlock0,
         readyNotice
      );
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
   async _decryptBlock0Common(
      pwdProvider: (hint: string) => Promise<string>,
      sk: CryptoKey,
      userCred: Uint8Array,
      cipherDataHeader: CipherDataHeader,
      cipherBlock0: CipherDataBlock0,
      readyNotice?: (params: Params) => void
   ): Promise<[decrypted: Uint8Array, ek: CryptoKey, sk: CryptoKey]> {

      if (userCred.byteLength != USERCRED_BYTES) {
         throw new Error('Invalid userCred length of: ' + userCred.byteLength);
      }

      let hintEnc = new Uint8Array(0);
      if (cipherBlock0.encryptedHint.byteLength != 0) {
         const hk = await this._genHintCipherKey(cipherBlock0.alg, userCred, cipherBlock0.slt);
         hintEnc = await this._doDecrypt(
            cipherBlock0.alg,
            hk,
            cipherBlock0.iv,
            cipherBlock0.encryptedHint
         );
      }

      const pwd = await pwdProvider(new TextDecoder().decode(hintEnc));
      if (!pwd) {
         throw new Error('password is empty');
      }

      if (readyNotice) {
         readyNotice(cipherBlock0);
      }

      const ek = await this._genCipherKey(cipherBlock0.alg, cipherBlock0.ic, pwd, userCred, cipherBlock0.slt);

      const decrypted = await this._doDecrypt(
         cipherBlock0.alg,
         ek,
         cipherBlock0.iv,
         cipherBlock0.encryptedData,
         cipherBlock0.additionalData,
      );

      console.log('_decryptCommon output bytes: ' + decrypted.byteLength);

      return [decrypted, ek, sk];
   }

   async _decryptBlockN(
      cipherDataHeader: CipherDataHeader,
      blockData: Uint8Array,
      ek: CryptoKey,
      sk: CryptoKey
   ): Promise<Uint8Array> {

      console.log('_decryptBlockN block bytes', blockData.byteLength);

      const cipherDataBlockN = await this._decodeCipherDataBlockN(
         cipherDataHeader,
         sk, this._verifyMAC,
         blockData);

      const decrypted = await this._doDecrypt(
         cipherDataBlockN.alg,
         ek,
         cipherDataBlockN.iv,
         cipherDataBlockN.encryptedData,
         cipherDataBlockN.additionalData,
      );

      console.log('_decryptBlockN output bytes: ' + decrypted.byteLength);

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
         const buffer = await crypto.subtle.decrypt({
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

   /*
      async getCipherDataBlock(
         input: Uint8Array,
         sk: CryptoKey,
      ): Promise<[CipherData4Block, number]> {

         // Putting the HMAC first (ahead of version) was a mistake, but as long we the length
         // isn't changed, its not a problem. If we ever want to use a longer HMAC a simple
         // solution would be to keep the first 256bits at the start and append the rest to the
         // and of encoded cipher data
         const hmac = new Uint8Array(input.buffer, 0, MAC_BYTES);
         const data = new Uint8Array(input.buffer, MAC_BYTES);

         if (hmac.byteLength != MAC_BYTES) {
            throw new Error('Invalid block HMAC length of: ' + hmac.byteLength);
         }

         // This is not a crypto function, just unpacking. We need to unpack to
         // get the salt used for signing key generation.
         //
         // IMPORTANT: The returned cipherData could be corrupted. Do not return
         //       this to the caller until after signature verified.
         const [cipherData, read] = this._decodeCipherData4Block(data);

         // Avoiding the Doom Principle and verify signature before crypto operations.
         // Aka, check HMAC as soon as possible after we have the signing key.
         // _verifyCipherData should throw an exception if invalid, but the boolean
         // return is a precaution... requires an explicit true result && no exception
   //      console.log(sk);
         const validSig = await this._verifyCipherData(sk, hmac, data);

         if (validSig) {
            return [cipherData, read + MAC_BYTES];
         }

         // Should never get here since verify throws on bad signature
         throw new Error('Invalid block HMAC signature');
      }
   */

   /*
   async getCipherData(
      userCred: Uint8Array,
      cipherText: string
   ): Promise<CipherData1> {

      if (userCred.byteLength != USERCRED_BYTES) {
         throw new Error('Invalid userCred length of: ' + userCred.byteLength);
      }

      const extended = base64ToBytes(cipherText);
      const hmac = extended.slice(0, MAC_BYTES);

      if (hmac.byteLength != MAC_BYTES) {
         throw new Error('Invalid HMAC length of: ' + hmac.byteLength);
      }
      const encoded = extended.slice(MAC_BYTES);

      // This is not a crypto function, just unpacking. We need to unpack to
      // get the salt used for signing key generation.
      //
      // IMPORTANT: The returned cipherData could be corrupted. Do not return
      //       this to the caller until after signature verified.
      const cipherData = this._decodeCipherData1(encoded);

      const sk = await this._genSigningKey(userCred, cipherData.slt);

      // Avoiding the Doom Principle and verify signature before crypto operations.
      // Aka, check HMAC as soon as possible after we have the signing key.
      // _verifyCipherData should throw an exception if invalid, but the boolean
      // return is a precaution... requires an explicit true result && no exception
      const validSig = await this._verifyCipherData(sk, hmac, encoded);

      if (validSig) {
         return cipherData;
      }

      // Should never get here since verify throws on bad signature
      throw new Error('Invalid HMAC signature');
   }
*/

   // public for testing, callers should not need to use this directly
   /*
   async _signCipherData(
      sk: CryptoKey,
      data: Uint8Array,
      hmacDest: Uint8Array
   ) {
      if (hmacDest.byteLength != MAC_BYTES) {
         throw new Error('Invalid hmac dest length: ' + hmacDest.byteLength);
      }
      const hmac = await crypto.subtle.sign('HMAC', sk, data);
      if (hmac.byteLength != MAC_BYTES) {
         throw new Error('Invalid HMAC length: ' + hmac.byteLength);
      }

      hmacDest.set(new Uint8Array(hmac));
   }
*/
   // public for testing, callers should not need to use this directly
   async _verifyMAC(
      sk: CryptoKey,
      cipherDataHeader: CipherDataHeader,
      additionalData: Uint8Array,
      encryptedData: Uint8Array
   ): Promise<boolean> {

      const encSizeBytes = numToBytes(cipherDataHeader.blockSize, CHUNK_SIZE_BYTES);
      const encVer = numToBytes(cipherDataHeader.ver, VER_BYTES);

      const headerData = new Uint8Array(VER_BYTES + CHUNK_SIZE_BYTES);
      headerData.set(encVer);
      headerData.set(encSizeBytes, VER_BYTES);

      const exportedSk = await crypto.subtle.exportKey("raw", sk);
      const skData = new Uint8Array(exportedSk);
      console.log('verify sk: ' + skData);
      const state = sodium.crypto_generichash_init(skData, MAC_BYTES);

      console.log('verify header: ' + headerData);
      sodium.crypto_generichash_update(state, headerData);
      console.log('verify addition: ' + additionalData);
      sodium.crypto_generichash_update(state, additionalData);
      console.log('verify encdata: ' + encryptedData);
      sodium.crypto_generichash_update(state, encryptedData);

      const testMac = sodium.crypto_generichash_final(state, MAC_BYTES);
      const valid: boolean = sodium.memcmp(cipherDataHeader.mac, testMac);
      console.log('verify result: ' + valid);
      if (valid) {
         return true;
      }

      throw new Error('Invalid MAC signature');
   }

   // public for testing, callers should not need to use this directly
   async _verifyHMAC1(
      sk: CryptoKey,
      cipherDataHeader: CipherDataHeader,
      additionalData: Uint8Array,
      encryptedData: Uint8Array
   ): Promise<boolean> {
      // Original version used SubtleCrypto HMAC
      const data = new Uint8Array(additionalData.byteLength + encryptedData.byteLength);
      data.set(additionalData);
      data.set(encryptedData, additionalData.byteLength);

      const valid: boolean = await crypto.subtle.verify('HMAC', sk, cipherDataHeader.mac, data);
      if (valid) {
         return true;
      }

      throw new Error('Invalid HMAC signature');
   }

   /*
   // public for testing, callers should not need to use this directly
   async _verifyCipherData(
      sk: CryptoKey,
      cipherDataHeader: CipherDataHeader,
      cipherDataBlock0: CipherDataBlock0
   ): Promise<boolean> {

//      console.log('_verifyCipherData', hmac.byteLength, hmac);
  //    console.log('_verifyCipherData', data.byteLength, data);

      const valid = await crypto.subtle.verify('HMAC', sk, hmac, data);
      if (valid) {
         return true;
      }

      throw new Error('Invalid HMAC signature');
   }
*/

   // Importers of CipherService should not need this function directly
   // but it is public for unit testing. Allows encoding with
   // zero length encrypted text
   //
   // Validates values and packs them into an Uint8Array
   _encodeAdditionalData(
      ver: number,
      args: {
         alg: string;
         iv: Uint8Array;
         ic?: number;
         slt?: Uint8Array;
         encryptedHint?: Uint8Array
      }): Uint8Array {

      this.validateCipherParams({ ...args, ver });

      const maxBytes = VER_BYTES + IV_MAX_BYTES + ALG_BYTES + IC_BYTES + SLT_BYTES + ENCRYPTED_HINT_MAX_BYTES;
      const buffer = new Uint8Array(maxBytes);

      let offset = 0;
      let extend = (data: Uint8Array) => {
         buffer.set(data, offset);
         offset += data.byteLength;
      }

      // If order, size, and encodings below changes, decoding must change and be versioned

      const algInfo = AlgInfo[args.alg];
      extend(numToBytes(Number(algInfo['id']), ALG_BYTES));
      extend(args.iv);

      if (args.slt) {
         extend(args.slt);
      }

      if (args.ic) {
         extend(numToBytes(args.ic, IC_BYTES));
      }

      // only V1 included version in additionalData
      if (ver < V1_BELOW) {
         extend(numToBytes(ver, VER_BYTES));
      }

      if(args.encryptedHint != undefined) {
         extend(numToBytes(args.encryptedHint.byteLength, HINT_LEN_BYTES));
         extend(args.encryptedHint);
      }

      return new Uint8Array(buffer.buffer, 0, offset);
   }


   /*
      // Importers of CipherService should not need this function directly
      // but it is public for unit testing. Allows encoding with
      // zero length encrypted text
      _encodeCipherDataHeader(
         cipherDataHeader: CipherDataHeader
      ): Uint8Array {
         this.validateCipherParams(cipherDataHeader);

         let offset = this._encodeCipherData4Block(cipherData4Header, output);
         let set = (data: Uint8Array) => {
            output.set(data, offset);
            offset += data.byteLength;
         }

         set(numToBytes(cipherData4Header.encryptedHint.byteLength, HINT_LEN_BYTES));
         if (cipherData4Header.encryptedHint.byteLength > 0) {
            set(cipherData4Header.encryptedHint);
         }

         set(numToBytes(cipherData4Header.ic, IC_BYTES));
         set(cipherData4Header.slt);

         return offset;
      }
   */
   /*
      // Importers of CipherService should not need this function directly
      // but it is public for unit testing. Allows encoding with
      // zero length encrypted text
      _encodeCipherData4Block(
         cipherData4Block: CipherData4Block,
         output: Uint8Array
      ): number {
         this.validateCipherParams(cipherData4Block);

         let offset = 0;
         let set = (data: Uint8Array) => {
            output.set(data, offset);
            offset += data.byteLength;
         }

         set(numToBytes(cipherData4Block.ver, VER_BYTES));
         const algInfo = AlgInfo[cipherData4Block.alg];
         set(numToBytes(Number(algInfo['id']), ALG_BYTES));
         set(cipherData4Block.iv);
         set(numToBytes(cipherData4Block.encryptedData.byteLength, CHUNK_SIZE_BYTES));
         set(cipherData4Block.encryptedData);

         return offset;
      }
   */
   // Importers of CipherService should not need this function directly
   // but it is public for unit testing. Allows encoding with
   // zero length encrypted text
   /*   _encodeCipherData(cipherData: CipherData1): Uint8Array {

         this.validateCipherData(cipherData);

         const algInfo = AlgInfo[cipherData.alg];

         const icEnc = numToBytes(cipherData.ic, IC_BYTES);
         const verEnc = numToBytes(CURRENT_VERSION, VER_BYTES);
         const algEnc = numToBytes(Number(algInfo['id']), ALG_BYTES);
         const hintLenEnc = numToBytes(cipherData.encryptedHint.byteLength, HINT_LEN_BYTES);
         const iv_bytes = Number(algInfo['iv_bytes']);

         let encoded = new Uint8Array(
            ALG_BYTES +
            iv_bytes +
            SLT_BYTES +
            IC_BYTES +
            VER_BYTES +
            HINT_LEN_BYTES +
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
         offset += HINT_LEN_BYTES;
         encoded.set(cipherData.encryptedHint, offset);
         offset += cipherData.encryptedHint.byteLength;
         encoded.set(cipherData.encryptedData, offset);

         return encoded;
      }
   */
   // Importers of CipherService should not need this function directly,
   // but it is public for unit testing. Does not allow encoding
   // with zero length encrypted text since that is not needed
   async _decodeCipherData1(
      userCred: Uint8Array,
      verifyMAC: verifyMACFun,
      encoded: Uint8Array
   ): Promise<[cipherData1: CipherData1, sk: CryptoKey]> {

      if (userCred.byteLength != USERCRED_BYTES) {
         throw new Error('Invalid userCred length of: ' + userCred.byteLength);
      }

      console.log('_decodeCipherData1 decoding:', encoded);


      // Need to treat all values an UNTRUSTED since the signature has not yet been
      // validated. Test each value for errors as we unpack
      let extractor = new Extractor(encoded);

      // Order must be invariant
      const mac = extractor.mac;
      const alg = extractor.alg;
      const iv = extractor.iv;
      const slt = extractor.slt;
      const ic = extractor.ic;
      const ver = extractor.ver;
      if (ver != 1) {
         throw new Error('Invalid version of: ' + ver);
      }
      const encryptedHint = extractor.hint;
      const encryptedData = extractor.remainder('edata');

      const ad = {
         alg: alg,
         ic: ic,
         iv: iv,
         slt: slt,
         encryptedHint: encryptedHint
      };
      const cipherDataHeader: CipherDataHeader = {
         mac: mac,
         ver: ver,
         blockSize: 0
      }

      const additionalData = this._encodeAdditionalData(ver, ad);
      const sk = await this._genSigningKey(userCred, slt);

      // Avoiding the Doom Principle and verify signature before crypto operations.
      // Aka, check MAC as soon as possible after we can have the signing key and data
      // Would be cleaner to do this elswhere, but keeping it at the lowest level
      // ensures we don't skip the step
      const validMac: boolean = await verifyMAC(sk, cipherDataHeader, additionalData, encryptedData);
      if (!validMac) {
         throw new Error('Invalid MAC');
      }

      return [{
         mac: mac,
         alg: alg,
         iv: iv,
         slt: slt,
         ic: ic,
         ver: ver,
         encryptedHint: encryptedHint,
         encryptedData: encryptedData,
         additionalData: additionalData
      }, sk];
   }

   /*
   export type CipherDataHeaderN = {
      readonly alg: string;      // ALG_BYTES
      readonly iv: Uint8Array;   // Variable, lookup in AlgInfo
      readonly encryptedData: Uint8Array;
   }

   export type CipherDataBlock0 = CipherDataHeaderN & {
      readonly ic: number;       // IC_BYTES
      readonly slt: Uint8Array;  // SLT_BYTES
      readonly encryptedHint: Uint8Array;  // limited to ENCRYPTED_HINT_MAX_BYTES bytes
   }
   */

   // Importers of CipherService should not need this function directly,
   // but it is public for unit testing. Does not allow encoding
   // with zero length encrypted text since that is not needed
   async _decodeCipherDataBlock0(
      cipherDataHeader: CipherDataHeader,
      userCred: Uint8Array,
      verifyMAC: verifyMACFun,
      encoded: Uint8Array
   ): Promise<[cipherDataBlock0: CipherDataBlock0, sk: CryptoKey]> {

      if (userCred.byteLength != USERCRED_BYTES) {
         throw new Error('Invalid userCred length of: ' + userCred.byteLength);
      }

      console.log('_decodeCipherDataBlock0 decoding:', encoded);

      // Need to treat all values an UNTRUSTED since the signature has not yet been
      // validated. Test each value for errors as we unpack
      let extractor = new Extractor(encoded);

      // Order must be invariant
      const alg = extractor.alg;
      const iv = extractor.iv;
      const slt = extractor.slt;
      const ic = extractor.ic;
      const encryptedHint = extractor.hint;
      const encryptedData = extractor.remainder('edata');

      const ad = {
         alg: alg,
         ic: ic,
         iv: iv,
         slt: slt,
         encryptedHint: encryptedHint
      };

      const additionalData = this._encodeAdditionalData(cipherDataHeader.ver, ad);
      const sk = await this._genSigningKey(userCred, slt);

      // Avoiding the Doom Principle and verify signature before crypto operations.
      // Aka, check MAC as soon as possible after we can have the signing key and data
      // Would be cleaner to do this elswhere, but keeping it at the lowest level
      // ensures we don't skip the step
      const validMac: boolean = await verifyMAC(sk, cipherDataHeader, additionalData, encryptedData);
      if (!validMac) {
         throw new Error('Invalid MAC');
      }

      return [{
         alg: alg,
         iv: iv,
         slt: slt,
         ic: ic,
         encryptedHint: encryptedHint,
         encryptedData: encryptedData,
         additionalData: additionalData
      }, sk];
   }

   /*
   export type CipherDataHeaderN = {
      readonly alg: string;      // ALG_BYTES
      readonly iv: Uint8Array;   // Variable, lookup in AlgInfo
      readonly encryptedData: Uint8Array;
   }
      */


   // Importers of CipherService should not need this function directly,
   // but it is public for unit testing. Does not allow encoding
   // with zero length encrypted text since that is not needed
   async _decodeCipherDataBlockN(
      cipherDataHeader: CipherDataHeader,
      sk: CryptoKey,
      verifyMAC: verifyMACFun,
      encoded: Uint8Array
   ): Promise<CipherDataBlockN> {

      console.log('_decodeCipherDataBlockN decoding:', encoded);

      // Need to treat all values an UNTRUSTED since the signature has not yet been
      // validated. Test each value for errors as we unpack
      let extractor = new Extractor(encoded);

      // Order must be invariant
      const alg = extractor.alg;
      const iv = extractor.iv;
      const encryptedData = extractor.remainder('edata');

      const ad = {
         alg: alg,
         iv: iv
      };

      const additionalData = this._encodeAdditionalData(cipherDataHeader.ver, ad);

      // Avoiding the Doom Principle and verify signature before crypto operations.
      // Aka, check MAC as soon as possible after we can have the signing key and data
      // Would be cleaner to do this elswhere, but keeping it at the lowest level
      // ensures we don't skip the step
      const validMac: boolean = await verifyMAC(sk, cipherDataHeader, additionalData, encryptedData);
      if (!validMac) {
         throw new Error('Invalid MAC');
      }

      return {
         alg: alg,
         iv: iv,
         encryptedData: encryptedData,
         additionalData: additionalData
      };
   }

   async _decodeCipherDataHeader(
      userCred: Uint8Array,
      encoded: Uint8Array
   ): Promise<CipherData1 | CipherDataHeader> {

      console.log('_decodeCipherDataHeader decoding:', encoded);

      // Need to treat all values an UNTRUSTED since the signature has not yet been
      // validated. Test each value for errors as we unpack
      if (userCred.byteLength != USERCRED_BYTES) {
         throw new Error('Invalid userCred length: ' + userCred.byteLength);
      }

      if (encoded.byteLength < HEADER_BYTES) {
         throw new Error('Invalid cipher data length: ' + encoded.byteLength);
      }

      console.log('_decodeCipherHeader', encoded);

      // This is a bit ugly, but the original CipherData1 encoding stupidly had the
      // version in the middle of the encoding. Detect old version by the first 2 bytes
      // being < 4 (because encoded start with ALG and v1 max ALG was 3 and beyond v1
      // version is >=4). Fortunately ALG_BYTES and VER_BYTES are equal.
      const verOrAlg = bytesToNum(new Uint8Array(encoded.buffer, MAC_BYTES, VER_BYTES));
      if (verOrAlg < V1_BELOW && verOrAlg > 0) {
         // Load old version and convert to CipherData4Header
         const [cipherData] = await this._decodeCipherData1(
            userCred, this._verifyHMAC1, encoded);
         return cipherData;
      }

      let extractor = new Extractor(encoded);

      // Order must be invariant
      const mac = extractor.mac;
      const ver = extractor.ver;
      if (ver != CURRENT_VERSION) {
         throw new Error('Invalid version of: ' + ver);
      }
      const blockSize = extractor.size;

      return {
         mac: mac,
         ver: ver,
         blockSize: blockSize
      }
   }

   /*
      // Importers of CipherService should not need this function directly,
      // but it is public for unit testing. Does not allow encoding
      // with zero length encrypted text since that is not needed
      _decodeCipherHeader(encoded: Uint8Array): [CipherData4Header, number] {

         // Need to treat all values an UNTRUSTED since the signature has not yet been
         // validated. Test each value for errors as we unpack

         if(encoded.byteLength < VER_BYTES) {
            throw new Error('Missing cipher data');
         }

         console.log('_decodeCipherHeader', encoded);

         let offset = 0;
         let extract = (what: string, len: number) => {
            const result = new Uint8Array(encoded.buffer, offset, len);
            // could happen if the encode data was clipped and reencoded
            // (slice annoyning doesn't throw on slicing beyond the end)
            if (result.byteLength != len) {
               throw new Error(`Invalid ${what} length: ${result.byteLength}`);
            }

            offset += len;
            return result;
         }

         // This is a bit ugly, but the original CipherData1 encoding stupidly had the
         // version in the middle of the encoding. Detect old version by the first 2 bytes
         // being < 4 (because encoded start with ALG and v1 max ALG was 3 and beyond v1
         // version is >=4). Fortunately ALG_BYTES and VER_BYTES are equal.
         const verOrAlg = bytesToNum(encoded.slice(0, VER_BYTES));
         if (verOrAlg < V1_BELOW && verOrAlg != 0) {
            // Load old version and convert to CipherData4Header
            const [cipherData1, read] = this._decodeCipherData1(encoded);
            return [{
               ...cipherData1
            }, read];
         } else if (verOrAlg == CURRENT_VERSION) {
            return this._decodeCipherData4Header(encoded);
         } else {
            throw new Error('Unknown version: ' + verOrAlg);
         }
      }
   */

   // Only useful for validating params before encoding. Decoded values are read with
   // expected sizes, so validity depends on signature validate rather than decoded lengths
   validateCipherParams(
      args: {
         ver: number,
         alg: string;
         iv: Uint8Array;
         encryptedData?: Uint8Array,
         ic?: number;
         slt?: Uint8Array;
         encryptedHint?: Uint8Array
   }) {
      if (!args.ver || args.ver > CURRENT_VERSION) {
         throw new Error('Invalid version number: ' + args.ver);
      }

      if (!(args.alg in AlgInfo)) {
         throw new Error('Invalid alg: ' + args.alg);
      }

      const ivBytes = Number(AlgInfo[args.alg]['iv_bytes']);
      if (args.iv.byteLength != ivBytes) {
         throw new Error('Invalid iv size: ' + args.iv.byteLength);
      }

      if (args.encryptedData && (args.encryptedData.byteLength == 0)) {
         throw new Error('Missing encrypted data');
      }

      if (args.slt) {
         if (args.slt.byteLength != SLT_BYTES) {
            throw new Error('Invalid slt len: ' + args.slt.byteLength);
         }
         // If there is a salt, ic must also be present (and valid)
         if (!args.ic) {
            throw new Error('Missing ic');
         }
      }

      if (args.ic && (args.ic < ICOUNT_MIN || args.ic > ICOUNT_MAX)) {
         throw new Error('Invalid ic: ' + args.ic);
      }

      if (args.encryptedHint && (args.encryptedHint.length > ENCRYPTED_HINT_MAX_BYTES)) {
         throw new Error('Invalid encrypted hint length: ' + args.encryptedHint.length);
      }
   }

   // Only useful for validating params before encoding. Decoded values are read with
   // expected sizes, so validity depends on signature validate rather than decoded lengths
   /*   validateCipherData(cipherData: CipherData1) {
         //May want to make these message more helpful...a
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
         if (cipherData.encryptedHint.length > ENCRYPTED_HINT_MAX_BYTES) {
            throw new Error('Invalid encrypted hint length of: ' + cipherData.encryptedHint.length);
         }
      }
   */

}


