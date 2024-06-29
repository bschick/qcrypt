import { Injectable } from '@angular/core';
import sodium from 'libsodium-wrappers';
import { base64URLStringToBuffer, bufferToBase64URLString } from '@simplewebauthn/browser';

const AES_GCM_TAG_BYTES = 16;
const X20_PLY_TAG_BYTES = 16; // sodium.crypto_aead_xchacha20poly1305_IETF_ABYTES, is not ready yet
const AEGIS_256_TAG_BYTES = 32; // sodium.crypto_aead_aegis256_ABYTES, is not ready yet
const AUTH_TAG_MAX_BYTES = Math.max(X20_PLY_TAG_BYTES, AES_GCM_TAG_BYTES, AEGIS_256_TAG_BYTES);
const AUTH_TAG_MIN_BYTES = Math.min(X20_PLY_TAG_BYTES, AES_GCM_TAG_BYTES, AEGIS_256_TAG_BYTES);

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
const CHUNK_SIZE_MAX = CHUNK_SIZE_START * 243; // 243 MiB
const CHUNK_SIZE_BYTES = 4;       // max 256^8 (aka 4 GiB)

export type EParams2 = {
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
   readonly iv: Uint8Array;   // Variable, lookup in AlgInfo
   readonly slt: Uint8Array;  // SLT_BYTES
   readonly ver: number;      // VER_BYTES
   readonly encryptedHint: Uint8Array;  // limited to ENCRYPTED_HINT_MAX_BYTES bytes
   readonly encryptedData: Uint8Array;
};


export const ALG_BYTES = 2;
export const SLT_BYTES = 16;
export const IC_BYTES = 4;
export const VER_BYTES = 2;
export const HMAC_BYTES = 32;
export const USERCRED_BYTES = 32;

export type CipherData4 = {
   readonly ver: number;      // VER_BYTES
   readonly alg: string;      // ALG_BYTES
   readonly iv: Uint8Array;   // Variable, lookup in AlgInfo
   readonly encryptedData: Uint8Array;
};

export type CipherData4Header = CipherData4 & {
   readonly ic: number;       // IC_BYTES
   readonly slt: Uint8Array;  // SLT_BYTES
   readonly encryptedHint: Uint8Array;  // limited to ENCRYPTED_HINT_MAX_BYTES bytes
};

// The following is not just the size of the CipherData4 structs,
// this is the MAX byte expansion of the output of encryption compared
// to the byte size of the input
export const OVERHEAD_MAX_BYTES = HMAC_BYTES + VER_BYTES + ALG_BYTES +
   IV_MAX_BYTES + AUTH_TAG_MAX_BYTES + IC_BYTES + SLT_BYTES +
   CHUNK_SIZE_BYTES + HINT_LEN_BYTES + ENCRYPTED_HINT_MAX_BYTES;

/*const OVERHEAD_MIN_BYTES = HMAC_BYTES + VER_BYTES + ALG_BYTES +
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

/*
async function readStream(
   reader: ReadableStreamDefaultReader<Uint8Array>
): Promise<Uint8Array> {

   let result = new Uint8Array(0);
   while (true) {
      // read() returns a promise that fulfills when a value has been received
      const { done, value } = await reader.read();

      console.log('readStream read: ', value, done);

      if (value) {
         const newres = new Uint8Array(result.byteLength + value.byteLength);
         newres.set(result);
         newres.set(value, result.byteLength);
         result = newres;
      }

      if (done || !value) {
         break;
      }
   }

   console.log('readStream returning: ' + result.byteLength);
   return result;
}
*/

async function readStreamBYOB(
   reader: ReadableStreamBYOBReader,
   output: Uint8Array
): Promise<[Uint8Array, number]> {

   let bytesReceived = 0;
   let offset = 0;
//   console.log('readStreamBYOB buffer: ' + output.byteLength);

   while (offset < output.byteLength) {
      // read() returns a promise that fulfills when a value has been received
      const { done, value } = await reader.read(
         new Uint8Array(output.buffer, offset, output.byteLength - offset)
      );

//      console.log('readStreamBYOB read: ', value, done);

      if (value) {
         // confirm this is really needed (along with return below)
         output = value;
         offset += value.byteLength;
         bytesReceived += value.byteLength;
      }

      if (done || !value) {
         break;
      }
   }

//   console.log('readStreamBYOB returning: ' + bytesReceived);
   return [output, bytesReceived];
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
      eparams: EParams2,
      readyNotice?: (params: Params) => void
   ): Promise<string> {
      if (!(typeof eparams.clear === 'string')) {
         throw new Error('Clear type must be string');
      }
      this._validateEparams(eparams);

      const input = new TextEncoder().encode(eparams.clear);
      const output = new Uint8Array(input.byteLength + OVERHEAD_MAX_BYTES);

      const [bytesWritten] = await this._encryptHeader(
         eparams,
         input,
         output,
         readyNotice
      );

      return bytesToBase64(new Uint8Array(output.buffer, 0, bytesWritten));
   }

   encryptStream(
      eparams: EParams2,
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
      let totalBytesWritten = 0;
      let chunkSize = CHUNK_SIZE_START;

//      console.log('encryptToBytes returning');

      return new ReadableStream({
         type: 'bytes',

         async start(controller) {
            console.log(`start(): ${controller.constructor.name}.byobRequest = ${controller.byobRequest}`);
            //            const buffer = controller.byobRequest!.view! as Uint8Array;

            // Header reading uses a smaller buffer since this is often likely the only
            // read for pasted text.
            const output = new Uint8Array(chunkSize);
            chunkSize *= 3;

            try {
               let input = new Uint8Array(output.byteLength - OVERHEAD_MAX_BYTES);
               let inputBytes: number;
               let outputBytes: number;

               try {
                  [input, inputBytes] = await readStreamBYOB(reader, input);
               } finally {
                  reader.releaseLock();
               }

               [outputBytes, ek, sk] = await cipherSvc._encryptHeader(
                  eparams,
                  new Uint8Array(input.buffer, 0, inputBytes),
                  output,
                  readyNotice
               );

               //               controller.byobRequest!.respond(written);
               controller.enqueue(new Uint8Array(output.buffer, 0, outputBytes));
               //            console.log('start(): closing');
               //            controller.close();
               totalBytesWritten += outputBytes;
               console.log('start(): total enqueued: ' + totalBytesWritten);
            } finally {
               console.log('start(): closing: ');
               controller.close();
            }
         },

         // TODO: change to to not use "header"
         async pull(controller) {
            console.log(`pull(): ${controller.constructor.name}.byobRequest = ${controller.byobRequest}`);
            //            console.log(`pull():${controller.constructor.name}.byobRequest.view.byteOffset = ${controller.byobRequest!.view?.byteOffset}`);
            //          console.log(`pull():${controller.constructor.name}.byobRequest.view.byteLength = ${controller.byobRequest!.view?.byteLength}`);
            //            controller.byobRequest!.respond(0);
            // should not be null with autoAllocateChunkSize set
            //            const buffer = controller.byobRequest!.view! as Uint8Array;

            // Header reading uses a smaller buffer since this is often likely the only
            // read for pasted text.
            const output = new Uint8Array(chunkSize);
            chunkSize = Math.min(chunkSize * 3, CHUNK_SIZE_MAX);

            try {
               let input = new Uint8Array(output.byteLength - OVERHEAD_MAX_BYTES);
               let inputBytes: number;
               let outputBytes: number;

               try {
                  [input, inputBytes] = await readStreamBYOB(reader, input);
               } finally {
                  reader.releaseLock();
               }

               [outputBytes, ek, sk] = await cipherSvc._encryptHeader(
                  eparams,
                  new Uint8Array(input.buffer, 0, inputBytes),
                  output,
                  readyNotice
               );

               //               controller.byobRequest!.respond(written);
               controller.enqueue(new Uint8Array(output.buffer, 0, outputBytes));
               //            console.log('start(): closing');
               //            controller.close();
               totalBytesWritten += outputBytes;
               console.log('pull(): total enqueued: ' + totalBytesWritten);
            } finally {
               console.log('pull(): closing: ');
               controller.close();
            }

            //            console.log('pull(): closing');
            //            controller.close();

            /*            // Header reading uses a smaller buffer since this is often likely the only
                        // read for pasted text.
                        const buffer = new Uint8Array(1048576);
                        // should not be null with autoAllocateChunkSize set
                        //            const buffer = controller.byobRequest!.view! as Uint8Array;
                        cipherSvc._encryptHeader(
                           eparams,
                           new Uint8Array(buffer),
                           readyNotice
                        ).then(([written, hek, hsk]) => {
                           console.log('stream written: ' + written);
                           bytesWritten = written;
                           ek = hek;
                           sk = hsk;
                           //               controller.byobRequest!.respond(written);
                           controller.enqueue(new Uint8Array(buffer, 0, written));
                        });*/
         }

      });
   }

   _validateEparams(eparams: EParams2) {
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

   // This method, and those it calls, could be optimized by writing directly
   // into buffer more than is done currently with allocate and copy.
   async _encryptHeader(
      eparams: EParams2,
      input: Uint8Array,
      output: Uint8Array,
      readyNotice?: (params: Params) => void
   ): Promise<[written: number, ek: CryptoKey, sk: CryptoKey]> {

//      console.log('_encryptHeader input bytes: ' + input.byteLength);
//      console.log('_encryptHeader max output bytes: ' + output.byteLength);

      if (input.byteLength == 0) {
         throw new Error('No data to encrypt');
      }

      // Create a new salt and IV each time a key is derviced from the password.
      // https://crypto.stackexchange.com/questions/53032/salt-for-non-stored-passwords
      const randomArray = await this._random48Cache.getRandomArray(
         eparams.trueRand,
         eparams.fallbackRand
      );

      const ivByteLen = Number(AlgInfo[eparams.alg]['iv_bytes']);
      const slt = randomArray.slice(0, SLT_BYTES);
      const iv = randomArray.slice(SLT_BYTES, SLT_BYTES + ivByteLen);

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
         ver: CURRENT_VERSION,
         alg: eparams.alg,
         ic: eparams.ic,
         iv: iv,
         slt: slt,
         encryptedHint: encryptedHint
      };

      const additionalData = this._encodeAdditionalData(ad);


      // max number of clear bytes that can be read into buffer so that we can
      // convert in place to b64
      // (even though the function return binary, we do this to simply b64 wrapper)
      /*      const adB64Size = Math.ceil(4 / 3 * (additionalData.byteLength + 2))
            const sigB64Size = Math.ceil(4 / 3 * (HMAC_BYTES + 2))
            const tagB64Size = Math.ceil(4 / 3 * (AUTH_TAG_MAX_BYTES + 2))
            const bufferFree = buffer.byteLength - adB64Size - sigB64Size - tagB64Size;
            const maxClearRead = Math.floor(3 / 4 * bufferFree - 2)
      */
      // TODO: not likely going to do B64 encoding in place, if so, change this to
      // be buffer.byteLength - headerSize

      // Read a maximum of OVERHEAD_MAX_BYTES less then the output buff
      // so we have space for header info
      /*      let clearData = new Uint8Array(output.byteLength - OVERHEAD_MAX_BYTES);
            let bytesRead = 0;

            const reader = eparams.clear.getReader({ mode: "byob" });

            try {
               // Header is special. Don't loop, just read a much as we can and retrun.
               // We expect to handle all the data for most cases (like pasted text and small files).
               [clearData, bytesRead] = await readStreamBYOB(reader, clearData);
            } finally {
               reader.releaseLock();
            }
      */
      const encryptedBytes = await this._doEncrypt(
         eparams.alg,
         ek,
         iv,
         input,
         additionalData,
      );
//      console.log('_encryptHeader encrypted bytes: ' + encryptedBytes.byteLength);

      const hmacSlot = new Uint8Array(output.buffer, 0, HMAC_BYTES);
      const dataSlot = new Uint8Array(output.buffer, HMAC_BYTES);

      const encodedSize = await this._encodeCipherData4Header({
            ...ad,
            encryptedData: encryptedBytes
         }, dataSlot
      );

//      console.log('_encryptHeader encoded bytes: ' + encodedSize);

      // Putting the HMAC first (ahead of version) was a mistake, but as long we the length
      // isn't changed, its not a problem. If we ever want to use a longer HMAC a simple
      // solution would be to keep the first 256bits at the start and append the rest to the
      // and of encoded cipher data
      await this._signCipherData(sk, new Uint8Array(output.buffer, HMAC_BYTES, encodedSize), hmacSlot);

/*      console.log(sk);
      console.log(hmacSlot.byteLength, hmacSlot);
      const data = new Uint8Array(dataSlot.buffer, HMAC_BYTES, encodedSize)
      console.log(data.byteLength, data);
*/
      // TODO: remove this if not encoding B64 in place
      /*      const encB64Size = Math.ceil(4 / 3 * (encryptedBytes.byteLength + 2));
            if (encB64Size + sigB64Size > buffer.byteLength) {
               throw new Error(`Invalid data size: ${encB64Size + sigB64Size} > ${buffer.byteLength}`);
            }

            const hmac = await this._signCipherBytes(sk, buffer);

            buffer.set(hmac);
            buffer.set(encoded, hmac.byteLength);

            console.log('_encryptHeader wrote: ' + (hmac.byteLength + encoded.byteLength));
      */
      return [encodedSize + HMAC_BYTES, ek, sk];
   }

   // This method, and those it calls, could be optimized by writing directly
   // into buffer more than is done currently with allocate and copy.
  /* async _encryptBlock(
      eparams: EParams2,
      buffer: Uint8Array,
      ek: CryptoKey,
      sk: CryptoKey,
   ): Promise<number> {

      console.log('_encryptBlock buffer: ' + buffer.byteLength);
      if (!(eparams.clear instanceof ReadableStream)) {
         throw new Error('Clear type must be ReadableStream');
      }

      const randomArray = await this._random48Cache.getRandomArray(
         eparams.trueRand,
         eparams.fallbackRand
      );

      const ivByteLen = Number(AlgInfo[eparams.alg]['iv_bytes']);
      const iv = randomArray.slice(0, ivByteLen);

      const cipherDataForAD: CipherData4Header = {
         alg: eparams.alg,
         ic: eparams.ic,
         iv: iv,
         slt: new Uint8Array(0),
         encryptedHint: new Uint8Array(0),
         encryptedData: new Uint8Array(0)
      };

      const additionalData = this._encodeCipherData(cipherDataForAD);

      const reader = eparams.clear.getReader({ mode: "byob" });

      // max number of clear bytes that can be read into buffer so that we can
      // convert in place to b64
      // (even though the function return binary, we do this to simply b64 wrapper)
      const adB64Size = Math.ceil(4 / 3 * (additionalData.byteLength + 2))
      const sigB64Size = Math.ceil(4 / 3 * (HMAC_BYTES + 2))
      const tagB64Size = Math.ceil(4 / 3 * (AUTH_TAG_MAX_BYTES + 2))
      const bufferFree = buffer.byteLength - adB64Size - sigB64Size - tagB64Size;
      const maxClearRead = Math.floor(3 / 4 * bufferFree - 2)

      let clearData = new Uint8Array(maxClearRead)
      let bytesRead = 0;

      try {
         // Header is special. Don't loop, just read a much as we can an retrun.
         // We expect to handle all the data for most cases (like pasted text and small files).
         [clearData, bytesRead] = await readStreamBYOB(reader, clearData);
      } finally {
         reader.releaseLock();
      }

      if (bytesRead <= 0) {
         throw new Error('No data to encrypt');
      }

      console.log('_encryptHeader clear bytes: ' + bytesRead);

      const encryptedBytes = await this._doEncrypt(
         eparams.alg,
         ek,
         iv,
         new Uint8Array(clearData, 0, bytesRead),
         additionalData,
      );
      console.log('_encryptHeader encrypted bytes: ' + encryptedBytes.byteLength);

      const encoded = this._encodeCipherData({
         ...cipherDataForAD,
         encryptedData: encryptedBytes
      });

      const encB64Size = Math.ceil(4 / 3 * (encryptedBytes.byteLength + 2));
      if (encB64Size + sigB64Size > buffer.byteLength) {
         throw new Error(`Invalid data size: ${encB64Size + sigB64Size} > ${buffer.byteLength}`);
      }

      const hmac = await this._signCipherBytes(sk, encoded);

      buffer.set(hmac);
      buffer.set(encoded, hmac.byteLength);

      console.log('_encryptHeader wrote: ' + (hmac.byteLength + encoded.byteLength));

      return hmac.byteLength + encoded.byteLength;
   }
*/

   // Overall order of operations:
   //
   // 1. Generate new salt and iv/nonce values
   // 2. Encode cipher parameters as additional data
   // 3. Generate signing key from userCred and cipher key from pwd + userCred
   // 4. Encrypt cleartext using cipher key (with addition data)
   // 5. Sign addtional data + cipher text with signing key
   // 6. Concat and return
   //
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
      return encryptedBytes;
   }

   async decryptString(
      pwdProvider: (hint: string) => Promise<string>,
      userCred: Uint8Array,
      cipherText: string,
      readyNotice?: (params: Params) => void
   ): Promise<string> {

      const input = base64ToBytes(cipherText);
      const output = new Uint8Array(input.byteLength); // always large enough due to overhead

      const [written] = await this._decryptHeader(
         pwdProvider,
         userCred,
         input,
         output,
         readyNotice
      );

      return new TextDecoder().decode(new Uint8Array(output.buffer, 0, written));
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
   async _decryptHeader(
      pwdProvider: (hint: string) => Promise<string>,
      userCred: Uint8Array,
      input: Uint8Array,
      output: Uint8Array,
      readyNotice?: (params: Params) => void
   ): Promise<[written: number, ek: CryptoKey, sk: CryptoKey]> {

//      console.log('_decryptHeader input bytes: ' + input.byteLength);
//      console.log('_decryptHeader max output bytes: ' + output.byteLength);

      const [cipherData, sk, read] = await this.getCipherData(userCred, input);

      let hintEnc = new Uint8Array(0);
      if (cipherData.encryptedHint.byteLength != 0) {
         const hk = await this._genHintCipherKey(cipherData.alg, userCred, cipherData.slt);
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

      const additionalData = this._encodeAdditionalData(cipherData);

      const decrypted = await this._doDecrypt(
         cipherData.alg,
         ek,
         cipherData.iv,
         cipherData.encryptedData,
         additionalData,
      );

//      console.log('_decryptHeader decrypted bytes: ' + decrypted.byteLength);
      output.set(decrypted);

      return [decrypted.byteLength, ek, sk];
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

   async getCipherData(
      userCred: Uint8Array,
      input: Uint8Array,
   ): Promise<[CipherData4Header, CryptoKey, number]> {

      if (userCred.byteLength != USERCRED_BYTES) {
         throw new Error('Invalid userCred length of: ' + userCred.byteLength);
      }

      // Putting the HMAC first (ahead of version) was a mistake, but as long we the length
      // isn't changed, its not a problem. If we ever want to use a longer HMAC a simple
      // solution would be to keep the first 256bits at the start and append the rest to the
      // and of encoded cipher data
      const hmac = new Uint8Array(input.buffer, 0, HMAC_BYTES);
      const data = new Uint8Array(input.buffer, HMAC_BYTES);

/*      console.log('getCipherData hmac', hmac.byteLength, hmac);
      console.log('getCipherData data', data.byteLength, data);
*/
      if (hmac.byteLength != HMAC_BYTES) {
         throw new Error('Invalid HMAC length of: ' + hmac.byteLength);
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
         return [cipherData, sk, read + HMAC_BYTES];
      }

      // Should never get here since verify throws on bad signature
      throw new Error('Invalid HMAC signature');
   }

/*
   async getCipherData(
      userCred: Uint8Array,
      cipherText: string
   ): Promise<CipherData1> {

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
   async _signCipherData(
      sk: CryptoKey,
      data: Uint8Array,
      hmacDest: Uint8Array
   ) {
      if (hmacDest.byteLength != HMAC_BYTES) {
         throw new Error('Invalid hmac dest length: ' + hmacDest.byteLength);
      }
      const hmac = await crypto.subtle.sign('HMAC', sk, data);
      if (hmac.byteLength != HMAC_BYTES) {
         throw new Error('Invalid HMAC length: ' + hmac.byteLength);
      }

/*      console.log('_signCipherData', hmac.byteLength, hmac);
      console.log('_signCipherData', data.byteLength, data);
*/
      hmacDest.set(new Uint8Array(hmac));
   }

   // public for testing, callers should not need to use this directly
   async _verifyCipherData(
      sk: CryptoKey,
      hmac: Uint8Array,
      data: Uint8Array
   ): Promise<boolean> {

/*      console.log('_verifyCipherData', hmac.byteLength, hmac);
      console.log('_verifyCipherData', data.byteLength, data);
*/
      const valid = await crypto.subtle.verify('HMAC', sk, hmac, data);
      if (valid) {
         return true;
      }

      throw new Error('Invalid HMAC signature');
   }

   // Importers of CipherService should not need this function directly
   // but it is public for unit testing. Allows encoding with
   // zero length encrypted text
   //
   // Validates values and packs them into an Uint8Array
   _encodeAdditionalData(args: {
      ver: number;
      alg: string;
      iv: Uint8Array;
      ic?: number;
      slt?: Uint8Array;
      encryptedHint?: Uint8Array
   }): Uint8Array {

      this.validateCipherParams(args);

      const maxBytes = VER_BYTES + IV_MAX_BYTES + ALG_BYTES + IC_BYTES + SLT_BYTES + ENCRYPTED_HINT_MAX_BYTES;
      const buffer = new Uint8Array(maxBytes);

      let offset = 0;
      let extend = (data: Uint8Array) => {
         buffer.set(data, offset);
         offset += data.byteLength;
      }

      // The order, size, and encodings below cannot change without versioning

      const algInfo = AlgInfo[args.alg];
      extend(numToBytes(Number(algInfo['id']), ALG_BYTES));
      extend(args.iv);

      if (args.slt) {
         extend(args.slt);
      }

      if (args.ic) {
         extend(numToBytes(args.ic, IC_BYTES));
      }

//      console.log('ad ver: ' +args.ver );
      extend(numToBytes(args.ver, VER_BYTES));

      if (args.encryptedHint) {
         extend(numToBytes(args.encryptedHint.byteLength, HINT_LEN_BYTES));
         extend(args.encryptedHint);
      } else {
         extend(numToBytes(0, HINT_LEN_BYTES));
      }

      return new Uint8Array(buffer.buffer, 0, offset);
   }


   // Importers of CipherService should not need this function directly
   // but it is public for unit testing. Allows encoding with
   // zero length encrypted text
   _encodeCipherData4Header(
      cipherData4Header: CipherData4Header,
      output: Uint8Array
   ): number {
      this.validateCipherParams(cipherData4Header);

      let offset = this._encodeCipherData4(cipherData4Header, output);
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

   // Importers of CipherService should not need this function directly
   // but it is public for unit testing. Allows encoding with
   // zero length encrypted text
   _encodeCipherData4(
      cipherData4: CipherData4,
      output: Uint8Array
   ): number {
      this.validateCipherParams(cipherData4);

      let offset = 0;
      let set = (data: Uint8Array) => {
         output.set(data, offset);
         offset += data.byteLength;
      }

      set(numToBytes(cipherData4.ver, VER_BYTES));
      const algInfo = AlgInfo[cipherData4.alg];
      set(numToBytes(Number(algInfo['id']), ALG_BYTES));
      set(cipherData4.iv);
      set(numToBytes(cipherData4.encryptedData.byteLength, CHUNK_SIZE_BYTES));
      set(cipherData4.encryptedData);

      return offset;
   }

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
   _decodeCipherData1(encoded: Uint8Array): [CipherData1, number] {

      // Need to treat all values an UNTRUSTED since the signature has not yet been
      // validated. Test each value for errors as we unpack

      let offset = 0;
      let extract = (what: string, len: number) => {
         const result = encoded.slice(offset, offset + len);
         // Cloud happen if the encode data was clipped and reencoded
         // (slice annoyning doesn't throw on slicing beyond the end)
         if (result.byteLength != len) {
            throw new Error(`Invalid ${what} length: ${result.byteLength}`);
         }

         offset += len;
         return result;
      }

      // ### algorithm id ###
      const algNum = bytesToNum(extract('alg', ALG_BYTES));
      if (algNum < 1 || algNum > Object.keys(AlgInfo).length) {
         throw new Error('Invalid alg id of: ' + algNum);
      }

      let alg: string;
      let ivBytes: number;
      for (alg in AlgInfo) {
         if (AlgInfo[alg]['id'] == algNum) {
            ivBytes = Number(AlgInfo[alg]['iv_bytes']);
            break;
         }
      }

      // ### iv ###
      const iv = extract('iv', ivBytes!);

      // ### salt ###
      const slt = extract('slt', SLT_BYTES);

      // ### iter count ###
      const ic = bytesToNum(extract('ic', IC_BYTES));
      if (ic < ICOUNT_MIN || ic > ICOUNT_MAX) {
         throw new Error('Invalid ic of: ' + ic);
      }

      // ### version ###
      const ver = bytesToNum(extract('ver', VER_BYTES));
      if (ver != 1) {
         throw new Error('Invalid version of: ' + ver);
      }

      // ### hint ###
      const hintLen = bytesToNum(extract('hlen', HINT_LEN_BYTES));
      const encryptedHint = extract('hint', hintLen);

      // ### encrypted data ###
      // v1 did not include data length since it was always at the tail
      const encryptedData = encoded.slice(offset);
      offset += encryptedData.byteLength;

      // Again, cloud happen if the encode data was clipped and reencoded
      if (encryptedData.byteLength == 0) {
         throw new Error('Missing et data, found only: ' + encryptedData.byteLength);
      }

      return [{
         alg: alg!,
         iv: iv,
         slt: slt,
         ic: ic,
         ver: ver,
         encryptedHint: encryptedHint,
         encryptedData: encryptedData,
      }, offset];
   }


   // Importers of CipherService should not need this function directly,
   // but it is public for unit testing. Does not allow encoding
   // with zero length encrypted text since that is not needed
   _decodeCipherData4(encoded: Uint8Array): [CipherData4, number] {

      // Need to treat all values an UNTRUSTED since the signature has not yet been
      // validated. Test each value for errors as we unpack

      let offset = 0;
      let extract = (what: string, len: number) => {
         const result = encoded.slice(offset, offset + len);
         // Cloud happen if the encode data was clipped and reencoded
         // (slice annoyning doesn't throw on slicing beyond the end)
         if (result.byteLength != len) {
            throw new Error(`Invalid ${what} length: ${result.byteLength}`);
         }

         offset += len;
         return result;
      }

      // ### version ###
      const ver = bytesToNum(extract('ver', VER_BYTES));
      // There has only ever been 1 version of CipherData at this point
      if (ver != CURRENT_VERSION) {
         throw new Error('Invalid version of: ' + ver);
      }

      // ### algorithm ###
      const algNum = bytesToNum(extract('alg', ALG_BYTES));
      if (algNum < 1 || algNum > Object.keys(AlgInfo).length) {
         throw new Error('Invalid alg id of: ' + algNum);
      }

      let alg: string;
      let ivBytes: number;
      for (alg in AlgInfo) {
         if (AlgInfo[alg]['id'] == algNum) {
            ivBytes = Number(AlgInfo[alg]['iv_bytes']);
            break;
         }
      }

      // ### iv ###
      const iv = extract('iv', ivBytes!);

      // ### encrypted data ###
      const dataBytes = bytesToNum(extract('dlen', CHUNK_SIZE_BYTES));
      if(dataBytes > CHUNK_SIZE_MAX || dataBytes < 1) {
         throw new Error('Invalid data size: ' + dataBytes);
      }
      const encryptedData = extract('data', dataBytes);

      return [{
         ver: ver,
         alg: alg!,
         iv: iv,
         encryptedData: encryptedData,
      }, offset];
   }

   // Importers of CipherService should not need this function directly,
   // but it is public for unit testing. Does not allow encoding
   // with zero length encrypted text since that is not needed
   _decodeCipherHeader(encoded: Uint8Array): [CipherData4Header, number] {

      // Need to treat all values an UNTRUSTED since the signature has not yet been
      // validated. Test each value for errors as we unpack

      if(encoded.byteLength < VER_BYTES) {
         throw new Error('Missing cipher data');
      }

      let offset = 0;
      let extract = (what: string, len: number) => {
         const result = encoded.slice(offset, offset + len);
         // Cloud happen if the encode data was clipped and reencoded
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
      if (verOrAlg < V1_BELOW) {
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


   // Importers of CipherService should not need this function directly,
   // but it is public for unit testing. Does not allow encoding
   // with zero length encrypted text since that is not needed
   _decodeCipherData4Header(encoded: Uint8Array): [CipherData4Header, number] {

      // Need to treat all values an UNTRUSTED since the signature has not yet been
      // validated. Test each value for errors as we unpack

      let offset = 0;
      let extract = (what: string, len: number) => {
         const result = encoded.slice(offset, offset + len);
         // Cloud happen if the encode data was clipped and reencoded
         // (slice annoyning doesn't throw on slicing beyond the end)
         if (result.byteLength != len) {
            throw new Error(`Invalid ${what} length: ${result.byteLength}`);
         }

         offset += len;
         return result;
      }

      let cipherData4: CipherData4;
      [cipherData4, offset] = this._decodeCipherData4(encoded);

      // ### hint ###
      const hintLen = bytesToNum(extract('hlen', HINT_LEN_BYTES));
      const encryptedHint = extract('hint', hintLen);

      // ### iter count ###
      const ic = bytesToNum(extract('ic', IC_BYTES));
      if (ic < ICOUNT_MIN || ic > ICOUNT_MAX) {
         throw new Error('Invalid ic of: ' + ic);
      }

      // ### salt ###
      const slt = extract('slt', SLT_BYTES);

      return [{
         ...cipherData4,
         ic: ic,
         slt: slt,
         encryptedHint: encryptedHint
      }, offset]
   }

   // Only useful for validating params before encoding. Decoded values are read with
   // expected sizes, so validity depends on signature validate rather than decoded lengths
   validateCipherParams(
      args: {
         ver: number;
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
