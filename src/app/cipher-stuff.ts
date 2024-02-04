import * as sodium from 'libsodium-wrappers';

export const ICOUNT_MIN = 400000;
export const ICOUNT_DEFAULT = 800000;
export const ICOUNT_MAX = 4294000000; // limited to 4 bytes unsigned rounded to millions
export const HINT_MAX_LEN = 128;
export const CURRENT_VERSION = 1;

export const AlgInfo: { [key: string]: [string, number] } = {
   'AES-GCM': ['AES Galois Counter (GCM)', 1],
   'AES-CBC': ['AES Cipher Block Chaining (CBC)', 2],
   'AES-CTR': ['AEX Counter (CTR)', 3],
   'X20-PLY': ['XChaCha20 Poly1305', 4],
};

// Length of all parameter except hint and et are fixed
export type CParams = {
   readonly alg: string;      // ALG_BYTES 
   readonly ic: number;       // IC_BYTES
   readonly iv: Uint8Array;   // IV_BYTES
   readonly slt: Uint8Array;  // SLT_BYTES
   readonly hint: string;     // limited to 128 characters
   readonly et: Uint8Array;
};

export const ALG_BYTES = 2;
export const IV_BYTES = 24;
export const SLT_BYTES = 16;
export const IC_BYTES = 4;
export const VER_BYTES = 2;
export const HMAC_BYTES = 32;
export const KEY_BYTES = 32;

interface EnDeParams {
   name: string;
   [key: string]: any;
};


/* Javascript converts to signed 32 bit int if you use bit shifting 
   and masking, so to this instead. Count is the number of bytes
   used to pack the number. 
*/
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


export function bytesToBase64(bytes: Uint8Array): string {
   var binString = '';
   bytes.forEach((b, i) => {
      binString += String.fromCharCode(b);
   });
   return btoa(binString);
}

export function base64ToBytes(b64: string): Uint8Array {
   var binString: string = atob(b64);
   // @ts-ignore
   return Uint8Array.from(binString, (m) => m.codePointAt(0));
}

export class Random40 {
   private trueRandCache: Promise<Uint8Array>;

   constructor() {
      this.trueRandCache = this.downloadTrueRand();
   }

   async getRandomArray(
      trueRand: boolean,
      fallback: boolean
   ): Promise<Uint8Array> {
      if (!trueRand) {
         if (!fallback) {
            throw new Error('both trueRand and fallback disabled');
         }
         return window.crypto.getRandomValues(new Uint8Array(40));
      } else {
         const lastCache = this.trueRandCache;
         this.trueRandCache = this.downloadTrueRand();
         return lastCache.then((buffer) => {
            return buffer;
         }).catch((err) => {
            console.error(err);
            // If pseudo random fallback is disabled, then throw error
            if (!fallback) {
               throw new Error('no connection to random.org and no fallback: ' + err.message);
            }
            return window.crypto.getRandomValues(new Uint8Array(40));
         });
      }
   }

   async downloadTrueRand(): Promise<Uint8Array> {
      const url = 'https://www.random.org/cgi-bin/randbyte?nbytes=' + 40;

      return fetch(url, {
         cache: 'no-store',
      }).then((response) => {
         if (!response.ok) {
            throw new Error('random.org response: ' + response.statusText);
         }
         return response.arrayBuffer();
      }).then((array) => {
         if (array.byteLength != 40) {
            throw new Error('missing bytes from random.org');
         }
         return new Uint8Array(array!);
      });
   }
}

export class Cipher {
   // CParams kept seperate bulk updates and to make
   // is clear these are the only values get encoded 
   readonly alg: string;
   readonly ic: number;
   readonly trueRand: boolean;
   readonly fallbackRand: boolean;

   // cache in case any use of true random
   static random40 = new Random40();

   constructor(alg: string, ic: number, trueRand: boolean = true, fallbackRand: boolean = true) {
      if (!Object.keys(AlgInfo).includes(alg)) {
         throw new Error('Invalid alg type of: ' + alg);
      }
      if (ic < ICOUNT_MIN || ic > ICOUNT_MAX) {
         throw new Error('Invalid ic of: ' + ic);
      }
      if (!trueRand && !fallbackRand) {
         throw new Error('Either trueRand or fallbackRand must be true');
      }

      this.trueRand = trueRand;
      this.fallbackRand = fallbackRand;
      this.alg = alg;
      this.ic = ic;
   }

   // Move to callers
   // Avoid briefly putting up spinner and disabling buttons
   /*            if (this.p.ic > this.spinnerAbove) {
                   this.showProgress = true;
                 }
   */
   private async genKeys(
      pwd: string,
      signature: Uint8Array,
      slt: Uint8Array
   ): Promise<[CryptoKey, CryptoKey]> {

      if (slt.byteLength != SLT_BYTES) {
         throw new Error("Invalid slt size of: " + slt.byteLength);
      }

      if (!pwd || signature.byteLength == 0) {
         throw new Error('password or signature is empty');
      }

      if (this.ic < ICOUNT_MIN || this.ic > ICOUNT_MAX) {
         throw new Error('Invalid ic of: ' + this.ic);
      }

      const pwdBytes = new TextEncoder().encode(pwd);
      let input = new Uint8Array(pwdBytes.byteLength + signature.byteLength);
      input.set(pwdBytes);
      input.set(signature, pwdBytes.byteLength);

      const keyMaterial = await window.crypto.subtle.importKey(
         'raw',
         input,
         'PBKDF2',
         false,
         ['deriveBits', 'deriveKey']
      );

      const kbits = await window.crypto.subtle.deriveBits(
         {
            name: 'PBKDF2',
            salt: slt,
            iterations: this.ic,
            hash: 'SHA-512',
         },
         keyMaterial,
         KEY_BYTES * 2 * 8
      );

      const ebits = kbits.slice(0, KEY_BYTES);
      const sbits = kbits.slice(KEY_BYTES);

      // A bit of a hack, but subtle doesn't support other algorithms... so lie.
      // This is safe because the key is exported as bits and used in libsodium
      // TODO: If more non-browser cipher are added, make this more generic.
      const alg = this.alg != 'X20-PLY' ? this.alg : 'AES-GCM';

      // Will throw error if alg is invalid
      const ek = await window.crypto.subtle.importKey(
         'raw',
         ebits,
         { name: alg, length: 256 },
         true,
         ['encrypt', 'decrypt']
      );

      const sk = await window.crypto.subtle.importKey(
         'raw',
         sbits,
         { name: 'HMAC', hash: 'SHA-256', length: 256 },
         false,
         ['sign', 'verify']
      );
      return [ek, sk];
   }

   async encrypt(
      pwd: string,
      hint: string,
      signature: Uint8Array,
      clear: Uint8Array
   ): Promise<string> {

      if (!pwd || signature.byteLength == 0) {
         throw new Error('password or signature is empty');
      }

      // Setup EncContext for new key derivation (and encryption)
      // Create a new salt each time a key is derviced from the password.
      // https://crypto.stackexchange.com/questions/53032/salt-for-non-stored-passwords
      const randomArray = await Cipher.random40.getRandomArray(
         this.trueRand,
         this.fallbackRand
      );

      const slt = randomArray.slice(0, SLT_BYTES);
      const iv = randomArray.slice(SLT_BYTES, SLT_BYTES + IV_BYTES);

      const [ek, sk] = await this.genKeys(pwd, signature, slt);

      let encryptedBytes: Uint8Array;
      if (this.alg == 'X20-PLY') {
         const exported = await window.crypto.subtle.exportKey("raw", ek);
         const keyBytes = new Uint8Array(exported);

         await sodium.ready;
         encryptedBytes = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
            clear,
            null,
            null,
            iv,
            keyBytes,
            "uint8array"
         );
      } else {
         let enParams: EnDeParams = {
            name: this.alg,
         };

         if (this.alg == 'AES-CTR') {
            enParams['counter'] = iv.slice(0, 16);
            enParams['length'] = 64;
         } else {
            enParams['iv'] = iv.slice(0, 16);
         }

         const cipherBuf = await window.crypto.subtle.encrypt(
            enParams,
            ek,
            clear
         );
         encryptedBytes = new Uint8Array(cipherBuf);
      }
      const encoded = Cipher.encode({
         alg: this.alg,
         ic: this.ic,
         iv: iv,
         slt: slt,
         hint: hint,
         et: encryptedBytes
      });

      const hmac = await Cipher.sign(sk, encoded);

      let extended = new Uint8Array(hmac.byteLength + encoded.byteLength);
      extended.set(new Uint8Array(hmac));
      extended.set(encoded, hmac.byteLength);

      return bytesToBase64(extended);
   }

   static async decrypt(
      pwdProvider: (hint: string) => Promise<string>,
      signature: Uint8Array,
      ct: string
   ): Promise<Uint8Array> {

      // This does HMAC signature verification on CT and throws if invalid
      const [cparams, ek] = await Cipher.getCipherParamsImpl(
         pwdProvider,
         signature,
         ct
      );

      let decrypted: Uint8Array;

      if (cparams.alg == 'X20-PLY') {
         const exported = await window.crypto.subtle.exportKey("raw", ek);
         const keyBytes = new Uint8Array(exported);

         decrypted = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
            null,
            cparams.et,
            null,
            cparams.iv,
            keyBytes,
            "uint8array"
         );
      } else {
         let ed_params: EnDeParams = {
            name: cparams.alg,
         };

         if (cparams.alg == 'AES-CTR') {
            ed_params['counter'] = cparams.iv.slice(0, 16);
            ed_params['length'] = 64;
         } else {
            ed_params['iv'] = cparams.iv.slice(0, 16);
         }
         const buffer = await window.crypto.subtle.decrypt(ed_params, ek, cparams.et);
         decrypted = new Uint8Array(buffer);
      }

      return decrypted;
   }

   static async getCipherParams(
      pwdProvider: (hint: string) => Promise<string>,
      signature: Uint8Array,
      ct: string
   ): Promise<CParams> {

      // This does HMAC signature verification on CT and throws if invalid
      const [cparams, _] = await Cipher.getCipherParamsImpl(
         pwdProvider,
         signature,
         ct
      );

      return cparams;
   }

   private static async getCipherParamsImpl(
      pwdProvider: (hint: string) => Promise<string>,
      signature: Uint8Array,
      ct: string
   ): Promise<[CParams, CryptoKey]> {

      if (signature.byteLength == 0) {
         throw new Error('signature is empty');
      }

      const extended = base64ToBytes(ct);

      const hmac = extended.slice(0, HMAC_BYTES);
      if (hmac.byteLength != HMAC_BYTES) {
         throw new Error('Invalid HMAC length of: ' + hmac.byteLength);
      }
      const encoded = extended.slice(HMAC_BYTES);

      // Do not return this until signature verified. It may be used or the
      // data displayed by the caller so the signature must be verified first
      const cparams = Cipher.decode(encoded);

      const pwd = await pwdProvider(cparams.hint);
      if (!pwd) {
         throw new Error('password is empty');
      }

      let cipher = new Cipher(cparams.alg, cparams.ic);
      const [ek, sk] = await cipher.genKeys(pwd, signature, cparams.slt);

      // Avoiding the Doom Principle and verify signature before crypto operations.
      // Aka, check as soon as possible after we have the signing key. This will raise
      // and exception if invalid, but the boolean return is an extra precaution 
      // requiring an explicit true result and no exception
      const validSig = await Cipher.verify(sk, hmac, encoded);
      if (validSig) {
         return [cparams, ek];
      }

      // Should never get here since verify throws on bad signature
      throw new Error('Invalid HMAC signature');
   }

   static async sign(
      sk: CryptoKey,
      encoded: Uint8Array
   ): Promise<Uint8Array> {

      const hmac = await window.crypto.subtle.sign('HMAC', sk, encoded);
      if (hmac.byteLength != HMAC_BYTES) {
         throw new Error('Invalid HMAC length of: ' + hmac.byteLength);
      }

      return new Uint8Array(hmac);
   }

   static async verify(
      sk: CryptoKey,
      hmac: Uint8Array,
      encoded: Uint8Array
   ): Promise<boolean> {

      const valid = await window.crypto.subtle.verify('HMAC', sk, hmac, encoded);
      if (valid) {
         return true;
      }

      throw new Error('Invalid HMAC signature');
   }

   static encode(cparams: CParams): Uint8Array {

      Cipher.validateCParams(cparams);

      const icEnc = numToBytes(cparams.ic, IC_BYTES);
      const verEnc = numToBytes(CURRENT_VERSION, VER_BYTES);
      const algEnc = numToBytes(AlgInfo[cparams.alg][1], ALG_BYTES);

      // Should have have bee rejected at validateCParams above, but just in
      // case  limited to HINT_MAX_LEN characters so all can be double byte and
      // fit under 255 bytes. Note that this could be zero
      const hintEnc = new TextEncoder().encode(cparams.hint.slice(0, HINT_MAX_LEN)).slice(0, 256);
      const hintLenEnc = numToBytes(hintEnc.byteLength, 1);

      let encoded = new Uint8Array(
         ALG_BYTES +
         IV_BYTES +
         SLT_BYTES +
         IC_BYTES +
         VER_BYTES +
         1 +
         hintEnc.byteLength +
         cparams.et.byteLength
      );

      let offset = 0;
      encoded.set(algEnc, offset);
      offset += ALG_BYTES;
      encoded.set(cparams.iv, offset);
      offset += IV_BYTES;
      encoded.set(cparams.slt, offset);
      offset += SLT_BYTES;
      encoded.set(icEnc, offset);
      offset += IC_BYTES;
      encoded.set(verEnc, offset);
      offset += VER_BYTES;
      encoded.set(hintLenEnc, offset);
      offset += 1;
      encoded.set(hintEnc, offset);
      offset += hintEnc.byteLength;
      encoded.set(cparams.et, offset);

      return encoded;
   }

   static decode(encoded: Uint8Array): CParams {

      // Need to treat all values an UNTRUSTED since the signature has
      // not yet been tested (slt param extracted here is required) 

      if (encoded.byteLength < ALG_BYTES + IV_BYTES + SLT_BYTES + IC_BYTES +
         VER_BYTES + 1 + 1) {
         throw new Error('Invalid cparam lengths');
      }

      // Using validCParams isn't applicable because we're reading fixed lengths, 
      // and if some data was clipped (like say IV) we cannot tell until we do
      // the signature check (or if the data is clipped so much other values are
      // missing). Also want to for errors as we unpack

      let offset = 0;

      // ### algorithm id ###
      const algNum = bytesToNum(encoded.slice(offset, offset + ALG_BYTES));
      offset += ALG_BYTES;
      if (algNum < 1 || algNum > Object.keys(AlgInfo).length) {
         throw new Error('Invalid alg id of: ' + algNum);
      }

      let alg: string;
      for (alg in AlgInfo) {
         if (AlgInfo[alg][1] == algNum) {
            break;
         }
      }

      // ### iv ###
      const iv = encoded.slice(offset, offset + IV_BYTES);
      offset += IV_BYTES;
      // Should never happen because of overall length check abvoe, 
      // but... defense in depth in case of an oversight
      if (iv.byteLength != IV_BYTES) {
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
      const hintEnc = encoded.slice(offset, offset + hintLen)
      offset += hintLen;
      // Can happen if the encode data was clipped and reencoded
      if (hintLen != hintEnc.byteLength) {
         throw new Error('Hint length does not match: ' + hintEnc.byteLength);
      }
      const hint = new TextDecoder().decode(hintEnc);

      // ### encrypted text ###
      const et = encoded.slice(offset);
      // Agaim, can happen if the encode data was clipped and reencoded
      if (et.byteLength == 0) {
         throw new Error('Missing et data, found only: ' + et.byteLength);
      }

      return {
         alg: alg!,
         iv: iv,
         slt: slt,
         ic: ic,
         hint: hint,
         et: et,
      };
   }

   // Only useful for validatin CParmas before encoding. Decoded values are read with 
   // the correct sizes, so it depends on signature validate rather than decoded lengths
   static validateCParams(cparams: CParams) {
      //May want to make these message more helpful...
      if (!(cparams.alg in AlgInfo)) {
         throw new Error('Invalid alg of: ' + cparams.alg);
      }
      if (cparams.iv.byteLength != IV_BYTES) {
         throw new Error('Invalid iv len of: ' + cparams.iv.byteLength);
      }
      if (cparams.slt.byteLength != SLT_BYTES) {
         throw new Error('Invalid slt len: ' + cparams.slt.byteLength);
      }
      if (cparams.ic < ICOUNT_MIN || cparams.ic > ICOUNT_MAX) {
         throw new Error('Invalid ic of: ' + cparams.ic);
      }
      if (cparams.hint.length > HINT_MAX_LEN) {
         throw new Error('Invalid hint length of: ' + cparams.hint.length);
      }
   }
}
