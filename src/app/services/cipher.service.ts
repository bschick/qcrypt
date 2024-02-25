import { Injectable } from '@angular/core';
import * as sodium from 'libsodium-wrappers';
import { base64URLStringToBuffer, bufferToBase64URLString } from '@simplewebauthn/browser';

export const ICOUNT_MIN = 400000;
export const ICOUNT_DEFAULT = 800000;
export const ICOUNT_MAX = 4294000000; // limited to 4 bytes unsigned rounded to millions
export const HINT_MAX_LEN = 128;
export const CURRENT_VERSION = 1;

export const AlgInfo: { [key: string]: [string, number] } = {
  'AES-GCM': ['AES Galois Counter (GCM)', 1],
  'X20-PLY': ['XChaCha20 Poly1305', 2],
};

export type Params = {
  readonly alg: string;      // ALG_BYTES 
  readonly ic: number;       // IC_BYTES
  readonly hint: string;     // limited to 128 characters
}

// Byte length of all parameter except hint and et are fixed
export type CipherData = Params & {
  readonly iv: Uint8Array;   // IV_BYTES
  readonly slt: Uint8Array;  // SLT_BYTES
  readonly et: Uint8Array;
};

export type EParams = Params & {
  readonly trueRand: boolean;
  readonly fallbackRand: boolean;
  readonly pwd: string;
  readonly siteKey: Uint8Array;
  readonly ct: Uint8Array;
}

export const ALG_BYTES = 2;
export const IV_BYTES = 24;
export const SLT_BYTES = 16;
export const IC_BYTES = 4;
export const VER_BYTES = 2;
export const HMAC_BYTES = 32;
export const KEY_BYTES = 32;
export const SITEKEY_BYTES = 32;


/* Javascript converts to signed 32 bit int when using bit shifting 
   and masking, so do this instead. Count is the number of bytes
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

export class Random40 {
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
      return crypto.getRandomValues(new Uint8Array(40));
    } else {
      const lastCache = this.trueRandCache;
      this.trueRandCache = this.downloadTrueRand();
      return lastCache.then((response) => {
        if (!response.ok) {
          throw new Error('random.org response: ' + response.statusText);
        }
        return response.arrayBuffer();
      }).then((array) => {
        if (array.byteLength != 40) {
          throw new Error('missing bytes from random.org');
        }
        return new Uint8Array(array!);
      }).catch((err) => {
        console.error(err);
        // If pseudo random fallback is disabled, then throw error
        if (!fallback) {
          throw new Error('no connection to random.org and no fallback: ' + err.message);
        }
        return crypto.getRandomValues(new Uint8Array(40));
      });
    }
  }

  async downloadTrueRand(): Promise<Response> {
    const url = 'https://www.random.org/cgi-bin/randbyte?nbytes=' + 40;
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
  private random40Cache = new Random40();
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
  async _genCipherKey(
    alg: string,
    ic: number,
    pwd: string,
    siteKey: Uint8Array,
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
    if (siteKey.byteLength != SITEKEY_BYTES) {
      throw new Error("Invalid siteKey size of: " + siteKey.byteLength);
    }
    if (!pwd) {
      throw new Error('Invalid empty password');
    }
    if (ic < ICOUNT_MIN || ic > ICOUNT_MAX) {
      throw new Error('Invalid ic of: ' + ic);
    }

    const pwdBytes = new TextEncoder().encode(pwd);
    let rawMaterial = new Uint8Array(pwdBytes.byteLength + SITEKEY_BYTES)
    rawMaterial.set(pwdBytes);
    rawMaterial.set(siteKey, pwdBytes.byteLength);

    const ekMaterial = await window.crypto.subtle.importKey(
      'raw',
      rawMaterial,
      'PBKDF2',
      false,
      ['deriveBits', 'deriveKey']
    );

    // A bit of a hack, but subtle doesn't support other algorithms... so lie.
    // This is safe because the key is exported as bits and used in libsodium
    // TODO: If more non-browser cipher are added, make this more generic.
    const useAlg = alg != 'X20-PLY' ? alg : 'AES-GCM';

    const ek = await window.crypto.subtle.deriveKey(
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
    siteKey: Uint8Array,
    slt: Uint8Array
  ): Promise<CryptoKey> {

    if (slt.byteLength != SLT_BYTES) {
      throw new Error("Invalid slt size of: " + slt.byteLength);
    }

    // Confirm how  long PassKey signature will be and check for that directly
    if (siteKey.byteLength != SITEKEY_BYTES) {
      throw new Error('Invalid siteKey length of: ' + siteKey.byteLength);
    }
    const skMaterial = await window.crypto.subtle.importKey(
      'raw',
      siteKey,
      'HKDF',
      false,
      ['deriveBits', 'deriveKey']
    );

    const sk = await window.crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        salt: slt,
        hash: 'SHA-512',
        info: new Uint8Array(0),
      },
      skMaterial,
      { name: 'HMAC', hash: 'SHA-256', length: 256 },
      false,
      ['sign', 'verify']
    );

    return sk;
  }

  // Overall order of operations:
  //
  // 1. Generate new salt and iv/nonce values
  // 2. Encode cipher parameters as additional data
  // 3. Generate signing key from siteKey and cipher key from pwd + siteKey
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
    if (!eparams.pwd || eparams.siteKey.byteLength != SITEKEY_BYTES) {
      throw new Error('Invalid password or siteKey');
    }

    // assume encrypting nothing is a mistake
    if (eparams.ct.byteLength == 0) {
      throw new Error('No data to encrypt');
    }

    // Setup EncContext for new key derivation (and encryption)
    // Create a new salt each time a key is derviced from the password.
    // https://crypto.stackexchange.com/questions/53032/salt-for-non-stored-passwords
    const randomArray = await this.random40Cache.getRandomArray(
      eparams.trueRand,
      eparams.fallbackRand
    );

    const slt = randomArray.slice(0, SLT_BYTES);
    const iv = randomArray.slice(SLT_BYTES, SLT_BYTES + IV_BYTES);

    if (readyNotice) {
      readyNotice(eparams);
    }

    const cipherDataForAD: CipherData = {
      alg: eparams.alg,
      ic: eparams.ic,
      iv: iv,
      slt: slt,
      hint: eparams.hint,
      et: new Uint8Array(0)
    };

    const additionalData = this._encodeCipherData(cipherDataForAD);
    const ek = await this._genCipherKey(eparams.alg, eparams.ic, eparams.pwd, eparams.siteKey, slt);
    const sk = await this._genSigningKey(eparams.siteKey, slt);

    let encryptedBytes: Uint8Array;
    if (eparams.alg == 'X20-PLY') {
      const exported = await window.crypto.subtle.exportKey("raw", ek);
      const keyBytes = new Uint8Array(exported);

      await sodium.ready;
      try {
        encryptedBytes = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
          eparams.ct,
          additionalData,
          null,
          iv,
          keyBytes,
          "uint8array"
        );
      } catch (err) {
        // Match behavior of Web Crytpo functions that throws limited DOMException
        throw new DOMException('', 'OperationError');
      }
    } else {
      const cipherBuf = await window.crypto.subtle.encrypt({
          name: eparams.alg,
          iv: iv,
          additionalData: additionalData,
          tagLength: 128
        },
        ek, 
        eparams.ct
      );
      encryptedBytes = new Uint8Array(cipherBuf);
    }
    const encoded = this._encodeCipherData({
      ...cipherDataForAD,
      et: encryptedBytes
    });

    const hmac = await this._signCipherBytes(sk, encoded);

    let extended = new Uint8Array(hmac.byteLength + encoded.byteLength);
    extended.set(hmac);
    extended.set(encoded, hmac.byteLength);

    return bytesToBase64(extended);
  }

  // Password is a callback because we need to extract any hint from ciphertext first.
  // We also don't want the caller (web page) to show anything from extracted from
  // ciphertext until after it has been verified again the siteKey (pass-key). Order
  // of operations is:
  //
  // 1. Unpack parameters from ct
  // 1.1.    Unpack validated values and checks siteKey based signature
  // 2. Callback to get the password with the hint unpacked & validated hint
  // 3. Encode cipher parameters as additional data
  // 4. Generate cipher keys using returned pwd + siteKey
  // 5. Decrypt encrypted text using cipher key and addtional data
  // 6. Return cleat text bytes
  //
  async decrypt(
    pwdProvider: (hint: string) => Promise<string>,
    siteKey: Uint8Array,
    ct: string,
    readyNotice?: (params: Params) => void
  ): Promise<Uint8Array> {

    // This does HMAC signature verification on CT and throws if invalid
    const cipherData = await this.getCipherData(siteKey, ct);

    const pwd = await pwdProvider(cipherData.hint);
    if (!pwd) {
      throw new Error('password is empty');
    }

    if (readyNotice) {
      readyNotice(cipherData);
    }

    const cipherDataForAD: CipherData = {
      ...cipherData,
      et: new Uint8Array(0)
    };

    const additionalData = this._encodeCipherData(cipherDataForAD);
    const ek = await this._genCipherKey(cipherData.alg, cipherData.ic, pwd, siteKey, cipherData.slt);

    let decrypted: Uint8Array;
    if (cipherData.alg == 'X20-PLY') {
      const exported = await window.crypto.subtle.exportKey("raw", ek);
      const keyBytes = new Uint8Array(exported);

      try {
        decrypted = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
          null,
          cipherData.et,
          additionalData,
          cipherData.iv,
          keyBytes,
          "uint8array"
        );
      } catch (err) {
        // Match behavior of Web Crytpo functions that throws limited DOMException
        throw new DOMException('', 'OperationError');
      }

    } else {
      const buffer = await window.crypto.subtle.decrypt({
        name: cipherData.alg,
        iv: cipherData.iv,
        additionalData: additionalData,
        tagLength: 128
      },
        ek, cipherData.et
      );
      decrypted = new Uint8Array(buffer);
    }

    return decrypted;
  }

  async getCipherData(
    siteKey: Uint8Array,
    ct: string
  ): Promise<CipherData> {

    if (siteKey.byteLength != SITEKEY_BYTES) {
      throw new Error('Invalid siteKey length of: ' + siteKey.byteLength);
    }

    const extended = base64ToBytes(ct);
    const hmac = extended.slice(0, HMAC_BYTES);

    if (hmac.byteLength != HMAC_BYTES) {
      throw new Error('Invalid HMAC length of: ' + hmac.byteLength);
    }
    const encoded = extended.slice(HMAC_BYTES);

    // This is not a crypto function, just unpacking. We need to unpack to
    // get the salt used for signing key generation.
    //
    // IMPORTANT: The returned CParams could be corrupted. Do not return
    //       this to the caller until after signature verified.
    const cipherData = this._decodeCipherData(encoded);

    const sk = await this._genSigningKey(siteKey, cipherData.slt);

    // Avoiding the Doom Principle and verify signature before crypto operations.
    // Aka, check HMAC as soon as possible after we have the signing key.
    // _verifyCipherBytes should throw an exception if invalid, but the boolean
    // return is a precaution... requires an explicit true result and no exception
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

    const hmac = await window.crypto.subtle.sign('HMAC', sk, encoded);
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

    const valid = await window.crypto.subtle.verify('HMAC', sk, hmac, encoded);
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

    const icEnc = numToBytes(cipherData.ic, IC_BYTES);
    const verEnc = numToBytes(CURRENT_VERSION, VER_BYTES);
    const algEnc = numToBytes(AlgInfo[cipherData.alg][1], ALG_BYTES);

    // Should have have bee rejected at validateCipherData above, but just in
    // case  limited to HINT_MAX_LEN characters so all can be double byte and
    // fit under 255 bytes. Note that this could be zero
    const hintEnc = new TextEncoder().encode(cipherData.hint.slice(0, HINT_MAX_LEN)).slice(0, 256);
    const hintLenEnc = numToBytes(hintEnc.byteLength, 1);

    let encoded = new Uint8Array(
      ALG_BYTES +
      IV_BYTES +
      SLT_BYTES +
      IC_BYTES +
      VER_BYTES +
      1 +
      hintEnc.byteLength +
      cipherData.et.byteLength
    );

    let offset = 0;
    encoded.set(algEnc, offset);
    offset += ALG_BYTES;
    encoded.set(cipherData.iv, offset);
    offset += IV_BYTES;
    encoded.set(cipherData.slt, offset);
    offset += SLT_BYTES;
    encoded.set(icEnc, offset);
    offset += IC_BYTES;
    encoded.set(verEnc, offset);
    offset += VER_BYTES;
    encoded.set(hintLenEnc, offset);
    offset += 1;
    encoded.set(hintEnc, offset);
    offset += hintEnc.byteLength;
    encoded.set(cipherData.et, offset);

    return encoded;
  }

  // Importers of CipherService should not need this function directly,
  // but it is public for unit testing. Does not allow encoding
  // with zero length encrypted text since that is not needed
  _decodeCipherData(encoded: Uint8Array): CipherData {

    // Need to treat all values an UNTRUSTED since the signature has not
    // been tested (slt param extracted here is required for HMAC test)

    if (encoded.byteLength < ALG_BYTES + IV_BYTES + SLT_BYTES + IC_BYTES +
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
    if (hintLen != hintEnc.byteLength || hintLen > HINT_MAX_LEN) {
      throw new Error('Invalid hint length of: ' + hintLen);
    }
    const hint = new TextDecoder().decode(hintEnc);

    // ### encrypted text ###
    const et = encoded.slice(offset);
    // Again, can happen if the encode data was clipped and reencoded
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
  validateCipherData(cipherData: CipherData) {
    //May want to make these message more helpful...
    if (!(cipherData.alg in AlgInfo)) {
      throw new Error('Invalid alg of: ' + cipherData.alg);
    }
    if (cipherData.iv.byteLength != IV_BYTES) {
      throw new Error('Invalid iv len of: ' + cipherData.iv.byteLength);
    }
    if (cipherData.slt.byteLength != SLT_BYTES) {
      throw new Error('Invalid slt len: ' + cipherData.slt.byteLength);
    }
    if (cipherData.ic < ICOUNT_MIN || cipherData.ic > ICOUNT_MAX) {
      throw new Error('Invalid ic of: ' + cipherData.ic);
    }
    if (cipherData.hint.length > HINT_MAX_LEN) {
      throw new Error('Invalid hint length of: ' + cipherData.hint.length);
    }
  }

}
