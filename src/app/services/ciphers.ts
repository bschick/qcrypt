/* MIT License

Copyright (c) 2025 Brad Schick

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
import { getRandom48, numToBytes, bytesToNum, BYOBStreamReader, bytesFromString } from './utils';
import * as cc from './cipher.consts';

// Simple perf testing with Chrome 126 on MacOS result in
// readAvailable with READ_SIZE_MAX of 4x to be the fastest
const READ_SIZE_START = 1048576; // 1 MiB
const READ_SIZE_MAX = READ_SIZE_START * 4;

// Used to create hardcoded cipherdata for some tests
//    NOTE: should find a better way to generate test data since
//    its too easy for forget to restore these values (resulting in inefficient
//    blocks)
//const READ_SIZE_START = 1048576/1024/4;
//const READ_SIZE_MAX =  READ_SIZE_START * 41;
//const READ_SIZE_START = 9;
//const READ_SIZE_MAX = READ_SIZE_START * 16


export type PWDProvider = (
   cdInfo: CipherDataInfo,
   encrypting: boolean
) => Promise<[string, string | undefined]>;

export enum CipherState {
   Error,
   Initialized,
   Block0Decoded,
   Block0Done,
   Finished
}

export type CipherDataBlock = {
   readonly parts: Uint8Array[];
   readonly state: CipherState;
};

export type CipherDataInfo = {
   readonly ver: number;
   readonly alg: string;
   readonly ic: number;
   readonly lp: number;
   readonly lpEnd: number;
   readonly iv: Uint8Array;
   readonly slt: Uint8Array;
   readonly hint?: string;
};

export type EParams = {
   readonly alg: string;
   readonly ic: number;
   readonly lp: number;
   readonly lpEnd: number;
};


// To geenrate matching keys, these must not change
const HKDF_INFO_SIGNING = "cipherdata signing key";
const HKDF_INFO_HINT = "hint encryption key";


export abstract class Ciphers {

   protected _ek?: CryptoKey;
   protected _sk?: CryptoKey;

   protected _reader: BYOBStreamReader;
   protected _userCred?: Uint8Array;
   protected _state: CipherState;

   protected constructor(
      userCred: Uint8Array,
      reader: BYOBStreamReader
   ) {
      if (!userCred || userCred.byteLength != cc.USERCRED_BYTES) {
         throw new Error('Invalid userCred');
      }

      this._state = CipherState.Initialized;
      this._userCred = userCred;
      this._reader = reader;
   }

   public finishedState() {
      this._state = CipherState.Finished;

      // Don't overwrite because this is only a reference
      this._userCred = undefined;
      this._ek = undefined;
      this._sk = undefined;
      this._reader.cleanup();
   }

   public errorState() {
      this._state = CipherState.Error;

      // Don't overwrite because this is only a reference
      this._userCred = undefined;
      this._ek = undefined;
      this._sk = undefined;
      this._reader.cleanup();
   }

   public abstract protocolVersion(): number;

   static async benchmark(
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

   static validateAlg(alg: string): boolean {
      return Object.keys(cc.AlgInfo).includes(alg);
   }

   static findAlg(algNum: number): string {
      if (algNum < 1 || algNum > Object.keys(cc.AlgInfo).length) {
         throw new Error('Invalid alg id of: ' + algNum);
      }

      let alg: string | undefined;
      for (alg in cc.AlgInfo) {
         if (cc.AlgInfo[alg]['id'] == algNum) {
            break;
         }
      }

      if (!alg) {
         throw new Error('Invalid alg id of: ' + algNum);
      }

      return alg!;
   }


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
      if (!pwd) {
         throw new Error('Invalid empty password');
      }
      if (userCred.byteLength != cc.USERCRED_BYTES) {
         throw new Error("Invalid userCred length of: " + userCred.byteLength);
      }
      if (slt.byteLength != cc.SLT_BYTES) {
         throw new Error("Invalid slt length of: " + slt.byteLength);
      }

      const pwdBytes = new TextEncoder().encode(pwd);
      let rawMaterial = new Uint8Array(pwdBytes.byteLength + cc.USERCRED_BYTES)
      rawMaterial.set(pwdBytes);
      rawMaterial.set(userCred, pwdBytes.byteLength);

      /* Maybe someday, but requires SUMO version of libsodium.js
            await sodium.ready;
            const rawKey = sodium.crypto_pwhash(
               32,
               rawMaterial,
               slt,
               sodium.crypto_pwhash_OPSLIMIT_MODERATE,
               sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
               sodium.crypto_pwhash_ALG_ARGON2I13,
               "uint8array"
            );

            const ek = await crypto.subtle.importKey(
               'raw',
               rawKey,
               'AES-GCM',
               true,
               ['encrypt', 'decrypt']
            );
      */
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

      if (userCred.byteLength != cc.USERCRED_BYTES) {
         throw new Error('Invalid userCred length of: ' + userCred.byteLength);
      }
      if (slt.byteLength != cc.SLT_BYTES) {
         throw new Error("Invalid slt length of: " + slt.byteLength);
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

      if (!Ciphers.validateAlg(alg)) {
         throw new Error('Invalid alg: ' + alg);
      }
      if (userCred.byteLength != cc.USERCRED_BYTES) {
         throw new Error('Invalid userCred length of: ' + userCred.byteLength);
      }
      if (slt.byteLength != cc.SLT_BYTES) {
         throw new Error("Invalid slt length of: " + slt.byteLength);
      }

      const hkMaterial = await crypto.subtle.importKey(
         'raw',
         userCred,
         'HKDF',
         false,
         ['deriveBits', 'deriveKey']
      );

      // A bit of a hack, but subtle doesn't support other algorithms... so lie. This
      // is safe because the key is exported as bits and used in libsodium when not
      // AES-GCM. TODO: If more non-browser cipher are added, make this more generic.
      const dkAlg = 'AES-GCM';

      const hk = await crypto.subtle.deriveKey(
         {
            name: 'HKDF',
            salt: slt,
            hash: 'SHA-512',
            info: new TextEncoder().encode(HKDF_INFO_HINT)
         },
         hkMaterial,
         { name: dkAlg, length: 256 },
         true,
         ['encrypt', 'decrypt']
      );

      return hk;
   }

   // Only useful for validating params before encoding. Decoded values are read with
   // expected sizes, so validity depends on signature validate rather than decoded lengths
   public static validateAdditionalData(
      args: {
         alg: string;
         iv: Uint8Array;
         ic?: number;
         slt?: Uint8Array;
         lp?: number;
         lpEnd?: number;
         ver?: number;
         encryptedHint?: Uint8Array
      }) {

      if (!Ciphers.validateAlg(args.alg)) {
         throw new Error('Invalid alg: ' + args.alg);
      }

      const ivBytes = Number(cc.AlgInfo[args.alg]['iv_bytes']);
      if (args.iv.byteLength != ivBytes) {
         throw new Error('Invalid iv size: ' + args.iv.byteLength);
      }

      if (args.ic && (args.ic < cc.ICOUNT_MIN || args.ic > cc.ICOUNT_MAX)) {
         throw new Error('Invalid ic: ' + args.ic);
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

      if (args.lpEnd) {
         if (!args.lp) {
            throw new Error('Missing lp');
         }
         if (args.lpEnd < 1 || args.lpEnd > cc.LP_MAX) {
            throw new Error('Invalid lpEnd: ' + args.lpEnd);
         }
         if (args.lp < 1 || args.lp > args.lpEnd) {
            throw new Error('Invalid lp: ' + args.lp);
         }
      } else if (args.lp) {
         throw new Error('Missing lpEnd');
      }

      // Should move this to subclasses... later...
      if (args.ver && args.ver != cc.VERSION1) {
         // Only V1 put version in additional data
         throw new Error('Unexpected version: ' + args.ver);
      }

      if (args.ver && args.lp) {
         throw new Error('Unexpected version and lp');
      }

      if (args.encryptedHint && (args.encryptedHint.length > cc.ENCRYPTED_HINT_MAX_BYTES)) {
         throw new Error('Invalid encrypted hint length: ' + args.encryptedHint.length);
      }
   }

   protected static _encodeAdditionalData(
      args: {
         alg: string;
         iv: Uint8Array;
         ic?: number;
         slt?: Uint8Array;
         lp?: number;
         lpEnd?: number;
         ver?: number;
         encryptedHint?: Uint8Array
      }): Uint8Array {

      Ciphers.validateAdditionalData(args);

      // Packer validates ranges as values are added
      const packer = new Packer(cc.ADDIONTAL_DATA_MAX_BYTES);

      packer.alg = args.alg;
      packer.iv = args.iv;

      if (args.slt) {
         packer.slt = args.slt;
      }

      if (args.ic) {
         packer.ic = args.ic;
      }

      if (args.lp && args.lpEnd) {
         packer.lpp(args.lp, args.lpEnd);
      }

      if (args.ver) {
         packer.ver = args.ver;
      }

      if (args.encryptedHint != undefined) {
         packer.hint = args.encryptedHint;
      }

      return packer.trim();
   }
}


export abstract class Encipher extends Ciphers {

   public static latest(
      userCred: Uint8Array,
      clearStream: ReadableStream<Uint8Array>
   ): Encipher {
      const reader = new BYOBStreamReader(clearStream);
      return new EncipherV5(userCred, reader);
   }

   protected constructor(
      userCred: Uint8Array,
      reader: BYOBStreamReader,
      ver: number
   ) {
      super(userCred, reader);
   }

   // The encryptBlock functions return CipherDataBlock instead of
   // an opaque byte array to reduce copying (the caller must write
   // all the blocks in order)

   // Helper that calls Block0 until ~success then BlockN
   public abstract encryptBlock(
      eparams: EParams,
      pwdProvider: PWDProvider
   ): Promise<CipherDataBlock>;

   public abstract encryptBlock0(
      eparams: EParams,
      pwdProvider: PWDProvider
   ): Promise<CipherDataBlock>;

   public abstract encryptBlockN(
      eparams: EParams
   ): Promise<CipherDataBlock>;

};


// Exported just for testing
export class EncipherV5 extends Encipher {
   /* V5 CipherData Layout. Tags are just notations,
    * and are not actually in the data stream. All encodings have one block0 instance
    * followed by zero or more blockN instances

      <Document>
         <Block0>
            <Header>
               MAC_BYTES - 32
               VER_BYTES - 2
               PAYLOAD_SIZE_BYTES - 3
               FLAGS_BYTES - 1
            </Header>
            <Payload>
               <Additional Data>
                  ALG_BYTES - 2
                  IV_BYTES (variable) - [12, 24, 32]
                  SLT_BYTES - 16
                  IC_BYTES - 4
                  LPP_BYTES (packed lp and lpEnd) - 1
                  EHINT_LEN_BYTES - 1
                  EHINT_BYTES (variable) - [0-128]
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
               FLAGS_BYTES
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

   private _readTarget = READ_SIZE_START;
   private _lastMac!: Uint8Array;
   private _slt!: Uint8Array; // stored as class member to help with testings

   constructor(
      userCred: Uint8Array,
      reader: BYOBStreamReader
   ) {
      super(userCred, reader, cc.VERSION5);
   }

   public override protocolVersion(): number {
      return cc.VERSION5;
   }

   override async encryptBlock(
      eparams: EParams,
      pwdProvider: PWDProvider
   ): Promise<CipherDataBlock> {

      if (this._state == CipherState.Initialized) {
         return this.encryptBlock0(eparams, pwdProvider);
      } else if (this._state == CipherState.Block0Done) {
         return this.encryptBlockN(eparams);
      } else {
         throw new Error(`Encipher invalid state ${this._state}`);
      }
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
      pwdProvider: PWDProvider
   ): Promise<CipherDataBlock> {

      try {
         EncipherV5.validateEParams(eparams);
         if (this._state != CipherState.Initialized) {
            throw new Error(`Encipher invalid state ${this._state}`);
         }

         if (this._sk || this._ek) {
            throw new Error('encryptBlock0 should only be called once');
         }

         const [clearBuffer, done] = await this._reader.readAvailable(
            new Uint8Array(this._readTarget)
         );

         if (clearBuffer.byteLength == 0) {
            if (done) {
               // must always have a block0
               throw new Error('Missing clear data');
            }
            // This can happen when the stream isn't done but return no data
            // callers should call encryptBlock0 again
            this._state = CipherState.Initialized;

            return {
               parts: [],
               state: this._state
            };
         }

         // Create a new salt and IV each time a key is derviced from the password.
         // https://crypto.stackexchange.com/questions/53032/salt-for-non-stored-passwords
         const randomArray = await getRandom48();

         const ivBytes = Number(cc.AlgInfo[eparams.alg]['iv_bytes']);
         this._slt = randomArray.slice(0, cc.SLT_BYTES);
         const iv = randomArray.slice(cc.SLT_BYTES, cc.SLT_BYTES + ivBytes);

         const [pwd, hint] = await pwdProvider({
               ver: cc.VERSION5,
               alg: eparams.alg,
               ic: eparams.ic,
               slt: this._slt,
               lp: eparams.lp,
               lpEnd: eparams.lpEnd,
               iv: iv,
               hint: undefined
            },
            true
         );
         if (hint && hint.length > cc.HINT_MAX_LEN) {
            throw new Error('Hint length exceeds: ' + cc.HINT_MAX_LEN);
         }
         if (!pwd) {
            throw new Error('Missing password');
         }

         const hk = await Ciphers._genHintCipherKey(eparams.alg, this._userCred!, this._slt);
         this._sk = await Ciphers._genSigningKey(this._userCred!, this._slt);
         this._ek = await Ciphers._genCipherKey(eparams.alg, eparams.ic, pwd, this._userCred!, this._slt);

         let encryptedHint = new Uint8Array(0);
         if (hint) {
            const maxHintBytes = cc.ENCRYPTED_HINT_MAX_BYTES - cc.AUTH_TAG_MAX_BYTES;
            let hintBytes = bytesFromString(hint, maxHintBytes);

            // It's possible that even a single character (e.g. emoji) might exceed maxHintBytes
            // If so proceed without a hint.
            if (hintBytes.byteLength > 0) {
               encryptedHint = await EncipherV5._doEncrypt(
                  eparams.alg,
                  hk,
                  iv,
                  hintBytes
               );
            }
         }

         const additionalData = Ciphers._encodeAdditionalData({
            alg: eparams.alg,
            iv: iv,
            ic: eparams.ic,
            lp: eparams.lp,
            lpEnd: eparams.lpEnd,
            slt: this._slt,
            encryptedHint: encryptedHint
         });

         const encryptedData = await EncipherV5._doEncrypt(
            eparams.alg,
            this._ek,
            iv,
            clearBuffer,
            additionalData,
         );

         const [headerData, mac] = await EncipherV5._createHeader(
            this._sk,
            encryptedData,
            additionalData,
            new Uint8Array(0),
            done
         );

         this._lastMac = mac;

         if (done) {
            this.finishedState();
         } else {
            this._state = CipherState.Block0Done;
         }

         return {
            parts: [
               headerData,
               additionalData,
               encryptedData
            ],
            state: this._state
         };
      } catch (err) {
         this.errorState();
         console.error(err);
         throw err;
      }
   }

   override async encryptBlockN(
      eparams: EParams
   ): Promise<CipherDataBlock> {

      try {
         EncipherV5.validateEParams(eparams);
         if (this._state != CipherState.Block0Done) {
            throw new Error(`Encipher invalid state ${this._state}`);
         }

         if (!this._sk || !this._ek) {
            throw new Error('Data not initialized, encrypt block0 first');
         }

         this._readTarget = Math.min(this._readTarget * 2, READ_SIZE_MAX);
         const [clearBuffer, done] = await this._reader.readAvailable(
            new Uint8Array(this._readTarget)
         );

         // There can be read stalls, caller must be ready to ignore empty results
         // and call BlockN again when state is not Finished
         if (clearBuffer.byteLength == 0) {
            return {
               parts: [],
               state: this._state
            };
         }

         const randomArray = await getRandom48();

         const ivBytes = Number(cc.AlgInfo[eparams.alg]['iv_bytes']);
         const iv = randomArray.slice(0, ivBytes);

         const additionalData = Ciphers._encodeAdditionalData({
            alg: eparams.alg,
            iv: iv
         });

         const encryptedData = await EncipherV5._doEncrypt(
            eparams.alg,
            this._ek,
            iv,
            clearBuffer,
            additionalData,
         );

         // chain mac value from last block so that order changes will cause failure
         const [headerData, mac] = await EncipherV5._createHeader(
            this._sk,
            encryptedData,
            additionalData,
            this._lastMac,
            done
         );

         this._lastMac = mac;

         if (done) {
            this.finishedState();
         }

         return {
            parts: [
               headerData,
               additionalData,
               encryptedData
            ],
            state: this._state
         };
      } catch (err) {
         this.errorState();
         console.error(err);
         throw err;
      }
   }

   public static validateEParams(eparams: EParams) {
      const {
         alg,
         ic,
         lp,
         lpEnd
      } = eparams;

      if (!Ciphers.validateAlg(alg)) {
         throw new Error('Invalid alg type of: ' + alg);
      }
      if (ic < cc.ICOUNT_MIN || ic > cc.ICOUNT_MAX) {
         throw new Error('Invalid ic of: ' + ic);
      }
      if (lpEnd < 1 || lpEnd > cc.LP_MAX) {
         throw new Error('Invalid lpEnd: ' + lpEnd);
      }
      if (lp < 1 || lp > lpEnd) {
         throw new Error('Invalid lp: ' + lp);
      }
   }

   // Helper function
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
            // Match behavior of Web Crytpo functions that throws limited DOMException
            const msg = err instanceof Error ? err.message : '';
            throw new DOMException(msg, 'OperationError ');
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
            // Match behavior of Web Crytpo functions that throws limited DOMException
            const msg = err instanceof Error ? err.message : '';
            throw new DOMException(msg, 'OperationError ');
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

   // Seperated out and made public for testing, normal callers should not be needed this
   public static async _createHeader(
      sk: CryptoKey,
      encryptedData: Uint8Array,
      additionalData: Uint8Array,
      lastMac: Uint8Array,
      terminalBlock: boolean
   ): Promise<[Uint8Array, Uint8Array]> {

      const payloadBytes = encryptedData.byteLength + additionalData.byteLength;
      // Packer validates ranges as values are added
      const packer = new Packer(cc.HEADER_BYTES, cc.MAC_BYTES);
      packer.ver = cc.VERSION5;
      packer.size = payloadBytes;
      // Will be a bitfield when more flags are needed
      packer.flags = terminalBlock ? 1 : 0;

      const exportedSk = await crypto.subtle.exportKey("raw", sk);
      const skData = new Uint8Array(exportedSk);

      const state = sodium.crypto_generichash_init(skData, cc.MAC_BYTES);
      sodium.crypto_generichash_update(state, new Uint8Array(packer.buffer, cc.MAC_BYTES));
      sodium.crypto_generichash_update(state, additionalData);
      sodium.crypto_generichash_update(state, encryptedData);
      sodium.crypto_generichash_update(state, lastMac);

      const mac = sodium.crypto_generichash_final(state, cc.MAC_BYTES);
      packer.offset = 0;
      packer.mac = mac;

      return [packer.detach(), mac];
   }
}

type BlockData = {
   readonly mac: Uint8Array;
   readonly ver: number;
   readonly payloadSize: number;
   readonly flags: number;
   alg?: string;
   iv?: Uint8Array;
   encryptedData?: Uint8Array;
   additionalData?: Uint8Array;
};

export abstract class Decipher extends Ciphers {

   protected _blockData?: BlockData; // keep block specific data together to make clear less error prone
   protected _slt?: Uint8Array;
   protected _ic?: number;
   protected _lp: number = 1; // Not all version support loop # so provide a default
   protected _lpEnd: number = 1; // Not all version support loop # so provide a default
   protected _hint?: string;

   // Return appropriate version of Ciphers
   public static async fromStream(
      userCred: Uint8Array,
      cipherStream: ReadableStream<Uint8Array>
   ): Promise<Decipher> {

      let decipher: Decipher;
      const reader = new BYOBStreamReader(cipherStream);

      const [header, done] = await reader.readFill(new Uint8Array(cc.HEADER_BYTES));

      if (header.byteLength != cc.HEADER_BYTES || done) {
         reader.cleanup();
         throw new Error('Invalid cipher stream length: ' + header.byteLength);
      }

      // This is rather ugly, but the original CiphersV1 encoding stupidly had the
      // version in the middle of the encoding. So detect old version by the first 2 bytes
      // after MAC being < 4 (since encoded started with ALG and v1 max ALG was 3 and beyond v1
      // version is >=4). Fortunately ALG_BYTES and VER_BYTES are equal.
      const verOrAlg = bytesToNum(new Uint8Array(header.buffer, cc.MAC_BYTES, cc.VER_BYTES));
      if (verOrAlg == cc.VERSION5) {
         decipher = new DecipherV5(userCred, reader, header);
      } else if (verOrAlg == cc.VERSION4) {
         decipher = new DecipherV4(userCred, reader, header);
      } else if (verOrAlg < cc.V1_BELOW && verOrAlg > 0) {
         decipher = new DecipherV1(userCred, reader, header);
      } else {
         throw new Error('Invalid version: ' + verOrAlg);
      }

      return decipher;
   }

   // When decryptBlock functions return an empty byte array, the
   // stream is done. It work like this because these function
   // retry until each block is read and decrypted (so only return
   // empty when done)

   // Helper that calls Block0 until ~success then BlockN
   async decryptBlock(
      pwdProvider: PWDProvider
   ): Promise<Uint8Array> {

      if ([CipherState.Initialized, CipherState.Block0Decoded].includes(this._state)) {
         return this.decryptBlock0(pwdProvider);
      } else if (this._state == CipherState.Block0Done) {
         return this.decryptBlockN();
      } else {
         throw new Error(`Decipher invalid state ${this._state}`);
      }
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
   public async decryptBlock0(
      pwdProvider: PWDProvider
   ): Promise<Uint8Array> {

      try {
         if (![CipherState.Initialized, CipherState.Block0Decoded].includes(this._state)) {
            throw new Error(`Decipher invalid state ${this._state}`);
         }

         if (this._ek) {
            throw new Error('Decipher unexpected encryption key');
         }

         if (this._userCred!.byteLength != cc.USERCRED_BYTES) {
            throw new Error('Invalid userCred length of: ' + this._userCred!.byteLength);
         }

         // This does MAC check
         await this._decodePayload0();

         if (!this._blockData || !this._blockData.alg || !this._blockData.iv || !this._blockData.encryptedData || !this._slt || !this._ic) {
            throw new Error('Data not initialized');
         }

         const [pwd] = await pwdProvider({
               ver: this._blockData.ver,
               alg: this._blockData.alg,
               ic: this._ic,
               slt: this._slt,
               lp: this._lp,
               lpEnd: this._lpEnd,
               iv: this._blockData.iv,
               hint: this._hint
            },
            false
         );
         if (!pwd) {
            throw new Error('password is empty');
         }

         this._ek = await Ciphers._genCipherKey(this._blockData.alg, this._ic, pwd, this._userCred!, this._slt);

         const decrypted = await Decipher._doDecrypt(
            this._blockData.alg,
            this._ek,
            this._blockData.iv,
            this._blockData.encryptedData,
            this._blockData.additionalData,
         );

         this._state = CipherState.Block0Done;
         return decrypted;
      } catch (err) {
         this.errorState();
         console.error(err);
         throw err;
      } finally {
         this._blockData = undefined;
      }
   }

   //public only for testing
   abstract _decodePayload0(): Promise<void>;

   public abstract decryptBlockN(): Promise<Uint8Array>;

   public async getCipherDataInfo(
   ): Promise<CipherDataInfo> {

      // This does MAC check
      await this._decodePayload0();

      if (!this._blockData || !this._blockData.alg || !this._blockData.iv || !this._slt || !this._ic) {
         throw new Error('Data not initialized');
      }

      return {
         ver: this._blockData.ver,
         alg: this._blockData.alg,
         ic: this._ic,
         slt: this._slt,
         lp: this._lp,
         lpEnd: this._lpEnd,
         iv: this._blockData.iv,
         hint: this._hint
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
            // Match behavior of Web Crytpo functions that throws limited DOMException
            const msg = err instanceof Error ? err.message : '';
            throw new DOMException(msg, 'OperationError ');
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
            // Match behavior of Web Crytpo functions that throws limited DOMException
            const msg = err instanceof Error ? err.message : '';
            throw new DOMException(msg, 'OperationError ');
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
};


class DecipherV1 extends Decipher {
   /* V1 CipherData Layout (it was a bit brain-dead, but it wasn't written to files)
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

   private _headerish?: Uint8Array;

   constructor(
      userCred: Uint8Array,
      reader: BYOBStreamReader,
      headerish?: Uint8Array
   ) {
      super(userCred, reader);

      // V1 didn't really have a header, save the data to combine
      // with the rest of the stream for decoding
      this._headerish = headerish;
   }

   public override protocolVersion(): number {
      return cc.VERSION1;
   }

   // For V1, this should be the entire CipherData array
   override async _decodePayload0(): Promise<void> {

      try {
         if (![CipherState.Initialized, CipherState.Block0Decoded].includes(this._state)) {
            throw new Error(`Decipher invalid state ${this._state}`);
         }

         // May be called multiple times calling getCipherDataInfo or others.
         if (this._state == CipherState.Block0Decoded) {
            return;
         }

         if (this._sk) {
            throw new Error('Decipher unexpected signing key');
         }

         // This isn't very efficient, but it simplifies object creation and V4 logic
         // (which are more important)
         let [payload] = await this._reader.readFill(new Uint8Array(cc.PAYLOAD_SIZE_MAX));

         if (this._headerish) {
            const newPayload = new Uint8Array(this._headerish.byteLength + payload.byteLength);
            newPayload.set(this._headerish);
            newPayload.set(payload, this._headerish.byteLength);
            this._headerish = undefined;
            payload = newPayload;
         }

         // V1 should test be larger, but this get simple cases
         if (payload.byteLength < cc.PAYLOAD_SIZE_MIN) {
            throw new Error('Invalid paysload size1: ' + payload.byteLength);
         }

         // Need to treat all values an UNTRUSTED since the signature has not yet been
         // validated, Extractor does test each value for valid ranges as we unpack
         let extractor = new Extractor(payload);

         // Order must be invariant (as oringally laid out in v1)
         const mac = extractor.mac;
         const alg = extractor.alg;
         const iv = extractor.iv;
         this._slt = extractor.slt;
         this._ic = extractor.ic;
         const ver = extractor.ver;
         if (ver != cc.VERSION1) {
            throw new Error('Invalid version of: ' + ver);
         }
         const encryptedHint = extractor.hint;
         const encryptedData = extractor.remainder('edata');

         // Repack because we don't have the contiguous data any longer
         const additionalData = Ciphers._encodeAdditionalData({
            alg: alg,
            iv: iv,
            ver: ver,
            ic: this._ic,
            slt: this._slt,
            encryptedHint: encryptedHint
         });

         this._blockData = {
            mac: mac,
            ver: ver,
            payloadSize: payload.byteLength,
            flags: 0,
            alg: alg,
            iv: iv,
            encryptedData: encryptedData,
            additionalData: additionalData
         }

         this._sk = await Ciphers._genSigningKey(this._userCred!, this._slt);

         // Avoiding the Doom Principle and verify signature before crypto operations.
         // Aka, check MAC as soon as possible after we  have the signing key and data.
         // Might be cleaner to do this elswhere, but keeping it at the lowest level
         // ensures we don't skip the step
         const validMac: boolean = await this._verifyMAC();
         if (!validMac) {
            throw new Error('Invalid MAC error');
         }

         let hint = new Uint8Array(0);
         if (encryptedHint!.byteLength != 0) {
            const hk = await Ciphers._genHintCipherKey(this._blockData.alg!, this._userCred!, this._slt);
            hint = await Decipher._doDecrypt(
               this._blockData.alg!,
               hk,
               this._blockData.iv!,
               encryptedHint
            );
         }

         this._hint = new TextDecoder().decode(hint)
         this._state = CipherState.Block0Decoded;

      } catch (err) {
         this.errorState();
         console.error(err);
         throw err;
      }
   }

   private async _verifyMAC(): Promise<boolean> {

      if (!this._blockData || !this._blockData.additionalData || !this._blockData.encryptedData || !this._sk || !this._blockData) {
         throw new Error('Invalid MAC data');
      }

      const data = new Uint8Array(this._blockData.additionalData.byteLength + this._blockData.encryptedData.byteLength);
      data.set(this._blockData.additionalData);
      data.set(this._blockData.encryptedData, this._blockData.additionalData.byteLength);

      // V1 uses HMAC from webcrypto
      const valid: boolean = await crypto.subtle.verify('HMAC', this._sk, this._blockData.mac, data);
      if (valid) {
         return true;
      }

      throw new Error('Invalid HMAC signature');
   }

   public override async decryptBlockN(): Promise<Uint8Array> {
      if (this._state != CipherState.Block0Done) {
         throw new Error('Decipher block0 not complete');
      }
      this.finishedState();

      // This is the signal decrytion is done. V1 never has more than block0
      return new Uint8Array();
   }

}


class DecipherV4 extends Decipher {
   /* V4 CipherData Layout (hopefully less brain dead). Tags are just notation...
    * and are not actually in the data stream. All encodings have one block0 instance
    * followed by zero or more blockN instances

      <Document>
         <Block0>
            <Header>
               MAC_BYTES - 32
               VER_BYTES - 2
               PAYLOAD_SIZE_BYTES - 4
            </Header>
            <Payload>
               <Additional Data>
                  ALG_BYTES - 2
                  IV_BYTES (variable) - [12, 24, 32]
                  SLT_BYTES - 16
                  IC_BYTES - 4
                  LPP_BYTES (packed lp and lpEnd) - 1
                  EHINT_LEN_BYTES - 1
                  EHINT_BYTES (variable) - [0-128]
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

   private _header?: Uint8Array;

   constructor(
      userCred: Uint8Array,
      reader: BYOBStreamReader,
      header?: Uint8Array
   ) {
      super(userCred, reader);
      this._header = header;
   }

   public override protocolVersion(): number {
      return cc.VERSION4;
   }

   private async _decodeHeader(header?: Uint8Array): Promise<boolean> {

      // Need to treat all values an UNTRUSTED since the signature has not yet been
      // validated.
      if (!header) {
         let done: boolean;
         [header, done] = await this._reader.readFill(new Uint8Array(cc.HEADER_BYTES));
         if (header.byteLength > 0 && (done || header.byteLength < cc.HEADER_BYTES)) {
            this._reader.cleanup();
            throw new Error('Missing cipher data header');
         }
      }

      // This signals successful completion of block reads
      if (header.byteLength == 0) {
         return true;
      }

      const extractor = new Extractor(header);

      // Order must be invariant
      const mac = extractor.mac;
      const ver = extractor.ver;
      if (ver != this.protocolVersion()) {
         throw new Error('Invalid version of: ' + ver);
      }
      const payloadSize = extractor.size;
      // V4 did not use flags, but had extra byte in payloadSize. Extract to move offset
      const flags = extractor.flags;

      this._blockData = {
         mac: mac,
         ver: ver,
         payloadSize: payloadSize,
         flags: flags,
      }

      return false;
   }

   // Importers of CipherService should not need this function directly,
   // but it is public for unit testing. Does not allow encoding
   // with zero length encrypted text since that is not needed
   override async _decodePayload0(): Promise<void> {

      try {
         if (![CipherState.Initialized, CipherState.Block0Decoded].includes(this._state)) {
            throw new Error(`Decipher invalid state ${this._state}`);
         }

         if (this._state == CipherState.Block0Decoded) {
            // If already decoded, return early since the state was saved
            return;
         }

         if (this._sk) {
            throw new Error('Decipher unexpected signing key');
         }

         await this._decodeHeader(this._header);
         this._header = undefined;

         if (!this._blockData) {
            throw new Error('Data not initialized');
         }

         // Need to treat all values an UNTRUSTED since the signature has not yet been
         // validated, Extractor does test each value for valid ranges as we unpack

         if (!this._blockData.payloadSize) {
            throw new Error('Invalid payload size1: ' + this._blockData.payloadSize);
         }

         const [payload, done] = await this._reader.readFill(new Uint8Array(this._blockData.payloadSize));
         if (done) {
            this._reader.cleanup();
         }

         if (payload.byteLength != this._blockData.payloadSize) {
            throw new Error('Cipher data length mismatch1: ' + payload.byteLength);
         }

         let extractor = new Extractor(payload);

         // Order must be invariant
         this._blockData.alg = extractor.alg;
         this._blockData.iv = extractor.iv;
         this._slt = extractor.slt;
         this._ic = extractor.ic;
         [this._lp, this._lpEnd] = extractor.lpp();
         const encryptedHint = extractor.hint;
         this._blockData.encryptedData = extractor.remainder('edata');

         // V4 additional data is the payload minus encrypted data
         this._blockData.additionalData = new Uint8Array(
            payload.buffer,
            payload.byteOffset,
            extractor.offset - this._blockData.encryptedData.byteLength
         );

         this._sk = await Ciphers._genSigningKey(this._userCred!, this._slt);

         // Avoiding the Doom Principle and verify signature before crypto operations.
         // Aka, check MAC as soon as possible after we have the signing key and data.
         // Might be cleaner to do this elsewhere, but keeping it at the lowest level
         // ensures we don't skip the step
         const validMac: boolean = await this._verifyMAC();
         if (!validMac) {
            throw new Error('Invalid MAC error');
         }

         let hint = new Uint8Array(0);
         if (encryptedHint!.byteLength != 0) {
            const hk = await Ciphers._genHintCipherKey(this._blockData.alg, this._userCred!, this._slt);
            hint = await Decipher._doDecrypt(
               this._blockData.alg,
               hk,
               this._blockData.iv,
               encryptedHint
            );
         }

         this._hint = new TextDecoder().decode(hint)
         this._state = CipherState.Block0Decoded;
      } catch (err) {
         this.errorState();
         console.error(err);
         throw err;
      }
   }

   public override async decryptBlockN(
   ): Promise<Uint8Array> {

      try {
         if (this._state != CipherState.Block0Done) {
            throw new Error(`Decipher invalid state ${this._state}`);
         }

         if (!this._sk || !this._ek) {
            throw new Error('Data not initialized, decrypt block0 first');
         }

         // This does MAC check
         await this._decodePayloadN();
         //@ts-ignore
         if (this._state === CipherState.Finished) {
            // this is the signal that decryption is complete
            return new Uint8Array(0);
         }

         if (!this._blockData || !this._blockData.alg || !this._ek || !this._blockData.iv || !this._blockData.encryptedData) {
            throw new Error('Data not initialized');
         }

         const decrypted = await Decipher._doDecrypt(
            this._blockData.alg,
            this._ek,
            this._blockData.iv,
            this._blockData.encryptedData,
            this._blockData.additionalData,
         );

         return decrypted;
      } catch (err) {
         this.errorState();
         console.error(err);
         throw err;
      } finally {
         this._blockData = undefined;
      }
   }

   // Importers of CipherService should not need this function directly,
   // but it is public for unit testing. Does not allow encoding
   // with zero length encrypted text since that is not needed
   protected async _decodePayloadN(): Promise<void> {

      // Need to treat all values an UNTRUSTED since the signature has not yet been
      // validated, Extractor does test each value for valid ranges as we unpack
      try {
         const done = await this._decodeHeader();
         if (done) {
            this.finishedState();
            return;
         }

         if (!this._blockData) {
            throw new Error('Data not initialized');
         }

         if (!this._blockData.payloadSize) {
            throw new Error('Invalid payload size2: ' + this._blockData.payloadSize);
         }

         // Don't need to look at done for the fill since there will will be another
         // call and the next header will report done.
         const [payload] = await this._reader.readFill(new Uint8Array(this._blockData.payloadSize));

         if (payload.byteLength != this._blockData.payloadSize) {
            throw new Error('Cipher data length mismatch2: ' + payload.byteLength);
         }

         let extractor = new Extractor(payload);

         // Order must be invariant
         this._blockData.alg = extractor.alg;
         this._blockData.iv = extractor.iv;
         this._blockData.encryptedData = extractor.remainder('edata');

         // V4 additional data is payload - encrypted data
         this._blockData.additionalData = new Uint8Array(
            payload.buffer,
            payload.byteOffset,
            extractor.offset - this._blockData.encryptedData.byteLength
         );

         // Avoiding the Doom Principle and verify signature before crypto operations.
         // Aka, check MAC as soon as possible after we  have the signing key and data.
         // Might be cleaner to do this elswhere, but keeping it at the lowest level
         // ensures we don't skip the step
         const validMac: boolean = await this._verifyMAC();
         if (!validMac) {
            throw new Error('Invalid MAC error');
         }
      } catch (err) {
         this.errorState();
         console.error(err);
         throw err;
      }
   }

   protected async _verifyMAC(): Promise<boolean> {

      if (!this._blockData || !this._blockData.payloadSize || !this._blockData.ver || !this._blockData.additionalData ||
         !this._sk || !this._blockData.encryptedData || !this._blockData.mac) {
         throw new Error('Data not initialized');
      }

      const encVer = numToBytes(this._blockData.ver, cc.VER_BYTES);
      const encSizeBytes = numToBytes(this._blockData.payloadSize, cc.PAYLOAD_SIZE_BYTES + cc.FLAGS_BYTES);

      const headerPortion = new Uint8Array(cc.VER_BYTES + cc.PAYLOAD_SIZE_BYTES + cc.FLAGS_BYTES);
      headerPortion.set(encVer);
      headerPortion.set(encSizeBytes, cc.VER_BYTES);

      const exportedSk = await crypto.subtle.exportKey("raw", this._sk);
      const skData = new Uint8Array(exportedSk);

      await sodium.ready;
      const state = sodium.crypto_generichash_init(skData, cc.MAC_BYTES);


      sodium.crypto_generichash_update(state, headerPortion);
      sodium.crypto_generichash_update(state, this._blockData.additionalData);
      sodium.crypto_generichash_update(state, this._blockData.encryptedData);

      const testMac = sodium.crypto_generichash_final(state, cc.MAC_BYTES);
      const validMac: boolean = sodium.memcmp(this._blockData.mac, testMac);

      if (validMac) {
         return true;
      }

      throw new Error('Invalid MAC signature');
   }
}

class DecipherV5 extends DecipherV4 {

   private _lastMac = new Uint8Array(0);
   private _lastFlags = 0;

   public override protocolVersion(): number {
      return cc.VERSION5;
   }

   override async _decodePayload0(): Promise<void> {

      await super._decodePayload0();

      // Eventually flags may be a bitfield
      if (this._state === CipherState.Finished && this._lastFlags !== 1) {
         throw new Error('Missing terminal data block');
      }

      if (this._blockData) {
         this._lastFlags = this._blockData!.flags;
      }
   }

   protected override async _decodePayloadN(): Promise<void> {

      await super._decodePayloadN();

      // If we loaded more data, and lastFlags was 1 (change to bitfield someday)
      // we have an error
      if (this._lastFlags === 1 && this._state !== CipherState.Finished) {
         throw new Error(`Terminal block already read ${this._state}`);
      }

      // Eventually flags may be a bitfield
      if (this._state === CipherState.Finished && this._lastFlags !== 1) {
         throw new Error('Missing terminal data block');
      }

      if (this._blockData) {
         this._lastFlags = this._blockData!.flags;
      }
   }

   protected override async _verifyMAC(): Promise<boolean> {

      if (!this._blockData || !this._blockData.payloadSize || !this._blockData.ver || !this._blockData.additionalData ||
         !this._sk || !this._blockData.encryptedData || !this._blockData.mac) {
         throw new Error('Data not initialized');
      }

      const encVer = numToBytes(this._blockData.ver, cc.VER_BYTES);
      const encSizeBytes = numToBytes(this._blockData.payloadSize, cc.PAYLOAD_SIZE_BYTES);
      const encFlags = numToBytes(this._blockData.flags!, cc.FLAGS_BYTES);

      const headerPortion = new Uint8Array(cc.VER_BYTES + cc.PAYLOAD_SIZE_BYTES + cc.FLAGS_BYTES);
      headerPortion.set(encVer);
      headerPortion.set(encSizeBytes, cc.VER_BYTES);
      headerPortion.set(encFlags, cc.VER_BYTES + cc.PAYLOAD_SIZE_BYTES);

      const exportedSk = await crypto.subtle.exportKey("raw", this._sk);
      const skData = new Uint8Array(exportedSk);

      await sodium.ready;
      const state = sodium.crypto_generichash_init(skData, cc.MAC_BYTES);

      sodium.crypto_generichash_update(state, headerPortion);
      sodium.crypto_generichash_update(state, this._blockData.additionalData);
      sodium.crypto_generichash_update(state, this._blockData.encryptedData);
      sodium.crypto_generichash_update(state, this._lastMac);

      const testMac = sodium.crypto_generichash_final(state, cc.MAC_BYTES);
      const validMac: boolean = sodium.memcmp(this._blockData.mac, testMac);
      this._lastMac = testMac;

      if (validMac) {
         return true;
      }

      throw new Error('Invalid MAC signature');
   }
}


class Extractor {
   private _encoded: Uint8Array;
   private _offset: number;
   private _alg?: string;

   constructor(encoded: Uint8Array, offset: number = 0) {
      this._encoded = encoded;
      this._offset = offset;
   }

   extract(what: string, len: number): Uint8Array {
      // some browsers complain about overruns (FF), while other don't (chrome),
      // so check explicitly
      if (this._encoded.byteOffset + this._offset + len > this._encoded.byteLength) {
         throw new Error(`Invalid ${what}, length: ${len}`);
      }

      const result = new Uint8Array(this._encoded.buffer,
         this._encoded.byteOffset + this._offset, len);

      // shouldn't hit this given test above, but check anyway
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
      this._alg = Ciphers.findAlg(algNum);
      return this._alg;
   }

   get iv(): Uint8Array {
      if (!this._alg) {
         throw new Error('iv length unknown, get extractor.alg first');
      }
      const ivBytes = Number(cc.AlgInfo[this._alg]['iv_bytes']);
      return this.extract('iv', ivBytes);
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

   lpp(): [lp: number, lpEnd: number] {
      let lpp = bytesToNum(this.extract('lpp', cc.LPP_BYTES));
      const lp = (lpp & 0x0F) + 1;
      const lpEnd = (lpp >> 4) + 1;
      // this can't happen... but... just check
      if (lpEnd < 1 || lpEnd > cc.LP_MAX) {
         throw new Error('Invalid lpEnd of: ' + lpEnd);
      }
      // only lp > lpEnd could happen
      if (lp < 1 || lp > lpEnd) {
         throw new Error('Invalid lp of: ' + lp);
      }
      return [lp, lpEnd];
   }

   get ver(): number {
      const ver = bytesToNum(this.extract('ver', cc.VER_BYTES));
      if (ver != cc.VERSION1 && ver != cc.VERSION4 && ver != cc.VERSION5) {
         throw new Error('Invalid version of: ' + ver);
      }
      return ver;
   }

   get flags(): number {
      const flags = bytesToNum(this.extract('flags', cc.FLAGS_BYTES));
      // May be a bitfield later. For now, 0 or 1
      if (flags != 0 && flags != 1) {
         throw new Error('Invalid flags of: ' + flags);
      }
      return flags;
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
         throw new Error('Invalid payload size3: ' + payloadSize);
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

   lpp(lp: number, lpEnd: number) {
      if (lpEnd < 1 || lpEnd > cc.LP_MAX) {
         throw new Error('Invalid lpEnd of: ' + lpEnd);
      }
      if (lp < 1 || lp > lpEnd) {
         throw new Error('Invalid lp of: ' + lp);
      }
      let lpp = (lpEnd - 1) << 4;
      lpp += (lp - 1);
      this.pack('lpp', numToBytes(lpp, cc.LPP_BYTES));
   }

   set ver(version: number) {
      if (version != cc.VERSION1 && version != cc.VERSION4 && version != cc.VERSION5) {
         throw new Error('Invalid version of: ' + version);
      }
      this.pack('ver', numToBytes(version, cc.VER_BYTES));
   }

   set flags(flags: number) {
      // May be a bitfield later. For now, 0 or 1
      if (flags != 0 && flags != 1) {
         throw new Error('Invalid flags of: ' + flags);
      }
      this.pack('flags', numToBytes(flags, cc.FLAGS_BYTES));
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
         throw new Error('Invalid payload size4: ' + payloadSize);
      }
      this.pack('size', numToBytes(payloadSize, cc.PAYLOAD_SIZE_BYTES));
   }
}
