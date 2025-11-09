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
import * as cc from './cipher.consts';
import {
   numToBytes,
   BYOBStreamReader,
   getArrayBuffer,
   ensureArrayBuffer
} from './utils';

import {
   Ciphers,
   Decipher,
   CipherState,
   Extractor,
   HKDF_INFO_SIGNING,
   HKDF_INFO_HINT
} from './ciphers-current';


export class DecipherV1 extends Decipher {
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
         let [payload] = await this._reader.readFill(new ArrayBuffer(cc.PAYLOAD_SIZE_MAX));

         if (this._headerish) {
            const newPayload = new Uint8Array(this._headerish.byteLength + payload.byteLength);
            newPayload.set(this._headerish);
            newPayload.set(payload, this._headerish.byteLength);
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
         const additionalData = DecipherV1._encodeAdditionalData({
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

         this._sk = await _genSigningKeyOld(this._userCred!, this._slt);

         // Avoiding the Doom Principle and verify signature before crypto operations.
         // Aka, check MAC as soon as possible after we  have the signing key and data.
         // Might be cleaner to do this elswhere, but keeping it at the lowest level
         // ensures we don't skip the step
         const validMac: boolean = await this._verifyMAC();
         if (!validMac) {
            throw new Error('Invalid MAC error');
         }

         let hint: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
         if (encryptedHint!.byteLength != 0) {
            let hk: Uint8Array | undefined = await _genHintCipherKeyOld(this._blockData!.alg!, this._userCred!, this._slt);
            this._hint = await Decipher._doDecrypt(
               this._blockData!.alg!,
               hk,
               this._blockData!.iv!,
               encryptedHint
            );

            crypto.getRandomValues(hk);
            hk = undefined;
         }

         this._state = CipherState.Block0Decoded;

      } catch (err) {
         this.errorState();
         console.error(err);
         throw err;
      } finally {
         this._headerish = undefined;
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
      let sk: CryptoKey | undefined = await crypto.subtle.importKey(
         'raw',
         getArrayBuffer(this._sk),
         { name: 'HMAC', hash: 'SHA-256', length: 256 },
         false,
         ['verify']
      );

      const valid: boolean = await crypto.subtle.verify('HMAC', sk, this._blockData.mac, data);
      sk = undefined;
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


export class DecipherV4 extends Decipher {
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
      let done: boolean = true;
      if (!header) {
         [header, done] = await this._reader.readFill(new ArrayBuffer(cc.HEADER_BYTES_OLD));
      } else if (header && header.byteLength < cc.HEADER_BYTES_OLD) {
         // This isn't very efficient, but it simplifies object creation and current version logic
         // (which are more important)
         let missed: Uint8Array;
         [missed, done] = await this._reader.readFill(new ArrayBuffer(cc.HEADER_BYTES_OLD - header.byteLength));
         const newHeader = new Uint8Array(cc.HEADER_BYTES_OLD);
         newHeader.set(header);
         newHeader.set(missed, header.byteLength);
         header = newHeader;
      }

      // This signals successful completion of block reads
      if (header.byteLength == 0) {
         return true;
      }
      if (done || header.byteLength < cc.HEADER_BYTES_OLD) {
         this._reader.cleanup();
         throw new Error('Missing cipher data header');
      }

      const extractor = new Extractor(header);

      // Order must be invariant (extractor validates sizes and ranges)
      const mac = extractor.mac;
      const ver = extractor.ver;
      if (ver != this.protocolVersion()) {
         throw new Error('Invalid version of: ' + ver);
      }
      const payloadSize = extractor.size;

      // V4 did not use flags, but had extra byte in payloadSize. Extract to move offset
      const flags = extractor.flags;

      this._blockData = {
         mac: ensureArrayBuffer(mac),
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

         if (!this._blockData) {
            throw new Error('Data not initialized');
         }

         // Need to treat all values an UNTRUSTED since the signature has not yet been
         // validated, Extractor does test each value for valid ranges as we unpack
         const [payload, done] = await this._reader.readFill(new ArrayBuffer(this._blockData.payloadSize));
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

         this._sk = await _genSigningKeyOld(this._userCred!, this._slt);

         // Avoiding the Doom Principle and verify signature before crypto operations.
         // Aka, check MAC as soon as possible after we have the signing key and data.
         // Might be cleaner to do this elsewhere, but keeping it at the lowest level
         // ensures we don't skip the step
         const validMac: boolean = await this._verifyMAC();
         if (!validMac) {
            throw new Error('Invalid MAC error');
         }

         let hint: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
         if (encryptedHint!.byteLength != 0) {
            let hk: Uint8Array | undefined = await _genHintCipherKeyOld(this._blockData.alg, this._userCred!, this._slt);
            this._hint = await Decipher._doDecrypt(
               this._blockData.alg,
               hk,
               this._blockData.iv,
               encryptedHint
            );

            crypto.getRandomValues(hk);
            hk = undefined;
         }

         this._state = CipherState.Block0Decoded;
      } catch (err) {
         this.errorState();
         console.error(err);
         throw err;
      } finally {
         this._header = undefined;
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

         // Don't need to look at done for the fill since there will will be another
         // call and the next header will report done.
         const [payload] = await this._reader.readFill(new ArrayBuffer(this._blockData.payloadSize));

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

      const state = sodium.crypto_generichash_init(this._sk, cc.MAC_BYTES);
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

function findPropertyOwner(obj: any, propName: string): object | null {
    let currentObj = obj;
    // Iterate up the prototype chain
    while (currentObj !== null) {
        // Check if the property is an "own" property of the current object
        if (Object.getOwnPropertyDescriptor(currentObj, propName) !== undefined) {
            return currentObj;
        }
        // Move up to the next prototype in the chain
        currentObj = Object.getPrototypeOf(currentObj);
    }
    return null; // Property not found in the chain
}

export class DecipherV5 extends DecipherV4 {

   private _lastMac?: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
   private _lastFlags = 0;

   public override protocolVersion(): number {
      return cc.VERSION5;
   }

   protected override _purge() {
      if (this._lastMac) {
         crypto.getRandomValues(this._lastMac);
         this._lastMac = undefined;
      }
      super._purge();
   }

   override async _decodePayload0(): Promise<void> {

      await super._decodePayload0();

      // Eventually flags may be a bitfield
      if (this._state === CipherState.Finished && this._lastFlags !== 1) {
         throw new Error('Missing terminal data block');
      }

      if (this._blockData) {
         this._lastFlags = this._blockData.flags!;
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
         this._lastFlags = this._blockData.flags!;
      }
   }

   protected override async _verifyMAC(): Promise<boolean> {

      if (!this._blockData || !this._blockData.payloadSize || !this._blockData.ver || !this._blockData.additionalData ||
         !this._sk || !this._blockData.encryptedData || !this._blockData.mac || !this._lastMac) {
         throw new Error('Data not initialized');
      }

      const encVer = numToBytes(this._blockData.ver, cc.VER_BYTES);
      const encSizeBytes = numToBytes(this._blockData.payloadSize, cc.PAYLOAD_SIZE_BYTES);
      const encFlags = numToBytes(this._blockData.flags!, cc.FLAGS_BYTES);

      const headerPortion = new Uint8Array(cc.VER_BYTES + cc.PAYLOAD_SIZE_BYTES + cc.FLAGS_BYTES);
      headerPortion.set(encVer);
      headerPortion.set(encSizeBytes, cc.VER_BYTES);
      headerPortion.set(encFlags, cc.VER_BYTES + cc.PAYLOAD_SIZE_BYTES);

      const state = sodium.crypto_generichash_init(this._sk, cc.MAC_BYTES);

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

// Exported for testing, normal callers should not need this
export async function _genSigningKeyOld(
   userCred: Uint8Array,
   slt: Uint8Array
): Promise<Uint8Array<ArrayBuffer>> {

   if (userCred.byteLength != cc.USERCRED_BYTES) {
      throw new Error('Invalid userCred length of: ' + userCred.byteLength);
   }
   if (slt.byteLength != cc.SLT_BYTES) {
      throw new Error("Invalid slt length of: " + slt.byteLength);
   }

   const skMaterial = await crypto.subtle.importKey(
      'raw',
      getArrayBuffer(userCred),
      'HKDF',
      false,
      ['deriveBits', 'deriveKey']
   );

   let subtleKey: CryptoKey | undefined = await crypto.subtle.deriveKey(
      {
         name: 'HKDF',
         salt: getArrayBuffer(slt),
         hash: 'SHA-512',
         info: new TextEncoder().encode(HKDF_INFO_SIGNING)
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
export async function _genHintCipherKeyOld(
   alg: string,
   userCred: Uint8Array,
   slt: Uint8Array
): Promise<Uint8Array<ArrayBuffer>> {

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
      getArrayBuffer(userCred),
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
         salt: getArrayBuffer(slt),
         hash: 'SHA-512',
         info: new TextEncoder().encode(HKDF_INFO_HINT)
      },
      hkMaterial,
      { name: dkAlg, length: 256 },
      true,
      ['encrypt', 'decrypt']
   );

   const exported = await crypto.subtle.exportKey("raw", subtleKey);
   subtleKey = undefined;
   return new Uint8Array(exported);
}
