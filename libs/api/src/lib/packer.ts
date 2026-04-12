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

import * as cc from '@qcrypt/crypto/consts';
import { 
   numToBytes, 
   bytesToNum, 
   byteCount, 
   base64ToBytes, 
   bytesToBase64, 
   combinedSigner 
} from '@qcrypt/crypto';


export class Packer {
   private _dest: Uint8Array<ArrayBuffer> | undefined;
   private _offset: number;
   private _signed = false;
   private _sign: boolean;

   constructor(maxBytes: number, sign: boolean) {
      this._dest = new Uint8Array(maxBytes);
      this._sign = sign
      this._offset = sign ? cc.COMBINED_SIG_BYTES : 0;
   }

   pack(what: string, data: Uint8Array) {
      if (!this._dest) {
         throw new Error('Packer was detached');
      }
      if (this._signed) {
         throw new Error('Already signed');
      }
      // happens if the encode data is not as long as expected
      if (this._offset + data.byteLength > this._dest.byteLength) {
         throw new Error(`Invalid ${what}, length: ${data.byteLength} to big by ${this._offset + data.byteLength - this._dest.byteLength}`);
      }

      this._dest.set(data, this._offset);
      this._offset += data.byteLength;
   }
   
   bytes(what: string, data: Uint8Array, maxLength: number, sizeByteCount: number = 0, minLen: number = 0) {
      if (sizeByteCount > 0) {
         if (byteCount(maxLength) > sizeByteCount) {
            throw new Error(`Invalid sizeByteCount ${sizeByteCount} for maxLength ${maxLength}`);
         }
         if (data.byteLength < minLen || data.byteLength > maxLength) {
            throw new Error(`Invalid ${what}, length: ${data.byteLength}`);
         }

         this.pack(what + '-len', numToBytes(data.byteLength, sizeByteCount));
         this.pack(what, data);
      } else {
         // Fixed length
         if (data.byteLength !== maxLength) {
             throw new Error(`Invalid ${what}, length: ${data.byteLength} expected ${maxLength}`);
         }
         this.pack(what, data);
      }
   }

   string(what: string, data: string, maxLength: number, sizeByteCount: number = 0, minLen: number = 0) {
      const dataBytes = new TextEncoder().encode(data);
      this.bytes(what, dataBytes, maxLength, sizeByteCount, minLen);
   }

   base64(what: string, data: string, maxLength: number, sizeByteCount: number = 0, minLen: number = 0) {
      const dataBytes = base64ToBytes(data);
      if (!dataBytes) {
         throw new Error(`Invalid base64 string for ${what}`);
      }
      this.bytes(what, dataBytes, maxLength, sizeByteCount, minLen);
   }

   number(what: string, data: number, sizeByteCount: number, maxValue: number = Number.MAX_SAFE_INTEGER, minValue: number = 0) {
      if (data < minValue || data > maxValue) {
         throw new Error(`Invalid ${what}, value: ${data}`);
      }
      this.pack(what, numToBytes(data, sizeByteCount));
   }

   sign(sigSecretKey: Uint8Array) {
      if (!this._dest) {
         throw new Error('Packer was detached');
      }
      const savedOffset = this._offset
      const signable = new Uint8Array(this._dest.buffer, this._dest.byteOffset + cc.COMBINED_SIG_BYTES, this._offset - cc.COMBINED_SIG_BYTES);
      const sig = combinedSigner.sign(signable, sigSecretKey);
      this._offset = 0;
      this.pack('sig', sig);
      this._offset = savedOffset;
      this._signed = true;
   }

   trim(): Uint8Array<ArrayBuffer> {
      if (!this._dest) {
         throw new Error('Packer was detached');
      }
      if (!this._signed && this._sign) {
         throw new Error('Not signed');
      }
      return new Uint8Array(this._dest.buffer, this._dest.byteOffset, this._offset);
   }

   detach(): Uint8Array<ArrayBuffer> {
      if (!this._dest) {
         throw new Error('Packer was detached');
      }
      if (!this._signed && this._sign) {
         throw new Error('Not signed');
      }
      const result = this._dest;
      this._dest = undefined;
      return result;
   }

   get signature(): Uint8Array {
      if (!this._dest) {
         throw new Error('Packer was detached');
      }
      if (!this._signed) {
         throw new Error('Not signed');
      }
      return new Uint8Array(this._dest.buffer, 0, cc.COMBINED_SIG_BYTES);
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

}


export class Extractor<T extends ArrayBufferLike> {
   private _encoded: Uint8Array<T>;
   private _offset: number;
   private _verified = false;
   private _verify;

   constructor(encoded: Uint8Array<T>, verify: boolean) {
      this._encoded = encoded;
      this._offset = 0;
      this._verify = verify;
   }

   extract(what: string, len: number): Uint8Array<T> {
//      console.log('byteOffset, offset, remaining, len (in extract)', this._encoded.byteOffset, this._offset, this._encoded.byteLength - this._offset, len);
      // some browsers complain about overruns (FF), while other don't (chrome),
      // so check explicitly
      if (this._offset + len > this._encoded.byteLength) {
         throw new Error(`Invalid ${what}, length: ${len}`);
      }
      if (this._verify && !this._verified) {
         throw new Error('Verify before extracting');
      }

      const result = new Uint8Array(this._encoded.buffer, this._encoded.byteOffset + this._offset, len);

      // shouldn't hit this given test above, but check anyway
      if (result.byteLength != len) {
         throw new Error(`Invalid ${what}, length: ${result.byteLength}`);
      }

      this._offset += len;
      return result;
   }

   bytes(what: string, maxLength: number, sizeByteCount: number = 0, minLen: number = 0): Uint8Array<T> {
      if (sizeByteCount > 0) {
         if (byteCount(maxLength) > sizeByteCount) {
            throw new Error(`Invalid sizeByteCount ${sizeByteCount} for maxLength ${maxLength}`);
         }
         const lenBytes = this.extract(what + '-len', sizeByteCount);
         const len = bytesToNum(lenBytes);

         if (len < minLen || len > maxLength) {
            throw new Error(`Invalid ${what}, length: ${len}`);
         }
         return this.extract(what, len);
      } else {
         // Fixed length
         if (maxLength < minLen) {
            throw new Error(`Invalid maxLength ${maxLength} < minLen ${minLen}`);
         }
         return this.extract(what, maxLength);
      }
   }

   string(what: string, maxLength: number, sizeByteCount: number = 0, minLen: number = 0): string {
      const bytes = this.bytes(what, maxLength, sizeByteCount, minLen);
      return new TextDecoder().decode(bytes);
   }

   base64(what: string, maxLength: number, sizeByteCount: number = 0, minLen: number = 0): string {
      const bytes = this.bytes(what, maxLength, sizeByteCount, minLen);
      return bytesToBase64(bytes)!;
   }

   number(what: string, sizeByteCount: number, maxValue: number = Number.MAX_SAFE_INTEGER, minValue: number = 0): number {
      const value = bytesToNum(this.extract(what, sizeByteCount));
      if (value < minValue || value > maxValue) {
         throw new Error(`Invalid ${what}, value: ${value}`);
      }
      return value;
   }

   verify(sigPublicKey: Uint8Array, what: string): boolean {
      this._verified = true;
//      console.log('length, byteOffset (in verify)', this._encoded.byteLength, this._encoded.byteOffset);
      const sig = this.extract('sig', cc.COMBINED_SIG_BYTES);
      const signed = new Uint8Array(this._encoded.buffer, this._encoded.byteOffset + cc.COMBINED_SIG_BYTES, this._encoded.byteLength - cc.COMBINED_SIG_BYTES);
//      console.log('signed (in verify)', signed);
      const valid = combinedSigner.verify(sig, signed, sigPublicKey);
      if (!valid) {
         this._verified = false;
         throw new Error('invalid ' + what);
      }
//      console.log('offset, remaining, offset (in verify)', this._offset, this._encoded.byteLength - this._offset, this._encoded.byteOffset + this._offset);
      return valid;
   }

   get offset(): number {
      return this._offset;
   }
}