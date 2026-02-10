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

import { FilterXSS } from 'xss';
import { Buffer } from "node:buffer";
import * as cc from './consts.ts';


export class ParamError extends Error {
}

export class AuthError extends Error {
   constructor(msg: string = 'not authorize') {
      super(msg);
   }
}

export class NotFoundError extends Error {
}

const filter = new FilterXSS({
   whiteList: {},
   stripIgnoreTag: true,
   // remove rather than escape stuff < and > (slight modification of original from github)
   escapeHtml: (html: string) => {
      return html.replace(/</g, "").replace(/>/g, "");
   }
});

const sanitizeXSS = filter.process.bind(filter);

export const sanitizeString = (input: string): string => {
   if (!input || typeof input !== 'string') {
      throw new ParamError('must be string value');
   }
   const sanitized = sanitizeXSS(input);
   if (!sanitized) {
      throw new ParamError('empty string value');
   }
   return sanitized.trim();
}

export const validB64 = (base64: string | null | undefined): boolean => {
   return !!base64 &&
      typeof base64 === 'string' &&
      /^[A-Za-z0-9+/=_-]+$/.test(base64);
}

export function base64UrlEncode(bytes: Uint8Array | undefined): string | undefined {
   return bytes ? Buffer.from(bytes).toString('base64url') : undefined;
}

export function base64UrlDecode(base64: string | undefined): Uint8Array<ArrayBuffer> | undefined {
   if (base64) {
      const nodeBuffer = Buffer.from(base64, 'base64url');
      return new Uint8Array(nodeBuffer.buffer, nodeBuffer.byteOffset, nodeBuffer.byteLength);
   }
   return undefined;
}

// Node implementation will handle either base64 or base6 4Url (for internal encoding and storage
// only use base64UrlEncode)
export function base64Decode(base64: string | undefined): Uint8Array<ArrayBuffer> | undefined {
   if (base64) {
      const nodeBuffer = Buffer.from(base64, 'base64');
      return new Uint8Array(nodeBuffer.buffer, nodeBuffer.byteOffset, nodeBuffer.byteLength);
   }
   return undefined;
}

/* Javascript converts to signed 32 bit int when using bit shifting
   and masking, so do this instead. Count is the number of bytes
   used to pack the number.  */
export function numToBytes(num: number, count: number): Uint8Array<ArrayBuffer> {
   if (count < 1 || num >= Math.pow(256, count)) {
      throw new Error(`Invalid arguments ${count} for ${num}`);
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


export class CertExtractor<T extends ArrayBufferLike> {
   private _encoded: Uint8Array<T>;
   private _offset: number;

   constructor(encoded: Uint8Array<T>, offset: number = 0) {
      this._encoded = encoded;
      this._offset = offset;
   }

   extract(what: string, len: number): Uint8Array<T> {
      // some browsers complain about overruns (FF), while other don't (chrome),
      // so check explicitly
      if (this._encoded.byteOffset + this._offset + len > this._encoded.byteLength) {
         throw new Error(`Invalid ${what}, length: ${len}`);
      }

      const result = new Uint8Array(this._encoded.buffer, this._encoded.byteOffset + this._offset, len);

      // shouldn't hit this given test above, but check anyway
      if (result.byteLength != len) {
         throw new Error(`Invalid ${what}, length: ${result.byteLength}`);
      }

      this._offset += len;
      return result;
   }

   get offset(): number {
      return this._offset;
   }

   get ver(): number {
      const ver = bytesToNum(this.extract('ver', cc.CERT_VERSION_BYTES));
      if (ver != cc.CERT_VERSION) {
         throw new Error('Invalid version of: ' + ver);
      }
      return ver;
   }

   get key(): Uint8Array<T> {
      return this.extract('key', cc.CERT_KEY_BYTES);
   }

   get uid(): string {
      return base64UrlEncode(this.extract('uid', cc.USERID_BYTES))!;
   }

   get uname(): string {
      const nameLen = bytesToNum(this.extract('nlen', cc.UNAME_LEN_BYTES));
      const nameBytes = this.extract('uname', nameLen);
      const name = new TextDecoder().decode(nameBytes);
      if (name.length < cc.UNAME_MIN_LEN || name.length > cc.UNAME_MAX_LEN) {
         throw new Error('user name must be 6 to 31 characters');
      }
      return name;
   }
}


export class CertPacker {
   private _dest?: Uint8Array<ArrayBuffer>;
   private _offset: number;

   constructor(offset: number = 0) {
      this._dest = new Uint8Array(cc.CERT_MAX_BYTES);
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

   trim(): Uint8Array<ArrayBuffer> {
      if (!this._dest) {
         throw new Error('Packer was detached');
      }
      return new Uint8Array(this._dest.buffer, this._dest.byteOffset, this._offset);
   }

   detach(): Uint8Array<ArrayBuffer> {
      if (!this._dest) {
         throw new Error('Packer was detached');
      }
      const result = this._dest;
      this._dest = undefined;
      return result;
   }

   set key(key: Uint8Array) {
      if (key.byteLength != cc.CERT_KEY_BYTES) {
         throw new Error('Invalid key length: ' + key.byteLength);
      }
      this.pack('key', key);
   }

   set ver(version: number) {
      if (version != cc.CERT_VERSION) {
         throw new Error('Invalid version of: ' + version);
      }
      this.pack('ver', numToBytes(version, cc.CERT_VERSION_BYTES));
   }

   set uid(userId: string) {
      const userIdBytes = base64UrlDecode(userId)!;
      if (userIdBytes.byteLength != cc.USERID_BYTES) {
         throw new Error('Invalid user id length: ' + userIdBytes.byteLength);
      }
      this.pack('uid', userIdBytes);
   }

   set uname(userName: string) {
      if (userName.length < cc.UNAME_MIN_LEN || userName.length > cc.UNAME_MAX_LEN) {
         throw new Error('user name must be 6 to 31 characters');
      }
      const nameBytes = new TextEncoder().encode(userName);
      this.pack('nlen', numToBytes(nameBytes.length, cc.UNAME_LEN_BYTES));
      this.pack('uname', nameBytes);
   }
}
