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
   constructor(msg: string = 'not authorized') {
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

// Constant-time string comparison. Early length check is acceptable for fixed-length secrets.
export function timingSafeEqual(a: string, b: string): boolean {
   if (a.length !== b.length) {
      return false;
   }
   let diff = 0;
   for (let i = 0; i < a.length; i++) {
      diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
   }
   return diff === 0;
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
