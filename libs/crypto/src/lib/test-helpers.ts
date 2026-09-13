/* MIT License

Copyright (c) 2024 Brad Schick

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

import { base64ToBytes, concatArrays, ensureArrayBuffer, readStreamAll } from '../index';

// Faster than .toEqual, resulting in few timeouts
export function isEqualArray(a: Uint8Array, b: Uint8Array): boolean {
   if (a.length !== b.length) {
      return false;
   }
   for (let i = 0; i < a.length; ++i) {
      if (a[i] !== b[i]) {
         return false;
      }
   }
   return true;
}

// Faster than .toEqual, resulting in few timeouts
export async function areEqual(
   a: Uint8Array | ReadableStream<Uint8Array>,
   b: Uint8Array | ReadableStream<Uint8Array>,
): Promise<boolean> {
   if (a instanceof ReadableStream) {
      a = await readStreamAll(a);
   }
   if (b instanceof ReadableStream) {
      b = await readStreamAll(b);
   }

   if (a.byteLength !== b.byteLength) {
      return false;
   }

   for (let i = 0; i < a.byteLength; ++i) {
      if (a[i] !== b[i]) {
         return false;
      }
   }
   return true;
}

export function streamFromBytes(data: Uint8Array | Uint8Array[]): [ReadableStream<Uint8Array>, Uint8Array] {
   const merged = data instanceof Uint8Array ? ensureArrayBuffer(data) : concatArrays(data);
   const blob = new Blob([merged], { type: 'application/octet-stream' });
   return [blob.stream(), merged];
}

export function streamFromStr(str: string): [ReadableStream<Uint8Array>, Uint8Array] {
   const data = new TextEncoder().encode(str);
   const blob = new Blob([data], { type: 'application/octet-stream' });
   return [blob.stream(), data];
}

export function streamFromBase64Url(b64Url: string): [ReadableStream<Uint8Array>, Uint8Array] {
   const data = base64ToBytes(b64Url);
   const blob = new Blob([data], { type: 'application/octet-stream' });
   return [blob.stream(), data];
}
