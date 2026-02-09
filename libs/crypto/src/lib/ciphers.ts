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

import * as cc from './cipher.consts';
import { BYOBStreamReader, bytesToNum } from "./utils";

import {
   Ciphers,
   Encipher,
   Decipher,
   EncipherV7,
   DecipherV67,
   EParams,
   PWDProvider,
   CipherState,
   CipherDataInfo,
}  from "./ciphers-current"

import {
   DecipherV1,
   DecipherV4,
   DecipherV5
}  from "./deciphers-old"


export {
   Ciphers,
   Encipher,
   Decipher,
   CipherState,
};

export type {
   EParams,
   PWDProvider,
   CipherDataInfo
};

export function latestEncipher(
   userCred: Uint8Array,
   clearStream: ReadableStream<Uint8Array>
): Encipher {
   const reader = new BYOBStreamReader(clearStream);
   return new EncipherV7(userCred, reader);
}


// Return appropriate version of Decipher
export async function streamDecipher(
   userCred: Uint8Array,
   cipherStream: ReadableStream<Uint8Array>
): Promise<Decipher> {

   let decipher: Decipher;
   const reader = new BYOBStreamReader(cipherStream);

   const [header, done] = await reader.readFill(new ArrayBuffer(cc.HEADER_BYTES_6P));

   if (header.byteLength != cc.HEADER_BYTES_6P || done) {
      reader.cleanup();
      throw new Error('Invalid cipher stream length: ' + header.byteLength);
   }

   // This is rather ugly, but the original CiphersV1 encoding stupidly had the
   // version in the middle of the encoding. So detect old version by the first 2 bytes
   // after MAC being < 4 (since encoded started with ALG and v1 max ALG was 3 and beyond v1
   // version is >=4). Fortunately ALG_BYTES and VER_BYTES are equal.
   const verOrAlg = bytesToNum(new Uint8Array(header.buffer, cc.MAC_BYTES, cc.VER_BYTES));

   if (verOrAlg == cc.VERSION6 || verOrAlg == cc.VERSION7) {
      decipher = new DecipherV67(userCred, reader, header);
   }
   else if (verOrAlg == cc.VERSION5) {
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


