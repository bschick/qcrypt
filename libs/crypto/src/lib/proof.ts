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

import { getCrux, getSodium } from './crypto';
import { getRandom } from './utils';

export function getProofKeyPair(secret: Uint8Array, context: string): { pubKey: Uint8Array<ArrayBuffer>; secKey: Uint8Array<ArrayBuffer> } {
   const sodium = getSodium();
   if (secret.byteLength < sodium.crypto_kdf_KEYBYTES) {
      throw new Error('proof secret too short');
   }
   if (context.length !== sodium.crypto_kdf_CONTEXTBYTES) {
      throw new Error('proof context must be 8 bytes');
   }

   const seed = sodium.crypto_kdf_derive_from_key(32, 1, context, secret);
   try {
      const keyPair = getCrux().ml_dsa_65_keygen(seed);
      return keyPair;
   } finally {
      seed.fill(0);
   }
}

export function signProof(secKey: Uint8Array, message: Uint8Array, context: string): Uint8Array<ArrayBuffer> {
   return getCrux().ml_dsa_65_sign(secKey, message, new TextEncoder().encode(context), getRandom(32));
}

export function verifyProof(pubKey: Uint8Array, message: Uint8Array, signature: Uint8Array, context: string): boolean {
   if (getCrux().ml_dsa_65_verify(pubKey, message, new TextEncoder().encode(context), signature)) {
      return true;
   }
   throw new Error('proof verification failed');
}
