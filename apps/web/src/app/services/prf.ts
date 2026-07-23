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

import {
   bytesToBase64,
   getArrayBuffer,
   streamFromBytes,
   streamFromBase64,
   readStreamAll,
   encryptStream,
   decryptStream,
   MasterKeyKeyProvider,
} from '@qcrypt/crypto';
import * as cc from '@qcrypt/crypto/consts';
import type {
   PublicKeyCredentialCreationOptionsJSON,
   PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/browser';

// Fixed PRF salt. NOT a secret: a WebAuthn PRF salt is a public HMAC input; security
// comes from the per-credential authenticator key, not this value. Never change it —
// doing so orphans every existing PRF userCred ciphertext.
export const PRF_SALT = new Uint8Array([
   79, 207, 95, 76, 134, 119, 236, 52, 72, 250, 231, 99, 35, 243, 1, 169,
   205, 253, 35, 140, 130, 201, 98, 86, 30, 119, 75, 185, 138, 67, 243, 33,
]);

// This function edits passed in optionsJson in place
export function injectPrfExtension(
   optionsJson: PublicKeyCredentialCreationOptionsJSON | PublicKeyCredentialRequestOptionsJSON
): void {
   // @simplewebauthn forwards extensions to the native call unchanged, so first must be a BufferSource
   if (!optionsJson.extensions) {
      optionsJson.extensions = {};
   }
   let extensions = optionsJson.extensions as { prf: {eval: {first: Uint8Array}} };
   extensions.prf = { eval: { first: PRF_SALT } };
}

export function prfEnabled(clientExtensionResults: AuthenticationExtensionsClientOutputs): boolean {
   return clientExtensionResults.prf?.enabled === true;
}

export function prfReadKey(
   clientExtensionResults: AuthenticationExtensionsClientOutputs
): Uint8Array<ArrayBuffer> | null {
   const first = clientExtensionResults.prf?.results?.first;
   if (!first) {
      return null;
   }
   // The spec says `first` should be an ArrayBuffer, but often isn't so correct
   const output = new Uint8Array(getArrayBuffer(first));
   if (output.byteLength !== cc.KEY_BYTES) {
      throw new Error('unexpected PRF output length: ' + output.byteLength);
   }
   return output;
}

// This function takes ownership of and clears prfKey
export async function prfEncrypt(
   plainText: Uint8Array<ArrayBuffer>,
   prfKey: Uint8Array<ArrayBuffer>,
   userId: string
): Promise<string> {
   try {
      const keyProvider = new MasterKeyKeyProvider(prfKey, userId);
      const cipherData = await readStreamAll(
         await encryptStream(streamFromBytes(plainText), keyProvider, { algs: ['X20-PLY'] })
      );
      return bytesToBase64(cipherData);
   } finally {
      prfKey.fill(0);
   }
}

// This function takes ownership of and clears prfKey
// Caller must overwrite the returned value ASAP if sensitive
export async function prfDecrypt(
   cipherText: string,
   prfKey: Uint8Array<ArrayBuffer>,
   userId: string
): Promise<Uint8Array<ArrayBuffer>> {
   try {
      const keyProvider = new MasterKeyKeyProvider(prfKey, userId);
      return await readStreamAll(await decryptStream(streamFromBase64(cipherText), keyProvider));
   } finally {
      prfKey.fill(0);
   }
}
