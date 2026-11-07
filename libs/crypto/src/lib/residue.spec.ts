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
import { describe, it, expect, beforeEach } from 'vitest';
import { cryptoReady, getSodium } from './crypto';
import { decryptStream, encryptStream } from './cipher-streams';
import { MasterKeyKeyProvider } from './keys';
import { getProofKeyPair, PROOF_SEED_BYTES } from './proof';
import { getRandom, readStreamAll, streamFromBytes } from './utils';
import * as cc from './cipher.consts';

// libsodium-wrappers exposes its wasm module as `libsodium` without declaring it in its types
type WrapperModule = { libsodium: { HEAPU8: Uint8Array } };
const libsodiumMemory = () => (getSodium() as unknown as WrapperModule).libsodium.HEAPU8;

function indexOf(haystack: Uint8Array, needle: Uint8Array): number {
   for (let pos = haystack.indexOf(needle[0]); pos !== -1; pos = haystack.indexOf(needle[0], pos + 1)) {
      if (needle.every((byte, offset) => haystack[pos + offset] === byte)) {
         return pos;
      }
   }
   return -1;
}

async function encrypt(alg: cc.CipherAlgs, masterKey: Uint8Array<ArrayBuffer>, clear: Uint8Array<ArrayBuffer>) {
   const keyProvider = new MasterKeyKeyProvider(masterKey.slice(), 'userId');
   return readStreamAll(await encryptStream(streamFromBytes(clear.slice()), keyProvider, { algs: [alg] }));
}

// Each library call below ends with libsodium's stack zeroed, so nothing the call handled stays in wasm memory
describe('libsodium memory after library calls', () => {
   beforeEach(async () => {
      await cryptoReady();
   });

   it('X20-PLY decryption leaves no clear text', async () => {
      const masterKey = getRandom(32);
      // Shorter than one ChaCha20 block, which libsodium handles in a stack buffer
      const clear = getRandom(41);
      const cipherData = await encrypt('X20-PLY', masterKey, clear);
      const keyProvider = new MasterKeyKeyProvider(masterKey.slice(), 'userId');
      const decrypted = await readStreamAll(await decryptStream(streamFromBytes(cipherData), keyProvider));
      expect(decrypted).toEqual(clear);
      expect(indexOf(libsodiumMemory(), clear)).toBe(-1);
   });

   it('getProofKeyPair leaves no seed', () => {
      const secret = getRandom(cc.USERCRED_BYTES);
      const seed = getSodium().crypto_kdf_derive_from_key(PROOF_SEED_BYTES, 1, 'UCredKey', secret);
      getProofKeyPair(secret, 'UCredKey');
      expect(indexOf(libsodiumMemory(), seed)).toBe(-1);
   });
});
