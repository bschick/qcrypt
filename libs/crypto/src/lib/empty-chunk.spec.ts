/* MIT License

Copyright (c) 2026 BeakDo

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

import { beforeEach, expect, it } from 'vitest';
import { cryptoReady } from './crypto';
import * as cc from './cipher.consts';
import { MasterKeyKeyProvider } from './keys';
import { CipherState, concatArrays, decryptStream, getLatestEncipher, getStreamDecipher } from '../index';

beforeEach(async () => {
   await cryptoReady();
});

async function encryptedFixture() {
   const key = crypto.getRandomValues(new Uint8Array(cc.KEY_BYTES));
   const plaintext = crypto.getRandomValues(new Uint8Array(64));
   const clearStream = new ReadableStream<Uint8Array>({
      start(controller) {
         controller.enqueue(plaintext);
         controller.close();
      },
   });
   const encipher = getLatestEncipher(clearStream, new MasterKeyKeyProvider(key.slice()), 'AES-GCM', 1, 1, 0, {
      startSize: 64,
      maxSize: 64,
   });
   const parts: Uint8Array[] = [];
   for (let blockNum = 0; blockNum < 4; blockNum++) {
      const block = await encipher.encryptBlock();
      parts.push(...block.parts);
      if (block.state === CipherState.Finished) {
         break;
      }
   }
   const ciphertext = concatArrays(parts);
   return { key, plaintext, ciphertext };
}

it('rejects appended bytes even when a zero-length stream chunk precedes them', async () => {
   const { key, plaintext, ciphertext } = await encryptedFixture();
   const controlStream = new ReadableStream<Uint8Array>({
      start(controller) {
         controller.enqueue(ciphertext);
         controller.enqueue(new Uint8Array([123]));
         controller.close();
      },
   });
   const controlDecipher = await getStreamDecipher(controlStream, new MasterKeyKeyProvider(key.slice()));
   expect(await controlDecipher.decryptBlock0()).toEqual(plaintext);
   await expect(controlDecipher.decryptBlockN()).rejects.toThrow(/extra data/i);

   const attackStream = new ReadableStream<Uint8Array>({
      start(controller) {
         controller.enqueue(ciphertext);
         controller.enqueue(new Uint8Array(0));
         controller.enqueue(new Uint8Array([123]));
         controller.close();
      },
   });
   const decipher = await getStreamDecipher(attackStream, new MasterKeyKeyProvider(key.slice()));
   expect(await decipher.decryptBlock0()).toEqual(plaintext);
   await expect(decipher.decryptBlockN()).rejects.toThrow(/extra data/i);
});

it('does not report a forged end of stream as successful decryption', async () => {
   const { key, ciphertext } = await encryptedFixture();
   let streamCompleted = false;
   const streamInput = new ReadableStream<Uint8Array>({
      start(controller) {
         controller.enqueue(ciphertext);
         controller.enqueue(new Uint8Array(0));
         controller.enqueue(new Uint8Array([123]));
         controller.close();
      },
   });
   const clearOutput = await decryptStream(streamInput, new MasterKeyKeyProvider(key.slice()), () => {
      streamCompleted = true;
   });
   await expect(new Response(clearOutput).arrayBuffer()).rejects.toThrow(/extra data/i);
   expect(streamCompleted).toBe(false);
});
