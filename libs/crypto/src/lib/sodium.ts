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

import type sodiumType from 'libsodium-wrappers';

// Lazy-loads libsodium so it lands in its own chunk instead of inflating main.

let _cryptoReady: Promise<void> | undefined;
let _sodium: typeof sodiumType | undefined;

export function cryptoReady(): Promise<void> {
   if (!_cryptoReady) {
      _cryptoReady = import('libsodium-wrappers').then(async (mod) => {
         await mod.default.ready;
         _sodium = mod.default;
      });
   }
   return _cryptoReady;
}

export function getSodium(): typeof sodiumType {
   if (!_sodium) {
      throw new Error('crypto: cryptoReady() not awaited');
   }
   return _sodium;
}
