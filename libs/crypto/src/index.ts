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


// Utility functions and classes
export {
   hasArrayBuffer,
   ensureArrayBuffer,
   getArrayBuffer,
   bytesToBase64,
   base64ToBytes,
   bufferToHexString,
   numToBytes,
   bytesToNum,
   byteCount,
   browserSupportsFilePickers,
   browserSupportsBytesStream,
   makeTookMsg,
   expired,
   ProcessCancelled,
   BYOBStreamReader,
   readStreamAll,
   streamWriteBYOD,
   getRandom,
   selectCipherFile,
   selectClearFile,
   selectWriteableFile,
   selectWriteableJsonFile,
   selectWriteableQQFile,
   selectWriteableTxtFile,
   bytesFromString,
} from './lib/utils';

// Cipher core types and classes
export {
   Ciphers,
   Encipher,
   Decipher,
   EncipherV67,
   DecipherV67,
   CipherState,
   Extractor,
   Packer,
} from './lib/ciphers-current';

export type {
   CipherDataInfo,
   CipherDataBlock,
} from './lib/ciphers-current';

// Cipher factory functions
export {
   latestEncipher,
   streamDecipher,
} from './lib/ciphers';

// Old decipher versions
export {
   DecipherV1,
   DecipherV4,
   DecipherV5
} from './lib/deciphers-old';

// Cipher streams
export {
   encryptStream,
   decryptStream,
   getCipherStreamInfo,
} from './lib/cipher-streams';

export type {
   EContext,
} from './lib/cipher-streams';

// Armor functions
export { makeCipherArmor, parseCipherArmor } from './lib/armor';

export type { PWDProvider } from './lib/keys';

// Lazy libsodium loader; callers must `await cryptoReady()` before invoking any other crypto export.
export { cryptoReady } from './lib/sodium';

// Lazy zxcvbn loader; callers must `await zxcvbnReady()` before invoking any other zxcvbn export.
export { zxcvbnReady, getZxcvbn, checkPwned, addMatcher, removeMatcher } from './lib/zxcvbn';
