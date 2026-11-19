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

import { constantTimeCompare, deriveTag, getRandom } from '@qcrypt/crypto';
import * as cc from '@qcrypt/crypto/consts';
import * as api from '@qcrypt/api';
import { entropyToMnemonic, mnemonicToEntropy } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';

const RECOVERY_TAG_PURPOSE = 'RecovTag';
const RECOVERY_TAG_BYTES = 4;
const TAGGED_RECOVERY_SECRET_BYTES = api.RECOVERY_SECRET_BYTES + RECOVERY_TAG_BYTES;

// BIP39 encodes at most 32 bytes per phrase, so a tagged recovery secret takes two phrases.
const PHRASE1_BYTES = 20;
export const RECOVERY_PHRASE1_COUNT = 15;
const RECOVERY_PHRASE2_COUNT = 12;
export const RECOVERY_WORD_COUNT = RECOVERY_PHRASE1_COUNT + RECOVERY_PHRASE2_COUNT;
export const UNTAGGED_RECOVERY_WORD_COUNT = 24;

export type Recovery = {
   recoverySecret: Uint8Array<ArrayBuffer>;
   recoveryPubKey: string;
   recoveryWords: string;
};

export type DecodedRecovery = {
   recoverySecret: Uint8Array<ArrayBuffer>;
   userId: string;
};

function normalizeRecoveryWords(words: string): string {
   return words.trim().toLowerCase().split(/\s+/).join(' ');
}

function newRecoverySecret(userId: string): Uint8Array<ArrayBuffer> {
   const recoveryId = getRandom(api.RECOVERYID_BYTES);
   try {
      return api.recoverySecret(recoveryId, userId);
   } finally {
      recoveryId.fill(0);
   }
}

// Recovery tags are short by design and are therefore secret; just like the recovery words they
// are part of. Callers should clear the memory after use.
function getRecoveryTag(userCred: Uint8Array, recoverySecret: Uint8Array): Uint8Array<ArrayBuffer> {
   if (userCred.byteLength !== cc.USERCRED_BYTES) {
      throw new Error(`Invalid userCred length of: ${userCred.byteLength}`);
   }
   if (recoverySecret.byteLength !== api.RECOVERY_SECRET_BYTES) {
      throw new Error(`Invalid recoverySecret length of: ${recoverySecret.byteLength}`);
   }

   return deriveTag(userCred, RECOVERY_TAG_PURPOSE, 1, RECOVERY_TAG_BYTES, [recoverySecret]);
}

// The caller takes ownership of and must overwrite Recovery.recoverySecret
export function newRecovery(userId: string, userCred: Uint8Array): Recovery {
   const recoverySecret = newRecoverySecret(userId);
   const tagged = new Uint8Array(TAGGED_RECOVERY_SECRET_BYTES);
   try {
      tagged.set(recoverySecret);
      const recoveryTag = getRecoveryTag(userCred, recoverySecret);
      tagged.set(recoveryTag, api.RECOVERY_SECRET_BYTES);
      recoveryTag.fill(0);

      const phrase1 = entropyToMnemonic(tagged.subarray(0, PHRASE1_BYTES), wordlist);
      const phrase2 = entropyToMnemonic(tagged.subarray(PHRASE1_BYTES), wordlist);
      return {
         recoverySecret,
         recoveryPubKey: api.getRecoveryPubKey(recoverySecret),
         recoveryWords: `${phrase1} ${phrase2}`,
      };
   } catch (err) {
      recoverySecret.fill(0);
      throw err;
   } finally {
      tagged.fill(0);
   }
}

// The caller takes ownership of and must overwrite recoverySecret.
// Older recovery words that do not carry a tag return a null recoveryTag.
function decodeRecoveryWords(words: string): {
   recoverySecret: Uint8Array<ArrayBuffer>;
   recoveryTag: Uint8Array<ArrayBuffer> | null;
} {
   const normalized = normalizeRecoveryWords(words);
   const allWords = normalized.split(' ');

   if (allWords.length === UNTAGGED_RECOVERY_WORD_COUNT) {
      const recoverySecret = mnemonicToEntropy(normalized, wordlist);
      return { recoverySecret, recoveryTag: null };
   } else if (allWords.length === RECOVERY_WORD_COUNT) {
      const segment1 = mnemonicToEntropy(allWords.slice(0, RECOVERY_PHRASE1_COUNT).join(' '), wordlist);
      let segment2: Uint8Array | undefined;
      try {
         segment2 = mnemonicToEntropy(allWords.slice(RECOVERY_PHRASE1_COUNT).join(' '), wordlist);
         const tagged = new Uint8Array(TAGGED_RECOVERY_SECRET_BYTES);
         try {
            tagged.set(segment1);
            tagged.set(segment2, segment1.byteLength);

            return {
               recoverySecret: tagged.slice(0, api.RECOVERY_SECRET_BYTES),
               recoveryTag: tagged.slice(api.RECOVERY_SECRET_BYTES),
            };
         } finally {
            tagged.fill(0);
         }
      } finally {
         segment1.fill(0);
         segment2?.fill(0);
      }
   } else {
      throw new Error('invalid recovery words');
   }
}

// The caller takes ownership of and must overwrite DecodedRecovery.recoverySecret
export function decodeRecovery(words: string): DecodedRecovery {
   const { recoverySecret, recoveryTag } = decodeRecoveryWords(words);
   recoveryTag?.fill(0);
   return { recoverySecret, userId: api.recoverySecretUserId(recoverySecret) };
}

export function checkRecovery(words: string, userCred: Uint8Array): void {
   const { recoverySecret, recoveryTag } = decodeRecoveryWords(words);
   let expectedTag: Uint8Array<ArrayBuffer> | undefined;
   try {
      if (recoveryTag) {
         expectedTag = getRecoveryTag(userCred, recoverySecret);
         if (!constantTimeCompare(recoveryTag, expectedTag)) {
            throw new Error('user credential does not match the recovery words');
         }
      }
   } finally {
      recoverySecret.fill(0);
      recoveryTag?.fill(0);
      expectedTag?.fill(0);
   }
}

export function validRecoveryWords(words: string): boolean {
   let recoverySecret: Uint8Array<ArrayBuffer> | null = null;
   try {
      recoverySecret = decodeRecovery(words).recoverySecret;
      return true;
   } catch {
      return false;
   } finally {
      recoverySecret?.fill(0);
   }
}
