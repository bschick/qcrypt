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

import { base64ToBytes, bytesToBase64, getRandom } from '@qcrypt/crypto';
import * as api from '@qcrypt/api';
import { entropyToMnemonic, mnemonicToEntropy } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { getUserCredTag, USERCRED_TAG_BYTES } from './credentialtag';

export const TAGGED_RECOVERY_SECRET_BYTES = api.RECOVERY_SECRET_BYTES + USERCRED_TAG_BYTES;

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
   tag: string | null;
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

// The caller takes ownership of and must overwrite recoverySecret
export function newRecovery(userId: string, userCred: Uint8Array): Recovery {
   const recoverySecret = newRecoverySecret(userId);
   const tagged = new Uint8Array(TAGGED_RECOVERY_SECRET_BYTES);
   try {
      tagged.set(recoverySecret);
      tagged.set(base64ToBytes(getUserCredTag(userCred)), api.RECOVERY_SECRET_BYTES);

      const phrase1 = entropyToMnemonic(tagged.subarray(0, PHRASE1_BYTES), wordlist);
      const phrase2 = entropyToMnemonic(tagged.subarray(PHRASE1_BYTES), wordlist);
      return {
         recoverySecret,
         recoveryPubKey: api.getRecoveryPubKey(recoverySecret),
         recoveryWords: `${phrase1} ${phrase2}`,
      };
   } finally {
      tagged.fill(0);
   }
}

// The caller takes ownership of and must overwrite recoverySecret. Older recovery words
// that do not carry a tag return the DecodedRecovery with a null tag.
export function decodeRecovery(words: string): DecodedRecovery {
   const normalized = normalizeRecoveryWords(words);
   const allWords = normalized.split(' ');

   if (allWords.length === UNTAGGED_RECOVERY_WORD_COUNT) {
      const recoverySecret = mnemonicToEntropy(normalized, wordlist);
      return { recoverySecret, userId: api.recoverySecretUserId(recoverySecret), tag: null };
   } else if (allWords.length === RECOVERY_WORD_COUNT) {
      const segment1 = mnemonicToEntropy(allWords.slice(0, RECOVERY_PHRASE1_COUNT).join(' '), wordlist);
      const segment2 = mnemonicToEntropy(allWords.slice(RECOVERY_PHRASE1_COUNT).join(' '), wordlist);
      try {
         const tagged = new Uint8Array(TAGGED_RECOVERY_SECRET_BYTES);
         try {
            tagged.set(segment1);
            tagged.set(segment2, segment1.byteLength);

            const recoverySecret = tagged.slice(0, api.RECOVERY_SECRET_BYTES);
            return {
               recoverySecret,
               userId: api.recoverySecretUserId(recoverySecret),
               tag: bytesToBase64(tagged.subarray(api.RECOVERY_SECRET_BYTES)),
            };
         } finally {
            tagged.fill(0);
         }
      } finally {
         segment1.fill(0);
         segment2.fill(0);
      }
   } else {
      throw new Error('invalid recovery words');
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
