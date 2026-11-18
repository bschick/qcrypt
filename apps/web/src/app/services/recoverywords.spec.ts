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
import { base64ToBytes, bytesToBase64, cryptoReady, getRandom } from '@qcrypt/crypto';
import * as cc from '@qcrypt/crypto/consts';
import * as api from '@qcrypt/api';
import { entropyToMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { getUserCredTag } from './credentialtag';
import {
   decodeRecovery,
   newRecovery,
   validRecoveryWords,
   RECOVERY_PHRASE1_COUNT,
   RECOVERY_WORD_COUNT,
   UNTAGGED_RECOVERY_WORD_COUNT,
} from './recoverywords';

// Every word set already written has to keep decoding to the secret it was made from
const PINNED_WORDS =
   'film broccoli stem dream horse empty twenty grid quarter excite bundle universe switch pluck annual ' +
   'spice exhibit shy taxi fresh bus purity oval spare alcohol chronic order';
const PINNED_SECRET = 'VkOPVSFG3JJ6yzOvadh5du3DTULRifMebzXMPeuU7dA';
const PINNED_TAG = 'YMChzg';

function randomUserId(): string {
   return bytesToBase64(getRandom(cc.USERID_BYTES));
}

function randomWords(): string[] {
   return newRecovery(randomUserId(), getRandom(cc.USERCRED_BYTES)).recoveryWords.split(' ');
}

describe('recovery words', () => {
   beforeEach(async () => {
      await cryptoReady();
   });

   it('round trips a secret and tag', () => {
      const userId = randomUserId();
      const userCred = getRandom(cc.USERCRED_BYTES);
      const { recoverySecret, recoveryPubKey, recoveryWords } = newRecovery(userId, userCred);

      expect(recoveryWords.split(' ')).toHaveLength(RECOVERY_WORD_COUNT);
      expect(recoveryPubKey).toBe(api.getRecoveryPubKey(recoverySecret));
      expect(decodeRecovery(recoveryWords)).toEqual({
         recoverySecret,
         userId,
         userCredTag: getUserCredTag(userCred),
      });
   });

   it('accepts words in any spacing and case', () => {
      const userId = randomUserId();
      const userCred = getRandom(cc.USERCRED_BYTES);
      const { recoverySecret, recoveryWords } = newRecovery(userId, userCred);
      const messy = `  ${recoveryWords.toUpperCase().replace(/ /g, '\n  ')}  `;

      expect(validRecoveryWords(messy)).toBe(true);
      expect(decodeRecovery(messy)).toEqual({ recoverySecret, userId, userCredTag: getUserCredTag(userCred) });
   });

   it('decodes a word set carrying no tag', () => {
      const userId = randomUserId();
      const recoverySecret = api.recoverySecret(getRandom(api.RECOVERYID_BYTES), userId);
      const words = entropyToMnemonic(recoverySecret, wordlist);

      expect(words.split(' ')).toHaveLength(UNTAGGED_RECOVERY_WORD_COUNT);
      expect(decodeRecovery(words)).toEqual({ recoverySecret, userId, userCredTag: null });
   });

   it('rejects a word count that is neither tagged nor untagged', () => {
      const words = randomWords();
      expect(validRecoveryWords(words.join(' '))).toBe(true);

      for (const count of [12, 15, UNTAGGED_RECOVERY_WORD_COUNT, RECOVERY_WORD_COUNT - 1]) {
         expect(validRecoveryWords(words.slice(0, count).join(' '))).toBe(false);
      }
      expect(validRecoveryWords([...words, words[0]].join(' '))).toBe(false);
   });

   it('rejects a word outside the list in either phrase', () => {
      const words = randomWords();
      expect(validRecoveryWords(words.join(' '))).toBe(true);

      for (const pos of [0, RECOVERY_WORD_COUNT - 1]) {
         const changed = [...words];
         changed[pos] = 'quickcrypt';
         expect(validRecoveryWords(changed.join(' '))).toBe(false);
      }
   });

   it('rejects swapped phrases', () => {
      const words = randomWords();
      expect(validRecoveryWords(words.join(' '))).toBe(true);

      const first = words.slice(0, RECOVERY_PHRASE1_COUNT);
      const second = words.slice(RECOVERY_PHRASE1_COUNT);
      expect(validRecoveryWords([...second, ...first].join(' '))).toBe(false);
   });

   // A fixed set, because one changed word passes a 12 word checksum with probability 1/16
   it('rejects a word that breaks a phrase checksum', () => {
      expect(validRecoveryWords(PINNED_WORDS)).toBe(true);

      for (const pos of [0, RECOVERY_WORD_COUNT - 1]) {
         const changed = PINNED_WORDS.split(' ');
         changed[pos] = 'abandon';
         expect(validRecoveryWords(changed.join(' '))).toBe(false);
      }
   });

   it('decoded words match expected values', () => {
      const recoverySecret = base64ToBytes(PINNED_SECRET);

      expect(decodeRecovery(PINNED_WORDS)).toEqual({
         recoverySecret,
         userId: api.recoverySecretUserId(recoverySecret),
         userCredTag: PINNED_TAG,
      });
   });
});
