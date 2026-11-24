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
import { checkHandle, createHandle, userIdFromHandle } from './credentialtag';

function randomUserId(): string {
   return bytesToBase64(getRandom(cc.USERID_BYTES));
}

function handleFromText(text: string): string {
   return bytesToBase64(new TextEncoder().encode(text));
}

// Passkeys registered before tagging hold this handle
function untaggedHandle(userId: string): string {
   return handleFromText(userId);
}

function handleTag(userId: string, userCred: Uint8Array): string {
   const text = new TextDecoder().decode(base64ToBytes(createHandle(userId, userCred)));
   return text.slice(userId.length);
}

describe('passkey handle', () => {
   beforeEach(async () => {
      await cryptoReady();
   });

   it('returns the user id of a tagged handle', () => {
      const userId = randomUserId();
      expect(userIdFromHandle(createHandle(userId, getRandom(cc.USERCRED_BYTES)))).toBe(userId);
   });

   it('returns the user id of an untagged handle', () => {
      const userId = randomUserId();
      expect(userIdFromHandle(untaggedHandle(userId))).toBe(userId);
   });

   it('rejects a handle created from a different user credential', () => {
      const userCred = getRandom(cc.USERCRED_BYTES);
      const userHandle = createHandle(randomUserId(), userCred);
      expect(() => checkHandle(userHandle, userCred)).not.toThrow();

      expect(() => checkHandle(userHandle, getRandom(cc.USERCRED_BYTES))).toThrow();
   });

   it('accepts an untagged handle with any user credential', () => {
      expect(() => checkHandle(untaggedHandle(randomUserId()), getRandom(cc.USERCRED_BYTES))).not.toThrow();
   });

   it('rejects a tag moved to a handle for another user id', () => {
      const userCred = getRandom(cc.USERCRED_BYTES);
      const userId = randomUserId();
      const otherUserId = randomUserId();
      expect(() => checkHandle(handleFromText(userId + handleTag(userId, userCred)), userCred)).not.toThrow();

      const moved = handleFromText(otherUserId + handleTag(userId, userCred));
      expect(() => checkHandle(moved, userCred)).toThrow();
   });

   it('rejects a user credential that is not USERCRED_BYTES', () => {
      const userId = randomUserId();
      expect(createHandle(userId, getRandom(cc.USERCRED_BYTES))).toBeTruthy();

      for (const length of [0, cc.USERCRED_BYTES - 1, cc.USERCRED_BYTES + 1]) {
         expect(() => createHandle(userId, getRandom(length))).toThrow();
      }
   });

   it('rejects a user id that is not USERID_BYTES', () => {
      const userId = randomUserId();
      const userCred = getRandom(cc.USERCRED_BYTES);
      expect(createHandle(userId, userCred)).toBeTruthy();

      for (const bad of ['', userId.slice(1), `${userId}A`]) {
         expect(() => createHandle(bad, userCred)).toThrow();
      }
   });

   it('rejects a handle that is neither tagged nor untagged', () => {
      const userId = randomUserId();
      const tag = handleTag(userId, getRandom(cc.USERCRED_BYTES));
      expect(userIdFromHandle(handleFromText(userId + tag))).toBe(userId);

      // The last case is a handle with the shorter tag of earlier development builds
      for (const text of [userId.slice(1), userId + tag.slice(1), `${userId}${tag}A`, userId + tag.slice(0, 6)]) {
         expect(() => userIdFromHandle(handleFromText(text))).toThrow();
      }
   });

   it('rejects a handle of the right length that is not base64', () => {
      const userId = randomUserId();
      const tag = handleTag(userId, getRandom(cc.USERCRED_BYTES));
      expect(userIdFromHandle(handleFromText(userId + tag))).toBe(userId);

      for (const text of ['!'.repeat(userId.length), userId + '!'.repeat(tag.length)]) {
         expect(() => userIdFromHandle(handleFromText(text))).toThrow();
      }
   });

   it('created handles match expected values', () => {
      const userId = '7cNNQtGJ8x5vNcw965Tt0A';
      const userCreds = [
         'dJSUi6L-p9ErmjPtEwdnTB2FxeJ3axgAYNB0wyhMgdY',
         'b-82e8UjFTYSP-TevQav_TDw6VFJHWMyc7ROM3B6PYg',
         'zgdgQRth8-vlwtciOHmONX0FHgMbhqBE_1dUR_2Rslg',
      ];

      const handles = userCreds.map((userCred) => createHandle(userId, base64ToBytes(userCred)));
      expect(handles).toEqual([
         'N2NOTlF0R0o4eDV2TmN3OTY1VHQwQVIyRFZTcEhVckdxbk4xUzZZelNDNHc',
         'N2NOTlF0R0o4eDV2TmN3OTY1VHQwQW1LY0hHbmtHaHAtek41UG8wSHZDNFE',
         'N2NOTlF0R0o4eDV2TmN3OTY1VHQwQWRiU19mZE81VEgwcnRHd2t6UGFkOXc',
      ]);
   });
});
