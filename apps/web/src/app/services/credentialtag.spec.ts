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
import { createHandle, decodeHandle, getUserCredTag, USERCRED_TAG_BYTES } from './credentialtag';

// Passkeys registered before tagging hold this handle
function untaggedHandle(userId: string): string {
   return bytesToBase64(new TextEncoder().encode(userId));
}

describe('credential tag', () => {
   beforeEach(async () => {
      await cryptoReady();
   });

   it('derives a tag of USERCRED_TAG_BYTES', () => {
      const tag = getUserCredTag(getRandom(cc.USERCRED_BYTES));
      expect(base64ToBytes(tag).byteLength).toBe(USERCRED_TAG_BYTES);
   });

   it('derives a different tag for a different userCred', () => {
      const tag = getUserCredTag(getRandom(cc.USERCRED_BYTES));
      expect(getUserCredTag(getRandom(cc.USERCRED_BYTES))).not.toBe(tag);
   });

   it('rejects a userCred that is not USERCRED_BYTES', () => {
      expect(getUserCredTag(getRandom(cc.USERCRED_BYTES))).toBeTruthy();

      for (const length of [0, cc.USERCRED_BYTES - 1, cc.USERCRED_BYTES + 1]) {
         expect(() => getUserCredTag(getRandom(length))).toThrow();
      }
   });

   it('derived tags match expected values', () => {
      const userCreds = [
         'dJSUi6L-p9ErmjPtEwdnTB2FxeJ3axgAYNB0wyhMgdY',
         'b-82e8UjFTYSP-TevQav_TDw6VFJHWMyc7ROM3B6PYg',
         'zgdgQRth8-vlwtciOHmONX0FHgMbhqBE_1dUR_2Rslg',
      ];

      const tags = userCreds.map((userCred) => getUserCredTag(base64ToBytes(userCred)));
      expect(tags).toEqual(['YMChzg', '1_CVog', '0RU_8Q']);
   });
});

describe('passkey handle', () => {
   beforeEach(async () => {
      await cryptoReady();
   });

   it('round trips a user id with no tag', () => {
      const userId = bytesToBase64(getRandom(cc.USERID_BYTES));
      expect(decodeHandle(untaggedHandle(userId))).toEqual({ userId, userCredTag: null });
   });

   it('round trips a user id and tag', () => {
      const userId = bytesToBase64(getRandom(cc.USERID_BYTES));
      const userCred = getRandom(cc.USERCRED_BYTES);
      expect(decodeHandle(createHandle(userId, userCred))).toEqual({
         userId,
         userCredTag: getUserCredTag(userCred),
      });
   });

   it('rejects a user id that is not USERID_BYTES', () => {
      const userId = bytesToBase64(getRandom(cc.USERID_BYTES));
      const userCred = getRandom(cc.USERCRED_BYTES);
      expect(createHandle(userId, userCred)).toBeTruthy();

      for (const bad of ['', userId.slice(1), `${userId}A`]) {
         expect(() => createHandle(bad, userCred)).toThrow();
      }
   });

   it('rejects a handle that is neither tagged nor untagged', () => {
      const userId = bytesToBase64(getRandom(cc.USERID_BYTES));
      const tag = getUserCredTag(getRandom(cc.USERCRED_BYTES));
      expect(decodeHandle(untaggedHandle(userId)).userId).toBe(userId);

      for (const text of [userId.slice(1), userId + tag.slice(1), `${userId}${tag}A`]) {
         expect(() => decodeHandle(bytesToBase64(new TextEncoder().encode(text)))).toThrow();
      }
   });

   it('rejects a handle of the right length that is not base64', () => {
      const userId = bytesToBase64(getRandom(cc.USERID_BYTES));
      const tag = getUserCredTag(getRandom(cc.USERCRED_BYTES));
      expect(decodeHandle(untaggedHandle(userId)).userId).toBe(userId);

      for (const text of ['!'.repeat(userId.length), userId + '!'.repeat(tag.length)]) {
         expect(() => decodeHandle(bytesToBase64(new TextEncoder().encode(text)))).toThrow();
      }
   });
});
