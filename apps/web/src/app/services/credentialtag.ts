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

import { base64ToBytes, bytesToBase64, deriveTag } from '@qcrypt/crypto';
import * as cc from '@qcrypt/crypto/consts';

const USERCRED_TAG_PURPOSE = 'UCredTag';
export const USERCRED_TAG_BYTES = 4;
const USERID_B64_LEN = Math.ceil((cc.USERID_BYTES * 4) / 3);
const TAG_B64_LEN = Math.ceil((USERCRED_TAG_BYTES * 4) / 3);

export function getUserCredTag(userCred: Uint8Array): string {
   return bytesToBase64(deriveTag(userCred, USERCRED_TAG_PURPOSE, 1, USERCRED_TAG_BYTES));
}

// SimpleWebAuthn v10+ encodes credential user.id as b64 rather than utf as older versions,
// so translate to keep the handle stable for passkeys registered under v9.
// https://github.com/MasterKale/SimpleWebAuthn/discussions/636
export function userIdToHandle(userId: string, userCred: Uint8Array): string {
   return bytesToBase64(new TextEncoder().encode(userId + getUserCredTag(userCred)));
}

export function userIdToUntaggedHandle(userId: string): string {
   return bytesToBase64(new TextEncoder().encode(userId));
}

export function handleToUserId(handle: string): { userId: string; tag: string | null } {
   const text = new TextDecoder('utf-8').decode(base64ToBytes(handle));
   if (text.length !== USERID_B64_LEN && text.length !== USERID_B64_LEN + TAG_B64_LEN) {
      throw new Error('invalid passkey handle');
   }

   return {
      userId: text.slice(0, USERID_B64_LEN),
      tag: text.length > USERID_B64_LEN ? text.slice(USERID_B64_LEN) : null,
   };
}
