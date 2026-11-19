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
const USERCRED_TAG_BYTES = 16;
const USERID_B64_LEN = Math.ceil((cc.USERID_BYTES * 4) / 3);
const TAG_B64_LEN = Math.ceil((USERCRED_TAG_BYTES * 4) / 3);

// Credential tags are long enough to be safe if published, so they are not treated as secret
function getUserCredTag(userCred: Uint8Array, userId: string): string {
   if (userCred.byteLength !== cc.USERCRED_BYTES) {
      throw new Error(`Invalid userCred length of: ${userCred.byteLength}`);
   }

   const userIdBytes = base64ToBytes(userId, cc.USERID_BYTES, 'userId');
   const userCredTag = deriveTag(userCred, USERCRED_TAG_PURPOSE, 1, USERCRED_TAG_BYTES, [userIdBytes]);
   return bytesToBase64(userCredTag);
}

// SimpleWebAuthn v10+ encodes credential user.id as b64 rather than utf as older versions,
// so translate to keep the handle stable for passkeys registered under v9.
// https://github.com/MasterKale/SimpleWebAuthn/discussions/636
export function createHandle(userId: string, userCred: Uint8Array): string {
   if (userId.length !== USERID_B64_LEN) {
      throw new Error(`Invalid userId length of: ${userId.length}`);
   }

   const userCredTag = getUserCredTag(userCred, userId);
   return bytesToBase64(new TextEncoder().encode(userId + userCredTag));
}

// A tagged handle is the user id text followed by the tag text.
// Passkeys created before tagging hold the user id text alone.
function decodeHandle(userHandle: string): { userId: string; userCredTag: string | null } {
   const text = new TextDecoder('utf-8').decode(base64ToBytes(userHandle));
   if (text.length !== USERID_B64_LEN && text.length !== USERID_B64_LEN + TAG_B64_LEN) {
      throw new Error('invalid passkey handle');
   }

   const userId = text.slice(0, USERID_B64_LEN);
   const userCredTag = text.length > USERID_B64_LEN ? text.slice(USERID_B64_LEN) : null;

   base64ToBytes(userId, cc.USERID_BYTES, 'userId');
   if (userCredTag) {
      base64ToBytes(userCredTag, USERCRED_TAG_BYTES, 'userCredTag');
   }

   return { userId, userCredTag };
}

// Returns the tagged and the untagged handle, for WebAuthn signals only.
export function signalHandles(userId: string, userCred: Uint8Array): string[] {
   const taggedHandle = createHandle(userId, userCred);
   const untaggedHandle = bytesToBase64(new TextEncoder().encode(userId));
   return [taggedHandle, untaggedHandle];
}

export function userIdFromHandle(userHandle: string): string {
   return decodeHandle(userHandle).userId;
}

export function checkHandle(userHandle: string, userCred: Uint8Array): void {
   const { userId, userCredTag } = decodeHandle(userHandle);
   if (userCredTag && userCredTag !== getUserCredTag(userCred, userId)) {
      throw new Error('user credential does not match the passkey handle');
   }
}
