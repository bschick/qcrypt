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

import { getProofKeyPair, signProof, verifyProof } from '@qcrypt/crypto';

export namespace RequestTypes {
}

export namespace ResponseTypes {
   export type AuthenticatorInfo = {
      credentialId: string;
      description: string;
      lightIcon: string;
      darkIcon: string;
      name: string;
   };

   export type InvitableInfo = {
      invitableId: string;
      description?: string;
   };

   export type UserInfo = {
      verified: boolean;
      userId?: string;
      userName?: string;
      hasRecoveryId?: boolean;
      authenticators?: AuthenticatorInfo[];
      invitables?: InvitableInfo[];
   };

   export type LoginUserInfo = UserInfo & {
      pkId?: string;
      userCred?: string;
      recoveryId?: string;
      csrf?: string;
   };
}

export const TOPIC_USERS_MAX = 255;
export const SESSION_TIMEOUT_SEC = 60 * 60 * 3;

const USERCRED_SCHEME = 'qcrypt-usercred-v1';
const USERCRED_KEY_CONTEXT = 'UCredKey';
const USERCRED_SIG_CONTEXT = 'qcrypt/usercred/proof/v1';

function buildUserCredMessage(method: string, path: string, timestampMs: string, bodyHashHex: string): Uint8Array<ArrayBuffer> {
   const message = [USERCRED_SCHEME, method.toUpperCase(), path, timestampMs, bodyHashHex.toLowerCase()].join('\n');
   return new TextEncoder().encode(message);
}

export function getUserCredPubKey(userCred: Uint8Array): Uint8Array<ArrayBuffer> {
   const { pubKey, secKey } = getProofKeyPair(userCred, USERCRED_KEY_CONTEXT);
   secKey.fill(0);
   return pubKey;
}

export function signUserCredProof(
   userCred: Uint8Array,
   method: string,
   path: string,
   timestampMs: string,
   bodyHashHex: string
): Uint8Array<ArrayBuffer> {
   const { secKey } = getProofKeyPair(userCred, USERCRED_KEY_CONTEXT);
   try {
      return signProof(secKey, buildUserCredMessage(method, path, timestampMs, bodyHashHex), USERCRED_SIG_CONTEXT);
   } finally {
      secKey.fill(0);
   }
}

export function verifyUserCredProof(
   pubKey: Uint8Array,
   method: string,
   path: string,
   timestampMs: string,
   bodyHashHex: string,
   signature: Uint8Array
): boolean {
   return verifyProof(pubKey, buildUserCredMessage(method, path, timestampMs, bodyHashHex), signature, USERCRED_SIG_CONTEXT);
}