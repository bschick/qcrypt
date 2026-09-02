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

import { getProofKeyPair, createProof, verifyProof, base64ToBytes, bytesToBase64, concatArrays } from '@qcrypt/crypto';
import * as cc from '@qcrypt/crypto/consts';

const USERCRED_KEY_CONTEXT = 'UCredKey';
const USERCRED_SIG_CONTEXT = 'qcrypt/usercred/proof/v1';

const RECOVERY_KEY_CONTEXT = 'RecovKey';

export type RecoveryOp = 'replace' | 'recover';

const RECOVERY_SIG_CONTEXTS: Readonly<Record<RecoveryOp, string>> = {
   replace: 'qcrypt/recovery/replace/v1',
   recover: 'qcrypt/recovery/recover/v1',
};

export const RECOVERYID_BYTES = 16;
export const CHALLENGE_BYTES = 32;

// ML-DSA-65 public key and signature length in bytes.
export const PROOF_PUBKEY_BYTES = 1952;
export const PROOF_SIG_BYTES = 3309;

function buildUserCredMessage(
   userId: string,
   method: string,
   path: string,
   timestampMs: string,
   nonce: string,
   bodyHashHex: string,
   queryString: string,
): Uint8Array<ArrayBuffer> {
   if (base64ToBytes(userId).byteLength !== cc.USERID_BYTES) {
      throw new Error('invalid userId length');
   }
   const fields = [userId, method.toUpperCase(), path, timestampMs, nonce, bodyHashHex.toLowerCase()];
   if (queryString) {
      fields.push(queryString);
   }
   const message = fields.join('\n');
   return new TextEncoder().encode(message);
}

export function getUserCredPubKey(userCred: Uint8Array): string {
   const { pubKey, secKey } = getProofKeyPair(userCred, USERCRED_KEY_CONTEXT);
   secKey.fill(0);
   return bytesToBase64(pubKey);
}

export function createUserCredProof(
   userCred: Uint8Array,
   userId: string,
   method: string,
   path: string,
   timestampMs: string,
   nonce: string,
   bodyHashHex: string,
   queryString: string = '',
): string {
   const { secKey } = getProofKeyPair(userCred, USERCRED_KEY_CONTEXT);
   try {
      return bytesToBase64(
         createProof(
            secKey,
            buildUserCredMessage(userId, method, path, timestampMs, nonce, bodyHashHex, queryString),
            USERCRED_SIG_CONTEXT,
         ),
      );
   } finally {
      secKey.fill(0);
   }
}

export function verifyUserCredProof(
   pubKey: string,
   userId: string,
   method: string,
   path: string,
   timestampMs: string,
   nonce: string,
   bodyHashHex: string,
   signature: string,
   queryString: string = '',
): boolean {
   return verifyProof(
      base64ToBytes(pubKey),
      buildUserCredMessage(userId, method, path, timestampMs, nonce, bodyHashHex, queryString),
      base64ToBytes(signature),
      USERCRED_SIG_CONTEXT,
   );
}

export function recoverySecret(recoveryId: Uint8Array, userId: string): Uint8Array<ArrayBuffer> {
   if (recoveryId.every((b) => b === 0)) {
      throw new Error('Invalid recoveryId: all zero bytes');
   }
   return concatArrays([recoveryId, base64ToBytes(userId)]);
}

function buildRecoveryMessage(userId: string, timestampMs: string, nonce: string): Uint8Array<ArrayBuffer> {
   if (base64ToBytes(userId).byteLength !== cc.USERID_BYTES) {
      throw new Error('invalid userId length');
   }
   if (base64ToBytes(nonce).byteLength !== CHALLENGE_BYTES) {
      throw new Error('invalid nonce length');
   }
   const message = [userId, timestampMs, nonce].join('\n');
   return new TextEncoder().encode(message);
}

export function getRecoveryPubKey(recoverySecret: Uint8Array): string {
   const { pubKey, secKey } = getProofKeyPair(recoverySecret, RECOVERY_KEY_CONTEXT);
   secKey.fill(0);
   return bytesToBase64(pubKey);
}

export function createRecoveryProof(
   recoverySecret: Uint8Array,
   userId: string,
   timestampMs: string,
   nonce: string,
   op: RecoveryOp,
): string {
   const { secKey } = getProofKeyPair(recoverySecret, RECOVERY_KEY_CONTEXT);
   try {
      const message = buildRecoveryMessage(userId, timestampMs, nonce);
      return bytesToBase64(createProof(secKey, message, RECOVERY_SIG_CONTEXTS[op]));
   } finally {
      secKey.fill(0);
   }
}

export function verifyRecoveryProof(
   pubKey: string,
   userId: string,
   timestampMs: string,
   nonce: string,
   signature: string,
   op: RecoveryOp,
): boolean {
   return verifyProof(
      base64ToBytes(pubKey),
      buildRecoveryMessage(userId, timestampMs, nonce),
      base64ToBytes(signature),
      RECOVERY_SIG_CONTEXTS[op],
   );
}
