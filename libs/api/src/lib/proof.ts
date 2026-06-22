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

import { getProofKeyPair, signProof, verifyProof, base64ToBytes, concatArrays } from '@qcrypt/crypto';
import * as cc from '@qcrypt/crypto/consts';

const USERCRED_SCHEME = 'qcrypt-usercred-v1';
const USERCRED_KEY_CONTEXT = 'UCredKey';
const USERCRED_SIG_CONTEXT = 'qcrypt/usercred/proof/v1';

const RECOVERY_SCHEME = 'qcrypt-recovery-v1';
const RECOVERY_KEY_CONTEXT = 'RecovKey';
const RECOVERY_SIG_CONTEXT = 'qcrypt/recovery/proof/v1';

export const CHALLENGE_BYTES = 32;
// ML-DSA-65 public key and signature length in bytes.
export const PROOF_PUBKEY_BYTES = 1952;
export const PROOF_SIG_BYTES = 3309;

// For backward compat only. After migration, this becomes a client only value
export const RECOVERYID_BYTES = 16;

function buildUserCredMessage(
   userId: string,
   method: string,
   path: string,
   timestampMs: string,
   bodyHashHex: string
): Uint8Array<ArrayBuffer> {
   if (base64ToBytes(userId).byteLength !== cc.USERID_BYTES) {
      throw new Error('invalid userId length');
   }
   const message = [
      USERCRED_SCHEME,
      userId,
      method.toUpperCase(),
      path,
      timestampMs,
      bodyHashHex.toLowerCase()
   ].join('\n');
   return new TextEncoder().encode(message);
}

export function getUserCredPubKey(userCred: Uint8Array): Uint8Array<ArrayBuffer> {
   const { pubKey, secKey } = getProofKeyPair(userCred, USERCRED_KEY_CONTEXT);
   secKey.fill(0);
   return pubKey;
}

export function signUserCredProof(
   userCred: Uint8Array,
   userId: string,
   method: string,
   path: string,
   timestampMs: string,
   bodyHashHex: string
): Uint8Array<ArrayBuffer> {
   const { secKey } = getProofKeyPair(userCred, USERCRED_KEY_CONTEXT);
   try {
      return signProof(
         secKey,
         buildUserCredMessage(userId, method, path, timestampMs, bodyHashHex),
         USERCRED_SIG_CONTEXT
      );
   } finally {
      secKey.fill(0);
   }
}

export function verifyUserCredProof(
   pubKey: Uint8Array,
   userId: string,
   method: string,
   path: string,
   timestampMs: string,
   bodyHashHex: string,
   signature: Uint8Array
): boolean {
   return verifyProof(
      pubKey,
      buildUserCredMessage(userId, method, path, timestampMs, bodyHashHex),
      signature,
      USERCRED_SIG_CONTEXT
   );
}

// Order must not change for recovery to function
// For backward compat only. After migration, this becomes a client only function
export function recoverySecret(recoveryId: Uint8Array, userId: string): Uint8Array<ArrayBuffer> {
   return concatArrays([recoveryId, base64ToBytes(userId)]);
}

function buildRecoveryMessage(
   userId: string,
   challenge: string
): Uint8Array<ArrayBuffer> {
   if (base64ToBytes(userId).byteLength !== cc.USERID_BYTES) {
      throw new Error('invalid userId length');
   }
   if (base64ToBytes(challenge).byteLength !== CHALLENGE_BYTES) {
      throw new Error('invalid challenge length');
   }
   const message = [
      RECOVERY_SCHEME,
      userId,
      challenge
   ].join('\n');
   return new TextEncoder().encode(message);
}

export function getRecoveryPubKey(recoverySecret: Uint8Array): Uint8Array<ArrayBuffer> {
   const { pubKey, secKey } = getProofKeyPair(recoverySecret, RECOVERY_KEY_CONTEXT);
   secKey.fill(0);
   return pubKey;
}

export function signRecoveryProof(
   recoverySecret: Uint8Array,
   userId: string,
   challenge: string
): Uint8Array<ArrayBuffer> {
   const { secKey } = getProofKeyPair(recoverySecret, RECOVERY_KEY_CONTEXT);
   try {
      return signProof(
         secKey,
         buildRecoveryMessage(userId, challenge),
         RECOVERY_SIG_CONTEXT
      );
   } finally {
      secKey.fill(0);
   }
}

export function verifyRecoveryProof(
   pubKey: Uint8Array,
   userId: string,
   challenge: string,
   signature: Uint8Array
): boolean {
   return verifyProof(
      pubKey,
      buildRecoveryMessage(userId, challenge),
      signature,
      RECOVERY_SIG_CONTEXT
   );
}
