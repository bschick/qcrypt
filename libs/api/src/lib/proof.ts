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

import {
   getProofKeyPair,
   createProof,
   verifyProof,
   base64ToBytes,
   bytesToBase64,
   concatArrays,
   ParamError,
} from '@qcrypt/crypto';
import * as cc from '@qcrypt/crypto/consts';

// Every public key a client sends for the server to store must come with a signature from the
// matching private key. The signature proves the client holds that key, and catches a client that
// sends the wrong key before anything depends on it.

const USERCRED_KEY_CONTEXT = 'UCredKey';
const USERCRED_SIG_CONTEXT = 'qcrypt/usercred/proof/v1';
const USERCRED_SESSIONLESS_SIG_CONTEXT = 'qcrypt/usercred/sessionless/v1';

const RECOVERY_KEY_CONTEXT = 'RecovKey';
const RECOVERY_REGISTER_SIG_CONTEXT = 'qcrypt/recovery/register/v1';

export type RecoveryOp = 'replace' | 'recover';

const RECOVERY_SIG_CONTEXTS: Readonly<Record<RecoveryOp, string>> = {
   replace: 'qcrypt/recovery/replace/v1',
   recover: 'qcrypt/recovery/recover/v1',
};

// BACKWARD COMPAT: clients before the per-operation contexts signed both operations with this one,
// which lets a proof for either operation stand in for the other. Delete once those clients are gone
const RECOVERY_COMPAT_SIG_CONTEXT = 'qcrypt/recovery/nonce/v1';

export const RECOVERYID_BYTES = 16;
export const CHALLENGE_BYTES = 32;
export const PROOF_SKEW_MS = 120 * 1000;

// ML-DSA-65 public key and signature length in bytes.
export const PROOF_PUBKEY_BYTES = 1952;
export const PROOF_SIG_BYTES = 3309;

function checkKeyAndSignature(pubKey: string, signature: string): void {
   base64ToBytes(pubKey, PROOF_PUBKEY_BYTES, 'public key');
   base64ToBytes(signature, PROOF_SIG_BYTES, 'signature');
}

function checkTimestamp(timestampMs: string): void {
   const timeMs = Number(timestampMs);
   if (!timestampMs || !Number.isFinite(timeMs) || Math.abs(Date.now() - timeMs) > PROOF_SKEW_MS) {
      throw new ParamError('proof timestamp outside skew window');
   }
}

function buildUserCredMessage(
   userId: string,
   method: string,
   path: string,
   timestampMs: string,
   nonce: string,
   bodyHashHex: string,
   queryString: string,
): Uint8Array<ArrayBuffer> {
   base64ToBytes(userId, cc.USERID_BYTES, 'userId');
   base64ToBytes(nonce, CHALLENGE_BYTES, 'nonce');
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

function signUserCredMessage(userCred: Uint8Array, message: Uint8Array, context: string): string {
   const { secKey } = getProofKeyPair(userCred, USERCRED_KEY_CONTEXT);
   try {
      return bytesToBase64(createProof(secKey, message, context));
   } finally {
      secKey.fill(0);
   }
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
   return signUserCredMessage(
      userCred,
      buildUserCredMessage(userId, method, path, timestampMs, nonce, bodyHashHex, queryString),
      USERCRED_SIG_CONTEXT,
   );
}

export function createSessionlessProof(
   userCred: Uint8Array,
   userId: string,
   method: string,
   path: string,
   timestampMs: string,
   nonce: string,
   bodyHashHex: string,
   queryString: string = '',
): string {
   return signUserCredMessage(
      userCred,
      buildUserCredMessage(userId, method, path, timestampMs, nonce, bodyHashHex, queryString),
      USERCRED_SESSIONLESS_SIG_CONTEXT,
   );
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
): void {
   checkKeyAndSignature(pubKey, signature);
   checkTimestamp(timestampMs);
   verifyProof(
      base64ToBytes(pubKey),
      buildUserCredMessage(userId, method, path, timestampMs, nonce, bodyHashHex, queryString),
      base64ToBytes(signature),
      USERCRED_SIG_CONTEXT,
   );
}

export function verifySessionlessProof(
   pubKey: string,
   userId: string,
   method: string,
   path: string,
   timestampMs: string,
   nonce: string,
   bodyHashHex: string,
   signature: string,
   queryString: string = '',
): void {
   checkKeyAndSignature(pubKey, signature);
   checkTimestamp(timestampMs);
   verifyProof(
      base64ToBytes(pubKey),
      buildUserCredMessage(userId, method, path, timestampMs, nonce, bodyHashHex, queryString),
      base64ToBytes(signature),
      USERCRED_SESSIONLESS_SIG_CONTEXT,
   );
}

export function recoverySecret(recoveryId: Uint8Array, userId: string): Uint8Array<ArrayBuffer> {
   if (recoveryId.every((b) => b === 0)) {
      throw new Error('Invalid recoveryId: all zero bytes');
   }
   return concatArrays([recoveryId, base64ToBytes(userId)]);
}

function buildRecoveryMessage(userId: string, timestampMs: string, nonce: string): Uint8Array<ArrayBuffer> {
   base64ToBytes(userId, cc.USERID_BYTES, 'userId');
   base64ToBytes(nonce, CHALLENGE_BYTES, 'nonce');
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
): void {
   checkKeyAndSignature(pubKey, signature);
   checkTimestamp(timestampMs);
   const keyBytes = base64ToBytes(pubKey);
   const message = buildRecoveryMessage(userId, timestampMs, nonce);
   const signatureBytes = base64ToBytes(signature);

   try {
      verifyProof(keyBytes, message, signatureBytes, RECOVERY_SIG_CONTEXTS[op]);
   } catch {
      // BACKWARD COMPAT: delete this catch, leaving only the call above
      verifyProof(keyBytes, message, signatureBytes, RECOVERY_COMPAT_SIG_CONTEXT);
   }
}

// Signed message includes userCredPubKey so each of the two keys a registration stores is covered
// by a proof from the other. The single-use registration challenge serves as the nonce.
function buildRecoveryRegisterMessage(
   userId: string,
   challenge: string,
   userCredPubKey: string,
): Uint8Array<ArrayBuffer> {
   base64ToBytes(userId, cc.USERID_BYTES, 'userId');
   base64ToBytes(challenge, CHALLENGE_BYTES, 'challenge');
   base64ToBytes(userCredPubKey, PROOF_PUBKEY_BYTES, 'userCredPubKey');
   const message = [userId, challenge, userCredPubKey].join('\n');
   return new TextEncoder().encode(message);
}

export function createRecoveryRegisterProof(
   recoverySecret: Uint8Array,
   userId: string,
   challenge: string,
   userCredPubKey: string,
): string {
   const { secKey } = getProofKeyPair(recoverySecret, RECOVERY_KEY_CONTEXT);
   try {
      const message = buildRecoveryRegisterMessage(userId, challenge, userCredPubKey);
      return bytesToBase64(createProof(secKey, message, RECOVERY_REGISTER_SIG_CONTEXT));
   } finally {
      secKey.fill(0);
   }
}

export function verifyRecoveryRegisterProof(
   pubKey: string,
   userId: string,
   challenge: string,
   userCredPubKey: string,
   signature: string,
): void {
   checkKeyAndSignature(pubKey, signature);
   verifyProof(
      base64ToBytes(pubKey),
      buildRecoveryRegisterMessage(userId, challenge, userCredPubKey),
      base64ToBytes(signature),
      RECOVERY_REGISTER_SIG_CONTEXT,
   );
}
