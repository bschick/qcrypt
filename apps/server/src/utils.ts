/* MIT License

Copyright (c) 2025 Brad Schick

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

import { FilterXSS } from 'xss';
import { Buffer } from 'node:buffer';
import * as crypto from 'node:crypto';
import * as api from '@qcrypt/api';
import { Challenges, type ChallengeItem, type UnverifiedUserItem, type VerifiedUserItem } from './models';
import type { HttpDetails } from './urls';
import { USERCRED_ENC_MIN_BYTES, USERCRED_ENC_MAX_BYTES, UNKNOWN_USER_ID } from './consts';

import { ParamError } from '@qcrypt/crypto';
export { ParamError };

export class AuthError extends Error {
   constructor(msg: string = 'not authorized') {
      super(msg);
   }
}

export class NotFoundError extends Error {}

const filter = new FilterXSS({
   whiteList: {},
   stripIgnoreTag: true,
   // remove rather than escape stuff < and > (slight modification of original from github)
   escapeHtml: (html: string) => {
      return html.replace(/</g, '').replace(/>/g, '');
   },
});

const sanitizeXSS = filter.process.bind(filter);

// Codepoints that direct processing or rendering rather than producing a visible glyph
const nonGlyphChars = /[\p{Cc}\p{Cf}\p{Default_Ignorable_Code_Point}\p{Noncharacter_Code_Point}]/gu;

export const sanitizeString = (input: string): string => {
   if (!input || typeof input !== 'string') {
      throw new ParamError('must be string value');
   }
   // Strip categories that steer processing or rendering without contributing a glyph
   const sanitized = sanitizeXSS(input).normalize('NFC').replace(nonGlyphChars, '');
   if (!sanitized) {
      throw new ParamError('empty string value');
   }
   return sanitized.trim();
};

export const validB64 = (base64: string | null | undefined): base64 is string => {
   return !!base64 && typeof base64 === 'string' && /^[A-Za-z0-9+/=_-]+$/.test(base64);
};

export function isReservedTestUserName(userName: string): boolean {
   return userName.toLowerCase().startsWith('pwtesty_');
}

export type Challenge = { challenge: string } & (
   | { purpose: 'auth'; userId: string; binding?: never }
   // BACKWARD COMPAT: the binding is optional only for clients that omit userCredPubKey
   | { purpose: 'reg'; userId: string; binding?: string }
   | { purpose: 'add' | 'recover' | 'confirm'; userId: string; binding: string }
);

// The challenge must match the given userId, unless it is an auth challenge created with UNKNOWN_USER_ID.
// The binding must also match; an omitted binding matches only a challenge created without one.
// A missing challenge and a mismatched one get the same error.
export async function consumeChallenge(check: Challenge): Promise<ChallengeItem> {
   if (!validB64(check.challenge) || !check.userId) {
      throw new ParamError('challenge not valid');
   }

   const consumed = await Challenges.delete({
      purpose: check.purpose,
      challenge: check.challenge,
   })
      .where((attr, op) => {
         const user =
            check.purpose === 'auth'
               ? `(${op.eq(attr.userId, check.userId)} OR ${op.eq(attr.userId, UNKNOWN_USER_ID)})`
               : op.eq(attr.userId, check.userId);
         const binding = check.binding === undefined ? op.notExists(attr.binding) : op.eq(attr.binding, check.binding);
         return `${user} AND ${binding}`;
      })
      .go({ response: 'all_old', returnOnConditionCheckFailure: true });

   if (consumed.rejected || !consumed.data) {
      throw new ParamError('challenge not valid');
   }
   if (Date.now() / 1000 > consumed.data.expiresAt) {
      throw new AuthError();
   }

   return consumed.data;
}

export async function storeChallenge(challenge: Challenge): Promise<void> {
   if (challenge.userId === UNKNOWN_USER_ID && challenge.purpose !== 'auth') {
      throw new Error(`${challenge.purpose} challenge cannot use UNKNOWN_USER_ID`);
   }

   await Challenges.create(challenge).go();
}

// Throws unless the proof is well formed, within the skew window, verifies, and its nonce has
// not been seen before. Retaining the nonce is what bounds replay to the skew window.
export async function verifyRecoveryNonceProof(
   recoveryPubKey: string,
   userId: string,
   proof: api.RecoverProof,
   op: api.RecoveryOp,
): Promise<void> {
   const { timestamp, nonce, signature } = proof;
   api.verifyRecoveryNonceProof(recoveryPubKey, userId, timestamp, nonce, signature, op);

   // Only needed for unauthenticated callers, but harmless for authenticated
   const outcome = await storeSingleUseNonce(nonce, 'nonce', userId);
   if (outcome === 'replayed') {
      throw new ParamError(`user account ${userId} replayed recovery proof`);
   }
   if (outcome === 'failed') {
      throw new ParamError(`user account ${userId} recovery proof nonce store failed`);
   }
}

function proofFields(header: string | undefined, count: number, label: string): string[] {
   const fields = header?.split(',').map((field) => field.trim());
   if (fields?.length !== count) {
      console.error(`proof header ${label} missing or malformed`);
      throw new AuthError();
   }
   return fields;
}

// proofHeader is "signature,timestamp,nonce"
export async function verifyUserCredNonceProof(
   verifiedUser: VerifiedUserItem,
   httpDetails: HttpDetails,
   proofHeader: string | undefined,
): Promise<void> {
   const label = `${httpDetails.name} ${verifiedUser.userId}`;
   const [signature, timestamp, nonce] = proofFields(proofHeader, 3, label);
   const bodyHashHex = crypto.createHash('sha256').update(httpDetails.rawBody, 'utf8').digest('hex');
   try {
      // A stale userCredPubKey after rotation surfaces here as a spurious 401.
      api.verifyUserCredNonceProof(
         verifiedUser.userCredPubKey!,
         verifiedUser.userId,
         httpDetails.method,
         httpDetails.path,
         timestamp,
         nonce,
         bodyHashHex,
         signature,
         httpDetails.rawQueryString,
      );
   } catch (err) {
      console.error(`nonce proof ${label}`, err);
      throw new AuthError();
   }

   // Replaying a GET has significantly less risk, so to reduce load enforce
   // single-use of the nonce only for state-changing requests
   // TODO: Consider moving this to AWS Elastic cache when usage increases
   if (httpDetails.method !== 'GET') {
      const outcome = await storeSingleUseNonce(nonce, 'api', verifiedUser.userId);
      if (outcome !== 'ok') {
         console.error(`nonce proof ${outcome} ${label}`);
         throw new AuthError();
      }
   }
}

// proofHeader is "signature,timestamp", and the proof signs the challenge in the request body.
// No single use nonce is stored, because the route consumes that challenge, which makes the proof
// single use.
export function verifyUserCredChallengeProof(
   user: UnverifiedUserItem,
   httpDetails: HttpDetails,
   proofHeader: string | undefined,
): void {
   const label = `${httpDetails.name} ${user.userId}`;
   const [signature, timestamp] = proofFields(proofHeader, 2, label);
   const { challenge } = httpDetails.body as api.ChallengeRiders;
   const bodyHashHex = crypto.createHash('sha256').update(httpDetails.rawBody, 'utf8').digest('hex');
   try {
      api.verifyUserCredChallengeProof(
         user.userCredPubKey!,
         user.userId,
         httpDetails.method,
         httpDetails.path,
         timestamp,
         challenge,
         bodyHashHex,
         signature,
         httpDetails.rawQueryString,
      );
   } catch (err) {
      console.error(`challenge proof ${label}`, err);
      throw new AuthError();
   }
}

// BACKWARD COMPAT: checks a recover/confirm proof carried in the body, signed with the nonce
// context. Delete once x-challenge-proof is required.
export function verifyRecoverConfirmProof(
   confirm: api.RecoverConfirmRequest,
   userCredPubKey: string,
   httpDetails: HttpDetails,
): void {
   const { userId, challenge, timestamp, signature } = confirm;
   // There is no body beyond the signature fields, so hash is for empty string
   const bodyHashHex = crypto.createHash('sha256').update('', 'utf8').digest('hex');
   api.verifyUserCredNonceProof(
      userCredPubKey,
      userId,
      httpDetails.method,
      httpDetails.path,
      timestamp!,
      challenge,
      bodyHashHex,
      signature!,
      httpDetails.rawQueryString,
   );
}

// Never throws: an error from the store itself is reported as 'failed'.
export async function storeSingleUseNonce(
   nonce: string,
   purpose: 'api' | 'nonce',
   userId: string,
): Promise<'ok' | 'replayed' | 'failed'> {
   try {
      const stored = await Challenges.create({ challenge: nonce, purpose, userId }).go({
         returnOnConditionCheckFailure: true,
      });
      return stored.rejected ? 'replayed' : 'ok';
   } catch (err) {
      console.error(`nonce store error for ${userId}`, err);
      return 'failed';
   }
}

export function validUserCredEnc(userCredEnc: string | null | undefined): userCredEnc is string {
   if (!validB64(userCredEnc)) {
      return false;
   }
   const encLen = base64UrlDecode(userCredEnc)!.length;
   return encLen >= USERCRED_ENC_MIN_BYTES && encLen <= USERCRED_ENC_MAX_BYTES;
}

export function base64UrlEncode(bytes: Uint8Array | undefined): string | undefined {
   return bytes ? Buffer.from(bytes).toString('base64url') : undefined;
}

export function base64UrlDecode(base64: string | undefined): Uint8Array<ArrayBuffer> | undefined {
   if (base64) {
      const nodeBuffer = Buffer.from(base64, 'base64url');
      return new Uint8Array(nodeBuffer.buffer, nodeBuffer.byteOffset, nodeBuffer.byteLength);
   }
   return undefined;
}

// Node implementation will handle either base64 or base6 4Url (for internal encoding and storage
// only use base64UrlEncode)
export function base64Decode(base64: string | undefined): Uint8Array<ArrayBuffer> | undefined {
   if (base64) {
      const nodeBuffer = Buffer.from(base64, 'base64');
      return new Uint8Array(nodeBuffer.buffer, nodeBuffer.byteOffset, nodeBuffer.byteLength);
   }
   return undefined;
}

// Constant-time comparison for known length arrays.
export function knownLenTimingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
   if (a.byteLength !== b.byteLength) {
      return false;
   }
   return crypto.timingSafeEqual(a, b);
}

/* Javascript converts to signed 32 bit int when using bit shifting
   and masking, so do this instead. Count is the number of bytes
   used to pack the number.  */
export function numToBytes(num: number, count: number): Uint8Array<ArrayBuffer> {
   if (count < 1 || num >= 256 ** count) {
      throw new Error(`Invalid arguments ${count} for ${num}`);
   }
   const arr = new Uint8Array(count);
   for (let i = 0; i < count; ++i) {
      arr[i] = num % 256;
      num = Math.floor(num / 256);
   }
   return arr;
}

export function bytesToNum(arr: Uint8Array): number {
   let num = 0;
   for (let i = arr.length - 1; i >= 0; --i) {
      num = num * 256 + arr[i];
   }
   return num;
}

export const ONE_PK_SHARE = 0.95;
export const NEXT_PK_SHARE = 0.09;

// Returns 1 for about ONE_PK_SHARE% of seeds
// Each count above 2 is about NEXT_PK_SHARE% as likely
export function dummyCredCount(seed: Uint8Array, maxCount: number): number {
   let count = 1;
   if (maxCount > 1 && seed[1] / 0x100 >= ONE_PK_SHARE) {
      count = 2;
      while (count < maxCount && seed[count] / 0x100 < NEXT_PK_SHARE) {
         count++;
      }
   }
   return count;
}
