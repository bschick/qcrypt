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
import { verifyRecoveryProof, PROOF_SIG_BYTES, type RequestTypes } from '@qcrypt/api';
import { Challenges, type ChallengeItem } from './models';
import { USERCRED_ENC_MIN_BYTES, USERCRED_ENC_MAX_BYTES, CHALLENGE_BYTES, PROOF_SKEW_MS } from './consts';

export class ParamError extends Error {}

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

export const sanitizeString = (input: string): string => {
   if (!input || typeof input !== 'string') {
      throw new ParamError('must be string value');
   }
   const sanitized = sanitizeXSS(input);
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

// When userId is given the challenge must also be bound to it, otherwise any binding is accepted
export async function consumeChallenge(
   challenge: string,
   purpose: ChallengeItem['purpose'],
   userId?: string,
): Promise<ChallengeItem> {
   if (!validB64(challenge)) {
      throw new ParamError('challenge not valid');
   }

   const consumed = await Challenges.delete({
      purpose,
      challenge,
   }).go({ response: 'all_old' });

   if (!consumed?.data) {
      throw new ParamError('challenge not valid');
   }
   if (Date.now() / 1000 > consumed.data.expiresAt) {
      throw new AuthError();
   }
   if (userId !== undefined && consumed.data.userId !== userId) {
      throw new AuthError();
   }

   return consumed.data;
}

// Throws unless the proof is well formed, within the skew window, verifies, and its nonce has
// not been seen before. Retaining the nonce is what bounds replay to the skew window.
export async function verifyRecoverProof(
   recoveryPubKey: string,
   userId: string,
   proof: RequestTypes.RecoverProof,
): Promise<void> {
   const { timestamp, nonce, signature } = proof;
   if (!validB64(nonce) || !validB64(signature)) {
      throw new ParamError('invalid recovery proof');
   }

   const nonceBytes = base64UrlDecode(nonce)!;
   const signatureBytes = base64UrlDecode(signature)!;
   if (nonceBytes.byteLength !== CHALLENGE_BYTES || signatureBytes.byteLength !== PROOF_SIG_BYTES) {
      throw new ParamError('invalid recovery proof');
   }

   const timestampMs = Number(timestamp);
   if (!Number.isFinite(timestampMs) || Math.abs(Date.now() - timestampMs) > PROOF_SKEW_MS) {
      throw new ParamError('invalid recovery proof');
   }

   try {
      verifyRecoveryProof(recoveryPubKey, userId, timestamp, nonce, signature);
   } catch {
      throw new ParamError(`user account ${userId} invalid recovery proof`);
   }

   const stored = await Challenges.create({
      challenge: nonce,
      purpose: 'nonce',
      userId: userId,
   }).go({ returnOnConditionCheckFailure: true });

   if (stored.rejected) {
      throw new ParamError(`user account ${userId} replayed recovery proof`);
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
