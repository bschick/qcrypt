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

import { describe, it, expect, vi, beforeEach } from 'vitest';

const go = vi.fn();
const created = vi.fn();
vi.mock('../src/models', () => ({
   Challenges: { delete: () => ({ go }), create: (item: unknown) => ({ go: () => created(item) }) },
}));

import { consumeChallenge, createChallenge, ParamError, AuthError, type ChallengeSpec } from '../src/utils';
import { UNKNOWN_USER_ID, CHALLENGE_TTL_SECS } from '../src/consts';

const VALID_B64_CHALLENGE = 'aGVsbG8td29ybGQ'; // base64url

describe('consumeChallenge', () => {
   beforeEach(() => go.mockReset());

   it('rejects an invalid base64 challenge', async () => {
      await expect(consumeChallenge('has space!', { purpose: 'auth', userId: 'user1' })).rejects.toThrow(ParamError);
      await expect(consumeChallenge('', { purpose: 'auth', userId: 'user1' })).rejects.toThrow(ParamError);
   });

   it('rejects when challenge is not found in table', async () => {
      go.mockResolvedValueOnce({ data: null });
      await expect(consumeChallenge(VALID_B64_CHALLENGE, { purpose: 'auth', userId: 'user1' })).rejects.toThrow(
         ParamError,
      );
   });

   it('rejects an expired challenge', async () => {
      go.mockResolvedValueOnce({
         data: {
            challenge: VALID_B64_CHALLENGE,
            purpose: 'auth',
            userId: 'user1',
            expiresAt: Math.floor(Date.now() / 1000) - 10,
         },
      });
      await expect(consumeChallenge(VALID_B64_CHALLENGE, { purpose: 'auth', userId: 'user1' })).rejects.toThrow(
         AuthError,
      );
   });

   describe('userId checks', () => {
      const activeExpiresAt = Math.floor(Date.now() / 1000) + CHALLENGE_TTL_SECS;

      it('accepts matching userId on a user-bound challenge', async () => {
         const item = {
            challenge: VALID_B64_CHALLENGE,
            purpose: 'auth' as const,
            userId: 'user1',
            expiresAt: activeExpiresAt,
         };
         go.mockResolvedValueOnce({ data: item });
         const result = await consumeChallenge(VALID_B64_CHALLENGE, { purpose: 'auth', userId: 'user1' });
         expect(result).toEqual(item);
      });

      it('rejects when challenge is bound to a userId but caller provides a different userId', async () => {
         go.mockResolvedValueOnce({
            data: {
               challenge: VALID_B64_CHALLENGE,
               purpose: 'auth',
               userId: 'user1',
               expiresAt: activeExpiresAt,
            },
         });
         await expect(consumeChallenge(VALID_B64_CHALLENGE, { purpose: 'auth', userId: 'user2' })).rejects.toThrow(
            AuthError,
         );
      });

      it('rejects when challenge is bound to a userId but caller provides undefined', async () => {
         go.mockResolvedValueOnce({
            data: {
               challenge: VALID_B64_CHALLENGE,
               purpose: 'auth',
               userId: 'user1',
               expiresAt: activeExpiresAt,
            },
         });
         await expect(
            consumeChallenge(VALID_B64_CHALLENGE, { purpose: 'auth', userId: undefined as unknown as string }),
         ).rejects.toThrow(AuthError);
      });

      it('accepts when challenge is unbound (UNKNOWN_USER_ID) and caller provides any userId', async () => {
         const item = {
            challenge: VALID_B64_CHALLENGE,
            purpose: 'auth' as const,
            userId: UNKNOWN_USER_ID,
            expiresAt: activeExpiresAt,
         };
         go.mockResolvedValueOnce({ data: item });
         const result = await consumeChallenge(VALID_B64_CHALLENGE, { purpose: 'auth', userId: 'anyUser' });
         expect(result).toEqual(item);
      });

      it('rejects an UNKNOWN_USER_ID challenge for a purpose other than auth', async () => {
         go.mockResolvedValueOnce({
            data: {
               challenge: VALID_B64_CHALLENGE,
               purpose: 'reg',
               userId: UNKNOWN_USER_ID,
               expiresAt: activeExpiresAt,
            },
         });
         await expect(consumeChallenge(VALID_B64_CHALLENGE, { purpose: 'reg', userId: 'user1' })).rejects.toThrow(
            AuthError,
         );
      });
   });

   describe('binding checks', () => {
      const activeExpiresAt = Math.floor(Date.now() / 1000) + CHALLENGE_TTL_SECS;

      it('accepts matching binding', async () => {
         const item = {
            challenge: VALID_B64_CHALLENGE,
            purpose: 'recover' as const,
            userId: 'user1',
            binding: 'bind123',
            expiresAt: activeExpiresAt,
         };
         go.mockResolvedValueOnce({ data: item });
         const result = await consumeChallenge(VALID_B64_CHALLENGE, {
            purpose: 'recover',
            userId: 'user1',
            binding: 'bind123',
         });
         expect(result).toEqual(item);
      });

      it('accepts when neither challenge nor caller has a binding', async () => {
         const item = {
            challenge: VALID_B64_CHALLENGE,
            purpose: 'reg' as const,
            userId: 'user1',
            expiresAt: activeExpiresAt,
         };
         go.mockResolvedValueOnce({ data: item });
         const result = await consumeChallenge(VALID_B64_CHALLENGE, { purpose: 'reg', userId: 'user1' });
         expect(result).toEqual(item);
      });

      it('rejects when challenge has a binding but caller provides no binding', async () => {
         go.mockResolvedValueOnce({
            data: {
               challenge: VALID_B64_CHALLENGE,
               purpose: 'recover',
               userId: 'user1',
               binding: 'bind123',
               expiresAt: activeExpiresAt,
            },
         });
         await expect(
            consumeChallenge(VALID_B64_CHALLENGE, { purpose: 'recover', userId: 'user1' } as unknown as ChallengeSpec),
         ).rejects.toThrow(AuthError);
      });

      it('rejects when challenge has no binding but caller provides a binding', async () => {
         go.mockResolvedValueOnce({
            data: {
               challenge: VALID_B64_CHALLENGE,
               purpose: 'reg',
               userId: 'user1',
               expiresAt: activeExpiresAt,
            },
         });
         await expect(
            consumeChallenge(VALID_B64_CHALLENGE, {
               purpose: 'reg',
               userId: 'user1',
               binding: 'bind123',
            } as unknown as ChallengeSpec),
         ).rejects.toThrow(AuthError);
      });

      it('rejects when challenge has a binding but caller provides a different binding', async () => {
         go.mockResolvedValueOnce({
            data: {
               challenge: VALID_B64_CHALLENGE,
               purpose: 'recover',
               userId: 'user1',
               binding: 'bind123',
               expiresAt: activeExpiresAt,
            },
         });
         await expect(
            consumeChallenge(VALID_B64_CHALLENGE, { purpose: 'recover', userId: 'user1', binding: 'bindWrong' }),
         ).rejects.toThrow(AuthError);
      });
   });
});

describe('createChallenge', () => {
   beforeEach(() => created.mockReset());

   it('creates an auth challenge for UNKNOWN_USER_ID', async () => {
      await createChallenge(VALID_B64_CHALLENGE, { purpose: 'auth', userId: UNKNOWN_USER_ID });
      expect(created).toHaveBeenCalledWith({
         challenge: VALID_B64_CHALLENGE,
         purpose: 'auth',
         userId: UNKNOWN_USER_ID,
      });
   });

   it('rejects UNKNOWN_USER_ID for a purpose other than auth', async () => {
      await createChallenge(VALID_B64_CHALLENGE, { purpose: 'reg', userId: 'user1' });
      expect(created).toHaveBeenCalledTimes(1);

      await expect(createChallenge(VALID_B64_CHALLENGE, { purpose: 'reg', userId: UNKNOWN_USER_ID })).rejects.toThrow();
      expect(created).toHaveBeenCalledTimes(1);
   });

   it('creates a confirm challenge with its binding', async () => {
      await createChallenge(VALID_B64_CHALLENGE, { purpose: 'confirm', userId: 'user1', binding: 'bind123' });
      expect(created).toHaveBeenCalledWith({
         challenge: VALID_B64_CHALLENGE,
         purpose: 'confirm',
         userId: 'user1',
         binding: 'bind123',
      });
   });
});
