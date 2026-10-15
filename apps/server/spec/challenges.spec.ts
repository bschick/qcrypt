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
let condition = '';
const op = {
   eq: (name: string, value: unknown) => `${name}=${value}`,
   notExists: (name: string) => `notExists(${name})`,
};
vi.mock('../src/models', () => ({
   Challenges: {
      delete: () => ({
         where: (build: (attr: Record<string, string>, ops: typeof op) => string) => {
            condition = build({ userId: 'userId', binding: 'binding' }, op);
            return { go };
         },
      }),
      create: (item: unknown) => ({ go: () => created(item) }),
   },
}));

import { consumeChallenge, storeChallenge, ParamError, AuthError, type Challenge } from '../src/utils';
import { UNKNOWN_USER_ID, CHALLENGE_TTL_SECS } from '../src/consts';

const VALID_B64_CHALLENGE = 'aGVsbG8td29ybGQ'; // base64url
const activeExpiresAt = Math.floor(Date.now() / 1000) + CHALLENGE_TTL_SECS;

describe('consumeChallenge', () => {
   beforeEach(() => go.mockReset());

   it('rejects an invalid base64 challenge without a delete', async () => {
      await expect(consumeChallenge({ challenge: 'has space!', purpose: 'auth', userId: 'user1' })).rejects.toThrow(
         ParamError,
      );
      await expect(consumeChallenge({ challenge: '', purpose: 'auth', userId: 'user1' })).rejects.toThrow(ParamError);
      expect(go).not.toHaveBeenCalled();
   });

   it('rejects a missing userId without a delete', async () => {
      await expect(
         consumeChallenge({ challenge: VALID_B64_CHALLENGE, purpose: 'auth', userId: undefined as unknown as string }),
      ).rejects.toThrow(ParamError);
      expect(go).not.toHaveBeenCalled();
   });

   it('rejects when the delete is rejected', async () => {
      go.mockResolvedValueOnce({ rejected: true });
      await expect(
         consumeChallenge({ challenge: VALID_B64_CHALLENGE, purpose: 'auth', userId: 'user1' }),
      ).rejects.toThrow(ParamError);
   });

   it('rejects an expired challenge', async () => {
      go.mockResolvedValueOnce({
         rejected: false,
         data: {
            challenge: VALID_B64_CHALLENGE,
            purpose: 'auth',
            userId: 'user1',
            expiresAt: Math.floor(Date.now() / 1000) - 10,
         },
      });
      await expect(
         consumeChallenge({ challenge: VALID_B64_CHALLENGE, purpose: 'auth', userId: 'user1' }),
      ).rejects.toThrow(AuthError);
   });

   it('returns the consumed challenge', async () => {
      const item = {
         challenge: VALID_B64_CHALLENGE,
         purpose: 'auth' as const,
         userId: 'user1',
         expiresAt: activeExpiresAt,
      };
      go.mockResolvedValueOnce({ rejected: false, data: item });
      expect(await consumeChallenge({ challenge: VALID_B64_CHALLENGE, purpose: 'auth', userId: 'user1' })).toEqual(
         item,
      );
   });

   describe('delete condition', () => {
      const cases: [string, Challenge, string][] = [
         [
            'auth matches the caller or UNKNOWN_USER_ID, and no binding',
            { challenge: VALID_B64_CHALLENGE, purpose: 'auth', userId: 'user1' },
            `(userId=user1 OR userId=${UNKNOWN_USER_ID}) AND notExists(binding)`,
         ],
         [
            'reg without a binding matches only the caller and no binding',
            { challenge: VALID_B64_CHALLENGE, purpose: 'reg', userId: 'user1' },
            'userId=user1 AND notExists(binding)',
         ],
         [
            'reg with a binding matches only the caller and that binding',
            { challenge: VALID_B64_CHALLENGE, purpose: 'reg', userId: 'user1', binding: 'bind123' },
            'userId=user1 AND binding=bind123',
         ],
         [
            'recover matches only the caller and its binding',
            { challenge: VALID_B64_CHALLENGE, purpose: 'recover', userId: 'user1', binding: 'bind123' },
            'userId=user1 AND binding=bind123',
         ],
      ];

      it.each(cases)('%s', async (_name, check, expected) => {
         go.mockResolvedValueOnce({ rejected: false, data: { ...check, expiresAt: activeExpiresAt } });
         await consumeChallenge(check);
         expect(condition).toBe(expected);
      });
   });
});

describe('storeChallenge', () => {
   beforeEach(() => created.mockReset());

   it('stores an auth challenge for UNKNOWN_USER_ID', async () => {
      await storeChallenge({ challenge: VALID_B64_CHALLENGE, purpose: 'auth', userId: UNKNOWN_USER_ID });
      expect(created).toHaveBeenCalledWith({
         challenge: VALID_B64_CHALLENGE,
         purpose: 'auth',
         userId: UNKNOWN_USER_ID,
      });
   });

   it('rejects UNKNOWN_USER_ID for a purpose other than auth', async () => {
      await storeChallenge({ challenge: VALID_B64_CHALLENGE, purpose: 'reg', userId: 'user1' });
      expect(created).toHaveBeenCalledTimes(1);

      await expect(
         storeChallenge({ challenge: VALID_B64_CHALLENGE, purpose: 'reg', userId: UNKNOWN_USER_ID }),
      ).rejects.toThrow();
      expect(created).toHaveBeenCalledTimes(1);
   });

   it('stores a confirm challenge with its binding', async () => {
      await storeChallenge({ challenge: VALID_B64_CHALLENGE, purpose: 'confirm', userId: 'user1', binding: 'bind123' });
      expect(created).toHaveBeenCalledWith({
         challenge: VALID_B64_CHALLENGE,
         purpose: 'confirm',
         userId: 'user1',
         binding: 'bind123',
      });
   });
});
