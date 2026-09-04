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

// A store error cannot be provoked against real DynamoDB, so the store is stubbed
const go = vi.fn();
vi.mock('../src/models', () => ({ Challenges: { create: () => ({ go }) } }));

import { storeSingleUseNonce } from '../src/utils';

describe('single use nonce store', () => {
   beforeEach(() => go.mockReset());

   it('reports a first use, a replay, and a store failure', async () => {
      go.mockResolvedValueOnce({ rejected: false });
      await expect(storeSingleUseNonce('n1', 'api', 'u1')).resolves.toBe('ok');

      go.mockResolvedValueOnce({ rejected: true });
      await expect(storeSingleUseNonce('n1', 'api', 'u1')).resolves.toBe('replayed');

      // A store error must never read as a fresh nonce
      go.mockRejectedValueOnce(new Error('ddb unavailable'));
      await expect(storeSingleUseNonce('n2', 'api', 'u1')).resolves.toBe('failed');
   });
});
