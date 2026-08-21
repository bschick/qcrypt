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

import type { Matcher } from '@zxcvbn-ts/core/dist/types';
import { zxcvbnReady, getZxcvbn, isPwned, addMatcher, removeMatcher } from './zxcvbn';

describe('zxcvbn lazy loader', () => {
   // The module caches its loaded state, so the "throws before ready" assertion
   // must run before any other test triggers zxcvbnReady().

   it('getZxcvbn throws before zxcvbnReady is awaited', () => {
      expect(() => getZxcvbn()).toThrow(/not awaited/);
   });

   it('zxcvbnReady resolves with a bundle exposing zxcvbnAsync and zxcvbnOptions', async () => {
      const bundle = await zxcvbnReady();
      expect(typeof bundle.zxcvbnAsync).toBe('function');
      expect(bundle.zxcvbnOptions).toBeDefined();
      expect(bundle.zxcvbnOptions.matchers).toBeDefined();
   });

   it('getZxcvbn returns the cached bundle once ready', async () => {
      await zxcvbnReady();
      const a = getZxcvbn();
      const b = getZxcvbn();
      expect(a).toBe(b);
      expect(a).toBe(await zxcvbnReady());
   });

   it('repeated zxcvbnReady calls share a single promise', () => {
      expect(zxcvbnReady()).toBe(zxcvbnReady());
   });

   it('addMatcher / removeMatcher manipulate the matchers map', async () => {
      const { zxcvbnOptions } = await zxcvbnReady();
      const dummy: Matcher = {
         Matching: class {
            match() {
               return [];
            }
         },
         feedback: () => null,
         scoring: () => 0,
      };
      await addMatcher('zxcvbn_spec_test', dummy);
      expect(zxcvbnOptions.matchers['zxcvbn_spec_test']).toBe(dummy);

      await removeMatcher('zxcvbn_spec_test');
      expect(zxcvbnOptions.matchers['zxcvbn_spec_test']).toBeUndefined();
   });

   it('isPwned reports a listed password', async () => {
      expect(await isPwned('one2many')).toBe(true);
   });

   it('isPwned returns false for a password the service does not list', async () => {
      expect(await isPwned(`Xk7$pLm2#qRw9-${crypto.randomUUID()}`)).toBe(false);
   });

   it('isPwned returns false when the service cannot be reached', async () => {
      const originalFetch = globalThis.fetch;
      globalThis.fetch = (() => Promise.reject(new Error('offline'))) as unknown as typeof fetch;
      try {
         expect(await isPwned('Xk7$pLm2#qRw9')).toBe(false);
      } finally {
         globalThis.fetch = originalFetch;
      }
   });

   it('the pwned matcher is never registered for scoring', async () => {
      const { zxcvbnOptions } = await zxcvbnReady();
      expect(zxcvbnOptions.matchers['pwned']).toBeUndefined();
   });

   it('zxcvbnAsync scores a sample password', async () => {
      const { zxcvbnAsync } = await zxcvbnReady();
      const result = await zxcvbnAsync('correcthorsebatterystaple');
      expect(result.score).toBeGreaterThanOrEqual(0);
      expect(result.score).toBeLessThanOrEqual(4);
   });

   it('scores representative passwords with the expected score', async () => {
      const { zxcvbnAsync } = await zxcvbnReady();
      const cases: Array<{ pwd: string; score: number }> = [
         { pwd: 'password', score: 0 },
         { pwd: '12345678', score: 0 },
         { pwd: 'qwerty', score: 0 },
         { pwd: 'iloveyou', score: 0 },
         { pwd: 'Password1!', score: 0 },
         { pwd: 'Tr0ub4dor&3', score: 1 },
         { pwd: 'jK4#mLp9', score: 2 },
         { pwd: 'Bicycle$Maple', score: 3 },
         { pwd: 'correcthorsebatterystaple', score: 4 },
         { pwd: 'c#7vP!9eK@2nQ$5xR', score: 4 },
      ];

      for (const { pwd, score } of cases) {
         const result = await zxcvbnAsync(pwd);
         if (result.score !== score) {
            throw new Error(`"${pwd}" scored ${result.score}, expected ${score}`);
         }
      }
   });
});
