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
import {
   zxcvbnReady,
   getZxcvbn,
   checkPwned,
   addMatcher,
   removeMatcher,
} from './zxcvbn';

describe('zxcvbn lazy loader', function () {
   // The module caches its loaded state, so the "throws before ready" assertion
   // must run before any other test triggers zxcvbnReady().

   it('getZxcvbn throws before zxcvbnReady is awaited', function () {
      expect(() => getZxcvbn()).toThrow(/not awaited/);
   });

   it('zxcvbnReady resolves with a bundle exposing zxcvbnAsync and zxcvbnOptions', async function () {
      const bundle = await zxcvbnReady();
      expect(typeof bundle.zxcvbnAsync).toBe('function');
      expect(bundle.zxcvbnOptions).toBeDefined();
      expect(bundle.zxcvbnOptions.matchers).toBeDefined();
   });

   it('getZxcvbn returns the cached bundle once ready', async function () {
      await zxcvbnReady();
      const a = getZxcvbn();
      const b = getZxcvbn();
      expect(a).toBe(b);
      expect(a).toBe(await zxcvbnReady());
   });

   it('repeated zxcvbnReady calls share a single promise', function () {
      expect(zxcvbnReady()).toBe(zxcvbnReady());
   });

   it('addMatcher / removeMatcher manipulate the matchers map', async function () {
      const { zxcvbnOptions } = await zxcvbnReady();
      const dummy: Matcher = {
         Matching: class {
            match() { return []; }
         },
         feedback: () => null,
         scoring: () => 0,
      };
      await addMatcher('zxcvbn_spec_test', dummy);
      expect(zxcvbnOptions.matchers['zxcvbn_spec_test']).toBe(dummy);

      await removeMatcher('zxcvbn_spec_test');
      expect(zxcvbnOptions.matchers['zxcvbn_spec_test']).toBeUndefined();
   });

   it('checkPwned toggles the pwned matcher', async function () {
      const { zxcvbnOptions } = await zxcvbnReady();

      await checkPwned(true);
      expect(zxcvbnOptions.matchers['pwned']).toBeDefined();

      await checkPwned(false);
      expect(zxcvbnOptions.matchers['pwned']).toBeUndefined();
   });

   it('zxcvbnAsync scores a sample password', async function () {
      const { zxcvbnAsync } = await zxcvbnReady();
      // Don't include pwned matcher — that hits the network.
      await checkPwned(false);

      const result = await zxcvbnAsync('correcthorsebatterystaple');
      expect(result.score).toBeGreaterThanOrEqual(0);
      expect(result.score).toBeLessThanOrEqual(4);
   });

   it('scores representative passwords with the expected score', async function () {
      const { zxcvbnAsync } = await zxcvbnReady();
      // Skip pwned to keep the test offline and deterministic.
      await checkPwned(false);

      const cases: Array<{ pwd: string; score: number }> = [
         { pwd: 'password',                  score: 0 },
         { pwd: '12345678',                  score: 0 },
         { pwd: 'qwerty',                    score: 0 },
         { pwd: 'iloveyou',                  score: 0 },
         { pwd: 'Password1!',                score: 0 },
         { pwd: 'Tr0ub4dor&3',               score: 1 },
         { pwd: 'jK4#mLp9',                  score: 2 },
         { pwd: 'Bicycle$Maple',             score: 3 },
         { pwd: 'correcthorsebatterystaple', score: 4 },
         { pwd: 'c#7vP!9eK@2nQ$5xR',         score: 4 },
      ];

      for (const { pwd, score } of cases) {
         const result = await zxcvbnAsync(pwd);
         if (result.score !== score) {
            throw new Error(`"${pwd}" scored ${result.score}, expected ${score}`);
         }
      }
   });
});
