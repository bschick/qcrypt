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

import { zxcvbnReady, isPwned, createZxcvbn } from './zxcvbn';

describe('zxcvbn lazy loader', () => {
   it('zxcvbnReady resolves with a bundle exposing ZxcvbnFactory and options', async () => {
      const bundle = await zxcvbnReady();
      expect(typeof bundle.ZxcvbnFactory).toBe('function');
      expect(bundle.options).toBeDefined();
      expect(bundle.options.dictionary).toBeDefined();
   });

   it('repeated zxcvbnReady calls share a single promise', () => {
      expect(zxcvbnReady()).toBe(zxcvbnReady());
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

   it('the pwned matcher is never part of scoring', async () => {
      const zxcvbn = await createZxcvbn();
      const result = await zxcvbn.checkAsync('one2many');
      expect(result.sequence.some((match) => match.pattern === 'pwned')).toBe(false);
   });

   it('checkAsync scores a sample password', async () => {
      const zxcvbn = await createZxcvbn();
      const result = await zxcvbn.checkAsync('correcthorsebatterystaple');
      expect(result.score).toBeGreaterThanOrEqual(0);
      expect(result.score).toBeLessThanOrEqual(4);
   });

   it('scores representative passwords with the expected score', async () => {
      const zxcvbn = await createZxcvbn();
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
         const result = await zxcvbn.checkAsync(pwd);
         if (result.score !== score) {
            throw new Error(`"${pwd}" scored ${result.score}, expected ${score}`);
         }
      }
   });
});
