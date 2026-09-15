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

import { describe, it, expect } from 'vitest';
import { postJson, testUserName } from './common';
import { ALGIDS } from '../src/consts';

const ML_DSA_65 = -49;

// TODO: register and authenticate with an ML-DSA credential once nid-webauthn-emulator can
// create one.
describe('registration options', () => {
   it('should offer the supported algorithms, most preferred first', async () => {
      const res = await postJson('/v1/reg/options', { userName: testUserName() }, {}, '');
      expect(res.status).toBe(200);

      const algs = res.data.pubKeyCredParams.map((param: { alg: number }) => param.alg);
      expect(algs).toEqual(ALGIDS);
      expect(algs[0]).toBe(ML_DSA_65);

      // COSE numbers every signature algorithm below zero, so a positive entry is an encryption
      // or MAC algorithm that no authenticator can answer with
      expect(algs.every((alg: number) => alg < 0)).toBe(true);

      for (const param of res.data.pubKeyCredParams) {
         expect(param.type).toBe('public-key');
      }
   });
});
