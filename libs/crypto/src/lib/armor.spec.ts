/* MIT License

Copyright (c) 2024 Brad Schick

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

import { makeCipherArmor, parseCipherArmor, bytesToBase64 } from '../index';
import { isEqualArray } from './test-helpers';

const CIPHER_DATA = new Uint8Array([1, 2, 3, 4, 250, 251, 252, 253]);
const CIPHER_B64 = bytesToBase64(CIPHER_DATA);

describe('parseCipherArmor', () => {
   it('round trips each armor format', () => {
      for (const format of ['compact', 'indent']) {
         const armor = makeCipherArmor(CIPHER_DATA, format);
         expect(isEqualArray(parseCipherArmor(armor), CIPHER_DATA)).toBe(true);
      }
   });

   it('accepts a link, a query fragment, and bare base64', () => {
      const link = makeCipherArmor(CIPHER_DATA, 'link', false, 'https://quickcrypt.org');
      for (const text of [link, `cipherarmor=${CIPHER_B64}`, CIPHER_B64]) {
         expect(isEqualArray(parseCipherArmor(text), CIPHER_DATA)).toBe(true);
      }
   });

   it('reports missing ct separately from malformed text', () => {
      expect(() => parseCipherArmor('{"notct":"abc"}')).toThrowError(/Missing ct/);
      expect(() => parseCipherArmor('{"ct":')).toThrowError(/not formatted correctly/);
      expect(() => parseCipherArmor('https://quickcrypt.org?other=1')).toThrowError(/not formatted correctly/);
   });
});
