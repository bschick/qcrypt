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
import { API_SERVER, RP_ORIGIN, sha256Hex } from './common';

// Stock Chrome UA — explicitly omits the QCTestClient marker so the server's
// PWTesty_ prefix guard treats this request as a real (non-test) client.
const REAL_CLIENT_UA =
   'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

async function postRegOptionsAsRealClient(userName: string) {
   const body = Buffer.from(JSON.stringify({ userName }), 'utf8');
   const res = await fetch(`${API_SERVER}/v1/reg/options`, {
      method: 'POST',
      headers: {
         'User-Agent': REAL_CLIENT_UA,
         'Origin': RP_ORIGIN,
         'Content-Type': 'application/json',
         'x-amz-content-sha256': sha256Hex(body),
      },
      body,
   });
   return { status: res.status, text: await res.text() };
}

describe('PWTesty_ prefix guard', () => {

   it('rejects PWTesty_ from a non-test client', async () => {
      const res = await postRegOptionsAsRealClient('PWTesty_');
      expect(res.status).toBe(400);
   });

   it('rejects pwtesty_ (lowercase) from a non-test client', async () => {
      const res = await postRegOptionsAsRealClient('pwtesty_');
      expect(res.status).toBe(400);
   });

   it('rejects PWTesty_<Date.now()> from a non-test client', async () => {
      const res = await postRegOptionsAsRealClient(`PWTesty_${Date.now()}`);
      expect(res.status).toBe(400);
   });

   // Sanity check that the rejections above are caused by the prefix guard,
   // not by the non-test UA being blocked outright. Leaks an unverified user
   // record; the server's unverified-user TTL will clean it up later.
   it('accepts a non-reserved username from a non-test client', async () => {
      const res = await postRegOptionsAsRealClient(`PWLeaky_${Date.now()}`);
      expect(res.status).toBe(200);
   });
});
