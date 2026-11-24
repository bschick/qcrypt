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

import { describe, it, beforeAll, afterAll, expect } from 'vitest';
import * as api from '@qcrypt/api';
import {
   RP_ORIGIN,
   postJson,
   registerTestUser,
   loginWithPasskey,
   expectPasskeyDeleted,
   setSessionSigner,
   type TestUser,
} from './common';

// The frontend's host on a port where no frontend is served
const OTHER_PORT_ORIGIN = `https://${new URL(RP_ORIGIN).hostname}:8443`;

describe('request origin', () => {
   let user: TestUser | undefined;

   beforeAll(async () => {
      user = await registerTestUser();
   });

   afterAll(async () => {
      if (user) {
         setSessionSigner(user.userId, user.userCred);
         const session = await loginWithPasskey(user);
         await expectPasskeyDeleted(user.credId, session.csrf, session.cookie);
         setSessionSigner(undefined);
      }
   });

   it('rejects auth/options from another port of the frontend host', async () => {
      const body = { userId: user!.userId };
      const ok = await postJson('/v1/auth/options', body, {}, '');
      expect(ok.status).toBe(200);

      const res = await postJson('/v1/auth/options', body, { Origin: OTHER_PORT_ORIGIN }, '');
      expect(res.status).toBe(400);
   });

   it('rejects a sign-in made on another port of the frontend host', async () => {
      const account = user!;
      await loginWithPasskey(account);

      const opts = await postJson('/v1/auth/options', { userId: account.userId }, {}, '');
      expect(opts.status).toBe(200);

      const assertion = account.emulator.getJSON(OTHER_PORT_ORIGIN, { ...opts.data });
      const res = await postJson(
         '/v1/auth/verify',
         api.makeAuthVerifyRequest(assertion as api.AuthenticationFields, { challenge: opts.data.challenge }),
         { Origin: OTHER_PORT_ORIGIN },
         '',
      );
      expect(res.status).toBe(400);
   });
});
