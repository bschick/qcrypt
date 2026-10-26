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
   addPasskey,
   expectPasskeyDeleted,
   getJson,
   postJson,
   postPasskeyVerify,
   registerNewCredential,
   registerTestUser,
   setSessionSigner,
   type TestUser,
} from './common';

// Tests can run in any order, so each must leave the account one passkey below the limit
describe('passkey limit', () => {
   let user: TestUser | undefined;
   const credIds: string[] = [];

   async function removePasskey(account: TestUser, credId: string): Promise<void> {
      await expectPasskeyDeleted(credId, account.csrf, account.cookie);
      credIds.splice(credIds.indexOf(credId), 1);
   }

   beforeAll(async () => {
      user = await registerTestUser(true, 'limit');
      credIds.push(user.credId);
      while (credIds.length < api.MAX_PASSKEYS - 1) {
         credIds.push(await addPasskey(user, user.csrf, user.cookie));
      }
   });

   afterAll(async () => {
      if (user) {
         // The registration passkey goes last because deleting the final passkey deletes the account
         setSessionSigner(user.userId, user.userCred);
         for (const credId of [...credIds].reverse()) {
            await expectPasskeyDeleted(credId, user.csrf, user.cookie);
         }
         setSessionSigner(undefined);
      }
   });

   it('refuses passkey/verify past the count limit', async () => {
      const account = user!;
      const auth = { 'x-csrf-token': account.csrf };
      setSessionSigner(account.userId, account.userCred);

      const firstOpts = await getJson('/v1/passkeys/options', auth, account.cookie);
      const secondOpts = await getJson('/v1/passkeys/options', auth, account.cookie);
      expect(firstOpts.status).toBe(200);
      expect(secondOpts.status).toBe(200);

      const firstAdd = await registerNewCredential(account, firstOpts.data);
      const firstRes = await postPasskeyVerify(
         account,
         api.makeAddVerifyRequest(firstAdd.attestation as api.RegistrationFields, {
            challenge: firstOpts.data.challenge,
            passkeyUserCredEnc: firstAdd.passkeyUserCredEnc,
         }),
         account.csrf,
         account.cookie,
      );
      expect(firstRes.status).toBe(200);
      credIds.push(firstAdd.attestation.id);

      const secondAdd = await registerNewCredential(account, secondOpts.data);
      const secondRes = await postPasskeyVerify(
         account,
         api.makeAddVerifyRequest(secondAdd.attestation as api.RegistrationFields, {
            challenge: secondOpts.data.challenge,
            passkeyUserCredEnc: secondAdd.passkeyUserCredEnc,
         }),
         account.csrf,
         account.cookie,
      );
      expect(secondRes.status).toBe(400);

      await removePasskey(account, firstAdd.attestation.id);
   });

   it('refuses passkey/options past the count limit', async () => {
      const account = user!;
      const auth = { 'x-csrf-token': account.csrf };
      setSessionSigner(account.userId, account.userCred);

      const belowLimit = await getJson('/v1/passkeys/options', auth, account.cookie);
      expect(belowLimit.status).toBe(200);

      const addedId = await addPasskey(account, account.csrf, account.cookie);
      credIds.push(addedId);
      const atLimit = await getJson('/v1/passkeys/options', auth, account.cookie);
      expect(atLimit.status).toBe(400);

      await removePasskey(account, addedId);
   });

   it('returns passkeys in credential id order', async () => {
      const res = await postJson('/v1/auth/options', { userId: user!.userId }, {}, '');
      expect(res.status).toBe(200);
      const ids = res.data.allowCredentials.map((cred: { id: string }) => cred.id);
      expect(ids.length).toBe(api.MAX_PASSKEYS - 1);
      expect(ids).toEqual([...ids].sort());
   });
});
