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

import { describe, it, afterEach, expect } from 'vitest';
import { bytesToBase64, getRandom } from '@qcrypt/crypto';
import * as cc from '@qcrypt/crypto/consts';
import { coreSuite } from './core.suite';
import { recoverySuite } from './recovery.suite';
import {
   registerTestUser,
   registerNewCredential,
   getJson,
   postJson,
   expectPasskeyDeleted,
   setSessionUserCred,
} from './common';

// The full authorized-API and recovery contract against a server-side (no-PRF) userCred account.
coreSuite(false);
recoverySuite(false);

// The mirror of the PRF all-or-nothing invariant: a no-PRF account rejects a per-passkey ciphertext.
describe('no-PRF account', () => {
   let cleanup: (() => Promise<void>) | undefined;

   afterEach(async () => {
      if (cleanup) {
         await cleanup();
         cleanup = undefined;
      }
   });

   it('rejects a passkey added with an encrypted userCred', async () => {
      const account = await registerTestUser(`PWTesty_gn_${Date.now()}`, false);
      const auth = { 'x-csrf-token': account.csrf };
      setSessionUserCred(account.userCred, account.userId);
      cleanup = async () => {
         setSessionUserCred(account.userCred, account.userId);
         await expectPasskeyDeleted(account.credId, account.csrf, account.cookie);
         setSessionUserCred(undefined);
      };

      // A valid add (no ciphertext) succeeds...
      const opts = await getJson('/v1/passkeys/options', auth, account.cookie);
      expect(opts.status).toBe(200);
      const add = await registerNewCredential(account, opts.data);
      const ok = await postJson(
         '/v1/passkeys/verify',
         { ...add.attestation, challenge: opts.data.challenge },
         auth,
         account.cookie,
      );
      expect(ok.status).toBe(200);
      await expectPasskeyDeleted(add.attestation.id, account.csrf, account.cookie);

      // ...but the same add carrying a passkeyUserCredEnc ciphertext is rejected.
      const opts2 = await getJson('/v1/passkeys/options', auth, account.cookie);
      const add2 = await registerNewCredential(account, opts2.data);
      const bad = await postJson(
         '/v1/passkeys/verify',
         {
            ...add2.attestation,
            challenge: opts2.data.challenge,
            passkeyUserCredEnc: bytesToBase64(getRandom(cc.USERCRED_BYTES)),
         },
         auth,
         account.cookie,
      );
      expect(bad.status).toBe(400);
   });
});
