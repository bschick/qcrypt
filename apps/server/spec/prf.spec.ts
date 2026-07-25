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
   buildPrfRegBody,
   getJson,
   postJson,
   expectPasskeyDeleted,
   setSessionUserCred,
   prfDecrypt,
   readPrfOutput,
   PRF_EXTENSION,
   RP_ORIGIN,
} from './common';

// The full authorized-API and recovery contract against a client-side (PRF) userCred account.
coreSuite(true);
recoverySuite(true);

// Behaviors with no no-PRF analog: the server stores only opaque ciphertexts and never returns
// plaintext userCred, and the account rejects a passkey added without its ciphertext.
describe('PRF account', () => {
   let cleanup: (() => Promise<void>) | undefined;

   afterEach(async () => {
      if (cleanup) {
         await cleanup();
         cleanup = undefined;
      }
   });

   it('logs in and decrypts the per-passkey ciphertext back to userCred', async () => {
      const account = await registerTestUser(`PWTesty_prf_${Date.now()}`, true);
      cleanup = async () => {
         setSessionUserCred(account.userCred, account.userId);
         await expectPasskeyDeleted(account.credId, account.csrf, account.cookie);
         setSessionUserCred(undefined);
      };

      const optsRes = await postJson('/v1/auth/options', { userId: account.userId }, {}, '');
      expect(optsRes.status).toBe(200);

      const assertion = account.emulator.getJSON(RP_ORIGIN, {
         ...optsRes.data,
         challenge: optsRes.data.challenge,
         extensions: PRF_EXTENSION,
      });

      const verifyRes = await postJson(
         '/v1/auth/verify?usercred=true',
         { ...assertion, challenge: optsRes.data.challenge },
         {},
         '',
      );
      expect(verifyRes.status).toBe(200);
      // The login supersedes the registration session, so clean up with the login session.
      cleanup = async () => {
         setSessionUserCred(account.userCred, account.userId);
         await expectPasskeyDeleted(account.credId, verifyRes.data.csrf, verifyRes.cookie);
         setSessionUserCred(undefined);
      };
      expect(verifyRes.data.verified).toBe(true);
      expect(verifyRes.data.prf).toBe(true);
      expect(verifyRes.data.userCred).toBeUndefined();
      expect(verifyRes.data.passkeyUserCredEnc).toBeDefined();

      // The login assertion reproduces the registration PRF output, so it decrypts the
      // server-stored per-passkey ciphertext back to the userCred the client generated.
      const prfOutput = readPrfOutput(assertion.clientExtensionResults);
      expect(prfOutput).not.toBeNull();
      const decrypted = await prfDecrypt(verifyRes.data.passkeyUserCredEnc, prfOutput!, account.userId);
      expect(bytesToBase64(decrypted)).toBe(account.userCred);
   });

   it('rejects a passkey added without an encrypted userCred', async () => {
      const account = await registerTestUser(`PWTesty_gp_${Date.now()}`, true);
      const auth = { 'x-csrf-token': account.csrf };
      setSessionUserCred(account.userCred, account.userId);
      cleanup = async () => {
         setSessionUserCred(account.userCred, account.userId);
         await expectPasskeyDeleted(account.credId, account.csrf, account.cookie);
         setSessionUserCred(undefined);
      };

      // A valid add (carrying the passkeyUserCredEnc ciphertext) succeeds...
      const opts = await getJson('/v1/passkeys/options', auth, account.cookie);
      expect(opts.status).toBe(200);
      const add = await registerNewCredential(account, opts.data);
      const ok = await postJson(
         '/v1/passkeys/verify',
         { ...add.attestation, challenge: opts.data.challenge, passkeyUserCredEnc: add.passkeyUserCredEnc },
         auth,
         account.cookie,
      );
      expect(ok.status).toBe(200);
      await expectPasskeyDeleted(add.attestation.id, account.csrf, account.cookie);

      // ...but the same add with the passkeyUserCredEnc ciphertext omitted is rejected.
      const opts2 = await getJson('/v1/passkeys/options', auth, account.cookie);
      const add2 = await registerNewCredential(account, opts2.data);
      const bad = await postJson(
         '/v1/passkeys/verify',
         { ...add2.attestation, challenge: opts2.data.challenge },
         auth,
         account.cookie,
      );
      expect(bad.status).toBe(400);
   });
});

// reg/verify rejects malformed PRF credential fields. Each test builds a valid PRF body (its
// reg/options is the opening 200) and tampers a single field, so the rejection is that field alone.
describe('PRF registration input validation', () => {
   const minEncBytes = cc.USERCRED_BYTES + cc.PAYLOAD_SIZE_MIN + cc.HEADER_BYTES_6P;

   // reg/verify is unauthenticated, so enumeration-hardening reports every rejection as a uniform 401.
   async function rejectsRegBody(mutate: (body: Record<string, any>) => void): Promise<void> {
      const { userId, body, userCred } = await buildPrfRegBody(`PWTesty_bad_${Date.now()}`);
      const tampered = { ...body };
      mutate(tampered);
      const bad = await postJson('/v1/reg/verify?usercred=true', tampered, {}, '');
      expect(bad.status).toBe(401);

      // The field is rejected before the challenge is consumed, so the untampered body still
      // completes registration (proving the tamper was the only cause); delete it to leave no account.
      const ok = await postJson('/v1/reg/verify?usercred=true', body, {}, '');
      expect(ok.status).toBe(200);
      setSessionUserCred(bytesToBase64(userCred), userId);
      await expectPasskeyDeleted(ok.data.pkId, ok.data.csrf, ok.cookie);
      setSessionUserCred(undefined);
   }

   it('rejects an empty passkeyUserCredEnc', () =>
      rejectsRegBody((b) => {
         b.passkeyUserCredEnc = '';
      }));
   it('rejects an empty recoveryUserCredEnc', () =>
      rejectsRegBody((b) => {
         b.recoveryUserCredEnc = '';
      }));
   it('rejects a non-base64 passkeyUserCredEnc', () =>
      rejectsRegBody((b) => {
         b.passkeyUserCredEnc = 'not b64 $$$';
      }));
   it('rejects a too-short passkeyUserCredEnc', () =>
      rejectsRegBody((b) => {
         b.passkeyUserCredEnc = bytesToBase64(getRandom(minEncBytes - 1));
      }));
   it('rejects a too-short recoveryUserCredEnc', () =>
      rejectsRegBody((b) => {
         b.recoveryUserCredEnc = bytesToBase64(getRandom(minEncBytes - 1));
      }));
   it('rejects a wrong-length userCredPubKey', () =>
      rejectsRegBody((b) => {
         b.userCredPubKey = bytesToBase64(getRandom(cc.USERCRED_BYTES));
      }));
   it('rejects a non-base64 userCredPubKey', () =>
      rejectsRegBody((b) => {
         b.userCredPubKey = 'not b64 $$$';
      }));
});
