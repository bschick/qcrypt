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

import { describe, it, beforeAll, beforeEach, afterAll, expect } from 'vitest';
import { cryptoReady, bytesToBase64, base64ToBytes, getRandom } from '@qcrypt/crypto';
import * as cc from '@qcrypt/crypto/consts';
import {
   getRecoveryPubKey,
   createRecoveryProof,
   recoverySecret,
   RECOVERYID_BYTES,
   CHALLENGE_BYTES,
   type RequestTypes,
} from '@qcrypt/api';
import {
   postJson,
   putJson,
   expectPasskeyDeleted,
   registerTestUser,
   setSessionUserCred,
   createCredential,
   prfEncrypt,
   prfDecrypt,
   type TestUser,
} from './common';

async function issueChallenge(userId: string): Promise<string> {
   const res = await postJson('/v1/recover2/challenge', { userId }, {}, '');
   expect(res.status).toBe(200);
   return res.data.challenge;
}

// Body for recover2/key. A PRF account keeps userCred encrypted under the recovery secret, so a
// key change must re-encrypt and send it under the new secret; no-PRF sends only the public key.
async function recoveryKeyBody(user: TestUser, secret: Uint8Array): Promise<Record<string, any>> {
   const body: Record<string, any> = { recoveryPubKey: bytesToBase64(getRecoveryPubKey(secret)) };
   if (user.prf) {
      body.userCredEnc = await prfEncrypt(base64ToBytes(user.userCred), secret.slice(0), user.userId);
   }
   return body;
}

type RecoverySession = {
   userCred: string;
   cookie: string;
   csrf: string;
   credId: string;
};

// Drives a full account recovery: authorize recover2 with a challenge-signed proof, then finish the
// registration the recovery starts so the account ends with a passkey. userCred is preserved: for a
// PRF account recover2 returns the recovery ciphertext, which the recovery secret decrypts back to
// the original userCred and which is then re-encrypted under the new passkey's PRF output. Returns
// the resulting session; unless keepSession is set the new passkey is deleted before returning.
async function recoverAccount(user: TestUser, opts: { keepSession?: boolean } = {}): Promise<RecoverySession> {
   const secret = user.recoverySecret;
   const challenge = await issueChallenge(user.userId);
   const signature = bytesToBase64(createRecoveryProof(secret, user.userId, challenge));

   const recoverRes = await postJson('/v1/recover2', { userId: user.userId, challenge, signature }, {}, '');
   expect(recoverRes.status).toBe(200);
   expect(recoverRes.data.user.id).toBe(user.userId);
   expect(recoverRes.data.challenge).toBeDefined();

   // Recovery replaces the account's credential, so it reuses the real userHandle.
   const createOptions = {
      ...recoverRes.data,
      user: { ...recoverRes.data.user, id: user.userId },
      challenge: recoverRes.data.challenge,
   };

   let verifyBody: RequestTypes.RecoverVerify;
   if (user.prf) {
      expect(recoverRes.data.prf).toBe(true);
      expect(recoverRes.data.userCredEnc).toBeDefined();
      const recoveredUserCred = await prfDecrypt(recoverRes.data.userCredEnc, secret.slice(0), user.userId);
      expect(bytesToBase64(recoveredUserCred)).toBe(user.userCred);

      const { attestation, prfOutput } = createCredential(user.emulator, createOptions, true);
      const passkeyUserCredEnc = await prfEncrypt(recoveredUserCred, prfOutput, user.userId);
      verifyBody = { ...attestation, userId: user.userId, challenge: recoverRes.data.challenge, passkeyUserCredEnc };
   } else {
      const { attestation } = createCredential(user.emulator, createOptions, false);
      verifyBody = { ...attestation, userId: user.userId, challenge: recoverRes.data.challenge };
   }

   const verifyRes = await postJson('/v1/reg/verify?usercred=true', verifyBody, {}, '');
   expect(verifyRes.status).toBe(200);
   expect(verifyRes.data.verified).toBe(true);
   expect(verifyRes.data.pkId).toBeDefined();
   expect(verifyRes.data.csrf).toBeDefined();
   if (user.prf) {
      expect(verifyRes.data.prf).toBe(true);
      expect(verifyRes.data.userCred).toBeUndefined();
      expect(verifyRes.data.passkeyUserCredEnc).toBeUndefined();
   } else {
      expect(verifyRes.data.userCred).toBe(user.userCred);
   }

   const session: RecoverySession = {
      userCred: user.userCred,
      cookie: verifyRes.cookie,
      csrf: verifyRes.data.csrf,
      credId: verifyRes.data.pkId,
   };

   if (!opts.keepSession) {
      setSessionUserCred(session.userCred, user.userId);
      await expectPasskeyDeleted(session.credId, session.csrf, session.cookie);
   }

   return session;
}

export function recoverySuite(prf: boolean): void {
   const label = prf ? 'PRF' : 'no-PRF';
   const tag = prf ? 'pf' : 'np';

   describe(`recovery proof (${label})`, () => {
      let user: TestUser;

      beforeAll(async () => {
         await cryptoReady();
         user = await registerTestUser(`PWTesty_rec${tag}_${Date.now()}`, prf);
      });

      // Tests run in arbitrary order and the proof signer is global, so re-point it at the
      // shared user before each test; recovery tests repoint it at their own user.
      beforeEach(() => {
         setSessionUserCred(user.userCred, user.userId);
      });

      afterAll(async () => {
         if (user?.cookie && user?.credId) {
            setSessionUserCred(user.userCred, user.userId);
            await expectPasskeyDeleted(user.credId, user.csrf, user.cookie);
         }
         setSessionUserCred(undefined);
      });

      it('issues a challenge for a valid userId', async () => {
         const challenge = await issueChallenge(user.userId);
         expect(typeof challenge).toBe('string');
         expect(Buffer.from(challenge, 'base64url').length).toBe(CHALLENGE_BYTES);
      });

      it('issues a challenge for an unknown user', async () => {
         // No account lookup happens here, so the endpoint cannot be used to probe for users.
         const challenge = await issueChallenge(bytesToBase64(getRandom(cc.USERID_BYTES)));
         expect(typeof challenge).toBe('string');
      });

      it('rejects a challenge request with a malformed userId', async () => {
         const res = await postJson('/v1/recover2/challenge', { userId: 'AAAA' }, {}, '');
         expect(res.status).toBe(401);
      });

      it('rejects a wrong signature', async () => {
         const challenge = await issueChallenge(user.userId);
         const wrongSecret = recoverySecret(getRandom(RECOVERYID_BYTES), user.userId);
         const signature = bytesToBase64(createRecoveryProof(wrongSecret, user.userId, challenge));
         const res = await postJson('/v1/recover2', { userId: user.userId, challenge, signature }, {}, '');
         expect(res.status).toBe(401);
      });

      it('rejects a never-issued challenge', async () => {
         const challenge = bytesToBase64(getRandom(CHALLENGE_BYTES));
         const signature = bytesToBase64(createRecoveryProof(user.recoverySecret, user.userId, challenge));
         const res = await postJson('/v1/recover2', { userId: user.userId, challenge, signature }, {}, '');
         expect(res.status).toBe(401);
      });

      it('rejects a tampered challenge', async () => {
         const challenge = await issueChallenge(user.userId);
         const tampered = (challenge[0] === 'A' ? 'B' : 'A') + challenge.slice(1);
         const signature = bytesToBase64(createRecoveryProof(user.recoverySecret, user.userId, tampered));
         const res = await postJson('/v1/recover2', { userId: user.userId, challenge: tampered, signature }, {}, '');
         expect(res.status).toBe(401);
      });

      it('rejects a challenge bound to a different userId', async () => {
         const otherUserId = bytesToBase64(getRandom(cc.USERID_BYTES));
         const challenge = await issueChallenge(otherUserId);
         const signature = bytesToBase64(createRecoveryProof(user.recoverySecret, user.userId, challenge));
         const res = await postJson('/v1/recover2', { userId: user.userId, challenge, signature }, {}, '');
         expect(res.status).toBe(401);
      });

      it('rejects a recover2 request missing any recovery proof', async () => {
         const res = await postJson('/v1/recover2', { userId: user.userId }, {}, '');
         expect(res.status).toBe(401);
      });

      it('rejects a recover2 challenge reused after it is spent', async () => {
         const challenge = await issueChallenge(user.userId);
         // The challenge is consumed before the signature is checked and well before any passkey
         // deletion, so a wrong-signature attempt spends it without wiping the shared account.
         const wrongSecret = recoverySecret(getRandom(RECOVERYID_BYTES), user.userId);
         const spent = await postJson(
            '/v1/recover2',
            {
               userId: user.userId,
               challenge,
               signature: bytesToBase64(createRecoveryProof(wrongSecret, user.userId, challenge)),
            },
            {},
            '',
         );
         expect(spent.status).toBe(401);

         // Single-use: even a correct signature is rejected once the challenge is spent.
         const reuse = await postJson(
            '/v1/recover2',
            {
               userId: user.userId,
               challenge,
               signature: bytesToBase64(createRecoveryProof(user.recoverySecret, user.userId, challenge)),
            },
            {},
            '',
         );
         expect(reuse.status).toBe(401);
      });

      it('rejects a recover2 challenge minted for another purpose', async () => {
         // An auth-purpose challenge, correctly signed and bound to the same user, still must not
         // satisfy recover2 — it requires a nonce-purpose challenge.
         const authOpts = await postJson('/v1/auth/options', { userId: user.userId }, {}, '');
         expect(authOpts.status).toBe(200);
         const challenge = authOpts.data.challenge;
         const signature = bytesToBase64(createRecoveryProof(user.recoverySecret, user.userId, challenge));
         const res = await postJson('/v1/recover2', { userId: user.userId, challenge, signature }, {}, '');
         expect(res.status).toBe(401);
      });

      // Reuse a single user session across multiple recovery key change tests
      // (instead of re-authenticating) to detect unintentional session invalidation
      it('updates the recovery public key with the current key', async () => {
         const body = await recoveryKeyBody(user, user.recoverySecret);
         const res = await putJson('/v1/recover2/key', body, { 'x-csrf-token': user.csrf }, user.cookie);
         expect(res.status).toBe(200);
      });

      it('updates the recovery public key with a new key', async () => {
         const body = await recoveryKeyBody(user, recoverySecret(getRandom(RECOVERYID_BYTES), user.userId));
         const res = await putJson('/v1/recover2/key', body, { 'x-csrf-token': user.csrf }, user.cookie);
         expect(res.status).toBe(200);
      });

      it('rejects a recovery public key of the wrong length', async () => {
         const full = getRecoveryPubKey(user.recoverySecret);
         const shortKey = bytesToBase64(full.slice(0, full.length - 1));
         const res = await putJson(
            '/v1/recover2/key',
            { recoveryPubKey: shortKey },
            { 'x-csrf-token': user.csrf },
            user.cookie,
         );
         expect(res.status).toBe(400);
      });

      it('rejects an empty recovery public key', async () => {
         const res = await putJson(
            '/v1/recover2/key',
            { recoveryPubKey: '' },
            { 'x-csrf-token': user.csrf },
            user.cookie,
         );
         expect(res.status).toBe(400);
      });

      it('rejects a recover2/key update without a session', async () => {
         const recoveryPubKey = bytesToBase64(getRecoveryPubKey(user.recoverySecret));
         const res = await putJson('/v1/recover2/key', { recoveryPubKey }, {}, '');
         expect(res.status).toBe(401);
      });

      // Recovery wipes all passkeys, so these run against their own throwaway users.
      it('account recovery succeeds', async () => {
         const recoverUser = await registerTestUser(`PWTesty_rok${tag}_${Date.now()}`, prf);
         await recoverAccount(recoverUser);
      });

      // Replacing recovery words rotates the recovery key, which must retire the prior one.
      it('rejects the previous recovery key after it is replaced', async () => {
         const recoverUser = await registerTestUser(`PWTesty_rgn${tag}_${Date.now()}`, prf);

         // The original key recovers the account before it is replaced.
         const session = await recoverAccount(recoverUser, { keepSession: true });

         const newSecret = recoverySecret(getRandom(RECOVERYID_BYTES), recoverUser.userId);
         setSessionUserCred(session.userCred, recoverUser.userId);
         const keyRes = await putJson(
            '/v1/recover2/key',
            await recoveryKeyBody(recoverUser, newSecret),
            { 'x-csrf-token': session.csrf },
            session.cookie,
         );
         expect(keyRes.status).toBe(200);

         // The original key no longer recovers the account.
         const challenge = await issueChallenge(recoverUser.userId);
         const signature = bytesToBase64(
            createRecoveryProof(recoverUser.recoverySecret, recoverUser.userId, challenge),
         );
         const staleRes = await postJson('/v1/recover2', { userId: recoverUser.userId, challenge, signature }, {}, '');
         expect(staleRes.status).toBe(401);

         // The replacement key recovers it.
         await recoverAccount({ ...recoverUser, recoverySecret: newSecret });
      });

      it('rejects a previous recovery id after the key is replaced', async () => {
         const recoverUser = await registerTestUser(`PWTesty_rgb${tag}_${Date.now()}`, prf);

         // The original recovery id recovers the account before the key is replaced.
         const session = await recoverAccount(recoverUser, { keepSession: true });

         const newSecret = recoverySecret(getRandom(RECOVERYID_BYTES), recoverUser.userId);
         setSessionUserCred(session.userCred, recoverUser.userId);
         const keyRes = await putJson(
            '/v1/recover2/key',
            await recoveryKeyBody(recoverUser, newSecret),
            { 'x-csrf-token': session.csrf },
            session.cookie,
         );
         expect(keyRes.status).toBe(200);

         // The original recovery id no longer recovers the account.
         const staleRes = await postJson(
            '/v1/recover2',
            { userId: recoverUser.userId, recoveryId: bytesToBase64(recoverUser.recoveryId) },
            {},
            '',
         );
         expect(staleRes.status).toBe(401);

         // The replacement key recovers it.
         await recoverAccount({ ...recoverUser, recoverySecret: newSecret });
      });
   });
}
