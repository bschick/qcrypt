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
   createRecoveryProofBackwardCompat,
   recoverySecret,
   RECOVERYID_BYTES,
   CHALLENGE_BYTES,
   type RequestTypes,
   type ResponseTypes,
} from '@qcrypt/api';
import {
   postJson,
   putJson,
   getJson,
   expectPasskeyDeleted,
   registerTestUser,
   setSessionSigner,
   createCredential,
   prfEncrypt,
   prfDecrypt,
   loginWithPasskey,
   addPasskey,
   type TestUser,
} from './common';

async function issueChallenge(userId: string): Promise<string> {
   const res = await postJson('/v1/recover2/challenge', { userId }, {}, '');
   expect(res.status).toBe(200);
   return res.data.challenge;
}

// Body for recover3/key. A PRF account keeps userCred encrypted under the recovery secret, so a
// key change must re-encrypt and send it under the new secret; no-PRF sends only the public key.
async function recoveryKeyBody(
   user: TestUser,
   secret: Uint8Array,
   opts: { proofSecret?: Uint8Array } = {},
): Promise<RequestTypes.Recover3Key> {
   const timestamp = String(Date.now());
   const nonce = bytesToBase64(getRandom(CHALLENGE_BYTES));
   const proofSecret = opts.proofSecret ?? secret;

   const body: RequestTypes.Recover3Key = {
      recoveryPubKey: bytesToBase64(getRecoveryPubKey(secret)),
      timestamp,
      nonce,
      signature: bytesToBase64(createRecoveryProof(proofSecret, user.userId, timestamp, nonce)),
   };
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
   const signature = bytesToBase64(createRecoveryProofBackwardCompat(secret, user.userId, challenge));

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
      expect(verifyRes.data.userCredEnc).toBeUndefined();
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
      setSessionSigner(user.userId, session.userCred);
      await expectPasskeyDeleted(session.credId, session.csrf, session.cookie);
   }

   return session;
}

// Signs the recover3 proof over a caller-chosen timestamp and nonce. opts let tests forge a
// stale timestamp or reuse a nonce without reaching into the proof internals.
function recover3Body(
   user: TestUser,
   opts: { secret?: Uint8Array; timestamp?: string; nonce?: string } = {},
): RequestTypes.Recover3 {
   const secret = opts.secret ?? user.recoverySecret;
   const timestamp = opts.timestamp ?? String(Date.now());
   const nonce = opts.nonce ?? bytesToBase64(getRandom(CHALLENGE_BYTES));
   return {
      userId: user.userId,
      timestamp,
      nonce,
      signature: bytesToBase64(createRecoveryProof(secret, user.userId, timestamp, nonce)),
   };
}

// A successful recover3 revokes whatever session the account held and issues a new one, so
// rebind the caller to it or every later call with that account is unauthorized.
async function postRecover3(user: TestUser, body: RequestTypes.Recover3 = recover3Body(user)): Promise<RecoverStart> {
   const res = await postJson('/v1/recover3', body, {}, '');
   if (res.status === 200) {
      user.cookie = res.cookie;
      user.csrf = res.data.csrf;
   }
   return res;
}

// Counts the account's passkeys using the mid-recovery session recover3 hands back.
async function passkeyCount(userId: string, userCred: string, csrf: string, cookie: string): Promise<number> {
   setSessionSigner(userId, userCred);
   const res = await getJson('/v1/user', { 'x-csrf-token': csrf }, cookie);
   expect(res.status).toBe(200);
   return res.data.authenticators.length;
}

type RecoverStart = {
   status: number;
   data: ResponseTypes.LoginUserInfo;
   cookie: string;
};

// Spends the mid-recovery session on confirm, which deletes the old passkeys, then registers
// the replacement that recovery promises.
async function finishRecovery3(
   user: TestUser,
   startRes: RecoverStart,
   recoveredUserCred: Uint8Array<ArrayBuffer>,
): Promise<RecoverySession> {
   setSessionSigner(user.userId, user.userCred);
   const confirmRes = await postJson(
      '/v1/recover/confirm',
      null,
      { 'x-csrf-token': startRes.data.csrf },
      startRes.cookie,
   );
   expect(confirmRes.status).toBe(200);
   expect(confirmRes.data.challenge).toBeDefined();

   // Recovery replaces the account's credential, so it reuses the real userHandle.
   const createOptions = {
      ...confirmRes.data,
      user: { ...confirmRes.data.user, id: user.userId },
      challenge: confirmRes.data.challenge,
   };

   let verifyBody: RequestTypes.RecoverVerify;
   if (user.prf) {
      const { attestation, prfOutput } = createCredential(user.emulator, createOptions, true);
      const passkeyUserCredEnc = await prfEncrypt(recoveredUserCred, prfOutput, user.userId);
      verifyBody = { ...attestation, userId: user.userId, challenge: confirmRes.data.challenge, passkeyUserCredEnc };
   } else {
      const { attestation } = createCredential(user.emulator, createOptions, false);
      verifyBody = { ...attestation, userId: user.userId, challenge: confirmRes.data.challenge };
   }

   const verifyRes = await postJson('/v1/recover/verify', verifyBody, {}, '');
   expect(verifyRes.status).toBe(200);
   expect(verifyRes.data.verified).toBe(true);
   expect(verifyRes.data.pkId).toBeDefined();
   expect(verifyRes.data.csrf).toBeDefined();
   if (user.prf) {
      expect(verifyRes.data.userCred).toBeUndefined();
   } else {
      expect(verifyRes.data.userCred).toBe(user.userCred);
   }

   // Recovery replaced both the session and the passkey, so rebind the account to them.
   user.cookie = verifyRes.cookie;
   user.csrf = verifyRes.data.csrf;
   user.credId = verifyRes.data.pkId;

   return {
      userCred: user.userCred,
      cookie: verifyRes.cookie,
      csrf: verifyRes.data.csrf,
      credId: verifyRes.data.pkId,
   };
}

// Starts recovery and rebuilds userCred from what recover3 returns, asserting the account is
// untouched at that point.
async function startRecovery3(
   user: TestUser,
   existingPasskeys: number = 1,
): Promise<{ startRes: RecoverStart; recoveredUserCred: Uint8Array<ArrayBuffer> }> {
   const startRes = await postRecover3(user);
   expect(startRes.status).toBe(200);
   expect(startRes.data.userId).toBe(user.userId);
   expect(startRes.data.pkId).toBeDefined();
   expect(startRes.data.csrf).toBeDefined();
   expect(startRes.cookie).toBeTruthy();

   let recoveredUserCred: Uint8Array<ArrayBuffer>;
   if (user.prf) {
      expect(startRes.data.prf).toBe(true);
      expect(startRes.data.userCredEnc).toBeDefined();
      expect(startRes.data.userCred).toBeUndefined();
      recoveredUserCred = await prfDecrypt(startRes.data.userCredEnc!, user.recoverySecret.slice(0), user.userId);
   } else {
      expect(startRes.data.prf).toBe(false);
      expect(startRes.data.userCredEnc).toBeUndefined();
      recoveredUserCred = base64ToBytes(startRes.data.userCred!);
   }
   expect(bytesToBase64(recoveredUserCred)).toBe(user.userCred);

   // Nothing is destroyed until confirm, so the account still has every passkey it started with.
   expect(await passkeyCount(user.userId, user.userCred, startRes.data.csrf!, startRes.cookie)).toBe(existingPasskeys);

   return { startRes, recoveredUserCred };
}

// Drives the whole two-phase recovery and returns the resulting session; unless keepSession is
// set the new passkey is deleted before returning.
async function recoverAccount3(
   user: TestUser,
   opts: { keepSession?: boolean; existingPasskeys?: number } = {},
): Promise<RecoverySession> {
   const { startRes, recoveredUserCred } = await startRecovery3(user, opts.existingPasskeys);
   const session = await finishRecovery3(user, startRes, recoveredUserCred);

   if (!opts.keepSession) {
      setSessionSigner(user.userId, session.userCred);
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
         setSessionSigner(user.userId, user.userCred);
      });

      afterAll(async () => {
         if (user?.cookie && user?.credId) {
            setSessionSigner(user.userId, user.userCred);
            await expectPasskeyDeleted(user.credId, user.csrf, user.cookie);
         }
         setSessionSigner(undefined);
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
         const signature = bytesToBase64(createRecoveryProofBackwardCompat(wrongSecret, user.userId, challenge));
         const res = await postJson('/v1/recover2', { userId: user.userId, challenge, signature }, {}, '');
         expect(res.status).toBe(401);
      });

      it('rejects a never-issued challenge', async () => {
         const challenge = bytesToBase64(getRandom(CHALLENGE_BYTES));
         const signature = bytesToBase64(
            createRecoveryProofBackwardCompat(user.recoverySecret, user.userId, challenge),
         );
         const res = await postJson('/v1/recover2', { userId: user.userId, challenge, signature }, {}, '');
         expect(res.status).toBe(401);
      });

      it('rejects a tampered challenge', async () => {
         const challenge = await issueChallenge(user.userId);
         const tampered = (challenge[0] === 'A' ? 'B' : 'A') + challenge.slice(1);
         const signature = bytesToBase64(createRecoveryProofBackwardCompat(user.recoverySecret, user.userId, tampered));
         const res = await postJson('/v1/recover2', { userId: user.userId, challenge: tampered, signature }, {}, '');
         expect(res.status).toBe(401);
      });

      it('rejects a challenge bound to a different userId', async () => {
         const otherUserId = bytesToBase64(getRandom(cc.USERID_BYTES));
         const challenge = await issueChallenge(otherUserId);
         const signature = bytesToBase64(
            createRecoveryProofBackwardCompat(user.recoverySecret, user.userId, challenge),
         );
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
               signature: bytesToBase64(createRecoveryProofBackwardCompat(wrongSecret, user.userId, challenge)),
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
               signature: bytesToBase64(createRecoveryProofBackwardCompat(user.recoverySecret, user.userId, challenge)),
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
         const signature = bytesToBase64(
            createRecoveryProofBackwardCompat(user.recoverySecret, user.userId, challenge),
         );
         const res = await postJson('/v1/recover2', { userId: user.userId, challenge, signature }, {}, '');
         expect(res.status).toBe(401);
      });

      // Reuse a single user session across multiple recovery key change tests
      // (instead of re-authenticating) to detect unintentional session invalidation
      it('updates the recovery public key with the current key', async () => {
         const body = await recoveryKeyBody(user, user.recoverySecret);
         const res = await putJson('/v1/recover3/key', body, { 'x-csrf-token': user.csrf }, user.cookie);
         expect(res.status).toBe(200);
      });

      it('updates the recovery public key with a new key', async () => {
         const newSecret = recoverySecret(getRandom(RECOVERYID_BYTES), user.userId);
         const body = await recoveryKeyBody(user, newSecret);
         const res = await putJson('/v1/recover3/key', body, { 'x-csrf-token': user.csrf }, user.cookie);
         expect(res.status).toBe(200);

         // Later tests sign with this secret, so it has to track what the server now stores
         user.recoverySecret = newSecret;
      });

      // BACKWARD COMPAT: deployed clients still send this path, and it reaches the same handler
      it('updates the recovery public key through the recover2 path', async () => {
         const body = await recoveryKeyBody(user, user.recoverySecret);
         const res = await putJson('/v1/recover2/key', body, { 'x-csrf-token': user.csrf }, user.cookie);
         expect(res.status).toBe(200);
      });

      it('rejects a recovery public key of the wrong length', async () => {
         const full = getRecoveryPubKey(user.recoverySecret);
         const shortKey = bytesToBase64(full.slice(0, full.length - 1));
         const res = await putJson(
            '/v1/recover3/key',
            { recoveryPubKey: shortKey },
            { 'x-csrf-token': user.csrf },
            user.cookie,
         );
         expect(res.status).toBe(400);
      });

      it('rejects an empty recovery public key', async () => {
         const res = await putJson(
            '/v1/recover3/key',
            { recoveryPubKey: '' },
            { 'x-csrf-token': user.csrf },
            user.cookie,
         );
         expect(res.status).toBe(400);
      });

      it('rejects a recovery public key with no proof of its secret', async () => {
         const newSecret = recoverySecret(getRandom(RECOVERYID_BYTES), user.userId);
         const good = await recoveryKeyBody(user, newSecret);
         const okRes = await putJson('/v1/recover3/key', good, { 'x-csrf-token': user.csrf }, user.cookie);
         expect(okRes.status).toBe(200);
         user.recoverySecret = newSecret;

         const unproven = { recoveryPubKey: bytesToBase64(getRecoveryPubKey(user.recoverySecret)) };
         const res = await putJson('/v1/recover3/key', unproven, { 'x-csrf-token': user.csrf }, user.cookie);
         expect(res.status).toBe(400);
      });

      it('rejects a recovery public key proved with the wrong secret', async () => {
         const otherSecret = recoverySecret(getRandom(RECOVERYID_BYTES), user.userId);
         const body = await recoveryKeyBody(user, user.recoverySecret, { proofSecret: otherSecret });
         const res = await putJson('/v1/recover3/key', body, { 'x-csrf-token': user.csrf }, user.cookie);
         expect(res.status).toBe(400);
      });

      it('rejects a replayed recovery key proof', async () => {
         const newSecret = recoverySecret(getRandom(RECOVERYID_BYTES), user.userId);
         const body = await recoveryKeyBody(user, newSecret);
         const okRes = await putJson('/v1/recover3/key', body, { 'x-csrf-token': user.csrf }, user.cookie);
         expect(okRes.status).toBe(200);
         user.recoverySecret = newSecret;

         const res = await putJson('/v1/recover3/key', body, { 'x-csrf-token': user.csrf }, user.cookie);
         expect(res.status).toBe(400);
      });

      it('rejects a recover3/key update without a session', async () => {
         const recoveryPubKey = bytesToBase64(getRecoveryPubKey(user.recoverySecret));
         const res = await putJson('/v1/recover3/key', { recoveryPubKey }, {}, '');
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
         setSessionSigner(recoverUser.userId, session.userCred);
         const keyRes = await putJson(
            '/v1/recover3/key',
            await recoveryKeyBody(recoverUser, newSecret),
            { 'x-csrf-token': session.csrf },
            session.cookie,
         );
         expect(keyRes.status).toBe(200);

         // The original key no longer recovers the account.
         const challenge = await issueChallenge(recoverUser.userId);
         const signature = bytesToBase64(
            createRecoveryProofBackwardCompat(recoverUser.recoverySecret, recoverUser.userId, challenge),
         );
         const staleRes = await postJson('/v1/recover2', { userId: recoverUser.userId, challenge, signature }, {}, '');
         expect(staleRes.status).toBe(401);

         // The replacement key recovers it.
         await recoverAccount({ ...recoverUser, recoverySecret: newSecret });
      });

      it('recover3 account recovery succeeds', async () => {
         const recoverUser = await registerTestUser(`PWTesty_r3ok${tag}_${Date.now()}`, prf);
         await recoverAccount3(recoverUser);
      });

      // The point of splitting recovery in two: proving the recovery secret alone must not
      // cost the user their passkeys, so an account that never confirms is left intact.
      it('recover3 leaves passkeys in place until confirm', async () => {
         const recoverUser = await registerTestUser(`PWTesty_r3ka${tag}_${Date.now()}`, prf);

         const startRes = await postRecover3(recoverUser);
         expect(startRes.status).toBe(200);

         // Abandon the recovery here, then sign in with the original passkey to show it survived.
         const session = await loginWithPasskey(recoverUser);
         setSessionSigner(recoverUser.userId, recoverUser.userCred);
         const userRes = await getJson('/v1/user', { 'x-csrf-token': session.csrf }, session.cookie);
         expect(userRes.status).toBe(200);
         expect(userRes.data.authenticators.length).toBe(1);
         expect(userRes.data.authenticators[0].credentialId).toBe(recoverUser.credId);

         await expectPasskeyDeleted(recoverUser.credId, session.csrf, session.cookie);
      });

      it('confirm recover3 deletes every passkey', async () => {
         const recoverUser = await registerTestUser(`PWTesty_r3del${tag}_${Date.now()}`, prf);

         // Recovery must clear the whole list, so give the account more than one to clear.
         const originalCredId = recoverUser.credId;
         const addedCredId = await addPasskey(recoverUser, recoverUser.csrf, recoverUser.cookie);
         expect(
            await passkeyCount(recoverUser.userId, recoverUser.userCred, recoverUser.csrf, recoverUser.cookie),
         ).toBe(2);

         const session = await recoverAccount3(recoverUser, { keepSession: true, existingPasskeys: 2 });

         // Both originals are gone and only the replacement remains.
         setSessionSigner(recoverUser.userId, session.userCred);
         const userRes = await getJson('/v1/user', { 'x-csrf-token': session.csrf }, session.cookie);
         expect(userRes.status).toBe(200);
         expect(userRes.data.authenticators.length).toBe(1);
         expect(userRes.data.authenticators[0].credentialId).toBe(session.credId);
         expect(session.credId).not.toBe(originalCredId);
         expect(session.credId).not.toBe(addedCredId);

         await expectPasskeyDeleted(session.credId, session.csrf, session.cookie);
      });

      it('rejects a recover3 proof signed with the wrong secret', async () => {
         const good = await postRecover3(user);
         expect(good.status).toBe(200);

         const wrongSecret = recoverySecret(getRandom(RECOVERYID_BYTES), user.userId);
         const res = await postJson('/v1/recover3', recover3Body(user, { secret: wrongSecret }), {}, '');
         expect(res.status).toBe(401);
      });

      it('rejects a replayed recover3 nonce', async () => {
         const body = recover3Body(user);
         const good = await postRecover3(user, body);
         expect(good.status).toBe(200);

         const res = await postJson('/v1/recover3', body, {}, '');
         expect(res.status).toBe(401);
      });

      it('rejects a recover3 timestamp outside the skew window', async () => {
         const good = await postRecover3(user);
         expect(good.status).toBe(200);

         const stale = String(Date.now() - 10 * 60 * 1000);
         const res = await postJson('/v1/recover3', recover3Body(user, { timestamp: stale }), {}, '');
         expect(res.status).toBe(401);
      });

      it('rejects a recover3 nonce of the wrong length', async () => {
         const good = await postRecover3(user);
         expect(good.status).toBe(200);

         const shortNonce = bytesToBase64(getRandom(CHALLENGE_BYTES - 1));
         const res = await postJson('/v1/recover3', { ...recover3Body(user), nonce: shortNonce }, {}, '');
         expect(res.status).toBe(401);
      });

      it('rejects a recover3 proof signed by another account', async () => {
         const good = await postRecover3(user);
         expect(good.status).toBe(200);

         const other = await registerTestUser(`PWTesty_r3ot${tag}_${Date.now()}`, prf);
         try {
            // A real recovery key, just not this account's
            const res = await postJson('/v1/recover3', recover3Body(user, { secret: other.recoverySecret }), {}, '');
            expect(res.status).toBe(401);
         } finally {
            setSessionSigner(other.userId, other.userCred);
            await expectPasskeyDeleted(other.credId, other.csrf, other.cookie);
         }
      });

      it('rejects a recover3 proof bound to a different userId', async () => {
         const good = await postRecover3(user);
         expect(good.status).toBe(200);

         const otherUserId = bytesToBase64(getRandom(cc.USERID_BYTES));
         const res = await postJson('/v1/recover3', { ...recover3Body(user), userId: otherUserId }, {}, '');
         expect(res.status).toBe(401);
      });

      it('rejects confirm from a session that did not start recovery', async () => {
         const recoverUser = await registerTestUser(`PWTesty_r3os${tag}_${Date.now()}`, prf);

         const res = await postJson(
            '/v1/recover/confirm',
            null,
            { 'x-csrf-token': recoverUser.csrf },
            recoverUser.cookie,
         );
         expect(res.status).toBe(401);

         expect(
            await passkeyCount(recoverUser.userId, recoverUser.userCred, recoverUser.csrf, recoverUser.cookie),
         ).toBe(1);

         await expectPasskeyDeleted(recoverUser.credId, recoverUser.csrf, recoverUser.cookie);
      });

      it('rejects confirm without a session', async () => {
         const startRes = await postRecover3(user);
         expect(startRes.status).toBe(200);

         const res = await postJson('/v1/recover/confirm', null, {}, '');
         expect(res.status).toBe(401);

         expect(await passkeyCount(user.userId, user.userCred, user.csrf, user.cookie)).toBe(1);
      });

      it('rejects confirm carrying a session but no userCred proof', async () => {
         const recoverUser = await registerTestUser(`PWTesty_r3np${tag}_${Date.now()}`, prf);

         const startRes = await postRecover3(recoverUser);
         expect(startRes.status).toBe(200);

         // An unset signer omits x-proof, leaving only the cookie and csrf token.
         setSessionSigner(undefined);
         const res = await postJson(
            '/v1/recover/confirm',
            null,
            { 'x-csrf-token': startRes.data.csrf },
            startRes.cookie,
         );
         expect(res.status).toBe(401);

         setSessionSigner(recoverUser.userId, recoverUser.userCred);
         await expectPasskeyDeleted(recoverUser.credId, recoverUser.csrf, recoverUser.cookie);
      });

      // A caller that cannot rebuild userCred signs with the wrong key, and the account must
      // come through that untouched.
      it('rejects confirm proved with the wrong userCred and keeps the passkeys', async () => {
         const recoverUser = await registerTestUser(`PWTesty_r3wc${tag}_${Date.now()}`, prf);

         const startRes = await postRecover3(recoverUser);
         expect(startRes.status).toBe(200);

         const wrongUserCred = bytesToBase64(getRandom(cc.USERCRED_BYTES));
         setSessionSigner(recoverUser.userId, wrongUserCred);
         const res = await postJson(
            '/v1/recover/confirm',
            null,
            { 'x-csrf-token': startRes.data.csrf },
            startRes.cookie,
         );
         expect(res.status).toBe(401);

         // Confirm the original credential still works
         expect(
            await passkeyCount(recoverUser.userId, recoverUser.userCred, recoverUser.csrf, recoverUser.cookie),
         ).toBe(1);

         await expectPasskeyDeleted(recoverUser.credId, recoverUser.csrf, recoverUser.cookie);
      });

      it('recover3 invalidates previous session', async () => {
         const recoverUser = await registerTestUser(`PWTesty_r3rev${tag}_${Date.now()}`, prf);

         // Recovery rebinds the account to its own session, so hold on to the original.
         const priorCsrf = recoverUser.csrf;
         const priorCookie = recoverUser.cookie;

         setSessionSigner(recoverUser.userId, recoverUser.userCred);
         const before = await getJson('/v1/user', { 'x-csrf-token': priorCsrf }, priorCookie);
         expect(before.status).toBe(200);

         const { startRes, recoveredUserCred } = await startRecovery3(recoverUser);

         const after = await getJson('/v1/user', { 'x-csrf-token': priorCsrf }, priorCookie);
         expect(after.status).toBe(401);

         const session = await finishRecovery3(recoverUser, startRes, recoveredUserCred);

         // Completing recovery retires the mid-recovery session along with the pre-recovery one.
         const spent = await getJson('/v1/user', { 'x-csrf-token': startRes.data.csrf }, startRes.cookie);
         expect(spent.status).toBe(401);

         setSessionSigner(recoverUser.userId, session.userCred);
         await expectPasskeyDeleted(session.credId, session.csrf, session.cookie);
      });

      it('rejects a previous recovery id after the key is replaced', async () => {
         const recoverUser = await registerTestUser(`PWTesty_rgb${tag}_${Date.now()}`, prf);

         // The original recovery id recovers the account before the key is replaced.
         const session = await recoverAccount(recoverUser, { keepSession: true });

         const newSecret = recoverySecret(getRandom(RECOVERYID_BYTES), recoverUser.userId);
         setSessionSigner(recoverUser.userId, session.userCred);
         const keyRes = await putJson(
            '/v1/recover3/key',
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
