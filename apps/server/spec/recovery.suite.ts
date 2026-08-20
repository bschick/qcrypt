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
import { cryptoReady, bytesToBase64, base64ToBytes, getRandom, hashString } from '@qcrypt/crypto';
import * as cc from '@qcrypt/crypto/consts';
import {
   getRecoveryPubKey,
   createUserCredProof,
   createRecoveryProof,
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
   sha256Hex,
   type TestUser,
} from './common';

const CONFIRM_PATH = '/v1/recover/confirm';

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
      recoveryPubKey: getRecoveryPubKey(secret),
      timestamp,
      nonce,
      signature: createRecoveryProof(proofSecret, user.userId, timestamp, nonce),
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
      signature: createRecoveryProof(secret, user.userId, timestamp, nonce),
   };
}

async function postRecover3(user: TestUser, body: RequestTypes.Recover3 = recover3Body(user)): Promise<StartResponse> {
   return await postJson('/v1/recover3', body, {}, '');
}

// Proves possession of the rebuilt userCred over the challenge recover3 issued. opts let tests
// sign with the wrong credential or a stale timestamp.
function confirmBody(
   user: TestUser,
   challenge: string,
   opts: { userCred?: string; timestamp?: string } = {},
): RequestTypes.RecoverConfirm {
   const userCred = opts.userCred ?? user.userCred;
   const timestamp = opts.timestamp ?? String(Date.now());
   return {
      userId: user.userId,
      challenge,
      timestamp,
      signature: createUserCredProof(
         base64ToBytes(userCred),
         user.userId,
         'POST',
         CONFIRM_PATH,
         timestamp,
         challenge,
         sha256Hex(Buffer.alloc(0)),
      ),
   };
}

async function passkeyCount(userId: string, userCred: string, csrf: string, cookie: string): Promise<number> {
   setSessionSigner(userId, userCred);
   const res = await getJson('/v1/user', { 'x-csrf-token': csrf }, cookie);
   expect(res.status).toBe(200);
   return res.data.authenticators.length;
}

type StartResponse = {
   status: number;
   data: ResponseTypes.RecoverStart;
};

// Spends the recovery challenge on confirm, which deletes the old passkeys, then registers
// the replacement that recovery promises.
async function finishRecovery3(
   user: TestUser,
   startRes: StartResponse,
   recoveredUserCred: Uint8Array<ArrayBuffer>,
): Promise<RecoverySession> {
   const confirmRes = await postJson('/v1/recover/confirm', confirmBody(user, startRes.data.challenge), {}, '');
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
      expect(verifyRes.data.prf).toBe(true);
      expect(verifyRes.data.userCred).toBeUndefined();
      expect(verifyRes.data.passkeyUserCredEnc).toBeUndefined();
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

// Starts recovery and rebuilds userCred from what recover3 returns.
async function startRecovery3(
   user: TestUser,
): Promise<{ startRes: StartResponse; recoveredUserCred: Uint8Array<ArrayBuffer> }> {
   const startRes = await postRecover3(user);
   expect(startRes.status).toBe(200);
   expect(startRes.data.challenge).toBeDefined();

   // The union promises exactly one credential field, but nothing makes the server honor it
   const data = startRes.data as { prf: boolean; userCred?: string; userCredEnc?: string };

   let recoveredUserCred: Uint8Array<ArrayBuffer>;
   if (user.prf) {
      expect(data.prf).toBe(true);
      expect(data.userCredEnc).toBeDefined();
      expect(data.userCred).toBeUndefined();
      recoveredUserCred = await prfDecrypt(data.userCredEnc!, user.recoverySecret.slice(0), user.userId);
   } else {
      expect(data.prf).toBe(false);
      expect(data.userCredEnc).toBeUndefined();
      recoveredUserCred = base64ToBytes(data.userCred!);
   }
   expect(bytesToBase64(recoveredUserCred)).toBe(user.userCred);

   return { startRes, recoveredUserCred };
}

// Drives the whole two-phase recovery and returns the resulting session; unless keepSession is
// set the new passkey is deleted before returning.
async function recoverAccount3(user: TestUser, opts: { keepSession?: boolean } = {}): Promise<RecoverySession> {
   const { startRes, recoveredUserCred } = await startRecovery3(user);
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
         if (user?.credId) {
            setSessionSigner(user.userId, user.userCred);
            // Starting a recovery revokes the session, and several tests above do
            const session = await loginWithPasskey(user);
            await expectPasskeyDeleted(user.credId, session.csrf, session.cookie);
         }
         setSessionSigner(undefined);
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

         expect(res.data.recoveryKeyId).toEqual(hashString(getRecoveryPubKey(newSecret)));
         expect(res.data.recoveryKeyId).not.toEqual(hashString(getRecoveryPubKey(user.recoverySecret)));

         // Later tests sign with this secret, so it has to track what the server now stores
         user.recoverySecret = newSecret;
      });

      it('rejects a recovery public key of the wrong length', async () => {
         const full = base64ToBytes(getRecoveryPubKey(user.recoverySecret));
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

      // The body is otherwise complete so that only the absent proof is under test.
      it('rejects a recovery public key with no proof of its secret', async () => {
         const newSecret = recoverySecret(getRandom(RECOVERYID_BYTES), user.userId);
         const good = await recoveryKeyBody(user, newSecret);
         const okRes = await putJson('/v1/recover3/key', good, { 'x-csrf-token': user.csrf }, user.cookie);
         expect(okRes.status).toBe(200);
         user.recoverySecret = newSecret;

         const unproven: Record<string, string> = { recoveryPubKey: getRecoveryPubKey(user.recoverySecret) };
         if (user.prf) {
            unproven['userCredEnc'] = await prfEncrypt(
               base64ToBytes(user.userCred),
               user.recoverySecret.slice(0),
               user.userId,
            );
         }
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
         const recoveryPubKey = getRecoveryPubKey(user.recoverySecret);
         const res = await putJson('/v1/recover3/key', { recoveryPubKey }, {}, '');
         expect(res.status).toBe(401);
      });

      // Recovery wipes all passkeys, so these run against their own throwaway users.
      // Replacing recovery words rotates the recovery key, which must retire the prior one.
      it('rejects the previous recovery key after it is replaced', async () => {
         const recoverUser = await registerTestUser(`PWTesty_rgn${tag}_${Date.now()}`, prf);

         // The original key recovers the account before it is replaced.
         const session = await recoverAccount3(recoverUser, { keepSession: true });

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
         const staleRes = await postRecover3(recoverUser);
         expect(staleRes.status).toBe(401);

         // The replacement key recovers it.
         await recoverAccount3({ ...recoverUser, recoverySecret: newSecret });
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

         const session = await recoverAccount3(recoverUser, { keepSession: true });

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

      it('rejects a recover3 request missing any recovery proof', async () => {
         const good = await postRecover3(user);
         expect(good.status).toBe(200);

         const { signature: _unsigned, ...noProof } = recover3Body(user);
         const res = await postJson('/v1/recover3', noProof, {}, '');
         expect(res.status).toBe(401);
      });

      it('rejects a recover3 proof for an unknown userId', async () => {
         // Same refusal as a known account with a bad proof, so recovery cannot probe for accounts.
         const unknown = bytesToBase64(getRandom(cc.USERID_BYTES));
         const timestamp = String(Date.now());
         const nonce = bytesToBase64(getRandom(CHALLENGE_BYTES));
         const res = await postJson(
            '/v1/recover3',
            {
               userId: unknown,
               timestamp,
               nonce,
               signature: createRecoveryProof(user.recoverySecret, unknown, timestamp, nonce),
            },
            {},
            '',
         );
         expect(res.status).toBe(401);
      });

      it('rejects a recover3 request with a malformed userId', async () => {
         const res = await postJson('/v1/recover3', { ...recover3Body(user), userId: 'AAAA' }, {}, '');
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

      it('rejects confirm with a challenge recover3 never issued', async () => {
         const recoverUser = await registerTestUser(`PWTesty_r3nc${tag}_${Date.now()}`, prf);

         // A correctly signed proof over a self-minted challenge: only recover3 can authorize confirm.
         const neverIssued = bytesToBase64(getRandom(CHALLENGE_BYTES));
         const res = await postJson('/v1/recover/confirm', confirmBody(recoverUser, neverIssued), {}, '');
         expect(res.status).toBe(401);

         expect(
            await passkeyCount(recoverUser.userId, recoverUser.userCred, recoverUser.csrf, recoverUser.cookie),
         ).toBe(1);

         await expectPasskeyDeleted(recoverUser.credId, recoverUser.csrf, recoverUser.cookie);
      });

      it('rejects a confirm challenge minted for another purpose', async () => {
         // An auth-purpose challenge for the same user, from the table confirm challenges share,
         // still must not satisfy confirm
         const recoverUser = await registerTestUser(`PWTesty_r3pp${tag}_${Date.now()}`, prf);

         const authOpts = await postJson('/v1/auth/options', { userId: recoverUser.userId }, {}, '');
         expect(authOpts.status).toBe(200);

         const res = await postJson(CONFIRM_PATH, confirmBody(recoverUser, authOpts.data.challenge), {}, '');
         expect(res.status).toBe(401);

         expect(
            await passkeyCount(recoverUser.userId, recoverUser.userCred, recoverUser.csrf, recoverUser.cookie),
         ).toBe(1);

         await expectPasskeyDeleted(recoverUser.credId, recoverUser.csrf, recoverUser.cookie);
      });

      it('rejects confirm carrying no userCred proof', async () => {
         const recoverUser = await registerTestUser(`PWTesty_r3np${tag}_${Date.now()}`, prf);

         const { startRes } = await startRecovery3(recoverUser);

         const { signature, ...unproven } = confirmBody(recoverUser, startRes.data.challenge);
         const res = await postJson('/v1/recover/confirm', unproven, {}, '');
         expect(res.status).toBe(401);

         const session = await loginWithPasskey(recoverUser);
         await expectPasskeyDeleted(recoverUser.credId, session.csrf, session.cookie);
      });

      // Only the body proof decides the outcome (session is ignored)
      it('ignores a session on confirm', async () => {
         const other = await registerTestUser(`PWTesty_r3os${tag}_${Date.now()}`, prf);
         const recoverUser = await registerTestUser(`PWTesty_r3ws${tag}_${Date.now()}`, prf);

         const { startRes } = await startRecovery3(recoverUser);

         // A live session, just not one belonging to the account being recovered. The fact
         // that this works is not a goal, it just proves the session was ignored.
         const res = await postJson(
            '/v1/recover/confirm',
            confirmBody(recoverUser, startRes.data.challenge),
            { 'x-csrf-token': other.csrf },
            other.cookie,
         );
         expect(res.status).toBe(200);

         setSessionSigner(other.userId, other.userCred);
         expect(await passkeyCount(other.userId, other.userCred, other.csrf, other.cookie)).toBe(1);
         await expectPasskeyDeleted(other.credId, other.csrf, other.cookie);
      });

      // A caller that cannot rebuild userCred signs with the wrong key, and the account must
      // come through that untouched.
      it('rejects confirm proved with the wrong userCred and keeps the passkeys', async () => {
         const recoverUser = await registerTestUser(`PWTesty_r3wc${tag}_${Date.now()}`, prf);

         const { startRes } = await startRecovery3(recoverUser);

         const wrongUserCred = bytesToBase64(getRandom(cc.USERCRED_BYTES));
         const res = await postJson(
            '/v1/recover/confirm',
            confirmBody(recoverUser, startRes.data.challenge, { userCred: wrongUserCred }),
            {},
            '',
         );
         expect(res.status).toBe(401);

         // Confirm the original credential still works
         const session = await loginWithPasskey(recoverUser);
         expect(await passkeyCount(recoverUser.userId, recoverUser.userCred, session.csrf, session.cookie)).toBe(1);

         await expectPasskeyDeleted(recoverUser.credId, session.csrf, session.cookie);
      });

      it('rejects a confirm challenge reused after it is spent', async () => {
         const recoverUser = await registerTestUser(`PWTesty_r3rc${tag}_${Date.now()}`, prf);

         const { startRes, recoveredUserCred } = await startRecovery3(recoverUser);
         const session = await finishRecovery3(recoverUser, startRes, recoveredUserCred);
         expect(await passkeyCount(recoverUser.userId, session.userCred, session.csrf, session.cookie)).toBe(1);

         const res = await postJson('/v1/recover/confirm', confirmBody(recoverUser, startRes.data.challenge), {}, '');
         expect(res.status).toBe(401);

         await expectPasskeyDeleted(session.credId, session.csrf, session.cookie);
      });

      // A spent challenge must not be redeemable against a later recovery, or a captured confirm
      // body could be replayed the moment someone starts a fresh one.
      it('rejects a spent confirm challenge against a second recovery', async () => {
         const recoverUser = await registerTestUser(`PWTesty_r3sc${tag}_${Date.now()}`, prf);

         const first = await startRecovery3(recoverUser);
         const spentBody = confirmBody(recoverUser, first.startRes.data.challenge);
         await finishRecovery3(recoverUser, first.startRes, first.recoveredUserCred);

         const second = await startRecovery3(recoverUser);
         const res = await postJson('/v1/recover/confirm', spentBody, {}, '');
         expect(res.status).toBe(401);

         const session = await finishRecovery3(recoverUser, second.startRes, second.recoveredUserCred);
         await expectPasskeyDeleted(session.credId, session.csrf, session.cookie);
      });

      it('rejects a confirm timestamp outside the skew window', async () => {
         const recoverUser = await registerTestUser(`PWTesty_r3ct${tag}_${Date.now()}`, prf);

         const { startRes } = await startRecovery3(recoverUser);

         const stale = String(Date.now() - 10 * 60 * 1000);
         const res = await postJson(
            '/v1/recover/confirm',
            confirmBody(recoverUser, startRes.data.challenge, { timestamp: stale }),
            {},
            '',
         );
         expect(res.status).toBe(401);

         const session = await loginWithPasskey(recoverUser);
         await expectPasskeyDeleted(recoverUser.credId, session.csrf, session.cookie);
      });

      it('recover3 invalidates previous session', async () => {
         const recoverUser = await registerTestUser(`PWTesty_r3rev${tag}_${Date.now()}`, prf);

         const before = await getJson('/v1/user', { 'x-csrf-token': recoverUser.csrf }, recoverUser.cookie);
         expect(before.status).toBe(200);

         const { startRes, recoveredUserCred } = await startRecovery3(recoverUser);

         const after = await getJson('/v1/user', { 'x-csrf-token': recoverUser.csrf }, recoverUser.cookie);
         expect(after.status).toBe(401);

         const session = await finishRecovery3(recoverUser, startRes, recoveredUserCred);
         await expectPasskeyDeleted(session.credId, session.csrf, session.cookie);
      });
   });
}
