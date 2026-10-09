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
import type WebAuthnEmulator from 'nid-webauthn-emulator';
import * as api from '@qcrypt/api';
import { bytesToBase64, base64ToBytes, getRandom } from '@qcrypt/crypto';
import * as cc from '@qcrypt/crypto/consts';
import {
   registerTestUser,
   registerNewCredential,
   getIsolatedWebAuthnEmulator,
   addPasskey,
   login,
   expectLogin,
   expectAllPasskeysDeleted,
   expectListedPasskeys,
   expectPasskeyDeleted,
   getJson,
   postJson,
   putJson,
   deleteJson,
   randomRecoverySecret,
   prfEncrypt,
   prfDecrypt,
   type LoginResult,
   type TestUser,
   type PrfTestUser,
} from './common';
import { recoverAccount3, recoveryKeyBody, startRecovery3, finishRecovery3 } from './recovery.suite';

const MIN_ENC_BYTES = cc.USERCRED_BYTES + cc.PAYLOAD_SIZE_MIN + cc.HEADER_BYTES_6P;

type Session = { cookie: string; csrf: string };

async function putPrfUpgrade(
   user: TestUser,
   session: Session,
   opts: { credentialId?: string; passkeyUserCredEnc?: string } = {},
) {
   const body: api.PrfUpgradeRequest = {
      credentialId: opts.credentialId ?? user.credId,
      passkeyUserCredEnc:
         opts.passkeyUserCredEnc ??
         (await prfEncrypt(base64ToBytes(user.userCred), user.prfOutput!.slice(0), user.userId)),
   };
   return await putJson('/v1/prfupgrade', body, { 'x-csrf-token': session.csrf }, session.cookie);
}

async function prfUpgradeConfirmBody(
   user: TestUser,
   challenge: string,
   opts: { secret?: Uint8Array; op?: api.RecoveryOp; recoveryUserCredEnc?: string } = {},
): Promise<api.PrfUpgradeConfirmRequest> {
   const secret = opts.secret ?? user.recoverySecret;
   const timestamp = String(Date.now());
   const recoveryUserCredEnc =
      opts.recoveryUserCredEnc ?? (await prfEncrypt(base64ToBytes(user.userCred), secret.slice(0), user.userId));

   return {
      challenge,
      recoveryUserCredEnc,
      timestamp,
      signature: api.createRecoveryProof(secret, user.userId, timestamp, challenge, opts.op ?? 'prfupgrade'),
   };
}

async function postPrfUpgradeConfirm(session: Session, body: api.PrfUpgradeConfirmRequest) {
   return await postJson('/v1/prfupgrade/confirm', body, { 'x-csrf-token': session.csrf }, session.cookie);
}

async function putRecoveryKey(user: TestUser, session: Session, secret: Uint8Array) {
   return await putJson(
      '/v1/recover3/key',
      await recoveryKeyBody(user, secret),
      { 'x-csrf-token': session.csrf },
      session.cookie,
   );
}

// Signs in and checks that the account is no-PRF and returns the original userCred
async function expectNoPrfLogin(user: TestUser, emulator: WebAuthnEmulator = user.emulator): Promise<LoginResult> {
   const session = await expectLogin(user, emulator);
   expect(session.data.prf).toBe(false);
   expect(session.data.userCred).toBe(user.userCred);
   return session;
}

// Signs in and checks that the account is PRF and the passkey's encrypted userCred decrypts to
// the original userCred
async function expectPrfLogin(user: TestUser, emulator: WebAuthnEmulator = user.emulator): Promise<LoginResult> {
   const session = await expectLogin(user, emulator);
   expect(session.data.prf).toBe(true);
   expect(session.data.userCred).toBeUndefined();
   expect(session.prfOutput).not.toBeNull();
   const decrypted = await prfDecrypt(session.data.passkeyUserCredEnc, session.prfOutput!.slice(0), user.userId);
   expect(bytesToBase64(decrypted)).toBe(user.userCred);
   return session;
}

async function upgradeToPrf(
   user: TestUser,
   session: Session,
   secret: Uint8Array = user.recoverySecret,
): Promise<PrfTestUser> {
   const putRes = await putPrfUpgrade(user, session);
   expect(putRes.status).toBe(200);

   const confirmRes = await postPrfUpgradeConfirm(
      session,
      await prfUpgradeConfirmBody(user, putRes.data.challenge, { secret }),
   );
   expect(confirmRes.status).toBe(200);
   expect(confirmRes.data.prf).toBe(true);

   const prfLogin = await expectPrfLogin(user);
   return {
      ...user,
      prf: true,
      cookie: prfLogin.cookie,
      csrf: prfLogin.csrf,
      recoverySecret: secret,
      passkeyUserCredEnc: prfLogin.data.passkeyUserCredEnc,
      prfOutput: prfLogin.prfOutput!,
   };
}

describe('PRF upgrade', () => {
   let cleanupUser: TestUser | undefined;

   afterEach(async () => {
      if (cleanupUser) {
         await expectAllPasskeysDeleted(cleanupUser);
         cleanupUser = undefined;
      }
   });

   async function registerUpgradable(): Promise<TestUser> {
      const user = await registerTestUser(false, undefined, { prfCapable: true });
      cleanupUser = user;
      return user;
   }

   describe('completed', () => {
      it('upgrades with the existing recovery words and removes other passkeys', async () => {
         const user = await registerUpgradable();
         const secondEmulator = getIsolatedWebAuthnEmulator();
         await addPasskey(user, user.csrf, user.cookie, secondEmulator);

         const upgraded = await upgradeToPrf(user, user);
         cleanupUser = upgraded;
         await expectListedPasskeys('/v1/user', [upgraded.credId], upgraded.csrf, upgraded.cookie);

         const removedLogin = await login(secondEmulator, {});
         expect(removedLogin.status).toBe(401);

         await recoverAccount3(upgraded, { keepSession: true });
      });

      it('completes with the challenge from a second PUT prfupgrade', async () => {
         const user = await registerUpgradable();

         const first = await putPrfUpgrade(user, user);
         expect(first.status).toBe(200);
         const second = await putPrfUpgrade(user, user);
         expect(second.status).toBe(200);

         const confirmRes = await postPrfUpgradeConfirm(user, await prfUpgradeConfirmBody(user, second.data.challenge));
         expect(confirmRes.status).toBe(200);

         await expectPrfLogin(user);
      });

      // T6, R9
      it('fails a second confirm and PUT prfupgrade after a completed upgrade', async () => {
         const user = await registerUpgradable();
         const putRes = await putPrfUpgrade(user, user);
         expect(putRes.status).toBe(200);
         const body = await prfUpgradeConfirmBody(user, putRes.data.challenge);

         const confirmRes = await postPrfUpgradeConfirm(user, body);
         expect(confirmRes.status).toBe(200);

         const repeatConfirm = await postPrfUpgradeConfirm(
            user,
            await prfUpgradeConfirmBody(user, putRes.data.challenge),
         );
         expect(repeatConfirm.status).toBe(400);

         const repeatPut = await putPrfUpgrade(user, user);
         expect(repeatPut.status).toBe(400);

         const userRes = await getJson('/v1/user', { 'x-csrf-token': user.csrf }, user.cookie);
         expect(userRes.status).toBe(200);
         expect(userRes.data.prf).toBe(true);
      });

      it('adds a PRF passkey after the upgrade and both passkeys sign in', async () => {
         const user = await registerUpgradable();
         const upgraded = await upgradeToPrf(user, user);

         const newEmulator = getIsolatedWebAuthnEmulator('hmac-secret-mc');
         await addPasskey(upgraded, upgraded.csrf, upgraded.cookie, newEmulator);

         await expectPrfLogin(upgraded, newEmulator);
         await expectPrfLogin(upgraded);
      });
   });

   describe('recovery words', () => {
      // T1
      it('upgrades with new recovery words', async () => {
         const user = await registerUpgradable();
         const newSecret = randomRecoverySecret(user.userId);

         const keyRes = await putRecoveryKey(user, user, newSecret);
         expect(keyRes.status).toBe(200);

         const session = await expectNoPrfLogin(user);
         const upgraded = await upgradeToPrf(user, session, newSecret);
         cleanupUser = upgraded;

         await recoverAccount3(upgraded, { keepSession: true });
      });

      // R3
      it('rejects a confirm after the recovery words change', async () => {
         const user = await registerUpgradable();
         const putRes = await putPrfUpgrade(user, user);
         expect(putRes.status).toBe(200);

         const newSecret = randomRecoverySecret(user.userId);
         const keyRes = await putRecoveryKey(user, user, newSecret);
         expect(keyRes.status).toBe(200);

         const confirmRes = await postPrfUpgradeConfirm(
            user,
            await prfUpgradeConfirmBody(user, putRes.data.challenge, { secret: newSecret }),
         );
         expect(confirmRes.status).toBe(401);

         await expectNoPrfLogin(user);
      });

      it('rejects a confirm signed with replaced recovery words', async () => {
         const user = await registerUpgradable();
         const keyRes = await putRecoveryKey(user, user, randomRecoverySecret(user.userId));
         expect(keyRes.status).toBe(200);

         const putRes = await putPrfUpgrade(user, user);
         expect(putRes.status).toBe(200);

         const confirmRes = await postPrfUpgradeConfirm(user, await prfUpgradeConfirmBody(user, putRes.data.challenge));
         expect(confirmRes.status).toBe(400);

         await expectNoPrfLogin(user);
      });
   });

   describe('interrupted', () => {
      // T2
      it('leaves a usable no-PRF account after PUT prfupgrade without a confirm', async () => {
         const user = await registerUpgradable();
         const secondEmulator = getIsolatedWebAuthnEmulator();
         await addPasskey(user, user.csrf, user.cookie, secondEmulator);

         const putRes = await putPrfUpgrade(user, user);
         expect(putRes.status).toBe(200);

         await expectNoPrfLogin(user);
         await expectNoPrfLogin(user, secondEmulator);
         await recoverAccount3(user, { keepSession: true });
      });

      // T3
      it('rejects reusing a challenge after a failed confirm, then completes with a new one', async () => {
         const user = await registerUpgradable();
         const putRes = await putPrfUpgrade(user, user);
         expect(putRes.status).toBe(200);
         const challenge = putRes.data.challenge;

         const wrongOp = await postPrfUpgradeConfirm(
            user,
            await prfUpgradeConfirmBody(user, challenge, { op: 'replace' }),
         );
         expect(wrongOp.status).toBe(400);

         const reused = await postPrfUpgradeConfirm(user, await prfUpgradeConfirmBody(user, challenge));
         expect(reused.status).toBe(400);

         const session = await expectNoPrfLogin(user);
         await upgradeToPrf(user, session);
      });

      // T5, R7
      it('completes after the other passkeys are deleted before the confirm', async () => {
         const user = await registerUpgradable();
         const secondCredId = await addPasskey(user, user.csrf, user.cookie, getIsolatedWebAuthnEmulator());

         const putRes = await putPrfUpgrade(user, user);
         expect(putRes.status).toBe(200);
         await expectPasskeyDeleted(secondCredId, user.csrf, user.cookie);

         const confirmRes = await postPrfUpgradeConfirm(user, await prfUpgradeConfirmBody(user, putRes.data.challenge));
         expect(confirmRes.status).toBe(200);

         await expectPrfLogin(user);
      });
   });

   describe('session changes', () => {
      // R10
      it('rejects a confirm after another sign-in with the same passkey', async () => {
         const user = await registerUpgradable();
         const putRes = await putPrfUpgrade(user, user);
         expect(putRes.status).toBe(200);
         const body = await prfUpgradeConfirmBody(user, putRes.data.challenge);

         const nextSession = await expectNoPrfLogin(user);

         const oldSessionConfirm = await postPrfUpgradeConfirm(user, body);
         expect(oldSessionConfirm.status).toBe(401);

         const nextSessionConfirm = await postPrfUpgradeConfirm(nextSession, body);
         expect(nextSessionConfirm.status).toBe(401);

         await expectNoPrfLogin(user);
      });

      // R1
      it('rejects a confirm after signing in with a different passkey', async () => {
         const user = await registerUpgradable();
         const secondEmulator = getIsolatedWebAuthnEmulator();
         const secondCredId = await addPasskey(user, user.csrf, user.cookie, secondEmulator);

         const putRes = await putPrfUpgrade(user, user);
         expect(putRes.status).toBe(200);
         const body = await prfUpgradeConfirmBody(user, putRes.data.challenge);

         const secondSession = await expectNoPrfLogin(user, secondEmulator);

         const oldSessionConfirm = await postPrfUpgradeConfirm(user, body);
         expect(oldSessionConfirm.status).toBe(401);

         const secondSessionConfirm = await postPrfUpgradeConfirm(secondSession, body);
         expect(secondSessionConfirm.status).toBe(400);

         await expectListedPasskeys('/v1/user', [user.credId, secondCredId], secondSession.csrf, secondSession.cookie);
         await expectNoPrfLogin(user);
      });

      // R2
      it('rejects a confirm after sign-out', async () => {
         const user = await registerUpgradable();
         const putRes = await putPrfUpgrade(user, user);
         expect(putRes.status).toBe(200);

         const signOut = await deleteJson('/v1/session', { 'x-csrf-token': user.csrf }, user.cookie);
         expect(signOut.status).toBe(200);

         const confirmRes = await postPrfUpgradeConfirm(user, await prfUpgradeConfirmBody(user, putRes.data.challenge));
         expect(confirmRes.status).toBe(401);

         await expectNoPrfLogin(user);
      });

      // R4
      it('rejects a confirm after recovery starts and recovery still completes', async () => {
         const user = await registerUpgradable();
         const putRes = await putPrfUpgrade(user, user);
         expect(putRes.status).toBe(200);
         const body = await prfUpgradeConfirmBody(user, putRes.data.challenge);

         const { startRes, recoveredUserCred } = await startRecovery3(user);

         const confirmRes = await postPrfUpgradeConfirm(user, body);
         expect(confirmRes.status).toBe(401);

         await finishRecovery3(user, startRes, recoveredUserCred);
         await expectNoPrfLogin(user);
      });
   });

   describe('rejected requests', () => {
      it('rejects PUT prfupgrade for a passkey other than the signed-in one', async () => {
         const user = await registerUpgradable();
         const secondCredId = await addPasskey(user, user.csrf, user.cookie, getIsolatedWebAuthnEmulator());

         const putRes = await putPrfUpgrade(user, user, { credentialId: secondCredId });
         expect(putRes.status).toBe(400);
      });

      it('rejects PUT prfupgrade on a PRF account', async () => {
         const user = await registerTestUser(true);
         cleanupUser = user;

         const userRes = await getJson('/v1/user', { 'x-csrf-token': user.csrf }, user.cookie);
         expect(userRes.status).toBe(200);
         expect(userRes.data.prf).toBe(true);

         const putRes = await putPrfUpgrade(user, user);
         expect(putRes.status).toBe(400);
      });

      it('rejects a confirm with an unknown challenge', async () => {
         const user = await registerUpgradable();
         const putRes = await putPrfUpgrade(user, user);
         expect(putRes.status).toBe(200);

         const unknown = bytesToBase64(getRandom(api.CHALLENGE_BYTES));
         const unknownConfirm = await postPrfUpgradeConfirm(user, await prfUpgradeConfirmBody(user, unknown));
         expect(unknownConfirm.status).toBe(400);

         const confirmRes = await postPrfUpgradeConfirm(user, await prfUpgradeConfirmBody(user, putRes.data.challenge));
         expect(confirmRes.status).toBe(200);
      });

      it('rejects malformed encrypted userCred values', async () => {
         const user = await registerUpgradable();
         const shortEnc = bytesToBase64(getRandom(MIN_ENC_BYTES - 1));

         const putRes = await putPrfUpgrade(user, user);
         expect(putRes.status).toBe(200);

         const shortConfirm = await postPrfUpgradeConfirm(
            user,
            await prfUpgradeConfirmBody(user, putRes.data.challenge, { recoveryUserCredEnc: shortEnc }),
         );
         expect(shortConfirm.status).toBe(400);

         const shortPut = await putPrfUpgrade(user, user, { passkeyUserCredEnc: shortEnc });
         expect(shortPut.status).toBe(400);

         const repeatShortConfirm = await postPrfUpgradeConfirm(
            user,
            await prfUpgradeConfirmBody(user, putRes.data.challenge, { recoveryUserCredEnc: shortEnc }),
         );
         expect(repeatShortConfirm.status).toBe(400);
      });

      it('rejects the first challenge after a second PUT prfupgrade with a different encrypted userCred', async () => {
         const user = await registerUpgradable();

         const first = await putPrfUpgrade(user, user);
         expect(first.status).toBe(200);
         const second = await putPrfUpgrade(user, user);
         expect(second.status).toBe(200);

         const confirmRes = await postPrfUpgradeConfirm(user, await prfUpgradeConfirmBody(user, first.data.challenge));
         expect(confirmRes.status).toBe(401);
      });
   });

   describe('races', () => {
      // R5
      it('accepts only one of two concurrent confirms', async () => {
         const user = await registerUpgradable();

         // The same encrypted userCred in both PUTs leaves both challenges usable
         const passkeyUserCredEnc = await prfEncrypt(
            base64ToBytes(user.userCred),
            user.prfOutput!.slice(0),
            user.userId,
         );
         const challenges: string[] = [];
         for (let i = 0; i < 2; i++) {
            const putRes = await putPrfUpgrade(user, user, { passkeyUserCredEnc });
            expect(putRes.status).toBe(200);
            challenges.push(putRes.data.challenge);
         }

         const bodies = await Promise.all(challenges.map((challenge) => prfUpgradeConfirmBody(user, challenge)));
         const results = await Promise.all(bodies.map((body) => postPrfUpgradeConfirm(user, body)));
         expect(results.map((res) => res.status).sort()).toEqual([200, 400]);

         await expectPrfLogin(user);
      });
   });

   describe('after the upgrade', () => {
      // R6
      it('rejects adding a passkey without an encrypted userCred', async () => {
         const user = await registerUpgradable();
         const upgraded = await upgradeToPrf(user, user);

         const optsRes = await getJson('/v1/passkeys/options', { 'x-csrf-token': upgraded.csrf }, upgraded.cookie);
         expect(optsRes.status).toBe(200);

         // The no-PRF view of the account sends no encrypted userCred
         const { attestation } = await registerNewCredential(user, optsRes.data);
         const body = api.makeAddVerifyRequest(attestation as api.RegistrationFields, {
            challenge: optsRes.data.challenge,
         });
         const verifyRes = await postJson(
            '/v1/passkeys/verify',
            body,
            { 'x-csrf-token': upgraded.csrf },
            upgraded.cookie,
         );
         expect(verifyRes.status).toBe(400);
      });

      // R8
      it('rejects new recovery words without an encrypted userCred', async () => {
         const user = await registerUpgradable();
         const upgraded = await upgradeToPrf(user, user);
         const newSecret = randomRecoverySecret(user.userId);

         // The no-PRF view of the account sends no encrypted userCred
         const withoutEnc = await putRecoveryKey(user, upgraded, newSecret);
         expect(withoutEnc.status).toBe(400);

         const withEnc = await putRecoveryKey(upgraded, upgraded, newSecret);
         expect(withEnc.status).toBe(200);
      });
   });
});
