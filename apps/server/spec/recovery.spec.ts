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

import { describe, it, beforeAll, beforeEach, afterAll, expect } from "vitest";
import { cryptoReady, bytesToBase64, getRandom } from "@qcrypt/crypto";
import * as cc from "@qcrypt/crypto/consts";
import { getRecoveryPubKey, signRecoveryProof, recoverySecret, RECOVERYID_BYTES, CHALLENGE_BYTES } from "@qcrypt/api";
import {
   postJson,
   putJson,
   deleteJson,
   registerTestUser,
   setSessionUserCred,
   RP_ORIGIN,
} from "./common";

type TestUser = Awaited<ReturnType<typeof registerTestUser>>;

async function issueChallenge(userId: string): Promise<string> {
   const res = await postJson("/v1/recover2/challenge", { userId }, {}, "");
   expect(res.status).toBe(200);
   return res.data.challenge;
}

type RecoverySession = {
   userCred: string;
   cookie: string;
   csrf: string;
   credId: string;
};

// Drives a full account recovery: authorize recover2 with a challenge-signed proof, or
// with the raw recovery id for legacy accounts, then finish the registration the recovery
// starts so the account ends with a passkey. Returns the resulting session; unless
// keepSession is set the new passkey is deleted before returning.
async function recoverAccount(
   testUser: TestUser,
   opts: { legacy?: boolean; keepSession?: boolean } = {}
): Promise<RecoverySession> {
   let recoverBody: Record<string, any>;
   // BACKWARD COMPAT: pre-recovery-words accounts authorize with the raw recovery id
   // instead of a challenge-signed proof.
   if (opts.legacy) {
      recoverBody = { userId: testUser.userId, recoveryId: bytesToBase64(testUser.recoveryId) };
   } else {
      const challenge = await issueChallenge(testUser.userId);
      const signature = bytesToBase64(signRecoveryProof(testUser.recoverySecret, testUser.userId, challenge));
      recoverBody = { userId: testUser.userId, challenge, signature };
   }

   const recoverRes = await postJson("/v1/recover2", recoverBody, {}, "");
   expect(recoverRes.status).toBe(200);
   expect(recoverRes.data.user.id).toBe(testUser.userId);
   expect(recoverRes.data.challenge).toBeDefined();

   const attestation = testUser.emulator.createJSON(RP_ORIGIN, {
      ...recoverRes.data,
      user: { ...recoverRes.data.user, id: testUser.userId },
      challenge: recoverRes.data.challenge,
   });
   const verifyRes = await postJson(
      "/v1/reg/verify?usercred=true",
      { ...attestation, userId: testUser.userId, challenge: recoverRes.data.challenge },
      {},
      ""
   );
   expect(verifyRes.status).toBe(200);
   expect(verifyRes.data.verified).toBe(true);
   expect(verifyRes.data.pkId).toBeDefined();
   expect(verifyRes.data.csrf).toBeDefined();
   // userCred is preserved across recovery.
   expect(verifyRes.data.userCred).toBe(testUser.userCred);

   const session: RecoverySession = {
      userCred: testUser.userCred,
      cookie: verifyRes.cookie,
      csrf: verifyRes.data.csrf,
      credId: verifyRes.data.pkId,
   };

   if (!opts.keepSession) {
      setSessionUserCred(session.userCred, testUser.userId);
      await deleteJson(`/v1/passkeys/${session.credId}`, { "x-csrf-token": session.csrf }, session.cookie);
   }

   return session;
}

describe("recovery proof", () => {
   let user: TestUser;

   beforeAll(async () => {
      await cryptoReady();
      user = await registerTestUser(`PWTesty_rec_${Date.now()}`);
   });

   // Tests run in arbitrary order and the proof signer is global, so re-point it at the
   // shared user before each test; recovery tests repoint it at their own user.
   beforeEach(() => {
      setSessionUserCred(user.userCred, user.userId);
   });

   afterAll(async () => {
      if (user?.cookie && user?.credId) {
         setSessionUserCred(user.userCred, user.userId);
         await deleteJson(`/v1/passkeys/${user.credId}`, { "x-csrf-token": user.csrf }, user.cookie);
      }
      setSessionUserCred(undefined);
   });

   it("issues a challenge for a valid userId", async () => {
      const challenge = await issueChallenge(user.userId);
      expect(typeof challenge).toBe("string");
      expect(Buffer.from(challenge, "base64url").length).toBe(CHALLENGE_BYTES);
   });

   it("issues a challenge for an unknown user", async () => {
      // No account lookup happens here, so the endpoint cannot be used to probe for users.
      const challenge = await issueChallenge(bytesToBase64(getRandom(cc.USERID_BYTES)));
      expect(typeof challenge).toBe("string");
   });

   it("rejects a challenge request with a malformed userId", async () => {
      const res = await postJson("/v1/recover2/challenge", { userId: "AAAA" }, {}, "");
      expect(res.status).toBe(400);
   });

   it("rejects a wrong signature", async () => {
      const challenge = await issueChallenge(user.userId);
      const wrongSecret = recoverySecret(getRandom(RECOVERYID_BYTES), user.userId);
      const signature = bytesToBase64(signRecoveryProof(wrongSecret, user.userId, challenge));
      const res = await postJson("/v1/recover2", { userId: user.userId, challenge, signature }, {}, "");
      expect(res.status).toBe(401);
   });

   it("rejects a never-issued challenge", async () => {
      const challenge = bytesToBase64(getRandom(CHALLENGE_BYTES));
      const signature = bytesToBase64(signRecoveryProof(user.recoverySecret, user.userId, challenge));
      const res = await postJson("/v1/recover2", { userId: user.userId, challenge, signature }, {}, "");
      expect(res.status).toBe(401);
   });

   it("rejects a tampered challenge", async () => {
      const challenge = await issueChallenge(user.userId);
      const tampered = (challenge[0] === "A" ? "B" : "A") + challenge.slice(1);
      const signature = bytesToBase64(signRecoveryProof(user.recoverySecret, user.userId, tampered));
      const res = await postJson("/v1/recover2", { userId: user.userId, challenge: tampered, signature }, {}, "");
      expect(res.status).toBe(401);
   });

   it("rejects a challenge bound to a different userId", async () => {
      const otherUserId = bytesToBase64(getRandom(cc.USERID_BYTES));
      const challenge = await issueChallenge(otherUserId);
      const signature = bytesToBase64(signRecoveryProof(user.recoverySecret, user.userId, challenge));
      const res = await postJson("/v1/recover2", { userId: user.userId, challenge, signature }, {}, "");
      expect(res.status).toBe(401);
   });

   it("rejects a recover2 request missing any recovery proof", async () => {
      const res = await postJson("/v1/recover2", { userId: user.userId }, {}, "");
      expect(res.status).toBe(400);
   });

   it("updates the recovery public key with the current key", async () => {
      const recoveryPubKey = bytesToBase64(getRecoveryPubKey(user.recoverySecret));
      const res = await putJson("/v1/recover2/key", { recoveryPubKey }, { "x-csrf-token": user.csrf }, user.cookie);
      expect(res.status).toBe(200);
   });

   it("updates the recovery public key with a new key", async () => {
      const newPubKey = bytesToBase64(getRecoveryPubKey(recoverySecret(getRandom(RECOVERYID_BYTES), user.userId)));
      const res = await putJson("/v1/recover2/key", { recoveryPubKey: newPubKey }, { "x-csrf-token": user.csrf }, user.cookie);
      expect(res.status).toBe(200);
   });

   it("rejects a recovery public key of the wrong length", async () => {
      const full = getRecoveryPubKey(user.recoverySecret);
      const shortKey = bytesToBase64(full.slice(0, full.length - 1));
      const res = await putJson("/v1/recover2/key", { recoveryPubKey: shortKey }, { "x-csrf-token": user.csrf }, user.cookie);
      expect(res.status).toBe(400);
   });

   it("rejects an empty recovery public key", async () => {
      const res = await putJson("/v1/recover2/key", { recoveryPubKey: "" }, { "x-csrf-token": user.csrf }, user.cookie);
      expect(res.status).toBe(400);
   });

   it("rejects a recover2/key update without a session", async () => {
      const recoveryPubKey = bytesToBase64(getRecoveryPubKey(user.recoverySecret));
      const res = await putJson("/v1/recover2/key", { recoveryPubKey }, {}, "");
      expect(res.status).toBe(401);
   });

   // Recovery wipes all passkeys, so these run against their own throwaway users.
   it("account recovery succeeds", async () => {
      const recoverUser = await registerTestUser(`PWTesty_recok_${Date.now()}`);
      await recoverAccount(recoverUser);
   });

   it("account recovery succeeds for a server-provisioned user", async () => {
      // BACKWARD COMPAT: legacy accounts whose recovery key the server generated.
      const recoverUser = await registerTestUser(`PWTesty_recbc_${Date.now()}`, { serverRecovery: true });
      await recoverAccount(recoverUser, { legacy: true });
   });

   // Replacing recovery words rotates the recovery key, which must retire the prior one.
   it("rejects the previous recovery key after it is replaced", async () => {
      const recoverUser = await registerTestUser(`PWTesty_regen_${Date.now()}`);

      // The original key recovers the account before it is replaced.
      const session = await recoverAccount(recoverUser, { keepSession: true });

      const newSecret = recoverySecret(getRandom(RECOVERYID_BYTES), recoverUser.userId);
      setSessionUserCred(session.userCred, recoverUser.userId);
      const keyRes = await putJson(
         "/v1/recover2/key",
         { recoveryPubKey: bytesToBase64(getRecoveryPubKey(newSecret)) },
         { "x-csrf-token": session.csrf },
         session.cookie
      );
      expect(keyRes.status).toBe(200);

      // The original key no longer recovers the account.
      const challenge = await issueChallenge(recoverUser.userId);
      const signature = bytesToBase64(signRecoveryProof(recoverUser.recoverySecret, recoverUser.userId, challenge));
      const staleRes = await postJson("/v1/recover2", { userId: recoverUser.userId, challenge, signature }, {}, "");
      expect(staleRes.status).toBe(401);

      // The replacement key recovers it.
      await recoverAccount({ ...recoverUser, recoverySecret: newSecret });
   });

   it("rejects a previous recovery id after the key is replaced", async () => {
      // BACKWARD COMPAT: a server-provisioned account starts out recoverable with a raw recovery id.
      const recoverUser = await registerTestUser(`PWTesty_regenbc_${Date.now()}`, { serverRecovery: true });

      // The original recovery id recovers the account before the key is replaced.
      const session = await recoverAccount(recoverUser, { legacy: true, keepSession: true });

      const newSecret = recoverySecret(getRandom(RECOVERYID_BYTES), recoverUser.userId);
      setSessionUserCred(session.userCred, recoverUser.userId);
      const keyRes = await putJson(
         "/v1/recover2/key",
         { recoveryPubKey: bytesToBase64(getRecoveryPubKey(newSecret)) },
         { "x-csrf-token": session.csrf },
         session.cookie
      );
      expect(keyRes.status).toBe(200);

      // The original recovery id no longer recovers the account.
      const staleRes = await postJson(
         "/v1/recover2",
         { userId: recoverUser.userId, recoveryId: bytesToBase64(recoverUser.recoveryId) },
         {},
         ""
      );
      expect(staleRes.status).toBe(401);

      // The replacement key recovers it.
      await recoverAccount({ ...recoverUser, recoverySecret: newSecret });
   });
});
