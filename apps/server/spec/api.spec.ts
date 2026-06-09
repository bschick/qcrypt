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
import { SESSION_TIMEOUT_SEC } from '@qcrypt/api';
import { WebAuthnEmulator } from "nid-webauthn-emulator";
import {
   registerTestUser,
   deleteJson,
   getJson,
   patchJson,
   postJson,
   setSessionUserCred,
   RP_ORIGIN
} from "./common";
import jwtPkg from 'jsonwebtoken';
import { randomBytes } from "node:crypto";

// postAuthVerify looks up the credential via the Authenticators GSI (credentialid-index),
// which is eventually consistent. When this suite registers a user and then immediately logs in,
// the GSI may not yet reflect the new Authenticator record. Retry to give the GSI time to catch
// up before failing. Not needed for normal clients because the calls are split by user actions
async function postAuthVerifyWithRetry(
   body: Record<string, unknown>,
   cookie: string,
): ReturnType<typeof postJson> {
   const maxAttempts = 3;
   let res = await postJson(`/v1/auth/verify`, body, {}, cookie);

   for (let attempt = 2; res.status !== 200 && attempt <= maxAttempts; attempt++) {
      await new Promise((r) => setTimeout(r, 10000));
      res = await postJson(`/v1/auth/verify`, body, {}, cookie);
   }
   return res;
}

// ----- Test Suite -----

describe("QuickCrypt WebAuthn Full API Suite", () => {

   // Shared state
   const testUser = `PWTesty_${Date.now()}`;
   let userId: string;
   let credId: string; // pkId
   let sessCookie: string = "";
   let csrfToken: string = "";
   let userCred: string;
   let emulator: WebAuthnEmulator;

   beforeAll(async () => {
      ({ userId, userCred, cookie: sessCookie, csrf: csrfToken, credId, emulator } =
         await registerTestUser(testUser));
      setSessionUserCred(userCred, userId);
   });

   describe("User & Session Management", () => {
      it("should fetch current session details", async () => {
         const res = await getJson(
            `/v1/session`,
            { "x-csrf-token": csrfToken },
            sessCookie,
         );
         expect(res.status).toBe(200);
         expect(res.data.verified).toBe(true);
         expect(res.data.userId).toBe(userId);
         expect(res.data.userName).toBe(testUser);
         expect(res.data.hasRecoveryId).toBeTruthy();
         expect(res.data.authenticators.length).toBe(1);
         expect(res.data.csrf).toBeDefined();
         expect(res.data.userCred).toBeUndefined();
         // Update CSRF in case it rotated (though usually static per session)
         if (res.data.csrf) {
            csrfToken = res.data.csrf;
         }
      });

      it("should fetch user info", async () => {
         const res = await getJson(
            `/v1/user`,
            { "x-csrf-token": csrfToken },
            sessCookie,
         );
         expect(res.status).toBe(200);
         expect(res.data.userName).toBe(testUser);
      });

      it("should update username (PATCH)", async () => {
         const newName = `${testUser}_upd`;
         let res = await patchJson(
            `/v1/user`,
            { userName: newName },
            { "x-csrf-token": csrfToken },
            sessCookie
         );
         expect(res.status).toBe(200);
         expect(res.data.userName).toBe(newName);

         // put it back
         res = await patchJson(
            `/v1/user`,
            { userName: testUser },
            { "x-csrf-token": csrfToken },
            sessCookie
         );
         expect(res.status).toBe(200);
         expect(res.data.userName).toBe(testUser);
      });

      it("should sanitize and bound username on PATCH", async () => {
         // Markup is stripped, leaving the text content
         let res = await patchJson(
            `/v1/user`,
            { userName: "<script>all</script> good" },
            { "x-csrf-token": csrfToken },
            sessCookie
         );
         expect(res.status).toBe(200);
         expect(res.data.userName).toBe("all good");

         // Over-length name is rejected
         res = await patchJson(
            `/v1/user`,
            { userName: "as0df9ufwefowifljop20w934fsldfklsdjflasdfkasoifjw0f9jw9f" },
            { "x-csrf-token": csrfToken },
            sessCookie
         );
         expect(res.status).toBe(400);

         res = await patchJson(
            `/v1/user`,
            { userName: testUser },
            { "x-csrf-token": csrfToken },
            sessCookie
         );
         expect(res.status).toBe(200);
         expect(res.data.userName).toBe(testUser);
      });

      it("should sanitize and validate passkey description on PATCH", async () => {
         // Markup is stripped from the description
         let res = await patchJson(
            `/v1/passkeys/${credId}`,
            { description: "567345 <b>5 > <a a" },
            { "x-csrf-token": csrfToken },
            sessCookie
         );
         expect(res.status).toBe(200);
         expect(res.data.authenticators[0].description).toBe("567345 5");

         // Non-string description is rejected
         res = await patchJson(
            `/v1/passkeys/${credId}`,
            { description: 5673455 },
            { "x-csrf-token": csrfToken },
            sessCookie
         );
         expect(res.status).toBe(400);
      });

      it("should add and remove passkey", async () => {

         // Get passkey registration options
         const optsRes = await getJson(
            `/v1/passkeys/options`,
            { "x-csrf-token": csrfToken },
            sessCookie,
         );
         expect(optsRes.status).toBe(200);

         // Sign Challenge (Note: We give the emulator a fake user.id so it doesn't overwrite our primary test credential)
         const attestation = emulator.createJSON(RP_ORIGIN, {
            ...optsRes.data,
            user: { ...optsRes.data.user, id: `${userId}_2` },
            challenge: optsRes.data.challenge,
            excludeCredentials: [],
         });

         // Verify passkey *with wrong userId* (it should just be ignored)
         const verifyRes = await postJson(
            `/v1/passkeys/verify`,
            { ...attestation, userId: 'De9RClwTFhA6aChuBzDK2g', challenge: optsRes.data.challenge },
            { "x-csrf-token": csrfToken },
            sessCookie,
         );


         expect(verifyRes.status).toBe(200);
         expect(verifyRes.data.verified).toBe(true);
         expect(verifyRes.data.userId).toBe(userId);

         const delRes = await deleteJson(
            `/v1/passkeys/${attestation.id}`,
            { "x-csrf-token": csrfToken },
            sessCookie,
         );
         expect(delRes.status).toBe(200);

      });

      it("should 404 fetching an unknown user", async () => {
         let res = await getJson(`/v1/user`, { "x-csrf-token": csrfToken }, sessCookie);
         expect(res.status).toBe(200);

         res = await getJson(
            `/v1/users/42ebNajPIp3leX4K4a0qND`,
            { "x-csrf-token": csrfToken },
            sessCookie,
         );
         expect(res.status).toBe(404);
      });

      it("should reject deleting an unknown passkey", async () => {
         let res = await getJson(`/v1/user`, { "x-csrf-token": csrfToken }, sessCookie);
         expect(res.status).toBe(200);

         res = await deleteJson(
            `/v1/passkeys/nfVho8Z8p3oEpOl8yvbh40`,
            { "x-csrf-token": csrfToken },
            sessCookie,
         );
         expect(res.status).toBe(400);
      });

      it("should reject patching an unknown passkey", async () => {
         let res = await patchJson(
            `/v1/passkeys/${credId}`,
            { description: "valid description" },
            { "x-csrf-token": csrfToken },
            sessCookie,
         );
         expect(res.status).toBe(200);

         res = await patchJson(
            `/v1/passkeys/nfVho8Z8p3oEpOl8yvbh40`,
            { description: "ignored" },
            { "x-csrf-token": csrfToken },
            sessCookie,
         );
         expect(res.status).toBe(400);
      });

      it("should 404 fetching session for an unknown user", async () => {
         let res = await getJson(`/v1/session`, { "x-csrf-token": csrfToken }, sessCookie);
         expect(res.status).toBe(200);

         res = await getJson(
            `/v1/users/42ebNajPIp3leX4K4a0qND/session`,
            { "x-csrf-token": csrfToken },
            sessCookie,
         );
         expect(res.status).toBe(404);
      });

      it("should 404 deleting session for an unknown user", async () => {
         let res = await getJson(`/v1/session`, { "x-csrf-token": csrfToken }, sessCookie);
         expect(res.status).toBe(200);

         res = await deleteJson(
            `/v1/users/42ebNajPIp3leX4K4a0qND/session`,
            { "x-csrf-token": csrfToken },
            sessCookie,
         );
         expect(res.status).toBe(404);
      });
   });

   describe("Logout & Re-Login", () => {
      it("should logout (DELETE session)", async () => {
         let res = await deleteJson(
            `/v1/session`,
            { "x-csrf-token": csrfToken },
            sessCookie,
         );
         expect(res.status).toBe(200);
         // Every authorized operation with the now-stale cookie is rejected.

         res = await patchJson(
            `/v1/passkeys/${credId}`,
            { description: "after logout" },
            { "x-csrf-token": csrfToken },
            sessCookie,
         );
         expect(res.status).toBe(401);

         res = await patchJson(
            `/v1/user`,
            { userName: testUser },
            { "x-csrf-token": csrfToken },
            sessCookie,
         );
         expect(res.status).toBe(401);

         res = await deleteJson(
            `/v1/session`,
            { "x-csrf-token": csrfToken },
            sessCookie,
         );
         expect(res.status).toBe(401);

         res = await getJson(
            `/v1/session`,
            { "x-csrf-token": csrfToken },
            sessCookie,
         );
         expect(res.status).toBe(401);

         res = await getJson(
            `/v1/user`,
            { "x-csrf-token": csrfToken },
            sessCookie, // Sending old cookie
         );

         sessCookie = '';
         expect(res.status).toBe(401); // Expect Unauthorized

         res = await getJson(
            `/v1/user`,
            { "x-csrf-token": csrfToken },
            sessCookie, // no cookie
         );
         expect(res.status).toBe(401); // Expect Unauthorized

         // Get Auth Options
         const optsRes = await postJson(
            `/v1/auth/options`,
            { userId },
            {},
            "",
         );
         expect(optsRes.status).toBe(200);

         // Sign Challenge
         const assertion = emulator.getJSON(RP_ORIGIN, {
            ...optsRes.data,
            challenge: optsRes.data.challenge,
         });

         // Verify Auth
         const verifyRes = await postAuthVerifyWithRetry(
            { ...assertion, challenge: optsRes.data.challenge },
            sessCookie,
         );

         expect(verifyRes.status).toBe(200);
         expect(verifyRes.data.verified).toBe(true);
         expect(verifyRes.cookie).toBeTruthy();
         expect(verifyRes.data.userId).toBe(userId);

         // Restore session state
         sessCookie = verifyRes.cookie;
         csrfToken = verifyRes.data.csrf;

         // The restored session works for a subsequent authorized read.
         const restored = await getJson(
            `/v1/user`,
            { "x-csrf-token": csrfToken },
            sessCookie,
         );
         expect(restored.status).toBe(200);
         expect(restored.data.verified).toBeTruthy();
         expect(restored.data.userName).toBe(testUser);
         expect(restored.data.userId).toBe(userId);
         expect(restored.data.hasRecoveryId).toBeTruthy();
         expect(restored.data.authenticators.length).toBe(1);
      });

      it("should login without userId in options", async () => {
         let res = await deleteJson(
            `/v1/session`,
            { "x-csrf-token": csrfToken },
            sessCookie,
         );
         expect(res.status).toBe(200);
         // Cookie should be invalidated/expired now

         res = await getJson(
            `/v1/user`,
            { "x-csrf-token": csrfToken },
            sessCookie, // Sending old cookie
         );

         expect(res.status).toBe(401); // Expect Unauthorized

         // Get Auth Options
         const optsRes = await postJson(
            `/v1/auth/options`,
            {},
            {},
            "",
         );
         expect(optsRes.status).toBe(200);

         // Sign Challenge
         const assertion = emulator.getJSON(RP_ORIGIN, {
            ...optsRes.data,
            challenge: optsRes.data.challenge,
         });

         // Verify Auth
         const verifyRes = await postAuthVerifyWithRetry(
            { ...assertion, challenge: optsRes.data.challenge },
            sessCookie,
         );

         expect(verifyRes.status).toBe(200);
         expect(verifyRes.data.verified).toBe(true);
         expect(verifyRes.cookie).toBeTruthy();
         expect(verifyRes.data.userId).toBe(userId);

         // Restore session state
         sessCookie = verifyRes.cookie;
         csrfToken = verifyRes.data.csrf;
      });
   });

   describe("Negative Tests", () => {
      it("should reject update user without cookie", async () => {
         let res = await getJson(`/v1/user`, { "x-csrf-token": csrfToken }, sessCookie);
         expect(res.status).toBe(200);

         res = await patchJson(
            `/v1/user`,
            { userName: "hacker" },
            { "x-csrf-token": csrfToken },
            "", // No cookies
         );
         expect(res.status).toBeGreaterThanOrEqual(401);
      });

      it("should reject update user without csrf", async () => {
         let res = await getJson(`/v1/user`, { "x-csrf-token": csrfToken }, sessCookie);
         expect(res.status).toBe(200);

         res = await patchJson(
            `/v1/user`,
            { userName: "hacker" },
            {}, // No csrf
            sessCookie,
         );
         expect(res.status).toBeGreaterThanOrEqual(401);
      });


      it("should reject manipulated cookie", async () => {
         let res = await getJson(`/v1/user`, { "x-csrf-token": csrfToken }, sessCookie);
         expect(res.status).toBe(200);

         const offset = 34;
         const badCookie = sessCookie.substring(0, offset) + (sessCookie[offset] === 'a' ? 'b' : 'a') + sessCookie.substring(offset + 1);

         res = await deleteJson(
            `/v1/passkeys/${credId}`,
            { "x-csrf-token": csrfToken },
            badCookie,
         );

         expect(res.status).toEqual(401);
      });

      it("should reject resigned cookie", async () => {
         let res = await getJson(`/v1/user`, { "x-csrf-token": csrfToken }, sessCookie);
         expect(res.status).toBe(200);

         const match = /^__Host-JWT=(.+)$/.exec(sessCookie);

         expect(match).toBeDefined();
         expect(match![1]).toBeDefined();
         const oldToken = match![1];

         const jwtPayload = jwtPkg.decode(
            oldToken, {
            json: true,
            complete: false
         });
         expect(jwtPayload).toBeDefined();

         const newPayload = {
            pkId: jwtPayload!.pkId,
            userId: jwtPayload!.userId
         };
         const jwtKey = randomBytes(32);
         const expiresIn = SESSION_TIMEOUT_SEC;

         const newToken = jwtPkg.sign(
            newPayload,
            jwtKey, {
            algorithm: 'HS512',
            expiresIn: expiresIn,
            issuer: 'quickcrypt'
         });

         const badCookie = `__Host-JWT=${newToken}`;

         res = await deleteJson(
            `/v1/passkeys/${credId}`,
            { "x-csrf-token": csrfToken },
            badCookie,
         );

         expect(res.status).toEqual(401);
      });

      it("should reject manipulated csrf", async () => {
         let res = await getJson(`/v1/user`, { "x-csrf-token": csrfToken }, sessCookie);
         expect(res.status).toBe(200);

         const offset = 6;
         const badCsrf = csrfToken.substring(0, offset) + (csrfToken[offset] === 'a' ? 'b' : 'a') + csrfToken.substring(offset + 1);

         res = await deleteJson(
            `/v1/passkeys/${credId}`,
            { "x-csrf-token": badCsrf },
            sessCookie,
         );

         expect(res.status).toEqual(401);
      });

      it("should reject missing or wrong csrf on reads and deletes", async () => {
         const wrongCsrf = "uajbCCy0AeBW5WDEqbR9viY12HaQOiKlJcNSG8yaGT0";

         let res = await getJson(`/v1/user`, { "x-csrf-token": csrfToken }, sessCookie);
         expect(res.status).toBe(200);

         res = await getJson(`/v1/user`, {}, sessCookie);
         expect(res.status).toBe(401);

         res = await deleteJson(`/v1/passkeys/${credId}`, {}, sessCookie);
         expect(res.status).toBe(401);

         res = await getJson(`/v1/user`, { "x-csrf-token": wrongCsrf }, sessCookie);
         expect(res.status).toBe(401);

         res = await deleteJson(`/v1/passkeys/${credId}`, { "x-csrf-token": wrongCsrf }, sessCookie);
         expect(res.status).toBe(401);
      });

      it("should reject auth/verify when challenge userId does not match credential owner", async () => {
         const attackerName = `PWTesty_atk_${Date.now()}`;
         let attackerUserId: string | undefined;
         let attackerCredId: string | undefined;
         let attackerCookie = "";
         let attackerCsrf = "";
         let attackerUserCred: string | undefined;

         try {
            const attacker = await registerTestUser(attackerName);
            attackerUserId = attacker.userId;
            attackerCredId = attacker.credId;
            attackerCookie = attacker.cookie;
            attackerCsrf = attacker.csrf;
            attackerUserCred = attacker.userCred;
            const attackerEmulator = attacker.emulator;

            // Self-login once so the credentialid-index GSI is certain to be consistent before the bypass attempt
            const selfOpts = await postJson(`/v1/auth/options`, { userId: attackerUserId }, {}, "");
            expect(selfOpts.status).toBe(200);
            const selfAssertion = attackerEmulator.getJSON(RP_ORIGIN, {
               ...selfOpts.data,
               challenge: selfOpts.data.challenge,
            });
            const selfVerify = await postAuthVerifyWithRetry(
               { ...selfAssertion, challenge: selfOpts.data.challenge },
               "",
            );
            expect(selfVerify.status).toBe(200);
            expect(selfVerify.data.userId).toBe(attackerUserId);
            if (selfVerify.cookie) {
               attackerCookie = selfVerify.cookie;
               attackerCsrf = selfVerify.data.csrf;
            }

            // Request an auth challenge bound to the victim (beforeAll user)
            const optsRes = await postJson(`/v1/auth/options`, { userId }, {}, "");
            expect(optsRes.status).toBe(200);

            // Set allowCredentials to be sure the emulator signs with the attacker's key
            const assertion = attackerEmulator.getJSON(RP_ORIGIN, {
               ...optsRes.data,
               allowCredentials: [{ id: attackerCredId, type: 'public-key' }],
               challenge: optsRes.data.challenge,
            });

            const bypass = await postJson(
               `/v1/auth/verify`,
               { ...assertion, challenge: optsRes.data.challenge },
               {},
               "",
            );

            expect(bypass.status).toBe(401);
            expect(bypass.rawText).toBe('not authorized');

            // Same attack, but also forge userHandle to the victim. The challenge-binding
            // check should still fires first since the credId resolves to the attacker.
            const optsRes2 = await postJson(`/v1/auth/options`, { userId }, {}, "");
            expect(optsRes2.status).toBe(200);
            const assertion2 = attackerEmulator.getJSON(RP_ORIGIN, {
               ...optsRes2.data,
               allowCredentials: [{ id: attackerCredId, type: 'public-key' }],
               challenge: optsRes2.data.challenge,
            });
            const bypass2 = await postJson(
               `/v1/auth/verify`,
               {
                  ...assertion2,
                  response: { ...assertion2.response, userHandle: userId },
                  challenge: optsRes2.data.challenge,
               },
               {},
               "",
            );
            expect(bypass2.status).toBe(401);
            expect(bypass2.rawText).toBe('not authorized');
         } finally {
            if (attackerCredId && attackerCookie) {
               setSessionUserCred(attackerUserCred, attackerUserId);
               await deleteJson(
                  `/v1/passkeys/${attackerCredId}`,
                  { "x-csrf-token": attackerCsrf },
                  attackerCookie,
               );
               setSessionUserCred(userCred, userId);
            }
         }
      });
   });

   afterAll(async () => {
      if (!userId || !credId) {
         return;
      }

      const res = await deleteJson(
         `/v1/passkeys/${credId}`,
         { "x-csrf-token": csrfToken },
         sessCookie,
      );

      expect(res.status).toBe(200);

      // Confirm user is gone
      // Try to fetch session or user info, should fail
      const checkRes = await getJson(`/v1/user`, {}, sessCookie);
      expect(checkRes.status).toBeGreaterThanOrEqual(400);
   });
});

