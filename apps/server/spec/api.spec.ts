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
import { WebAuthnEmulator } from "nid-webauthn-emulator";
import {
   getWebAuthnEmulator,
   deleteJson,
   getJson,
   patchJson,
   postJson,
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
   let emulator: WebAuthnEmulator;

   beforeAll(async () => {
      // A. Options
      const regOpts = await postJson("/v1/reg/options", { userName: testUser }, {}, "");
      expect(regOpts.status).toBe(200);
      expect(regOpts.data.user.name).toBe(testUser);

      userId = regOpts.data.user.id;
      emulator = getWebAuthnEmulator();

      // B. Verify
      const attestation = emulator.createJSON(RP_ORIGIN, {
         ...regOpts.data,
         user: { ...regOpts.data.user, id: userId },
         challenge: regOpts.data.challenge,
      });

      const verifyRes = await postJson(
         `/v1/reg/verify`,
         { ...attestation, userId, challenge: regOpts.data.challenge },
         {},
         sessCookie
      );

      expect(verifyRes.status).toBe(200);
      expect(verifyRes.data.verified).toBe(true);
      expect(verifyRes.data.csrf).toBeDefined();
      expect(verifyRes.data.pkId).toBeDefined();
      expect(verifyRes.cookie).toBeTruthy();

      sessCookie = verifyRes.cookie;
      csrfToken = verifyRes.data.csrf;
      credId = verifyRes.data.pkId;
   });

   describe("User & Session Management", () => {
      it("should fetch current session details", async () => {
         const res = await getJson(
            `/v1/session`,
            { "x-csrf-token": csrfToken },
            sessCookie,
         );
         expect(res.status).toBe(200);
         expect(res.data.csrf).toBeDefined();
         // Update CSRF in case it rotated (though usually static per session)
         if (res.data.csrf) csrfToken = res.data.csrf;
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
   });

   describe("Logout & Re-Login", () => {
      it("should logout (DELETE session)", async () => {
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
         const res = await patchJson(
            `/v1/user`,
            { userName: "hacker" },
            { "x-csrf-token": csrfToken },
            "", // No cookies
         );
         expect(res.status).toBeGreaterThanOrEqual(401);
      });

      it("should reject update user without csrf", async () => {
         const res = await patchJson(
            `/v1/user`,
            { userName: "hacker" },
            {}, // No csrf
            sessCookie,
         );
         expect(res.status).toBeGreaterThanOrEqual(401);
      });


      it("should reject manipulated cookie", async () => {
         const offset = 34;
         const badCookie = sessCookie.substring(0, offset) + (sessCookie[offset] === 'a' ? 'b' : 'a') + sessCookie.substring(offset + 1);

         const res = await deleteJson(
            `/v1/passkeys/${credId}`,
            { "x-csrf-token": csrfToken },
            badCookie,
         );

         expect(res.status).toEqual(401);
      });

      it("should reject resigned cookie", async () => {

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
         const expiresIn = 10800;

         const newToken = jwtPkg.sign(
            newPayload,
            jwtKey, {
            algorithm: 'HS512',
            expiresIn: expiresIn,
            issuer: 'quickcrypt'
         });

         const badCookie = `__Host-JWT=${newToken}`;

         const res = await deleteJson(
            `/v1/passkeys/${credId}`,
            { "x-csrf-token": csrfToken },
            badCookie,
         );

         expect(res.status).toEqual(401);
      });

      it("should reject manipulated csrf", async () => {
         const offset = 6;
         const badCsrf = csrfToken.substring(0, offset) + (csrfToken[offset] === 'a' ? 'b' : 'a') + csrfToken.substring(offset + 1);

         const res = await deleteJson(
            `/v1/passkeys/${credId}`,
            { "x-csrf-token": badCsrf },
            sessCookie,
         );

         expect(res.status).toEqual(401);
      });

      // Regression: reject an auth/verify whose challenge was issued for a different user
      // (per the check in index.ts at the comment "If the auth challenge was bound to a
      // specific user at creation, the verify must match").
      it("should reject auth/verify when challenge userId does not match credential owner", async () => {
         const attackerName = `PWTesty_atk_${Date.now()}`;
         const attackerEmulator = getWebAuthnEmulator();
         let attackerUserId: string | undefined;
         let attackerCredId: string | undefined;
         let attackerCookie = "";
         let attackerCsrf = "";

         try {
            const regOpts = await postJson("/v1/reg/options", { userName: attackerName }, {}, "");
            expect(regOpts.status).toBe(200);
            attackerUserId = regOpts.data.user.id;

            const attestation = attackerEmulator.createJSON(RP_ORIGIN, {
               ...regOpts.data,
               user: { ...regOpts.data.user, id: attackerUserId },
               challenge: regOpts.data.challenge,
            });

            const regVerify = await postJson(
               `/v1/reg/verify`,
               { ...attestation, userId: attackerUserId, challenge: regOpts.data.challenge },
               {},
               "",
            );
            expect(regVerify.status).toBe(200);
            attackerCredId = regVerify.data.pkId;
            attackerCookie = regVerify.cookie;
            attackerCsrf = regVerify.data.csrf;

            // Self-login once so the credentialid-index GSI is consistent before the bypass attempt;
            // otherwise the attempt can 401 at the cred lookup and skip the binding check.
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

            // Override allowCredentials so the emulator signs with the attacker's key rather than
            // the victim-credId the server returned in optsRes
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
            expect(bypass.rawText).toBe('challenge not valid');
         } finally {
            if (attackerCredId && attackerCookie) {
               await deleteJson(
                  `/v1/passkeys/${attackerCredId}`,
                  { "x-csrf-token": attackerCsrf },
                  attackerCookie,
               );
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

