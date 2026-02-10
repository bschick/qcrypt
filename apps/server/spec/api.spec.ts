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

// ----- Test Suite -----

describe("QuickCrypt WebAuthn Full API Suite", () => {

   // Shared state
   const testUser = `test_${Date.now()}`;
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
         const optsRes = await getJson(
            `/v1/auth/options?userid=${userId}`,
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
         const verifyRes = await postJson(
            `/v1/auth/verify`,
            { ...assertion, userId, challenge: optsRes.data.challenge },
            {},
            sessCookie,
         );

         expect(verifyRes.status).toBe(200);
         expect(verifyRes.data.verified).toBe(true);
         expect(verifyRes.cookie).toBeTruthy();

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
      expect(checkRes.status).toBeGreaterThanOrEqual(400); // 400, 401, or 404
   });
});

