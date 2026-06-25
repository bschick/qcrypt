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

import { describe, it, beforeAll, afterAll, expect } from "vitest";
import { randomBytes } from "node:crypto";
import {
   getJson,
   patchJson,
   deleteJson,
   makeProofHeaders,
   registerTestUser,
   setSessionUserCred,
} from "./common";

// BACKWARD COMPATIBILITY: skipped while verifyProof enforcement is observe-only for the
// production soak. Re-enable together with the throw in verifyProof.
describe.skip("proof of userCred enforcement", () => {
   const testUser = `PWTesty_enf_${Date.now()}`;
   let userId: string;
   let userCred: string;
   let cookie: string;
   let csrf: string;
   let credId: string;

   beforeAll(async () => {
      ({ userId, userCred, cookie, csrf, credId } = await registerTestUser(testUser));
      // Each test crafts its own proof; disable the harness auto-signer.
      setSessionUserCred(undefined);
   });

   afterAll(async () => {
      if (cookie && credId) {
         // Deleting under enforcement needs a valid proof, so re-enable auto-signing.
         setSessionUserCred(userCred, userId);
         await deleteJson(`/v1/passkeys/${credId}`, { "x-csrf-token": csrf }, cookie);
         setSessionUserCred(undefined);
      }
   });

   it("accepts a valid proof", async () => {
      const proof = await makeProofHeaders("GET", "/v1/user", undefined, userCred, userId);
      const res = await getJson("/v1/user", { "x-csrf-token": csrf, ...proof }, cookie);
      expect(res.status).toBe(200);
   });

   it("rejects a replayed proof on a mutating request", async () => {
      const body = Buffer.from(JSON.stringify({ userName: testUser }));
      const proof = await makeProofHeaders("PATCH", "/v1/user", body, userCred, userId);
      const res1 = await patchJson("/v1/user", { userName: testUser }, { "x-csrf-token": csrf, ...proof }, cookie);
      expect(res1.status).toBe(200);

      const res2 = await patchJson("/v1/user", { userName: testUser }, { "x-csrf-token": csrf, ...proof }, cookie);
      expect(res2.status).toBe(401);
   });

   it("allow replayed proof on a read within time window", async () => {
      const proof = await makeProofHeaders("GET", "/v1/user", undefined, userCred, userId);
      const res1 = await getJson("/v1/user", { "x-csrf-token": csrf, ...proof }, cookie);
      expect(res1.status).toBe(200);

      const res2 = await getJson("/v1/user", { "x-csrf-token": csrf, ...proof }, cookie);
      expect(res2.status).toBe(200);
   });

   it("rejects a request carrying no proof", async () => {
      const res = await getJson("/v1/user", { "x-csrf-token": csrf }, cookie);
      expect(res.status).toBe(401);
   });

   it("rejects a tampered signature", async () => {
      const proof = await makeProofHeaders("GET", "/v1/user", undefined, userCred, userId, { tamperSig: true });
      const res = await getJson("/v1/user", { "x-csrf-token": csrf, ...proof }, cookie);
      expect(res.status).toBe(401);
   });

   it("rejects a proof timestamp outside the skew window", async () => {
      const expired = String(Date.now() - 10 * 60 * 1000);
      const proof = await makeProofHeaders("GET", "/v1/user", undefined, userCred, userId, { timestampMs: expired });
      const res = await getJson("/v1/user", { "x-csrf-token": csrf, ...proof }, cookie);
      expect(res.status).toBe(401);
   });

   it("rejects a proof signed with the wrong userCred", async () => {
      const wrongCred = randomBytes(32).toString("base64url");
      const proof = await makeProofHeaders("GET", "/v1/user", undefined, wrongCred, userId);
      const res = await getJson("/v1/user", { "x-csrf-token": csrf, ...proof }, cookie);
      expect(res.status).toBe(401);
   });

   it("rejects a proof bound to a different userId", async () => {
      const wrongUserId = randomBytes(16).toString("base64url");
      const proof = await makeProofHeaders("GET", "/v1/user", undefined, userCred, wrongUserId);
      const res = await getJson("/v1/user", { "x-csrf-token": csrf, ...proof }, cookie);
      expect(res.status).toBe(401);
   });

   it("rejects requests with missing proof parts", async () => {
      const proof = await makeProofHeaders("GET", "/v1/user", undefined, userCred, userId);
      const parts = proof['x-proof'].split(',');
      expect(parts.length).toBe(3);

      proof['x-proof'] = parts.join(',');
      let res = await getJson("/v1/user", { "x-csrf-token": csrf, ...proof }, cookie);
      expect(res.status).toBe(200);

      proof['x-proof'] = parts.slice(1).join(',');
      res = await getJson("/v1/user", { "x-csrf-token": csrf, ...proof }, cookie);
      expect(res.status).toBe(401);

      proof['x-proof'] = parts.slice(0,1).join(',');
      res = await getJson("/v1/user", { "x-csrf-token": csrf, ...proof }, cookie);
      expect(res.status).toBe(401);

      proof['x-proof'] = [parts[0], parts[2]].join(',');
      res = await getJson("/v1/user", { "x-csrf-token": csrf, ...proof }, cookie);
      expect(res.status).toBe(401);
   });

   it("requires a proof on getSession", async () => {
      // getSession skips csrf but still gates CSRF issuance on proof of userCred.
      const res = await getJson("/v1/session", {}, cookie);
      expect(res.status).toBe(401);
   });
});
