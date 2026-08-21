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
import { randomBytes } from 'node:crypto';
import {
   getJson,
   patchJson,
   expectPasskeyDeleted,
   makeProofHeaders,
   registerTestUser,
   setSessionSigner,
} from './common';

describe('proof of userCred enforcement', () => {
   // Labelled rather than derived: one test appends "_x" and needs room under UNAME_MAX_LEN (31)
   let testUser: string;
   let userId: string;
   let userCred: string;
   let cookie: string;
   let csrf: string;
   let credId: string;

   beforeAll(async () => {
      // A PRF account's proof public key is supplied by the client (not derived server-side), so
      // enforce proof verification against that client-provisioned key.
      ({ userId, userName: testUser, userCred, cookie, csrf, credId } = await registerTestUser(true, 'enf'));
      // Each test crafts its own proof; disable the harness auto-signer.
      setSessionSigner(undefined);
   });

   afterAll(async () => {
      if (cookie && credId) {
         // Deleting under enforcement needs a valid proof, so re-enable auto-signing.
         setSessionSigner(userId, userCred);
         await expectPasskeyDeleted(credId, csrf, cookie);
         setSessionSigner(undefined);
      }
   });

   it('accepts a valid proof', async () => {
      const proof = await makeProofHeaders('GET', '/v1/user', undefined, userCred, userId);
      const res = await getJson('/v1/user', { 'x-csrf-token': csrf, ...proof }, cookie);
      expect(res.status).toBe(200);
   });

   it('rejects a replayed proof on a mutating request', async () => {
      const body = Buffer.from(JSON.stringify({ userName: testUser }));
      const proof = await makeProofHeaders('PATCH', '/v1/user', body, userCred, userId);
      const res1 = await patchJson('/v1/user', { userName: testUser }, { 'x-csrf-token': csrf, ...proof }, cookie);
      expect(res1.status).toBe(200);

      const res2 = await patchJson('/v1/user', { userName: testUser }, { 'x-csrf-token': csrf, ...proof }, cookie);
      expect(res2.status).toBe(401);
   });

   it('allow replayed proof on a read within time window', async () => {
      const proof = await makeProofHeaders('GET', '/v1/user', undefined, userCred, userId);
      const res1 = await getJson('/v1/user', { 'x-csrf-token': csrf, ...proof }, cookie);
      expect(res1.status).toBe(200);

      const res2 = await getJson('/v1/user', { 'x-csrf-token': csrf, ...proof }, cookie);
      expect(res2.status).toBe(200);
   });

   it('rejects a request carrying no proof', async () => {
      const res = await getJson('/v1/user', { 'x-csrf-token': csrf }, cookie);
      expect(res.status).toBe(401);
   });

   it('rejects a tampered signature', async () => {
      const proof = await makeProofHeaders('GET', '/v1/user', undefined, userCred, userId, { tamperSig: true });
      const res = await getJson('/v1/user', { 'x-csrf-token': csrf, ...proof }, cookie);
      expect(res.status).toBe(401);
   });

   it('rejects a proof timestamp outside the skew window', async () => {
      const expired = String(Date.now() - 10 * 60 * 1000);
      const proof = await makeProofHeaders('GET', '/v1/user', undefined, userCred, userId, { timestampMs: expired });
      const res = await getJson('/v1/user', { 'x-csrf-token': csrf, ...proof }, cookie);
      expect(res.status).toBe(401);
   });

   it('rejects a proof signed with the wrong userCred', async () => {
      const wrongCred = randomBytes(32).toString('base64url');
      const proof = await makeProofHeaders('GET', '/v1/user', undefined, wrongCred, userId);
      const res = await getJson('/v1/user', { 'x-csrf-token': csrf, ...proof }, cookie);
      expect(res.status).toBe(401);
   });

   it('rejects a proof bound to a different userId', async () => {
      const wrongUserId = randomBytes(16).toString('base64url');
      const proof = await makeProofHeaders('GET', '/v1/user', undefined, userCred, wrongUserId);
      const res = await getJson('/v1/user', { 'x-csrf-token': csrf, ...proof }, cookie);
      expect(res.status).toBe(401);
   });

   it('rejects requests with missing proof parts', async () => {
      const proof = await makeProofHeaders('GET', '/v1/user', undefined, userCred, userId);
      const parts = proof['x-proof'].split(',');
      expect(parts.length).toBe(3);

      proof['x-proof'] = parts.join(',');
      let res = await getJson('/v1/user', { 'x-csrf-token': csrf, ...proof }, cookie);
      expect(res.status).toBe(200);

      proof['x-proof'] = parts.slice(1).join(',');
      res = await getJson('/v1/user', { 'x-csrf-token': csrf, ...proof }, cookie);
      expect(res.status).toBe(401);

      proof['x-proof'] = parts.slice(0, 1).join(',');
      res = await getJson('/v1/user', { 'x-csrf-token': csrf, ...proof }, cookie);
      expect(res.status).toBe(401);

      proof['x-proof'] = [parts[0], parts[2]].join(',');
      res = await getJson('/v1/user', { 'x-csrf-token': csrf, ...proof }, cookie);
      expect(res.status).toBe(401);
   });

   it('requires a proof on getSession', async () => {
      // getSession skips csrf but still gates CSRF issuance on proof of userCred.
      const res = await getJson('/v1/session', {}, cookie);
      expect(res.status).toBe(401);
   });

   it('accepts a proof that binds a query string the handler ignores', async () => {
      const proof = await makeProofHeaders('GET', '/v1/user?ignored=1', undefined, userCred, userId);
      const res = await getJson('/v1/user?ignored=1', { 'x-csrf-token': csrf, ...proof }, cookie);
      expect(res.status).toBe(200);
   });

   it('rejects when the request query differs from the signed query', async () => {
      const proof = await makeProofHeaders('GET', '/v1/user?ignored=1', undefined, userCred, userId);
      const res = await getJson('/v1/user?ignored=2', { 'x-csrf-token': csrf, ...proof }, cookie);
      expect(res.status).toBe(401);
   });

   it('rejects a proof reused on a different method or path', async () => {
      // A GET proof replays within the skew window, so the nonce doesn't prevent reuse here — the
      // signed method and path do.
      const proof = await makeProofHeaders('GET', '/v1/user', undefined, userCred, userId);

      const own = await getJson('/v1/user', { 'x-csrf-token': csrf, ...proof }, cookie);
      expect(own.status).toBe(200);

      const otherPath = await getJson('/v1/passkeys/options', { 'x-csrf-token': csrf, ...proof }, cookie);
      expect(otherPath.status).toBe(401);

      const otherMethod = await patchJson('/v1/user', null, { 'x-csrf-token': csrf, ...proof }, cookie);
      expect(otherMethod.status).toBe(401);
   });

   it('rejects a mutating request whose body differs from the signed body', async () => {
      const signed = { userName: testUser };
      const signedBuf = Buffer.from(JSON.stringify(signed));

      const good = await makeProofHeaders('PATCH', '/v1/user', signedBuf, userCred, userId);
      const ok = await patchJson('/v1/user', signed, { 'x-csrf-token': csrf, ...good }, cookie);
      expect(ok.status).toBe(200);

      // Fresh proof (the one above spent its nonce) so this 401 is the body mismatch, not a replay.
      const proof = await makeProofHeaders('PATCH', '/v1/user', signedBuf, userCred, userId);
      const res = await patchJson(
         '/v1/user',
         { userName: `${testUser}_x` },
         { 'x-csrf-token': csrf, ...proof },
         cookie,
      );
      expect(res.status).toBe(401);
   });

   it('admits only one of several concurrent replays of one proof', async () => {
      const body = Buffer.from(JSON.stringify({ userName: testUser }));
      const proof = await makeProofHeaders('PATCH', '/v1/user', body, userCred, userId);

      // The nonce store is a conditional insert, so racing the same proof still admits exactly one.
      const results = await Promise.all(
         Array.from({ length: 5 }, () =>
            patchJson('/v1/user', { userName: testUser }, { 'x-csrf-token': csrf, ...proof }, cookie),
         ),
      );
      expect(results.filter((r) => r.status === 200).length).toBe(1);
      expect(results.filter((r) => r.status === 401).length).toBe(4);
   });
});
