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
import { describe, it, expect } from 'vitest';
import { createHash, randomBytes } from 'node:crypto';
import { postJson, RP_ORIGIN } from './common';
import { base64UrlDecode } from '../src/utils';

type AllowCred = {
   id: string;
   type: string;
   transports: string[];
};

// WebAuthn AuthenticatorTransport values (W3C + CTAP). Any transport outside
// this set is itself a shape failure.
const VALID_TRANSPORTS = new Set([
   'usb', 'nfc', 'ble', 'internal', 'hybrid', 'cable', 'smart-card'
]);

// Loose credentialId byte-length bounds. MIN is 16 to cover the observed
// minimum in the Authenticators table (also the smallest DUMMY_PROFILES entry)
// so both real and dummy responses pass the same shape check.
const MIN_CRED_BYTES = 16;
const MAX_CRED_BYTES = 96;

// Must stay in sync with dummyAllowedCreds() in apps/server/src/index.ts.
// Transport ordering is significant — a mismatch with the real-path order
// would itself leak information, so entries are compared positionally.
const DUMMY_PROFILES: { len: number; transports: string[] }[] = [
   { len: 16, transports: ['hybrid', 'internal'] },
   { len: 32, transports: ['internal'] },
   { len: 20, transports: ['hybrid', 'internal'] },
   { len: 16, transports: ['internal'] },
   { len: 48, transports: ['usb'] },
];

// A pre-registered user on the test server. Absent in prod, so the test that
// uses this ID is skipped when QC_ENV=prod.
const REAL_TEST_USER_ID = 'U1hfQPpLzjCXvaRQ-2hVDg';

// Hardcoded unknown userId that decodes to exactly 16 bytes (matches real
// server-assigned userId size, passes current and future decoded-length
// validation). Decodes to ASCII "test-pinned-usr1".
const PINNED_UNKNOWN_USER_ID = 'dGVzdC1waW5uZWQtdXNyMQ';

// Expected dummy credential for PINNED_UNKNOWN_USER_ID. Replace placeholders
// with the actual values returned by the test server on first run. Update if
// EncMaterial (the KMS-encrypted jwtMaterial seed) is rotated.
const EXPECTED_PINNED_CRED_TEST: AllowCred = {
   id: 'mNcU4fpleZNUSgbS3pSfnQ',
   type: 'public-key',
   transports: ['hybrid', 'internal']
};
const EXPECTED_PINNED_CRED_PROD: AllowCred = {
   id: '-UKU3OnG2DtIBmROhlNLug',
   type: 'public-key',
   transports: ['hybrid', 'internal']
};

function unknownUserId(): string {
   // 16 random bytes → 22-char base64url (no padding), matching real userId shape.
   return randomBytes(16).toString('base64url');
}

function assertValidCredentialShape(
   cred: Record<string, unknown>
): asserts cred is AllowCred {
   // Exact key set — an extra field would itself be a tell.
   expect(Object.keys(cred).sort()).toEqual(['id', 'transports', 'type']);

   expect(cred.type).toBe('public-key');

   expect(typeof cred.id).toBe('string');
   const bytes = base64UrlDecode(cred.id as string);
   expect(bytes).toBeDefined();
   expect(bytes!.byteLength).toBeGreaterThanOrEqual(MIN_CRED_BYTES);
   expect(bytes!.byteLength).toBeLessThanOrEqual(MAX_CRED_BYTES);

   expect(Array.isArray(cred.transports)).toBe(true);
   const transports = cred.transports as unknown[];
   expect(transports.length).toBeGreaterThan(0);
   for (const t of transports) {
      expect(typeof t).toBe('string');
      expect(VALID_TRANSPORTS.has(t as string), `unexpected transport: ${String(t)}`).toBe(true);
   }
}

function matchesAnyDummyProfile(cred: Record<string, unknown>): boolean {
   assertValidCredentialShape(cred);
   const bytes = base64UrlDecode(cred.id)!;
   return DUMMY_PROFILES.some(p =>
      p.len === bytes.byteLength &&
      p.transports.length === cred.transports.length &&
      p.transports.every((t, i) => t === cred.transports[i])
   );
}

async function getAllowCredentials(userId: string): Promise<AllowCred[]> {
   const res = await postJson('/v1/auth/options', { userId }, {}, '');
   expect(res.status).toBe(200);
   expect(Array.isArray(res.data.allowCredentials)).toBe(true);
   return res.data.allowCredentials as AllowCred[];
}

describe('auth/options credential shape', () => {

   it.skipIf(process.env.QC_ENV === 'prod')(
      'real registered user returns credentials with valid shape',
      async () => {
         const creds = await getAllowCredentials(REAL_TEST_USER_ID);
         expect(creds.length).toBeGreaterThan(0);
         for (const c of creds) {
            assertValidCredentialShape(c);
         }
      }
   );

   it('multiple unknown userIds each return a dummy credential matching a known profile', async () => {
      for (let i = 0; i < 5; i++) {
         const creds = await getAllowCredentials(unknownUserId());
         expect(creds.length).toBe(1);
         const cred = creds[0];
         expect(
            matchesAnyDummyProfile(cred),
            `unexpected dummy cred: ${JSON.stringify(cred)}`
         ).toBe(true);
      }
   });

   it('pinned unknown userId returns the expected hardcoded dummy credential on every call', async () => {
      const a = await getAllowCredentials(PINNED_UNKNOWN_USER_ID);
      const b = await getAllowCredentials(PINNED_UNKNOWN_USER_ID);
      expect(a.length).toBe(1);
      expect(b.length).toBe(1);
      expect(a[0]).toStrictEqual(b[0]);
      expect(a[0]).toStrictEqual(process.env.QC_ENV === 'prod' ? EXPECTED_PINNED_CRED_PROD : EXPECTED_PINNED_CRED_TEST);
      assertValidCredentialShape(a[0]);
   });

   it('different unknown userIds return different credential ids', async () => {
      const samples = 8;
      const ids = new Set<string>();
      for (let i = 0; i < samples; i++) {
         const creds = await getAllowCredentials(unknownUserId());
         expect(creds.length).toBe(1);
         ids.add(creds[0].id);
      }
      expect(ids.size).toBe(samples);
   });
});

// Builds a WebAuthn AuthenticationResponseJSON the server will accept
// structurally so the verify reaches the signature check, where it fails
// because we don't have the private key. Used to prove that the credential-known
// and credential-unknown branches return indistinguishable responses.
function buildForgedAssertion(
   credentialId: string,
   challenge: string,
   userId: string,
   rpId: string,
): Record<string, unknown> {
   const clientDataJSON = Buffer.from(
      JSON.stringify({
         type: 'webauthn.get',
         challenge,
         origin: RP_ORIGIN,
         crossOrigin: false,
      }),
      'utf8',
   ).toString('base64url');
   const rpIdHash = createHash('sha256').update(rpId).digest();
   const flags = Buffer.from([0x05]); // UP | UV
   const counter = Buffer.from([0, 0, 0, 0]);
   const authenticatorData = Buffer.concat([rpIdHash, flags, counter]).toString('base64url');
   return {
      id: credentialId,
      rawId: credentialId,
      type: 'public-key',
      challenge,
      response: {
         clientDataJSON,
         authenticatorData,
         signature: randomBytes(72).toString('base64url'),
         userHandle: userId,
      },
      clientExtensionResults: {},
   };
}

async function forgeAndVerify(userId: string) {
   const opts = await postJson('/v1/auth/options', { userId }, {}, '');
   expect(opts.status).toBe(200);
   const credId = opts.data.allowCredentials[0].id;
   const forged = buildForgedAssertion(credId, opts.data.challenge, userId, opts.data.rpId);
   return postJson('/v1/auth/verify', forged, {}, '');
}

describe('auth/verify response parity', () => {

   it('two different unknown userIds return indistinguishable 401 responses', async () => {
      const a = await forgeAndVerify(unknownUserId());
      const b = await forgeAndVerify(unknownUserId());
      expect(a.status).toBe(401);
      expect(b.status).toBe(401);
      expect(a.rawText).toBe(b.rawText);
   });

   it.skipIf(process.env.QC_ENV === 'prod')(
      'real userId with forged signature returns same status and body as unknown userId',
      async () => {
         const real = await forgeAndVerify(REAL_TEST_USER_ID);
         const dummy = await forgeAndVerify(unknownUserId());
         expect(real.status).toBe(401);
         expect(dummy.status).toBe(401);
         expect(real.rawText).toBe(dummy.rawText);
      }
   );
});
