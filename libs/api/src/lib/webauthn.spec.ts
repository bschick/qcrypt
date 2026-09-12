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
import { randomBytes } from 'node:crypto';
import WebAuthnEmulator from 'nid-webauthn-emulator';
import {
   generateAuthenticationOptions,
   generateRegistrationOptions,
   verifyAuthenticationResponse,
   verifyRegistrationResponse,
} from '@simplewebauthn/server';
import * as cc from '@qcrypt/crypto/consts';
import {
   makeAddVerifyRequest,
   makeAuthOptionsResponse,
   makeAuthVerifyRequest,
   makeRecoverVerifyRequest,
   makeRegOptionsResponse,
   makeRegVerifyRequest,
   toAuthenticationResponseJSON,
   toRegistrationResponseJSON,
} from './webauthn';

const RP_ORIGIN = process.env.QC_ENV === 'prod' ? 'https://quickcrypt.org' : 'https://t1.quickcrypt.org:4200';
const RP_ID = new URL(RP_ORIGIN).hostname;
const ALGIDS = [-8, -7, -257];

const UNWANTED = 'unwanted-extra-value';
const prfSecret = Array.from(randomBytes(cc.KEY_BYTES));

// What an extension-based provider adds beyond the fields a ceremony needs: a PRF output in the
// plain-array form, the getPublicKey() copies, and an unknown future field.
const CREDENTIAL_EXTRAS = {
   authenticatorAttachment: UNWANTED,
   clientExtensionResults: { prf: { results: { first: prfSecret } } },
   futureFieldAddedByALibraryUpgrade: UNWANTED,
};
const ATTESTATION_EXTRAS = {
   authenticatorData: UNWANTED,
   publicKey: UNWANTED,
   publicKeyAlgorithm: UNWANTED,
};
const ASSERTION_EXTRAS = { futureResponseField: UNWANTED };
const RP_EXTRAS = { origin: UNWANTED };
const OPTIONS_EXTRAS = { internalDbAttribute: UNWANTED };

const REG_UNWANTED = [...Object.keys(CREDENTIAL_EXTRAS), ...Object.keys(ATTESTATION_EXTRAS)];
const AUTH_UNWANTED = [...Object.keys(CREDENTIAL_EXTRAS), ...Object.keys(ASSERTION_EXTRAS)];
const OPTIONS_UNWANTED = [...Object.keys(RP_EXTRAS), ...Object.keys(OPTIONS_EXTRAS)];

function expectNoUnwanteds(payload: unknown, unwanted: readonly string[]): void {
   const json = JSON.stringify(payload);
   for (const name of unwanted) {
      expect(json).not.toContain(`"${name}"`);
   }
   expect(json).not.toContain(JSON.stringify(prfSecret));
}

function providerRegistrationResponse() {
   return {
      id: 'credential-id',
      rawId: 'credential-id',
      type: 'public-key' as const,
      ...CREDENTIAL_EXTRAS,
      response: {
         clientDataJSON: 'client-data',
         attestationObject: 'attestation-object',
         transports: ['internal' as const],
         ...ATTESTATION_EXTRAS,
      },
   };
}

function providerAuthenticationResponse() {
   return {
      id: 'credential-id',
      rawId: 'credential-id',
      type: 'public-key' as const,
      ...CREDENTIAL_EXTRAS,
      response: {
         clientDataJSON: 'client-data',
         authenticatorData: 'authenticator-data',
         signature: 'signature',
         userHandle: 'user-handle',
         ...ASSERTION_EXTRAS,
      },
   };
}

describe('webauthn request builders', () => {
   it('makeAuthVerifyRequest carries nothing beyond the expected properties', () => {
      const request = makeAuthVerifyRequest(providerAuthenticationResponse(), { challenge: 'chal' });
      expectNoUnwanteds(request, AUTH_UNWANTED);
   });

   it('makeRegVerifyRequest carries nothing beyond the expected properties', () => {
      const request = makeRegVerifyRequest(providerRegistrationResponse(), {
         userId: 'user-id',
         challenge: 'chal',
         recoveryPubKey: 'recovery-pub-key',
         passkeyUserCredEnc: 'passkey-enc',
         recoveryUserCredEnc: 'recovery-enc',
         userCredPubKey: 'user-cred-pub-key',
      });
      expectNoUnwanteds(request, REG_UNWANTED);
   });

   it('makeRecoverVerifyRequest carries nothing beyond the expected properties', () => {
      const request = makeRecoverVerifyRequest(providerRegistrationResponse(), {
         userId: 'user-id',
         challenge: 'chal',
         passkeyUserCredEnc: 'passkey-enc',
      });
      expectNoUnwanteds(request, REG_UNWANTED);
   });

   it('makeAddVerifyRequest carries nothing beyond the expected properties', () => {
      const request = makeAddVerifyRequest(providerRegistrationResponse(), {
         challenge: 'chal',
         passkeyUserCredEnc: 'passkey-enc',
      });
      expectNoUnwanteds(request, REG_UNWANTED);
   });

   it('omitted riders serialize away rather than reaching the wire', () => {
      const add = makeAddVerifyRequest(providerRegistrationResponse(), { challenge: 'chal' });
      expect(JSON.stringify(add)).not.toContain('"passkeyUserCredEnc"');
   });
});

// Dropping whatever the declared shape does not name is what makes declaring them separately worthwhile.
describe('webauthn options responses', () => {
   async function serverRegOptions() {
      const options = await generateRegistrationOptions({
         rpName: 'Quick Crypt',
         rpID: RP_ID,
         userID: new Uint8Array(randomBytes(cc.USERID_BYTES)),
         userName: 'someone',
         attestationType: 'none',
         excludeCredentials: [{ id: 'excluded-id', transports: ['internal'] }],
         authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
         supportedAlgorithmIDs: ALGIDS,
      });
      return { ...options, rp: { ...options.rp, ...RP_EXTRAS }, ...OPTIONS_EXTRAS };
   }

   async function serverAuthOptions() {
      const options = await generateAuthenticationOptions({
         rpID: RP_ID,
         allowCredentials: [{ id: 'allowed-id', transports: ['internal'] }],
         userVerification: 'required',
      });
      return { ...options, ...OPTIONS_EXTRAS };
   }

   it('makeRegOptionsResponse carries nothing beyond the expected properties', async () => {
      expectNoUnwanteds(makeRegOptionsResponse(await serverRegOptions()), OPTIONS_UNWANTED);
   });

   it('makeAuthOptionsResponse carries nothing beyond the expected properties', async () => {
      expectNoUnwanteds(makeAuthOptionsResponse(await serverAuthOptions()), OPTIONS_UNWANTED);
   });
});

// A trimmed payload must still drive a real ceremony, or a builder dropped something load-bearing.
describe('webauthn round trip', () => {
   it('a full register then authenticate ceremony verifies through the builders', async () => {
      const emulator = new WebAuthnEmulator();

      const regOptions = await generateRegistrationOptions({
         rpName: 'Quick Crypt',
         rpID: RP_ID,
         userID: new Uint8Array(randomBytes(cc.USERID_BYTES)),
         userName: 'someone',
         attestationType: 'none',
         supportedAlgorithmIDs: ALGIDS,
      });

      const attestation = emulator.createJSON(RP_ORIGIN, makeRegOptionsResponse(regOptions));
      const regRequest = makeRegVerifyRequest(attestation, {
         userId: 'user-id',
         challenge: regOptions.challenge,
         recoveryPubKey: 'recovery-pub-key',
      });

      const registered = await verifyRegistrationResponse({
         response: toRegistrationResponseJSON(regRequest),
         expectedChallenge: regOptions.challenge,
         expectedOrigin: RP_ORIGIN,
         expectedRPID: RP_ID,
         supportedAlgorithmIDs: ALGIDS,
      });
      expect(registered.verified).toBe(true);

      const authOptions = await generateAuthenticationOptions({ rpID: RP_ID, userVerification: 'required' });
      const assertion = emulator.getJSON(RP_ORIGIN, makeAuthOptionsResponse(authOptions));
      const authRequest = makeAuthVerifyRequest(assertion, { challenge: authOptions.challenge });

      const authenticated = await verifyAuthenticationResponse({
         response: toAuthenticationResponseJSON(authRequest),
         expectedChallenge: authOptions.challenge,
         expectedOrigin: RP_ORIGIN,
         expectedRPID: RP_ID,
         credential: {
            id: registered.registrationInfo!.credential.id,
            publicKey: registered.registrationInfo!.credential.publicKey,
            counter: 0,
         },
      });
      expect(authenticated.verified).toBe(true);
   });
});
