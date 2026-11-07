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
import { bytesToBase64, getRandom } from '@qcrypt/crypto';
import * as cc from '@qcrypt/crypto/consts';
import * as api from '@qcrypt/api';
import { USERCRED_ENC_MIN_BYTES, USERCRED_ENC_MAX_BYTES, PROOF_SKEW_MS } from '../src/consts';
import {
   type Registration,
   type RegVerifyOpts,
   buildRegBody,
   expectRegistered,
   expectRegRejected,
   makeChallengeProofHeaders,
   makeNonceProofHeaders,
   postJson,
   postRegVerify,
   sha256Hex,
   testUserName,
} from './common';

function recoverySignature(
   reg: Registration,
   opts: { recoverySecret?: Uint8Array; timestampMs?: string; challenge?: string; userCredPubKey?: string },
): string {
   return api.createRecoveryChallengeProof(
      opts.recoverySecret ?? reg.recoverySecret,
      reg.userId,
      opts.timestampMs ?? reg.body.recoveryTimestamp!,
      opts.challenge ?? reg.body.challenge,
      opts.userCredPubKey ?? reg.userCredPubKey,
   );
}

// BACKWARD COMPAT: a request from a client that does not prove userCred. Only its PRF requests carry
// userCredPubKey.
function oldFormat(reg: Registration, prf: boolean): RegVerifyOpts {
   return {
      body: {
         userCred: undefined,
         recoveryTimestamp: undefined,
         recoverySignature: undefined,
         userCredPubKey: prf ? reg.userCredPubKey : undefined,
      },
      headers: {},
   };
}

export function registrationSuite(prf: boolean): void {
   const label = prf ? 'PRF' : 'no-PRF';

   describe(`registration proofs (${label})`, () => {
      it('accepts a request with valid proofs', async () => {
         const reg = await buildRegBody(testUserName(), prf);
         await expectRegistered(reg);
      });

      it('rejects a userCred proof from another userCred', async () => {
         const reg = await buildRegBody(testUserName(), prf);
         await expectRegRejected(reg, { keySecret: getRandom(cc.USERCRED_BYTES) });
      });

      it('rejects a recovery proof over another userCredPubKey', async () => {
         const reg = await buildRegBody(testUserName(), prf);
         const otherPubKey = api.getUserCredPubKey(getRandom(cc.USERCRED_BYTES));
         await expectRegRejected(reg, {
            body: { recoverySignature: recoverySignature(reg, { userCredPubKey: otherPubKey }) },
         });
      });

      it('rejects a recovery proof from another recovery secret', async () => {
         const reg = await buildRegBody(testUserName(), prf);
         const otherSecret = api.recoverySecret(getRandom(api.RECOVERYID_BYTES), reg.userId);
         await expectRegRejected(reg, {
            body: { recoverySignature: recoverySignature(reg, { recoverySecret: otherSecret }) },
         });
      });

      it('rejects a request without its recovery proof', async () => {
         const reg = await buildRegBody(testUserName(), prf);
         await expectRegRejected(reg, { body: { recoverySignature: undefined } });
      });

      // The substitute recovery key matches its own proof, but the userCred proof covers the original body
      it('rejects a body changed after its userCred proof was signed', async () => {
         const reg = await buildRegBody(testUserName(), prf);
         const otherSecret = api.recoverySecret(getRandom(api.RECOVERYID_BYTES), reg.userId);
         await expectRegRejected(reg, {
            body: {
               recoveryPubKey: api.getRecoveryPubKey(otherSecret),
               recoverySignature: recoverySignature(reg, { recoverySecret: otherSecret }),
            },
            headers: reg.headers,
         });
      });

      // Both proofs come from the other userCred, whose key the body carries. The userCred proof does not
      // match the userCredPubKey sent to reg/options.
      it('rejects a userCredPubKey other than the one sent to reg/options', async () => {
         const reg = await buildRegBody(testUserName(), prf);
         const otherUserCred = getRandom(cc.USERCRED_BYTES);
         const otherPubKey = api.getUserCredPubKey(otherUserCred);
         await expectRegRejected(reg, {
            body: {
               userCredPubKey: otherPubKey,
               recoverySignature: recoverySignature(reg, { userCredPubKey: otherPubKey }),
            },
            keySecret: otherUserCred,
         });
      });

      // A PRF request carries no plaintext userCred
      if (!prf) {
         it('rejects a userCred that does not match userCredPubKey', async () => {
            const reg = await buildRegBody(testUserName(), prf);
            await expectRegRejected(reg, { body: { userCred: bytesToBase64(getRandom(cc.USERCRED_BYTES)) } });
         });

         // Both proofs come from the other userCred, which the body carries with its key. The userCred proof
         // does not match the userCredPubKey sent to reg/options.
         it('rejects a userCred and userCredPubKey other than those sent to reg/options', async () => {
            const reg = await buildRegBody(testUserName(), prf);
            const otherUserCred = getRandom(cc.USERCRED_BYTES);
            const otherPubKey = api.getUserCredPubKey(otherUserCred);
            await expectRegRejected(reg, {
               body: {
                  userCred: bytesToBase64(otherUserCred),
                  userCredPubKey: otherPubKey,
                  recoverySignature: recoverySignature(reg, { userCredPubKey: otherPubKey }),
               },
               keySecret: otherUserCred,
            });
         });
      }

      it('rejects a request without its userCred proof', async () => {
         const reg = await buildRegBody(testUserName(), prf);
         await expectRegRejected(reg, { headers: {} });
      });

      it('rejects a request with a proof but without userCred or its ciphertexts', async () => {
         const reg = await buildRegBody(testUserName(), prf);
         await expectRegRejected(reg, {
            body: { userCred: undefined, passkeyUserCredEnc: undefined, recoveryUserCredEnc: undefined },
         });
      });

      it('rejects a userCred proof timestamp outside the skew window', async () => {
         const reg = await buildRegBody(testUserName(), prf);
         const stale = String(Date.now() - 2 * PROOF_SKEW_MS);
         const headers = makeChallengeProofHeaders(
            '/v1/reg/verify',
            reg.body,
            reg.userCred,
            reg.userId,
            reg.body.challenge,
            { timestampMs: stale },
         );
         await expectRegRejected(reg, { headers });
      });

      it('rejects a recovery proof timestamp outside the skew window', async () => {
         const reg = await buildRegBody(testUserName(), prf);
         const stale = String(Date.now() - 2 * PROOF_SKEW_MS);
         await expectRegRejected(reg, {
            body: { recoveryTimestamp: stale, recoverySignature: recoverySignature(reg, { timestampMs: stale }) },
         });
      });

      it('rejects a recovery proof in nonce form', async () => {
         const reg = await buildRegBody(testUserName(), prf);
         const nonceSig = api.createRecoveryNonceProof(
            reg.recoverySecret,
            reg.userId,
            reg.body.recoveryTimestamp!,
            reg.body.challenge,
            'recover',
         );
         await expectRegRejected(reg, { body: { recoverySignature: nonceSig } });
      });

      // A nonce-form signature over the same request, sent as the challenge proof
      it('rejects a userCred proof in nonce form', async () => {
         const reg = await buildRegBody(testUserName(), prf);
         const timestamp = String(Date.now());
         const signature = api.createUserCredNonceProof(
            reg.userCred,
            reg.userId,
            'POST',
            '/v1/reg/verify',
            timestamp,
            reg.body.challenge,
            sha256Hex(Buffer.from(JSON.stringify(reg.body), 'utf8')),
         );
         await expectRegRejected(reg, { headers: { 'x-challenge-proof': `${signature},${timestamp}` } });
      });

      it('rejects a nonce proof header in place of the challenge proof', async () => {
         const reg = await buildRegBody(testUserName(), prf);
         const headers = await makeNonceProofHeaders(
            'POST',
            '/v1/reg/verify',
            Buffer.from(JSON.stringify(reg.body), 'utf8'),
            bytesToBase64(reg.userCred),
            reg.userId,
         );
         await expectRegRejected(reg, { headers });
      });

      // Two full proofs exceed the edge's request header limit, which returns 413 before the server
      // sees them, so the nonce header carries a short placeholder
      it('rejects a nonce proof header alongside the challenge proof', async () => {
         const reg = await buildRegBody(testUserName(), prf);
         await expectRegRejected(reg, { headers: { ...reg.headers, 'x-nonce-proof': 'signature,timestamp,nonce' } });
      });

      it('rejects an old-format request after reg/options received userCredPubKey', async () => {
         const reg = await buildRegBody(testUserName(), prf);
         await expectRegRejected(reg, oldFormat(reg, prf));
      });

      it('rejects a challenge that was never issued', async () => {
         const reg = await buildRegBody(testUserName(), prf);
         const challenge = bytesToBase64(getRandom(api.CHALLENGE_BYTES));
         await expectRegRejected(reg, {
            body: { challenge, recoverySignature: recoverySignature(reg, { challenge }) },
         });
      });

      // The other registration binds the same userCredPubKey, so its challenge differs only in the userId
      // it was issued to
      it('rejects a challenge issued to another registration', async () => {
         const reg = await buildRegBody(testUserName(), prf);
         const other = await postJson(
            '/v1/reg/options',
            { userName: testUserName(), userCredPubKey: reg.userCredPubKey },
            {},
            '',
         );
         expect(other.status).toBe(200);
         const challenge: string = other.data.challenge;
         await expectRegRejected(reg, {
            body: { challenge, recoverySignature: recoverySignature(reg, { challenge }) },
         });
      });

      // WebAuthn verification runs after the challenge is consumed, so the unmodified request then fails too
      it('rejects an attestation from another origin', async () => {
         const reg = await buildRegBody(testUserName(), prf);
         const clientData = JSON.parse(Buffer.from(reg.body.response.clientDataJSON, 'base64url').toString('utf8'));
         const clientDataJSON = Buffer.from(
            JSON.stringify({ ...clientData, origin: 'https://example.com' }),
            'utf8',
         ).toString('base64url');

         const bad = await postRegVerify(reg, { body: { response: { ...reg.body.response, clientDataJSON } } });
         expect(bad.status).toBe(401);
         const retry = await postRegVerify(reg, {});
         expect(retry.status).toBe(401);
      });
   });

   describe(`registration input validation (${label})`, () => {
      const randomB64 = (byteLength: number) => bytesToBase64(getRandom(byteLength));

      it('rejects the userCredPubKey sent to reg/options repeated in the body', async () => {
         const reg = await buildRegBody(testUserName(), prf);
         await expectRegRejected(reg, { body: { userCredPubKey: reg.userCredPubKey } });
      });
      it('rejects a wrong-length recoveryPubKey', async () => {
         const reg = await buildRegBody(testUserName(), prf);
         await expectRegRejected(reg, { body: { recoveryPubKey: randomB64(cc.USERCRED_BYTES) } });
      });
      it('rejects a non-base64 recoveryPubKey', async () => {
         const reg = await buildRegBody(testUserName(), prf);
         await expectRegRejected(reg, { body: { recoveryPubKey: 'not b64 $$$' } });
      });
      it('rejects a malformed userId', async () => {
         const reg = await buildRegBody(testUserName(), prf);
         await expectRegRejected(reg, { body: { userId: 'not b64 $$$' } });
      });
      it('rejects an unknown userId', async () => {
         const reg = await buildRegBody(testUserName(), prf);
         await expectRegRejected(reg, { body: { userId: randomB64(cc.USERID_BYTES) } });
      });
      it('rejects an invalid transport', async () => {
         const reg = await buildRegBody(testUserName(), prf);
         await expectRegRejected(reg, { body: { response: { ...reg.body.response, transports: ['Not Valid'] } } });
      });
      it('rejects userCred ciphertexts together with a plaintext userCred', async () => {
         const reg = await buildRegBody(testUserName(), prf);
         const both = prf
            ? { userCred: randomB64(cc.USERCRED_BYTES) }
            : {
                 passkeyUserCredEnc: randomB64(USERCRED_ENC_MIN_BYTES),
                 recoveryUserCredEnc: randomB64(USERCRED_ENC_MIN_BYTES),
              };
         await expectRegRejected(reg, { body: both });
      });

      if (prf) {
         it('rejects an empty passkeyUserCredEnc', async () => {
            const reg = await buildRegBody(testUserName(), prf);
            await expectRegRejected(reg, { body: { passkeyUserCredEnc: '' } });
         });
         it('rejects an empty recoveryUserCredEnc', async () => {
            const reg = await buildRegBody(testUserName(), prf);
            await expectRegRejected(reg, { body: { recoveryUserCredEnc: '' } });
         });
         it('rejects a non-base64 passkeyUserCredEnc', async () => {
            const reg = await buildRegBody(testUserName(), prf);
            await expectRegRejected(reg, { body: { passkeyUserCredEnc: 'not b64 $$$' } });
         });
         it('rejects a too-short passkeyUserCredEnc', async () => {
            const reg = await buildRegBody(testUserName(), prf);
            await expectRegRejected(reg, { body: { passkeyUserCredEnc: randomB64(USERCRED_ENC_MIN_BYTES - 1) } });
         });
         it('rejects a too-short recoveryUserCredEnc', async () => {
            const reg = await buildRegBody(testUserName(), prf);
            await expectRegRejected(reg, { body: { recoveryUserCredEnc: randomB64(USERCRED_ENC_MIN_BYTES - 1) } });
         });
         it('rejects a too-long passkeyUserCredEnc', async () => {
            const reg = await buildRegBody(testUserName(), prf);
            await expectRegRejected(reg, { body: { passkeyUserCredEnc: randomB64(USERCRED_ENC_MAX_BYTES + 1) } });
         });
      } else {
         it('rejects a wrong-length userCred', async () => {
            const reg = await buildRegBody(testUserName(), prf);
            await expectRegRejected(reg, { body: { userCred: randomB64(cc.USERCRED_BYTES - 1) } });
         });
         it('rejects a non-base64 userCred', async () => {
            const reg = await buildRegBody(testUserName(), prf);
            await expectRegRejected(reg, { body: { userCred: 'not b64 $$$' } });
         });
      }
   });

   // BACKWARD COMPAT: remove once clients that do not prove userCred are gone
   describe(`old-format registration (${label})`, () => {
      it('accepts an old-format request', async () => {
         const reg = await buildRegBody(testUserName(), prf, false);
         await expectRegistered(reg, oldFormat(reg, prf));
      });

      // A client signed in to another account sends that session's proof with every request
      it('ignores an x-proof nonce proof on an old-format request', async () => {
         const reg = await buildRegBody(testUserName(), prf, false);
         const sessionProof = await makeNonceProofHeaders(
            'POST',
            '/v1/reg/verify',
            undefined,
            bytesToBase64(getRandom(cc.USERCRED_BYTES)),
            bytesToBase64(getRandom(cc.USERID_BYTES)),
            { legacyHeader: true },
         );
         await expectRegistered(reg, { ...oldFormat(reg, prf), headers: sessionProof });
      });

      it('rejects a challenge proof after reg/options received no userCredPubKey', async () => {
         const reg = await buildRegBody(testUserName(), prf, false);
         await expectRegRejected(reg, { body: { userCredPubKey: undefined } }, oldFormat(reg, prf));
      });

      if (prf) {
         it('rejects an invalid userCredPubKey', async () => {
            const reg = await buildRegBody(testUserName(), prf, false);
            const old = oldFormat(reg, prf);
            const userCredPubKey = bytesToBase64(getRandom(cc.USERCRED_BYTES));
            await expectRegRejected(reg, { ...old, body: { ...old.body, userCredPubKey } }, old);
         });
         it('rejects a non-base64 userCredPubKey', async () => {
            const reg = await buildRegBody(testUserName(), prf, false);
            const old = oldFormat(reg, prf);
            await expectRegRejected(reg, { ...old, body: { ...old.body, userCredPubKey: 'not b64 $$$' } }, old);
         });
      } else {
         // BACKWARD COMPAT: old format creates userCred on the server therefore callers cannot provide userCredPubKey
         it('rejects a userCredPubKey in the body', async () => {
            const reg = await buildRegBody(testUserName(), prf, false);
            const old = oldFormat(reg, prf);
            const userCredPubKey = api.getUserCredPubKey(getRandom(cc.USERCRED_BYTES));
            await expectRegRejected(reg, { ...old, body: { ...old.body, userCredPubKey } }, old);
         });
      }
   });
}
