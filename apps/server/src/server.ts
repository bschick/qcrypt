/* MIT License

Copyright (c) 2025-2026 Brad Schick

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

import * as cc from './consts';
import type { APIGatewayProxyEventV2, APIGatewayProxyStructuredResultV2, Context } from 'aws-lambda';
import { INTERNAL_VERSION, matchEvent, Patterns, type HttpDetails, type MethodMap } from './urls';

import {
   generateAuthenticationOptions,
   verifyAuthenticationResponse,
   generateRegistrationOptions,
   verifyRegistrationResponse,
} from '@simplewebauthn/server';

import type {
   VerifiedRegistrationResponse,
   VerifiedAuthenticationResponse,
   PublicKeyCredentialRequestOptionsJSON,
   PublicKeyCredentialCreationOptionsJSON,
   WebAuthnCredential,
   PublicKeyCredentialDescriptorJSON,
} from '@simplewebauthn/server';

import {
   Users,
   Authenticators,
   AuthEvents,
   AAGUIDs,
   Invitables,
   type VerifiedUserItem,
   type UnverifiedUserItem,
   type AuthItem,
   type InvitableItem,
} from './models';

import { ElectroError } from 'electrodb';
import { KMSClient, EncryptCommand, DecryptCommand, GenerateRandomCommand } from '@aws-sdk/client-kms';

import { hkdfSync, randomInt, randomBytes } from 'node:crypto';
import { setTimeout } from 'node:timers/promises';
import { sign, verify, decode, type JwtPayload } from 'jsonwebtoken';
import { postCleanupTestUsers, postConsistency, postLoadAAGUIDs, postMunge } from './internal';
import {
   ParamError,
   AuthError,
   NotFoundError,
   sanitizeString,
   validB64,
   validUserCredEnc,
   verifyRecoveryNonceProof,
   verifyUserCredNonceProof,
   verifyUserCredChallengeProof,
   verifyRecoverConfirmProof,
   base64UrlEncode,
   base64UrlDecode,
   knownLenTimingSafeEqual,
   isReservedTestUserName,
   consumeChallenge,
   storeChallenge,
   type Challenge,
} from './utils';

export type Response = {
   // biome-ignore lint/suspicious/noExplicitAny: response bodies are arbitrary JSON
   content: Record<string, any>;
   startSession?: VerifiedUserItem;
   endSession?: boolean;
   returnCsrf?: boolean;
};

import * as api from '@qcrypt/api';
import { cryptoReady, hashString, base64ToBytes } from '@qcrypt/crypto';

type AAGUIDInfo = {
   data: {
      lightIcon: string;
      darkIcon: string;
      name: string;
   };
   timestamp: number;
};

export const lightFileDefault = 'assets/aaguid/img/default_light.svg';
export const darkFileDefault = 'assets/aaguid/img/default_dark.svg';

const aaguidCache = new Map<string, AAGUIDInfo>();
const AAGUID_CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

// The WebAuthn spec keeps adding transports, so bound the shape rather than enumerate
// values and reject an authenticator newer than this code
const TRANSPORT_MAX_COUNT = 8;
const TRANSPORT_PATTERN = /^[a-z-]{1,16}$/;

enum EventNames {
   AuthOptions = 'AuthOptions',
   AuthVerify = 'AuthVerify',
   RegOptions = 'RegOptions',
   RegVerify = 'RegVerify',
   RegDelete = 'RegDelete',
   UserDelete = 'UserDelete',
   PutDescription = 'PutDescription',
   PutUserName = 'PutUserName',
   PutRecover3Key = 'PutRecover3Key',
   Recover = 'Recover',
   GetRecovery = 'GetRecovery',
}

export const kmsClient = new KMSClient({ region: 'us-east-1' });
let jwtMaterial: Uint8Array | undefined;
const INTERNAL_PHRASE = "Yup, I'm internal";

const RECENT_COOKIE_SEC = 10;

await cryptoReady();

function isVerified(unverifiedUser: UnverifiedUserItem, userId: string): unverifiedUser is VerifiedUserItem {
   return (
      unverifiedUser?.verified &&
      unverifiedUser.userId === userId &&
      validB64(unverifiedUser.userId) &&
      validB64(unverifiedUser.userCredEnc) &&
      unverifiedUser.prf !== undefined &&
      unverifiedUser.userName !== undefined &&
      unverifiedUser.userName.length > 0 &&
      unverifiedUser.createdAt !== undefined
   );
}

function checkVerified(unverifiedUser: UnverifiedUserItem, userId: string): VerifiedUserItem {
   if (!isVerified(unverifiedUser, userId)) {
      throw new AuthError();
   }
   return unverifiedUser;
}

async function encryptField(
   field: Uint8Array,
   context: { [key: string]: string },
   keyId: string = cc.KMS_KEYID_NEW,
): Promise<string> {
   if (!keyId) {
      throw new Error('missing kms keyid');
   }

   const enc = new EncryptCommand({
      Plaintext: field,
      KeyId: keyId,
      EncryptionContext: context,
   });

   const result = await kmsClient.send(enc);
   if (!result.CiphertextBlob) {
      throw new Error('field encryption failed');
   }

   return base64UrlEncode(result.CiphertextBlob)!;
}

export async function decryptField(
   fieldEnc: string,
   context: { [key: string]: string },
   expectedBytes: number,
   keyId: string = cc.KMS_KEYID_NEW,
): Promise<Uint8Array> {
   if (!keyId) {
      throw new Error('missing kms keyid');
   }

   const fieldEncBytes = base64UrlDecode(fieldEnc);
   const dec = new DecryptCommand({
      CiphertextBlob: fieldEncBytes,
      KeyId: keyId,
      EncryptionContext: context,
   });

   const result = await kmsClient.send(dec);
   if (!result.Plaintext || result.Plaintext.byteLength !== expectedBytes) {
      throw new Error('field decryption failed');
   }

   return result.Plaintext!;
}

async function setupJwtMaterial(): Promise<Uint8Array> {
   if (!process.env.EncMaterial) {
      throw new Error('missing environment value');
   }

   try {
      const encodedMaterial = await decryptField(process.env.EncMaterial, { purpose: 'jwt' }, cc.JWTMATERIAL_BYTES);

      if (!encodedMaterial) {
         throw new Error('encoded material undefined');
      }
      return encodedMaterial;
   } catch (error) {
      console.error('auth setup errror', error);
      throw new Error('auth setup error');
   }
}

async function recordEvent(eventName: EventNames, userId: string, credentialId: string | undefined = undefined) {
   try {
      await AuthEvents.create({
         event: eventName,
         userId,
         credentialId,
      }).go();
   } catch (error) {
      // log but eat the error
      console.error(error);
   }
}

async function getSession(_httpDetails: HttpDetails, verifiedUser: VerifiedUserItem): Promise<Response> {
   const responseContent = await makeLoginUserInfoResponse(verifiedUser, null);

   // Return passed in csrf but don't start new session so that expiration is not reset
   return {
      content: responseContent,
      returnCsrf: true,
   };
}

// authCount is incremented atomically so concurrent calls receive distinct values
async function _setLastCredential(user: UnverifiedUserItem, credentialId: string | null): Promise<void> {
   if (credentialId === '') {
      throw new Error('empty credential id');
   }

   const lastCredentialId = credentialId ?? '';
   const updated = await Users.patch({
      userId: user.userId,
   })
      .set({
         lastCredentialId,
      })
      .add({
         authCount: 1,
      })
      .go({ response: 'all_new' });

   user.lastCredentialId = lastCredentialId;
   user.authCount = updated.data.authCount;
}

function buildChallenge(
   challenge: string,
   spec:
      | { purpose: 'auth'; userId: string }
      | { purpose: 'reg' | 'add' | 'recover' | 'confirm'; user: UnverifiedUserItem },
): Challenge {
   if (!validB64(challenge) || base64UrlDecode(challenge)?.byteLength !== cc.CHALLENGE_BYTES) {
      throw new ParamError('challenge not valid');
   }

   let result: Challenge;
   if (spec.purpose === 'auth') {
      result = { challenge, purpose: spec.purpose, userId: spec.userId };
   } else if (spec.purpose === 'reg' && !spec.user.userCredPubKey) {
      // BACKWARD COMPAT: a user whose client omitted userCredPubKey from reg/options gets an
      // unbound challenge
      result = { challenge, purpose: spec.purpose, userId: spec.user.userId, binding: undefined };
   } else if (!spec.user.userCredPubKey) {
      throw new AuthError();
   } else if (spec.purpose === 'reg' || spec.purpose === 'add') {
      result = {
         challenge,
         purpose: spec.purpose,
         userId: spec.user.userId,
         binding: hashString(spec.user.userCredPubKey),
      };
   } else {
      const { recoveryPubKey, authCount, userCredPubKey } = spec.user;
      result = {
         challenge,
         purpose: spec.purpose,
         userId: spec.user.userId,
         binding: hashString(`${recoveryPubKey ?? ''}:${authCount}:${userCredPubKey}`),
      };
   }
   return result;
}

async function deleteSession(_httpDetails: HttpDetails, verifiedUser: VerifiedUserItem): Promise<Response> {
   await _setLastCredential(verifiedUser, null);

   return {
      content: { message: 'done' },
      endSession: true,
   };
}

async function postAuthVerify(httpDetails: HttpDetails): Promise<Response> {
   const { rpID, rpOrigin } = httpDetails;
   const authVerifyRequest = httpDetails.body as api.AuthVerifyRequest;

   const userHandle = authVerifyRequest.response?.userHandle;
   if (!userHandle) {
      throw new ParamError('missing userHandle');
   }
   if (!validB64(userHandle) || base64UrlDecode(userHandle)?.length !== cc.USERID_BYTES) {
      throw new ParamError('invalid userHandle');
   }
   if (!validB64(authVerifyRequest.id)) {
      throw new ParamError('invalid authenticatorId');
   }

   // Unbound auth challenges are allowed for discoverable credential flow.
   const challenge = await consumeChallenge(
      buildChallenge(authVerifyRequest.challenge, { purpose: 'auth', userId: userHandle }),
   );

   // Read consistently so a passkey created moments earlier is found
   const credResult = await Authenticators.get({
      userId: userHandle,
      credentialId: authVerifyRequest.id,
   }).go({ consistent: true });

   if (!credResult?.data) {
      // Timing parity for the credential-not-found branch.
      try {
         await getUnverifiedUser('AAAAAAAAAAAAAAAAAAAAAA', true);
      } catch {
         /* expected */
      }
      try {
         await verifyAuthenticationResponse({
            response: api.toAuthenticationResponseJSON(authVerifyRequest),
            expectedChallenge: challenge.challenge,
            expectedOrigin: rpOrigin,
            expectedRPID: rpID,
            credential: {
               publicKey: randomBytes(77),
               id: 'AAAAAAAAAAAAAAAAAAAAAA',
               counter: 0,
               transports: ['internal'],
            },
         });
      } catch {
         /* expected */
      }

      // Jitter blurs the residual gap: empty vs populated DDB returns, etc
      await setTimeout(randomInt(5, 45));
      throw new AuthError();
   }

   const authenticator = credResult.data;
   const unverifiedUser = await getUnverifiedUser(authenticator.userId, true);

   const webAuthnCredential: WebAuthnCredential = {
      publicKey: base64UrlDecode(authenticator.credentialPublicKey)!,
      id: authenticator.credentialId,
      counter: 0, // not using counters
      transports: authenticator.transports,
   };

   let verification: VerifiedAuthenticationResponse;
   try {
      verification = await verifyAuthenticationResponse({
         response: api.toAuthenticationResponseJSON(authVerifyRequest),
         expectedChallenge: challenge.challenge,
         expectedOrigin: rpOrigin,
         expectedRPID: rpID,
         requireUserVerification: true,
         credential: webAuthnCredential,
      });
   } catch (error) {
      console.error(error);
      throw new AuthError();
   }

   // @simplewebauthn returns verified:false (without throwing) when signature check
   // fails. Return same 401 as other failures to avoid leaking information
   if (!verification.verified) {
      throw new AuthError();
   }

   const verifiedUser = checkVerified(unverifiedUser, authenticator.userId);
   const startSession = verifiedUser;

   // ok if this fails
   const patchAuths = Authenticators.patch({
      userId: authenticator.userId,
      credentialId: authenticator.credentialId,
   })
      .set({
         lastLogin: Date.now(),
      })
      .go();

   await Promise.all([patchAuths, _setLastCredential(verifiedUser, authenticator.credentialId)]);

   const responseContent = await makeLoginUserInfoResponse(
      verifiedUser,
      authenticator,
      await loadAuthenticators(verifiedUser, true),
   );

   // Let this happen async
   recordEvent(EventNames.AuthVerify, unverifiedUser.userId, authenticator.credentialId);

   return {
      content: responseContent,
      startSession,
   };
}

async function postPasskeyVerify(httpDetails: HttpDetails, verifiedUser: VerifiedUserItem): Promise<Response> {
   const addVerifyRequest = httpDetails.body as api.AddVerifyRequest;

   if (verifiedUser.prf && !addVerifyRequest.passkeyUserCredEnc) {
      throw new ParamError(`missing passkey userCred ciphertext for ${verifiedUser.userId}`);
   }
   if (!verifiedUser.prf && addVerifyRequest.passkeyUserCredEnc) {
      throw new ParamError(`unexpected passkey userCred ciphertext ${verifiedUser.userId}`);
   }

   const auth = await _createAuthenticator(
      httpDetails,
      verifiedUser,
      buildChallenge(addVerifyRequest.challenge, { purpose: 'add', user: verifiedUser }),
   );

   // force consistent read to capture recent create authenticator
   const authenticators = await loadAuthenticators(verifiedUser, true);
   const responseContent = await makeLoginUserInfoResponse(verifiedUser, null, authenticators);

   // Let this happen async
   recordEvent(EventNames.RegVerify, verifiedUser.userId, auth.credentialId);
   return { content: responseContent };
}

async function postRegVerify(
   httpDetails: HttpDetails,
   unverifiedUser: UnverifiedUserItem,
   // BACKWARD COMPAT: remove once x-challenge-proof is required
   proved: boolean,
): Promise<Response> {
   const regVerifyRequest = httpDetails.body as api.RegVerifyRequest;

   if (unverifiedUser.verified) {
      throw new ParamError();
   }

   // Careful to never overwrite userCredEnc (due to a bug or whatever)
   if (unverifiedUser.userCredEnc) {
      throw new ParamError(`unexpected user credential for ${unverifiedUser.userId}`);
   }

   // BACKWARD COMPAT: a request without a challenge proof must find no userCredPubKey stored by
   // reg/options, and supplies the key in its body. A proved request must not carry a key of its
   // own. Once x-challenge-proof is required, reject any key in the body.
   if (
      (!proved && unverifiedUser.userCredPubKey !== undefined) ||
      (proved && regVerifyRequest.userCredPubKey !== undefined)
   ) {
      throw new ParamError('invalid registration proof');
   }
   // BACKWARD COMPAT: use only the stored key once x-challenge-proof is required
   let userCredPubKey = unverifiedUser.userCredPubKey ?? regVerifyRequest.userCredPubKey;

   // Validate the client credential fields before creating the passkey so invalid input
   // never leaves a passkey behind.
   const hasPrf = !!regVerifyRequest.recoveryUserCredEnc || !!regVerifyRequest.passkeyUserCredEnc;
   const hasUserCred = regVerifyRequest.userCred !== undefined;

   // BACKWARD COMPAT: change this to `hasPrf === hasUserCred` once clients without proofs are gone.
   // Their no-PRF requests carry neither field.
   if (hasPrf && hasUserCred) {
      throw new ParamError('invalid user credential data');
   }
   if (
      hasPrf &&
      (!validUserCredEnc(regVerifyRequest.recoveryUserCredEnc) ||
         !validUserCredEnc(regVerifyRequest.passkeyUserCredEnc))
   ) {
      throw new ParamError('invalid user credential data');
   }
   if (hasUserCred) {
      const userCred = base64ToBytes(regVerifyRequest.userCred!, cc.USERCRED_BYTES, 'user credential');
      // Confirm the userCred derives the public key provided
      if (api.getUserCredPubKey(userCred) !== userCredPubKey) {
         throw new ParamError('user credential does not match its public key');
      }
   }
   if (hasPrf || hasUserCred) {
      base64ToBytes(userCredPubKey!, api.PROOF_PUBKEY_BYTES, 'user credential public key');
   }

   // The client generates the recovery secret and sends only its public key
   const recoveryPubKey = regVerifyRequest.recoveryPubKey;
   base64ToBytes(recoveryPubKey, api.PROOF_PUBKEY_BYTES, 'recovery public key');

   // BACKWARD COMPAT: run this block unconditionally, and drop the else, once x-challenge-proof is
   // required
   if (proved) {
      // A request with a proof must carry userCred or both ciphertexts. BACKWARD COMPAT: delete this
      // check when the one above changes to `hasPrf === hasUserCred`, which covers it.
      if (!hasPrf && !hasUserCred) {
         throw new ParamError('missing user credential data');
      }
      api.verifyRecoveryChallengeProof(
         recoveryPubKey,
         unverifiedUser.userId,
         regVerifyRequest.recoveryTimestamp!,
         regVerifyRequest.challenge,
         userCredPubKey!,
         regVerifyRequest.recoverySignature!,
      );
   } else if (hasUserCred) {
      throw new ParamError('missing registration proof');
   }

   const auth = await _createAuthenticator(
      httpDetails,
      unverifiedUser,
      buildChallenge(regVerifyRequest.challenge, { purpose: 'reg', user: unverifiedUser }),
   );

   // To reduces calls to KMS when user creation
   // is abandonded, delay creation of random values unit here
   const rparams = {
      NumberOfBytes: cc.USERCRED_BYTES + cc.INVITABLEID_BYTES * cc.RETRIES,
   };
   const rand = new GenerateRandomCommand(rparams);
   const result = await kmsClient.send(rand);

   const randData = result.Plaintext;
   let randOffset = 0;
   if (!randData || randData.byteLength !== rparams.NumberOfBytes) {
      throw new Error('GenerateRandomCommand failure');
   }

   let userCredEnc: string | undefined;
   let userCredEncBackup: string | undefined;

   if (hasPrf) {
      userCredEnc = regVerifyRequest.recoveryUserCredEnc;
   } else {
      // BACKWARD COMPAT: a no-PRF request without userCred gets one from the server
      const userCred = hasUserCred
         ? base64ToBytes(regVerifyRequest.userCred!)
         : randData.slice(randOffset, randOffset + cc.USERCRED_BYTES);
      randOffset += cc.USERCRED_BYTES;
      userCredEnc = await encryptField(userCred, { userId: unverifiedUser.userId });

      userCredEncBackup = await encryptField(userCred, { userId: unverifiedUser.userId }, cc.KMS_KEYID_BACKUP);

      // BACKWARD COMPAT: derive the key of a userCred the server created
      userCredPubKey ??= api.getUserCredPubKey(userCred);
   }

   // Loop in the very unlikley event that we randomly pick
   // a duplicate (out of 3.4e38 possible)
   let invId: string | undefined;
   for (let i = 0; i < cc.RETRIES; ++i) {
      const invIdBytes = randData.slice(randOffset, randOffset + cc.INVITABLEID_BYTES);
      randOffset += cc.INVITABLEID_BYTES;

      invId = base64UrlEncode(invIdBytes)!;
      const invitable = await Invitables.query
         .byInvitableId({
            invitableId: invId,
         })
         .go();

      if (!invitable || invitable.data.length === 0) {
         break;
      } else {
         invId = undefined;
      }
   }

   if (!invId) {
      throw new Error('could not allocate invitableId');
   }

   await Invitables.create({
      userId: unverifiedUser.userId,
      invitableId: invId,
      description: unverifiedUser.userName,
   }).go();

   // Very important that we remove the expiresAt attribute so that the
   // record is not automatically cleaned up by dynamoDB. Note that userCredEnc
   // has differnt content with and without PRF. With PRF it is client-side encrypted
   // and without it is server-side encrypted
   await Users.patch({
      userId: unverifiedUser.userId,
   })
      .set({
         verified: true,
         prf: hasPrf,
         userCredEnc,
         userCredEncOld: userCredEncBackup,
         userCredPubKey,
         recoveryPubKey,
         lastCredentialId: auth.credentialId,
         authCount: 1,
      })
      .remove(['expiresAt'])
      .go();

   unverifiedUser.verified = true;
   unverifiedUser.prf = hasPrf;
   unverifiedUser.userCredEnc = userCredEnc;
   unverifiedUser.userCredPubKey = userCredPubKey;
   unverifiedUser.recoveryPubKey = recoveryPubKey;
   unverifiedUser.lastCredentialId = auth.credentialId;
   unverifiedUser.authCount = 1;

   // should now be verified
   const verifiedUser = checkVerified(unverifiedUser, auth.userId);

   // force consistent read to capture recent create
   const authenticators = await loadAuthenticators(verifiedUser, true);
   const responseContent = await makeLoginUserInfoResponse(verifiedUser, hasPrf ? null : auth, authenticators);

   // Let this happen async
   recordEvent(EventNames.RegVerify, verifiedUser.userId, auth.credentialId);
   return {
      content: responseContent,
      startSession: verifiedUser,
   };
}

// BACKWARD COMPAT: this route accepts a request without x-challenge-proof, which carries no userCred
// proof at all
async function postRecoverVerify(httpDetails: HttpDetails, unverifiedUser: UnverifiedUserItem): Promise<Response> {
   const recoverVerifyRequest = httpDetails.body as api.RecoverVerifyRequest;

   // should be empty for recovered account
   if (unverifiedUser.lastCredentialId) {
      throw new ParamError(`lastCredentialId should not be set during recovery for ${unverifiedUser.userId}`);
   }
   if (!unverifiedUser.verified) {
      throw new ParamError(`cannot recover unverified account ${unverifiedUser.userId}`);
   }
   if (unverifiedUser.prf && !recoverVerifyRequest.passkeyUserCredEnc) {
      throw new ParamError(`missing passkey userCred ciphertext for ${unverifiedUser.userId}`);
   }
   if (!unverifiedUser.prf && recoverVerifyRequest.passkeyUserCredEnc) {
      throw new ParamError(`unexpected passkey userCred ciphertext ${unverifiedUser.userId}`);
   }

   const auth = await _createAuthenticator(
      httpDetails,
      unverifiedUser,
      buildChallenge(recoverVerifyRequest.challenge, { purpose: 'recover', user: unverifiedUser }),
   );

   await _setLastCredential(unverifiedUser, auth.credentialId);

   const verifiedUser = checkVerified(unverifiedUser, auth.userId);

   // force consistent read to capture just created authenticator
   const authenticators = await loadAuthenticators(verifiedUser, true);
   const responseContent = await makeLoginUserInfoResponse(
      verifiedUser,
      verifiedUser.prf ? null : auth,
      authenticators,
   );

   // Let this happen async
   recordEvent(EventNames.RegVerify, verifiedUser.userId, auth.credentialId);
   return {
      content: responseContent,
      startSession: verifiedUser,
   };
}

async function _createAuthenticator(
   httpDetails: HttpDetails,
   unverifiedUser: UnverifiedUserItem,
   check: Challenge,
): Promise<AuthItem> {
   const { rpID, rpOrigin } = httpDetails;
   const passkeyVerifyRequest = httpDetails.body as api.PasskeyVerifyRequest;

   if (!validB64(passkeyVerifyRequest.challenge)) {
      throw new ParamError('invalid challenge format');
   }
   if (passkeyVerifyRequest.passkeyUserCredEnc && !validUserCredEnc(passkeyVerifyRequest.passkeyUserCredEnc)) {
      throw new ParamError('invalid passkey userCred ciphertext');
   }

   const transports = passkeyVerifyRequest.response.transports;
   if (transports) {
      if (transports.length > TRANSPORT_MAX_COUNT || !transports.every((tport) => TRANSPORT_PATTERN.test(tport))) {
         throw new ParamError('invalid transports');
      }
   }

   const challenge = await consumeChallenge(check);

   let verification: VerifiedRegistrationResponse;
   try {
      verification = await verifyRegistrationResponse({
         response: api.toRegistrationResponseJSON(passkeyVerifyRequest),
         expectedChallenge: challenge.challenge,
         expectedOrigin: rpOrigin,
         expectedRPID: rpID,
         requireUserVerification: true,
         supportedAlgorithmIDs: cc.ALGIDS,
      });
   } catch (err) {
      console.error(err);
      throw new AuthError();
   }

   if (!verification.verified) {
      throw new AuthError();
   }

   const { aaguid, credential, attestationObject, userVerified, credentialDeviceType, credentialBackedUp, origin } =
      verification.registrationInfo!;

   const { id, publicKey } = credential;

   const aaguidDetails = await AAGUIDs.get({
      aaguid,
   }).go();

   let description = 'Passkey';

   if (aaguidDetails?.data) {
      description = aaguidDetails.data.name ?? 'Passkey';
      description = description.slice(0, cc.DESC_MAX_LEN);
   } else {
      console.error('aaguid not found:', JSON.stringify(aaguid));
   }

   // SimpleWebAuthen renamed these to WebAuthnCredential, now we have a missmatch
   const auth = await Authenticators.create({
      userId: unverifiedUser.userId,
      description,
      credentialId: id,
      credentialPublicKey: base64UrlEncode(publicKey)!,
      credentialDeviceType,
      userVerified,
      credentialBackedUp,
      transports,
      userCredEnc: passkeyVerifyRequest.passkeyUserCredEnc,
      origin,
      aaguid,
      attestationObject: base64UrlEncode(attestationObject),
   }).go();

   return auth.data;
}

// Dummy allowCredentials list for unknown/invalid userIds to defeat
// enumeration via /v1/auth/options. Determinism (seeded by jwtMaterial + inputUserId)
// means repeat probes for the same bad userId return the same list
async function dummyAllowedCreds(inputUserId: string): Promise<PublicKeyCredentialDescriptorJSON[]> {
   if (!jwtMaterial) {
      jwtMaterial = await setupJwtMaterial();
   }

   // Must cover the 2-byte profile pick plus the longest dummy credential id (48 bytes)
   const material = Buffer.from(hkdfSync('sha256', jwtMaterial, Buffer.from(inputUserId), 'dummy-auth-options', 64));

   // Cumulative weights reflect the observed (len, transports) distribution
   // in the Authenticators table. Ceil is summed weights. Since 98% of users have
   // exactly one credential, we return a single entry. Resample and retune
   // as the mix shifts.
   const profiles: { ceil: number; len: number; transports: string[] }[] = [
      { ceil: 82, len: 16, transports: ['hybrid', 'internal'] },
      { ceil: 124, len: 32, transports: ['internal'] },
      { ceil: 143, len: 20, transports: ['hybrid', 'internal'] },
      { ceil: 147, len: 16, transports: ['internal'] },
      { ceil: 149, len: 48, transports: ['usb'] },
   ];

   const pick = material.readUInt16BE(0) % 149;
   const profile = profiles.find((p) => pick < p.ceil)!;
   const id = material.subarray(2, 2 + profile.len);
   return [
      {
         id: base64UrlEncode(id)!,
         type: 'public-key',
         transports: profile.transports,
      },
   ];
}

async function postAuthOptions(httpDetails: HttpDetails): Promise<Response> {
   const { rpID } = httpDetails;
   const authOptionsRequest = httpDetails.body as api.AuthOptionsRequest;

   let userId = cc.UNKNOWN_USER_ID;
   const unverifiedUserId = authOptionsRequest?.userId;

   // If no userid is provided, then we don't return allowed creds and
   // the user is forced to pick one on their own. That happens when the user is
   // linking a new device to a existing passkey or has fully signed out
   let allowedCreds: PublicKeyCredentialDescriptorJSON[] | undefined;

   if (unverifiedUserId) {
      // To prevent callers from using this to guess userids, the "user not found"
      // and "user has no auths" paths fall through to return dummy responses.
      try {
         const unverifiedUser = await getUnverifiedUser(unverifiedUserId);
         userId = unverifiedUser.userId;
         const auths = await Authenticators.query
            .byUserId({
               userId,
            })
            .go();

         if (auths && auths.data.length > 0) {
            allowedCreds = auths.data.map((cred: AuthItem) => ({
               id: cred.credentialId,
               type: 'public-key',
               transports: cred.transports,
            }));
         }
      } catch (err) {
         // the userId itself was invalid, and we should fail rather return dummy
         if (err instanceof ParamError) {
            throw err;
         }
         console.error(err);
      }

      if (!allowedCreds) {
         allowedCreds = await dummyAllowedCreds(unverifiedUserId);
         // Binds like a real account so the challenge is locked to the guessed userId
         userId = unverifiedUserId;

         // Jitter blurs the gap between this path's empty lookups and the
         // real path's populated DDB get + query.
         await setTimeout(randomInt(5, 95));
      }
   }

   try {
      const options: PublicKeyCredentialRequestOptionsJSON = await generateAuthenticationOptions({
         allowCredentials: allowedCreds,
         rpID,
         userVerification: 'preferred',
      });

      await storeChallenge(buildChallenge(options.challenge, { purpose: 'auth', userId }));

      // Let this happen async. Don't report a credentialId since
      // there could be none or multiple
      recordEvent(EventNames.AuthOptions, userId);

      return { content: api.makeAuthOptionsResponse(options) };
   } catch (err) {
      console.error(err);
      throw new Error('unable to generate authentication options');
   }
}

async function getPasskeyOptions(httpDetails: HttpDetails, verifiedUser: VerifiedUserItem): Promise<Response> {
   const { rpID } = httpDetails;

   return registrationOptions(rpID, verifiedUser, (challenge) =>
      buildChallenge(challenge, { purpose: 'add', user: verifiedUser }),
   );
}

async function postRegOptions(httpDetails: HttpDetails): Promise<Response> {
   const { rpID } = httpDetails;
   const regOptionsRequest = httpDetails.body as api.RegOptionsRequest;

   // Totally new user, must provide a username
   const userName = sanitizeString(regOptionsRequest.userName);
   if (userName.length < cc.UNAME_MIN_LEN || userName.length > cc.UNAME_MAX_LEN) {
      throw new ParamError('user name must greater than 5 and less than 32 characters');
   }

   // Some names reserved for automated tests, so cleanup is safer. Not a security
   // control since its easily spoofed, just a guardrail against admin errors.
   if (isReservedTestUserName(userName) && !isTestClient(httpDetails)) {
      throw new ParamError('reserved username prefix');
   }

   // BACKWARD COMPAT: userCredPubKey is optional only for clients that omit it
   const userCredPubKey = regOptionsRequest.userCredPubKey;
   if (userCredPubKey !== undefined) {
      base64ToBytes(userCredPubKey, api.PROOF_PUBKEY_BYTES, 'user credential public key');
   }

   let uId: string | undefined;

   // Reduce round-trips by getting enough data for 3 x 16 bytes ID tries
   // and 1 x 32 bytes userCred
   const rparams = {
      NumberOfBytes: cc.RETRIES * cc.USERID_BYTES,
   };
   const rand = new GenerateRandomCommand(rparams);
   const result = await kmsClient.send(rand);

   const randData = result.Plaintext;
   if (!randData || randData.byteLength !== rparams.NumberOfBytes) {
      throw new Error('GenerateRandomCommand failure');
   }

   let randOffset = 0;

   // Loop in the very unlikley event that we randomly pick
   // a duplicate (out of 3.4e38 possible)
   for (let i = 0; i < cc.RETRIES; ++i) {
      const uIdBytes = randData.slice(randOffset, randOffset + cc.USERID_BYTES);
      randOffset += cc.USERID_BYTES;

      uId = base64UrlEncode(uIdBytes)!;

      const users = await Users.query
         .byUserId({
            userId: uId,
         })
         .go({ attributes: ['userId'] });

      if (!users || users.data.length === 0) {
         break;
      } else {
         uId = undefined;
      }
   }

   if (!uId) {
      throw new Error('could not allocate userId');
   }

   // TTL value that DynamoDB references to delete recrod 1 day from now if
   // the registration is not verified (verify removes expiresAt attribute)
   const expires = Math.floor(Date.now() / 1000) + 86400;

   const user = await Users.create({
      userId: uId,
      userName,
      expiresAt: expires,
      userCredEnc: undefined,
      userCredPubKey,
   }).go();

   return registrationOptions(rpID, user.data, (challenge) =>
      buildChallenge(challenge, { purpose: 'reg', user: user.data }),
   );
}

async function registrationOptions(
   rpID: string,
   unverifiedUser: UnverifiedUserItem,
   build: (challenge: string) => Challenge,
): Promise<Response> {
   if (!unverifiedUser) {
      throw new ParamError('invalid user');
   }

   try {
      // Consistent so the list matches the stored passkeys
      const auths = await Authenticators.query
         .byUserId({
            userId: unverifiedUser.userId,
         })
         .go({ consistent: true });

      let excludeCreds: {
         id: string;
         transports?: string[];
      }[] = [];

      if (auths?.data) {
         excludeCreds = auths.data.map((cred: AuthItem) => ({
            id: cred.credentialId,
            transports: cred.transports,
         }));
      }

      const options: PublicKeyCredentialCreationOptionsJSON = await generateRegistrationOptions({
         rpName: cc.RPNAME,
         rpID,
         userID: base64UrlDecode(unverifiedUser.userId),
         userName: unverifiedUser.userName,
         attestationType: 'none',
         excludeCredentials: excludeCreds, // prevent re-registering existing passkeys
         authenticatorSelection: {
            residentKey: 'required',
            userVerification: 'required',
         },
         supportedAlgorithmIDs: cc.ALGIDS,
      });

      await storeChallenge(build(options.challenge));

      // Let this happen async
      recordEvent(EventNames.RegOptions, unverifiedUser.userId);
      return { content: api.makeRegOptionsResponse(options) };
   } catch (err) {
      console.error(err);
      throw new Error('unable to generate registration options');
   }
}

// A non-null passkey adds the user credential to the response and must be the record of
// verifiedUser.lastCredentialId
async function makeLoginUserInfoResponse(
   verifiedUser: VerifiedUserItem,
   passkey: AuthItem | null,
   auths?: api.AuthenticatorInfoResponse[],
): Promise<api.LoginUserInfoResponse> {
   const userInfo = await makeUserInfoResponse(verifiedUser, auths);

   try {
      let userCred: string | undefined;
      let passkeyUserCredEnc: string | undefined;

      if (passkey) {
         if (passkey.credentialId !== verifiedUser.lastCredentialId) {
            throw new Error('passkey is not the last credential');
         }
         if (verifiedUser.prf) {
            passkeyUserCredEnc = passkey.userCredEnc;
            if (!passkeyUserCredEnc) {
               throw new Error('missing encrypted user credential');
            }
         } else {
            const decrypted = await decryptField(
               verifiedUser.userCredEnc,
               { userId: verifiedUser.userId },
               cc.USERCRED_BYTES,
            );

            userCred = base64UrlEncode(decrypted);
         }
      }

      return {
         ...userInfo,
         userCred,
         passkeyUserCredEnc,
         pkId: verifiedUser.lastCredentialId,
      };
   } catch (error) {
      console.error('auth setup errror', error);
      throw new AuthError('auth setup error');
   }
}

async function makeUserInfoResponse(
   verifiedUser: VerifiedUserItem,
   auths?: api.AuthenticatorInfoResponse[],
   invitables?: api.InvitableInfoResponse[],
): Promise<api.UserInfoResponse> {
   auths = auths ?? (await loadAuthenticators(verifiedUser));
   invitables = invitables ?? (await loadInvitables(verifiedUser));

   // user explicit assignment rather than spread operator to prevent leaking information
   // in UserItem table that is internal only or provided separatly
   const userInfo: api.UserInfoResponse = {
      verified: verifiedUser.verified,
      userId: verifiedUser.userId,
      userName: verifiedUser.userName,
      recoveryKeyId: verifiedUser.recoveryPubKey ? hashString(verifiedUser.recoveryPubKey) : undefined,
      prf: verifiedUser.prf,
      authenticators: auths,
      invitables,
   };

   return userInfo;
}

function makeInvitableResponse(invitable: InvitableItem): api.InvitableInfoResponse {
   const invitableInfo: api.InvitableInfoResponse = {
      invitableId: invitable.invitableId,
      description: invitable.description,
   };

   return invitableInfo;
}

async function patchPasskey(httpDetails: HttpDetails, verifiedUser: VerifiedUserItem): Promise<Response> {
   const { resources } = httpDetails;
   const patchPasskeyRequest = httpDetails.body as api.PatchPasskeyRequest;

   // only desciption can be changed
   const description = sanitizeString(patchPasskeyRequest.description);
   if (description.length < cc.DESC_MIN_LEN || description.length > cc.DESC_MAX_LEN) {
      throw new ParamError(
         `description must be more than ${cc.DESC_MIN_LEN - 1} and less than ${cc.DESC_MAX_LEN + 1} character`,
      );
   }

   const credId = resources.credid;
   if (!validB64(credId)) {
      throw new ParamError('invalid credential id');
   }

   // This will raise if credId is invalid, catch to return a consistend error
   try {
      await Authenticators.patch({
         userId: verifiedUser.userId,
         credentialId: credId!,
      })
         .set({
            description,
         })
         .go();
   } catch (err) {
      if (err instanceof ElectroError) {
         console.error(err);
         throw new ParamError('description update failed');
      }
      throw err;
   }

   // force consistent read to capture patch
   const auths = await loadAuthenticators(verifiedUser, true);

   // Let this happen async
   recordEvent(EventNames.PutDescription, verifiedUser.userId, credId);

   // return with full api.UserInfoResponse to make client side refresh simpler
   const response = await makeUserInfoResponse(verifiedUser, auths);
   return { content: response };
}

async function patchUser(httpDetails: HttpDetails, verifiedUser: VerifiedUserItem): Promise<Response> {
   const patchUserRequest = httpDetails.body as api.PatchUserRequest;

   // Only support userName changes
   const userName = sanitizeString(patchUserRequest.userName);
   if (userName.length < cc.UNAME_MIN_LEN || userName.length > cc.UNAME_MAX_LEN) {
      throw new ParamError(
         `username must be more than ${cc.UNAME_MIN_LEN - 1} and less than ${cc.UNAME_MAX_LEN + 1} character`,
      );
   }

   // Same guardrail as postRegOptions, reserved for testing (and cleanup)
   if (isReservedTestUserName(userName) && !isTestClient(httpDetails)) {
      throw new ParamError('reserved username prefix');
   }

   try {
      await Users.patch({
         userId: verifiedUser.userId,
      })
         .set({
            userName,
         })
         .go();
   } catch (err) {
      if (err instanceof ElectroError) {
         console.error(err);
         throw new ParamError('username update failed');
      }
      throw err;
   }

   // Let this happen async
   recordEvent(EventNames.PutUserName, verifiedUser.userId, verifiedUser.lastCredentialId);

   // return with full api.UserInfoResponse to make client side refresh simpler
   verifiedUser.userName = userName;
   const response = await makeUserInfoResponse(verifiedUser);
   return { content: response };
}

// Updates a user's recovery public key after they regenerate their recovery words.
async function putRecover3Key(httpDetails: HttpDetails, verifiedUser: VerifiedUserItem): Promise<Response> {
   const recover3KeyRequest = httpDetails.body as api.Recover3KeyRequest;

   const recoveryPubKey = recover3KeyRequest?.recoveryPubKey;
   if (!validB64(recoveryPubKey) || base64UrlDecode(recoveryPubKey)!.length !== api.PROOF_PUBKEY_BYTES) {
      throw new ParamError('invalid recovery public key');
   }

   // Verified against the submitted key, so the caller must hold its secret.
   await verifyRecoveryNonceProof(recoveryPubKey, verifiedUser.userId, recover3KeyRequest, 'replace');

   const updates: { recoveryPubKey: string; userCredEnc?: string } = {
      recoveryPubKey,
   };

   // A PRF account keeps userCred encrypted with the recovery secret in userCredEnc, so new
   // recovery words re-encrypt and send it.
   if (verifiedUser.prf) {
      if (!validUserCredEnc(recover3KeyRequest.userCredEnc)) {
         throw new ParamError('invalid user credential');
      }
      updates.userCredEnc = recover3KeyRequest.userCredEnc;
   }

   await Users.patch({
      userId: verifiedUser.userId,
   })
      .set(updates)
      .go();

   // Let this happen async
   recordEvent(EventNames.PutRecover3Key, verifiedUser.userId, verifiedUser.lastCredentialId);

   // return with full api.UserInfoResponse to make client side refresh simpler. Callers treat
   // success as proof of commit, so only return after the write
   verifiedUser.recoveryPubKey = recoveryPubKey!;
   const response = await makeUserInfoResponse(verifiedUser);
   return { content: response };
}

// Not tracking events for this method since they are frequent and not particularly
// interesting
async function getInvitables(httpDetails: HttpDetails, _verifiedUser: VerifiedUserItem): Promise<Response> {
   const { resources } = httpDetails;

   const invitableId = resources.invid;
   if (!validB64(invitableId)) {
      throw new ParamError('invalid invitable id');
   }

   // May not want to bring back all parameter
   const invitables = await Invitables.query
      .byInvitableId({
         invitableId,
      })
      .go();

   if (!invitables || invitables.data.length === 0) {
      throw new ParamError('invalid invitable id');
   }

   const response = makeInvitableResponse(invitables.data[0]);
   return { content: response };
}

// Not tracking events for this method since they are frequent and not particlyarly
// interesting
async function getUser(_httpDetails: HttpDetails, verifiedUser: VerifiedUserItem): Promise<Response> {
   const response = await makeUserInfoResponse(verifiedUser);
   return { content: response };
}

// Ensures every passkey is deleted, raising an exception to abort the caller if any survive.
// Reads 'all' pages because the 1MB query budget is charged against full items, and reads
// consistently so no passkeys are missed
async function deleteAllAuthenticators(verifiedUser: VerifiedUserItem): Promise<void> {
   const auths = await Authenticators.query
      .byUserId({
         userId: verifiedUser.userId,
      })
      .go({ attributes: ['userId', 'credentialId'], pages: 'all', consistent: true });

   let pending = auths?.data ?? [];
   for (let attempt = 0; pending.length !== 0 && attempt < cc.RETRIES; attempt++) {
      // A batch delete skips items rather than failing, reporting them as unprocessed
      const deleted = await Authenticators.delete(pending).go();
      pending = deleted?.unprocessed ?? [];
   }

   if (pending.length !== 0) {
      throw new Error(`failed to delete all passkeys for ${verifiedUser.userId}`);
   }
}

export async function loadAuthenticators(
   verifiedUser: VerifiedUserItem,
   consistent: boolean = false,
): Promise<api.AuthenticatorInfoResponse[]> {
   const auths = await Authenticators.query
      .byUserId({
         userId: verifiedUser.userId,
      })
      .go({
         attributes: ['description', 'credentialId', 'aaguid', 'createdAt'],
         consistent,
         pages: 'all',
      });

   if (!auths || auths.data.length === 0) {
      return [];
   }

   // sort ascending (oldest to newest)
   auths.data.sort((left, right) => {
      return (left.createdAt ?? 0) - (right.createdAt ?? 0);
   });

   const aaguids = new Set<string>(auths.data.map((cred) => cred.aaguid || ''));
   const aaguidsToGet: string[] = [];

   for (const aaguid of aaguids) {
      const cachedItem = aaguidCache.get(aaguid);
      if (!cachedItem || Date.now() - cachedItem.timestamp > AAGUID_CACHE_TTL_MS) {
         aaguidsToGet.push(aaguid);
      }
   }

   if (aaguidsToGet.length > 0) {
      // AAGUIDs not in the table keep these defaults, so they aren't looked up on every call
      const timestamp = Date.now();
      const defaultData = { lightIcon: lightFileDefault, darkIcon: darkFileDefault, name: 'Passkey' };
      for (const aaguid of aaguidsToGet) {
         aaguidCache.set(aaguid, { data: defaultData, timestamp });
      }

      const getParams = aaguidsToGet.map((aaguid) => ({ aaguid }));
      const aaguidsDetail = await AAGUIDs.get(getParams).go();

      // Update cache with the known AAGUIDs we found
      for (const aaguidDetail of aaguidsDetail.data) {
         aaguidCache.set(aaguidDetail.aaguid, {
            data: {
               lightIcon: aaguidDetail.lightIcon,
               darkIcon: aaguidDetail.darkIcon,
               name: aaguidDetail.name,
            },
            timestamp: Date.now(),
         });
      }
   }

   const authenticators: api.AuthenticatorInfoResponse[] = auths.data.map((cred) => {
      const cachedItem = aaguidCache.get(cred.aaguid!);
      return {
         credentialId: cred.credentialId,
         description: cred.description || '',
         lightIcon: cachedItem?.data.lightIcon ?? lightFileDefault,
         darkIcon: cachedItem?.data.darkIcon ?? darkFileDefault,
         name: cachedItem?.data.name ?? 'Passkey',
      };
   });

   return authenticators;
}

async function loadInvitables(
   verifiedUser: VerifiedUserItem,
   consistent: boolean = false,
): Promise<api.InvitableInfoResponse[]> {
   const invitableItems = await Invitables.query
      .byUserId({
         userId: verifiedUser.userId,
      })
      .go({
         consistent,
      });

   if (!invitableItems || invitableItems.data.length === 0) {
      return [];
   }

   // sort ascending (oldest to newest)
   invitableItems.data.sort((left, right) => {
      return (left.createdAt ?? 0) - (right.createdAt ?? 0);
   });

   const invitables: api.InvitableInfoResponse[] = invitableItems.data.map((item) => {
      return {
         invitableId: item.invitableId,
         description: item.description || '',
      };
   });

   return invitables;
}

async function deletePasskey(httpDetails: HttpDetails, verifiedUser: VerifiedUserItem): Promise<Response> {
   const { resources } = httpDetails;

   const credId = resources.credid;
   if (!validB64(credId)) {
      throw new ParamError('invalid credential id');
   }

   const deleted = await Authenticators.delete({
      userId: verifiedUser.userId,
      credentialId: credId!,
   }).go({
      response: 'all_old', // needed to determine of anything was deleted
   });

   if (!deleted?.data) {
      throw new ParamError('authenticator not found');
   }

   // force consistent read to capture delete
   const auths = await loadAuthenticators(verifiedUser, true);

   let response: api.UserInfoResponse = {
      verified: false,
   };
   let endSession = false;

   // If there are no authenticators remaining, delete the
   // entire user identity and return unverified api.UserInfoResponse object
   if (auths.length === 0) {
      // Delete all invitables for this user
      const invitables = await Invitables.query
         .byUserId({
            userId: verifiedUser.userId,
         })
         .go({ attributes: ['userId', 'invitableId'] });

      if (invitables && invitables.data.length > 0) {
         const result = await Invitables.delete(invitables.data).go();
         if (result?.unprocessed && result.unprocessed.length > 0) {
            console.error(`failed to delete all invitables for user ${verifiedUser.userId}`);
         }
      }

      const deleted = await Users.delete({
         userId: verifiedUser.userId,
      }).go({
         response: 'all_old', // needed to determine of anything was deleted
      });

      if (!deleted?.data) {
         throw new AuthError();
      }
      // Let this happen async
      recordEvent(EventNames.UserDelete, verifiedUser.userId, credId);
      endSession = true;
   } else {
      recordEvent(EventNames.RegDelete, verifiedUser.userId, credId);
      response = await makeUserInfoResponse(verifiedUser, auths);
      if (credId === verifiedUser.lastCredentialId) {
         await deleteSession(httpDetails, verifiedUser);
         endSession = true;
      }
   }

   return { content: response, endSession };
}

// recover removes all existing passkeys, then initiates the
// process or creating a new passkey. Caller is expected to followup
// with a call to verifyRegistration
async function postRecover(httpDetails: HttpDetails): Promise<Response> {
   const { rpID } = httpDetails;
   const recoverRequest = httpDetails.body as api.RecoverRequest;

   const userCred = recoverRequest?.userCred;
   const userId = recoverRequest?.userId;

   if (!validB64(userCred)) {
      throw new ParamError('invalid user credential');
   }

   let unverifiedUser: UnverifiedUserItem;
   let verifiedUser: VerifiedUserItem;

   try {
      // Require an existing verified user for recovery
      unverifiedUser = await getUnverifiedUser(userId);
      verifiedUser = checkVerified(unverifiedUser, userId);
   } catch {
      // Decryption and equality comparision can take a few MS to run on a warm server,
      // so add delay to prevent detection of siming differences
      await setTimeout(randomInt(2, 5));
      throw new AuthError();
   }

   // An account with a recovery key has moved to recovery words, which disables the
   // old recovery-link path.
   if (verifiedUser.recoveryPubKey) {
      throw new ParamError(`user account ${verifiedUser.userId} must use recovery words`);
   }

   const userCredDecBytes = await decryptField(
      verifiedUser.userCredEnc,
      { userId: verifiedUser.userId },
      cc.USERCRED_BYTES,
   );

   // Critical check to ensure we do not recover the wrong user
   if (!knownLenTimingSafeEqual(userCredDecBytes, base64UrlDecode(userCred)!)) {
      throw new ParamError(`user account ${verifiedUser.userId} invalid user credential`);
   }

   // Note that if the follow up creation of a new passkey is aborted or cancels, the
   // account will be left with no passkeys. Recovery can be run again to create a new
   // passkey. Could alternatively address this by marking passkey for deletion and
   // cleaning up after, but then recovery may be less certain in a security incident.
   await deleteAllAuthenticators(verifiedUser);

   const rcount = verifiedUser.recovered ? verifiedUser.recovered + 1 : 1;

   await Users.patch({
      userId: verifiedUser.userId,
   })
      .set({
         recovered: rcount,
      })
      .go();

   // Let this happen async
   recordEvent(EventNames.Recover, verifiedUser.userId);

   const response = await deleteSession(httpDetails, verifiedUser);
   const regResponse = await registrationOptions(rpID, verifiedUser, (challenge) =>
      buildChallenge(challenge, { purpose: 'recover', user: verifiedUser }),
   );
   response.content = regResponse.content;
   return response;
}

// Interleaved recover3 flows are not allowed.
async function postRecover3(httpDetails: HttpDetails): Promise<Response> {
   const recover3Request = httpDetails.body as api.Recover3Request;

   const { userId } = recover3Request;
   if (!validB64(userId)) {
      throw new ParamError('invalid recovery proof');
   }

   // Read consistently so a recently updated recovery key is always loaded
   const unverifiedUser = await getUnverifiedUser(userId, true);

   if (!unverifiedUser.recoveryPubKey) {
      throw new ParamError(`user account ${unverifiedUser.userId} has no recovery key`);
   }

   // This call takes < 1ms to run on a warm server, so detecting timing
   // differences to guess valid userId is not practicle
   await verifyRecoveryNonceProof(unverifiedUser.recoveryPubKey, userId, recover3Request, 'recover');

   // Now the user is confirmed
   const verifiedUser = checkVerified(unverifiedUser, userId);

   const rand = new GenerateRandomCommand({
      NumberOfBytes: cc.CHALLENGE_BYTES,
   });
   const result = await kmsClient.send(rand);
   const challengeBytes = result.Plaintext;

   if (!challengeBytes || challengeBytes.byteLength !== cc.CHALLENGE_BYTES) {
      throw new Error('GenerateRandomCommand failure');
   }

   // The recovery binding must reflect the incremented authCount, which requires deleteSession to run
   // before challenge creation
   const response = await deleteSession(httpDetails, verifiedUser);

   // Redeemed by POST /recover/confirm
   const challenge = base64UrlEncode(challengeBytes)!;
   await storeChallenge(buildChallenge(challenge, { purpose: 'confirm', user: verifiedUser }));

   let content: api.RecoverStartResponse;

   if (verifiedUser.prf) {
      content = { prf: true, challenge, userCredEnc: verifiedUser.userCredEnc };
   } else {
      const decrypted = await decryptField(
         verifiedUser.userCredEnc,
         { userId: verifiedUser.userId },
         cc.USERCRED_BYTES,
      );
      content = { prf: false, challenge, userCred: base64UrlEncode(decrypted)! };
   }

   response.content = content;
   return response;
}

async function postRecoverConfirm(
   httpDetails: HttpDetails,
   unverifiedUser: UnverifiedUserItem,
   // BACKWARD COMPAT: remove once x-challenge-proof is required
   proved: boolean,
): Promise<Response> {
   const { rpID } = httpDetails;
   const confirmRequest = httpDetails.body as api.RecoverConfirmRequest;

   // handler() read the user consistently
   await consumeChallenge(buildChallenge(confirmRequest.challenge, { purpose: 'confirm', user: unverifiedUser }));

   if (!unverifiedUser.verified || !validB64(unverifiedUser.userCredPubKey)) {
      throw new AuthError();
   }

   // BACKWARD COMPAT: a request without x-challenge-proof carries its proof in the body, which is
   // checked after the consume. Remove once x-challenge-proof is required.
   if (!proved) {
      verifyRecoverConfirmProof(confirmRequest, unverifiedUser.userCredPubKey, httpDetails);
   }

   const verifiedUser = checkVerified(unverifiedUser, unverifiedUser.userId);

   // Note that if the follow up creation of a new passkey is aborted or cancels, the
   // account will be left with no passkeys. Recovery can be run again to create a new
   // passkey. Could alternatively address this by marking passkey for deletion and
   // cleaning up after, but then recovery may be less certain in a security incident.
   await deleteAllAuthenticators(verifiedUser);

   const rcount = verifiedUser.recovered ? verifiedUser.recovered + 1 : 1;

   await Users.patch({
      userId: verifiedUser.userId,
   })
      .set({
         recovered: rcount,
      })
      .go();

   recordEvent(EventNames.Recover, verifiedUser.userId);

   const response = await deleteSession(httpDetails, verifiedUser);
   const regResponse = await registrationOptions(rpID, verifiedUser, (challenge) =>
      buildChallenge(challenge, { purpose: 'recover', user: verifiedUser }),
   );
   response.content = regResponse.content;
   return response;
}

// Currently origin is stored on each Authenticator, but it isn't used (other
// than within passkwy library signature test).
// Consider if rpOrigin should be moved from being per Authenticator to
// per User. This wouldn't be more secure, but it might prevent errors during
// development if a real users data was used in a test region.
async function getUnverifiedUser(userId: string, consistent: boolean = false): Promise<UnverifiedUserItem> {
   if (!validB64(userId) || base64UrlDecode(userId)?.length !== cc.USERID_BYTES) {
      throw new ParamError('invalid userid format');
   }

   // Eventually consistent by default because this is the hottest read in the system. That
   // means a recent write could go unseen by this read, including a previous logout. That
   // race exists regardless or read consistency, however, and sessions always end when
   // consistency is reached.
   const unverifiedUser = await Users.get({
      userId,
   }).go({ consistent });

   if (!unverifiedUser?.data) {
      throw new AuthError();
   }

   return unverifiedUser.data;
}

// User may be verified or unverified
async function getSessionKey(user: UnverifiedUserItem, purpose: string): Promise<Buffer> {
   if (!jwtMaterial) {
      jwtMaterial = await setupJwtMaterial();
   }

   // Deriving the key from lastCredentialId is what invalidates prior cookies and csrf
   // tokens on logout (which clears it) and on a passkey change (which rotates it).
   if (!user.lastCredentialId) {
      throw new AuthError();
   }

   const salt = base64UrlDecode(user.userId)!;
   const userMaterial = base64UrlDecode(user.lastCredentialId)!;
   const combined = Buffer.concat([userMaterial, jwtMaterial]);
   const sessionVersion = process.env.SessionVersion ?? '0';

   return Buffer.from(
      hkdfSync('sha512', combined, salt, `${purpose}:${user.authCount}:${sessionVersion}`, cc.SESSION_KEY_BYTES),
   );
}

function killCookie(): string {
   return '__Host-JWT=X; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=0';
}

// Test runners tag User-Agent with this marker so we can discourage normal
// users and allow creation of test user names. Not a security
// control since its easily spoofed, just a guardrail against admin errors.
function isTestClient(httpDetails: HttpDetails): boolean {
   return (httpDetails.userAgent ?? '').includes('QCTestClient');
}

async function createCsrf(verifiedUser: VerifiedUserItem): Promise<Uint8Array> {
   if (!verifiedUser) {
      throw new AuthError();
   }

   return await getSessionKey(verifiedUser, 'csrf');
}

async function createCookie(verifiedUser: VerifiedUserItem, rpID: string): Promise<string> {
   if (!verifiedUser) {
      throw new AuthError();
   }

   const jwtKey = await getSessionKey(verifiedUser, 'jwt_key');

   const payload = {
      userId: verifiedUser.userId,
   };

   const expiresIn = api.SESSION_TIMEOUT_SEC;
   const token = sign(payload, jwtKey, {
      algorithm: 'HS512',
      expiresIn,
      issuer: rpID,
   });

   const cookie = `__Host-JWT=${token}; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=${expiresIn}`;
   return cookie;
}

async function verifyCsrf(verifiedUser: VerifiedUserItem, checkCsrf: boolean, headerCsrf: string | undefined) {
   // Even if we don't check csrf, make sure we can create one
   const serverCsrfBytes = await createCsrf(verifiedUser);

   if (checkCsrf) {
      const headerCsrfBytes = base64UrlDecode(headerCsrf);
      if (!headerCsrfBytes || !knownLenTimingSafeEqual(serverCsrfBytes, headerCsrfBytes)) {
         throw new AuthError('invalid csrf token');
      }
   }
}

async function verifyCookie(cookie: string, rpID: string): Promise<VerifiedUserItem> {
   try {
      const match = /^__Host-JWT=(.+)$/.exec(cookie);
      if (!match?.[1] || match[1].length < 10) {
         throw new Error('invalid cookie');
      }
      const token = match[1];

      const unverifiedPayload = decode(token, {
         json: true,
         complete: false,
      });

      if (!unverifiedPayload?.userId) {
         throw new Error('invalid cookie');
      }

      const verifyWithUser = async (unverifiedUser: UnverifiedUserItem): Promise<VerifiedUserItem> => {
         const jwtKey = await getSessionKey(unverifiedUser, 'jwt_key');

         // Internally verifies exp date set with expiresIn during cookie creation
         const verifiedPayload = verify(token, jwtKey, {
            algorithms: ['HS512'],
            issuer: rpID,
            complete: false,
         }) as JwtPayload;

         if (!verifiedPayload || verifiedPayload.iss !== rpID) {
            throw new Error('invalid cookie');
         }

         return checkVerified(unverifiedUser, verifiedPayload.userId);
      };

      try {
         // Default to eventually consistent user read to reduce cost
         return await verifyWithUser(await getUnverifiedUser(unverifiedPayload.userId));
      } catch (err) {
         // Retry as consistent user read if within RECENT_COOKIE_SEC window
         const cookieAgeSec = Date.now() / 1000 - (unverifiedPayload.iat ?? 0);
         if (cookieAgeSec < 0 || cookieAgeSec > RECENT_COOKIE_SEC) {
            throw err;
         }
         console.warn('cookie verification using a consistent read after the first check failed', err);
         return await verifyWithUser(await getUnverifiedUser(unverifiedPayload.userId, true));
      }
   } catch (err) {
      console.error(err);
      throw new AuthError();
   }
}

function makeResponse(content: string, status: number, cookie?: string): APIGatewayProxyStructuredResultV2 {
   const resp = {
      statusCode: status,
      headers: {
         'Content-Type': 'application/json',
         'Cache-Control': 'no-store',
         Pragma: 'no-cache',
      } as { [key: string]: string },
      body: content,
   };

   if (cookie) {
      resp.headers['Set-Cookie'] = cookie;
   }

   console.log(`status: ${status}, cookie: ${Boolean(cookie)} ${status !== 200 ? `, error: ${content}` : ''}`);
   return resp;
}

export async function handler(event: APIGatewayProxyEventV2, _context: Context) {
   // Uncomment for temporary debuging only, since this logs user credentials
   // console.log(event);

   let httpDetails: HttpDetails | undefined;

   try {
      httpDetails = matchEvent(event, METHODMAP);
      const route = httpDetails.route;

      console.log(`calling function: ${httpDetails.name}, authorize: ${route.authorize}, proof: ${route.proof}`);
      console.log(`rpID: ${httpDetails.rpID}, rpOrigin: ${httpDetails.rpOrigin}`);

      if (httpDetails.version === INTERNAL_VERSION) {
         let dbytes: Uint8Array | undefined;
         try {
            dbytes = await decryptField(httpDetails.params.testkey, { purpose: 'internal' }, INTERNAL_PHRASE.length);
         } catch {
            throw new AuthError();
         }
         if (!dbytes || new TextDecoder().decode(dbytes) !== INTERNAL_PHRASE) {
            throw new AuthError();
         }
      }

      const nonceHeader = event.headers['x-nonce-proof'];
      const challengeHeader = event.headers['x-challenge-proof'];
      // BACKWARD COMPAT: x-proof also carries a nonce proof. It is read only on routes that take a
      // nonce proof and is ignored elsewhere. Once x-nonce-proof is required, x-proof is not read at
      // all, like any other unknown header.
      const legacyNonceHeader = event.headers['x-proof'];

      // Reject a request with more than one proof header, or with a proof header its route does not
      // take. BACKWARD COMPAT: the legacyNonceHeader checks go with legacyNonceHeader.
      if (
         (nonceHeader !== undefined && (route.proof !== 'nonce' || legacyNonceHeader !== undefined)) ||
         (challengeHeader !== undefined && (route.proof !== 'challenge' || legacyNonceHeader !== undefined))
      ) {
         throw new ParamError('unexpected proof header');
      }

      let verifiedUser: VerifiedUserItem | undefined;
      let response: Response;

      if (route.authorize) {
         if (!httpDetails.cookie) {
            throw new AuthError();
         }
         const headerCsrf = event.headers['x-csrf-token'];

         // these throw an exception if cookie or headerCsrf is invalid
         verifiedUser = await verifyCookie(httpDetails.cookie, httpDetails.rpID);
         await verifyCsrf(verifiedUser, httpDetails.checkCsrf, headerCsrf);

         if (route.proof === 'challenge' && challengeHeader !== undefined) {
            verifyUserCredChallengeProof(verifiedUser, httpDetails, challengeHeader);
         } else {
            // BACKWARD COMPAT: without x-challenge-proof, a challenge route accepts a nonce proof in
            // x-proof. Make x-challenge-proof required here once every client sends it.
            await verifyUserCredNonceProof(verifiedUser, httpDetails, nonceHeader ?? legacyNonceHeader);
         }
         response = await route.handler(httpDetails, verifiedUser);
      } else if (route.proof === 'challenge') {
         // Read consistently, so a user created or updated just before this request is seen as written
         const unverifiedUser = await getUnverifiedUser((httpDetails.body as api.ChallengeRiders).userId, true);

         // BACKWARD COMPAT: always verify once older clients that omit x-challenge-proof are gone
         const proved = challengeHeader !== undefined;
         if (proved) {
            verifyUserCredChallengeProof(unverifiedUser, httpDetails, challengeHeader);
         }
         response = await route.handler(httpDetails, unverifiedUser, proved);
      } else if (route.proof === 'none') {
         response = await route.handler(httpDetails);
      } else {
         // METHODMAP's types exclude this, so it is reached only by a route declared without a
         // session but with a nonce proof
         throw new Error(`invalid route ${httpDetails.name}`);
      }

      let respCookie: string | undefined;
      if (response.startSession) {
         respCookie = await createCookie(response.startSession, httpDetails.rpID);
         response.content.csrf = base64UrlEncode(await createCsrf(response.startSession));
      } else if (response.endSession) {
         respCookie = killCookie();
      } else if (response.returnCsrf) {
         response.content.csrf = base64UrlEncode(await createCsrf(verifiedUser!));
      }
      return makeResponse(JSON.stringify(response.content), 200, respCookie);
   } catch (err) {
      console.error(err);

      // Unauthenticated endpoints: one response for every failure so an attacker can't tell a
      // valid userId from an invalid one via type/message/status. (Timing is not addressed here.)
      if (httpDetails && !httpDetails.route.authorize) {
         return makeResponse(new AuthError().message, 401);
      }

      if (err instanceof ParamError) {
         return makeResponse(err.message, 400);
      } else if (err instanceof AuthError) {
         return makeResponse(err.message, 401);
      } else if (err instanceof NotFoundError) {
         return makeResponse(err.message, 404);
      } else {
         const msg = err instanceof Error ? err.name : 'internal error';
         return makeResponse(msg, 500);
      }
   }
}

const METHODMAP: MethodMap = {
   GET: [
      { name: 'getUser', pattern: Patterns.user, version: 1, authorize: true, proof: 'nonce', handler: getUser },
      {
         name: 'getPasskeyOptions',
         pattern: Patterns.passkeyOptions,
         version: 1,
         authorize: true,
         proof: 'nonce',
         handler: getPasskeyOptions,
      },
      // Special case of an authenticated method that does not require csrf. Needed so GET session works in a fresh
      // tab/window, and is safe since csrf isn't technically needed for GET calls due to Same-Origin
      {
         name: 'getSession',
         pattern: Patterns.session,
         version: 1,
         authorize: true,
         proof: 'nonce',
         checkCsrf: false,
         handler: getSession,
      },
      {
         name: 'getInvitables',
         pattern: Patterns.invitables,
         version: 1,
         authorize: true,
         proof: 'nonce',
         handler: getInvitables,
      },
   ],
   POST: [
      {
         name: 'postAuthOptions',
         pattern: Patterns.authOptions,
         version: 1,
         authorize: false,
         proof: 'none',
         handler: postAuthOptions,
      },
      {
         name: 'postAuthVerify',
         pattern: Patterns.authVerify,
         version: 1,
         authorize: false,
         proof: 'none',
         handler: postAuthVerify,
      },
      {
         name: 'postPasskeyVerify',
         pattern: Patterns.passkeyVerify,
         version: 1,
         authorize: true,
         proof: 'challenge',
         handler: postPasskeyVerify,
      },
      {
         name: 'postRegOptions',
         pattern: Patterns.regOptions,
         version: 1,
         authorize: false,
         proof: 'none',
         handler: postRegOptions,
      },
      {
         name: 'postRegVerify',
         pattern: Patterns.regVerify,
         version: 1,
         authorize: false,
         proof: 'challenge',
         handler: postRegVerify,
      },
      {
         name: 'postRecoverConfirm',
         pattern: Patterns.recoverConfirm,
         version: 1,
         authorize: false,
         proof: 'challenge',
         handler: postRecoverConfirm,
      },
      {
         name: 'postRecoverVerify',
         pattern: Patterns.recoverVerify,
         version: 1,
         authorize: false,
         proof: 'challenge',
         handler: postRecoverVerify,
      },
      {
         name: 'postRecover',
         pattern: Patterns.recover,
         version: 1,
         authorize: false,
         proof: 'none',
         handler: postRecover,
      },
      {
         name: 'postRecover3',
         pattern: Patterns.recover3,
         version: 1,
         authorize: false,
         proof: 'none',
         handler: postRecover3,
      },
      // Internal only endpoints that are not exposed in cloudfront and require special auth
      {
         name: 'postMunge',
         pattern: Patterns.munge,
         version: INTERNAL_VERSION,
         authorize: false,
         proof: 'none',
         handler: postMunge,
      },
      {
         name: 'postConsistency',
         pattern: Patterns.consistency,
         version: INTERNAL_VERSION,
         authorize: false,
         proof: 'none',
         handler: postConsistency,
      },
      {
         name: 'postLoadAAGUIDs',
         pattern: Patterns.loadaaguids,
         version: INTERNAL_VERSION,
         authorize: false,
         proof: 'none',
         handler: postLoadAAGUIDs,
      },
      {
         name: 'postCleanupTestUsers',
         pattern: Patterns.cleanuptestusers,
         version: INTERNAL_VERSION,
         authorize: false,
         proof: 'none',
         handler: postCleanupTestUsers,
      },
   ],
   PUT: [
      {
         name: 'putRecover3Key',
         pattern: Patterns.recover3Key,
         version: 1,
         authorize: true,
         proof: 'nonce',
         handler: putRecover3Key,
      },
   ],
   PATCH: [
      {
         name: 'patchPasskey',
         pattern: Patterns.passkey,
         version: 1,
         authorize: true,
         proof: 'nonce',
         handler: patchPasskey,
      },
      { name: 'patchUser', pattern: Patterns.user, version: 1, authorize: true, proof: 'nonce', handler: patchUser },
   ],
   DELETE: [
      {
         name: 'deletePasskey',
         pattern: Patterns.passkey,
         version: 1,
         authorize: true,
         proof: 'nonce',
         handler: deletePasskey,
      },
      {
         name: 'deleteSession',
         pattern: Patterns.session,
         version: 1,
         authorize: true,
         proof: 'nonce',
         handler: deleteSession,
      },
   ],
};
