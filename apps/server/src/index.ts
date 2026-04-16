/* MIT License

Copyright (c) 2025 Brad Schick

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
import {
   INTERNAL_VERSION,
   matchEvent,
   Patterns,
   type HttpDetails,
   type MethodMap,
} from './urls';

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
   AuthenticatorTransportFuture,
   PublicKeyCredentialDescriptorJSON,
   AuthenticationResponseJSON,
   RegistrationResponseJSON
} from '@simplewebauthn/server';

import {
   Users,
   Authenticators,
   Challenges,
   AuthEvents,
   AAGUIDs,
   Invitables,
   type VerifiedUserItem,
   type UnverifiedUserItem,
   type AuthItem,
   type InvitableItem,
} from "./models";

import { ElectroError, type EntityItem, type EntityRecord } from 'electrodb';
import {
   KMSClient,
   EncryptCommand,
   DecryptCommand,
   GenerateRandomCommand,
   type EncryptCommandOutput
} from "@aws-sdk/client-kms";

import { hkdfSync } from 'node:crypto';
import { sign, verify, decode, type JwtPayload } from 'jsonwebtoken';
import { postConsistency, postLoadAAGUIDs, postMunge } from './internal';
import {
   ParamError,
   AuthError,
   NotFoundError,
   sanitizeString,
   validB64,
   base64UrlEncode,
   base64UrlDecode
} from './utils';

export type Response = {
   content: Record<string, any>;
   startSession?: VerifiedUserItem;
   endSession?: boolean;
   returnCsrf?: boolean;
};

import type { ResponseTypes } from '@qcrypt/api';
type AuthenticatorInfo = ResponseTypes.AuthenticatorInfo;
type UserInfo = ResponseTypes.UserInfo;
type LoginUserInfo = ResponseTypes.LoginUserInfo;
type InvitableInfo = ResponseTypes.InvitableInfo;


type AAGUIDInfo = {
   data: {
      lightIcon: string;
      darkIcon: string;
      name: string;
   };
   timestamp: number;
};

export const lightFileDefault = 'assets/aaguid/img/default_light.svg'
export const darkFileDefault = 'assets/aaguid/img/default_dark.svg'

const aaguidCache = new Map<string, AAGUIDInfo>();
const AAGUID_CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

const UnknownUserId = 'unknown';

enum EventNames {
   AuthOptions = 'AuthOptions',
   AuthVerify = 'AuthVerify',
   RegOptions = 'RegOptions',
   RegVerify = 'RegVerify',
   RegDelete = 'RegDelete',
   UserDelete = 'UserDelete',
   PutDescription = 'PutDescription',
   PutUserName = 'PutUserName',
   Recover = 'Recover',
   GetRecovery = 'GetRecovery',
}


export const kmsClient = new KMSClient({ region: "us-east-1" });
let jwtMaterial: Uint8Array | undefined;
const INTERNAL_PHRASE = "Yup, I'm internal";


function isVerified(unverifiedUser: UnverifiedUserItem, userId: string): unverifiedUser is VerifiedUserItem {
   return unverifiedUser && unverifiedUser.verified &&
      unverifiedUser.userId === userId &&
      validB64(unverifiedUser.userId) &&
      validB64(unverifiedUser.userCredEnc) &&
      unverifiedUser.userName !== undefined && unverifiedUser.userName.length > 0 &&
      unverifiedUser.createdAt !== undefined;
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
   keyId: string = cc.KMS_KEYID_NEW
): Promise<string> {
   if (!keyId) {
      throw new Error('missing kms keyid')
   }

   const enc = new EncryptCommand({
      Plaintext: field,
      KeyId: keyId,
      EncryptionContext: context
   });

   const result = await kmsClient.send(enc);
   if (!result.CiphertextBlob) {
      throw new Error('field encryption failed');
   }

   return base64UrlEncode(result.CiphertextBlob)!;
}


async function decryptField(
   fieldEnc: string,
   context: { [key: string]: string },
   expectedBytes: number,
   keyId: string = cc.KMS_KEYID_NEW
): Promise<Uint8Array> {
   if (!keyId) {
      throw new Error('missing kms keyid')
   }

   const fieldEncBytes = base64UrlDecode(fieldEnc);
   const dec = new DecryptCommand({
      CiphertextBlob: fieldEncBytes,
      KeyId: keyId,
      EncryptionContext: context
   });

   const result = await kmsClient.send(dec);
   if (!result.Plaintext || result.Plaintext.byteLength != expectedBytes) {
      throw new Error('field decryption failed');
   }

   return result.Plaintext!;
}


async function setupJwtMaterial(): Promise<Uint8Array> {
   if (!process.env.EncMaterial) {
      throw new Error('missing environment value');
   }

   try {
      const encodedMaterial = await decryptField(
         process.env.EncMaterial,
         { purpose: "jwt" },
         cc.JWTMATERIAL_BYTES
      );

      if (!encodedMaterial) {
         throw new Error('encoded material undefined');
      }
      return encodedMaterial;
   } catch (error) {
      console.error("auth setup errror", error);
      throw new Error('auth setup error');
   }
}


async function recordEvent(
   eventName: EventNames,
   userId: string,
   credentialId: string | undefined = undefined
) {
   try {
      const event = await AuthEvents.create({
         event: eventName,
         userId: userId,
         credentialId: credentialId
      }).go();

      // record, but don't fail
      if (!event || !event.data) {
         console.error('event not created');
      }
   } catch (error) {
      // log but eat the error
      console.error(error);
   }
}

async function getSession(
   httpDetails: HttpDetails,
   verifiedUser?: VerifiedUserItem
): Promise<Response> {

   if (!verifiedUser) {
      throw new AuthError();
   }

   // TODO: This endpoint is the only way to get userCred and csrf token w/o
   // (re)authentication, making it the weakest link in security. Should we force
   // fresh tabs/windows to reauth?
   const responseContent = await makeLoginUserInfoResponse(verifiedUser, true, false);

   // Return passed in csrf but don't start new session so that expiration is not reset
   return {
      content: responseContent,
      returnCsrf: true
   };
}


async function deleteSession(
   httpDetails: HttpDetails,
   verifiedUser?: VerifiedUserItem
): Promise<Response> {

   if (!verifiedUser) {
      throw new AuthError();
   }

   await Users.patch({
      userId: verifiedUser.userId,
   }).set({
      lastCredentialId: ''
   }).go();

   return {
      content: { message: "done" },
      endSession: true
   };
}


async function postAuthVerify(
   httpDetails: HttpDetails
): Promise<Response> {
   const {
      rpID,
      rpOrigin,
      params,
      body
   } = httpDetails;

   if (!body.response || !body.response.userHandle) {
      throw new ParamError('missing userHandle');
   }
   if (!validB64(body.id)) {
      throw new ParamError('invalid authenticatorId');
   }
   if (!validB64(body.challenge)) {
      throw new ParamError('invalid challenge format');
   }

   const unverifiedUser = await getUnverifiedUser(body.response.userHandle!);

   // Make sure this is a challenge the server really issued and that it is
   // not outdated. Once found, remove to prevent reuse even in error cases
   const challenge = await Challenges.get({
      challenge: body.challenge
   }).go();

   if (!challenge || !challenge.data) {
      throw new ParamError('challenge not valid');
   }

   // must wait or node can exit too fast on error
   await Challenges.delete({
      challenge: body.challenge
   }).go();

   if ((Date.now() / 1000) > challenge.data.expiresAt) {
      throw new AuthError('challenge not valid');
   }

   // Refuse challenges that were issued for a different flow (reg/addpasskey).
   if (challenge.data.purpose !== 'auth') {
      throw new AuthError('challenge not valid');
   }

   // If the auth challenge was bound to a specific user at creation, the verify must match.
   // Unbound auth challenges are allowed for discoverable credential flow.
   if (challenge.data.userId !== UnknownUserId && challenge.data.userId !== unverifiedUser.userId) {
      throw new AuthError('challenge not valid');
   }

   // SimpleWebAuthn renamed these to WebAuthnCredential, so now we have a name missmatch with DB
   const authenticator = await Authenticators.get({
      userId: unverifiedUser.userId,
      credentialId: body.id
   }).go();

   if (!authenticator || !authenticator.data) {
      throw new AuthError();
   }

   const webAuthnCredential: WebAuthnCredential = {
      publicKey: base64UrlDecode(authenticator.data.credentialPublicKey)!,
      id: authenticator.data.credentialId,
      counter: 0, // not using counters
      transports: authenticator.data.transports as AuthenticatorTransportFuture[]
   };

   let verification: VerifiedAuthenticationResponse;
   try {
      verification = await verifyAuthenticationResponse({
         response: body as AuthenticationResponseJSON,
         expectedChallenge: challenge.data.challenge,
         expectedOrigin: rpOrigin,
         expectedRPID: rpID,
         credential: webAuthnCredential
      });
   } catch (error) {
      console.error(error);
      throw new AuthError('invalid authorization');
   }

   // Should this be changed to throw an error if not verified?
   let startSession: VerifiedUserItem | undefined;
   let responseContent: LoginUserInfo = {
      verified: verification.verified
   };

   if (verification.verified) {
      // should now be verified
      const verifiedUser = checkVerified(unverifiedUser, body.response.userHandle!);
      startSession = verifiedUser

      // ok if this fails
      const patchAuths = Authenticators.patch({
         userId: authenticator.data.userId,
         credentialId: authenticator.data.credentialId
      }).set({
         lastLogin: Date.now()
      }).go();

      const patchUsers = Users.patch({
         userId: verifiedUser.userId,
      }).set({
         lastCredentialId: authenticator.data.credentialId,
         authCount: verifiedUser.authCount + 1
      }).go();

      await Promise.all([patchAuths, patchUsers]);

      verifiedUser.lastCredentialId = authenticator.data.credentialId;
      verifiedUser.authCount += 1;

      const includeUserCred = !!params.usercred;
      const includeRecovery = !!params.recovery;

      if (includeRecovery &&
         (!verifiedUser.recoveryIdEnc || verifiedUser.recoveryIdEnc.length == 0)) {
         const rand = new GenerateRandomCommand({
            NumberOfBytes: cc.RECOVERYID_BYTES
         });
         const result = await kmsClient.send(rand);
         const recoveryId = result.Plaintext;

         if (!recoveryId || recoveryId.byteLength != cc.RECOVERYID_BYTES) {
            throw new Error("GenerateRandomCommand failure");
         }

         const recoveryIdEnc = await encryptField(
            recoveryId,
            { userId: verifiedUser.userId }
         );

         const patched = await Users.patch({
            userId: verifiedUser.userId,
         }).set({
            recoveryIdEnc: recoveryIdEnc
         }).go();

         if (!patched || !patched.data) {
            throw new ParamError('recovery update failed');
         }

         verifiedUser['recoveryIdEnc'] = recoveryIdEnc;
      }

      responseContent = await makeLoginUserInfoResponse(verifiedUser, includeUserCred, includeRecovery);
   }

   // Let this happen async
   recordEvent(EventNames.AuthVerify, unverifiedUser.userId, authenticator.data.credentialId);

   return {
      content: responseContent,
      startSession: startSession
   };
}

async function postPasskeyVerify(
   httpDetails: HttpDetails,
   verifiedUser?: VerifiedUserItem
): Promise<Response> {
   if (!verifiedUser) {
      throw new AuthError();
   }
   return _doPostRegVerify(httpDetails, verifiedUser, 'add', false);
}

async function postRegVerify(
   httpDetails: HttpDetails
): Promise<Response> {
   const {
      body
   } = httpDetails;

   const unverifiedUser = await getUnverifiedUser(body.userId);
   return _doPostRegVerify(httpDetails, unverifiedUser, 'reg', true);
}

async function _doPostRegVerify(
   httpDetails: HttpDetails,
   unverifiedUser: UnverifiedUserItem,
   expectedPurpose: 'reg' | 'add',
   newSession: boolean
): Promise<Response> {
   const {
      rpID,
      rpOrigin,
      params,
      body
   } = httpDetails;

   if (!validB64(body.challenge)) {
      throw new ParamError('invalid challenge format');
   }

   // Make sure this is a challenge the server really issued and that it is
   // not outdated. Once found, remove to prevent reuse even in error cases
   const challenge = await Challenges.get({
      challenge: body.challenge
   }).go();

   if (!challenge || !challenge.data) {
      throw new ParamError('challenge not valid');
   }

   // must wait or node can exit too fast
   await Challenges.delete({
      challenge: body.challenge
   }).go();

   // Must use the last challenged within 1 minute or its rejected
   if ((Date.now() / 1000) > challenge.data.expiresAt) {
      throw new AuthError('challenge not valid');
   }

   // Registration-style challenges are always userId-bound at creation time.
   if (challenge.data.purpose !== expectedPurpose ||
       challenge.data.userId !== unverifiedUser.userId) {
      throw new AuthError('challenge not valid');
   }

   let verification: VerifiedRegistrationResponse;
   try {
      verification = await verifyRegistrationResponse({
         response: body as RegistrationResponseJSON,
         expectedChallenge: challenge.data.challenge,
         expectedOrigin: rpOrigin,
         expectedRPID: rpID,
         supportedAlgorithmIDs: cc.ALGIDS
      });
   } catch (err) {
      console.error(err);
      throw new AuthError('invalid registration');
   }

   // Should this be changed to throw and error if no verified?
   let startSession: VerifiedUserItem | undefined;
   let responseContent: LoginUserInfo = {
      verified: verification.verified
   };

   if (verification.verified) {
      const {
         aaguid,
         credential,
         attestationObject,
         userVerified,
         credentialDeviceType,
         credentialBackedUp,
         origin
      } = verification.registrationInfo!;

      const {
         id,
         publicKey,
      } = credential;

      const aaguidDetails = await AAGUIDs.get({
         aaguid: aaguid
      }).go();

      let description = 'Passkey';

      if (aaguidDetails && aaguidDetails.data) {
         description = aaguidDetails.data.name ?? 'Passkey';
         description = description.slice(0, 42);
      } else {
         console.error('aaguid not found:', JSON.stringify(aaguid));
      }

      // SimpleWebAuthen renamed these to WebAuthnCredential, now we have a missmatch
      const auth = await Authenticators.create({
         userId: unverifiedUser.userId,
         description: description,
         credentialId: id,
         credentialPublicKey: base64UrlEncode(publicKey)!,
         credentialDeviceType: credentialDeviceType,
         userVerified: userVerified,
         credentialBackedUp: credentialBackedUp,
         transports: body.response.transports,
         origin: origin,
         aaguid: aaguid,
         attestationObject: base64UrlEncode(attestationObject),
      }).go();

      if (!auth || !auth.data) {
         throw new ParamError('credentail creation failed');
      }

      const rparams = {
         NumberOfBytes: cc.USERCRED_BYTES + cc.RECOVERYID_BYTES + (cc.INVITABLEID_BYTES * cc.RETRIES)
      };
      const rand = new GenerateRandomCommand(rparams);
      const result = await kmsClient.send(rand);

      const randData = result.Plaintext;
      if (!randData || randData.byteLength != rparams.NumberOfBytes) {
         throw new Error("GenerateRandomCommand failure");
      }

      // To reduces calls to KMS when user creation
      // is abandonded, delay creation for userCred and recoveryId until this point.
      // If this is a new user reg, verified is false and the user will not have
      // a userCred or recoveryId
      if (!unverifiedUser.verified) {
         // Careful to never overwrite userCredEnc (due to a bug or whatever)
         if (unverifiedUser.userCredEnc || unverifiedUser.recoveryIdEnc) {
            throw new Error('unexpected user credential or recovery id');
         }

         let randOffset = 0
         const userCred = randData.slice(randOffset, randOffset + cc.USERCRED_BYTES);
         randOffset += cc.USERCRED_BYTES;
         const userCredEnc = await encryptField(
            userCred,
            { userId: unverifiedUser.userId }
         );

         const userCredEncBackup = await encryptField(
            userCred,
            { userId: unverifiedUser.userId },
            cc.KMS_KEYID_BACKUP
         );

         const recoveryId = randData.slice(randOffset, randOffset + cc.RECOVERYID_BYTES);
         randOffset += cc.RECOVERYID_BYTES;
         const recoveryIdEnc = await encryptField(
            recoveryId,
            { userId: unverifiedUser.userId }
         );

         // Loop in the very unlikley event that we randomly pick
         // a duplicate (out of 3.4e38 possible)
         let invId: string | undefined;
         for(let i = 0; i < cc.RETRIES; ++i) {
            const invIdBytes = randData.slice(randOffset, randOffset + cc.INVITABLEID_BYTES);
            randOffset += cc.INVITABLEID_BYTES;

            invId = base64UrlEncode(invIdBytes)!;
            const invitable = await Invitables.query.byInvitableId({
               invitableId: invId
            }).go();

            if (!invitable || invitable.data.length == 0) {
               break;
            } else {
               invId = undefined;
            }
         }

         if (!invId) {
            throw new Error('could not allocate invitableId');
         }

         const invitable = await Invitables.create({
            userId: unverifiedUser.userId,
            invitableId: invId,
            description: unverifiedUser.userName
         }).go();

         if (!invitable || !invitable.data) {
            throw new ParamError('invitable not created or found');
         }

         // Very important that we remove the expiresAt attribute so that the
         // record is not automatically cleaned up by dynamoDB
         await Users.patch({
            userId: unverifiedUser.userId,
         }).set({
            verified: true,
            userCredEnc: userCredEnc,
            userCredEncOld: userCredEncBackup,
            recoveryIdEnc: recoveryIdEnc,
            lastCredentialId: auth.data.credentialId,
            authCount: 1
         }).remove(['expiresAt']).go();

         unverifiedUser.verified = true;
         unverifiedUser.userCredEnc = userCredEnc;
         unverifiedUser.recoveryIdEnc = recoveryIdEnc;
         unverifiedUser.lastCredentialId = auth.data.credentialId;
         unverifiedUser.authCount = 1;

      } else if (!unverifiedUser.lastCredentialId || unverifiedUser.lastCredentialId.length === 0) {
         // This occurs after account recovery because all Passkeys are wiped.
         // During normal credential addition, lastCredentialId isn't changed
         await Users.patch({
            userId: unverifiedUser.userId,
         }).set({
            lastCredentialId: auth.data.credentialId,
            authCount: unverifiedUser.authCount + 1
         }).go();

         unverifiedUser.lastCredentialId = auth.data.credentialId;
         unverifiedUser.authCount += 1;
      }

      // should now be verified
      const verifiedUser = checkVerified(unverifiedUser, challenge.data.userId);
      startSession = newSession ? verifiedUser : undefined;

      const includeUserCred = !!params.usercred;
      const includeRecovery = !!params.recovery;

      // force consistent read to capture recent create
      const authenticators = await loadAuthenticators(verifiedUser, true);
      responseContent = await makeLoginUserInfoResponse(
         verifiedUser,
         includeUserCred,
         includeRecovery,
         authenticators
      );
   }

   // Let this happen async
   recordEvent(EventNames.RegVerify, unverifiedUser.userId, verification.registrationInfo?.credential.id);

   return {
      content: responseContent,
      startSession: startSession
   };
}


async function postAuthOptions(
   httpDetails: HttpDetails
): Promise<Response> {
   const {
      rpID,
      params,
      body
   } = httpDetails;

   let userId = UnknownUserId;

   // Temporarily for backward compat, check params for userId
   let unverifiedUserId = body?.userId ?? params?.userid;

   // If no userid is provided, then we don't return allowed creds and
   // the user is forced to pick one on their own. That happens when the user is
   // linking a new device to a existing passkey or has fully signed out
   let allowedCreds: PublicKeyCredentialDescriptorJSON[] | undefined = undefined;

   if (unverifiedUserId) {
      // Callers could use this to guess userids, but userid is 128bits psuedo-random,
      // so it would take an eternity (and size-large aws bills for me)
      const unverifiedUser = await getUnverifiedUser(unverifiedUserId);

      userId = unverifiedUser.userId;
      const auths = await Authenticators.query.byUserId({
         userId
      }).go();

      // a user id without authenticator creds was never verified, so reject
      if (!auths || auths.data.length === 0) {
         throw new ParamError('invalid user');
      }

      allowedCreds = auths.data.map((cred: AuthItem) => ({
         id: cred.credentialId,
         type: 'public-key',
         transports: cred.transports as AuthenticatorTransportFuture[],
      }));
   }

   try {
      const options: PublicKeyCredentialRequestOptionsJSON = await generateAuthenticationOptions({
         allowCredentials: allowedCreds,
         rpID: rpID,
         userVerification: 'preferred',
      });

      // Bind the challenge to its purpose, and to the userId. Note that userId
      // can be "Unknown" for the discoverable-credential auth flow.
      await Challenges.create({
         challenge: options.challenge,
         purpose: 'auth',
         userId
      }).go();

      // Let this happen async. Don't report a credentialId since
      // there could be none or multiple
      recordEvent(EventNames.AuthOptions, userId);

      return { content: options };

   } catch (err) {
      console.error(err);
      throw new Error('unable to generate authentication options');
   }
}

async function getPasskeyOptions(
   httpDetails: HttpDetails,
   verifiedUser?: VerifiedUserItem
): Promise<Response> {
   const {
      rpID,
      rpOrigin
   } = httpDetails;

   if (!verifiedUser) {
      throw new AuthError();
   }

   return registrationOptions(rpID, rpOrigin, verifiedUser, 'add');
}


async function postRegOptions(
   httpDetails: HttpDetails
): Promise<Response> {
   const {
      rpID,
      rpOrigin,
      body,
   } = httpDetails;

   // Totally new user, must provide a username
   const userName = sanitizeString(body.userName);
   if (userName.length < 6 || userName.length > 31) {
      throw new ParamError('user name must greater than 5 and less than 32 characters');
   }

   let uId: string | undefined;

   // Reduce round-trips by getting enough data for 3 x 16 bytes ID tries
   // and 1 x 32 bytes userCred
   const rparams = {
      NumberOfBytes: cc.RETRIES * cc.USERID_BYTES
   };
   const rand = new GenerateRandomCommand(rparams);
   const result = await kmsClient.send(rand);

   const randData = result.Plaintext;
   if (!randData || randData.byteLength != rparams.NumberOfBytes) {
      throw new Error("GenerateRandomCommand failure");
   }

   let randOffset = 0;

   // Loop in the very unlikley event that we randomly pick
   // a duplicate (out of 3.4e38 possible)
   for (let i = 0; i < cc.RETRIES; ++i) {
      const uIdBytes = randData.slice(randOffset, randOffset + cc.USERID_BYTES);
      randOffset += cc.USERID_BYTES;

      uId = base64UrlEncode(uIdBytes)!;

      const users = await Users.query.byUserId({
         userId: uId
      }).go({ attributes: ['userId'] });

      if (!users || users.data.length == 0) {
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
      userName: userName,
      expiresAt: expires,
      userCredEnc: undefined,
      recoveryIdEnc: undefined
   }).go();

   if (!user || !user.data) {
      throw new ParamError('user not created or found');
   }

   return registrationOptions(rpID, rpOrigin, user.data, 'reg');
}

async function registrationOptions(
   rpID: string,
   rpOrigin: string,
   unverifiedUser: UnverifiedUserItem,
   purpose: 'reg' | 'add'
): Promise<Response> {

   if (!unverifiedUser) {
      throw new ParamError('invalid user')
   }

   try {
      const auths = await Authenticators.query.byUserId({
         userId: unverifiedUser.userId
      }).go();

      let excludeCreds: {
         id: string;
         transports?: AuthenticatorTransportFuture[];
      }[] = [];

      if (auths && auths.data) {
         excludeCreds = auths.data.map((cred: AuthItem) => ({
            id: cred.credentialId,
            transports: cred.transports as AuthenticatorTransportFuture[]
         }));
      }

      const options: PublicKeyCredentialCreationOptionsJSON = await generateRegistrationOptions({
         rpName: cc.RPNAME,
         rpID: rpID,
         userID: base64UrlDecode(unverifiedUser.userId),
         userName: unverifiedUser.userName,
         attestationType: 'none',
         excludeCredentials: excludeCreds, // prevent re-registering existing passkeys
         authenticatorSelection: {
            residentKey: 'required',
            userVerification: 'preferred',
         },
         supportedAlgorithmIDs: cc.ALGIDS,
      });

      await Challenges.create({
         challenge: options.challenge,
         purpose: purpose,
         userId: unverifiedUser.userId
      }).go();

      // Let this happen async
      recordEvent(EventNames.RegOptions, unverifiedUser.userId);
      //@ts-ignore
      options.rp['origin'] = rpOrigin;
      return { content: options };
   } catch (err) {
      console.error(err);
      throw new Error('unable to generate registration options');
   }
};

async function makeLoginUserInfoResponse(
   verifiedUser: VerifiedUserItem,
   includeUserCred: boolean,
   includeRecovery: boolean,
   auths?: AuthenticatorInfo[]
): Promise<LoginUserInfo> {

   const userInfo = await makeUserInfoResponse(verifiedUser, auths);

   try {
      let userCred: Uint8Array | undefined;
      if (includeUserCred) {
         userCred = await decryptField(
            verifiedUser.userCredEnc,
            { userId: verifiedUser.userId },
            cc.USERCRED_BYTES
         );
      }

      let recoveryId: Uint8Array | undefined;
      if (includeRecovery && verifiedUser.recoveryIdEnc) {
         recoveryId = await decryptField(
            verifiedUser.recoveryIdEnc,
            { userId: verifiedUser.userId },
            cc.RECOVERYID_BYTES
         );
      }

      return {
         ...userInfo,
         userCred: base64UrlEncode(userCred),
         recoveryId: base64UrlEncode(recoveryId),
         pkId: verifiedUser.lastCredentialId
      };

   } catch (error) {
      console.error("auth setup errror", error);
      throw new AuthError('auth setup error');
   }
}


async function makeUserInfoResponse(
   verifiedUser: VerifiedUserItem,
   auths?: AuthenticatorInfo[],
   invitables?: InvitableInfo[]
): Promise<UserInfo> {

   auths = auths ?? await loadAuthenticators(verifiedUser);
   invitables = invitables ?? await loadInvitables(verifiedUser);

   // user explicit assignment rather than spread operator to prevent leaking information
   // in UserItem table that is internal only or provided separatly (like recoveryId)
   const userInfo: UserInfo = {
      verified: verifiedUser.verified,
      userId: verifiedUser.userId,
      userName: verifiedUser.userName,
      hasRecoveryId: !!verifiedUser.recoveryIdEnc && verifiedUser.recoveryIdEnc.length > 0,
      authenticators: auths,
      invitables: invitables
   };

   return userInfo;
}


function makeInvitableResponse(
   invitable: InvitableItem
): InvitableInfo {

   const invitableInfo: InvitableInfo = {
      invitableId: invitable.invitableId,
      description: invitable.description
   };

   return invitableInfo;
}

async function patchPasskey(
   httpDetails: HttpDetails,
   verifiedUser?: VerifiedUserItem
): Promise<Response> {
   const {
      resources,
      body,
   } = httpDetails;

   if (!verifiedUser) {
      throw new AuthError();
   }

   // only desciption can be changed
   const description = sanitizeString(body.description);
   if (description.length < 6 || description.length > 42) {
      throw new ParamError('description must more than 5 and less than 43 character');
   }

   const credId = resources['credid'];
   if (!validB64(credId)) {
      throw new ParamError('invalid credential id');
   }

   // This will raise if credId is invalid, catch to return a consistend error
   try {
      const patched = await Authenticators.patch({
         userId: verifiedUser.userId,
         credentialId: credId!
      }).set({
         description: description
      }).go();

      if (!patched || !patched.data) {
         throw new ParamError('description update failed');
      }
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

   // return with full UserInfo to make client side refresh simpler
   const response = await makeUserInfoResponse(verifiedUser, auths);
   return { content: response };
}


async function patchUser(
   httpDetails: HttpDetails,
   verifiedUser?: VerifiedUserItem
): Promise<Response> {
   const {
      body
   } = httpDetails;

   if (!verifiedUser) {
      throw new AuthError();
   }

   // Only support userName changes
   const userName = sanitizeString(body.userName);
   if (userName.length < 6 || userName.length > 31) {
      throw new ParamError('username must more than 5 and less than 32 character');
   }

   try {
      const patched = await Users.patch({
         userId: verifiedUser.userId
      }).set({
         userName: userName
      }).go();

      if (!patched || !patched.data) {
         throw new ParamError('username update failed');
      }
   } catch (err) {
      if (err instanceof ElectroError) {
         console.error(err);
         throw new ParamError('username update failed');
      }
      throw err;
   }

   // Let this happen async
   recordEvent(EventNames.PutUserName, verifiedUser.userId, verifiedUser.lastCredentialId);

   // return with full UserInfo to make client side refresh simpler
   verifiedUser['userName'] = userName;
   const response = await makeUserInfoResponse(verifiedUser);
   return { content: response };
}

// Not tracking events for this method since they are frequent and not particlyarly
// interesting
async function getInvitables(
   httpDetails: HttpDetails,
   verifiedUser?: VerifiedUserItem
): Promise<Response> {
   const {
      resources
   } = httpDetails;

   if (!verifiedUser) {
      throw new AuthError();
   }

   const invitableId = resources['invid'];
   if (!validB64(invitableId)) {
      throw new ParamError('invalid invitable id');
   }

   // May not want to bring back all parameter (like recoveryIdEnc)
   const invitables = await Invitables.query.byInvitableId({
      invitableId
   }).go();

   if (!invitables || invitables.data.length === 0) {
      throw new ParamError('invalid invitable id');
   }

   const response = makeInvitableResponse(invitables.data[0]);
   return { content: response };
}

// Not tracking events for this method since they are frequent and not particlyarly
// interesting
async function getUser(
   httpDetails: HttpDetails,
   verifiedUser?: VerifiedUserItem
): Promise<Response> {

   if (!verifiedUser) {
      throw new AuthError();
   }

   const response = await makeUserInfoResponse(verifiedUser);
   return { content: response };
}

// Not tracking events for this method since they are frequent and not particlyarly
// interesting
async function getAuthenticators(
   httpDetails: HttpDetails,
   verifiedUser: VerifiedUserItem
): Promise<Response> {

   if (!verifiedUser) {
      throw new AuthError();
   }

   const response = await loadAuthenticators(verifiedUser);
   return { content: response };
}


async function loadAuthenticators(
   verifiedUser: VerifiedUserItem,
   consistent: boolean = false
): Promise<AuthenticatorInfo[]> {

   const auths = await Authenticators.query.byUserId({
      userId: verifiedUser.userId
   }).go({
      attributes: ['description', 'credentialId', 'aaguid', 'createdAt'],
      consistent: consistent
   });

   if (!auths || auths.data.length == 0) {
      return [];
   }

   // sort ascending (oldest to newest)
   auths.data.sort((left: any, right: any) => {
      return left.createdAt - right.createdAt;
   });

   const aaguids = new Set<string>(auths.data.map((cred) => cred.aaguid || ''));
   const aaguidsToGet: string[] = [];

   for (const aaguid of aaguids) {
      const cachedItem = aaguidCache.get(aaguid);
      if (!cachedItem || (Date.now() - cachedItem.timestamp > AAGUID_CACHE_TTL_MS)) {
         aaguidsToGet.push(aaguid);
      }
   }

   if (aaguidsToGet.length > 0) {
      const getParams = aaguidsToGet.map((aaguid) => ({ aaguid: aaguid }));
      const aaguidsDetail = await AAGUIDs.get(getParams).go();

      for (let aaguidDetail of aaguidsDetail.data) {
         aaguidCache.set(aaguidDetail.aaguid, {
            data: {
               lightIcon: aaguidDetail.lightIcon,
               darkIcon: aaguidDetail.darkIcon,
               name: aaguidDetail.name
            },
            timestamp: Date.now()
         });
      }
   }

   const authenticators: AuthenticatorInfo[] = auths.data.map((cred) => {
      const cachedItem = aaguidCache.get(cred.aaguid!);
      return {
         credentialId: cred.credentialId,
         description: cred.description || '',
         lightIcon: cachedItem?.data.lightIcon ?? lightFileDefault,
         darkIcon: cachedItem?.data.darkIcon ?? darkFileDefault,
         name: cachedItem?.data.name ?? 'Passkey',
      }
   });

   return authenticators;
}

async function loadInvitables(
   verifiedUser: VerifiedUserItem,
   consistent: boolean = false
): Promise<InvitableInfo[]> {

   const invitableItems = await Invitables.query.byUserId({
      userId: verifiedUser.userId
   }).go({
      consistent: consistent
   });

   if (!invitableItems || invitableItems.data.length == 0) {
      return [];
   }

   // sort ascending (oldest to newest)
   invitableItems.data.sort((left: any, right: any) => {
      return left.createdAt - right.createdAt;
   });

   const invitables: InvitableInfo[] = invitableItems.data.map((item) => {
      return {
         invitableId: item.invitableId,
         description: item.description || '',
      }
   });

   return invitables;
}

async function deletePasskey(
   httpDetails: HttpDetails,
   verifiedUser?: VerifiedUserItem
): Promise<Response> {
   const {
      resources
   } = httpDetails;

   if (!verifiedUser) {
      throw new AuthError();
   }
   const credId = resources['credid'];
   if (!validB64(credId)) {
      throw new ParamError('invalid credential id');
   }

   const deleted = await Authenticators.delete({
      userId: verifiedUser.userId,
      credentialId: credId!
   }).go({
      response: 'all_old' // needed to determine of anything was deleted
   });

   if (!deleted || !deleted.data) {
      throw new ParamError('authenticator not found');
   }

   // force consistent read to capture delete
   const auths = await loadAuthenticators(verifiedUser, true);

   let response: UserInfo = {
      verified: false
   };

   // If there are no authenticators remaining, delete the
   // entire user identity and return unverified UserInfo object
   if (auths.length == 0) {

      // Delete all invitables for this user
      const invitables = await Invitables.query.byUserId({
         userId: verifiedUser.userId
      }).go({ attributes: ['userId', 'invitableId'] });

      if (invitables && invitables.data.length > 0) {
         const result = await Invitables.delete(invitables.data).go();
         if (result && result.unprocessed && result.unprocessed.length > 0) {
            console.error(`failed to delete all invitables for user ${verifiedUser.userId}`);
         }
      }

      const deleted = await Users.delete({
         userId: verifiedUser.userId
      }).go({
         response: 'all_old' // needed to determine of anything was deleted
      });

      if (!deleted || !deleted.data) {
         throw new AuthError();
      }
      // Let this happen async
      recordEvent(EventNames.UserDelete, verifiedUser.userId, credId);
   } else {
      response = await makeUserInfoResponse(verifiedUser, auths);
      recordEvent(EventNames.RegDelete, verifiedUser.userId, credId);
   }

   return { content: response };
}

// recover removes all existing passkeys, then initiates the
// process or creating a new passkey. Caller is expected to followup
// with a call to verifyRegistration
async function postRecover(
   httpDetails: HttpDetails
): Promise<Response> {
   const {
      rpID,
      rpOrigin,
      resources,
   } = httpDetails;

   const userCred = resources['usercred'];
   if (!validB64(userCred)) {
      throw new ParamError('invalid user credential');
   }

   // Require an existing verified user for recovery
   const unverifiedUser = await getUnverifiedUser(resources.userid);
   const verifiedUser = checkVerified(unverifiedUser, resources.userid);

   if (verifiedUser.recoveryIdEnc && verifiedUser.recoveryIdEnc.length > 1) {
      // vague error to make guessing harder
      console.error(`user account ${verifiedUser.userId} must use recovery words`);
      throw new AuthError();
   }

   const userCredDecBytes = await decryptField(
      verifiedUser.userCredEnc,
      { userId: verifiedUser.userId },
      cc.USERCRED_BYTES
   );

   // Critical check to ensure we do not recover the wrong user
   if (base64UrlEncode(userCredDecBytes) !== userCred) {
      // vague error to make guessing harder
      console.error(`user account ${verifiedUser.userId} invalid user credential`);
      throw new AuthError();
   }

   const auths = await Authenticators.query.byUserId({
      userId: verifiedUser.userId
   }).go({ attributes: ['userId', 'credentialId'] });

   // Note that if the creation of a new passkey is aborted or cancels, the account
   // will be left with no passkeys. Recovery can be run again to create a new passkey.
   // Could alternatively address this by marking passkey for deletion and cleaning
   // up after, but then recovery may be less certain in a security incident.
   if (auths && auths.data.length != 0) {
      const deleted = await Authenticators.delete(auths.data).go();
      // log but continue... 'all_old' not needed because response is different
      if (!deleted) {
         console.error('authenticator delete failed');
      }
   }

   const rcount = verifiedUser.recovered ? verifiedUser.recovered + 1 : 1;

   const patched = await Users.patch({
      userId: verifiedUser.userId
   }).set({
      recovered: rcount,
      lastCredentialId: ''
   }).go();

   // log but continue...
   if (!patched || !patched.data) {
      console.error('recovered count update failed');
   }

   // Let this happen async
   recordEvent(EventNames.Recover, verifiedUser.userId);

   // caller should followup with call to verifyRegistration
   return registrationOptions(rpID, rpOrigin, verifiedUser, 'reg');
}

// recover removes all existing passkeys, then initiates the
// process or creating a new passkey. Caller is expected to followup
// with a call to verifyRegistration
async function postRecover2(
   httpDetails: HttpDetails
): Promise<Response> {
   const {
      rpID,
      rpOrigin,
      body
   } = httpDetails;

   let recoveryId = body?.recoveryId;
   let userId = body?.userId;

   if (!validB64(recoveryId)) {
      throw new ParamError('invalid recovery id');
   }

   // Require an existing verified user for recovery
   const unverifiedUser = await getUnverifiedUser(userId);
   const verifiedUser = checkVerified(unverifiedUser, userId);

   // due to switch from recover to recover2, not all verified users have recoveryIdEnc
   if (!verifiedUser.recoveryIdEnc ||
      verifiedUser.recoveryIdEnc.length < 10) {
      // vague error on purpose to make guessing harder
      console.error(`user account ${verifiedUser.userId} not using recovery words`);
      throw new AuthError();
   }

   const recoveryIdDecBytes = await decryptField(
      verifiedUser.recoveryIdEnc,
      { userId: verifiedUser.userId },
      cc.RECOVERYID_BYTES
   );

   // Critical check to ensure we do not recover the wrong user
   if (base64UrlEncode(recoveryIdDecBytes) !== recoveryId) {
      // vague error on purpose to make guessing harder
      console.error(`user account ${verifiedUser.userId} invalid recovery id`);
      throw new AuthError();
   }

   const auths = await Authenticators.query.byUserId({
      userId: verifiedUser.userId
   }).go({ attributes: ['userId', 'credentialId'] });

   // Note that if the creation of a new passkey is aborted or cancels, the account
   // will be left with no passkeys. Recovery can be run again to create a new passkey.
   // Could alternatively address this by marking passkey for deletion and cleaning
   // up after, but then recovery may be less certain in a security incident.
   if (auths && auths.data.length != 0) {
      const deleted = await Authenticators.delete(auths.data).go();
      // log but continue... 'all_old' not needed because response is different
      if (!deleted) {
         console.error('authenticator delete failed');
      }
   }

   const rcount = verifiedUser.recovered ? verifiedUser.recovered + 1 : 1;

   const patched = await Users.patch({
      userId: verifiedUser.userId
   }).set({
      recovered: rcount,
      lastCredentialId: ''
   }).go();

   // log but continue...
   if (!patched || !patched.data) {
      console.error('recovered count update failed');
   }

   // Let this happen async
   recordEvent(EventNames.Recover, verifiedUser.userId);

   // caller should followup with call to verifyRegistration
   return registrationOptions(rpID, rpOrigin, verifiedUser, 'reg');
}

// Currently origin is stored on each Authenticator, but it isn't used (other
// than within passkwy library signature test).
// Consider if rpOrigin should be moved from being per Authenticator to
// per User. This wouldn't be more secure, but it might prevent errors during
// development if a real users data was used in a test region.
// If origin is moved to user, then we could add a test here to confirm the
// original user origin is used for all following actions.
//
async function getUnverifiedUser(
   userId: string
): Promise<UnverifiedUserItem> {

   if (!validB64(userId)) {
      throw new ParamError('invalid user');
   }

   // May not want to bring back all parameter (like recoveryIdEnc)
   const unverifiedUser = await Users.get({
      userId: userId
   }).go();

   if (!unverifiedUser || !unverifiedUser.data) {
      // Auth error are usually generic to attackers cannot use response to
      // tell the difference between bad creds, incorrect userid, or no permission
      throw new AuthError();
   }

   return unverifiedUser.data;
}



// User may be verified or unverified
async function getSessionKey(user: UnverifiedUserItem, purpose: string): Promise<Buffer> {
   if (!jwtMaterial) {
      jwtMaterial = await setupJwtMaterial();
   }

   const salt = base64UrlDecode(user.userId)!;
   const userMaterial = base64UrlDecode(user.userCredEnc)!;
   const combined = Buffer.concat([userMaterial, jwtMaterial]);

   return Buffer.from(hkdfSync(
      'sha512',
      combined,
      salt,
      purpose + user.authCount,
      32
   ));
}

function killCookie(): string {
   return '__Host-JWT=X; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=0';
}

async function createCsrf(verifiedUser: VerifiedUserItem): Promise<string> {
   if (!verifiedUser) {
      throw new AuthError();
   }

   const csrfBytes = await getSessionKey(verifiedUser, "csrf");
   return base64UrlEncode(csrfBytes)!;
}

async function createCookie(verifiedUser: VerifiedUserItem): Promise<string> {
   if (!verifiedUser) {
      throw new AuthError();
   }

   const jwtKey = await getSessionKey(verifiedUser, "jwt_key");

   const payload = {
      pkId: verifiedUser.lastCredentialId,
      userId: verifiedUser.userId
   };

   const expiresIn = 10800;
   const token = sign(
      payload,
      jwtKey, {
         algorithm: 'HS512',
         expiresIn: expiresIn,
         issuer: 'quickcrypt'
      }
   );

   const cookie = `__Host-JWT=${token}; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=${expiresIn}`
   return cookie;
}

async function verifyCsrf(
   verifiedUser: VerifiedUserItem,
   checkCsrf: boolean,
   headerCsrf: string | undefined
) {
   // Even if we don't check csrf, make sure we can create one
   const serverCsrf = await createCsrf(verifiedUser);

   if (checkCsrf && (serverCsrf !== headerCsrf || !headerCsrf)) {
      throw new AuthError('invalid csrf token');
   }
}

async function verifyCookie(
   cookie: string
): Promise<VerifiedUserItem> {

   try {
      const match = /^__Host-JWT=(.+)$/.exec(cookie);
      if (!match || !match[1] || match[1].length < 10) {
         throw new Error('invalid cookie');
      }
      const token = match[1];

      const unverifiedPayload = decode(
         token, {
         json: true,
         complete: false
      });

      if (!unverifiedPayload || !unverifiedPayload.userId) {
         throw new Error('invalid cookie');
      }

      const unverifiedUser = await getUnverifiedUser(unverifiedPayload.userId);
      const jwtKey = await getSessionKey(unverifiedUser, "jwt_key");

      // Internally verifies exp date set with expiresIn during cookie creation
      const verifiedPayload = verify(
         token,
         jwtKey, {
            algorithms: ['HS512'],
            issuer: 'quickcrypt',
            complete: false
      }) as JwtPayload;

      // lastCredentialId is cleared on logout so cookie is invalid after logout
      if (!verifiedPayload ||
         !verifiedPayload.pkId ||
         verifiedPayload.pkId !== unverifiedUser.lastCredentialId ||
         verifiedPayload.iss !== 'quickcrypt'
      ) {
         throw new Error('invalid cookie');
      }

      return checkVerified(unverifiedUser, verifiedPayload.userId);

   } catch (err) {
      console.error(err);
      throw new AuthError();
   }
}


function makeResponse(content: string, status: number, cookie?: string): any {
   const resp = {
      statusCode: status,
      headers: {
         'Content-Type': 'application/json',
      } as { [key: string]: string },
      body: content
   };

   if (cookie) {
      resp.headers["Set-Cookie"] = cookie;
   }

   console.log(`status: ${status}, cookie: ${Boolean(cookie)} ${status != 200 ? ', error: ' + content : ''}`);
   return resp;
}

export async function handler(event: any, context: any) {

   // Uncomment for temporary debuging only, since this logs user credentials
   // console.log(event);

   try {
      const httpDetails = matchEvent(event, METHODMAP);

      console.log(`calling function: ${httpDetails.name}, authorize: ${httpDetails.authorize}`);
      console.log(`rpID: ${httpDetails.rpID}, rpOrigin: ${httpDetails.rpOrigin}`);

      let verifiedUser: VerifiedUserItem | undefined;

      if (httpDetails.authorize) {
         if (!httpDetails.cookie) {
            throw new AuthError();
         }
         const headerCsrf = event['headers']['x-csrf-token'];

         // these throw an exception if cookie or headerCsrf is invalid
         verifiedUser = await verifyCookie(httpDetails.cookie);
         await verifyCsrf(verifiedUser, httpDetails.checkCsrf, headerCsrf);
      }

      if (httpDetails.version === INTERNAL_VERSION) {
         let dbytes: Uint8Array | undefined = undefined;
         try {
            dbytes = await decryptField(httpDetails.params.testkey, { purpose: 'internal' }, INTERNAL_PHRASE.length);
         } finally {
            if (!dbytes || new TextDecoder().decode(dbytes) !== INTERNAL_PHRASE) {
               throw new AuthError();
            }
         }
      }

      let response = await httpDetails.handler(httpDetails, verifiedUser);

      let respCookie: string | undefined;
      if (response.startSession) {
         respCookie = await createCookie(response.startSession);
         response.content['csrf'] = await createCsrf(response.startSession);
      } else if (response.endSession) {
         respCookie = killCookie();
      } else if (response.returnCsrf) {
         response.content['csrf'] = await createCsrf(verifiedUser!);
      }
      return makeResponse(JSON.stringify(response.content), 200, respCookie);

   } catch (err) {
      console.error(err);
      if (err instanceof ParamError) {
         return makeResponse(err.message, 400);
      } else if (err instanceof AuthError) {
         return makeResponse(err.message, 401);
      } else if (err instanceof NotFoundError) {
         return makeResponse(err.message, 404);
      } else {
         const msg = err instanceof Error ? err.name : "internal error";
         return makeResponse(msg, 500);
      }
   }
}


const METHODMAP: MethodMap = {
   GET: [
      // temporary for backward compatibility
      { name: 'getAuthOptions', pattern: Patterns.authOptions, version: 1, authorize: false, handler: postAuthOptions },
      { name: 'getUser', pattern: Patterns.user, version: 1, authorize: true, handler: getUser },
      { name: 'getPasskeyOptions', pattern: Patterns.passkeyOptions, version: 1, authorize: true, handler: getPasskeyOptions },
      // Special case of an authenticated method that does not require csrf. Needed so GET session works in a fresh
      // tab/window, and should be safe since csrf isn't technically needed for GET calls due to Same-Origin
      { name: 'getSession', pattern: Patterns.session, version: 1, authorize: true, checkCsrf: false, handler: getSession },
      { name: 'getInvitables', pattern: Patterns.invitables, version: 1, authorize: true, handler: getInvitables },
   ],
   POST: [
      { name: 'postAuthOptions', pattern: Patterns.authOptions, version: 1, authorize: false, handler: postAuthOptions },
      { name: 'postAuthVerify', pattern: Patterns.authVerify, version: 1, authorize: false, handler: postAuthVerify },
      { name: 'postPasskeyVerify', pattern: Patterns.passkeyVerify, version: 1, authorize: true, handler: postPasskeyVerify },
      { name: 'postRegOptions', pattern: Patterns.regOptions, version: 1, authorize: false, handler: postRegOptions },
      { name: 'postRegVerify', pattern: Patterns.regVerify, version: 1, authorize: false, handler: postRegVerify },
      { name: 'postRecover', pattern: Patterns.recover, version: 1, authorize: false, handler: postRecover },
      { name: 'postRecover2', pattern: Patterns.recover2, version: 1, authorize: false, handler: postRecover2 },

      // Internal only endpoints that are not exposed in cloudfront and require special auth
      { name: 'postMunge', pattern: Patterns.munge, version: INTERNAL_VERSION, authorize: false, handler: postMunge },
      { name: 'postConsistency', pattern: Patterns.consistency, version: INTERNAL_VERSION, authorize: false, handler: postConsistency },
      { name: 'postLoadAAGUIDs', pattern: Patterns.loadaaguids, version: INTERNAL_VERSION, authorize: false, handler: postLoadAAGUIDs },
   ],
   PUT: [
   ],
   PATCH: [
      { name: 'patchPasskey', pattern: Patterns.passkey, version: 1, authorize: true, handler: patchPasskey },
      { name: 'patchUser', pattern: Patterns.user, version: 1, authorize: true, handler: patchUser },
   ],
   DELETE: [
      { name: 'deletePasskey', pattern: Patterns.passkey, version: 1, authorize: true, handler: deletePasskey },
      { name: 'deleteSession', pattern: Patterns.session, version: 1, authorize: true, handler: deleteSession },
   ],
};

