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

import type { PublicKeyCredentialCreationOptionsJSON, RegistrationResponseJSON } from '@simplewebauthn/browser';

export {
   getUserCredPubKey,
   createUserCredProof,
   verifyUserCredProof,
   getRecoveryPubKey,
   createRecoveryProof,
   verifyRecoveryProof,
   // BACKWARD COMPAT: until clients update to call postRecover3 directly
   createRecoveryProofBackwardCompat,
   verifyRecoveryProofBackwardCompat,
   recoverySecret,
   RECOVERYID_BYTES,
   CHALLENGE_BYTES,
   PROOF_PUBKEY_BYTES,
   PROOF_SIG_BYTES,
} from './lib/proof';

export namespace RequestTypes {
   export type RegVerify = RegistrationResponseJSON & {
      userId: string;
      challenge: string;
      recoveryPubKey: string;
      passkeyUserCredEnc?: string;
      recoveryUserCredEnc?: string;
      userCredPubKey?: string;
   };
   export type RecoverVerify = RegistrationResponseJSON & {
      userId: string;
      challenge: string;
      passkeyUserCredEnc?: string;
   };
   export type AddVerify = RegistrationResponseJSON & {
      challenge: string;
      passkeyUserCredEnc?: string;
   };
   export type PasskeyVerify = RegVerify | RecoverVerify | AddVerify;

   export type RecoverProof = {
      timestamp: string;
      nonce: string;
      signature: string;
   };

   export type Recover3 = RecoverProof & {
      userId: string;
   };

   export type Recover3Key = RecoverProof & {
      recoveryPubKey: string;
      userCredEnc?: string;
   };
}

export namespace ResponseTypes {
   export type AuthenticatorInfo = {
      credentialId: string;
      description: string;
      lightIcon: string;
      darkIcon: string;
      name: string;
   };

   export type InvitableInfo = {
      invitableId: string;
      description?: string;
   };

   export type UserInfo = {
      verified: boolean;
      userId?: string;
      userName?: string;
      hasRecoveryId?: boolean;
      prf?: boolean;
      authenticators?: AuthenticatorInfo[];
      invitables?: InvitableInfo[];
   };

   export type LoginUserInfo = UserInfo & {
      pkId?: string;
      userCred?: string;
      userCredEnc?: string;
      csrf?: string;
   };

   export type RecoverInfo = PublicKeyCredentialCreationOptionsJSON & {
      prf?: boolean;
      userCredEnc?: string;
   };
}

export const TOPIC_USERS_MAX = 255;
export const SESSION_TIMEOUT_SEC = 60 * 60 * 3;
