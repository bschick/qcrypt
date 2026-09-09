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

// Builds each WebAuthn payload from named fields only, so anything else carried on a source
// object is left behind rather than spread along.

// Leaf and enum types are reused from simplewebauthn because they constrain values rather than
// shape, and reusing them keeps these types assignable to the browser ceremony calls.
import type {
   AttestationConveyancePreference,
   AuthenticationExtensionsClientInputs,
   AuthenticationResponseJSON,
   AuthenticatorAttachment,
   AuthenticatorSelectionCriteria,
   AuthenticatorTransportFuture,
   COSEAlgorithmIdentifier,
   PublicKeyCredentialCreationOptionsJSON,
   PublicKeyCredentialRequestOptionsJSON,
   PublicKeyCredentialType,
   RegistrationResponseJSON,
   ResidentKeyRequirement,
   UserVerificationRequirement,
} from '@simplewebauthn/browser';

// The credential public key and its algorithm travel inside attestationObject.
export type RegistrationFields = {
   id: string;
   rawId: string;
   type: PublicKeyCredentialType;
   response: {
      clientDataJSON: string;
      attestationObject: string;
      transports?: AuthenticatorTransportFuture[];
   };
};

// userHandle is the one field here not covered by the assertion signature.
export type AuthenticationFields = {
   id: string;
   rawId: string;
   type: PublicKeyCredentialType;
   response: {
      clientDataJSON: string;
      authenticatorData: string;
      signature: string;
      userHandle?: string;
   };
};

function pickRegistrationFields(source: RegistrationFields): RegistrationFields {
   return {
      id: source.id,
      rawId: source.rawId,
      type: source.type,
      response: {
         clientDataJSON: source.response.clientDataJSON,
         attestationObject: source.response.attestationObject,
         transports: source.response.transports,
      },
   };
}

function pickAuthenticationFields(source: AuthenticationFields): AuthenticationFields {
   return {
      id: source.id,
      rawId: source.rawId,
      type: source.type,
      response: {
         clientDataJSON: source.response.clientDataJSON,
         authenticatorData: source.response.authenticatorData,
         signature: source.response.signature,
         userHandle: source.response.userHandle,
      },
   };
}

// ----- Requests (client to server) -----

// A null userId asks for every passkey on the domain rather than a named account's.
export type AuthOptionsRequest = {
   userId: string | null;
};

export type RegOptionsRequest = {
   userName: string;
};

export type AuthVerifyRiders = {
   challenge: string;
};

export type RegVerifyRiders = {
   userId: string;
   challenge: string;
   recoveryPubKey: string;
   passkeyUserCredEnc?: string;
   recoveryUserCredEnc?: string;
   userCredPubKey?: string;
};

export type RecoverVerifyRiders = {
   userId: string;
   challenge: string;
   passkeyUserCredEnc?: string;
};

export type AddVerifyRiders = {
   challenge: string;
   passkeyUserCredEnc?: string;
};

export type AuthVerifyRequest = AuthenticationFields & AuthVerifyRiders;
export type RegVerifyRequest = RegistrationFields & RegVerifyRiders;
export type RecoverVerifyRequest = RegistrationFields & RecoverVerifyRiders;
export type AddVerifyRequest = RegistrationFields & AddVerifyRiders;
export type PasskeyVerifyRequest = RegVerifyRequest | RecoverVerifyRequest | AddVerifyRequest;

export function makeAuthVerifyRequest(source: AuthenticationFields, riders: AuthVerifyRiders): AuthVerifyRequest {
   return {
      ...pickAuthenticationFields(source),
      challenge: riders.challenge,
   };
}

export function makeRegVerifyRequest(source: RegistrationFields, riders: RegVerifyRiders): RegVerifyRequest {
   return {
      ...pickRegistrationFields(source),
      userId: riders.userId,
      challenge: riders.challenge,
      recoveryPubKey: riders.recoveryPubKey,
      passkeyUserCredEnc: riders.passkeyUserCredEnc,
      recoveryUserCredEnc: riders.recoveryUserCredEnc,
      userCredPubKey: riders.userCredPubKey,
   };
}

export function makeRecoverVerifyRequest(
   source: RegistrationFields,
   riders: RecoverVerifyRiders,
): RecoverVerifyRequest {
   return {
      ...pickRegistrationFields(source),
      userId: riders.userId,
      challenge: riders.challenge,
      passkeyUserCredEnc: riders.passkeyUserCredEnc,
   };
}

export function makeAddVerifyRequest(source: RegistrationFields, riders: AddVerifyRiders): AddVerifyRequest {
   return {
      ...pickRegistrationFields(source),
      challenge: riders.challenge,
      passkeyUserCredEnc: riders.passkeyUserCredEnc,
   };
}

// ----- Responses (server to client) -----

// These match the simplewebauthn options types as of 2026-09-08. They are declared separately so
// that later library changes cannot silently alter the wire shape.

export type CredentialDescriptorResponse = {
   id: string;
   type: PublicKeyCredentialType;
   transports?: AuthenticatorTransportFuture[];
};

export type RegOptionsResponse = {
   rp: { name: string; id?: string };
   user: { id: string; name: string; displayName: string };
   challenge: string;
   pubKeyCredParams: { alg: COSEAlgorithmIdentifier; type: PublicKeyCredentialType }[];
   timeout?: number;
   excludeCredentials?: CredentialDescriptorResponse[];
   authenticatorSelection?: {
      authenticatorAttachment?: AuthenticatorAttachment;
      residentKey?: ResidentKeyRequirement;
      requireResidentKey?: boolean;
      userVerification?: UserVerificationRequirement;
   };
   hints?: PublicKeyCredentialCreationOptionsJSON['hints'];
   attestation?: AttestationConveyancePreference;
   attestationFormats?: PublicKeyCredentialCreationOptionsJSON['attestationFormats'];
   extensions?: AuthenticationExtensionsClientInputs;
};

export type AuthOptionsResponse = {
   challenge: string;
   timeout?: number;
   rpId?: string;
   allowCredentials?: CredentialDescriptorResponse[];
   userVerification?: UserVerificationRequirement;
   hints?: PublicKeyCredentialRequestOptionsJSON['hints'];
   extensions?: AuthenticationExtensionsClientInputs;
};

function pickDescriptors(
   descriptors: CredentialDescriptorResponse[] | undefined,
): CredentialDescriptorResponse[] | undefined {
   return descriptors?.map((descriptor) => ({
      id: descriptor.id,
      type: descriptor.type,
      transports: descriptor.transports,
   }));
}

function pickSelection(
   selection: AuthenticatorSelectionCriteria | undefined,
): RegOptionsResponse['authenticatorSelection'] {
   if (!selection) {
      return undefined;
   }
   return {
      authenticatorAttachment: selection.authenticatorAttachment,
      residentKey: selection.residentKey,
      requireResidentKey: selection.requireResidentKey,
      userVerification: selection.userVerification,
   };
}

export function makeRegOptionsResponse(source: PublicKeyCredentialCreationOptionsJSON): RegOptionsResponse {
   return {
      rp: { name: source.rp.name, id: source.rp.id },
      user: { id: source.user.id, name: source.user.name, displayName: source.user.displayName },
      challenge: source.challenge,
      pubKeyCredParams: source.pubKeyCredParams.map((param) => ({ alg: param.alg, type: param.type })),
      timeout: source.timeout,
      excludeCredentials: pickDescriptors(source.excludeCredentials),
      authenticatorSelection: pickSelection(source.authenticatorSelection),
      hints: source.hints,
      attestation: source.attestation,
      attestationFormats: source.attestationFormats,
      // An open map interpreted by the browser, so it is carried whole rather than enumerated.
      extensions: source.extensions,
   };
}

export function makeAuthOptionsResponse(source: PublicKeyCredentialRequestOptionsJSON): AuthOptionsResponse {
   return {
      challenge: source.challenge,
      timeout: source.timeout,
      rpId: source.rpId,
      allowCredentials: pickDescriptors(source.allowCredentials),
      userVerification: source.userVerification,
      hints: source.hints,
      // See makeRegOptionsResponse
      extensions: source.extensions,
   };
}

// ----- Adapters for @simplewebauthn/server -----

// Both verifier types require clientExtensionResults, so supply an empty value.

export function toRegistrationResponseJSON(request: RegistrationFields): RegistrationResponseJSON {
   return { ...pickRegistrationFields(request), clientExtensionResults: {} };
}

export function toAuthenticationResponseJSON(request: AuthenticationFields): AuthenticationResponseJSON {
   return { ...pickAuthenticationFields(request), clientExtensionResults: {} };
}
