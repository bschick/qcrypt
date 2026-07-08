import type { AuthenticatorInteractionOptions, AuthenticatorOptions } from "../authenticator/ctap-model";
import { CoseKey } from "./cose-key";
export declare class RpId {
    readonly value: string;
    constructor(value: string);
    get hash(): Uint8Array<ArrayBuffer>;
    /** @see https://www.w3.org/TR/webauthn-3/#sctn-validating-origin */
    validate(origin: string, relatedOrigins?: string[]): boolean;
}
/** @see https://www.w3.org/TR/webauthn-3/#public-key-credential-source */
export type PublicKeyCredentialSource = {
    type: "public-key";
    id: Uint8Array<ArrayBuffer>;
    privateKey: Uint8Array<ArrayBuffer>;
    rpId: RpId;
    userHandle?: Uint8Array<ArrayBuffer>;
    credRandom?: Uint8Array<ArrayBuffer>;
};
/** @see https://www.w3.org/TR/webauthn-3/#sctn-attested-credential-data */
export type AttestedCredentialData = {
    aaguid: Uint8Array<ArrayBuffer>;
    credentialId: Uint8Array<ArrayBuffer>;
    credentialPublicKey: CoseKey;
};
/** @see https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data */
export type AuthenticatorData = {
    rpIdHash: Uint8Array<ArrayBuffer>;
    flags: {
        userPresent?: boolean;
        userVerified?: boolean;
        backupEligibility?: boolean;
        backupState?: boolean;
        attestedCredentialData?: boolean;
        extensionData?: boolean;
    };
    signCount: number;
    attestedCredentialData?: AttestedCredentialData;
    extensions?: object;
};
/** @see https://www.w3.org/TR/webauthn-3/#attestation-object */
export type AttestationObject = {
    fmt: string;
    attStmt: object;
    authData: AuthenticatorData;
};
/** @see https://www.w3.org/TR/webauthn-3/#dictionary-client-data */
export type CollectedClientData = {
    type: "webauthn.get" | "webauthn.create";
    challenge: string;
    origin: string;
    crossOrigin: boolean;
};
export declare function packAttestationObject(attestationObject: AttestationObject): Uint8Array<ArrayBuffer>;
export declare function packAuthenticatorData(authData: AuthenticatorData): Uint8Array<ArrayBuffer>;
export declare function unpackAttestationObject(attestationObject: Uint8Array<ArrayBuffer>): AttestationObject;
export declare function unpackAuthenticatorData(authData: Uint8Array<ArrayBuffer>): AuthenticatorData;
export type PublicKeyCredentialSourceJSON = {
    type: "public-key";
    id: string;
    privateKey: string;
    rpId: string;
    userHandle?: string;
    credRandom?: string;
};
export declare function toPublickeyCredentialSourceJSON(credentialSource: PublicKeyCredentialSource): PublicKeyCredentialSourceJSON;
export declare function parsePublicKeyCredentialSourceFromJSON(json: PublicKeyCredentialSourceJSON): PublicKeyCredentialSource;
/** @see https://www.w3.org/TR/webauthn-3/#CreateCred-async-loop */
export declare function toFido2CreateOptions(criteria?: AuthenticatorSelectionCriteria): AuthenticatorOptions;
/** @see https://www.w3.org/TR/webauthn-3/#sctn-issuing-cred-request-to-authenticator */
export declare function toFido2RequestOptions(require?: UserVerificationRequirement): AuthenticatorInteractionOptions;
