import type { PasskeysCredentialsRepository } from "../repository/credentials-repository";
import { type AuthenticatorData, type PublicKeyCredentialSource } from "../webauthn/webauthn-model";
import { type AuthenticatorCredentialManagementRequest, type AuthenticatorCredentialManagementResponse, type AuthenticatorGetAssertionRequest, type AuthenticatorGetAssertionResponse, type AuthenticatorGetInfoResponse, type AuthenticatorMakeCredentialRequest, type AuthenticatorMakeCredentialResponse, type AuthenticatorOptions, type CTAPAuthenticatorRequest, type CTAPAuthenticatorResponse } from "./ctap-model";
type InteractionResponse = {
    options: {
        uv: boolean;
        up: boolean;
    };
};
export declare const COSEAlgorithmIdentifier: {
    ES256: number;
    RS256: number;
    EdDSA: number;
};
export type PasskeyCredential = {
    readonly publicKeyCredentialDescriptor: PublicKeyCredentialDescriptor;
    readonly publicKeyCredentialSource: PublicKeyCredentialSource;
    readonly authenticatorData: AuthenticatorData;
    readonly user: PublicKeyCredentialUserEntity | undefined;
};
export type HmacSecretMode = "none" | "hmac-secret" | "hmac-secret-mc";
export type AuthenticatorParameters = {
    readonly aaguid: Uint8Array<ArrayBuffer>;
    readonly transports: AuthenticatorTransport[];
    readonly algorithmIdentifiers: readonly (keyof typeof COSEAlgorithmIdentifier)[];
    readonly signCounterIncrement: number;
    readonly verifications: {
        readonly userPresent: boolean;
        readonly userVerified: boolean;
    };
    readonly userMakeCredentialInteraction: (user: PublicKeyCredentialUserEntity, options?: Partial<AuthenticatorOptions>) => InteractionResponse | undefined;
    readonly userGetAssertionInteraction: (user: PublicKeyCredentialUserEntity | undefined, options?: Partial<AuthenticatorOptions>) => InteractionResponse | undefined;
    readonly credentialsRepository: PasskeysCredentialsRepository | undefined;
    readonly stateless: boolean;
    readonly hmacSecret: HmacSecretMode;
};
export type MakeCredentialInteraction = (user: PublicKeyCredentialUserEntity, uv: boolean) => boolean;
/**
 * Authenticator emulator
 */
export declare class AuthenticatorEmulator {
    private static readonly ENCRYPT_KEY;
    /** Authenticator Attestation Global Unique Identifier (16byte)  */
    private static readonly DEFAULT_AAGUID;
    private static readonly DEFAULT_TRANSPORTS;
    private static readonly DEFAULT_ALGORITHM_IDENTIFIERS;
    private static readonly DEFAULT_SIGN_COUNTER_INCREMENT;
    private static readonly DEFAULT_VERIFICATIONS;
    private static readonly DEFAULT_MAKE_CREDENTIAL_INTERACTION;
    private static readonly DEFAULT_GET_ASSERTION_INTERACTION;
    private static readonly DEFAULT_CREDENTIALS_REPOSITORY;
    private static readonly DEFAULT_STATELESS;
    private static readonly DEFAULT_HMAC_SECRET;
    params: AuthenticatorParameters;
    constructor(params?: Partial<AuthenticatorParameters>);
    /** @see https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticator-api */
    command(request: CTAPAuthenticatorRequest): CTAPAuthenticatorResponse;
    /**
     * @see https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorCredentialManagement
     */
    authenticatorCredentialManagement(request: AuthenticatorCredentialManagementRequest): AuthenticatorCredentialManagementResponse;
    private enumerationState;
    private authenticatorEnumerateCredentialsBegin;
    private authenticatorEnumerateCredentialsGetNextCredential;
    private authenticatorUpdateUserInformation;
    private authenticatorDeleteCredential;
    /** @see https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorGetInfo */
    authenticatorGetInfo(): AuthenticatorGetInfoResponse;
    /**
     * @see https://www.w3.org/TR/webauthn/#sctn-op-make-cred
     * @see https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorMakeCredential
     **/
    authenticatorMakeCredential(request: AuthenticatorMakeCredentialRequest): AuthenticatorMakeCredentialResponse;
    /**
     * @see https://www.w3.org/TR/webauthn/#sctn-op-get-assertion
     * @see https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorGetAssertion
     **/
    authenticatorGetAssertion(request: AuthenticatorGetAssertionRequest): AuthenticatorGetAssertionResponse;
}
export {};
