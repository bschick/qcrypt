export type AuthenticatorOptions = {
    rk: boolean;
    uv: boolean;
    up: boolean;
};
export type AuthenticatorInteractionOptions = {
    up: boolean;
    uv: boolean;
};
/** @see https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorMakeCredential */
export interface AuthenticatorMakeCredentialRequest {
    clientDataHash: Uint8Array<ArrayBuffer>;
    rp: PublicKeyCredentialRpEntity & {
        id: string;
    };
    user: PublicKeyCredentialUserEntity;
    pubKeyCredParams: PublicKeyCredentialParameters[];
    excludeList?: PublicKeyCredentialDescriptor[];
    extensions?: object;
    options?: Partial<AuthenticatorOptions>;
    pinAuth?: Uint8Array<ArrayBuffer>;
    pinProtocol?: number;
}
/** @see https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorMakeCredential */
export interface AuthenticatorMakeCredentialResponse {
    fmt: string;
    authData: Uint8Array<ArrayBuffer>;
    attStmt: object;
}
/** @see https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorGetAssertion */
export interface AuthenticatorGetAssertionRequest {
    rpId: string;
    clientDataHash: Uint8Array<ArrayBuffer>;
    allowList?: PublicKeyCredentialDescriptor[];
    extensions?: object;
    options?: Partial<AuthenticatorOptions>;
    pinAuth?: Uint8Array<ArrayBuffer>;
    pinProtocol?: number;
}
/** @see https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorGetAssertion */
export interface AuthenticatorGetAssertionResponse {
    credential?: PublicKeyCredentialDescriptor;
    authData: Uint8Array<ArrayBuffer>;
    signature: Uint8Array<ArrayBuffer>;
    user?: PublicKeyCredentialUserEntity;
    numberOfCredentials: number;
}
/** @see https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorGetInfo */
export type AuthenticatorGetInfoResponse = {
    versions: string[];
    extensions?: string[];
    aaguid: Uint8Array<ArrayBuffer>;
    options?: Partial<AuthenticatorOptions> & {
        plat?: boolean;
        clientPin?: boolean;
    };
    maxMsgSize?: number;
    pinProtocols?: number[];
};
/** @see https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#error-responses */
export declare enum CTAP_STATUS_CODE {
    CTAP2_OK = 0,
    CTAP1_ERR_INVALID_COMMAND = 1,
    CTAP1_ERR_INVALID_PARAMETER = 2,
    CTAP2_ERR_INVALID_CBOR = 18,
    CTAP2_ERR_CREDENTIAL_EXCLUDED = 25,
    CTAP2_ERR_UNSUPPORTED_ALGORITHM = 38,
    CTAP2_ERR_OPERATION_DENIED = 39,
    CTAP2_ERR_NO_CREDENTIALS = 46,
    CTAP2_ERR_NOT_ALLOWED = 48
}
/** @see https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#commands */
export declare enum CTAP_COMMAND {
    authenticatorMakeCredential = 1,
    authenticatorGetAssertion = 2,
    authenticatorGetInfo = 4,
    authenticatorClientPIN = 6,
    authenticatorReset = 7,
    authenticatorGetNextAssertion = 8,
    authenticatorCredentialManagement = 10
}
export declare enum CREDENTIAL_MANAGEMENT_SUBCOMMAND {
    getCredsMetadata = 1,
    enumerateRPsBegin = 2,
    enumerateRPsGetNextRP = 3,
    enumerateCredentialsBegin = 4,
    enumerateCredentialsGetNextCredential = 5,
    deleteCredential = 6,
    updateUserInformation = 7
}
export interface AuthenticatorCredentialManagementRequest {
    subCommand: CREDENTIAL_MANAGEMENT_SUBCOMMAND;
    subCommandParams?: {
        credentialId?: Uint8Array<ArrayBuffer>;
        rpId?: string;
        user?: PublicKeyCredentialUserEntity;
    };
    pinUvAuthProtocol?: number;
    pinUvAuthParam?: Uint8Array<ArrayBuffer>;
}
export interface AuthenticatorCredentialManagementResponse {
    existingResidentCredentialsCount?: number;
    maxPossibleRemainingResidentCredentialsCount?: number;
    rp?: PublicKeyCredentialRpEntity;
    rpIDHash?: Uint8Array<ArrayBuffer>;
    totalRPs?: number;
    user?: PublicKeyCredentialUserEntity;
    credentialID?: Uint8Array<ArrayBuffer>;
    publicKey?: Uint8Array<ArrayBuffer>;
    totalCredentials?: number;
    credProtect?: number;
    largeBlobKey?: Uint8Array<ArrayBuffer>;
}
/** @see https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#responses */
export interface CTAPAuthenticatorResponse {
    status: CTAP_STATUS_CODE;
    data?: Uint8Array<ArrayBuffer>;
}
/** @see https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#commands */
export interface CTAPAuthenticatorRequest {
    command: CTAP_COMMAND;
    data?: Uint8Array<ArrayBuffer>;
}
export declare class AuthenticationEmulatorError extends Error {
    status: CTAP_STATUS_CODE;
    type: string;
    constructor(status: CTAP_STATUS_CODE, options?: ErrorOptions);
}
export declare function unpackRequest(request: CTAPAuthenticatorRequest): {
    command: CTAP_COMMAND;
    request: unknown;
};
export declare function packMakeCredentialRequest(request: AuthenticatorMakeCredentialRequest): CTAPAuthenticatorRequest;
export declare function packGetAssertionRequest(request: AuthenticatorGetAssertionRequest): CTAPAuthenticatorRequest;
export declare function packCredentialManagementRequest(request: AuthenticatorCredentialManagementRequest): CTAPAuthenticatorRequest;
export declare function unpackCredentialManagementRequest(request: CTAPAuthenticatorRequest): AuthenticatorCredentialManagementRequest;
export declare function unpackMakeCredentialResponse(response: CTAPAuthenticatorResponse): AuthenticatorMakeCredentialResponse;
export declare function packMakeCredentialResponse(response: AuthenticatorMakeCredentialResponse): CTAPAuthenticatorResponse;
export declare function unpackGetAssertionResponse(response: CTAPAuthenticatorResponse): AuthenticatorGetAssertionResponse;
export declare function packGetAssertionResponse(response: AuthenticatorGetAssertionResponse): CTAPAuthenticatorResponse;
export declare function unpackGetInfoResponse(response: CTAPAuthenticatorResponse): AuthenticatorGetInfoResponse;
export declare function packGetInfoResponse(response: AuthenticatorGetInfoResponse): CTAPAuthenticatorResponse;
export declare function packCredentialManagementResponse(response: AuthenticatorCredentialManagementResponse): CTAPAuthenticatorResponse;
export declare function unpackCredentialManagementResponse(response: CTAPAuthenticatorResponse): AuthenticatorCredentialManagementResponse;
