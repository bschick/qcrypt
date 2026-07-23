import { type AuthenticatorData, type PublicKeyCredentialSource, type PublicKeyCredentialSourceJSON } from "../webauthn/webauthn-model";
export type PasskeyDiscoverableCredential = {
    readonly publicKeyCredentialDescriptor: PublicKeyCredentialDescriptor;
    readonly publicKeyCredentialSource: PublicKeyCredentialSource;
    readonly authenticatorData: AuthenticatorData;
    readonly user: PublicKeyCredentialUserEntity;
};
export type PasskeyDiscoverableCredentialJSON = {
    publicKeyCredentialDescriptor: PublicKeyCredentialDescriptorJSON;
    publicKeyCredentialSource: PublicKeyCredentialSourceJSON;
    authenticatorData: string;
    user: PublicKeyCredentialUserEntityJSON;
};
/**
 * Passkey credentials repository
 */
export interface PasskeysCredentialsRepository {
    saveCredential(credential: PasskeyDiscoverableCredential): void;
    deleteCredential(credential: PasskeyDiscoverableCredential): void;
    loadCredentials(): PasskeyDiscoverableCredential[];
}
/**
 * Get the ID of a credential
 * @param credential Credential
 */
export declare function getRepositoryId(credential: PasskeyDiscoverableCredential): string;
/**
 * Serialize a credential to a JSON string
 * @param credential Credential
 * @returns { id: Credential ID; data: JSON Credential }
 */
export declare function serializeCredential(credential: PasskeyDiscoverableCredential): string;
/**
 * Deserialize a credential from a JSON string
 * @param data JSON string
 * @returns Credential
 */
export declare function deserializeCredential(data: string): PasskeyDiscoverableCredential;
