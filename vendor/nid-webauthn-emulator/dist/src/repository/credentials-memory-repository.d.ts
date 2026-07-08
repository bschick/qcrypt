import { type PasskeyDiscoverableCredential, type PasskeysCredentialsRepository } from "./credentials-repository";
export declare class PasskeysCredentialsMemoryRepository implements PasskeysCredentialsRepository {
    private readonly credentials;
    saveCredential(credential: PasskeyDiscoverableCredential): void;
    deleteCredential(credential: PasskeyDiscoverableCredential): void;
    loadCredentials(): PasskeyDiscoverableCredential[];
}
