import { type PasskeyDiscoverableCredential, type PasskeysCredentialsRepository } from "./credentials-repository";
export declare class PasskeysCredentialsFileRepository implements PasskeysCredentialsRepository {
    private readonly credentialsDir;
    constructor(credentialsDir?: string);
    saveCredential(credential: PasskeyDiscoverableCredential): void;
    deleteCredential(credential: PasskeyDiscoverableCredential): void;
    loadCredentials(): PasskeyDiscoverableCredential[];
}
