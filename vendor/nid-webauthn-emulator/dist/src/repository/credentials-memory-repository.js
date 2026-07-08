"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PasskeysCredentialsMemoryRepository = void 0;
const credentials_repository_1 = require("./credentials-repository");
class PasskeysCredentialsMemoryRepository {
    credentials = new Map();
    saveCredential(credential) {
        const id = (0, credentials_repository_1.getRepositoryId)(credential);
        const serialized = (0, credentials_repository_1.serializeCredential)(credential);
        this.credentials.set(id, serialized);
    }
    deleteCredential(credential) {
        const id = (0, credentials_repository_1.getRepositoryId)(credential);
        this.credentials.delete(id);
    }
    loadCredentials() {
        return Array.from(this.credentials.values()).map((serialized) => (0, credentials_repository_1.deserializeCredential)(serialized));
    }
}
exports.PasskeysCredentialsMemoryRepository = PasskeysCredentialsMemoryRepository;
