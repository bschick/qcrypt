"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getRepositoryId = getRepositoryId;
exports.serializeCredential = serializeCredential;
exports.deserializeCredential = deserializeCredential;
const encode_utils_1 = __importDefault(require("../libs/encode-utils"));
const webauthn_model_1 = require("../webauthn/webauthn-model");
const webauthn_model_json_1 = require("../webauthn/webauthn-model-json");
/**
 * Get the ID of a credential
 * @param credential Credential
 */
function getRepositoryId(credential) {
    return encode_utils_1.default.encodeBase64Url(credential.publicKeyCredentialDescriptor.id);
}
/**
 * Serialize a credential to a JSON string
 * @param credential Credential
 * @returns { id: Credential ID; data: JSON Credential }
 */
function serializeCredential(credential) {
    const serialized = {
        publicKeyCredentialDescriptor: (0, webauthn_model_json_1.toPublicKeyCredentialDescriptorJSON)(credential.publicKeyCredentialDescriptor),
        publicKeyCredentialSource: (0, webauthn_model_1.toPublickeyCredentialSourceJSON)(credential.publicKeyCredentialSource),
        authenticatorData: encode_utils_1.default.encodeBase64Url((0, webauthn_model_1.packAuthenticatorData)(credential.authenticatorData)),
        user: (0, webauthn_model_json_1.toPublicKeyCredentialUserEntityJSON)(credential.user),
    };
    return JSON.stringify(serialized, null, 2);
}
/**
 * Deserialize a credential from a JSON string
 * @param data JSON string
 * @returns Credential
 */
function deserializeCredential(data) {
    const serialized = JSON.parse(data);
    return {
        publicKeyCredentialDescriptor: (0, webauthn_model_json_1.parsePublicKeyCredentialDescriptorFromJSON)(serialized.publicKeyCredentialDescriptor),
        publicKeyCredentialSource: (0, webauthn_model_1.parsePublicKeyCredentialSourceFromJSON)(serialized.publicKeyCredentialSource),
        authenticatorData: (0, webauthn_model_1.unpackAuthenticatorData)(encode_utils_1.default.decodeBase64Url(serialized.authenticatorData)),
        user: (0, webauthn_model_json_1.parsePublicKeyCredentialUserEntityFromJSON)(serialized.user),
    };
}
