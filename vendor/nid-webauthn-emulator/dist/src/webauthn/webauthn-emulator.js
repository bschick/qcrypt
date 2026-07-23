"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.WebAuthnEmulator = exports.WebAuthnEmulatorError = void 0;
const node_crypto_1 = require("node:crypto");
const authenticator_emulator_1 = require("../authenticator/authenticator-emulator");
const ctap_model_1 = require("../authenticator/ctap-model");
const encode_utils_1 = __importDefault(require("../libs/encode-utils"));
const webauthn_model_1 = require("./webauthn-model");
const webauthn_model_json_1 = require("./webauthn-model-json");
const PRF_OUTPUT_LENGTH = 32;
const PRF_SALT_PREFIX = encode_utils_1.default.strToUint8Array("WebAuthn PRF");
class WebAuthnEmulatorError extends Error {
}
exports.WebAuthnEmulatorError = WebAuthnEmulatorError;
/**
 * WebAuthn emulator
 */
class WebAuthnEmulator {
    authenticator;
    constructor(authenticator = new authenticator_emulator_1.AuthenticatorEmulator()) {
        this.authenticator = authenticator;
    }
    mapAuthenticatorErrorToDOMException(error) {
        let name;
        switch (error.status) {
            case ctap_model_1.CTAP_STATUS_CODE.CTAP2_ERR_CREDENTIAL_EXCLUDED:
                name = "NotAllowedError";
                break;
            case ctap_model_1.CTAP_STATUS_CODE.CTAP2_ERR_UNSUPPORTED_ALGORITHM:
                name = "NotSupportedError";
                break;
            case ctap_model_1.CTAP_STATUS_CODE.CTAP2_ERR_OPERATION_DENIED:
            case ctap_model_1.CTAP_STATUS_CODE.CTAP2_ERR_NOT_ALLOWED:
            case ctap_model_1.CTAP_STATUS_CODE.CTAP2_ERR_NO_CREDENTIALS:
                name = "NotAllowedError";
                break;
            case ctap_model_1.CTAP_STATUS_CODE.CTAP1_ERR_INVALID_PARAMETER:
            case ctap_model_1.CTAP_STATUS_CODE.CTAP2_ERR_INVALID_CBOR:
                name = "DataError";
                break;
            default:
                name = "UnknownError";
                break;
        }
        return new DOMException(error.message, name);
    }
    handleAuthenticatorCall(fn) {
        try {
            return fn();
        }
        catch (error) {
            if (error instanceof ctap_model_1.AuthenticationEmulatorError) {
                throw this.mapAuthenticatorErrorToDOMException(error);
            }
            throw error;
        }
    }
    getJSON(origin, optionsJSON, relatedOrigins = []) {
        const options = (0, webauthn_model_json_1.parseRequestOptionsFromJSON)(optionsJSON);
        const response = this.get(origin, { publicKey: options }, relatedOrigins);
        return response.toJSON();
    }
    createJSON(origin, optionsJSON, relatedOrigins = []) {
        const options = (0, webauthn_model_json_1.parseCreationOptionsFromJSON)(optionsJSON);
        const response = this.create(origin, { publicKey: options }, relatedOrigins);
        return response.toJSON();
    }
    getAuthenticatorInfo() {
        const authenticatorInfo = this.handleAuthenticatorCall(() => (0, ctap_model_1.unpackGetInfoResponse)(this.authenticator.command({ command: ctap_model_1.CTAP_COMMAND.authenticatorGetInfo })));
        return {
            version: authenticatorInfo.versions.join(", "),
            aaguid: encode_utils_1.default.encodeBase64Url(authenticatorInfo.aaguid),
            options: {
                rk: authenticatorInfo.options?.rk,
                uv: authenticatorInfo.options?.uv,
            },
        };
    }
    signalUnknownCredential(options) {
        const credentialId = (0, webauthn_model_json_1.decodeBase64Url)(options.credentialId);
        this.handleAuthenticatorCall(() => this.authenticator.command((0, ctap_model_1.packCredentialManagementRequest)({
            subCommand: ctap_model_1.CREDENTIAL_MANAGEMENT_SUBCOMMAND.deleteCredential,
            subCommandParams: {
                credentialId: encode_utils_1.default.bufferSourceToUint8Array(credentialId),
                rpId: options.rpId,
            },
        })));
    }
    /**
     * Signal all accepted credentials for a user
     * @see https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredential/signalAllAcceptedCredentials_static
     */
    signalAllAcceptedCredentials(options) {
        // Create a set of accepted credential IDs for quick lookup
        const acceptedCredentialIds = new Set(options.allAcceptedCredentialIds);
        // Start enumerating credentials for the specified RP
        const beginResponse = this.handleAuthenticatorCall(() => (0, ctap_model_1.unpackCredentialManagementResponse)(this.authenticator.command((0, ctap_model_1.packCredentialManagementRequest)({
            subCommand: ctap_model_1.CREDENTIAL_MANAGEMENT_SUBCOMMAND.enumerateCredentialsBegin,
            subCommandParams: {
                rpId: options.rpId,
            },
        }))));
        // Get the total number of credentials
        const totalCredentials = beginResponse.totalCredentials ?? 0;
        // Get all credentials for the RP and delete those not in the accepted list
        this.processCredentials(options.rpId, options.userId, acceptedCredentialIds, totalCredentials);
    }
    /**
     * Process credentials for an RP and delete those not in the accepted list
     */
    processCredentials(rpId, userId, acceptedCredentialIds, totalCredentials) {
        // Process each credential
        for (let i = 0; i < totalCredentials; i++) {
            // Get next credential and unpack the response
            const credResponse = this.handleAuthenticatorCall(() => (0, ctap_model_1.unpackCredentialManagementResponse)(this.authenticator.command((0, ctap_model_1.packCredentialManagementRequest)({
                subCommand: ctap_model_1.CREDENTIAL_MANAGEMENT_SUBCOMMAND.enumerateCredentialsGetNextCredential,
            }))));
            // Skip if this is not for the user we're looking for
            if (credResponse.user && encode_utils_1.default.encodeBase64Url(credResponse.user.id) !== userId) {
                continue;
            }
            // Delete credential if it's not in the accepted list
            if (credResponse.credentialID) {
                const credentialId = encode_utils_1.default.encodeBase64Url(credResponse.credentialID);
                if (!acceptedCredentialIds.has(credentialId)) {
                    // Delete the credential directly
                    this.handleAuthenticatorCall(() => this.authenticator.command((0, ctap_model_1.packCredentialManagementRequest)({
                        subCommand: ctap_model_1.CREDENTIAL_MANAGEMENT_SUBCOMMAND.deleteCredential,
                        subCommandParams: {
                            credentialId: credResponse.credentialID,
                            rpId: rpId,
                        },
                    })));
                }
            }
        }
    }
    /**
     * Signal current user details
     * @see https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredential/signalCurrentUserDetails_static
     */
    signalCurrentUserDetails(options) {
        const userId = (0, webauthn_model_json_1.decodeBase64Url)(options.userId);
        // Create user object with updated information
        const user = {
            id: userId,
            name: options.name,
            displayName: options.displayName,
        };
        // Update user information using the credential management API
        this.handleAuthenticatorCall(() => this.authenticator.command((0, ctap_model_1.packCredentialManagementRequest)({
            subCommand: ctap_model_1.CREDENTIAL_MANAGEMENT_SUBCOMMAND.updateUserInformation,
            subCommandParams: {
                rpId: options.rpId,
                user: user,
            },
        })));
    }
    /** @see https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/get */
    get(origin, options, relatedOrigins = []) {
        if (!options.publicKey)
            throw new TypeError("PublicKeyCredentialRequestOptions are required");
        const rpId = new webauthn_model_1.RpId(options.publicKey.rpId ?? new URL(origin).hostname);
        if (!rpId.validate(origin, relatedOrigins))
            throw new DOMException(`Invalid rpId: RP_ID=${rpId.value}, ORIGIN=${origin}`, "SecurityError");
        const clientData = {
            type: "webauthn.get",
            challenge: encode_utils_1.default.encodeBase64Url(options.publicKey.challenge),
            origin,
            crossOrigin: false,
        };
        const prf = options.publicKey.extensions?.prf;
        const requestExtensions = {};
        if (prf && (prf.eval || prf.evalByCredential)) {
            const allowCredentials = options.publicKey.allowCredentials;
            if (prf.evalByCredential && !allowCredentials?.length) {
                throw new DOMException("prf.evalByCredential requires allowCredentials", "NotSupportedError");
            }
            let prfValues = prf.eval;
            // In real browsers the WebAuthn layer selects the credential before building the CTAP request, which
            // resolves evalByCredential to that credential's salt. The NID emulator selects credentials in the
            // CTAP layer, so we only handle a single allowed credential to avoid polluting the CTAP layer
            if (prf.evalByCredential && allowCredentials?.length === 1) {
                const credentialId = encode_utils_1.default.encodeBase64Url(allowCredentials[0].id);
                prfValues = prf.evalByCredential[credentialId] ?? prfValues;
            }
            if (prfValues) {
                requestExtensions["hmac-secret"] = prfValuesToSalts(prfValues);
            }
        }
        const authenticatorRequest = (0, ctap_model_1.packGetAssertionRequest)({
            rpId: rpId.value,
            clientDataHash: encode_utils_1.default.bufferSourceToUint8Array(new Uint8Array((0, node_crypto_1.createHash)("sha256").update(JSON.stringify(clientData)).digest())),
            allowList: options.publicKey.allowCredentials,
            extensions: requestExtensions,
            options: (0, webauthn_model_1.toFido2RequestOptions)(options.publicKey.userVerification),
        });
        const authenticatorResponse = this.handleAuthenticatorCall(() => (0, ctap_model_1.unpackGetAssertionResponse)(this.authenticator.command(authenticatorRequest)));
        const responseId = authenticatorResponse.credential?.id ?? options.publicKey.allowCredentials?.[0]?.id;
        const authData = (0, webauthn_model_1.unpackAuthenticatorData)(authenticatorResponse.authData);
        const rawId = encode_utils_1.default.bufferSourceToUint8Array(responseId);
        const publicKeyCredential = {
            id: encode_utils_1.default.encodeBase64Url(rawId),
            type: "public-key",
            rawId: rawId.buffer,
            response: {
                clientDataJSON: encode_utils_1.default.strToUint8Array(JSON.stringify(clientData)).buffer,
                authenticatorData: authenticatorResponse.authData.buffer,
                signature: authenticatorResponse.signature.buffer,
                userHandle: authenticatorResponse.user
                    ? encode_utils_1.default.bufferSourceToUint8Array(authenticatorResponse.user.id).buffer
                    : null,
            },
            authenticatorAttachment: null,
            getClientExtensionResults: () => {
                const results = {
                    credProps: { rk: authenticatorResponse.user !== undefined },
                };
                const extensions = authData.extensions;
                const hmacOutput = extensions?.["hmac-secret"];
                if (hmacOutput instanceof Uint8Array) {
                    results.prf = { results: hmacSecretToPrfResults(hmacOutput) };
                }
                return results;
            },
            toJSON: () => (0, webauthn_model_json_1.toAuthenticationResponseJSON)(publicKeyCredential),
        };
        return publicKeyCredential;
    }
    /** @see https://developer.mozilla.org/ja/docs/Web/API/CredentialsContainer/create */
    create(origin, options, relatedOrigins = []) {
        if (!options.publicKey)
            throw new TypeError("PublicKeyCredentialCreationOptions are required");
        const rpId = new webauthn_model_1.RpId(options.publicKey.rp.id ?? new URL(origin).hostname);
        if (!rpId.validate(origin, relatedOrigins))
            throw new DOMException(`Invalid rpId: RP_ID=${rpId.value}, ORIGIN=${origin}`, "SecurityError");
        const clientData = {
            challenge: encode_utils_1.default.encodeBase64Url(options.publicKey.challenge),
            origin,
            type: "webauthn.create",
            crossOrigin: false,
        };
        const clientDataJSON = JSON.stringify(clientData);
        const prf = options.publicKey.extensions?.prf;
        const requestExtensions = {};
        if (prf) {
            requestExtensions["hmac-secret"] = true;
            if (prf.eval) {
                requestExtensions["hmac-secret-mc"] = prfValuesToSalts(prf.eval);
            }
        }
        const authenticatorRequest = (0, ctap_model_1.packMakeCredentialRequest)({
            clientDataHash: encode_utils_1.default.bufferSourceToUint8Array(new Uint8Array((0, node_crypto_1.createHash)("sha256").update(clientDataJSON).digest())),
            rp: { name: options.publicKey.rp.name, id: rpId.value },
            user: options.publicKey.user,
            pubKeyCredParams: options.publicKey.pubKeyCredParams,
            excludeList: options.publicKey.excludeCredentials,
            extensions: requestExtensions,
            options: (0, webauthn_model_1.toFido2CreateOptions)(options.publicKey.authenticatorSelection),
        });
        const authenticatorResponse = this.handleAuthenticatorCall(() => (0, ctap_model_1.unpackMakeCredentialResponse)(this.authenticator.command(authenticatorRequest)));
        const authData = (0, webauthn_model_1.unpackAuthenticatorData)(authenticatorResponse.authData);
        const attestedCredentialData = authData.attestedCredentialData;
        const attestationObject = {
            fmt: "none",
            attStmt: {},
            authData,
        };
        const response = {
            attestationObject: (0, webauthn_model_1.packAttestationObject)(attestationObject).buffer,
            clientDataJSON: encode_utils_1.default.strToUint8Array(clientDataJSON).buffer,
            getAuthenticatorData: () => (0, webauthn_model_1.packAuthenticatorData)(authData).buffer,
            getPublicKey: () => attestedCredentialData.credentialPublicKey.toDer().buffer,
            getPublicKeyAlgorithm: () => attestedCredentialData.credentialPublicKey.alg,
            getTransports: () => this.authenticator.params.transports,
        };
        const publicKeyCredential = {
            id: encode_utils_1.default.encodeBase64Url(attestedCredentialData.credentialId),
            type: "public-key",
            rawId: attestedCredentialData.credentialId.buffer,
            response,
            authenticatorAttachment: null,
            getClientExtensionResults: () => {
                const results = { credProps: { rk: true } };
                if (prf) {
                    const extensions = authData.extensions;
                    const hmacOutput = extensions?.["hmac-secret"];
                    if (hmacOutput instanceof Uint8Array) {
                        results.prf = { enabled: true, results: hmacSecretToPrfResults(hmacOutput) };
                    }
                    else {
                        results.prf = { enabled: hmacOutput === true };
                    }
                }
                return results;
            },
            toJSON: () => (0, webauthn_model_json_1.toRegistrationResponseJSON)(publicKeyCredential),
        };
        return publicKeyCredential;
    }
}
exports.WebAuthnEmulator = WebAuthnEmulator;
// A PRF input maps to a CTAP hmac-secret salt as SHA-256("WebAuthn PRF" || 0x00 || input).
function prfInputToSalt(input) {
    const inputBytes = encode_utils_1.default.bufferSourceToUint8Array(input);
    if (inputBytes.length === 0) {
        throw new TypeError("PRF eval input must not be empty");
    }
    const data = new Uint8Array(PRF_SALT_PREFIX.length + 1 + inputBytes.length);
    data.set(PRF_SALT_PREFIX, 0);
    data.set(inputBytes, PRF_SALT_PREFIX.length + 1);
    return new Uint8Array((0, node_crypto_1.createHash)("sha256").update(data).digest());
}
function prfValuesToSalts(values) {
    const first = prfInputToSalt(values.first);
    let salts = first;
    if (values.second) {
        const second = prfInputToSalt(values.second);
        salts = new Uint8Array(first.length + second.length);
        salts.set(first, 0);
        salts.set(second, first.length);
    }
    return salts;
}
function hmacSecretToPrfResults(output) {
    if (output.length === PRF_OUTPUT_LENGTH) {
        return { first: output.slice(0, PRF_OUTPUT_LENGTH).buffer };
    }
    return {
        first: output.slice(0, PRF_OUTPUT_LENGTH).buffer,
        second: output.slice(PRF_OUTPUT_LENGTH, 2 * PRF_OUTPUT_LENGTH).buffer,
    };
}
