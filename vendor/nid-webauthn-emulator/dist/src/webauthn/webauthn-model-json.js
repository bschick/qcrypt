"use strict";
// Do not import anything here, it should be a standalone file
Object.defineProperty(exports, "__esModule", { value: true });
exports.parseCreationOptionsFromJSON = parseCreationOptionsFromJSON;
exports.parseRequestOptionsFromJSON = parseRequestOptionsFromJSON;
exports.toRegistrationResponseJSON = toRegistrationResponseJSON;
exports.toAuthenticationResponseJSON = toAuthenticationResponseJSON;
exports.toCreationOptionsJSON = toCreationOptionsJSON;
exports.toRequestOptionsJSON = toRequestOptionsJSON;
exports.parseRegistrationResponseFromJSON = parseRegistrationResponseFromJSON;
exports.parseAuthenticationResponseFromJSON = parseAuthenticationResponseFromJSON;
exports.toPublicKeyCredentialDescriptorJSON = toPublicKeyCredentialDescriptorJSON;
exports.parsePublicKeyCredentialDescriptorFromJSON = parsePublicKeyCredentialDescriptorFromJSON;
exports.toPublicKeyCredentialUserEntityJSON = toPublicKeyCredentialUserEntityJSON;
exports.parsePublicKeyCredentialUserEntityFromJSON = parsePublicKeyCredentialUserEntityFromJSON;
exports.parsePRFValuesFromJSON = parsePRFValuesFromJSON;
exports.parseExtensionResultsFromJSON = parseExtensionResultsFromJSON;
exports.toPRFValuesJSON = toPRFValuesJSON;
exports.toPRFInputsJSON = toPRFInputsJSON;
exports.toExtensionInputsJSON = toExtensionInputsJSON;
exports.encodeBase64Url = encodeBase64Url;
exports.decodeBase64Url = decodeBase64Url;
/** @see https://www.w3.org/TR/webauthn-3/#sctn-parseCreationOptionsFromJSON */
function parseCreationOptionsFromJSON(optionsJSON) {
    return {
        rp: optionsJSON.rp,
        user: parsePublicKeyCredentialUserEntityFromJSON(optionsJSON.user),
        challenge: decodeBase64Url(optionsJSON.challenge),
        pubKeyCredParams: optionsJSON.pubKeyCredParams,
        timeout: optionsJSON.timeout,
        excludeCredentials: optionsJSON.excludeCredentials?.map(parsePublicKeyCredentialDescriptorFromJSON),
        authenticatorSelection: optionsJSON.authenticatorSelection,
        attestation: optionsJSON.attestation,
        extensions: parseExtensionsFromJSON(optionsJSON.extensions),
    };
}
/** @see https://www.w3.org/TR/webauthn-3/#sctn-parseRequestOptionsFromJSON */
function parseRequestOptionsFromJSON(optionsJSON) {
    return {
        challenge: decodeBase64Url(optionsJSON.challenge),
        timeout: optionsJSON.timeout,
        rpId: optionsJSON.rpId,
        allowCredentials: optionsJSON.allowCredentials?.map(parsePublicKeyCredentialDescriptorFromJSON),
        userVerification: optionsJSON.userVerification,
        extensions: parseExtensionsFromJSON(optionsJSON.extensions),
    };
}
// Not standard mapping functions
function toRegistrationResponseJSON(credential) {
    const attestationResponse = credential.response;
    const publicKey = attestationResponse.getPublicKey();
    const algorithm = attestationResponse.getPublicKeyAlgorithm();
    const responseJSON = {
        clientDataJSON: encodeBase64Url(attestationResponse.clientDataJSON),
        authenticatorData: encodeBase64Url(attestationResponse.getAuthenticatorData()),
        transports: attestationResponse.getTransports(),
        publicKey: publicKey ? encodeBase64Url(publicKey) : undefined,
        publicKeyAlgorithm: algorithm,
        attestationObject: encodeBase64Url(attestationResponse.attestationObject),
    };
    return {
        id: credential.id,
        rawId: credential.id,
        response: responseJSON,
        authenticatorAttachment: credential.authenticatorAttachment === null
            ? undefined
            : credential.authenticatorAttachment,
        clientExtensionResults: toExtensionResultsJSON(credential.getClientExtensionResults()),
        type: credential.type,
    };
}
function toAuthenticationResponseJSON(credential) {
    const assertionResponse = credential.response;
    const responseJson = {
        clientDataJSON: encodeBase64Url(assertionResponse.clientDataJSON),
        authenticatorData: encodeBase64Url(assertionResponse.authenticatorData),
        signature: encodeBase64Url(assertionResponse.signature),
        userHandle: assertionResponse.userHandle ? encodeBase64Url(assertionResponse.userHandle) : undefined,
    };
    return {
        id: credential.id,
        rawId: credential.id,
        response: responseJson,
        authenticatorAttachment: credential.authenticatorAttachment === null
            ? undefined
            : credential.authenticatorAttachment,
        clientExtensionResults: toExtensionResultsJSON(credential.getClientExtensionResults()),
        type: credential.type,
    };
}
function toCreationOptionsJSON(options) {
    return {
        rp: options.rp,
        user: toPublicKeyCredentialUserEntityJSON(options.user),
        challenge: encodeBase64Url(options.challenge),
        pubKeyCredParams: options.pubKeyCredParams,
        timeout: options.timeout,
        excludeCredentials: options.excludeCredentials?.map(toPublicKeyCredentialDescriptorJSON),
        authenticatorSelection: options.authenticatorSelection,
        attestation: options.attestation,
        extensions: toExtensionInputsJSON(options.extensions),
    };
}
function toRequestOptionsJSON(options) {
    return {
        challenge: encodeBase64Url(options.challenge),
        timeout: options.timeout,
        rpId: options.rpId,
        allowCredentials: options.allowCredentials?.map(toPublicKeyCredentialDescriptorJSON),
        userVerification: options.userVerification,
        extensions: toExtensionInputsJSON(options.extensions),
    };
}
function parseRegistrationResponseFromJSON(options) {
    return {
        id: options.id,
        rawId: decodeBase64Url(options.rawId),
        response: {
            clientDataJSON: decodeBase64Url(options.response.clientDataJSON),
            getAuthenticatorData: () => decodeBase64Url(options.response.authenticatorData),
            getTransports: () => options.response.transports,
            getPublicKey: () => (options.response.publicKey ? decodeBase64Url(options.response.publicKey) : null),
            getPublicKeyAlgorithm: () => options.response.publicKeyAlgorithm ?? -1,
            attestationObject: decodeBase64Url(options.response.attestationObject),
        },
        authenticatorAttachment: options.authenticatorAttachment ?? null,
        getClientExtensionResults: () => parseExtensionResultsFromJSON(options.clientExtensionResults),
        toJSON: () => options,
        type: options.type,
    };
}
function parseAuthenticationResponseFromJSON(options) {
    return {
        id: options.id,
        rawId: decodeBase64Url(options.rawId),
        response: {
            clientDataJSON: decodeBase64Url(options.response.clientDataJSON),
            authenticatorData: decodeBase64Url(options.response.authenticatorData),
            signature: decodeBase64Url(options.response.signature),
            userHandle: options.response.userHandle ? decodeBase64Url(options.response.userHandle) : null,
        },
        authenticatorAttachment: options.authenticatorAttachment ?? null,
        getClientExtensionResults: () => parseExtensionResultsFromJSON(options.clientExtensionResults),
        toJSON: () => options,
        type: options.type,
    };
}
function toPublicKeyCredentialDescriptorJSON(credential) {
    return {
        id: encodeBase64Url(credential.id),
        type: credential.type,
        transports: credential.transports,
    };
}
function parsePublicKeyCredentialDescriptorFromJSON(credential) {
    return {
        id: decodeBase64Url(credential.id),
        type: credential.type,
        transports: credential.transports,
    };
}
function toPublicKeyCredentialUserEntityJSON(user) {
    return { ...user, id: encodeBase64Url(user.id) };
}
function parsePublicKeyCredentialUserEntityFromJSON(user) {
    return { ...user, id: decodeBase64Url(user.id) };
}
function parsePRFValuesFromJSON(values) {
    const parsed = { first: decodeBase64Url(values.first) };
    if (values.second !== undefined) {
        parsed.second = decodeBase64Url(values.second);
    }
    return parsed;
}
function parsePRFInputsFromJSON(prf) {
    const parsed = {};
    if (prf.eval) {
        parsed.eval = parsePRFValuesFromJSON(prf.eval);
    }
    if (prf.evalByCredential) {
        parsed.evalByCredential = Object.fromEntries(Object.entries(prf.evalByCredential).map(([credentialId, values]) => [credentialId, parsePRFValuesFromJSON(values)]));
    }
    return parsed;
}
// Decodes each supported extension's JSON-encoded inputs into their non-json form.
// Only prf needs decoding today. A future extension with encoded inputs should add code here.
function parseExtensionsFromJSON(extensionsJSON) {
    if (!extensionsJSON) {
        return undefined;
    }
    const parsed = { ...extensionsJSON };
    if (extensionsJSON.prf) {
        parsed.prf = parsePRFInputsFromJSON(extensionsJSON.prf);
    }
    return parsed;
}
// Decodes each supported extension's JSON-encoded outputs into their non-json form.
// Only prf needs decoding today. A future extension with encoded outputs should add code here.
function parseExtensionResultsFromJSON(resultsJSON) {
    const parsed = { ...resultsJSON };
    if (resultsJSON.prf?.results) {
        parsed.prf = { ...resultsJSON.prf, results: parsePRFValuesFromJSON(resultsJSON.prf.results) };
    }
    return parsed;
}
function toPRFValuesJSON(values) {
    const json = { first: encodeBase64Url(values.first) };
    if (values.second !== undefined) {
        json.second = encodeBase64Url(values.second);
    }
    return json;
}
// Encodes each supported extension's outputs into their json form.
// Only prf needs encoding today. A future extension with encoded outputs should add code here.
function toExtensionResultsJSON(results) {
    const json = { ...results };
    if (results.prf?.results) {
        json.prf = { ...results.prf, results: toPRFValuesJSON(results.prf.results) };
    }
    return json;
}
function toPRFInputsJSON(prf) {
    const json = {};
    if (prf.eval) {
        json.eval = toPRFValuesJSON(prf.eval);
    }
    if (prf.evalByCredential) {
        json.evalByCredential = Object.fromEntries(Object.entries(prf.evalByCredential).map(([credentialId, values]) => [credentialId, toPRFValuesJSON(values)]));
    }
    return json;
}
// Encodes each supported extension's inputs into their json form.
// Only prf needs encoding today. A future extension with encoded inputs should add code here.
function toExtensionInputsJSON(extensions) {
    if (!extensions) {
        return undefined;
    }
    const json = { ...extensions };
    if (extensions.prf) {
        json.prf = toPRFInputsJSON(extensions.prf);
    }
    return json;
}
// Helper functions
function encodeBase64Url(buffer) {
    const toArrayBuffer = (bufferSource) => {
        if (bufferSource instanceof ArrayBuffer) {
            return bufferSource;
        }
        return bufferSource.buffer.slice(bufferSource.byteOffset, bufferSource.byteOffset + bufferSource.byteLength);
    };
    return btoa(String.fromCharCode(...new Uint8Array(toArrayBuffer(buffer))))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "");
}
function decodeBase64Url(base64Url) {
    const base64 = base64Url
        .replace(/-/g, "+")
        .replace(/_/g, "/")
        .padEnd(base64Url.length + ((4 - (base64Url.length % 4)) % 4), "=");
    const binaryString = atob(base64);
    const byteArray = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        byteArray[i] = binaryString.charCodeAt(i);
    }
    return byteArray.buffer;
}
