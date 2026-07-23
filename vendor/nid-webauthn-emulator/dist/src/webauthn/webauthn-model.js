"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.RpId = void 0;
exports.packAttestationObject = packAttestationObject;
exports.packAuthenticatorData = packAuthenticatorData;
exports.unpackAttestationObject = unpackAttestationObject;
exports.unpackAuthenticatorData = unpackAuthenticatorData;
exports.toPublickeyCredentialSourceJSON = toPublickeyCredentialSourceJSON;
exports.parsePublicKeyCredentialSourceFromJSON = parsePublicKeyCredentialSourceFromJSON;
exports.toFido2CreateOptions = toFido2CreateOptions;
exports.toFido2RequestOptions = toFido2RequestOptions;
const node_crypto_1 = require("node:crypto");
const tldts_1 = require("tldts");
const encode_utils_1 = __importDefault(require("../libs/encode-utils"));
const cose_key_1 = require("./cose-key");
class RpId {
    value;
    constructor(value) {
        this.value = value;
    }
    get hash() {
        return new Uint8Array((0, node_crypto_1.createHash)("sha256").update(this.value).digest());
    }
    /** @see https://www.w3.org/TR/webauthn-3/#sctn-validating-origin */
    validate(origin, relatedOrigins = []) {
        const parsedOrigin = (0, tldts_1.parse)(origin, { validHosts: ["localhost"] });
        const expectedOrigins = [this.value, ...relatedOrigins];
        // Check each origin using standard validation
        for (const expectedOrigin of expectedOrigins) {
            const parsedExpectedOrigin = (0, tldts_1.parse)(expectedOrigin, { validHosts: ["localhost"] });
            const isValid = Boolean(parsedOrigin.domain &&
                parsedOrigin.subdomain !== null &&
                parsedExpectedOrigin.subdomain !== null &&
                parsedOrigin.domain === parsedExpectedOrigin.domain &&
                parsedOrigin.subdomain.endsWith(parsedExpectedOrigin.subdomain));
            if (isValid) {
                return true;
            }
        }
        return false;
    }
}
exports.RpId = RpId;
function packAttestationObject(attestationObject) {
    return encode_utils_1.default.encodeCbor({
        fmt: attestationObject.fmt,
        attStmt: attestationObject.attStmt,
        authData: packAuthenticatorData(attestationObject.authData),
    });
}
function packAuthenticatorData(authData) {
    const ret = [];
    const cred = authData.attestedCredentialData;
    const extensions = authData.extensions && Object.keys(authData.extensions).length > 0 ? authData.extensions : undefined;
    ret.push(...authData.rpIdHash);
    ret.push(packAuthenticatorDataFlags({
        ...authData.flags,
        attestedCredentialData: Boolean(cred),
        extensionData: Boolean(extensions),
    }));
    ret.push(...packSignCount(authData.signCount));
    if (cred)
        ret.push(...packAttestedCredentialData(cred));
    if (extensions)
        ret.push(...encode_utils_1.default.encodeCbor(extensions));
    return new Uint8Array(ret);
}
function packSignCount(signCount) {
    const ret = new ArrayBuffer(4);
    const view = new DataView(ret);
    view.setUint32(0, signCount, false);
    return new Uint8Array(ret);
}
function packAttestedCredentialData(attestedCredentialData) {
    const ret = [];
    const rawId = attestedCredentialData.credentialId;
    const credentialIdLength = [rawId.length >> 8, rawId.length & 0xff];
    ret.push(...attestedCredentialData.aaguid);
    ret.push(...credentialIdLength);
    ret.push(...rawId);
    ret.push(...attestedCredentialData.credentialPublicKey.toBytes());
    return new Uint8Array(ret);
}
function packAuthenticatorDataFlags(flags) {
    return ((flags.userPresent ? 1 << 0 : 0) |
        (flags.userVerified ? 1 << 2 : 0) |
        (flags.backupEligibility ? 1 << 3 : 0) |
        (flags.backupState ? 1 << 4 : 0) |
        (flags.attestedCredentialData ? 1 << 6 : 0) |
        (flags.extensionData ? 1 << 7 : 0));
}
function unpackAttestationObject(attestationObject) {
    const { fmt, attStmt, authData } = encode_utils_1.default.decodeCbor(attestationObject);
    return {
        fmt,
        attStmt,
        authData: unpackAuthenticatorData(authData),
    };
}
function unpackAuthenticatorData(authData) {
    const rpIdHash = authData.slice(0, 32);
    const flags = unpackAuthenticatorDataFlags(authData[32]);
    const signCount = (authData[33] << 24) | (authData[34] << 16) | (authData[35] << 8) | authData[36];
    let offset = 37;
    let attestedCredentialData;
    if (flags.attestedCredentialData) {
        const unpacked = unpackAttestedCredentialData(authData.slice(offset));
        attestedCredentialData = unpacked.attestedCredentialData;
        offset += unpacked.length;
    }
    let extensions;
    if (flags.extensionData) {
        extensions = encode_utils_1.default.decodeCbor(authData.slice(offset));
    }
    return { rpIdHash, flags, signCount, attestedCredentialData, extensions };
}
function unpackAttestedCredentialData(data) {
    const aaguid = data.slice(0, 16);
    const credentialIdLength = (data[16] << 8) | data[17];
    const credentialId = data.slice(18, 18 + credentialIdLength);
    const { value, remainder } = encode_utils_1.default.decodeCborWithRemainder(data.slice(18 + credentialIdLength));
    const credentialPublicKey = cose_key_1.CoseKey.fromDecoded(value);
    return {
        attestedCredentialData: { aaguid, credentialId, credentialPublicKey },
        length: data.length - remainder.length,
    };
}
function unpackAuthenticatorDataFlags(flags) {
    return {
        userPresent: Boolean(flags & (1 << 0)),
        userVerified: Boolean(flags & (1 << 2)),
        backupEligibility: Boolean(flags & (1 << 3)),
        backupState: Boolean(flags & (1 << 4)),
        attestedCredentialData: Boolean(flags & (1 << 6)),
        extensionData: Boolean(flags & (1 << 7)),
    };
}
function toPublickeyCredentialSourceJSON(credentialSource) {
    return {
        type: "public-key",
        id: encode_utils_1.default.encodeBase64Url(credentialSource.id),
        privateKey: encode_utils_1.default.encodeBase64Url(credentialSource.privateKey),
        rpId: credentialSource.rpId.value,
        userHandle: credentialSource.userHandle ? encode_utils_1.default.encodeBase64Url(credentialSource.userHandle) : undefined,
        credRandom: credentialSource.credRandom ? encode_utils_1.default.encodeBase64Url(credentialSource.credRandom) : undefined,
    };
}
function parsePublicKeyCredentialSourceFromJSON(json) {
    return {
        type: "public-key",
        id: encode_utils_1.default.decodeBase64Url(json.id),
        privateKey: encode_utils_1.default.decodeBase64Url(json.privateKey),
        rpId: new RpId(json.rpId),
        userHandle: json.userHandle ? encode_utils_1.default.decodeBase64Url(json.userHandle) : undefined,
        credRandom: json.credRandom ? encode_utils_1.default.decodeBase64Url(json.credRandom) : undefined,
    };
}
/** @see https://www.w3.org/TR/webauthn-3/#CreateCred-async-loop */
function toFido2CreateOptions(criteria) {
    let requireResidentKey = false;
    let userVerification = false;
    if (criteria) {
        if (criteria.residentKey) {
            if (criteria.residentKey === "required") {
                requireResidentKey = true;
            }
            else if (criteria.residentKey === "preferred") {
                requireResidentKey = true;
            }
            else if (criteria.residentKey === "discouraged") {
                requireResidentKey = false;
            }
        }
        else {
            requireResidentKey = !!criteria.requireResidentKey;
        }
        if (criteria.userVerification === "required") {
            userVerification = true;
        }
        else if (criteria.userVerification === "preferred") {
            userVerification = true;
        }
        else if (criteria.userVerification === "discouraged") {
            userVerification = false;
        }
    }
    return {
        rk: requireResidentKey,
        uv: userVerification,
        up: true,
    };
}
/** @see https://www.w3.org/TR/webauthn-3/#sctn-issuing-cred-request-to-authenticator */
function toFido2RequestOptions(require) {
    let userVerification;
    if (require === "required") {
        userVerification = true;
    }
    else if (require === "preferred") {
        userVerification = true;
    }
    else if (require === "discouraged") {
        userVerification = false;
    }
    else {
        userVerification = false;
    }
    return {
        uv: userVerification,
        up: true,
    };
}
