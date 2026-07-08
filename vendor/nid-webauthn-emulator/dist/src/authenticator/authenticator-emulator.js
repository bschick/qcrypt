"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthenticatorEmulator = exports.COSEAlgorithmIdentifier = void 0;
const node_crypto_1 = require("node:crypto");
const encode_utils_1 = __importDefault(require("../libs/encode-utils"));
const credentials_memory_repository_1 = require("../repository/credentials-memory-repository");
const cose_key_1 = require("../webauthn/cose-key");
const webauthn_model_1 = require("../webauthn/webauthn-model");
const ctap_model_1 = require("./ctap-model");
exports.COSEAlgorithmIdentifier = {
    ES256: -7,
    RS256: -257,
    EdDSA: -8,
};
const HMAC_SECRET_SALT_LENGTH = 32;
const CRED_RANDOM_LENGTH = 32;
/**
 * Authenticator emulator
 */
class AuthenticatorEmulator {
    static ENCRYPT_KEY = encode_utils_1.default.strToUint8Array("NID-AUTH-31415926535897932384626");
    /** Authenticator Attestation Global Unique Identifier (16byte)  */
    static DEFAULT_AAGUID = encode_utils_1.default.strToUint8Array("NID-AUTH-3141592");
    static DEFAULT_TRANSPORTS = ["usb"];
    static DEFAULT_ALGORITHM_IDENTIFIERS = ["ES256", "RS256", "EdDSA"];
    static DEFAULT_SIGN_COUNTER_INCREMENT = 1;
    static DEFAULT_VERIFICATIONS = { userPresent: true, userVerified: true };
    static DEFAULT_MAKE_CREDENTIAL_INTERACTION = (user) => ({
        user: user,
        options: { uv: true, up: true },
    });
    static DEFAULT_GET_ASSERTION_INTERACTION = (user) => ({
        user: user,
        options: { uv: true, up: true },
    });
    static DEFAULT_CREDENTIALS_REPOSITORY = new credentials_memory_repository_1.PasskeysCredentialsMemoryRepository();
    static DEFAULT_STATELESS = false;
    static DEFAULT_HMAC_SECRET = "none";
    params;
    constructor(params = {}) {
        this.params = {
            aaguid: params.aaguid ?? AuthenticatorEmulator.DEFAULT_AAGUID,
            transports: params.transports ?? AuthenticatorEmulator.DEFAULT_TRANSPORTS,
            algorithmIdentifiers: params.algorithmIdentifiers ?? AuthenticatorEmulator.DEFAULT_ALGORITHM_IDENTIFIERS,
            signCounterIncrement: params.stateless
                ? 0
                : (params.signCounterIncrement ?? AuthenticatorEmulator.DEFAULT_SIGN_COUNTER_INCREMENT),
            verifications: params.verifications ?? AuthenticatorEmulator.DEFAULT_VERIFICATIONS,
            userMakeCredentialInteraction: params.userMakeCredentialInteraction ?? AuthenticatorEmulator.DEFAULT_MAKE_CREDENTIAL_INTERACTION,
            userGetAssertionInteraction: params.userGetAssertionInteraction ?? AuthenticatorEmulator.DEFAULT_GET_ASSERTION_INTERACTION,
            credentialsRepository: params.stateless
                ? undefined
                : (params.credentialsRepository ?? AuthenticatorEmulator.DEFAULT_CREDENTIALS_REPOSITORY),
            stateless: params.stateless ?? AuthenticatorEmulator.DEFAULT_STATELESS,
            hmacSecret: params.hmacSecret ?? AuthenticatorEmulator.DEFAULT_HMAC_SECRET,
        };
    }
    /** @see https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticator-api */
    command(request) {
        const unpackedRequest = (0, ctap_model_1.unpackRequest)(request);
        if (unpackedRequest.command === ctap_model_1.CTAP_COMMAND.authenticatorMakeCredential) {
            const makeCredentialRequest = unpackedRequest.request;
            const makeCredentialResponse = this.authenticatorMakeCredential(makeCredentialRequest);
            return (0, ctap_model_1.packMakeCredentialResponse)(makeCredentialResponse);
        }
        if (unpackedRequest.command === ctap_model_1.CTAP_COMMAND.authenticatorGetAssertion) {
            const getAssertionRequest = unpackedRequest.request;
            const getAssertionResponse = this.authenticatorGetAssertion(getAssertionRequest);
            return (0, ctap_model_1.packGetAssertionResponse)(getAssertionResponse);
        }
        if (unpackedRequest.command === ctap_model_1.CTAP_COMMAND.authenticatorGetInfo) {
            return (0, ctap_model_1.packGetInfoResponse)(this.authenticatorGetInfo());
        }
        if (unpackedRequest.command === ctap_model_1.CTAP_COMMAND.authenticatorCredentialManagement) {
            const credentialManagementRequest = (0, ctap_model_1.unpackCredentialManagementRequest)(request);
            const credentialManagementResponse = this.authenticatorCredentialManagement(credentialManagementRequest);
            return (0, ctap_model_1.packCredentialManagementResponse)(credentialManagementResponse);
        }
        throw new ctap_model_1.AuthenticationEmulatorError(ctap_model_1.CTAP_STATUS_CODE.CTAP1_ERR_INVALID_COMMAND);
    }
    /**
     * @see https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorCredentialManagement
     */
    authenticatorCredentialManagement(request) {
        const repository = this.params.credentialsRepository;
        if (!repository) {
            throw new ctap_model_1.AuthenticationEmulatorError(ctap_model_1.CTAP_STATUS_CODE.CTAP2_ERR_NOT_ALLOWED);
        }
        switch (request.subCommand) {
            case ctap_model_1.CREDENTIAL_MANAGEMENT_SUBCOMMAND.deleteCredential:
                return this.authenticatorDeleteCredential(request);
            case ctap_model_1.CREDENTIAL_MANAGEMENT_SUBCOMMAND.enumerateCredentialsBegin:
                return this.authenticatorEnumerateCredentialsBegin(request);
            case ctap_model_1.CREDENTIAL_MANAGEMENT_SUBCOMMAND.enumerateCredentialsGetNextCredential:
                return this.authenticatorEnumerateCredentialsGetNextCredential();
            case ctap_model_1.CREDENTIAL_MANAGEMENT_SUBCOMMAND.updateUserInformation:
                return this.authenticatorUpdateUserInformation(request);
            default:
                throw new ctap_model_1.AuthenticationEmulatorError(ctap_model_1.CTAP_STATUS_CODE.CTAP1_ERR_INVALID_COMMAND);
        }
    }
    // Store the current enumeration state
    enumerationState = null;
    authenticatorEnumerateCredentialsBegin(request) {
        const repository = this.params.credentialsRepository;
        if (!repository) {
            throw new ctap_model_1.AuthenticationEmulatorError(ctap_model_1.CTAP_STATUS_CODE.CTAP2_ERR_NOT_ALLOWED);
        }
        const rpId = request.subCommandParams?.rpId;
        if (!rpId) {
            throw new ctap_model_1.AuthenticationEmulatorError(ctap_model_1.CTAP_STATUS_CODE.CTAP1_ERR_INVALID_PARAMETER);
        }
        // Get all credentials for the RP
        const allCredentials = repository.loadCredentials();
        const rpCredentials = allCredentials.filter((cred) => cred.publicKeyCredentialSource.rpId.value === rpId);
        // Store the enumeration state
        this.enumerationState = {
            rpId,
            credentials: rpCredentials,
            currentIndex: 0,
        };
        return {
            totalCredentials: rpCredentials.length,
        };
    }
    authenticatorEnumerateCredentialsGetNextCredential() {
        if (!this.enumerationState || this.enumerationState.currentIndex >= this.enumerationState.credentials.length) {
            throw new ctap_model_1.AuthenticationEmulatorError(ctap_model_1.CTAP_STATUS_CODE.CTAP2_ERR_NO_CREDENTIALS);
        }
        const credential = this.enumerationState.credentials[this.enumerationState.currentIndex++];
        return {
            user: credential.user,
            credentialID: encode_utils_1.default.bufferSourceToUint8Array(credential.publicKeyCredentialDescriptor.id),
            publicKey: credential.authenticatorData.attestedCredentialData?.credentialPublicKey.toDer(),
        };
    }
    authenticatorUpdateUserInformation(request) {
        const repository = this.params.credentialsRepository;
        if (!repository) {
            throw new ctap_model_1.AuthenticationEmulatorError(ctap_model_1.CTAP_STATUS_CODE.CTAP2_ERR_NOT_ALLOWED);
        }
        const rpId = request.subCommandParams?.rpId;
        const user = request.subCommandParams?.user;
        if (!rpId || !user) {
            throw new ctap_model_1.AuthenticationEmulatorError(ctap_model_1.CTAP_STATUS_CODE.CTAP1_ERR_INVALID_PARAMETER);
        }
        // Find all credentials for this user and RP
        const allCredentials = repository.loadCredentials();
        const userCredentials = allCredentials.filter((cred) => cred.publicKeyCredentialSource.rpId.value === rpId &&
            encode_utils_1.default.encodeBase64Url(cred.user.id) === encode_utils_1.default.encodeBase64Url(user.id));
        if (userCredentials.length === 0) {
            throw new ctap_model_1.AuthenticationEmulatorError(ctap_model_1.CTAP_STATUS_CODE.CTAP2_ERR_NO_CREDENTIALS);
        }
        // Update user information for all matching credentials
        for (const credential of userCredentials) {
            const updatedCredential = {
                ...credential,
                user: {
                    ...user,
                    id: user.id, // Keep the same ID
                },
            };
            repository.deleteCredential(credential);
            repository.saveCredential(updatedCredential);
        }
        return {};
    }
    authenticatorDeleteCredential(request) {
        const repository = this.params.credentialsRepository;
        if (!repository) {
            throw new ctap_model_1.AuthenticationEmulatorError(ctap_model_1.CTAP_STATUS_CODE.CTAP2_ERR_NOT_ALLOWED);
        }
        if (!request.subCommandParams?.credentialId) {
            throw new ctap_model_1.AuthenticationEmulatorError(ctap_model_1.CTAP_STATUS_CODE.CTAP1_ERR_INVALID_PARAMETER);
        }
        const credentialId = request.subCommandParams.credentialId;
        const credentials = repository.loadCredentials();
        const credential = credentials.find((cred) => encode_utils_1.default.encodeBase64Url(cred.publicKeyCredentialSource.id) === encode_utils_1.default.encodeBase64Url(credentialId));
        if (!credential) {
            throw new ctap_model_1.AuthenticationEmulatorError(ctap_model_1.CTAP_STATUS_CODE.CTAP2_ERR_NO_CREDENTIALS);
        }
        repository.deleteCredential(credential);
        return {
            existingResidentCredentialsCount: repository.loadCredentials().length,
        };
    }
    /** @see https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorGetInfo */
    authenticatorGetInfo() {
        const extensions = [];
        if (this.params.hmacSecret !== "none") {
            extensions.push("hmac-secret");
        }
        if (this.params.hmacSecret === "hmac-secret-mc") {
            extensions.push("hmac-secret-mc");
        }
        return {
            versions: ["FIDO_2_0"],
            extensions: extensions.length > 0 ? extensions : undefined,
            aaguid: this.params.aaguid,
            options: {
                rk: true,
                uv: this.params.verifications.userVerified,
                up: this.params.verifications.userPresent,
            },
        };
    }
    /**
     * @see https://www.w3.org/TR/webauthn/#sctn-op-make-cred
     * @see https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorMakeCredential
     **/
    authenticatorMakeCredential(request) {
        const rpId = new webauthn_model_1.RpId(request.rp.id);
        const repository = this.params.credentialsRepository;
        // Exclude list
        if (request.excludeList && request.excludeList.length > 0 && repository) {
            const existingCredentials = getCredentials(rpId, request.excludeList, repository);
            if (existingCredentials.length > 0) {
                throw new ctap_model_1.AuthenticationEmulatorError(ctap_model_1.CTAP_STATUS_CODE.CTAP2_ERR_CREDENTIAL_EXCLUDED);
            }
        }
        // Algorithm selection
        const allowAlgSet = new Set(request.pubKeyCredParams.map((param) => param.alg));
        const alg = this.params.algorithmIdentifiers.find((alg) => allowAlgSet.has(exports.COSEAlgorithmIdentifier[alg]));
        if (!alg)
            throw new ctap_model_1.AuthenticationEmulatorError(ctap_model_1.CTAP_STATUS_CODE.CTAP2_ERR_UNSUPPORTED_ALGORITHM);
        // User operation
        const interactionResponse = this.params.userMakeCredentialInteraction(request.user, request.options);
        if (!interactionResponse)
            throw new ctap_model_1.AuthenticationEmulatorError(ctap_model_1.CTAP_STATUS_CODE.CTAP2_ERR_OPERATION_DENIED);
        // Create credential
        const hmacSecret = request.extensions
            ? makeCredentialHmacSecret(this.params.hmacSecret, request.extensions)
            : undefined;
        const extensions = { ...hmacSecret?.extension };
        const credential = makeCredential(this.params.aaguid, rpId, alg, this.params.transports, interactionResponse, request.user, repository ? undefined : AuthenticatorEmulator.ENCRYPT_KEY, hmacSecret?.credRandom, extensions);
        if (repository) {
            const discoverableCredential = {
                ...credential,
                user: request.user,
            };
            saveCredential(discoverableCredential, repository);
        }
        return {
            fmt: "none",
            authData: (0, webauthn_model_1.packAuthenticatorData)(credential.authenticatorData),
            attStmt: {},
        };
    }
    /**
     * @see https://www.w3.org/TR/webauthn/#sctn-op-get-assertion
     * @see https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorGetAssertion
     **/
    authenticatorGetAssertion(request) {
        const rpId = new webauthn_model_1.RpId(request.rpId);
        const repository = this.params.credentialsRepository;
        const allowList = request.allowList ?? [];
        // Allow list
        const credentials = repository
            ? getCredentials(rpId, allowList, repository)
            : getCredentialsStateless(rpId, allowList, AuthenticatorEmulator.ENCRYPT_KEY);
        if (credentials.length === 0)
            throw new ctap_model_1.AuthenticationEmulatorError(ctap_model_1.CTAP_STATUS_CODE.CTAP2_ERR_NO_CREDENTIALS);
        const credential = credentials[credentials.length - 1];
        // User operation
        const interactionResponse = this.params.userGetAssertionInteraction(credential.user, request.options);
        if (!interactionResponse)
            throw new ctap_model_1.AuthenticationEmulatorError(ctap_model_1.CTAP_STATUS_CODE.CTAP2_ERR_OPERATION_DENIED);
        // Get assertion
        const newSignCount = !repository ? 0 : credential.authenticatorData.signCount + this.params.signCounterIncrement;
        const hmacSecret = request.extensions
            ? getAssertionHmacSecret(this.params.hmacSecret, request.extensions, credential.publicKeyCredentialSource.credRandom)
            : undefined;
        const extensions = { ...hmacSecret };
        const { authData, signature } = getAssertion(rpId.hash, request.clientDataHash, newSignCount, credential.publicKeyCredentialSource, interactionResponse, !repository, extensions);
        // Update sign count
        if (repository && credential.user) {
            const updatedCredential = {
                ...credential,
                authenticatorData: {
                    ...credential.authenticatorData,
                    signCount: newSignCount,
                },
                user: credential.user,
            };
            saveCredential(updatedCredential, repository);
        }
        return {
            credential: request.allowList?.length === 1 ? undefined : credential.publicKeyCredentialDescriptor,
            authData,
            signature,
            user: credential.user,
            numberOfCredentials: credentials.length,
        };
    }
}
exports.AuthenticatorEmulator = AuthenticatorEmulator;
function getCredentialsStateless(rpId, allowCredentials, key) {
    return allowCredentials.map((descriptor) => {
        const id = encode_utils_1.default.bufferSourceToUint8Array(descriptor.id);
        const { privateKey, credRandom } = encode_utils_1.default.decodeCbor(decryptBytes(key, id));
        const publicKeyCredentialSource = {
            type: "public-key",
            id,
            privateKey,
            rpId: rpId,
            credRandom,
        };
        const authData = {
            rpIdHash: rpId.hash,
            flags: {
                backupEligibility: false,
                backupState: false,
                userPresent: true,
                userVerified: true,
                attestedCredentialData: false,
                extensionData: false,
            },
            signCount: 0,
        };
        return {
            publicKeyCredentialDescriptor: descriptor,
            publicKeyCredentialSource,
            authenticatorData: authData,
            user: undefined,
        };
    });
}
function getCredentials(rpId, credentialsFilter, repository) {
    const allowIds = new Set(credentialsFilter.map((descriptor) => encode_utils_1.default.encodeBase64Url(descriptor.id)));
    const credentials = repository.loadCredentials();
    return credentials.filter((credential) => {
        if (rpId.value !== credential.publicKeyCredentialSource.rpId.value)
            return false;
        if (credentialsFilter.length > 0) {
            const rawId = credential.publicKeyCredentialDescriptor.id;
            if (!allowIds?.has(encode_utils_1.default.encodeBase64Url(rawId)))
                return false;
        }
        return true;
    });
}
function saveCredential(credential, repository) {
    const credentials = repository.loadCredentials();
    const index = credentials.findIndex((c) => {
        if (c.publicKeyCredentialSource.rpId.value !== credential.publicKeyCredentialSource.rpId.value)
            return false;
        return encode_utils_1.default.encodeBase64Url(c.user.id) === encode_utils_1.default.encodeBase64Url(credential.user.id);
    });
    if (index >= 0) {
        repository.deleteCredential(credentials[index]);
    }
    repository.saveCredential(credential);
}
function getAssertion(rpIdHash, clientDataHash, newSignCounter, credential, interactionResponse, stateless, extensions) {
    const authenticatorData = {
        rpIdHash,
        flags: {
            userPresent: interactionResponse.options.up,
            userVerified: interactionResponse.options.uv,
            backupEligibility: !stateless,
            backupState: !stateless,
            attestedCredentialData: false,
            extensionData: Boolean(extensions),
        },
        signCount: newSignCounter,
        extensions,
    };
    const payload = [];
    payload.push(...(0, webauthn_model_1.packAuthenticatorData)(authenticatorData));
    payload.push(...clientDataHash);
    const privateKey = (0, node_crypto_1.createPrivateKey)({
        format: "der",
        type: "pkcs8",
        key: credential.privateKey,
    });
    const signature = encode_utils_1.default.bufferSourceToUint8Array(new Uint8Array((0, node_crypto_1.sign)(null, new Uint8Array(payload), privateKey)));
    return { authData: (0, webauthn_model_1.packAuthenticatorData)(authenticatorData), signature };
}
function computeHmacSecrets(credRandom, salts) {
    if (!(salts instanceof Uint8Array) ||
        (salts.length !== HMAC_SECRET_SALT_LENGTH && salts.length !== 2 * HMAC_SECRET_SALT_LENGTH)) {
        throw new ctap_model_1.AuthenticationEmulatorError(ctap_model_1.CTAP_STATUS_CODE.CTAP1_ERR_INVALID_PARAMETER);
    }
    const outputs = new Uint8Array(salts.length);
    for (let offset = 0; offset < salts.length; offset += HMAC_SECRET_SALT_LENGTH) {
        const salt = salts.subarray(offset, offset + HMAC_SECRET_SALT_LENGTH);
        outputs.set((0, node_crypto_1.createHmac)("sha256", credRandom).update(salt).digest(), offset);
    }
    return outputs;
}
function makeCredentialHmacSecret(mode, extensions) {
    const requested = extensions;
    const enabled = requested["hmac-secret"] === true;
    const salts = requested["hmac-secret-mc"];
    if (!enabled || mode === "none") {
        return undefined;
    }
    const credRandom = new Uint8Array((0, node_crypto_1.randomBytes)(CRED_RANDOM_LENGTH));
    if (salts === undefined || mode !== "hmac-secret-mc") {
        return { credRandom, extension: { "hmac-secret": true } };
    }
    return { credRandom, extension: { "hmac-secret": computeHmacSecrets(credRandom, salts) } };
}
function getAssertionHmacSecret(mode, extensions, credRandom) {
    const requested = extensions;
    const salts = requested["hmac-secret"];
    if (salts === undefined || mode === "none") {
        return undefined;
    }
    if (!credRandom) {
        return undefined;
    }
    return { "hmac-secret": computeHmacSecrets(credRandom, salts) };
}
function makeCredential(aaguid, rpId, alg, transports, interactionResponse, user, statelessKey, credRandom, extensions) {
    const generatekeyPair = (alg) => {
        if (alg === "RS256")
            return (0, node_crypto_1.generateKeyPairSync)("rsa", { modulusLength: 2048 });
        if (alg === "EdDSA")
            return (0, node_crypto_1.generateKeyPairSync)("ed25519");
        return (0, node_crypto_1.generateKeyPairSync)("ec", { namedCurve: "P-256" });
    };
    const keyPair = generatekeyPair(alg);
    const privateKey = new Uint8Array(keyPair.privateKey.export({ format: "der", type: "pkcs8" }));
    const credentialId = statelessKey
        ? encryptBytes(statelessKey, encode_utils_1.default.encodeCbor(credRandom ? { privateKey, credRandom } : { privateKey }))
        : new Uint8Array((0, node_crypto_1.randomBytes)(32));
    const publicKeyCredentialSource = {
        type: "public-key",
        id: credentialId,
        privateKey: new Uint8Array(keyPair.privateKey.export({ format: "der", type: "pkcs8" })),
        rpId: rpId,
        userHandle: user && !statelessKey ? encode_utils_1.default.bufferSourceToUint8Array(user.id) : undefined,
        credRandom,
    };
    const publicKeyCredentialDescriptor = {
        type: "public-key",
        id: credentialId,
        transports,
    };
    const authenticatorData = {
        rpIdHash: rpId.hash,
        flags: {
            backupEligibility: !statelessKey,
            backupState: !statelessKey,
            userPresent: interactionResponse.options.up,
            userVerified: interactionResponse.options.uv,
            attestedCredentialData: true,
            extensionData: Boolean(extensions),
        },
        signCount: 0,
        attestedCredentialData: {
            aaguid,
            credentialId,
            credentialPublicKey: cose_key_1.CoseKey.fromKeyObject(keyPair.publicKey),
        },
        extensions,
    };
    return {
        publicKeyCredentialDescriptor,
        publicKeyCredentialSource,
        authenticatorData,
        user,
    };
}
function encryptBytes(key, data) {
    const iv = (0, node_crypto_1.randomBytes)(16);
    const cipher = (0, node_crypto_1.createCipheriv)("aes-256-ctr", key, iv);
    const encrypted = cipher.update(data);
    return Buffer.concat([iv, encrypted, cipher.final()]);
}
function decryptBytes(key, data) {
    const iv = data.slice(0, 16);
    const encrypted = data.slice(16);
    const cipher = (0, node_crypto_1.createCipheriv)("aes-256-ctr", key, iv);
    return Buffer.concat([cipher.update(encrypted), cipher.final()]);
}
