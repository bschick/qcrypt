"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthenticationEmulatorError = exports.CREDENTIAL_MANAGEMENT_SUBCOMMAND = exports.CTAP_COMMAND = exports.CTAP_STATUS_CODE = void 0;
exports.unpackRequest = unpackRequest;
exports.packMakeCredentialRequest = packMakeCredentialRequest;
exports.packGetAssertionRequest = packGetAssertionRequest;
exports.packCredentialManagementRequest = packCredentialManagementRequest;
exports.unpackCredentialManagementRequest = unpackCredentialManagementRequest;
exports.unpackMakeCredentialResponse = unpackMakeCredentialResponse;
exports.packMakeCredentialResponse = packMakeCredentialResponse;
exports.unpackGetAssertionResponse = unpackGetAssertionResponse;
exports.packGetAssertionResponse = packGetAssertionResponse;
exports.unpackGetInfoResponse = unpackGetInfoResponse;
exports.packGetInfoResponse = packGetInfoResponse;
exports.packCredentialManagementResponse = packCredentialManagementResponse;
exports.unpackCredentialManagementResponse = unpackCredentialManagementResponse;
const encode_utils_1 = __importDefault(require("../libs/encode-utils"));
/** @see https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#error-responses */
var CTAP_STATUS_CODE;
(function (CTAP_STATUS_CODE) {
    CTAP_STATUS_CODE[CTAP_STATUS_CODE["CTAP2_OK"] = 0] = "CTAP2_OK";
    CTAP_STATUS_CODE[CTAP_STATUS_CODE["CTAP1_ERR_INVALID_COMMAND"] = 1] = "CTAP1_ERR_INVALID_COMMAND";
    CTAP_STATUS_CODE[CTAP_STATUS_CODE["CTAP1_ERR_INVALID_PARAMETER"] = 2] = "CTAP1_ERR_INVALID_PARAMETER";
    CTAP_STATUS_CODE[CTAP_STATUS_CODE["CTAP2_ERR_INVALID_CBOR"] = 18] = "CTAP2_ERR_INVALID_CBOR";
    CTAP_STATUS_CODE[CTAP_STATUS_CODE["CTAP2_ERR_CREDENTIAL_EXCLUDED"] = 25] = "CTAP2_ERR_CREDENTIAL_EXCLUDED";
    CTAP_STATUS_CODE[CTAP_STATUS_CODE["CTAP2_ERR_UNSUPPORTED_ALGORITHM"] = 38] = "CTAP2_ERR_UNSUPPORTED_ALGORITHM";
    CTAP_STATUS_CODE[CTAP_STATUS_CODE["CTAP2_ERR_OPERATION_DENIED"] = 39] = "CTAP2_ERR_OPERATION_DENIED";
    CTAP_STATUS_CODE[CTAP_STATUS_CODE["CTAP2_ERR_NO_CREDENTIALS"] = 46] = "CTAP2_ERR_NO_CREDENTIALS";
    CTAP_STATUS_CODE[CTAP_STATUS_CODE["CTAP2_ERR_NOT_ALLOWED"] = 48] = "CTAP2_ERR_NOT_ALLOWED";
})(CTAP_STATUS_CODE || (exports.CTAP_STATUS_CODE = CTAP_STATUS_CODE = {}));
/** @see https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#commands */
var CTAP_COMMAND;
(function (CTAP_COMMAND) {
    CTAP_COMMAND[CTAP_COMMAND["authenticatorMakeCredential"] = 1] = "authenticatorMakeCredential";
    CTAP_COMMAND[CTAP_COMMAND["authenticatorGetAssertion"] = 2] = "authenticatorGetAssertion";
    CTAP_COMMAND[CTAP_COMMAND["authenticatorGetInfo"] = 4] = "authenticatorGetInfo";
    CTAP_COMMAND[CTAP_COMMAND["authenticatorClientPIN"] = 6] = "authenticatorClientPIN";
    CTAP_COMMAND[CTAP_COMMAND["authenticatorReset"] = 7] = "authenticatorReset";
    CTAP_COMMAND[CTAP_COMMAND["authenticatorGetNextAssertion"] = 8] = "authenticatorGetNextAssertion";
    CTAP_COMMAND[CTAP_COMMAND["authenticatorCredentialManagement"] = 10] = "authenticatorCredentialManagement";
})(CTAP_COMMAND || (exports.CTAP_COMMAND = CTAP_COMMAND = {}));
var CREDENTIAL_MANAGEMENT_SUBCOMMAND;
(function (CREDENTIAL_MANAGEMENT_SUBCOMMAND) {
    CREDENTIAL_MANAGEMENT_SUBCOMMAND[CREDENTIAL_MANAGEMENT_SUBCOMMAND["getCredsMetadata"] = 1] = "getCredsMetadata";
    CREDENTIAL_MANAGEMENT_SUBCOMMAND[CREDENTIAL_MANAGEMENT_SUBCOMMAND["enumerateRPsBegin"] = 2] = "enumerateRPsBegin";
    CREDENTIAL_MANAGEMENT_SUBCOMMAND[CREDENTIAL_MANAGEMENT_SUBCOMMAND["enumerateRPsGetNextRP"] = 3] = "enumerateRPsGetNextRP";
    CREDENTIAL_MANAGEMENT_SUBCOMMAND[CREDENTIAL_MANAGEMENT_SUBCOMMAND["enumerateCredentialsBegin"] = 4] = "enumerateCredentialsBegin";
    CREDENTIAL_MANAGEMENT_SUBCOMMAND[CREDENTIAL_MANAGEMENT_SUBCOMMAND["enumerateCredentialsGetNextCredential"] = 5] = "enumerateCredentialsGetNextCredential";
    CREDENTIAL_MANAGEMENT_SUBCOMMAND[CREDENTIAL_MANAGEMENT_SUBCOMMAND["deleteCredential"] = 6] = "deleteCredential";
    CREDENTIAL_MANAGEMENT_SUBCOMMAND[CREDENTIAL_MANAGEMENT_SUBCOMMAND["updateUserInformation"] = 7] = "updateUserInformation";
})(CREDENTIAL_MANAGEMENT_SUBCOMMAND || (exports.CREDENTIAL_MANAGEMENT_SUBCOMMAND = CREDENTIAL_MANAGEMENT_SUBCOMMAND = {}));
// Not standard functions and interfaces
class AuthenticationEmulatorError extends Error {
    status;
    type = "CTAPError";
    constructor(status, options) {
        super(`CTAP error: ${CTAP_STATUS_CODE[status]} (${status})`, options);
        this.status = status;
    }
}
exports.AuthenticationEmulatorError = AuthenticationEmulatorError;
function unpackRequest(request) {
    let data = {};
    try {
        data = (request.data ? encode_utils_1.default.decodeCbor(request.data) : {});
    }
    catch (error) {
        throw new AuthenticationEmulatorError(CTAP_STATUS_CODE.CTAP2_ERR_INVALID_CBOR, { cause: error });
    }
    switch (request.command) {
        case CTAP_COMMAND.authenticatorMakeCredential:
            return {
                command: request.command,
                request: {
                    clientDataHash: encode_utils_1.default.bufferSourceToUint8Array(data[0x01]),
                    rp: data[0x02],
                    user: data[0x03],
                    pubKeyCredParams: data[0x04],
                    excludeList: data[0x05],
                    extensions: data[0x06],
                    options: data[0x07],
                    pinAuth: data[0x08] ? encode_utils_1.default.bufferSourceToUint8Array(data[0x08]) : undefined,
                    pinProtocol: data[0x09],
                },
            };
        case CTAP_COMMAND.authenticatorGetAssertion:
            return {
                command: request.command,
                request: {
                    rpId: data[0x01],
                    clientDataHash: encode_utils_1.default.bufferSourceToUint8Array(data[0x02]),
                    allowList: data[0x03],
                    extensions: data[0x04],
                    options: data[0x05],
                    pinAuth: data[0x06] ? encode_utils_1.default.bufferSourceToUint8Array(data[0x06]) : undefined,
                    pinProtocol: data[0x07],
                },
            };
        case CTAP_COMMAND.authenticatorCredentialManagement:
            return {
                command: request.command,
                request: {
                    subCommand: data[0x01],
                    subCommandParams: data[0x02]
                        ? {
                            credentialId: data[0x02][0x01]
                                ? encode_utils_1.default.bufferSourceToUint8Array(data[0x02][0x01])
                                : undefined,
                            rpId: data[0x02][0x02],
                            user: data[0x02][0x03],
                        }
                        : undefined,
                    pinUvAuthProtocol: data[0x03],
                    pinUvAuthParam: data[0x04] ? encode_utils_1.default.bufferSourceToUint8Array(data[0x04]) : undefined,
                },
            };
        default:
            return {
                command: request.command,
                request: undefined,
            };
    }
}
function packMakeCredentialRequest(request) {
    return {
        command: CTAP_COMMAND.authenticatorMakeCredential,
        data: encode_utils_1.default.encodeCbor({
            "1": request.clientDataHash,
            "2": request.rp,
            "3": request.user,
            "4": request.pubKeyCredParams,
            "5": request.excludeList,
            "6": request.extensions,
            "7": request.options,
            "8": request.pinAuth,
            "9": request.pinProtocol,
        }),
    };
}
function packGetAssertionRequest(request) {
    return {
        command: CTAP_COMMAND.authenticatorGetAssertion,
        data: encode_utils_1.default.encodeCbor({
            "1": request.rpId,
            "2": request.clientDataHash,
            "3": request.allowList,
            "4": request.extensions,
            "5": request.options,
            "6": request.pinAuth,
            "7": request.pinProtocol,
        }),
    };
}
function packCredentialManagementRequest(request) {
    return {
        command: CTAP_COMMAND.authenticatorCredentialManagement,
        data: encode_utils_1.default.encodeCbor({
            "1": request.subCommand,
            "2": request.subCommandParams
                ? {
                    "1": request.subCommandParams.credentialId,
                    "2": request.subCommandParams.rpId,
                    "3": request.subCommandParams.user,
                }
                : undefined,
            "3": request.pinUvAuthProtocol,
            "4": request.pinUvAuthParam,
        }),
    };
}
function unpackCredentialManagementRequest(request) {
    try {
        const data = encode_utils_1.default.decodeCbor(request.data);
        const subCommandParams = data[0x02];
        return {
            subCommand: data[0x01],
            subCommandParams: subCommandParams
                ? {
                    credentialId: subCommandParams[0x01]
                        ? encode_utils_1.default.bufferSourceToUint8Array(subCommandParams[0x01])
                        : undefined,
                    rpId: subCommandParams[0x02],
                    user: subCommandParams[0x03],
                }
                : undefined,
            pinUvAuthProtocol: data[0x03],
            pinUvAuthParam: data[0x04] ? encode_utils_1.default.bufferSourceToUint8Array(data[0x04]) : undefined,
        };
    }
    catch (error) {
        throw new AuthenticationEmulatorError(CTAP_STATUS_CODE.CTAP2_ERR_INVALID_CBOR, { cause: error });
    }
}
function unpackMakeCredentialResponse(response) {
    try {
        const data = encode_utils_1.default.decodeCbor(response.data);
        return {
            fmt: data[0x01],
            authData: encode_utils_1.default.bufferSourceToUint8Array(data[0x02]),
            attStmt: data[0x03],
        };
    }
    catch (error) {
        throw new AuthenticationEmulatorError(CTAP_STATUS_CODE.CTAP2_ERR_INVALID_CBOR, { cause: error });
    }
}
function packMakeCredentialResponse(response) {
    return {
        status: CTAP_STATUS_CODE.CTAP2_OK,
        data: encode_utils_1.default.encodeCbor({
            "1": response.fmt,
            "2": response.authData,
            "3": response.attStmt,
        }),
    };
}
function unpackGetAssertionResponse(response) {
    try {
        const data = encode_utils_1.default.decodeCbor(response.data);
        return {
            credential: data[0x01],
            authData: encode_utils_1.default.bufferSourceToUint8Array(data[0x02]),
            signature: encode_utils_1.default.bufferSourceToUint8Array(data[0x03]),
            user: data[0x04],
            numberOfCredentials: data[0x05],
        };
    }
    catch (error) {
        throw new AuthenticationEmulatorError(CTAP_STATUS_CODE.CTAP2_ERR_INVALID_CBOR, { cause: error });
    }
}
function packGetAssertionResponse(response) {
    return {
        status: CTAP_STATUS_CODE.CTAP2_OK,
        data: encode_utils_1.default.encodeCbor({
            "1": response.credential,
            "2": response.authData,
            "3": response.signature,
            "4": response.user,
            "5": response.numberOfCredentials,
        }),
    };
}
function unpackGetInfoResponse(response) {
    try {
        const data = encode_utils_1.default.decodeCbor(response.data);
        return {
            versions: data[0x01],
            extensions: data[0x02],
            aaguid: encode_utils_1.default.bufferSourceToUint8Array(data[0x03]),
            options: data[0x04],
            maxMsgSize: data[0x05],
            pinProtocols: data[0x06],
        };
    }
    catch (error) {
        throw new AuthenticationEmulatorError(CTAP_STATUS_CODE.CTAP2_ERR_INVALID_CBOR, { cause: error });
    }
}
function packGetInfoResponse(response) {
    return {
        status: CTAP_STATUS_CODE.CTAP2_OK,
        data: encode_utils_1.default.encodeCbor({
            "1": response.versions,
            "2": response.extensions,
            "3": response.aaguid,
            "4": response.options,
            "5": response.maxMsgSize,
            "6": response.pinProtocols,
        }),
    };
}
function packCredentialManagementResponse(response) {
    return {
        status: CTAP_STATUS_CODE.CTAP2_OK,
        data: encode_utils_1.default.encodeCbor({
            "1": response.existingResidentCredentialsCount,
            "2": response.maxPossibleRemainingResidentCredentialsCount,
            "3": response.rp,
            "4": response.rpIDHash,
            "5": response.totalRPs,
            "6": response.user,
            "7": response.credentialID,
            "8": response.publicKey,
            "9": response.totalCredentials,
            "10": response.credProtect,
            "11": response.largeBlobKey,
        }),
    };
}
function unpackCredentialManagementResponse(response) {
    try {
        const data = encode_utils_1.default.decodeCbor(response.data);
        return {
            existingResidentCredentialsCount: data[0x01],
            maxPossibleRemainingResidentCredentialsCount: data[0x02],
            rp: data[0x03],
            rpIDHash: data[0x04] ? encode_utils_1.default.bufferSourceToUint8Array(data[0x04]) : undefined,
            totalRPs: data[0x05],
            user: data[0x06],
            credentialID: data[0x07] ? encode_utils_1.default.bufferSourceToUint8Array(data[0x07]) : undefined,
            publicKey: data[0x08] ? encode_utils_1.default.bufferSourceToUint8Array(data[0x08]) : undefined,
            totalCredentials: data[0x09],
            credProtect: data[0x0a],
            largeBlobKey: data[0x0b] ? encode_utils_1.default.bufferSourceToUint8Array(data[0x0b]) : undefined,
        };
    }
    catch (error) {
        throw new AuthenticationEmulatorError(CTAP_STATUS_CODE.CTAP2_ERR_INVALID_CBOR, { cause: error });
    }
}
