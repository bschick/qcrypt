"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createPasskeysEmulator = void 0;
const authenticator_emulator_1 = require("../authenticator/authenticator-emulator");
const webauthn_emulator_1 = require("../webauthn/webauthn-emulator");
const webauthn_model_json_1 = require("../webauthn/webauthn-model-json");
const createInteraction = (exception) => exception
    ? () => {
        throw new DOMException("test", exception);
    }
    : undefined;
const addTestPasskey = (emulator, origin, userId, rpId = "localhost") => {
    const creationOption = {
        challenge: "EA3d-yrkJAfNWICZ7It5ErO0XngxTe32L0t8IjEj9r8",
        rp: { name: "Test RP", id: rpId },
        user: {
            id: (0, webauthn_model_json_1.encodeBase64Url)(Buffer.from(userId)),
            name: "test",
            displayName: "",
        },
        pubKeyCredParams: [
            { alg: -8, type: "public-key" },
            { alg: -7, type: "public-key" },
            { alg: -257, type: "public-key" },
        ],
    };
    return emulator.createJSON(origin, creationOption);
};
const createPasskeysEmulator = (params) => {
    const authenticator = new authenticator_emulator_1.AuthenticatorEmulator({
        userMakeCredentialInteraction: createInteraction(params?.creationException),
        userGetAssertionInteraction: createInteraction(params?.requestException),
    });
    const instance = new webauthn_emulator_1.WebAuthnEmulator(authenticator);
    const origin = params?.origin ?? "http://localhost";
    const publicKeyCredentials = {
        isConditionalMediationAvailable: async () => Promise.resolve(params?.autofill ?? true),
        signalUnknownCredential: async (options) => instance.signalUnknownCredential(options),
        signalAllAcceptedCredentials: async (options) => instance.signalAllAcceptedCredentials(options),
        signalCurrentUserDetails: async (options) => instance.signalCurrentUserDetails(options),
        getClientCapabilities: async () => ({ conditionalGet: true }),
        isUserVerifyingPlatformAuthenticatorAvailable: async () => true,
        parseCreationOptionsFromJSON: webauthn_model_json_1.parseCreationOptionsFromJSON,
        parseRequestOptionsFromJSON: webauthn_model_json_1.parseRequestOptionsFromJSON,
    };
    const credentialsContainer = {
        get: async (options) => instance.get(origin, options ?? {}),
        create: async (options) => instance.create(origin, options ?? {}),
    };
    const addPasskey = (userId) => addTestPasskey(instance, origin, userId, params?.rpId);
    return {
        instance,
        addPasskey,
        methods: {
            credentialsContainer,
            publicKeyCredentials,
        },
    };
};
exports.createPasskeysEmulator = createPasskeysEmulator;
