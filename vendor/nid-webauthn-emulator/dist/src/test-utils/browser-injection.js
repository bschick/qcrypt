"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.HookWebAuthnApis = exports.WebAuthnEmulatorSignalCurrentUserDetails = exports.WebAuthnEmulatorSignalAllAcceptedCredentials = exports.WebAuthnEmulatorSignalUnknownCredential = exports.WebAuthnEmulatorCreate = exports.WebAuthnEmulatorGet = void 0;
const Model = __importStar(require("../webauthn/webauthn-model-json"));
exports.WebAuthnEmulatorGet = "webAuthnEmulatorGet";
exports.WebAuthnEmulatorCreate = "webAuthnEmulatorCreate";
exports.WebAuthnEmulatorSignalUnknownCredential = "webAuthnEmulatorSignalUnknownCredential";
exports.WebAuthnEmulatorSignalAllAcceptedCredentials = "webAuthnEmulatorSignalAllAcceptedCredentials";
exports.WebAuthnEmulatorSignalCurrentUserDetails = "webAuthnEmulatorSignalCurrentUserDetails";
const webAuthnModelExports = Object.values(Model)
    .map((m) => m.toString())
    .join("\n  ");
exports.HookWebAuthnApis = `
(function () {
  ${webAuthnModelExports}

  window.navigator.credentials.create = async (options) => {
    if (!options.publicKey) return undefined;
    const optionsJSON = toCreationOptionsJSON(options.publicKey);
    const responseJSON = await window.${exports.WebAuthnEmulatorCreate}(optionsJSON);
    return parseRegistrationResponseFromJSON(responseJSON);
  }

  window.navigator.credentials.get = async (options) => {
    if (!options.publicKey) return undefined;
    const optionsJSON = toRequestOptionsJSON(options.publicKey);
    const responseJSON = await window.${exports.WebAuthnEmulatorGet}(optionsJSON);
    return parseAuthenticationResponseFromJSON(responseJSON);
  }
  
  PublicKeyCredential.isConditionalMediationAvailable = async () => true;
  
  PublicKeyCredential.signalUnknownCredential = async (options) => {
    if (!options || !options.rpId || !options.credentialId) return;
    await window.${exports.WebAuthnEmulatorSignalUnknownCredential}(options);
  }

  PublicKeyCredential.signalAllAcceptedCredentials = async (options) => {
    if (!options || !options.rpId || !options.userId || !options.allAcceptedCredentialIds) return;
    await window.${exports.WebAuthnEmulatorSignalAllAcceptedCredentials}(options);
  }

  PublicKeyCredential.signalCurrentUserDetails = async (options) => {
    if (!options || !options.rpId || !options.userId) return;
    await window.${exports.WebAuthnEmulatorSignalCurrentUserDetails}(options);
  }
})();
`;
