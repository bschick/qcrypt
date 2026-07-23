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
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.BrowserInjection = void 0;
const browser_injection_1 = require("./test-utils/browser-injection");
const webauthn_emulator_1 = require("./webauthn/webauthn-emulator");
exports.default = webauthn_emulator_1.WebAuthnEmulator;
__exportStar(require("./authenticator/authenticator-emulator"), exports);
__exportStar(require("./authenticator/ctap-model"), exports);
__exportStar(require("./repository/credentials-file-repository"), exports);
__exportStar(require("./repository/credentials-memory-repository"), exports);
__exportStar(require("./repository/credentials-repository"), exports);
__exportStar(require("./test-utils/unit-test"), exports);
__exportStar(require("./webauthn/cose-key"), exports);
__exportStar(require("./webauthn/webauthn-emulator"), exports);
__exportStar(require("./webauthn/webauthn-model"), exports);
__exportStar(require("./webauthn/webauthn-model-json"), exports);
exports.BrowserInjection = {
    WebAuthnEmulatorGet: browser_injection_1.WebAuthnEmulatorGet,
    WebAuthnEmulatorCreate: browser_injection_1.WebAuthnEmulatorCreate,
    WebAuthnEmulatorSignalUnknownCredential: browser_injection_1.WebAuthnEmulatorSignalUnknownCredential,
    HookWebAuthnApis: browser_injection_1.HookWebAuthnApis,
};
