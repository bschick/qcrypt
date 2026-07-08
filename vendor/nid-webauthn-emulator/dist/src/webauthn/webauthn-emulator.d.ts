import { AuthenticatorEmulator } from "../authenticator/authenticator-emulator";
import { type CreatePublicKeyCredential, type RequestPublicKeyCredential } from "./webauthn-model-json";
export type AuthenticatorInfo = {
    version: string;
    aaguid: string;
    options: {
        rk?: boolean;
        uv?: boolean;
    };
};
export declare class WebAuthnEmulatorError extends Error {
}
/**
 * WebAuthn emulator
 */
export declare class WebAuthnEmulator {
    authenticator: AuthenticatorEmulator;
    constructor(authenticator?: AuthenticatorEmulator);
    private mapAuthenticatorErrorToDOMException;
    private handleAuthenticatorCall;
    getJSON(origin: string, optionsJSON: PublicKeyCredentialRequestOptionsJSON, relatedOrigins?: string[]): AuthenticationResponseJSON;
    createJSON(origin: string, optionsJSON: PublicKeyCredentialCreationOptionsJSON, relatedOrigins?: string[]): RegistrationResponseJSON;
    getAuthenticatorInfo(): AuthenticatorInfo;
    signalUnknownCredential(options: UnknownCredentialOptions): void;
    /**
     * Signal all accepted credentials for a user
     * @see https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredential/signalAllAcceptedCredentials_static
     */
    signalAllAcceptedCredentials(options: AllAcceptedCredentialsOptions): void;
    /**
     * Process credentials for an RP and delete those not in the accepted list
     */
    private processCredentials;
    /**
     * Signal current user details
     * @see https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredential/signalCurrentUserDetails_static
     */
    signalCurrentUserDetails(options: CurrentUserDetailsOptions): void;
    /** @see https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/get */
    get(origin: string, options: CredentialRequestOptions, relatedOrigins?: string[]): RequestPublicKeyCredential;
    /** @see https://developer.mozilla.org/ja/docs/Web/API/CredentialsContainer/create */
    create(origin: string, options: CredentialCreationOptions, relatedOrigins?: string[]): CreatePublicKeyCredential;
}
