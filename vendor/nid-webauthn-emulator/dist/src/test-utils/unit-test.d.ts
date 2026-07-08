import { WebAuthnEmulator } from "../webauthn/webauthn-emulator";
type PasskeysEmulatorParams = {
    origin?: string;
    autofill?: boolean;
    creationException?: string;
    requestException?: string;
    rpId?: string;
};
export declare const createPasskeysEmulator: (params?: PasskeysEmulatorParams) => {
    instance: WebAuthnEmulator;
    addPasskey: (userId: string) => RegistrationResponseJSON;
    methods: {
        credentialsContainer: CredentialsContainer;
        publicKeyCredentials: {
            new (): PublicKeyCredential;
            prototype: PublicKeyCredential;
            getClientCapabilities(): Promise<PublicKeyCredentialClientCapabilities>;
            isConditionalMediationAvailable(): Promise<boolean>;
            isUserVerifyingPlatformAuthenticatorAvailable(): Promise<boolean>;
            parseCreationOptionsFromJSON(options: PublicKeyCredentialCreationOptionsJSON): PublicKeyCredentialCreationOptions;
            parseRequestOptionsFromJSON(options: PublicKeyCredentialRequestOptionsJSON): PublicKeyCredentialRequestOptions;
            signalAllAcceptedCredentials(options: AllAcceptedCredentialsOptions): Promise<void>;
            signalCurrentUserDetails(options: CurrentUserDetailsOptions): Promise<void>;
            signalUnknownCredential(options: UnknownCredentialOptions): Promise<void>;
        } & {
            signalUnknownCredential(options: UnknownCredentialOptions): Promise<void>;
            signalAllAcceptedCredentials(options: AllAcceptedCredentialsOptions): Promise<void>;
            signalCurrentUserDetails(options: CurrentUserDetailsOptions): Promise<void>;
            isConditionalMediationAvailable?(): Promise<boolean>;
        };
    };
};
export {};
