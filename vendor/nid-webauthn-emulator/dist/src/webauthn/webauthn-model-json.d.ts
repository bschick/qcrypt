/** @see https://www.w3.org/TR/webauthn-3/#sctn-parseCreationOptionsFromJSON */
export declare function parseCreationOptionsFromJSON(optionsJSON: PublicKeyCredentialCreationOptionsJSON): PublicKeyCredentialCreationOptions;
/** @see https://www.w3.org/TR/webauthn-3/#sctn-parseRequestOptionsFromJSON */
export declare function parseRequestOptionsFromJSON(optionsJSON: PublicKeyCredentialRequestOptionsJSON): PublicKeyCredentialRequestOptions;
export interface CreatePublicKeyCredential extends PublicKeyCredential {
    readonly response: AuthenticatorAttestationResponse;
    toJSON(): RegistrationResponseJSON;
}
export interface RequestPublicKeyCredential extends PublicKeyCredential {
    readonly response: AuthenticatorAssertionResponse;
    toJSON(): AuthenticationResponseJSON;
}
export declare function toRegistrationResponseJSON(credential: PublicKeyCredential): RegistrationResponseJSON;
export declare function toAuthenticationResponseJSON(credential: PublicKeyCredential): AuthenticationResponseJSON;
export declare function toCreationOptionsJSON(options: PublicKeyCredentialCreationOptions): PublicKeyCredentialCreationOptionsJSON;
export declare function toRequestOptionsJSON(options: PublicKeyCredentialRequestOptions): PublicKeyCredentialRequestOptionsJSON;
export declare function parseRegistrationResponseFromJSON(options: RegistrationResponseJSON): CreatePublicKeyCredential;
export declare function parseAuthenticationResponseFromJSON(options: AuthenticationResponseJSON): RequestPublicKeyCredential;
export declare function toPublicKeyCredentialDescriptorJSON(credential: PublicKeyCredentialDescriptor): PublicKeyCredentialDescriptorJSON;
export declare function parsePublicKeyCredentialDescriptorFromJSON(credential: PublicKeyCredentialDescriptorJSON): PublicKeyCredentialDescriptor;
export declare function toPublicKeyCredentialUserEntityJSON(user: PublicKeyCredentialUserEntity): PublicKeyCredentialUserEntityJSON;
export declare function parsePublicKeyCredentialUserEntityFromJSON(user: PublicKeyCredentialUserEntityJSON): PublicKeyCredentialUserEntity;
export declare function parsePRFValuesFromJSON(values: AuthenticationExtensionsPRFValuesJSON): AuthenticationExtensionsPRFValues;
export declare function parseExtensionResultsFromJSON(resultsJSON: AuthenticationExtensionsClientOutputsJSON): AuthenticationExtensionsClientOutputs;
export declare function toPRFValuesJSON(values: AuthenticationExtensionsPRFValues): AuthenticationExtensionsPRFValuesJSON;
export declare function toPRFInputsJSON(prf: AuthenticationExtensionsPRFInputs): AuthenticationExtensionsPRFInputsJSON;
export declare function toExtensionInputsJSON(extensions: AuthenticationExtensionsClientInputs | undefined): AuthenticationExtensionsClientInputsJSON | undefined;
export declare function encodeBase64Url(buffer: BufferSource): string;
export declare function decodeBase64Url(base64Url: string): ArrayBuffer;
