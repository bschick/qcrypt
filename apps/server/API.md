# API Documentation v1

This document provides documentation for the passkey-based authentication server API v1.

## Registration Endpoints

### POST /v1/reg/options

- **Method:** `POST`
- **Path:** `/v1/reg/options`
- **Headers:** 'x-amz-content-sha256': SHA-256 Hex string digest of request body
- **Authorization:** Not required
- **Description:** Start registration of a new user and returns registration options for creating a passkey.
- **Request Body:** A JSON object with a `userName` key. Example: `{"userName": "New User"}`. User name must be greater than 5 and less than 32 characters and may not contain HTML tags.
- **Responses:**
  - `200 OK`: A SimpleWebAuthn/server [`PublicKeyCredentialCreationOptionsJSON`](#publickeycredentialcreationoptionsjson) JSON object.
  - `400 Bad Request`: The request was malformed or the username is invalid.

### POST /v1/reg/verify

- **Method:** `POST`
- **Path:** `/v1/reg/verify`
- **Headers:** 'x-amz-content-sha256': SHA-256 Hex string digest of request body
- **Authorization:** Not required
- **Description:** Verifies a registration response from a client, creating a new user and passkey. Response contains a `csrf` token that must be sent in the `x-csrf-token` header for authorized requests.
- **Request Body:** A [`RegVerify`](#regverify) object created by the client from the previous POST to `/v1/reg/options`: the SimpleWebAuthn/client `RegistrationResponseJSON` response, `userId`, `challenge`, `recoveryPubKey`, and the client-encrypted credential fields `passkeyUserCredEnc`, `recoveryUserCredEnc`, and `userCredPubKey`.
- **Responses:**
  - `200 OK`: A [`LoginUserInfo`](#loginuserinfo) JSON object including `csrf` and session cookie.
  - `400 Bad Request`: The request was malformed or the request body is invalid.
  - `401 Unauthorized`: The registration challenge has expired or is invalid.

## Authentication Endpoints

### POST /v1/auth/options

- **Method:** `POST`
- **Path:** `/v1/auth/options`
- **Authorization:** Not required
- **Description:** Retrieves authentication options for a user. If a `userId` is sent in the request body, the response will include a list of allowed credentials for that user only.
- **Request Body:** (optional) A JSON object with the `userId` of a user whose allowed credentials should be returned. Example: `{"userId": "base64id"}`.
- **Responses:**
  - `200 OK`: A SimpleWebAuthn/server [`PublicKeyCredentialRequestOptionsJSON`](#publickeycredentialrequestoptionsjson) JSON object.
  - `400 Bad Request`: The request was malformed or missing required parameters.

### POST /v1/auth/verify

- **Method:** `POST`
- **Path:** `/v1/auth/verify`
- **Headers:** 'x-amz-content-sha256': SHA-256 Hex string digest of request body
- **Authorization:** Not required
- **Description:** Verifies an authentication response from a client and establishes a new user session. Response contains a `csrf` token that must be sent in a `x-csrf-token` header for authorized requests.
- **Request Body:** The SimpleWebAuthn/client `AuthenticationResponseJSON` JSON object response & `challenge` created by client from previous POST to `/v1/auth/options`.
- **Responses:**
  - `200 OK`: A [`LoginUserInfo`](#loginuserinfo) JSON object including `csrf` and session cookie.
  - `400 Bad Request`: The request was malformed or the request body is invalid.
  - `401 Unauthorized`: The authentication challenge has expired or is invalid.

## Passkey Endpoints

### GET /v1/passkeys/options

- **Method:** `GET`
- **Path:** `/v1/passkeys/options`
- **Authorization:** Required (cookie, x-csrf-token, and x-proof)
- **Description:** Returns registration options for adding a new passkey to the currently authenticated user.
- **Responses:**
  - `200 OK`: A SimpleWebAuthn/server [`PublicKeyCredentialCreationOptionsJSON`](#publickeycredentialcreationoptionsjson) JSON object.
  - `401 Unauthorized`: The request is not authorized.

### POST /v1/passkeys/verify

- **Method:** `POST`
- **Path:** `/v1/passkeys/verify`
- **Headers:** 'x-amz-content-sha256': SHA-256 Hex string digest of request body
- **Authorization:** Required (cookie, x-csrf-token, and x-proof)
- **Description:** Verifies a registration response from a client and adds a new passkey to the currently authenticated user.
- **Request Body:** An [`AddVerify`](#addverify) object created by the client from the previous GET to `/v1/passkeys/options`: the SimpleWebAuthn/client `RegistrationResponseJSON` response, `challenge`, and the client-encrypted credential field `passkeyUserCredEnc`.
- **Responses:**
  - `200 OK`: A [`LoginUserInfo`](#loginuserinfo) JSON object.
  - `400 Bad Request`: The request was malformed or the request body is invalid.
  - `401 Unauthorized`: The registration challenge has expired or is invalid.

### PATCH /v1/passkeys/{credid}

- **Method:** `PATCH`
- **Path:** `/v1/passkeys/{credid}`
- **Headers:** 'x-amz-content-sha256': SHA-256 Hex string digest of request body
- **Authorization:** Required (cookie, x-csrf-token, and x-proof)
- **Description:** Updates the description of the passkey specified by `credid` for the currently authenticated user.
- **Request Body:** A JSON object with a `description` key. Example: `{"description": "My Yubikey"}`. Passkey description must be greater than 5 and less than 43 characters and may not contain HTML tags.
- **Responses:**
  - `200 OK`: A [`UserInfo`](#userinfo) JSON object.
  - `400 Bad Request`: The request was malformed or the description is invalid.
  - `401 Unauthorized`: The request is not authorized.

### DELETE /v1/passkeys/{credid}

- **Method:** `DELETE`
- **Path:** `/v1/passkeys/{credid}`
- **Authorization:** Required (cookie, x-csrf-token, and x-proof)
- **Description:** Deletes the passkey specified by `credid` for the currently authenticated user. When a user's last passkey is deleted, the entire user account is permanently deleted and cannot be recovered.
- **Responses:**
  - `200 OK`: A [`UserInfo`](#userinfo) JSON object. If this was the last passkey, the entire user account will be deleted and the response will indicate the user is not verified.
  - `400 Bad Request`: The credential ID is not valid.
  - `401 Unauthorized`: The request is not authorized.

## User Endpoints

### GET /v1/user

- **Method:** `GET`
- **Path:** `/v1/user`
- **Authorization:** Required (cookie, x-csrf-token, and x-proof)
- **Description:** Retrieves information about the currently authenticated user.
- **Responses:**
  - `200 OK`: A [`UserInfo`](#userinfo) JSON object.
  - `400 Bad Request`: The request was malformed.
  - `401 Unauthorized`: The request is not authorized.

### PATCH /v1/user

- **Method:** `PATCH`
- **Path:** `/v1/user`
- **Headers:** 'x-amz-content-sha256': SHA-256 Hex string digest of request body
- **Authorization:** Required (cookie, x-csrf-token, and x-proof)
- **Description:** Updates the username of the currently authenticated user.
- **Request Body:** A JSON object with a `userName` key. Example: `{"userName": "Some Name"}`. User name must be greater than 5 and less than 32 characters and may not contain HTML tags.
- **Responses:**
  - `200 OK`: A [`UserInfo`](#userinfo) JSON object.
  - `400 Bad Request`: The request was malformed or the request body is invalid.
  - `401 Unauthorized`: The request is not authorized.

### POST /v1/recover

- **Method:** `POST`
- **Path:** `/v1/recover`
- **Headers:** 'x-amz-content-sha256': SHA-256 Hex string digest of request body
- **Authorization:** Not required
- **Description:** DEPRECATED. Upgrade account and use `/v1/recover2` instead. Initiates the account recovery process for the user Id and user credential sent in the request body. This will delete all existing passkeys for the user and return registration options to create a new passkey.
- **Request Body:** A JSON object with `userId` and `userCred` keys. Example: `{"userId": "base64id", "userCred": "base64usercred"}`.
- **Responses:**
  - `200 OK`: A SimpleWebAuthn/server [`PublicKeyCredentialCreationOptionsJSON`](#publickeycredentialcreationoptionsjson) JSON object.
  - `400 Bad Request`: The user credential is not valid.
  - `401 Unauthorized`: The request is not authorized.

### POST /v1/recover2/challenge

- **Method:** `POST`
- **Path:** `/v1/recover2/challenge`
- **Headers:** 'x-amz-content-sha256': SHA-256 Hex string digest of request body
- **Authorization:** Not required
- **Description:** Returns a single-use challenge for the user to sign with their recovery key, proving possession before calling `/v1/recover2`.
- **Request Body:** A JSON object with a `userId` key. Example: `{"userId": "base64id"}`.
- **Responses:**
  - `200 OK`: A JSON object with a `challenge` key.
  - `400 Bad Request`: The request was malformed or the userId is invalid.

### POST /v1/recover2

- **Method:** `POST`
- **Path:** `/v1/recover2`
- **Headers:** 'x-amz-content-sha256': SHA-256 Hex string digest of request body
- **Authorization:** Not required
- **Description:** Initiates account recovery by verifying a recovery proof: a signature, made with the account's recovery key, over the challenge from `/v1/recover2/challenge`. On success it deletes all existing passkeys for the user and returns registration options to create a replacement passkey.
- **Request Body:** A JSON object with `userId`, `challenge`, and `signature` keys, where `challenge` is the value from `/v1/recover2/challenge` and `signature` is the recovery proof over it. Example: `{"userId": "base64id", "challenge": "base64challenge", "signature": "base64signature"}`.
- **Responses:**
  - `200 OK`: A [`RecoverInfo`](#recoverinfo) JSON object.
  - `400 Bad Request`: The request was malformed or the recovery proof is invalid.
  - `401 Unauthorized`: The request is not authorized.

### POST /v1/recover/verify

- **Method:** `POST`
- **Path:** `/v1/recover/verify`
- **Headers:** 'x-amz-content-sha256': SHA-256 Hex string digest of request body
- **Authorization:** Not required
- **Description:** Completes account recovery by verifying the registration response for the replacement passkey created after `/v1/recover2` (or the deprecated `/v1/recover`), and establishes a new session. Response contains a `csrf` token that must be sent in the `x-csrf-token` header for authorized requests.
- **Request Body:** A [`RecoverVerify`](#recoververify) object: the SimpleWebAuthn/client `RegistrationResponseJSON` response, `userId`, `challenge`, and the client-encrypted credential field `passkeyUserCredEnc`.
- **Responses:**
  - `200 OK`: A [`LoginUserInfo`](#loginuserinfo) JSON object including `csrf` and session cookie.
  - `400 Bad Request`: The request was malformed or the request body is invalid.
  - `401 Unauthorized`: The recovery challenge has expired or is invalid.

### PUT /v1/recover2/key

- **Method:** `PUT`
- **Path:** `/v1/recover2/key`
- **Headers:** 'x-amz-content-sha256': SHA-256 Hex string digest of request body
- **Authorization:** Required (cookie, x-csrf-token, and x-proof)
- **Description:** Replaces the recovery key generated from new recovery words for the authenticated user. For accounts where `prf` is true, the user credential re-encrypted under the new recovery secret must also be supplied.
- **Request Body:** A JSON object with a `recoveryPubKey` key, and a `userCredEnc` key when `prf` is true. Example: `{"recoveryPubKey": "base64pubkey", "userCredEnc": "base64usercredenc"}`.
- **Responses:**
  - `200 OK`: A [`UserInfo`](#userinfo) JSON object.
  - `400 Bad Request`: The request was malformed or the request body is invalid.
  - `401 Unauthorized`: The request is not authorized.

## Session Endpoints

### GET /v1/session

- **Method:** `GET`
- **Path:** `/v1/session`
- **Authorization:** Required (cookie and x-proof)
- **Description:** If a session exists and is valid, returns information for the currently authenticated user which includes a `csrf` token that must be sent in a `x-csrf-token` header for all other authorized requests.
- **Responses:**
  - `200 OK`: A [`LoginUserInfo`](#loginuserinfo) JSON object including `csrf` but not `userCred` or `passkeyUserCredEnc`.
  - `400 Bad Request`: The request was malformed.
  - `401 Unauthorized`: The request is not authorized.

### DELETE /v1/session

- **Method:** `DELETE`
- **Path:** `/v1/session`
- **Authorization:** Required (cookie, x-csrf-token, and x-proof)
- **Description:** Ends the current session and invalidates the session cookie and csrf token. Sessions will expire automatically, this endpoint is only needed to force early termination.
- **Responses:**
  - `200 OK`: A JSON object with a `message` key and a value of "done", along with an expired session cookie.
  - `400 Bad Request`: The request was malformed.
  - `401 Unauthorized`: The request is not authorized.

## Request Data Models

These are the objects sent by the client in request bodies. Each `*Verify` object is a SimpleWebAuthn/client `RegistrationResponseJSON` object with the additional fields below. The client-encrypted credential fields hold a user credential the client generated and encrypted itself; the server stores them as opaque values it cannot decrypt.

### RegVerify

Sent to `POST /v1/reg/verify` to create a new user and passkey.

- `userId` (string): The unique identifier for the user.
- `challenge` (string): A string that must be sent back to the server for verification.
- `recoveryPubKey` (string): The recovery proof public key derived from the client's recovery secret.
- `passkeyUserCredEnc` (string): The user credential encrypted under the new passkey's key.
- `recoveryUserCredEnc` (string): The user credential encrypted under the recovery secret.
- `userCredPubKey` (string): The proof public key derived from the client-generated user credential.

The three credential fields are all-or-nothing: send all three to create a `prf` account, or none to have the server generate and hold the credential.

### RecoverVerify

Sent to `POST /v1/recover/verify` to complete account recovery.

- `userId` (string): The unique identifier for the user.
- `challenge` (string): A string that must be sent back to the server for verification.
- `passkeyUserCredEnc` (string): The user credential re-encrypted under the new passkey's key. Required when `prf` is true, rejected otherwise.

### AddVerify

Sent to `POST /v1/passkeys/verify` to add a passkey to the authenticated user.

- `challenge` (string): A string that must be sent back to the server for verification.
- `passkeyUserCredEnc` (string): The user credential re-encrypted under the new passkey's key. Required when `prf` is true, rejected otherwise.

## Response Data Models

These are the objects that are returned to the client in API responses.

### UserInfo

The `UserInfo` object contains public information about a user.

- `verified` (boolean): Whether the user has been verified.
- `userId` (string, optional): The unique identifier for the user.
- `userName` (string, optional): The user's chosen name.
- `hasRecoveryId` (boolean, optional): `true` for recovery words, `false` for the original recovery link.
- `prf` (boolean, optional): Whether the account generated and encrypts the user credential locally.
- `authenticators` (array of [`AuthenticatorInfo`](#authenticatorinfo) objects, optional): A list of the user's authenticators.

### LoginUserInfo

The `LoginUserInfo` object extends the [`UserInfo`](#userinfo) object with additional information that is only returned after a successful login or registration verification.

- All fields from [`UserInfo`](#userinfo).
- `pkId` (string, optional): The ID of the public key credential used for the last login.
- `userCred` (string, optional): The plaintext user credential, returned only when `prf` is false.
- `passkeyUserCredEnc` (string, optional): The user credential encrypted under the last passkey, returned when `prf` is true.
- `csrf` (string, optional): A Cross-Site Request Forgery (CSRF) token that must be sent in a `x-csrf-token` header for authorized requests.

### RecoverInfo

The `RecoverInfo` object is a [`PublicKeyCredentialCreationOptionsJSON`](#publickeycredentialcreationoptionsjson) object with two additional recovery fields.

- All fields from [`PublicKeyCredentialCreationOptionsJSON`](#publickeycredentialcreationoptionsjson).
- `prf` (boolean, optional): Whether the account generated and encrypts the user credential locally.
- `userCredEnc` (string, optional): When `prf` is true, the user credential encrypted under the recovery secret.

### AuthenticatorInfo

The `AuthenticatorInfo` object contains public information about a user's authenticator.

- `credentialId` (string): The unique identifier for the credential.
- `description` (string): A user-provided description for the authenticator.
- `lightIcon` (string): A URL to a light theme icon for the authenticator.
- `darkIcon` (string): A URL to a dark theme icon for the authenticator.
- `name` (string): The name of the authenticator model.

### PublicKeyCredentialCreationOptionsJSON

The SimpleWebAuthn/server `PublicKeyCredentialCreationOptionsJSON` object contains the options needed to create a new passkey.

- `rp`: An object containing information about the Relying Party (your website).
- `user`: An object containing information about the user.
- `challenge`: A string that must be sent back to the server for verification.
- `pubKeyCredParams`: An array specifying the types of public key credentials to create.
- `timeout`: The time in milliseconds that the operation has to complete.
- `attestation`: The type of attestation to perform.
- `excludeCredentials`: An array of existing credentials to prevent re-registration.
- `authenticatorSelection`: An object specifying requirements for the authenticator.

### PublicKeyCredentialRequestOptionsJSON

The SimpleWebAuthn/server `PublicKeyCredentialRequestOptionsJSON` object contains the options needed to authenticate with a passkey.

- `challenge`: A string that must be sent back to the server for verification.
- `timeout`: The time in milliseconds that the operation has to complete.
- `rpId`: The ID of the Relying Party (your website).
- `allowCredentials`: An array of credentials that are allowed to be used for authentication.
- `userVerification`: The user verification requirement.

## Authorization

Endpoints that require authorization expect a `__Host-JWT` cookie, a `x-csrf-token` header, and a `x-proof` header to be sent with the request. The cookie and `csrf` token are issued by the `POST /v1/auth/verify` and `POST /v1/reg/verify` endpoints upon successful authentication. Once a session cookie is obtained, the `csrf` token is also returned by the `GET /v1/session` endpoint. The cookie contains a JSON Web Token (JWT) for authorization. The JWT is valid for a limited time or until `DELETE /v1/session` is called which returns a `__Host-JWT` cookie without a JWT, ending a session and invalidating the `csrf` token immediately.

The `x-proof` header proves possession of the user credential. It is a comma-separated `signature,timestamp,nonce` value, where `timestamp` is the current time and `signature` is an ML-DSA signature over the request computed with a key derived from the user credential. For details, see the `apps/web/src/app/services/authenticator.service.ts` and `libs/api/src/lib/proof.ts` source files.
