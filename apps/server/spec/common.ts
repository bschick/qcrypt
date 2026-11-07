/* MIT License

Copyright (c) 2026 Brad Schick

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE. */

import crypto from 'node:crypto';
import WebAuthnEmulator, {
   AuthenticatorEmulator,
   PasskeysCredentialsFileRepository,
   PasskeysCredentialsMemoryRepository,
   type HmacSecretMode,
} from 'nid-webauthn-emulator';
import * as api from '@qcrypt/api';
import {
   cryptoReady,
   bytesToBase64,
   base64ToBytes,
   getRandom,
   hashString,
   MasterKeyKeyProvider,
   encryptStream,
   decryptStream,
   streamFromBytes,
   streamFromBase64,
   readStreamAll,
} from '@qcrypt/crypto';
import * as cc from '@qcrypt/crypto/consts';
import { expect } from 'vitest';

// ----- Setup -----
export const API_SERVER = process.env.QC_ENV === 'prod' ? 'https://quickcrypt.org' : 'https://test.quickcrypt.org';
export const RP_ORIGIN = process.env.QC_ENV === 'prod' ? 'https://quickcrypt.org' : 'https://t1.quickcrypt.org:4200';

// ----- Helpers -----
export const sha256Hex = (buf: Buffer): string => crypto.createHash('sha256').update(buf).digest('hex');

// Mirrors a browser that holds one userCred for the whole session.
let sessionUserCred: string | undefined;
let sessionUserId: string | undefined;

// Routes that reject a nonce proof, so the session nonce proof is never added to them
const NO_NONCE_PROOF = [
   '/v1/auth/options',
   '/v1/auth/verify',
   '/v1/reg/options',
   '/v1/reg/verify',
   '/v1/recover',
   '/v1/recover3',
   '/v1/recover/confirm',
   '/v1/recover/verify',
   '/v1/passkeys/verify',
];

export function setSessionSigner(userId: string | undefined, userCred?: string): void {
   sessionUserId = userId;
   sessionUserCred = userCred;
}

async function proofHeaders(method: string, path: string, body: Buffer | undefined): Promise<Record<string, string>> {
   let headers: Record<string, string> = {};
   if (sessionUserCred && sessionUserId) {
      headers = await makeNonceProofHeaders(method, path, body, sessionUserCred, sessionUserId);
   }
   return headers;
}

// Craft proof-of-userCred headers with an explicit credential and userId. opts let
// enforcement tests forge a bad proof: an out-of-window timestamp or a flipped signature.
export async function makeNonceProofHeaders(
   method: string,
   path: string,
   body: Buffer | undefined,
   userCred: string,
   userId: string,
   // BACKWARD COMPAT: legacyHeader sends the proof in the x-proof header
   opts: { timestampMs?: string; tamperSig?: boolean; nonce?: string; legacyHeader?: boolean } = {},
): Promise<Record<string, string>> {
   await cryptoReady();
   const timestamp = opts.timestampMs ?? String(Date.now());
   const nonce = opts.nonce ?? Buffer.from(getRandom(32)).toString('base64url');
   const bodyHashHex = sha256Hex(body ?? Buffer.alloc(0));

   // Sign the decoded path. The server verifies (event.requestContext.http.path), not the
   // re-encoded URL pathname.
   const pathname = path.split('?')[0];
   const queryString = path.split('?')[1] || '';
   const signature = api.createUserCredNonceProof(
      Buffer.from(userCred, 'base64url'),
      userId,
      method,
      pathname,
      timestamp,
      nonce,
      bodyHashHex,
      queryString,
   );

   let sigStr = signature;
   if (opts.tamperSig) {
      const sigBytes = base64ToBytes(signature);
      sigBytes[0] ^= 0x01;
      sigStr = bytesToBase64(sigBytes);
   }

   return {
      // BACKWARD COMPAT: x-proof only when legacyHeader is set
      [opts.legacyHeader ? 'x-proof' : 'x-nonce-proof']: `${sigStr},${timestamp},${nonce}`,
   };
}

// The x-challenge-proof for a POST that answers a server-issued challenge, which the proof signs
// in place of a nonce. The body hash must match the JSON that postJson sends for the same object.
export function makeChallengeProofHeaders(
   path: string,
   bodyObj: object,
   userCred: Uint8Array,
   userId: string,
   challenge: string,
   opts: { timestampMs?: string } = {},
): Record<string, string> {
   const timestamp = opts.timestampMs ?? String(Date.now());
   const [pathname, queryString = ''] = path.split('?');
   const signature = api.createUserCredChallengeProof(
      userCred,
      userId,
      'POST',
      pathname,
      timestamp,
      challenge,
      sha256Hex(Buffer.from(JSON.stringify(bodyObj), 'utf8')),
      queryString,
   );
   return { 'x-challenge-proof': `${signature},${timestamp}` };
}

export function getWebAuthnEmulator(
   persistent: boolean = false,
   hmacSecret: HmacSecretMode = 'none',
): WebAuthnEmulator {
   let emulator: WebAuthnEmulator;

   if (!persistent && hmacSecret === 'none') {
      emulator = new WebAuthnEmulator();
   } else {
      const auth = new AuthenticatorEmulator({
         transports: ['internal'],
         hmacSecret,
         ...(persistent
            ? { credentialsRepository: new PasskeysCredentialsFileRepository('apps/server/spec/credentials') }
            : {}),
      });
      emulator = new WebAuthnEmulator(auth);
   }

   return emulator;
}

// Returns an emulator with its own credential store. Emulators created without a repository share one
// default store, which keeps a single credential per userHandle.
export function getIsolatedWebAuthnEmulator(hmacSecret: HmacSecretMode = 'none'): WebAuthnEmulator {
   return new WebAuthnEmulator(
      new AuthenticatorEmulator({
         transports: ['internal'],
         hmacSecret,
         credentialsRepository: new PasskeysCredentialsMemoryRepository(),
      }),
   );
}

// Must match the fixed PRF salt in apps/web/src/app/services/prf.ts (NOT a secret).
export const PRF_SALT = new Uint8Array([
   79, 207, 95, 76, 134, 119, 236, 52, 72, 250, 231, 99, 35, 243, 1, 169, 205, 253, 35, 140, 130, 201, 98, 86, 30, 119,
   75, 185, 138, 67, 243, 33,
]);

// The emulator's JSON API expects/returns PRF values as base64url text.
const PRF_SALT_INPUT = bytesToBase64(PRF_SALT);
export const PRF_EXTENSION = { prf: { eval: { first: PRF_SALT_INPUT } } };

// Reads the PRF output (results.first) from a credential's client extension results,
// or null if not present
export function readPrfOutput(clientExtensionResults: any): Uint8Array<ArrayBuffer> | null {
   const first = clientExtensionResults?.prf?.results?.first;
   let output: Uint8Array<ArrayBuffer> | null = null;
   if (first) {
      output = base64ToBytes(first);
      if (output.byteLength !== cc.KEY_BYTES) {
         throw new Error(`unexpected PRF output length: ${output.byteLength}`);
      }
   }
   return output;
}

// Encrypt a client-generated userCred under a 32-byte key (a PRF output or the recovery
// secret), matching the web client's ciphertext construction. Takes ownership of and wipes key.
export async function prfEncrypt(
   plainText: Uint8Array<ArrayBuffer>,
   key: Uint8Array<ArrayBuffer>,
   userId: string,
): Promise<string> {
   try {
      const keyProvider = new MasterKeyKeyProvider(key, userId);
      const cipherData = await readStreamAll(
         await encryptStream(streamFromBytes(plainText), keyProvider, { algs: ['X20-PLY'] }),
      );
      return bytesToBase64(cipherData);
   } finally {
      key.fill(0);
   }
}

// Take ownership of and wipe key.
export async function prfDecrypt(
   cipherText: string,
   key: Uint8Array<ArrayBuffer>,
   userId: string,
): Promise<Uint8Array<ArrayBuffer>> {
   try {
      const keyProvider = new MasterKeyKeyProvider(key, userId);
      return await readStreamAll(await decryptStream(streamFromBase64(cipherText), keyProvider));
   } finally {
      key.fill(0);
   }
}

export type EmulatorAttestation = ReturnType<WebAuthnEmulator['createJSON']>;

// Register a credential and, for PRF accounts, return its per-credential PRF output. The emulator
// advertises hmac-secret-mc, so the output is present in the registration response (the server API
// is oblivious to the create-vs-assert timing that a real client must handle).
export function createCredential(
   emulator: WebAuthnEmulator,
   createOptions: PublicKeyCredentialCreationOptionsJSON,
   prf: true,
): { attestation: EmulatorAttestation; prfOutput: Uint8Array<ArrayBuffer> };
export function createCredential(
   emulator: WebAuthnEmulator,
   createOptions: PublicKeyCredentialCreationOptionsJSON,
   prf: false,
): { attestation: EmulatorAttestation };
export function createCredential(
   emulator: WebAuthnEmulator,
   createOptions: PublicKeyCredentialCreationOptionsJSON,
   prf: boolean,
): { attestation: EmulatorAttestation; prfOutput?: Uint8Array<ArrayBuffer> };
export function createCredential(
   emulator: WebAuthnEmulator,
   createOptions: PublicKeyCredentialCreationOptionsJSON,
   prf: boolean,
): { attestation: EmulatorAttestation; prfOutput?: Uint8Array<ArrayBuffer> } {
   let created: { attestation: EmulatorAttestation; prfOutput?: Uint8Array<ArrayBuffer> };
   if (prf) {
      const attestation = emulator.createJSON(RP_ORIGIN, { ...createOptions, extensions: PRF_EXTENSION });
      const prfOutput = readPrfOutput(attestation.clientExtensionResults);
      if (!prfOutput) {
         throw new Error('emulator returned no PRF output');
      }
      created = { attestation, prfOutput };
   } else {
      created = { attestation: emulator.createJSON(RP_ORIGIN, createOptions) };
   }
   return created;
}

async function request(
   method: string,
   path: string,
   bodyObj: any = null,
   extraHeaders: Record<string, string> = {},
   cookie = '',
) {
   const headers: Record<string, string> = {
      ...extraHeaders,
      // QCTestClient marker lets the server's PWTesty_ prefix guard recognize
      // these vitest specs as a known test client.
      'User-Agent': 'Mozilla/5.0 QCTestClient',
      Origin: RP_ORIGIN,
   };

   if (cookie) {
      headers['Cookie'] = cookie;
   }

   let body: Buffer | undefined;
   if (bodyObj) {
      const json = JSON.stringify(bodyObj);
      body = Buffer.from(json, 'utf8');
      headers['Content-Type'] = 'application/json';
      headers['x-amz-content-sha256'] = sha256Hex(body);
   }

   // The server rejects a request with more than one proof header, so a proof header passed in
   // replaces the session nonce proof. BACKWARD COMPAT: x-proof is the compat nonce proof header.
   const hasProof = ['x-nonce-proof', 'x-challenge-proof', 'x-proof'].some((name) => name in headers);
   if (cookie && !hasProof && !NO_NONCE_PROOF.includes(path)) {
      Object.assign(headers, await proofHeaders(method, path, body));
   }

   // Node's Buffer isn't assignable to the DOM BodyInit type, so hand fetch a plain view of the same bytes
   const res = await fetch(`${API_SERVER}${path}`, {
      method,
      headers,
      body: body ? new Uint8Array(body) : undefined,
   });
   const raw = await res.text();

   let data: any;
   try {
      data = JSON.parse(raw);
   } catch {
      data = undefined;
   }

   let responseCookie = '';
   const match = /(__Host-JWT=.+?);/.exec(res.headers.getSetCookie()[0]);
   if (match?.[1]) {
      responseCookie = match[1];
   }

   return { status: res.status, data, cookie: responseCookie, rawText: raw };
}

export const postJson = (p: string, b: any, h: any, c: string) => request('POST', p, b, h, c);
export const getJson = (p: string, h: any, c: string) => request('GET', p, null, h, c);
export const putJson = (p: string, b: any, h: any, c: string) => request('PUT', p, b, h, c);
export const patchJson = (p: string, b: any, h: any, c: string) => request('PATCH', p, b, h, c);
export const deleteJson = (p: string, h: any, c: string) => request('DELETE', p, null, h, c);

// A swallowed cleanup-delete failure leaks a verified, no-TTL account permanently,
// so assert success here instead of ignoring the result.
export async function expectPasskeyDeleted(credId: string, csrf: string, cookie: string): Promise<void> {
   const res = await deleteJson(`/v1/passkeys/${credId}`, { 'x-csrf-token': csrf }, cookie);
   expect(res.status).toBe(200);
}

// Polls because session and user reads list passkeys eventually consistently
export async function expectListedPasskeys(
   path: '/v1/session' | '/v1/user',
   credIds: string[],
   csrf: string,
   cookie: string,
) {
   const expected = [...credIds].sort();
   const listed = (res: Awaited<ReturnType<typeof getJson>>): string[] =>
      res.data.authenticators.map((auth: api.AuthenticatorInfoResponse) => auth.credentialId).sort();

   let res = await getJson(path, { 'x-csrf-token': csrf }, cookie);
   for (let retry = 0; retry < 2 && res.status === 200 && listed(res).join() !== expected.join(); retry++) {
      await new Promise((resolve) => setTimeout(resolve, 1000));
      res = await getJson(path, { 'x-csrf-token': csrf }, cookie);
   }
   expect(res.status).toBe(200);
   expect(listed(res)).toEqual(expected);
   return res;
}

const NAME_PREFIX = 'PWTesty_';
const NAME_MAX_LEN = 31;
const SKIP_WORDS = ['and', 'the', 'but', 'for', 'nor', 'yet', 'that', 'this', 'when', 'then', 'its'];

// Hyphens are removed rather than split on so "no-PRF" stays one word and cannot be mistaken
// for "PRF". Short and joining words are dropped because they crowd out the words that
// identify the test.
function condense(text: string, words: number, chars: number): string {
   return text
      .toLowerCase()
      .replace(/-/g, '')
      .split(/[^a-z0-9]+/)
      .filter((word) => word.length > 2 && !SKIP_WORDS.includes(word))
      .slice(0, words)
      .map((word) => word.slice(0, chars))
      .join('');
}

let nameCount = 0;
let namedTest = '';

// Names an account after the test that created it so a leaked user names its own source. The
// count distinguishes accounts within one test. Pass a label where the derived one would be
// unhelpful, or where a test appends to the name and needs the room.
export function testUserName(label?: string): string {
   const state = expect.getState();
   const testName = state.currentTestName ?? '';
   if (testName !== namedTest) {
      namedTest = testName;
      nameCount = 0;
   }

   const fileName = (state.testPath ?? '').split('/').pop() ?? '';
   // A registration inside a hook has no test name yet, leaving only the file to go on
   const derived = [
      condense(fileName.replace(/\.(spec|suite)\.ts$/, ''), 1, 6),
      condense(testName.split('>').at(-1) ?? '', 3, 4),
   ]
      .filter((part) => part)
      .join('_');
   const suffix = `_${++nameCount}`;
   return `${NAME_PREFIX}${(label ?? derived).slice(0, NAME_MAX_LEN - NAME_PREFIX.length - suffix.length)}${suffix}`;
}

interface TestUserBase {
   userId: string;
   userName: string;
   userCred: string;
   cookie: string;
   csrf: string;
   credId: string;
   emulator: WebAuthnEmulator;
   recoverySecret: Uint8Array;
   recoveryId: Uint8Array;
}

// The prf discriminant narrows to the extra fields a PRF account carries.
export interface NoPrfTestUser extends TestUserBase {
   prf: false;
}
export interface PrfTestUser extends TestUserBase {
   prf: true;
   passkeyUserCredEnc: string;
   prfOutput: Uint8Array;
}
export type TestUser = NoPrfTestUser | PrfTestUser;

// Registers a fresh account the way the current client does, and returns what later requests need:
// the session, the userCred that signs proofs, and the recovery secret. userCred is created here in
// both modes. A PRF account sends only ciphertexts of it, and a no-PRF account sends it in plaintext.
export async function registerTestUser(prf: boolean = false, label?: string): Promise<TestUser> {
   await cryptoReady();

   const userName = testUserName(label);
   const { userId, body, headers, emulator, userCred, recoverySecret, recoveryId, prfOutput } = await buildRegBody(
      userName,
      prf,
   );

   const verifyRes = await postJson('/v1/reg/verify', body, headers, '');
   expect(verifyRes.status).toBe(200);
   expect(verifyRes.data.verified).toBe(true);
   expect(verifyRes.data.prf).toBe(prf);
   expect(verifyRes.data.passkeyUserCredEnc).toBeUndefined();
   expect(verifyRes.data.userCred).toBe(prf ? undefined : bytesToBase64(userCred));
   expect(verifyRes.data.csrf).toBeDefined();
   expect(verifyRes.data.pkId).toBeDefined();
   expect(verifyRes.data.recoveryKeyId).toEqual(hashString(api.getRecoveryPubKey(recoverySecret)));
   expect(verifyRes.cookie).toBeTruthy();

   const base: TestUserBase = {
      userId,
      userName,
      userCred: bytesToBase64(userCred),
      cookie: verifyRes.cookie,
      csrf: verifyRes.data.csrf,
      credId: verifyRes.data.pkId,
      emulator,
      recoverySecret,
      recoveryId,
   };
   const user: TestUser = prf
      ? { ...base, prf: true, passkeyUserCredEnc: body.passkeyUserCredEnc!, prfOutput: prfOutput! }
      : { ...base, prf: false };

   // Make this user the current session signer
   setSessionSigner(user.userId, user.userCred);

   return user;
}

// Signs in with an account's existing passkey
export async function loginWithPasskey(user: TestUser): Promise<{ cookie: string; csrf: string }> {
   const optsRes = await postJson('/v1/auth/options', { userId: user.userId }, {}, '');
   expect(optsRes.status).toBe(200);

   const assertion = user.emulator.getJSON(RP_ORIGIN, { ...optsRes.data, challenge: optsRes.data.challenge });
   const body = api.makeAuthVerifyRequest(assertion as api.AuthenticationFields, {
      challenge: optsRes.data.challenge,
   });
   const verifyRes = await postJson('/v1/auth/verify', body, {}, '');
   expect(verifyRes.status).toBe(200);
   expect(verifyRes.data.verified).toBe(true);
   return { cookie: verifyRes.cookie, csrf: verifyRes.data.csrf };
}

// Register an additional credential and return its attestation. Without an emulator override, a
// throwaway userHandle is used so the emulator's per-handle credential eviction does not affect the
// primary credential; the server still binds the new credential to the session's account since a
// registration response carries no userHandle. When an emulator is supplied, the credential is
// registered under the account's own userId. For a PRF account this also returns the new
// credential's ciphertext of the account userCred; no-PRF returns only the attestation.
export async function registerNewCredential(
   user: TestUser,
   optionsData: PublicKeyCredentialCreationOptionsJSON,
   emulator?: WebAuthnEmulator,
): Promise<{ attestation: EmulatorAttestation; passkeyUserCredEnc?: string }> {
   const createOptions = {
      ...optionsData,
      user: { ...optionsData.user, id: emulator ? user.userId : bytesToBase64(getRandom(cc.USERID_BYTES)) },
      challenge: optionsData.challenge,
      excludeCredentials: [],
   };
   const target = emulator ?? user.emulator;

   let result: { attestation: EmulatorAttestation; passkeyUserCredEnc?: string };
   if (user.prf) {
      const { attestation, prfOutput } = createCredential(target, createOptions, true);
      const passkeyUserCredEnc = await prfEncrypt(base64ToBytes(user.userCred), prfOutput, user.userId);
      result = { attestation, passkeyUserCredEnc };
   } else {
      const { attestation } = createCredential(target, createOptions, false);
      result = { attestation };
   }
   return result;
}

// Adds a passkey to an account holding a live session, returning the new credential id.
export async function addPasskey(user: TestUser, csrf: string, cookie: string): Promise<string> {
   setSessionSigner(user.userId, user.userCred);
   const optsRes = await getJson('/v1/passkeys/options', { 'x-csrf-token': csrf }, cookie);
   expect(optsRes.status).toBe(200);

   const { attestation, passkeyUserCredEnc } = await registerNewCredential(user, optsRes.data);
   const body = api.makeAddVerifyRequest(attestation as api.RegistrationFields, {
      challenge: optsRes.data.challenge,
      passkeyUserCredEnc,
   });

   const verifyRes = await postPasskeyVerify(user, body, csrf, cookie);
   expect(verifyRes.status).toBe(200);
   expect(verifyRes.data.verified).toBe(true);

   return attestation.id;
}

// Sends passkeys/verify with a challenge proof over the body's challenge, signed with user's userCred
export function postPasskeyVerify(
   user: TestUser,
   body: Record<string, unknown> & { challenge: string },
   csrf: string,
   cookie: string,
   path: string = '/v1/passkeys/verify',
) {
   const headers = makeChallengeProofHeaders(path, body, base64ToBytes(user.userCred), user.userId, body.challenge);
   return postJson(path, body, { 'x-csrf-token': csrf, ...headers }, cookie);
}

// Prepares a registration up to, but not including, reg/verify. reg/options has already run, so the
// challenge is live and bound to userCred's public key. Any change to the returned body invalidates
// the proof in the returned headers. A PRF registration sends only ciphertexts of userCred, and a
// no-PRF registration sends it in plaintext.
export async function buildRegBody(
   userName: string,
   prf: boolean,
   // BACKWARD COMPAT: false leaves the challenge unbound, as reg/options does for clients that omit userCredPubKey
   bindKey: boolean = true,
): Promise<{
   userId: string;
   body: api.RegVerifyRequest;
   headers: Record<string, string>;
   emulator: WebAuthnEmulator;
   userCred: Uint8Array<ArrayBuffer>;
   userCredPubKey: string;
   recoverySecret: Uint8Array;
   recoveryId: Uint8Array;
   prfOutput?: Uint8Array<ArrayBuffer>;
}> {
   await cryptoReady();
   const userCred = getRandom(cc.USERCRED_BYTES);
   const userCredPubKey = api.getUserCredPubKey(userCred);
   const regOpts = await postJson('/v1/reg/options', bindKey ? { userName, userCredPubKey } : { userName }, {}, '');
   expect(regOpts.status).toBe(200);
   expect(regOpts.data.user.name).toBe(userName);

   const userId: string = regOpts.data.user.id;
   const challenge: string = regOpts.data.challenge;
   const emulator = getWebAuthnEmulator(false, prf ? 'hmac-secret-mc' : 'none');
   const { attestation, prfOutput } = createCredential(
      emulator,
      {
         ...regOpts.data,
         user: { ...regOpts.data.user, id: userId },
         challenge,
      },
      prf,
   );
   const recoveryId = getRandom(api.RECOVERYID_BYTES);
   const secret = api.recoverySecret(recoveryId, userId);

   const recoveryTimestamp = String(Date.now());
   const riders: api.RegVerifyRiders = {
      userId,
      challenge,
      // BACKWARD COMPAT: a client that omits userCredPubKey from reg/options sends it here
      userCredPubKey: bindKey ? undefined : userCredPubKey,
      recoveryPubKey: api.getRecoveryPubKey(secret),
      recoveryTimestamp,
      recoverySignature: api.createRecoveryChallengeProof(secret, userId, recoveryTimestamp, challenge, userCredPubKey),
   };
   if (prf) {
      riders.passkeyUserCredEnc = await prfEncrypt(userCred.slice(0), prfOutput!.slice(0), userId);
      riders.recoveryUserCredEnc = await prfEncrypt(userCred.slice(0), secret.slice(0), userId);
   } else {
      riders.userCred = bytesToBase64(userCred);
   }

   const body = api.makeRegVerifyRequest(attestation as api.RegistrationFields, riders);
   const headers = makeChallengeProofHeaders('/v1/reg/verify', body, userCred, userId, challenge);
   return { userId, body, headers, emulator, userCred, userCredPubKey, recoverySecret: secret, recoveryId, prfOutput };
}

export type Registration = Awaited<ReturnType<typeof buildRegBody>>;

// Overrides for a request built by buildRegBody. Fields in body replace the built ones. The
// x-challenge-proof over the final body is signed with the private key derived from keySecret, which
// defaults to the built userCred. Headers that are passed are sent in place of the x-challenge-proof.
export interface RegVerifyOpts {
   body?: Partial<api.RegVerifyRequest>;
   keySecret?: Uint8Array;
   headers?: Record<string, string>;
}

export function postRegVerify(reg: Registration, opts: RegVerifyOpts) {
   const body = { ...reg.body, ...opts.body };
   const headers =
      opts.headers ??
      makeChallengeProofHeaders('/v1/reg/verify', body, opts.keySecret ?? reg.userCred, reg.userId, body.challenge);
   return postJson('/v1/reg/verify', body, headers, '');
}

// Deletes the account a successful registration creates
export async function expectRegistered(reg: Registration, opts: RegVerifyOpts = {}): Promise<void> {
   const res = await postRegVerify(reg, opts);
   expect(res.status).toBe(200);
   // A no-PRF response returns the account's userCred
   setSessionSigner(reg.userId, res.data.userCred ?? bytesToBase64(reg.userCred));
   await expectPasskeyDeleted(res.data.pkId, res.data.csrf, res.cookie);
   setSessionSigner(undefined);
}

// reg/verify reports every rejection as a uniform 401 because it is unauthenticated. The request
// without overrides is then sent on the same challenge and must succeed. Its success proves the
// rejection did not consume the challenge, and that the overrides alone caused the rejection.
export async function expectRegRejected(
   reg: Registration,
   opts: RegVerifyOpts,
   // BACKWARD COMPAT: the old-format request to send after the rejection
   retry: RegVerifyOpts = {},
): Promise<void> {
   const bad = await postRegVerify(reg, opts);
   expect(bad.status).toBe(401);
   // BACKWARD COMPAT: send the request without overrides once old-format requests are gone
   await expectRegistered(reg, retry);
}
