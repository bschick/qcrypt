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
   type HmacSecretMode,
} from 'nid-webauthn-emulator';
import {
   createUserCredProof,
   getUserCredPubKey,
   getRecoveryPubKey,
   recoverySecret,
   RECOVERYID_BYTES,
   type RequestTypes,
} from '@qcrypt/api';
import {
   cryptoReady,
   bytesToBase64,
   base64ToBytes,
   getRandom,
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

export function setSessionUserCred(userCred: string | undefined, userId?: string): void {
   sessionUserCred = userCred;
   sessionUserId = userId;
}

async function proofHeaders(method: string, path: string, body: Buffer | undefined): Promise<Record<string, string>> {
   let headers: Record<string, string> = {};
   if (sessionUserCred && sessionUserId) {
      headers = await makeProofHeaders(method, path, body, sessionUserCred, sessionUserId);
   }
   return headers;
}

// Craft proof-of-userCred headers with an explicit credential and userId. opts let
// enforcement tests forge a bad proof: an out-of-window timestamp or a flipped signature.
export async function makeProofHeaders(
   method: string,
   path: string,
   body: Buffer | undefined,
   userCred: string,
   userId: string,
   opts: { timestampMs?: string; tamperSig?: boolean; nonce?: string } = {},
): Promise<Record<string, string>> {
   await cryptoReady();
   const timestamp = opts.timestampMs ?? String(Date.now());
   const nonce = opts.nonce ?? Buffer.from(getRandom(32)).toString('base64url');
   const bodyHashHex = sha256Hex(body ?? Buffer.alloc(0));

   // Sign the decoded path. The server verifies (event.requestContext.http.path), not the
   // re-encoded URL pathname.
   const pathname = path.split('?')[0];
   const queryString = path.split('?')[1] || '';
   const signature = createUserCredProof(
      Buffer.from(userCred, 'base64url'),
      userId,
      method,
      pathname,
      timestamp,
      nonce,
      bodyHashHex,
      queryString,
   );

   const sigBytes = Buffer.from(signature);
   if (opts.tamperSig) {
      sigBytes[0] ^= 0x01;
   }
   const sigStr = sigBytes.toString('base64url');

   return {
      'x-proof': `${sigStr},${timestamp},${nonce}`,
   };
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

// createJSON returns RegistrationResponseJSON, which only becomes a DOM global in TypeScript 6
// (this project is on 5.9). Track it through the emulator's method so it resolves under both.
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

   if (cookie) {
      Object.assign(headers, await proofHeaders(method, path, body));
   }

   // Node's Buffer isn't assignable to the DOM BodyInit type, so hand fetch a plain view of the same bytes
   const res = await fetch(`${API_SERVER}${path}`, {
      method,
      headers: headers,
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

interface TestUserBase {
   userId: string;
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

// Register a fresh account (reg/options + reg/verify) and return everything needed to make
// authorized, proof-signed requests. The recovery secret is generated here as the real client
// does and only its public key is sent; the secret is returned for recovery flows. When prf is
// true the client generates userCred locally and sends only opaque ciphertexts (the server never
// sees plaintext userCred); when false the server generates and returns userCred as before.
export async function registerTestUser(userName: string, prf: boolean = false): Promise<TestUser> {
   await cryptoReady();

   let user: TestUser;
   if (prf) {
      const {
         userId,
         body,
         emulator,
         userCred,
         recoverySecret: secret,
         recoveryId,
         prfOutput,
      } = await buildPrfRegBody(userName);

      const verifyRes = await postJson(`/v1/reg/verify?usercred=true`, body, {}, '');
      expect(verifyRes.status).toBe(200);
      expect(verifyRes.data.verified).toBe(true);
      expect(verifyRes.data.prf).toBe(true);
      expect(verifyRes.data.passkeyUserCredEnc).toBeUndefined();
      expect(verifyRes.data.userCred).toBeUndefined();
      expect(verifyRes.data.csrf).toBeDefined();
      expect(verifyRes.data.pkId).toBeDefined();
      expect(verifyRes.cookie).toBeTruthy();

      user = {
         prf: true,
         userId,
         userCred: bytesToBase64(userCred),
         cookie: verifyRes.cookie,
         csrf: verifyRes.data.csrf,
         credId: verifyRes.data.pkId,
         emulator,
         recoverySecret: secret,
         recoveryId,
         passkeyUserCredEnc: body.passkeyUserCredEnc!,
         prfOutput,
      };
   } else {
      const regOpts = await postJson('/v1/reg/options', { userName }, {}, '');
      expect(regOpts.status).toBe(200);
      expect(regOpts.data.user.name).toBe(userName);

      const userId: string = regOpts.data.user.id;
      const recoveryId = getRandom(RECOVERYID_BYTES);
      const secret = recoverySecret(recoveryId, userId);
      const emulator = getWebAuthnEmulator();
      const { attestation } = createCredential(
         emulator,
         {
            ...regOpts.data,
            user: { ...regOpts.data.user, id: userId },
            challenge: regOpts.data.challenge,
         },
         false,
      );

      const body: RequestTypes.RegVerify = {
         ...attestation,
         userId,
         challenge: regOpts.data.challenge,
         recoveryPubKey: bytesToBase64(getRecoveryPubKey(secret)),
      };
      const verifyRes = await postJson(`/v1/reg/verify?usercred=true`, body, {}, '');
      expect(verifyRes.status).toBe(200);
      expect(verifyRes.data.verified).toBe(true);
      expect(verifyRes.data.csrf).toBeDefined();
      expect(verifyRes.data.pkId).toBeDefined();
      expect(verifyRes.data.userCred).toBeDefined();
      expect(verifyRes.cookie).toBeTruthy();

      user = {
         prf: false,
         userId,
         userCred: verifyRes.data.userCred,
         cookie: verifyRes.cookie,
         csrf: verifyRes.data.csrf,
         credId: verifyRes.data.pkId,
         emulator,
         recoverySecret: secret,
         recoveryId,
      };
   }

   return user;
}

// Register an additional credential on the account and return its attestation. The emulator evicts
// any stored credential sharing a userHandle, so a throwaway handle keeps the primary credential
// intact; it stays invisible to the server, which binds the new credential to the session's account
// (a registration response carries no userHandle). For a PRF account it also returns the new
// credential's ciphertext of the account userCred; no-PRF returns only the attestation.
export async function registerNewCredential(
   user: TestUser,
   optionsData: PublicKeyCredentialCreationOptionsJSON,
): Promise<{ attestation: EmulatorAttestation; passkeyUserCredEnc?: string }> {
   const createOptions = {
      ...optionsData,
      user: { ...optionsData.user, id: bytesToBase64(getRandom(cc.USERID_BYTES)) },
      challenge: optionsData.challenge,
      excludeCredentials: [],
   };

   let result: { attestation: EmulatorAttestation; passkeyUserCredEnc?: string };
   if (user.prf) {
      const { attestation, prfOutput } = createCredential(user.emulator, createOptions, true);
      const passkeyUserCredEnc = await prfEncrypt(base64ToBytes(user.userCred), prfOutput, user.userId);
      result = { attestation, passkeyUserCredEnc };
   } else {
      const { attestation } = createCredential(user.emulator, createOptions, false);
      result = { attestation };
   }
   return result;
}

// Run reg/options and build a valid PRF reg/verify body, returning it with the material behind it:
// the plaintext userCred, the recovery secret and id, the primary credential's PRF output, and the
// emulator holding that credential.
export async function buildPrfRegBody(userName: string): Promise<{
   userId: string;
   body: RequestTypes.RegVerify;
   emulator: WebAuthnEmulator;
   userCred: Uint8Array<ArrayBuffer>;
   recoverySecret: Uint8Array;
   recoveryId: Uint8Array;
   prfOutput: Uint8Array<ArrayBuffer>;
}> {
   await cryptoReady();
   const regOpts = await postJson('/v1/reg/options', { userName }, {}, '');
   expect(regOpts.status).toBe(200);
   expect(regOpts.data.user.name).toBe(userName);

   const userId: string = regOpts.data.user.id;
   const emulator = getWebAuthnEmulator(false, 'hmac-secret-mc');
   const userCred = getRandom(cc.USERCRED_BYTES);
   const { attestation, prfOutput } = createCredential(
      emulator,
      {
         ...regOpts.data,
         user: { ...regOpts.data.user, id: userId },
         challenge: regOpts.data.challenge,
      },
      true,
   );
   const recoveryId = getRandom(RECOVERYID_BYTES);
   const secret = recoverySecret(recoveryId, userId);

   const body: RequestTypes.RegVerify = {
      ...attestation,
      userId,
      challenge: regOpts.data.challenge,
      passkeyUserCredEnc: await prfEncrypt(userCred.slice(0), prfOutput.slice(0), userId),
      recoveryUserCredEnc: await prfEncrypt(userCred.slice(0), secret.slice(0), userId),
      userCredPubKey: bytesToBase64(getUserCredPubKey(userCred)),
      recoveryPubKey: bytesToBase64(getRecoveryPubKey(secret)),
   };
   return { userId, body, emulator, userCred, recoverySecret: secret, recoveryId, prfOutput };
}
