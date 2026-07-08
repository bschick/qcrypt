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

import crypto from "crypto";
import WebAuthnEmulator, { AuthenticatorEmulator, PasskeysCredentialsFileRepository, type HmacSecretMode } from "nid-webauthn-emulator";
import { signUserCredProof, getUserCredPubKey, getRecoveryPubKey, recoverySecret, RECOVERYID_BYTES } from "@qcrypt/api";
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
} from "@qcrypt/crypto";
import * as cc from "@qcrypt/crypto/consts";
import { expect } from "vitest";

// ----- Setup -----
export const API_SERVER = process.env.QC_ENV === 'prod' ? "https://quickcrypt.org" : "https://test.quickcrypt.org";
export const RP_ORIGIN = process.env.QC_ENV === 'prod' ? "https://quickcrypt.org" : "https://t1.quickcrypt.org:4200";

// ----- Helpers -----
export const sha256Hex = (buf: Buffer): string => crypto.createHash("sha256").update(buf).digest("hex");

// Mirrors a browser that holds one userCred for the whole session.
let sessionUserCred: string | undefined;
let sessionUserId: string | undefined;

export function setSessionUserCred(userCred: string | undefined, userId?: string): void {
   sessionUserCred = userCred;
   sessionUserId = userId;
}

async function proofHeaders(
   method: string,
   path: string,
   body: Buffer | undefined
): Promise<Record<string, string>> {
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
   opts: { timestampMs?: string; tamperSig?: boolean; nonce?: string } = {}
): Promise<Record<string, string>> {
   await cryptoReady();
   const timestamp = opts.timestampMs ?? String(Date.now());
   const nonce = opts.nonce ?? Buffer.from(getRandom(32)).toString("base64url");
   const bodyHashHex = sha256Hex(body ?? Buffer.alloc(0));

   // Sign the decoded path. The server verifies (event.requestContext.http.path), not the
   // re-encoded URL pathname.
   const pathname = path.split("?")[0];
   const signature = signUserCredProof(
      Buffer.from(userCred, "base64url"),
      userId,
      method,
      pathname,
      timestamp,
      nonce,
      bodyHashHex
   );

   const sigBytes = Buffer.from(signature);
   if (opts.tamperSig) {
      sigBytes[0] ^= 0x01;
   }
   const sigStr = sigBytes.toString("base64url");

   return {
      "x-proof": `${sigStr},${timestamp},${nonce}`
   };
}


export function getWebAuthnEmulator(
   persistent: boolean = false,
   hmacSecret: HmacSecretMode = "none"
): WebAuthnEmulator {
   let emulator: WebAuthnEmulator;

   if (!persistent && hmacSecret === "none") {
      emulator = new WebAuthnEmulator();
   } else {
      const auth = new AuthenticatorEmulator({
         transports: ['internal'],
         hmacSecret,
         ...(persistent
            ? { credentialsRepository: new PasskeysCredentialsFileRepository("apps/server/spec/credentials") }
            : {})
      });
      emulator = new WebAuthnEmulator(auth);
   }

   return emulator;
}

// Fixed PRF salt, mirrors apps/web/src/app/services/prf.ts (SHA-256 of "qcrypt/prf/v1").
// Sent to the emulator as the WebAuthn PRF eval.first input; never change it.
export const PRF_SALT = new Uint8Array([
   135, 160, 31, 62, 121, 231, 107, 36, 153, 237, 167, 166, 197, 60, 242, 199,
   130, 254, 201, 171, 58, 139, 70, 172, 87, 190, 17, 210, 6, 26, 99, 120,
]);

// The emulator's JSON API expects/returns PRF values as base64url text.
const PRF_SALT_INPUT = bytesToBase64(PRF_SALT);
export const PRF_EXTENSION = { prf: { eval: { first: PRF_SALT_INPUT } } };

// Reads the PRF output (results.first) from a credential's client extension results,
// which the emulator's JSON API base64url-encodes. Returns null when no output is
// present (hmac-secret at registration time, before the Case B follow-up assertion).
export function readPrfOutput(clientExtensionResults: any): Uint8Array<ArrayBuffer> | null {
   const first = clientExtensionResults?.prf?.results?.first;
   let output: Uint8Array<ArrayBuffer> | null = null;
   if (first) {
      output = base64ToBytes(first);
      if (output.byteLength !== cc.KEY_BYTES) {
         throw new Error('unexpected PRF output length: ' + output.byteLength);
      }
   }
   return output;
}

// Encrypt a client-generated userCred under a 32-byte key (a PRF output or the recovery
// secret), matching the web client's ciphertext construction. Takes ownership of and wipes key.
export async function prfEncrypt(
   plainText: Uint8Array<ArrayBuffer>,
   key: Uint8Array<ArrayBuffer>,
   userId: string
): Promise<string> {
   try {
      const keyProvider = new MasterKeyKeyProvider(key, userId);
      const cipherData = await readStreamAll(
         await encryptStream(streamFromBytes(plainText), keyProvider, { algs: ['X20-PLY'] })
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
   userId: string
): Promise<Uint8Array<ArrayBuffer>> {
   try {
      const keyProvider = new MasterKeyKeyProvider(key, userId);
      return await readStreamAll(await decryptStream(streamFromBase64(cipherText), keyProvider));
   } finally {
      key.fill(0);
   }
}

async function request(
   method: string,
   path: string,
   bodyObj: any = null,
   extraHeaders: Record<string, string> = {},
   cookie = "",
) {

   const headers: Record<string, string> = {
      ...extraHeaders,
      // QCTestClient marker lets the server's PWTesty_ prefix guard recognize
      // these vitest specs as a known test client.
      "User-Agent": "Mozilla/5.0 QCTestClient",
      "Origin": RP_ORIGIN
   };

   if (cookie) headers["Cookie"] = cookie;

   let body;
   if (bodyObj) {
      const json = JSON.stringify(bodyObj);
      body = Buffer.from(json, "utf8");
      headers["Content-Type"] = "application/json";
      headers["x-amz-content-sha256"] = sha256Hex(body);
   }

   if (cookie) {
      Object.assign(headers, await proofHeaders(method, path, body));
   }

   const res = await fetch(`${API_SERVER}${path}`, { method, headers: headers, body });
   const raw = await res.text();


   let data: any;
   try { data = JSON.parse(raw); } catch { data = undefined; }

   let responseCookie = '';
   const match = /(__Host-JWT=.+?);/.exec(res.headers.getSetCookie()[0]);
   if (match && match[1]) {
      responseCookie = match[1];
   }

   return { status: res.status, data, cookie: responseCookie, rawText: raw };
}

export const postJson = (p: string, b: any, h: any, c: string) => request("POST", p, b, h, c);
export const getJson = (p: string, h: any, c: string) => request("GET", p, null, h, c);
export const putJson = (p: string, b: any, h: any, c: string) => request("PUT", p, b, h, c);
export const patchJson = (p: string, b: any, h: any, c: string) => request("PATCH", p, b, h, c);
export const deleteJson = (p: string, h: any, c: string) => request("DELETE", p, null, h, c);

// Register a fresh user (reg/options + reg/verify) and return everything needed to make
// authorized, proof-signed requests. Like the real client, the recovery secret is
// generated here and only its public key is sent; the secret is returned for recovery
// flows. The emulator is returned so callers can drive later auth/assertion flows.
export async function registerTestUser(
   userName: string
): Promise<{
   userId: string;
   userCred: string;
   cookie: string;
   csrf: string;
   credId: string;
   emulator: WebAuthnEmulator;
   recoverySecret: Uint8Array;
   recoveryId: Uint8Array;
}> {
   await cryptoReady();
   const regOpts = await postJson("/v1/reg/options", { userName }, {}, "");
   expect(regOpts.status).toBe(200);
   expect(regOpts.data.user.name).toBe(userName);

   const userId: string = regOpts.data.user.id;
   const emulator = getWebAuthnEmulator();

   const attestation = emulator.createJSON(RP_ORIGIN, {
      ...regOpts.data,
      user: { ...regOpts.data.user, id: userId },
      challenge: regOpts.data.challenge,
   });

   let recoveryId = getRandom(RECOVERYID_BYTES);
   let secret = recoverySecret(recoveryId, userId);
   const verifyBody: Record<string, any> = { ...attestation, userId, challenge: regOpts.data.challenge };
   let params = "usercred=true";
   verifyBody.recoveryPubKey = bytesToBase64(getRecoveryPubKey(secret));

   const verifyRes = await postJson(`/v1/reg/verify?${params}`, verifyBody, {}, "");
   expect(verifyRes.status).toBe(200);
   expect(verifyRes.data.verified).toBe(true);
   expect(verifyRes.data.csrf).toBeDefined();
   expect(verifyRes.data.pkId).toBeDefined();
   expect(verifyRes.data.userCred).toBeDefined();
   expect(verifyRes.cookie).toBeTruthy();

   return {
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

// Register a fresh PRF account: the client generates userCred locally, obtains a PRF output
// from the passkey, and sends only opaque ciphertexts (the server never sees plaintext userCred).
// hmac-secret-mc returns the PRF output during registration; hmac-secret returns it only during
// an assertion, so a local follow-up assertion reads it. Returns the known plaintext userCred so
// callers can verify that a later login decrypts back to it.
export async function registerPrfTestUser(
   userName: string,
   hmacSecret: "hmac-secret" | "hmac-secret-mc" = "hmac-secret-mc"
): Promise<{
   userId: string;
   userCred: string;
   cookie: string;
   csrf: string;
   credId: string;
   emulator: WebAuthnEmulator;
   recoverySecret: Uint8Array;
   recoveryId: Uint8Array;
   passkeyUserCredEnc: string;
   prfCase: 'create' | 'assert';
}> {
   await cryptoReady();
   const regOpts = await postJson("/v1/reg/options", { userName }, {}, "");
   expect(regOpts.status).toBe(200);
   expect(regOpts.data.user.name).toBe(userName);

   const userId: string = regOpts.data.user.id;
   const emulator = getWebAuthnEmulator(false, hmacSecret);

   const userCred = getRandom(cc.USERCRED_BYTES);

   const attestation = emulator.createJSON(RP_ORIGIN, {
      ...regOpts.data,
      user: { ...regOpts.data.user, id: userId },
      challenge: regOpts.data.challenge,
      extensions: PRF_EXTENSION,
   });

   let prfOutput = readPrfOutput(attestation.clientExtensionResults);
   let prfCase: 'create' | 'assert' = 'create';
   if (!prfOutput) {
      // hmac-secret returns no output at registration, so read it with a local follow-up
      // assertion on the just-created credential. This assertion is never sent to the server.
      prfCase = 'assert';
      const assertion = emulator.getJSON(RP_ORIGIN, {
         challenge: bytesToBase64(getRandom(32)),
         rpId: regOpts.data.rp.id,
         allowCredentials: [{ type: 'public-key', id: attestation.id }],
         extensions: PRF_EXTENSION,
      });
      prfOutput = readPrfOutput(assertion.clientExtensionResults);
   }
   if (!prfOutput) {
      throw new Error('emulator returned no PRF output');
   }

   const recoveryId = getRandom(RECOVERYID_BYTES);
   const secret = recoverySecret(recoveryId, userId);

   const userCredPubKey = bytesToBase64(getUserCredPubKey(userCred));
   const recoveryPubKey = bytesToBase64(getRecoveryPubKey(secret));
   const passkeyUserCredEnc = await prfEncrypt(userCred.slice(0), prfOutput, userId);
   const recoveryUserCredEnc = await prfEncrypt(userCred.slice(0), secret.slice(0), userId);

   const verifyBody: Record<string, any> = {
      ...attestation,
      userId,
      challenge: regOpts.data.challenge,
      passkeyUserCredEnc,
      recoveryUserCredEnc,
      userCredPubKey,
      recoveryPubKey,
   };

   const verifyRes = await postJson(`/v1/reg/verify?usercred=true`, verifyBody, {}, "");
   expect(verifyRes.status).toBe(200);
   expect(verifyRes.data.verified).toBe(true);
   expect(verifyRes.data.prf).toBe(true);
   expect(verifyRes.data.passkeyUserCredEnc).toBeDefined();
   expect(verifyRes.data.userCred).toBeUndefined();
   expect(verifyRes.data.csrf).toBeDefined();
   expect(verifyRes.data.pkId).toBeDefined();
   expect(verifyRes.cookie).toBeTruthy();

   return {
      userId,
      userCred: bytesToBase64(userCred),
      cookie: verifyRes.cookie,
      csrf: verifyRes.data.csrf,
      credId: verifyRes.data.pkId,
      emulator,
      recoverySecret: secret,
      recoveryId,
      passkeyUserCredEnc,
      prfCase,
   };
}

