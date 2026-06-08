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
import { WebAuthnEmulator, AuthenticatorEmulator, PasskeysCredentialsFileRepository } from "nid-webauthn-emulator";
import { signUserCredProof } from "@qcrypt/api";
import { cryptoReady } from "@qcrypt/crypto";
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
   opts: { timestampMs?: string; tamperSig?: boolean } = {}
): Promise<Record<string, string>> {
   await cryptoReady();
   const timestamp = opts.timestampMs ?? String(Date.now());
   const bodyHashHex = sha256Hex(body ?? Buffer.alloc(0));
   // Sign the decoded path the server verifies (event.requestContext.http.path), not the
   // re-encoded URL pathname, so proofs still match when a path carries odd characters.
   const pathname = path.split("?")[0];
   const signature = signUserCredProof(
      Buffer.from(userCred, "base64url"),
      userId,
      method,
      pathname,
      timestamp,
      bodyHashHex
   );
   const sigBytes = Buffer.from(signature);
   if (opts.tamperSig) {
      sigBytes[0] ^= 0x01;
   }
   return {
      "x-proof-sig": sigBytes.toString("base64url"),
      "x-proof-ts": timestamp
   };
}


export function getWebAuthnEmulator(persistent: boolean = false): WebAuthnEmulator {
   const repo = new PasskeysCredentialsFileRepository("apps/server/spec/credentials");
   const auth = new AuthenticatorEmulator({
      credentialsRepository: repo,
      transports: ['internal']
   });
   return persistent ? new WebAuthnEmulator(auth) : new WebAuthnEmulator();
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
export const patchJson = (p: string, b: any, h: any, c: string) => request("PATCH", p, b, h, c);
export const deleteJson = (p: string, h: any, c: string) => request("DELETE", p, null, h, c);

// Register a fresh user (reg/options + reg/verify with userCred) and return everything
// needed to make authorized, proof-signed requests. The emulator is returned so callers
// can drive later auth/assertion flows with the same credential.
export async function registerTestUser(userName: string): Promise<{
   userId: string;
   userCred: string;
   cookie: string;
   csrf: string;
   credId: string;
   emulator: WebAuthnEmulator;
}> {
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

   const verifyRes = await postJson(
      "/v1/reg/verify?usercred=true",
      { ...attestation, userId, challenge: regOpts.data.challenge },
      {},
      ""
   );
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
   };
}

