import crypto from "crypto";
import { WebAuthnEmulator, AuthenticatorEmulator, PasskeysCredentialsFileRepository } from "nid-webauthn-emulator";

// ----- Setup -----
export const API_SERVER = process.env.QC_ENV === 'prod' ? "https://quickcrypt.org" : "https://test.quickcrypt.org";
export const RP_ORIGIN = process.env.QC_ENV === 'prod' ? "https://quickcrypt.org" : "https://t1.quickcrypt.org:4200";

// ----- Helpers -----
export const sha256Hex = (buf: Buffer): string => crypto.createHash("sha256").update(buf).digest("hex");


export function getWebAuthnEmulator(persistent: boolean = false): WebAuthnEmulator {
   const repo = new PasskeysCredentialsFileRepository("spec/credentials");
   const auth = new AuthenticatorEmulator({ credentialsRepository: repo });
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
      "User-Agent": "Mozilla/5.0",
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

