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

import * as fs from 'fs';
import * as path from 'path';
import { describe, it, expect } from 'vitest';
import { entropyToMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import {
    postJson,
    getWebAuthnEmulator,
    RP_ORIGIN,
} from "../common";

function base64ToBytes(base64: string): Uint8Array {
    return new Uint8Array(Buffer.from(base64, 'base64'));
}

function base64UrlToBase64(base64Url: string): string {
    let b64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4 !== 0) b64 += '=';
    return b64;
}

// Playwright's CDP virtual authenticator expects standard Base64 encoding. While standard
// credential attributes like credentialId are just byte arrays, qcrypt's authenticator.service.ts
// decodes the userHandle bytes as UTF-8 string bytes to maintain backward compatibility with older
// simplewebauthn versions.
function stringToUTF8Base64(str: string): string {
    return Buffer.from(str, 'utf8').toString('base64');
}

function findCredentialValues(userName: string): any {
    const credsDir = path.join(process.cwd(), 'apps', 'server', 'spec', 'credentials');
    if (!fs.existsSync(credsDir)) return null;

    for (const file of fs.readdirSync(credsDir)) {
        if (!file.endsWith('.json')) continue;
        const data = JSON.parse(fs.readFileSync(path.join(credsDir, file), 'utf8'));
        if (data.user?.name === userName) {
            return data.publicKeyCredentialSource;
        }
    }
    return null;
}

describe("Create a new user, normally do not run", () => {

    // Shared state
    const testUser = `KeeperNew${Date.now()}`;
    let userId: string;
    let credId: string; // pkId
    let sessionCookie: string = "";
    let csrfToken: string = "";
    const emulator = getWebAuthnEmulator(true);

    it("should create and persist a new user", async () => {
        const regOpts = await postJson("/v1/reg/options", { userName: testUser }, {}, "");
        expect(regOpts.status).toBe(200);
        expect(regOpts.data.user.name).toBe(testUser);

        userId = regOpts.data.user.id;
        sessionCookie = regOpts.cookie;
        csrfToken = regOpts.data.csrf;

        const attestation = emulator.createJSON(RP_ORIGIN, {
            ...regOpts.data,
            user: { ...regOpts.data.user, id: userId },
            challenge: regOpts.data.challenge,
        });

        // The backend recognizes this as an 'internal' transport
        // as configured in the emulator via getWebAuthnEmulator.

        const verifyRes = await postJson(
            `/v1/reg/verify?usercred=true&recovery=true`,
            { ...attestation, userId, challenge: regOpts.data.challenge },
            { "x-csrf-token": csrfToken },
            sessionCookie,
        );

        expect(verifyRes.status).toBe(200);
        expect(verifyRes.data.verified).toBe(true);

        sessionCookie = verifyRes.cookie;
        csrfToken = verifyRes.data.csrf;
        credId = verifyRes.data.pkId;

        const { recoveryId, userCred } = verifyRes.data;

        const recoveryIdBytes = base64ToBytes(recoveryId);
        const userIdBytes = base64ToBytes(userId);
        const recoveryBytes = new Uint8Array(recoveryIdBytes.byteLength + userIdBytes.byteLength);
        recoveryBytes.set(recoveryIdBytes, 0);
        recoveryBytes.set(userIdBytes, recoveryIdBytes.byteLength);

        const words = entropyToMnemonic(recoveryBytes, wordlist);

        const credValues = findCredentialValues(testUser) || {
            id: "NOT_FOUND", rpId: "NOT_FOUND", privateKey: "NOT_FOUND", userHandle: "NOT_FOUND"
        };

        const block = `
const NEW_CRED_local: Credential = {
  credentialId: '${base64UrlToBase64(credValues.id)}',
  isResidentCredential: true,
  rpId: '${credValues.rpId}',
  privateKey: '${base64UrlToBase64(credValues.privateKey)}',
  userHandle: '${stringToUTF8Base64(credValues.userHandle)}',
  signCount: 0,
  backupEligibility: false,
  backupState: false,
  userName: '${testUser}'
};
const NEW_CRED_Recovery_local = "${words}";

// Insert into credentials hash:
    keeperNew: {
      id: NEW_CRED_local,
      words: NEW_CRED_Recovery_local,
      userCred: "${userCred}"
    }
`;
        console.log("================ REQUIRED VALUES FOR common.ts ================");
        console.log(block);
        console.log("===============================================================");
    });
});
