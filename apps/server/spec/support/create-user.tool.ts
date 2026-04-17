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

import {
    postJson,
    getWebAuthnEmulator,
    RP_ORIGIN
} from "./common";

jasmine.DEFAULT_TIMEOUT_INTERVAL = 60000;

describe("Create a new user, normally do not run", () => {

    // Shared state
    const testUser = `SenderLinkTest2`;
    let userId: string;
    let credId: string; // pkId
    let sessionCookie: string = "";
    let csrfToken: string = "";
    const emulator = getWebAuthnEmulator();

    it("should create and persist a new user", async () => {
        const regOpts = await postJson("/v1/reg/options", { userName: testUser }, {}, "");
        expect(regOpts.status).toBe(200);
        expect(regOpts.data.user.name).toBe(testUser);

        userId = regOpts.data.user.id;

        const attestation = emulator.createJSON(RP_ORIGIN, {
            ...regOpts.data,
            user: { ...regOpts.data.user, id: userId },
            challenge: regOpts.data.challenge,
        });

        const verifyRes = await postJson(
            `/v1/reg/verify`,
            { ...attestation, userId, challenge: regOpts.data.challenge },
            {},
            sessionCookie,
        );

        expect(verifyRes.status).toBe(200);
        expect(verifyRes.data.verified).toBe(true);
        expect(verifyRes.data.csrf).toBeDefined();
        expect(verifyRes.data.pkId).toBeDefined();
        expect(verifyRes.cookie).toBeTruthy();

        sessionCookie = verifyRes.cookie;
        csrfToken = verifyRes.data.csrf;
        credId = verifyRes.data.pkId;
    });
});
