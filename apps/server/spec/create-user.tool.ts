import {
    postJson,
    getWebAuthnEmulator,
    RP_ORIGIN
} from "./common.ts";

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
            `/v1/users/${userId}/reg/verify`,
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
