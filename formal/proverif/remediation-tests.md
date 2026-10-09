# Remediation tests

These are unit tests for fixes that the models motivate. Each test is ready to use but is not in
the source tree yet, because the code fixes ship separately. Each test fails against the code as it
stands. Restore a test together with its fix, and confirm it fails before the fix is applied.

## I-01: the browser accepts any user id the server names

**Where it goes:** `apps/web/src/app/services/authenticator.service.spec.ts`. Paste the block inside
the top-level `describe('AuthenticatorService', ...)`, directly after `describe('session user
binding', ...)`. It uses that file's existing fixtures and imports: `userId`, `pkId`, `userCred`,
`sessionResponse`, `fetchMock`, `primeLocalStorage`, `cc`, `api`, `entropyToMnemonic` and
`wordlist`.

**What each test shows.** Each test first runs a flow with matching user ids, which proves the
setup is valid. It then repeats the flow while the server names a different user id:

| Test | Server response that names another user | Result on current code |
|---|---|---|
| sign-in | `auth/verify` | reauthentication succeeds and signs the browser in to the server's account |
| registration | `reg/verify` | `newUser` succeeds and signs in to the server's account |
| add passkey | `passkeys/options` | a passkey is created with the server's user id as its user handle |
| recovery | `recover/confirm` | a passkey is created for the server's user id, not the one in the recovery words |

All four failed on 2026-10-09, each at the mismatch step and never in its matching-id run.

**Fix these tests drive** (I-01 in `conformance.md`). Halt (`_halt`) on any mismatch:

- `_createSessionImpl`: after `auth/verify`, when the response is verified and its `userId`
  differs from `verifyBody.response.userHandle`. The check sits inside the existing `try`, so the
  `catch` wipes `prfKey`.
- `newUser`: after `reg/verify`, when `serverLoginUserInfo.userId` differs from the `userId` taken
  from the registration options.
- `addPasskey`: before `_startRegistration`, when `optionsJson.user.id` differs from `this.userId`.
  `_startRegistration` overwrites `user.id` with the encoded handle, so the comparison has to come
  first.
- `_finishRecovery`: before `_startRegistration`, wipe `userCred` and halt when `regOptions.user.id`
  differs from the recovery words' user id. After `recover/verify`, halt when the returned
  `userId` differs.

The `recover/verify` check has no test yet. The recovery test stops at the passkey ceremony.

```ts
   describe('server user binding', () => {
      const hasWebAuthn = !!window.PublicKeyCredential && !!navigator.credentials;

      function otherUserId(): string {
         return bytesToBase64(getRandom(cc.USERID_BYTES));
      }

      function regOptions(id: string): api.RegOptionsResponse {
         return {
            rp: { name: 'Quick Crypt', id: window.location.hostname },
            user: { id, name: 'test-user', displayName: 'test-user' },
            challenge: bytesToBase64(getRandom(api.CHALLENGE_BYTES)),
            pubKeyCredParams: [{ alg: -7, type: 'public-key' }],
         };
      }

      // An assertion from a passkey whose user handle names userId
      function assertionForUser(): Credential {
         return {
            id: pkId,
            rawId: base64ToBytes(pkId).buffer,
            type: 'public-key',
            authenticatorAttachment: 'platform',
            response: {
               authenticatorData: new Uint8Array(37).buffer,
               clientDataJSON: new Uint8Array(1).buffer,
               signature: new Uint8Array(1).buffer,
               userHandle: new TextEncoder().encode(userId).buffer,
            },
            getClientExtensionResults: () => ({}),
         } as unknown as Credential;
      }

      // A newly created passkey without PRF output
      function attestation(): Credential {
         return {
            id: pkId,
            rawId: base64ToBytes(pkId).buffer,
            type: 'public-key',
            authenticatorAttachment: 'platform',
            response: {
               attestationObject: new Uint8Array(1).buffer,
               clientDataJSON: new Uint8Array(1).buffer,
               getTransports: () => ['internal'],
               getPublicKey: () => new Uint8Array(1).buffer,
               getPublicKeyAlgorithm: () => -7,
               getAuthenticatorData: () => new Uint8Array(37).buffer,
            },
            getClientExtensionResults: () => ({}),
         } as unknown as Credential;
      }

      it.skipIf(!hasWebAuthn)('halts when sign-in names a different user than the passkey', async () => {
         let verifyUserId = userId;
         fetchMock.mockImplementation((url: URL) => ({
            ok: true,
            json: async () =>
               url.pathname.endsWith('/auth/options')
                  ? { challenge: bytesToBase64(getRandom(api.CHALLENGE_BYTES)) }
                  : { ...sessionResponse, userId: verifyUserId },
         }));
         vi.spyOn(navigator.credentials, 'get').mockResolvedValue(assertionForUser());

         await service.createSession();
         expect(service.hasSession()).toBe(true);
         expect(service.halted).toBe(false);

         verifyUserId = otherUserId();
         await expect(service.reauthenticate()).rejects.toThrow();
         expect(service.halted).toBe(true);
      });

      it.skipIf(!hasWebAuthn)('halts when registration verify names a different user', async () => {
         const newUserId = bytesToBase64(getRandom(cc.USERID_BYTES));
         let verifyUserId = newUserId;
         fetchMock.mockImplementation((url: URL) => ({
            ok: true,
            json: async () =>
               url.pathname.endsWith('/reg/options') ? regOptions(newUserId) : { ...sessionResponse, userId: verifyUserId },
         }));
         vi.spyOn(navigator.credentials, 'create').mockResolvedValue(attestation());

         await service.newUser('test-user', async () => 'standard');
         expect(service.userId).toBe(newUserId);
         expect(service.halted).toBe(false);

         verifyUserId = otherUserId();
         await expect(service.newUser('test-user', async () => 'standard')).rejects.toThrow();
         expect(service.halted).toBe(true);
      });

      it.skipIf(!hasWebAuthn)('halts when add-passkey options name a different user', async () => {
         primeLocalStorage();
         // @ts-expect-error — exercising private path
         await service._loginUser(sessionResponse, base64ToBytes(userCred));
         let optionsUserId = userId;
         fetchMock.mockImplementation((url: URL) => ({
            ok: true,
            json: async () => (url.pathname.endsWith('/passkeys/options') ? regOptions(optionsUserId) : sessionResponse),
         }));
         const createSpy = vi.spyOn(navigator.credentials, 'create').mockRejectedValue(new Error('stopped'));

         await expect(service.addPasskey()).rejects.toThrow('stopped');
         expect(service.halted).toBe(false);

         optionsUserId = otherUserId();
         createSpy.mockClear();
         await expect(service.addPasskey()).rejects.toThrow();
         expect(createSpy).not.toHaveBeenCalled();
         expect(service.halted).toBe(true);
      });

      it.skipIf(!hasWebAuthn)('halts when recovery names a different user than the recovery words', async () => {
         const recoveryWords = entropyToMnemonic(api.recoverySecret(getRandom(api.RECOVERYID_BYTES), userId), wordlist);
         let confirmUserId = userId;
         fetchMock.mockImplementation((url: URL) => ({
            ok: true,
            json: async () =>
               url.pathname.endsWith('/recover3')
                  ? { prf: false, challenge: bytesToBase64(getRandom(api.CHALLENGE_BYTES)), userCred }
                  : regOptions(confirmUserId),
         }));
         const createSpy = vi.spyOn(navigator.credentials, 'create').mockRejectedValue(new Error('stopped'));

         await expect(service.recover3(recoveryWords)).rejects.toThrow('stopped');
         expect(service.halted).toBe(false);

         confirmUserId = otherUserId();
         createSpy.mockClear();
         await expect(service.recover3(recoveryWords)).rejects.toThrow();
         expect(createSpy).not.toHaveBeenCalled();
         expect(service.halted).toBe(true);
      });
   });
```
