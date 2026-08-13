import { test, expect, Page, BrowserContext, type Cookie } from '@playwright/test';
import { createUserCredProof } from '@qcrypt/api';
import {
   cryptoReady,
   MasterKeyKeyProvider,
   decryptStream,
   encryptStream,
   streamFromBase64,
   streamFromBytes,
   readStreamAll,
} from '@qcrypt/crypto';
import {
   WebAuthnEmulator,
   AuthenticatorEmulator,
   BrowserInjection,
   PasskeysCredentialsMemoryRepository,
   PasskeysCredentialsFileRepository,
   type HmacSecretMode,
} from 'nid-webauthn-emulator';
import { createHash, randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

// Must match the fixed PRF salt in apps/web/src/app/services/prf.ts (NOT a secret).
const PRF_SALT = new Uint8Array([
   79, 207, 95, 76, 134, 119, 236, 52, 72, 250, 231, 99, 35, 243, 1, 169, 205, 253, 35, 140, 130, 201, 98, 86, 30, 119,
   75, 185, 138, 67, 243, 33,
]);
const PRF_SALT_B64URL = Buffer.from(PRF_SALT).toString('base64url');

// A virtual authenticator: one emulator over its own credential store. The emulator
// keeps at most one credential per userId (a second create for the same account
// evicts the first), so an account that needs two independently-usable passkeys uses
// two authenticators, one per passkey.
export type Authenticator = { emulator: WebAuthnEmulator; mode: HmacSecretMode };

// Authorized API calls require a signed proof of userCred. Cleanup is bodiless
// GET/DELETE, so the hashed body is empty.
async function proofHeaders(
   method: string,
   url: string,
   userCred: string,
   userId: string,
): Promise<Record<string, string>> {
   await cryptoReady();
   const timestamp = String(Date.now());
   const nonce = randomBytes(32).toString('base64url');
   const bodyHashHex = createHash('sha256').update('').digest('hex');
   const signature = createUserCredProof(
      Buffer.from(userCred, 'base64url'),
      userId,
      method,
      new URL(url).pathname,
      timestamp,
      nonce,
      bodyHashHex,
      new URL(url).search.slice(1),
   );
   return {
      'x-proof': `${signature},${timestamp},${nonce}`,
   };
}

// Reconstructs a PRF account's plaintext userCred, which the server never returns.
// Drives the emulator directly to read the passkey's PRF output for the fixed salt,
// then decrypts the passkeyUserCredEnc the client sent at registration.
async function recomputeUserCred(
   emulator: WebAuthnEmulator,
   origin: string,
   rpId: string,
   credentialId: string,
   passkeyUserCredEnc: string,
   userId: string,
): Promise<string> {
   await cryptoReady();
   const prfKey = readPrfKey(emulator, origin, rpId, credentialId);
   const keyProvider = new MasterKeyKeyProvider(prfKey, userId);
   const userCredBytes = await readStreamAll(await decryptStream(streamFromBase64(passkeyUserCredEnc), keyProvider));
   return Buffer.from(userCredBytes).toString('base64url');
}

function readPrfKey(
   emulator: WebAuthnEmulator,
   origin: string,
   rpId: string,
   credentialId: string,
): Uint8Array<ArrayBuffer> {
   const assertion = emulator.getJSON(origin, {
      rpId,
      challenge: randomBytes(32).toString('base64url'),
      allowCredentials: [{ id: credentialId, type: 'public-key' }],
      userVerification: 'preferred',
      extensions: { prf: { eval: { first: PRF_SALT_B64URL } } },
   });
   const prfFirst = (assertion.clientExtensionResults as { prf?: { results?: { first?: string } } }).prf?.results
      ?.first;
   if (!prfFirst) {
      throw new Error('readPrfKey: emulator returned no PRF output');
   }
   return new Uint8Array(Buffer.from(prfFirst, 'base64url'));
}

// Encrypts arbitrary bytes the way the client encrypts userCred for a passkey, so a test
// can hand a PRF account a credential that decrypts correctly but is not its own.
export async function prfEncryptForPasskey(
   emulator: WebAuthnEmulator,
   origin: string,
   rpId: string,
   credentialId: string,
   userId: string,
   plainText: Uint8Array<ArrayBuffer>,
): Promise<string> {
   await cryptoReady();
   const keyProvider = new MasterKeyKeyProvider(readPrfKey(emulator, origin, rpId, credentialId), userId);
   const cipherData = await readStreamAll(
      await encryptStream(streamFromBytes(plainText), keyProvider, { algs: ['X20-PLY'] }),
   );
   return Buffer.from(cipherData).toString('base64url');
}

export type hosts = 't1.quickcrypt.org' | 'quickcrypt.org';

// Keeper passkeys live in a gitignored directory (one emulator credential file per
// keeper per host) so the public repo can't be used to sign in to, recover, or wipe
// these persistent test accounts.
const keeperCredsDir = join(dirname(fileURLToPath(import.meta.url)), 'keeper-creds');
export const haveKeeperCreds = existsSync(keeperCredsDir);

// The credential-repository directory holding a keeper account's passkey.
export function keeperDir(host: hosts, keeper: string): string {
   return join(keeperCredsDir, host, keeper);
}

// Intended PRF account mode per keeper.
export const keeperPrf: Record<string, boolean> = {
   keeper1: false,
   keeper2: true,
};

export type CreatedTestUser = {
   userId: string;
   userName: string;
   userCred: string;
   recoveryWords: string;
   prf: boolean;
};

// Info passed to trackUser by tests that create users outside createTestUser
// (inline UI registration, direct API). Cookies+csrf are optional; if provided
// they enable the fast cleanup path.
export type TrackUserInfo = {
   userId: string;
   userName: string;
   userCred: string;
   // The registration passkey, and the authenticator holding it, so cleanup can
   // delete it and sign back in via the fallback path.
   credentialId: string;
   authenticator: Authenticator;
   fastSession?: { cookies: Cookie[]; csrf: string };
};

export type AuthFixture = {
   page: Page;
   // In-memory authenticator ('hmac-secret-mc' → PRF, 'none' → no PRF, 'hmac-secret'
   // → PRF at assertion only).
   memAuthenticator: (mode?: HmacSecretMode) => Authenticator;
   // Authenticator whose newly created passkey persists to the credential directory.
   provisionAuthenticator: (dir: string, mode: HmacSecretMode) => Authenticator;
   // Authenticator loaded read-only from a credential directory, inferring PRF from the
   // stored credential.
   loadAuthenticator: (dir: string) => Authenticator;
   // Creates a fresh PWTesty_e2e_<timestamp> user on the authenticator via the UI
   // registration flow. A 'none' authenticator hits the fallback dialog: without
   // differentAuth it takes 'standard' (same passkey, no-PRF account); with
   // differentAuth it takes 'different', discarding that passkey and registering a
   // fresh one on differentAuth. Returns signed-in on '/' (Encryption Mode visible).
   createTestUser: (authenticator: Authenticator, differentAuth?: Authenticator) => Promise<CreatedTestUser>;
   // Number of navigator.credentials.create calls the emulators have handled so far.
   credentialCreateCount: () => number;
   // Register a user created outside createTestUser. Tests doing inline
   // UI registration or direct-API user creation MUST call this so cleanup
   // can find the user.
   trackUser: (info: TrackUserInfo) => void;
   // Register an already-created passkey on an already-tracked user.
   trackPasskey: (userId: string, credentialId: string) => void;
   // Removes a tracked user so cleanup won't retry an account the test deleted itself.
   untrackUser: (userId: string) => void;
   // Runs a UI trigger that creates a passkey on the authenticator for an
   // already-tracked user ("New Passkey", recovery, etc.) — the app calls
   // navigator.credentials.create, which the authenticator fulfills — then captures
   // the verify response for the new credentialId and registers it.
   addPasskey: (userId: string, authenticator: Authenticator, trigger: () => Promise<void>) => Promise<string>;
   // Directs the next create at the authenticator and runs a UI trigger the client
   // is expected to refuse (e.g. a no-PRF passkey on a PRF account), which never
   // reaches the server. Nothing is created or tracked; the caller asserts the error.
   expectPasskeyRejected: (authenticator: Authenticator, trigger: () => Promise<void>) => Promise<void>;
   // Runs a UI trigger that signs in using the authenticator and waits for the
   // server to verify the assertion. Pass opts.page for a sign-in driven from a tab
   // other than the fixture page; opts.awaitVerify=false for error-path triggers that
   // never reach /auth/verify.
   passkeyAuth: (
      authenticator: Authenticator,
      trigger: () => Promise<void>,
      opts?: { page?: Page; awaitVerify?: boolean },
   ) => Promise<void>;
};

type TrackedUser = {
   userId: string;
   userName: string;
   userCred: string;
   // The emulator holding the registration passkey, used by the cleanup fallback
   // to sign back in.
   emulator: WebAuthnEmulator;
   // Passkey credentialIds known to belong to this user. Mutated as cleanup
   // deletes them. The first entry is the registration PK.
   credentialIds: string[];
   // Registration-time session, used by the fast cleanup path. Absent for
   // users tracked late (e.g., via trackUser without cookies).
   fastSession?: { cookies: Cookie[]; csrf: string };
};

export const testWithAuth = test.extend<{ authFixture: AuthFixture }>({
   authFixture: async ({ page }, use, testInfo) => {
      const baseURL = (testInfo.project.use as { baseURL: string }).baseURL;
      const apiUrl = (testInfo.project.use as { apiURL: string }).apiURL;
      const origin = new URL(baseURL).origin;
      const rpId = new URL(baseURL).hostname;

      // Buffer browser console.error + uncaught page errors (across every tab,
      // including ones a test opens later) and dump them only if the test fails, so
      // a failure shows the client-side cause without spamming passing runs.
      const browserErrors: string[] = [];
      const watchConsole = (watched: Page) => {
         watched.on('console', (msg) => {
            if (msg.type() === 'error' && !msg.text().includes('WebSocket connection to')) {
               browserErrors.push(`[console.error] ${msg.text()}`);
            }
         });
         watched.on('pageerror', (err) => {
            browserErrors.push(`[pageerror] ${err.message}`);
         });
      };
      page.context().pages().forEach(watchConsole);
      page.context().on('page', watchConsole);

      // Route navigator.credentials to whichever emulator the current operation
      // selected. Each operation sets `active` before triggering its ceremony.
      let active: WebAuthnEmulator | undefined;
      let createCount = 0;
      const makeAuthenticator = (
         mode: HmacSecretMode,
         repo: PasskeysCredentialsMemoryRepository | PasskeysCredentialsFileRepository,
      ): Authenticator => {
         const emulator = new WebAuthnEmulator(
            new AuthenticatorEmulator({ hmacSecret: mode, credentialsRepository: repo }),
         );
         active ??= emulator;
         return { emulator, mode };
      };
      const memAuthenticator = (mode: HmacSecretMode = 'hmac-secret-mc'): Authenticator =>
         makeAuthenticator(mode, new PasskeysCredentialsMemoryRepository());
      const provisionAuthenticator = (dir: string, mode: HmacSecretMode): Authenticator =>
         makeAuthenticator(mode, new PasskeysCredentialsFileRepository(dir));
      // Runs against an in-memory copy of the stored credential to prevent sign-ins from
      // updating the persisted keeper file, working around a nid FileRepository bug where
      // its async unlink can race a sync write and drop the credential.
      const loadAuthenticator = (dir: string): Authenticator => {
         const stored = new PasskeysCredentialsFileRepository(dir).loadCredentials();
         if (stored.length === 0) {
            throw new Error(`loadAuthenticator: no credential in ${dir}`);
         }
         const repo = new PasskeysCredentialsMemoryRepository();
         for (const cred of stored) {
            repo.saveCredential(cred);
         }
         const mode: HmacSecretMode = stored.some((cred) => cred.publicKeyCredentialSource.credRandom !== undefined)
            ? 'hmac-secret-mc'
            : 'none';
         return makeAuthenticator(mode, repo);
      };

      const context: BrowserContext = page.context();
      await context.exposeFunction(
         BrowserInjection.WebAuthnEmulatorCreate,
         (optionsJSON: Parameters<WebAuthnEmulator['createJSON']>[1]) => {
            if (!active) {
               throw new Error('no authenticator selected');
            }
            createCount++;
            return active.createJSON(origin, optionsJSON);
         },
      );
      await context.exposeFunction(
         BrowserInjection.WebAuthnEmulatorGet,
         (optionsJSON: Parameters<WebAuthnEmulator['getJSON']>[1]) => {
            if (!active) {
               throw new Error('no authenticator selected');
            }
            return active.getJSON(origin, optionsJSON);
         },
      );
      // Guarded because addInitScript also runs on about:blank, where
      // navigator.credentials is undefined and the hook would throw.
      await context.addInitScript(`if (window.navigator?.credentials) { ${BrowserInjection.HookWebAuthnApis} }`);

      const trackedUsers: TrackedUser[] = [];

      const createTestUser = async (
         authenticator: Authenticator,
         differentAuth?: Authenticator,
      ): Promise<CreatedTestUser> => {
         active = authenticator.emulator;
         const userName = `PWTesty_e2e_${Date.now()}`;
         await page.goto('/');

         const verifyPromise = page.waitForResponse(
            (r) => r.url().includes('/v1/reg/verify') && r.request().method() === 'POST',
         );
         await page.getByRole('button', { name: 'I am new to Quick Crypt' }).click();
         await expect(page.getByRole('heading', { name: 'Create A New user' })).toBeVisible({ timeout: 10000 });
         await page.locator('input#userName').fill(userName);
         await page.getByRole('button', { name: /Create new/ }).click();
         if (authenticator.mode === 'none') {
            // No PRF from the authenticator → the client offers the fallback dialog.
            await expect(page.getByRole('heading', { name: /doesn't support local key creation/ })).toBeVisible({
               timeout: 10000,
            });
            if (differentAuth) {
               active = differentAuth.emulator;
               await page.getByRole('button', { name: 'Try a different passkey' }).click();
            } else {
               await page.getByRole('button', { name: 'Continue with standard protection' }).click();
            }
         }
         // The emulator that produced the account's passkey (differentAuth's after a
         // 'different' fallback, otherwise the original).
         const finalEmulator = active;

         const verifyResp = await verifyPromise;
         const reqBody = JSON.parse((await verifyResp.request().postData()) ?? '{}');
         const body = await verifyResp.json();
         if (!body.userId || !body.csrf || !body.pkId) {
            throw new Error('createTestUser: missing userId/csrf/pkId in /reg/verify response');
         }

         const userCred = body.prf
            ? await recomputeUserCred(finalEmulator, origin, rpId, body.pkId, reqBody.passkeyUserCredEnc, body.userId)
            : body.userCred;
         if (!userCred) {
            throw new Error('createTestUser: could not determine userCred');
         }

         // Track the user the moment it exists server-side, before the
         // post-creation UI assertions — a slow-network failure in those would
         // otherwise leak it past cleanup.
         trackedUsers.push({
            userId: body.userId,
            userName,
            userCred,
            emulator: finalEmulator,
            credentialIds: [body.pkId],
            fastSession: {
               cookies: await context.cookies(),
               csrf: body.csrf,
            },
         });

         await expect(page).toHaveURL(/\/showrecovery$/, { timeout: 10000 });
         await expect(page.getByRole('heading', { name: 'Account Backup and Recovery' })).toBeVisible({
            timeout: 10000,
         });
         const recoveryWords = await page.locator('textarea#wordsArea').inputValue();
         await page.getByRole('button', { name: /I saved my/ }).click();
         await expect(page).toHaveURL(/\/$/);
         await expect(page.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({ timeout: 10000 });
         return { userId: body.userId, userName, userCred, recoveryWords, prf: !!body.prf };
      };

      const trackUser = (info: TrackUserInfo): void => {
         if (trackedUsers.some((user) => user.userId === info.userId)) {
            throw new Error(`trackUser: userId ${info.userId} already tracked`);
         }
         trackedUsers.push({
            userId: info.userId,
            userName: info.userName,
            userCred: info.userCred,
            emulator: info.authenticator.emulator,
            credentialIds: [info.credentialId],
            fastSession: info.fastSession,
         });
      };

      const trackPasskey = (userId: string, credentialId: string): void => {
         const user = trackedUsers.find((tracked) => tracked.userId === userId);
         if (!user) {
            throw new Error(`trackPasskey: userId ${userId} not tracked`);
         }
         user.credentialIds.push(credentialId);
      };

      const untrackUser = (userId: string): void => {
         const index = trackedUsers.findIndex((tracked) => tracked.userId === userId);
         if (index === -1) {
            throw new Error(`untrackUser: userId ${userId} not tracked`);
         }
         trackedUsers.splice(index, 1);
      };

      const addPasskey = async (
         userId: string,
         authenticator: Authenticator,
         trigger: () => Promise<void>,
      ): Promise<string> => {
         active = authenticator.emulator;
         const verifyPromise = page.waitForResponse(
            (r) =>
               (r.url().includes('/v1/passkeys/verify') ||
                  r.url().includes('/v1/reg/verify') ||
                  r.url().includes('/v1/recover/verify')) &&
               r.request().method() === 'POST',
         );
         await trigger();
         const body = await (await verifyPromise).json();
         if (!body.pkId) {
            throw new Error(`addPasskey: missing pkId in verify response for ${userId}`);
         }
         trackPasskey(userId, body.pkId);
         return body.pkId;
      };

      const expectPasskeyRejected = async (
         authenticator: Authenticator,
         trigger: () => Promise<void>,
      ): Promise<void> => {
         active = authenticator.emulator;
         await trigger();
      };

      const passkeyAuth = async (
         authenticator: Authenticator,
         trigger: () => Promise<void>,
         opts: { page?: Page; awaitVerify?: boolean } = {},
      ): Promise<void> => {
         const targetPage = opts.page ?? page;
         const awaitVerify = opts.awaitVerify ?? true;
         active = authenticator.emulator;
         const verifyPromise: Promise<unknown> = awaitVerify
            ? targetPage.waitForResponse((r) => r.url().includes('/v1/auth/verify') && r.request().method() === 'POST')
            : Promise.resolve();
         await trigger();
         await verifyPromise;
      };

      await use({
         page,
         memAuthenticator,
         provisionAuthenticator,
         loadAuthenticator,
         credentialCreateCount: () => createCount,
         createTestUser,
         trackUser,
         trackPasskey,
         untrackUser,
         addPasskey,
         expectPasskeyRejected,
         passkeyAuth,
      });

      if (testInfo.status !== testInfo.expectedStatus && browserErrors.length) {
         console.log(`[browser errors] ${testInfo.title}\n${browserErrors.join('\n')}`);
      }

      // Cleanup. Fast path: restore the registration-time cookies+csrf, GET /user,
      // DELETE each passkey (active PK sorted last so the session survives until the
      // last DELETE). Fallback: sign back in through the UI on the user's authenticator
      // and delete with the fresh session.
      const originalCookies = await context.cookies();

      // Deletes every passkey the server lists for the user; the account is removed
      // with its last passkey. Returns true only if it was fully removed.
      const deleteAllPasskeys = async (
         csrf: string,
         currentPkId: string | undefined,
         userCred: string,
         userId: string,
      ): Promise<boolean> => {
         try {
            const userUrl = `${apiUrl}/user`;
            const userResp = await page.request.get(userUrl, {
               headers: {
                  'x-csrf-token': csrf,
                  Origin: origin,
                  ...(await proofHeaders('GET', userUrl, userCred, userId)),
               },
            });
            if (!userResp.ok()) {
               return false;
            }
            const user = await userResp.json();
            const auths: { credentialId: string }[] = user.authenticators ?? [];
            // Delete the current passkey last — deleting it invalidates the session.
            auths.sort(
               (left, right) => Number(left.credentialId === currentPkId) - Number(right.credentialId === currentPkId),
            );
            for (const auth of auths) {
               const delUrl = `${apiUrl}/passkeys/${auth.credentialId}`;
               const delResp = await page.request.delete(delUrl, {
                  headers: {
                     'x-csrf-token': csrf,
                     Origin: origin,
                     ...(await proofHeaders('DELETE', delUrl, userCred, userId)),
                  },
               });
               if (!delResp.ok()) {
                  return false;
               }
            }
            return auths.length > 0;
         } catch {
            return false;
         }
      };

      const fastDelete = async (user: TrackedUser): Promise<boolean> => {
         if (!user.fastSession) {
            return false;
         }
         try {
            await context.clearCookies();
            await context.addCookies(user.fastSession.cookies);
            return await deleteAllPasskeys(user.fastSession.csrf, user.credentialIds[0], user.userCred, user.userId);
         } catch {
            return false;
         }
      };

      const fallbackDelete = async (user: TrackedUser): Promise<boolean> => {
         try {
            active = user.emulator;
            await context.clearCookies();
            await page.goto('/');
            await page.evaluate(() => localStorage.clear());
            await page.reload();
            const verifyPromise = page.waitForResponse(
               (r) => r.url().includes('/v1/auth/verify') && r.request().method() === 'POST',
            );
            await page.getByRole('button', { name: /I have used Quick Crypt/ }).click();
            const verifyResp = await verifyPromise;
            if (!verifyResp.ok()) {
               return false;
            }
            const verifyBody = await verifyResp.json();
            if (!verifyBody.csrf) {
               return false;
            }
            return await deleteAllPasskeys(verifyBody.csrf, verifyBody.pkId, user.userCred, user.userId);
         } catch {
            return false;
         }
      };

      // A user still tracked here wasn't deleted by its test (that would have untracked
      // it), so surviving both the fast and fallback delete is a real leak.
      for (const user of trackedUsers) {
         const cleaned = (await fastDelete(user)) || (await fallbackDelete(user));
         if (!cleaned) {
            console.error(
               `cleanup: leaked tracked user ${user.userId} (${user.userName}) — fast and fallback both failed`,
            );
         }
      }

      await context.clearCookies();
      if (originalCookies.length > 0) {
         await context.addCookies(originalCookies);
      }
   },
});

export async function toggleCredentials(page: Page): Promise<void> {
   await page.getByRole('button', { name: 'Passkey information' }).click();
   await expect(page.locator('table.credtable tbody tr').first()).toBeVisible();
}

// Asserts the credentials sidenav PRF badge matches the account mode. Requires the
// sidenav to be open.
export async function expectPrfBadge(page: Page, prf: boolean): Promise<void> {
   const badge = page.locator('.prf-badge');
   if (prf) {
      await expect(badge).toBeVisible();
   } else {
      await expect(badge).toHaveCount(0);
   }
}

// Verifies the page's tab can complete an authenticated server call.
// Triggers the credentials sidenav Refresh and asserts the resulting
// /user request returned 200.
export async function expectActiveServerSession(page: Page, expectedUserName?: string): Promise<void> {
   if (!(await page.locator('table.credtable tbody tr').first().isVisible())) {
      await toggleCredentials(page);
   }
   const userResponse = page.waitForResponse(
      (response) => response.url().includes('/v1/user') && response.request().method() === 'GET',
   );
   await page.getByRole('button', { name: 'Refresh' }).click();
   const resp = await userResponse;
   expect(resp.status()).toBe(200);
   if (expectedUserName !== undefined) {
      await expect(page.locator('mat-sidenav input').first()).toHaveValue(expectedUserName);
   }
}

export type PasskeyReauth = (trigger: () => Promise<void>) => Promise<void>;

// The client re-authenticates before deleting an account's final passkey, so that delete only
// reaches the server when reauth runs the confirmation inside a ceremony the emulator answers.
async function confirmPasskeyDelete(
   page: Page,
   isLast: boolean,
   userName?: string,
   reauth?: PasskeyReauth,
): Promise<void> {
   if (isLast && userName) {
      await page.locator('input#confirmInput').fill(userName);
   }

   const deleted = page.waitForResponse(
      (response) => response.url().includes('/passkeys') && response.request().method() === 'DELETE',
   );
   const confirm = async () => {
      await page.getByRole('button', { name: 'Yes' }).click();
   };

   if (reauth) {
      await reauth(confirm);
   } else {
      await confirm();
   }

   const deleteResponse = await deleted;
   expect(deleteResponse.status()).toBe(200);
}

export async function deleteFirstPasskey(page: Page, userName?: string, reauth?: PasskeyReauth): Promise<void> {
   const tableBody = page.locator('table.credtable tbody');
   const count = await tableBody.locator('tr').count();

   await page.getByRole('button', { name: 'Delete' }).first().click();
   await confirmPasskeyDelete(page, count === 1, userName, reauth);
}

// Does not handle removal of last Passkey
export async function deleteLastPasskey(page: Page, userName?: string, reauth?: PasskeyReauth): Promise<void> {
   const tableBody = page.locator('table.credtable tbody');
   const count = await tableBody.locator('tr').count();

   await page.getByRole('button', { name: 'Delete' }).last().click();
   await confirmPasskeyDelete(page, count === 1, userName, reauth);
}

export async function fillPwdAndAccept(
   page: Page,
   heading: RegExp,
   pwd: string,
   hint: string | undefined,
   encDec: 'enc' | 'dec',
   ready: () => Promise<void>,
) {
   await ready();
   await expect(page.getByRole('heading', { name: heading })).toBeVisible();

   await page.locator('input#password').fill(pwd);
   if (encDec === 'enc') {
      await expect(page.getByText('Password is allowed')).toBeVisible();
   }

   if (hint) {
      if (encDec === 'enc') {
         await page.locator('input#hint').fill(hint);
      } else {
         await expect(page.locator('input#hint')).toHaveValue(hint);
      }
   }

   await page.getByRole('button', { name: 'Accept' }).click();
}
