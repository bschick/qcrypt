import { test, expect, Page, CDPSession, type Cookie } from '@playwright/test';
import { Protocol } from 'devtools-protocol';
import { signUserCredProof } from '@qcrypt/api';
import { cryptoReady } from '@qcrypt/crypto';
import { createHash, randomBytes } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

export type Credential = Protocol.WebAuthn.Credential;

// Authorized API calls require a signed proof of userCred. Cleanup is bodiless
// GET/DELETE, so the hashed body is empty.
async function proofHeaders(
  method: string,
  url: string,
  userCred: string,
  userId: string
): Promise<Record<string, string>> {
  await cryptoReady();
  const timestamp = String(Date.now());
  const nonce = randomBytes(32).toString('base64url');
  const bodyHashHex = createHash('sha256').update('').digest('hex');
  const signature = signUserCredProof(
    Buffer.from(userCred, 'base64url'),
    userId,
    method,
    new URL(url).pathname,
    timestamp,
    nonce,
    bodyHashHex
  );
  const sigB64 = Buffer.from(signature).toString('base64url');
  return {
    'x-proof': `${sigB64},${timestamp},${nonce}`
  };
}

export type hosts = 't1.quickcrypt.org' | 'quickcrypt.org';

type KeeperEntry = { id: Credential; words: string };
type KeeperCreds = Record<hosts, { keeper1: KeeperEntry; keeper2: KeeperEntry }>;

// Keeper credentials live in a gitignored file so the public repo can't be used to
// sign in to, recover, or wipe these persistent test accounts.
const credsPath = join(dirname(fileURLToPath(import.meta.url)), '.creds.json');
export const haveKeeperCreds = existsSync(credsPath);
export const credentials: KeeperCreds = haveKeeperCreds
  ? JSON.parse(readFileSync(credsPath, 'utf8'))
  : ({} as KeeperCreds);

export type CreatedTestUser = {
  userId: string;
  userName: string;
  userCred: string;
  recoveryWords: string;
  credential: Credential;
};

// TODO: This has become sloppy AI generated code, which I generally don't mind for testing
// but test user leaks is a repeating problem, so this should be refactored by a human.

// A passkey owned by a tracked user. The fixture needs three things to clean
// it up: the server-side credentialId (to issue DELETE), the CDP authenticator
// holding it (so the fallback can put the credential back if the registration
// session is stale), and the CDP credential payload itself (to feed addCredential).
export type TrackedPasskey = {
  credentialId: string;
  authenticatorId: string;
  credential: Credential;
};

// Info passed to trackUser by tests that create users outside createTestUser
// (inline UI registration, direct API). Cookies+csrf are optional; if provided
// they enable the fast cleanup path.
export type TrackUserInfo = {
  userId: string;
  userName: string;
  userCred: string;
  passkey: TrackedPasskey;
  fastSession?: { cookies: Cookie[]; csrf: string };
};

export type AuthFixture = {
  page: Page;
  session: CDPSession;
  authenticatorId1: string;
  authenticatorId2: string;
  // Creates a fresh PWTesty_e2e_<timestamp> user via the UI registration flow on
  // `authenticatorId`. Returns signed-in on '/' (Encryption Mode visible).
  // The user and its initial passkey are auto-tracked.
  createTestUser: (authenticatorId: string) => Promise<CreatedTestUser>;
  // Register a user created outside createTestUser. Tests doing inline
  // UI registration or direct-API user creation MUST call this so cleanup
  // can find the user.
  trackUser: (info: TrackUserInfo) => void;
  // Register an already-created passkey on an already-tracked user. Use
  // when the passkey is created via a path that doesn't go through addPasskey
  // (e.g., direct API).
  trackPasskey: (userId: string, passkey: TrackedPasskey) => void;
  // Convenience wrapper around passkeyCreation for the common case of adding
  // a passkey to an already-tracked user via UI ("New Passkey", recovery,
  // etc.). Captures /passkeys/verify (or /reg/verify) to extract the new
  // credentialId, then registers it on the user.
  addPasskey: (
    userId: string,
    authenticatorId: string,
    trigger: () => Promise<void>
  ) => Promise<Credential>;
};

type TrackedUser = {
  userId: string;
  userName: string;
  userCred: string;
  // Passkeys we know belong to this user. Mutated as cleanup deletes them.
  // The first entry is the registration PK and is assumed to be the active
  // one for the fast-path session — fast-path delete sorts it last.
  passkeys: TrackedPasskey[];
  // Registration-time session, used by the fast cleanup path. Absent for
  // users tracked late (e.g., via trackUser without cookies).
  fastSession?: { cookies: Cookie[]; csrf: string };
};

export const testWithAuth = test.extend<{authFixture: AuthFixture}>({
  authFixture: async ({ page }, use, testInfo) => {
    // Buffer browser console.error + uncaught page errors (across every tab,
    // including ones a test opens later) and dump them only if the test fails, so
    // a failure shows the client-side cause without spamming passing runs.
    const browserErrors: string[] = [];
    const watchConsole = (watched: Page) => {
      watched.on('console', (msg) => {
        // skip vite's HMR dev-server websocket noise
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

    const session = await page.context().newCDPSession(page);
    const authenticatorId1 = await setupAuthenticator(session, page, 'internal');
    const authenticatorId2 = await setupAuthenticator(session, page, 'usb');
    const trackedUsers: TrackedUser[] = [];

    const createTestUser = async (authenticatorId: string): Promise<CreatedTestUser> => {
      const userName = `PWTesty_e2e_${Date.now()}`;
      await page.goto('/');

      const verifyPromise = page.waitForResponse((r) =>
        r.url().includes('/v1/reg/verify') && r.request().method() === 'POST'
      );
      const credential = await passkeyCreation(page, session, authenticatorId, async () => {
        await page.getByRole('button', { name: 'I am new to Quick Crypt' }).click();
        await expect(page.getByRole('heading', { name: 'Create A New user' })).toBeVisible({ timeout: 10000 });
        await page.locator('input#userName').fill(userName);
        await page.getByRole('button', { name: /Create new/ }).click();
      });
      const body = await (await verifyPromise).json();
      if (!body.userId || !body.userCred || !body.csrf || !body.pkId) {
        throw new Error('createTestUser: missing userId/userCred/csrf/pkId in /reg/verify response');
      }
      await expect(page).toHaveURL(/\/showrecovery$/);
      await expect(page.getByRole('heading', { name: 'Account Backup and Recovery' })).toBeVisible({ timeout: 10000 });
      const recoveryWords = await page.locator('textarea#wordsArea').inputValue();
      await page.getByRole('button', { name: /I saved my/ }).click();
      await expect(page).toHaveURL(/\/$/);
      await expect(page.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({ timeout: 10000 });

      trackedUsers.push({
        userId: body.userId,
        userName,
        userCred: body.userCred,
        passkeys: [{
          credentialId: body.pkId,
          authenticatorId,
          credential,
        }],
        fastSession: {
          cookies: await page.context().cookies(),
          csrf: body.csrf,
        },
      });
      return {
        userId: body.userId,
        userName,
        userCred: body.userCred,
        recoveryWords,
        credential,
      };
    };

    const trackUser = (info: TrackUserInfo): void => {
      if (trackedUsers.some(u => u.userId === info.userId)) {
        throw new Error(`trackUser: userId ${info.userId} already tracked`);
      }
      trackedUsers.push({
        userId: info.userId,
        userName: info.userName,
        userCred: info.userCred,
        passkeys: [info.passkey],
        fastSession: info.fastSession,
      });
    };

    const trackPasskey = (userId: string, passkey: TrackedPasskey): void => {
      const user = trackedUsers.find(u => u.userId === userId);
      if (!user) {
        throw new Error(`trackPasskey: userId ${userId} not tracked`);
      }
      user.passkeys.push(passkey);
    };

    const addPasskey = async (
      userId: string,
      authenticatorId: string,
      trigger: () => Promise<void>
    ): Promise<Credential> => {
      const verifyPromise = page.waitForResponse((r) =>
        (r.url().includes('/v1/passkeys/verify') || r.url().includes('/v1/reg/verify')) &&
        r.request().method() === 'POST'
      );
      const credential = await passkeyCreation(page, session, authenticatorId, trigger);
      const body = await (await verifyPromise).json();
      if (!body.pkId) {
        throw new Error(`addPasskey: missing pkId in verify response for ${userId}`);
      }
      trackPasskey(userId, {
        credentialId: body.pkId,
        authenticatorId,
        credential,
      });
      return credential;
    };

    await use({
      page,
      session,
      authenticatorId1: authenticatorId1,
      authenticatorId2: authenticatorId2,
      createTestUser,
      trackUser,
      trackPasskey,
      addPasskey,
    });

    if (testInfo.status !== testInfo.expectedStatus && browserErrors.length) {
      console.log(`[browser errors] ${testInfo.title}\n${browserErrors.join('\n')}`);
    }

    // Cleanup runs in two stages per user. Fast path: restore the
    // registration-time cookies+csrf, GET /user, DELETE each passkey
    // (active PK sorted last so the session survives until the last DELETE).
    // Fallback: iterate the user's tracked passkeys, re-auth with each in
    // turn; on success run deleteAllPasskeys with a fresh session; on 401
    // (passkey gone from server) shift to the next. Successfully-deleted PKs
    // are removed from the tracked list so the two stages compose cleanly.
    const apiUrl = (testInfo.project.use as { apiURL: string }).apiURL;
    const originalCookies = await page.context().cookies();
    const baseURL = (testInfo.project.use as { baseURL: string }).baseURL;

    const deleteAllPasskeys = async (
      csrf: string,
      currentPkId: string,
      userCred: string,
      userId: string,
      label: string
    ): Promise<boolean> => {
      const userUrl = `${apiUrl}/user`;
      const userResp = await page.request.get(
        userUrl,
        { headers: { 'x-csrf-token': csrf, 'Origin': baseURL, ...(await proofHeaders('GET', userUrl, userCred, userId)) } }
      );
      if (!userResp.ok()) {
        console.error(`${label}: GET /user failed (${userResp.status()})`);
        return false;
      }
      const user = await userResp.json();
      // Sort the current passkey last — deleting it invalidates the session
      // and any subsequent delete would 401.
      const auths: { credentialId: string }[] = user.authenticators ?? [];
      auths.sort((a, b) => Number(a.credentialId === currentPkId) - Number(b.credentialId === currentPkId));
      for (const auth of auths) {
        const delUrl = `${apiUrl}/passkeys/${auth.credentialId}`;
        const delResp = await page.request.delete(
          delUrl,
          { headers: { 'x-csrf-token': csrf, 'Origin': baseURL, ...(await proofHeaders('DELETE', delUrl, userCred, userId)) } }
        );
        if (!delResp.ok()) {
          console.error(`${label}: DELETE /passkeys/${auth.credentialId} failed (${delResp.status()})`);
        }
      }
      return true;
    };

    for (const user of trackedUsers) {
      // Fast path. Best-effort; safe to skip on any failure.
      if (user.fastSession) {
        try {
          await page.context().clearCookies();
          await page.context().addCookies(user.fastSession.cookies);

          const fastUserUrl = `${apiUrl}/user`;
          const fastResp = await page.request.get(
            fastUserUrl,
            { headers: { 'x-csrf-token': user.fastSession.csrf, 'Origin': baseURL, ...(await proofHeaders('GET', fastUserUrl, user.userCred, user.userId)) } }
          );
          if (fastResp.ok()) {
            const data = await fastResp.json();
            const auths: { credentialId: string }[] = data.authenticators ?? [];
            // The fast-path session was authenticated by the registration PK,
            // which is the first tracked passkey. Sort that last so we don't
            // kill the session before deleting the others.
            const activePkId = user.passkeys[0]?.credentialId;
            auths.sort((a, b) => Number(a.credentialId === activePkId) - Number(b.credentialId === activePkId));
            for (const auth of auths) {
              const fastDelUrl = `${apiUrl}/passkeys/${auth.credentialId}`;
              const delResp = await page.request.delete(
                fastDelUrl,
                { headers: { 'x-csrf-token': user.fastSession.csrf, 'Origin': baseURL, ...(await proofHeaders('DELETE', fastDelUrl, user.userCred, user.userId)) } }
              );
              if (delResp.ok()) {
                user.passkeys = user.passkeys.filter(p => p.credentialId !== auth.credentialId);
              } else {
                break;
              }
            }
          }
        } catch (err) {
          console.error(`cleanup: fast path threw for ${user.userId}`, err);
        }
      }

      // Fallback: iterate remaining tracked passkeys, re-auth with each.
      // 401 means that PK is gone from the server — shift and try the next.
      // A successful sign-in delegates to deleteAllPasskeys with the fresh
      // session and ends iteration.
      while (user.passkeys.length > 0) {
        const pk = user.passkeys[0];
        let cleaned = false;
        try {
          await page.context().clearCookies();
          await clearCredentials(session, pk.authenticatorId);
          await addCredential(session, pk.authenticatorId, pk.credential);

          await page.goto('/');
          await page.evaluate(() => localStorage.clear());
          await page.reload();
          await expect(page.getByRole('button', { name: /I have used Quick Crypt/ })).toBeVisible({ timeout: 10000 });

          const verifyPromise = page.waitForResponse((r) =>
            r.url().includes('/v1/auth/verify') && r.request().method() === 'POST'
          );
          await passkeyAuth(page, session, pk.authenticatorId, async () => {
            await page.getByRole('button', { name: /I have used Quick Crypt/ }).click();
          });
          const verifyResp = await verifyPromise;
          if (verifyResp.ok()) {
            const verifyBody = await verifyResp.json();
            if (verifyBody.csrf && verifyBody.pkId) {
              await deleteAllPasskeys(verifyBody.csrf, verifyBody.pkId, user.userCred, user.userId, `cleanup-fallback (${user.userId})`);
              cleaned = true;
            } else {
              console.error(`cleanup-fallback: missing csrf or pkId for ${user.userId}`);
            }
          } else if (verifyResp.status() !== 401) {
            console.error(`cleanup-fallback: /auth/verify for ${user.userId} via ${pk.credentialId} failed (${verifyResp.status()})`);
          }
        } catch (err) {
          console.error(`cleanup-fallback: failed for ${user.userId} via ${pk.credentialId}`, err);
        }

        if (cleaned) {
          user.passkeys = [];
        } else {
          user.passkeys.shift();
        }
      }
    }

    await page.context().clearCookies();
    if (originalCookies.length > 0) {
      await page.context().addCookies(originalCookies);
    }

    await removeAuthenticator(session, authenticatorId1);
    await removeAuthenticator(session, authenticatorId2);
    await session.detach();
  }
});

export async function setupAuthenticator(
  session: CDPSession, page:
  Page,
  transport: Protocol.WebAuthn.AuthenticatorTransport
): Promise<string> {
  // Enable WebAuthn environment in this session
  await session.send('WebAuthn.enable');

  // Attach a virtual authenticator with specific options
  const result = await session.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: transport,
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: false,
    },
  });

  return result.authenticatorId;
}

export async function addCredential(
  session: CDPSession,
  authenticatorId: string,
  credential: Credential
): Promise<void> {
  const result = await session.send('WebAuthn.addCredential', {
    authenticatorId: authenticatorId,
    credential: credential,
  });
}

export async function clearCredentials(
  session: CDPSession,
  authenticatorId: string
): Promise<void> {
  const result = await session.send('WebAuthn.clearCredentials', {
    authenticatorId: authenticatorId
  });
}

export async function removeAuthenticator(session: CDPSession, authenticatorId: string): Promise<void> {
  await session.send('WebAuthn.removeVirtualAuthenticator', {
    authenticatorId: authenticatorId
  });
}

export async function toggleCredentials(page: Page): Promise<void> {
  await page.getByRole('button', { name: 'Passkey information' }).click();
  await expect(page.locator('table.credtable tbody tr').first()).toBeVisible();
}

// Verifies the page's tab can complete an authenticated server call.
// Triggers the credentials sidenav Refresh and asserts the resulting
// /user request returned 200.
export async function expectActiveServerSession(page: Page, expectedUserName?: string): Promise<void> {
  if (!(await page.locator('table.credtable tbody tr').first().isVisible())) {
    await toggleCredentials(page);
  }
  const userResponse = page.waitForResponse((response) =>
    response.url().includes('/v1/user') && response.request().method() === 'GET'
  );
  await page.getByRole('button', { name: 'Refresh' }).click();
  const resp = await userResponse;
  expect(resp.status()).toBe(200);
  if (expectedUserName !== undefined) {
    await expect(page.locator('mat-sidenav input').first()).toHaveValue(expectedUserName);
  }
}

export async function deleteFirstPasskey(
  page: Page, userName?: string
): Promise<void> {
  const tableBody = page.locator('table.credtable tbody');
  const count = await tableBody.locator('tr').count();

  await page.getByRole('button', { name: 'Delete' }).first().click();
  if (count === 1 && userName) {
    await page.locator('input#confirmInput').fill(userName);
  }

  const [deleteResponse] = await Promise.all([
    page.waitForResponse(response =>
      (response.url().includes('/passkeys')) &&
      response.request().method() === 'DELETE'
    ),
    page.getByRole('button', { name: 'Yes' }).click()
  ]);
  expect(deleteResponse.status()).toBe(200);
}

// Does not handle removal of last Passkey
export async function deleteLastPasskey(
  page: Page, userName?: string
): Promise<void> {
  const tableBody = page.locator('table.credtable tbody');
  const count = await tableBody.locator('tr').count();

  await page.getByRole('button', { name: 'Delete' }).last().click();
  if (count === 1 && userName) {
    await page.locator('input#confirmInput').fill(userName);
  }

  const [deleteResponse] = await Promise.all([
    page.waitForResponse(response =>
      (response.url().includes('/passkeys')) &&
      response.request().method() === 'DELETE'
    ),
    page.getByRole('button', { name: 'Yes' }).click()
  ]);
  expect(deleteResponse.status()).toBe(200);
}

export async function passkeyAuth(
  page: Page,
  session: CDPSession,
  authenticatorId: string | string[],
  operationTrigger: () => Promise<void>,
  awaitVerify: boolean = true
): Promise<Credential> {

  // Pass an array when more than one authenticator holds a credential
  // matching the user being signed in — the browser may pick any of them,
  // and presence simulation must be enabled on whichever it picks.
  const authenticatorIds = Array.isArray(authenticatorId) ? authenticatorId : [authenticatorId];
  let credential: Credential;

  // initialize event listeners to wait for a successful passkey input event
  const operationCompleted = new Promise<void>(resolve => {
    const timeout = setTimeout(() => resolve(), 8000);
    session.on('WebAuthn.credentialAsserted', (payload) => {
      clearTimeout(timeout);
      credential = payload.credential;
      resolve();
    });
  });

  // also wait for the server-side verify response so callers can assert on
  // signed-in UI without racing the response. Opt out for error-path tests
  // that never reach /v1/auth/verify.
  const verifyPromise: Promise<unknown> = awaitVerify ? page.waitForResponse((r) =>
    r.url().includes('/v1/auth/verify') && r.request().method() === 'POST'
  ) : Promise.resolve();

  for (const id of authenticatorIds) {
    await session.send('WebAuthn.setUserVerified', {
      authenticatorId: id,
      isUserVerified: true,
    });
    await session.send('WebAuthn.setAutomaticPresenceSimulation', {
      authenticatorId: id,
      enabled: true,
    });
  }

  await operationTrigger();

  // wait to receive the event that the passkey was successfully registered or verified
  await operationCompleted;
  await verifyPromise;

  for (const id of authenticatorIds) {
    await session.send('WebAuthn.setAutomaticPresenceSimulation', {
      authenticatorId: id,
      enabled: false,
    });
  }

  return credential!;
}

export async function passkeyCreation(
  page: Page,
  session: CDPSession,
  authenticatorId: string | string[],
  operationTrigger: () => Promise<void>,
  awaitVerify: boolean = true
): Promise<Credential> {

  const authenticatorIds = Array.isArray(authenticatorId) ? authenticatorId : [authenticatorId];
  let credential: Credential;

  // initialize event listeners to wait for a successful passkey input event
  const operationCompleted = new Promise<void>(resolve => {
    const timeout = setTimeout(() => resolve(), 8000);
    session.on('WebAuthn.credentialAdded', (payload) => {
      clearTimeout(timeout);
      credential = payload.credential;
      resolve();
    });
  });

  // also wait for the server-side verify response so callers can assert on
  // signed-in UI without racing the response. Opt out for error-path tests
  // that never reach the /verify endpoint.
  const verifyPromise: Promise<unknown> = awaitVerify ? page.waitForResponse((r) =>
    (r.url().includes('/v1/reg/verify') || r.url().includes('/v1/passkeys/verify')) &&
    r.request().method() === 'POST'
  ) : Promise.resolve();

  for (const id of authenticatorIds) {
    await session.send('WebAuthn.setUserVerified', {
      authenticatorId: id,
      isUserVerified: true,
    });
    await session.send('WebAuthn.setAutomaticPresenceSimulation', {
      authenticatorId: id,
      enabled: true,
    });
  }

  await operationTrigger();

  // wait to receive the event that the passkey was successfully registered or verified
  await operationCompleted;
  await verifyPromise;

  for (const id of authenticatorIds) {
    await session.send('WebAuthn.setAutomaticPresenceSimulation', {
      authenticatorId: id,
      enabled: false,
    });
  }

  return credential!;
}

export async function fillPwdAndAccept(
  page: Page,
  heading: RegExp,
  pwd: string,
  hint: string | undefined,
  encDec: 'enc' | 'dec',
  ready: () => Promise<void>
) {
  await ready();
  await expect(page.getByRole('heading', { name: heading })).toBeVisible();

  await page.locator('input#password').fill(pwd);
  if (encDec === 'enc') {
    await expect(page.getByText('Password is allowed')).toBeVisible();
  }

  if(hint) {
    if (encDec === 'enc') {
      await page.locator('input#hint').fill(hint);
    } else {
      await expect(page.locator('input#hint')).toHaveValue(hint);
    }
  }

  await page.getByRole('button', { name: 'Accept' }).click();
}
