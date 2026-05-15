import { test, expect, Page, CDPSession, type Cookie } from '@playwright/test';
import { Protocol } from 'devtools-protocol';

export type Credential = Protocol.WebAuthn.Credential;

const keeper1_local: Credential = {
  credentialId: 'YpKdnBAh/1dsoA6FrdIbmAaGJU408ToZBeljHs9Qx78=',
  isResidentCredential: true,
  rpId: 't1.quickcrypt.org',
  privateKey: 'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgtU5Hu+SXiB2zVrByWMR3U1GozkxaHzYOAtf/fAkf0FShRANCAATnoR0vbf5IHoNi8TLrQabuQzwaILNShvd+ay47VfrJUgS2KN6VVzJib59Q6OTYVCcnEWLzbIteN/fcgZNEb0gG',
  userHandle: 'VTFoZlFQcEx6akNYdmFSUS0yaFZEZw==',
  signCount: 1,
  backupEligibility: false,
  backupState: false,
  userName: 'KeeperOne'
};
const keeper1Recovery_local = "tool uniform squirrel melody lawn okay hazard work web middle desert modify culture cook advance enact soda lucky urge emerge autumn reflect feature six"

const keeper2_local: Credential = {
  credentialId: 'Ce7OGaF7BJD80YxFMKV/QeUU9P31T2RVihbM7m6VXoQ=',
  isResidentCredential: true,
  rpId: 't1.quickcrypt.org',
  privateKey: 'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgSBrv0BJG5Z1sjMctzWTSTmu+UECFQ49ygT+KbXDo85GhRANCAAQ+gHUxJDGgCEQ+ABkWTarZkFqqoeovpFUra7r6LGIrhlYpweejncc+OQ390N3CogmaSdhJjZaVpZoe/45ARBU5',
  userHandle: 'U0tIM0VZU0R5WXFEbWdIY3FiZEJlQQ==',
  signCount: 0,
  backupEligibility: false,
  backupState: false,
  userName: 'KeeperTwo'
};
const keeper2Recovery_local = "token force rigid turkey chunk detail erode badge album enlist manual pig meat wine ecology motor sister favorite track admit skin sweet album appear";

const keeper1_prod: Credential = {
  credentialId: 'Zti4nmkLHo/4rnNimBROJ7CgP0cAJbfCWGgVlXfsiS8=',
  isResidentCredential: true,
  rpId: 'quickcrypt.org',
  privateKey: 'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgsSWkWH0RtGtqbDw2a2BomwIq/Xv95lt35Sk5iSXvb6ShRANCAAR9n7Ue93B2oXcj5grRlWm0y/KUNrKA7GtITw+XpKWGXWIrrAZD3WOXyeDRtChx2bk+GfBgsZGhDHbSWJkWySS2',
  userHandle: 'am1GeGplTDg0UmdsUkpEVGtJeG56dw==',
  signCount: 1,
  backupEligibility: false,
  backupState: false,
  userName: 'KeeperOne'
}
const keeper1Recovery_prod = 'captain truly apology rude correct access above index cart save open home toward rhythm daring garbage three scorpion eye canvas decorate economy palace venture';

const keeper2_prod: Credential = {
  credentialId: 'JerYY/YvBC4SiQtBWx/4NMIvMrBH2S99hIRaXwCI+DA=',
  isResidentCredential: true,
  rpId: 'quickcrypt.org',
  privateKey: 'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgt72ZEvhrD9O+H8hn/0pbBRScVHjPEMI6B3edO0piTaWhRANCAAQbVIDhQXmmMMNMry/G4XfRGdGdKHmbCb6NDNtQpzTKXxqj9GMlGoc709quv0C/t5UxrxefYb1mERc/+Pr1m/ej',
  userHandle: 'MGxVaDd4SVZxY0tLSDdHcjZTVEFLZw==',
  signCount: 1,
  backupEligibility: false,
  backupState: false,
  userName: 'KeeperTwo'
}
const keeper2Recovery_prod = 'cable dismiss find crouch legend tourist fork caught gaze fragile opera moral census movie rough dress prefer begin margin globe salon mystery absent dwarf';

export type hosts = 't1.quickcrypt.org' | 'quickcrypt.org';
export const credentials= {
  't1.quickcrypt.org': {
    keeper1: {
      id: keeper1_local,
      words: keeper1Recovery_local,
      userCred: "get when used"
    },
    keeper2: {
      id: keeper2_local,
      words: keeper2Recovery_local,
      userCred: "otjn8rPDTFaJ_T-SwwfS6PeG6U_ffzsFdA_35ZeawSg"
    }
  },
  'quickcrypt.org': {
    keeper1: {
      id: keeper1_prod,
      words: keeper1Recovery_prod,
      userCred: "get when used"
    },
    keeper2: {
      id: keeper2_prod,
      words: keeper2Recovery_prod,
      userCred: "pQhdwd-e4LGH5BWi-nWaMalzARJ3bImx0SJgLV4Y9YI"
    }
  },
};

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
  passkey: TrackedPasskey;
  fastSession?: { cookies: Cookie[]; csrf: string };
};

export type AuthFixture = {
  page: Page;
  session: CDPSession;
  authenticatorId1: string;
  authenticatorId2: string;
  // Creates a fresh PWTesty_<timestamp> user via the UI registration flow on
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
    const session = await page.context().newCDPSession(page);
    const authenticatorId1 = await setupAuthenticator(session, page, 'internal');
    const authenticatorId2 = await setupAuthenticator(session, page, 'usb');
    const trackedUsers: TrackedUser[] = [];

    const createTestUser = async (authenticatorId: string): Promise<CreatedTestUser> => {
      const userName = `PWTesty_${Date.now()}`;
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
      label: string
    ): Promise<boolean> => {
      const userResp = await page.request.get(
        `${apiUrl}/user`,
        { headers: { 'x-csrf-token': csrf, 'Origin': baseURL } }
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
        const delResp = await page.request.delete(
          `${apiUrl}/passkeys/${auth.credentialId}`,
          { headers: { 'x-csrf-token': csrf, 'Origin': baseURL } }
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

          const fastResp = await page.request.get(
            `${apiUrl}/user`,
            { headers: { 'x-csrf-token': user.fastSession.csrf, 'Origin': baseURL } }
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
              const delResp = await page.request.delete(
                `${apiUrl}/passkeys/${auth.credentialId}`,
                { headers: { 'x-csrf-token': user.fastSession.csrf, 'Origin': baseURL } }
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
              await deleteAllPasskeys(verifyBody.csrf, verifyBody.pkId, `cleanup-fallback (${user.userId})`);
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

    // Leak alarm. If a PWTesty_ session is still authenticatable after
    // cleanup, a test created a user/passkey without calling trackUser /
    // trackPasskey / addPasskey. Log loudly and opportunistically clean up.
    if (testInfo.tags.includes('@nukeall')) {
      try {
        const sessionResp = await page.request.get(`${apiUrl}/session`);
        if (sessionResp.ok()) {
          const sess = await sessionResp.json();
          if (typeof sess.userName === 'string' && sess.userName.startsWith('PWTesty_')) {
            console.error(`@nukeall LEAK ALARM: untracked PWTesty user ${sess.userName} (${sess.userId}) — tests must call trackUser/trackPasskey/addPasskey for users and passkeys created outside createTestUser`);
            for (const auth of sess.authenticators ?? []) {
              const delResp = await page.request.delete(
                `${apiUrl}/passkeys/${auth.credentialId}`,
                { headers: { 'x-csrf-token': sess.csrf, 'Origin': baseURL } }
              );
              if (!delResp.ok()) {
                console.error(`@nukeall: DELETE /passkeys/${auth.credentialId} failed (${delResp.status()})`);
              }
            }
          } else if (sess.userName) {
            console.error(`@nukeall: refusing to nuke non-PWTesty_ user ${sess.userName}`);
          }
        } else if (sessionResp.status() !== 401) {
          console.error(`@nukeall: GET /session failed (${sessionResp.status()})`);
        }
      } catch (err) {
        console.error('@nukeall: cleanup threw', err);
      }
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
