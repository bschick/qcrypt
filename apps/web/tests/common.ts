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

export type AuthFixture = {
  page: Page;
  session: CDPSession;
  authId1: string;
  authId2: string;
  // Creates a fresh PWTesty_<timestamp> user via the UI registration flow on
  // `authId`. The session is signed-in on return (page at '/' with Encryption
  // Mode visible). Created users are tracked and torn down after the test.
  createTestUser: (authId: string) => Promise<CreatedTestUser>;
};

type TrackedUser = {
  userId: string;
  authId: string;
  csrf: string;
  // Snapshot of context cookies right after registration (notably the
  // __Host-JWT session cookie). Restored before each cleanup request so
  // we authenticate as this specific user, even after the test signed
  // out or switched users.
  cookies: Cookie[];
  // Saved so the fallback re-auth can put the credential back on the
  // authenticator if the captured cookie is stale (e.g. test signed out,
  // bumping authCount).
  credential: Credential;
};

export const testWithAuth = test.extend<{authFixture: AuthFixture}>({
  authFixture: async ({ page }, use, testInfo) => {
    const session = await page.context().newCDPSession(page);
    const authId1 = await setupAuthenticator(session, page, 'internal');
    const authId2 = await setupAuthenticator(session, page, 'usb');
    const trackedUsers: TrackedUser[] = [];

    const createTestUser = async (authId: string): Promise<CreatedTestUser> => {
      const userName = `PWTesty_${Date.now()}`;
      await page.goto('/');

      const verifyPromise = page.waitForResponse((r) =>
        r.url().includes('/v1/reg/verify') && r.request().method() === 'POST'
      );
      const credential = await passkeyCreation(session, authId, async () => {
        await page.getByRole('button', { name: 'I am new to Quick Crypt' }).click();
        await expect(page.getByRole('heading', { name: 'Create A New user' })).toBeVisible({ timeout: 10000 });
        await page.locator('input#userName').fill(userName);
        await page.getByRole('button', { name: /Create new/ }).click();
      });
      const body = await (await verifyPromise).json();
      if (!body.userId || !body.userCred || !body.csrf) {
        throw new Error('createTestUser: missing userId/userCred/csrf in /reg/verify response');
      }

      await page.waitForURL('/showrecovery', { waitUntil: 'domcontentloaded' });
      await expect(page.getByRole('heading', { name: 'Account Backup and Recovery' })).toBeVisible({ timeout: 10000 });
      const recoveryWords = await page.locator('textarea#wordsArea').inputValue();
      await page.getByRole('button', { name: /I saved my/ }).click();
      await page.waitForURL('/', { waitUntil: 'domcontentloaded' });
      await expect(page.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({ timeout: 10000 });

      trackedUsers.push({
        userId: body.userId,
        authId,
        csrf: body.csrf,
        cookies: await page.context().cookies(),
        credential,
      });
      return {
        userId: body.userId,
        userName,
        userCred: body.userCred,
        recoveryWords,
        credential,
      };
    };

    await use({
      page,
      session,
      authId1,
      authId2,
      createTestUser,
    });

    // Cleanup of users created via the helper. Fast path: restore the
    // cookie+CSRF captured at registration, GET /v1/user, DELETE each
    // passkey (server cascades the user record when the last one goes).
    // Fallback: any test that signs out or switches users will have
    // bumped authCount, so the captured cookie is stale and the fast
    // path 401s — re-auth via the UI as the tracked user (using the
    // saved credential) and DELETE through the fresh session. Original
    // cookies are restored at the end so @nukeall sees the test's
    // end state.
    const apiUrl = (testInfo.project.use as { apiURL: string }).apiURL;
    const originalCookies = await page.context().cookies();

    const deleteAllPasskeys = async (csrf: string, label: string): Promise<boolean> => {
      const userResp = await page.request.get(
        `${apiUrl}/user`,
        { headers: { 'x-csrf-token': csrf } }
      );
      if (!userResp.ok()) {
        console.error(`${label}: GET /user failed (${userResp.status()})`);
        return false;
      }
      const user = await userResp.json();
      for (const auth of user.authenticators ?? []) {
        const delResp = await page.request.delete(
          `${apiUrl}/passkeys/${auth.credentialId}`,
          { headers: { 'x-csrf-token': csrf } }
        );
        if (!delResp.ok()) {
          console.error(`${label}: DELETE /passkeys/${auth.credentialId} failed (${delResp.status()})`);
        }
      }
      return true;
    };

    for (const tracked of trackedUsers) {
      // Fast path. Any failure (non-ok GET, non-ok DELETE, throw) falls
      // through to the fallback re-auth.
      let fastPathOk = false;
      try {
        await page.context().clearCookies();
        await page.context().addCookies(tracked.cookies);

        const fastResp = await page.request.get(
          `${apiUrl}/user`,
          { headers: { 'x-csrf-token': tracked.csrf } }
        );
        if (fastResp.ok()) {
          const user = await fastResp.json();
          let allDeleted = true;
          for (const auth of user.authenticators ?? []) {
            const delResp = await page.request.delete(
              `${apiUrl}/passkeys/${auth.credentialId}`,
              { headers: { 'x-csrf-token': tracked.csrf } }
            );
            if (!delResp.ok()) {
              allDeleted = false;
              break;
            }
          }
          fastPathOk = allDeleted;
        }
      } catch (err) {
        console.error(`cleanup: fast path threw for ${tracked.userId}`, err);
      }

      if (fastPathOk) {
        continue;
      }

      // Fallback: re-auth via UI then delete. Signs out the context, puts
      // only the tracked user's credential on the authenticator, navigates
      // to '/' as a fresh session, and clicks "I have used Quick Crypt"
      // through passkeyAuth so the WebAuthn dance completes.
      try {
        await page.context().clearCookies();
        await clearCredentials(session, tracked.authId);
        await addCredential(session, tracked.authId, tracked.credential);

        await page.goto('/');
        await page.evaluate(() => localStorage.clear());
        await page.reload();
        await expect(page.getByRole('button', { name: /I have used Quick Crypt/ })).toBeVisible({ timeout: 10000 });

        const verifyPromise = page.waitForResponse((r) =>
          r.url().includes('/v1/auth/verify') && r.request().method() === 'POST'
        );
        await passkeyAuth(session, tracked.authId, async () => {
          await page.getByRole('button', { name: /I have used Quick Crypt/ }).click();
        });
        const verifyResp = await verifyPromise;
        if (!verifyResp.ok()) {
          // Most common cause: the test removed the last passkey, which
          // cascades the user record. Nothing to clean up — server-side
          // state already matches what we wanted.
          if (verifyResp.status() !== 401) {
            console.error(`cleanup-fallback: /auth/verify for ${tracked.userId} failed (${verifyResp.status()})`);
          }
          continue;
        }
        const verifyBody = await verifyResp.json();
        if (!verifyBody.csrf) {
          console.error(`cleanup-fallback: missing csrf in /auth/verify response for ${tracked.userId}`);
          continue;
        }
        await deleteAllPasskeys(verifyBody.csrf, `cleanup-fallback (${tracked.userId})`);
      } catch (err) {
        console.error(`cleanup-fallback: failed for ${tracked.userId}`, err);
      }
    }

    await page.context().clearCookies();
    if (originalCookies.length > 0) {
      await page.context().addCookies(originalCookies);
    }

    // Fallback for tests that create users without the helper (e.g. inline
    // registration in lifecycle.spec.ts). Uses the same /session approach
    // and refuses to delete anything that isn't a PWTesty_ user, so a future
    // @nukeall test that happens to end signed in as a Keeper can't wipe it.
    if (testInfo.tags.includes('@nukeall')) {
      try {
        const sessionResp = await page.request.get(`${apiUrl}/session`);
        if (sessionResp.ok()) {
          const session = await sessionResp.json();
          if (typeof session.userName === 'string' && session.userName.startsWith('PWTesty_')) {
            for (const [count, auth] of (session.authenticators ?? []).entries()) {
              console.log(`cleanup on isle ${count + 1}`);
              const delResp = await page.request.delete(
                `${apiUrl}/passkeys/${auth.credentialId}`,
                { headers: { 'x-csrf-token': session.csrf } }
              );
              if (!delResp.ok()) {
                console.error(`@nukeall: DELETE /passkeys/${auth.credentialId} failed (${delResp.status()})`);
              }
            }
          } else if (session.userName) {
            console.error(`@nukeall: refusing to nuke non-PWTesty_ user ${session.userName}`);
          }
        } else if (sessionResp.status() !== 401) {
          console.error(`@nukeall: GET /session failed (${sessionResp.status()})`);
        }
      } catch (err) {
        console.error('@nukeall: cleanup threw', err);
      }
    }

    await removeAuthenticator(session, authId1);
    await removeAuthenticator(session, authId2);
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

export async function openCredentials(page: Page): Promise<void> {
  await page.getByRole('button', { name: 'Passkey information' }).click();
  await expect(page.locator('table.credtable tbody tr').first()).toBeVisible();
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
  session: CDPSession,
  authId: string | string[],
  operationTrigger: () => Promise<void>
): Promise<Credential> {

  // Pass an array when more than one authenticator holds a credential
  // matching the user being signed in — the browser may pick any of them,
  // and presence simulation must be enabled on whichever it picks.
  const authIds = Array.isArray(authId) ? authId : [authId];
  let credential: Credential;

  // initialize event listeners to wait for a successful passkey input event
  const operationCompleted = new Promise<void>(resolve => {
    const timeout = setTimeout(() => resolve(), 5000);
    session.on('WebAuthn.credentialAsserted', (payload) => {
      clearTimeout(timeout);
      credential = payload.credential;
      resolve();
    });
  });

  for (const id of authIds) {
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

  for (const id of authIds) {
    await session.send('WebAuthn.setAutomaticPresenceSimulation', {
      authenticatorId: id,
      enabled: false,
    });
  }

  return credential!;
}

export async function passkeyCreation(
  session: CDPSession,
  authId: string | string[],
  operationTrigger: () => Promise<void>
): Promise<Credential> {

  const authIds = Array.isArray(authId) ? authId : [authId];
  let credential: Credential;

  // initialize event listeners to wait for a successful passkey input event
  const operationCompleted = new Promise<void>(resolve => {
    const timeout = setTimeout(() => resolve(), 5000);
    session.on('WebAuthn.credentialAdded', (payload) => {
      clearTimeout(timeout);
      credential = payload.credential;
      resolve();
    });
  });

  for (const id of authIds) {
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

  for (const id of authIds) {
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
