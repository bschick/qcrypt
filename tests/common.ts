import { test, expect, Page, CDPSession } from '@playwright/test';
import { Protocol } from 'devtools-protocol';
import playwright from 'playwright';
import { AuthenticationResponseJSON, startAuthentication } from '@simplewebauthn/browser';
import { base64ToBytes } from '../src/app/services/utils';
import { timeout } from 'rxjs';

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
  credentialId: 'NAoLrbsz01Uj5ZrW7bdbS3MV2vjCanWtTi+4rq/0E6c=',
  isResidentCredential: true,
  rpId: 't1.quickcrypt.org',
  privateKey: 'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgbVRXcVEZzAI8BMfm6EbPaLoizJcQp3sp+nOsTssQ+rehRANCAASnOPbUIq9XiTOIsVQRPy3gtcInBC5YQqITmdDESr1LTfrhTp0sl7EvVo7KKfiN5TySTqsuaq3Av6ENzRTKF2a4',
  userHandle: 'UVJqczhRYmxJckxfTzg5bGZ0MWxLUQ==',
  signCount: 1,
  backupEligibility: false,
  backupState: false,
  userName: 'KeeperTwo'
};
const keeper2Recovery_local = "cave salt anxiety lady chronic quit vapor device useless husband misery region bag island series syrup cargo obey solve paddle fitness huge net couple"

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
      userCred: "KKuQbsfkRbebFRRPPsDHC7ZNfdgjbvtjEOtkeSJ7N50"
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

export type AuthFixture = {
  page: Page;
  session: CDPSession;
  authId: string;
};

export const testWithAuth = test.extend<{authFixture: AuthFixture}>({
  authFixture: async ({ page }, use, testInfo) => {
    const session = await page.context().newCDPSession(page);
    const authId = await setupAuthenticator(session, page);

    await use({
      page,
      session,
      authId
    });

    // a bit ugly, but it works.
    if (testInfo.tags.includes('@nukeall')) {

      const storageState = await page.context().storageState();
      const loclStorage = storageState.origins[0].localStorage;
      const userId = loclStorage.find(item => item.name === 'userid')?.value;

      // If the test completd, the user lougout happened because the last PK was deleted
      // So the existance of userid in localstorage means we didn't finish, so cleanup...
      if (userId) {
        //@ts-ignore
        const apiUrl = testInfo.project.use.apiURL;

        const authsResponse = await page.request.get(
          `${apiUrl}/user/${userId}/authenticators`
        );

        const auths = await authsResponse.json();
        for (const [count, auth] of auths.entries()) {
          console.log(`cleanup on isle ${count+1}`);
          const authsResponse = await page.request.delete(
            //@ts-ignore
            `${apiUrl}/user/${userId}/authenticator/${auth.credentialId}`
          );
          console.log(authsResponse.ok() ? 'done' : await authsResponse.text());
        }
      }
    }

    await removeAuthenticator(session, authId);
    await session.detach();
  }
});

export async function setupAuthenticator(session: CDPSession, page: Page): Promise<string> {
  // Enable WebAuthn environment in this session
  await session.send('WebAuthn.enable');

  // Attach a virtual authenticator with specific options
  const result = await session.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
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

export async function deleteFirstPasskey(page: Page): Promise<void> {
  const tableBody = page.locator('table.credtable tbody');
  const count = await tableBody.locator('tr').count();

  await page.getByRole('button', { name: 'Delete' }).first().click();
  if (count === 1) {
    await page.locator('input#confirmInput').fill('PWFlippy');
  }

  const [deleteResponse] = await Promise.all([
    page.waitForResponse(response =>
      response.url().includes('/authenticator') &&
      response.request().method() === 'DELETE'
    ),
    page.getByRole('button', { name: 'Yes' }).click()
  ]);
  expect(deleteResponse.status()).toBe(200);
}

export async function passkeyAuth(
  session: CDPSession,
  authId :string,
  operationTrigger: () => Promise<void>
): Promise<Credential> {

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

  // set isUserVerified option to true
  // (so that subsequent passkey operations will be successful)
  await session.send('WebAuthn.setUserVerified', {
    authenticatorId: authId,
    isUserVerified: true,
  });

  // set automaticPresenceSimulation option to true
  // (so that the virtual authenticator will respond to the next passkey prompt)
  await session.send('WebAuthn.setAutomaticPresenceSimulation', {
    authenticatorId: authId,
    enabled: true,
  });

  await operationTrigger();

  // wait to receive the event that the passkey was successfully registered or verified
  await operationCompleted;

  // set automaticPresenceSimulation option back to false
  await session.send('WebAuthn.setAutomaticPresenceSimulation', {
    authenticatorId: authId,
    enabled: false,
  });

  return credential!;
}

export async function passkeyCreation(
  session: CDPSession,
  authId :string,
  operationTrigger: () => Promise<void>
): Promise<Credential> {

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

  // set isUserVerified option to true
  // (so that subsequent passkey operations will be successful)
  await session.send('WebAuthn.setUserVerified', {
    authenticatorId: authId,
    isUserVerified: true,
  });

  // set automaticPresenceSimulation option to true
  // (so that the virtual authenticator will respond to the next passkey prompt)
  await session.send('WebAuthn.setAutomaticPresenceSimulation', {
    authenticatorId: authId,
    enabled: true,
  });

  await operationTrigger();

  // wait to receive the event that the passkey was successfully registered or verified
  await operationCompleted;

  // set automaticPresenceSimulation option back to false
  await session.send('WebAuthn.setAutomaticPresenceSimulation', {
    authenticatorId: authId,
    enabled: false,
  });

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
    await expect(page.getByText('Password is acceptable')).toBeVisible();
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
