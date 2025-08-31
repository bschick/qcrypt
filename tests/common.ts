import { test, expect, Page, CDPSession } from '@playwright/test';
import { Protocol } from 'devtools-protocol';

export type Credential = Protocol.WebAuthn.Credential;
export const testURL = 'https://t1.quickcrypt.org:4200';

export const keeper1: Credential = {
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
export const keeper1Recovery = "tool uniform squirrel melody lawn okay hazard work web middle desert modify culture cook advance enact soda lucky urge emerge autumn reflect feature six"

export const keeper2: Credential = {
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
export const keeper2Recovery = "cave salt anxiety lady chronic quit vapor device useless husband misery region bag island series syrup cargo obey solve paddle fitness huge net couple"

export type AuthFixture = {
  page: Page;
  session: CDPSession;
  authId: string;
};

export const testWithAuth = test.extend<{authFixture: AuthFixture}>({
  authFixture: async ({ page }, use) => {
    const session = await page.context().newCDPSession(page);
    const authId = await setupAuthenticator(session, page);

    await use({
      page,
      session,
      authId
    });

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
    session.on('WebAuthn.credentialAsserted', (payload) => {
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
    session.on('WebAuthn.credentialAdded', (payload) => {
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
