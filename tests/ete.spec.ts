import { test, expect, Page, CDPSession } from '@playwright/test';
import { Protocol } from 'devtools-protocol';
type Credential = Protocol.WebAuthn.Credential;

const testURL = 'https://t1.quickcrypt.org:4200';

const keeper1: Credential = {
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
const keeper1Recovery = "tool uniform squirrel melody lawn okay hazard work web middle desert modify culture cook advance enact soda lucky urge emerge autumn reflect feature six"

const keeper2: Credential = {
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
const keeper2Recovery = "cave salt anxiety lady chronic quit vapor device useless husband misery region bag island series syrup cargo obey solve paddle fitness huge net couple"

type AuthFixture = {
  page: Page;
  session: CDPSession;
  authId: string;
};

const testWithAuth = test.extend<{authFixture: AuthFixture}>({
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


async function setupAuthenticator(session: CDPSession, page: Page): Promise<string> {
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

async function addCredential(
  session: CDPSession,
  authenticatorId: string,
  credential: Credential
): Promise<void> {
  const result = await session.send('WebAuthn.addCredential', {
    authenticatorId: authenticatorId,
    credential: credential,
  });
}

async function clearCredentials(
  session: CDPSession,
  authenticatorId: string
): Promise<void> {
  const result = await session.send('WebAuthn.clearCredentials', {
    authenticatorId: authenticatorId
  });
}


async function removeAuthenticator(session: CDPSession, authenticatorId: string): Promise<void> {
  await session.send('WebAuthn.removeVirtualAuthenticator', {
    authenticatorId: authenticatorId
  });
}

async function deleteFirstPasskey(page: Page): Promise<void> {
  const tableBody = page.locator('table.credtable tbody');
  const count = await tableBody.locator('tr').count();

  await page.getByRole('button', { name: 'Delete' }).first().click();
  if (count === 1) {
    await page.locator('input#confirmInput').fill('PWFlippy');
  }

  const [deleteResponse] = await Promise.all([
    page.waitForResponse(response =>
      response.url().includes('v1/authenticator') &&
      response.request().method() === 'DELETE'
    ),
    page.getByRole('button', { name: 'Yes' }).click()
  ]);
  expect(deleteResponse.status()).toBe(200);
}

async function passkeyAuth(
  session: CDPSession,
  authId :string,
  operationTrigger: () => Promise<void>
): Promise<Credential> {

  let credential: Credential;

  // initialize event listeners to wait for a successful passkey input event
  const operationCompleted = new Promise<void>(resolve => {
//     session.on('WebAuthn.credentialAdded', (payload) => {
//       credential = payload.credential;
// //      console.log(payload);
//       resolve();
//     });
    session.on('WebAuthn.credentialAsserted', (payload) => {
      credential = payload.credential;
//      console.log(payload);
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

async function passkeyCreation(
  session: CDPSession,
  authId :string,
  operationTrigger: () => Promise<void>
): Promise<Credential> {

  let credential: Credential;

  // let authenticatorId: string;

  // initialize event listeners to wait for a successful passkey input event
  const operationCompleted = new Promise<void>(resolve => {
    session.on('WebAuthn.credentialAdded', (payload) => {
      credential = payload.credential;
//      console.log(payload);
      resolve();
    });
//    session.on('WebAuthn.credentialAsserted', () => resolve());
  });

  // // Attach a virtual authenticator with specific options
  // const result = await session.send('WebAuthn.addVirtualAuthenticator', {
  //   options: {
  //     protocol: 'ctap2',
  //     transport: 'internal',
  //     hasResidentKey: true,
  //     hasUserVerification: true,
  //     isUserVerified: true,
  //     automaticPresenceSimulation: false,
  //   },
  // });

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

test('has title', async ({ page }) => {
  await page.goto(testURL);

  // Expect a title "to contain" a substring.
  await expect(page).toHaveTitle(/Quick Crypt/);
  await expect(page.getByRole('heading', { name: /Quick Crypt: Easy, Trustworthy/ })).toBeVisible();
});

test('new user fill in', async ({ page }) => {
  await page.goto(testURL);

  // Click the get started link.
  await page.getByRole('button', { name: 'I am new to Quick Crypt' }).click();

  // Expects page to have a heading with the name of Installation.
  await expect(page.getByRole('heading', { name: 'Create A New user' })).toBeVisible();

  await page.locator('input#userName').fill('PWFlippy');
  await expect(page.locator('input#userName')).toHaveValue('PWFlippy');

});

test('get overview', async ({ page }) => {
  await page.goto(testURL);

  // Click the get started link.
  await page.getByRole('button', { name: 'Help' }).click();

  // Click the get started link.
  await page.getByRole('menuitem', { name: 'Overview' }).click();

  // Expects page to have a heading with the name of Installation.
  await expect(page.getByRole('heading', { name: 'Quick Crypt: Easy, Trustworthy Personal Encryption' })).toBeVisible();
});


testWithAuth('log in and out', async ({ authFixture }) => {
  const { page, session, authId } = authFixture;
  await addCredential(session, authId, keeper2);
  await page.goto(testURL);

  await passkeyAuth(session, authId, async () => {
    await page.getByRole('button', { name: 'I have used Quick Crypt' }).click();
  });
  await page.waitForURL(testURL, { waitUntil: 'domcontentloaded' });
  await expect(page.getByRole('button', { name: 'Encryption Mode' })).toBeVisible();

  await page.getByRole('button', { name: 'Passkey information' }).click();

  let tableBody = page.locator('table.credtable tbody');
  await expect(tableBody.locator('tr')).toHaveCount(1);

  await page.getByRole('button', { name: /Sign out/ }).click();

  await passkeyAuth(session, authId, async () => {
    await page.getByRole('button', { name: /Sign in as Keeper/ }).click();
  });

  await page.waitForURL(testURL, { waitUntil: 'domcontentloaded' });
  await expect(page.getByRole('button', { name: 'Encryption Mode' })).toBeVisible();

  await page.getByRole('button', { name: 'Passkey information' }).click();

  tableBody = page.locator('table.credtable tbody');
  await expect(tableBody.locator('tr')).toHaveCount(1);

  await page.getByRole('button', { name: /Sign out/ }).click();
  await page.getByRole('button', { name: /Sign in as a different user/ }).click();

  await page.waitForURL(testURL + '/welcome', { waitUntil: 'domcontentloaded' });
  await expect(page.getByRole('heading', { name: /Quick Crypt: Easy, Trustworthy/ })).toBeVisible();

});

testWithAuth('2nd tab logout', async ({ authFixture }) => {
  const { page, session, authId } = authFixture;
  const page1 = page;
  await addCredential(session, authId, keeper1);
  await page1.goto(testURL);

  await passkeyAuth(session, authId, async () => {
    await page1.getByRole('button', { name: 'I have used Quick Crypt' }).click();
  });
  await page1.waitForURL(testURL, { waitUntil: 'domcontentloaded' });
  await expect(page1.getByRole('button', { name: 'Encryption Mode' })).toBeVisible();

  const page2 = await page1.context().newPage();
  await page2.goto(testURL);
  await page2.waitForURL(testURL, { waitUntil: 'domcontentloaded' });
  await expect(page2.getByRole('button', { name: 'Encryption Mode' })).toBeVisible();

  // logout 2nd page and confirm first is logged out
  await page2.getByRole('button', { name: 'Passkey information' }).click();

  let tableBody2 = page2.locator('table.credtable tbody');
  await expect(tableBody2.locator('tr')).toHaveCount(1);
  await expect(page2.locator('mat-sidenav input').first()).toHaveValue('KeeperOne');

  await page2.getByRole('button', { name: /Sign out/ }).click();
  await expect(page2.getByRole('heading', { name: /Quick Crypt Sign In/ })).toBeVisible();

  await page1.goto(testURL);
  await page1.waitForURL(testURL, { waitUntil: 'domcontentloaded' });
  await expect(page1.getByRole('heading', { name: /Quick Crypt Sign In/ })).toBeVisible();

});

testWithAuth('3 tabs switching users', async ({ authFixture }) => {
  const { page, session, authId } = authFixture;
  const page1 = page;
  await addCredential(session, authId, keeper1);
  await page1.goto(testURL);

  await passkeyAuth(session, authId, async () => {
    await page1.getByRole('button', { name: 'I have used Quick Crypt' }).click();
  });
  await page1.waitForURL(testURL, { waitUntil: 'domcontentloaded' });
  await expect(page1.getByRole('button', { name: 'Encryption Mode' })).toBeVisible();

  const page2 = await page1.context().newPage();
  await page2.goto(testURL);
  await page2.waitForURL(testURL, { waitUntil: 'domcontentloaded' });
  await expect(page2.getByRole('button', { name: 'Encryption Mode' })).toBeVisible();
  await page2.getByRole('button', { name: 'Passkey information' }).click();
  await expect(page2.locator('mat-sidenav input').first()).toHaveValue('KeeperOne');

  // log 1st page in as keepertwo
  await page1.getByRole('button', { name: 'Passkey information' }).click();

  let tableBody1 = page1.locator('table.credtable tbody');
  await expect(tableBody1.locator('tr')).toHaveCount(1);
  await expect(page1.locator('mat-sidenav input').first()).toHaveValue('KeeperOne');

  await page1.getByRole('button', { name: /Sign out/ }).click();
  await page1.getByRole('button', { name: /Sign in as a different user/ }).click();

  await page1.waitForURL(testURL + '/welcome', { waitUntil: 'domcontentloaded' });
  await expect(page1.getByRole('heading', { name: /Quick Crypt: Easy, Trustworthy/ })).toBeVisible();

  await clearCredentials(session, authId);
  await addCredential(session, authId, keeper2);

  await passkeyAuth(session, authId, async () => {
    await page1.getByRole('button', { name: 'I have used Quick Crypt' }).click();
  });
  await page1.waitForURL(testURL, { waitUntil: 'domcontentloaded' });
  await expect(page1.getByRole('button', { name: 'Encryption Mode' })).toBeVisible();
  await page1.getByRole('button', { name: 'Passkey information' }).click();
  await expect(page1.locator('mat-sidenav input').first()).toHaveValue('KeeperTwo');

  // page2 should go to welcome page since it origianl user user logged out
  await page2.goto(testURL);
  await page2.waitForURL(testURL + '/welcome', { waitUntil: 'domcontentloaded' });
  await expect(page2.getByRole('heading', { name: /Quick Crypt: Easy, Trustworthy/ })).toBeVisible();

  // page3 should open to main page because it didn't have preivous user context
  const page3 = await page1.context().newPage();

  await page3.goto(testURL);
  await page3.waitForURL(testURL, { waitUntil: 'domcontentloaded' });
  await expect(page3.getByRole('button', { name: 'Encryption Mode' })).toBeVisible();
  await page3.getByRole('button', { name: 'Passkey information' }).click();
  let tableBody3 = page3.locator('table.credtable tbody');
  await expect(tableBody3.locator('tr')).toHaveCount(1);
  await expect(page3.locator('mat-sidenav input').first()).toHaveValue('KeeperTwo');
  await page3.getByRole('button', { name: /Sign out/ }).click();
  await expect(page3.getByRole('heading', { name: /Quick Crypt Sign In/ })).toBeVisible();

  // page2 should still go to welcome page since it origianl user user logged out
  await page2.goto(testURL);
  await page2.waitForURL(testURL + '/welcome', { waitUntil: 'domcontentloaded' });
  await expect(page2.getByRole('heading', { name: /Quick Crypt: Easy, Trustworthy/ })).toBeVisible();

  // page1 should go to sign in dialog
  await page1.goto(testURL);
  await page1.waitForURL(testURL, { waitUntil: 'domcontentloaded' });
  await expect(page1.getByRole('heading', { name: /Quick Crypt Sign In/ })).toBeVisible();

  // sign back in as Keeper1
  await page1.getByRole('button', { name: /Sign in as a different user/ }).click();

  await page1.waitForURL(testURL + '/welcome', { waitUntil: 'domcontentloaded' });
  await expect(page1.getByRole('heading', { name: /Quick Crypt: Easy, Trustworthy/ })).toBeVisible();

  await clearCredentials(session, authId);
  await addCredential(session, authId, keeper1);

  await passkeyAuth(session, authId, async () => {
    await page1.getByRole('button', { name: 'I have used Quick Crypt' }).click();
  });
  await page1.waitForURL(testURL, { waitUntil: 'domcontentloaded' });
  await expect(page1.getByRole('button', { name: 'Encryption Mode' })).toBeVisible();
  await page1.getByRole('button', { name: 'Passkey information' }).click();
  await expect(page1.locator('mat-sidenav input').first()).toHaveValue('KeeperOne');
  await page1.getByRole('button', { name: 'Passkey information' }).click();

  // page2 should now go to enryption page since origianl user is logged in again
  await page2.goto(testURL);
  await page2.waitForURL(testURL, { waitUntil: 'domcontentloaded' });
  await expect(page2.getByRole('button', { name: 'Encryption Mode' })).toBeVisible();
  await page2.getByRole('button', { name: 'Passkey information' }).click();
  await expect(page2.locator('mat-sidenav input').first()).toHaveValue('KeeperOne');

});


testWithAuth('full lifecycle', async ({ authFixture }) => {
  const { page, session, authId } = authFixture;

  await page.goto(testURL);

  await passkeyCreation(session, authId, async () => {
    await page.getByRole('button', { name: 'I am new to Quick Crypt' }).click();
    await expect(page.getByRole('heading', { name: 'Create A New user' })).toBeVisible();
    await page.locator('input#userName').fill('PWFlipp<script>y</script>');
    await page.getByRole('button', { name: /Create new/ }).click();
  });

  await page.waitForURL(testURL + '/showrecovery', { waitUntil: 'domcontentloaded' });

  await expect(page.getByRole('heading', { name: 'Account Backup and Recovery' })).toBeVisible();

  //save recovery pattern
  const recoveryWords = await page.locator('textarea#wordsArea').inputValue();

  await page.getByRole('button', { name: /I saved my/ }).click();

  await page.waitForURL(testURL, { waitUntil: 'domcontentloaded' });
  await expect(page.getByRole('button', { name: 'Encryption Mode' })).toBeVisible();
  await page.getByRole('button', { name: 'Passkey information' }).click();

  let tableBody = page.locator('table.credtable tbody');
  await expect(tableBody.locator('tr')).toHaveCount(1);

  await passkeyCreation(session, authId, async () => {
    await page.getByRole('button', { name: /New Passkey/ }).click();
  });

  await expect(tableBody.locator('tr')).toHaveCount(2);

  await page.getByRole('button', { name: /Sign out/ }).click();

  await passkeyAuth(session, authId, async () => {
    await page.getByRole('button', { name: /Sign in as PWFlippy/ }).click();
  });

  await page.waitForURL(testURL, { waitUntil: 'domcontentloaded' });

  await page.goto(testURL + '/recovery2');
  await page.waitForURL(testURL + '/recovery2', { waitUntil: 'networkidle' });

  await page.locator('textarea#wordsArea').fill(recoveryWords);

  await passkeyCreation(session, authId, async () => {
    await page.getByRole('button', { name: /Start recovery/ }).click();
  });

  await page.waitForURL(testURL, { waitUntil: 'domcontentloaded' });
  await expect(page.getByRole('button', { name: 'Encryption Mode' })).toBeVisible();
  await page.getByRole('button', { name: 'Passkey information' }).click();

  tableBody = page.locator('table.credtable tbody');
  await expect(tableBody.locator('tr')).toHaveCount(1);

  await deleteFirstPasskey(page);

  await page.waitForURL(testURL + '/welcome', { waitUntil: 'domcontentloaded' });
  await expect(page.getByRole('heading', { name: /Quick Crypt: Easy, Trustworthy/ })).toBeVisible();

});
