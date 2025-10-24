import { test, expect, Page, CDPSession } from '@playwright/test';
import {
  testWithAuth,
  passkeyAuth,
  passkeyCreation,
  deleteFirstPasskey,
  clearCredentials,
  addCredential,
  hosts,
  credentials
} from '.././common';


test.describe('errors', () => {

  testWithAuth('user too short', async ({ authFixture }) => {
    const { page, session, authId1, authId2 } = authFixture;

    await page.goto('/');

    await passkeyCreation(session, authId1, async () => {
      await page.getByRole('button', { name: 'I am new to Quick Crypt' }).click();
      await expect(page.getByRole('heading', { name: 'Create A New user' })).toBeVisible({timeout:10000});
      await page.locator('input#userName').fill('short');
      await page.getByRole('button', { name: /Create new/ }).click();
    });

    const parent = page.locator('.error-msg p');
    expect(parent).toContainText('User name must be 6 to 31 characters long');
  });

  testWithAuth('user too long', async ({ authFixture }) => {
    const { page, session, authId1, authId2 } = authFixture;

    await page.goto('/');

    await passkeyCreation(session, authId1, async () => {
      await page.getByRole('button', { name: 'I am new to Quick Crypt' }).click();
      await expect(page.getByRole('heading', { name: 'Create A New user' })).toBeVisible({timeout:10000});
      await page.locator('input#userName').fill('1234567890123456789012345678901234567890');
      await page.getByRole('button', { name: /Create new/ }).click();
    });

    const parent = page.locator('.error-msg p');
    expect(parent).toContainText('User name must be 6 to 31 characters long');
  });

  testWithAuth('no passkey cold', async ({ authFixture }) => {
    const { page, session, authId1, authId2 } = authFixture;

    await page.goto('/');

    await passkeyAuth(session, authId1, async () => {
      await page.getByRole('button', { name: 'I have used Quick Crypt' }).click();
    });
    const parent = page.locator('p.error-msg');
    expect(parent).toContainText(/Passkey not recognized/);
  });

  testWithAuth('no passkey re-signin', async ({ authFixture }) => {
    const { page, session, authId1, authId2 } = authFixture;

    await page.goto('/');

    const testHost = new URL(page.url()).hostname as hosts;
    await addCredential(session, authId1, credentials[testHost]['keeper1']['id']);

    await passkeyAuth(session, authId1, async () => {
      await page.getByRole('button', { name: 'I have used Quick Crypt' }).click();
    });
    await page.waitForURL('/', { waitUntil: 'domcontentloaded' });
    await expect(page.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({timeout:10000});

    await page.getByRole('button', { name: 'Passkey information' }).click();
    await page.getByRole('button', { name: /Sign out/ }).click();

    await clearCredentials(session, authId1);

    await passkeyAuth(session, authId1, async () => {
      await page.getByRole('button', { name: /Sign in as Keeper/ }).click();
    });

    expect(page.locator('div.button-host div.error-msg')).toContainText(/Sign in failed, try again or change users/);
  });


  testWithAuth('enc dec errors', async ({ authFixture }) => {
    const { page, session, authId1, authId2 } = authFixture;
    test.setTimeout(45000);

    await page.goto('/');

    const testHost = new URL(page.url()).hostname as hosts;
    await addCredential(session, authId1, credentials[testHost]['keeper2']['id']);

    await passkeyAuth(session, authId1, async () => {
      await page.getByRole('button', { name: 'I have used Quick Crypt' }).click();
    });
    await page.waitForURL('/', { waitUntil: 'domcontentloaded' });
    await expect(page.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({timeout:10000});

    await page.getByRole('button', { name: 'Encrypt Text'}).click();
    expect(page.locator('.errorBox').nth(1)).toContainText(/Missing clear text/);

    await page.getByRole('button', { name: 'Decrypt Text'}).click();
    expect(page.locator('.errorBox').nth(0)).toContainText(/Missing cipher armor/);

  });

  testWithAuth('edit errors', async ({ authFixture }) => {
    const { page, session, authId1, authId2 } = authFixture;
    test.setTimeout(45000);

    await page.goto('/');

    const testHost = new URL(page.url()).hostname as hosts;
    await addCredential(session, authId1, credentials[testHost]['keeper2']['id']);

    await passkeyAuth(session, authId1, async () => {
      await page.getByRole('button', { name: 'I have used Quick Crypt' }).click();
    });
    await page.waitForURL('/', { waitUntil: 'domcontentloaded' });
    await expect(page.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({timeout:10000});

    await page.getByRole('button', { name: 'Passkey information' }).click();

    await page.locator('mat-sidenav input').first().click();
    await page.locator('mat-sidenav input').first().fill('12345');
    await page.keyboard.press('Enter');

    expect(page.locator('div.error-msg')).toContainText(/Name change failed, must be 6 to 31 characters/);

    await page.locator('mat-sidenav input').nth(1).click();
    await page.locator('mat-sidenav input').nth(1).fill('12345');
    await page.keyboard.press('Enter');

    expect(page.locator('div.error-msg')).toContainText(/Description change failed, must be 6 to 42 characters/);
  });


  testWithAuth('no recovery access', async ({ authFixture }) => {
    const { page, session, authId1, authId2 } = authFixture;
    test.setTimeout(45000);

    await page.goto('/');

    const testHost = new URL(page.url()).hostname as hosts;
    await addCredential(session, authId1, credentials[testHost]['keeper2']['id']);

    await passkeyAuth(session, authId1, async () => {
      await page.getByRole('button', { name: 'I have used Quick Crypt' }).click();
    });
    await page.waitForURL('/', { waitUntil: 'domcontentloaded' });
    await expect(page.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({timeout:10000});

    await page.getByRole('button', { name: 'Passkey information' }).click();

    await clearCredentials(session, authId1);

    await passkeyAuth(session, authId1, async () => {
      await page.getByRole('button', { name: /Show recovery link/ }).click();
    });

    await page.waitForURL('/showrecovery', { waitUntil: 'domcontentloaded' });
    await expect(page.getByRole('button', { name: 'Try again' })).toBeVisible({timeout:10000});

    expect(page.locator('.error-msg p')).toContainText('Retrieval failed, try again', {timeout:10000});

  });

  testWithAuth('no usercred access', async ({ authFixture }) => {
    const { page, session, authId1, authId2 } = authFixture;
    test.setTimeout(45000);

    await page.goto('/');

    const testHost = new URL(page.url()).hostname as hosts;
    await addCredential(session, authId1, credentials[testHost]['keeper2']['id']);

    await passkeyAuth(session, authId1, async () => {
      await page.getByRole('button', { name: 'I have used Quick Crypt' }).click();
    });
    await page.waitForURL('/', { waitUntil: 'domcontentloaded' });
    await expect(page.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({timeout:10000});

    await clearCredentials(session, authId1);

    await passkeyAuth(session, authId1, async () => {
      await page.goto('/cmdline');
    });

    await page.waitForURL('/cmdline', { waitUntil: 'domcontentloaded' });
    await expect(page.getByRole('button', { name: 'Try again' })).toBeVisible({timeout:10000});

    expect(page.locator('.error-msg p')).toContainText('Retrieval failed, try again', {timeout:10000});
  });


});
