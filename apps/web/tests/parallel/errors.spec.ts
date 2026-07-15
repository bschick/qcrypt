import { test, expect } from '@playwright/test';
import {
  testWithAuth,
  toggleCredentials
} from '.././common';


test.describe('errors', () => {

  testWithAuth('user too short', async ({ authFixture }) => {
    const { page } = authFixture;

    await page.goto('/');

    // Client rejects on length before any passkey ceremony.
    await page.getByRole('button', { name: 'I am new to Quick Crypt' }).click();
    await expect(page.getByRole('heading', { name: 'Create A New user' })).toBeVisible({timeout:10000});
    await page.locator('input#userName').fill('short');
    await page.getByRole('button', { name: /Create new/ }).click();

    const parent = page.locator('.error-msg p');
    await expect(parent).toContainText('User name must be 6 to 31 characters long');
  });

  testWithAuth('user too long', async ({ authFixture }) => {
    const { page } = authFixture;

    await page.goto('/');

    await page.getByRole('button', { name: 'I am new to Quick Crypt' }).click();
    await expect(page.getByRole('heading', { name: 'Create A New user' })).toBeVisible({timeout:10000});
    await page.locator('input#userName').fill('1234567890123456789012345678901234567890');
    await page.getByRole('button', { name: /Create new/ }).click();

    const parent = page.locator('.error-msg p');
    await expect(parent).toContainText('User name must be 6 to 31 characters long');
  });

  testWithAuth('no passkey cold', async ({ authFixture }) => {
    const { page } = authFixture;

    await page.goto('/');

    // An authenticator with no credential fails the discoverable sign-in.
    await authFixture.passkeyAuth(authFixture.newAuthenticator(), async () => {
      await page.getByRole('button', { name: 'I have used Quick Crypt' }).click();
    }, { awaitVerify: false });
    const parent = page.locator('p.error-msg');
    await expect(parent).toContainText(/Passkey not recognized/);
  });

  testWithAuth('no passkey re-signin', async ({ authFixture }) => {
    const { page } = authFixture;

    const testUser = await authFixture.createTestUser(authFixture.newAuthenticator());

    await toggleCredentials(page);
    await page.getByRole('button', { name: /Sign out/ }).click();

    // Sign in from a device that lacks the passkey → an empty authenticator.
    await authFixture.passkeyAuth(authFixture.newAuthenticator(), async () => {
      await page.getByRole('button', { name: new RegExp(`Sign in as ${testUser.userName}`) }).click();
    }, { awaitVerify: false });

    await expect(page.locator('div.button-host div.error-msg')).toContainText(/Sign in failed, try again or change users/);
  });


  testWithAuth('edit errors', async ({ authFixture }) => {
    const { page } = authFixture;
    test.setTimeout(45000);

    await authFixture.createTestUser(authFixture.newAuthenticator());

    await toggleCredentials(page);

    await page.locator('mat-sidenav input').first().click();
    await page.locator('mat-sidenav input').first().fill('12345');
    await page.keyboard.press('Enter');

    await expect(page.locator('div.error-msg')).toContainText(/Name change failed, must be 6 to 31 characters/);

    await page.locator('mat-sidenav input').nth(1).click();
    await page.locator('mat-sidenav input').nth(1).fill('12345');
    await page.keyboard.press('Enter');

    await expect(page.locator('div.error-msg')).toContainText(/Description change failed, must be 6 to 42 characters/);
  });


  testWithAuth('no recovery access', async ({ authFixture }) => {
    const { page } = authFixture;
    test.setTimeout(45000);

    await authFixture.createTestUser(authFixture.newAuthenticator());

    await toggleCredentials(page);

    await page.getByRole('button', { name: /Replace recovery words/ }).click();
    await expect(page).toHaveURL(/\/regenrecovery$/);

    // Reauthenticating from a device without the passkey fails the replacement.
    await authFixture.passkeyAuth(authFixture.newAuthenticator(), async () => {
      await page.getByRole('button', { name: /Generate new recovery words/ }).click();
    }, { awaitVerify: false });

    await expect(page).toHaveURL(/\/regenrecovery$/);
    await expect(page.locator('.error-msg p')).toContainText('Could not replace recovery words', {timeout:15000});

  });

  testWithAuth('no usercred access', async ({ authFixture }) => {
    const { page } = authFixture;
    test.setTimeout(45000);

    await authFixture.createTestUser(authFixture.newAuthenticator());

    // Reauthenticating from a device without the passkey fails the userCred fetch.
    await authFixture.passkeyAuth(authFixture.newAuthenticator(), async () => {
      await page.goto('/cmdline');
    }, { awaitVerify: false });

    await expect(page).toHaveURL(/\/cmdline$/);
    await expect(page.getByRole('button', { name: 'Try again' })).toBeVisible({timeout:10000});

    await expect(page.locator('.error-msg p')).toContainText('Retrieval failed, try again', {timeout:10000});
  });

  testWithAuth('another account passkey on device', async ({ authFixture }) => {
    const { page } = authFixture;
    test.setTimeout(60000);

    // A separate account's device holds only userB's passkey.
    const authB = authFixture.newAuthenticator();
    await authFixture.createTestUser(authB);
    await toggleCredentials(page);
    await page.getByRole('button', { name: /Sign out/ }).click();
    await page.getByRole('button', { name: /Sign in as a different user/ }).click();
    await expect(page).toHaveURL(/\/welcome$/);

    const authA = authFixture.newAuthenticator();
    const userA = await authFixture.createTestUser(authA);
    await toggleCredentials(page);
    await page.getByRole('button', { name: /Sign out/ }).click();

    // Signing in as userA asks for userA's passkey, but authB holds only userB's, so
    // the authenticator has a resident credential yet none the request accepts.
    await authFixture.passkeyAuth(authB, async () => {
      await page.getByRole('button', { name: new RegExp(`Sign in as ${userA.userName}`) }).click();
    }, { awaitVerify: false });

    await expect(page.locator('div.button-host div.error-msg')).toContainText(/Sign in failed, try again or change users/);
  });


});
