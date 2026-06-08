import { test, expect, Page, CDPSession } from '@playwright/test';
import {
  testWithAuth,
  passkeyAuth,
  passkeyCreation,
  deleteFirstPasskey,
  clearCredentials,
  toggleCredentials
} from '.././common';


test.describe('errors', () => {

  testWithAuth('user too short', async ({ authFixture }) => {
    const { page, session, authenticatorId1, authenticatorId2 } = authFixture;

    await page.goto('/');

    await passkeyCreation(page, session, authenticatorId1, async () => {
      await page.getByRole('button', { name: 'I am new to Quick Crypt' }).click();
      await expect(page.getByRole('heading', { name: 'Create A New user' })).toBeVisible({timeout:10000});
      await page.locator('input#userName').fill('short');
      await page.getByRole('button', { name: /Create new/ }).click();
    }, false);

    const parent = page.locator('.error-msg p');
    expect(parent).toContainText('User name must be 6 to 31 characters long');
  });

  testWithAuth('user too long', async ({ authFixture }) => {
    const { page, session, authenticatorId1, authenticatorId2 } = authFixture;

    await page.goto('/');

    await passkeyCreation(page, session, authenticatorId1, async () => {
      await page.getByRole('button', { name: 'I am new to Quick Crypt' }).click();
      await expect(page.getByRole('heading', { name: 'Create A New user' })).toBeVisible({timeout:10000});
      await page.locator('input#userName').fill('1234567890123456789012345678901234567890');
      await page.getByRole('button', { name: /Create new/ }).click();
    }, false);

    const parent = page.locator('.error-msg p');
    expect(parent).toContainText('User name must be 6 to 31 characters long');
  });

  testWithAuth('no passkey cold', async ({ authFixture }) => {
    const { page, session, authenticatorId1, authenticatorId2 } = authFixture;

    await page.goto('/');

    await passkeyAuth(page, session, authenticatorId1, async () => {
      await page.getByRole('button', { name: 'I have used Quick Crypt' }).click();
    }, false);
    const parent = page.locator('p.error-msg');
    expect(parent).toContainText(/Passkey not recognized/);
  });

  testWithAuth('no passkey re-signin', async ({ authFixture }) => {
    const { page, session, authenticatorId1 } = authFixture;

    const testUser = await authFixture.createTestUser(authenticatorId1);

    await toggleCredentials(page);
    await page.getByRole('button', { name: /Sign out/ }).click();

    await clearCredentials(session, authenticatorId1);

    await passkeyAuth(page, session, authenticatorId1, async () => {
      await page.getByRole('button', { name: new RegExp(`Sign in as ${testUser.userName}`) }).click();
    }, false);

    expect(page.locator('div.button-host div.error-msg')).toContainText(/Sign in failed, try again or change users/);
  });


  testWithAuth('edit errors', async ({ authFixture }) => {
    const { page, authenticatorId1 } = authFixture;
    test.setTimeout(45000);

    await authFixture.createTestUser(authenticatorId1);

    await toggleCredentials(page);

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
    const { page, session, authenticatorId1 } = authFixture;
    test.setTimeout(45000);

    await authFixture.createTestUser(authenticatorId1);

    await toggleCredentials(page);

    await clearCredentials(session, authenticatorId1);

    await passkeyAuth(page, session, authenticatorId1, async () => {
      await page.getByRole('button', { name: /Show recovery link/ }).click();
    }, false);

    await expect(page).toHaveURL(/\/showrecovery$/);
    await expect(page.getByRole('button', { name: 'Try again' })).toBeVisible({timeout:10000});

    expect(page.locator('.error-msg p')).toContainText('Retrieval failed, try again', {timeout:10000});

  });

  testWithAuth('no usercred access', async ({ authFixture }) => {
    const { page, session, authenticatorId1 } = authFixture;
    test.setTimeout(45000);

    await authFixture.createTestUser(authenticatorId1);

    await clearCredentials(session, authenticatorId1);

    await passkeyAuth(page, session, authenticatorId1, async () => {
      await page.goto('/cmdline');
    }, false);

    await expect(page).toHaveURL(/\/cmdline$/);
    await expect(page.getByRole('button', { name: 'Try again' })).toBeVisible({timeout:10000});

    expect(page.locator('.error-msg p')).toContainText('Retrieval failed, try again', {timeout:10000});
  });


});
