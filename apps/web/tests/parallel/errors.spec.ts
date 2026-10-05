import { test, expect, Response } from '@playwright/test';
import { testWithAuth, toggleCredentials, waitForApiResponse } from '.././common';

test.describe('errors', () => {
   testWithAuth('user too short', async ({ authFixture }) => {
      const { page } = authFixture;

      await page.goto('/');

      // Client rejects on length before any passkey ceremony.
      await page.getByRole('button', { name: 'I am new to Quick Crypt' }).click();
      await expect(page.getByRole('heading', { name: 'Create A New user' })).toBeVisible({ timeout: 10000 });
      await page.locator('input#userName').fill('short');
      await page.getByRole('button', { name: /Create new/ }).click();

      const parent = page.locator('.error-msg p');
      await expect(parent).toContainText('User name must be 6 to 31 characters long');
   });

   testWithAuth('user too long', async ({ authFixture }) => {
      const { page } = authFixture;

      await page.goto('/');

      await page.getByRole('button', { name: 'I am new to Quick Crypt' }).click();
      await expect(page.getByRole('heading', { name: 'Create A New user' })).toBeVisible({ timeout: 10000 });
      await page.locator('input#userName').fill('1234567890123456789012345678901234567890');
      await page.getByRole('button', { name: /Create new/ }).click();

      const parent = page.locator('.error-msg p');
      await expect(parent).toContainText('User name must be 6 to 31 characters long');
   });

   testWithAuth('no passkey cold', async ({ authFixture }) => {
      const { page } = authFixture;

      await page.goto('/');

      // An authenticator with no credential fails the discoverable sign-in.
      await authFixture.passkeyAuth(
         authFixture.memAuthenticator(),
         async () => {
            await page.getByRole('button', { name: 'I have used Quick Crypt' }).click();
         },
         { awaitVerify: false },
      );
      const parent = page.locator('p.error-msg');
      await expect(parent).toContainText(/Passkey not recognized/);
   });

   testWithAuth('no passkey re-signin', async ({ authFixture }) => {
      const { page } = authFixture;

      const testUser = await authFixture.createTestUser(authFixture.memAuthenticator());

      await toggleCredentials(page);
      await page.getByRole('button', { name: /Sign out/ }).click();

      // Sign in from a device that lacks the passkey → an empty authenticator.
      await authFixture.passkeyAuth(
         authFixture.memAuthenticator(),
         async () => {
            await page.getByRole('button', { name: new RegExp(`Sign in as ${testUser.userName}`) }).click();
         },
         { awaitVerify: false },
      );

      await expect(page.locator('.signin div.error-msg')).toContainText(/Sign in failed, try again or change users/);
   });

   testWithAuth('edit errors', async ({ authFixture }) => {
      const { page } = authFixture;
      test.setTimeout(45000);

      await authFixture.createTestUser(authFixture.memAuthenticator());

      await toggleCredentials(page);

      await page.locator('mat-sidenav input').first().click();
      await page.locator('mat-sidenav input').first().fill('12345');
      await page.keyboard.press('Enter');

      await expect(page.locator('div.error-msg')).toContainText(/Name change failed, must be 6 to 31 characters/);

      // A rejected name keeps focus, and Escape abandons it so another field can take the click
      await page.keyboard.press('Escape');
      await expect(page.locator('div.error-msg')).not.toContainText('Name change failed');

      await page.locator('mat-sidenav input').nth(1).click();
      await page.locator('mat-sidenav input').nth(1).fill('12345');
      await page.keyboard.press('Enter');

      await expect(page.locator('div.error-msg')).toContainText(
         /Description change failed, must be 6 to 42 characters/,
      );

      await page.keyboard.press('Escape');
      await expect(page.locator('div.error-msg')).not.toContainText('Description change failed');

      // Long enough as typed, but the server removes the tag before counting
      await page.locator('mat-sidenav input').nth(1).fill('1Pass<script>');
      await page.keyboard.press('Enter');

      await expect(page.locator('div.error-msg')).toContainText(
         /Description change failed, must be 6 to 42 characters after unsupported characters are removed/,
      );
   });

   testWithAuth('no recovery access', async ({ authFixture }) => {
      const { page } = authFixture;
      test.setTimeout(45000);

      await authFixture.createTestUser(authFixture.memAuthenticator());

      await toggleCredentials(page);

      await page.getByRole('button', { name: /Replace recovery words/ }).click();
      await expect(page).toHaveURL(/\/regenrecovery$/);

      // Reauthenticating from a device without the passkey fails the replacement.
      await authFixture.passkeyAuth(
         authFixture.memAuthenticator(),
         async () => {
            await page.getByRole('button', { name: /Generate new recovery words/ }).click();
         },
         { awaitVerify: false },
      );

      await expect(page).toHaveURL(/\/regenrecovery$/);
      await expect(page.locator('.error-msg p')).toContainText('Could not replace recovery words', { timeout: 15000 });
   });

   testWithAuth('no usercred access', async ({ authFixture }) => {
      const { page } = authFixture;
      test.setTimeout(45000);

      await authFixture.createTestUser(authFixture.memAuthenticator());

      // Reauthenticating from a device without the passkey fails the userCred fetch.
      await authFixture.passkeyAuth(
         authFixture.memAuthenticator(),
         async () => {
            await page.goto('/cmdline');
         },
         { awaitVerify: false },
      );

      await expect(page).toHaveURL(/\/cmdline$/);
      await expect(page.getByRole('button', { name: 'Try again' })).toBeVisible({ timeout: 10000 });

      await expect(page.locator('.error-msg p')).toContainText('Retrieval failed, try again', { timeout: 10000 });
   });

   testWithAuth('another account passkey on device', async ({ authFixture }) => {
      const { page } = authFixture;
      test.setTimeout(60000);

      // A separate account's device holds only userB's passkey.
      const authB = authFixture.memAuthenticator();
      await authFixture.createTestUser(authB);
      await toggleCredentials(page);
      await page.getByRole('button', { name: /Sign out/ }).click();
      await page.getByRole('button', { name: /Sign in as a different user/ }).click();
      await expect(page).toHaveURL(/\/welcome$/);

      const authA = authFixture.memAuthenticator();
      const userA = await authFixture.createTestUser(authA);
      await toggleCredentials(page);
      await page.getByRole('button', { name: /Sign out/ }).click();

      // Signing in as userA asks for userA's passkey, but authB holds only userB's, so
      // the authenticator has a resident credential yet none the request accepts.
      await authFixture.passkeyAuth(
         authB,
         async () => {
            await page.getByRole('button', { name: new RegExp(`Sign in as ${userA.userName}`) }).click();
         },
         { awaitVerify: false },
      );

      await expect(page.locator('.signin div.error-msg')).toContainText(/Sign in failed, try again or change users/);
   });

   testWithAuth('failed sign out is reported', async ({ authFixture }) => {
      const { page } = authFixture;

      await authFixture.createTestUser(authFixture.memAuthenticator());

      // Only the session delete fails, leaving the rest of the sign out to proceed normally
      await page.route('**/v1/session', async (route) => {
         if (route.request().method() === 'DELETE') {
            await route.abort('failed');
         } else {
            await route.continue();
         }
      });

      await toggleCredentials(page);
      await page.getByRole('button', { name: /Sign out/ }).click();

      await expect(page.locator('.signin div.error-msg')).toContainText(/Sign out failed/);
   });

   testWithAuth('failed rename keeps the entered name for editing', async ({ authFixture }) => {
      const { page } = authFixture;
      const rand = Math.floor(Math.random() * 100);

      await authFixture.createTestUser(authFixture.memAuthenticator());
      await toggleCredentials(page);

      const nameInput = page.locator('mat-sidenav input').first();
      const accepted = `PWTesty_err_${rand}`;

      const userPatch = (response: Response) =>
         response.url().includes('/user') &&
         !response.url().includes('/users/') &&
         response.request().method() === 'PATCH';

      await nameInput.click();
      await nameInput.fill(accepted);
      const [resp] = await Promise.all([waitForApiResponse(page, userPatch), nameInput.press('Enter')]);
      expect(resp.status()).toBe(200);
      await expect(nameInput).toHaveValue(accepted);

      await page.route('**/v1/user*', async (route) => {
         if (route.request().method() === 'PATCH') {
            await route.abort('failed');
         } else {
            await route.continue();
         }
      });

      const rejected = `PWTesty_gone_${rand}`;
      await nameInput.click();
      await nameInput.fill(rejected);
      await nameInput.press('Enter');

      await expect(page.locator('mat-sidenav .error-msg')).toContainText('Name change failed');
      await expect(nameInput).toHaveValue(rejected);
      await expect(nameInput).toBeFocused();

      // The entered name still differs from the stored one, so leaving the field saves it again
      await page.unroute('**/v1/user*');
      const [retry] = await Promise.all([waitForApiResponse(page, userPatch), nameInput.blur()]);
      expect(retry.status()).toBe(200);
      await expect(nameInput).toHaveValue(rejected);
   });
});
