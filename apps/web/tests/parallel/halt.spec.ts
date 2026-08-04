import { test, expect, type Page } from '@playwright/test';
import { randomBytes } from 'node:crypto';
import { testWithAuth, toggleCredentials, prfEncryptForPasskey } from '.././common';

// A response body is rewritten mid-flight to stand in for a server that contradicts what
// the browser recorded when it first signed in to the account.
type LoginBody = { prf: boolean; userId: string; pkId: string; userCred?: string; userCredEnc?: string };

async function expectStopped(page: Page): Promise<void> {
   await expect(page.getByText('Quick Crypt detected a problem')).toBeVisible({ timeout: 10000 });
   await expect(page.getByText('Quick Crypt Sign In')).toBeHidden();
   await expect(page.getByRole('button', { name: 'Sign in as a different user' })).toBeHidden();
   await expect(page.getByRole('button', { name: 'Encrypt Text' })).toBeHidden();
}

// The stop is in-memory, so dropping the interception and reloading leaves a working app
// for the fixture's cleanup to sign in and delete the account with.
async function restoreApp(page: Page): Promise<void> {
   await page.unroute('**/v1/auth/verify');
   await page.goto('/');
   await page.reload();
}

testWithAuth('stops when a PRF account is reported as no-PRF at sign in', async ({ authFixture }) => {
   const { page } = authFixture;
   test.setTimeout(45000);

   const authenticator = authFixture.memAuthenticator('hmac-secret-mc');
   const testUser = await authFixture.createTestUser(authenticator);

   await toggleCredentials(page);
   await page.getByRole('button', { name: /Sign out/ }).click();

   await page.route('**/v1/auth/verify', async (route) => {
      const response = await route.fetch();
      const body = (await response.json()) as LoginBody;
      body.prf = false;
      body.userCred = randomBytes(32).toString('base64url');
      body.userCredEnc = undefined;
      await route.fulfill({ response: response, json: body });
   });

   await authFixture.passkeyAuth(authenticator, async () => {
      await page.getByRole('button', { name: new RegExp(`Sign in as ${testUser.userName}`) }).click();
   });

   await expectStopped(page);

   // The toolbar stays usable so the help pages explaining the stop are reachable
   await page.getByRole('button', { name: 'Help' }).click();
   await page.getByRole('menuitem', { name: 'Overview' }).click();
   await expect(page).toHaveURL(/\/help\/overview$/);
   await expect(page.getByText('Quick Crypt detected a problem')).toBeHidden();

   await restoreApp(page);
});

testWithAuth('stops when a PRF account returns a substituted credential', async ({ authFixture }) => {
   const { page } = authFixture;
   test.setTimeout(45000);

   const baseURL = (test.info().project.use as { baseURL: string }).baseURL;
   const origin = new URL(baseURL).origin;
   const rpId = new URL(baseURL).hostname;

   const authenticator = authFixture.memAuthenticator('hmac-secret-mc');
   const testUser = await authFixture.createTestUser(authenticator);

   await toggleCredentials(page);
   await page.getByRole('button', { name: /Sign out/ }).click();

   // The account stays PRF and the ciphertext still decrypts under this passkey, so only
   // the credential inside it is wrong
   await page.route('**/v1/auth/verify', async (route) => {
      const response = await route.fetch();
      const body = (await response.json()) as LoginBody;
      body.userCredEnc = await prfEncryptForPasskey(
         authenticator.emulator,
         origin,
         rpId,
         body.pkId,
         body.userId,
         new Uint8Array(randomBytes(32)),
      );
      await route.fulfill({ response: response, json: body });
   });

   await authFixture.passkeyAuth(authenticator, async () => {
      await page.getByRole('button', { name: new RegExp(`Sign in as ${testUser.userName}`) }).click();
   });

   await expectStopped(page);

   await restoreApp(page);
});
