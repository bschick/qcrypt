import { test, expect } from '@playwright/test';
import { testWithAuth, toggleCredentials } from '.././common';

test('has title', async ({ page }) => {
  await page.goto('/');

  // Expect a title "to contain" a substring.
  await expect(page).toHaveTitle(/Quick Crypt/);
  await expect(page.getByText('Easy, Trustworthy Personal Encryption')).toBeVisible();
});

test('new user fill in', async ({ page }) => {
  await page.goto('/');

  // Click the get started link.
  await page.getByRole('button', { name: 'I am new to Quick Crypt' }).click();

  // Expects page to have a heading with the name of Installation.
  await expect(page.getByRole('heading', { name: 'Create A New user' })).toBeVisible();

  await page.locator('input#userName').fill('PWTesty_e2e_');
  await expect(page.locator('input#userName')).toHaveValue('PWTesty_e2e_');

});

test('get overview', async ({ page }) => {
  await page.goto('/');

  // Click the Overview link in the footer.
  await page.getByRole('link', { name: 'Overview' }).click();

  // Expects page to have a heading with the name of Installation.
  await expect(page.getByRole('heading', { name: 'Quick Crypt: Easy, Trustworthy Personal Encryption' })).toBeVisible();
});

testWithAuth('username is sanitized on create', async ({ authFixture }) => {
  const { page } = authFixture;
  test.setTimeout(45000);

  // The server strips <script> tags but keeps their inner text. The wrapper leaves
  // room for only a 2-digit suffix under the 31-character username limit.
  const suffix = Date.now().toString().slice(-2);
  const rawName = `PWTesty<script>_e2e_${suffix}</script>`;
  const sanitizedName = `PWTesty_e2e_${suffix}`;

  const authenticator = authFixture.memAuthenticator('none');
  await page.goto('/');

  const verifyPromise = page.waitForResponse((r) =>
    r.url().includes('/v1/reg/verify') && r.request().method() === 'POST'
  );
  await page.getByRole('button', { name: 'I am new to Quick Crypt' }).click();
  await expect(page.getByRole('heading', { name: 'Create A New user' })).toBeVisible({ timeout: 10000 });
  await page.locator('input#userName').fill(rawName);
  await page.getByRole('button', { name: /Create new/ }).click();
  await page.getByRole('button', { name: 'Continue with standard protection' }).click();

  const body = await (await verifyPromise).json();
  authFixture.trackUser({
    userId: body.userId,
    userName: sanitizedName,
    userCred: body.userCred,
    credentialId: body.pkId,
    authenticator,
    fastSession: { cookies: await page.context().cookies(), csrf: body.csrf },
  });

  await expect(page).toHaveURL(/\/showrecovery$/, { timeout: 10000 });
  await page.getByRole('button', { name: /I saved my/ }).click();
  await expect(page).toHaveURL(/\/$/);
  await expect(page.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({ timeout: 10000 });

  await toggleCredentials(page);
  await expect(page.locator('mat-sidenav input').first()).toHaveValue(sanitizedName);
});
