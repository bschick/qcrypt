import { test, expect } from '@playwright/test';
import { testWithAuth } from '.././common';

// Queries the live haveibeenpwned service, so it fails when that service is unreachable
const BREACHED_PWD = 'one2many';
const STRONG_PWD = 'Xk7$pLm2#qRw9';

testWithAuth('a breached password stays rejected while the hint is typed', async ({ authFixture }) => {
   const { page } = authFixture;
   test.setTimeout(45000);

   const authenticator = authFixture.memAuthenticator('none');
   await authFixture.createTestUser(authenticator);
   await expect(page.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({ timeout: 10000 });

   // The lowest minimum leaves the breach check as the only thing that can reject this password
   await page.getByRole('button', { name: 'Advanced Options' }).click();
   await page.locator('mat-select#pwdStrength').click();
   await page.locator('mat-option').filter({ hasText: 'Terrible' }).click();
   await page.getByRole('switch', { name: 'Check If Stolen' }).check();

   await page.locator('textarea#clearInput').fill('this is very secret');
   await page.getByRole('button', { name: 'Encrypt Text' }).click();

   await page.locator('input#password').fill(BREACHED_PWD);
   await expect(page.getByText('Password is allowed')).toBeVisible({ timeout: 10000 });

   // Leaving the field is what triggers the lookup
   await page.locator('input#password').press('Tab');
   await expect(page.getByText('Password is too weak')).toBeVisible({ timeout: 10000 });
   await expect(page.getByText(/exposed by a data breach/)).toBeVisible();

   // Scoring the password again must not discard what the lookup found
   await page.locator('input#hint').fill('a hint');
   // The rescore is on a timer, so the state has to still hold after it has run
   await page.waitForTimeout(500);
   await expect(page.getByText(/exposed by a data breach/)).toBeVisible();
   await expect(page.getByText('Password is too weak')).toBeVisible();

   await page.getByRole('button', { name: 'Accept' }).click();
   await expect(page.locator('input#password')).toBeVisible();
   await expect(page.getByText(/exposed by a data breach/)).toBeVisible();
   await expect(page.locator('textarea#cipherInput')).toBeEmpty();
});

testWithAuth('a failed breach check shows a notice and still encrypts', async ({ authFixture }) => {
   const { page } = authFixture;
   test.setTimeout(45000);

   const authenticator = authFixture.memAuthenticator('none');
   await authFixture.createTestUser(authenticator);
   await expect(page.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({ timeout: 10000 });

   await page.route('https://api.pwnedpasswords.com/**', (route) => route.abort());
   await page.getByRole('button', { name: 'Advanced Options' }).click();
   await page.getByRole('switch', { name: 'Check If Stolen' }).check();

   await page.locator('textarea#clearInput').fill('this is very secret');
   await page.getByRole('button', { name: 'Encrypt Text' }).click();

   await page.locator('input#password').fill(STRONG_PWD);
   await expect(page.getByText('Password is allowed')).toBeVisible({ timeout: 10000 });

   // Blurring the field triggers the lookup
   await page.locator('input#password').press('Tab');
   const notice = page.getByText('Could not check if your password was stolen');
   await expect(notice).toBeVisible({ timeout: 10000 });
   // Fails if the notice is hidden behind the dialog's backdrop
   await notice.hover({ trial: true });
   await expect(page.getByText('Password is allowed')).toBeVisible();

   await page.getByRole('button', { name: 'Accept' }).click();
   await expect(page.locator('textarea#cipherInput')).not.toBeEmpty({ timeout: 10000 });
});
