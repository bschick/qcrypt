import { test, expect } from '@playwright/test';
import { testWithAuth } from '.././common';

testWithAuth('checks recovery words against the stored key', async ({ authFixture }) => {
   const { page } = authFixture;
   test.setTimeout(90000);

   const authenticator = authFixture.memAuthenticator('hmac-secret-mc');
   await authFixture.createTestUser(authenticator);

   async function generateWords(): Promise<string> {
      await page.goto('/regenrecovery');
      await authFixture.passkeyAuth(authenticator, async () => {
         await page.getByRole('button', { name: 'Generate new recovery words' }).click();
      });
      await expect(page).toHaveURL(/\/showrecovery$/, { timeout: 10000 });
      return page.locator('textarea#wordsArea').inputValue();
   }

   async function check(words: string): Promise<void> {
      await page.locator('textarea#wordsArea').fill(words);
      await page.getByRole('button', { name: 'Check recovery words' }).click();
   }

   const supersededWords = await generateWords();
   const currentWords = await generateWords();
   expect(currentWords).not.toEqual(supersededWords);

   // Reached through the page that offers it, so the button only shown for accounts that
   // already have a recovery key is exercised too
   await page.goto('/regenrecovery');
   await page.getByRole('button', { name: 'Check existing recovery words' }).click();
   await expect(page).toHaveURL(/\/checkrecovery$/);

   await check(currentWords);
   await expect(page.getByText('These are the correct recovery words')).toBeVisible({ timeout: 10000 });

   await expect(page.getByRole('button', { name: 'Print emergency recovery sheet' })).toBeVisible();

   // The words this account used to have are well formed but no longer recover it
   await check(supersededWords);
   await expect(page.getByText('These recovery words are incorrect')).toBeVisible({ timeout: 10000 });
   await expect(page.getByRole('button', { name: 'Print emergency recovery sheet' })).toBeHidden();
});

testWithAuth('rejects input that is not a recovery word pattern', async ({ authFixture }) => {
   const { page } = authFixture;
   test.setTimeout(60000);

   const authenticator = authFixture.memAuthenticator('hmac-secret-mc');
   await authFixture.createTestUser(authenticator);

   await page.goto('/checkrecovery');

   await page.getByRole('button', { name: 'Check recovery words' }).click();
   await expect(page.getByText('Enter your recovery words')).toBeVisible();

   await page.locator('textarea#wordsArea').fill('these words are not a valid bip39 pattern at all');
   await page.getByRole('button', { name: 'Check recovery words' }).click();
   await expect(page.getByText('not formatted correctly')).toBeVisible({ timeout: 10000 });
});
