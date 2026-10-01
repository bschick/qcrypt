import { expect, test } from '@playwright/test';
import { testWithAuth, fillPwdAndAccept } from '.././common';

const TEXT_AREA_TIP = 'To encrypt some data, type or paste text here';
const ENCRYPT_TIP = 'When you have finished entering text, click the Encrypt button';
const PASSWORD = 'Xk7$pLm2#qRw9';

test.describe('main page', () => {
   testWithAuth('help bubbles follow whether there is clear text', async ({ authFixture }) => {
      const { page } = authFixture;
      await authFixture.createTestUser(authFixture.memAuthenticator());

      const textAreaBubble = page.locator('.bubble--visible', { hasText: TEXT_AREA_TIP });
      const encryptBubble = page.locator('.bubble--visible', { hasText: ENCRYPT_TIP });
      await expect(textAreaBubble).toBeVisible({ timeout: 10000 });

      const clearInput = page.locator('textarea#clearInput');
      await clearInput.pressSequentially('secret');
      await expect(encryptBubble).toBeVisible();
      await expect(textAreaBubble).toHaveCount(0);

      await clearInput.selectText();
      await clearInput.press('Backspace');
      await expect(textAreaBubble).toBeVisible();
      await expect(encryptBubble).toHaveCount(0);
   });

   testWithAuth('a cached password counts down and is flushed when its time runs out', async ({ authFixture }) => {
      const { page } = authFixture;
      const testUser = await authFixture.createTestUser(authFixture.memAuthenticator());

      await page.getByRole('button', { name: 'Advanced Options' }).click();
      await page.getByLabel('Cache Time (secs)').fill('4');

      const clearInput = page.locator('textarea#clearInput');
      await clearInput.fill('secret');
      await page.getByRole('button', { name: 'Encrypt Text' }).click();
      await fillPwdAndAccept(page, new RegExp(testUser.userName), PASSWORD, undefined, 'enc', async () => {});
      await expect(page.locator('textarea#cipherInput')).not.toBeEmpty({ timeout: 10000 });

      const flush = page.locator('button.clear-button');
      await expect(flush).toBeVisible();
      await expect(flush).toHaveText(/\((4|3)\)/);
      await expect(flush).toHaveText(/\(1\)/, { timeout: 6000 });
      await expect(flush).toBeHidden({ timeout: 6000 });
      await expect(clearInput).toHaveValue('');
   });

   testWithAuth('URL text loads with a warning that clears once the text is erased', async ({ authFixture }) => {
      const { page } = authFixture;
      const testUser = await authFixture.createTestUser(authFixture.memAuthenticator());

      const clearInput = page.locator('textarea#clearInput');
      const cipherInput = page.locator('textarea#cipherInput');
      await clearInput.fill('secret');
      await page.getByRole('button', { name: 'Encrypt Text' }).click();
      await fillPwdAndAccept(page, new RegExp(testUser.userName), PASSWORD, undefined, 'enc', async () => {});
      await expect(cipherInput).not.toBeEmpty({ timeout: 10000 });
      const armor = await cipherInput.inputValue();

      const linkText = 'hello from a link';
      await page.goto(`/?cleartext=${encodeURIComponent(linkText)}&cipherarmor=${encodeURIComponent(armor)}`);
      await expect(clearInput).toHaveValue(linkText, { timeout: 10000 });
      await expect(cipherInput).toHaveValue(armor);
      const warnings = page.getByRole('button', { name: 'Warning' });
      await expect(warnings).toHaveCount(2);

      await clearInput.selectText();
      await clearInput.press('Backspace');
      await expect(warnings).toHaveCount(1);

      await cipherInput.selectText();
      await cipherInput.press('Backspace');
      await expect(warnings).toHaveCount(0);
   });
});
