import { test, expect, Page, CDPSession } from '@playwright/test';

test('has title', async ({ page }) => {
  await page.goto('/');

  // Expect a title "to contain" a substring.
  await expect(page).toHaveTitle(/Quick Crypt/);
  await expect(page.getByRole('heading', { name: /Quick Crypt: Easy, Trustworthy/ })).toBeVisible();
});

test('new user fill in', async ({ page }) => {
  await page.goto('/');

  // Click the get started link.
  await page.getByRole('button', { name: 'I am new to Quick Crypt' }).click();

  // Expects page to have a heading with the name of Installation.
  await expect(page.getByRole('heading', { name: 'Create A New user' })).toBeVisible();

  await page.locator('input#userName').fill('PWFlippy');
  await expect(page.locator('input#userName')).toHaveValue('PWFlippy');

});

test('get overview', async ({ page }) => {
  await page.goto('/');

  // Click the get started link.
  await page.getByRole('button', { name: 'Help' }).click();

  // Click the get started link.
  await page.getByRole('menuitem', { name: 'Overview' }).click();

  // Expects page to have a heading with the name of Installation.
  await expect(page.getByRole('heading', { name: 'Quick Crypt: Easy, Trustworthy Personal Encryption' })).toBeVisible();
});
