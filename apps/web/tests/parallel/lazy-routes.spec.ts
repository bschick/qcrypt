import { test, expect } from '@playwright/test';

test.describe('lazy routes render', () => {
  const smokeRoutes = [
    '/welcome',
    '/newuser',
    '/recovery',
    '/recovery2',
    '/help/overview',
    '/help/faqs',
    '/help/protocol',
    '/help/protocol1',
    '/help/protocol4',
    '/help/protocol5',
    '/help/protocol6',
  ];

  for (const path of smokeRoutes) {
    test(`loads ${path}`, async ({ page }) => {
      await page.goto(path);
      await page.waitForURL(path, { waitUntil: 'domcontentloaded' });
      await expect(page.locator('[role=main]')).toBeVisible({ timeout: 10000 });
    });
  }
});

test.describe('help page content', () => {
  test('/help/overview shows its top header', async ({ page }) => {
    await page.goto('/help/overview');
    await expect(
      page.getByRole('heading', { name: /Easy, Trustworthy Personal Encryption/ })
    ).toBeVisible({ timeout: 10000 });
  });

  test('/help/faqs shows its top header', async ({ page }) => {
    await page.goto('/help/faqs');
    await expect(
      page.getByRole('heading', { name: 'Frequently Asked Questions' })
    ).toBeVisible({ timeout: 10000 });
  });

  test('/help/protocol shows its top header', async ({ page }) => {
    await page.goto('/help/protocol');
    await expect(
      page.getByRole('heading', { name: /Protocol Description/ })
    ).toBeVisible({ timeout: 10000 });
  });
});
