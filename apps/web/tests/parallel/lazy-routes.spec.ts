import { test, expect } from '@playwright/test';

test.describe('lazy routes render', () => {
   const smokeRoutes = [
      '/newuser',
      '/recovery',
      '/recovery3',
      '/help/overview',
      '/help/faqs',
      '/help/faqs/bad',
      '/help/protocol',
      '/help/protocol1',
      '/help/protocol4',
      '/help/protocol5',
      '/help/protocol6',
   ];

   for (const path of smokeRoutes) {
      test(`loads ${path}`, async ({ page }) => {
         await page.goto(path);
         await expect(page).toHaveURL(new RegExp(`${path.replace(/\//g, '\\/')}$`));
         await expect(page.locator('mat-sidenav-content')).toBeVisible({ timeout: 10000 });
      });
   }
});

test.describe('help page content', () => {
   test('/help/overview shows its top header', async ({ page }) => {
      await page.goto('/help/overview');
      await expect(page.getByRole('heading', { name: /Easy, Trustworthy Personal Encryption/ })).toBeVisible({
         timeout: 10000,
      });
   });

   test('/help/faqs shows its top header', async ({ page }) => {
      await page.goto('/help/faqs');
      await expect(page.getByRole('heading', { name: 'Frequently Asked Questions' })).toBeVisible({ timeout: 10000 });
   });

   test('/help/faqs/bad shows that one answer alone', async ({ page }) => {
      await page.goto('/help/faqs/bad');
      await expect(page.getByText(/obtained my emergency recovery sheet/)).toBeVisible({ timeout: 10000 });
      await expect(page.getByRole('link', { name: /All FAQs/ })).toBeVisible();
      await expect(page.locator('tr.element-row')).toHaveCount(1);
   });

   test('/help/protocol shows its top header', async ({ page }) => {
      await page.goto('/help/protocol');
      await expect(page.getByRole('heading', { name: /Protocol Description/ })).toBeVisible({ timeout: 10000 });
   });
});
