
import { test, expect } from '@playwright/test';

test('dark mode toggle', async ({ page }) => {
  await page.goto('/');

  // Click the dark mode toggle button
  await page.click('button[aria-label="Toggle dark mode"]');

  // Expect the body to have the dark-mode class
  await expect(page.locator('body')).toHaveClass('dark-mode');

  // Click the dark mode toggle button again
  await page.click('button[aria-label="Toggle dark mode"]');

  // Expect the body to not have the dark-mode class
  await expect(page.locator('body')).not.toHaveClass('dark-mode');
});
