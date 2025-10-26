import { test, expect, Page } from '@playwright/test';

test('Karam unit tests', async ({ page }) => {
  test.setTimeout(205000);

  await page.goto('/');

  // Expect a title "to contain" a substring.
  await expect(page).toHaveTitle(/Karma/);

  const frame = page.frameLocator('iframe[src="context.html"]');

  const durationSpan = frame.locator('span.jasmine-duration');
  await expect(durationSpan).toBeVisible({timeout:180000});

  const resultSpan = frame.locator('span.jasmine-overall-result');
  await expect(resultSpan).toHaveText(/0 failures/);

});
