import { test, expect, Page } from '@playwright/test';

test('Karam crypto unit tests', async ({ page }) => {
  test.setTimeout(265000);

  await page.goto('/');

  await expect(page).toHaveTitle(/Karma/);
  const frame = page.frameLocator('iframe[src="context.html"]');

  const durationSpan = frame.locator('span.jasmine-duration');
  await expect(durationSpan).toBeVisible({timeout:240000});

  const resultSpan = frame.locator('span.jasmine-overall-result');
  await expect(resultSpan).toHaveText(/0 failures/);

});
