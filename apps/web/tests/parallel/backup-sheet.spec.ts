import { test, expect } from '@playwright/test';
import { testWithAuth } from '.././common';

// Records what a "Save as PDF" would be named, and keeps the print dialog from blocking
type PrintProbe = { printTitle?: string };

testWithAuth('emergency backup sheet prints both recovery values', async ({ authFixture }, testInfo) => {
   const { page } = authFixture;
   test.setTimeout(60000);

   const authenticator = authFixture.memAuthenticator('hmac-secret-mc');
   const testUser = await authFixture.createTestUser(authenticator);

   // Rotation is the second place the sheet is offered, and it yields a fresh pattern
   await page.goto('/regenrecovery');
   await authFixture.passkeyAuth(authenticator, async () => {
      await page.getByRole('button', { name: 'Generate new recovery words' }).click();
   });
   await expect(page).toHaveURL(/\/showrecovery$/, { timeout: 10000 });

   const recoveryWords = await page.locator('textarea#wordsArea').inputValue();
   expect(recoveryWords.split(/\s+/).length).toBeGreaterThan(11);

   await page.evaluate(() => {
      const probe = window as unknown as PrintProbe;
      probe.printTitle = undefined;
      window.print = () => {
         probe.printTitle = document.title;
      };
   });

   await page.getByRole('button', { name: 'Print emergency recovery sheet' }).click();

   // Both values belong on one sheet: the words alone die with the account, and the
   // credential alone is what still decrypts after it is gone
   const sheet = page.locator('.print-sheet');
   await expect(sheet).toContainText(recoveryWords);
   await expect(sheet).toContainText(testUser.userCred);
   // Printed on paper, so the link has to keep resolving after the id is out of our hands
   await expect(sheet).toContainText('/help/faqs/bad');

   await expect
      .poll(() => page.evaluate(() => (window as unknown as PrintProbe).printTitle))
      .toBe('quick_crypt_account_recovery');

   await page.emulateMedia({ media: 'print' });

   // Anything left in the layout keeps the page as wide as the app and crops the sheet
   await expect(page.getByRole('button', { name: 'Help' })).toBeHidden();
   const fit = await page.evaluate(() => {
      const box = document.querySelector('.print-sheet')!.getBoundingClientRect();
      return {
         sheetRight: Math.ceil(box.right),
         docWidth: document.documentElement.clientWidth,
         scrollWidth: document.documentElement.scrollWidth,
      };
   });
   expect(fit.sheetRight).toBeLessThanOrEqual(fit.docWidth);
   expect(fit.scrollWidth).toBeLessThanOrEqual(fit.docWidth);

   // Rendered at true paper size, which is the only place clipping actually shows up
   const pdfPath = testInfo.outputPath('backup-sheet.pdf');
   await page.pdf({ path: pdfPath, format: 'Letter', printBackground: true });
   await testInfo.attach('backup-sheet', { path: pdfPath, contentType: 'application/pdf' });

   await page.emulateMedia({ media: 'screen' });
});
