import { test, expect } from '@playwright/test';
import { testWithAuth, toggleCredentials } from '.././common';

// When a registering passkey has no PRF, the client offers a dialog with two choices.
// Standard protection keeps that same passkey as a no-PRF account, for one create in
// total. A different passkey discards it and registers another, for two creates.

test.describe('prf fallback', () => {
   testWithAuth('one no-PRF authenticator registers a no-PRF account', async ({ authFixture }) => {
      const { page } = authFixture;
      test.setTimeout(45000);

      const noPrfAuth = authFixture.memAuthenticator('none');
      const testUser = await authFixture.createTestUser(noPrfAuth);

      expect(authFixture.credentialCreateCount()).toBe(1);
      expect(testUser.prf).toBe(false);

      await toggleCredentials(page);
      await expect(page.locator('.prf-badge')).toHaveCount(0);
      await expect(page.locator('table.credtable tbody tr')).toHaveCount(1);
   });

   // Restarting registration abandons the first reg/options account, and nothing can delete an
   // account with no passkey. The client reuses the entered name for the retry, so both accounts
   // carry the lky mark rather than only the abandoned one.
   testWithAuth(
      'a no-PRF authenticator followed by a PRF one registers a PRF account',
      { tag: '@u:lky_prffal' },
      async ({ authFixture }) => {
         const { page } = authFixture;
         test.setTimeout(45000);

         const noPrfAuth = authFixture.memAuthenticator('none');
         const prfAuth = authFixture.memAuthenticator('hmac-secret-mc');
         const testUser = await authFixture.createTestUser(noPrfAuth, prfAuth);

         expect(authFixture.credentialCreateCount()).toBe(2);
         expect(testUser.prf).toBe(true);

         await toggleCredentials(page);
         await expect(page.locator('.prf-badge')).toBeVisible();
         await expect(page.locator('table.credtable tbody tr')).toHaveCount(1);
      },
   );
});
