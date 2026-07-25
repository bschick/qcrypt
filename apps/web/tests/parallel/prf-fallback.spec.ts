import { test, expect } from '@playwright/test';
import { testWithAuth, toggleCredentials } from '.././common';

// When a registering passkey has no PRF, the client offers a dialog: 'standard'
// completes that same passkey (one create) as a no-PRF account, 'different' discards
// it and registers a fresh one (a second create).

test.describe('prf fallback', () => {
   testWithAuth('standard completes the same passkey as a no-PRF account', async ({ authFixture }) => {
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

   testWithAuth('different discards and recreates as a PRF account', async ({ authFixture }) => {
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
   });
});
