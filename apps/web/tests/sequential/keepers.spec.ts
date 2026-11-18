import { test, expect } from '@playwright/test';
import {
   hosts,
   keeperDir,
   keeperHandle,
   keepers,
   haveKeeperCreds,
   testWithAuth,
   toggleCredentials,
   expectPrfBadge,
} from '.././common';
import { decodeHandle } from '../../src/app/services/credentialtag';

// The other keeper specs pass whichever mode an account was created in, so without
// this a keeper provisioned in the wrong mode is only noticed when it silently stops
// covering the mode it was meant to cover.
for (const [keeper, { prf, tagged }] of Object.entries(keepers)) {
   testWithAuth(`${keeper} account prf mode and handle format`, async ({ authFixture }) => {
      test.skip(!haveKeeperCreds, 'keeper credentials not provided (apps/web/tests/keeper-creds)');
      const { page } = authFixture;

      await page.goto('/');

      const testHost = new URL(page.url()).hostname as hosts;

      const { userCredTag } = decodeHandle(keeperHandle(testHost, keeper));
      if (tagged) {
         expect(userCredTag).not.toBeNull();
      } else {
         expect(userCredTag).toBeNull();
      }

      const authenticator = authFixture.loadAuthenticator(keeperDir(testHost, keeper));

      await authFixture.passkeyAuth(authenticator, async () => {
         await page.getByRole('button', { name: 'I have used Quick Crypt' }).click();
      });
      await expect(page).toHaveURL(/\/$/);
      await expect(page.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({ timeout: 10000 });

      await toggleCredentials(page);
      await expectPrfBadge(page, prf);
   });
}
