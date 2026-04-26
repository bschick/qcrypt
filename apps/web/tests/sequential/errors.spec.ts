import { test, expect, Page, CDPSession } from '@playwright/test';
import {
  testWithAuth,
  passkeyAuth,
  addCredential,
  hosts,
  credentials,
} from '.././common';


test.describe('errors', () => {

  // Uses shared KeeperTwo. A parallel sign-in (other test in another session
  // or another runner) can invalidate this session before the test finishes —
  // playwright's retry recovers. Single login + local-only operations after,
  // so retry is sufficient and we keep the shared user.
  testWithAuth('enc dec errors', async ({ authFixture }) => {
    const { page, session, authId1, authId2 } = authFixture;
    test.setTimeout(45000);

    await page.goto('/');

    const testHost = new URL(page.url()).hostname as hosts;
    await addCredential(session, authId1, credentials[testHost]['keeper2']['id']);

    await passkeyAuth(session, authId1, async () => {
      await page.getByRole('button', { name: 'I have used Quick Crypt' }).click();
    });
    await page.waitForURL('/', { waitUntil: 'domcontentloaded' });
    await expect(page.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({timeout:10000});

    await page.getByRole('button', { name: 'Encrypt Text'}).click();
    expect(page.locator('.errorBox').nth(1)).toContainText(/Missing clear text/);

    await page.getByRole('button', { name: 'Decrypt Text'}).click();
    expect(page.locator('.errorBox').nth(0)).toContainText(/Missing cipher armor/);

  });

});
