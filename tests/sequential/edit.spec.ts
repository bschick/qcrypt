import { test, expect } from '@playwright/test';
import {
  testWithAuth,
  addCredential,
  credentials,
  passkeyAuth,
  hosts
} from '.././common';


testWithAuth('edit fields', async ({ authFixture }) => {
  const { page, session, authId } = authFixture;
  test.setTimeout(60000);
  const rand = Math.floor(Math.random() * (99 - 0 + 1)) + 0;

  await page.goto('/');

  const testHost = new URL(page.url()).hostname as hosts;
  await addCredential(session, authId, credentials[testHost]['keeper1']['id']);

  await passkeyAuth(session, authId, async () => {
    await page.getByRole('button', { name: 'I have used Quick Crypt' }).click();
  });
  await page.waitForURL('/', { waitUntil: 'domcontentloaded' });
  await expect(page.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({timeout:10000});

  await page.getByRole('button', { name: 'Passkey information' }).click();

  await page.locator('mat-sidenav input').first().click();
  await page.locator('mat-sidenav input').first().fill('Keeper<script>'+rand);
  await page.keyboard.press('Enter');

  await expect(page.getByText('User name updated')).toBeVisible({timeout:10000});
  await expect(page.getByText('User name updated')).not.toBeVisible({timeout:10000});
  await expect(page.locator('mat-sidenav input').first()).toHaveValue('Keeper'+rand);

  await page.locator('mat-sidenav input').first().click();
  await page.locator('mat-sidenav input').first().fill('KeeperTwo');
  await page.keyboard.press('Enter');
  await expect(page.getByText('User name updated')).toBeVisible({timeout:10000});
  await expect(page.getByText('User name updated')).not.toBeVisible({timeout:10000});
  await expect(page.locator('mat-sidenav input').first()).toHaveValue('KeeperTwo');

  await page.locator('mat-sidenav input').nth(1).click();
  await page.locator('mat-sidenav input').nth(1).fill('VirtualPK'+rand);
  await page.keyboard.press('Enter');

  await expect(page.getByText('Passkey description updated')).toBeVisible({timeout:10000});
  await expect(page.getByText('Passkey description updated')).not.toBeVisible({timeout:10000});
  await expect(page.locator('mat-sidenav input').nth(1)).toHaveValue('VirtualPK'+rand);

  await page.locator('mat-sidenav input').nth(1).click();
  await page.locator('mat-sidenav input').nth(1).fill('Passkey');
  await page.keyboard.press('Enter');

  await expect(page.getByText('Passkey description updated')).toBeVisible({timeout:10000});
  await expect(page.getByText('Passkey description updated')).not.toBeVisible({timeout:10000});
  await expect(page.locator('mat-sidenav input').nth(1)).toHaveValue('Passkey');

});