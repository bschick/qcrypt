import { test, expect } from '@playwright/test';
import {
  testWithAuth,
  addCredential,
  credentials,
  passkeyAuth,
  hosts,
  openCredentials
} from '.././common';


testWithAuth('edit fields', async ({ authFixture }) => {
  const { page, session, authId1, authId2 } = authFixture;
  test.setTimeout(60000);
  const rand = Math.floor(Math.random() * (99 - 0 + 1)) + 0;

  await page.goto('/');

  const testHost = new URL(page.url()).hostname as hosts;
  await addCredential(session, authId1, credentials[testHost]['keeper2']['id']);

  await passkeyAuth(session, authId1, async () => {
    await page.getByRole('button', { name: 'I have used Quick Crypt' }).click();
  });
  await page.waitForURL('/', { waitUntil: 'domcontentloaded' });
  await expect(page.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({timeout:10000});

  await openCredentials(page);

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

testWithAuth('options persistence and defaults', async ({ authFixture }) => {
  const { page, session, authId1, authId2 } = authFixture;
  test.setTimeout(60000);
  const rand = Math.floor(Math.random() * (99 - 0 + 1)) + 0;

  await page.goto('/');

  const testHost = new URL(page.url()).hostname as hosts;
  await addCredential(session, authId1, credentials[testHost]['keeper2']['id']);

  await passkeyAuth(session, authId1, async () => {
    await page.getByRole('button', { name: 'I have used Quick Crypt' }).click();
  });
  await page.waitForURL('/', { waitUntil: 'domcontentloaded' });
  await page.locator('mat-expansion-panel-header').filter({ hasText: 'Encryption Mode' }).click();
  await expect(page.locator('text="XChaCha20 Poly1305"')).toHaveCount(1);
  await page.locator('mat-expansion-panel-header').filter({ hasText: 'Advanced Options' }).click();

  await page.getByRole('switch', { name: 'Check If Stolen' }).check();
  await page.getByRole('switch', { name: 'Clear When Hidden' }).uncheck();
  await page.getByRole('switch', { name: 'Hide Password' }).uncheck();
  await page.locator('mat-select#pwdStrength').click();
  await page.locator('mat-option').filter({ hasText: 'Strong' }).click();
  await page.getByLabel('Hash Iterations').fill('3210000');
  await page.locator('input[name="loops"]').fill('2');
  await page.keyboard.press('Tab');
  await page.locator('text="AEGIS 256"').nth(0).click();
  await page.locator('text="AES 256 GCM"').nth(1).click();

  // Log out and back in to verify persistence
  await openCredentials(page);
  let tableBody = page.locator('table.credtable tbody');
  await expect(tableBody.locator('tr')).toHaveCount(1);
  await expect(page.locator('mat-sidenav input').first()).toHaveValue('KeeperTwo');
  await page.getByRole('button', { name: /Sign out/ }).click();
  await expect(page.getByRole('heading', { name: /Quick Crypt Sign In/ })).toBeVisible({timeout:10000});

  await passkeyAuth(session, authId1, async () => {
    await page.getByRole('button', { name: /Sign in as KeeperTwo/ }).click();
  });
  await page.waitForURL('/', { waitUntil: 'domcontentloaded' });
  // Accordians should stay open
  await expect(page.locator('text="XChaCha20 Poly1305"')).toHaveCount(2);

  await expect(page.getByRole('switch', { name: 'Check If Stolen' })).toBeChecked();
  await expect(page.getByRole('switch', { name: 'Clear When Hidden' })).not.toBeChecked();
  await expect(page.getByRole('switch', { name: 'Hide Password' })).not.toBeChecked();
  await expect(page.getByRole('switch', { name: 'Decryption Reminder' })).toBeChecked();
  await expect(page.getByRole('combobox', { name: 'Default Strength' })).toContainText('Strong');
  await expect(page.locator('input[name="loops"]')).toHaveValue('2');
  await expect(page.locator('text="AEGIS 256"').nth(0)).toBeChecked();
  await expect(page.locator('text="AES 256 GCM"').nth(1)).toBeChecked();
  await expect(page.getByLabel('Hash Iterations')).toHaveValue('3210000');

  // Reset to default, check expected values then log out and in to verify persistence
  await page.getByRole('button', { name: 'Reset To Defaults' }).click();

  await openCredentials(page);
  tableBody = page.locator('table.credtable tbody');
  await expect(tableBody.locator('tr')).toHaveCount(1);
  await expect(page.locator('mat-sidenav input').first()).toHaveValue('KeeperTwo');
  await page.getByRole('button', { name: /Sign out/ }).click();
  await expect(page.getByRole('heading', { name: /Quick Crypt Sign In/ })).toBeVisible({timeout:10000});

  await passkeyAuth(session, authId1, async () => {
    await page.getByRole('button', { name: /Sign in as KeeperTwo/ }).click();
  });
  await page.waitForURL('/', { waitUntil: 'domcontentloaded' });
  // Accordians should stay open
  await expect(page.locator('text="AES 256 GCM"')).toHaveCount(1);
  await expect(page.getByRole('switch', { name: 'Check If Stolen' })).not.toBeChecked();
  await expect(page.getByRole('switch', { name: 'Clear When Hidden' })).toBeChecked();
  await expect(page.getByRole('switch', { name: 'Hide Password' })).toBeChecked();
  await expect(page.getByRole('switch', { name: 'Decryption Reminder' })).toBeChecked();
  await expect(page.getByRole('combobox', { name: 'Default Strength' })).toContainText('Good');
  await expect(page.locator('input[name="loops"]')).toHaveValue('1');
  await expect(page.locator('text="XChaCha20 Poly1305"').nth(0)).toBeChecked();
  await expect(page.getByLabel('Hash Iterations')).not.toHaveValue('3210000');
});