import { test, expect, Response } from '@playwright/test';
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

  const nameInput = page.locator('mat-sidenav input').first();
  const descInput = page.locator('mat-sidenav input').nth(1);

  // The success toast is only shown for ~2s, so polling for it can race with
  // its appearance/removal. Instead, wait for the PATCH response and then
  // assert the stable post-state (input value reflects server-sanitized result).
  const userPatch = (response: Response) =>
    response.url().includes('/user') &&
    !response.url().includes('/users/') &&
    response.request().method() === 'PATCH';

  const passkeyPatch = (response: Response) =>
    response.url().includes('/passkeys') &&
    response.request().method() === 'PATCH';

  await nameInput.click();
  await nameInput.fill('Keeper<script>'+rand);
  await expect(nameInput).toHaveValue('Keeper<script>'+rand);
  let [resp] = await Promise.all([
    page.waitForResponse(userPatch),
    nameInput.press('Enter')
  ]);
  expect(resp.status()).toBe(200);
  await expect(nameInput).toHaveValue('Keeper'+rand);

  await nameInput.click();
  await nameInput.fill('KeeperTwo');
  await expect(nameInput).toHaveValue('KeeperTwo');
  [resp] = await Promise.all([
    page.waitForResponse(userPatch),
    nameInput.press('Enter')
  ]);
  expect(resp.status()).toBe(200);
  await expect(nameInput).toHaveValue('KeeperTwo');

  await descInput.click();
  await descInput.fill('VirtualPK'+rand);
  await expect(descInput).toHaveValue('VirtualPK'+rand);
  [resp] = await Promise.all([
    page.waitForResponse(passkeyPatch),
    descInput.press('Enter')
  ]);
  expect(resp.status()).toBe(200);
  await expect(descInput).toHaveValue('VirtualPK'+rand);

  await descInput.click();
  await descInput.fill('Passkey');
  await expect(descInput).toHaveValue('Passkey');
  [resp] = await Promise.all([
    page.waitForResponse(passkeyPatch),
    descInput.press('Enter')
  ]);
  expect(resp.status()).toBe(200);
  await expect(descInput).toHaveValue('Passkey');

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
  await expect(page.getByRole('heading', { name: /Quick Crypt Sign In/ })).not.toBeVisible();
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
  await expect(page.getByRole('heading', { name: /Quick Crypt Sign In/ })).not.toBeVisible();
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