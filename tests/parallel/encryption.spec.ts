import { test, expect, Page, CDPSession } from '@playwright/test';
import {
  hosts,
  credentials,
  testWithAuth,
  addCredential,
  passkeyAuth,
  fillPwdAndAccept
} from '.././common';



testWithAuth('encrypt decrypt', async ({ authFixture }) => {
  const { page, session, authId } = authFixture;

  await page.goto('/');

  const testHost = new URL(page.url()).hostname as hosts;
  await addCredential(session, authId, credentials[testHost]['keeper1']['id']);

  await passkeyAuth(session, authId, async () => {
    await page.getByRole('button', { name: 'I have used Quick Crypt' }).click();
  });
  await page.waitForURL('/', { waitUntil: 'domcontentloaded' });
  await expect(page.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({timeout:10000});

  const clearText = 'this is very secret, do not 🦜';
  const pwd = "you'll never know";
  const hint = "🚔";
  await page.locator('textarea#clearInput').fill(clearText);
  await page.getByRole('button', { name: 'Encrypt Text' }).click();

  await expect(page.getByRole('heading', { name: "KeeperOne" })).toBeVisible({timeout:10000});
  await fillPwdAndAccept(page, /KeeperOne/, pwd, hint, 'enc', async () => {
    await expect(page.getByText(/KeeperOne/)).toBeVisible({timeout:10000});
  });

  await expect(page.locator('textarea#cipherInput')).not.toBeEmpty();
  await page.getByRole('button', { name: 'Info', exact: true }).click();

  await expect(page.getByLabel('Decryption Parameters').getByText('XChaCha20 Poly1305')).toBeVisible({timeout:10000});
  await expect(page.getByLabel('Decryption Parameters').getByText(hint)).toBeVisible({timeout:10000});
  await page.keyboard.press('Escape');

  await page.getByRole('button', { name: 'Decrypt Text' }).click();
  await expect(page.getByRole('heading', { name: "KeeperOne" })).toBeVisible({timeout:10000});
  await fillPwdAndAccept(page, /KeeperOne/, pwd, hint, 'dec', async () => {
    await expect(page.getByText(/KeeperOne/)).toBeVisible({timeout:10000});
  });

  await expect(page.locator('textarea#clearInput')).not.toBeEmpty();
  await expect(page.locator('textarea#clearInput')).toHaveValue(clearText);

});


testWithAuth('loop encrypt decrypt', async ({ authFixture }) => {
  const { page, session, authId } = authFixture;

  await page.goto('/');

  const testHost = new URL(page.url()).hostname as hosts;
  await addCredential(session, authId, credentials[testHost]['keeper2']['id']);

  const loops = 3
  const clearText = 'this is another 🚧';

  await passkeyAuth(session, authId, async () => {
    await page.getByRole('button', { name: 'I have used Quick Crypt' }).click();
  });
  await page.waitForURL('/', { waitUntil: 'domcontentloaded' });
  await page.getByRole('button', { name: 'Encryption Mode' }).click();
  await page.getByRole('button', { name: 'Advanced Options' }).click();
  await page.getByRole('switch', { name: 'Hide Password' }).uncheck();

  await page.locator('input[name="loops"]').fill(`${loops}`);
  await page.keyboard.press('Tab');

  await page.locator('textarea#clearInput').fill(clearText);
  await page.getByRole('button', { name: 'Encrypt Text' }).click();

  for (let l = 1; l <= loops; l++) {
    await fillPwdAndAccept(page, /KeeperTwo/, `${l}+foie F2]43$Rad`, `${l}`, 'enc', async () => {
      await expect(page.getByText(`loop ${l} of ${loops}`)).toBeVisible({timeout:10000});
    });
  }

  await expect(page.locator('textarea#cipherInput')).not.toBeEmpty();
  await page.getByRole('button', { name: 'Decrypt Text' }).click();

  for (let l = loops; l >= 1; l--) {
    await fillPwdAndAccept(page, /KeeperTwo/, `${l}+foie F2]43$Rad`, `${l}`, 'dec', async () => {
      await expect(page.getByText(`loop ${l} of ${loops}`)).toBeVisible({timeout:10000});
    });
  }

  await expect(page.locator('textarea#clearInput')).not.toBeEmpty();
  await expect(page.locator('textarea#clearInput')).toHaveValue(clearText);

});
