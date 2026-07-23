// Run this tool with either:
// > NODE_EXTRA_CA_CERTS=./apps/web/localssl/qcrypt.pem pnpm exec playwright test --config apps/web/playwright.config.ts apps/web/tests/keeper.spec.ts --project=local
// > NODE_EXTRA_CA_CERTS=./apps/web/localssl/qcrypt.pem pnpm exec playwright test --config apps/web/playwright.config.ts apps/web/tests/keeper.spec.ts --project=prod

import { test, expect } from '@playwright/test';
import { HmacSecretMode } from 'nid-webauthn-emulator';
import { existsSync, readdirSync } from 'node:fs';
import { hosts, keeperDir, testWithAuth } from './common';

// Manual tool (not run by the e2e runner) that provisions a persistent keeper account
// and writes its passkey to the gitignored keeper-creds dir. Edit the constants (the
// config host must match --project). For CI, tar + base64 keeper-creds.
testWithAuth('provision keeper', async ({ authFixture }) => {
  test.setTimeout(60000);
  const { page } = authFixture;

  // Edit per keeper before running ('none' mode for a no-PRF keeper).
  const config: { host: hosts; keeper: string; mode: HmacSecretMode; userName: string } = {
    host: 't1.quickcrypt.org',
    keeper: 'keeper2',
    mode: 'hmac-secret-mc',
    userName: 'KeeperTwo',
  };
  const { host, keeper, mode, userName } = config;

  const dir = keeperDir(host, keeper);
  if (existsSync(dir) && readdirSync(dir).length > 0) {
    throw new Error(`${dir} already has a credential — delete it before re-provisioning`);
  }
  const authenticator = authFixture.provisionAuthenticator(dir, mode);

  await page.goto('/');
  await page.getByRole('button', { name: 'I am new to Quick Crypt' }).click();
  await expect(page.getByRole('heading', { name: 'Create A New user' })).toBeVisible({ timeout: 10000 });
  await page.locator('input#userName').fill(userName);
  await page.getByRole('button', { name: /Create new/ }).click();
  if (mode === 'none') {
    await page.getByRole('button', { name: 'Continue with standard protection' }).click();
  }

  await expect(page).toHaveURL(/\/showrecovery$/, { timeout: 10000 });
  // Keeper accounts are never recovered (a lost passkey is fixed by re-running this
  // tool), so the recovery words are discarded. Uncomment to capture them if that changes.
  const recoveryWords = await page.locator('textarea#wordsArea').inputValue();
  await page.getByRole('button', { name: /I saved my/ }).click();
  await expect(page).toHaveURL(/\/$/);
  await expect(page.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({ timeout: 10000 });

  expect(authenticator.mode).toBe(mode);
  console.log(`\n[keeper] provisioned ${host}/${keeper} → ${dir}\n`);
  // console.log(`recovery words:\n${recoveryWords}\n`);
});
