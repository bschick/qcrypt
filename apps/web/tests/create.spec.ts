import { test, expect, Page, CDPSession } from '@playwright/test';
import {
  testWithAuth,
  passkeyCreation,
} from './common';


testWithAuth('account creation', async ({ authFixture }) => {
  const { page, session, authenticatorId1, authenticatorId2 } = authFixture;
  test.setTimeout(60000);

  await page.goto('/');

  const credential = await passkeyCreation(page, session, authenticatorId1, async () => {
    await page.getByRole('button', { name: 'I am new to Quick Crypt' }).click();
    await expect(page.getByRole('heading', { name: 'Create A New user' })).toBeVisible();
    await page.locator('input#userName').fill('');
    await page.getByRole('button', { name: /Create new/ }).click();
  });

  await expect(page).toHaveURL(/\/showrecovery$/);

  await expect(page.getByRole('heading', { name: 'Account Backup and Recovery' })).toBeVisible();

  //save recovery pattern
  const recoveryWords = await page.locator('textarea#wordsArea').inputValue();

  console.log(credential);
  console.log(recoveryWords);

});