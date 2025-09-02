import { test, expect, Page, CDPSession } from '@playwright/test';
import {
  testWithAuth,
  passkeyAuth,
  passkeyCreation,
  deleteFirstPasskey
} from '.././common';


test.describe('creation', () => {

  testWithAuth('full lifecycle', { tag: '@nukeall' }, async ({ authFixture }) => {
    const { page, session, authId } = authFixture;
    test.setTimeout(60000);

    await page.goto('/');

    await passkeyCreation(session, authId, async () => {
      await page.getByRole('button', { name: 'I am new to Quick Crypt' }).click();
      await expect(page.getByRole('heading', { name: 'Create A New user' })).toBeVisible({timeout:10000});
      await page.locator('input#userName').fill('PWFlipp<script>y</script>');
      await page.getByRole('button', { name: /Create new/ }).click();
    });

    await page.waitForURL('/showrecovery', { waitUntil: 'domcontentloaded' });

    await expect(page.getByRole('heading', { name: 'Account Backup and Recovery' })).toBeVisible({timeout:10000});

    //save recovery pattern
    const recoveryWords = await page.locator('textarea#wordsArea').inputValue();

    await page.getByRole('button', { name: /I saved my/ }).click();

    await page.waitForURL('/', { waitUntil: 'domcontentloaded' });
    await expect(page.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({timeout:10000});
    await page.getByRole('button', { name: 'Passkey information' }).click();

    let tableBody = page.locator('table.credtable tbody');
    await expect(tableBody.locator('tr')).toHaveCount(1);

    await passkeyCreation(session, authId, async () => {
      await page.getByRole('button', { name: /New Passkey/ }).click();
    });

    await expect(tableBody.locator('tr')).toHaveCount(2);

    await page.getByRole('button', { name: /Sign out/ }).click();

    await passkeyAuth(session, authId, async () => {
      await page.getByRole('button', { name: /Sign in as PWFlippy/ }).click();
    });

    await page.waitForURL('/', { waitUntil: 'domcontentloaded' });

    await page.goto('/recovery2');
    await page.waitForURL('/recovery2', { waitUntil: 'networkidle' });

    await page.locator('textarea#wordsArea').fill(recoveryWords);

    await passkeyCreation(session, authId, async () => {
      await page.getByRole('button', { name: /Start Recovery/ }).click();
    });

    await page.waitForURL('/', { waitUntil: 'domcontentloaded' });
    await expect(page.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({timeout:10000});
    await page.getByRole('button', { name: 'Passkey information' }).click();

    tableBody = page.locator('table.credtable tbody');
    await expect(tableBody.locator('tr')).toHaveCount(1);

    await deleteFirstPasskey(page);

    await page.waitForURL('/welcome', { waitUntil: 'domcontentloaded' });
    await expect(page.getByRole('heading', { name: /Quick Crypt: Easy, Trustworthy/ })).toBeVisible({timeout:10000});

  });

});


// testWithAuth('full lifecycle', async ({ authFixture }) => {
//   const { page, session, authId } = authFixture;
//   test.setTimeout(60000);

//   await page.goto('/');

//   await passkeyCreation(session, authId, async () => {
//     await page.getByRole('button', { name: 'I am new to Quick Crypt' }).click();
//     await expect(page.getByRole('heading', { name: 'Create A New user' })).toBeVisible();
//     await page.locator('input#userName').fill('PWFlipp<script>y</script>');
//     await page.getByRole('button', { name: /Create new/ }).click();
//   });

//   await page.waitForURL('/showrecovery', { waitUntil: 'domcontentloaded' });

//   await expect(page.getByRole('heading', { name: 'Account Backup and Recovery' })).toBeVisible();

//   //save recovery pattern
//   const recoveryWords = await page.locator('textarea#wordsArea').inputValue();

//   await page.getByRole('button', { name: /I saved my/ }).click();

//   await page.waitForURL('/', { waitUntil: 'domcontentloaded' });
//   await expect(page.getByRole('button', { name: 'Encryption Mode' })).toBeVisible();
//   await page.getByRole('button', { name: 'Passkey information' }).click();

//   let tableBody = page.locator('table.credtable tbody');
//   await expect(tableBody.locator('tr')).toHaveCount(1);

//   await passkeyCreation(session, authId, async () => {
//     await page.getByRole('button', { name: /New Passkey/ }).click();
//   });

//   await expect(tableBody.locator('tr')).toHaveCount(2);

//   await page.getByRole('button', { name: /Sign out/ }).click();

//   await passkeyAuth(session, authId, async () => {
//     await page.getByRole('button', { name: /Sign in as PWFlippy/ }).click();
//   });

//   await page.waitForURL('/', { waitUntil: 'domcontentloaded' });

//   await page.goto('/recovery2');
//   await page.waitForURL('/recovery2', { waitUntil: 'networkidle' });

//   await page.locator('textarea#wordsArea').fill(recoveryWords);

//   await passkeyCreation(session, authId, async () => {
//     await page.getByRole('button', { name: /Start Recovery/ }).click();
//   });

//   await page.waitForURL('/', { waitUntil: 'domcontentloaded' });
//   await expect(page.getByRole('button', { name: 'Encryption Mode' })).toBeVisible();
//   await page.getByRole('button', { name: 'Passkey information' }).click();

//   tableBody = page.locator('table.credtable tbody');
//   await expect(tableBody.locator('tr')).toHaveCount(1);

//   await deleteFirstPasskey(page);

//   await page.waitForURL('/welcome', { waitUntil: 'domcontentloaded' });
//   await expect(page.getByRole('heading', { name: /Quick Crypt: Easy, Trustworthy/ })).toBeVisible();

// });

