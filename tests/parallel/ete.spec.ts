import { test, expect, Page, CDPSession } from '@playwright/test';
import {
  hosts,
  credentials,
  testWithAuth,
  addCredential,
  passkeyAuth,
  fillPwdAndAccept,
  clearCredentials,
  passkeyCreation,
  deleteFirstPasskey
} from '.././common';

test.describe('sign on', () => {

  testWithAuth('log in and out', async ({ authFixture }) => {
    const { page, session, authId } = authFixture;
    test.setTimeout(45000);

    await page.goto('/');

    const testHost = new URL(page.url()).hostname as hosts;
    await addCredential(session, authId, credentials[testHost]['keeper2']['id']);

    await passkeyAuth(session, authId, async () => {
      await page.getByRole('button', { name: 'I have used Quick Crypt' }).click();
    });
    await page.waitForURL('/', { waitUntil: 'domcontentloaded' });
    await expect(page.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({timeout:10000});

    await page.getByRole('button', { name: 'Passkey information' }).click();

    let tableBody = page.locator('table.credtable tbody');
    await expect(tableBody.locator('tr')).toHaveCount(1);

    await page.getByRole('button', { name: /Sign out/ }).click();

    await passkeyAuth(session, authId, async () => {
      await page.getByRole('button', { name: /Sign in as Keeper/ }).click();
    });

    await page.waitForURL('/', { waitUntil: 'domcontentloaded' });
    await expect(page.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({timeout:10000});

    await page.getByRole('button', { name: 'Passkey information' }).click();

    tableBody = page.locator('table.credtable tbody');
    await expect(tableBody.locator('tr')).toHaveCount(1);

    await page.getByRole('button', { name: /Sign out/ }).click();
    await page.getByRole('button', { name: /Sign in as a different user/ }).click();

    await page.waitForURL('/welcome', { waitUntil: 'domcontentloaded' });
    await expect(page.getByRole('heading', { name: /Quick Crypt: Easy, Trustworthy/ })).toBeVisible({timeout:10000});

  });

  testWithAuth('2 tabs logout', async ({ authFixture }) => {
    const { page, session, authId } = authFixture;
    test.setTimeout(45000);

    const page1 = page;
    await page1.goto('/');

    const testHost = new URL(page1.url()).hostname as hosts;
    await addCredential(session, authId, credentials[testHost]['keeper1']['id']);

    await passkeyAuth(session, authId, async () => {
      await page1.getByRole('button', { name: 'I have used Quick Crypt' }).click();
    });
    await page1.waitForURL('/', { waitUntil: 'domcontentloaded' });
    await expect(page1.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({timeout:10000});

    const page2 = await page1.context().newPage();
    await page2.goto('/');
    await page2.waitForURL('/', { waitUntil: 'domcontentloaded' });
    await expect(page2.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({timeout:10000});

    // logout 2nd page and confirm first is logged out
    await page2.getByRole('button', { name: 'Passkey information' }).click();

    let tableBody2 = page2.locator('table.credtable tbody');
    await expect(tableBody2.locator('tr')).toHaveCount(1);
    await expect(page2.locator('mat-sidenav input').first()).toHaveValue('KeeperOne');

    await page2.getByRole('button', { name: /Sign out/ }).click();
    await expect(page2.getByRole('heading', { name: /Quick Crypt Sign In/ })).toBeVisible({timeout:10000});

    await page1.goto('/');
    await page1.waitForURL('/', { waitUntil: 'domcontentloaded' });
    await expect(page1.getByRole('heading', { name: /Quick Crypt Sign In/ })).toBeVisible({timeout:10000});

    await page2.getByRole('button', { name: /Sign in as a different user/ }).click();
    await page2.waitForURL('/welcome', { waitUntil: 'domcontentloaded' });
    await expect(page2.getByRole('heading', { name: /Quick Crypt: Easy, Trustworthy/ })).toBeVisible({timeout:10000});

    // page1 should also go back to welcome page
    await page1.goto('/');
    await page1.waitForURL('/welcome', { waitUntil: 'domcontentloaded' });
    await expect(page1.getByRole('heading', { name: /Quick Crypt: Easy, Trustworthy/ })).toBeVisible({timeout:10000});
  });

  testWithAuth('3 tabs switch user', async ({ authFixture }) => {
    const { page, session, authId } = authFixture;
    test.setTimeout(60000);

    const page1 = page;
    await page1.goto('/');
    const testHost = new URL(page.url()).hostname as hosts;
    await addCredential(session, authId, credentials[testHost]['keeper1']['id']);

    await passkeyAuth(session, authId, async () => {
      await page1.getByRole('button', { name: 'I have used Quick Crypt' }).click();
    });
    await page1.waitForURL('/', { waitUntil: 'domcontentloaded' });
    await expect(page1.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({timeout:10000});

    const page2 = await page1.context().newPage();
    await page2.goto('/');
    await page2.waitForURL('/', { waitUntil: 'domcontentloaded' });
    await expect(page2.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({timeout:10000});
    await page2.getByRole('button', { name: 'Passkey information' }).click();
    await expect(page2.locator('mat-sidenav input').first()).toHaveValue('KeeperOne');

    // log 1st page in as keepertwo
    await page1.getByRole('button', { name: 'Passkey information' }).click();

    let tableBody1 = page1.locator('table.credtable tbody');
    await expect(tableBody1.locator('tr')).toHaveCount(1);
    await expect(page1.locator('mat-sidenav input').first()).toHaveValue('KeeperOne');

    await page1.getByRole('button', { name: /Sign out/ }).click();
    await page1.getByRole('button', { name: /Sign in as a different user/ }).click();

    await page1.waitForURL('/welcome', { waitUntil: 'domcontentloaded' });
    await expect(page1.getByRole('heading', { name: /Quick Crypt: Easy, Trustworthy/ })).toBeVisible({timeout:10000});

    await clearCredentials(session, authId);
    await addCredential(session, authId, credentials[testHost]['keeper2']['id']);

    await passkeyAuth(session, authId, async () => {
      await page1.getByRole('button', { name: 'I have used Quick Crypt' }).click();
    });
    await page1.waitForURL('/', { waitUntil: 'domcontentloaded' });
    await expect(page1.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({timeout:10000});
    await page1.getByRole('button', { name: 'Passkey information' }).click();
    await expect(page1.locator('mat-sidenav input').first()).toHaveValue('KeeperTwo');

    // page2 should go to welcome page since it origianl user user logged out
    await page2.goto('/');
    await page2.waitForURL('/welcome', { waitUntil: 'domcontentloaded' });
    await expect(page2.getByRole('heading', { name: /Quick Crypt: Easy, Trustworthy/ })).toBeVisible({timeout:10000});

    // page3 should open to main page because it didn't have preivous user context
    const page3 = await page1.context().newPage();

    await page3.goto('/');
    await page3.waitForURL('/', { waitUntil: 'domcontentloaded' });
    await expect(page3.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({timeout:10000});
    await page3.getByRole('button', { name: 'Passkey information' }).click();
    let tableBody3 = page3.locator('table.credtable tbody');
    await expect(tableBody3.locator('tr')).toHaveCount(1);
    await expect(page3.locator('mat-sidenav input').first()).toHaveValue('KeeperTwo');
    await page3.getByRole('button', { name: /Sign out/ }).click();
    await expect(page3.getByRole('heading', { name: /Quick Crypt Sign In/ })).toBeVisible({timeout:10000});

    // page2 should still go to welcome page since its origianl user was logged out
    await page2.goto('/');
    await page2.waitForURL('/welcome', { waitUntil: 'domcontentloaded' });
    await expect(page2.getByRole('heading', { name: /Quick Crypt: Easy, Trustworthy/ })).toBeVisible({timeout:10000});

    // page1 should go to sign in dialog
    await page1.goto('/');
    await page1.waitForURL('/', { waitUntil: 'domcontentloaded' });
    await expect(page1.getByRole('heading', { name: /Quick Crypt Sign In/ })).toBeVisible({timeout:10000});

    // sign back in as Keeper1
    await page1.getByRole('button', { name: /Sign in as a different user/ }).click();
    await page1.waitForURL('/welcome', { waitUntil: 'domcontentloaded' });
    await expect(page1.getByRole('heading', { name: /Quick Crypt: Easy, Trustworthy/ })).toBeVisible({timeout:10000});

    await clearCredentials(session, authId);
    await addCredential(session, authId, credentials[testHost]['keeper1']['id']);

    await passkeyAuth(session, authId, async () => {
      await page1.getByRole('button', { name: 'I have used Quick Crypt' }).click();
    });
    await page1.waitForURL('/', { waitUntil: 'domcontentloaded' });
    await expect(page1.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({timeout:10000});
    await page1.getByRole('button', { name: 'Passkey information' }).click();
    await expect(page1.locator('mat-sidenav input').first()).toHaveValue('KeeperOne');
    await page1.getByRole('button', { name: 'Passkey information' }).click();

    // page2 should now go to enryption page since origianl user is logged in again
    await page2.goto('/');
    await page2.waitForURL('/', { waitUntil: 'domcontentloaded' });
    await expect(page2.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({timeout:10000});
    await page2.getByRole('button', { name: 'Passkey information' }).click();
    await expect(page2.locator('mat-sidenav input').first()).toHaveValue('KeeperOne');

    // page3 should go to welcome page since it its user was logged out
    await page3.goto('/');
    await page3.waitForURL('/welcome', { waitUntil: 'domcontentloaded' });
    await expect(page3.getByRole('heading', { name: /Quick Crypt: Easy, Trustworthy/ })).toBeVisible({timeout:10000});

  });

});

test.describe('encryption', () => {

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
});
