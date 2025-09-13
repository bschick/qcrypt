import { test, expect, Page, CDPSession } from '@playwright/test';
import {
  testWithAuth,
  passkeyAuth,
  passkeyCreation,
  deleteFirstPasskey,
  clearCredentials,
  addCredential,
  hosts,
  credentials
} from '.././common';


test.describe('errors', () => {

  testWithAuth('user too short', async ({ authFixture }) => {
    const { page, session, authId } = authFixture;

    await page.goto('/');

    await passkeyCreation(session, authId, async () => {
      await page.getByRole('button', { name: 'I am new to Quick Crypt' }).click();
      await expect(page.getByRole('heading', { name: 'Create A New user' })).toBeVisible({timeout:10000});
      await page.locator('input#userName').fill('short');
      await page.getByRole('button', { name: /Create new/ }).click();
    });

    const parent = page.locator('.error-msg p');
    expect(parent).toContainText('User name must be 6 to 31 characters long');
  });

  testWithAuth('user too long', async ({ authFixture }) => {
    const { page, session, authId } = authFixture;

    await page.goto('/');

    await passkeyCreation(session, authId, async () => {
      await page.getByRole('button', { name: 'I am new to Quick Crypt' }).click();
      await expect(page.getByRole('heading', { name: 'Create A New user' })).toBeVisible({timeout:10000});
      await page.locator('input#userName').fill('1234567890123456789012345678901234567890');
      await page.getByRole('button', { name: /Create new/ }).click();
    });

    const parent = page.locator('.error-msg p');
    expect(parent).toContainText('User name must be 6 to 31 characters long');
  });

  testWithAuth('no passkey', async ({ authFixture }) => {
    const { page, session, authId } = authFixture;

    await page.goto('/');

    await passkeyAuth(session, authId, async () => {
      await page.getByRole('button', { name: 'I have used Quick Crypt' }).click();
    });
    const parent = page.locator('p.error-msg');
    expect(parent).toContainText(/Passkey not recognized/);

  });

  testWithAuth('enc dec errors', async ({ authFixture }) => {
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

    await page.getByRole('button', { name: 'Encrypt Text'}).click();
    expect(page.locator('.errorBox').nth(1)).toContainText(/Missing clear text/);

    await page.getByRole('button', { name: 'Decrypt Text'}).click();
    expect(page.locator('.errorBox').nth(0)).toContainText(/Missing cipher armor/);

  });

  testWithAuth('edit errors', async ({ authFixture }) => {
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

    await page.locator('mat-sidenav input').first().click();
    await page.locator('mat-sidenav input').first().fill('12345');
    await page.keyboard.press('Enter');

    expect(page.locator('div.error-msg')).toContainText(/Name change failed, must be 6 to 31 characters/);

    await page.locator('mat-sidenav input').nth(1).click();
    await page.locator('mat-sidenav input').nth(1).fill('12345');
    await page.keyboard.press('Enter');

    expect(page.locator('div.error-msg')).toContainText(/Description change failed, must be 6 to 42 characters/);
  });


  testWithAuth('no recovery', async ({ authFixture }) => {
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

    await clearCredentials(session, authId);

    await passkeyAuth(session, authId, async () => {
      await page.getByRole('button', { name: /Show recovery link/ }).click();
    });

    await page.waitForURL('/showrecovery', { waitUntil: 'domcontentloaded' });
    await expect(page.getByRole('button', { name: 'Try again' })).toBeVisible({timeout:10000});

    expect(page.locator('.error-msg p')).toContainText('Retrieval failed, try again', {timeout:10000});

  });

  testWithAuth('no usercred', async ({ authFixture }) => {
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

    await clearCredentials(session, authId);

    await passkeyAuth(session, authId, async () => {
      await page.goto('/cmdline');
    });

    await page.waitForURL('/cmdline', { waitUntil: 'domcontentloaded' });
    await expect(page.getByRole('button', { name: 'Try again' })).toBeVisible({timeout:10000});

    expect(page.locator('.error-msg p')).toContainText('Retrieval failed, try again', {timeout:10000});
  });


});


// test.describe('sign on', () => {

//   testWithAuth('log in and out', async ({ authFixture }) => {
//     const { page, session, authId } = authFixture;
//     test.setTimeout(45000);

//     await page.goto('/');

//     const testHost = new URL(page.url()).hostname as hosts;
//     await addCredential(session, authId, credentials[testHost]['keeper2']['id']);

//     await passkeyAuth(session, authId, async () => {
//       await page.getByRole('button', { name: 'I have used Quick Crypt' }).click();
//     });
//     await page.waitForURL('/', { waitUntil: 'domcontentloaded' });
//     await expect(page.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({timeout:10000});

//     await page.getByRole('button', { name: 'Passkey information' }).click();

//     let tableBody = page.locator('table.credtable tbody');
//     await expect(tableBody.locator('tr')).toHaveCount(1);

//     await page.getByRole('button', { name: /Sign out/ }).click();

//     await passkeyAuth(session, authId, async () => {
//       await page.getByRole('button', { name: /Sign in as Keeper/ }).click();
//     });

//     await page.waitForURL('/', { waitUntil: 'domcontentloaded' });
//     await expect(page.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({timeout:10000});

//     await page.getByRole('button', { name: 'Passkey information' }).click();

//     tableBody = page.locator('table.credtable tbody');
//     await expect(tableBody.locator('tr')).toHaveCount(1);

//     await page.getByRole('button', { name: /Sign out/ }).click();
//     await page.getByRole('button', { name: /Sign in as a different user/ }).click();

//     await page.waitForURL('/welcome', { waitUntil: 'domcontentloaded' });
//     await expect(page.getByRole('heading', { name: /Quick Crypt: Easy, Trustworthy/ })).toBeVisible({timeout:10000});

//   });

//   testWithAuth('2 tabs logout', async ({ authFixture }) => {
//     const { page, session, authId } = authFixture;
//     test.setTimeout(45000);

//     const page1 = page;
//     await page1.goto('/');

//     const testHost = new URL(page1.url()).hostname as hosts;
//     await addCredential(session, authId, credentials[testHost]['keeper1']['id']);

//     await passkeyAuth(session, authId, async () => {
//       await page1.getByRole('button', { name: 'I have used Quick Crypt' }).click();
//     });
//     await page1.waitForURL('/', { waitUntil: 'domcontentloaded' });
//     await expect(page1.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({timeout:10000});

//     const page2 = await page1.context().newPage();
//     await page2.goto('/');
//     await page2.waitForURL('/', { waitUntil: 'domcontentloaded' });
//     await expect(page2.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({timeout:10000});

//     // logout 2nd page and confirm first is logged out
//     await page2.getByRole('button', { name: 'Passkey information' }).click();

//     let tableBody2 = page2.locator('table.credtable tbody');
//     await expect(tableBody2.locator('tr')).toHaveCount(1);
//     await expect(page2.locator('mat-sidenav input').first()).toHaveValue('KeeperOne');

//     await page2.getByRole('button', { name: /Sign out/ }).click();
//     await expect(page2.getByRole('heading', { name: /Quick Crypt Sign In/ })).toBeVisible({timeout:10000});

//     await page1.goto('/');
//     await page1.waitForURL('/', { waitUntil: 'domcontentloaded' });
//     await expect(page1.getByRole('heading', { name: /Quick Crypt Sign In/ })).toBeVisible({timeout:10000});

//     await page2.getByRole('button', { name: /Sign in as a different user/ }).click();
//     await page2.waitForURL('/welcome', { waitUntil: 'domcontentloaded' });
//     await expect(page2.getByRole('heading', { name: /Quick Crypt: Easy, Trustworthy/ })).toBeVisible({timeout:10000});

//     // page1 should also go back to welcome page
//     await page1.goto('/');
//     await page1.waitForURL('/welcome', { waitUntil: 'domcontentloaded' });
//     await expect(page1.getByRole('heading', { name: /Quick Crypt: Easy, Trustworthy/ })).toBeVisible({timeout:10000});
//   });

//   testWithAuth('3 tabs switch user', async ({ authFixture }) => {
//     const { page, session, authId } = authFixture;
//     test.setTimeout(60000);

//     const page1 = page;
//     await page1.goto('/');
//     const testHost = new URL(page.url()).hostname as hosts;
//     await addCredential(session, authId, credentials[testHost]['keeper1']['id']);

//     await passkeyAuth(session, authId, async () => {
//       await page1.getByRole('button', { name: 'I have used Quick Crypt' }).click();
//     });
//     await page1.waitForURL('/', { waitUntil: 'domcontentloaded' });
//     await expect(page1.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({timeout:10000});

//     const page2 = await page1.context().newPage();
//     await page2.goto('/');
//     await page2.waitForURL('/', { waitUntil: 'domcontentloaded' });
//     await expect(page2.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({timeout:10000});
//     await page2.getByRole('button', { name: 'Passkey information' }).click();
//     await expect(page2.locator('mat-sidenav input').first()).toHaveValue('KeeperOne');

//     // log 1st page in as keepertwo
//     await page1.getByRole('button', { name: 'Passkey information' }).click();

//     let tableBody1 = page1.locator('table.credtable tbody');
//     await expect(tableBody1.locator('tr')).toHaveCount(1);
//     await expect(page1.locator('mat-sidenav input').first()).toHaveValue('KeeperOne');

//     await page1.getByRole('button', { name: /Sign out/ }).click();
//     await page1.getByRole('button', { name: /Sign in as a different user/ }).click();

//     await page1.waitForURL('/welcome', { waitUntil: 'domcontentloaded' });
//     await expect(page1.getByRole('heading', { name: /Quick Crypt: Easy, Trustworthy/ })).toBeVisible({timeout:10000});

//     await clearCredentials(session, authId);
//     await addCredential(session, authId, credentials[testHost]['keeper2']['id']);

//     await passkeyAuth(session, authId, async () => {
//       await page1.getByRole('button', { name: 'I have used Quick Crypt' }).click();
//     });
//     await page1.waitForURL('/', { waitUntil: 'domcontentloaded' });
//     await expect(page1.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({timeout:10000});
//     await page1.getByRole('button', { name: 'Passkey information' }).click();
//     await expect(page1.locator('mat-sidenav input').first()).toHaveValue('KeeperTwo');

//     // page2 should go to welcome its user context is keeper2 and we don't directly transition
//     await page2.goto('/');
//     await page2.waitForURL('/welcome', { waitUntil: 'domcontentloaded' });
//     await expect(page2.getByRole('heading', { name: /Quick Crypt: Easy, Trustworthy/ })).toBeVisible({timeout:10000});

//     // page3 should open to core page because it didn't have preivous user context
//     const page3 = await page1.context().newPage();

//     await page3.goto('/');
//     await page3.waitForURL('/', { waitUntil: 'domcontentloaded' });
//     await expect(page3.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({timeout:10000});
//     await page3.getByRole('button', { name: 'Passkey information' }).click();
//     let tableBody3 = page3.locator('table.credtable tbody');
//     await expect(tableBody3.locator('tr')).toHaveCount(1);
//     await expect(page3.locator('mat-sidenav input').first()).toHaveValue('KeeperTwo');
//     await page3.getByRole('button', { name: /Sign out/ }).click();
//     await expect(page3.getByRole('heading', { name: /Quick Crypt Sign In/ })).toBeVisible({timeout:10000});

//     // page2 should still go to welcome page since its origianl user was logged out
//     await page2.goto('/');
//     await page2.waitForURL('/welcome', { waitUntil: 'domcontentloaded' });
//     await expect(page2.getByRole('heading', { name: /Quick Crypt: Easy, Trustworthy/ })).toBeVisible({timeout:10000});

//     // page1 should go to sign in dialog
//     await page1.goto('/');
//     await page1.waitForURL('/', { waitUntil: 'domcontentloaded' });
//     await expect(page1.getByRole('heading', { name: /Quick Crypt Sign In/ })).toBeVisible({timeout:10000});

//     // sign back in as Keeper1
//     await page1.getByRole('button', { name: /Sign in as a different user/ }).click();
//     await page1.waitForURL('/welcome', { waitUntil: 'domcontentloaded' });
//     await expect(page1.getByRole('heading', { name: /Quick Crypt: Easy, Trustworthy/ })).toBeVisible({timeout:10000});

//     await clearCredentials(session, authId);
//     await addCredential(session, authId, credentials[testHost]['keeper1']['id']);

//     await passkeyAuth(session, authId, async () => {
//       await page1.getByRole('button', { name: 'I have used Quick Crypt' }).click();
//     });
//     await page1.waitForURL('/', { waitUntil: 'domcontentloaded' });
//     await expect(page1.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({timeout:10000});
//     await page1.getByRole('button', { name: 'Passkey information' }).click();
//     await expect(page1.locator('mat-sidenav input').first()).toHaveValue('KeeperOne');
//     await page1.getByRole('button', { name: 'Passkey information' }).click();

//     // page2 should now go to enryption page since origianl user is logged in again
//     await page2.goto('/');
//     await page2.waitForURL('/', { waitUntil: 'domcontentloaded' });
//     await expect(page2.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({timeout:10000});
//     await page2.getByRole('button', { name: 'Passkey information' }).click();
//     await expect(page2.locator('mat-sidenav input').first()).toHaveValue('KeeperOne');

//     // page3 should go to welcome page since it its user was logged out
//     await page3.goto('/');
//     await page3.waitForURL('/welcome', { waitUntil: 'domcontentloaded' });
//     await expect(page3.getByRole('heading', { name: /Quick Crypt: Easy, Trustworthy/ })).toBeVisible({timeout:10000});

//   });

// });