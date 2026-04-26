import { test, expect, Page, CDPSession } from '@playwright/test';
import {
  testWithAuth,
  passkeyAuth,
  passkeyCreation,
  deleteFirstPasskey,
  clearCredentials,
  addCredential,
  hosts,
  credentials,
  deleteLastPasskey,
  openCredentials
} from '.././common';


test.describe('creation', () => {

  testWithAuth('full lifecycle', { tag: '@nukeall' }, async ({ authFixture }) => {
    const { page, session, authId1, authId2 } = authFixture;
    test.setTimeout(60000);

    // Server strips <script> tags but keeps their content, so this fill
    // sanitizes to userName — exercises XSS sanitization on the create path.
    // Short rand keeps the fill (incl. tags) under the 31-char input limit.
    const rand = Math.floor(Math.random() * 10000).toString().padStart(4, '0');
    const userName = `PWTesty_${rand}`;
    const fillValue = `PWTesty<script>_${rand}</script>`;

    await page.goto('/');

    await passkeyCreation(session, authId1, async () => {
      await page.getByRole('button', { name: 'I am new to Quick Crypt' }).click();
      await expect(page.getByRole('heading', { name: 'Create A New user' })).toBeVisible({timeout:10000});
      await page.locator('input#userName').fill(fillValue);
      await page.getByRole('button', { name: /Create new/ }).click();
    });

    await page.waitForURL('/showrecovery', { waitUntil: 'domcontentloaded' });
    await expect(page.getByRole('heading', { name: 'Account Backup and Recovery' })).toBeVisible({timeout:10000});

    //save recovery pattern
    const recoveryWords = await page.locator('textarea#wordsArea').inputValue();

    await page.getByRole('button', { name: /I saved my/ }).click();

    await page.waitForURL('/', { waitUntil: 'domcontentloaded' });
    await expect(page.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({timeout:10000});
    await openCredentials(page);

    let tableBody = page.locator('table.credtable tbody');
    await expect(tableBody.locator('tr')).toHaveCount(1);

    await passkeyCreation(session, authId2, async () => {
      await page.getByRole('button', { name: /New Passkey/ }).click();
    });

    await expect(tableBody.locator('tr')).toHaveCount(2);

    await page.getByRole('button', { name: /Sign out/ }).click();

    // Both authIds hold a passkey for the test user at this point — pass both
    // so presence sim covers whichever the browser picks.
    await passkeyAuth(session, [authId1, authId2], async () => {
      await page.getByRole('button', { name: new RegExp(`Sign in as ${userName}`) }).click();
    });

    await page.waitForURL('/', { waitUntil: 'domcontentloaded' });

    await openCredentials(page);

    tableBody = page.locator('table.credtable tbody');
    await expect(tableBody.locator('tr')).toHaveCount(2);

    await page.getByRole('button', { name: /Sign out/ }).click();

    await passkeyAuth(session, [authId1, authId2], async () => {
      await page.getByRole('button', { name: new RegExp(`Sign in as ${userName}`) }).click();
    });

    await page.waitForURL('/', { waitUntil: 'domcontentloaded' });

    await page.goto('/recovery2');
    await page.waitForURL('/recovery2', { waitUntil: 'networkidle' });

    await page.locator('textarea#wordsArea').fill(recoveryWords);

    await passkeyCreation(session, authId2, async () => {
      await page.getByRole('button', { name: /Start Recovery/ }).click();
    });

    await page.waitForURL('/', { waitUntil: 'domcontentloaded' });
    await expect(page.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({timeout:10000});

    //NOTE: comment out the line below to test leaking passkey & user
    await openCredentials(page);

    tableBody = page.locator('table.credtable tbody');
    await expect(tableBody.locator('tr')).toHaveCount(1);

    await deleteFirstPasskey(page, userName);

    await page.waitForURL('/welcome', { waitUntil: 'domcontentloaded' });
    await expect(page.getByText('Easy, Trustworthy Personal Encryption')).toBeVisible({timeout:10000});

  });

  testWithAuth('delete active passkey signs out', { tag: '@nukeall' }, async ({ authFixture }) => {
    const { page, session, authId1, authId2 } = authFixture;
    test.setTimeout(60000);

    const rand = Math.floor(Math.random() * 10000).toString().padStart(4, '0');
    const userName = `PWTesty_${rand}`;

    await page.goto('/');

    await passkeyCreation(session, authId1, async () => {
      await page.getByRole('button', { name: 'I am new to Quick Crypt' }).click();
      await expect(page.getByRole('heading', { name: 'Create A New user' })).toBeVisible({timeout:10000});
      await page.locator('input#userName').fill(userName);
      await page.getByRole('button', { name: /Create new/ }).click();
    });

    await page.waitForURL('/showrecovery', { waitUntil: 'domcontentloaded' });
    await expect(page.getByRole('heading', { name: 'Account Backup and Recovery' })).toBeVisible({timeout:10000});
    await page.getByRole('button', { name: /I saved my/ }).click();

    await page.waitForURL('/', { waitUntil: 'domcontentloaded' });
    await expect(page.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({timeout:10000});
    await openCredentials(page);

    let tableBody = page.locator('table.credtable tbody');
    await expect(tableBody.locator('tr')).toHaveCount(1);

    await passkeyCreation(session, authId2, async () => {
      await page.getByRole('button', { name: /New Passkey/ }).click();
    });

    await expect(tableBody.locator('tr')).toHaveCount(2);

    // Delete the first passkey, which is the one used to sign in (active PK).
    // Server invalidates the session, client calls logout(true), sign-in dialog appears.
    await deleteFirstPasskey(page);
    await expect(page.getByRole('heading', { name: /Quick Crypt Sign In/ })).toBeVisible({timeout:10000});

    // Sign in with the remaining passkey (authId2)
    await passkeyAuth(session, authId2, async () => {
      await page.getByRole('button', { name: new RegExp(`Sign in as ${userName}`) }).click();
    });

    await page.waitForURL('/', { waitUntil: 'domcontentloaded' });
    await expect(page.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({timeout:10000});

    await openCredentials(page);
    tableBody = page.locator('table.credtable tbody');
    await expect(tableBody.locator('tr')).toHaveCount(1);

    // Add a secondary passkey, then delete it. Active PK (authId2) is unchanged,
    // so the session stays valid and the Sign In dialog must not appear.
    await passkeyCreation(session, authId1, async () => {
      await page.getByRole('button', { name: /New Passkey/ }).click();
    });
    await expect(tableBody.locator('tr')).toHaveCount(2);

    await deleteLastPasskey(page);
    await expect(tableBody.locator('tr')).toHaveCount(1);
    await expect(page.getByRole('heading', { name: /Quick Crypt Sign In/ })).not.toBeVisible();

    // Refresh and confirm the session was not invalidated
    await page.reload();
    await page.waitForURL('/', { waitUntil: 'domcontentloaded' });
    await expect(page.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({timeout:10000});
    await expect(page.getByRole('heading', { name: /Quick Crypt Sign In/ })).not.toBeVisible();

    await openCredentials(page);
    tableBody = page.locator('table.credtable tbody');
    await expect(tableBody.locator('tr')).toHaveCount(1);

    // Cleanup: delete the last passkey, which also deletes the user
    await deleteFirstPasskey(page, userName);
    await page.waitForURL('/welcome', { waitUntil: 'domcontentloaded' });
    await expect(page.getByText('Easy, Trustworthy Personal Encryption')).toBeVisible({timeout:10000});
  });

});


test.describe('sign on', () => {

  testWithAuth('check show reocvery', { tag: '@nukeall' }, async ({ authFixture }) => {
    const { page, session, authId1 } = authFixture;
    test.setTimeout(45000);

    const testUser = await authFixture.createTestUser(authId1);

    await openCredentials(page);

    let tableBody = page.locator('table.credtable tbody');
    await expect(tableBody.locator('tr')).toHaveCount(1);

    await passkeyAuth(session, authId1, async () => {
      await page.getByRole('button', { name: /Show recovery link/ }).click();
    });

    await page.waitForURL('/showrecovery', { waitUntil: 'domcontentloaded' });
    await expect(page.getByRole('button', { name: /I saved my recovery words securely/ })).toBeVisible({timeout:10000});

    await expect(page.locator('textarea#wordsArea')).toHaveValue(testUser.recoveryWords);

  });

  testWithAuth('check usercred', { tag: '@nukeall' }, async ({ authFixture }) => {
    const { page, session, authId1 } = authFixture;
    test.setTimeout(45000);

    const testUser = await authFixture.createTestUser(authId1);

    await passkeyAuth(session, authId1, async () => {
      await page.goto('/cmdline');
    });

    await page.waitForURL('/cmdline', { waitUntil: 'domcontentloaded' });

    await expect(page.locator('input#credential')).toBeVisible();
    await expect(page.locator('input#credential')).toHaveValue(testUser.userCred);

  });

  // This was a bug in the past where could not make further authenticated
  // calls after cmdline (or recoveryword) download.
  // Also exercises full UI-driven user teardown (delete every passkey →
  // server removes the user) — the helper's after-test cleanup should find
  // nothing left to do.
  testWithAuth('check usercred and add pk', { tag: '@nukeall' }, async ({ authFixture }) => {
    const { page, session, authId1, authId2 } = authFixture;
    test.setTimeout(45000);

    const testUser = await authFixture.createTestUser(authId1);

    await passkeyAuth(session, authId1, async () => {
      await page.goto('/cmdline');
    });

    await page.waitForURL('/cmdline', { waitUntil: 'domcontentloaded' });

    await expect(page.locator('input#credential')).toBeVisible();
    await expect(page.locator('input#credential')).toHaveValue(testUser.userCred);

    await openCredentials(page);

    let tableBody = page.locator('table.credtable tbody');
    await expect(tableBody.locator('tr')).toHaveCount(1);

    await passkeyCreation(session, authId2, async () => {
      await page.getByRole('button', { name: /New Passkey/ }).click();
    });

    await expect(tableBody.locator('tr')).toHaveCount(2);

    // Delete passkeys until the user is gone. The last delete needs username
    // confirmation; the redirect to /welcome confirms the server removed the user.
    await deleteLastPasskey(page);
    await expect(tableBody.locator('tr')).toHaveCount(1);
    await deleteLastPasskey(page, testUser.userName);
    await page.waitForURL('/welcome', { waitUntil: 'domcontentloaded' });
  });

  testWithAuth('log in and out', { tag: '@nukeall' }, async ({ authFixture }) => {
    const { page, session, authId1 } = authFixture;
    test.setTimeout(45000);

    const testUser = await authFixture.createTestUser(authId1);

    await openCredentials(page);

    let tableBody = page.locator('table.credtable tbody');
    await expect(tableBody.locator('tr')).toHaveCount(1);

    await page.getByRole('button', { name: /Sign out/ }).click();

    await passkeyAuth(session, authId1, async () => {
      await page.getByRole('button', { name: new RegExp(`Sign in as ${testUser.userName}`) }).click();
    });

    await page.waitForURL('/', { waitUntil: 'domcontentloaded' });
    await expect(page.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({timeout:10000});

    await openCredentials(page);

    tableBody = page.locator('table.credtable tbody');
    await expect(tableBody.locator('tr')).toHaveCount(1);

    await page.getByRole('button', { name: /Sign out/ }).click();
    await page.getByRole('button', { name: /Sign in as a different user/ }).click();

    await page.waitForURL('/welcome', { waitUntil: 'domcontentloaded' });
    await expect(page.getByText('Easy, Trustworthy Personal Encryption')).toBeVisible({timeout:10000});

  });

  testWithAuth('3 tabs logout and forget', { tag: '@nukeall' }, async ({ authFixture }) => {
    const { page, authId1 } = authFixture;
    test.setTimeout(45000);

    const page1 = page;
    const testUser = await authFixture.createTestUser(authId1);

    const page2 = await page1.context().newPage();
    await page2.goto('/');
    await page2.waitForURL('/', { waitUntil: 'domcontentloaded' });
    await expect(page2.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({timeout:10000});

    // logout 2nd page and confirm first is logged out with Sign In dialog showing
    await openCredentials(page2);

    let tableBody2 = page2.locator('table.credtable tbody');
    await expect(tableBody2.locator('tr')).toHaveCount(1);
    await expect(page2.locator('mat-sidenav input').first()).toHaveValue(testUser.userName);

    await page2.getByRole('button', { name: /Sign out/ }).click();
    await expect(page2.getByRole('heading', { name: /Quick Crypt Sign In/ })).toBeVisible({timeout:10000});

    await page1.goto('/');
    await page1.waitForURL('/', { waitUntil: 'domcontentloaded' });
    await expect(page1.getByRole('heading', { name: /Quick Crypt Sign In/ })).toBeVisible({timeout:10000});

    // make sure a new pages goes to the sign in dialog not welcome pages
    const page3 = await page1.context().newPage();
    await page3.goto('/');
    await page3.waitForURL('/', { waitUntil: 'domcontentloaded' });
    await expect(page3.getByRole('heading', { name: /Quick Crypt Sign In/ })).toBeVisible({timeout:10000});

    // Forget user and all pages should go back to welcome page
    await page2.getByRole('button', { name: /Sign in as a different user/ }).click();
    await page2.waitForURL('/welcome', { waitUntil: 'domcontentloaded' });
    await expect(page2.getByText('Easy, Trustworthy Personal Encryption')).toBeVisible({timeout:10000});

    await page1.goto('/');
    await page1.waitForURL('/welcome', { waitUntil: 'domcontentloaded' });
    await expect(page1.getByText('Easy, Trustworthy Personal Encryption')).toBeVisible({timeout:10000});

    await page3.goto('/');
    await page3.waitForURL('/welcome', { waitUntil: 'domcontentloaded' });
    await expect(page3.getByText('Easy, Trustworthy Personal Encryption')).toBeVisible({timeout:10000});

  });

  testWithAuth('3 tabs switch user', { tag: '@nukeall' }, async ({ authFixture }) => {
    const { page, session, authId1 } = authFixture;
    test.setTimeout(60000);

    const page1 = page;
    const testUserA = await authFixture.createTestUser(authId1);

    const page2 = await page1.context().newPage();
    await page2.goto('/');
    await page2.waitForURL('/', { waitUntil: 'domcontentloaded' });
    await expect(page2.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({timeout:10000});
    await openCredentials(page2);
    await expect(page2.locator('mat-sidenav input').first()).toHaveValue(testUserA.userName);

    // log 1st page in as a different user
    await openCredentials(page1);

    let tableBody1 = page1.locator('table.credtable tbody');
    await expect(tableBody1.locator('tr')).toHaveCount(1);
    await expect(page1.locator('mat-sidenav input').first()).toHaveValue(testUserA.userName);

    await page1.getByRole('button', { name: /Sign out/ }).click();
    await page1.getByRole('button', { name: /Sign in as a different user/ }).click();

    await page1.waitForURL('/welcome', { waitUntil: 'domcontentloaded' });
    await expect(page1.getByText('Easy, Trustworthy Personal Encryption')).toBeVisible({timeout:10000});

    await clearCredentials(session, authId1);
    const testUserB = await authFixture.createTestUser(authId1);

    await openCredentials(page1);
    await expect(page1.locator('mat-sidenav input').first()).toHaveValue(testUserB.userName);

    // page2 should go to welcome since its user context is now testUserB and we don't directly transition
    await page2.goto('/');
    await page2.waitForURL('/welcome', { waitUntil: 'domcontentloaded' });
    await expect(page2.getByText('Easy, Trustworthy Personal Encryption')).toBeVisible({timeout:10000});

    // page3 should open to core page because it didn't have preivous user context
    const page3 = await page1.context().newPage();

    await page3.goto('/');
    await page3.waitForURL('/', { waitUntil: 'domcontentloaded' });
    await expect(page3.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({timeout:10000});
    await openCredentials(page3);
    let tableBody3 = page3.locator('table.credtable tbody');
    await expect(tableBody3.locator('tr')).toHaveCount(1);
    await expect(page3.locator('mat-sidenav input').first()).toHaveValue(testUserB.userName);
    await page3.getByRole('button', { name: /Sign out/ }).click();
    await expect(page3.getByRole('heading', { name: /Quick Crypt Sign In/ })).toBeVisible({timeout:10000});

    // page2 should still go to welcome page since its origianl user was logged out
    await page2.goto('/');
    await page2.waitForURL('/welcome', { waitUntil: 'domcontentloaded' });
    await expect(page2.getByText('Easy, Trustworthy Personal Encryption')).toBeVisible({timeout:10000});

    // page1 should go to sign in dialog
    await page1.goto('/');
    await page1.waitForURL('/', { waitUntil: 'domcontentloaded' });
    await expect(page1.getByRole('heading', { name: /Quick Crypt Sign In/ })).toBeVisible({timeout:10000});

    // sign back in as testUserA — restore its credential first so authId1 can authenticate
    await page1.getByRole('button', { name: /Sign in as a different user/ }).click();
    await page1.waitForURL('/welcome', { waitUntil: 'domcontentloaded' });
    await expect(page1.getByText('Easy, Trustworthy Personal Encryption')).toBeVisible({timeout:10000});

    await clearCredentials(session, authId1);
    await addCredential(session, authId1, testUserA.credential);

    await passkeyAuth(session, authId1, async () => {
      await page1.getByRole('button', { name: 'I have used Quick Crypt' }).click();
    });
    await page1.waitForURL('/', { waitUntil: 'domcontentloaded' });
    await expect(page1.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({timeout:10000});
    await openCredentials(page1);
    await expect(page1.locator('mat-sidenav input').first()).toHaveValue(testUserA.userName);
    await page1.getByRole('button', { name: 'Passkey information' }).click();

    // page2 should now go to enryption page since origianl user is logged in again
    await page2.goto('/');
    await page2.waitForURL('/', { waitUntil: 'domcontentloaded' });
    await expect(page2.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({timeout:10000});
    await openCredentials(page2);
    await expect(page2.locator('mat-sidenav input').first()).toHaveValue(testUserA.userName);

    // page3 should go to welcome page since it its user was logged out
    await page3.goto('/');
    await page3.waitForURL('/welcome', { waitUntil: 'domcontentloaded' });
    await expect(page3.getByText('Easy, Trustworthy Personal Encryption')).toBeVisible({timeout:10000});

  });

});

