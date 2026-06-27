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
  toggleCredentials
} from '.././common';


test.describe('creation', () => {

  testWithAuth('full lifecycle', async ({ authFixture }) => {
    const { page, session, authenticatorId1: authenticatorId1, authenticatorId2: authenticatorId2 } = authFixture;
    test.setTimeout(60000);

    // Server strips <script> tags but keeps their content, so this fill
    // sanitizes to userName — exercises XSS sanitization on the create path.
    // The e2e marker plus the <script> wrapper only leaves room for a 2-digit
    // rand under the 31-char user-name limit.
    const rand = Math.floor(Math.random() * 100).toString().padStart(2, '0');
    const userName = `PWTesty_e2e_${rand}`;
    const fillValue = `PWTesty<script>_e2e_${rand}</script>`;

    await page.goto('/');

    const regVerify = page.waitForResponse((r) =>
      r.url().includes('/v1/reg/verify') && r.request().method() === 'POST'
    );
    const credential = await passkeyCreation(page, session, authenticatorId1, async () => {
      await page.getByRole('button', { name: 'I am new to Quick Crypt' }).click();
      await expect(page.getByRole('heading', { name: 'Create A New user' })).toBeVisible({timeout:10000});
      await page.locator('input#userName').fill(fillValue);
      await page.getByRole('button', { name: /Create new/ }).click();
    });
    const regBody = await (await regVerify).json();
    authFixture.trackUser({
      userId: regBody.userId,
      userName,
      userCred: regBody.userCred,
      passkey: { credentialId: regBody.pkId, authenticatorId: authenticatorId1, credential },
      fastSession: { cookies: await page.context().cookies(), csrf: regBody.csrf },
    });

    await expect(page).toHaveURL(/\/showrecovery$/, {timeout:10000});
    await expect(page.getByRole('heading', { name: 'Account Backup and Recovery' })).toBeVisible({timeout:10000});

    //save recovery pattern
    const recoveryWords = await page.locator('textarea#wordsArea').inputValue();

    await page.getByRole('button', { name: /I saved my/ }).click();

    await expect(page).toHaveURL(/\/$/);
    await expect(page.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({timeout:10000});
    await toggleCredentials(page);

    let tableBody = page.locator('table.credtable tbody');
    await expect(tableBody.locator('tr')).toHaveCount(1);

    await authFixture.addPasskey(regBody.userId, authenticatorId2, async () => {
      await page.getByRole('button', { name: /New Passkey/ }).click();
    });

    await expect(tableBody.locator('tr')).toHaveCount(2);

    await page.getByRole('button', { name: /Sign out/ }).click();

    // Both authenticatorIds hold a passkey for the test user at this point — pass both
    // so presence sim covers whichever the browser picks.
    await passkeyAuth(page, session, [authenticatorId1, authenticatorId2], async () => {
      await page.getByRole('button', { name: new RegExp(`Sign in as ${userName}`) }).click();
    });

    await expect(page).toHaveURL(/\/$/);

    await toggleCredentials(page);

    tableBody = page.locator('table.credtable tbody');
    await expect(tableBody.locator('tr')).toHaveCount(2);

    await page.getByRole('button', { name: /Sign out/ }).click();

    await passkeyAuth(page, session, [authenticatorId1, authenticatorId2], async () => {
      await page.getByRole('button', { name: new RegExp(`Sign in as ${userName}`) }).click();
    });

    await expect(page).toHaveURL(/\/$/);

    await page.goto('/recovery2');
    await expect(page).toHaveURL(/\/recovery2$/);

    await page.locator('textarea#wordsArea').fill(recoveryWords);

    // Recovery wipes all server-side PKs and creates a new one. Track the new
    // one; cleanup naturally shifts the now-stale prior entries.
    await authFixture.addPasskey(regBody.userId, authenticatorId2, async () => {
      await page.getByRole('button', { name: /Start Recovery/ }).click();
    });

    await expect(page).toHaveURL(/\/$/);
    await expect(page.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({timeout:10000});

    //NOTE: comment out the line below to test leaking passkey & user
    await toggleCredentials(page);

    tableBody = page.locator('table.credtable tbody');
    await expect(tableBody.locator('tr')).toHaveCount(1);

    await deleteFirstPasskey(page, userName);

    await expect(page).toHaveURL(/\/welcome$/);
    await expect(page.getByText('Easy, Trustworthy Personal Encryption')).toBeVisible({timeout:10000});

  });

  testWithAuth('delete active passkey signs out', async ({ authFixture }) => {
    const { page, session, authenticatorId1: authenticatorId1, authenticatorId2: authenticatorId2 } = authFixture;
    test.setTimeout(60000);

    const rand = Math.floor(Math.random() * 10000).toString().padStart(4, '0');
    const userName = `PWTesty_e2e_${rand}`;

    await page.goto('/');

    const regVerify = page.waitForResponse((r) =>
      r.url().includes('/v1/reg/verify') && r.request().method() === 'POST'
    );
    const credential = await passkeyCreation(page, session, authenticatorId1, async () => {
      await page.getByRole('button', { name: 'I am new to Quick Crypt' }).click();
      await expect(page.getByRole('heading', { name: 'Create A New user' })).toBeVisible({timeout:10000});
      await page.locator('input#userName').fill(userName);
      await page.getByRole('button', { name: /Create new/ }).click();
    });
    const regBody = await (await regVerify).json();
    authFixture.trackUser({
      userId: regBody.userId,
      userName,
      userCred: regBody.userCred,
      passkey: { credentialId: regBody.pkId, authenticatorId: authenticatorId1, credential },
      fastSession: { cookies: await page.context().cookies(), csrf: regBody.csrf },
    });

    await expect(page).toHaveURL(/\/showrecovery$/, {timeout:10000});
    await expect(page.getByRole('heading', { name: 'Account Backup and Recovery' })).toBeVisible({timeout:10000});
    await page.getByRole('button', { name: /I saved my/ }).click();

    await expect(page).toHaveURL(/\/$/);
    await expect(page.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({timeout:10000});
    await toggleCredentials(page);

    let tableBody = page.locator('table.credtable tbody');
    await expect(tableBody.locator('tr')).toHaveCount(1);

    await authFixture.addPasskey(regBody.userId, authenticatorId2, async () => {
      await page.getByRole('button', { name: /New Passkey/ }).click();
    });

    await expect(tableBody.locator('tr')).toHaveCount(2);

    // Delete the first passkey, which is the one used to sign in (active PK).
    // Server invalidates the session, client calls logout(true), sign-in dialog appears.
    await deleteFirstPasskey(page);
    await expect(page.getByRole('heading', { name: /Quick Crypt Sign In/ })).toBeVisible({timeout:10000});

    // Sign in with the remaining passkey (authenticatorId2)
    await passkeyAuth(page, session, authenticatorId2, async () => {
      await page.getByRole('button', { name: new RegExp(`Sign in as ${userName}`) }).click();
    });

    await expect(page).toHaveURL(/\/$/);
    await expect(page.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({timeout:10000});

    await toggleCredentials(page);
    tableBody = page.locator('table.credtable tbody');
    await expect(tableBody.locator('tr')).toHaveCount(1);

    // Add a secondary passkey, then delete it. Active PK (authenticatorId2) is unchanged,
    // so the session stays valid and the Sign In dialog must not appear.
    await authFixture.addPasskey(regBody.userId, authenticatorId1, async () => {
      await page.getByRole('button', { name: /New Passkey/ }).click();
    });
    await expect(tableBody.locator('tr')).toHaveCount(2);

    await deleteLastPasskey(page);
    await expect(tableBody.locator('tr')).toHaveCount(1);
    await expect(page.getByRole('heading', { name: /Quick Crypt Sign In/ })).not.toBeVisible();

    // Refresh and confirm the session was not invalidated
    await page.reload();
    await expect(page).toHaveURL(/\/$/);
    await expect(page.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({timeout:10000});
    await expect(page.getByRole('heading', { name: /Quick Crypt Sign In/ })).not.toBeVisible();

    await toggleCredentials(page);
    tableBody = page.locator('table.credtable tbody');
    await expect(tableBody.locator('tr')).toHaveCount(1);

    // Cleanup: delete the last passkey, which also deletes the user
    await deleteFirstPasskey(page, userName);
    await expect(page).toHaveURL(/\/welcome$/);
    await expect(page.getByText('Easy, Trustworthy Personal Encryption')).toBeVisible({timeout:10000});
  });

});


test.describe('sign on', () => {

  testWithAuth('regenerate recovery words', async ({ authFixture }) => {
    const { page, session, authenticatorId1: authenticatorId1, authenticatorId2: authenticatorId2 } = authFixture;
    test.setTimeout(60000);

    const testUser = await authFixture.createTestUser(authenticatorId1);

    await toggleCredentials(page);

    let tableBody = page.locator('table.credtable tbody');
    await expect(tableBody.locator('tr')).toHaveCount(1);

    await page.getByRole('button', { name: /Replace recovery words/ }).click();
    await expect(page).toHaveURL(/\/regenrecovery$/);

    await passkeyAuth(page, session, authenticatorId1, async () => {
      await page.getByRole('button', { name: /Generate new recovery words/ }).click();
    });

    await expect(page).toHaveURL(/\/showrecovery$/, {timeout:10000});
    await expect(page.getByRole('button', { name: /I saved my recovery words securely/ })).toBeVisible({timeout:10000});

    const newWords = await page.locator('textarea#wordsArea').inputValue();
    expect(newWords.length).toBeGreaterThan(0);
    expect(newWords).not.toBe(testUser.recoveryWords);
    await expect(page.locator('mat-card-content')).toContainText('Replace all saved copies', {timeout:10000});

    await page.getByRole('button', { name: /I saved my recovery words securely/ }).click();
    await expect(page).toHaveURL(/\/$/);

    // The replaced words can no longer recover the account.
    await page.goto('/recovery2');
    await expect(page).toHaveURL(/\/recovery2$/);
    await page.locator('textarea#wordsArea').fill(testUser.recoveryWords);
    await page.getByRole('button', { name: /Start Recovery/ }).click();
    await expect(page.locator('.control-host .error-msg')).toContainText('recovery word pattern', {timeout:15000});
    await expect(page).toHaveURL(/\/recovery2$/);

    // The new words do. Recovery wipes the old passkey and creates a new one; track it.
    await page.locator('textarea#wordsArea').fill(newWords);
    await authFixture.addPasskey(testUser.userId, authenticatorId2, async () => {
      await page.getByRole('button', { name: /Start Recovery/ }).click();
    });
    await expect(page).toHaveURL(/\/$/);
    await expect(page.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({timeout:10000});

    // Tear down through the post-recovery passkey: deleting the last one removes the
    // user, proving cleanup still works after the passkey was swapped by recovery.
    await toggleCredentials(page);
    tableBody = page.locator('table.credtable tbody');
    await expect(tableBody.locator('tr')).toHaveCount(1);
    await deleteFirstPasskey(page, testUser.userName);
    await expect(page).toHaveURL(/\/welcome$/);

  });

  testWithAuth('check usercred', async ({ authFixture }) => {
    const { page, session, authenticatorId1: authenticatorId1 } = authFixture;
    test.setTimeout(45000);

    const testUser = await authFixture.createTestUser(authenticatorId1);

    await passkeyAuth(page, session, authenticatorId1, async () => {
      await page.goto('/cmdline');
    });

    await expect(page).toHaveURL(/\/cmdline$/);

    await expect(page.locator('input#credential')).toBeVisible();
    await expect(page.locator('input#credential')).toHaveValue(testUser.userCred);

  });

  // This was a bug in the past where could not make further authenticated
  // calls after cmdline (or recoveryword) download.
  // Also exercises full UI-driven user teardown (delete every passkey →
  // server removes the user) — the helper's after-test cleanup should find
  // nothing left to do.
  testWithAuth('check usercred and add pk', async ({ authFixture }) => {
    const { page, session, authenticatorId1: authenticatorId1, authenticatorId2: authenticatorId2 } = authFixture;
    test.setTimeout(45000);

    const testUser = await authFixture.createTestUser(authenticatorId1);

    await passkeyAuth(page, session, authenticatorId1, async () => {
      await page.goto('/cmdline');
    });

    await expect(page).toHaveURL(/\/cmdline$/);

    await expect(page.locator('input#credential')).toBeVisible();
    await expect(page.locator('input#credential')).toHaveValue(testUser.userCred);

    await toggleCredentials(page);

    let tableBody = page.locator('table.credtable tbody');
    await expect(tableBody.locator('tr')).toHaveCount(1);

    await authFixture.addPasskey(testUser.userId, authenticatorId2, async () => {
      await page.getByRole('button', { name: /New Passkey/ }).click();
    });

    await expect(tableBody.locator('tr')).toHaveCount(2);

    // Delete passkeys until the user is gone. The last delete needs username
    // confirmation; the redirect to /welcome confirms the server removed the user.
    await deleteLastPasskey(page);
    await expect(tableBody.locator('tr')).toHaveCount(1);
    await deleteLastPasskey(page, testUser.userName);
    await expect(page).toHaveURL(/\/welcome$/);
  });

  testWithAuth('log in and out', async ({ authFixture }) => {
    const { page, session, authenticatorId1: authenticatorId1 } = authFixture;
    test.setTimeout(45000);

    const testUser = await authFixture.createTestUser(authenticatorId1);

    await toggleCredentials(page);

    let tableBody = page.locator('table.credtable tbody');
    await expect(tableBody.locator('tr')).toHaveCount(1);

    await page.getByRole('button', { name: /Sign out/ }).click();

    await passkeyAuth(page, session, authenticatorId1, async () => {
      await page.getByRole('button', { name: new RegExp(`Sign in as ${testUser.userName}`) }).click();
    });

    await expect(page).toHaveURL(/\/$/);
    await expect(page.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({timeout:10000});

    await toggleCredentials(page);

    tableBody = page.locator('table.credtable tbody');
    await expect(tableBody.locator('tr')).toHaveCount(1);

    await page.getByRole('button', { name: /Sign out/ }).click();
    await page.getByRole('button', { name: /Sign in as a different user/ }).click();

    await expect(page).toHaveURL(/\/welcome$/);
    await expect(page.getByText('Easy, Trustworthy Personal Encryption')).toBeVisible({timeout:10000});

  });

  testWithAuth('3 tabs logout and forget', async ({ authFixture }) => {
    const { page, authenticatorId1: authenticatorId1 } = authFixture;
    test.setTimeout(75000);

    const page1 = page;
    const testUser = await authFixture.createTestUser(authenticatorId1);

    const page2 = await page1.context().newPage();
    await page2.goto('/');
    await expect(page2).toHaveURL(/\/$/);
    await expect(page2.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({timeout:10000});

    // logout 2nd page and confirm first is logged out with Sign In dialog showing
    await toggleCredentials(page2);

    let tableBody2 = page2.locator('table.credtable tbody');
    await expect(tableBody2.locator('tr')).toHaveCount(1);
    await expect(page2.locator('mat-sidenav input').first()).toHaveValue(testUser.userName);

    await page2.getByRole('button', { name: /Sign out/ }).click();
    await expect(page2.getByRole('heading', { name: /Quick Crypt Sign In/ })).toBeVisible({timeout:10000});

    await page1.goto('/');
    await expect(page1).toHaveURL(/\/$/);
    await expect(page1.getByRole('heading', { name: /Quick Crypt Sign In/ })).toBeVisible({timeout:10000});

    // make sure a new pages goes to the sign in dialog not welcome pages
    const page3 = await page1.context().newPage();
    await page3.goto('/');
    await expect(page3).toHaveURL(/\/$/);
    await expect(page3.getByRole('heading', { name: /Quick Crypt Sign In/ })).toBeVisible({timeout:10000});

    // Forget user and all pages should go back to welcome page
    await page2.getByRole('button', { name: /Sign in as a different user/ }).click();
    await expect(page2).toHaveURL(/\/welcome$/);
    await expect(page2.getByText('Easy, Trustworthy Personal Encryption')).toBeVisible({timeout:10000});

    await page1.goto('/');
    await expect(page1).toHaveURL(/\/welcome$/);
    await expect(page1.getByText('Easy, Trustworthy Personal Encryption')).toBeVisible({timeout:10000});

    await page3.goto('/');
    await expect(page3).toHaveURL(/\/welcome$/);
    await expect(page3.getByText('Easy, Trustworthy Personal Encryption')).toBeVisible({timeout:10000});

  });

  testWithAuth('3 tabs switch user', async ({ authFixture }) => {
    const { page, session, authenticatorId1: authenticatorId1 } = authFixture;
    test.setTimeout(120000);

    const page1 = page;
    const testUserA = await authFixture.createTestUser(authenticatorId1);

    const page2 = await page1.context().newPage();
    await page2.goto('/');
    await expect(page2).toHaveURL(/\/$/);
    await expect(page2.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({timeout:10000});
    await toggleCredentials(page2);
    await expect(page2.locator('mat-sidenav input').first()).toHaveValue(testUserA.userName);

    // log 1st page in as a different user
    await toggleCredentials(page1);

    let tableBody1 = page1.locator('table.credtable tbody');
    await expect(tableBody1.locator('tr')).toHaveCount(1);
    await expect(page1.locator('mat-sidenav input').first()).toHaveValue(testUserA.userName);

    await page1.getByRole('button', { name: /Sign out/ }).click();
    await page1.getByRole('button', { name: /Sign in as a different user/ }).click();

    await expect(page1).toHaveURL(/\/welcome$/);
    await expect(page1.getByText('Easy, Trustworthy Personal Encryption')).toBeVisible({timeout:10000});

    await clearCredentials(session, authenticatorId1);
    const testUserB = await authFixture.createTestUser(authenticatorId1);

    await toggleCredentials(page1);
    await expect(page1.locator('mat-sidenav input').first()).toHaveValue(testUserB.userName);

    // page2 should go to welcome since its user context is now testUserB and we don't directly transition
    await page2.goto('/');
    await expect(page2).toHaveURL(/\/welcome$/);
    await expect(page2.getByText('Easy, Trustworthy Personal Encryption')).toBeVisible({timeout:10000});

    // page3 should open to core page because it didn't have preivous user context
    const page3 = await page1.context().newPage();

    await page3.goto('/');
    await expect(page3).toHaveURL(/\/$/);
    await expect(page3.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({timeout:10000});
    await toggleCredentials(page3);
    let tableBody3 = page3.locator('table.credtable tbody');
    await expect(tableBody3.locator('tr')).toHaveCount(1);
    await expect(page3.locator('mat-sidenav input').first()).toHaveValue(testUserB.userName);
    await page3.getByRole('button', { name: /Sign out/ }).click();
    await expect(page3.getByRole('heading', { name: /Quick Crypt Sign In/ })).toBeVisible({timeout:10000});

    // page2 should still go to welcome page since its origianl user was logged out
    await page2.goto('/');
    await expect(page2).toHaveURL(/\/welcome$/);
    await expect(page2.getByText('Easy, Trustworthy Personal Encryption')).toBeVisible({timeout:10000});

    // page1 should go to sign in dialog
    await page1.goto('/');
    await expect(page1).toHaveURL(/\/$/);
    await expect(page1.getByRole('heading', { name: /Quick Crypt Sign In/ })).toBeVisible({timeout:10000});

    // sign back in as testUserA — restore its credential first so authenticatorId1 can authenticate
    await page1.getByRole('button', { name: /Sign in as a different user/ }).click();
    await expect(page1).toHaveURL(/\/welcome$/);
    await expect(page1.getByText('Easy, Trustworthy Personal Encryption')).toBeVisible({timeout:10000});

    await clearCredentials(session, authenticatorId1);
    await addCredential(session, authenticatorId1, testUserA.credential);

    await passkeyAuth(page, session, authenticatorId1, async () => {
      await page1.getByRole('button', { name: 'I have used Quick Crypt' }).click();
    });
    await expect(page1).toHaveURL(/\/$/);
    await expect(page1.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({timeout:10000});
    await toggleCredentials(page1);
    await expect(page1.locator('mat-sidenav input').first()).toHaveValue(testUserA.userName);
    await page1.getByRole('button', { name: 'Passkey information' }).click();

    // page2 should now go to enryption page since origianl user is logged in again
    await page2.goto('/');
    await expect(page2).toHaveURL(/\/$/);
    await expect(page2.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({timeout:10000});
    await toggleCredentials(page2);
    await expect(page2.locator('mat-sidenav input').first()).toHaveValue(testUserA.userName);

    // page3 should go to welcome page since it its user was logged out
    await page3.goto('/');
    await expect(page3).toHaveURL(/\/welcome$/);
    await expect(page3.getByText('Easy, Trustworthy Personal Encryption')).toBeVisible({timeout:10000});

  });

});

