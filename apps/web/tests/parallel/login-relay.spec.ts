/* MIT License

Copyright (c) 2026 Brad Schick

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE. */

/* Between the tests in this file and authenticator.service.spec.ts (unit) we attempt
to assert most of the meaninful actions in this table
+-------------------------------------------------------+--------------------------+--------------------------------+-------------------------------------+------------------------------------------------+-------------------------------------------------------------------------------------+-----------------------------------------------+
| Sender Action                                         | recipient at /welcome    | recipient at login - same user | recipient at login - different user | recipient active session PK1 - same user       | recipient active session PK2 - same user                                            | recipient active session PKx - different user |
+-------------------------------------------------------+--------------------------+--------------------------------+-------------------------------------+------------------------------------------------+-------------------------------------------------------------------------------------+-----------------------------------------------+
| forget user                                           | forget local             | forget local                   | forget local                        | forget local                                   | forget local                                                                        | forget local                                  |
| msg: kind                                             |                          |                                |                                     |                                                |                                                                                     |                                               |
| keystore: deleted                                     |                          |                                |                                     |                                                |                                                                                     |                                               |
+-------------------------------------------------------+--------------------------+--------------------------------+-------------------------------------+------------------------------------------------+-------------------------------------------------------------------------------------+-----------------------------------------------+
| logout local                                          | no action                | no action                      | no action                           | no action                                      | no action                                                                           | no action                                     |
| msg: none                                             |                          |                                |                                     |                                                |                                                                                     |                                               |
| keystore: no change                                   |                          |                                |                                     |                                                |                                                                                     |                                               |
+-------------------------------------------------------+--------------------------+--------------------------------+-------------------------------------+------------------------------------------------+-------------------------------------------------------------------------------------+-----------------------------------------------+
| logout global                                         | no action                | no action                      | no action                           | version >=: logout local                       | version >=: logout local                                                            | (unreachable w/o dropped messages)            |
| msg: kind, pkid, version                              |                          |                                |                                     | version <: no action                           | version <: no action                                                                | version >=: logout local                      |
| keystore: no change                                   |                          |                                |                                     |                                                |                                                                                     | version <: no action                          |
+-------------------------------------------------------+--------------------------+--------------------------------+-------------------------------------+------------------------------------------------+-------------------------------------------------------------------------------------+-----------------------------------------------+
| login w/ PK1                                          | forget local             | no action                      | navigate to /welcome                | version >: store sessionState and GET /session | version > AND                                                                       | version >: forget local                       |
| msg: kind, pkid, version, userCredEnc, userCredExpiry | (due to simplified code) |                                |                                     | version <=: no action                          | PK1 known: switch current PK, store sessionState, GET /sessio                       | version <=: no action                         |
| keystore: (re)created                                 |                          |                                |                                     |                                                | PK1 unknown: logout local, go back to login page (unreachable w/o dropped messages) |                                               |
|                                                       |                          |                                |                                     |                                                +-------------------------------------------------------------------------------------+                                               |
|                                                       |                          |                                |                                     |                                                | version <=: no action                                                               |                                               |
+-------------------------------------------------------+--------------------------+--------------------------------+-------------------------------------+------------------------------------------------+-------------------------------------------------------------------------------------+-----------------------------------------------+
| PK created w/ current PK1                             | no action                | no action                      | no action                           | refresh userInfo                               | PK1 known: refresh userInfo                                                         | no action                                     |
| msg: kind, pkid                                       |                          |                                |                                     |                                                | PK1 unknown: no action                                                              |                                               |
| keystore: no change                                   |                          |                                |                                     |                                                |                                                                                     |                                               |
+-------------------------------------------------------+--------------------------+--------------------------------+-------------------------------------+------------------------------------------------+-------------------------------------------------------------------------------------+-----------------------------------------------+
*/

import { test, expect } from '@playwright/test';
import { testWithAuth, toggleCredentials, passkeyAuth, passkeyCreation, deleteFirstPasskey, deleteLastPasskey, clearCredentials, addCredential, setupAuthenticator, removeAuthenticator, expectActiveServerSession } from '.././common';


test.describe('login relay', () => {

  testWithAuth('reload preserves session in the same tab', { tag: '@nukeall' }, async ({ authFixture }) => {
    const { page, authenticatorId1 } = authFixture;
    test.setTimeout(45000);

    await authFixture.createTestUser(authenticatorId1);
    await expect(page.getByRole('button', { name: 'Encryption Mode' })).toBeVisible();

    await page.reload();
    await expect(page).toHaveURL(/\/$/);

    await expect(page.getByRole('button', { name: 'Encryption Mode' })).toBeVisible();
    await expect(page.getByRole('heading', { name: /Quick Crypt Sign In/ })).not.toBeVisible();
  });

  testWithAuth('second tab restores via peer relay without prompting', { tag: '@nukeall' }, async ({ authFixture }) => {
    const { page: page1, authenticatorId1 } = authFixture;
    test.setTimeout(45000);

    await authFixture.createTestUser(authenticatorId1);
    await expect(page1.getByRole('button', { name: 'Encryption Mode' })).toBeVisible();

    const page2 = await page1.context().newPage();
    await page2.goto('/');
    await expect(page2).toHaveURL(/\/$/);

    await expect(page2.getByRole('button', { name: 'Encryption Mode' })).toBeVisible();
    await expect(page2.getByRole('heading', { name: /Quick Crypt Sign In/ })).not.toBeVisible();

    // page1 should keep its session alive.
    await expect(page1.getByRole('button', { name: 'Encryption Mode' })).toBeVisible();
  });

  testWithAuth('reloading either tab keeps both signed in', { tag: '@nukeall' }, async ({ authFixture }) => {
    const { page: page1, authenticatorId1 } = authFixture;
    test.setTimeout(60000);

    await authFixture.createTestUser(authenticatorId1);
    await expect(page1.getByRole('button', { name: 'Encryption Mode' })).toBeVisible();

    const page2 = await page1.context().newPage();
    await page2.goto('/');
    await expect(page2).toHaveURL(/\/$/);
    await expect(page2.getByRole('button', { name: 'Encryption Mode' })).toBeVisible();

    await page1.reload();
    await expect(page1).toHaveURL(/\/$/);
    await expect(page1.getByRole('button', { name: 'Encryption Mode' })).toBeVisible();
    await expect(page1.getByRole('heading', { name: /Quick Crypt Sign In/ })).not.toBeVisible();

    await expect(page2.getByRole('button', { name: 'Encryption Mode' })).toBeVisible();

    await page2.reload();
    await expect(page2).toHaveURL(/\/$/);
    await expect(page2.getByRole('button', { name: 'Encryption Mode' })).toBeVisible();
    await expect(page2.getByRole('heading', { name: /Quick Crypt Sign In/ })).not.toBeVisible();
  });

  testWithAuth('navigate away then back via history keeps session', { tag: '@nukeall' }, async ({ authFixture }) => {
    const { page, authenticatorId1 } = authFixture;
    test.setTimeout(45000);

    await authFixture.createTestUser(authenticatorId1);
    await expect(page.getByRole('button', { name: 'Encryption Mode' })).toBeVisible();

    await page.goto('about:blank');
    await page.goBack();
    await expect(page).toHaveURL(/\/$/);

    await expect(page.getByRole('button', { name: 'Encryption Mode' })).toBeVisible();
    await expect(page.getByRole('heading', { name: /Quick Crypt Sign In/ })).not.toBeVisible();
  });

  testWithAuth('navigate away then re-navigate to qcrypt keeps session', { tag: '@nukeall' }, async ({ authFixture }) => {
    const { page, authenticatorId1 } = authFixture;
    test.setTimeout(45000);

    await authFixture.createTestUser(authenticatorId1);
    await expect(page.getByRole('button', { name: 'Encryption Mode' })).toBeVisible();

    await page.goto('about:blank');
    await page.goto('/');
    await expect(page).toHaveURL(/\/$/);

    await expect(page.getByRole('button', { name: 'Encryption Mode' })).toBeVisible();
    await expect(page.getByRole('heading', { name: /Quick Crypt Sign In/ })).not.toBeVisible();
  });

  testWithAuth('peer fresh-login then tab reload restores via updated relay', { tag: '@nukeall' }, async ({ authFixture }) => {
    const { page: page1, session, authenticatorId1 } = authFixture;
    test.setTimeout(60000);

    const testUser = await authFixture.createTestUser(authenticatorId1);
    await expect(page1.getByRole('button', { name: 'Encryption Mode' })).toBeVisible();

    const page2 = await page1.context().newPage();
    await page2.goto('/');
    await expect(page2).toHaveURL(/\/$/);
    await expect(page2.getByRole('button', { name: 'Encryption Mode' })).toBeVisible();

    await toggleCredentials(page1);
    await page1.getByRole('button', { name: /Sign out/ }).click();
    await expect(page1.getByRole('heading', { name: /Quick Crypt Sign In/ })).toBeVisible();

    // page2 should have received logout message
    await expect(page2.getByRole('heading', { name: /Quick Crypt Sign In/ })).toBeVisible();

    await passkeyAuth(page1, session, authenticatorId1, async () => {
      await page1.getByRole('button', { name: new RegExp(`Sign in as ${testUser.userName}`) }).click();
    });
    await expect(page1.getByRole('button', { name: 'Encryption Mode' })).toBeVisible();

    // page2 should not react to the login broadcast — it's the same user we already know.
    await page2.waitForTimeout(500);
    await expect(page2.getByRole('heading', { name: /Quick Crypt Sign In/ })).toBeVisible();
    await expect(page2.getByRole('button', { name: new RegExp(`Sign in as ${testUser.userName}`) })).toBeVisible();

    // page2 reload with same user — must restablish new session and relay creds from page1.
    await page2.reload();
    await expect(page2).toHaveURL(/\/$/);
    await expect(page2.getByRole('button', { name: 'Encryption Mode' })).toBeVisible();
    await expect(page2.getByRole('heading', { name: /Quick Crypt Sign In/ })).not.toBeVisible();
    await expectActiveServerSession(page1, testUser.userName);
    await expectActiveServerSession(page2, testUser.userName);
  });

  testWithAuth('sign out in one tab fans out to peers', { tag: '@nukeall' }, async ({ authFixture }) => {
    const { page: page1, authenticatorId1 } = authFixture;
    test.setTimeout(45000);

    await authFixture.createTestUser(authenticatorId1);
    await expect(page1.getByRole('button', { name: 'Encryption Mode' })).toBeVisible();

    const page2 = await page1.context().newPage();
    await page2.goto('/');
    await expect(page2).toHaveURL(/\/$/);
    await expect(page2.getByRole('button', { name: 'Encryption Mode' })).toBeVisible();

    const page3 = await page1.context().newPage();
    await page3.goto('/');
    await expect(page3).toHaveURL(/\/$/);
    await expect(page3.getByRole('button', { name: 'Encryption Mode' })).toBeVisible();

    await toggleCredentials(page2);
    await page2.getByRole('button', { name: /Sign out/ }).click();

    await expect(page3.getByRole('heading', { name: /Quick Crypt Sign In/ })).toBeVisible();
    await expect(page2.getByRole('heading', { name: /Quick Crypt Sign In/ })).toBeVisible();
    await expect(page1.getByRole('heading', { name: /Quick Crypt Sign In/ })).toBeVisible();
  });

  testWithAuth('forget user in one tab fans out peers to /welcome', { tag: '@nukeall' }, async ({ authFixture }) => {
    const { page: page1, authenticatorId1 } = authFixture;
    test.setTimeout(45000);

    await authFixture.createTestUser(authenticatorId1);
    await expect(page1.getByRole('button', { name: 'Encryption Mode' })).toBeVisible();

    const page2 = await page1.context().newPage();
    await page2.goto('/');
    await expect(page2).toHaveURL(/\/$/);
    await expect(page2.getByRole('button', { name: 'Encryption Mode' })).toBeVisible();

    await toggleCredentials(page2);
    await page2.getByRole('button', { name: /Sign out/ }).click();
    await page2.getByRole('button', { name: /Sign in as a different user/ }).click();
    await expect(page2).toHaveURL(/\/welcome$/);

    await expect(page1).toHaveURL(/\/welcome$/);
    await expect(page1.getByText('Easy, Trustworthy Personal Encryption')).toBeVisible();
  });

  testWithAuth('sign in logs out tabs with a different user', { tag: '@nukeall' }, async ({ authFixture }) => {
    const { page: page1, session, authenticatorId1 } = authFixture;
    test.setTimeout(75000);

    const userA = await authFixture.createTestUser(authenticatorId1);
    await expect(page1.getByRole('button', { name: 'Encryption Mode' })).toBeVisible();

    await toggleCredentials(page1);
    await page1.getByRole('button', { name: /Sign out/ }).click();
    await page1.getByRole('button', { name: /Sign in as a different user/ }).click();
    await expect(page1).toHaveURL(/\/welcome$/);

    await clearCredentials(session, authenticatorId1);
    const userB = await authFixture.createTestUser(authenticatorId1);
    await expect(page1.getByRole('button', { name: 'Encryption Mode' })).toBeVisible();

    await toggleCredentials(page1);
    await page1.getByRole('button', { name: /Sign out/ }).click();
    await page1.getByRole('button', { name: /Sign in as a different user/ }).click();
    await expect(page1).toHaveURL(/\/welcome$/);

    // CDP WebAuthn state is per-tab, so page2 needs its own virtual authenticator.
    const page2 = await page1.context().newPage();
    const session2 = await page2.context().newCDPSession(page2);
    const page2Authenticator = await setupAuthenticator(session2, page2, 'internal');
    try {
      await page2.goto('/welcome', { waitUntil: 'domcontentloaded' });

      // sign in page1 as userA
      await clearCredentials(session, authenticatorId1);
      await addCredential(session, authenticatorId1, userA.credential);
      await passkeyAuth(page1, session, authenticatorId1, async () => {
        await page1.getByRole('button', { name: 'I have used Quick Crypt' }).click();
      });
      await expect(page1.getByRole('button', { name: 'Encryption Mode' })).toBeVisible();

      // sign in page2 as userB
      await addCredential(session2, page2Authenticator, userB.credential);
      await passkeyAuth(page2, session2, page2Authenticator, async () => {
        await page2.getByRole('button', { name: 'I have used Quick Crypt' }).click();
      });
      await expect(page2.getByRole('button', { name: 'Encryption Mode' })).toBeVisible();

      await expect(page1).toHaveURL(/\/welcome$/, { timeout: 10000 });
      await expect(page1.getByText('Easy, Trustworthy Personal Encryption')).toBeVisible();
      await expectActiveServerSession(page2, userB.userName);

      // page2 is signed in as userB. Delete userB's passkey explicitly so the
      // fixture's tracked-user cleanup doesn't fall back to re-auth for a credential we no longer hold.
      await deleteFirstPasskey(page2, userB.userName);
    } finally {
      await removeAuthenticator(session2, page2Authenticator);
      await session2.detach();
    }

    // Restore the fixture user's credential so the tracked-user cleanup can re-auth if the fast path fails.
    await clearCredentials(session, authenticatorId1);
    await addCredential(session, authenticatorId1, userA.credential);
  });

  testWithAuth('new passkey from peer refreshes credentials view', { tag: '@nukeall' }, async ({ authFixture }) => {
    const { page: page1, session, authenticatorId1, authenticatorId2 } = authFixture;
    test.setTimeout(60000);

    await authFixture.createTestUser(authenticatorId1);
    await expect(page1.getByRole('button', { name: 'Encryption Mode' })).toBeVisible();
    await toggleCredentials(page1);
    const tableBody1 = page1.locator('table.credtable tbody');
    await expect(tableBody1.locator('tr')).toHaveCount(1);

    const page2 = await page1.context().newPage();
    await page2.goto('/');
    await expect(page2).toHaveURL(/\/$/);
    await expect(page2.getByRole('button', { name: 'Encryption Mode' })).toBeVisible();

    await toggleCredentials(page2);
    const tableBody2 = page2.locator('table.credtable tbody');
    await expect(tableBody2.locator('tr')).toHaveCount(1);

    await passkeyCreation(page1, session, authenticatorId2, async () => {
      await page1.getByRole('button', { name: /New Passkey/ }).click();
    });

    await expect(tableBody1.locator('tr')).toHaveCount(2);
    await expect(tableBody2.locator('tr')).toHaveCount(2);
    await expectActiveServerSession(page2);
  });

  testWithAuth('deleted passkey from peer refreshes credentials view', { tag: '@nukeall' }, async ({ authFixture }) => {
    const { page: page1, session, authenticatorId1, authenticatorId2 } = authFixture;
    test.setTimeout(60000);

    await authFixture.createTestUser(authenticatorId1);
    await expect(page1.getByRole('button', { name: 'Encryption Mode' })).toBeVisible();
    await toggleCredentials(page1);
    const tableBody1 = page1.locator('table.credtable tbody');
    await expect(tableBody1.locator('tr')).toHaveCount(1);

    await passkeyCreation(page1, session, authenticatorId2, async () => {
      await page1.getByRole('button', { name: /New Passkey/ }).click();
    });
    await expect(tableBody1.locator('tr')).toHaveCount(2);

    const page2 = await page1.context().newPage();
    await page2.goto('/');
    await expect(page2).toHaveURL(/\/$/);
    await expect(page2.getByRole('button', { name: 'Encryption Mode' })).toBeVisible();

    await toggleCredentials(page2);
    const tableBody2 = page2.locator('table.credtable tbody');
    await expect(tableBody2.locator('tr')).toHaveCount(2);

    await deleteLastPasskey(page1);

    await expect(tableBody1.locator('tr')).toHaveCount(1);
    await expect(tableBody2.locator('tr')).toHaveCount(1);
    await expectActiveServerSession(page1);
    await expectActiveServerSession(page2);
  });

  testWithAuth('switch passkey within same user propagates to peer', { tag: '@nukeall' }, async ({ authFixture }) => {
    const { page: page1, session, authenticatorId1, authenticatorId2 } = authFixture;
    test.setTimeout(75000);

    const testUser = await authFixture.createTestUser(authenticatorId1);
    await expect(page1.getByRole('button', { name: 'Encryption Mode' })).toBeVisible();

    await toggleCredentials(page1);
    await passkeyCreation(page1, session, authenticatorId2, async () => {
      await page1.getByRole('button', { name: /New Passkey/ }).click();
    });
    await expect(page1.locator('table.credtable tbody').locator('tr')).toHaveCount(2);

    await page1.getByRole('button', { name: /Sign out/ }).click();
    await expect(page1.getByRole('heading', { name: /Quick Crypt Sign In/ })).toBeVisible();

    // CDP WebAuthn state is per-tab, so page2 needs its own virtual authenticator.
    const page2 = await page1.context().newPage();
    const session2 = await page2.context().newCDPSession(page2);
    const page2Auth = await setupAuthenticator(session2, page2, 'internal');
    try {
      await page2.goto('/');
      await expect(page2).toHaveURL(/\/$/);
      await expect(page2.getByRole('heading', { name: /Quick Crypt Sign In/ })).toBeVisible();

      // page2 signs in with first passkey
      await addCredential(session2, page2Auth, testUser.credential);
      await passkeyAuth(page2, session2, page2Auth, async () => {
        await page2.getByRole('button', { name: new RegExp(`Sign in as ${testUser.userName}`) }).click();
      });
      await expect(page2.getByRole('button', { name: 'Encryption Mode' })).toBeVisible();

      await toggleCredentials(page2);
      const page2Rows = page2.locator('table.credtable tbody tr');
      await expect(page2Rows).toHaveCount(2);
      const page2HighlightedIndex = async () => page2.evaluate(() => {
        const rows = Array.from(document.querySelectorAll('table.credtable tbody tr'));
        return rows.findIndex((row) => row.querySelector('td.current-pk') !== null);
      });
      const firstHighlighted = await page2HighlightedIndex();
      expect(firstHighlighted).toBeGreaterThanOrEqual(0);

      // page1 signs in with second passkey
      await clearCredentials(session, authenticatorId1);
      await passkeyAuth(page1, session, authenticatorId2, async () => {
        await page1.getByRole('button', { name: new RegExp(`Sign in as ${testUser.userName}`) }).click();
      });
      await expect(page1.getByRole('button', { name: 'Encryption Mode' })).toBeVisible();

      await expect.poll(page2HighlightedIndex).not.toBe(firstHighlighted);
      await expect(page2.getByRole('button', { name: 'Encryption Mode' })).toBeVisible();
      await expectActiveServerSession(page1, testUser.userName);
      await expectActiveServerSession(page2, testUser.userName);
    } finally {
      await removeAuthenticator(session2, page2Auth);
      await session2.detach();
    }

    // Restore the fixture user's credential so the tracked-user cleanup can re-auth if the fast path fails.
    await addCredential(session, authenticatorId1, testUser.credential);
  });

  testWithAuth('login as different user navigates peer sign-in dialog to /welcome', { tag: '@nukeall' }, async ({ authFixture }) => {
    const { page: page1, session, authenticatorId1 } = authFixture;
    test.setTimeout(90000);

    const userA = await authFixture.createTestUser(authenticatorId1);
    await expect(page1.getByRole('button', { name: 'Encryption Mode' })).toBeVisible();

    await toggleCredentials(page1);
    await page1.getByRole('button', { name: /Sign out/ }).click();
    await page1.getByRole('button', { name: /Sign in as a different user/ }).click();
    await expect(page1).toHaveURL(/\/welcome$/);

    await clearCredentials(session, authenticatorId1);
    const userB = await authFixture.createTestUser(authenticatorId1);
    await expect(page1.getByRole('button', { name: 'Encryption Mode' })).toBeVisible();

    await toggleCredentials(page1);
    await page1.getByRole('button', { name: /Sign out/ }).click();
    await page1.getByRole('button', { name: /Sign in as a different user/ }).click();
    await expect(page1).toHaveURL(/\/welcome$/);

    const page2 = await page1.context().newPage();
    const session2 = await page2.context().newCDPSession(page2);
    const page2Authenticator = await setupAuthenticator(session2, page2, 'internal');
    try {
      await addCredential(session2, page2Authenticator, userB.credential);
      await page2.goto('/welcome');
      await passkeyAuth(page2, session2, page2Authenticator, async () => {
        await page2.getByRole('button', { name: 'I have used Quick Crypt' }).click();
      });
      await expect(page2.getByRole('button', { name: 'Encryption Mode' })).toBeVisible();

      await toggleCredentials(page2);
      await page2.getByRole('button', { name: /Sign out/ }).click();
      await expect(page2.getByRole('button', { name: new RegExp(`Sign in as ${userB.userName}`) })).toBeVisible();

      await clearCredentials(session, authenticatorId1);
      await addCredential(session, authenticatorId1, userA.credential);
      await passkeyAuth(page1, session, authenticatorId1, async () => {
        await page1.getByRole('button', { name: 'I have used Quick Crypt' }).click();
      });
      await expect(page1.getByRole('button', { name: 'Encryption Mode' })).toBeVisible();

      await expect(page2).toHaveURL(/\/welcome$/, { timeout: 15000 });
    } finally {
      await removeAuthenticator(session2, page2Authenticator);
      await session2.detach();
    }

    await clearCredentials(session, authenticatorId1);
    await addCredential(session, authenticatorId1, userA.credential);
  });

  testWithAuth('peer at sign-in dialog ignores broadcasts from same user', { tag: '@nukeall' }, async ({ authFixture }) => {
    const { page: page1, session, authenticatorId1 } = authFixture;
    test.setTimeout(60000);

    const testUser = await authFixture.createTestUser(authenticatorId1);
    await expect(page1.getByRole('button', { name: 'Encryption Mode' })).toBeVisible();

    const page2 = await page1.context().newPage();
    await page2.goto('/');
    await expect(page2).toHaveURL(/\/$/);
    await expect(page2.getByRole('button', { name: 'Encryption Mode' })).toBeVisible();

    // page1 signs out → page2 opens sign-in dialog.
    await toggleCredentials(page1);
    await page1.getByRole('button', { name: /Sign out/ }).click();
    await expect(page1.getByRole('heading', { name: /Quick Crypt Sign In/ })).toBeVisible();
    await expect(page2.getByRole('heading', { name: /Quick Crypt Sign In/ })).toBeVisible();

    // page1 signs back in → page2 at dialog should not react.
    await passkeyAuth(page1, session, authenticatorId1, async () => {
      await page1.getByRole('button', { name: new RegExp(`Sign in as ${testUser.userName}`) }).click();
    });
    await expect(page1.getByRole('button', { name: 'Encryption Mode' })).toBeVisible();
    await page2.waitForTimeout(500);
    await expect(page2.getByRole('button', { name: new RegExp(`Sign in as ${testUser.userName}`) })).toBeVisible();

    // page1 signs out again → page2 still at dialog should not react.
    await toggleCredentials(page1);
    await page1.getByRole('button', { name: /Sign out/ }).click();
    await expect(page1.getByRole('heading', { name: /Quick Crypt Sign In/ })).toBeVisible();
    await page2.waitForTimeout(500);
    await expect(page2.getByRole('button', { name: new RegExp(`Sign in as ${testUser.userName}`) })).toBeVisible();
  });

  testWithAuth('cold start with no live peer prompts for sign in', { tag: '@nukeall' }, async ({ authFixture }) => {
    const { page: page1, authenticatorId1 } = authFixture;
    test.setTimeout(45000);

    await authFixture.createTestUser(authenticatorId1);
    await expect(page1.getByRole('button', { name: 'Encryption Mode' })).toBeVisible();

    // Unload qcrypt from page1 so it stops responding on the broadcast channel
    await page1.goto('about:blank');

    const page2 = await page1.context().newPage();
    await page2.goto('/');
    await expect(page2).toHaveURL(/\/$/);

    await expect(page2.getByRole('heading', { name: /Quick Crypt Sign In/ })).toBeVisible();
  });

});
