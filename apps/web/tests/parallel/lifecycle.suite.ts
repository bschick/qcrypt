import { test, expect, Page } from '@playwright/test';
import { HmacSecretMode } from 'nid-webauthn-emulator';
import {
  testWithAuth,
  toggleCredentials,
  deleteFirstPasskey,
  deleteLastPasskey,
} from '.././common';

// Account lifecycle shared between a PRF account (hmac-secret-mc) and a no-PRF
// account (none). Consumed by lifecycle.spec.ts (no-PRF) and prf-lifecycle.spec.ts
// (PRF); branches only where the two modes must differ (the PRF badge and the
// add-passkey downgrade rules).
export function lifecycleSuite(prf: boolean): void {
  const mode: HmacSecretMode = prf ? 'hmac-secret-mc' : 'none';
  const label = prf ? 'PRF' : 'no-PRF';

  async function expectPrfBadge(page: Page): Promise<void> {
    const badge = page.locator('.prf-badge');
    if (prf) {
      await expect(badge).toBeVisible();
    } else {
      await expect(badge).toHaveCount(0);
    }
  }

  testWithAuth(`${label}: log in and out`, async ({ authFixture }) => {
    const { page } = authFixture;
    test.setTimeout(45000);

    const authenticator = authFixture.memAuthenticator(mode);
    const testUser = await authFixture.createTestUser(authenticator);

    // Creating the account is a single passkey ceremony — PRF at create, or the
    // no-PRF fallback completing the same passkey.
    expect(authFixture.credentialCreateCount()).toBe(1);

    await toggleCredentials(page);
    await expectPrfBadge(page);
    const tableBody = page.locator('table.credtable tbody');
    await expect(tableBody.locator('tr')).toHaveCount(1);

    await page.getByRole('button', { name: /Sign out/ }).click();
    await authFixture.passkeyAuth(authenticator, async () => {
      await page.getByRole('button', { name: new RegExp(`Sign in as ${testUser.userName}`) }).click();
    });

    await expect(page).toHaveURL(/\/$/);
    await expect(page.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({ timeout: 10000 });

    await toggleCredentials(page);
    await expect(tableBody.locator('tr')).toHaveCount(1);
    await expectPrfBadge(page);

    await page.getByRole('button', { name: /Sign out/ }).click();
    await page.getByRole('button', { name: /Sign in as a different user/ }).click();

    await expect(page).toHaveURL(/\/welcome$/);
    await expect(page.getByText('Easy, Trustworthy Personal Encryption')).toBeVisible({ timeout: 10000 });
  });

  testWithAuth(`${label}: check usercred matches /cmdline`, async ({ authFixture }) => {
    const { page } = authFixture;
    test.setTimeout(45000);

    const authenticator = authFixture.memAuthenticator(mode);
    const testUser = await authFixture.createTestUser(authenticator);

    await authFixture.passkeyAuth(authenticator, async () => {
      await page.goto('/cmdline');
    });
    await expect(page).toHaveURL(/\/cmdline$/);

    await expect(page.locator('input#credential')).toBeVisible();
    await expect(page.locator('input#credential')).toHaveValue(testUser.userCred);
  });

  testWithAuth(`${label}: full lifecycle`, async ({ authFixture }) => {
    const { page } = authFixture;
    test.setTimeout(60000);

    const authenticator1 = authFixture.memAuthenticator(mode);
    const testUser = await authFixture.createTestUser(authenticator1);

    // Each passkey the account gains — create, add, recovery — is one create ceremony.
    expect(authFixture.credentialCreateCount()).toBe(1);

    await toggleCredentials(page);
    await expectPrfBadge(page);
    const tableBody = page.locator('table.credtable tbody');
    await expect(tableBody.locator('tr')).toHaveCount(1);

    // A second passkey needs a second authenticator (one credential per userId per
    // authenticator), standing in for a second device.
    const authenticator2 = authFixture.memAuthenticator(mode);
    await authFixture.addPasskey(testUser.userId, authenticator2, async () => {
      await page.getByRole('button', { name: /New Passkey/ }).click();
    });
    await expect(tableBody.locator('tr')).toHaveCount(2);
    expect(authFixture.credentialCreateCount()).toBe(2);

    await page.getByRole('button', { name: /Sign out/ }).click();
    await authFixture.passkeyAuth(authenticator1, async () => {
      await page.getByRole('button', { name: new RegExp(`Sign in as ${testUser.userName}`) }).click();
    });
    await expect(page).toHaveURL(/\/$/);

    // Recovery wipes the server passkeys and provisions a new one while preserving
    // userCred, so the account keeps its mode.
    await page.goto('/recovery2');
    await expect(page).toHaveURL(/\/recovery2$/);
    await page.locator('textarea#wordsArea').fill(testUser.recoveryWords);
    await authFixture.addPasskey(testUser.userId, authenticator2, async () => {
      await page.getByRole('button', { name: /Start Recovery/ }).click();
    });
    await expect(page).toHaveURL(/\/$/);
    await expect(page.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({ timeout: 10000 });
    expect(authFixture.credentialCreateCount()).toBe(3);

    await toggleCredentials(page);
    await expect(tableBody.locator('tr')).toHaveCount(1);
    await expectPrfBadge(page);

    await deleteFirstPasskey(page, testUser.userName);
    await expect(page).toHaveURL(/\/welcome$/);
    await expect(page.getByText('Easy, Trustworthy Personal Encryption')).toBeVisible({ timeout: 10000 });
    authFixture.untrackUser(testUser.userId);
  });

  // Exercises the past bug where authenticated calls failed after a cmdline (or
  // recovery word) download, plus full UI-driven teardown (delete every passkey →
  // the server removes the user).
  testWithAuth(`${label}: check usercred and add pk`, async ({ authFixture }) => {
    const { page } = authFixture;
    test.setTimeout(45000);

    const authenticator1 = authFixture.memAuthenticator(mode);
    const testUser = await authFixture.createTestUser(authenticator1);

    await authFixture.passkeyAuth(authenticator1, async () => {
      await page.goto('/cmdline');
    });
    await expect(page).toHaveURL(/\/cmdline$/);
    await expect(page.locator('input#credential')).toBeVisible();
    await expect(page.locator('input#credential')).toHaveValue(testUser.userCred);

    await toggleCredentials(page);
    const tableBody = page.locator('table.credtable tbody');
    await expect(tableBody.locator('tr')).toHaveCount(1);

    const authenticator2 = authFixture.memAuthenticator(mode);
    await authFixture.addPasskey(testUser.userId, authenticator2, async () => {
      await page.getByRole('button', { name: /New Passkey/ }).click();
    });
    await expect(tableBody.locator('tr')).toHaveCount(2);

    // Delete passkeys until the user is gone; the last delete needs username
    // confirmation and redirects to /welcome once the server removes the user.
    await deleteLastPasskey(page);
    await expect(tableBody.locator('tr')).toHaveCount(1);
    await deleteLastPasskey(page, testUser.userName);
    await expect(page).toHaveURL(/\/welcome$/);
    authFixture.untrackUser(testUser.userId);
  });

  testWithAuth(`${label}: delete active passkey signs out`, async ({ authFixture }) => {
    const { page } = authFixture;
    test.setTimeout(60000);

    const authenticator1 = authFixture.memAuthenticator(mode);
    const testUser = await authFixture.createTestUser(authenticator1);

    await toggleCredentials(page);
    const tableBody = page.locator('table.credtable tbody');
    await expect(tableBody.locator('tr')).toHaveCount(1);

    const authenticator2 = authFixture.memAuthenticator(mode);
    await authFixture.addPasskey(testUser.userId, authenticator2, async () => {
      await page.getByRole('button', { name: /New Passkey/ }).click();
    });
    await expect(tableBody.locator('tr')).toHaveCount(2);

    // Deleting the active passkey (the one that signed in) invalidates the session,
    // so the client drops to the Sign In dialog.
    await deleteFirstPasskey(page);
    await expect(page.getByRole('heading', { name: /Quick Crypt Sign In/ })).toBeVisible({ timeout: 10000 });

    await authFixture.passkeyAuth(authenticator2, async () => {
      await page.getByRole('button', { name: new RegExp(`Sign in as ${testUser.userName}`) }).click();
    });
    await expect(page).toHaveURL(/\/$/);
    await expect(page.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({ timeout: 10000 });

    await toggleCredentials(page);
    await expect(tableBody.locator('tr')).toHaveCount(1);

    // Deleting a non-active passkey leaves the active one (authenticator2) in place,
    // so the session stays valid and no Sign In dialog appears.
    await authFixture.addPasskey(testUser.userId, authenticator1, async () => {
      await page.getByRole('button', { name: /New Passkey/ }).click();
    });
    await expect(tableBody.locator('tr')).toHaveCount(2);

    await deleteLastPasskey(page);
    await expect(tableBody.locator('tr')).toHaveCount(1);
    await expect(page.getByRole('heading', { name: /Quick Crypt Sign In/ })).not.toBeVisible();

    await page.reload();
    await expect(page).toHaveURL(/\/$/);
    await expect(page.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({ timeout: 10000 });
    await expect(page.getByRole('heading', { name: /Quick Crypt Sign In/ })).not.toBeVisible();

    await toggleCredentials(page);
    await expect(tableBody.locator('tr')).toHaveCount(1);

    await deleteFirstPasskey(page, testUser.userName);
    await expect(page).toHaveURL(/\/welcome$/);
    await expect(page.getByText('Easy, Trustworthy Personal Encryption')).toBeVisible({ timeout: 10000 });
    authFixture.untrackUser(testUser.userId);
  });

  testWithAuth(`${label}: regenerate recovery words`, async ({ authFixture }) => {
    const { page } = authFixture;
    test.setTimeout(60000);

    const authenticator1 = authFixture.memAuthenticator(mode);
    const testUser = await authFixture.createTestUser(authenticator1);

    await toggleCredentials(page);
    const tableBody = page.locator('table.credtable tbody');
    await expect(tableBody.locator('tr')).toHaveCount(1);

    await page.getByRole('button', { name: /Replace recovery words/ }).click();
    await expect(page).toHaveURL(/\/regenrecovery$/);

    await authFixture.passkeyAuth(authenticator1, async () => {
      await page.getByRole('button', { name: /Generate new recovery words/ }).click();
    });

    await expect(page).toHaveURL(/\/showrecovery$/, { timeout: 10000 });
    await expect(page.getByRole('button', { name: /I saved my recovery words securely/ })).toBeVisible({ timeout: 10000 });

    const newWords = await page.locator('textarea#wordsArea').inputValue();
    expect(newWords.length).toBeGreaterThan(0);
    expect(newWords).not.toBe(testUser.recoveryWords);
    await expect(page.locator('mat-card-content')).toContainText('Replace all saved copies', { timeout: 10000 });

    await page.getByRole('button', { name: /I saved my recovery words securely/ }).click();
    await expect(page).toHaveURL(/\/$/);

    // The replaced words can no longer recover the account.
    await page.goto('/recovery2');
    await expect(page).toHaveURL(/\/recovery2$/);
    await page.locator('textarea#wordsArea').fill(testUser.recoveryWords);
    await page.getByRole('button', { name: /Start Recovery/ }).click();
    await expect(page.locator('.control-host .error-msg')).toContainText('recovery word pattern', { timeout: 15000 });
    await expect(page).toHaveURL(/\/recovery2$/);

    // The new words do. Recovery wipes the old passkey and creates a new one on a
    // second authenticator.
    await page.locator('textarea#wordsArea').fill(newWords);
    const authenticator2 = authFixture.memAuthenticator(mode);
    await authFixture.addPasskey(testUser.userId, authenticator2, async () => {
      await page.getByRole('button', { name: /Start Recovery/ }).click();
    });
    await expect(page).toHaveURL(/\/$/);
    await expect(page.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({ timeout: 10000 });

    await toggleCredentials(page);
    await expect(tableBody.locator('tr')).toHaveCount(1);
    await deleteFirstPasskey(page, testUser.userName);
    await expect(page).toHaveURL(/\/welcome$/);
    authFixture.untrackUser(testUser.userId);
  });

  testWithAuth(`${label}: 3 tabs logout and forget`, async ({ authFixture }) => {
    const { page } = authFixture;
    test.setTimeout(75000);

    const page1 = page;
    const authenticator1 = authFixture.memAuthenticator(mode);
    const testUser = await authFixture.createTestUser(authenticator1);

    const page2 = await page1.context().newPage();
    await page2.goto('/');
    await expect(page2).toHaveURL(/\/$/);
    await expect(page2.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({ timeout: 10000 });

    // Logging out the 2nd tab logs out the 1st, which drops to the Sign In dialog.
    await toggleCredentials(page2);
    const tableBody2 = page2.locator('table.credtable tbody');
    await expect(tableBody2.locator('tr')).toHaveCount(1);
    await expect(page2.locator('mat-sidenav input').first()).toHaveValue(testUser.userName);

    await page2.getByRole('button', { name: /Sign out/ }).click();
    await expect(page2.getByRole('heading', { name: /Quick Crypt Sign In/ })).toBeVisible({ timeout: 10000 });

    await page1.goto('/');
    await expect(page1).toHaveURL(/\/$/);
    await expect(page1.getByRole('heading', { name: /Quick Crypt Sign In/ })).toBeVisible({ timeout: 10000 });

    // A newly opened tab shows the Sign In dialog, not the welcome page.
    const page3 = await page1.context().newPage();
    await page3.goto('/');
    await expect(page3).toHaveURL(/\/$/);
    await expect(page3.getByRole('heading', { name: /Quick Crypt Sign In/ })).toBeVisible({ timeout: 10000 });

    // Forgetting the user sends every tab back to the welcome page.
    await page2.getByRole('button', { name: /Sign in as a different user/ }).click();
    await expect(page2).toHaveURL(/\/welcome$/);
    await expect(page2.getByText('Easy, Trustworthy Personal Encryption')).toBeVisible({ timeout: 10000 });

    await page1.goto('/');
    await expect(page1).toHaveURL(/\/welcome$/);
    await expect(page1.getByText('Easy, Trustworthy Personal Encryption')).toBeVisible({ timeout: 10000 });

    await page3.goto('/');
    await expect(page3).toHaveURL(/\/welcome$/);
    await expect(page3.getByText('Easy, Trustworthy Personal Encryption')).toBeVisible({ timeout: 10000 });
  });

  testWithAuth(`${label}: 3 tabs switch user`, async ({ authFixture }) => {
    const { page } = authFixture;
    test.setTimeout(120000);

    const page1 = page;
    const authenticatorA = authFixture.memAuthenticator(mode);
    const testUserA = await authFixture.createTestUser(authenticatorA);

    const page2 = await page1.context().newPage();
    await page2.goto('/');
    await expect(page2).toHaveURL(/\/$/);
    await expect(page2.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({ timeout: 10000 });
    await toggleCredentials(page2);
    await expect(page2.locator('mat-sidenav input').first()).toHaveValue(testUserA.userName);

    // Sign the 1st tab out and forget, then create a different user on a second
    // authenticator.
    await toggleCredentials(page1);
    const tableBody1 = page1.locator('table.credtable tbody');
    await expect(tableBody1.locator('tr')).toHaveCount(1);
    await expect(page1.locator('mat-sidenav input').first()).toHaveValue(testUserA.userName);

    await page1.getByRole('button', { name: /Sign out/ }).click();
    await page1.getByRole('button', { name: /Sign in as a different user/ }).click();
    await expect(page1).toHaveURL(/\/welcome$/);
    await expect(page1.getByText('Easy, Trustworthy Personal Encryption')).toBeVisible({ timeout: 10000 });

    const authenticatorB = authFixture.memAuthenticator(mode);
    const testUserB = await authFixture.createTestUser(authenticatorB);

    await toggleCredentials(page1);
    await expect(page1.locator('mat-sidenav input').first()).toHaveValue(testUserB.userName);

    // page2's user context is now testUserB, so it goes to welcome.
    await page2.goto('/');
    await expect(page2).toHaveURL(/\/welcome$/);
    await expect(page2.getByText('Easy, Trustworthy Personal Encryption')).toBeVisible({ timeout: 10000 });

    // page3 opens to the core page because it had no previous user context.
    const page3 = await page1.context().newPage();
    await page3.goto('/');
    await expect(page3).toHaveURL(/\/$/);
    await expect(page3.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({ timeout: 10000 });
    await toggleCredentials(page3);
    const tableBody3 = page3.locator('table.credtable tbody');
    await expect(tableBody3.locator('tr')).toHaveCount(1);
    await expect(page3.locator('mat-sidenav input').first()).toHaveValue(testUserB.userName);
    await page3.getByRole('button', { name: /Sign out/ }).click();
    await expect(page3.getByRole('heading', { name: /Quick Crypt Sign In/ })).toBeVisible({ timeout: 10000 });

    // page2 still goes to welcome since its user was logged out.
    await page2.goto('/');
    await expect(page2).toHaveURL(/\/welcome$/);
    await expect(page2.getByText('Easy, Trustworthy Personal Encryption')).toBeVisible({ timeout: 10000 });

    // page1 goes to the sign in dialog.
    await page1.goto('/');
    await expect(page1).toHaveURL(/\/$/);
    await expect(page1.getByRole('heading', { name: /Quick Crypt Sign In/ })).toBeVisible({ timeout: 10000 });

    // Sign back in as testUserA on its own authenticator.
    await page1.getByRole('button', { name: /Sign in as a different user/ }).click();
    await expect(page1).toHaveURL(/\/welcome$/);
    await expect(page1.getByText('Easy, Trustworthy Personal Encryption')).toBeVisible({ timeout: 10000 });

    await authFixture.passkeyAuth(authenticatorA, async () => {
      await page1.getByRole('button', { name: 'I have used Quick Crypt' }).click();
    });
    await expect(page1).toHaveURL(/\/$/);
    await expect(page1.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({ timeout: 10000 });
    await toggleCredentials(page1);
    await expect(page1.locator('mat-sidenav input').first()).toHaveValue(testUserA.userName);

    // page2 now goes to the core page since its original user is logged in again.
    await page2.goto('/');
    await expect(page2).toHaveURL(/\/$/);
    await expect(page2.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({ timeout: 10000 });
    await toggleCredentials(page2);
    await expect(page2.locator('mat-sidenav input').first()).toHaveValue(testUserA.userName);

    // page3 goes to welcome since its user was logged out.
    await page3.goto('/');
    await expect(page3).toHaveURL(/\/welcome$/);
    await expect(page3.getByText('Easy, Trustworthy Personal Encryption')).toBeVisible({ timeout: 10000 });
  });

  if (prf) {
    testWithAuth(`${label}: adding a non-PRF passkey is rejected (no downgrade)`, async ({ authFixture }) => {
      const { page } = authFixture;
      test.setTimeout(45000);

      const prfAuthenticator = authFixture.memAuthenticator('hmac-secret-mc');
      await authFixture.createTestUser(prfAuthenticator);
      await toggleCredentials(page);
      const tableBody = page.locator('table.credtable tbody');
      await expect(tableBody.locator('tr')).toHaveCount(1);

      // A PRF account must refuse a no-PRF passkey rather than silently downgrade.
      const noPrfAuthenticator = authFixture.memAuthenticator('none');
      await authFixture.expectPasskeyRejected(noPrfAuthenticator, async () => {
        await page.getByRole('button', { name: /New Passkey/ }).click();
      });
      await expect(page.getByText(/requires passkeys that support/)).toBeVisible({ timeout: 10000 });
      await expect(tableBody.locator('tr')).toHaveCount(1);
      // The passkey was created locally (create at account + this attempt) then
      // rejected client-side, so no second passkey reaches the server.
      expect(authFixture.credentialCreateCount()).toBe(2);
    });
  } else {
    testWithAuth(`${label}: adding a PRF-capable passkey stays non-PRF`, async ({ authFixture }) => {
      const { page } = authFixture;
      test.setTimeout(45000);

      const noPrfAuthenticator = authFixture.memAuthenticator('none');
      const testUser = await authFixture.createTestUser(noPrfAuthenticator);
      await toggleCredentials(page);
      const tableBody = page.locator('table.credtable tbody');
      await expect(tableBody.locator('tr')).toHaveCount(1);

      // A no-PRF account never requests PRF, so even a PRF-capable authenticator
      // just adds a standard passkey and the account stays no-PRF.
      const prfAuthenticator = authFixture.memAuthenticator('hmac-secret-mc');
      await authFixture.addPasskey(testUser.userId, prfAuthenticator, async () => {
        await page.getByRole('button', { name: /New Passkey/ }).click();
      });
      await expect(tableBody.locator('tr')).toHaveCount(2);
      await expectPrfBadge(page);
    });
  }
}
