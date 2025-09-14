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
import { bufferToHexString } from '../../src/app/services/utils';

// Currently not direclty testing API that does authentication and registion of
// users because haven't gotten SimpleWebAuthn to work in playwright.

test.describe('api', () => {

  testWithAuth('create and remove user', { tag: '@nukeall' }, async ({ authFixture }, testInfo) => {
    const { page, session, authId } = authFixture;

    await page.goto('/');

    await passkeyCreation(session, authId, async () => {
      await page.getByRole('button', { name: 'I am new to Quick Crypt' }).click();
      await expect(page.getByRole('heading', { name: 'Create A New user' })).toBeVisible({ timeout: 10000 });
      await page.locator('input#userName').fill('PWFlippy');
      await page.getByRole('button', { name: /Create new/ }).click();
    });

    await page.waitForURL('/showrecovery', { waitUntil: 'domcontentloaded' });
    await expect(page.getByRole('heading', { name: 'Account Backup and Recovery' })).toBeVisible({ timeout: 10000 });

    const storageState = await page.context().storageState();
    const loclStorage = storageState.origins[0].localStorage;
    const userId = loclStorage.find(item => item.name === 'userid')?.value;
    expect(userId).toBeTruthy();

    //@ts-ignore
    const apiUrl = testInfo.project.use.apiURL;

    const authsResponse = await page.request.get(
      `${apiUrl}/user/${userId}/authenticators`
    );
    expect(authsResponse).toBeOK();

    const auths = await authsResponse.json();
    expect(auths.length).toBe(1);

    const delResponse = await page.request.delete(
      //@ts-ignore
      `${apiUrl}/user/${userId}/authenticator/${auths[0].credentialId}`
    );
    expect(delResponse).toBeOK();

    const infoResponse = await page.request.get(
      //@ts-ignore
      `${apiUrl}/user/${userId}/userinfo`
    );

    expect(infoResponse.status()).toBe(401);
    // user should be gone at this point, but cruft remains in the browser since we
    // called APIs direclty. Clean up userid so nukeall handler doesn't try
    await page.evaluate(() => {
      window.localStorage.removeItem('userid');
    });

  });

  testWithAuth('verify session', { tag: '@nukeall' }, async ({ authFixture }, testInfo) => {
    const { page, session, authId } = authFixture;

    await page.goto('/');

    await passkeyCreation(session, authId, async () => {
      await page.getByRole('button', { name: 'I am new to Quick Crypt' }).click();
      await expect(page.getByRole('heading', { name: 'Create A New user' })).toBeVisible({ timeout: 10000 });
      await page.locator('input#userName').fill('PWFlippy');
      await page.getByRole('button', { name: /Create new/ }).click();
    });

    await page.waitForURL('/showrecovery', { waitUntil: 'domcontentloaded' });
    await expect(page.getByRole('heading', { name: 'Account Backup and Recovery' })).toBeVisible({ timeout: 10000 });

    const storageState = await page.context().storageState();
    const loclStorage = storageState.origins[0].localStorage;
    const userId = loclStorage.find(item => item.name === 'userid')?.value;
    expect(userId).toBeTruthy();

    //@ts-ignore
    const apiUrl = testInfo.project.use.apiURL;

    const headers: Record<string, string> = {
        'Content-Type': 'application/json',
    };

    const bodyData = new TextEncoder().encode('');
    const hash = await crypto.subtle.digest("SHA-256", bodyData);
    headers['x-amz-content-sha256'] = bufferToHexString(hash);

    const verifyResponse = await page.request.post(
      `${apiUrl}/user/${userId}/verifysess`,
      { headers: headers}
    );
    expect(verifyResponse).toBeOK();

    const userInfo = await verifyResponse.json();
    expect(userInfo.verified).toBeTruthy();
    expect(userInfo.userName).toBe('PWFlippy');
    expect(userInfo.userId).toBe(userId);
    expect(userInfo.hasRecoveryId).toBeTruthy()
    expect(userInfo.authenticators.length).toBe(1);

    const delResponse = await page.request.delete(
      //@ts-ignore
      `${apiUrl}/user/${userId}/authenticator/${userInfo.authenticators[0].credentialId}`
    );
    expect(delResponse).toBeOK();

    const infoResponse = await page.request.get(
      //@ts-ignore
      `${apiUrl}/user/${userId}/userinfo`
    );

    expect(infoResponse.status()).toBe(401);
    // user should be gone at this point, but cruft remains in the browser since we
    // called APIs direclty. Clean up userid so nukeall handler doesn't try
    await page.evaluate(() => {
      window.localStorage.removeItem('userid');
    });

  });


  testWithAuth('end session', { tag: '@nukeall' }, async ({ authFixture }, testInfo) => {
    const { page, session, authId } = authFixture;

    await page.goto('/');

    await passkeyCreation(session, authId, async () => {
      await page.getByRole('button', { name: 'I am new to Quick Crypt' }).click();
      await expect(page.getByRole('heading', { name: 'Create A New user' })).toBeVisible({ timeout: 10000 });
      await page.locator('input#userName').fill('PWFlippy');
      await page.getByRole('button', { name: /Create new/ }).click();
    });

    await page.waitForURL('/showrecovery', { waitUntil: 'domcontentloaded' });
    await expect(page.getByRole('heading', { name: 'Account Backup and Recovery' })).toBeVisible({ timeout: 10000 });

    const storageState = await page.context().storageState();
    const loclStorage = storageState.origins[0].localStorage;
    const userId = loclStorage.find(item => item.name === 'userid')?.value;
    expect(userId).toBeTruthy();

    //@ts-ignore
    const apiUrl = testInfo.project.use.apiURL;

    const headers: Record<string, string> = {
        'Content-Type': 'application/json',
    };

    const bodyData = new TextEncoder().encode('');
    const hash = await crypto.subtle.digest("SHA-256", bodyData);
    headers['x-amz-content-sha256'] = bufferToHexString(hash);

    const endResponse = await page.request.post(
      `${apiUrl}/user/${userId}/endsess`,
      { headers: headers}
    );
    expect(endResponse).toBeOK();

    let infoResponse = await page.request.get(
      //@ts-ignore
      `${apiUrl}/user/${userId}/userinfo`
    );

    expect(infoResponse.status()).toBe(401);

    await page.goto('/');

    await passkeyAuth(session, authId, async () => {
      await page.getByRole('button', { name: /Sign in as PWFlippy/ }).click();
    });
    await page.waitForURL('/', { waitUntil: 'domcontentloaded' });
    await expect(page.getByRole('button', { name: 'Sign in as PWFlippy' })).not.toBeVisible({timeout:10000});

    infoResponse = await page.request.get(
      //@ts-ignore
      `${apiUrl}/user/${userId}/userinfo`
    );
    expect(infoResponse).toBeOK();
    const userInfo = await infoResponse.json();
    expect(userInfo.verified).toBeTruthy();
    expect(userInfo.userName).toBe('PWFlippy');
    expect(userInfo.userId).toBe(userId);
    expect(userInfo.hasRecoveryId).toBeTruthy()
    expect(userInfo.authenticators.length).toBe(1);

    const delResponse = await page.request.delete(
      //@ts-ignore
      `${apiUrl}/user/${userId}/authenticator/${userInfo.authenticators[0].credentialId}`
    );
    expect(delResponse).toBeOK();

    infoResponse = await page.request.get(
      //@ts-ignore
      `${apiUrl}/user/${userId}/userinfo`
    );

    expect(infoResponse.status()).toBe(401);
    // user should be gone at this point, but cruft remains in the browser since we
    // called APIs direclty. Clean up userid so nukeall handler doesn't try
    await page.evaluate(() => {
      window.localStorage.removeItem('userid');
    });
  });

});