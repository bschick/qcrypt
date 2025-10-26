import { test, expect, Page, CDPSession, TestInfo } from '@playwright/test';
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
import { ServerLoginUserInfo } from '../../src/app/services/authenticator.service';

// Currently not direclty testing API that does authentication and registion of
// users because haven't gotten SimpleWebAuthn to work in playwright.

test.describe('api', () => {

   testWithAuth('create, edit, remove passkey', { tag: '@nukeall' }, async ({ authFixture }, testInfo) => {
      const { page, session, authId1, authId2 } = authFixture;

      const [apiUrl, apiUser, headers] = await apiSetup(testInfo, page, session, authId1);

      // Success case
      let usersResponse = await page.request.get(
         `${apiUrl}/users/${apiUser.userId}`,
         { headers: headers }
      );
      expect(usersResponse).toBeOK();

      const user = await usersResponse.json();
      expect(user.userName).toBe('PWFlippy');
      expect(user.authenticators.length).toBe(1);

      // Failure case, invalid userid
      usersResponse = await page.request.get(
         `${apiUrl}/users/42ebNajPIp3leX4K4a0qND`,
         { headers: headers }
      );
      expect(usersResponse.status()).toBe(401);


      // Should fail, invalid credid
      let delResponse = await page.request.delete(
         //@ts-ignore
         `${apiUrl}/users/${apiUser.userId}/passkeys/nfVho8Z8p3oEpOl8yvbh40`,
         { headers: headers }
      );
      expect(delResponse.status()).toBe(400);

      // Should fail, invalid userId with valid credential
      delResponse = await page.request.delete(
         //@ts-ignore
         `${apiUrl}/users/42ebNajPIp3leX4K4a0qND/passkeys/${user.authenticators[0].credentialId}`,
         { headers: headers }
      );
      expect(delResponse.status()).toBe(401);

      // Should fail, invalid userId and credential
      delResponse = await page.request.delete(
         //@ts-ignore
         `${apiUrl}/users/42ebNajPIp3leX4K4a0qND/passkeys/nfVho8Z8p3oEpOl8yvbh40`,
         { headers: headers }
      );
      expect(delResponse.status()).toBe(401);


      // Valid passkey delete
      delResponse = await page.request.delete(
         //@ts-ignore
         `${apiUrl}/users/${apiUser.userId}/passkeys/${user.authenticators[0].credentialId}`,
         { headers: headers }
      );
      expect(delResponse).toBeOK();

      // should confirm this fails when another PK still exists (error should be 400 in that case)
      delResponse = await page.request.delete(
         //@ts-ignore
         `${apiUrl}/users/${apiUser.userId}/passkeys/${user.authenticators[0].credentialId}`,
         { headers: headers }
      );
      expect(delResponse.status()).toBe(401);


      // User should be gone, so this should fail
      const infoResponse = await page.request.get(
         //@ts-ignore
         `${apiUrl}/users/${apiUser.userId}`,
         { headers: headers }
      );
      expect(infoResponse.status()).toBe(401);

      // user should be gone at this point, but cruft remains in the browser since we
      // called APIs direclty. Clean up userid so nukeall handler doesn't try
      await page.evaluate(() => {
         window.localStorage.removeItem('userid');
      });

   });

   testWithAuth('edit passkey description', { tag: '@nukeall' }, async ({ authFixture }, testInfo) => {
      const { page, session, authId1, authId2 } = authFixture;

      let [apiUrl, apiUser, headers] = await apiSetup(testInfo, page, session, authId1);

      // Test good patch of description
      const body1 = {
         description: "5673455"
      }

      let bodyData = new TextEncoder().encode(JSON.stringify(body1));
      let hash = await crypto.subtle.digest("SHA-256", bodyData);
      headers['x-amz-content-sha256'] = bufferToHexString(hash);

      let descResponse = await page.request.patch(
         //@ts-ignore
         `${apiUrl}/users/${apiUser.userId}/passkeys/${apiUser.authenticators[0].credentialId}`,
         { headers: headers, data: body1 }
      );
      expect(descResponse.status()).toBe(200);
      let user = await descResponse.json();
      expect(user.authenticators[0].description).toBe(body1.description);

      // Stripping of all html stuff
      const body2 = {
         description: "567345 <b>5 > <a a"
      }

      bodyData = new TextEncoder().encode(JSON.stringify(body2));
      hash = await crypto.subtle.digest("SHA-256", bodyData);
      headers['x-amz-content-sha256'] = bufferToHexString(hash);

      descResponse = await page.request.patch(
         //@ts-ignore
         `${apiUrl}/users/${apiUser.userId}/passkeys/${user.authenticators[0].credentialId}`,
         { headers: headers, data: body2 }
      );
      expect(descResponse.status()).toBe(200);
      user = await descResponse.json();
      expect(user.authenticators[0].description).toBe("567345 5");


      // invalid user id
      descResponse = await page.request.patch(
         //@ts-ignore
         `${apiUrl}/users/42ebNajPIp3leX4K4a0qND/passkeys/${user.authenticators[0].credentialId}`,
         { headers: headers, data: body2 }
      );
      expect(descResponse.status()).toBe(401);

      // invalid cred id
      descResponse = await page.request.patch(
         //@ts-ignore
         `${apiUrl}/users/${apiUser.userId}/passkeys/nfVho8Z8p3oEpOl8yvbh40`,
         { headers: headers, data: body2 }
      );
      expect(descResponse.status()).toBe(400);

      // invalid cred id and userid
      descResponse = await page.request.patch(
         //@ts-ignore
         `${apiUrl}/users/42ebNajPIp3leX4K4a0qND/passkeys/nfVho8Z8p3oEpOl8yvbh40`,
         { headers: headers, data: body2 }
      );
      expect(descResponse.status()).toBe(401);


      // Should fail, because description is not a string
      const body3 = {
         description: 5673455
      }

      bodyData = new TextEncoder().encode(JSON.stringify(body3));
      hash = await crypto.subtle.digest("SHA-256", bodyData);
      headers['x-amz-content-sha256'] = bufferToHexString(hash);

      descResponse = await page.request.patch(
         //@ts-ignore
         `${apiUrl}/users/${apiUser.userId}/passkeys/${user.authenticators[0].credentialId}`,
         { headers: headers, data: body3 }
      );
      expect(descResponse.status()).toBe(400);

      // make sure we are still good...
      const body4 = {
         description: "something"
      }

      bodyData = new TextEncoder().encode(JSON.stringify(body4));
      hash = await crypto.subtle.digest("SHA-256", bodyData);
      headers['x-amz-content-sha256'] = bufferToHexString(hash);

      // should fail due to session being deleted
      descResponse = await page.request.patch(
         //@ts-ignore
         `${apiUrl}/users/${apiUser.userId}/passkeys/${user.authenticators[0].credentialId}`,
         { headers: headers, data: body4 }
      );
      expect(descResponse.status()).toBe(200);
      user = await descResponse.json();
      expect(user.authenticators[0].description).toBe(body4.description);


      // Delete session and confirm further edits don't work
      const endResponse = await page.request.delete(
         `${apiUrl}/users/${apiUser.userId}/session`,
         { headers: headers }
      );
      expect(endResponse).toBeOK();

      descResponse = await page.request.patch(
         //@ts-ignore
         `${apiUrl}/users/${apiUser.userId}/passkeys/${user.authenticators[0].credentialId}`,
         { headers: headers, data: body4 }
      );
      expect(descResponse.status()).toBe(401);

      // sign back to get new session
      [apiUser, headers] = await reSetup(testInfo, page, session, authId1);

      // Valid passkey delete
      let delResponse = await page.request.delete(
         //@ts-ignore
         `${apiUrl}/users/${apiUser.userId}/passkeys/${user.authenticators[0].credentialId}`,
         { headers: headers }
      );
      expect(delResponse).toBeOK();

      // User should now be gone, so this should fail
      const infoResponse = await page.request.get(
         //@ts-ignore
         `${apiUrl}/users/${apiUser.userId}`,
         { headers: headers }
      );
      expect(infoResponse.status()).toBe(401);

      // user should be gone at this point, but cruft remains in the browser since we
      // called APIs direclty. Clean up userid so nukeall handler doesn't try
      await page.evaluate(() => {
         window.localStorage.removeItem('userid');
      });

   });


   testWithAuth('edit user name', { tag: '@nukeall' }, async ({ authFixture }, testInfo) => {
      const { page, session, authId1, authId2 } = authFixture;

      let [apiUrl, apiUser, headers] = await apiSetup(testInfo, page, session, authId1);

      // Success case
      let usersResponse = await page.request.get(
         `${apiUrl}/users/${apiUser.userId}`,
         { headers: headers }
      );
      expect(usersResponse).toBeOK();

      let user = await usersResponse.json();
      expect(user.userName).toBe('PWFlippy');
      expect(user.authenticators.length).toBe(1);


      // Test good patch of description
      const body1 = {
         userName: "yppilFWP"
      }

      let bodyData = new TextEncoder().encode(JSON.stringify(body1));
      let hash = await crypto.subtle.digest("SHA-256", bodyData);
      headers['x-amz-content-sha256'] = bufferToHexString(hash);

      let patchResponse = await page.request.patch(
         //@ts-ignore
         `${apiUrl}/users/${apiUser.userId}`,
         { headers: headers, data: body1 }
      );

      expect(patchResponse.status()).toBe(200);
      user = await patchResponse.json();
      expect(user.userName).toBe(body1.userName);
      expect(user.authenticators.length).toBe(1);


      // Test removal of <script> element
      const body2 = {
         userName: "<script>all</script> good"
      }

      bodyData = new TextEncoder().encode(JSON.stringify(body2));
      hash = await crypto.subtle.digest("SHA-256", bodyData);
      headers['x-amz-content-sha256'] = bufferToHexString(hash);

      patchResponse = await page.request.patch(
         //@ts-ignore
         `${apiUrl}/users/${apiUser.userId}`,
         { headers: headers, data: body2 }
      );
      expect(patchResponse.status()).toBe(200);
      user = await patchResponse.json();
      expect(user.userName).toBe("all good");

      // String too long, should fail
      const body3 = {
         userName: "as0df9ufwefowifljop20w934fsldfklsdjflasdfkasoifjw0f9jw9f"
      }

      bodyData = new TextEncoder().encode(JSON.stringify(body3));
      hash = await crypto.subtle.digest("SHA-256", bodyData);
      headers['x-amz-content-sha256'] = bufferToHexString(hash);

      patchResponse = await page.request.patch(
         //@ts-ignore
         `${apiUrl}/users/${apiUser.userId}`,
         { headers: headers, data: body3 }
      );
      expect(patchResponse.status()).toBe(400);


      // confirm still at previous value
      usersResponse = await page.request.get(
         `${apiUrl}/users/${apiUser.userId}`,
         { headers: headers }
      );
      expect(usersResponse).toBeOK();

      user = await usersResponse.json();
      expect(user.userName).toBe('all good');
      expect(user.authenticators.length).toBe(1);

      bodyData = new TextEncoder().encode('');
      hash = await crypto.subtle.digest("SHA-256", bodyData);
      headers['x-amz-content-sha256'] = bufferToHexString(hash);

      // Delete session and confirm further edits don't work
      const endResponse = await page.request.delete(
         `${apiUrl}/users/${apiUser.userId}/session`,
         { headers: headers }
      );
      expect(endResponse).toBeOK();

      // User account will be leaked server-side if there is an abort
      // between this comment and passkeyAuth success

      const body4 = {
         userName: "PWFlippy"
      }

      bodyData = new TextEncoder().encode(JSON.stringify(body4));
      hash = await crypto.subtle.digest("SHA-256", bodyData);
      headers['x-amz-content-sha256'] = bufferToHexString(hash);

      // should fail due to session being deleted
      patchResponse = await page.request.patch(
         //@ts-ignore
         `${apiUrl}/users/${apiUser.userId}`,
         { headers: headers, data: body4 }
      );
      expect(patchResponse.status()).toBe(401);

      // sign back to get new session
      [apiUser, headers] = await reSetup(testInfo, page, session, authId1);

      const delResponse = await page.request.delete(
         //@ts-ignore
         `${apiUrl}/users/${apiUser.userId}/passkeys/${apiUser.authenticators[0].credentialId}`,
         { headers: headers }
      );
      expect(delResponse).toBeOK();

      usersResponse = await page.request.get(
         //@ts-ignore
         `${apiUrl}/users/${apiUser.userId}`,
         { headers: headers }
      );
      expect(usersResponse.status()).toBe(401);

      // user should be gone at this point, but cruft remains in the browser since we
      // called APIs direclty. Clean up userid so nukeall handler doesn't try
      await page.evaluate(() => {
         window.localStorage.removeItem('userid');
      });

   });

   testWithAuth('get session', { tag: '@nukeall' }, async ({ authFixture }, testInfo) => {
      const { page, session, authId1, authId2 } = authFixture;

      let [apiUrl, apiUser, headers] = await apiSetup(testInfo, page, session, authId1);

      let sessionResponse = await page.request.get(
         `${apiUrl}/users/${apiUser.userId}/session`,
         { headers: headers }
      );
      expect(sessionResponse).toBeOK();

      let user = await sessionResponse.json();
      expect(user.verified).toBeTruthy();
      expect(user.userName).toBe('PWFlippy');
      expect(user.userId).toBe(apiUser.userId);
      expect(user.hasRecoveryId).toBeTruthy()
      expect(user.authenticators.length).toBe(1);

      sessionResponse = await page.request.get(
         `${apiUrl}/users/42ebNajPIp3leX4K4a0qND/session`,
         { headers: headers }
      );
      expect(sessionResponse.status()).toBe(401);


      const delResponse = await page.request.delete(
         //@ts-ignore
         `${apiUrl}/users/${apiUser.userId}/passkeys/${user.authenticators[0].credentialId}`,
         { headers: headers }
      );
      expect(delResponse).toBeOK();


      sessionResponse = await page.request.get(
         `${apiUrl}/users/${apiUser.userId}/session`,
         { headers: headers }
      );
      expect(sessionResponse.status()).toBe(401);

      // user should be gone at this point, but cruft remains in the browser since we
      // called APIs direclty. Clean up userid so nukeall handler doesn't try
      await page.evaluate(() => {
         window.localStorage.removeItem('userid');
      });

   });


   testWithAuth('delete session', { tag: '@nukeall' }, async ({ authFixture }, testInfo) => {
      const { page, session, authId1, authId2 } = authFixture;

      let [apiUrl, apiUser, headers] = await apiSetup(testInfo, page, session, authId1);

      let sessionResponse = await page.request.get(
         `${apiUrl}/users/${apiUser.userId}/session`,
         { headers: headers }
      );
      expect(sessionResponse).toBeOK();

      const bodyData = new TextEncoder().encode('');
      const hash = await crypto.subtle.digest("SHA-256", bodyData);
      headers['x-amz-content-sha256'] = bufferToHexString(hash);

      // delete with valid session cookie, but invalid userId should fail
      let endResponse = await page.request.delete(
         `${apiUrl}/users/42ebNajPIp3leX4K4a0qND/session`,
         { headers: headers }
      );
      expect(endResponse.status()).toBe(401);


      endResponse = await page.request.delete(
         `${apiUrl}/users/${apiUser.userId}/session`,
         { headers: headers }
      );
      expect(endResponse).toBeOK();

      // User account will be leaked server-side if there is an abort
      // between this comment and passkeyAuth success

      endResponse = await page.request.delete(
         `${apiUrl}/users/${apiUser.userId}/session`,
         { headers: headers }
      );
      expect(endResponse.status()).toBe(401);

      sessionResponse = await page.request.get(
         `${apiUrl}/users/${apiUser.userId}/session`,
         { headers: headers }
      );
      expect(sessionResponse.status()).toBe(401);

      let infoResponse = await page.request.get(
         //@ts-ignore
         `${apiUrl}/users/${apiUser.userId}`,
         { headers: headers }
      );
      expect(infoResponse.status()).toBe(401);


      // sign back to get new session
      [apiUser, headers] = await reSetup(testInfo, page, session, authId1);

      infoResponse = await page.request.get(
         //@ts-ignore
         `${apiUrl}/users/${apiUser.userId}`,
         { headers: headers }
      );
      expect(infoResponse).toBeOK();
      let user = await infoResponse.json();
      expect(user.verified).toBeTruthy();
      expect(user.userName).toBe('PWFlippy');
      expect(user.userId).toBe(apiUser.userId);
      expect(user.hasRecoveryId).toBeTruthy()
      expect(user.authenticators.length).toBe(1);

      const delResponse = await page.request.delete(
         //@ts-ignore
         `${apiUrl}/users/${apiUser.userId}/passkeys/${user.authenticators[0].credentialId}`,
         { headers: headers }
      );
      expect(delResponse).toBeOK();

      infoResponse = await page.request.get(
         //@ts-ignore
         `${apiUrl}/users/${apiUser.userId}`,
         { headers: headers }
      );
      expect(infoResponse.status()).toBe(401);

      // user should be gone at this point, but cruft remains in the browser since we
      // called APIs direclty. Clean up userid so nukeall handler doesn't try
      await page.evaluate(() => {
         window.localStorage.removeItem('userid');
      });
   });

   testWithAuth('authorized invalid', { tag: '@nukeall' }, async ({ authFixture }, testInfo) => {
      const { page, session, authId1, authId2 } = authFixture;

      let [apiUrl, apiUser, headers] = await apiSetup(testInfo, page, session, authId1);

      await runInvalids(page, apiUrl, apiUser.userId!, headers);

      // user should be gone at this point, but cruft remains in the browser since we
      // called APIs direclty. Clean up userid so nukeall handler doesn't try
      await page.evaluate(() => {
         window.localStorage.removeItem('userid');
      });

   });

   testWithAuth('unauthorized invalid', async ({ authFixture }, testInfo) => {
      const { page, session, authId1, authId2 } = authFixture;

      await page.goto('/');

      //@ts-ignore
      const apiUrl = testInfo.project.use.apiURL;

      const headers: Record<string, string> = {
         'Content-Type': 'application/json',
         'x-csrf-token': 'xhBTx1eYZnHVx7GlS4PenA'
      };

      await runInvalids(page, apiUrl, '22eba19cIp4leXyK4a3qNB', headers);

      // user should be gone at this point, but cruft remains in the browser since we
      // called APIs direclty. Clean up userid so nukeall handler doesn't try
      await page.evaluate(() => {
         window.localStorage.removeItem('userid');
      });

   });

});


async function runInvalids(
   page: Page,
   apiUrl: any,
   userId: string,
   headers: Record<string, string>
) {
   // GET UserInfo

   let infoResponse = await page.request.get(
      //@ts-ignore
      `${apiUrl}/users/42ebNajPIp3leX4K4a0qND`,
      { headers: headers }
   );
   expect(infoResponse.status()).toBe(401);

   infoResponse = await page.request.get(
      //@ts-ignore
      `${apiUrl}/users/null`,
      { headers: headers }
   );
   expect(infoResponse.status()).toBe(401);

   infoResponse = await page.request.get(
      //@ts-ignore
      `${apiUrl}/users/42ebNajPIp3leX4K4a0qND42ebNajPIp3leX4K4a0qND42ebNajPIp3leX4K4a0qND`,
      { headers: headers }
   );
   expect(infoResponse.status()).toBe(401);

   // PATCH UserInfo

   const body1 = {
      userName: "yppilFWP"
   }

   let bodyData = new TextEncoder().encode(JSON.stringify(body1));
   let hash = await crypto.subtle.digest("SHA-256", bodyData);
   headers['x-amz-content-sha256'] = bufferToHexString(hash);

   let patchResponse = await page.request.patch(
      //@ts-ignore
      `${apiUrl}/users/`,
      { headers: headers, data: body1 }
   );

   expect(patchResponse.status()).toBe(404);

   patchResponse = await page.request.patch(
      //@ts-ignore
      `${apiUrl}/users/42ebNajPIp3leX4K4a0qND`,
      { headers: headers, data: body1 }
   );

   expect(patchResponse.status()).toBe(401);

   patchResponse = await page.request.patch(
      //@ts-ignore
      `${apiUrl}/users/0`,
      { headers: headers, data: body1 }
   );

   expect(patchResponse.status()).toBe(401);

   patchResponse = await page.request.patch(
      //@ts-ignore
      `${apiUrl}/users/PWFlippy`,
      { headers: headers, data: body1 }
   );

   expect(patchResponse.status()).toBe(401);


   // PATCH passkey
   const body2 = {
      description: "5673455"
   }

   bodyData = new TextEncoder().encode(JSON.stringify(body2));
   hash = await crypto.subtle.digest("SHA-256", bodyData);
   headers['x-amz-content-sha256'] = bufferToHexString(hash);

   patchResponse = await page.request.patch(
      //@ts-ignore
      `${apiUrl}/users//passkeys/ff243l4wl3ifnasdfi`,
      { headers: headers, data: body2 }
   );
   expect(patchResponse.status()).toBe(403); // stopped by cloudfront

   patchResponse = await page.request.patch(
      //@ts-ignore
      `${apiUrl}/users/42ebNajPIp3leX4K4a0qND/passkeys/ff243l4wl3ifnasdfi`,
      { headers: headers, data: body2 }
   );
   expect(patchResponse.status()).toBe(401);

   patchResponse = await page.request.patch(
      //@ts-ignore
      `${apiUrl}/users/;24r(%/passkeys/ff243l4wl3ifnasdfi`,
      { headers: headers, data: body2 }
   );
   expect(patchResponse.status()).toBe(400);

   patchResponse = await page.request.patch(
      //@ts-ignore
      `${apiUrl}/users/${userId}/passkeys/ff243l4wl3ifnasdfi`,
      { headers: headers, data: body2 }
   );
   expect(patchResponse).not.toBeOK();

   patchResponse = await page.request.patch(
      //@ts-ignore
      `${apiUrl}/users/${userId}/passkeys/`,
      { headers: headers, data: body2 }
   );
   expect(patchResponse.status()).toBe(404);

   patchResponse = await page.request.patch(
      //@ts-ignore
      `${apiUrl}/users/${userId}/passkeys/(0)`,
      { headers: headers, data: body2 }
   );
   expect(patchResponse).not.toBeOK();

   // DELETE passkeys

   let delResponse = await page.request.delete(
      //@ts-ignore
      `${apiUrl}/users/42ebNajPIp3leX4K4a0qND/passkeys/42ebNajPIp3leX4K4a0qND`,
      { headers: headers }
   );
   expect(delResponse.status()).toBe(401);

   delResponse = await page.request.delete(
      //@ts-ignore
      `${apiUrl}/users/passkeys/42ebNajPIp3leX4K4a0qND`,
      { headers: headers }
   );
   expect(delResponse.status()).toBe(404);

   delResponse = await page.request.delete(
      //@ts-ignore
      `${apiUrl}/users/${userId}/passkeys/42ebNajPIp3leX4K4a0qND`,
      { headers: headers }
   );
   expect(delResponse).not.toBeOK();

   delResponse = await page.request.delete(
      //@ts-ignore
      `${apiUrl}/users/${userId}/passkeys/*`,
      { headers: headers }
   );
   expect(delResponse).not.toBeOK();

   // GET session

   let sessionResponse = await page.request.get(
      `${apiUrl}/users/session`,
      { headers: headers }
   );
   expect(sessionResponse.status()).toBe(401);

   sessionResponse = await page.request.get(
      `${apiUrl}/users/42ebNajPIp3leX4K4a0qND/session`,
      { headers: headers }
   );
   expect(sessionResponse.status()).toBe(401);

   sessionResponse = await page.request.get(
      `${apiUrl}/users/undefined/session`,
      { headers: headers }
   );
   expect(sessionResponse.status()).toBe(401);

   sessionResponse = await page.request.get(
      `${apiUrl}/users/0/session`,
      { headers: headers }
   );
   expect(sessionResponse.status()).toBe(401);

   // DELETE  session

   bodyData = new TextEncoder().encode('');
   hash = await crypto.subtle.digest("SHA-256", bodyData);
   headers['x-amz-content-sha256'] = bufferToHexString(hash);

   delResponse = await page.request.delete(
      `${apiUrl}/users/0/session`,
      { headers: headers }
   );
   expect(delResponse.status()).toBe(401);

   delResponse = await page.request.delete(
      `${apiUrl}/users`,
      { headers: headers }
   );
   expect(delResponse.status()).toBe(404);

   delResponse = await page.request.delete(
      `${apiUrl}/users/${userId}`,
      { headers: headers }
   );
   expect(delResponse.status()).toBe(404);

   // Bad URLS generally
   let getResponse = await page.request.get(
      //@ts-ignore
      `${apiUrl}/fl2i4bNajPIp3leX4K4a0qND`,
      { headers: headers }
   );
   expect(getResponse.status()).toBe(404);

   getResponse = await page.request.get(
      //@ts-ignore
      `${apiUrl}/`,
      { headers: headers }
   );
   expect(getResponse.status()).toBe(404);

   //TODO get a library to do this...

}

async function apiSetup(
   testInfo: TestInfo,
   page: Page,
   session: CDPSession,
   authId: string
): Promise<[string, ServerLoginUserInfo, Record<string, string>]> {

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

   let sessResp = await page.request.get(
      `${apiUrl}/users/${userId}/session`
   );
   expect(sessResp).toBeOK();
   const apiUser: ServerLoginUserInfo = await sessResp.json();

   const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'x-csrf-token': apiUser.csrf!
   };

   return [apiUrl, apiUser, headers];
}

async function reSetup(
   testInfo: TestInfo,
   page: Page,
   session: CDPSession,
   authId: string
): Promise<[ServerLoginUserInfo, Record<string, string>]> {

   await page.goto('/');

   await passkeyAuth(session, authId, async () => {
      await page.getByRole('button', { name: /Sign in as PWFlippy/ }).click();
   });
   await page.waitForURL('/', { waitUntil: 'domcontentloaded' });
   await expect(page.getByRole('button', { name: 'Sign in as PWFlippy' })).not.toBeVisible({ timeout: 10000 });

   const storageState = await page.context().storageState();
   const loclStorage = storageState.origins[0].localStorage;
   const userId = loclStorage.find(item => item.name === 'userid')?.value;
   expect(userId).toBeTruthy();

   //@ts-ignore
   const apiUrl = testInfo.project.use.apiURL;

   let sessResp = await page.request.get(
      `${apiUrl}/users/${userId}/session`
   );
   expect(sessResp).toBeOK();
   const apiUser: ServerLoginUserInfo = await sessResp.json();

   const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'x-csrf-token': apiUser.csrf!
   };

   return [apiUser, headers];
}
