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

test.describe('authenticated api tests', () => {

   // Each worker gets its own context, so these should be different instances across workers
   let apiUrl: ApiSetupResults[0];
   let apiUser: ApiSetupResults[1];
   let apiHeaders: ApiSetupResults[2];

   //@ts-ignore
   test.beforeEach(async ({ authFixture }, testInfo) => {
      const { page, session, authId1, authId2 } = authFixture;
      [apiUrl, apiUser, apiHeaders] = await apiSetup(testInfo, page, session, authId1);
   });

   test.afterEach(async ({ page }, testInfo) => {
      if (testInfo.status === 'passed') {
         // Expect the main function to have deleted user, so this should fail
         const infoResponse = await page.request.get(
            //@ts-ignore
            `${apiUrl}/user`,
            { headers: apiHeaders }
         );
         expect(infoResponse.status()).toBe(401);

         // user should be gone at this point, but cruft remains in the browser since we
         // called APIs direclty. Clean up userid so nukeall handler doesn't try
         await page.evaluate(() => {
            window.localStorage.removeItem('userid');
         });
      }
   });

   testWithAuth('create, edit, remove passkey', { tag: ['@nukeall', '@api'] }, async ({ authFixture }, testInfo) => {
      const { page, session, authId1, authId2 } = authFixture;

      // Success case
      let usersResponse = await page.request.get(
         `${apiUrl}/user`,
         { headers: apiHeaders }
      );
      expect(usersResponse).toBeOK();

      const user = await usersResponse.json();
      expect(user.userName).toBe('PWFlippy');
      expect(user.authenticators.length).toBe(1);

      // Failure case, invalid userid
      // Comment out during backward compatibility period
      usersResponse = await page.request.get(
         `${apiUrl}/users/42ebNajPIp3leX4K4a0qND`,
         { headers: apiHeaders }
      );
      expect(usersResponse.status()).toBe(404);


      // Should fail, invalid credid
      let delResponse = await page.request.delete(
         //@ts-ignore
         `${apiUrl}/passkeys/nfVho8Z8p3oEpOl8yvbh40`,
         { headers: apiHeaders }
      );
      expect(delResponse.status()).toBe(400);

      // Should fail, invalid userId with valid credential
      // comment out during backward compatibility period
      // delResponse = await page.request.delete(
      //    //@ts-ignore
      //    `${apiUrl}/users/42ebNajPIp3leX4K4a0qND/passkeys/${user.authenticators[0].credentialId}`,
      //    { headers: apiHeaders }
      // );
      // expect(delResponse.status()).toBe(401);

      // Should fail, invalid userId and credential
      delResponse = await page.request.delete(
         //@ts-ignore
         `${apiUrl}/passkeys/nfVho8Z8p3oEpOl8yvbh40`,
         { headers: apiHeaders }
      );
      expect(delResponse.status()).toBe(400);


      // Valid passkey delete
      delResponse = await page.request.delete(
         //@ts-ignore
         `${apiUrl}/passkeys/${user.authenticators[0].credentialId}`,
         { headers: apiHeaders }
      );
      expect(delResponse).toBeOK();

      // should confirm this fails when another PK still exists (error should be 400 in that case)
      delResponse = await page.request.delete(
         //@ts-ignore
         `${apiUrl}/passkeys/${user.authenticators[0].credentialId}`,
         { headers: apiHeaders }
      );
      expect(delResponse.status()).toBe(401);

   });

   testWithAuth('edit passkey description', { tag: ['@nukeall', '@api'] }, async ({ authFixture }, testInfo) => {
      const { page, session, authId1, authId2 } = authFixture;

      // Test good patch of description
      const body1 = {
         description: "5673455"
      }

      let bodyData = new TextEncoder().encode(JSON.stringify(body1));
      let hash = await crypto.subtle.digest("SHA-256", bodyData);
      apiHeaders['x-amz-content-sha256'] = bufferToHexString(hash);

      let descResponse = await page.request.patch(
         //@ts-ignore
         `${apiUrl}/passkeys/${apiUser.authenticators[0].credentialId}`,
         { headers: apiHeaders, data: body1 }
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
      apiHeaders['x-amz-content-sha256'] = bufferToHexString(hash);

      descResponse = await page.request.patch(
         //@ts-ignore
         `${apiUrl}/passkeys/${user.authenticators[0].credentialId}`,
         { headers: apiHeaders, data: body2 }
      );
      expect(descResponse.status()).toBe(200);
      user = await descResponse.json();
      expect(user.authenticators[0].description).toBe("567345 5");


      // invalid user id
      // comment out during backward compatibility period
      // descResponse = await page.request.patch(
      //    //@ts-ignore
      //    `${apiUrl}/users/42ebNajPIp3leX4K4a0qND/passkeys/${user.authenticators[0].credentialId}`,
      //    { headers: apiHeaders, data: body2 }
      // );
      // expect(descResponse.status()).toBe(401);

      // invalid cred id
      descResponse = await page.request.patch(
         //@ts-ignore
         `${apiUrl}/passkeys/nfVho8Z8p3oEpOl8yvbh40`,
         { headers: apiHeaders, data: body2 }
      );
      expect(descResponse.status()).toBe(400);

      // Should fail, because description is not a string
      const body3 = {
         description: 5673455
      }

      bodyData = new TextEncoder().encode(JSON.stringify(body3));
      hash = await crypto.subtle.digest("SHA-256", bodyData);
      apiHeaders['x-amz-content-sha256'] = bufferToHexString(hash);

      descResponse = await page.request.patch(
         //@ts-ignore
         `${apiUrl}/passkeys/${user.authenticators[0].credentialId}`,
         { headers: apiHeaders, data: body3 }
      );
      expect(descResponse.status()).toBe(400);

      // make sure we are still good...
      const body4 = {
         description: "something"
      }

      bodyData = new TextEncoder().encode(JSON.stringify(body4));
      hash = await crypto.subtle.digest("SHA-256", bodyData);
      apiHeaders['x-amz-content-sha256'] = bufferToHexString(hash);

      // should fail due to session being deleted
      descResponse = await page.request.patch(
         //@ts-ignore
         `${apiUrl}/passkeys/${user.authenticators[0].credentialId}`,
         { headers: apiHeaders, data: body4 }
      );
      expect(descResponse.status()).toBe(200);
      user = await descResponse.json();
      expect(user.authenticators[0].description).toBe(body4.description);


      // Delete session and confirm further edits don't work
      const endResponse = await page.request.delete(
         `${apiUrl}/session`,
         { headers: apiHeaders }
      );
      expect(endResponse).toBeOK();

      descResponse = await page.request.patch(
         //@ts-ignore
         `${apiUrl}/passkeys/${user.authenticators[0].credentialId}`,
         { headers: apiHeaders, data: body4 }
      );
      expect(descResponse.status()).toBe(401);

      // sign back to get new session
      [apiUser, apiHeaders] = await reSetup(testInfo, page, session, authId1);

      // Valid passkey delete
      let delResponse = await page.request.delete(
         //@ts-ignore
         `${apiUrl}/passkeys/${user.authenticators[0].credentialId}`,
         { headers: apiHeaders }
      );
      expect(delResponse).toBeOK();

   });

   testWithAuth('edit user name', { tag: ['@nukeall', '@api'] }, async ({ authFixture }, testInfo) => {
      const { page, session, authId1, authId2 } = authFixture;

      // Success case
      let usersResponse = await page.request.get(
         `${apiUrl}/user`,
         { headers: apiHeaders }
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
      apiHeaders['x-amz-content-sha256'] = bufferToHexString(hash);

      let patchResponse = await page.request.patch(
         //@ts-ignore
         `${apiUrl}/user`,
         { headers: apiHeaders, data: body1 }
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
      apiHeaders['x-amz-content-sha256'] = bufferToHexString(hash);

      patchResponse = await page.request.patch(
         //@ts-ignore
         `${apiUrl}/user`,
         { headers: apiHeaders, data: body2 }
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
      apiHeaders['x-amz-content-sha256'] = bufferToHexString(hash);

      patchResponse = await page.request.patch(
         //@ts-ignore
         `${apiUrl}/user`,
         { headers: apiHeaders, data: body3 }
      );
      expect(patchResponse.status()).toBe(400);


      // confirm still at previous value
      usersResponse = await page.request.get(
         `${apiUrl}/user`,
         { headers: apiHeaders }
      );
      expect(usersResponse).toBeOK();

      user = await usersResponse.json();
      expect(user.userName).toBe('all good');
      expect(user.authenticators.length).toBe(1);

      bodyData = new TextEncoder().encode('');
      hash = await crypto.subtle.digest("SHA-256", bodyData);
      apiHeaders['x-amz-content-sha256'] = bufferToHexString(hash);

      // Delete session and confirm further edits don't work
      const endResponse = await page.request.delete(
         `${apiUrl}/session`,
         { headers: apiHeaders }
      );
      expect(endResponse).toBeOK();

      // User account will be leaked server-side if there is an abort
      // between this comment and passkeyAuth success

      const body4 = {
         userName: "PWFlippy"
      }

      bodyData = new TextEncoder().encode(JSON.stringify(body4));
      hash = await crypto.subtle.digest("SHA-256", bodyData);
      apiHeaders['x-amz-content-sha256'] = bufferToHexString(hash);

      // should fail due to session being deleted
      patchResponse = await page.request.patch(
         //@ts-ignore
         `${apiUrl}/user`,
         { headers: apiHeaders, data: body4 }
      );
      expect(patchResponse.status()).toBe(401);

      // sign back to get new session
      [apiUser, apiHeaders] = await reSetup(testInfo, page, session, authId1);

      const delResponse = await page.request.delete(
         //@ts-ignore
         `${apiUrl}/passkeys/${apiUser.authenticators[0].credentialId}`,
         { headers: apiHeaders }
      );
      expect(delResponse).toBeOK();

   });

   testWithAuth('get session', { tag: ['@nukeall', '@api'] }, async ({ authFixture }, testInfo) => {
      const { page, session, authId1, authId2 } = authFixture;

      let sessionResponse = await page.request.get(
         `${apiUrl}/session`,
         { headers: apiHeaders }
      );
      expect(sessionResponse).toBeOK();

      let user = await sessionResponse.json();
      expect(user.verified).toBeTruthy();
      expect(user.userName).toBe('PWFlippy');
      expect(user.userId).toBe(apiUser.userId);
      expect(user.hasRecoveryId).toBeTruthy()
      expect(user.authenticators.length).toBe(1);

      // invalid user id
      sessionResponse = await page.request.get(
         `${apiUrl}/users/42ebNajPIp3leX4K4a0qND/session`,
         { headers: apiHeaders }
      );
      expect(sessionResponse.status()).toBe(404);

      const delResponse = await page.request.delete(
         //@ts-ignore
         `${apiUrl}/passkeys/${user.authenticators[0].credentialId}`,
         { headers: apiHeaders }
      );
      expect(delResponse).toBeOK();

   });

   testWithAuth('delete session', { tag: ['@nukeall', '@api'] }, async ({ authFixture }, testInfo) => {
      const { page, session, authId1, authId2 } = authFixture;

      let sessionResponse = await page.request.get(
         `${apiUrl}/session`,
         { headers: apiHeaders }
      );
      expect(sessionResponse).toBeOK();

      const bodyData = new TextEncoder().encode('');
      const hash = await crypto.subtle.digest("SHA-256", bodyData);
      apiHeaders['x-amz-content-sha256'] = bufferToHexString(hash);

      // delete with valid session cookie, but invalid userId should fail
      let endResponse = await page.request.delete(
         `${apiUrl}/users/42ebNajPIp3leX4K4a0qND/session`,
         { headers: apiHeaders }
      );
      expect(endResponse.status()).toBe(404);


      endResponse = await page.request.delete(
         `${apiUrl}/session`,
         { headers: apiHeaders }
      );
      expect(endResponse).toBeOK();

      // User account will be leaked server-side if there is an abort
      // between this comment and passkeyAuth success

      endResponse = await page.request.delete(
         `${apiUrl}/session`,
         { headers: apiHeaders }
      );
      expect(endResponse.status()).toBe(401);

      sessionResponse = await page.request.get(
         `${apiUrl}/session`,
         { headers: apiHeaders }
      );
      expect(sessionResponse.status()).toBe(401);

      let infoResponse = await page.request.get(
         //@ts-ignore
         `${apiUrl}/user`,
         { headers: apiHeaders }
      );
      expect(infoResponse.status()).toBe(401);


      // sign back to get new session
      [apiUser, apiHeaders] = await reSetup(testInfo, page, session, authId1);

      infoResponse = await page.request.get(
         //@ts-ignore
         `${apiUrl}/user`,
         { headers: apiHeaders }
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
         `${apiUrl}/passkeys/${user.authenticators[0].credentialId}`,
         { headers: apiHeaders }
      );
      expect(delResponse).toBeOK();
   });


   testWithAuth('test bad csrf', { tag: ['@nukeall', '@api'] }, async ({ authFixture }, testInfo) => {
      const { page, session, authId1, authId2 } = authFixture;

      let headers = structuredClone(apiHeaders);
      delete headers['x-csrf-token'];

      // for absent CSRF is removed (when clients update)
      // Should fail due to missing csrf
      let usersResponse = await page.request.get(
         `${apiUrl}/user`,
         { headers }
      );
      expect(usersResponse.status()).toBe(401);

      // for absent CSRF is removed (when clients update)
      // Should fail due to missing csrf
      let delResponse = await page.request.delete(
         //@ts-ignore
         `${apiUrl}/passkeys/${apiUser.authenticators[0].credentialId}`,
         { headers }
      );
      expect(delResponse.status()).toBe(401);

      headers['x-csrf-token'] = 'uajbCCy0AeBW5WDEqbR9viY12HaQOiKlJcNSG8yaGT0';

      // Should fail due to bad csrf
      usersResponse = await page.request.get(
         `${apiUrl}/user`,
         { headers }
      );
      expect(usersResponse.status()).toBe(401);

      // Should fail due to bad csrf
      delResponse = await page.request.delete(
         //@ts-ignore
         `${apiUrl}/passkeys/${apiUser.authenticators[0].credentialId}`,
         { headers }
      );
      expect(delResponse.status()).toBe(401);

      // Correcr csrf, should work
      delResponse = await page.request.delete(
         //@ts-ignore
         `${apiUrl}/passkeys/${apiUser.authenticators[0].credentialId}`,
         { headers: apiHeaders }
      );
      expect(delResponse).toBeOK();
   });

   testWithAuth('small fuzz', { tag: ['@nukeall', '@api'] }, async ({ authFixture }, testInfo) => {
      const { page, session, authId1, authId2 } = authFixture;

      test.setTimeout(60000);

      await smallFuzzCommaon(page, apiUrl, apiUser.userId!, apiHeaders);

      const delResponse = await page.request.delete(
         //@ts-ignore
         `${apiUrl}/passkeys/${apiUser.authenticators[0].credentialId}`,
         { headers: apiHeaders }
      );
      expect(delResponse).toBeOK();
   });

   testWithAuth('full fuzz', { tag: ['@nukeall', '@api', '@fullfuzz'] }, async ({ authFixture }, testInfo) => {
      const { page, session, authId1, authId2 } = authFixture;

      test.setTimeout(180000);

      await fullFuzzCommaon(page, apiUrl, apiUser.userId!, apiHeaders);

      const delResponse = await page.request.delete(
         //@ts-ignore
         `${apiUrl}/passkeys/${apiUser.authenticators[0].credentialId}`,
         { headers: apiHeaders }
      );
      expect(delResponse).toBeOK();
   });

});


test.describe('unauthenticated api', () => {

   testWithAuth('full fuzz', { tag: ['@api', '@fullfuzz'] }, async ({ authFixture }, testInfo) => {
      const { page, session, authId1, authId2 } = authFixture;
      test.setTimeout(180000);

      await page.goto('/');

      //@ts-ignore
      const apiUrl = testInfo.project.use.apiURL;

      const headers: Record<string, string> = {
         'Content-Type': 'application/json',
         'x-csrf-token': 'xhBTx1eYZnHVx7GlS4PenA'
      };

      await fullFuzzCommaon(page, apiUrl, '22eba19cIp4leXyK4a3qNB', headers);
   });

   testWithAuth('small fuzz', { tag: ['@api'] }, async ({ authFixture }, testInfo) => {
      const { page, session, authId1, authId2 } = authFixture;
      test.setTimeout(60000);

      await page.goto('/');

      //@ts-ignore
      const apiUrl = testInfo.project.use.apiURL;

      const headers: Record<string, string> = {
         'Content-Type': 'application/json',
         'x-csrf-token': 'xhBTx1eYZnHVx7GlS4PenA'
      };

      await smallFuzzCommaon(page, apiUrl, '22eba19cIp4leXyK4a3qNB', headers);
   });

});


const badIds = ['', '<script>alert(0)</script>', '42ebNajPIp3leX4K4a0qND', 0, ';24r(%', 3423409, undefined, 'null', '42ebNajPIp3l<seX4K4a0qND42ebNajPIp3leX4K4a0qND42ebNajPIp3leX4K4a0qND'];
const badIdsSmall = ['', '42ebNajPIp3leX4K4a0qND', 0];
const badNames = ['', 123, null, 0, 'aaa2f3lkmflm2;342ebNajPIp3leX4K4a0qNDfm2;l3rm2;rm;1asdfaaaa'];
const badNamesSmall = ['', 0, 'aaa2f3lkmflm2;342ebNajPIp3leX4K4a0qNDfm2;l3rm2;rm;1asdfaaaa'];

async function smallFuzzCommaon(
   page: Page,
   apiUrl: any,
   userId: string,
   headers: Record<string, string>
) {
   // GET UserInfo
   // await fuzzGet(page, headers,
   //    `${apiUrl}/users/{0}`,
   //    [badIdsSmall]
   // );

   // PATCH passkey
   await fuzzPatch(page, headers,
      `${apiUrl}/passkeys/{1}`,
      [[...badIdsSmall, userId], badIdsSmall],
      'description',
      badNamesSmall
   );

   // DELETE  session
   // comment out during backward compatibility period
   // await fuzzDelete(page, headers,
   //    `${apiUrl}/users/{0}/session`,
   //    [badIdsSmall]
   // );

   // POST auth verify
   await fuzzPost(page, headers,
      `${apiUrl}/auth/verify`,
      [[...badIdsSmall, userId]],
      'authenticator',
      badNamesSmall
   );

}

async function fullFuzzCommaon(
   page: Page,
   apiUrl: any,
   userId: string,
   headers: Record<string, string>
) {
   // GET UserInfo
   // comment out during backward compatibility period
   // await fuzzGet(page, headers,
   //    `${apiUrl}/users/{0}`,
   //    [badIds]
   // );

   // PATCH UserInfo
   await fuzzPatch(page, headers,
      `${apiUrl}/user`,
      [badIds],
      'userName',
      badNames
   );

   // PATCH passkey
   // also include good userid
   await fuzzPatch(page, headers,
      `${apiUrl}/passkeys/{1}`,
      [[...badIdsSmall, userId], badIds],
      'description',
      badNames
   );

   // DELETE passkeys
   await fuzzDelete(page, headers,
      `${apiUrl}/passkeys/{1}`,
      [[...badIdsSmall, userId], badIds]
   );

   // GET session
   // comment out during backward compatibility period
   // await fuzzGet(page, headers,
   //    `${apiUrl}/users/{0}/session`,
   //    [badIds]
   // );

   // DELETE  session
   // comment out during backward compatibility period
   // await fuzzDelete(page, headers,
   //    `${apiUrl}/users/{0}/session`,
   //    [badIds]
   // );

   let delResponse = await page.request.delete(
      `${apiUrl}/user`,
      { headers: headers }
   );
   expect(delResponse).not.toBeOK();

   delResponse = await page.request.delete(
      `${apiUrl}/user`,
      { headers: headers }
   );
   expect(delResponse.status()).toBe(404);

   // POST reg verify
   await fuzzPost(page, headers,
      `${apiUrl}/reg/verify`,
      [[...badIds, userId]],
      'authenticator',
      badNames
   );

   // POST auth verify
   await fuzzPost(page, headers,
      `${apiUrl}/auth/verify`,
      [[...badIds, userId]],
      'authenticator',
      badNames
   );

   // POST recovery
   await fuzzPost(page, headers,
      `${apiUrl}/users/{0}/recover/{1}`,
      [[...badIdsSmall, userId], badIds]
   );

   // POST recovery2
   await fuzzPost(page, headers,
      `${apiUrl}/users/{0}/recover2/{1}`,
      [[...badIdsSmall, userId], badIds]
   );

   // GET passkeys options
   // comment out during backward compatibility period
   // await fuzzGet(page, headers,
   //    `${apiUrl}/users/{0}/passkeys/options`,
   //    [badIds]
   // );

   // POST passkeys verify
   await fuzzPost(page, headers,
      `${apiUrl}/passkeys/verify`,
      [[...badIds, userId]]
   );

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

}

type ApiSetupResults = [string, ServerLoginUserInfo, Record<string, string>];

async function apiSetup(
   testInfo: TestInfo,
   page: Page,
   session: CDPSession,
   authId: string
): Promise<ApiSetupResults> {

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
      `${apiUrl}/session`
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
      `${apiUrl}/session`
   );
   expect(sessResp).toBeOK();
   const apiUser: ServerLoginUserInfo = await sessResp.json();

   const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'x-csrf-token': apiUser.csrf!
   };

   return [apiUser, headers];
}


async function fuzzGet(
   page: Page,
   defaultHeaders: Record<string, string>,
   urlTemplate: string,
   urlValues: any[][],
) {

   let headers = structuredClone(defaultHeaders);

   const subs = cartesianProduct(urlValues);
   for (let sub of subs) {
      let url = urlTemplate;
      for (let pos = 0; pos < sub.length; ++pos) {
         url = url.replace(`{${pos}}`, String(sub[pos]))
      }
      //      console.log(`GET ${url}`);
      const response = await page.request.get(
         //@ts-ignore
         url,
         { headers: headers }
      );
      expect(response).not.toBeOK();
   }
}

async function fuzzDelete(
   page: Page,
   defaultHeaders: Record<string, string>,
   urlTemplate: string,
   urlValues: any[][],
) {

   let headers = structuredClone(defaultHeaders);

   let bodyData = new TextEncoder().encode(JSON.stringify(''));
   let hash = await crypto.subtle.digest("SHA-256", bodyData);
   headers['x-amz-content-sha256'] = bufferToHexString(hash);

   const subs = cartesianProduct(urlValues);
   for (let sub of subs) {
      let url = urlTemplate;
      for (let pos = 0; pos < sub.length; ++pos) {
         url = url.replace(`{${pos}}`, String(sub[pos]))
      }
      //      console.log(`DELETE ${url}`);
      const response = await page.request.delete(
         //@ts-ignore
         url,
         { headers }
      );
      expect(response).not.toBeOK();
   }
}


async function fuzzPatch(
   page: Page,
   defaultHeaders: Record<string, string>,
   urlTemplate: string,
   urlValues: any[][],
   dataKey: string,
   dataValues: any[]
) {
   urlValues.push(dataValues)
   const subs = cartesianProduct(urlValues);

   let headers = structuredClone(defaultHeaders);

   for (let sub of subs) {
      let url = urlTemplate;
      let pos = 0;
      for (; pos < sub.length - 1; ++pos) {
         url = url.replace(`{${pos}}`, String(sub[pos]))
      }

      const data: Record<string, any> = {};
      //    console.log(`datakey ${dataKey} ${pos} ${sub[pos]}`);

      data[dataKey] = sub[pos];

      let bodyData = new TextEncoder().encode(JSON.stringify(data));
      let hash = await crypto.subtle.digest("SHA-256", bodyData);
      headers['x-amz-content-sha256'] = bufferToHexString(hash);

      // console.log(`PATCH ${url}\n${JSON.stringify(data)}`);
      const response = await page.request.patch(
         //@ts-ignore
         url,
         { headers, data }
      );
      expect(response).not.toBeOK();
   }
}


async function fuzzPost(
   page: Page,
   defaultHeaders: Record<string, string>,
   urlTemplate: string,
   urlValues: any[][],
   dataKey?: string,
   dataValues?: any[]
) {
   if (dataValues) {
      urlValues.push(dataValues);
   }
   const subs = cartesianProduct(urlValues);

   let headers = structuredClone(defaultHeaders);

   for (let sub of subs) {
      let url = urlTemplate;
      let pos = 0;
      for (; pos < sub.length - (dataValues ? 1 : 0); ++pos) {
         url = url.replace(`{${pos}}`, String(sub[pos]))
      }

      const data: Record<string, any> = {};

      if (dataKey) {
         // console.log(`datakey ${dataKey} ${pos} ${sub[pos]}`);

         data[dataKey] = sub[pos];
         let bodyData = new TextEncoder().encode(JSON.stringify(data));
         let hash = await crypto.subtle.digest("SHA-256", bodyData);
         headers['x-amz-content-sha256'] = bufferToHexString(hash);
      }

      // console.log(`POST ${url}\n${JSON.stringify(data)}`);
      const response = await page.request.post(
         //@ts-ignore
         url,
         { headers, data }
      );
      expect(response).not.toBeOK();
   }
}


/**
 * Creates the Cartesian product of an array of arrays.
 * The function takes an array of arrays (arrOfArr) and returns a new
 * array of arrays, where each inner array is a unique combination
 * of elements from the original inner arrays.
 *
 * @param arrOfArr - An array of arrays, e.g., [['a', 'b'], [1, 2]].
 * @returns A new array of arrays containing the Cartesian product,
 * e.g., [['a', 1], ['a', 2], ['b', 1], ['b', 2]].
 */
export function cartesianProduct(arrOfArr: any[][]): any[][] {
   // If the input is null, undefined, or an empty array,
   // return an empty array as there's no product to compute.
   if (!arrOfArr || arrOfArr.length === 0) {
      return [];
   }

   // We use `reduce` to iteratively build the product.
   // The 'accumulator' (which we call 'acc') holds the
   // combinations built so far.
   // We start the accumulator with an array containing one empty array: `[[]]`.
   return arrOfArr.reduce(
      (acc, currentArray) => {
         // This will be the new accumulator for the next iteration.
         const newAcc: any[][] = [];

         // For each combination we've already built (accItem)...
         for (const accItem of acc) {
            // ...and for each item in the *current* array we're processing...
            for (const item of currentArray) {
               // ...create a new combination by adding the current item
               // to the existing combination.
               newAcc.push([...accItem, item]);
            }
         }

         // Return the newly built set of combinations
         // to be used as the accumulator for the next array.
         return newAcc;
      },
      [[]] as any[][] // Initial value: An array with one empty array.
   );
}