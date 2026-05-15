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

/* Between the tests in this file and login-relay.spec.ts (e2e) we attempt
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


import { TestBed } from '@angular/core/testing';
import { AuthenticatorService, AuthEvent, LoginUserInfo } from './authenticator.service';
import { BroadcastService } from './broadcast.service';
import { KeystoreService } from './keystore.service';
import * as cc from '@qcrypt/crypto/consts';
import { bytesToBase64, cryptoReady, getRandom } from '@qcrypt/crypto';

describe('AuthenticatorService', () => {
   let service: AuthenticatorService;
   let peerResponder: BroadcastService;
   let pkId: string;
   let userId: string;
   let userCred: string;
   let peerExpiry: string;
   let sessionResponse: LoginUserInfo;
   let originalFetch: typeof fetch;
   let fetchMock: ReturnType<typeof vi.fn>;
   const allAuthEvents = [AuthEvent.Login, AuthEvent.Logout, AuthEvent.Forget, AuthEvent.Delete];

   beforeEach(async () => {
      await cryptoReady();

      pkId = bytesToBase64(getRandom(cc.PKID_MIN_BYTES));
      userId = bytesToBase64(getRandom(cc.USERID_BYTES));
      userCred = bytesToBase64(getRandom(cc.USERCRED_BYTES));
      peerExpiry = new Date(Date.now() + 60 * 60 * 1000).toISOString();

      sessionResponse = {
         verified: true,
         userId: userId,
         userName: 'test-user',
         pkId: pkId,
         userCred: userCred,
         csrf: 'csrf-token-from-test',
         hasRecoveryId: true,
         authenticators: [{
            credentialId: pkId,
            description: 'Test laptop authenticator',
            lightIcon: 'laptop-light.svg',
            darkIcon: 'laptop-dark.svg',
            name: 'YubiKey 5 NFC'
         }]
      };

      originalFetch = window.fetch;
      fetchMock = vi.fn().mockResolvedValue({
         ok: true,
         json: async () => sessionResponse
      });
      window.fetch = fetchMock as typeof fetch;

      service = TestBed.inject(AuthenticatorService);
      await service.ready;
      peerResponder = new BroadcastService();
      peerResponder.start();
   });

   afterEach(async () => {
      peerResponder.close();
      TestBed.inject(BroadcastService).close();
      window.fetch = originalFetch;
      localStorage.clear();
      sessionStorage.clear();
      await TestBed.inject(KeystoreService).flush();
      vi.restoreAllMocks();
   });

   function primeLocalStorage() {
      const future = new Date(Date.now() + 60000).toISOString();
      localStorage.setItem('userid', userId);
      localStorage.setItem('username', 'test-user');
      localStorage.setItem('pkid', pkId);
      localStorage.setItem('sessionexpiry', future);
      localStorage.setItem('activityexpiry', future);
   }

   it('should be created', () => {
      expect(service).toBeTruthy();
   });

   it('restore returns false when no peer responds', async () => {
      primeLocalStorage();

      const keystoreSvc = TestBed.inject(KeystoreService);
      const createSpy = vi.spyOn(keystoreSvc, 'create');
      const getSpy = vi.spyOn(keystoreSvc, 'get');
      const events: AuthEvent[] = [];
      service.on(allAuthEvents, (ed) => events.push(ed.event));

      const restored = await service._restoreSession();

      expect(restored).toBe(false);
      expect(createSpy).not.toHaveBeenCalled();
      expect(getSpy).not.toHaveBeenCalled();
      expect(fetchMock).toHaveBeenCalled();
      expect((fetchMock.mock.calls[0][0] as URL).pathname).toContain('/session');
      expect((fetchMock.mock.calls[0][0] as URL).search).toContain('usercred=false');
      expect(service.hasSession()).toBe(false);
      expect(events).toEqual([]);
   });

   it('relay login with peer response', async () => {
      primeLocalStorage();

      peerResponder.setCredentialProvider(() => ({
         pkId: pkId,
         userCredEnc: bytesToBase64(new Uint8Array([1, 2, 3, 4])),
         userCredExpiry: peerExpiry,
         version: 1,
      }));

      const keystoreSvc = TestBed.inject(KeystoreService);
      const createSpy = vi.spyOn(keystoreSvc, 'create');
      const getSpy = vi.spyOn(keystoreSvc, 'get');
      const events: AuthEvent[] = [];
      service.on(allAuthEvents, (ed) => events.push(ed.event));

      await service._restoreSession();

      expect(createSpy).not.toHaveBeenCalled();
      expect(getSpy).toHaveBeenCalled();
      expect(fetchMock).toHaveBeenCalled();
      expect((fetchMock.mock.calls[0][0] as URL).pathname).toContain('/session');
      // Only check first position due to test side-effect adding extra event
      expect(events[0]).toBe(AuthEvent.Login);
      // cannot test hasSession() because response userCredEnc was faked and won't
      // decryt. see 'full login then relay login...' test for that
   });

   it('simulated tab refresh succeeds', async () => {
      primeLocalStorage();

      // @ts-ignore — exercising private path
      await service._loginUser(sessionResponse);
      const restoredState1 = JSON.parse(sessionStorage.getItem('sessionstate')!);
      const userCredEnc1: string = restoredState1.userCredEnc;
      expect(userCredEnc1).toBeTruthy();

      fetchMock.mockClear();
      const keystoreSvc = TestBed.inject(KeystoreService);
      const createSpy = vi.spyOn(keystoreSvc, 'create');
      const getSpy = vi.spyOn(keystoreSvc, 'get');
      const events: AuthEvent[] = [];
      service.on(allAuthEvents, (ed) => events.push(ed.event));

      const restored = await service._restoreSession();

      expect(restored).toBe(true);
      expect(createSpy).not.toHaveBeenCalled();
      expect(getSpy).toHaveBeenCalled();
      expect(fetchMock).toHaveBeenCalled();
      const restoredState2 = JSON.parse(sessionStorage.getItem('sessionstate')!);
      expect(restoredState2.userCredEnc).toBe(userCredEnc1);
      expect(service.hasSession()).toBe(true);
      expect(events).toEqual([AuthEvent.Login]);
   });

   it('full login then relay login, restore session succeeds', async () => {
      primeLocalStorage();

      const keystoreSvc = TestBed.inject(KeystoreService);
      const createSpy = vi.spyOn(keystoreSvc, 'create');
      const getSpy = vi.spyOn(keystoreSvc, 'get');
      const events: AuthEvent[] = [];
      service.on(allAuthEvents, (ed) => events.push(ed.event));

      // Step 1: invoke _loginUser directly to populate IndexedDB and write
      // a userCredEnc to sessionStorage.
      // @ts-ignore — exercising private path
      await service._loginUser(sessionResponse);

      const restoredState1 = JSON.parse(sessionStorage.getItem('sessionstate')!);
      const userCredEnc1: string = restoredState1.userCredEnc;
      const version1: number = restoredState1.version;
      expect(userCredEnc1).toBeTruthy();
      expect(createSpy).toHaveBeenCalled();
      expect(getSpy).not.toHaveBeenCalled();
      expect(service.hasSession()).toBe(true);

      // Step 2: simulate a fresh tab by clearing sessionState and
      // redoing the session restore with a response from step 1.
      sessionStorage.clear();
      fetchMock.mockClear();
      createSpy.mockClear();
      getSpy.mockClear();

      peerResponder.setCredentialProvider(() => ({
         pkId: pkId,
         userCredEnc: userCredEnc1,
         userCredExpiry: peerExpiry,
         version: version1,
      }));

      service.logout(false);
      const restored = await service._restoreSession();

      expect(restored).toBe(true);
      expect(getSpy).toHaveBeenCalled();
      expect(createSpy).not.toHaveBeenCalled();
      expect(fetchMock).toHaveBeenCalled();
      expect((fetchMock.mock.calls[0][0] as URL).pathname).toContain('/session');
      const restoredState2 = JSON.parse(sessionStorage.getItem('sessionstate')!);
      expect(restoredState2.userCredEnc).toBe(userCredEnc1);
      expect(restoredState2.version).toBe(version1);
      expect(service.hasSession()).toBe(true);
      expect(events).toEqual([AuthEvent.Login, AuthEvent.Logout, AuthEvent.Login]);
   });

   it('restore returns false when session pkId differs from local pkId', async () => {
      primeLocalStorage();
      const serverPkId = bytesToBase64(getRandom(cc.PKID_MIN_BYTES));
      sessionResponse.pkId = serverPkId;

      // Peer ready to respond, but has a different pkId so restore fails
      peerResponder.setCredentialProvider(() => ({
         pkId: pkId,
         userCredEnc: bytesToBase64(new Uint8Array([5, 6, 7, 8])),
         userCredExpiry: peerExpiry,
         version: 1,
      }));

      const keystoreSvc = TestBed.inject(KeystoreService);
      const createSpy = vi.spyOn(keystoreSvc, 'create');
      const getSpy = vi.spyOn(keystoreSvc, 'get');
      const events: AuthEvent[] = [];
      service.on(allAuthEvents, (ed) => events.push(ed.event));

      const restored = await service._restoreSession();

      expect(restored).toBe(false);
      expect(createSpy).not.toHaveBeenCalled();
      expect(getSpy).not.toHaveBeenCalled();
      expect(fetchMock).toHaveBeenCalled();
      expect((fetchMock.mock.calls[0][0] as URL).pathname).toContain('/session');
      expect(service.hasSession()).toBe(false);
      expect(events).toEqual([]);
   });

   it('no restore attempt without a potential session', async () => {
      // no potential session because primeLocalStorage() not called

      const keystoreSvc = TestBed.inject(KeystoreService);
      const createSpy = vi.spyOn(keystoreSvc, 'create');
      const getSpy = vi.spyOn(keystoreSvc, 'get');
      const events: AuthEvent[] = [];
      service.on(allAuthEvents, (ed) => events.push(ed.event));

      await service._restoreSession();

      expect(fetchMock).not.toHaveBeenCalled();
      expect(createSpy).not.toHaveBeenCalled();
      expect(getSpy).not.toHaveBeenCalled();
      expect(events).toEqual([]);
   });

   describe('peer message handling', () => {

      it('login with higher version and matching pkId adopts via relay', async () => {
         primeLocalStorage();
         // @ts-ignore — exercising private path
         await service._loginUser(sessionResponse);
         const phase1 = JSON.parse(sessionStorage.getItem('sessionstate')!);

         fetchMock.mockClear();
         const keystoreSvc = TestBed.inject(KeystoreService);
         const createSpy = vi.spyOn(keystoreSvc, 'create');
         const events: AuthEvent[] = [];
         service.on(allAuthEvents, (ed) => events.push(ed.event));

         peerResponder.setCredentialProvider(() => ({
            pkId: pkId,
            userCredEnc: phase1.userCredEnc,
            userCredExpiry: peerExpiry,
            version: phase1.version + 5,
         }));
         peerResponder.sendLogin({
            pkId: pkId,
            userCredEnc: phase1.userCredEnc,
            userCredExpiry: peerExpiry,
            version: phase1.version + 5,
         });

         await new Promise((resolve) => setTimeout(resolve, 200));

         expect(createSpy).not.toHaveBeenCalled();
         expect(fetchMock).toHaveBeenCalled();
         const restored = JSON.parse(sessionStorage.getItem('sessionstate')!);
         expect(restored.version).toBe(phase1.version + 5);
         expect(service.hasSession()).toBe(true);
         expect(events).toEqual([AuthEvent.Login]);
      });

      it('login with lower-or-equal version is ignored', async () => {
         primeLocalStorage();
         // @ts-ignore — exercising private path
         await service._loginUser(sessionResponse);
         const phase1 = JSON.parse(sessionStorage.getItem('sessionstate')!);

         fetchMock.mockClear();
         const events: AuthEvent[] = [];
         service.on(allAuthEvents, (ed) => events.push(ed.event));

         peerResponder.sendLogin({
            pkId: pkId,
            userCredEnc: 'stale',
            userCredExpiry: peerExpiry,
            version: phase1.version,
         });

         await new Promise((resolve) => setTimeout(resolve, 200));

         expect(fetchMock).not.toHaveBeenCalled();
         const after = JSON.parse(sessionStorage.getItem('sessionstate')!);
         expect(after.userCredEnc).toBe(phase1.userCredEnc);
         expect(after.version).toBe(phase1.version);
         expect(events).toEqual([]);
      });

      it('login with unknown pkId for same user emits logout', async () => {
         primeLocalStorage();
         // @ts-ignore — exercising private path
         await service._loginUser(sessionResponse);
         const phase1 = JSON.parse(sessionStorage.getItem('sessionstate')!);
         const strangerPkId = bytesToBase64(getRandom(cc.PKID_MIN_BYTES));
         const events: AuthEvent[] = [];
         service.on([AuthEvent.Logout, AuthEvent.Forget], (ed) => events.push(ed.event));

         peerResponder.sendLogin({
            pkId: strangerPkId,
            userCredEnc: 'fresher',
            userCredExpiry: peerExpiry,
            version: phase1.version + 1,
         });

         await new Promise((resolve) => setTimeout(resolve, 200));
         expect(service.hasSession()).toBe(false);
         expect(events).toEqual([AuthEvent.Logout]);
      });

      it('login with unknown pkId for a different user emits forget', async () => {
         primeLocalStorage();
         // @ts-ignore — exercising private path
         await service._loginUser(sessionResponse);
         const phase1 = JSON.parse(sessionStorage.getItem('sessionstate')!);
         const strangerPkId = bytesToBase64(getRandom(cc.PKID_MIN_BYTES));
         const events: AuthEvent[] = [];
         service.on([AuthEvent.Logout, AuthEvent.Forget], (ed) => events.push(ed.event));

         // Simulate another tab signing in as a different user.
         localStorage.setItem('userid', bytesToBase64(getRandom(cc.USERID_BYTES)));

         peerResponder.sendLogin({
            pkId: strangerPkId,
            userCredEnc: 'fresher',
            userCredExpiry: peerExpiry,
            version: phase1.version + 1,
         });

         await new Promise((resolve) => setTimeout(resolve, 200));
         expect(service.hasSession()).toBe(false);
         expect(events).toEqual([AuthEvent.Forget]);
      });

      it('logout with version >= local triggers logout', async () => {
         primeLocalStorage();
         // @ts-ignore — exercising private path
         await service._loginUser(sessionResponse);
         const phase1 = JSON.parse(sessionStorage.getItem('sessionstate')!);
         const events: AuthEvent[] = [];
         service.on(allAuthEvents, (ed) => events.push(ed.event));

         peerResponder.sendLogout({ pkId: pkId, version: phase1.version });

         await new Promise((resolve) => setTimeout(resolve, 50));
         expect(service.hasSession()).toBe(false);
         expect(events).toEqual([AuthEvent.Logout]);
      });

      it('logout with version < local is ignored', async () => {
         primeLocalStorage();
         // @ts-ignore — exercising private path
         await service._loginUser(sessionResponse);
         const phase1 = JSON.parse(sessionStorage.getItem('sessionstate')!);
         const events: AuthEvent[] = [];
         service.on(allAuthEvents, (ed) => events.push(ed.event));

         fetchMock.mockClear();
         peerResponder.sendLogout({ pkId: pkId, version: phase1.version - 1 });

         await new Promise((resolve) => setTimeout(resolve, 50));
         expect(fetchMock).not.toHaveBeenCalled();
         expect(service.hasSession()).toBe(true);
         expect(events).toEqual([]);
      });

      it('forget triggers local forget', async () => {
         primeLocalStorage();
         // @ts-ignore — exercising private path
         await service._loginUser(sessionResponse);
         expect(service.hasSession()).toBe(true);
         const events: AuthEvent[] = [];
         service.on(allAuthEvents, (ed) => events.push(ed.event));

         // Real sender of forget clears shared localStorage before broadcasting.
         localStorage.removeItem('userid');
         localStorage.removeItem('username');
         localStorage.removeItem('pkid');
         peerResponder.sendForget();

         await new Promise((resolve) => setTimeout(resolve, 50));
         expect(service.hasSession()).toBe(false);
         expect(service.validKnownUser()).toBe(false);
         expect(events).toEqual([AuthEvent.Forget]);
      });

      it('userInfoChanged for matching pkId triggers refreshUserInfo', async () => {
         primeLocalStorage();
         // @ts-ignore — exercising private path
         await service._loginUser(sessionResponse);

         fetchMock.mockClear();

         peerResponder.sendUserInfoChanged({ pkId: pkId });

         await new Promise((resolve) => setTimeout(resolve, 100));

         expect(fetchMock).toHaveBeenCalled();
         const calledUrl = fetchMock.mock.calls[0][0] as URL;
         expect(calledUrl.pathname).toContain('/user');
      });

      it('forget with no session emits forget', async () => {
         const events: AuthEvent[] = [];
         service.on(allAuthEvents, (ed) => events.push(ed.event));

         peerResponder.sendForget();

         await new Promise((resolve) => setTimeout(resolve, 50));
         expect(events).toEqual([AuthEvent.Forget]);
      });

      it('forget when not logged in - same user emits forget', async () => {
         primeLocalStorage();
         const events: AuthEvent[] = [];
         service.on(allAuthEvents, (ed) => events.push(ed.event));

         peerResponder.sendForget();

         await new Promise((resolve) => setTimeout(resolve, 50));
         expect(events).toEqual([AuthEvent.Forget]);
      });

      it('forget when not logged in - different user emits forget', async () => {
         primeLocalStorage();
         sessionStorage.setItem('sessionstate', JSON.stringify({
            userId: bytesToBase64(getRandom(cc.USERID_BYTES)),
         }));
         const events: AuthEvent[] = [];
         service.on(allAuthEvents, (ed) => events.push(ed.event));

         peerResponder.sendForget();

         await new Promise((resolve) => setTimeout(resolve, 50));
         expect(events).toEqual([AuthEvent.Forget]);
      });

      it('logout with no session is no action', async () => {
         const events: AuthEvent[] = [];
         service.on(allAuthEvents, (ed) => events.push(ed.event));

         peerResponder.sendLogout({ pkId: pkId, version: 1 });

         await new Promise((resolve) => setTimeout(resolve, 50));
         expect(events).toEqual([]);
      });

      it('logout when not logged in - same user is no action', async () => {
         primeLocalStorage();
         const events: AuthEvent[] = [];
         service.on(allAuthEvents, (ed) => events.push(ed.event));

         peerResponder.sendLogout({ pkId: pkId, version: 1 });

         await new Promise((resolve) => setTimeout(resolve, 50));
         expect(events).toEqual([]);
      });

      it('logout when not logged in - different user is no action', async () => {
         primeLocalStorage();
         sessionStorage.setItem('sessionstate', JSON.stringify({
            userId: bytesToBase64(getRandom(cc.USERID_BYTES)),
         }));
         const events: AuthEvent[] = [];
         service.on(allAuthEvents, (ed) => events.push(ed.event));

         peerResponder.sendLogout({ pkId: pkId, version: 1 });

         await new Promise((resolve) => setTimeout(resolve, 50));
         expect(events).toEqual([]);
      });

      it('login with no session emits forget', async () => {
         const events: AuthEvent[] = [];
         service.on(allAuthEvents, (ed) => events.push(ed.event));

         peerResponder.sendLogin({
            pkId: pkId,
            userCredEnc: 'enc',
            userCredExpiry: peerExpiry,
            version: 1,
         });

         await new Promise((resolve) => setTimeout(resolve, 50));
         expect(events).toEqual([AuthEvent.Forget]);
      });

      it('login when not logged in - same user is no action', async () => {
         primeLocalStorage();
         const events: AuthEvent[] = [];
         service.on(allAuthEvents, (ed) => events.push(ed.event));

         peerResponder.sendLogin({
            pkId: pkId,
            userCredEnc: 'enc',
            userCredExpiry: peerExpiry,
            version: 1,
         });

         await new Promise((resolve) => setTimeout(resolve, 50));
         expect(events).toEqual([]);
      });

      it('login when not logged in - different user emits forget', async () => {
         primeLocalStorage();
         // Simulate sessionStorage preserved from a previous session as a different user.
         sessionStorage.setItem('sessionstate', JSON.stringify({
            userId: bytesToBase64(getRandom(cc.USERID_BYTES)),
         }));
         const events: AuthEvent[] = [];
         service.on(allAuthEvents, (ed) => events.push(ed.event));

         peerResponder.sendLogin({
            pkId: pkId,
            userCredEnc: 'enc',
            userCredExpiry: peerExpiry,
            version: 1,
         });

         await new Promise((resolve) => setTimeout(resolve, 50));
         expect(events).toEqual([AuthEvent.Forget]);
      });
   });
});
