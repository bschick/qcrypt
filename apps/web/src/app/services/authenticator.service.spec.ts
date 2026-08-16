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
import { AuthenticatorService, AuthEvent, type LoginUserInfo } from './authenticator.service';
import { BroadcastService } from './broadcast.service';
import { KEYSTORE_DB_NAME, KeystoreService } from './keystore.service';
import * as cc from '@qcrypt/crypto/consts';
import { base64ToBytes, bytesToBase64, cryptoReady, getRandom } from '@qcrypt/crypto';
import { CHALLENGE_BYTES, RECOVERYID_BYTES, getUserCredPubKey, recoverySecret } from '@qcrypt/api';
import { entropyToMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';

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
   const loadCrypto = () => cryptoReady();

   beforeEach(async () => {
      await cryptoReady();

      pkId = bytesToBase64(getRandom(cc.PKID_MIN_BYTES));
      userId = bytesToBase64(getRandom(cc.USERID_BYTES));
      userCred = bytesToBase64(getRandom(cc.USERCRED_BYTES));
      peerExpiry = new Date(Date.now() + 60 * 60 * 1000).toISOString();

      sessionResponse = {
         verified: true,
         userId,
         userName: 'test-user',
         pkId,
         userCred,
         csrf: 'csrf-token-from-test',
         hasRecoveryId: true,
         prf: false,
         authenticators: [
            {
               credentialId: pkId,
               description: 'Test laptop authenticator',
               lightIcon: 'laptop-light.svg',
               darkIcon: 'laptop-dark.svg',
               name: 'YubiKey 5 NFC',
            },
         ],
      };

      originalFetch = window.fetch;
      fetchMock = vi.fn().mockResolvedValue({
         ok: true,
         json: async () => sessionResponse,
      });
      window.fetch = fetchMock as typeof fetch;

      TestBed.configureTestingModule({
         providers: [{ provide: KEYSTORE_DB_NAME, useValue: 'quickcrypt-authenticator-spec' }],
      });
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

   it('restore is a no-op when no peer responds and no local credential', async () => {
      primeLocalStorage();

      const keystoreSvc = TestBed.inject(KeystoreService);
      const createSpy = vi.spyOn(keystoreSvc, 'create');
      const getSpy = vi.spyOn(keystoreSvc, 'get');
      const events: AuthEvent[] = [];
      service.on(allAuthEvents, (ed) => events.push(ed.event));

      await service._restoreSession(loadCrypto);

      // No userCredEnc (no peer, none in sessionStorage) means getSession cannot be
      // signed, so it is never sent.
      expect(fetchMock).not.toHaveBeenCalled();
      expect(createSpy).not.toHaveBeenCalled();
      expect(getSpy).not.toHaveBeenCalled();
      expect(service.hasSession()).toBe(false);
      expect(events).toEqual([]);
   });

   it('relay login with peer response', async () => {
      primeLocalStorage();

      // A real login first, so the relayed userCredEnc is one this device can decrypt
      // @ts-expect-error — exercising private path
      await service._loginUser(sessionResponse, base64ToBytes(userCred));
      const phase1 = JSON.parse(sessionStorage.getItem('sessionstate')!);
      sessionStorage.clear();
      service.logout(false);

      peerResponder.setCredentialProvider(() => ({
         pkId,
         userCredEnc: phase1.userCredEnc,
         userCredExpiry: peerExpiry,
         version: phase1.version,
      }));

      fetchMock.mockClear();
      const keystoreSvc = TestBed.inject(KeystoreService);
      const createSpy = vi.spyOn(keystoreSvc, 'create');
      const getSpy = vi.spyOn(keystoreSvc, 'get');
      const events: AuthEvent[] = [];
      service.on(allAuthEvents, (ed) => events.push(ed.event));

      await service._restoreSession(loadCrypto);

      expect(createSpy).not.toHaveBeenCalled();
      expect(getSpy).toHaveBeenCalled();
      expect(fetchMock).toHaveBeenCalled();
      expect((fetchMock.mock.calls[0][0] as URL).pathname).toContain('/session');
      expect(service.hasSession()).toBe(true);
      expect(events).toEqual([AuthEvent.Login]);
   });

   it('simulated tab refresh succeeds', async () => {
      primeLocalStorage();

      // @ts-expect-error — exercising private path
      await service._loginUser(sessionResponse, base64ToBytes(userCred));
      const restoredState1 = JSON.parse(sessionStorage.getItem('sessionstate')!);
      const userCredEnc1: string = restoredState1.userCredEnc;
      expect(userCredEnc1).toBeTruthy();

      fetchMock.mockClear();
      const keystoreSvc = TestBed.inject(KeystoreService);
      const createSpy = vi.spyOn(keystoreSvc, 'create');
      const getSpy = vi.spyOn(keystoreSvc, 'get');
      const events: AuthEvent[] = [];
      service.on(allAuthEvents, (ed) => events.push(ed.event));

      await service._restoreSession(loadCrypto);

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
      // @ts-expect-error — exercising private path
      await service._loginUser(sessionResponse, base64ToBytes(userCred));

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
         pkId,
         userCredEnc: userCredEnc1,
         userCredExpiry: peerExpiry,
         version: version1,
      }));

      service.logout(false);
      await service._restoreSession(loadCrypto);

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

   it('restore fails when the server reports a pkId with no local key', async () => {
      primeLocalStorage();

      // @ts-expect-error — exercising private path
      await service._loginUser(sessionResponse, base64ToBytes(userCred));
      const phase1 = JSON.parse(sessionStorage.getItem('sessionstate')!);
      sessionStorage.clear();
      service.logout(false);

      // The server reports a pkId this device has no keystore entry for, so the
      // post-restore decrypt check fails and the session is not restored.
      sessionResponse.pkId = bytesToBase64(getRandom(cc.PKID_MIN_BYTES));
      peerResponder.setCredentialProvider(() => ({
         pkId,
         userCredEnc: phase1.userCredEnc,
         userCredExpiry: peerExpiry,
         version: phase1.version,
      }));

      await service._restoreSession(loadCrypto);

      expect(service.hasSession()).toBe(false);
   });

   it('no restore attempt without a potential session', async () => {
      // no potential session because primeLocalStorage() not called

      const keystoreSvc = TestBed.inject(KeystoreService);
      const createSpy = vi.spyOn(keystoreSvc, 'create');
      const getSpy = vi.spyOn(keystoreSvc, 'get');
      const events: AuthEvent[] = [];
      service.on(allAuthEvents, (ed) => events.push(ed.event));

      await service._restoreSession(loadCrypto);

      expect(fetchMock).not.toHaveBeenCalled();
      expect(createSpy).not.toHaveBeenCalled();
      expect(getSpy).not.toHaveBeenCalled();
      expect(events).toEqual([]);
   });

   describe('account pin', () => {
      async function login(prf: boolean, credB64: string): Promise<void> {
         const response = { ...sessionResponse, prf, userCred: credB64 };
         // @ts-expect-error — exercising private path
         await service._loginUser(response, base64ToBytes(credB64));
      }

      function readPin(): { prf: boolean; userCredPubKey: string } {
         return JSON.parse(localStorage.getItem(`${userId}accountpin`)!);
      }

      it('records the account on first login', async () => {
         primeLocalStorage();
         await login(false, userCred);
         expect(readPin().prf).toBe(false);
         expect(readPin().userCredPubKey).toBe(getUserCredPubKey(base64ToBytes(userCred)));
         expect(service.halted).toBe(false);
      });

      it('halts when a PRF account is later reported as no-PRF', async () => {
         primeLocalStorage();
         await login(true, userCred);
         expect(service.hasSession()).toBe(true);
         expect(service.halted).toBe(false);

         await expect(login(false, userCred)).rejects.toThrow();
         expect(service.halted).toBe(true);
         expect(service.hasSession()).toBe(false);
      });

      it('halts when the account returns a different user credential', async () => {
         primeLocalStorage();
         await login(false, userCred);
         expect(service.halted).toBe(false);

         // Same account and mode, a well formed credential that is not this account's
         const otherCred = bytesToBase64(getRandom(cc.USERCRED_BYTES));
         await expect(login(false, otherCred)).rejects.toThrow();
         expect(service.halted).toBe(true);
      });

      it('halts before adopting a credential offered by a downgraded response', async () => {
         primeLocalStorage();
         await login(true, userCred);
         expect(service.halted).toBe(false);

         const substitute = { ...sessionResponse, prf: false, userCred: bytesToBase64(getRandom(cc.USERCRED_BYTES)) };
         // @ts-expect-error — exercising private path
         await expect(service._resolveUserCred(substitute, null)).rejects.toThrow();
         expect(service.halted).toBe(true);
      });

      it('halts when a user info response flips the account mode', async () => {
         primeLocalStorage();
         await login(true, userCred);
         expect(service.halted).toBe(false);

         const flipped = { ...sessionResponse, prf: false };
         // @ts-expect-error — exercising private path
         expect(() => service._updateLoggedInUser(flipped)).toThrow();
         expect(service.halted).toBe(true);
      });

      it('allows a no-PRF account to gain PRF', async () => {
         primeLocalStorage();
         await login(false, userCred);
         expect(readPin().prf).toBe(false);

         await login(true, userCred);
         expect(service.halted).toBe(false);
         expect(service.hasSession()).toBe(true);
         expect(readPin().prf).toBe(true);
      });

      it('resolves the credential when the account matches', async () => {
         primeLocalStorage();
         await login(false, userCred);

         const response = { ...sessionResponse, prf: false, userCred };
         // @ts-expect-error — exercising private path
         const resolved = await service._resolveUserCred(response, null);
         expect(bytesToBase64(resolved)).toBe(userCred);
         expect(service.halted).toBe(false);
      });

      it('continues recovery when the account matches', async () => {
         primeLocalStorage();
         await login(false, userCred);

         const recoveryWords = entropyToMnemonic(recoverySecret(getRandom(RECOVERYID_BYTES), userId), wordlist);
         const startResp = {
            prf: false,
            challenge: bytesToBase64(getRandom(CHALLENGE_BYTES)),
            userCred,
         };
         fetchMock.mockImplementation((url: URL) => ({
            ok: true,
            json: async () => (url.pathname.endsWith('/recover3') ? startResp : sessionResponse),
         }));

         // Recovery still fails, because the passkey ceremony that follows cannot run
         // here, but only after reaching the step that replaces the passkeys
         await expect(service.recover3(recoveryWords)).rejects.toThrow();
         expect(service.halted).toBe(false);
         const paths = fetchMock.mock.calls.map((call) => (call[0] as URL).pathname);
         expect(paths.some((path) => path.endsWith('/recover/confirm'))).toBe(true);
      });

      it('halts when account is downgraded during recovery', async () => {
         primeLocalStorage();
         await login(true, userCred);
         expect(service.halted).toBe(false);

         const recoveryWords = entropyToMnemonic(recoverySecret(getRandom(RECOVERYID_BYTES), userId), wordlist);
         const startResp = {
            prf: false,
            challenge: bytesToBase64(getRandom(CHALLENGE_BYTES)),
            userCred: bytesToBase64(getRandom(cc.USERCRED_BYTES)),
         };
         fetchMock.mockImplementation((url: URL) => ({
            ok: true,
            json: async () => (url.pathname.endsWith('/recover3') ? startResp : sessionResponse),
         }));

         await expect(service.recover3(recoveryWords)).rejects.toThrow();
         expect(service.halted).toBe(true);
         const paths = fetchMock.mock.calls.map((call) => (call[0] as URL).pathname);
         expect(paths.some((path) => path.endsWith('/recover3'))).toBe(true);
         expect(paths.some((path) => path.endsWith('/recover/confirm'))).toBe(false);
      });

      it('fails without halting when the account mode is absent', async () => {
         primeLocalStorage();
         await login(false, userCred);
         expect(service.halted).toBe(false);

         const noMode: Record<string, unknown> = { ...sessionResponse, userCred };
         delete noMode['prf'];
         // @ts-expect-error — exercising private path
         await expect(service._loginUser(noMode, base64ToBytes(userCred))).rejects.toThrow();
         expect(service.halted).toBe(false);
      });
   });

   describe('session user binding', () => {
      it('refuses a user info response with a different account', async () => {
         primeLocalStorage();
         // @ts-expect-error — exercising private path
         await service._loginUser(sessionResponse, base64ToBytes(userCred));

         const refreshed = await service.refreshUserInfo();
         expect(refreshed.userId).toBe(userId);

         const otherUserId = bytesToBase64(getRandom(cc.USERID_BYTES));
         fetchMock.mockResolvedValue({
            ok: true,
            json: async () => ({ ...sessionResponse, userId: otherUserId }),
         });

         await expect(service.refreshUserInfo()).rejects.toThrow();
         expect(service.userId).toBe(userId);
         expect(service.halted).toBe(false);
      });
   });

   describe('peer message handling', () => {
      it('login with higher version and matching pkId adopts via relay', async () => {
         primeLocalStorage();
         // @ts-expect-error — exercising private path
         await service._loginUser(sessionResponse, base64ToBytes(userCred));
         const phase1 = JSON.parse(sessionStorage.getItem('sessionstate')!);

         fetchMock.mockClear();
         const keystoreSvc = TestBed.inject(KeystoreService);
         const createSpy = vi.spyOn(keystoreSvc, 'create');
         const events: AuthEvent[] = [];
         service.on(allAuthEvents, (ed) => events.push(ed.event));

         peerResponder.setCredentialProvider(() => ({
            pkId,
            userCredEnc: phase1.userCredEnc,
            userCredExpiry: peerExpiry,
            version: phase1.version + 5,
         }));
         peerResponder.sendLogin({
            pkId,
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
         // @ts-expect-error — exercising private path
         await service._loginUser(sessionResponse, base64ToBytes(userCred));
         const phase1 = JSON.parse(sessionStorage.getItem('sessionstate')!);

         fetchMock.mockClear();
         const events: AuthEvent[] = [];
         service.on(allAuthEvents, (ed) => events.push(ed.event));

         peerResponder.sendLogin({
            pkId,
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
         // @ts-expect-error — exercising private path
         await service._loginUser(sessionResponse, base64ToBytes(userCred));
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
         // @ts-expect-error — exercising private path
         await service._loginUser(sessionResponse, base64ToBytes(userCred));
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
         // @ts-expect-error — exercising private path
         await service._loginUser(sessionResponse, base64ToBytes(userCred));
         const phase1 = JSON.parse(sessionStorage.getItem('sessionstate')!);
         const events: AuthEvent[] = [];
         service.on(allAuthEvents, (ed) => events.push(ed.event));

         peerResponder.sendLogout({ pkId, version: phase1.version });

         await new Promise((resolve) => setTimeout(resolve, 50));
         expect(service.hasSession()).toBe(false);
         expect(events).toEqual([AuthEvent.Logout]);
      });

      it('logout with version < local is ignored', async () => {
         primeLocalStorage();
         // @ts-expect-error — exercising private path
         await service._loginUser(sessionResponse, base64ToBytes(userCred));
         const phase1 = JSON.parse(sessionStorage.getItem('sessionstate')!);
         const events: AuthEvent[] = [];
         service.on(allAuthEvents, (ed) => events.push(ed.event));

         fetchMock.mockClear();
         peerResponder.sendLogout({ pkId, version: phase1.version - 1 });

         await new Promise((resolve) => setTimeout(resolve, 50));
         expect(fetchMock).not.toHaveBeenCalled();
         expect(service.hasSession()).toBe(true);
         expect(events).toEqual([]);
      });

      it('forget triggers local forget', async () => {
         primeLocalStorage();
         // @ts-expect-error — exercising private path
         await service._loginUser(sessionResponse, base64ToBytes(userCred));
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
         // @ts-expect-error — exercising private path
         await service._loginUser(sessionResponse, base64ToBytes(userCred));

         fetchMock.mockClear();

         peerResponder.sendUserInfoChanged({ pkId });

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
         sessionStorage.setItem(
            'sessionstate',
            JSON.stringify({
               userId: bytesToBase64(getRandom(cc.USERID_BYTES)),
            }),
         );
         const events: AuthEvent[] = [];
         service.on(allAuthEvents, (ed) => events.push(ed.event));

         peerResponder.sendForget();

         await new Promise((resolve) => setTimeout(resolve, 50));
         expect(events).toEqual([AuthEvent.Forget]);
      });

      it('logout with no session is no action', async () => {
         const events: AuthEvent[] = [];
         service.on(allAuthEvents, (ed) => events.push(ed.event));

         peerResponder.sendLogout({ pkId, version: 1 });

         await new Promise((resolve) => setTimeout(resolve, 50));
         expect(events).toEqual([]);
      });

      it('logout when not logged in - same user is no action', async () => {
         primeLocalStorage();
         const events: AuthEvent[] = [];
         service.on(allAuthEvents, (ed) => events.push(ed.event));

         peerResponder.sendLogout({ pkId, version: 1 });

         await new Promise((resolve) => setTimeout(resolve, 50));
         expect(events).toEqual([]);
      });

      it('logout when not logged in - different user is no action', async () => {
         primeLocalStorage();
         sessionStorage.setItem(
            'sessionstate',
            JSON.stringify({
               userId: bytesToBase64(getRandom(cc.USERID_BYTES)),
            }),
         );
         const events: AuthEvent[] = [];
         service.on(allAuthEvents, (ed) => events.push(ed.event));

         peerResponder.sendLogout({ pkId, version: 1 });

         await new Promise((resolve) => setTimeout(resolve, 50));
         expect(events).toEqual([]);
      });

      it('login with no session emits forget', async () => {
         const events: AuthEvent[] = [];
         service.on(allAuthEvents, (ed) => events.push(ed.event));

         peerResponder.sendLogin({
            pkId,
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
            pkId,
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
         sessionStorage.setItem(
            'sessionstate',
            JSON.stringify({
               userId: bytesToBase64(getRandom(cc.USERID_BYTES)),
            }),
         );
         const events: AuthEvent[] = [];
         service.on(allAuthEvents, (ed) => events.push(ed.event));

         peerResponder.sendLogin({
            pkId,
            userCredEnc: 'enc',
            userCredExpiry: peerExpiry,
            version: 1,
         });

         await new Promise((resolve) => setTimeout(resolve, 50));
         expect(events).toEqual([AuthEvent.Forget]);
      });
   });
});
