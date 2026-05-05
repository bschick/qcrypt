/* MIT License

Copyright (c) 2025 Brad Schick

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

import { environment } from '../../environments/environment';
import { Injectable, afterNextRender, signal } from '@angular/core';
import {
   PublicKeyCredentialCreationOptionsJSON,
   PublicKeyCredentialRequestOptionsJSON,
   AuthenticationResponseJSON,
   RegistrationResponseJSON,
   startRegistration, startAuthentication
} from '@simplewebauthn/browser';
import { Subject, Subscription, filter } from 'rxjs';
import {
   base64ToBytes,
   bytesToBase64,
   bufferToHexString,
   expired,
   cryptoReady,
   zxcvbnReady,
   streamFromBase64,
   MasterKeyKeyProvider,
   readStreamAll } from '@qcrypt/crypto';
import { entropyToMnemonic, mnemonicToEntropy, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';

const baseUrl = environment.apiHost;

export const SESSION_TIMEOUT = 60 * 60 * 6;
export const ACTIVITY_TIMEOUT = 60 * 60 * 1.5;
const EXPIRY_CHECK_INTERVAL = 1000 * 60 * 2;
const RECOVERID_BYTES = 16;

import type { ResponseTypes } from '@qcrypt/api';
import { KeystoreService } from './keystore.service';
import { CipherService } from './cipher.service';
export type AuthenticatorInfo = ResponseTypes.AuthenticatorInfo;
export type UserInfo = ResponseTypes.UserInfo;
export type LoginUserInfo = ResponseTypes.LoginUserInfo;
export type InvitableInfo = ResponseTypes.InvitableInfo;

export type VerifiedUserInfo = {
   userId: string;
   userName: string;
   pkId: string;
   hasRecoveryId: boolean;
   authenticators: AuthenticatorInfo[];
};

type FetchArgs = {
   method: 'GET' | 'POST' | 'DELETE' | 'PUT' | 'PATCH';
   resource?: string;
   userId?: string | null;
   resourceId?: string;
   params?: string;
   bodyJSON?: string;
}

type SessionState = {
   pkId: string;
   userCredEnc?: string;
};


export type SenderLinkInfo = {
   linkId: string;
   url: string;
   description: string;
   otherId: string;
   otherName: string;
   send: boolean;
   receive: boolean;
};

export enum AuthEvent {
   Login,
   Logout,
   Forget,
   Delete
};

export type AuthEventData = {
   readonly event: AuthEvent,
   readonly userId: string | null,
   readonly userName: string | null,
};

@Injectable({
   providedIn: 'root'
})
export class AuthenticatorService {

   public userInfo = signal<VerifiedUserInfo | undefined>(undefined);
   public ready: Promise<void>;

   private _subject = new Subject<AuthEventData>();
   private _intervalId: number = 0;
   private _csrf?: string = undefined;
   private _cachedRecoveryId?: string;
   private _pendingLogout: Promise<unknown> = Promise.resolve();

   constructor(
      private _keystoreSvc: KeystoreService,
      private _cipherSvc: CipherService,
   ) {
      this.ready = new Promise<void>((resolve) => {
         this.restoreSession().catch(
            // just for debugging, remove
            (err) => console.error(err)
         ).finally(() => resolve());
      });

      // Warm crypto and zxcvbn after first render so their chunks don't
      // compete with LCP.
      afterNextRender(() => {
         const kickoff = () => {
            cryptoReady().catch((err) => console.error(err));
            zxcvbnReady().catch((err) => console.error(err));
         };
         if (typeof window.requestIdleCallback === 'function') {
            window.requestIdleCallback(kickoff, { timeout: 2000 });
         } else {
            kickoff();
         }
      });
   }


   // it is possible for "hasSession" to be true and "potentialSession"
   // to be false. this happens when another tab logs out, or out then in,
   // using a different Pk until this tab detects it
   public hasSession(): boolean {
      return !!this._getSessionState()?.userCredEnc
         && !!this._csrf
         && !!this.userInfo();
   }

   public potentialSession(): boolean {
      // Expiry or changed passkey (from another tab) mean invalid sessoin
      // Cookie may still be valid, but we won't use it.
      const globalPKId = localStorage.getItem('pkid');
      const myPKId = this._getSessionState()?.pkId;
      const sessionExpired = expired(localStorage, 'sessionexpiry');
      const activityExpired = expired(localStorage, 'activityexpiry');
      const [userId, userName] = this.loadKnownUser();

      const valid = !(
         !globalPKId ||
         (myPKId && (globalPKId !== myPKId)) ||
         sessionExpired ||
         activityExpired ||
         !userId || !userName
      );
      return valid;
   }

   public validKnownUser(): boolean {
      const [userId, userName] = this.loadKnownUser();
      if (userId && userName) {
         const globalPKId = localStorage.getItem('pkid');
         const myPKId = this._getSessionState()?.pkId;
         if (globalPKId &&
            ((globalPKId === myPKId) || !myPKId)) {
            return true;
         }
      }
      return false;
   }

   public loadKnownUser(): [string | null, string | null] {
      return [
         localStorage.getItem('userid'),
         localStorage.getItem('username')
      ];
   }

   private _getSessionState(): SessionState | null {
      const raw = sessionStorage.getItem('sessionstate');
      return raw ? JSON.parse(raw) : null;
   }

   public isCurrentPk(testPK: string): boolean {
      return testPK === this.pkId;
   }

   //*** Start: These methods all return authenticated information */

   public get userName(): string {
      return this.getUserInfo().userName;
   }

   public get userId(): string {
      return this.getUserInfo().userId;
   }

   public hasRecoveryId(): boolean {
      return this.getUserInfo().hasRecoveryId;
   }

   public get pkId(): string {
      return this.getUserInfo().pkId;
   }

   // Callers MUST overwrite returned value ASAP
   public async getUserCred(): Promise<Uint8Array<ArrayBuffer>> {
      const session = this._getSessionState();
      if (!session?.userCredEnc) {
         throw new Error('no active user');
      }

      const masterKey = await this._keystoreSvc.get('user-cred-key', session.pkId);
      if (!masterKey) {
         throw new Error('no active user');
      }

      // Keyprovider takes ownership of masterkey and decryptStream takes ownership of keyprovider.
      // The caller of getUserCred still needs to overwrite the returned userCred ASAP
      const keyProvider = new MasterKeyKeyProvider(masterKey, this.userId);
      try {
         // This will fail if another tab has logged in with a different pkID (for any userId)
         const clearStream = await this._cipherSvc.decryptStream(streamFromBase64(session.userCredEnc), keyProvider);
         return await readStreamAll(clearStream);
      } catch {
         this.logout(false);
         throw new Error('credentials are stale');
      }
   }

   public getUserInfo(): VerifiedUserInfo {
      if (!this.hasSession()) {
         throw new Error('no active user');
      }
      return this.userInfo()!;
   }

   //*** End: These methods all return authenticated information */

   private async _doFetch<T>(
      args: FetchArgs
   ): Promise<T> {
      const {
         method,
         userId,
         resource,
         resourceId,
         params,
         bodyJSON
      } = args;

      const headers = new Headers({
         'Content-Type': 'application/json',
         'x-csrf-token': this._csrf!
      });

      // required for AWS OAC (access control to lambda).
      if (method === 'PUT' || method === 'POST' || method === 'PATCH') {
         const bodyData = new TextEncoder().encode(bodyJSON ?? '');
         const hash = await crypto.subtle.digest("SHA-256", bodyData);
         headers.append('x-amz-content-sha256', bufferToHexString(hash));
      }

      let path = `${environment.apiVersion}`;
      path += userId ? `/users/${userId}` : '';
      path += resource ? `/${resource}` : '';
      path += resourceId ? `/${resourceId}` : '';
      path += params ? `?${params}` : '';

      const url = new URL(path, baseUrl);
      try {
         var response = await fetch(url, {
            method: method,
            mode: 'cors',
            cache: 'no-store',
            credentials: 'include',
            body: bodyJSON,
            headers: headers
         });
      } catch (err) {
         console.error(err);
         throw new Error('fetch error: ' + url);
      }

      if (!response.ok) {
         if (response.status == 401) {
            // currently 401 only comes back when auth failed, so logout
            // make sure to pass false to deleteSession to avoid doFetch loop
            this.logout(false);
            throw new Error('logged out');
         } else {
            throw new Error('response error: ' + await response.text());
         }
      }

      return response.json() as T;
   }

   // does not recieve cookies, downloads user data again
   public async restoreSession(): Promise<boolean> {
      if (!this.potentialSession()) {
         return false;
      }
      const serverLoginUserInfo = await this._doFetch<LoginUserInfo>({
         method: 'GET',
         resource: 'session'
      });

      if (!serverLoginUserInfo || !serverLoginUserInfo.verified) {
         return false;
      }

      await this._loginUser(serverLoginUserInfo);
      return true;
   }

   // require reauthentication with passkey
   public async getRecoveryWords(): Promise<string> {
      await this.ready;

      if (!this.hasSession()) {
         throw new Error('no active user');
      }

      // only stored during user creation, clear after 1 use
      let recoveryId = this._cachedRecoveryId;
      this._cachedRecoveryId = undefined;

      if (!recoveryId) {
         const serverLoginUserInfo = await this._createSessionImpl(true, true, this.userId);
         if (!serverLoginUserInfo.recoveryId) {
            throw new Error('authentication failed');
         }

         // must call loginUser since fetch above changes csrf
         recoveryId = serverLoginUserInfo.recoveryId;
         await this._loginUser(serverLoginUserInfo);
      }

      const recoveryIdBytes = base64ToBytes(recoveryId);
      if (recoveryIdBytes.byteLength != RECOVERID_BYTES) {
         throw new Error('invalid recovery id length');
      }

      const userIdBytes = base64ToBytes(this.userId);

      let recoveryBytes = new Uint8Array(recoveryIdBytes.byteLength + userIdBytes.byteLength);
      recoveryBytes.set(recoveryIdBytes, 0);
      recoveryBytes.set(userIdBytes, recoveryIdBytes.byteLength);

      return entropyToMnemonic(recoveryBytes, wordlist);
   }

   on(events: AuthEvent[], action: (data: AuthEventData) => void): Subscription {
      return this._subject.pipe(
         filter((ed: AuthEventData) => events.includes(ed.event))
      ).subscribe(action);
   }

   private _captureEventData(event: AuthEvent): AuthEventData {
      return {
         event: event,
         userId: this.hasSession() ? this.userId : null,
         userName: this.hasSession() ? this.userName : null
      };
   }

   private _emit(eventData: AuthEventData) {
      this._subject.next(eventData);
   }

   private async _loginUser(
      serverLogin: LoginUserInfo
   ): Promise<VerifiedUserInfo> {
      if (!serverLogin.userId || serverLogin.userId.length == 0) {
         throw new Error('invalid user id')
      }
      if (!serverLogin.userCred || serverLogin.userCred.length == 0) {
         throw new Error('invalid user credential')
      }
      if (!serverLogin.pkId || serverLogin.pkId.length == 0) {
         throw new Error('invalid passkey id')
      }
      if (!serverLogin.csrf || serverLogin.csrf.length == 0) {
         throw new Error('invalid csrf token')
      }

      const masterKey = await this._keystoreSvc.create('user-cred-key', serverLogin.pkId);
      if (!masterKey) {
         throw new Error('no active user');
      }

      // Keyprovider takes ownership of masterkey and encryptStream takes ownership of keyprovider
      const keyProvider = new MasterKeyKeyProvider(masterKey, serverLogin.userId);
      const cipherData = await readStreamAll(
         await this._cipherSvc.encryptStream(
            streamFromBase64(serverLogin.userCred),
            keyProvider,
            { algs: ['X20-PLY'] }
         )
      );
      const session: SessionState = {
         pkId: serverLogin.pkId,
         userCredEnc: bytesToBase64(cipherData)
      };
      sessionStorage.setItem('sessionstate', JSON.stringify(session));

      const sessExpiry = new Date(Date.now() + SESSION_TIMEOUT * 1000).toISOString();
      this._csrf = serverLogin.csrf;
      localStorage.setItem('sessionexpiry', sessExpiry);
      localStorage.setItem('userid', serverLogin.userId);
      localStorage.setItem('pkid', serverLogin.pkId);

      const userInfo = this._updateLoggedInUser(serverLogin);
      this._emit(this._captureEventData(AuthEvent.Login));

      return userInfo;
   }

   private _updateLoggedInUser(
      serverUser: UserInfo
   ): VerifiedUserInfo {
      if (!serverUser.verified) {
         throw new Error('unverified user');
      }
      if (!serverUser.userId || !serverUser.userName) {
         throw new Error('missing userId or userName');
      }
      if (!serverUser.authenticators || serverUser.authenticators.length == 0) {
         throw new Error('missing authenticators');
      }
      if (serverUser.hasRecoveryId === undefined) {
         throw new Error('missing recovery id info');
      }

      const session = this._getSessionState();
      if (!session) {
         throw new Error('no active user');
      }

      localStorage.setItem('username', serverUser.userName);

      // TODO (CHANGED, but keeping comment during testing):
      // The logic behind setting to globalPKId seems wrong. If in another tab a
      // new user or new pkID for the current user is the current globalPKId, then
      // that is injected into current userInfo, which seems wrong. Seems like
      // this should be storing sessionStorage pkID and if that doesn't agree
      // with global this user will be logged out by the timer tick. Although,
      // that situation is unlikely because _updateLoggedInUser is preceeded by
      // server calls which would return failure if our pkID and CSRF are out of date.
      const userInfo: VerifiedUserInfo = {
         userId: serverUser.userId!,
         userName: serverUser.userName!,
         pkId: session.pkId,
         hasRecoveryId: serverUser.hasRecoveryId!,
         authenticators: serverUser.authenticators!
      };

      this.userInfo.set(userInfo);
      this.activity();
      return userInfo;
   }

   activity() {
      if (this._intervalId) {
         clearInterval(this._intervalId);
         this._intervalId = 0;
      }

      // Currently 1.5 hours inactivity expritation
      const activityExpiry = new Date(Date.now() + ACTIVITY_TIMEOUT * 1000).toISOString();
      localStorage.setItem('activityexpiry', activityExpiry);

      // Currently every 2 minutes
      this._intervalId = window.setInterval(() => this._timerTick(), EXPIRY_CHECK_INTERVAL);
   }

   private _timerTick(): void {
      if (!this.validKnownUser()) {
         // this happens when another tab or windows forgets the user or changes passkey.
         // don't do a global forget user since other tab could have a valid session
         this.forgetUser(false);
      } else if (!this.potentialSession()) {
         // potentialSession becomes false if either inactivity timer expires in this tab
         // or another. since we are tracking other tabs, this may be a bit annoying
         // but its more conservative, and having multiple tabs open is less common
         this.logout(true);
      }
   }

   private _deletedUser() {
      const eventData = this._captureEventData(AuthEvent.Delete);
      // kill other tab sessions
      this.forgetUser(true);
      this._emit(eventData);
   }

   forgetUser(global: boolean) {
      const eventData = this._captureEventData(AuthEvent.Forget);
      this.logout(global, false);
      // Don't clear sessionStorage for non-global logout because we want to
      // prevent a page from surprisingly refreshing to another user or passkey
      if (global) {
         localStorage.removeItem('username');
         localStorage.removeItem('userid');
         localStorage.removeItem('pkid');
         sessionStorage.clear();
      }
      this._emit(eventData);
   }

   logout(global: boolean, emit: boolean = true) {
      const eventData = this._captureEventData(AuthEvent.Logout);

      if (global) {
         // Avoid trampling _pendingLogout by firing multiple DELETE's.
         // They are noops when already logged out anyway.
         if (this.hasSession()) {
            this._pendingLogout = this._doFetch<string>({
               method: 'DELETE',
               resource: 'session'
            }).catch(() => undefined);
         }

         // rather than clear values, which can trigger error in other tabs,
         // set expirations to the past to trigger clear self-logout
         const expired = new Date(Date.now() - 10000).toISOString();
         localStorage.setItem('activityexpiry', expired);
         localStorage.setItem('sessionexpiry', expired);
         this._keystoreSvc.delete('user-cred-key');
      }

      if (this._intervalId) {
         clearInterval(this._intervalId);
         this._intervalId = 0;
      }

      this.userInfo.set(undefined);
      // Preserve pkId so this tab refuses to auto-resume a different user's
      // session.
      const session = this._getSessionState();
      if (session?.pkId) {
         sessionStorage.setItem('sessionstate', JSON.stringify({ pkId: session.pkId }));
      } else {
         sessionStorage.removeItem('sessionstate');
      }

      // clear sensitive in-memory values
      this._csrf = undefined;
      this._cachedRecoveryId = undefined;

      if (emit) {
         this._emit(eventData);
      }
   }

   async setPasskeyDescription(
      credentialId: string,
      description: string
   ): Promise<VerifiedUserInfo> {
      if (!description) {
         throw new Error('missing description');
      }
      if (description.length < 6 || description.length > 42) {
         throw new Error('description must be 6 to 42 characters');
      }
      if (!credentialId) {
         throw new Error('invalid credentialId');
      }
      if (!this.hasSession()) {
         throw new Error('no active user');
      }

      const serverUserInfo = await this._doFetch<UserInfo>({
         method: 'PATCH',
         resource: 'passkeys',
         resourceId: credentialId,
         bodyJSON: JSON.stringify({ description: description })
      });

      if (!serverUserInfo) {
         throw new Error('authentication failed');
      }

      return this._updateLoggedInUser(serverUserInfo);
   }

   async setUserName(userName: string): Promise<VerifiedUserInfo> {
      if (!userName) {
         throw new Error('missing description');
      }
      if (userName.length < 6 || userName.length > 31) {
         throw new Error('user name must be 6 to 31 characters');
      }
      if (!this.hasSession()) {
         throw new Error('no active user');
      }

      const serverUserInfo = await this._doFetch<UserInfo>({
         method: 'PATCH',
         resource: 'user',
         bodyJSON: JSON.stringify({ userName: userName })
      });

      if (!serverUserInfo) {
         throw new Error('authentication failed');
      }

      return this._updateLoggedInUser(serverUserInfo);
   }

   async deletePasskey(credentialId: string): Promise<number> {
      if (!credentialId) {
         throw new Error('invalid credentialId');
      }
      if (!this.hasSession()) {
         throw new Error('no active user');
      }

      const wasCurrentPk = this.isCurrentPk(credentialId);

      const serverUserInfo = await this._doFetch<UserInfo>({
         method: 'DELETE',
         resource: 'passkeys',
         resourceId: credentialId
      });

      if (!serverUserInfo) {
         throw new Error('authentication failed');
      }

      // Unverified response means that was the last PK and the user was deleted.
      // If the user is still valid but we deleted our own current PK, the server
      // invalidated our session so sign out locally.
      if (!serverUserInfo.verified) {
         this._deletedUser();
         return 0;
      } else if (wasCurrentPk) {
         this.logout(true);
      } else {
         this._updateLoggedInUser(serverUserInfo);
      }

      return serverUserInfo.authenticators!.length;
   }

   async refreshUserInfo(): Promise<VerifiedUserInfo> {
      if (!this.hasSession()) {
         throw new Error('no active user');
      }

      const serverUserInfo = await this._doFetch<UserInfo>({
         method: 'GET',
         resource: 'user',
      });

      if (!serverUserInfo) {
         throw new Error('authentication failed');
      }

      return this._updateLoggedInUser(serverUserInfo);
   }

   async getInvitableInfo(invitableId: string): Promise<InvitableInfo> {
      if (!this.hasSession()) {
         throw new Error('no active user');
      }

      const invitableInfo = await this._doFetch<InvitableInfo>({
         method: 'GET',
         resource: 'invitables',
         resourceId: invitableId
      });

      if (!invitableInfo) {
         throw new Error('missing invitable');
      }

      return invitableInfo;
   }

   // Uses the current stored userId
   async createDefaultSession(): Promise<VerifiedUserInfo> {
      const [userId] = this.loadKnownUser();
      if (!userId) {
         throw new Error('missing local userId, sign in as different user');
      }

      return this.createSession(userId);
   }

   async createSession(userId: string | null = null): Promise<VerifiedUserInfo> {
      if (this.hasSession()) {
         throw new Error('must be logged out to log in');
      }

      await this._pendingLogout;
      const serverLoginUserInfo = await this._createSessionImpl(true, false, userId);
      return this._loginUser(serverLoginUserInfo);
   }

   // If no userId is provided, will present all Passkeys for this domain
   private async _createSessionImpl(
      includeUserCred: boolean,
      includeRecovery: boolean,
      userId: string | null = null
   ): Promise<LoginUserInfo> {
      const parts = includeUserCred ? ['usercred=true'] : [];
      if (includeRecovery) {
         parts.push('recovery=true');
      }
      const params = parts.join('&');

      const verifyBody = await this._startAuth(userId);
      const serverLoginUserInfo = await this._doFetch<LoginUserInfo>({
         method: 'POST',
         resource: 'auth/verify',
         bodyJSON: JSON.stringify(verifyBody),
         params: params
      });

      if (!serverLoginUserInfo) {
         throw new Error('authentication failed');
      }

      return serverLoginUserInfo;
   }

   private async _startAuth(
      userId: string | null
   ): Promise<Record<string, any>> {
      // Start the process without userId just doesn't limit authenticator creds
      // so the user can look for an existing credential
      const optionsJson = await this._doFetch<PublicKeyCredentialRequestOptionsJSON>({
         method: 'POST',
         resource: 'auth/options',
         bodyJSON: JSON.stringify({ userId: userId })
      });

      let startAuth: AuthenticationResponseJSON;
      try {
         startAuth = await startAuthentication({
            optionsJSON: optionsJson,
            useBrowserAutofill: false
         });
      } catch (err) {
         console.error('startAuthentication', err);
         throw err;
      }

      // SimpleWebAuthn v10 caused incompatibility with older versions by
      // decoding credential user.id to b64 rather than utf as older versions
      // We therefore need to translate.
      const handleBytes = base64ToBytes(startAuth.response.userHandle!);
      startAuth.response.userHandle = new TextDecoder("utf-8").decode(handleBytes);

      // Need to return challenge for server lookup w/o userId
      return {
         ...startAuth,
         challenge: optionsJson.challenge
      };
   }

   getRecoveryValues(recoveryWords: string): [string, string] {

      if (!recoveryWords || recoveryWords.length == 0) {
         throw new Error('missing recovery words');
      }

      if (!validateMnemonic(recoveryWords, wordlist)) {
         throw new Error('invalid recovery words');
      }

      const recoveryBytes = mnemonicToEntropy(recoveryWords, wordlist);
      if (!recoveryBytes || recoveryBytes.byteLength < RECOVERID_BYTES + 1) {
         throw new Error('invalid recovery id');
      }

      const recoveryIdBytes = new Uint8Array(recoveryBytes.buffer, 0, RECOVERID_BYTES);
      const userIdBytes = new Uint8Array(recoveryBytes.buffer, RECOVERID_BYTES);
      if (recoveryIdBytes.byteLength != RECOVERID_BYTES) {
         throw new Error('invalid recovery id length ' + recoveryIdBytes.byteLength);
      }

      const recoveryId = bytesToBase64(recoveryIdBytes);
      const userId = bytesToBase64(userIdBytes);

      return [recoveryId, userId];
   }

   async recover2(recoveryWords: string): Promise<VerifiedUserInfo> {

      const [recoveryId, userId] = this.getRecoveryValues(recoveryWords);
      await this._pendingLogout;
      const optionsJson = await this._doFetch<PublicKeyCredentialCreationOptionsJSON>({
         method: 'POST',
         resource: 'recover2',
         bodyJSON: JSON.stringify({ userId: userId, recoveryId: recoveryId })
      });

      const serverLoginUserInfo = await this._finishRegistration(optionsJson, true, false);
      return this._loginUser(serverLoginUserInfo);
   }

   async recover(userId: string, userCred: string): Promise<VerifiedUserInfo> {

      if (!userId || !userCred) {
         throw new Error('missing userid or usercred');
      }

      await this._pendingLogout;
      const optionsJson = await this._doFetch<PublicKeyCredentialCreationOptionsJSON>({
         method: 'POST',
         resource: 'recover',
         bodyJSON: JSON.stringify({ userId: userId, userCred: userCred })
      });

      const serverLoginUserInfo = await this._finishRegistration(optionsJson, true, false);
      return this._loginUser(serverLoginUserInfo);
   }

   // Creates new user and first passkey
   async newUser(userName: string): Promise<VerifiedUserInfo> {
      if (!userName) {
         throw new Error('missing require userName');
      }

      await this._pendingLogout;
      const optionsJson = await this._doFetch<PublicKeyCredentialCreationOptionsJSON>({
         method: 'POST',
         resource: 'reg/options',
         bodyJSON: JSON.stringify({ userName: userName })
      });

      const serverLoginUserInfo = await this._finishRegistration(optionsJson, true, true);

      // New user creation temporarily caches _recoveryId for use in the recovery word
      // display page that immediately follows.
      if (!serverLoginUserInfo || !serverLoginUserInfo.recoveryId) {
         throw new Error('missing recoveryId');
      }
      this._cachedRecoveryId = serverLoginUserInfo.recoveryId;

      return this._loginUser(serverLoginUserInfo);
   }

   // Adds passkey to current user
   async addPasskey(): Promise<VerifiedUserInfo> {

      if (!this.hasSession()) {
         throw new Error('no active user');
      }

      const optionsJson = await this._doFetch<PublicKeyCredentialCreationOptionsJSON>({
         method: 'GET',
         resource: 'passkeys/options'
      });

      const serverLoginUserInfo = await this._passkeyVerify(optionsJson, false, false);
      return this._updateLoggedInUser(serverLoginUserInfo);
   }

   private async _passkeyVerify(
      optionsJson: PublicKeyCredentialCreationOptionsJSON,
      includeUserCred: boolean,
      includeRecovery: boolean
   ): Promise<LoginUserInfo> {

      return this._doPasskeyVerify(
         'passkeys',
         optionsJson,
         includeUserCred,
         includeRecovery
      );
   }

   private async _finishRegistration(
      optionsJson: PublicKeyCredentialCreationOptionsJSON,
      includeUserCred: boolean,
      includeRecovery: boolean
   ): Promise<LoginUserInfo> {

      return this._doPasskeyVerify(
         'reg',
         optionsJson,
         includeUserCred,
         includeRecovery
      );
   }

   private async _doPasskeyVerify(
      base: string,
      optionsJson: PublicKeyCredentialCreationOptionsJSON,
      includeUserCred: boolean,
      includeRecovery: boolean
   ): Promise<LoginUserInfo> {

      // SimpleWebAuthn v10 caused incompatibility with older versions by
      // encoding credential user.id as b64 rather than utf as older versions
      // We therefore need to translate.
      const actualB64UserId = optionsJson.user.id;
      const idBytes = new TextEncoder().encode(optionsJson.user.id);
      optionsJson.user.id = bytesToBase64(idBytes);

      let startReg: RegistrationResponseJSON;
      try {
         startReg = await startRegistration({ optionsJSON: optionsJson });
      } catch (err) {
         console.error('startRegistration', err);
         throw err;
      }

      // Need to return challenge because in some cases it is not bound
      // to a user when created. The server validates it created the challenge
      // and its age.
      // Also, seems odd the userHandle isn't returned from .create
      const expanded = {
         ...startReg,
         // To maintain compatibility with old clients, need to put this
         // back to actual b64Url rather than b64ofUT8BytesofBase64... argg
         // UserId is ignored by server for passkeys/verify
         userId: actualB64UserId,
         challenge: optionsJson.challenge,
      }

      const parts = includeUserCred ? ['usercred=true'] : [];
      if (includeRecovery) {
         parts.push('recovery=true');
      }
      const params = parts.join('&');

      const serverLoginUserInfo = await this._doFetch<LoginUserInfo>({
         method: 'POST',
         resource: base + '/verify',
         bodyJSON: JSON.stringify(expanded),
         params: params
      });

      if (!serverLoginUserInfo) {
         throw new Error('registration failed');
      }

      return serverLoginUserInfo;
   }
}
