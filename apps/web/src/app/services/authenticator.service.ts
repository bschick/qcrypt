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

import sodium from 'libsodium-wrappers';
import { environment } from '../../environments/environment';
import { Injectable, signal } from '@angular/core';
import {
   PublicKeyCredentialCreationOptionsJSON,
   PublicKeyCredentialRequestOptionsJSON,
   AuthenticationResponseJSON,
   RegistrationResponseJSON,
   startRegistration, startAuthentication
} from '@simplewebauthn/browser';
import { Subject, Subscription, filter } from 'rxjs';
import { DateTime } from 'luxon';
import { base64ToBytes, bytesToBase64, bufferToHexString, expired } from '@qcrypt/crypto';
import { entropyToMnemonic, mnemonicToEntropy, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';

const baseUrl = environment.apiHost;

export const SESSION_TIMEOUT = 60 * 60 * 6;
export const ACTIVITY_TIMEOUT = 60 * 60 * 1.5;
const EXPIRY_INTERVAL = 1000 * 60 * 2;

const RECOVERID_BYTES = 16;

export type AuthenticatorInfo = {
   credentialId: string;
   description: string;
   lightIcon: string;
   darkIcon: string;
   name: string;
};

export type UserInfo = {
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

type ServerUserInfo = {
   verified: boolean;
   userId?: string;
   userName?: string;
   hasRecoveryId?: boolean;
   authenticators?: AuthenticatorInfo[];
};

export type ServerLoginUserInfo = ServerUserInfo & {
   pkId?: string;
   userCred?: string;
   recoveryId?: string;
   csrf?: string;
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

   public userInfo = signal<UserInfo | undefined>(undefined);
   public senderLinks = signal<SenderLinkInfo[]>([]);

   private _subject = new Subject<AuthEventData>();
   private _intervalId: number = 0;
   private _userCred?: Uint8Array = undefined;
   private _csrf?: string = undefined;
   private _cachedRecoveryId?: string;
   public ready: Promise<[void, void]>;

   constructor(
   ) {
      const loadSess = new Promise<void>((resolve) => {
         this.loadSession().catch(
            // just for debugging, remove
            (err) => console.error(err)
         ).finally(
            () => resolve()
         );
      });

      this.ready = Promise.all([loadSess, sodium.ready]);
   }


   // it is possible for "authenticated" to be true and "validaSession"
   // to be false. this happens when another tab logs out or out then in
   // using a different Pk until this tab detects it
   public authenticated(): boolean {
      return !!this._userCred && !!this._csrf;
   }

   public potentialSession(): boolean {
      // Expiry or changed passkey (from another tab) mean invalid sessoin
      // Cookie may still be valid, but we won't use it.
      const globalPKId = localStorage.getItem('pkid');
      const myPKId = sessionStorage.getItem('pkid');
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
      let valid = false;
      const [userId, userName] = this.loadKnownUser();
      if (userId && userName) {
         const globalPKId = localStorage.getItem('pkid');
         const myPKId = sessionStorage.getItem('pkid');
         if (myPKId && (globalPKId === myPKId)) {
            valid = true;
         }
      }
      return valid;
   }

   public loadKnownUser(): [string | null, string | null] {
      return [
         localStorage.getItem('userid'),
         localStorage.getItem('username')
      ];
   }

   public isCurrentPk(testPK: string): boolean {
      return testPK === this.pkId;
   }

   //*** Start: These methods all return authenticated inforomation */

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

   public get userCred(): Uint8Array {
      if (!this.authenticated()) {
         throw new Error('no active user');
      }
      return this._userCred!;
   }

   public getUserInfo(): UserInfo {
      if (!this.authenticated()) {
         throw new Error('no active user');
      }
      return this.userInfo()!;
   }

   //*** End: These methods all return authenticated inforomation */

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
   public async loadSession(): Promise<boolean> {

      if (!this.potentialSession()) {
         return false;
      }
      const serverLoginUserInfo = await this._doFetch<ServerLoginUserInfo>({
         method: 'GET',
         resource: 'session'
      });

      if (!serverLoginUserInfo || !serverLoginUserInfo.verified) {
         return false;
      }

      this._loginUser(serverLoginUserInfo);
      return true;
   }

   // require reauthentication with passkey
   public async getRecoveryWords(): Promise<string> {
      await this.ready;

      if (!this.authenticated()) {
         throw new Error('no active user');
      }

      // only stored during user creation, clear after 1 use
      let recoveryId = this._cachedRecoveryId;
      this._cachedRecoveryId = undefined;

      if (!recoveryId) {
         const verifyBody = await this._startAuth(this.userId);
         const serverLoginUserInfo = await this._doFetch<ServerLoginUserInfo>({
            method: 'POST',
            resource: 'auth/verify',
            bodyJSON: JSON.stringify(verifyBody),
            params: 'recovery=true'
         });

         if (!serverLoginUserInfo || !serverLoginUserInfo.recoveryId) {
            throw new Error('authentication failed');
         }
         recoveryId = serverLoginUserInfo.recoveryId;
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


   lsGet(key: string): string | null {
      if (this.authenticated()) {
         return localStorage.getItem(this.userId + key);
      }
      return null;
   }

   lsSet(key: string, value: string | number | boolean | null): boolean {
      if (value != null && this.authenticated()) {
         localStorage.setItem(this.userId + key, value.toString());
         return true;
      }
      return false;
   }

   lsDel(key: string) {
      if (this.authenticated()) {
         localStorage.removeItem(this.userId + key);
      }
   }

   private _captureEventData(event: AuthEvent): AuthEventData {
      return {
         event: event,
         userId: this.authenticated() ? this.userId : null,
         userName: this.authenticated() ? this.userName : null
      };
   }

   private _emit(eventData: AuthEventData) {
      this._subject.next(eventData);
   }

   private _loginUser(
      serverLogin: ServerLoginUserInfo
   ): UserInfo {
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

      const sessExpiry = DateTime.now().plus({ seconds: SESSION_TIMEOUT }).toISO();

      this._userCred = base64ToBytes(serverLogin.userCred);
      this._csrf = serverLogin.csrf;
      localStorage.setItem('sessionexpiry', sessExpiry);
      localStorage.setItem('userid', serverLogin.userId);
      localStorage.setItem('pkid', serverLogin.pkId);
      sessionStorage.setItem('pkid', serverLogin.pkId);

      const userInfo = this._updateLoggedInUser(serverLogin);
      this._emit(this._captureEventData(AuthEvent.Login));

      return userInfo;
   }

   private _updateLoggedInUser(
      serverUser: ServerUserInfo
   ): UserInfo {

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

      if (!this.authenticated()) {
         throw new Error('no active user');
      }

      const globalPKId = localStorage.getItem('pkid');
      if (!globalPKId) {
         throw new Error('missing passkey id');
      }

      localStorage.setItem('username', serverUser.userName);

      const userInfo: UserInfo = {
         userId: serverUser.userId,
         userName: serverUser.userName,
         pkId: globalPKId,
         hasRecoveryId: serverUser.hasRecoveryId,
         authenticators: serverUser.authenticators
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
      const activityExpiry = DateTime.now().plus({ seconds: ACTIVITY_TIMEOUT }).toISO();
      localStorage.setItem('activityexpiry', activityExpiry);

      // Currently every 2 minutes
      this._intervalId = window.setInterval(() => this._timerTick(), EXPIRY_INTERVAL);
   }

   private _timerTick(): void {
      if (!this.validKnownUser()) {
         // this happens when another tab or windows forgets the user or changes passkey
         // don't do a global forget since other tab are onto a new user
         this.forgetUser(false);
      } else if (!this.potentialSession()) {
         // validSession becomes false if either inactivity time happens in this tab
         // or another. since we are tracking other tabs, this may be a bit annoying
         // but its more conservative (and common) scenario to just have 1 open
         this.logout(true);
      }
   }

   private _deletedUser() {
      const eventData = this._captureEventData(AuthEvent.Delete);
      this.forgetUser(true);
      this._emit(eventData);
   }

   forgetUser(global: boolean) {
      const eventData = this._captureEventData(AuthEvent.Forget);
      this.logout(global, false);
      sessionStorage.clear();
      if (global) {
         localStorage.removeItem('username');
         localStorage.removeItem('userid');
         localStorage.removeItem('pkid');
      }
      this._emit(eventData);
   }

   logout(global: boolean, emit: boolean = true) {
      const eventData = this._captureEventData(AuthEvent.Logout);

      if (global) {
         // let this happen in the background. creates a race condition with next
         // login, but highly unlikley to be an issue since login presents passkey auth
         this._doFetch<string>({
            method: 'DELETE',
            resource: 'session'
         }).catch((err) => {
            // ignore
         });

         // rather than clear values, which can trigger error in other tabs,
         // set expirations to the past to trigger clear self-logout
         const expired = DateTime.now().minus({ seconds: 10 }).toISO();
         localStorage.setItem('activityexpiry', expired);
         localStorage.setItem('sessionexpiry', expired);
      }

      if (this._intervalId) {
         clearInterval(this._intervalId);
         this._intervalId = 0;
      }

      // clear sensitive in-memory values
      this.userInfo.set(undefined);
      if (this._userCred) {
         crypto.getRandomValues(this._userCred);
         this._userCred = undefined;
      }
      this._csrf = undefined;

      if (emit) {
         this._emit(eventData);
      }
   }

   async setPasskeyDescription(
      credentialId: string,
      description: string
   ): Promise<UserInfo> {
      if (!description) {
         throw new Error('missing description');
      }
      if (description.length < 6 || description.length > 42) {
         throw new Error('description must be 6 to 42 characters');
      }
      if (!credentialId) {
         throw new Error('invalid credentialId');
      }
      if (!this.authenticated()) {
         throw new Error('not active user');
      }

      const serverUserInfo = await this._doFetch<ServerUserInfo>({
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

   async setUserName(userName: string): Promise<UserInfo> {
      if (!userName) {
         throw new Error('missing description');
      }
      if (userName.length < 6 || userName.length > 31) {
         throw new Error('user name must be 6 to 31 characters');
      }
      if (!this.authenticated()) {
         throw new Error('not active user');
      }

      const serverUserInfo = await this._doFetch<ServerUserInfo>({
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
      if (!this.authenticated()) {
         throw new Error('not active user');
      }

      const serverUserInfo = await this._doFetch<ServerUserInfo>({
         method: 'DELETE',
         resource: 'passkeys',
         resourceId: credentialId
      });

      if (!serverUserInfo) {
         throw new Error('authentication failed');
      }

      // If we have an unverified response, that was the last PK and the user was deleted
      if (!serverUserInfo.verified) {
         this._deletedUser();
         return 0;
      } else {
         this._updateLoggedInUser(serverUserInfo);
         return serverUserInfo.authenticators!.length;
      }
   }

   async refreshSenderLinks(): Promise<SenderLinkInfo[]> {
      if (!this.authenticated()) {
         throw new Error('not active user');
      }
      /*
            const links = await this.doFetch<SenderLinkInfo[]>(
               `senderlinks?userid=${this._userId}`,
               'GET'
            );
      */
      const links = [
         {
            linkId: '1l23rks34',
            url: 'https://quickcrypt.org/send/1l23rks34',
            description: 'this is for a friend to send stuff',
            otherId: 'l23rknmfwc923jf9',
            otherName: 'nedfered t great',
            send: false,
            receive: true
         },
         {
            linkId: '3LDKFJ)(3',
            url: 'https://quickcrypt.org/send/3LDKFJ3d3',
            description: 'for private comms',
            otherId: 'asdflinf29',
            otherName: 'weston schick',
            send: true,
            receive: false
         }
      ];
      this.senderLinks.set(links);
      return links;
   }


   async refreshUserInfo(): Promise<UserInfo> {
      if (!this.authenticated()) {
         throw new Error('not active user');
      }

      const serverUserInfo = await this._doFetch<ServerUserInfo>({
         method: 'GET',
         resource: 'user',
      });

      if (!serverUserInfo) {
         throw new Error('authentication failed');
      }

      return this._updateLoggedInUser(serverUserInfo);
   }

   // Uses the current stored userId
   async defaultLogin(): Promise<UserInfo> {
      const [userId] = this.loadKnownUser();
      if (!userId) {
         throw new Error('missing local userId, sign in as different user');
      }

      return this.findLogin(userId);
   }

   // If no userId is provided, will present all Passkeys for this domain
   async findLogin(userId: string | null = null): Promise<UserInfo> {

      if (this.authenticated()) {
         throw new Error('must be logged out to log in');
      }

      const verifyBody = await this._startAuth(userId);
      const serverLoginUserInfo = await this._doFetch<ServerLoginUserInfo>({
         method: 'POST',
         resource: 'auth/verify',
         bodyJSON: JSON.stringify(verifyBody),
         params: 'usercred=true'
      });

      if (!serverLoginUserInfo) {
         throw new Error('authentication failed');
      }

      return this._loginUser(serverLoginUserInfo);
   }

   private async _startAuth(
      userId: string | null
   ): Promise<Record<string, any>> {

      // Start the process without userId just doesn't limit authenticator creds
      // so the user can look for an existing credential
      const optionsJson = await this._doFetch<PublicKeyCredentialRequestOptionsJSON>({
         method: 'GET',
         resource: 'auth/options',
         params: userId ? `userid=${userId}` : ''
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

      // Need to return challenge because in some cases it is not bound to
      // a user id when created. The server validates that it created the challenge
      // and the challenge's age. createRecovery controls creation of reocvery words
      // on old account until when it is expicit
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

   async recover2(recoveryWords: string): Promise<UserInfo> {

      const [recoveryId, userId] = this.getRecoveryValues(recoveryWords);
      const optionsJson = await this._doFetch<PublicKeyCredentialCreationOptionsJSON>({
         method: 'POST',
         userId: userId,
         resource: 'recover2',
         resourceId: recoveryId
      });

      const serverLoginUserInfo = await this._finishRegistration(optionsJson, true, false);
      return this._loginUser(serverLoginUserInfo);
   }

   async recover(userId: string, userCred: string): Promise<UserInfo> {

      if (!userId || !userCred) {
         throw new Error('missing userid or usercred');
      }

      const optionsJson = await this._doFetch<PublicKeyCredentialCreationOptionsJSON>({
         method: 'POST',
         userId: userId,
         resource: 'recover',
         resourceId: userCred
      });

      const serverLoginUserInfo = await this._finishRegistration(optionsJson, true, false);
      return this._loginUser(serverLoginUserInfo);
   }

   // Creates new user and first passkey
   async newUser(userName: string): Promise<UserInfo> {
      if (!userName) {
         throw new Error('missing require userName');
      }

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
   async addPasskey(): Promise<UserInfo> {

      if (!this.authenticated()) {
         throw new Error('not active user');
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
   ): Promise<ServerLoginUserInfo> {

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
   ): Promise<ServerLoginUserInfo> {

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
   ): Promise<ServerLoginUserInfo> {

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
         userId: actualB64UserId,
         challenge: optionsJson.challenge,
      }

      let parts = includeUserCred ? ['usercred=true'] : [];
      if (includeRecovery) {
         parts.push('recovery=true');
      }
      const params = parts.join('&');

      const serverLoginUserInfo = await this._doFetch<ServerLoginUserInfo>({
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
