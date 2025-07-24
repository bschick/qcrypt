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
import { base64ToBytes, bytesToBase64, expired } from './utils';
import { entropyToMnemonic, mnemonicToEntropy, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';

const baseUrl = environment.domain;

export const SESSION_TIMEOUT = 60 * 60 * 6;
//export const ACTIVITY_TIMEOUT = 60 * 10;
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

type ServerUserInfo = {
   verified: boolean;
   userId?: string;
   userName?: string;
   hasRecoveryId?: boolean;
   authenticators?: AuthenticatorInfo[];
};

type ServerLoginUserInfo = ServerUserInfo & {
   pkId?: string;
   userCred?: string;
   recoveryId?: string;
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
   private _userCred?: string = undefined;
   public ready: Promise<void>;

   constructor(
   ) {
      this.ready = new Promise<void>((resolve) => {
         this.loadSession().catch(
            // just for debugging, remove
            (err) => console.error(err)
         ).finally(
            () => resolve()
         );
      });
   }

   // it is possible for "authenticated" to be true and "validaSession"
   // to be false. this happens when another tab logs out or out then in
   // using a different Pk until this tab detects it
   public authenticated(): boolean {
      return !!this._userCred;
   }

   public validSession(): boolean {
      // Expiry or changed passkey (from another tab) mean invalid sessoin
      // Cookie may still be valid, but we won't use it.
      const globalPKId = localStorage.getItem('pkid');
      const myPKId = sessionStorage.getItem('pkid');
      const sessionExpired = expired(localStorage, 'sessionexpiry');
      const activityExpired = expired(localStorage, 'activityexpiry');

      return !(
         !globalPKId ||
         (myPKId && (globalPKId !== myPKId)) ||
         sessionExpired ||
         activityExpired
      );
   }

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

   public isCurrentPk(testPK: string): boolean {
      return testPK === this.pkId;
   }

   public get userCred(): string {
      if (!this.authenticated()) {
         throw new Error('no active user');
      }
      return this._userCred!;
   }

   public isUserKnown(): boolean {
      const [userId, userName] = this.loadKnownUser();
      return userId != null && userName != null;
   }

   public loadKnownUser(): [string | null, string | null] {
      const userId = localStorage.getItem('userid');
      const userName = localStorage.getItem('username');
      return [userId, userName];
   }

   public getUserInfo(): UserInfo {
      if (!this.authenticated()) {
         throw new Error('no active user');
      }
      return this.userInfo()!;
   }

   private async _doFetch<T>(
      urlPath: string,
      method: string,
      body?: string,
   ): Promise<T> {

      const url = new URL(urlPath, baseUrl);
      try {
         var response = await fetch(url, {
            method: method,
            mode: 'cors',
            cache: 'no-store',
            credentials: 'include',
            body: body,
            headers: {
               'Content-Type': 'application/json',
            },
         });
      } catch (err) {
         console.error(err);
         throw new Error('fetch error: ' + url);
      }

      if (!response.ok) {
         if (response.status == 401) {
            this.logout();
            throw new Error('logged out');
         } else {
            throw new Error('response error: ' + await response.text());
         }
      }

      return response.json() as T;
   }

   // does not recieve cookies, downloads user data again
   public async loadSession(): Promise<boolean> {

      if (!this.validSession()) {
         return false;
      }
      const [userId, _] = this.loadKnownUser();
      const serverLoginUserInfo = await this._doFetch<ServerLoginUserInfo>(
         `verifysess?userid=${userId}`,
         'POST'
      );

      if (!serverLoginUserInfo || !serverLoginUserInfo.verified) {
         return false;
      }

      this._loginUser(serverLoginUserInfo);
      return true;
   }

   // require re-authentication with passkey
   public async getRecoveryWords(): Promise<string> {
      await this.ready;

      if (!this.authenticated()) {
         throw new Error('no active user');
      }

      const verifyBody = await this._startAuth(this.userId, true);
      const serverLoginUserInfo = await this._doFetch<ServerLoginUserInfo>(
         'verifyauth',
         'POST',
         verifyBody,
      );

      if (!serverLoginUserInfo || !serverLoginUserInfo.recoveryId) {
         throw new Error('authentication failed');
      }

      const recoveryIdBytes = base64ToBytes(serverLoginUserInfo.recoveryId);
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

   lsSet(key: string, value: string | number | boolean | null) {
      if (value != null && this.authenticated()) {
         localStorage.setItem(this.userId + key, value.toString());
      }
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

      const sessExpiry = DateTime.now().plus({ seconds: SESSION_TIMEOUT }).toISO();

      this._userCred = serverLogin.userCred;
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
      // validSession becomes false if either inactivity time happens in this tab
      // or another. also if another tab logs into a differerent passkey
      if (!this.validSession()) {
         this.logout();
      }
   }

   private _deleteUser() {
      const eventData = this._captureEventData(AuthEvent.Delete);
      this.forgetUser();
      this._emit(eventData);

   }

   // log out globally, and forget user globally
   forgetUser() {
      const eventData = this._captureEventData(AuthEvent.Forget);
      this.logout();

      // not yet handled well if multiple tabs are open
      localStorage.removeItem('username');
      localStorage.removeItem('userid');
      this._emit(eventData);
   }

   // log out globally, and remember user (other tap will logout on timertick)
   logout() {
      const eventData = this._captureEventData(AuthEvent.Logout);
      if (this._intervalId) {
         clearInterval(this._intervalId);
         this._intervalId = 0;
      }

      // rather than clear values, which can trigger error in other tabs,
      // set expirations to the past to trigger clear self-logout
      const expired = DateTime.now().minus({ seconds: 10 }).toISO();
      localStorage.setItem('activityexpiry', expired);
      localStorage.setItem('sessionexpiry', expired);

      // clear this tabs sensitive in-memory values
      this.userInfo.set(undefined);
      this._userCred = undefined;
      sessionStorage.clear();

      this._emit(eventData);
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

      const serverUserInfo = await this._doFetch<ServerUserInfo>(
         `description?credid=${credentialId}&userid=${this.userId}`,
         'PUT',
         description,
      );

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

      const serverUserInfo = await this._doFetch<ServerUserInfo>(
         `username?userid=${this.userId}`,
         'PUT',
         userName
      );

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

      const serverUserInfo = await this._doFetch<ServerUserInfo>(
         `authenticator?credid=${credentialId}&userid=${this.userId}`,
         'DELETE'
      );

      if (!serverUserInfo) {
         throw new Error('authentication failed');
      }

      // If we have an unverified response, that was the last PK and the user was deleted
      if (!serverUserInfo.verified) {
         this._deleteUser();
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

      const serverUserInfo = await this._doFetch<ServerUserInfo>(
         `userinfo?userid=${this.userId}`,
         'GET'
      );

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

      const verifyBody = await this._startAuth(userId, false);
      const serverLoginUserInfo = await this._doFetch<ServerLoginUserInfo>(
         'verifyauth',
         'POST',
         verifyBody
      );

      if (!serverLoginUserInfo) {
         throw new Error('authentication failed');
      }

      return this._loginUser(serverLoginUserInfo);
   }

   private async _startAuth(
      userId: string | null,
      createRecovery: boolean
   ): Promise<string> {

      let urlPath: string;
      if (!userId) {
         // Trying to link to an existing passkey but have lost track of user id.
         // Start the process without userId just doesn't limit authenticator creds
         // so the user can look for an existing credential
         urlPath = 'authoptions';
      } else {
         urlPath = `authoptions?userid=${userId}`;
      }

      const optionsJson = await this._doFetch<PublicKeyCredentialRequestOptionsJSON>(
         urlPath,
         'GET'
      );

      let startAuth: AuthenticationResponseJSON;
      try {
         startAuth = await startAuthentication({
            optionsJSON: optionsJson,
            useBrowserAutofill: false
         });
      } catch (err) {
         console.error(err);
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
      return JSON.stringify({
         ...startAuth,
         challenge: optionsJson.challenge,
         createRecovery: createRecovery
      });
   }

   // getRecoveryValues(recoveryWords: string): [string, string] {

   //    if (!recoveryWords || recoveryWords.length == 0) {
   //       throw new Error('missing recovery words');
   //    }

   //    if (!validateMnemonic(recoveryWords, wordlist)) {
   //       throw new Error('invalid recovery words');
   //    }

   //    const recoveryBytes = mnemonicToEntropy(recoveryWords, wordlist);
   //    if (!recoveryBytes || recoveryBytes.byteLength < RECOVERID_BYTES + 1) {
   //       throw new Error('invalid recovery id');
   //    }

   //    const recoveryIdBytes = new Uint8Array(recoveryBytes.buffer, 0, RECOVERID_BYTES);
   //    const userIdBytes = new Uint8Array(recoveryBytes.buffer, RECOVERID_BYTES);
   //    if (recoveryIdBytes.byteLength != RECOVERID_BYTES) {
   //       throw new Error('invalid recovery id length ' + recoveryIdBytes.byteLength);
   //    }

   //    const recoveryId = bytesToBase64(recoveryIdBytes);
   //    const userId = bytesToBase64(userIdBytes);

   //    return [recoveryId, userId];
   // }

   async recover2(recoveryWords: string): Promise<UserInfo> {

      const [recoveryId, userId] = this.getRecoveryValues(recoveryWords);
      const optionsJson = await this._doFetch<PublicKeyCredentialCreationOptionsJSON>(
         `recovery2?userid=${userId}&recoveryId=${recoveryId}`,
         'POST'
      );

      const serverLoginUserInfo = await this._finishRegistration(optionsJson);
      return this._loginUser(serverLoginUserInfo);
   }

   async recover(userId: string, userCred: string): Promise<UserInfo> {

      if (!userId || !userCred) {
         throw new Error('missing userid or usercred');
      }

      const optionsJson = await this._doFetch<PublicKeyCredentialCreationOptionsJSON>(
         `recovery?userid=${userId}&usercred=${userCred}`,
         'POST'
      );

      const serverLoginUserInfo = await this._finishRegistration(optionsJson);
      return this._loginUser(serverLoginUserInfo);
   }

   // Creates new user and first passkey
   async newUser(userName: string): Promise<UserInfo> {
      if (!userName) {
         throw new Error('missing require userName');
      }

      const optionsJson = await this._doFetch<PublicKeyCredentialCreationOptionsJSON>(
         `regoptions?username=${userName}`,
         'GET'
      );

      const serverLoginUserInfo = await this._finishRegistration(optionsJson);
      return this._loginUser(serverLoginUserInfo);
   }

   // Adds passkey to current user
   async addPasskey(): Promise<UserInfo> {

      if (!this.authenticated()) {
         throw new Error('not active user');
      }

      const optionsJson = await this._doFetch<PublicKeyCredentialCreationOptionsJSON>(
         `regoptions?userid=${this.userId}`,
         'GET'
      );

      const serverLoginUserInfo = await this._finishRegistration(optionsJson);
      return this._updateLoggedInUser(serverLoginUserInfo);
   }

   private async _finishRegistration(
      optionsJson: PublicKeyCredentialCreationOptionsJSON
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
         console.error(err);
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

      const serverLoginUserInfo = await this._doFetch<ServerLoginUserInfo>(
         'verifyreg',
         'POST',
         JSON.stringify(expanded),
      );

      if (!serverLoginUserInfo) {
         throw new Error('registration failed');
      }

      return serverLoginUserInfo;
   }

}
