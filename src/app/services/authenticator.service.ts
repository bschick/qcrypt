/* MIT License

Copyright (c) 2024 Brad Schick

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
import { base64ToBytes, bytesToBase64 } from './utils';
import { entropyToMnemonic, mnemonicToEntropy, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';

const baseUrl = environment.domain;

// 6 hours in seconds
export const INACTIVITY_TIMEOUT = 60 * 60 * 6;
export const RECOVERID_BYTES = 16;


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
   Forget
}

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
   private _expiration = DateTime.fromISO('2017-05-15');
   private _userCred? : string = undefined;
   public ready: Promise<void>;

   constructor() {
      const [userId, userName] = this.loadKnownUser();

      //TODO... fix this with JWT sessions
      this.ready = new Promise<void>( (resolve) => {
         let refreshing = false;
         if (userId && userName) {
            const userCred = sessionStorage.getItem(userId + 'usercred');
            if (userCred) {
               const exp = sessionStorage.getItem(userId + 'expiration');
               if (exp) {
                  this._expiration = DateTime.fromISO(exp);
               }

               if (DateTime.now() > this._expiration) {
                  this.logout();
               } else {
                  // just enough to boostrap, then call refresh
                  this.updateLoggedInUser({
                        verified: true,
                        userId: userId,
                        userName: userName,
                     }
                  );
                  refreshing = true;
                  this.refreshUserInfo().then(
                     () => this.emit(this.captureEventData(AuthEvent.Login))
                  ).finally(
                     () => resolve()
                  );
               }
            }
         }

         if (!refreshing) {
            resolve();
         }
      });
   }

   public isAuthenticated(): boolean {
      // pkid is cleared at logout
      const pkId = localStorage.getItem('pkid');
      return (this._userCred && pkId) ? true : false;
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
      if (!this.isAuthenticated()) {
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
      if (!this.isAuthenticated()) {
         throw new Error('no active user');
      }

      return this.userInfo()!;
   }

   // require re-authentication with passkey
   public async getRecoveryWords(): Promise<string> {
      await this.ready;

      if (!this.isAuthenticated()) {
         throw new Error('no active user');
      }

      const verifyBody = await this._startAuth(this.userId);
      const verifyUrl = new URL('verifyauth', baseUrl);

      try {
         var verificationResp = await fetch(verifyUrl, {
            method: 'POST',
            mode: 'cors',
            cache: 'no-store',
            headers: {
               'Content-Type': 'application/json',
            },
            body: verifyBody,
         });
      } catch (err) {
         console.error(err);
         throw new Error('verifyauth fetch error');
      }

      if (!verificationResp.ok) {
         throw new Error('authentication failed: ' + await verificationResp.text());
      }

      const serverLoginUserInfo = await verificationResp.json() as ServerLoginUserInfo;
      if (!serverLoginUserInfo || !serverLoginUserInfo.recoveryId) {
         throw new Error('authentication failed');
      }

      const recoveryIdBytes = base64ToBytes(serverLoginUserInfo.recoveryId);
      if(recoveryIdBytes.byteLength != RECOVERID_BYTES) {
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
      if (this.isAuthenticated()) {
         return localStorage.getItem(this.userId + key);
      }
      return null;
   }

   lsSet(key: string, value: string | number | boolean | null) {
      if (value != null && this.isAuthenticated()) {
         localStorage.setItem(this.userId + key, value.toString());
      }
   }

   lsDel(key: string) {
      if (this.isAuthenticated()) {
         localStorage.removeItem(this.userId + key);
      }
   }

   private captureEventData(event: AuthEvent): AuthEventData {
      return {
         event: event,
         userId: this.isAuthenticated() ? this.userId : null,
         userName: this.isAuthenticated() ? this.userName : null
      };
   }

   private emit(eventData: AuthEventData) {
      this._subject.next(eventData);
   }

   private loginUser(
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

      this._userCred = serverLogin.userCred;
      localStorage.setItem('userid', serverLogin.userId);
      localStorage.setItem('pkid', serverLogin.pkId);

      const userInfo = this.updateLoggedInUser(serverLogin);
      this.emit(this.captureEventData(AuthEvent.Login));

      return userInfo;
   }

   private updateLoggedInUser(
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
      if (!this.isAuthenticated()) {
         throw new Error('no active user');
      }

      const pkId = localStorage.getItem('pkid');
      if (!pkId) {
         throw new Error('missing passkey id');
      }

      localStorage.setItem('username', serverUser.userName);

      const userInfo: UserInfo = {
         userId: serverUser.userId,
         userName: serverUser.userName,
         pkId: pkId,
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

      // 6 hours inactivity expritation
      this._expiration = DateTime.now().plus({ seconds: INACTIVITY_TIMEOUT });
      sessionStorage.setItem(this.userId + 'expiration', this._expiration.toISO()!);

      // Check every 5 minutes
      this._intervalId = window.setInterval(() => this.timerTick(), 1000 * 60 * 5);
   }

   private timerTick(): void {
      if (DateTime.now() > this._expiration) {
         this.logout();
      }
   }

   secondsRemaining() {
      let result = 0;
      if (this._intervalId) {
         const diff = this._expiration.diff(DateTime.now());
         result = Math.max(0, Math.round(diff.toMillis() / 1000));
      }
      return result;
   }

   forgetUserInfo() {
      this.logout();
      const eventData = this.captureEventData(AuthEvent.Forget);
      localStorage.removeItem('username');
      localStorage.removeItem('userid');
      this.emit(eventData);
   }

   logout() {
      const wasAuthenticated = this.isAuthenticated();
      const eventData = this.captureEventData(AuthEvent.Logout);
      if (this._intervalId) {
         clearInterval(this._intervalId);
         this._intervalId = 0;
      }
      this._userCred = undefined;
      localStorage.removeItem('pkid');
      sessionStorage.clear();
      this.userInfo.set(undefined);

      if(wasAuthenticated) {
         this.emit(eventData);
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
      if (!this.isAuthenticated()) {
         throw new Error('not active user');
      }

      const putDescUrl = new URL(`description?credid=${credentialId}&userid=${this.userId}&usercred=${this.userCred!}`, baseUrl);
      try {
         var putDescResp = await fetch(putDescUrl, {
            method: 'PUT',
            mode: 'cors',
            cache: 'no-store',
            body: description,
         });
      } catch (err) {
         console.error(err);
         throw new Error('description fetch error');
      }

      if (!putDescResp.ok) {
         throw new Error('setting description failed: ' + await putDescResp.text());
      }

      const serverUserInfo = await putDescResp.json() as ServerUserInfo;
      if (!serverUserInfo) {
         throw new Error('authentication failed');
      }

      return this.updateLoggedInUser(serverUserInfo);
   }

   async setUserName(userName: string): Promise<UserInfo> {
      if (!userName) {
         throw new Error('missing description');
      }
      if (userName.length < 6 || userName.length > 31) {
         throw new Error('user name must be 6 to 31 characters');
      }
      if (!this.isAuthenticated()) {
         throw new Error('not active user');
      }

      const putUserNameUrl = new URL(`username?userid=${this.userId}&usercred=${this.userCred!}`, baseUrl);
      try {
         var putUserNameResp = await fetch(putUserNameUrl, {
            method: 'PUT',
            mode: 'cors',
            cache: 'no-store',
            body: userName,
         });
      } catch (err) {
         console.error(err);
         throw new Error('username fetch error');
      }

      if (!putUserNameResp.ok) {
         throw new Error('setting user name failed: ' + await putUserNameResp.text());
      }

      const serverUserInfo = await putUserNameResp.json() as ServerUserInfo;
      if (!serverUserInfo) {
         throw new Error('authentication failed');
      }

      return this.updateLoggedInUser(serverUserInfo);
   }

   async deletePasskey(credentialId: string): Promise<number> {
      if (!credentialId) {
         throw new Error('invalid credentialId');
      }
      if (!this.isAuthenticated()) {
         throw new Error('not active user');
      }

      const delPasskeyUrl = new URL(`authenticator?credid=${credentialId}&userid=${this.userId}&usercred=${this.userCred!}`, baseUrl);
      try {
         var delPasskeyResp = await fetch(delPasskeyUrl, {
            method: 'DELETE',
            mode: 'cors',
            cache: 'no-store',
         });
      } catch (err) {
         console.error(err);
         throw new Error('authenticator fetch error');
      }

      if (!delPasskeyResp.ok) {
         throw new Error('setting description failed: ' + await delPasskeyResp.text());
      }

      const serverUserInfo = await delPasskeyResp.json() as ServerUserInfo;
      if (!serverUserInfo) {
         throw new Error('authentication failed');
      }

      // If we have an unverified response, that was the last PK and the user was deleted
      if (!serverUserInfo.verified) {
         this.forgetUserInfo();
         return 0;
      } else {
         this.updateLoggedInUser(serverUserInfo);
         return serverUserInfo.authenticators!.length;
      }
   }

   async refreshSenderLinks(): Promise<SenderLinkInfo[]> {
      if (!this.isAuthenticated()) {
         throw new Error('not active user');
      }
      /*
            const getAuthsUrl = new URL(`senderlinks?userid=${this._userId}&usercred=${this._userCred!}`, baseUrl);
            try {
               var getAuthsResp = await fetch(getAuthsUrl, {
                  method: 'GET',
                  mode: 'cors',
                  cache: 'no-store',
               });
            } catch (err) {
               console.error(err);
               throw new Error('senderlinks fetch error');
            }

            if (!getAuthsResp.ok) {
               throw new Error('retrieving senderlinks failed: ' + await getAuthsResp.text());
            }

            const links = await getAuthsResp.json() as SenderLinkInfo[];
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
      if (!this.isAuthenticated()) {
         throw new Error('not active user');
      }

      const getInfoUrl = new URL(`userinfo?userid=${this.userId}&usercred=${this.userCred}`, baseUrl);
      try {
         var getInfoResp = await fetch(getInfoUrl, {
            method: 'GET',
            mode: 'cors',
            cache: 'no-store',
         });
      } catch (err) {
         console.error(err);
         throw new Error('authenticators fetch error');
      }

      if (!getInfoResp.ok) {
         throw new Error('retrieving userinfo failed: ' + await getInfoResp.text());
      }

      const serverUserInfo = await getInfoResp.json() as ServerUserInfo;

      if (!serverUserInfo) {
         throw new Error('authentication failed');
      }

      return this.updateLoggedInUser(serverUserInfo);
   }

   // Uses the current stored userId
   async defaultLogin(): Promise<UserInfo> {
      const [userId] = this.loadKnownUser();
      if (!userId) {
         throw new Error('missing local userId, try findLogin');
      }

      return this.findLogin(userId);
   }

   // If no userId is provided, will present all Passkeys for this domain
   async findLogin(userId: string | null = null): Promise<UserInfo> {

      if( this.isAuthenticated()) {
         throw new Error('must be logged out to log in');
      }

      const verifyBody = await this._startAuth(userId);
      const verifyUrl = new URL('verifyauth', baseUrl);

      try {
         var verificationResp = await fetch(verifyUrl, {
            method: 'POST',
            mode: 'cors',
            cache: 'no-store',
            headers: {
               'Content-Type': 'application/json',
            },
            body: verifyBody,
         });
      } catch (err) {
         console.error(err);
         throw new Error('verifyauth fetch error');
      }

      if (!verificationResp.ok) {
         throw new Error('authentication failed: ' + await verificationResp.text());
      }

      const serverLoginUserInfo = await verificationResp.json() as ServerLoginUserInfo;
      if (!serverLoginUserInfo) {
         throw new Error('authentication failed');
      }

      return this.loginUser(serverLoginUserInfo);
   }

   private async _startAuth(
      userId: string | null = null
   ): Promise<string> {

      let optUrl: URL;
      if (!userId) {
         // Trying to link to an existing passkey but have lost track of user id.
         // Start the process without userId just doesn't limit authenticator creds
         // so the user can look for an existing credential
         optUrl = new URL('authoptions', baseUrl);
      } else {
         optUrl = new URL(`authoptions?userid=${userId}`, baseUrl);
      }

      try {
         var optionsResp = await fetch(optUrl, {
            method: 'GET',
            mode: 'cors',
            cache: 'no-store'
         });
      } catch (err) {
         console.error(err);
         throw new Error('authoptions fetch error');
      }

      if (!optionsResp.ok) {
         throw new Error('authentication failed: ' + await optionsResp.text());
      }

      const optionsJson = await optionsResp.json() as PublicKeyCredentialRequestOptionsJSON;

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
      // and the challenge's age
      return JSON.stringify({
            ...startAuth,
            challenge: optionsJson.challenge,
      });
   }

   getRecoveryValues(recoveryWords: string): [string, string] {

      if (!recoveryWords || recoveryWords.length == 0) {
         throw new Error('missing recovery words');
      }

      if(!validateMnemonic(recoveryWords, wordlist)) {
         throw new Error('invalid recovery words');
      }

      const recoveryBytes = mnemonicToEntropy(recoveryWords, wordlist);
      if (!recoveryBytes || recoveryBytes.byteLength < RECOVERID_BYTES + 1 ) {
         throw new Error('invalid recovery id');
      }

      const recoveryIdBytes = new Uint8Array(recoveryBytes.buffer, 0, RECOVERID_BYTES );
      const userIdBytes = new Uint8Array(recoveryBytes.buffer, RECOVERID_BYTES );
      if(recoveryIdBytes.byteLength != RECOVERID_BYTES) {
         throw new Error('invalid recovery id length ' + recoveryIdBytes.byteLength);
      }

      const recoveryId = bytesToBase64(recoveryIdBytes);
      const userId = bytesToBase64(userIdBytes);

      return [recoveryId, userId];
   }

   async recover2(recoveryWords: string): Promise<UserInfo> {

      const [recoveryId, userId] = this.getRecoveryValues(recoveryWords);
      const recoveryUrl = new URL(`recovery2?userid=${userId}&recoveryId=${recoveryId}`, baseUrl);
      try {
         var recoveryResp = await fetch(recoveryUrl, {
            method: 'POST',
            mode: 'cors',
            cache: 'no-store'
         });
      } catch (err) {
         console.error(err);
         throw new Error('recover2 fetch error');
      }

      const serverLoginUserInfo = await this._finishRegistration(recoveryResp);
      return this.loginUser(serverLoginUserInfo);
   }

   async recover(userId: string, userCred: string): Promise<UserInfo> {

      if (!userId || !userCred) {
         throw new Error('missing userid or usercred');
      }

      const recoveryUrl = new URL(`recovery?userid=${userId}&usercred=${userCred}`, baseUrl);
      try {
         var recoveryResp = await fetch(recoveryUrl, {
            method: 'POST',
            mode: 'cors',
            cache: 'no-store'
         });
      } catch (err) {
         console.error(err);
         throw new Error('recover fetch error');
      }

      const serverLoginUserInfo = await this._finishRegistration(recoveryResp);
      return this.loginUser(serverLoginUserInfo);
   }

   // Creates new user and first passkey
   async newUser(userName: string): Promise<UserInfo> {
      if (!userName) {
         throw new Error('missing require userName');
      }

      const optUrl = new URL(`regoptions?username=${userName}`, baseUrl);
      try {
         var optionsResp = await fetch(optUrl, {
            method: 'GET',
            mode: 'cors',
            cache: 'no-store'
         });
      } catch (err) {
         console.error(err);
         throw new Error('regoptions fetch error');
      }

      const serverLoginUserInfo = await this._finishRegistration(optionsResp);
      return this.loginUser(serverLoginUserInfo);
   }

   // Adds passkey to current user
   async addPasskey(): Promise<UserInfo> {

      if (!this.isAuthenticated()) {
         throw new Error('not active user');
      }

      const optUrl = new URL(`regoptions?userid=${this.userId}&usercred=${this.userCred}`, baseUrl);
      try {
         var optionsResp = await fetch(optUrl, {
            method: 'GET',
            mode: 'cors',
            cache: 'no-store'
         });
      } catch (err) {
         console.error(err);
         throw new Error('regoptions fetch error');
      }

      const serverLoginUserInfo = await this._finishRegistration(optionsResp);
      return this.updateLoggedInUser(serverLoginUserInfo);
   }

   private async _finishRegistration(
      optionsResp: Response
   ): Promise<ServerLoginUserInfo> {

      if (!optionsResp.ok) {
         throw new Error('registration failed: ' + await optionsResp.text());
      }

      const optionsJson = await optionsResp.json() as PublicKeyCredentialCreationOptionsJSON;

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

      const verifyUrl = new URL('verifyreg', baseUrl);
      try {
         var verificationResp = await fetch(verifyUrl, {
            method: 'POST',
            mode: 'cors',
            cache: 'no-store',
            headers: {
               'Content-Type': 'application/json',
            },
            body: JSON.stringify(expanded),
         });
      } catch (err) {
         console.error(err);
         throw new Error('verifyreg fetch error');
      }

      if (!verificationResp.ok) {
         throw new Error('registration failed: ' + await verificationResp.text());
      }

      const serverLoginUserInfo = await verificationResp.json() as ServerLoginUserInfo;
      if (!serverLoginUserInfo) {
         throw new Error('registration failed');
      }

      return serverLoginUserInfo;
   }

}
