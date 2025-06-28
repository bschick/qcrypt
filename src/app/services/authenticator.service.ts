import { environment } from '../../environments/environment';
import { Injectable, signal } from '@angular/core';
import {
   PublicKeyCredentialCreationOptionsJSON,
   PublicKeyCredentialRequestOptionsJSON,
   startRegistration, startAuthentication
} from '@simplewebauthn/browser';
import { Subject, Subscription, filter } from 'rxjs';
import { DateTime } from 'luxon';
import { base64ToBytes, bytesToBase64 } from './utils';
import { entropyToMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';

const baseUrl = environment.domain;

// 6 hours in seconds
export const INACTIVITY_TIMEOUT = 60 * 60 * 6;


export type RegistrationInfo = {
   verified: boolean;
   userCred: string;
   userId: string;
   userName: string;
   recoveryId: string;
   lightIcon: string;
   darkIcon: string;
   description: string;
};

export type AuthenticatorInfo = {
   credentialId: string;
   description: string;
   lightIcon: string;
   darkIcon: string;
   name: string;
};

export type UserInfo = {
   verified: boolean;
   userCred: string;
   userId: string;
   userName: string;
   recoveryId: string;
   authenticators: AuthenticatorInfo[];
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

export type DeleteInfo = {
   credentialId: string;
   userId?: string;
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
   readonly userCred: string | null
};


@Injectable({
   providedIn: 'root'
})
export class AuthenticatorService {

   private _userCred: string | null = null;
   private _userName: string | null = null;
   private _userId: string | null = null;
   private _pkId: string | null = null;
   private _recoveryId: string = '';
   private _subject = new Subject<AuthEventData>();
   private _intervalId: number = 0;
   private _expiration!: DateTime;

   constructor() {
      this._userId = localStorage.getItem('userid');
      this._userName = localStorage.getItem('username');
      if (this._userId) {
         this._userCred = sessionStorage.getItem(this._userId + 'usercred');
         if (this._userCred) {
            const exp = sessionStorage.getItem(this._userId + 'expiration');
            const pkId = sessionStorage.getItem(this._userId + 'pkid');
            const recoveryId = sessionStorage.getItem(this._userId + 'recoveryid') || '';
            this.setActiveUser(
               this._userId,
               this._userName!,
               this._userCred,
               recoveryId,
               pkId!
            );
            // replace the default expiration (set indirectly by setActiveUser)
            // with the save value if present
            if (exp) {
               this._expiration = DateTime.fromISO(exp);
               sessionStorage.setItem(this._userId + 'expiration', this._expiration.toISO()!);
               // don't wait 5 minutes to check
               this.timerTick();
            }
         }
      }
   }

   public userInfo = signal<UserInfo | undefined>(undefined);
   public senderLinks = signal<SenderLinkInfo[]>([]);

   get userCred(): string | null {
      return this._userCred;
   }

   get userName(): string | null {
      return this._userName;
   }

   get userId(): string | null {
      return this._userId;
   }

   get recoveryId(): string {
      return this._recoveryId;
   }

   get pkId(): string | null {
      return this._pkId;
   }

   isAuthenticated(): boolean {
      return this._userCred && this._userId ? true : false;
   }

   isUserKnown(): boolean {
      const userId = localStorage.getItem('userid');
      const userName = localStorage.getItem('username');
      return Boolean(userId && userName);
   }

   getUserInfo(): [string | null, string | null] {
      const userId = localStorage.getItem('userid');
      const userName = localStorage.getItem('username');
      return [userId, userName];
   }

   getRecoveryWords(): string {
      if (!this.isAuthenticated()) {
         throw new Error('No active user');
      }

      const recoveryBytes = base64ToBytes(this._recoveryId);
      const userIdBytes = base64ToBytes(this._userId!);

      let recoveryId = new Uint8Array(recoveryBytes.byteLength + userIdBytes.byteLength);
      recoveryId.set(recoveryBytes, 0);
      recoveryId.set(userIdBytes, recoveryBytes.byteLength );

      const recoveryWords = entropyToMnemonic(recoveryId, wordlist);
      return recoveryWords;
   }

   on(events: AuthEvent[], action: (data: AuthEventData) => void): Subscription {
      return this._subject.pipe(
         filter((ed: AuthEventData) => events.includes(ed.event))
      ).subscribe(action);
   }

   lsGet(key: string): string | null {
      if (this.isAuthenticated()) {
         const [userId] = this.getUserInfo();
         return localStorage.getItem(this.userId + key);
      }
      return null;
   }

   lsSet(key: string, value: string | number | boolean | null) {
      if (value != null && this.isAuthenticated()) {
         const [userId] = this.getUserInfo();
         localStorage.setItem(userId + key, value.toString());
      }
   }

   lsDel(key: string) {
      if (this.isAuthenticated()) {
         const [userId] = this.getUserInfo();
         localStorage.removeItem(userId + key);
      }
   }

   private captureEventData(event: AuthEvent): AuthEventData {
      return {
         event: event,
         userId: this._userId,
         userName: this._userName,
         userCred: this._userCred
      };
   }

   private emit(eventData: AuthEventData) {
      this._subject.next(eventData);
   }

   private storeUserInfo(userId: string, userName: string) {
      if (!userId || !userName) {
         throw new Error('missing userId or userName');
      }
      this._userId = userId;
      this._userName = userName;
      localStorage.setItem('userid', this._userId);
      localStorage.setItem('username', this._userName);
   }

   private setActiveUser(
      userId: string,
      userName: string,
      userCred: string,
      recoveryId: string,
      pkId: string
   ) {
      if (!userCred) {
         throw new Error('missing userCred');
      }
      this.storeUserInfo(userId, userName);

      this._userCred = userCred;
      this._pkId = pkId;
      this._recoveryId = recoveryId;

      // Include userId in key in case there are multiple tabs open to
      // different users and this one is reloaded. This prevents
      // mixing of _userId and _userCred from different accounts
      sessionStorage.setItem(this._userId + 'usercred', this._userCred);
      sessionStorage.setItem(this._userId + 'pkid', this._pkId);
      sessionStorage.setItem(this._userId + 'recoveryid', this._recoveryId);

      this.refreshUserInfo().then( () => {
//      this.refreshSenderLinks();
         this.emit(this.captureEventData(AuthEvent.Login));
         this.activity();
      });
   }

   activity() {
      if (this._intervalId) {
         clearInterval(this._intervalId);
         this._intervalId = 0;
      }

      // 6 hours inactivity expritation
      this._expiration = DateTime.now().plus({ seconds: INACTIVITY_TIMEOUT });
      sessionStorage.setItem(this._userId + 'expiration', this._expiration.toISO()!);

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
      if (this._userId) {
         const eventData = this.captureEventData(AuthEvent.Forget);
         localStorage.removeItem('username');
         localStorage.removeItem('userid');
         this._userId = null;
         this._userName = null;
         this.emit(eventData);
      }
   }

   logout() {
      if (this._userCred) {
         if (this._intervalId) {
            clearInterval(this._intervalId);
            this._intervalId = 0;
         }
         const eventData = this.captureEventData(AuthEvent.Logout);
         sessionStorage.clear();
         this._userCred = null;
         this._pkId = null;
         this._recoveryId = '';
         this.userInfo.set(undefined);
         this.emit(eventData);
      }
   }

   async setPasskeyDescription(credentialId: string, description: string): Promise<string> {
      if (!description) {
         throw new Error('missing description');
      }
      if (description.length < 6 || description.length > 42) {
         throw new Error('description must more than 5 and less than 43 character');
      }
      if (!credentialId) {
         throw new Error('invalid credentialId');
      }
      if (!this.isAuthenticated()) {
         throw new Error('not active user');
      }

      const putDescUrl = new URL(`description?credid=${credentialId}&userid=${this._userId}&usercred=${this._userCred!}`, baseUrl);
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

      const putDescInfo = await putDescResp.json();
      return putDescInfo.description;
   }

   async setUserName(userName: string): Promise<string> {
      if (!userName) {
         throw new Error('missing description');
      }
      if (userName.length < 6 || userName.length > 31) {
         throw new Error('user name must more than 5 and less than 32 character');
      }
      if (!this.isAuthenticated()) {
         throw new Error('not active user');
      }

      const putUserNameUrl = new URL(`username?userid=${this._userId}&usercred=${this._userCred!}`, baseUrl);
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

      const putUserNameInfo = await putUserNameResp.json();
      this.storeUserInfo(this._userId!, putUserNameInfo.userName);
      return putUserNameInfo.userName;
   }

   async deletePasskey(credentialId: string): Promise<DeleteInfo> {
      if (!credentialId) {
         throw new Error('invalid credentialId');
      }
      if (!this.isAuthenticated()) {
         throw new Error('not active user');
      }

      const delPasskeyUrl = new URL(`authenticator?credid=${credentialId}&userid=${this._userId}&usercred=${this._userCred!}`, baseUrl);
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

      const delPasskeyInfo = await delPasskeyResp.json() as DeleteInfo;

      // If user was also deleted... so forgeeet about it
      if (delPasskeyInfo.userId) {
         this.forgetUserInfo();
      }

      return delPasskeyInfo;
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

      const getAuthUrl = new URL(`userinfo?userid=${this._userId}&usercred=${this._userCred!}`, baseUrl);
      try {
         var getAuthResp = await fetch(getAuthUrl, {
            method: 'GET',
            mode: 'cors',
            cache: 'no-store',
         });
      } catch (err) {
         console.error(err);
         throw new Error('authenticators fetch error');
      }

      if (!getAuthResp.ok) {
         throw new Error('retrieving userinfo failed: ' + await getAuthResp.text());
      }

      const userInfo = await getAuthResp.json() as UserInfo;
      this._userName = userInfo.userName;
      this._recoveryId = userInfo.recoveryId;

      this.storeUserInfo(userInfo.userId, userInfo.userName);
      sessionStorage.setItem(userInfo.userId + 'recoveryid', userInfo.recoveryId);
      this.userInfo.set(userInfo);

      return userInfo;
   }

   // Uses the current stored userId
   async defaultLogin(): Promise<UserInfo> {
      const [userId] = this.getUserInfo();
      if (!userId) {
         throw new Error('missing local userId, try findLogin');
      }

      return this.findLogin(userId);
   }

   // If no userId is provided, will present all Passkeys for this domain
   async findLogin(userId: string | null = null): Promise<UserInfo> {

      let optUrl;
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

      let startAuth;
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
      // a user id when created. The server validates it created the challenge
      // and its age
      const expanded = {
         ...startAuth,
         challenge: optionsJson.challenge,
      }

      const verifyUrl = new URL('verifyauth', baseUrl);

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
         throw new Error('verifyauth fetch error');
      }

      if (!verificationResp.ok) {
         throw new Error('authentication failed: ' + await verificationResp.text());
      }

      const userInfo = await verificationResp.json() as UserInfo;

      if (!userInfo || !userInfo.verified) {
         throw new Error('authentication failed');
      }

      this.setActiveUser(
         userInfo.userId,
         userInfo.userName,
         userInfo.userCred,
         userInfo.recoveryId,
         startAuth.id
      );

      return userInfo;
   }

   async recover(userId: string, userCred: string): Promise<RegistrationInfo> {

      if (!userId || !userCred) {
         throw new Error('missing userid or usercred');
      }

      const recoverUrl = new URL(`recover?userid=${userId}&usercred=${userCred}`, baseUrl);
      try {
         var recoverResp = await fetch(recoverUrl, {
            method: 'POST',
            mode: 'cors',
            cache: 'no-store'
         });
      } catch (err) {
         console.error(err);
         throw new Error('recover fetch error');
      }

      return this.finishRegistration(recoverResp, true);
   }

   // Creates new user and first passkey
   async newUser(userName: string): Promise<RegistrationInfo> {
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

      return this.finishRegistration(optionsResp, true);
   }

   // Adds passkey to current user
   async addPasskey(): Promise<RegistrationInfo> {

      if (!this.isAuthenticated()) {
         throw new Error('not active user');
      }

      const optUrl = new URL(`regoptions?userid=${this._userId}&usercred=${this._userCred!}`, baseUrl);
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

      const regInfo = this.finishRegistration(optionsResp, false);
      this.refreshUserInfo();
      return regInfo;
   }

   async finishRegistration(
      optionsResp: Response,
      setActiveUser: boolean
   ): Promise<RegistrationInfo> {

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

      let startReg;
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

      const registrationInfo = await verificationResp.json() as RegistrationInfo;

      if (!registrationInfo || !registrationInfo.verified) {
         throw new Error('registration failed');
      }

      if (setActiveUser) {
         this.setActiveUser(
            registrationInfo.userId,
            registrationInfo.userName,
            registrationInfo.userCred,
            registrationInfo.recoveryId,
            startReg.id
         );
      }
      return registrationInfo;
   }

}
