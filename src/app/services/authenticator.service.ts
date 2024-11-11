import { environment } from '../../environments/environment';
import { Injectable, signal } from '@angular/core';
import { startRegistration, startAuthentication } from '@simplewebauthn/browser';
import {
   PublicKeyCredentialCreationOptionsJSON,
   PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/types';
import { Subject, Subscription, filter } from 'rxjs';
import { DateTime } from 'luxon';

const baseUrl = environment.domain;

// 6 hours in seconds
export const INACTIVITY_TIMEOUT = 60 * 60 * 6;

export type RegistrationInfo = {
   verified: boolean;
   userCred: string;
   userId: string;
   userName: string;
   lightIcon: string;
   darkIcon: string;
   description: string;
};

export type AuthenticationInfo = {
   verified: boolean;
   userCred: string;
   userId: string;
   userName: string;
};

export type AuthenticatorInfo = {
   credentialId: string;
   description: string;
   lightIcon: string;
   darkIcon: string;
   name: string;
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
            this.setActiveUser(this._userId, this._userName!, this._userCred, pkId!);
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

   public passKeys = signal<AuthenticatorInfo[]>([]);

   get userCred(): string | null {
      return this._userCred;
   }

   get userName(): string | null {
      return this._userName;
   }

   get userId(): string | null {
      return this._userId;
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

   getRecoveryLink(): string {
      if (!this.isAuthenticated()) {
         throw new Error('No active user');
      }
      return new URL(
         window.location.origin + '/recovery' +
         '?userid=' + this.userId +
         '&usercred=' + this.userCred
      ).toString();
   }

   on(events: AuthEvent[], action: (data: AuthEventData) => void): Subscription {
      return this._subject.pipe(
         filter((ed: AuthEventData) => events.includes(ed.event))
      ).subscribe(action);
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

   private setActiveUser(userId: string, userName: string, userCred: string, pkId: string) {
      if (!userCred) {
         throw new Error('missing userCred');
      }
      this.storeUserInfo(userId, userName);

      this._userCred = userCred;
      this._pkId = pkId;
      // Include userId in key in case there are multiple tabs open to
      // different users and this one is reloaded. This prevents
      // mixing of _userId and _userCred from different accounts
      sessionStorage.setItem(this._userId + 'usercred', this._userCred);
      sessionStorage.setItem(this._userId + 'pkid', this._pkId);

      this.refreshPasskeys();
      this.emit(this.captureEventData(AuthEvent.Login));
      this.activity();
   }

   activity() {
      if (this._intervalId) {
         clearInterval(this._intervalId);
         this._intervalId = 0;
      }

      // 6 hours inactivity expritation
      this._expiration = DateTime.now().plus({ seconds: INACTIVITY_TIMEOUT });
      sessionStorage.setItem(this._userId + 'expiration', this._expiration.toISO()!);

      // @ts-ignore
      // Check every 5 minutes
      this._intervalId = setInterval(() => this.timerTick(), 1000 * 60 * 5);
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
         this.passKeys.set([]);
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

      // User is gone... so forgeeet about it
      if (delPasskeyInfo.userId) {
         this.forgetUserInfo();
      }

      return delPasskeyInfo;
   }

   async refreshPasskeys(): Promise<AuthenticatorInfo[]> {
      if (!this.isAuthenticated()) {
         throw new Error('not active user');
      }

      const getAuthsUrl = new URL(`authenticators?userid=${this._userId}&usercred=${this._userCred!}`, baseUrl);
      try {
         var getAuthsResp = await fetch(getAuthsUrl, {
            method: 'GET',
            mode: 'cors',
            cache: 'no-store',
         });
      } catch (err) {
         console.error(err);
         throw new Error('authenticators fetch error');
      }

      if (!getAuthsResp.ok) {
         throw new Error('retrieving passkeys failed: ' + await getAuthsResp.text());
      }

      const authsInfo = await getAuthsResp.json() as AuthenticatorInfo[];

      this.passKeys.set(authsInfo);
      return authsInfo;
   }

   // Uses the current stored userId
   async defaultLogin(): Promise<AuthenticationInfo> {
      const [userId, _] = this.getUserInfo();
      if (!userId) {
         throw new Error('missing local userId, try findLogin');
      }

      return this.findLogin(userId);
   }

   // If not userId is provided, will present all Passkeys for this domain
   async findLogin(userId: string | null = null): Promise<AuthenticationInfo> {

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

      // Need to return challenge because in some cases it is not bound to
      // a user id when created. The server validates it created the challenge
      // and its age
      const expanded = {
         ...startAuth,
         challenge: optionsJson.challenge,
      }

      console.log(expanded);

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

      const authInfo = await verificationResp.json() as AuthenticationInfo;

      if (!authInfo || !authInfo.verified) {
         throw new Error('authentication failed');
      }

      this.setActiveUser(authInfo.userId, authInfo.userName, authInfo.userCred, startAuth.id);
      return authInfo;
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
      this.refreshPasskeys();
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

      let startReg;
      try {
         startReg = await startRegistration({optionsJSON: optionsJson});
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
         userId: optionsJson.user.id,
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
         this.setActiveUser(registrationInfo.userId, registrationInfo.userName, registrationInfo.userCred, startReg.id);
      }
      return registrationInfo;
   }

}
