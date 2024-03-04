import { Injectable, signal } from '@angular/core';
import { startRegistration, startAuthentication } from '@simplewebauthn/browser';
import {
   PublicKeyCredentialCreationOptionsJSON,
   PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/types';
import { base64ToBytes, bytesToBase64 } from './cipher.service';

const baseUrl = 'https://qcrypt.schicks.net/';

export type RegistrationInfo = {
   verified: boolean;
   siteKey: string;
   userId: string;
   userName: string;
   lightIcon: string;
   description: string;
};

export type AuthenticationInfo = {
   verified: boolean;
   siteKey: string;
   userId: string;
   userName: string;
};

export type AuthenticatorInfo = {
   credentialId: string;
   description: string;
   lightIcon: string;
   name: string;
};

export type DeleteInfo = {
   credentialId: string;
   userId?: string;
};


@Injectable({
   providedIn: 'root'
})
export class AuthenticatorService {

   private _siteKey: string | null = 'bTahdd5CNVLLWhESfOgUsoAneWYMAFBoX6XP-FYUp6g'; //new Uint8Array([0x6d, 0x36, 0xa1, 0x75, 0xde, 0x42, 0x35, 0x52, 0xcb, 0x5a, 0x11, 0x12, 0x7c, 0xe8, 0x14, 0xb2, 0x80, 0x27, 0x79, 0x66, 0x0c, 0x00, 0x50, 0x68, 0x5f, 0xa5, 0xcf, 0xf8, 0x56, 0x14, 0xa7, 0xa8]);//null;
   private _userName: string | null = 'waldo here'; //null;
   private _userId: string | null = '5DzRiAARcI6vXCmfpYOpbA'; //null;

   constructor() { }

   public passKeys = signal<AuthenticatorInfo[]>([]);

   get siteKey(): string | null {
      return this._siteKey;
   }

   get userName(): string | null {
      return this._userName;
   }

   get userId(): string | null {
      return this._userId;
   }

   isAuthenticated(): boolean {
      return this._siteKey ? true : false;
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

   storeUserInfo(userId: string, userName: string) {
      if (!userId || !userName) {
         throw new Error('missing userId or userName');
      }
      this._userId = userId;
      this._userName = userName;
      localStorage.setItem('userid', this._userId);
      localStorage.setItem('username', this._userName);
   }

   forgetUserInfo() {
      this._userId = null;
      this._userName = null;
      this._siteKey = null;
      localStorage.removeItem('userid');
      localStorage.removeItem('username');
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

      const putDescUrl = new URL(`description?credid=${credentialId}&userid=${this._userId}&sitekey=${this._siteKey!}`, baseUrl);
      const putDescResp = await fetch(putDescUrl, {
         method: 'PUT',
         mode: 'cors',
         cache: 'no-store',
         body: description,
      });

//      console.log('putDescResp, ', putDescResp);
      if (!putDescResp.ok) {
         throw new Error('setting description failed: ' + await putDescResp.text());
      }

      const putDescInfo = await putDescResp.json();
//      console.log('putDescInfo, ', putDescInfo);
      return putDescInfo.description;
   }

   async setUserName(userName: string): Promise<string> {
      if (!userName) {
         throw new Error('missing description');
      }
      if (userName.length < 6 || userName.length > 31) {
         throw new Error('user name must more than 5 and less than 32 character');
      }

      const putUserNameUrl = new URL(`username?userid=${this._userId}&sitekey=${this._siteKey!}`, baseUrl);
      const putUserNameResp = await fetch(putUserNameUrl, {
         method: 'PUT',
         mode: 'cors',
         cache: 'no-store',
         body: userName,
      });

//      console.log('putUserNameResp, ', putUserNameResp);
      if (!putUserNameResp.ok) {
         throw new Error('setting user name failed: ' + await putUserNameResp.text());
      }

      const putUserNameInfo = await putUserNameResp.json();
//      console.log('putUserNameInfo, ', putUserNameInfo);
      this.storeUserInfo(this._userId!, putUserNameInfo.userName);
      return putUserNameInfo.userName;
   }

   async deletePasskey(credentialId: string): Promise<DeleteInfo> {
      if (!credentialId) {
         throw new Error('invalid credentialId');
      }

      const delPasskeyUrl = new URL(`authenticator?credid=${credentialId}&userid=${this._userId}&sitekey=${this._siteKey!}`, baseUrl);
      const delPasskeyResp = await fetch(delPasskeyUrl, {
         method: 'DELETE',
         mode: 'cors',
         cache: 'no-store',
      });

//      console.log('delPasskeyResp ', delPasskeyResp);
      if (!delPasskeyResp.ok) {
         throw new Error('setting description failed: ' + await delPasskeyResp.text());
      }

      const delPasskeyInfo = await delPasskeyResp.json() as DeleteInfo;
//      console.log('delPasskeyInfo ', delPasskeyInfo);

      // User is gone... so forgeeet about it
      if(delPasskeyInfo.userId) {
         this.forgetUserInfo();
      }

      return delPasskeyInfo;
   }

   async refreshPasskeys(): Promise<AuthenticatorInfo[]> {

      if (!this.isAuthenticated()) {
         throw new Error('must be authenticated to retrieve passkeys');
      }

      const getAuthsUrl = new URL(`authenticators?userid=${this._userId}&sitekey=${this._siteKey!}`, baseUrl);

      const getAuthsResp = await fetch(getAuthsUrl, {
         method: 'GET',
         mode: 'cors',
         cache: 'no-store',
      });

      console.log('getAuthsResp, ', getAuthsResp);
      if (!getAuthsResp.ok) {
         throw new Error('retrieving passkeys failed: ' + await getAuthsResp.text());
      }

      const authsInfo = await getAuthsResp.json() as AuthenticatorInfo[];
      console.log('authsInfo, ', authsInfo);

      this.passKeys.set(authsInfo);
      return authsInfo;
   }

   async passkeyLogin(): Promise<AuthenticationInfo> {
      if(!this._userId) {
         throw new Error('missing local userId, try findLogin');
      }

      return this.findLogin(this._userId);
   }

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

      const optionsResp = await fetch(optUrl, {
         method: 'GET',
         mode: 'cors',
         cache: 'no-store'
      });

//      console.log('optionsResp, ', optionsResp);
      if (!optionsResp.ok) {
         throw new Error('authentication failed: ' + await optionsResp.text());
      }

      const optionsJson = await optionsResp.json() as PublicKeyCredentialRequestOptionsJSON;
//      console.log('optionsJson, ', optionsJson);

      let startAuth;
      try {
         startAuth = await startAuthentication(optionsJson);
      } catch (err) {
         console.error(err);
         throw err;
      }

      // Need to return challenge because in some cases it cannot be bound
      // to a user when created. The server validates it created the challenge
      // and its age
      const expanded = {
         ...startAuth,
         challenge: optionsJson.challenge,
      }

//      console.log('expanded ', JSON.stringify(expanded));

      const verifyUrl = new URL('verifyauth', baseUrl);
      const verificationResp = await fetch(verifyUrl, {
         method: 'POST',
         mode: 'cors',
         cache: 'no-store',
         headers: {
            'Content-Type': 'application/json',
         },
         body: JSON.stringify(expanded),
      });

//      console.log('verificationResp, ', verificationResp);
      if (!verificationResp.ok) {
         throw new Error('authentication failed: ' + await verificationResp.text());
      }

      const authInfo = await verificationResp.json() as AuthenticationInfo;
//      console.log('authInfo, ', authInfo);

      if (!authInfo || !authInfo.verified) {
         throw new Error('authentication failed');
      }

      this._siteKey = authInfo.siteKey;
      this.storeUserInfo(authInfo.userId, authInfo.userName);
      return authInfo;
   }

   async recover(userId: string, siteKey: string): Promise<RegistrationInfo> {

      if (!userId || !siteKey) {
         throw new Error('missing userid or sitekey');
      }

      const recoverUrl = new URL(`recover?userid=${userId}&sitekey=${siteKey}`, baseUrl);
      const recoverResp = await fetch(recoverUrl, {
         method: 'POST',
         mode: 'cors',
         cache: 'no-store'
      });

      return this.finishRegistration(recoverResp);
   }

   // Creates new user and first passkey
   async newUser(userName: string): Promise<RegistrationInfo> {
      if(!userName) {
         throw new Error('missing require userName');
      }

      const  optUrl = new URL(`regoptions?username=${userName}`, baseUrl);
      const optionsResp = await fetch(optUrl, {
         method: 'GET',
         mode: 'cors',
         cache: 'no-store'
      });

      return this.finishRegistration(optionsResp);
   }

   // Adds passkey to current user
   async addPasskey(): Promise<RegistrationInfo> {

      if(!this._userId) {
         throw new Error('not active user');
      }

      const optUrl = new URL(`regoptions?userid=${this._userId}`, baseUrl);
      const optionsResp = await fetch(optUrl, {
         method: 'GET',
         mode: 'cors',
         cache: 'no-store'
      });

      return this.finishRegistration(optionsResp);
   }

   async finishRegistration(
      optionsResp: Response
   ): Promise<RegistrationInfo> {

//      console.log('optionsResp, ', optionsResp);
      if (!optionsResp.ok) {
         throw new Error('registration failed: ' + await optionsResp.text());
      }

      const optionsJson = await optionsResp.json() as PublicKeyCredentialCreationOptionsJSON;
//      console.log('optionsJson ', optionsJson);

      let startReg;
      try {
         startReg = await startRegistration(optionsJson);
      } catch (err) {
         console.error(err);
         throw err;
      }

      // Need to return challenge because in some cases it cannot be bound
      // to a user when created. The server validates it created the challenge
      // and its age (seems odd the userHandle isn't returned from .create)
      const expanded = {
         ...startReg,
         userId: optionsJson.user.id,
         challenge: optionsJson.challenge,
      }

//      console.log('expanded ', JSON.stringify(expanded));

      const verifyUrl = new URL('verifyreg', baseUrl);
      const verificationResp = await fetch(verifyUrl, {
         method: 'POST',
         mode: 'cors',
         cache: 'no-store',
         headers: {
            'Content-Type': 'application/json',
         },
         body: JSON.stringify(expanded),
      });

//      console.log('verifyResp, ', verificationResp);
      if (!verificationResp.ok) {
         throw new Error('registration failed: ' + await verificationResp.text());
      }

      const registrationInfo = await verificationResp.json() as RegistrationInfo;
//      console.log('registrationInfo, ', registrationInfo);

      if (!registrationInfo || !registrationInfo.verified) {
         throw new Error('registration failed');
      }

      this._siteKey = registrationInfo.siteKey;
      this.storeUserInfo(registrationInfo.userId, registrationInfo.userName);
      return registrationInfo;
   }

}
