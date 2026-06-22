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
   type PublicKeyCredentialCreationOptionsJSON,
   type PublicKeyCredentialRequestOptionsJSON,
   type AuthenticationResponseJSON,
   type RegistrationResponseJSON,
   startRegistration, startAuthentication
} from '@simplewebauthn/browser';
import { Subject, Subscription, filter } from 'rxjs';
import {
   base64ToBytes,
   bytesToBase64,
   bufferToHexString,
   bufferToBase64URLString,
   expired,
   cryptoReady,
   zxcvbnReady,
   streamFromBase64,
   MasterKeyKeyProvider,
   readStreamAll,
   getRandom } from '@qcrypt/crypto';
import { entropyToMnemonic, mnemonicToEntropy, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import * as cc from '@qcrypt/crypto/consts';

import {
   SESSION_TIMEOUT_SEC,
   signUserCredProof,
   signRecoveryProof,
   getRecoveryPubKey,
   recoverySecret,
   RECOVERYID_BYTES,
   CHALLENGE_BYTES,
   type ResponseTypes
} from '@qcrypt/api';
import { KeystoreService } from './keystore.service';
import { CipherService } from './cipher.service';
import {
   BroadcastService,
   type CredentialPayload,
   type LoginPayload,
   type LogoutPayload,
   MessageKind,
   type PasskeyIdPayload,
   type PeerMessage,
} from './broadcast.service';
export type AuthenticatorInfo = ResponseTypes.AuthenticatorInfo;
export type UserInfo = ResponseTypes.UserInfo;
export type LoginUserInfo = ResponseTypes.LoginUserInfo;
export type InvitableInfo = ResponseTypes.InvitableInfo;

const baseUrl = environment.apiHost;
export const ACTIVITY_TIMEOUT_SEC = 60 * 60 * 1.5;
const EXPIRY_CHECK_INTERVAL_MS = 1000 * 60 * 2;
const KEYSTORE_SLOT = 'user-cred-key';


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
   session?: SessionState;
}

type SessionState = Partial<CredentialPayload> & { userId: string };

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
   public ready: Promise<[void, void]>;

   private _subject = new Subject<AuthEventData>();
   private _intervalId: number = 0;
   private _csrf?: string = undefined;
   private _cachedRecoveryWords?: string;
   private _pendingLogout: Promise<unknown> = Promise.resolve();

   constructor(
      private _keystoreSvc: KeystoreService,
      private _cipherSvc: CipherService,
      private _broadcastSvc: BroadcastService,
   ) {
      this._broadcastSvc.setCredentialProvider(() => this._getCredentialPayload());
      this._broadcastSvc.setMessageHandler((msg) => this._handlePeerMessage(msg));
      this._broadcastSvc.start();

      let resolveCrypto!: () => void;
      const cryptoLoaded = new Promise<void>((resolve) => {
         resolveCrypto = resolve;
      });

      const loadCrypto = async () => {
         try { await cryptoReady(); } finally { resolveCrypto(); }
      };

      const restore = this._restoreSession(loadCrypto).catch((err) => console.error(err));

      // this allows either _restoreSession or the afterRender below to loadCrypto
      this.ready = Promise.all([cryptoLoaded, restore]);

      // Load crypto and zxcvbn after first render so their chunks don't
      // compete with LCP. zxcvbn's is big, so wait 4s after first idle to load
      afterNextRender(() => {
         const kickoff = () => {
            loadCrypto().catch((err) => console.error(err));
            setTimeout(() => {
               zxcvbnReady().catch((err) => console.error(err));
            }, 4000);
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
      const session = this._getSessionState();
      return !!session
         && !!session.pkId
         && !!session.userCredEnc
         && !!session.version
         && !!this._csrf
         && !!this.userInfo();
   }

   public potentialSession(): boolean {
      // Expiry or changed user (from another tab) means invalid session.
      // Cookie may still be valid, but we won't use it.
      const globalPKId = localStorage.getItem('pkid');
      const myUserId = this._getSessionState()?.userId;
      const sessionExpired = expired(localStorage, 'sessionexpiry');
      const activityExpired = expired(localStorage, 'activityexpiry');
      const [userId, userName] = this.loadKnownUser();

      const valid = !(
         !globalPKId ||
         (myUserId && (userId !== myUserId)) ||
         sessionExpired ||
         activityExpired ||
         !userId || !userName
      );
      return valid;
   }

   public validKnownUser(): boolean {
      const [userId, userName] = this.loadKnownUser();
      if (userId && userName && localStorage.getItem('pkid')) {
         const myUserId = this._getSessionState()?.userId;
         if (!myUserId || myUserId === userId) {
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
      if (!session?.userCredEnc || !session.pkId) {
         throw new Error('no active user');
      }
      return this._decryptUserCredEnc(session.userCredEnc, session.pkId, session.userId);
   }

   // The caller must overwrite the returned userCred ASAP.
   private async _decryptUserCredEnc(
      userCredEnc: string,
      pkId: string,
      userId: string
   ): Promise<Uint8Array<ArrayBuffer>> {
      const { derivedKey } = await this._keystoreSvc.get(KEYSTORE_SLOT, pkId);
      if (!derivedKey) {
         throw new Error('no active user');
      }

      // Keyprovider takes ownership of derivedKey and decryptStream takes ownership of keyProvider.
      const keyProvider = new MasterKeyKeyProvider(derivedKey, userId);
      try {
         // This will fail if another tab has logged in with a different pkID, and this tab has not updated
         const clearStream = await this._cipherSvc.decryptStream(streamFromBase64(userCredEnc), keyProvider);
         return await readStreamAll(clearStream);
      } catch (err) {
         console.error('userCredEnc decrypt failed', err);
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
      const session = args.session ?? this._getSessionState();

      const headers = new Headers({
         'Content-Type': 'application/json',
         'x-csrf-token': this._csrf!
      });

      const bodyData = new TextEncoder().encode(bodyJSON ?? '');
      const bodyHashHex = bufferToHexString(await crypto.subtle.digest("SHA-256", bodyData));

      // required for AWS OAC (access control to lambda).
      if (method === 'PUT' || method === 'POST' || method === 'PATCH') {
         headers.append('x-amz-content-sha256', bodyHashHex);
      }

      let path = `${environment.apiVersion}`;
      path += userId ? `/users/${userId}` : '';
      path += resource ? `/${resource}` : '';
      path += resourceId ? `/${resourceId}` : '';
      path += params ? `?${params}` : '';

      const url = new URL(path, baseUrl);

      if (session && session.userCredEnc) {
         const userCred = await this._decryptUserCredEnc(
            session.userCredEnc,
            session.pkId!,
            session.userId
         );

         try {
            const proofTs = String(Date.now());
            const proofSig = signUserCredProof(
               userCred,
               session.userId,
               method,
               url.pathname,
               proofTs,
               bodyHashHex
            );
            headers.append('x-proof-sig', bufferToBase64URLString(proofSig.buffer));
            headers.append('x-proof-ts', proofTs);
         } finally {
            userCred.fill(0);
         }
      }

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

   // public to simplify testing, normal clients shouldn't call
   public async _restoreSession(loadCrypto: () => Promise<void>): Promise<void> {
      if (!this.potentialSession()) {
         return;
      }

      let session = this._getSessionState();

      if (!session || !session.userCredEnc) {
         const targetPkId = localStorage.getItem('pkid')
         if (!targetPkId) {
            return;
         }
         const relay = await this._broadcastSvc.requestCredential(targetPkId, true);
         if (!relay) {
            return;
         }
         const [userId] = this.loadKnownUser();
         session = {
            userId: userId!,
            userCredEnc: relay.userCredEnc,
            userCredExpiry: relay.userCredExpiry,
            version: relay.version,
            pkId: relay.pkId
         }
      }

      if (!session.userCredEnc || !session.userCredExpiry || (session.version ?? 0) < 1) {
         return;
      }

      // Load crypto after the relay, not before: the base64-WASM decode + init blocks
      // the main thread, which would otherwise stall this tab's relay message handling.
      await loadCrypto();

      // pass session directly because it came from relay and is not yet in
      // sessionStorage for _doFetch to load
      const serverLoginUserInfo = await this._doFetch<LoginUserInfo>({
         method: 'GET',
         resource: 'session',
         session
      });

      if (!serverLoginUserInfo || !serverLoginUserInfo.verified) {
         console.error('restore aborted: getSession returned unverified');
         return;
      }

      await this._loginRestore(
         serverLoginUserInfo,
         session.userCredEnc,
         session.userCredExpiry,
         session.version!
      );

      // test decrypt to fail fast if userCredEnc is invalid
      try {
         const userCred = await this.getUserCred();
         userCred.fill(0);
      } catch {
         // we could try a requestCredential here in case our version is just stale
         // and we missed a broadcase message, but that seems rare and not worth the
         // added code. Add if its more common than expected.
         this.logout(false);
         return;
      }
   }

   public hasRecoveryWords(): boolean {
      return !!this._cachedRecoveryWords;
   }

   // Recovery words can only be shown once, right after they are generated. The
   // server cannot reproduce them, so a later request must regenerate instead.
   public consumeRecoveryWords(): string {
      if (!this.hasSession()) {
         throw new Error('no active user');
      }
      if (!this._cachedRecoveryWords) {
         throw new Error('recovery words not available');
      }

      const words = this._cachedRecoveryWords;
      this._cachedRecoveryWords = undefined;
      return words;
   }

   // Generates a fresh recovery secret for userId and returns its public key (to
   // store) and words (to show once).
   private _newRecovery(userId: string): { recoveryPubKey: string, recoveryWords: string } {
      const recoveryId = getRandom(RECOVERYID_BYTES);
      const secret = recoverySecret(recoveryId, userId);
      try {
         return {
            recoveryPubKey: bytesToBase64(getRecoveryPubKey(secret)),
            recoveryWords: entropyToMnemonic(secret, wordlist)
         };
      } finally {
         secret.fill(0);
         recoveryId.fill(0);
      }
   }

   // Generates fresh recovery words and replaces the server-stored public key. The
   // words are cached for the one-time display that follows.
   public async changeRecoveryWords(): Promise<void> {
      if (!this.hasSession()) {
         throw new Error('no active user');
      }

      // Force another authentication
      await this.reauthenticate();

      const { recoveryPubKey, recoveryWords } = this._newRecovery(this.userId);
      const serverUserInfo = await this._doFetch<UserInfo>({
         method: 'PUT',
         resource: 'recover2/key',
         bodyJSON: JSON.stringify({ recoveryPubKey: recoveryPubKey })
      });

      this._updateLoggedInUser(serverUserInfo);
      this._cachedRecoveryWords = recoveryWords;
   }

   // Forces a passkey assertion for the active user, refreshing the cached userCred.
   public async reauthenticate(): Promise<VerifiedUserInfo> {
      if (!this.hasSession()) {
         throw new Error('no active user');
      }

      const serverLoginUserInfo = await this._createSessionImpl(this.userId);
      return this._loginUser(serverLoginUserInfo);
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
      if (!serverLogin?.userId || serverLogin.userId.length == 0) {
         throw new Error('invalid user id')
      }
      if (!serverLogin.userCred || serverLogin.userCred.length == 0) {
         throw new Error('invalid user credential')
      }
      if (!serverLogin.pkId || serverLogin.pkId.length == 0) {
         throw new Error('invalid passkey id')
      }

      const { derivedKey, version } = await this._keystoreSvc.create(KEYSTORE_SLOT, serverLogin.pkId);
      if (!derivedKey) {
         throw new Error('no active user');
      }

      // Keyprovider takes ownership of masterkey and encryptStream takes ownership of keyprovider
      const keyProvider = new MasterKeyKeyProvider(derivedKey, serverLogin.userId);
      const cipherData = await readStreamAll(
         await this._cipherSvc.encryptStream(
            streamFromBase64(serverLogin.userCred),
            keyProvider,
            { algs: ['X20-PLY'] }
         )
      );

      const userCredEnc = bytesToBase64(cipherData);
      const userCredExpiry = new Date(Date.now() + SESSION_TIMEOUT_SEC * 1000).toISOString();
      const userInfo = this._loginRestore(serverLogin, userCredEnc, userCredExpiry, version )
      this._broadcastSvc.sendLogin({
         pkId: serverLogin.pkId,
         userCredEnc,
         userCredExpiry,
         version,
      });

      return userInfo;
   }

   // Restores session from a peer tab's relay.
   private async _loginRestore(
      serverLogin: LoginUserInfo,
      userCredEnc: string,
      userCredExpiry: string,
      version: number
   ): Promise<VerifiedUserInfo> {
      if (!serverLogin.userId || serverLogin.userId.length == 0) {
         throw new Error('invalid user id')
      }
      if (!serverLogin.pkId || serverLogin.pkId.length == 0) {
         throw new Error('invalid passkey id')
      }
      if (!userCredEnc) {
         throw new Error('missing encrypted credential')
      }
      if (!userCredExpiry) {
         throw new Error('missing credential expiry')
      }
      if (version < 1) {
         throw new Error('invalid version number')
      }

      const sessionState: SessionState = {
         pkId: serverLogin.pkId,
         userId: serverLogin.userId,
         userCredEnc: userCredEnc,
         userCredExpiry: userCredExpiry,
         version: version,
      };
      sessionStorage.setItem('sessionstate', JSON.stringify(sessionState));
      return this._loginFinalize(serverLogin, userCredExpiry);
   }

   private _loginFinalize(serverLogin: LoginUserInfo, sessExpiry: string): VerifiedUserInfo {
      if (!serverLogin.csrf || serverLogin.csrf.length == 0) {
         throw new Error('invalid csrf token')
      }
      if (!sessExpiry) {
         throw new Error('missing session expiry')
      }

      this._csrf = serverLogin.csrf;
      localStorage.setItem('sessionexpiry', sessExpiry);
      localStorage.setItem('userid', serverLogin.userId!);
      localStorage.setItem('pkid', serverLogin.pkId!);

      const userInfo = this._updateLoggedInUser(serverLogin);
      this._emit(this._captureEventData(AuthEvent.Login));
      return userInfo;
   }

   private _getCredentialPayload(): CredentialPayload | undefined {
      const sessionState = this._getSessionState();
      if (sessionState && this.hasSession() && !expired(localStorage, 'sessionexpiry')) {
         return {
            pkId: sessionState.pkId!,
            version: sessionState.version!,
            userCredEnc: sessionState.userCredEnc!,
            userCredExpiry: sessionState.userCredExpiry!,
         };
      }
      return undefined;
   }

   private _handlePeerMessage(msg: PeerMessage): void {
      switch (msg.kind) {
         case MessageKind.Forget:
            this._handlePeerForget();
            return;
         case MessageKind.Logout:
            this._handlePeerLogout(msg);
            return;
         case MessageKind.Login:
            this._handlePeerLogin(msg);
            return;
         case MessageKind.UserInfoChanged:
            this._handlePeerUserInfoChanged(msg);
            return;
      }
   }

   private _handlePeerForget(): void {
      this.forgetUser(false);
   }

   private _handlePeerLogout(msg: LogoutPayload): void {
      const sessionState = this._getSessionState();
      if (sessionState && sessionState.version && msg.version >= sessionState.version) {
         this.logout(false);
      }
   }

   private _handlePeerLogin(msg: LoginPayload): void {
      if(this.hasSession()) {
         const sessionState = this._getSessionState()!;
         if (msg.version > sessionState.version!) {
            if (this.userInfo()!.authenticators.some((auth: AuthenticatorInfo) => auth.credentialId === msg.pkId)) {
               // We know the passkey, switch to it
               this._adoptPeerLogin(msg);
            } else if (this.validKnownUser()) {
               // Same user, unknown passkey (rare), logout
               this.logout(false);
            } else {
               // Different user signed in
               this.forgetUser(false);
            }
         }
      } else if (!this.validKnownUser()) {
         // No session and a different user signed in
         this.forgetUser(false);
      }
   }

   private _handlePeerUserInfoChanged(msg: PasskeyIdPayload): void {
      const userInfo = this.userInfo();
      if (this.hasSession() && userInfo!.authenticators.some((auth: AuthenticatorInfo) => auth.credentialId === msg.pkId)) {
         this.refreshUserInfo().catch((err) => console.error(err));
      }
   }

   private async _adoptPeerLogin(msg: LoginPayload): Promise<void> {
      // must use new peer session state to access userCred and GET the session csrf
      // from the server
      const session: SessionState = {
         userId: this.userId,
         pkId: msg.pkId,
         userCredEnc: msg.userCredEnc,
         userCredExpiry: msg.userCredExpiry,
         version: msg.version,
      };
      const serverLoginUserInfo = await this._doFetch<LoginUserInfo>({
         method: 'GET',
         resource: 'session',
         session,
      });
      if (!serverLoginUserInfo || !serverLoginUserInfo.verified) {
         this.logout(false);
      } else {
         await this._loginRestore(
            serverLoginUserInfo,
            msg.userCredEnc,
            msg.userCredExpiry,
            msg.version,
         );
      }
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

      const userInfo: VerifiedUserInfo = {
         userId: serverUser.userId!,
         userName: serverUser.userName!,
         pkId: session.pkId!,
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
      const activityExpiry = new Date(Date.now() + ACTIVITY_TIMEOUT_SEC * 1000).toISOString();
      localStorage.setItem('activityexpiry', activityExpiry);

      // Currently every 2 minutes
      this._intervalId = window.setInterval(() => this._timerTick(), EXPIRY_CHECK_INTERVAL_MS);
   }

   private _timerTick(): void {
      if (!this.validKnownUser()) {
         // this happens when another tab or window forgets the user or switches to a different user.
         // don't do a global forgetuser since other tab could have a valid session
         this.forgetUser(false);
      } else if (!this.potentialSession()) {
         // potentialSession becomes false if either inactivity timer expires in this tab
         // or another. since we are tracking other tabs, this may be a bit annoying
         // but is more conservative, and having multiple tabs open is less common
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
         this._keystoreSvc.delete(KEYSTORE_SLOT);
         this._broadcastSvc.sendForget();
      }
      this._emit(eventData);
   }

   logout(global: boolean, emit: boolean = true) {
      const eventData = this._captureEventData(AuthEvent.Logout);
      const session = this._getSessionState();

      if (global && this.hasSession()) {
         this._pendingLogout = this._doFetch<string>({
            method: 'DELETE',
            resource: 'session'
         }).catch(() => undefined);

         // rather than clear values, which can trigger error in other tabs,
         // set expirations to the past to trigger clear self-logout
         const expired = new Date(Date.now() - 10000).toISOString();
         localStorage.setItem('activityexpiry', expired);
         localStorage.setItem('sessionexpiry', expired);

         this._broadcastSvc.sendLogout({ pkId: session!.pkId!, version: session!.version! });
      }

      if (this._intervalId) {
         clearInterval(this._intervalId);
         this._intervalId = 0;
      }

      this.userInfo.set(undefined);
      if (session?.userId) {
         // Preserve userId so this tab refuses to auto-resume a different user's session
         const partial: SessionState = { userId: session.userId };
         sessionStorage.setItem('sessionstate', JSON.stringify(partial));
      } else {
         sessionStorage.removeItem('sessionstate');
      }

      // clear sensitive in-memory values
      this._csrf = undefined;
      this._cachedRecoveryWords = undefined;

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

      const userInfo = this._updateLoggedInUser(serverUserInfo);
      this._broadcastSvc.sendUserInfoChanged({ pkId: userInfo.pkId });
      return userInfo;
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

      const userInfo = this._updateLoggedInUser(serverUserInfo);
      this._broadcastSvc.sendUserInfoChanged({ pkId: userInfo.pkId });
      return userInfo;
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
         const userInfo = this._updateLoggedInUser(serverUserInfo);
         this._broadcastSvc.sendUserInfoChanged({ pkId: userInfo.pkId });
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
      const serverLoginUserInfo = await this._createSessionImpl(userId);
      return this._loginUser(serverLoginUserInfo);
   }

   // If no userId is provided, will present all Passkeys for this domain
   private async _createSessionImpl(
      userId: string | null = null
   ): Promise<LoginUserInfo> {
      const params = 'usercred=true';
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
      if (!recoveryBytes || recoveryBytes.byteLength !== RECOVERYID_BYTES + cc.USERID_BYTES) {
         throw new Error('invalid recovery words');
      }

      const recoveryIdBytes = new Uint8Array(recoveryBytes.buffer, 0, RECOVERYID_BYTES);
      const userIdBytes = new Uint8Array(recoveryBytes.buffer, RECOVERYID_BYTES);

      const recoveryId = bytesToBase64(recoveryIdBytes);
      const userId = bytesToBase64(userIdBytes);

      return [recoveryId, userId];
   }

   async recover2(recoveryWords: string): Promise<VerifiedUserInfo> {

      const [, userId] = this.getRecoveryValues(recoveryWords);
      const secret = mnemonicToEntropy(recoveryWords, wordlist);
      await this._pendingLogout;

      try {
         const { challenge } = await this._doFetch<{ challenge: string }>({
            method: 'POST',
            resource: 'recover2/challenge',
            bodyJSON: JSON.stringify({ userId: userId })
         });
         if (!challenge || base64ToBytes(challenge).byteLength !== CHALLENGE_BYTES) {
            throw new Error('invalid challenge');
         }

         const signature = signRecoveryProof(secret, userId, challenge);
         const optionsJson = await this._doFetch<PublicKeyCredentialCreationOptionsJSON>({
            method: 'POST',
            resource: 'recover2',
            bodyJSON: JSON.stringify({
               userId: userId,
               challenge: challenge,
               signature: bytesToBase64(signature)
            })
         });

         const serverLoginUserInfo = await this._finishRegistration(optionsJson);
         return this._loginUser(serverLoginUserInfo);
      } finally {
         secret.fill(0);
      }
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

      const serverLoginUserInfo = await this._finishRegistration(optionsJson);
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

      // Create the account with its recovery key in one step. The words are cached
      // for the one-time display that follows creation.
      const { recoveryPubKey, recoveryWords } = this._newRecovery(optionsJson.user.id);

      const serverLoginUserInfo = await this._finishRegistration(optionsJson, recoveryPubKey);
      const userInfo = await this._loginUser(serverLoginUserInfo);
      this._cachedRecoveryWords = recoveryWords;
      return userInfo;
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

      const serverLoginUserInfo = await this._passkeyVerify(optionsJson, false);
      const userInfo = this._updateLoggedInUser(serverLoginUserInfo);
      this._broadcastSvc.sendUserInfoChanged({ pkId: userInfo.pkId });
      return userInfo;
   }

   private async _passkeyVerify(
      optionsJson: PublicKeyCredentialCreationOptionsJSON,
      includeUserCred: boolean
   ): Promise<LoginUserInfo> {

      return this._doPasskeyVerify(
         'passkeys',
         optionsJson,
         includeUserCred
      );
   }

   private async _finishRegistration(
      optionsJson: PublicKeyCredentialCreationOptionsJSON,
      recoveryPubKey?: string
   ): Promise<LoginUserInfo> {

      return this._doPasskeyVerify(
         'reg',
         optionsJson,
         true,
         recoveryPubKey
      );
   }

   private async _doPasskeyVerify(
      base: string,
      optionsJson: PublicKeyCredentialCreationOptionsJSON,
      includeUserCred: boolean,
      recoveryPubKey?: string
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
         ...(recoveryPubKey ? { recoveryPubKey } : {})
      }

      const params = includeUserCred ? 'usercred=true' : '';

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
