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
import { Injectable } from '@angular/core';

const CHANNEL_NAME = 'qcrypt-encrypted-credentials';
const COLLECTION_WINDOW_MS = 120;
const COLLECTION_MAX_STAGES = 6;
const PROPAGATION_DELAY_MS = 10;

export enum MessageKind {
   Login = 'login',
   Logout = 'logout',
   Forget = 'forget',
   UserInfoChanged = 'userInfoChanged',
   CredentialRequest = 'sessRequest',
   CredentialResponse = 'sessResponse',
}

export type PasskeyIdPayload = {
   pkId: string;
};

export type LogoutPayload = PasskeyIdPayload & {
   version: number;
};

export type CredentialPayload = PasskeyIdPayload & {
   version: number;
   userCredEnc: string;
   userCredExpiry: string;
};

export type LoginPayload = CredentialPayload;

export type LoginMessage = LoginPayload & {kind: MessageKind.Login};
export type LogoutMessage = LogoutPayload & {kind: MessageKind.Logout};
export type ForgetMessage = {kind: MessageKind.Forget};
export type UserInfoChangedMessage = PasskeyIdPayload & {kind: MessageKind.UserInfoChanged};
type CredentialRequestMessage = PasskeyIdPayload & {kind: MessageKind.CredentialRequest; nonce: string};
type CredentialResponseMessage = CredentialPayload & {kind: MessageKind.CredentialResponse; nonce: string};

export type PeerMessage =
   | LoginMessage
   | LogoutMessage
   | ForgetMessage
   | UserInfoChangedMessage
   | CredentialRequestMessage
   | CredentialResponseMessage;

type Responses = {
   pkId: string;
   credentials: CredentialPayload[];
   timer: number;
   resolve: (value: CredentialPayload | undefined) => void;
};

@Injectable({
   providedIn: 'root',
})
export class BroadcastService {
   private _channel?: BroadcastChannel;
   private _pending = new Map<string, Responses>();
   private _unfulfilledNonce?: string;
   private _credentialProvider?: () => CredentialPayload | undefined;
   private _messageHandler?: (msg: LoginMessage | LogoutMessage | ForgetMessage | UserInfoChangedMessage) => void;

   public start() {
      if (!this._channel) {
         this._channel = new BroadcastChannel(CHANNEL_NAME);
         this._channel.addEventListener('message', this._dispatch);
      }
   }

   public close() {
      for (const pending of this._pending.values()) {
         clearTimeout(pending.timer);
         pending.resolve(undefined);
      }
      this._pending.clear();

      if (this._channel) {
         this._channel.removeEventListener('message', this._dispatch);
         this._channel.close();
      }
      this._channel = undefined;
   }

   public setCredentialProvider(credentialProvider: () => CredentialPayload | undefined) {
      this._credentialProvider = credentialProvider;
   }

   public setMessageHandler(messageHandler: (msg: PeerMessage) => void) {
      this._messageHandler = messageHandler;
   }

   // Pass extendIfEmpty=true when the caller's main thread may be under
   // contention and additional time may be needed for response collection
   public async requestCredential(
      pkId: string,
      extendIfEmpty: boolean = false
   ): Promise<CredentialPayload | undefined> {
      this._requireStarted();
      const nonce = crypto.randomUUID();

      return new Promise<CredentialPayload | undefined>((resolve) => {
         // Run one collection window unless extendIfEmpty is set, in which case start new
         // collections until one receives a response or COLLECTION_MAX_STAGES extensions elapse.
         const startStage = (count: number): number => {
            return window.setTimeout(() => {
               const pending = this._pending.get(nonce);
               if (pending) {
                  if (pending.credentials.length === 0 && extendIfEmpty && count < COLLECTION_MAX_STAGES) {
                     pending.timer = startStage(count + 1)
                  } else {
                     this._pending.delete(nonce);
                     this._unfulfilledNonce = pending.credentials.length === 0 ? nonce : undefined;
                     pending.resolve(this._getBestCredential(pending.credentials));
                  }
               }
            }, COLLECTION_WINDOW_MS);
         };

         this._pending.set(nonce, { pkId, credentials: [], timer:  startStage(1), resolve });
         this._channel!.postMessage({ kind: MessageKind.CredentialRequest, pkId, nonce });
      });
   }

   public sendLogin(login: LoginPayload) {
      this._requireStarted();
      this._channel!.postMessage({ kind: MessageKind.Login, ...login });
   }

   public sendLogout(logout: LogoutPayload) {
      this._requireStarted();
      this._channel!.postMessage({ kind: MessageKind.Logout, ...logout });
   }

   public sendForget() {
      this._requireStarted();
      this._channel!.postMessage({ kind: MessageKind.Forget });
   }

   public sendUserInfoChanged(passkeyId: PasskeyIdPayload) {
      this._requireStarted();
      this._channel!.postMessage({ kind: MessageKind.UserInfoChanged, ...passkeyId });
   }

   private _requireStarted() {
      if (!this._channel) {
         throw new Error('BroadcastService not started');
      }
   }

   private _dispatch = (event: MessageEvent): void => {
      const msg = decodeMessage(event.data);
      if (msg) {
         switch (msg.kind) {
            case MessageKind.CredentialRequest:
               this._credentialRequest(msg);
               return;
            case MessageKind.CredentialResponse:
               this._credentialResponse(msg);
               return;
            default:
               // Yield so cross-tab localStorage writes that preceded this
               // message have time to propagate to our renderer.
               setTimeout(() => this._messageHandler?.(msg), PROPAGATION_DELAY_MS);
         }
      }
   }

   private _credentialRequest(request: CredentialRequestMessage) {
      const myCredential = this._credentialProvider?.();
      if (myCredential && myCredential.pkId === request.pkId) {
         this._channel!.postMessage({
            kind: MessageKind.CredentialResponse,
            nonce: request.nonce,
            ...myCredential
         });
      }
   }

   private _credentialResponse(response: CredentialResponseMessage) {
      const pending = this._pending.get(response.nonce);
      if (response.nonce === this._unfulfilledNonce) {
         console.error('credential response arrived after its collection window closed');
      }
      if (pending && response.pkId === pending.pkId) {
         const { pkId, version, userCredEnc, userCredExpiry } = response;
         pending.credentials.push({ pkId, version, userCredEnc, userCredExpiry });
      }
   }

   private _getBestCredential(credentials: CredentialPayload[]): CredentialPayload | undefined {
      if (credentials.length === 0) {
         return undefined;
      }
      return credentials.reduce((best, response) => {
         if (response.version > best.version) {
            return response;
         }
         return best;
      });
   }
}

export function decodeMessage(raw: unknown): PeerMessage | undefined {
   if (!raw || typeof raw !== 'object') {
      return undefined;
   }
   const candidate = raw as Partial<PeerMessage>;
   if (candidate.kind === MessageKind.Login
      && typeof candidate.pkId === 'string'
      && typeof candidate.version === 'number'
      && typeof candidate.userCredEnc === 'string'
      && typeof candidate.userCredExpiry === 'string') {
      return candidate as PeerMessage;
   } else if (candidate.kind === MessageKind.Logout
      && typeof candidate.pkId === 'string'
      && typeof candidate.version === 'number') {
      return candidate as PeerMessage;
   } else if (candidate.kind === MessageKind.Forget) {
      return candidate as PeerMessage;
   } else if (candidate.kind === MessageKind.UserInfoChanged
      && typeof candidate.pkId === 'string') {
      return candidate as PeerMessage;
   } else if (candidate.kind === MessageKind.CredentialRequest
      && typeof candidate.pkId === 'string'
      && typeof (candidate as { nonce?: unknown }).nonce === 'string') {
      return candidate as PeerMessage;
   } else if (candidate.kind === MessageKind.CredentialResponse
      && typeof candidate.pkId === 'string'
      && typeof candidate.version === 'number'
      && typeof candidate.userCredEnc === 'string'
      && typeof candidate.userCredExpiry === 'string'
      && typeof (candidate as { nonce?: unknown }).nonce === 'string') {
      return candidate as PeerMessage;
   }

   return undefined;
}


