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
import { TestBed } from '@angular/core/testing';
import {
   BroadcastService,
   type CredentialPayload,
   MessageKind,
   type PeerMessage,
} from './broadcast.service';

const TEST_PK_ID = 'pk-test-1234567890abcdef';
const ALT_PK_ID = 'pk-test-fedcba0987654321';
const USER_CRED_ENC = 'enc-blob-base64-aaaaaaaaaaaaaaaa';
const ALT_USER_CRED_ENC = 'enc-blob-base64-bbbbbbbbbbbbbbbb';
const TEST_EXPIRY = new Date(Date.now() + 60 * 60 * 1000).toISOString();
const ALT_EXPIRY = new Date(Date.now() + 2 * 60 * 60 * 1000).toISOString();
const CHANNEL_NAME = 'qcrypt-encrypted-credentials';

const TEST_CRED: CredentialPayload = {
   pkId: TEST_PK_ID,
   userCredEnc: USER_CRED_ENC,
   userCredExpiry: TEST_EXPIRY,
   version: 1,
};

const ALT_CRED: CredentialPayload = {
   pkId: ALT_PK_ID,
   userCredEnc: ALT_USER_CRED_ENC,
   userCredExpiry: ALT_EXPIRY,
   version: 2,
};

describe('BroadcastService', () => {
   let requester: BroadcastService;
   let responder: BroadcastService;

   beforeEach(() => {
      TestBed.configureTestingModule({});
      requester = TestBed.inject(BroadcastService);
      responder = new BroadcastService();
      requester.start();
      responder.start();
   });

   afterEach(() => {
      requester.close();
      responder.close();
   });

   it('should be created', () => {
      expect(requester).toBeTruthy();
   });

   it('round-trips a credential when peer pkId matches', async () => {
      responder.setCredentialProvider(() => TEST_CRED);
      const result = await requester.requestCredential(TEST_PK_ID);
      expect(result).toEqual(TEST_CRED);
   });

   it('returns undefined when no peer provider is registered', async () => {
      const result = await requester.requestCredential(TEST_PK_ID);
      expect(result).toBeUndefined();
   });

   it('extendIfEmpty extends collection time when no peer responds', async () => {
      const baseStart = performance.now();
      const baseResult = await requester.requestCredential(TEST_PK_ID);
      const baseElapsed = performance.now() - baseStart;
      expect(baseResult).toBeUndefined();

      const extendedStart = performance.now();
      const extendedResult = await requester.requestCredential(TEST_PK_ID, true);
      const extendedElapsed = performance.now() - extendedStart;
      expect(extendedResult).toBeUndefined();

      // Extended must take longer than the default to prove the extension fired
      expect(extendedElapsed).toBeGreaterThan(baseElapsed * 2);
   });

   it('returns undefined when peer provider pkId does not match', async () => {
      responder.setCredentialProvider(() => ALT_CRED);
      const result = await requester.requestCredential(TEST_PK_ID);
      expect(result).toBeUndefined();
   });

   it('returns undefined when peer provider returns undefined', async () => {
      responder.setCredentialProvider(() => undefined);
      const result = await requester.requestCredential(TEST_PK_ID);
      expect(result).toBeUndefined();
   });

   it('picks the highest-version response within the collection window', async () => {
      const peerA = new BroadcastService();
      const peerB = new BroadcastService();
      peerA.start();
      peerB.start();

      try {
         peerA.setCredentialProvider(() => ({ ...TEST_CRED, version: 3 }));
         peerB.setCredentialProvider(() => ({ ...TEST_CRED, version: 5 }));

         const result = await requester.requestCredential(TEST_PK_ID);

         expect(result).toEqual({ ...TEST_CRED, version: 5 });
      } finally {
         peerA.close();
         peerB.close();
      }
   });

   it('concurrent requestCredential calls resolve independently', async () => {
      responder.setCredentialProvider(() => TEST_CRED);

      const [a, b] = await Promise.all([
         requester.requestCredential(TEST_PK_ID),
         requester.requestCredential(TEST_PK_ID),
      ]);

      expect(a).toEqual(TEST_CRED);
      expect(b).toEqual(TEST_CRED);
   });

   it('reflects live credential changes via the callback', async () => {
      let credential: CredentialPayload | undefined = undefined;
      responder.setCredentialProvider(() => credential);

      const firstAttempt = await requester.requestCredential(TEST_PK_ID);
      expect(firstAttempt).toBeUndefined();

      credential = TEST_CRED;
      const secondAttempt = await requester.requestCredential(TEST_PK_ID);
      expect(secondAttempt).toEqual(TEST_CRED);
   });

   it('ignores responses with mismatched nonce', async () => {
      const interloper = new BroadcastChannel(CHANNEL_NAME);
      try {
         interloper.postMessage({
            kind: MessageKind.CredentialResponse,
            ...TEST_CRED,
            nonce: 'stale-nonce-not-from-this-request',
         });
         const result = await requester.requestCredential(TEST_PK_ID);
         expect(result).toBeUndefined();
      } finally {
         interloper.close();
      }
   });

   it('ignores ill-formed messages', async () => {
      const interloper = new BroadcastChannel(CHANNEL_NAME);
      try {
         interloper.postMessage('not-an-object');
         interloper.postMessage(42);
         interloper.postMessage({ kind: MessageKind.CredentialResponse });
         interloper.postMessage({ kind: MessageKind.CredentialResponse, pkId: TEST_PK_ID });
         interloper.postMessage({ kind: 'unknown-kind', pkId: TEST_PK_ID });
         const result = await requester.requestCredential(TEST_PK_ID);
         expect(result).toBeUndefined();
      } finally {
         interloper.close();
      }
   });

   it('responder ignores ill-formed credRequest messages', async () => {
      const seen: PeerMessage[] = [];
      const sniffer = new BroadcastChannel(CHANNEL_NAME);
      sniffer.addEventListener('message', (event) => {
         const data = event.data;
         if (data && typeof data === 'object' && (data as { kind?: string }).kind === MessageKind.CredentialResponse) {
            seen.push(data);
         }
      });

      responder.setCredentialProvider(() => TEST_CRED);

      const interloper = new BroadcastChannel(CHANNEL_NAME);
      try {
         interloper.postMessage('not-an-object');
         interloper.postMessage({ kind: MessageKind.CredentialRequest });
         interloper.postMessage({ kind: MessageKind.CredentialRequest, pkId: TEST_PK_ID });
         interloper.postMessage({ kind: 'unknown-kind', pkId: TEST_PK_ID, nonce: 'n' });

         await new Promise((resolve) => setTimeout(resolve, 100));
         expect(seen).toEqual([]);
      } finally {
         interloper.close();
         sniffer.close();
      }
   });

   it('start is idempotent', () => {
      expect(() => requester.start()).not.toThrow();
      expect(() => requester.start()).not.toThrow();
   });

   it('requestCredential throws when not started', async () => {
      const fresh = new BroadcastService();
      try {
         await expect(fresh.requestCredential(TEST_PK_ID)).rejects.toThrow(/not started/);
      } finally {
         fresh.close();
      }
   });

   it('close resolves pending requests with undefined', async () => {
      const pending = requester.requestCredential(TEST_PK_ID);
      requester.close();
      await expect(pending).resolves.toBeUndefined();
   });

   it('handler receives login messages', async () => {
      const received: PeerMessage[] = [];
      requester.setMessageHandler((msg) => received.push(msg));

      responder.sendLogin({
         pkId: TEST_PK_ID,
         version: 7,
         userCredEnc: USER_CRED_ENC,
         userCredExpiry: TEST_EXPIRY,
      });

      await new Promise((resolve) => setTimeout(resolve, 50));
      expect(received).toEqual([{
         kind: MessageKind.Login,
         pkId: TEST_PK_ID,
         version: 7,
         userCredEnc: USER_CRED_ENC,
         userCredExpiry: TEST_EXPIRY,
      }]);
   });

   it('handler receives logout messages', async () => {
      const received: PeerMessage[] = [];
      requester.setMessageHandler((msg) => received.push(msg));

      responder.sendLogout({ pkId: TEST_PK_ID, version: 4 });

      await new Promise((resolve) => setTimeout(resolve, 50));
      expect(received).toEqual([{
         kind: MessageKind.Logout,
         pkId: TEST_PK_ID,
         version: 4,
      }]);
   });

   it('handler receives forget messages', async () => {
      const received: PeerMessage[] = [];
      requester.setMessageHandler((msg) => received.push(msg));

      responder.sendForget();

      await new Promise((resolve) => setTimeout(resolve, 50));
      expect(received).toEqual([{ kind: MessageKind.Forget }]);
   });

   it('handler receives userInfoChanged messages', async () => {
      const received: PeerMessage[] = [];
      requester.setMessageHandler((msg) => received.push(msg));

      responder.sendUserInfoChanged({ pkId: TEST_PK_ID });

      await new Promise((resolve) => setTimeout(resolve, 50));
      expect(received).toEqual([{ kind: MessageKind.UserInfoChanged, pkId: TEST_PK_ID }]);
   });

   it('handler does not receive credRequest or credResponse internal messages', async () => {
      const received: PeerMessage[] = [];
      requester.setMessageHandler((msg) => received.push(msg));
      responder.setCredentialProvider(() => TEST_CRED);

      await requester.requestCredential(TEST_PK_ID);

      expect(received).toEqual([]);
   });

   it('close discards the channel and stops dispatching', async () => {
      const received: PeerMessage[] = [];
      requester.setMessageHandler((msg) => received.push(msg));
      requester.close();

      responder.sendForget();

      await new Promise((resolve) => setTimeout(resolve, 50));
      expect(received).toEqual([]);
   });

   it('different requested pkIds are routed to their own pending', async () => {
      const altResponder = new BroadcastService();
      altResponder.start();

      try {
         responder.setCredentialProvider(() => TEST_CRED);
         altResponder.setCredentialProvider(() => ALT_CRED);

         const [matchedTest, matchedAlt, unmatched] = await Promise.all([
            requester.requestCredential(TEST_PK_ID),
            requester.requestCredential(ALT_PK_ID),
            requester.requestCredential('pk-bogus-not-served-by-anyone'),
         ]);

         expect(matchedTest).toEqual(TEST_CRED);
         expect(matchedAlt).toEqual(ALT_CRED);
         expect(unmatched).toBeUndefined();
      } finally {
         altResponder.close();
      }
   });
});
