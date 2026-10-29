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

import { bufferToHexString, bytesToBase64, cryptoReady, getRandom } from '@qcrypt/crypto';
import * as cc from '@qcrypt/crypto/consts';
import * as api from '@qcrypt/api';
import { challengeFetch, nonceFetch, plainFetch } from './apifetch';

type SentRequest = { url: URL; init: RequestInit; headers: Headers };

describe('apifetch', () => {
   let originalFetch: typeof fetch;
   let fetchMock: ReturnType<typeof vi.fn>;
   let userId: string;

   beforeEach(async () => {
      await cryptoReady();
      userId = bytesToBase64(getRandom(cc.USERID_BYTES));
      originalFetch = window.fetch;
      fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => ({}) });
      window.fetch = fetchMock as typeof fetch;
   });

   afterEach(() => {
      window.fetch = originalFetch;
   });

   function sentRequest(index: number = 0): SentRequest {
      const [url, init] = fetchMock.mock.calls[index] as [URL, RequestInit];
      return { url, init, headers: init.headers as Headers };
   }

   function newUserCred(): { userCred: Uint8Array<ArrayBuffer>; pubKey: string } {
      const userCred = getRandom(cc.USERCRED_BYTES);
      return { userCred, pubKey: api.getUserCredPubKey(userCred) };
   }

   async function sha256Hex(text: string): Promise<string> {
      return bufferToHexString(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)));
   }

   function verifyNonceProof(sent: SentRequest, pubKey: string, bodyHashHex: string): void {
      const [signature, timestamp, nonce] = sent.headers.get('x-nonce-proof')!.split(',');
      api.verifyUserCredNonceProof(
         pubKey,
         userId,
         sent.init.method!,
         sent.url.pathname,
         timestamp,
         nonce,
         bodyHashHex,
         signature,
         sent.url.search.slice(1),
      );
   }

   function verifyChallengeProof(sent: SentRequest, pubKey: string, bodyHashHex: string, challenge: string): void {
      const [signature, timestamp] = sent.headers.get('x-challenge-proof')!.split(',');
      api.verifyUserCredChallengeProof(
         pubKey,
         userId,
         sent.init.method!,
         sent.url.pathname,
         timestamp,
         challenge,
         bodyHashHex,
         signature,
         sent.url.search.slice(1),
      );
   }

   it('a GET sends no body and no content hash', async () => {
      await plainFetch({ method: 'GET', resource: 'user' });

      const { init, headers } = sentRequest();
      expect(init.method).toBe('GET');
      expect(init.body).toBeUndefined();
      expect(init.credentials).toBe('include');
      expect(headers.has('x-amz-content-sha256')).toBe(false);
   });

   it('a POST sends the body with its SHA-256 hash', async () => {
      const bodyJSON = JSON.stringify({ userName: 'test user' });
      await plainFetch({ method: 'POST', resource: 'reg/options', bodyJSON });

      const { init, headers } = sentRequest();
      expect(init.body).toBe(bodyJSON);
      expect(headers.get('x-amz-content-sha256')).toBe(await sha256Hex(bodyJSON));
   });

   it('a request with resourceId and params sends both in the URL', async () => {
      await plainFetch({ method: 'GET', resource: 'passkeys', resourceId: 'pk1', params: 'limit=2' });

      const { url } = sentRequest();
      expect(url.pathname.endsWith('/passkeys/pk1')).toBe(true);
      expect(url.search).toBe('?limit=2');
   });

   it('a plain request sends no CSRF token or proof', async () => {
      await plainFetch({ method: 'POST', resource: 'auth/options', bodyJSON: '{}' });

      const { headers } = sentRequest();
      expect(headers.has('x-csrf-token')).toBe(false);
      expect(headers.has('x-nonce-proof')).toBe(false);
      expect(headers.has('x-challenge-proof')).toBe(false);
      expect(headers.has('x-proof')).toBe(false);
   });

   it('a nonce request with a CSRF token sends it and a proof', async () => {
      const { userCred, pubKey } = newUserCred();
      const bodyJSON = JSON.stringify({ description: 'test passkey' });
      await nonceFetch(
         { method: 'PATCH', resource: 'passkeys', resourceId: 'pk1', params: 'limit=2', bodyJSON },
         { userId, userCred },
         'csrf-token',
      );

      const sent = sentRequest();
      expect(sent.headers.get('x-csrf-token')).toBe('csrf-token');
      expect(sent.headers.has('x-challenge-proof')).toBe(false);
      verifyNonceProof(sent, pubKey, await sha256Hex(bodyJSON));

      const otherHashHex = await sha256Hex('{}');
      expect(() => verifyNonceProof(sent, pubKey, otherHashHex)).toThrow();
   });

   it('a nonce request without a CSRF token sends only a proof', async () => {
      await nonceFetch({ method: 'GET', resource: 'session' }, { userId, userCred: newUserCred().userCred }, undefined);

      const { headers } = sentRequest();
      expect(headers.has('x-csrf-token')).toBe(false);
      expect(headers.has('x-nonce-proof')).toBe(true);
   });

   it('a challenge request without a CSRF token sends only a proof', async () => {
      const { userCred, pubKey } = newUserCred();
      const challenge = bytesToBase64(getRandom(api.CHALLENGE_BYTES));
      const bodyJSON = JSON.stringify({ userId, challenge });
      await challengeFetch(
         { method: 'POST', resource: 'recover/verify', bodyJSON },
         { userId, userCred, challenge },
         undefined,
      );

      const sent = sentRequest();
      expect(sent.headers.has('x-csrf-token')).toBe(false);
      expect(sent.headers.has('x-nonce-proof')).toBe(false);
      const bodyHashHex = await sha256Hex(bodyJSON);
      verifyChallengeProof(sent, pubKey, bodyHashHex, challenge);

      const otherChallenge = bytesToBase64(getRandom(api.CHALLENGE_BYTES));
      expect(() => verifyChallengeProof(sent, pubKey, bodyHashHex, otherChallenge)).toThrow();
   });

   it('a challenge request with a CSRF token sends it and a proof', async () => {
      const challenge = bytesToBase64(getRandom(api.CHALLENGE_BYTES));
      await challengeFetch(
         { method: 'POST', resource: 'passkeys/verify', bodyJSON: JSON.stringify({ challenge }) },
         { userId, userCred: newUserCred().userCred, challenge },
         'csrf-token',
      );

      const { headers } = sentRequest();
      expect(headers.get('x-csrf-token')).toBe('csrf-token');
      expect(headers.has('x-challenge-proof')).toBe(true);
   });

   it('nonce and challenge requests wipe userCred', async () => {
      const nonceCred = newUserCred().userCred;
      await nonceFetch({ method: 'GET', resource: 'user' }, { userId, userCred: nonceCred }, 'csrf-token');
      expect(nonceCred.every((byte) => byte === 0)).toBe(true);

      const challengeCred = newUserCred().userCred;
      const challenge = bytesToBase64(getRandom(api.CHALLENGE_BYTES));
      await challengeFetch(
         { method: 'POST', resource: 'reg/verify', bodyJSON: '{}' },
         { userId, userCred: challengeCred, challenge },
         undefined,
      );
      expect(challengeCred.every((byte) => byte === 0)).toBe(true);
   });

   it('a request that fails to sign wipes userCred and sends nothing', async () => {
      await nonceFetch({ method: 'GET', resource: 'user' }, { userId, userCred: newUserCred().userCred }, 'csrf-token');
      expect(fetchMock).toHaveBeenCalledTimes(1);

      const nonceCred = newUserCred().userCred;
      await expect(
         nonceFetch(
            { method: 'GET', resource: 'user' },
            { userId: 'not-a-user-id', userCred: nonceCred },
            'csrf-token',
         ),
      ).rejects.toThrow();
      expect(nonceCred.every((byte) => byte === 0)).toBe(true);

      const challengeCred = newUserCred().userCred;
      await expect(
         challengeFetch(
            { method: 'POST', resource: 'reg/verify', bodyJSON: '{}' },
            { userId, userCred: challengeCred, challenge: 'not-a-challenge' },
            undefined,
         ),
      ).rejects.toThrow();
      expect(challengeCred.every((byte) => byte === 0)).toBe(true);
      expect(fetchMock).toHaveBeenCalledTimes(1);
   });

   it('a 401 calls errorLogout with false and rejects', async () => {
      const errorLogout = vi.fn();
      await plainFetch({ method: 'GET', resource: 'user', errorLogout });
      expect(errorLogout).not.toHaveBeenCalled();

      fetchMock.mockResolvedValueOnce({ ok: false, status: 401, text: async () => 'unauthorized' });
      await expect(plainFetch({ method: 'GET', resource: 'user', errorLogout })).rejects.toThrow('unauthorized');
      expect(errorLogout).toHaveBeenCalledExactlyOnceWith(false);
   });

   it('a non-401 error rejects without calling errorLogout', async () => {
      const errorLogout = vi.fn();
      fetchMock.mockResolvedValueOnce({ ok: false, status: 500, text: async () => 'server error' });

      await expect(plainFetch({ method: 'GET', resource: 'user', errorLogout })).rejects.toThrow('server error');
      expect(errorLogout).not.toHaveBeenCalled();
   });

   it('a network failure rejects with the URL', async () => {
      vi.spyOn(console, 'error').mockImplementation(() => undefined);
      fetchMock.mockRejectedValueOnce(new TypeError('Failed to fetch'));

      await expect(plainFetch({ method: 'GET', resource: 'user' })).rejects.toThrow(/fetch error: .*\/user/);
   });
});
