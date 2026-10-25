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

import { environment } from '../../environments/environment';
import { bytesToBase64, bufferToHexString, getRandom } from '@qcrypt/crypto';
import * as api from '@qcrypt/api';

const baseUrl = environment.apiHost;

export type ApiRequest = {
   errorLogout?: (global: boolean) => void;
} & (
   | {
        method: 'GET' | 'DELETE';
        resource: string;
        resourceId?: string;
        params?: string;
     }
   | {
        method: 'POST' | 'PUT' | 'PATCH';
        resource: string;
        resourceId?: string;
        params?: string;
        bodyJSON?: string;
     }
);

type RequestInfo = {
   url: URL;
   headers: Headers;
   body?: string;
   bodyHashHex: string;
};

export async function plainFetch<T>(request: ApiRequest): Promise<T> {
   return _doFetch<T>(request, await _prepareRequest(request));
}

// Takes ownership of and clears the `userCred` parameter
export async function nonceFetch<T>(
   request: ApiRequest,
   csrf: string | undefined,
   userId: string,
   userCred: Uint8Array,
): Promise<T> {
   let requestInfo: RequestInfo;
   try {
      requestInfo = await _prepareRequest(request, csrf);
      const timestamp = String(Date.now());
      const nonce = bytesToBase64(getRandom(api.CHALLENGE_BYTES));
      const signature = api.createUserCredNonceProof(
         userCred,
         userId,
         request.method,
         requestInfo.url.pathname,
         timestamp,
         nonce,
         requestInfo.bodyHashHex,
         requestInfo.url.search.slice(1),
      );
      requestInfo.headers.append('x-nonce-proof', `${signature},${timestamp},${nonce}`);
   } finally {
      userCred.fill(0);
   }

   return _doFetch<T>(request, requestInfo);
}

// Takes ownership of and clears the `userCred` parameter
export async function challengeFetch<T>(
   request: ApiRequest,
   csrf: string | undefined,
   userId: string,
   userCred: Uint8Array,
   challenge: string,
): Promise<T> {
   let requestInfo: RequestInfo;
   try {
      requestInfo = await _prepareRequest(request, csrf);
      const timestamp = String(Date.now());
      const signature = api.createUserCredChallengeProof(
         userCred,
         userId,
         request.method,
         requestInfo.url.pathname,
         timestamp,
         challenge,
         requestInfo.bodyHashHex,
         requestInfo.url.search.slice(1),
      );
      requestInfo.headers.append('x-challenge-proof', `${signature},${timestamp}`);
   } finally {
      userCred.fill(0);
   }

   return _doFetch<T>(request, requestInfo);
}

async function _prepareRequest(request: ApiRequest, csrf?: string): Promise<RequestInfo> {
   const { method, resource, resourceId, params } = request;
   const body = 'bodyJSON' in request ? request.bodyJSON : undefined;

   let path = `${environment.apiVersion}/${resource}`;
   path += resourceId ? `/${resourceId}` : '';
   path += params ? `?${params}` : '';
   const url = new URL(path, baseUrl);

   const bodyData = new TextEncoder().encode(body ?? '');
   const bodyHashHex = bufferToHexString(await crypto.subtle.digest('SHA-256', bodyData));

   const headers = new Headers({ 'Content-Type': 'application/json' });
   if (csrf) {
      headers.append('x-csrf-token', csrf);
   }

   // required for AWS OAC (access control to lambda).
   if (method === 'PUT' || method === 'POST' || method === 'PATCH') {
      headers.append('x-amz-content-sha256', bodyHashHex);
   }

   return { url, headers, body, bodyHashHex };
}

async function _doFetch<T>(request: ApiRequest, requestInfo: RequestInfo): Promise<T> {
   const { url, headers, body } = requestInfo;

   let response: Response;
   try {
      response = await fetch(url, {
         method: request.method,
         mode: 'cors',
         cache: 'no-store',
         credentials: 'include',
         body,
         headers,
      });
   } catch (err) {
      console.error(err);
      throw new Error(`fetch error: ${url}`);
   }

   if (!response.ok) {
      if (response.status === 401 && request.errorLogout) {
         // currently 401 only comes back when auth failed, so logout if
         // provided. pass false to avoid fetch loop
         request.errorLogout(false);
      }
      throw new Error(`response error: ${await response.text()}`);
   }

   return response.json() as T;
}
