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

import { base64Decode, NotFoundError, ParamError } from "./utils";
import type { VerifiedUserItem } from "./models";

export type QParams = Record<string, string>;
export const INTERNAL_VERSION = 0;
export type Method = 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
export type Version = typeof INTERNAL_VERSION | 1;


type HttpHandler = (
   httpDetails: HttpDetails,
   verifiedUser?: VerifiedUserItem,
) => any

export type HttpDetails = {
   name: string,
   method: Method,
   rpID: string,
   rpOrigin: string,
   authorize: boolean,
   resources: Record<string, any>,
   params: QParams,
   body: Record<string, any>,
   handler: HttpHandler,
   version: Version,
   checkCsrf: boolean,
   cookie?: string
};

type HandlerInfo = {
   name: string,
   pattern: URLPattern,
   version: Version,
   authorize: boolean,
   checkCsrf?: boolean,
   handler: HttpHandler
};

export type MethodMap = Record<Method, HandlerInfo[]>;


const hostname = '{*.}?quickcrypt.org'
// Not using specific regext because we get no error information just
// a failed match.
//const b64Chars = '[A-Za-z0-9+/=_-]';

export const Patterns = {
   regOptions: new URLPattern({
      pathname: '/v:ver/reg/options',
   }),
   regVerify: new URLPattern({
      pathname: '/v:ver/reg/verify',
   }),
   authOptions: new URLPattern({
      pathname: '/v:ver/auth/options',
   }),
   authVerify: new URLPattern({
      pathname: '/v:ver/auth/verify',
   }),
   user: new URLPattern({
      pathname: `/v:ver/user`,
   }),
   recover: new URLPattern({
      pathname: `/v:ver/users/:userid/recover/:usercred`,
   }),
   recover2: new URLPattern({
      pathname: `/v:ver/users/:userid/recover2/:recoveryid`,
   }),
   session: new URLPattern({
      pathname: `/v:ver/session`,
   }),
   // Must search options and verify before passkey/:authid
   passkeyOptions: new URLPattern({
      pathname: `/v:ver/passkeys/options`,
   }),
   // Must seach options and verify before passkey/:authid
   passkeyVerify: new URLPattern({
      pathname: `/v:ver/passkeys/verify`,
   }),
   passkey: new URLPattern({
      pathname: `/v:ver/passkeys/:credid`
   }),

   // Sender Link patterns
   senderLinks: new URLPattern({
      pathname: `/v:ver/senderlinks`
   }),
   senderLinkVerify: new URLPattern({
      pathname: `/v:ver/senderlinks/:linkid/verify`
   }),
   senderLinkBind: new URLPattern({
      pathname: `/v:ver/senderlinks/:linkid/bind`
   }),
   senderLink: new URLPattern({
      pathname: `/v:ver/senderlinks/:linkid`
   }),
   senderLinksDelete: new URLPattern({
      pathname: `/v:ver/senderlinks/delete`
   }),

   // Internal only URLS (not allowed through Cloudfront)
   munge: new URLPattern({
      pathname: '/v:ver/munge'
   }),
   loadaaguids: new URLPattern({
      pathname: '/v:ver/loadaaguids'
   }),
   consistency: new URLPattern({
      pathname: '/v:ver/consistency'
   })
};


export function matchEvent(event: Record<string, any>, methodMap: MethodMap): HttpDetails {

   if (!event || !event['requestContext'] ||
      !event['requestContext']['http'] || !event['headers'] ||
      !event['headers']['x-passkey-rpid']
   ) {
      throw new ParamError("invalid request, missing context");
   }

   const rpID = event['headers']['x-passkey-rpid'];
   let rpOrigin = `https://${rpID}`;
   if (event['headers']['x-passkey-port']) {
      rpOrigin += `:${event['headers']['x-passkey-port']}`;
   }

   const method: Method = event['requestContext']['http']['method'].toUpperCase();
   const path = event['requestContext']['http']['path'];
   // console.log(`${method} ${path}`);

   const handlerInfos: HandlerInfo[] = methodMap[method];

   for (let handerInfo of handlerInfos) {
      const match = handerInfo.pattern.exec({
         hostname: rpID,
         pathname: path
      });

      if (match && Number(match.pathname.groups.ver) === handerInfo.version) {

         let body: Record<string, any> = {};
         if ('body' in event) {
            let rawBody = event['body'];
            // Uncomment for debugging
            // console.log(`raw body: ${rawBody}`);

            try {
               if (event.isBase64Encoded) {
                  rawBody = new TextDecoder().decode(base64Decode(rawBody));
               }
               body = JSON.parse(rawBody);
            } catch (err) {
               console.error(err);
               throw new ParamError('invalid json in body');
            }
         }

         const params: QParams = event['queryStringParameters'] ?? {};
         const cookie: string | undefined = event['headers']['cookie'];

         // Uncomment for debugging
         // console.log('resources: ' + JSON.stringify(params));
         // console.log('params: ' + JSON.stringify(match.pathname.groups));
         // console.log('body: ' + JSON.stringify(body));

         return {
            name: handerInfo.name,
            method: method,
            rpID: rpID,
            rpOrigin: rpOrigin,
            authorize: handerInfo.authorize,
            checkCsrf: !(handerInfo.checkCsrf === false), // true or undefined make it required
            resources: match.pathname.groups,
            handler: handerInfo.handler,
            version: handerInfo.version,
            params: params,
            body: body,
            cookie: cookie
         };

      }
   }

   throw new NotFoundError(`invalid request, no ${method} ${path} handler`);
}
