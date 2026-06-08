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

import { describe, it, beforeAll, afterAll, expect } from "vitest";
import {
   getJson,
   postJson,
   patchJson,
   deleteJson,
   registerTestUser,
   setSessionUserCred,
} from "./common";

// Full fuzz is hundreds of live requests; gate it so normal runs stay quick.
const FULL_FUZZ = process.env.QC_FULL_FUZZ === "true";

const badIds = ['', '<script>alert(0)</script>', '42ebNajPIp3leX4K4a0qND', 0, ';24r(%', 3423409, undefined, 'null', '42ebNajPIp3l<seX4K4a0qND42ebNajPIp3leX4K4a0qND42ebNajPIp3leX4K4a0qND'];
const badIdsSmall = ['', '42ebNajPIp3leX4K4a0qND', 0];
const badNames = ['', 123, null, 0, 'aaa2f3lkmflm2;342ebNajPIp3leX4K4a0qNDfm2;l3rm2;rm;1asdfaaaa'];
const badNamesSmall = ['', 0, 'aaa2f3lkmflm2;342ebNajPIp3leX4K4a0qNDfm2;l3rm2;rm;1asdfaaaa'];

function cartesianProduct(arrOfArr: any[][]): any[][] {
   if (!arrOfArr || arrOfArr.length === 0) {
      return [];
   }
   return arrOfArr.reduce(
      (acc, currentArray) => {
         const newAcc: any[][] = [];
         for (const accItem of acc) {
            for (const item of currentArray) {
               newAcc.push([...accItem, item]);
            }
         }
         return newAcc;
      },
      [[]] as any[][]
   );
}

// request() injects a valid proof and the content hash whenever a cookie is
// passed, so these helpers only need to assemble fuzzed paths and bodies.
async function fuzzGet(
   cookie: string,
   csrf: string,
   pathTemplate: string,
   pathValues: any[][]
) {
   for (const sub of cartesianProduct(pathValues)) {
      let path = pathTemplate;
      for (let pos = 0; pos < sub.length; ++pos) {
         path = path.replace(`{${pos}}`, String(sub[pos]));
      }
      const res = await getJson(path, { "x-csrf-token": csrf }, cookie);
      expect(res.status).toBeGreaterThanOrEqual(400);
   }
}

async function fuzzDelete(
   cookie: string,
   csrf: string,
   pathTemplate: string,
   pathValues: any[][]
) {
   for (const sub of cartesianProduct(pathValues)) {
      let path = pathTemplate;
      for (let pos = 0; pos < sub.length; ++pos) {
         path = path.replace(`{${pos}}`, String(sub[pos]));
      }
      const res = await deleteJson(path, { "x-csrf-token": csrf }, cookie);
      expect(res.status).toBeGreaterThanOrEqual(400);
   }
}

async function fuzzPatch(
   cookie: string,
   csrf: string,
   pathTemplate: string,
   pathValues: any[][],
   dataKey: string,
   dataValues: any[]
) {
   pathValues.push(dataValues);
   for (const sub of cartesianProduct(pathValues)) {
      let path = pathTemplate;
      let pos = 0;
      for (; pos < sub.length - 1; ++pos) {
         path = path.replace(`{${pos}}`, String(sub[pos]));
      }
      const data: Record<string, any> = {};
      data[dataKey] = sub[pos];
      const res = await patchJson(path, data, { "x-csrf-token": csrf }, cookie);
      expect(res.status).toBeGreaterThanOrEqual(400);
   }
}

// Replacement values fill either URL {} positions or, when bodyKeys is given,
// body fields keyed by bodyKeys[].
async function fuzzPost(
   cookie: string,
   csrf: string,
   pathTemplate: string,
   replaceValues: any[][],
   bodyKeys?: string[]
) {
   for (const sub of cartesianProduct(replaceValues)) {
      let path = pathTemplate;
      const data: Record<string, any> = {};
      let pos = 0;
      if (bodyKeys) {
         for (; pos < sub.length; ++pos) {
            data[bodyKeys[pos]] = sub[pos];
         }
      } else {
         for (; pos < sub.length; ++pos) {
            path = path.replace(`{${pos}}`, String(sub[pos]));
         }
      }
      const res = await postJson(path, data, { "x-csrf-token": csrf }, cookie);
      expect(res.status).toBeGreaterThanOrEqual(400);
   }
}

async function smallFuzz(cookie: string, csrf: string, userId: string) {
   await fuzzPatch(cookie, csrf,
      `/v1/passkeys/{1}`,
      [[...badIdsSmall, userId], badIdsSmall],
      'description',
      badNamesSmall
   );

   await fuzzPost(cookie, csrf,
      `/v1/auth/verify`,
      [badNamesSmall],
      ['authenticator']
   );
}

async function fullFuzz(cookie: string, csrf: string, userId: string) {
   await fuzzPatch(cookie, csrf,
      `/v1/user`,
      [badIds],
      'userName',
      badNames
   );

   await fuzzPatch(cookie, csrf,
      `/v1/passkeys/{1}`,
      [[...badIdsSmall, userId], badIds],
      'description',
      badNames
   );

   await fuzzDelete(cookie, csrf,
      `/v1/passkeys/{1}`,
      [[...badIdsSmall, userId], badIds]
   );

   let res = await deleteJson(`/v1/user`, { "x-csrf-token": csrf }, cookie);
   expect(res.status).toBeGreaterThanOrEqual(400);
   res = await deleteJson(`/v1/user`, { "x-csrf-token": csrf }, cookie);
   expect(res.status).toBe(404);

   await fuzzPost(cookie, csrf,
      `/v1/reg/verify`,
      [badNames],
      ['authenticator']
   );

   await fuzzPost(cookie, csrf,
      `/v1/auth/verify`,
      [badNames],
      ['authenticator']
   );

   await fuzzPost(cookie, csrf,
      `/v1/users/{0}/recover/{1}`,
      [[...badIdsSmall, userId], badIds]
   );

   await fuzzPost(cookie, csrf,
      `/v1/recover2/`,
      [[...badIdsSmall, userId], badIds],
      ["userId", "recoveryId"]
   );

   await fuzzGet(cookie, csrf,
      `/v1/{0}`,
      [['fl2i4bNajPIp3leX4K4a0qND', '']]
   );
}

describe("api fuzzing (authenticated)", () => {
   let userId: string;
   let cookie: string;
   let csrf: string;
   let credId: string;

   beforeAll(async () => {
      let userCred: string;
      ({ userId, userCred, cookie, csrf, credId } = await registerTestUser(`PWTesty_fuzz_${Date.now()}`));
      setSessionUserCred(userCred, userId);
   });

   afterAll(async () => {
      if (cookie && credId) {
         await deleteJson(`/v1/passkeys/${credId}`, { "x-csrf-token": csrf }, cookie);
      }
      setSessionUserCred(undefined);
   });

   it("small fuzz", async () => {
      await smallFuzz(cookie, csrf, userId);
   }, 60000);

   it.skipIf(!FULL_FUZZ)("full fuzz", async () => {
      await fullFuzz(cookie, csrf, userId);
   }, 180000);
});

describe("api fuzzing (unauthenticated)", () => {
   const fakeCsrf = 'xhBTx1eYZnHVx7GlS4PenA';
   const fakeUserId = '22eba19cIp4leXyK4a3qNB';

   it("small fuzz", async () => {
      await smallFuzz("", fakeCsrf, fakeUserId);
   }, 60000);

   it.skipIf(!FULL_FUZZ)("full fuzz", async () => {
      await fullFuzz("", fakeCsrf, fakeUserId);
   }, 180000);
});
