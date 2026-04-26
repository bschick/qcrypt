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

import * as cc from './consts';
import type { HttpDetails } from "./urls";
import {
   Users,
   Authenticators,
   AAGUIDs,
   Invitables
} from "./models";

import {
   darkFileDefault,
   kmsClient,
   lightFileDefault,
   type Response
} from "./index";

import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { setTimeout } from 'node:timers/promises';
import { base64UrlEncode, isReservedTestUserName } from "./utils";
import { GenerateRandomCommand } from '@aws-sdk/client-kms';

export async function postLoadAAGUIDs(
   httpDetails: HttpDetails
): Promise<Response> {

   try {
      const filePath = resolve('./combined.json');
      const contents = await readFile(filePath, { encoding: 'utf8' });

      const aaguids = JSON.parse(contents);
      const keys = Object.keys(aaguids);

      let count = 0;
      let batch = [];
      for (let key of keys) {
         const details = aaguids[key];

         batch.push({
            aaguid: key,
            name: details['name'],
            lightIcon: details['light_file'] ?? lightFileDefault,
            darkIcon: details['dark_file'] ?? darkFileDefault
         });

         if (++count % 10 === 0) {
            await AAGUIDs.put(batch).go();
            batch = [];
            await setTimeout(1000);
         }
      }

      const results = await AAGUIDs.put(batch).go();
      return { content: { message: 'success' } };
   } catch (err) {
      console.error(err);
      return { content: { message: 'failed' } };
   }
}


export async function postConsistency(
   httpDetails: HttpDetails
): Promise<Response> {
   const {
      params
   } = httpDetails;

   const batchSize = 50;
   const maxScan = 1000;
   const daysOld = 1;

   if (!params['tables'] || params.tables.includes('authenticators')) {

      const authAttrs = ["userId", "credentialId"] as const;
      let auths = await Authenticators.scan.go({
         attributes: authAttrs,
         limit: batchSize
      });

      let total = 0;
      let leaked = 0;
      let deleted = 0;
      let deleteBatch = [];

      while (auths && auths.data && auths.data.length > 0) {
         total += auths.data.length;

         for (let auth of auths.data) {
            const user = await Users.get({
               userId: auth.userId
            }).go({ attributes: ['userId'] });

            if (!user || !user.data) {
               console.log(`missing userId ${auth.userId} for auth ${auth.credentialId}`);
               leaked += 1;
               if (params['cleanse'] === 'true') {
                  deleteBatch.push({
                     userId: auth.userId,
                     credentialId: auth.credentialId
                  });
               }
            }
         }

         if (!auths.cursor || total >= maxScan) {
            break;
         }
         auths = await Authenticators.scan.go({
            attributes: authAttrs,
            limit: batchSize,
            cursor: auths.cursor
         });
      }

      if (params['cleanse'] === 'true' && deleteBatch.length > 0) {
         // ElectroDB handles running this sequentially in groups of 25 for dynamoDB
         console.log(`deleting ${deleteBatch.length} authenticators`);
         const result = await Authenticators.delete(deleteBatch).go();

         // results are unprocessed records, meaning it didn't complete if they exist
         if (result && result.unprocessed && result.unprocessed.length > 0) {
            console.error(`delete of all ${deleteBatch.length} authenticators failed`);
         } else {
            deleted = deleteBatch.length;
         }
      }

      console.log(`${total} authenticators scanned with ${leaked} leaked and ${deleted} deleted`);

   }
   if (params['tables'] && params.tables.includes('users')) {

      const userAttrs = ["userId", "verified", "userName", "createdAt"] as const;
      let users = await Users.scan.go({
         attributes: userAttrs,
         limit: batchSize
      });

      let total = 0;
      let unverified = 0;
      let leaked = 0;
      let expired = 0;
      let deleted = 0;
      let deleteBatch = [];

      const olderThan = Date.now() - (daysOld * 24 * 60 * 60 * 1000);

      while (users && users.data && users.data.length > 0) {
         total += users.data.length;

         for (let user of users.data) {
            // fake user to prevent Id use
            if (user.userId == 'AAAAAAAAAAAAAAAAAAAAAA') {
               continue;
            }

            if (user.verified) {
               const auths = await Authenticators.query.byUserId({
                  userId: user.userId
               }).go({ attributes: ['credentialId'] });

               if (!auths || auths.data.length === 0) {
                  console.log(`no credentials for user: ${user.userId}, ${user.userName}`);
                  leaked += 1;
                  if (params['cleanse'] === 'true') {
                     deleteBatch.push({
                        userId: user.userId
                     });
                  }
               }
            } else {
               // This is for cleanup of records where something has gone wrong or left-over from
               // previous to the use of DynamoDB TTL automatic cleanup.
               unverified += 1;
               if (user.createdAt && user.createdAt < olderThan) {
                  console.log(`unverified user is expired: ${user.userId}, ${user.userName}`);
                  expired += 1;
                  if (params['cleanse'] === 'true') {
                     deleteBatch.push({
                        userId: user.userId
                     });
                  }
               }
            }
         }

         if (!users.cursor || total >= maxScan) {
            break;
         }
         users = await Users.scan.go({
            attributes: userAttrs,
            limit: batchSize,
            cursor: users.cursor
         });
      }

      if (params['cleanse'] === 'true' && deleteBatch.length > 0) {
         // ElectroDB handles running this sequentially in groups of 25 for dynamoDB
         console.log(`deleting ${deleteBatch.length} users`);
         const result = await Users.delete(deleteBatch).go();

         // results are unprocessed records, meaning it didn't complete if they exist
         if (result && result.unprocessed && result.unprocessed.length > 0) {
            console.error(`delete of all ${deleteBatch.length} users failed`);
         } else {
            deleted = deleteBatch.length;
         }
      }
      console.log(`${total} users scanned with ${leaked} leaked, ${expired} expired, ${unverified} unverified, and ${deleted} deleted`);
   }
   if (params['tables'] && params.tables.includes('invitables')) {

      const invAttrs = ["invitableId", "userId"] as const;
      let invitables = await Invitables.scan.go({
         attributes: invAttrs,
         limit: batchSize
      });

      let total = 0;
      let leaked = 0;
      let deleted = 0;
      let deleteBatch = [];

      while (invitables && invitables.data && invitables.data.length > 0) {
         total += invitables.data.length;

         for (let invitable of invitables.data) {
            const user = await Users.get({
               userId: invitable.userId
            }).go({ attributes: ['userId'] });

            if (!user || !user.data) {
               console.log(`missing userId ${invitable.userId} for invitable ${invitable.invitableId}`);
               leaked += 1;
               if (params['cleanse'] === 'true') {
                  deleteBatch.push({
                     userId: invitable.userId,
                     invitableId: invitable.invitableId
                  });
               }
            }
         }

         if (!invitables.cursor || total >= maxScan) {
            break;
         }
         invitables = await Invitables.scan.go({
            attributes: invAttrs,
            limit: batchSize,
            cursor: invitables.cursor
         });
      }

      if (params['cleanse'] === 'true' && deleteBatch.length > 0) {
         // ElectroDB handles running this sequentially in groups of 25 for dynamoDB
         console.log(`deleting ${deleteBatch.length} invitables`);
         const result = await Invitables.delete(deleteBatch).go();

         // results are unprocessed records, meaning it didn't complete if they exist
         if (result && result.unprocessed && result.unprocessed.length > 0) {
            console.error(`delete of all ${deleteBatch.length} invitables failed`);
         } else {
            deleted = deleteBatch.length;
         }
      }

      console.log(`${total} invitables scanned with ${leaked} leaked and ${deleted} deleted`);
   }

   return { content: { message: "done" } };
}

export async function postCleanupTestUsers(
   httpDetails: HttpDetails
): Promise<Response> {
   const {
      params
   } = httpDetails;

   if (!params['tables'] || !params.tables.includes('users')) {
      return { content: { message: "skipped, missing users table" } };
   }

   const batchSize = 50;
   const maxScan = 1000;
   const minAgeMs = 15 * 60 * 1000;
   const olderThan = Date.now() - minAgeMs;
   // Per-call delete cap. Large cleanups need repeat invocations;
   const maxDeletes = 25;

   const userAttrs = ["userId", "userName", "createdAt"] as const;
   let users = await Users.scan.go({
      attributes: userAttrs,
      limit: batchSize
   });

   let total = 0;
   let capReached = false;
   let candidates: { userId: string; userName: string }[] = [];

   while (users && users.data && users.data.length > 0) {
      total += users.data.length;

      for (let user of users.data) {
         if (!isReservedTestUserName(user.userName)) {
            continue;
         }
         if (user.userId === 'AAAAAAAAAAAAAAAAAAAAAA') {
            continue;
         }
         if (!user.createdAt || user.createdAt > olderThan) {
            console.log(`not expired test user ${user.userName} - ${user.userId}`);
            continue;
         }
         console.log(`expired test user ${user.userName} - ${user.userId}`);
         candidates.push({
            userId: user.userId,
            userName: user.userName
         });
         if (candidates.length >= maxDeletes) {
            console.log(`cap of ${maxDeletes} reached`);
            capReached = true;
            break;
         }
      }

      if (capReached || !users.cursor || total >= maxScan) {
         break;
      }
      users = await Users.scan.go({
         attributes: userAttrs,
         limit: batchSize,
         cursor: users.cursor
      });
   }

   // Defense in depth: re-verify each candidate's prefix
   const deleteBatch = candidates
      .filter(c => isReservedTestUserName(c.userName))
      .map(c => ({ userId: c.userId }));

   let deleted = 0;
   if (params['cleanse'] === 'true' && deleteBatch.length > 0) {
      // ElectroDB handles running this sequentially in groups of 25 for dynamoDB
      console.log(`deleting ${deleteBatch.length} users`);
      const result = await Users.delete(deleteBatch).go();

      // results are unprocessed records, meaning it didn't complete if they exist
      if (result && result.unprocessed && result.unprocessed.length > 0) {
         console.error(`delete of all ${deleteBatch.length} users failed`);
      } else {
         deleted = deleteBatch.length;
      }

      // Sweep auths/invitables orphaned by the deletes above.
      httpDetails.params.tables = httpDetails.params.tables.replace('users', '');
      httpDetails.handler = postConsistency;
      await postConsistency(httpDetails);
   }

   console.log(`${total} users scanned, ${deleteBatch.length} matched, and ${deleted} deleted`);
   return { content: { message: "done" } };
}

export async function postMunge(
   httpDetails: HttpDetails
): Promise<Response> {

   const batchSize = 14;

   const userAttrs = ["userId", "userName"] as const;
   let users = await Users.scan.go({
      attributes: userAttrs,
      limit: batchSize
   });

   let total = 0;

   while (users && users.data && users.data.length > 0) {
      total += users.data.length

      // Reduce round-trips by getting enough data for 3 retries for each user in batch
      const rparams = {
         NumberOfBytes: users.data.length * cc.RETRIES * cc.INVITABLEID_BYTES
      };
      const rand = new GenerateRandomCommand(rparams);
      const result = await kmsClient.send(rand);
      let byteOffset = 0;

      for (let user of users.data) {
         // fake user to prevent Id use
         if (user.userId === 'AAAAAAAAAAAAAAAAAAAAAA') {
            continue;
         }

         try {
            let invId: string | undefined;

            const randData = result.Plaintext;
            if (!randData || randData.byteLength != rparams.NumberOfBytes) {
               throw new Error("GenerateRandomCommand failure");
            }

            for(let i = 0; i < cc.RETRIES; ++i) {
               const invIdBytes = randData.slice(byteOffset, byteOffset + cc.INVITABLEID_BYTES);
               byteOffset += cc.INVITABLEID_BYTES;

               invId = base64UrlEncode(invIdBytes)!;
               const invitable = await Invitables.query.byInvitableId({
                  invitableId: invId
               }).go();

               if (!invitable || invitable.data.length == 0) {
                  break;
               } else {
                  invId = undefined;
               }
            }

            if (!invId) {
               throw new Error('could not allocate invitableId');
            }

            const invitable = await Invitables.create({
               userId: user.userId,
               invitableId: invId,
               description: user.userName
            }).go();

            if (!invitable || !invitable.data) {
               throw new Error('invitable not created or found');
            }

         } catch (error) {
            console.error(`Error for ${user.userId}`, error);
         }
      }

      if (!users.cursor) {
         console.log('breaking');
         break;
      }
      users = await Users.scan.go({
         attributes: userAttrs,
         limit: batchSize,
         cursor: users.cursor
      });
   }

   console.log(`${total} users total`);
   return { content: { message: "done" } };
}
