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

import type { HttpDetails } from "./urls";
import {
   Users,
   Authenticators,
   AAGUIDs
} from "./models";

import {
   darkFileDefault,
   lightFileDefault,
   type Response
} from "./index";

import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { setTimeout } from 'node:timers/promises';
import sodium from 'libsodium-wrappers';
import { base64UrlEncode } from "./utils";

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
               if (params['cleanse']) {
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

      if (params['cleanse'] && deleteBatch.length > 0) {
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
                  if (params['cleanse']) {
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
                  if (params['cleanse']) {
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

      if (params['cleanse'] && deleteBatch.length > 0) {
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

   return { content: { message: "done" } };
}

export async function postMunge(
   httpDetails: HttpDetails
): Promise<Response> {

   await sodium.ready;

   const { publicKey, privateKey } = sodium.crypto_sign_keypair();

   console.log(`publicKey: ${base64UrlEncode(publicKey)}`);
   console.log(`privateKey: ${base64UrlEncode(privateKey)}`);

   // https://gist.githubusercontent.com/quickcrypt-security/b5ad7deadcaf9aec23acebd0d17c6739/raw/43107c6d8f9285cee18193136b07abe52df1d1f8/keys.json

   // public-key1 -- prod
   // 2025-11-23T21:40:10.139Z	21ab5f95-21a7-4054-90a0-16b7c7e2e291	INFO	publicKey: kVyD3JMfbqWSEe4XIzwxudJIyHMmID6lg69BQCGTcZk
   // 2025-11-23T21:40:10.140Z	21ab5f95-21a7-4054-90a0-16b7c7e2e291	INFO	privateKey: H4S7djHVYhtUPG9e2gUOSIvqPCW4xBcHKb9lT1Djlb6RXIPckx9upZIR7hcjPDG50kjIcyYgPqWDr0FAIZNxmQ

   // public-key2 -- dev
   // 2025-11-23T21:42:19.136Z	b29c2810-b30a-4f70-9d85-a59c58378b9f	INFO	publicKey: 0pbIB1B3k-oOTnMkq-41srsyiF18jms5HQKGiqS3f3c
   // 2025-11-23T21:42:19.136Z	b29c2810-b30a-4f70-9d85-a59c58378b9f	INFO	privateKey: ig890QSJChMRLdz0jTDHLdsJ4OUgE_kpmsy33grFBO3SlsgHUHeT6g5OcySr7jWyuzKIXXyOazkdAoaKpLd_dw


   // const batchSize = 14;

   // const userAttrs = ["userId", "userCredEnc", "userCredEncOld", "verified"] as const;
   // let users = await Users.scan.go({
   //    attributes: userAttrs,
   //    limit: batchSize
   // });

   // let total = 0;

   // while (users && users.data && users.data.length > 0) {
   //    total += users.data.length

   //    for (let user of users.data) {
   //       // fake user to prevent Id use
   //       if (user.userId === 'AAAAAAAAAAAAAAAAAAAAAA') {
   //          continue;
   //       }

   //       try {
   //          if(user.userCredEncOld && user.userCredEnc) {
   //             const credDecBytes = await decryptField(
   //                user.userCredEnc,
   //                { userId: user.userId },
   //                USERCRED_BYTES
   //             );

   //             const credDecOldBytes = await decryptField(
   //                user.userCredEncOld,
   //                { userId: user.userId },
   //                USERCRED_BYTES,
   //                KMS_KEYID_OLD
   //             );

   //             if (base64UrlEncode(credDecBytes) === base64UrlEncode(credDecOldBytes)) {
   //                console.log(`all good for ${user.userId} `);
   //             } else {
   //                console.error(`mismatched for ${user.userId} of ${base64UrlEncode(credDecBytes)} and ${base64UrlEncode(credDecOldBytes)}`);
   //            }
   //          } else {
   //             console.log(`skipping ${user.userId}, ok? ${!user.verified} `);
   //          }
   //       } catch (error) {
   //          console.error(`Error for ${user.userId}`, error);
   //       }
   //    }

   //    if (!users.cursor) {
   //       console.log('breaking');
   //       break;
   //    }
   //    users = await Users.scan.go({
   //       attributes: userAttrs,
   //       limit: batchSize,
   //       cursor: users.cursor
   //    });
   // }

   // console.log(`${total} users total`);
   return { content: { message: "done" } };
}
