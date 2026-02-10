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

import { Entity, type EntityItem, type EntityRecord } from "electrodb";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";


const client = new DynamoDBClient({
   region: "us-east-1",
});


export const Users = new Entity(
   {
      model: {
         entity: "user",
         version: "1",
         service: "quickcrypt"
      },
      attributes: {
         userId: {
            type: "string",
            required: true
         },
         userName: {
            type: "string",
            required: true
         },
         userCredEnc: {
            type: "string",
            required: false
         },
         userCredEncOld: {
            type: "string",
            required: false
         },
         lastCredentialId: {
            type: "string",
            required: false
         },
         recoveryIdEnc: {
            type: "string",
            required: false
         },
         verified: {
            type: "boolean",
            default: () => false,
            required: true
         },
         recovered: {
            type: "number",
            default: () => 0,
            required: true
         },
         authCount: {
            type: "number",
            default: () => 0,
            required: true
         },
         createdAt: {
            type: "number",
            default: () => Date.now(),
            // should not be modified after created
            readOnly: true
         },
         expiresAt: {
            type: "number",
            required: false
         }
      },
      indexes: {
         byUserId: {
            pk: {
               field: "pk",
               cast: "string",
               composite: ["userId"],
               casing: 'none'
            }
         },
      }
   },
   {
      table: "Users",
      client: client
   }
);

export const Authenticators = new Entity(
   {
      model: {
         entity: "authenticator",
         version: "1",
         service: "quickcrypt"
      },
      attributes: {
         userId: {
            type: "string",
            required: true
         },
         credentialId: {
            type: "string",
            required: true
         },
         description: {
            type: "string",
            required: false
         },
         credentialPublicKey: {
            type: "string",
            required: true
         },
         credentialDeviceType: {
            type: "string",
            required: true
         },
         credentialBackedUp: {
            type: "boolean",
            required: false
         },
         transports: {
            type: "set",
            items: "string",
            default: () => [],
            required: false
         },
         userVerified: {
            type: "boolean",
            required: false
         },
         origin: {
            type: "string",
            required: true
         },
         aaguid: {
            type: "string",
            required: false
         },
         attestationObject: {
            type: "string",
            required: false
         },
         createdAt: {
            type: "number",
            default: () => Date.now(),
            // should not be modified after created
            readOnly: true
         },
         lastLogin: {
            type: "number",
            required: false
         }
      },
      indexes: {
         byUserId: {
            pk: {
               field: "pk",
               cast: "string",
               composite: ["userId"],
               casing: 'none'
            },
            sk: {
               field: "sk",
               cast: "string",
               composite: ["credentialId"],
               casing: 'none'
            }
         },
         /*         byCredId: {
                     index: "cidpk-index",
                     pk: {
                        field: "cidpk",
                        composite: ["credentialId"],
                     },
                  }*/
      }
   },
   {
      table: "Authenticators",
      client: client
   }
);

export const SenderLinks = new Entity(
   {
      model: {
         entity: "senderlink",
         version: "1",
         service: "quickcrypt"
      },
      attributes: {
         linkId: {
            type: "string",
            required: true
         },
         senderId: {
            type: "string",
            required: true
         },
         receiverId: {
            type: "string",
            required: true
         },
         description: {
            type: "string",
            required: true
         },
         receiverCert: {
            type: "string",
            required: true
         },
         transportCert: {
            type: "string",
            required: true
         },
         transportPrivateKey: {
            type: "string",
            required: true
         },
         multiUser: {
            type: "boolean",
            required: true
         },
         eep: {
            type: "string",
            required: false
         },
         createdAt: {
            type: "number",
            default: () => Date.now(),
            // should not be modified after created
            readOnly: true
         }
      },
      indexes: {
         byLinkSenderId: {
            pk: {
               field: "pk",
               cast: "string",
               composite: ["linkId"],
               casing: 'none'
            },
            sk: {
               field: "sk",
               cast: "string",
               composite: ["senderId"],
               casing: 'none'
            },
         },
         byReceiverId: {
            index: "receiverid-index",
            pk: {
               field: "receiverId",
               cast: "string",
               composite: ["receiverId"],
               casing: 'none'
            }
         }
      }
   },
   {
      table: "SenderLinks",
      client: client
   }
);


export const Challenges = new Entity(
   {
      model: {
         entity: "challenge",
         version: "1",
         service: "quickcrypt"
      },
      attributes: {
         challenge: {
            type: "string",
            required: true
         },
         expiresAt: {
            type: "number",
            // Needs unix time (convert from MS to S) and add 5 minutes after creation
            // Which is a 4 minute buffer since webauthn stuff defaults to 1 minute timeout
            default: () => (Math.floor(Date.now() / 1000) + 300),
            required: true,
            readOnly: true
         }
      },
      indexes: {
         byChallenge: {
            pk: {
               field: "pk",
               cast: "string",
               composite: ["challenge"],
               casing: 'none'
            }
         }
      }
   },
   {
      table: "Challenges",
      client: client
   }
);


export const AuthEvents = new Entity(
   {
      model: {
         entity: "event",
         version: "1",
         service: "quickcrypt"
      },
      attributes: {
         event: {
            type: "string",
            required: true
         },
         userId: {
            type: "string",
            required: true
         },
         when: {
            type: "number",
            default: () => Date.now(),
            // should not be modified after created
            readOnly: true
         },
         credentialId: {
            type: "string",
            required: false
         },
      },
      indexes: {
         byUser: {
            pk: {
               field: "pk",
               cast: "string",
               composite: ["userId"],
               casing: 'none'
            },
            sk: {
               field: "sk",
               cast: "number",
               composite: ["when"]
            }
         }
      }
   },
   {
      table: "Events",
      client: client
   }
);

export const AAGUIDs = new Entity(
   {
      model: {
         entity: "aaguid",
         version: "1",
         service: "quickcrypt"
      },
      attributes: {
         aaguid: {
            type: "string",
            required: true
         },
         name: {
            type: "string",
            required: true
         },
         lightIcon: {
            type: "string",
            required: true
         },
         darkIcon: {
            type: "string",
            required: true
         }
      },
      indexes: {
         byAAGUID: {
            pk: {
               field: "pk",
               cast: "string",
               composite: ["aaguid"],
               casing: 'none'
            }
         }
      }
   },
   {
      table: "AAGUIDs",
      client: client
   }
);

export type UnverifiedUserItem = EntityItem<typeof Users>;
export type AuthItem = EntityItem<typeof Authenticators>;
export type SenderLinkItem = EntityItem<typeof SenderLinks>;
export type VerifiedUserItem = EntityRecord<typeof Users> & {
   lastCredentialId?: string;
   recoveryIdEnc?: string;
};
