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

import { Extractor, Packer } from "./packer";


   export type CreateTopicInfo = {
      ownerKEMPublicKey: string;
      participants?: string[];
      additionalCount: number;
      fork: boolean;
      description?: string;
   };


// It is tempting to put ladderBytes into the topic class, but the topic is created
// and used before the ladder is know (and saved into Binders while the topic is filling
// with users). To avoid inconsistent state, we keep ladderBytes out of the topic class.
export class TopicResponse {
   public topicId!: string;
   public userCertBytes!: Uint8Array;
   public description!: string;
//   public ladderBytes!: Uint8Array;
   public topicSigCertBytes!: Uint8Array;
   // public messages!: number;
   public createdAt!: number;

   private constructor() {
   }

   public static fromValues(
      topicId: string,
      userCertBytes: Uint8Array,
      description: string,
//      ladderBytes: Uint8Array,
      topicSigCertBytes: Uint8Array,
      // messages: number,
      createdAt: number
   ) {
      const topic = new TopicResponse();
      topic.topicId = topicId;
      topic.userCertBytes = userCertBytes;
      topic.description = description;
//      topic.ladderBytes = ladderBytes;
      topic.topicSigCertBytes = topicSigCertBytes;
      // topic.messages = messages;
      topic.createdAt = createdAt;
      return topic;
   }

   public static fromPacked(data: Uint8Array) {
      const extractor = new Extractor(data, false);

      const topicId = extractor.base64('id', TOPICID_BYTES);
      const userCertBytes = extractor.bytes('ucert', KEM_CERT_MAX_BYTES, CERT_LEN_BYTES);
      const description = extractor.string('desc', DESC_MAX_LEN, DESC_LEN_BYTES);
//      const ladderBytes = extractor.bytes('ladder', LADDER_MAX_BYTES, LADDER_LEN_BYTES);
      const topicSigCertBytes = extractor.bytes('scert', SIG_CERT_MAX_BYTES, CERT_LEN_BYTES);
      // const messages = bytesToNum(extractor.extract('msgs', MAX_TOPIC_MESSAGES_BYTES));
      // if (messages > MAX_TOPIC_MESSAGES) {
      //    throw new Error('messages must be less than ' + MAX_TOPIC_MESSAGES);
      // }
      const createdAt = extractor.number('created', TIMESTAMP_BYTES);

      return TopicResponse.fromValues(
         topicId,
         userCertBytes,
         description,
//         ladderBytes,
         topicSigCertBytes,
         // messages,
         createdAt
      );
   }

   public pack(): Uint8Array {
      const packer = new Packer(TOPIC_MAX_BYTES, false);

      packer.base64('id', this.topicId, TOPICID_BYTES);
      packer.bytes('ucert', this.userCertBytes, KEM_CERT_MAX_BYTES, CERT_LEN_BYTES);
      packer.string('desc', this.description, DESC_MAX_LEN, DESC_LEN_BYTES);
//      packer.bytes('ladder', this.ladderBytes, LADDER_MAX_BYTES, LADDER_LEN_BYTES);
      packer.bytes('scert', this.topicSigCertBytes, SIG_CERT_MAX_BYTES, CERT_LEN_BYTES);
      // if (this.messages > MAX_TOPIC_MESSAGES) {
      //    throw new Error('messages must be less than ' + MAX_TOPIC_MESSAGES);
      // }
      // packer.pack('msgs', numToBytes(this.messages, MAX_TOPIC_MESSAGES_BYTES));
      packer.number('created', this.createdAt, TIMESTAMP_BYTES);

      return packer.trim();
   }
}