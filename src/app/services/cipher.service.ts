/* MIT License

Copyright (c) 2024 Brad Schick

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
import { browserSupportsBytesStream, BYOBStreamReader, streamWriteBYOD, } from './utils';
import { Ciphers, EParams, CipherDataInfo, PWDProvider } from './ciphers';
import * as cc from './cipher.consts';

export { CipherDataInfo, PWDProvider };

export type EncContext3 = {
   readonly alg: string;
   readonly ic: number;
   readonly trueRand: boolean;
   readonly fallbackRand: boolean;
   readonly lpEnd: number;
};

// Simple perf testing with Chrome 126 on MacOS result in
// readAvailable with READ_SIZE_MAX of 4x to be the fastest
const READ_SIZE_START = 1048576; // 1 MiB
const READ_SIZE_MAX = READ_SIZE_START * 4;

@Injectable({
   providedIn: 'root'
})
export class CipherService {

   private _hashRate = 0;
   private _iCountMax = cc.ICOUNT_MAX;

   get hashRate(): number {
      return this._hashRate;
   }

   async benchmark(
      testSize: number,
      targetMillis: number,
      maxMillis: number
   ): Promise<[number, number, number]> {

      let iCount: number;
      [iCount, this._iCountMax, this._hashRate] = await Ciphers.latest().benchmark(
         testSize,
         targetMillis,
         maxMillis
      );

      return [iCount, this._iCountMax, this._hashRate];
   }

   validateAlg(alg: string): boolean {
      return Ciphers.validateAlg(alg);
   }

   algDescription(alg: string): string {
      return Ciphers.validateAlg(alg) ? cc.AlgInfo[alg]['description'] as string : 'Invalid';
   }

   algs(): string[] {
      return Object.keys(cc.AlgInfo);
   }


   async encryptStream(
      econtext: EncContext3,
      pwdProvider: PWDProvider,
      userCred: Uint8Array,
      clearStream: ReadableStream<Uint8Array>,
      readyNotice?: (cdInfo: CipherDataInfo) => void,
      lp: number = 1
   ): Promise<ReadableStream<Uint8Array>> {

      if (econtext.ic > this._iCountMax) {
         throw new Error('Invalid ic, exceeded: ' + this._iCountMax);
      }
      if (econtext.lpEnd > cc.LP_MAX) {
         throw new Error('Loop count exceeded: ' + cc.LP_MAX);
      }

      const reader = new BYOBStreamReader(clearStream);
      const ciphers = Ciphers.latest();
      let totalBytesOutput = 0;
      let readTarget = READ_SIZE_START;
      const [pwd, hint] = await pwdProvider(lp, econtext.lpEnd);

      const eparams: EParams = {
         ...econtext,
         pwd,
         lp,
         userCred,
         hint
      };

      let cipherStream = new ReadableStream({
         type: (browserSupportsBytesStream() ? 'bytes' : undefined),

         async start(controller) {

            try {
               const buffer = new ArrayBuffer(readTarget);
               const [clearBuffer, done] = await reader.readAvailable(buffer);

               if (clearBuffer.byteLength) {
                  const cipherData = await ciphers.encryptBlock0(
                     eparams,
                     clearBuffer,
                     readyNotice
                  );

                  // for debugging, but needs to happen first because they get deteached by enqueue
                  totalBytesOutput += (cipherData.headerData.byteLength + cipherData.encryptedData.byteLength + cipherData.additionalData.byteLength);
                  controller.enqueue(cipherData.headerData);
                  controller.enqueue(cipherData.additionalData);
                  // To simplify, only try to write the potentially large portion to BYOD
                  streamWriteBYOD(controller, cipherData.encryptedData);
               }

               if (done) {
                  controller.close();
                  // See: https://stackoverflow.com/questions/78804588/why-does-read-not-return-in-byob-mode-when-stream-is-closed/
                  //@ts-ignore
                  controller.byobRequest?.respond(0);
                  reader.cleanup();
               }
            } catch (err) {
               console.error(err);
               controller.error(err);
               reader.cleanup();
            }
         },

         async pull(controller) {
            readTarget = Math.min(readTarget * 2, READ_SIZE_MAX);

            try {
               const buffer = new ArrayBuffer(readTarget);
               const [clearBuffer, done] = await reader.readAvailable(buffer);

               if (clearBuffer.byteLength) {
                  const cipherData = await ciphers.encryptBlockN(
                     eparams,
                     clearBuffer
                  );

                  // for debugging, but needs to happen first because they get deteached by enqueue
                  totalBytesOutput += (cipherData.headerData.byteLength + cipherData.encryptedData.byteLength + cipherData.additionalData.byteLength);
                  controller.enqueue(cipherData.headerData);
                  controller.enqueue(cipherData.additionalData);
                  // To simplify, only try to write the potentially large portion to BYOD
                  streamWriteBYOD(controller, cipherData.encryptedData);
               }

               if (done) {
                  controller.close();
                  // See: https://stackoverflow.com/questions/78804588/why-does-read-not-return-in-byob-mode-when-stream-is-closed/
                  //@ts-ignore
                  controller.byobRequest?.respond(0);
                  reader.cleanup();
               }
            } catch (err) {
               console.error(err);
               controller.error(err);
               reader.cleanup();
            }
         }
      });


      if (lp < econtext.lpEnd) {
         cipherStream = await this.encryptStream(
            econtext,
            pwdProvider,
            userCred,
            cipherStream,
            readyNotice,
            lp + 1
         );
      }

      return cipherStream;
   }

   async getCipherStreamInfo(
      userCred: Uint8Array,
      cipherStream: ReadableStream<Uint8Array>,
   ): Promise<CipherDataInfo> {

      const reader = new BYOBStreamReader(cipherStream);
      try {
         let buffer = new ArrayBuffer(cc.HEADER_BYTES);
         const [headerData] = await reader.readFill(buffer);

         const ciphers = Ciphers.fromHeader(headerData);
         ciphers.decodeHeader(headerData);

         buffer = new ArrayBuffer(ciphers.payloadSize);
         const [payloadData] = await reader.readFill(buffer);
         if (payloadData.byteLength != ciphers.payloadSize) {
            throw new Error('Invalid payload size: ' + ciphers.payloadSize);
         }

         return ciphers.getCipherDataInfo(
            userCred,
            payloadData
         );
      } finally {
         reader.cleanup();
      }
   }

   async decryptStream(
      pwdProvider: PWDProvider,
      userCred: Uint8Array,
      cipherStream: ReadableStream<Uint8Array>,
      readyNotice?: (cdInfo: CipherDataInfo) => void,
      lpEnd?: number
   ): Promise<ReadableStream<Uint8Array>> {

      const reader = new BYOBStreamReader(cipherStream);
      let ciphers: Ciphers;
      let totalBytesOutput = 0;
      let payload0Data: Uint8Array | undefined;
      let cdInfo: CipherDataInfo;

      try {
         // Read Block0 early so we can find the number of loops and nest
         // decryption. Stream should deference this below to free ASAP
         let buffer = new ArrayBuffer(cc.HEADER_BYTES);
         const [headerData] = await reader.readFill(buffer);

         // If we don't get enough data, let Ciphers throw and error
         ciphers = Ciphers.fromHeader(headerData);
         ciphers.decodeHeader(headerData);

         buffer = new ArrayBuffer(ciphers.payloadSize);
         [payload0Data] = await reader.readFill(buffer);
         if (payload0Data.byteLength != ciphers.payloadSize) {
            throw new Error('Invalid payload size: ' + ciphers.payloadSize);
         }

         cdInfo = await ciphers.getCipherDataInfo(
            userCred,
            payload0Data
         );

         if(!lpEnd) {
            lpEnd = cdInfo.lp;
         }

      } catch(err) {
         console.error(err);
         reader.cleanup();
         throw err;
      }

      let readableStream = new ReadableStream({
         type: (browserSupportsBytesStream() ? 'bytes' : undefined),

         async start(controller) {

            try {
               if (!payload0Data || payload0Data.byteLength != ciphers.payloadSize) {
                  throw new Error('Invalid payload0 size: ' + ciphers.payloadSize);
               }

               // Only the inner most stread calls ready notice
               const decrypted = await ciphers.decryptPayload0(
                  pwdProvider,
                  lpEnd,
                  userCred,
                  payload0Data,
                  readyNotice
               );

               totalBytesOutput += decrypted.byteLength;
               streamWriteBYOD(controller, decrypted);

            } catch (err) {
               console.error('start() error, closing', err);
               controller.error(err);
               reader.cleanup();
            } finally {
               payload0Data = undefined;
            }
         },

         async pull(controller) {

            try {
               let buffer = new ArrayBuffer(cc.HEADER_BYTES);
               const [headerData] = await reader.readFill(buffer);

               if (headerData.byteLength) {
                  ciphers.decodeHeader(headerData);

                  buffer = new ArrayBuffer(ciphers.payloadSize);
                  const [payloadData] = await reader.readFill(buffer);
                  if (payloadData.byteLength != ciphers.payloadSize) {
                     throw new Error('Invalid payload size: ' + ciphers.payloadSize);
                  }

                  const decrypted = await ciphers.decryptPayloadN(payloadData);

                  totalBytesOutput += decrypted.byteLength;
                  streamWriteBYOD(controller, decrypted);
               } else {
                  // Reach the end of the stream peacefully...
                  controller.close();
                  // See: https://stackoverflow.com/questions/78804588/why-does-read-not-return-in-byob-mode-when-stream-is-closed/
                  //@ts-ignore
                  controller.byobRequest?.respond(0);
                  reader.cleanup();
               }

            } catch (err) {
               console.error(err);
               controller.error(err);
               reader.cleanup();
            }
         }

      });

      if(cdInfo.lp > 1) {
         readableStream = await this.decryptStream(
            pwdProvider,
            userCred,
            readableStream,
            readyNotice,
            lpEnd
         );
      }

      return readableStream
   }

}


