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
import { readStreamFill, readStreamUntil, base64ToBytes, bytesToBase64 } from './utils';
import { Ciphers, EParams, CipherDataInfo, HEADER_BYTES, HINT_MAX_LEN,
   ICOUNT_MIN, ICOUNT_MAX, ICOUNT_DEFAULT } from './ciphers';

export { EParams, CipherDataInfo, HINT_MAX_LEN, ICOUNT_MIN,
   ICOUNT_MAX, ICOUNT_DEFAULT, base64ToBytes, bytesToBase64 };


// Simple perf testing with Chrome 126 on MacOS result in
// readStreamUntil with READ_SIZE_MAX of 4x to be the fastest
const READ_SIZE_START = 1048576; // 1 MiB
const READ_SIZE_MAX = READ_SIZE_START * 4;

@Injectable({
   providedIn: 'root'
})
export class CipherService {

   private _hashRate = 0;
   private _iCountMax = 0;

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
      return Ciphers.validateAlg(alg) ? Ciphers.algDescription(alg) : 'Invalid';
   }

   async encryptString(
      eparams: EParams,
      clearText: string,
      readyNotice?: (cdInfo: CipherDataInfo) => void
   ): Promise<string> {
      if( eparams.ic > this._iCountMax) {
         throw new Error('iCount exeeded: ' + this._iCountMax);
      }
      if(clearText.length == 0) {
         throw new Error('Missing clear text');
      }

      const ciphers = Ciphers.latest();

      const input = new TextEncoder().encode(clearText);
      const cipherData = await ciphers.encryptBlock0(
         eparams,
         input,
         readyNotice
      );

      const output = new Uint8Array(cipherData.headerData.byteLength +
         cipherData.additionalData.byteLength +
         cipherData.encryptedData.byteLength
      );

      output.set(cipherData.headerData);
      output.set(cipherData.additionalData, cipherData.headerData.byteLength);
      output.set(cipherData.encryptedData,
         cipherData.headerData.byteLength + cipherData.additionalData.byteLength);

      return bytesToBase64(output);
   }

   encryptStream(
      eparams: EParams,
      clearStream: ReadableStream<Uint8Array>,
      readyNotice?: (cdInfo: CipherDataInfo) => void
   ): ReadableStream<Uint8Array> {

      if( eparams.ic > this._iCountMax) {
         throw new Error('iCount exeeded: ' + this._iCountMax);
      }

      const reader = clearStream.getReader({ mode: "byob" });
      const ciphers = Ciphers.latest();
      let totalBytesOutput = 0;
      let readTarget = READ_SIZE_START;

      console.log('encryptToBytes returning');

      return new ReadableStream({
         type: 'bytes',

         async start(controller) {
            console.log(`start(): ${controller.constructor.name}.byobRequest = ${controller.byobRequest}`);

            try {
               let done = false;
               let clearBuffer = new Uint8Array(readTarget);

               [clearBuffer, done] = await readStreamUntil(reader, clearBuffer);
               console.log('start(): readTarget, readBytes', readTarget, clearBuffer.byteLength);

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
                  controller.enqueue(cipherData.encryptedData);
                  console.log('start(): total enqueued: ' + totalBytesOutput);
               }

               if (done) {
                  console.log('start(): closing');
                  controller.close();
                  reader.releaseLock();
               }
            } catch (err) {
               console.error(err);
               controller.close();
               reader.releaseLock();
               // TODO: Need a way to report error back to parent
            }
         },

         async pull(controller) {
            console.log(`pull(): ${controller.constructor.name}.byobRequest = ${controller.byobRequest}`);

            readTarget = Math.min(readTarget * 2, READ_SIZE_MAX);

            try {
               let done = false;
               let clearBuffer = new Uint8Array(readTarget);

               [clearBuffer, done] = await readStreamUntil(reader, clearBuffer);
               console.log('pull(): readTarget, readBytes', readTarget, clearBuffer.byteLength);

               if (clearBuffer.byteLength) {
                  const cipherData = await ciphers.encryptBlockN(
                     eparams,
                     clearBuffer
                  );

                  // for debugging, but needs to happen first because they get deteached by enqueue
                  totalBytesOutput += (cipherData.headerData.byteLength + cipherData.encryptedData.byteLength + cipherData.additionalData.byteLength);
                  controller.enqueue(cipherData.headerData);
                  controller.enqueue(cipherData.additionalData);
                  controller.enqueue(cipherData.encryptedData);

                  console.log('pull(): total enqueued: ' + totalBytesOutput);
               }

               if (done) {
                  console.log('pull(): closing');
                  controller.close();
                  reader.releaseLock();
               }
            } catch (err) {
               console.error(err);
               controller.close();
               reader.releaseLock();
               // TODO: Need a way to report error back to parent
            }
         }

      });
   }

   async getCipherStreamInfo(
      userCred: Uint8Array,
      cipherStream: ReadableStream<Uint8Array>,
   ): Promise<CipherDataInfo> {

      const reader = cipherStream.getReader({ mode: "byob" });
      let headerData = new Uint8Array(HEADER_BYTES);
      [headerData] = await readStreamFill(reader, headerData);
      console.log('info(): HEADER_BYTES, headerData', HEADER_BYTES, headerData);

      const ciphers = Ciphers.fromHeader(headerData);
      ciphers.decodeHeader(headerData);

      let payloadData = new Uint8Array(ciphers.payloadSize);
      [payloadData] = await readStreamFill(reader, payloadData);
      console.log('info(): payloadSize, payloadData', ciphers.payloadSize, payloadData);

      return ciphers.getCipherDataInfo(
         userCred,
         payloadData
      );
   }

   async getCipherTextInfo(
      userCred: Uint8Array,
      cipherText: string,
   ): Promise<CipherDataInfo> {

      const block0 = base64ToBytes(cipherText);
      const ciphers = Ciphers.fromHeader(block0);
      const consumedBytes = ciphers.decodeHeader(block0);
      return ciphers.getCipherDataInfo(
         userCred,
         new Uint8Array(block0.buffer, consumedBytes),
      );
   }

   async decryptString(
      pwdProvider: (hint: string) => Promise<string>,
      userCred: Uint8Array,
      cipherText: string,
      readyNotice?: (cdInfo: CipherDataInfo) => void
   ): Promise<string> {

      const block0 = base64ToBytes(cipherText);
      const ciphers = Ciphers.fromHeader(block0);
      const consumedBytes = ciphers.decodeHeader(block0);

      const decrypted = await ciphers.decryptPayload0(
         pwdProvider,
         userCred,
         new Uint8Array(block0.buffer, consumedBytes),
         readyNotice
      );

      return new TextDecoder().decode(decrypted);
   }

   decryptStream(
      pwdProvider: (hint: string) => Promise<string>,
      userCred: Uint8Array,
      cipherStream: ReadableStream<Uint8Array>,
      readyNotice?: (cdInfo: CipherDataInfo) => void
   ): ReadableStream<Uint8Array> {

      const reader = cipherStream.getReader({ mode: "byob" });
      let ciphers: Ciphers;
      let totalBytesOutput = 0;

      console.log('decryptStream returning');

      return new ReadableStream({
         type: 'bytes',

         async start(controller) {
            console.log(`start(): ${controller.constructor.name}.byobRequest = ${controller.byobRequest}`);

            try {
               let readBytes: number;
               let headerData = new Uint8Array(HEADER_BYTES);
               [headerData] = await readStreamFill(reader, headerData);
               console.log('start(): HEADER_BYTES, headerData', HEADER_BYTES, headerData);

               ciphers = Ciphers.fromHeader(headerData);
               ciphers.decodeHeader(headerData);

               let payloadData = new Uint8Array(ciphers.payloadSize);
               [payloadData] = await readStreamFill(reader, payloadData);
               console.log('start(): payloadSize, payloadData', ciphers.payloadSize, payloadData);

               const decrypted = await ciphers.decryptPayload0(
                  pwdProvider,
                  userCred,
                  payloadData,
                  readyNotice
               );

               totalBytesOutput += decrypted.byteLength;
               controller.enqueue(decrypted);
               console.log('start(): total enqueued', totalBytesOutput);
            } catch (err) {
               console.error(err);
               controller.close();
               reader.releaseLock();
               // TODO: Need a way to report error back to parent
            }
         },

         async pull(controller) {
            console.log(`pull(): ${controller.constructor.name}.byobRequest = ${controller.byobRequest}`);

            try {
               let readBytes: number;
               let headerData = new Uint8Array(HEADER_BYTES);
               try {
                  [headerData] = await readStreamFill(reader, headerData);
                  console.log('pull(): HEADER_BYTES, headerData', HEADER_BYTES, headerData);
               } catch (err) {
                  // don't report as an error since if the file being done
                  console.log('pull(): closing');
                  controller.close();
                  reader.releaseLock();
                  return;
               }

               ciphers.decodeHeader(headerData);

               let payloadData = new Uint8Array(ciphers.payloadSize);
               [payloadData] = await readStreamFill(reader, payloadData);
               console.log('pull(): payloadSize, payloadData', ciphers.payloadSize, payloadData);

               const decrypted = await ciphers.decryptPayloadN(payloadData);

               totalBytesOutput += decrypted.byteLength;
               controller.enqueue(decrypted);
               console.log('pull(): total enqueued', totalBytesOutput);
            } catch (err) {
               console.error(err);
               controller.close();
               reader.releaseLock();
               // TODO: Need a way to report error back to parent
            }
         }

      });
   }

}


