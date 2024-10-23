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
import { EParams, CipherDataInfo, PWDProvider, Ciphers, Encipher, Decipher, CipherDataBlock } from './ciphers';
import * as cc from './cipher.consts';

export { CipherDataInfo, PWDProvider };

export type EncContext3 = {
   readonly alg: string;
   readonly ic: number;
   readonly trueRand: boolean;
   readonly fallbackRand: boolean;
   readonly lpEnd: number;
};


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
      [iCount, this._iCountMax, this._hashRate] = await Ciphers.benchmark(
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

      const encipher = Encipher.latest(clearStream);
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

         async pull(controller) {

            try {
               const cipherData = await encipher.encryptBlock(eparams, readyNotice);

               if (cipherData.parts.length) {
                  for(let data of cipherData.parts) {
                     streamWriteBYOD(controller, data);
                  }
               }

               if (cipherData.done) {
                  controller.close();
                  // See: https://stackoverflow.com/questions/78804588/why-does-read-not-return-in-byob-mode-when-stream-is-closed/
                  //@ts-ignore
                  controller.byobRequest?.respond(0);
               }
            } catch (err) {
               controller.error(err);
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
      const decipher = await Decipher.fromStream(cipherStream);
      return decipher.getCipherDataInfo(userCred);
   }

   async decryptStream(
      pwdProvider: PWDProvider,
      userCred: Uint8Array,
      cipherStream: ReadableStream<Uint8Array>,
      readyNotice?: (cdInfo: CipherDataInfo) => void,
      lpEnd?: number
   ): Promise<ReadableStream<Uint8Array>> {


      const decipher = await Decipher.fromStream(cipherStream);
      const cdInfo = await decipher.getCipherDataInfo(userCred);

      if (!lpEnd) {
         lpEnd = cdInfo.lp;
      }

      let readableStream = new ReadableStream({
         type: (browserSupportsBytesStream() ? 'bytes' : undefined),

         async pull(controller) {

            try {
               const decrypted = await decipher.decryptBlock(
                  pwdProvider,
                  lpEnd,
                  userCred,
                  readyNotice
               );

               if (decrypted.byteLength) {
                  streamWriteBYOD(controller, decrypted);
               } else {
                  // Reached the end of the stream peacefully...
                  controller.close();
                  // See: https://stackoverflow.com/questions/78804588/why-does-read-not-return-in-byob-mode-when-stream-is-closed/
                  //@ts-ignore
                  controller.byobRequest?.respond(0);
               }

            } catch (err) {
               controller.error(err);
            }
         }

      });

      if (cdInfo.lp > 1) {
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


