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

import * as cc from './cipher.consts';
import {
   Ciphers,
   CipherState,
   streamDecipher,
   latestEncipher
} from './ciphers';

import type {
   EParams,
   CipherDataInfo,
   PWDProvider
} from './ciphers';
import { browserSupportsBytesStream, streamWriteBYOD } from './utils';

export type {CipherDataInfo, PWDProvider};

export type EContext = {
   readonly algs: string[];
   readonly ic: number;
};


export async function encryptStream(
   econtext: EContext,
   pwdProvider: PWDProvider,
   userCred: Uint8Array,
   clearStream: ReadableStream<Uint8Array>
): Promise<ReadableStream<Uint8Array>> {
   return _encryptStreamImpl(
      econtext,
      pwdProvider,
      userCred,
      clearStream,
      1
   );
}

async function _encryptStreamImpl(
   econtext: EContext,
   pwdProvider: PWDProvider,
   userCred: Uint8Array,
   clearStream: ReadableStream<Uint8Array>,
   lp: number
): Promise<ReadableStream<Uint8Array>> {

   if (lp < 1 || lp > econtext.algs.length) {
      throw new Error('Invalid loop of: ' + lp);
   }
   if (econtext.algs.length > cc.LP_MAX) {
      throw new Error('Invalid loop end of: ' + econtext.algs.length);
   }

   const alg = econtext.algs[lp - 1];

   if (!Ciphers.validateAlg(alg)) {
      throw new Error('Invalid alg of: ' + alg);
   }
   if (econtext.ic < cc.ICOUNT_MIN || econtext.ic > cc.ICOUNT_MAX) {
      throw new Error('Invalid ic of: ' + econtext.ic);
   }
   if (userCred.byteLength != cc.USERCRED_BYTES) {
      throw new Error('Invalid userCred length of: ' + userCred.byteLength);
   }

   const encipher = latestEncipher(userCred, clearStream);

   const eparams: EParams = {
      ...econtext,
      alg: alg,
      lp,
      lpEnd: econtext.algs.length
   };

   let cipherStream = new ReadableStream({
      type: (browserSupportsBytesStream() ? 'bytes' : undefined),

      async pull(controller) {

         try {
            // Encryption may return zero data and not be Finished
            const cipherData = await encipher.encryptBlock(eparams, pwdProvider);

            if (cipherData.parts.length) {
               for (let data of cipherData.parts) {
                  streamWriteBYOD(controller, data);
               }
            }

            if (cipherData.state === CipherState.Finished) {
               controller.close();
               // See: https://stackoverflow.com/questions/78804588/why-does-read-not-return-in-byob-mode-when-stream-is-closed/
               //@ts-ignore
               controller.byobRequest?.respond(0);
            }
         } catch (err) {
            // Chrome throws an odd "network err" when files have errors, so replace with a consistent error
            if(err instanceof Error && err.message.toLowerCase().includes("network")) {
               err = new Error('Error reading stream');
            }
            controller.error(err);
         }
      }
   });

   if (lp < econtext.algs.length) {
      cipherStream = await _encryptStreamImpl(
         econtext,
         pwdProvider,
         userCred,
         cipherStream,
         lp + 1
      );
   }

   return cipherStream;
}


export async function getCipherStreamInfo(
   userCred: Uint8Array,
   cipherStream: ReadableStream<Uint8Array>,
): Promise<CipherDataInfo> {
   if (userCred.byteLength != cc.USERCRED_BYTES) {
      throw new Error('Invalid userCred length of: ' + userCred.byteLength);
   }

   const decipher = await streamDecipher(userCred, cipherStream);
   return decipher.getCipherDataInfo();
}


export async function decryptStream(
   pwdProvider: PWDProvider,
   userCred: Uint8Array,
   cipherStream: ReadableStream<Uint8Array>
): Promise<ReadableStream<Uint8Array>> {

   if (userCred.byteLength != cc.USERCRED_BYTES) {
      throw new Error('Invalid userCred length of: ' + userCred.byteLength);
   }

   const decipher = await streamDecipher(userCred, cipherStream);
   const cdInfo = await decipher.getCipherDataInfo();

   let readableStream = new ReadableStream({
      type: (browserSupportsBytesStream() ? 'bytes' : undefined),

      async pull(controller) {

         try {
            // Decryption always returns data if any remains
            const decrypted = await decipher.decryptBlock(pwdProvider);

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
            // Chrome throws an odd "network err" when files have errors, so replace with a consistent error
            if(err instanceof Error && err.message.toLowerCase().includes("network")) {
               err = new Error('Error reading stream');
            }
            controller.error(err);
         }
      }

   });

   if (cdInfo.lp > 1) {
      readableStream = await decryptStream(
         pwdProvider,
         userCred,
         readableStream
      );
   }

   return readableStream
}