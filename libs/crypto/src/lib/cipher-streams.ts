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
   getStreamDecipher,
   getLatestEncipher
} from './ciphers';

import type {
   CipherDataInfo,
   PWDProvider,
   ReadOpts
} from './ciphers';
import { KeyProvider } from './keys';
import { browserSupportsBytesStream, streamWriteBYOD } from './utils';

export type { CipherDataInfo, PWDProvider, ReadOpts };

export type EContext = {
   readonly algs: cc.CipherAlgs[];
   readonly ic?: number | undefined;
   readonly readOpts?: ReadOpts | undefined;
};


// This method purges the passed in KeyProvider
export async function encryptStream(
   clearStream: ReadableStream<Uint8Array>,
   keyProvider: KeyProvider,
   econtext: EContext,
): Promise<ReadableStream<Uint8Array>> {
   try {
      return await _encryptStreamImpl(
         clearStream,
         keyProvider,
         econtext,
         1
      );
   } finally {
      keyProvider.purge();
   }
}


async function _encryptStreamImpl(
   clearStream: ReadableStream<Uint8Array>,
   keyProvider: KeyProvider,
   econtext: EContext,
   lp: number,
): Promise<ReadableStream<Uint8Array>> {

   if (lp < 1 || lp > econtext.algs.length) {
      throw new Error('Invalid loop of: ' + lp);
   }
   if (econtext.algs.length > cc.LP_MAX) {
      throw new Error('Invalid loop end of: ' + econtext.algs.length);
   }

   const validatedAlg = Ciphers.validateAlg(econtext.algs[lp - 1]);
   const keyProviderClone = keyProvider.clone();

   try {
      const encipher = getLatestEncipher(
         clearStream,
         keyProviderClone,
         validatedAlg,
         lp,
         econtext.algs.length,
         econtext.ic,
         econtext.readOpts
      );

      let cipherStream = new ReadableStream({
         type: (browserSupportsBytesStream() ? 'bytes' : undefined),

         async pull(controller) {
            try {
               // Encryption may return zero data and not be Finished
               const cipherData = await encipher.encryptBlock();

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
               encipher.errorState();
               controller.error(err);
            }
         },
         async cancel(reason) {
            encipher.errorState();
            await clearStream.cancel(reason);
         }
      });

      if (lp < econtext.algs.length) {
         return await _encryptStreamImpl(cipherStream, keyProvider, econtext, lp + 1);
      }

      return cipherStream;
   } catch (err) {
      keyProviderClone.purge();
      throw err;
   }
}


// This method purges the passed in KeyProvider
export async function getCipherStreamInfo(
   cipherStream: ReadableStream<Uint8Array>,
   keyProvider: KeyProvider,
): Promise<CipherDataInfo> {
   try {
      const decipher = await getStreamDecipher(cipherStream, keyProvider);
      const info = await decipher.getCipherDataInfo();
      decipher.finishedState();
      return info;
   } catch (err) {
      // No clones inside getStreamDecipher, so catch instead of finally
      keyProvider.purge();
      throw err;
   }
}


// This method purges the passed in KeyProvider
export async function decryptStream(
   cipherStream: ReadableStream<Uint8Array>,
   keyProvider: KeyProvider
): Promise<ReadableStream<Uint8Array>> {
   try {
      return await _decryptStreamImpl(cipherStream, keyProvider);
   } finally {
      keyProvider.purge();
   }
}

async function _decryptStreamImpl(
   cipherStream: ReadableStream<Uint8Array>,
   keyProvider: KeyProvider
): Promise<ReadableStream<Uint8Array>> {

   const keyProviderClone = keyProvider.clone();
   try {
      const decipher = await getStreamDecipher(cipherStream, keyProviderClone);
      const cdInfo = await decipher.getCipherDataInfo();

      if (cdInfo.lp < 1 || cdInfo.lp > cc.LP_MAX) {
         decipher.errorState();
         throw new Error('Invalid loop of: ' + cdInfo.lp);
      }

      let readableStream = new ReadableStream({
         type: (browserSupportsBytesStream() ? 'bytes' : undefined),

         async pull(controller) {

            try {
               // Decryption always returns data if any remains
               const decrypted = await decipher.decryptBlock();

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
               decipher.errorState();
               controller.error(err);
            }
         },
         async cancel(reason) {
            decipher.errorState();
            await cipherStream.cancel(reason);
         }
      });

      if (cdInfo.lp > 1) {
         return await _decryptStreamImpl(readableStream, keyProvider);
      }

      return readableStream
   } catch (err) {
      keyProviderClone.purge();
      throw err;
   }

}
