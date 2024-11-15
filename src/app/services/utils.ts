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

import { base64URLStringToBuffer, bufferToBase64URLString } from './base64';



// Returns base64Url text
export function bytesToBase64(bytes: Uint8Array): string {
   return bufferToBase64URLString(bytes);
}

// Accepts either base64 or base64Url text
export function base64ToBytes(b64: string): Uint8Array {
   return new Uint8Array(base64URLStringToBuffer(b64));
}

/* Javascript converts to signed 32 bit int when using bit shifting
   and masking, so do this instead. Count is the number of bytes
   used to pack the number.  */
export function numToBytes(num: number, count: number): Uint8Array {
   if (count < 1 || num >= Math.pow(256, count)) {
      throw new Error(`Invalid arguments ${count} for ${num}`);
   }
   let arr = new Uint8Array(count);
   for (let i = 0; i < count; ++i) {
      arr[i] = num % 256;
      num = Math.floor(num / 256);
   }
   return arr;
}

export function bytesToNum(arr: Uint8Array): number {
   let num = 0;
   for (let i = arr.length - 1; i >= 0; --i) {
      num = num * 256 + arr[i];
   }
   return num;
}

export function browserSupportsFilePickers(): boolean {
   //@ts-ignore
   if (window.showSaveFilePicker) {
      return true;
   } else {
      return false;
   }
}

export function browserSupportsBytesStream(): boolean {
   try {
      new ReadableStream({ type: "bytes" });
      return true;
   } catch (err) {
      return false;
   }
}

export class ProcessCancelled extends Error {
   constructor() {
      super('Process Cancelled');
      this.name = this.constructor.name;
   }

   static isProcessCancelled(err: any): boolean {
      return (err instanceof ProcessCancelled) ||
         (err instanceof Error && err.message.indexOf('ProcessCancelled') >= 0);
   }
}


export class BYOBStreamReader {

   private _reader: ReadableStreamBYOBReader | ReadableStreamDefaultReader;
   private _extra?: Uint8Array;
   private _byob: boolean;

   constructor(stream: ReadableStream<Uint8Array>) {
      try {
         this._reader = stream.getReader({ mode: "byob" });
         this._byob = true;
      } catch (err) {
         this._byob = false;
         this._reader = stream.getReader();
      }
   }

   cleanup() {
      this._reader.releaseLock();
   }

   // Use when the reader cannot accept less then the size of output (or stream done)
   async readFill(buffer: ArrayBuffer)
      : Promise<[data: Uint8Array, done: boolean]> {
      try {
         if (this._byob) {
            return this._readBYOB(buffer, false);
         } else {
            return this._readStupidSafari(buffer, false);
         }
      }
      catch (err) {
         this.cleanup();
         throw err;
      }
   }

   async readAvailable(buffer: ArrayBuffer)
      : Promise<[data: Uint8Array, done: boolean]> {
      try {
         if (this._byob) {
            return this._readBYOB(buffer, true);
         } else {
            return this._readStupidSafari(buffer, true);
         }
      } catch (err) {
         this.cleanup();
         throw err;
      }
   }

   private async _readBYOB(
      buffer: ArrayBuffer,
      breakOnStall: boolean
   ): Promise<[data: Uint8Array, done: boolean]> {

      const reader = this._reader as ReadableStreamBYOBReader;
      if (buffer instanceof Uint8Array) {
         buffer = buffer.buffer;
      }

      const targetBytes = buffer.byteLength;
      let readBytes = 0;
      let streamDone = false;

      while (readBytes < targetBytes) {
         let { done, value } = await reader.read(
            new Uint8Array(buffer, readBytes, targetBytes - readBytes)
         );

         if (value) {
            readBytes += value.byteLength;
            buffer = value.buffer;
         }
         streamDone = done;
         if (done || (breakOnStall && !value?.byteLength)) {
            break;
         }
      }

      return [new Uint8Array(buffer, 0, readBytes), streamDone];
   }

   private async _readStupidSafari(
      buffer: ArrayBuffer,
      breakOnStall: boolean
   ): Promise<[data: Uint8Array, done: boolean]> {

      const reader = this._reader as ReadableStreamDefaultReader;
      if (buffer instanceof Uint8Array) {
         buffer = buffer.buffer;
      }

      const targetBytes = buffer.byteLength;
      const writeable = new Uint8Array(buffer);
      let wroteBytes = 0;
      let streamDone = false;

      while (wroteBytes < targetBytes) {
         let done: boolean;
         let value: Uint8Array;

         if (this._extra) {
            done = false;
            value = this._extra;
            this._extra = undefined;
         } else {
            const results = await reader.read();
            done = results.done;
            if (typeof results.value === 'string') {
               value = new TextEncoder().encode(results.value);
            } else {
               value = results.value;
            }
         }

         if (value) {
            const unfilledBytes = targetBytes - wroteBytes;
            if (value.byteLength > unfilledBytes) {
               this._extra = new Uint8Array(value.buffer, value.byteOffset + unfilledBytes, value.byteLength - unfilledBytes);
               value = new Uint8Array(value.buffer, value.byteOffset, unfilledBytes);
               done = false;
            }

            writeable.set(value, wroteBytes);
            wroteBytes += value.byteLength;
         }

         streamDone = done;
         if (done || (breakOnStall && !value?.byteLength)) {
            break;
         }
      }

      return [new Uint8Array(buffer, 0, wroteBytes), streamDone];
   }
}


type TrueType = true;
type FalseType = false;

export async function readStreamAll(stream: ReadableStream<Uint8Array>): Promise<Uint8Array>
export async function readStreamAll(stream: ReadableStream<Uint8Array>, decode: FalseType): Promise<Uint8Array>
export async function readStreamAll(stream: ReadableStream<Uint8Array>, decode: TrueType): Promise<string>
export async function readStreamAll(
   stream: ReadableStream<Uint8Array>, decode: TrueType | FalseType = false
): Promise<string | Uint8Array> {

   let result: string | Uint8Array;
   const reader = stream.getReader();
   try {
      let readBytes = 0;
      const blocks: Uint8Array[] = [];

      while (true) {
         const { done, value } = await reader.read();
         if (value) {
            blocks.push(value);
            readBytes += value.byteLength;
         }

         if (done) {
            break;
         }
      }

      result = coalesceBlocks(blocks, readBytes);
      if (decode) {
         result = new TextDecoder().decode(result);
      }
   } finally {
      reader.releaseLock();
   }

   return result;
}

function coalesceBlocks(
   blocks: Uint8Array[],
   byteLen: number
): Uint8Array {

   let result = new Uint8Array(0);
   if (blocks.length > 1) {
      result = new Uint8Array(byteLen);
      let offset = 0;
      for (const block of blocks) {
         result.set(block, offset);
         offset += block.byteLength;
      }
   } else {
      result = blocks[0];
   }

   return result;
}


export function streamWriteBYOD(
   controller: ReadableByteStreamController | ReadableStreamDefaultController<Uint8Array>,
   data: Uint8Array
): number {
   let written = 0;

   if (!browserSupportsBytesStream() ||
      controller instanceof ReadableStreamDefaultController ||
      !controller.byobRequest?.view) {
      written += data.byteLength;
      controller.enqueue(data);
   } else {
      const byodView = controller.byobRequest.view;
      const byodBytes = Math.min(data.byteLength, byodView.byteLength);
      const writeableView = new Uint8Array(byodView.buffer, byodView.byteOffset, byodView.byteLength);
      writeableView.set(new Uint8Array(data.buffer, 0, byodBytes));
      written += byodBytes;
      controller.byobRequest.respond(byodBytes);

      if (byodBytes < data.byteLength) {
         const remainder = new Uint8Array(data.buffer, byodBytes)
         written += remainder.byteLength;
         controller.enqueue(remainder);
      }
   }

   return written;
}

export async function selectCipherFile(): Promise<FileSystemFileHandle> {
   try {
      //@ts-ignore
      const [fileHandle] = await window.showOpenFilePicker({
         id: 'quickcrypt_org',
         multiple: false,
         types: [{
            description: 'Encrypted files',
            accept: {
               'application/octet-stream': ['.qq', '.json'],
            }
         }, {
            description: 'JSON file',
            accept: {
               'application/json': ['.json'],
            }
         },
         ]
      });
      return fileHandle;
   } catch (err) {
      console.error(err);
      throw new ProcessCancelled();
   }

}

export async function selectClearFile(): Promise<FileSystemFileHandle> {
   try {
      //@ts-ignore
      const [fileHandle] = await window.showOpenFilePicker({
         id: 'quickcrypt_org',
         multiple: false
      });
      return fileHandle;
   } catch (err) {
      console.error(err);
      throw new ProcessCancelled();
   }
}

async function selectWriteableFileImpl(options: { [key: string]: any }): Promise<FileSystemFileHandle> {
   try {
      //@ts-ignore
      return await window.showSaveFilePicker(options);
   } catch (err) {
      console.error(err);
      throw new ProcessCancelled();
   }
}

export async function selectWriteableFile(baseName?: string): Promise<FileSystemFileHandle> {
   const suggested = baseName ?? '';
   const options = {
      id: 'quickcrypt_org',
      suggestedName: suggested
   };

   return selectWriteableFileImpl(options);
}


export async function selectWriteableJsonFile(baseName?: string): Promise<FileSystemFileHandle> {
   const suggested = baseName ? `${baseName}.json` : '';
   const options = {
      id: 'quickcrypt_org_json',
      suggestedName: suggested,
      types: [{
         description: 'JSON file',
         accept: {
            'application/json': ['.json'],
         }
      }]
   };

   return selectWriteableFileImpl(options);
}

export async function selectWriteableQQFile(baseName?: string): Promise<FileSystemFileHandle> {
   const suggested = baseName ? `${baseName}.qq` : '';
   const options = {
      id: 'quickcrypt_org_qq',
      suggestedName: suggested,
      types: [{
         description: 'Encrypted files',
         accept: {
            'application/octet-stream': ['.qq'],
         }
      }]
   };

   return selectWriteableFileImpl(options);
}

export async function selectWriteableTxtFile(baseName?: string): Promise<FileSystemFileHandle> {
   const suggested = baseName ? `${baseName}.txt` : '';
   const options = {
      id: 'quickcrypt_org_txt',
      suggestedName: suggested,
      types: [{
         description: 'Text file',
         accept: {
            'text/plain': ['.txt'],
         }
      }]
   };

   return selectWriteableFileImpl(options);
}

export class Random48 {
   private _trueRandCache: Promise<Response>;
   private _testing: boolean;

   constructor(testing: boolean) {
      this._testing = testing;
      this._trueRandCache = this.downloadTrueRand();
   }

   async getRandomArray(
      trueRand: boolean = true,
      fallback: boolean = true
   ): Promise<Uint8Array> {
      if (!trueRand) {
         if (!fallback) {
            throw new Error('both trueRand and fallback disabled');
         }
         return crypto.getRandomValues(new Uint8Array(48));
      } else {
         const lastCache = this._trueRandCache;
         this._trueRandCache = this.downloadTrueRand();
         return lastCache.then(async (response) => {
            if (!response.ok) {
               const bdy = await response.text();
               throw new Error('random.org response: ' + response.statusText + ' ' + bdy);
            }
            return response.arrayBuffer();
         }).then((array) => {
            if (array.byteLength != 48) {
               throw new Error('missing bytes from random.org');
            }
            return new Uint8Array(array!);
         }).catch((err) => {
            console.error(err);
            // If pseudo random fallback is disabled, then throw error
            if (!fallback) {
               throw new Error('no connection to random.org and no fallback: ' + err.message);
            }
            return crypto.getRandomValues(new Uint8Array(48));
         });
      }
   }

   async downloadTrueRand(): Promise<Response> {
      if (this._testing) {
         return Promise.reject();
      }

      const url = 'https://www.random.org/cgi-bin/randbyte?nbytes=' + 48;
      try {
         const p = fetch(url, {
            cache: 'no-store'
         });
         return p;
      } catch (err) {
         // According to the docs, this should not happend but it seems to sometimes
         // (perfhaps just on nodejs, but not sure)
         console.error('wtf fetch, ', err);
         return Promise.reject();
      }
   }
}
