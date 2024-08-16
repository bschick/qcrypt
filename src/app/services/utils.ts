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

import { base64URLStringToBuffer, bufferToBase64URLString } from '@simplewebauthn/browser';


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

// Returns base64Url text
export function bytesToBase64(bytes: Uint8Array): string {
   // simplewebauthn function return base64Url format
   return (bufferToBase64URLString(bytes));
}

export function browserSupportsFilePickers() : boolean {
   //@ts-ignore
   if(window.showSaveFilePicker) {
      return true;
   } else {
      return false;
   }
}

export function browserSupportsBytesStream() : boolean {
   try {
      new ReadableStream({ type: "bytes" });
      return true;
   } catch(err) {
      return false;
   }
}

// Accepts either base64 or base64Url text
export function base64ToBytes(b64: string): Uint8Array {
   // simplewebauthn function accepts either as input to base64ToBytes
   return new Uint8Array(base64URLStringToBuffer(b64));
}

export async function readStreamBYODFill(
   reader: ReadableStreamBYOBReader,
   buffer: ArrayBuffer
): Promise<[data: Uint8Array, done: boolean]> {

   const targetBytes = buffer.byteLength;
   let readBytes = 0;
   let streamDone = false;
//   console.log('readStreamUntil-' + targetBytes + ' start');

   while (readBytes < targetBytes) {
      let { done, value } = await reader.read(
         new Uint8Array(buffer, readBytes, targetBytes - readBytes)
      );

//      console.log('readStreamUntil-' + targetBytes, ' read', data.byteLength, done);
      if(!value) {
         break
      }

      streamDone = done;
      readBytes += value.byteLength;
      buffer = value.buffer;

      if (done) {
         break;
      }
   }

   return [new Uint8Array(buffer, 0, readBytes), streamDone];
}


// Use when the reader cannot accept less then the size of output (or stream done)
export async function readStreamBYODUntil(
   reader: ReadableStreamBYOBReader,
   buffer: ArrayBuffer
): Promise<[data: Uint8Array, done: boolean]> {

   const targetBytes = buffer.byteLength;
   let readBytes = 0;
   let streamDone = false;
//   console.log('readStreamUntil-' + targetBytes + ' start');

   while (readBytes < targetBytes) {
      let { done, value } = await reader.read(
         new Uint8Array(buffer, readBytes, targetBytes - readBytes)
      );

//      console.log('readStreamUntil-' + targetBytes, ' read', data.byteLength, done);
      if(!value) {
         break
      }

      streamDone = done;
      readBytes += value.byteLength;
      buffer = value.buffer;

      if (!value.byteLength || done) {
         break;
      }
   }

   return [new Uint8Array(buffer, 0, readBytes), streamDone];
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
   //   console.log('readStreamAll- start');

      while (true) {
         const { done, value } = await reader.read();
   //      console.log('readStreamAll- read', value?.byteLength, done);
         if (value) {
            blocks.push(value);
            readBytes += value.byteLength;
         }

         if (done) {
            break;
         }
      }

      result = coalesceBlocks(blocks, readBytes);
      if(decode) {
         result = new TextDecoder().decode(result);
      }
   } finally {
      reader.releaseLock();
   }

//   console.log('readStreamAll- exit returnedBytes, done:',
//      result.byteLength,
//      streamDone
//   );

   return result;
}

function coalesceBlocks(
   blocks: Uint8Array[],
   byteLen: number
): Uint8Array {
//   console.log('coalescing blocks: ' + blocks.length);

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


// There doesn't seem to be a way to force ReadableStreamBYOBReader.read
// to write into the provided buffer, it sometime returns internal buffer.
// That means we have to return the data buffer and its size.
// Returns empty Uint8Array rather than null or undefined (make helps below cleaner)
export async function readStreamBYOBOLD(
   reader: ReadableStreamBYOBReader,
   output: Uint8Array
): Promise<[Uint8Array, boolean]> {

//   console.log('readStreamBYOB reading:', output.byteLength);
   let { done, value } = await reader.read(output);
//   console.log('readStreamBYOB read:', value?.byteLength, done);
   value = value ?? new Uint8Array(0);
   return [value, done];
}


// Use when the reader cannot accept less then the size of output (or stream done)
export async function readStreamBYODFillOLD(
   reader: ReadableStreamBYOBReader,
   output: Uint8Array
): Promise<[data: Uint8Array, done: boolean]> {

   const targetBytes = output.byteLength;
   let readBytes = 0;
   const blocks: Uint8Array[] = [];
   let streamDone = false;
//   console.log('readStreamFill-' + targetBytes + ' start');

   while (readBytes < targetBytes) {
      const [data, done] = await readStreamBYOBOLD(reader, output);
//      console.log('readStreamFill-' + targetBytes, ' read', data.byteLength, done);
      blocks.push(data);
      streamDone = done;
      readBytes += data.byteLength;

      if (done) {
         break;
      }
      if (readBytes < targetBytes) {
         output = new Uint8Array(targetBytes - readBytes);
      }
   }

   const result = coalesceBlocks(blocks, readBytes);
//   console.log('readStreamFill-' + targetBytes + ' exit returnedBytes, done:',
//      result.byteLength,
//      streamDone
//   );

   return [result, streamDone];
}


// Use when the reader cannot accept less then the size of output (or stream done)
export async function readStreamBYODUntilOLD(
   reader: ReadableStreamBYOBReader,
   output: Uint8Array
): Promise<[data: Uint8Array, done: boolean]> {

   const targetBytes = output.byteLength;
   let readBytes = 0;
   const blocks: Uint8Array[] = [];
   let streamDone = false;
//   console.log('readStreamUntil-' + targetBytes + ' start');

   while (readBytes < targetBytes) {
      const [data, done] = await readStreamBYOBOLD(reader, output);
//      console.log('readStreamUntil-' + targetBytes, ' read', data.byteLength, done);
      blocks.push(data);
      streamDone = done;
      readBytes += data.byteLength;

      if (!data.byteLength || done) {
         break;
      }
      if (readBytes < targetBytes) {
         output = new Uint8Array(targetBytes - readBytes);
      }
   }

   const result = coalesceBlocks(blocks, readBytes);
//   console.log('readStreamUntil-' + targetBytes + ' exit returnedBytes, done:',
//      result.byteLength,
//      streamDone
//   );

   return [result, streamDone];
}


export function streamWriteBYOD(
   controller: ReadableByteStreamController,
   data: Uint8Array
): number {
   let written = 0;
   const byodView = controller.byobRequest?.view;

   if(byodView) {
     const byodBytes = Math.min(data.byteLength, byodView.byteLength);
//     console.log("stream write- byod:", byodBytes);
     const writeableView = new Uint8Array(byodView.buffer, byodView.byteOffset, byodView.byteLength);
     writeableView.set(new Uint8Array(data.buffer, 0, byodBytes));
     written += byodBytes;
     controller.byobRequest.respond(byodBytes);

     if(byodBytes < data.byteLength) {
       const remainder = new Uint8Array(data.buffer, byodBytes)
//       console.log("stream write- enqueuing:", remainder.byteLength);
       written += remainder.byteLength;
       controller.enqueue(remainder);
     }
   } else {
//     console.log("stream write- enqueuing:", data.byteLength);
     written += data.byteLength;
     controller.enqueue(data);
   }
//   console.log("stream write- total:", written);
   return written;
}

export async function selectCipherFile() : Promise<FileSystemFileHandle> {
   //@ts-ignore
   const [fileHandle] = await window.showOpenFilePicker({
      id: 'quickcrypt_org',
      multiple: false,
      types: [{
         description: 'Encrypted files',
         accept: {
            'application/octet-stream': ['.qq', '.json'],
         }}, {
            description: 'JSON file',
            accept: {
               'application/json': ['.json'],
            }},
      ]
   });
   return fileHandle;
}

export async function selectClearFile(): Promise<FileSystemFileHandle> {
   //@ts-ignore
   const [fileHandle] = await window.showOpenFilePicker({
      id: 'quickcrypt_org',
      multiple: false
   });
   return fileHandle;
}

export async function selectWriteableTxtFile(
   baseName?: string
): Promise<FileSystemFileHandle> {

   const suggested = baseName ? `${baseName}.txt` : '';
   const options = {
      id: 'quickcrypt_org',
      suggestedName: suggested,
      types: [{
         description: 'Text file',
         accept: {
            'text/plain': ['.txt'],
         }
      }]
   };
   //@ts-ignore
   return await window.showSaveFilePicker(options);
}

export async function selectWriteableFile(baseName?: string): Promise<FileSystemFileHandle> {

   const suggested = baseName ?? '';
   const options = {
      id: 'quickcrypt_org',
      suggestedName: suggested
   };
   //@ts-ignore
   return await window.showSaveFilePicker(options);
}


export async function selectWriteableJsonFile(baseName?: string): Promise<FileSystemFileHandle> {

   const suggested = baseName ? `${baseName}.json` : '';
   const options = {
      id: 'quickcrypt_org',
      suggestedName: suggested,
      types: [{
         description: 'JSON file',
         accept: {
            'application/json': ['.json'],
         }
      }]
   };
   //@ts-ignore
   return await window.showSaveFilePicker(options);
}

export async function selectWriteableQQFile(baseName?: string): Promise<FileSystemFileHandle> {

   const suggested = baseName ? `${baseName}.qq` : '';
   const options = {
      id: 'quickcrypt_org',
      suggestedName: suggested,
      types: [{
         description: 'Encrypted files',
         accept: {
            'application/octet-stream': ['.qq'],
         }
      }]
   };
   //@ts-ignore
   return await window.showSaveFilePicker(options);
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
         return lastCache.then((response) => {
            if (!response.ok) {
               throw new Error('random.org response: ' + response.statusText);
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
            cache: 'no-store',
            mode: 'no-cors'
         });
         return p;
      } catch (err) {
         // According to the docs, this should not happend but it seems to sometimes
         // (perfhaps just one nodejs, but not sure)
         console.error('wtf fetch, ', err);
         return Promise.reject();
      }
   }
}
