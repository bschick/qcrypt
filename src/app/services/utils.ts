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

// Accepts either base64 or base64Url text
export function base64ToBytes(b64: string): Uint8Array {
   // simplewebauthn function accepts either as input to base64ToBytes
   return new Uint8Array(base64URLStringToBuffer(b64));
}



// Sadly, there doesn't seem to be a way to force ReadableStreamBYOBReader.read
// to write into the provided buffer. To support zero copy it sometime returns
// internal buffer. That means we have to return the data buffer and its size.
// Returns empty Uint8Array rather than null or undefined (make helps below cleaner)
export async function readStreamBYOB(
   reader: ReadableStreamBYOBReader,
   output: Uint8Array
): Promise<[Uint8Array, boolean]> {

   console.log('readStreamBYOB buffer: ' + output.byteLength);

   // read() returns a promise that fulfills when a value has been received
   let { done, value } = await reader.read(output);
   value = value ?? new Uint8Array(0);

   console.log('readStreamBYOB read: ', value, done);
   return [value, done];
}

// Use when the reader cannot accept less then the size of output
export async function readStreamFill(
   reader: ReadableStreamBYOBReader,
   output: Uint8Array
): Promise<[data: Uint8Array, done: boolean]> {

   const targetBytes = output.byteLength;
   let remainingBytes = targetBytes;
   const blocks: Uint8Array[] = [];
   let streamDone = false;

   while(remainingBytes > 0) {
      const [data, done] = await readStreamBYOB(reader, output);
      blocks.push(data);
      streamDone = done;
      remainingBytes -= data.byteLength;

      // Keep going until filled or error
      if(remainingBytes > 0) {
         if(done) {
            throw new Error('Missing data from stream: ' + remainingBytes);
         }
         output = new Uint8Array(remainingBytes);
      }
   }

   console.log('readStreamFill blocks, remainingBytes: ', blocks.length, remainingBytes);

   let result: Uint8Array;
   if(blocks.length > 1) {
      result = new Uint8Array(targetBytes);
      let offset = 0;
      for(const block of blocks) {
         result.set(block, offset);
         offset += block.byteLength;
      }
   } else {
      result = blocks[0];
   }

   return [result, streamDone];
}


// Use when the reader cannot accept less then the size of output
export async function readStreamUntil(
   reader: ReadableStreamBYOBReader,
   output: Uint8Array
): Promise<[data: Uint8Array, done: boolean]> {

   const targetBytes = output.byteLength;
   let remainingBytes = targetBytes;
   const blocks: Uint8Array[] = [];
   let streamDone = false;

   while(remainingBytes > 0) {
      const [data, done] = await readStreamBYOB(reader, output);
      blocks.push(data);
      streamDone = done;
      remainingBytes -= data.byteLength;

      // Keep going until stall or done
      if(!data.byteLength || done) {
         break;
      }
      if(remainingBytes > 0) {
         output = new Uint8Array(remainingBytes);
      }
   }

   console.log('readStreamUntil blocks, remainingBytes: ', blocks.length, remainingBytes);

   let result: Uint8Array;
   if(blocks.length > 1) {
      result = new Uint8Array(targetBytes - remainingBytes);
      let offset = 0;
      for(const block of blocks) {
         result.set(block, offset);
         offset += block.byteLength;
      }
   } else {
      result = blocks[0];
   }

   return [result, streamDone];
}


/*
async function readStream(
  reader: ReadableStreamDefaultReader<Uint8Array>
): Promise<Uint8Array> {

  let result = new Uint8Array(0);
  while (true) {
     // read() returns a promise that fulfills when a value has been received
     const { done, value } = await reader.read();

     console.log('readStream read: ', value, done);

     if (value) {
        const newres = new Uint8Array(result.byteLength + value.byteLength);
        newres.set(result);
        newres.set(value, result.byteLength);
        result = newres;
     }

     if (done || !value) {
        break;
     }
  }

  console.log('readStream returning: ' + result.byteLength);
  return result;
}
*/

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
      if(this._testing) {
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
