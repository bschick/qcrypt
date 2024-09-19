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
import {
   Random48,
   numToBytes,
   bytesToNum,
   base64ToBytes,
   bytesToBase64,
   BYOBStreamReader
} from './utils';

function isEqualArray(a: Uint8Array, b: Uint8Array): boolean {
   if (a.length != b.length) {
      return false;
   }
   for (let i = 0; i < a.length; ++i) {
      if (a[i] != b[i]) {
         return false;
      }
   }
   return true;
}

function randomBlob(byteLength: number): Blob {
   // Create on max-size array and repeate it
   const randData = crypto.getRandomValues(new Uint8Array(512));
   const count = Math.ceil(byteLength / 512);

   let arr = new Array<Uint8Array>;
   for (let i = 0; i < count; ++i) {
      arr.push(randData);
   }
   return new Blob(arr, { type: 'application/octet-stream' });
}


describe("Base64 encode decode", function () {

   it("random bytes", function () {
      const rb = crypto.getRandomValues(new Uint8Array(43))
      const b64 = bytesToBase64(rb);
      expect(b64.length).toBeGreaterThanOrEqual(rb.byteLength);
      expect(isEqualArray(rb, base64ToBytes(b64))).toBeTrue();
   });

   it("detect bad encodings", function () {
      // correct values
      const correctBytes = new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x3e, 0x33]);
      const correctText = 'Hello>3';

      // expect we start valid
      const good = 'SGVsbG8-Mw';
      const bytes = base64ToBytes(good);
      expect(isEqualArray(bytes, correctBytes)).toBeTrue();
      expect(new TextDecoder().decode(bytes)).toBe(correctText);

      // underlying simplewebauthn library converts nonURL base64 to base64URL
      // so this should work also (goodRfc is standard base64)
      const goodRfc = 'SGVsbG8+Mw==';
      const bytes2 = base64ToBytes(goodRfc);
      expect(isEqualArray(bytes2, correctBytes)).toBeTrue();

      // extra padding is stripped (so not an error to be missing some)
      const extraPadding = 'SGVsbG8-Mw=';
      const bytes3 = base64ToBytes(extraPadding);
      expect(isEqualArray(bytes3, correctBytes)).toBeTrue();

      const badChar = 'SGVsbG8.Mw';
      expect(() => base64ToBytes(badChar)).toThrowError();

      const badLen = 'SGVsbG8Mw';
      expect(() => base64ToBytes(badLen)).toThrowError();
   });
});

describe("Random48 tests", function () {

   /* Removed by default to avoid spamming random.org
      it("true random", async function () {
         let rand = new Random48(false);
         const r1 = await rand.getRandomArray(true, false);
         const r2 = await rand.getRandomArray(true, false);

         expect(r1.byteLength).toBe(48);
         expect(r2.byteLength).toBe(48);
         expect(isEqualArray(r1, r2)).toBeFalse();
      });
   */

   it("pseudo random", async function () {
      let rand = new Random48(true);
      const r1 = await rand.getRandomArray(false, true);
      const r2 = await rand.getRandomArray(false, true);

      expect(r1.byteLength).toBe(48);
      expect(r2.byteLength).toBe(48);
      expect(isEqualArray(r1, r2)).toBeFalse();
      await expectAsync(rand.getRandomArray(false, false)).toBeRejectedWithError(Error);
   });
});

describe("Number byte packing", function () {

   it("one byte ok", function () {
      let a1 = numToBytes(0, 1);
      expect(bytesToNum(a1)).toBe(0);
      expect(a1.byteLength).toBe(1);

      a1 = numToBytes(1, 1);
      expect(bytesToNum(a1)).toBe(1);
      expect(a1.byteLength).toBe(1);

      a1 = numToBytes(255, 1);
      expect(bytesToNum(a1)).toBe(255);
      expect(a1.byteLength).toBe(1);
   });

   it("detect overflow check", function () {
      expect(() => numToBytes(256, 1)).toThrowError();
      expect(() => numToBytes(2456, 1)).toThrowError();
      expect(() => numToBytes(65536, 2)).toThrowError();
      expect(() => numToBytes(18777216, 3)).toThrowError();
      expect(() => numToBytes(187742949672967216, 4)).toThrowError();
   });

   it("other lengths ok", function () {
      let a2 = numToBytes(567, 2);
      expect(bytesToNum(a2)).toBe(567);
      expect(a2.byteLength).toBe(2);

      a2 = numToBytes(65535, 2);
      expect(bytesToNum(a2)).toBe(65535);
      expect(a2.byteLength).toBe(2);

      let a3 = numToBytes(2, 3);
      expect(bytesToNum(a3)).toBe(2);
      expect(a3.byteLength).toBe(3);

      let a4 = numToBytes(4294000000, 4);
      expect(bytesToNum(a4)).toBe(4294000000);
      expect(a4.byteLength).toBe(4);
   });

});


describe("Stream reading", function () {
   it("buffer matches", async function () {
      let blob1k = randomBlob(1024);
      let buffer1k = new ArrayBuffer(blob1k.size);

      let stream1k = blob1k.stream();

      let reader = new BYOBStreamReader(stream1k);
      let [readData] = await reader.readFill(buffer1k);
      reader.cleanup();
      expect(readData.byteLength).toBe(blob1k.size);
      expect(isEqualArray(
         new Uint8Array(await blob1k.arrayBuffer()),
         readData
      )).toBeTrue();

      blob1k = randomBlob(1024);
      buffer1k = new ArrayBuffer(blob1k.size);
      stream1k = blob1k.stream();

      // May not read entire stream
      reader = new BYOBStreamReader(stream1k);
      [readData] = await reader.readAvailable(buffer1k);
      reader.cleanup();
      expect(isEqualArray(
         new Uint8Array(await blob1k.arrayBuffer(), 0, readData.byteLength),
         readData
      )).toBeTrue();
   });

   it("larger stream", async function () {
      let blob4m = randomBlob(1024 * 1024 * 4);
      let buffer4m = new ArrayBuffer(blob4m.size);
      let stream4m = blob4m.stream();

      let reader = new BYOBStreamReader(stream4m);
      let [readData] = await reader.readFill(buffer4m);
      reader.cleanup();
      expect(readData.byteLength).toBe(blob4m.size);
      expect(isEqualArray(
         new Uint8Array(await blob4m.arrayBuffer()),
         readData
      )).toBeTrue();

      blob4m = randomBlob(1024 * 1024 * 4);
      buffer4m = new ArrayBuffer(blob4m.size);
      stream4m = blob4m.stream();

      // May not read entire stream
      reader = new BYOBStreamReader(stream4m);
      [readData] = await reader.readAvailable(buffer4m);
      reader.cleanup();
      expect(isEqualArray(
         new Uint8Array(await blob4m.arrayBuffer(), 0, readData.byteLength),
         readData
      )).toBeTrue();
   });

   it("under read stream", async function () {
      let blob3m = randomBlob(1024 * 1024 * 3);
      let buffer1m = new ArrayBuffer(1024 * 1024);

      let stream3m = blob3m.stream();

      let reader = new BYOBStreamReader(stream3m);
      let [readData] = await reader.readFill(buffer1m);
      reader.cleanup();

/*      console.log('results',
         new Uint8Array(await blob3m.arrayBuffer(), 0, readData.byteLength),
         readData
      );
*/
      expect(readData.byteLength).toBe(1024 * 1024);
      expect(isEqualArray(
         new Uint8Array(await blob3m.arrayBuffer(), 0, readData.byteLength),
         readData
      )).toBeTrue();

      blob3m = randomBlob(1024 * 1024 * 3);
      buffer1m = new ArrayBuffer(1024 * 1024);
      stream3m = blob3m.stream();

      // May not read entire stream
      reader = new BYOBStreamReader(stream3m);
      [readData] = await reader.readAvailable(buffer1m);
      reader.cleanup();
      expect(isEqualArray(
         new Uint8Array(await blob3m.arrayBuffer(), 0, readData.byteLength),
         readData
      )).toBeTrue();
   });

   it("over read stream", async function () {
      let blob3m = randomBlob(1024 * 1024 * 3);
      let buffer4m = new ArrayBuffer(1024 * 1024 * 4);
      let stream3m = blob3m.stream();

      let reader = new BYOBStreamReader(stream3m);
      let [readData] = await reader.readFill(buffer4m);
      reader.cleanup();
      expect(readData.byteLength).toBe(blob3m.size);
      expect(isEqualArray(
         new Uint8Array(await blob3m.arrayBuffer()),
         readData
      )).toBeTrue();

      blob3m = randomBlob(1024 * 1024 * 3);
      buffer4m = new ArrayBuffer(1024 * 1024 * 4);
      stream3m = blob3m.stream();

      // May not read entire stream
      reader = new BYOBStreamReader(stream3m);
      [readData] = await reader.readAvailable(buffer4m);
      reader.cleanup();
      expect(isEqualArray(
         new Uint8Array(await blob3m.arrayBuffer(), 0, readData.byteLength),
         readData
      )).toBeTrue();
   });
});
