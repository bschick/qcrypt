


// Sadly, there doesn't seem to be a way to force ReadableStreamBYOBReader.read
// to write into the provided buffer. To support zero copy it sometime returns
// internal buffer. That means we have to return the data buffer and its size.
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
       if(!data || !data.byteLength || done) {
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