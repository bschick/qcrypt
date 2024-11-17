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
    base64ToBytes,
    bytesToBase64
 } from '../services/utils';


 export function makeCipherArmor(
    cipherData: Uint8Array,
    format: string,
    reminder: boolean = false
) : string {
    // Rebuild object to control ordering (better way to do this?)
    let result: { [key: string]: string | number } = {};
    result['ct'] = bytesToBase64(cipherData);

    if (format == 'link') {
       const ctParam = encodeURIComponent(JSON.stringify(result));
       return 'https://' + location.host + '?cipherarmor=' + ctParam;
    } else {
       if (reminder) {
          result['reminder'] = 'decrypt with quick crypt';
       }
       return JSON.stringify(result, null, format == 'indent' ? 3 : 0);
    }
 }

 export function parseCipherArmor(
    cipherArmor: string
) : Uint8Array {
    try {
       let trimmed = cipherArmor.trim();
       if (trimmed.startsWith('https://')) {
          const ct = new URL(trimmed).searchParams.get('cipherarmor');
          if (ct == null) {
             let err = Error();
             err.name = 'Url missing cipherarmor';
             throw err;
          }
          trimmed = ct;
       } else if (trimmed.startsWith('cipherarmor=')) {
          trimmed = trimmed.slice('cipherarmor='.length);
       }

       // %7B is urlencoded '{' character, so decode
       if (trimmed.startsWith('%7B')) {
          trimmed = decodeURIComponent(trimmed);
       }

       // turn baseUrl ecoded CT w/o json into json
       if (!trimmed.startsWith('{')) {
          trimmed = `{"ct":"${trimmed.replace(/[''""]/g, '')}"}`;
       }
       var jsonParts = JSON.parse(trimmed);
    } catch (err) {
       console.error(err);
       if (err instanceof Error) {
          throw new Error('Cipher armor text not formatted correctly. ' + err.name);
       }
    }
    if (!('ct' in jsonParts)) {
       throw new Error('Missing ct in cipher armor text');
    }
    const ct = jsonParts.ct;

    // note that we ignore lps in the original V1 cipher armor since it was
    // never used in the wild
    return base64ToBytes(ct);
 }
