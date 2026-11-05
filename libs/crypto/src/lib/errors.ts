/* MIT License

Copyright (c) 2025 Brad Schick

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

export class WrongPasswordError extends Error {
   constructor(options?: ErrorOptions) {
      super('Invalid key commitment', options);
      this.name = 'WrongPasswordError';
   }
}

export class ModifiedDataError extends Error {
   constructor(options?: ErrorOptions) {
      super('Invalid MAC signature', options);
      this.name = 'ModifiedDataError';
   }
}

export class ForgedDataError extends Error {
   constructor(options?: ErrorOptions) {
      super('Cipher data appears forged', options);
      this.name = 'ForgedDataError';
   }
}

// Returns undefined for errors with no decryption message so the caller can choose its own.
// credential is the caller's name for what holds the userCred, such as 'passkey'.
export function decryptionErrorMessage(err: unknown, credential: string): string | undefined {
   let msg: string | undefined;
   if (err instanceof WrongPasswordError) {
      msg = 'Decryption failed because the password is incorrect.';
   } else if (err instanceof ModifiedDataError) {
      msg = 'Decryption failed because the cipher armor was either modified or encrypted by a different account.';
   } else if (err instanceof ForgedDataError) {
      msg = 'Decryption failed because the cipher armor appears to be forged.';
   } else if (err instanceof DOMException) {
      // Generic AEAD failure
      msg = `Decryption failed because the password or ${credential} is incorrect, or the cipher armor is not valid.`;
   }
   return msg;
}
