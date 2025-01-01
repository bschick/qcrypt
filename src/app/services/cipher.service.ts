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

import { Injectable } from "@angular/core";
import * as cc from "./cipher.consts";
import { Ciphers } from "./ciphers";
import {
   EContext,
   encryptStream,
   decryptStream,
   getCipherStreamInfo,
   CipherDataInfo,
   PWDProvider,
} from "./cipher-streams";

export { EContext, CipherDataInfo, PWDProvider };

/* Thin wrapper around Ciphers and cipher stream functions to create
an Angular service. Must of that functionality was previously in this
class directly, and perhaps this class could now be removed, but keeping
it for now to avoid having to update other code and many tests */

@Injectable({
   providedIn: "root",
})
export class CipherService {
   private _iCount = 0;
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
      if (this._iCount === 0) {
         [this._iCount, this._iCountMax, this._hashRate] = await Ciphers.benchmark(
            testSize,
            targetMillis,
            maxMillis
         );
      }

      return [this._iCount, this._iCountMax, this._hashRate];
   }

   validateAlgs(algs: string[]): boolean {
      for (let alg of algs) {
         if (!Ciphers.validateAlg(alg)) {
            return false;
         }
      }
      return true;
   }

   validateAlg(alg: string): boolean {
      return Ciphers.validateAlg(alg);
   }

   algDescription(alg: string): string {
      return Ciphers.validateAlg(alg)
         ? (cc.AlgInfo[alg]["description"] as string)
         : "Invalid";
   }

   algs(): string[] {
      return Object.keys(cc.AlgInfo);
   }

   async encryptStream(
      econtext: EContext,
      pwdProvider: PWDProvider,
      userCred: Uint8Array,
      clearStream: ReadableStream<Uint8Array>
   ): Promise<ReadableStream<Uint8Array>> {
      return encryptStream(econtext, pwdProvider, userCred, clearStream);
   }

   async getCipherStreamInfo(
      userCred: Uint8Array,
      cipherStream: ReadableStream<Uint8Array>
   ): Promise<CipherDataInfo> {
      return getCipherStreamInfo(userCred, cipherStream);
   }

   async decryptStream(
      pwdProvider: PWDProvider,
      userCred: Uint8Array,
      cipherStream: ReadableStream<Uint8Array>
   ): Promise<ReadableStream<Uint8Array>> {
      return decryptStream(pwdProvider, userCred, cipherStream);
   }
}
