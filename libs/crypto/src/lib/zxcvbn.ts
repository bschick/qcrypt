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

import type { Matcher, MatcherBaseClass, OptionsType, ZxcvbnFactory } from '@zxcvbn-ts/core';
import type { haveIBeenPwned } from '@zxcvbn-ts/matcher-pwned';
import { logError } from './utils';

// Lazy-loads the @zxcvbn-ts/* dictionary chunks so they land in their own
// chunks instead of inflating main.

type ZxcvbnBundle = {
   ZxcvbnFactory: typeof ZxcvbnFactory;
   MatcherBaseClass: typeof MatcherBaseClass;
   options: OptionsType;
   pwnedLookup: typeof haveIBeenPwned;
};

let _zxcvbnReady: Promise<ZxcvbnBundle> | undefined;
let _bundle: ZxcvbnBundle | undefined;

export function zxcvbnReady(): Promise<ZxcvbnBundle> {
   if (!_zxcvbnReady) {
      _zxcvbnReady = (async () => {
         const [common, en, pwned, core] = await Promise.all([
            import('@zxcvbn-ts/language-common'),
            import('@zxcvbn-ts/language-en'),
            import('@zxcvbn-ts/matcher-pwned'),
            import('@zxcvbn-ts/core'),
         ]);
         _bundle = {
            ZxcvbnFactory: core.ZxcvbnFactory,
            MatcherBaseClass: core.MatcherBaseClass,
            options: {
               translations: en.translations,
               dictionary: {
                  ...common.dictionary,
                  ...en.dictionary,
               },
               graphs: common.adjacencyGraphs,
               useLevenshteinDistance: true,
            },
            pwnedLookup: pwned.haveIBeenPwned,
         };
         return _bundle;
      })();
   }
   return _zxcvbnReady;
}

// Returns true when the password was found in a breach, false when not in a breach, and undefined for errors
export async function isPwned(password: string): Promise<boolean | undefined> {
   try {
      const { pwnedLookup } = await zxcvbnReady();
      const found = await pwnedLookup(password, {
         universalFetch: fetch,
         // pwnedLookup returns false for network and HTTP errors by default, so rethrow them
         networkErrorHandler: (error) => {
            throw error instanceof Response ? new Error(`pwned lookup failed: ${error.status}`) : error;
         },
      });
      return !!found;
   } catch (err) {
      logError(err);
      return undefined;
   }
}

// Matcher is built from the lazily loaded MatcherBaseClass to avoid a static import
export async function createZxcvbn(
   makeMatchers?: (base: typeof MatcherBaseClass) => Record<string, Matcher>,
): Promise<ZxcvbnFactory> {
   const { ZxcvbnFactory: Factory, MatcherBaseClass: base, options } = await zxcvbnReady();
   return new Factory(options, makeMatchers?.(base));
}
