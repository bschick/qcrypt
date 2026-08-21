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

import type { zxcvbnAsync, zxcvbnOptions } from '@zxcvbn-ts/core';
import type { Matcher } from '@zxcvbn-ts/core/dist/types';
import type { haveIBeenPwned } from '@zxcvbn-ts/matcher-pwned';

// Lazy-loads the @zxcvbn-ts/* dictionary chunks so they land in their own
// chunks instead of inflating main.

type ZxcvbnBundle = {
   zxcvbnAsync: typeof zxcvbnAsync;
   zxcvbnOptions: typeof zxcvbnOptions;
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
         core.zxcvbnOptions.setOptions({
            translations: en.translations,
            dictionary: {
               ...common.dictionary,
               ...en.dictionary,
            },
            graphs: common.adjacencyGraphs,
            useLevenshteinDistance: true,
         });
         _bundle = {
            zxcvbnAsync: core.zxcvbnAsync,
            zxcvbnOptions: core.zxcvbnOptions,
            pwnedLookup: pwned.haveIBeenPwned,
         };
         return _bundle;
      })();
   }
   return _zxcvbnReady;
}

export function getZxcvbn(): ZxcvbnBundle {
   if (!_bundle) {
      throw new Error('zxcvbn: zxcvbnReady() not awaited');
   }
   return _bundle;
}

// Fails open: an unreachable service reports the password as not breached rather than throwing
export async function isPwned(password: string): Promise<boolean> {
   try {
      const { pwnedLookup } = await zxcvbnReady();
      return !!(await pwnedLookup(password, { universalFetch: fetch }));
   } catch (err) {
      console.error(err);
      return false;
   }
}

export async function addMatcher(name: string, matcher: Matcher): Promise<void> {
   const { zxcvbnOptions } = await zxcvbnReady();
   zxcvbnOptions.addMatcher(name, matcher);
}

export async function removeMatcher(name: string): Promise<void> {
   const { zxcvbnOptions } = await zxcvbnReady();
   delete zxcvbnOptions.matchers[name];
}
