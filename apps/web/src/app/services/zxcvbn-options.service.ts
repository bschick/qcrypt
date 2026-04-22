import { Injectable } from '@angular/core';
import type { zxcvbnAsync, zxcvbnOptions } from '@zxcvbn-ts/core';
import type { Matcher } from '@zxcvbn-ts/core/dist/types';

type ZxcvbnBundle = {
   zxcvbnAsync: typeof zxcvbnAsync;
   zxcvbnOptions: typeof zxcvbnOptions;
};

@Injectable({
   providedIn: 'root'
})
export class ZxcvbnOptionsService {

   private _bundle?: Promise<ZxcvbnBundle>;
   private _pwnedMatcher?: Matcher;

   // Kicks off (or returns the cached) dynamic load of @zxcvbn-ts/* packages.
   // Callers should await this before using zxcvbnAsync, addMatcher, etc.
   // Safe to call eagerly (e.g. at app startup) to warm the chunk.
   preload(): Promise<ZxcvbnBundle> {
      if (!this._bundle) {
         this._bundle = (async () => {
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
            this._pwnedMatcher = pwned.matcherPwnedFactory(fetch, core.zxcvbnOptions);
            return { zxcvbnAsync: core.zxcvbnAsync, zxcvbnOptions: core.zxcvbnOptions };
         })();
      }
      return this._bundle;
   }

   async checkPwned(check: boolean): Promise<void> {
      const { zxcvbnOptions } = await this.preload();
      if (check) {
         if (!zxcvbnOptions.matchers['pwned'] && this._pwnedMatcher) {
            zxcvbnOptions.addMatcher('pwned', this._pwnedMatcher);
         }
      } else {
         delete zxcvbnOptions.matchers['pwned'];
      }
   }

   async addMatcher(name: string, matcher: Matcher): Promise<void> {
      const { zxcvbnOptions } = await this.preload();
      zxcvbnOptions.addMatcher(name, matcher);
   }

   async removeMatcher(name: string): Promise<void> {
      const { zxcvbnOptions } = await this.preload();
      delete zxcvbnOptions.matchers[name];
   }
}
