import { Injectable } from '@angular/core';
import * as zxcvbnCommonPackage from '@zxcvbn-ts/language-common';
import * as zxcvbnEnPackage from '@zxcvbn-ts/language-en';
import { matcherPwnedFactory } from '@zxcvbn-ts/matcher-pwned';
import { zxcvbnOptions } from '@zxcvbn-ts/core';
import { Matcher } from '@zxcvbn-ts/core/dist/types'

@Injectable({
   providedIn: 'root'
})
export class ZxcvbnOptionsService {

   private matcherPwned: Matcher;

   constructor() {

      const options = {
         translations: zxcvbnEnPackage.translations,
         dictionary: {
            ...zxcvbnCommonPackage.dictionary,
            ...zxcvbnEnPackage.dictionary,
         },
         graphs: zxcvbnCommonPackage.adjacencyGraphs,
         useLevenshteinDistance: true,
      };
      zxcvbnOptions.setOptions(options);
      this.matcherPwned = matcherPwnedFactory(fetch, zxcvbnOptions);

   }

   checkPwned(check: boolean) {
      if (check) {
         if (!zxcvbnOptions.matchers['pwned']) {
            zxcvbnOptions.addMatcher('pwned', this.matcherPwned);
         }
      } else {
         delete zxcvbnOptions.matchers['pwned'];
      }
   }

   addMatcher(name: string, matcher: Matcher) {
      zxcvbnOptions.addMatcher(name, matcher);
   }

   removeMatcher(name: string) {
      delete zxcvbnOptions.matchers[name];
   }
}
