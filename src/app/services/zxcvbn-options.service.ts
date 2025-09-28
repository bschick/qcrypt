import { Injectable } from '@angular/core';
import { Matcher, zxcvbnOptions } from '@zxcvbn-ts/core';
import * as zxcvbnCommonPackage from '@zxcvbn-ts/language-common';
import * as zxcvbnEnPackage from '@zxcvbn-ts/language-en';
import { matcherPwnedFactory } from '@zxcvbn-ts/matcher-pwned';

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

}
