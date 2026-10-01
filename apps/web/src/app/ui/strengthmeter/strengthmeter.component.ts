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
   Component,
   ElementRef,
   type AfterViewInit,
   ChangeDetectionStrategy,
   effect,
   inject,
   input,
   linkedSignal,
   output,
   signal,
   untracked,
   viewChild,
} from '@angular/core';

import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatSliderModule } from '@angular/material/slider';
import { FormsModule } from '@angular/forms';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatSnackBar } from '@angular/material/snack-bar';
import { isPwned, createZxcvbn } from '@qcrypt/crypto';
import type { MatcherBaseClass, ZxcvbnFactory, ZxcvbnResult } from '@zxcvbn-ts/core';
import * as lev from '../../services/levenshtein';
import type { MatchEstimated, MatchExtended, Match, MatchOptions, Matcher, Options } from '@zxcvbn-ts/core';

const COLORS = [
   'var(--red-pwd-color)',
   'var(--red-pwd-color)',
   'var(--yellow-pwd-color)',
   'var(--green-pwd-color)',
   'var(--green-pwd-color)',
];

const BREACH_WARNING = 'Your password was exposed by a data breach on the Internet.';
const BREACH_SUGGESTION = 'Add more words that are less common.';
const BREACH_CHECK_FAILED = 'Could not check if your password was stolen';

export type AcceptableState = {
   acceptable: boolean;
   strength: number;
};

@Component({
   selector: 'app-strengthmeter',
   imports: [MatIconModule, MatButtonModule, MatSliderModule, FormsModule, MatTooltipModule],
   templateUrl: './strengthmeter.component.html',
   changeDetection: ChangeDetectionStrategy.Eager,
   styleUrl: './strengthmeter.component.scss',
})
export class StrengthMeterComponent implements AfterViewInit {
   readonly minStrength = input(0);
   readonly pwned = input(false);
   readonly usedPasswords = input<string[]>([]);
   readonly hint = input('');
   readonly password = input('');

   protected readonly strength = signal(-1);
   // Local overrides of strengthMin take precedence until minStrength() changes
   protected readonly strengthMin = linkedSignal(() => Math.max(0, Math.min(this.minStrength(), 4)));
   protected readonly segmentOffColor = 'var(--none-pwd-color)';
   protected readonly strengthSlider = signal(1);
   protected readonly warning = signal('');
   protected readonly suggestion = signal('');

   private _acceptable = false;
   private _lastStrength = -1;
   private _usedPasswords: string[] = [];
   private _testQueue: string[] = [];
   private _processing = false;
   private _processDone: Promise<void> = Promise.resolve();
   private _processTimerId: ReturnType<typeof setTimeout> | undefined = undefined;
   private _currentHint = '';
   private _pwnedChecked = false;
   private _pwnedDone: Promise<void> = Promise.resolve();
   private _breachedPassword = '';
   private _scorer: Promise<ZxcvbnFactory> | undefined;
   private _snackBar = inject(MatSnackBar);

   readonly sliderRef = viewChild.required<ElementRef>('sliderElem');

   readonly acceptableChanged = output<AcceptableState>();

   constructor() {
      effect(() => {
         const password = this.password();
         this._pwnedChecked = false;
         this._breachedPassword = '';

         // _updateAcceptable reads strength and strengthMin, which must not trigger a rescore
         untracked(() => {
            if (password) {
               this._startedProcessing();
            } else {
               clearTimeout(this._processTimerId);
               this._processTimerId = undefined;
               this._setStrength(-1);
               this.warning.set('');
               this.suggestion.set('');
               this._updateAcceptable();
            }
         });
      });

      effect(() => {
         this._currentHint = this.hint();
         this._usedPasswords = this.usedPasswords();
         untracked(() => this._startedProcessing());
      });
   }

   private _startedProcessing() {
      // Scores at most once per interval to improve performance (lag at the end is acceptable)
      if (!this._processTimerId && this.password()) {
         this._processTimerId = setTimeout(() => {
            this._testQueue.push(this.password());
            this._processZxcvbn();
            this._processTimerId = undefined;
         }, 175);
      }
   }

   // Intended to be called once per password to check for breaches
   public async checkIfPwned(): Promise<AcceptableState> {
      // Cancel any queued scoring timer and score the current password before checking pwned status
      if (this._processTimerId) {
         clearTimeout(this._processTimerId);
         this._processTimerId = undefined;
         this._testQueue.push(this.password());
         this._processZxcvbn();
      }
      await this._processDone;

      if (this.pwned() && this.password() && !this._pwnedChecked) {
         this._pwnedChecked = true;
         this._pwnedDone = (async () => {
            const pwd = this.password();
            const pwned = await isPwned(pwd);
            // Ignore is the password has changed while we await an answer
            if (pwd !== this.password()) {
               return;
            }
            if (pwned === undefined) {
               this._snackBar.open(BREACH_CHECK_FAILED, '', { duration: 5000 });
            } else if (pwned) {
               this._breachedPassword = pwd;
               this._testQueue.push(pwd);
               await this._processZxcvbn();
            }
         })().catch((err) => console.error(err));
      }

      await this._pwnedDone;
      return { acceptable: this._acceptable, strength: this.strength() };
   }

   private _processZxcvbn(): Promise<void> {
      if (!this._processing) {
         this._processing = true;
         this._processDone = (async () => {
            let results: ZxcvbnResult | undefined;
            try {
               this._scorer ??= createZxcvbn((base) => ({ qcMatcher: this._makeMatcher(base) }));
               const zxcvbn = await this._scorer;
               while (this._testQueue.length > 0) {
                  try {
                     // Use the last password in the queue and drop everything else before it
                     const testPwd = this._testQueue.at(-1)!;
                     this._testQueue.length = 0;

                     // Loop because new items could be added while we await checkAsync
                     const scored = await zxcvbn.checkAsync(testPwd);

                     // Ignore results for a password the user has since changed
                     if (testPwd === this.password()) {
                        results = scored;

                        // Below the lowest selectable minimum, so a breach is rejected at any setting
                        this._setStrength(testPwd === this._breachedPassword ? -1 : results.score);
                     }
                  } catch (err) {
                     console.error(err);
                  }
               }
            } catch (err) {
               // Reset the cached loader so the next attempt retries the dictionary download
               this._scorer = undefined;
               console.error(err);
            } finally {
               this._processing = false;
            }
            this._updateAcceptable();

            if (results?.password === this._breachedPassword) {
               this.warning.set(BREACH_WARNING);
               this.suggestion.set(BREACH_SUGGESTION);
            } else if (results?.feedback) {
               this.warning.set(results.feedback.warning ?? '');

               // Ugly, but zxcvbn puts its own suggestion first so detect our match and pick #2
               let suggestionIndex = 0;
               const qcMatch = results.sequence.find((match) => 'qcMatcher' === match.pattern);
               if (qcMatch) {
                  suggestionIndex = 1;
               }
               this.suggestion.set(results.feedback.suggestions[suggestionIndex] ?? '');
            }
         })();
      }

      return this._processDone;
   }

   private _makeMatcher(base: typeof MatcherBaseClass): Matcher {
      const parent = this;

      // cloned from https://zxcvbn-ts.github.io/zxcvbn/guide/matcher/#creating-a-custom-matcher
      const qcMatcher: Matcher = {
         Matching: class QCPasswordChecker extends base {
            match({ password }: MatchOptions) {
               const matches: Match[] = [];

               if (parent._usedPasswords.length > 0) {
                  const result = lev.closest(password, parent._usedPasswords);
                  if (result.dist < 3) {
                     matches.push({
                        pattern: 'qcMatcher',
                        token: password,
                        i: 0,
                        j: password.length - 1,
                        exact: result.dist === 0,
                        isHint: false,
                     });
                  }
               }

               if (matches.length === 0 && parent._currentHint) {
                  const result = lev.match(password.toLowerCase(), parent._currentHint.toLowerCase());
                  if (result.norm >= 0.7) {
                     matches.push({
                        pattern: 'qcMatcher',
                        token: password,
                        i: 0,
                        j: password.length - 1,
                        exact: result.dist === 0,
                        isHint: true,
                     });
                  }
               }

               return matches;
            }
         },

         feedback(_options: Options, match: MatchEstimated, _isSoleMatch?: boolean) {
            if (match['isHint']) {
               return {
                  warning: `Your hint is similar to your password.`,
                  suggestions: ['Use a hint that helps only you remember the password.'],
               };
            } else {
               return {
                  warning: `You already used ${match['exact'] ? 'the same' : 'a similar'} password in a previous loop.`,
                  suggestions: ['For better security, choose a unique password for each loop.'],
               };
            }
         },

         scoring(_match: MatchExtended) {
            return 0;
         },
      };

      return qcMatcher;
   }

   ngAfterViewInit(): void {
      // https://github.com/angular/components/issues/28679
      const sliderRef = this.sliderRef();
      if (sliderRef?.nativeElement) {
         const parent = sliderRef.nativeElement.parentNode;
         const ripple = parent.getElementsByClassName('mat-ripple');
         if (ripple.length) {
            ripple[0].remove();
         }

         parent.style.setProperty('--mat-slider-active-track-color', 'transparent');
         parent.style.setProperty('--mat-slider-inactive-track-color', 'transparent');
      }

      this._setMinStrength(this.strengthMin());
   }

   protected onStrengthMinChange(_$event: Event) {
      this._setMinStrength(this.strengthSlider() - 1);
   }

   private _setMinStrength(strengthMin: number) {
      strengthMin = Math.max(0, Math.min(strengthMin, 4));
      this.strengthSlider.set(strengthMin + 1);
      this.strengthMin.set(strengthMin);

      this._updateAcceptable();
   }

   private _setStrength(strength: number) {
      this.strength.set(Math.max(-1, Math.min(strength, 4)));
   }

   private _updateAcceptable() {
      const strength = this.strength();
      const acceptable = strength >= this.strengthMin();

      if (acceptable !== this._acceptable || strength !== this._lastStrength) {
         this._acceptable = acceptable;
         this._lastStrength = strength;

         this.acceptableChanged.emit({
            acceptable: !!acceptable,
            strength,
         });
      }
   }

   protected segmentColor(segment: number): string {
      const strength = this.strength();
      return strength >= segment ? COLORS[strength] : this.segmentOffColor;
   }
}
