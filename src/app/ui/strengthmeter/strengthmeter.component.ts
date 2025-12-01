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
   Output, Input, EventEmitter,
   ViewChild, ElementRef,
   AfterViewInit,
   OnInit,
   OnDestroy
} from '@angular/core';

import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatSliderModule } from '@angular/material/slider';
import { FormControl, ReactiveFormsModule } from '@angular/forms';
import { MatTooltipModule } from '@angular/material/tooltip';
import { ZxcvbnOptionsService } from '../../services/zxcvbn-options.service';
import { zxcvbnAsync, ZxcvbnResult } from '@zxcvbn-ts/core'
import * as lev from '../../services/levenshtein';
import {
   MatchEstimated,
   MatchExtended,
   Match,
   MatchOptions,
   Matcher,
} from '@zxcvbn-ts/core/dist/types'

const COLORS = ['var(--red-pwd-color)', 'var(--red-pwd-color)', 'var(--yellow-pwd-color)', 'var(--green-pwd-color)', 'var(--green-pwd-color)'];

export type AcceptableState = {
   acceptable: boolean;
   strength: number;
}

@Component({
   selector: 'app-strengthmeter',
   imports: [MatIconModule, MatButtonModule, MatSliderModule, ReactiveFormsModule, MatTooltipModule],
   templateUrl: './strengthmeter.component.html',
   styleUrl: './strengthmeter.component.scss'
})
export class StrengthMeterComponent implements AfterViewInit, OnInit, OnDestroy {

   public strength = -1;
   public strengthMin = 0;

   public segmentOnColor = '';
   public segmentOffColor = '#dcdcdc';
   public strengthSlider = new FormControl(this.strengthMin + 1);
   public warning = '';
   public suggestion = '';
   private _checkPwned = false;
   private _acceptable = false;
   private _lastStrength = -1;
   private _usedPasswords: string[] = [];
   private _testQueue: string[] = [];
   private _processing = false;
   private _processTimerId: any = undefined;
   private _currentPassword = '';
   private _currentHint = '';

   @ViewChild('sliderElem') sliderRef!: ElementRef;
   @ViewChild('matripple') rippleRef!: ElementRef;

   @Output() acceptableChanged = new EventEmitter<AcceptableState>();

   @Input() set minStrength(strengthMin: number) {
      this.strengthMin = Math.max(0, Math.min(strengthMin, 4));
   }

   @Input() set pwned(check: boolean) {
      this._checkPwned = check;
   }

   @Input() set usedPasswords(usedPasswords: string[]) {
      this._usedPasswords = usedPasswords;
      if (this._currentPassword) {
         this.startedProcessing();
      }
   }

   @Input() set hint(hint: string) {
      this._currentHint = hint;
      if (this._currentPassword) {
         this.startedProcessing();
      }
   }

   @Input() set password(passwd: string) {
      this._currentPassword = passwd;
      if (!this._currentPassword) {
         this.setStrength(-1);
         this.warning = '';
         this.suggestion = '';
         this.updateAcceptable();
      } else {
         this.startedProcessing();
      }
   }

   private startedProcessing() {
      // "debounce" a bit to improve performance (lag at the end is acceptable)
      if (!this._processTimerId && this._currentPassword) {
         this._processTimerId = setTimeout(() => {
            this._testQueue.push(this._currentPassword);
            this.processZxcvbn();
            this._processTimerId = undefined;
         }, 175);
      }
   }


   private processZxcvbn() {

      if (!this._processing) {
         this._processing = true;
         (async () => {
            let results: ZxcvbnResult | undefined = undefined;
            while (this._testQueue.length > 0) {
               try {
                  // Use the last password in the queue and drop everything else before it
                  const testPwd = this._testQueue.at(-1)!;
                  this._testQueue.length = 0;

                  // Loop because new items could be added while we await zxcvbnAsync
                  results = await zxcvbnAsync(testPwd);
                  this.setStrength(results.score);
               }
               catch (err) {
                  console.error(err);
               }
            }
            this._processing = false;
            this.updateAcceptable();

            if (results?.feedback) {
               this.warning = results.feedback.warning ?? '';

               // Ugly, but zxcvbn puts its own suggestion first so detect our match and pick #2
               let suggestionIndex = 0;
               const qqMatch = results.sequence.find(
                  match => 'qqMatcher' === match.pattern
               );
               if (qqMatch) {
                  suggestionIndex = 1;
               }
               this.suggestion = results.feedback.suggestions[suggestionIndex] ?? '';
            }
         })();
      }
   }

   constructor(
      private zxcvbnOptions: ZxcvbnOptionsService,
   ) {
   }

   ngOnInit(): void {
      this.zxcvbnOptions.checkPwned(this._checkPwned);

      const parent = this;

      // cloned from https://zxcvbn-ts.github.io/zxcvbn/guide/matcher/#creating-a-custom-matcher
      const qqMatcher: Matcher = {
         Matching: class QQPasswordChecker {
            match({ password }: MatchOptions) {
               const matches: Match[] = [];

               if (parent._usedPasswords.length > 0) {
                  const result = lev.closest(password, parent._usedPasswords);
                  if (result.dist < 3) {
                     matches.push({
                        pattern: 'qqMatcher',
                        token: password,
                        i: 0,
                        j: password.length - 1,
                        exact: result.dist === 0,
                        isHint: false
                     });
                  }
               }

               if (matches.length === 0 && parent._currentHint) {
                  const result = lev.match(password, parent._currentHint);
                  if (result.norm >= 0.70) {
                     matches.push({
                        pattern: 'qqMatcher',
                        token: password,
                        i: 0,
                        j: password.length - 1,
                        exact: result.dist === 0,
                        isHint: true
                     });
                  }
               }

               return matches;
            }
         },

         feedback(match: MatchEstimated, isSoleMatch?: boolean) {
            if (match['isHint']) {
               return {
                  warning: `Your hint is ${match['exact'] ? 'the same as' : 'similar to'} your password.`,
                  suggestions: ['Use a hint that helps only you remember the password.'],
               }
            } else {
               return {
                  warning: `You already used ${match['exact'] ? 'the same' : 'a similar'} password in a previous loop.`,
                  suggestions: ['For better security, choose a unique password for each loop.'],
               }
            }
         },

         scoring(match: MatchExtended) {
            return 0;
         }
      }

      this.zxcvbnOptions.addMatcher('qqMatcher', qqMatcher);
   }

   ngOnDestroy(): void {
      this.zxcvbnOptions.removeMatcher('qqMatcher');
   }

   ngAfterViewInit(): void {
      // https://github.com/angular/components/issues/28679
      if (this.sliderRef?.nativeElement) {
         const parent = this.sliderRef.nativeElement.parentNode;
         const ripple = parent.getElementsByClassName('mat-ripple');
         if (ripple.length) {
            ripple[0].remove();
         }

         parent.style.setProperty(
            '--mat-slider-active-track-color',
            'transparent'
         );
         parent.style.setProperty(
            '--mat-slider-inactive-track-color',
            'transparent'
         );
      }

      this.setMinStrength(this.strengthMin);
   }

   onStrengthMinChange($event: Event) {
      this.setMinStrength(this.strengthSlider.value! - 1);
   }

   setMinStrength(strengthMin: number) {
      strengthMin = Math.max(0, Math.min(strengthMin, 4));
      this.strengthSlider.setValue(strengthMin + 1);
      this.strengthMin = strengthMin;

      this.updateAcceptable();
   }

   setStrength(strength: number) {
      strength = Math.max(-1, Math.min(strength, 4));

      if (strength >= 0) {
         const color = COLORS[strength];
         this.segmentOnColor = color;
      }
      this.strength = strength;
   }

   updateAcceptable() {
      const acceptable = this.strength >= this.strengthMin;

      if (acceptable !== this._acceptable || this.strength !== this._lastStrength) {
         this._acceptable = acceptable;
         this._lastStrength = this.strength;

         // Avoids RuntimeError: NG0100 (and seems very hacky)
         setTimeout(() => {
            this.acceptableChanged.emit({
               acceptable: !!acceptable,
               strength: this.strength
            });
         });
      }
   }

   segmentColor(segment: number): string {
      return this.strength >= segment ? this.segmentOnColor : this.segmentOffColor;
   }

}
