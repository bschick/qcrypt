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
   OnInit
} from '@angular/core';

import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatSliderModule } from '@angular/material/slider';
import { FormControl, ReactiveFormsModule } from '@angular/forms';
import { MatTooltipModule } from '@angular/material/tooltip';
import { ZxcvbnOptionsService } from '../../services/zxcvbn-options.service';
import { zxcvbnAsync, ZxcvbnResult } from '@zxcvbn-ts/core'

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
export class StrengthMeterComponent implements AfterViewInit, OnInit {

   public strength = -1;
   public strengthMin = 0;

   private testQueue: string[] = [];
   public segmentOnColor = '';
   public segmentOffColor = '#dcdcdc';
   public strengthSlider = new FormControl(this.strengthMin + 1);
   private checkPwned = false;
   private acceptable = false;
   private lastStrength = -1;
   public warning = '';
   public suggestion = '';

   @ViewChild('sliderElem') sliderRef!: ElementRef;
   @ViewChild('matripple') rippleRef!: ElementRef;

   @Output() acceptableChanged = new EventEmitter<AcceptableState>();

   @Input() set minStrength(strengthMin: number) {
      this.strengthMin = Math.max(0, Math.min(strengthMin, 4));
   }

   @Input() set pwned(check: boolean) {
      this.checkPwned = check;
   }

   @Input() set password(passwd: string) {
      this.testQueue.push(passwd);

      if (this.testQueue.length === 1) {
         (async () => {
            let results: ZxcvbnResult | undefined = undefined;
            while (this.testQueue.length > 0) {
               try {
                  const testPwd = this.testQueue[0];
                  let score = -1;
                  if (testPwd) {
                     results = await zxcvbnAsync(testPwd);
                     score = results.score;
                  }
                  this.setStrength(score);
               }
               catch (err) {
                  console.error(err);
               } finally {
                  this.testQueue.shift()!;
               }
            }

            this.updateAcceptable();

            if( results?.feedback ){
               this.warning = results.feedback.warning ?? '';
               this.suggestion = results.feedback.suggestions[0] ?? '';
            }
         })();
      }
   }

   constructor(
      private zxcvbnOptions: ZxcvbnOptionsService,
   ) {
   }

   ngOnInit(): void {
      this.zxcvbnOptions.checkPwned(this.checkPwned);
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

      if( strength >= 0 ) {
         const color = COLORS[strength];
         this.segmentOnColor = color;
      }
      this.strength = strength;
   }

   updateAcceptable() {
      const acceptable = this.strength >= this.strengthMin;

      if (acceptable !== this.acceptable || this.strength !== this.lastStrength) {
         this.acceptable = acceptable;
         this.lastStrength = this.strength;

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
