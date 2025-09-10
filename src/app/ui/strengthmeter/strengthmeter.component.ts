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
   AfterViewInit
} from '@angular/core';
import { CommonModule } from '@angular/common';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatSliderModule } from '@angular/material/slider';
import { FormControl, ReactiveFormsModule } from '@angular/forms';
import { MatTooltipModule } from '@angular/material/tooltip';

const NAMES = ['terrible', 'weak', 'decent', 'good', 'best'];
const COLORS = ['var(--red-pwd-color)', 'var(--red-pwd-color)', 'var(--yellow-pwd-color)', 'var(--green-pwd-color)', 'var(--green-pwd-color)'];

@Component({
   selector: 'app-strengthmeter',
   imports: [CommonModule, MatIconModule, MatButtonModule, MatSliderModule,
      ReactiveFormsModule, MatTooltipModule
   ],
   templateUrl: './strengthmeter.component.html',
   styleUrl: './strengthmeter.component.scss'
})
export class StrengthMeterComponent implements AfterViewInit {

   public strength = 0;
   public backgroundColor = 'white';
   public stenghSlider = new FormControl(this.strength);

   //   @ViewChild('editableInput', { static: true }) editInput!: ElementRef;
   @Output() rangeChanged = new EventEmitter<StrengthMeterComponent>();
   @ViewChild('sliderElem') sliderRef!: ElementRef;
   @ViewChild('matripple') rippleRef!: ElementRef;

   @Input() set stength(strength: number) {
      this.strength = strength;
   }

   ngAfterViewInit(): void {
      // https://github.com/angular/components/issues/28679
      if (this.sliderRef?.nativeElement) {
         const parent = this.sliderRef.nativeElement.parentNode;
         const ripple = parent.getElementsByClassName('mat-ripple');
         if (ripple.length) {
            ripple[0].remove();
            console.log('removed');
         }
      }
   }


   onStrengthChange($event: Event) {
      let color = COLORS[0];
      let strength = this.stenghSlider.value!;

      if (strength > 0) {
         color = COLORS[strength - 1];
      } else {
         strength = 1;
         this.stenghSlider.setValue(1);
      }

      console.log('setting ', strength, color);
      this.sliderRef.nativeElement.parentNode.style.setProperty(
         '--mdc-slider-active-track-color',
         color
      );
      this.backgroundColor = color;
      this.strength = strength;
   }

   formatLabel(stength: number): string {
      return NAMES[stength];
   }

   get stength(): number {
      return this.strength;
   }

   onFocusOut() {
      this.rangeChanged.emit(this);
   }

}
