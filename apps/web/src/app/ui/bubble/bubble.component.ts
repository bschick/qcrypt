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
import { ChangeDetectorRef, Component, OnInit } from '@angular/core';
import { NgClass } from '@angular/common';

export const BubblePosition = {
   ABOVE: 'above',
   UPPER: 'upper',
   RIGHT: 'right',
   DEFAULT: 'upper'
} as const;

export type BubblePosition = typeof BubblePosition[keyof typeof BubblePosition];

@Component({
    selector: 'bubble',
    templateUrl: './bubble.component.html',
    styleUrl: './bubble.component.scss',
    imports: [NgClass]
})
export class BubbleComponent implements OnInit {

   position: BubblePosition = BubblePosition.DEFAULT;
   theme = 'light';
   tip = '';
   left = 0;
   top = 0;
   width?: string;
   height?: string;
   visible = false;

   constructor(
      public changeRef: ChangeDetectorRef,
   ) {}

   ngOnInit(): void {}
}
