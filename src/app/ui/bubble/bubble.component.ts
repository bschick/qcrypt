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
