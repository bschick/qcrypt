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
import { ChangeDetectorRef, Component, ChangeDetectionStrategy, inject, signal } from '@angular/core';

export const BubblePosition = {
   ABOVE: 'above',
   BELOW: 'below',
   RIGHT: 'right',
   DEFAULT: 'above',
} as const;

export type BubblePosition = (typeof BubblePosition)[keyof typeof BubblePosition];

@Component({
   selector: 'bubble',
   templateUrl: './bubble.component.html',
   styleUrl: './bubble.component.scss',
   changeDetection: ChangeDetectionStrategy.Eager,
   imports: [],
})
export class BubbleComponent {
   // BubbleDirective creates this component dynamically and drives its change detection from outside
   public readonly changeRef = inject(ChangeDetectorRef);

   readonly position = signal<BubblePosition>(BubblePosition.DEFAULT);
   readonly theme = signal('light');
   readonly tip = signal('');
   readonly left = signal(0);
   readonly top = signal(0);
   readonly width = signal<string | undefined>(undefined);
   readonly height = signal<string | undefined>(undefined);
   readonly fontSize = signal<string | undefined>(undefined);
   readonly visible = signal(false);

   close(): void {
      this.visible.set(false);
   }
}
