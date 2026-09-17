/* MIT License

Copyright (c) 2024-2026 Brad Schick

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
   Directive,
   ComponentRef,
   ElementRef,
   Injector,
   ViewContainerRef,
   NgZone,
   inject,
   input,
   numberAttribute,
} from '@angular/core';
import { BubbleComponent, BubblePosition } from './bubble.component';

@Directive({
   selector: '[bubbleTip]',
   exportAs: 'bubbleTip',
   standalone: true,
})
export class BubbleDirective {
   private readonly _elementRef = inject(ElementRef);
   private readonly _viewContainerRef = inject(ViewContainerRef);
   private readonly _injector = inject(Injector);
   private readonly _ngZone = inject(NgZone);

   private _bubbleIndex!: number;

   readonly bubbleTip = input('this is a QC tip');
   readonly bubblePosition = input<BubblePosition>(BubblePosition.DEFAULT);
   readonly bubbleWidth = input<string>();
   readonly bubbleHeight = input<string>();
   readonly bubbleFontSize = input<string>();
   readonly bubbleShiftX = input(0, { transform: numberAttribute });
   readonly bubbleShiftY = input(0, { transform: numberAttribute });

   private _componentRef: ComponentRef<BubbleComponent> | null = null;
   private _scrollHandler: (() => void) | null = null;
   private _resizeHandler: (() => void) | null = null;
   private _pendingFrame = false;

   public show() {
      this._initializeBubble();
      setTimeout(() => {
         if (this._componentRef !== null) {
            this._positionAndClamp();
            this._addEventListeners();
            this._componentRef.instance.visible.set(true);
         }
      }, 200);
   }

   public hide() {
      this.destroy();
   }

   private _getScrollContainer(): Element | null {
      return document.getElementById('scrollContent');
   }

   private _initializeBubble() {
      if (this._componentRef === null) {
         this._componentRef = this._viewContainerRef.createComponent(BubbleComponent, { injector: this._injector });
         this._setComponentProperties();
         this._bubbleIndex = this._viewContainerRef.indexOf(this._componentRef.hostView);
      }
   }

   private _setComponentProperties() {
      if (this._componentRef !== null) {
         this._componentRef.instance.tip.set(this.bubbleTip());
         this._componentRef.instance.position.set(this.bubblePosition());
         this._componentRef.instance.width.set(this.bubbleWidth());
         this._componentRef.instance.height.set(this.bubbleHeight());
         this._componentRef.instance.fontSize.set(this.bubbleFontSize());
         this._positionAndClamp();
      }
   }

   private _positionAndClamp() {
      if (this._componentRef === null) {
         return;
      }

      const { left, right, top, bottom } = this._elementRef.nativeElement.getBoundingClientRect();

      const bubblePosition = this.bubblePosition();
      switch (bubblePosition) {
         case BubblePosition.ABOVE: {
            this._componentRef.instance.left.set(Math.round((right - left) / 2 + left));
            this._componentRef.instance.top.set(Math.round(top));
            break;
         }
         case BubblePosition.RIGHT: {
            this._componentRef.instance.left.set(Math.round(right));
            this._componentRef.instance.top.set(Math.round(top + (bottom - top) / 2));
            break;
         }
         case BubblePosition.BELOW: {
            this._componentRef.instance.left.set(Math.round((right - left) / 2 + left));
            this._componentRef.instance.top.set(Math.round(bottom));
            break;
         }
         default: {
            console.error('unknown bubble position', bubblePosition);
         }
      }

      this._componentRef.instance.left.update((value) => value + this.bubbleShiftX());
      this._componentRef.instance.top.update((value) => value + this.bubbleShiftY());

      this._componentRef.instance.changeRef.detectChanges();

      // Only clamp to the viewport when the anchor is outside the scroll container, since elements
      // inside the container move with it and should not be clamped.
      const container = this._getScrollContainer();
      const clampToViewport = !container?.contains(this._elementRef.nativeElement);

      if (clampToViewport) {
         const bubbleEl = this._componentRef.location.nativeElement.querySelector('.bubble');
         if (bubbleEl) {
            const rect = bubbleEl.getBoundingClientRect();
            const vw = window.visualViewport?.width ?? window.innerWidth;
            const vh = window.visualViewport?.height ?? window.innerHeight;
            const margin = 8;

            let adjustLeft = 0;
            let adjustTop = 0;

            if (rect.left < margin) {
               adjustLeft = margin - rect.left;
            } else if (rect.right > vw - margin) {
               adjustLeft = vw - margin - rect.right;
            }

            if (rect.top < margin) {
               adjustTop = margin - rect.top;
            } else if (rect.bottom > vh - margin) {
               adjustTop = vh - margin - rect.bottom;
            }

            if (adjustLeft !== 0 || adjustTop !== 0) {
               this._componentRef.instance.left.update((value) => value + adjustLeft);
               this._componentRef.instance.top.update((value) => value + adjustTop);
               this._componentRef.instance.changeRef.detectChanges();
            }
         }
      }
   }

   private _addEventListeners() {
      if (this._scrollHandler || this._resizeHandler) {
         return;
      }

      const container = this._getScrollContainer();
      if (container?.contains(this._elementRef.nativeElement)) {
         this._scrollHandler = () => this._reposition();

         this._ngZone.runOutsideAngular(() => {
            container.addEventListener('scroll', this._scrollHandler!);
         });
      }

      this._resizeHandler = () => this._reposition();

      this._ngZone.runOutsideAngular(() => {
         window.addEventListener('resize', this._resizeHandler!);
      });
   }

   // Scroll fires far more often than a frame renders, so coalesce to one measurement per frame
   private _reposition() {
      if (this._pendingFrame || this._componentRef === null) {
         return;
      }
      this._pendingFrame = true;
      requestAnimationFrame(() => {
         this._pendingFrame = false;
         if (this._componentRef !== null) {
            this._positionAndClamp();
         }
      });
   }

   private _removeEventListeners() {
      if (this._scrollHandler) {
         const container = this._getScrollContainer();
         container?.removeEventListener('scroll', this._scrollHandler);
         this._scrollHandler = null;
      }
      if (this._resizeHandler) {
         window.removeEventListener('resize', this._resizeHandler);
         this._resizeHandler = null;
      }
   }

   ngOnDestroy(): void {
      this.destroy();
   }

   destroy(): void {
      this._removeEventListeners();
      if (this._componentRef !== null) {
         this._componentRef.instance.visible.set(false);
         this._viewContainerRef.remove(this._bubbleIndex);
         this._componentRef.destroy();
         this._componentRef = null;
      }
   }
}
