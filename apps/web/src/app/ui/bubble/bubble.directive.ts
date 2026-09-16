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
import { Directive, ComponentRef, ElementRef, Injector, ViewContainerRef, NgZone, inject, input } from '@angular/core';
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

   private _componentRef: ComponentRef<BubbleComponent> | null = null;
   private _scrollHandler: (() => void) | null = null;
   private _resizeHandler: (() => void) | null = null;
   private _clampedLeft = 0;
   private _clampedTop = 0;
   private _initialScrollLeft = 0;
   private _initialScrollTop = 0;

   public show() {
      this._initializeBubble();
      setTimeout(() => {
         if (this._componentRef !== null) {
            this._positionAndClamp();
            this._addEventListeners();
            this._componentRef.instance.visible = true;
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
         this._componentRef.instance.tip = this.bubbleTip();
         this._componentRef.instance.position = this.bubblePosition();
         this._componentRef.instance.width = this.bubbleWidth();
         this._componentRef.instance.height = this.bubbleHeight();
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
         case BubblePosition.UPPER:
         case BubblePosition.ABOVE: {
            this._componentRef.instance.left = Math.round((right - left) / 2 + left);
            this._componentRef.instance.top = Math.round(top);
            break;
         }
         case BubblePosition.RIGHT: {
            this._componentRef.instance.left = Math.round(right);
            this._componentRef.instance.top = Math.round(top + (bottom - top) / 2);
            break;
         }
         default: {
            console.error('unknown bubble position', bubblePosition);
         }
      }

      this._componentRef.instance.changeRef.detectChanges();

      const bubbleEl = this._componentRef.location.nativeElement.querySelector('.bubble');
      if (!bubbleEl) {
         return;
      }

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
         this._componentRef.instance.left += adjustLeft;
         this._componentRef.instance.top += adjustTop;
         this._componentRef.instance.changeRef.detectChanges();
      }

      // Store clamped position and initial scroll state for scroll tracking
      this._clampedLeft = this._componentRef.instance.left;
      this._clampedTop = this._componentRef.instance.top;
      const container = this._getScrollContainer();
      this._initialScrollLeft = container?.scrollLeft ?? 0;
      this._initialScrollTop = container?.scrollTop ?? 0;
   }

   private _addEventListeners() {
      if (this._scrollHandler || this._resizeHandler) {
         return;
      }

      const container = this._getScrollContainer();
      if (container?.contains(this._elementRef.nativeElement)) {
         // Inside scroll container: track scroll to maintain page-relative position
         this._scrollHandler = () => {
            if (this._componentRef) {
               this._componentRef.instance.left = this._clampedLeft - (container.scrollLeft - this._initialScrollLeft);
               this._componentRef.instance.top = this._clampedTop - (container.scrollTop - this._initialScrollTop);
               this._componentRef.instance.changeRef.detectChanges();
            }
         };

         this._ngZone.runOutsideAngular(() => {
            container.addEventListener('scroll', this._scrollHandler!);
         });
      } else {
         // Outside scroll container (e.g. dialog): reposition on resize
         // Use requestAnimationFrame to let the dialog complete its layout first
         this._resizeHandler = () => {
            if (this._componentRef) {
               this._positionAndClamp();
            }
         };

         this._ngZone.runOutsideAngular(() => {
            window.addEventListener('resize', this._resizeHandler!);
         });
      }
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
         this._componentRef.instance.visible = false;
         this._viewContainerRef.remove(this._bubbleIndex);
         this._componentRef.destroy();
         this._componentRef = null;
      }
   }
}
