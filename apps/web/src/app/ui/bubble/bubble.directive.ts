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
   Input,
   ComponentRef,
   ElementRef,
   Injector,
   ViewContainerRef,
   NgZone
} from '@angular/core';
import { BubbleComponent, BubblePosition } from './bubble.component';

@Directive({
   selector: '[bubbleTip]',
   exportAs: 'bubbleTip',
   standalone: true
})
export class BubbleDirective {

   private bubbleIndex!: number;

   @Input() bubbleTip = 'this is a QC tip';
   @Input() bubblePosition: BubblePosition = BubblePosition.DEFAULT;
   @Input() bubbleWidth?: string;
   @Input() bubbleHeight?: string;

   private componentRef: ComponentRef<BubbleComponent> | null = null;
   private scrollHandler: (() => void) | null = null;
   private resizeHandler: (() => void) | null = null;
   private clampedLeft = 0;
   private clampedTop = 0;
   private initialScrollLeft = 0;
   private initialScrollTop = 0;

   constructor(private elementRef: ElementRef,
      private viewContainerRef: ViewContainerRef,
      private injector: Injector,
      private ngZone: NgZone
   ) {

   }

   public show() {
      this.initializeBubble();
      setTimeout(() => {
         if (this.componentRef !== null) {
            this.positionAndClamp();
            this.addEventListeners();
            this.componentRef.instance.visible = true;
         }
      }, 200);
   }

   public hide() {
      this.destroy();
   }

   private getScrollContainer(): Element | null {
      return document.getElementById('scrollContent');
   }

   private initializeBubble() {
      if (this.componentRef === null) {
         this.componentRef = this.viewContainerRef.createComponent(BubbleComponent, { injector: this.injector });
         this.setComponentProperties();
         this.bubbleIndex = this.viewContainerRef.indexOf(this.componentRef.hostView);
      }
   }

   private setComponentProperties() {
      if (this.componentRef !== null) {
         this.componentRef.instance.tip = this.bubbleTip;
         this.componentRef.instance.position = this.bubblePosition;
         this.componentRef.instance.width = this.bubbleWidth;
         this.componentRef.instance.height = this.bubbleHeight;
         this.positionAndClamp();
      }
   }

   private positionAndClamp() {
      if (this.componentRef === null) {
         return;
      }

      const { left, right, top, bottom } = this.elementRef.nativeElement.getBoundingClientRect();

      switch (this.bubblePosition) {
         case BubblePosition.UPPER:
         case BubblePosition.ABOVE: {
            this.componentRef.instance.left = Math.round((right - left) / 2 + left);
            this.componentRef.instance.top = Math.round(top);
            break;
         }
         case BubblePosition.RIGHT: {
            this.componentRef.instance.left = Math.round(right);
            this.componentRef.instance.top = Math.round(top + (bottom - top) / 2);
            break;
         }
         default: {
            console.error('unknown bubble position', this.bubblePosition);
         }
      }

      this.componentRef.instance.changeRef.detectChanges();

      const bubbleEl = this.componentRef.location.nativeElement.querySelector('.bubble');
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
         adjustLeft = (vw - margin) - rect.right;
      }

      if (rect.top < margin) {
         adjustTop = margin - rect.top;
      } else if (rect.bottom > vh - margin) {
         adjustTop = (vh - margin) - rect.bottom;
      }

      if (adjustLeft !== 0 || adjustTop !== 0) {
         this.componentRef.instance.left += adjustLeft;
         this.componentRef.instance.top += adjustTop;
         this.componentRef.instance.changeRef.detectChanges();
      }

      // Store clamped position and initial scroll state for scroll tracking
      this.clampedLeft = this.componentRef.instance.left;
      this.clampedTop = this.componentRef.instance.top;
      const container = this.getScrollContainer();
      this.initialScrollLeft = container?.scrollLeft ?? 0;
      this.initialScrollTop = container?.scrollTop ?? 0;
   }

   private addEventListeners() {
      if (this.scrollHandler || this.resizeHandler) {
         return;
      }

      const container = this.getScrollContainer();
      if (container && container.contains(this.elementRef.nativeElement)) {
         // Inside scroll container: track scroll to maintain page-relative position
         this.scrollHandler = () => {
            if (this.componentRef) {
               this.componentRef.instance.left = this.clampedLeft - (container.scrollLeft - this.initialScrollLeft);
               this.componentRef.instance.top = this.clampedTop - (container.scrollTop - this.initialScrollTop);
               this.componentRef.instance.changeRef.detectChanges();
            }
         };

         this.ngZone.runOutsideAngular(() => {
            container.addEventListener('scroll', this.scrollHandler!);
         });
      } else {
         // Outside scroll container (e.g. dialog): reposition on resize
         // Use requestAnimationFrame to let the dialog complete its layout first
         this.resizeHandler = () => {
            if (this.componentRef) {
               this.positionAndClamp();
            }
         };

         this.ngZone.runOutsideAngular(() => {
            window.addEventListener('resize', this.resizeHandler!);
         });
      }
   }

   private removeEventListeners() {
      if (this.scrollHandler) {
         const container = this.getScrollContainer();
         container?.removeEventListener('scroll', this.scrollHandler);
         this.scrollHandler = null;
      }
      if (this.resizeHandler) {
         window.removeEventListener('resize', this.resizeHandler);
         this.resizeHandler = null;
      }
   }

   ngOnDestroy(): void {
      this.destroy();
   }

   destroy(): void {
      this.removeEventListeners();
      if (this.componentRef !== null) {
         this.componentRef.instance.visible = false;
         this.viewContainerRef.remove(this.bubbleIndex);
         this.componentRef.destroy();
         this.componentRef = null;
      }
   }
}
