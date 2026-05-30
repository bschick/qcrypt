/* MIT License

Copyright (c) 2025-2026 Brad Schick

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
   ChangeDetectorRef,
   DestroyRef,
   Directive,
   ElementRef,
   HostListener,
   computed,
   effect,
   inject,
   input,
   signal,
   untracked,
} from '@angular/core';

const MIN_SCALE = 1;
const MAX_SCALE = 12;
const WHEEL_STEP = 1.04;
const BUTTON_STEP = 1.25;
const KEY_PAN_PX = 60;
const KEY_PAN_PX_FAST = 200;
const DRAG_PIXEL_THRESHOLD = 4;

@Directive({
   selector: '[panZoom]',
   exportAs: 'panZoom',
   host: {
      tabindex: '0',
      style: 'touch-action: none; overflow: hidden; user-select: none;',
      '[style.cursor]': 'cursorStyle()',
   },
})
export class PanZoomDirective {
   private readonly host = inject(ElementRef<HTMLElement>);
   private readonly changeDector = inject(ChangeDetectorRef);

   readonly panZoomKey = input<string | null | undefined>(undefined);

   readonly scale = signal(1);
   // panX/panY: the SVG's offset, in host pixels, from its centered position
   // 0 = centered.
   readonly panX = signal(0);
   readonly panY = signal(0);
   readonly dragging = signal(false);

   readonly cursorStyle = computed(() => {
      // Only show a grab cursor when there's actually something to
      // pan (scale > 1)
      if (this.scale() <= 1) {
         return 'default';
      }
      return this.dragging() ? 'grabbing' : 'grab';
   });

   private originalViewBox: { x: number; y: number; w: number; h: number } | null = null;
   private cachedSvg: SVGSVGElement | null = null;
   private downX = 0;
   private downY = 0;
   private lastX = 0;
   private lastY = 0;
   private movedFar = false;
   private activePointerId: number | null = null;

   constructor() {
      const destroyRef = inject(DestroyRef);
      destroyRef.onDestroy(() => this.releaseCapture());

      effect(() => {
         this.panZoomKey();
         untracked(() => {
            this.originalViewBox = null;
            this.cachedSvg = null;
            this.reset();
         });
      });

      // Resizing the host re-fits the SVG, which changes the pan limits, so
      // pull the current offset back inside the new bounds and redraw.
      if (typeof ResizeObserver !== 'undefined') {
         const observer = new ResizeObserver(() => this.clampPanToLimits());
         observer.observe(this.host.nativeElement);
         destroyRef.onDestroy(() => observer.disconnect());
      }
   }

   reset(): void {
      this.scale.set(1);
      this.panX.set(0);
      this.panY.set(0);
      this.applyViewBox();
   }

   zoomIn(): void {
      this.scaleAtCenter(BUTTON_STEP);
   }

   zoomOut(): void {
      this.scaleAtCenter(1 / BUTTON_STEP);
   }

   panBy(dx: number, dy: number): void {
      if (this.scale() <= 1) {
         return;
      }
      const { cw0, ch0 } = this.geometry();
      const scale = this.scale();
      this.panX.set(this.clampPan(this.panX() + dx, cw0, scale));
      this.panY.set(this.clampPan(this.panY() + dy, ch0, scale));
      this.applyViewBox();
   }

   private clampPanToLimits(): void {
      const { cw0, ch0 } = this.geometry();
      const scale = this.scale();
      this.panX.set(this.clampPan(this.panX(), cw0, scale));
      this.panY.set(this.clampPan(this.panY(), ch0, scale));
      this.applyViewBox();
   }

   wasDrag(): boolean {
      return this.movedFar;
   }

   focus(): void {
      this.host.nativeElement.focus({ preventScroll: true });
   }

   private getOrCacheOriginalViewBox(svg: SVGSVGElement): { x: number; y: number; w: number; h: number } | null {
      if (svg !== this.cachedSvg || !this.originalViewBox) {
         this.cachedSvg = svg;
         const base = svg.viewBox.baseVal;
         if (base && base.width > 0 && base.height > 0) {
            this.originalViewBox = { x: base.x, y: base.y, w: base.width, h: base.height };
         } else {
            this.originalViewBox = null;
         }
      }
      return this.originalViewBox;
   }

   // Host viewport size and the SVG content's size at scale 1 (fit with
   // letterbox margins on the narrower axis). Falls back to a host-filling
   // size until the SVG element is present.
   private geometry(): { ew: number; eh: number; cw0: number; ch0: number } {
      const rect = this.host.nativeElement.getBoundingClientRect();
      const ew = rect.width || 1;
      const eh = rect.height || 1;
      const svg = this.host.nativeElement.querySelector('svg') as SVGSVGElement | null;
      const orig = svg ? this.getOrCacheOriginalViewBox(svg) : null;
      if (!orig) {
         return { ew, eh, cw0: ew, ch0: eh };
      }
      const fit = Math.min(ew / orig.w, eh / orig.h);
      return { ew, eh, cw0: orig.w * fit, ch0: orig.h * fit };
   }

   // Max pan offset is half the SVG's overhang past its fit rectangle. 0 at
   // scale 1 (locked centered), growing linearly with scale.
   private clampPan(pan: number, fitSize: number, scale: number): number {
      const maxPan = (fitSize * (scale - 1)) / 2;
      return clamp(pan, -maxPan, maxPan);
   }

   private scaleAtCenter(factor: number): void {
      const rect = this.host.nativeElement.getBoundingClientRect();
      this.scaleAt(factor, rect.width / 2, rect.height / 2);
   }

   private scaleAt(factor: number, px: number, py: number): void {
      const oldScale = this.scale();
      const newScale = clamp(oldScale * factor, MIN_SCALE, MAX_SCALE);
      if (newScale === oldScale) {
         return;
      }
      const ratio = newScale / oldScale;
      const { ew, eh, cw0, ch0 } = this.geometry();

      // Current top-left of the SVG on screen (centered position + pan).
      const tx = (ew - cw0 * oldScale) / 2 + this.panX();
      const ty = (eh - ch0 * oldScale) / 2 + this.panY();

      // Clamp the cursor into the SVG's on-screen rect so a point in the
      // letterbox margin zooms toward the nearest SVG edge instead of empty space.
      const fx = clamp(px, Math.max(0, tx), Math.min(ew, tx + cw0 * oldScale));
      const fy = clamp(py, Math.max(0, ty), Math.min(eh, ty + ch0 * oldScale));

      // Keep that point fixed across the scale change, then re-express as a pan
      // offset under the new scale and clamp to the new limits.
      const txNew = fx - (fx - tx) * ratio;
      const tyNew = fy - (fy - ty) * ratio;
      this.scale.set(newScale);
      this.panX.set(this.clampPan(txNew - (ew - cw0 * newScale) / 2, cw0, newScale));
      this.panY.set(this.clampPan(tyNew - (eh - ch0 * newScale) / 2, ch0, newScale));
      this.applyViewBox();
   }

   @HostListener('wheel', ['$event'])
   onWheel(event: WheelEvent): void {
      event.preventDefault();
      const rect = this.host.nativeElement.getBoundingClientRect();
      const factor = event.deltaY < 0 ? WHEEL_STEP : 1 / WHEEL_STEP;
      this.scaleAt(factor, event.clientX - rect.left, event.clientY - rect.top);
   }

   @HostListener('pointerdown', ['$event'])
   onPointerDown(event: PointerEvent): void {
      if (event.button !== 0 && event.pointerType === 'mouse') {
         return;
      }
      // Intentionally not calling preventDefault or setPointerCapture.
      this.activePointerId = event.pointerId;
      this.dragging.set(true);
      this.downX = this.lastX = event.clientX;
      this.downY = this.lastY = event.clientY;
      this.movedFar = false;
      this.focus();
   }

   @HostListener('pointermove', ['$event'])
   onPointerMove(event: PointerEvent): void {
      if (!this.dragging() || event.pointerId !== this.activePointerId) {
         return;
      }
      const dx = event.clientX - this.lastX;
      const dy = event.clientY - this.lastY;
      this.lastX = event.clientX;
      this.lastY = event.clientY;
      if (!this.movedFar) {
         const totalDx = event.clientX - this.downX;
         const totalDy = event.clientY - this.downY;
         if (totalDx * totalDx + totalDy * totalDy > DRAG_PIXEL_THRESHOLD * DRAG_PIXEL_THRESHOLD) {
            this.movedFar = true;
            // Past the drag threshold - capture so subsequent moves are
            // tracked even after the pointer leaves the SVG content area.
            try {
               this.host.nativeElement.setPointerCapture(event.pointerId);
            } catch {
               /* element may already be released or detached */
            }
         }
      }
      this.panBy(dx, dy);
   }

   @HostListener('pointerup', ['$event'])
   @HostListener('pointercancel', ['$event'])
   @HostListener('pointerleave', ['$event'])
   onPointerUp(event: PointerEvent): void {
      if (event.pointerId !== this.activePointerId) {
         return;
      }
      this.releaseCapture();
   }

   @HostListener('dblclick', ['$event'])
   onDoubleClick(event: MouseEvent): void {
      event.preventDefault();
      const rect = this.host.nativeElement.getBoundingClientRect();
      this.scaleAt(BUTTON_STEP * BUTTON_STEP, event.clientX - rect.left, event.clientY - rect.top);
   }

   @HostListener('keydown', ['$event'])
   onKeyDown(event: KeyboardEvent): void {
      const step = event.shiftKey ? KEY_PAN_PX_FAST : KEY_PAN_PX;
      switch (event.key) {
         case '+':
         case '=':
            this.zoomIn();
            break;
         case '-':
         case '_':
            this.zoomOut();
            break;
         case '0':
         case 'Home':
            this.reset();
            break;
         case 'ArrowLeft':
            this.panBy(step, 0);
            break;
         case 'ArrowRight':
            this.panBy(-step, 0);
            break;
         case 'ArrowUp':
            this.panBy(0, step);
            break;
         case 'ArrowDown':
            this.panBy(0, -step);
            break;
         default:
            return;
      }
      event.preventDefault();
   }

   private releaseCapture(): void {
      if (this.activePointerId !== null) {
         try {
            this.host.nativeElement.releasePointerCapture(this.activePointerId);
         } catch {
            /* element already detached */
         }
      }
      this.activePointerId = null;
      this.dragging.set(false);
      this.changeDector.markForCheck();
   }

   private applyViewBox(): void {
      const svg = this.host.nativeElement.querySelector('svg') as SVGSVGElement | null;
      if (!svg) {
         return;
      }
      const orig = this.getOrCacheOriginalViewBox(svg);
      if (!orig) {
         return;
      }
      // Map the SVG's target screen rect back to a viewBox. The SVG viewBox
      // matches the host aspect ratio, so SVG meet adds no extra bars.
      const { ew, eh, cw0, ch0 } = this.geometry();
      const scale = this.scale();
      const tx = (ew - cw0 * scale) / 2 + this.panX();
      const ty = (eh - ch0 * scale) / 2 + this.panY();
      const pxPerUnit = (cw0 / orig.w) * scale;
      const vw = ew / pxPerUnit;
      const vh = eh / pxPerUnit;
      const vx = orig.x - tx / pxPerUnit;
      const vy = orig.y - ty / pxPerUnit;
      svg.setAttribute('viewBox', `${vx} ${vy} ${vw} ${vh}`);
   }
}

function clamp(value: number, lo: number, hi: number): number {
   return Math.max(lo, Math.min(hi, value));
}
