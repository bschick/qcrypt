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

interface ViewBoxRect {
   x: number;
   y: number;
   w: number;
   h: number;
}

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
   private readonly cdr = inject(ChangeDetectorRef);

   readonly panZoomKey = input<string | null | undefined>(undefined);

   readonly scale = signal(1);
   readonly tx = signal(0);
   readonly ty = signal(0);
   readonly dragging = signal(false);

   readonly cursorStyle = computed(() => {
      // Only show a grab/grabbing cursor when there's actually something to
      // pan (scale > 1). At scale 1 the SVG fits the host exactly, so a grab
      // hand would be misleading.
      if (this.scale() <= 1) {
         return 'default';
      }
      return this.dragging() ? 'grabbing' : 'grab';
   });

   private originalViewBox: ViewBoxRect | null = null;
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
            this.scale.set(1);
            this.tx.set(0);
            this.ty.set(0);
            this.applyViewBox();
         });
      });
   }

   reset(): void {
      this.scale.set(1);
      this.tx.set(0);
      this.ty.set(0);
      this.applyViewBox();
   }

   zoomIn(): void {
      this.scaleAtCenter(BUTTON_STEP);
   }

   zoomOut(): void {
      this.scaleAtCenter(1 / BUTTON_STEP);
   }

   panBy(dx: number, dy: number): void {
      this.tx.set(this.clampTx(this.tx() + dx));
      this.ty.set(this.clampTy(this.ty() + dy));
      this.applyViewBox();
   }

   wasDrag(): boolean {
      return this.movedFar;
   }

   focus(): void {
      this.host.nativeElement.focus({ preventScroll: true });
   }

   private clampTx(value: number): number {
      const width = this.host.nativeElement.getBoundingClientRect().width;
      if (width === 0) {
         return value;
      }
      // SVG edges must stay at or outside host edges.
      // At scale s the rendered content is host_width * s wide.
      // tx ∈ [width * (1 - s), 0]
      const min = width * (1 - this.scale());
      return Math.max(min, Math.min(0, value));
   }

   private clampTy(value: number): number {
      const height = this.host.nativeElement.getBoundingClientRect().height;
      if (height === 0) {
         return value;
      }
      const min = height * (1 - this.scale());
      return Math.max(min, Math.min(0, value));
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
      this.scale.set(newScale);
      this.tx.set(this.clampTx(px - (px - this.tx()) * ratio));
      this.ty.set(this.clampTy(py - (py - this.ty()) * ratio));
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
      // Intentionally NOT calling preventDefault and NOT calling
      // setPointerCapture here. Capturing on pointerdown re-routes the
      // synthesized click to the capture target (the host div), preventing
      // subprocess clicks from reaching their <g data-target="..."> element.
      // We capture lazily in onPointerMove once the user has actually moved
      // past the drag threshold; pure clicks therefore never trigger capture.
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
      this.cdr.markForCheck();
   }

   private applyViewBox(): void {
      const svg = this.host.nativeElement.querySelector('svg') as SVGSVGElement | null;
      if (!svg) {
         return;
      }
      if (svg !== this.cachedSvg) {
         this.cachedSvg = svg;
         this.originalViewBox = readViewBox(svg);
      }
      const orig = this.originalViewBox;
      if (!orig) {
         return;
      }
      const rect = this.host.nativeElement.getBoundingClientRect();
      const ew = rect.width || 1;
      const eh = rect.height || 1;
      const scale = this.scale();
      const vw = orig.w / scale;
      const vh = orig.h / scale;
      const vx = orig.x - (this.tx() * vw) / ew;
      const vy = orig.y - (this.ty() * vh) / eh;
      svg.setAttribute('viewBox', `${vx} ${vy} ${vw} ${vh}`);
   }
}

function clamp(value: number, lo: number, hi: number): number {
   return Math.max(lo, Math.min(hi, value));
}

function readViewBox(svg: SVGSVGElement): ViewBoxRect | null {
   const attr = svg.getAttribute('viewBox');
   if (attr) {
      const parts = attr.split(/[\s,]+/).map(Number);
      if (parts.length === 4 && parts.every(n => Number.isFinite(n))) {
         return { x: parts[0], y: parts[1], w: parts[2], h: parts[3] };
      }
   }
   const w = svg.clientWidth;
   const h = svg.clientHeight;
   if (w > 0 && h > 0) {
      return { x: 0, y: 0, w, h };
   }
   return null;
}
