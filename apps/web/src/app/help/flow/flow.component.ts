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
import { ChangeDetectionStrategy, Component, computed, effect, inject, signal, viewChild } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { toSignal } from '@angular/core/rxjs-interop';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatSnackBar } from '@angular/material/snack-bar';
import { CopyrightComponent } from '../../ui/copyright/copyright.component';
import { SubLabelComponent } from './sub-label/sub-label.component';
import { PanZoomDirective } from './pan-zoom/pan-zoom.directive';
import { SvgInlineDirective } from './svg-inline/svg-inline.directive';
import { FLOW_ANIM_MS, FLOW_MAX_DEPTH, FLOW_OVERVIEWS, FLOW_SUBSYSTEMS, FlowItem } from './flow.config';

interface BreadcrumbChip {
   label: string;
   queryParams: Record<string, string | null> | null;
}

function lookupSegment(segment: string, index: number): FlowItem | null {
   return index === 0 ? FLOW_OVERVIEWS[segment] ?? null : FLOW_SUBSYSTEMS[segment] ?? null;
}

@Component({
   selector: 'app-flow',
   changeDetection: ChangeDetectionStrategy.OnPush,
   templateUrl: './flow.component.html',
   styleUrl: './flow.component.scss',
   imports: [
      CopyrightComponent,
      SubLabelComponent,
      PanZoomDirective,
      SvgInlineDirective,
      MatIconModule,
      MatButtonModule,
      MatTooltipModule,
   ],
})
export class FlowComponent {
   private readonly route = inject(ActivatedRoute);
   private readonly router = inject(Router);
   private readonly snackBar = inject(MatSnackBar);

   private readonly params = toSignal(this.route.queryParamMap, { requireSync: true });

   readonly viewer = viewChild<PanZoomDirective>('viewer');

   readonly reducedMotion = signal(false);
   private zoomFromRect: DOMRect | null = null;

   readonly overviewEntries = Object.entries(FLOW_OVERVIEWS) as [string, FlowItem][];

   // Parses ?path=<seg0>,<seg1>,... and truncates to the longest valid prefix.
   readonly path = computed<string[]>(() => {
      const raw = this.params().get('path');
      if (!raw) {
         return [];
      }
      const segments = raw.split(',').filter(Boolean).slice(0, FLOW_MAX_DEPTH);
      const valid: string[] = [];
      for (let i = 0; i < segments.length; i++) {
         if (!lookupSegment(segments[i], i)) {
            break;
         }
         valid.push(segments[i]);
      }
      return valid;
   });

   readonly currentItem = computed<FlowItem | null>(() => {
      const p = this.path();
      if (p.length === 0) {
         return null;
      }
      return lookupSegment(p[p.length - 1], p.length - 1);
   });

   readonly mode = computed<'grid' | 'node'>(() => (this.path().length === 0 ? 'grid' : 'node'));

   readonly viewerKey = computed<string | null>(() => {
      const p = this.path();
      return p.length === 0 ? null : p.join(',');
   });

   readonly currentSvgUrl = computed<string | null>(() => this.currentItem()?.svg ?? null);

   readonly breadcrumbs = computed<BreadcrumbChip[]>(() => {
      const chips: BreadcrumbChip[] = [];
      const p = this.path();
      if (p.length === 0) {
         chips.push({ label: 'Overview', queryParams: null });
         return chips;
      }
      chips.push({ label: 'Overview', queryParams: { path: null } });
      for (let i = 0; i < p.length; i++) {
         const item = lookupSegment(p[i], i);
         if (!item) {
            continue;
         }
         const last = i === p.length - 1;
         chips.push({
            label: item.label,
            queryParams: last ? null : { path: p.slice(0, i + 1).join(',') },
         });
      }
      return chips;
   });

   constructor() {
      effect(() => {
         const viewer = this.viewer();
         if (viewer && this.mode() !== 'grid') {
            viewer.focus();
         }
      });

      if (typeof window !== 'undefined') {
         const query = window.matchMedia('(prefers-reduced-motion: reduce)');
         this.reducedMotion.set(query.matches);
         query.addEventListener('change', event => this.reducedMotion.set(event.matches));
      }
   }

   selectOverview(overviewId: string, event: Event): void {
      const sourceRect = (event.currentTarget as HTMLElement | null)?.getBoundingClientRect();
      if (sourceRect) {
         this.zoomFromRect = sourceRect;
      }
      this.navigateTo([overviewId]);
   }

   onCrumbClick(event: MouseEvent, queryParams: Record<string, string | null>): void {
      event.preventDefault();
      this.router.navigate([], {
         relativeTo: this.route,
         queryParams,
         queryParamsHandling: 'merge',
      });
   }

   onSvgLoaded(svg: SVGSVGElement): void {
      svg.querySelectorAll<SVGElement>('[data-target]').forEach(el => {
         const target = el.getAttribute('data-target');
         if (!target || !FLOW_SUBSYSTEMS[target]) {
            return;
         }
         el.setAttribute('tabindex', '0');
         el.setAttribute('role', 'link');
         el.setAttribute('aria-label', FLOW_SUBSYSTEMS[target].label);
         el.addEventListener('keydown', event => {
            if (event.key === 'Enter' || event.key === ' ') {
               event.preventDefault();
               event.stopPropagation();
               this.zoomFromRect = el.getBoundingClientRect();
               this.navigateTo([...this.path(), target]);
            }
         });
      });
      if (this.zoomFromRect) {
         this.playZoomIn(svg, this.zoomFromRect);
         this.zoomFromRect = null;
      }
   }

   onSvgClick(event: MouseEvent): void {
      if (this.viewer()?.wasDrag()) {
         return;
      }
      const hit = (event.target as Element | null)?.closest('[data-target]') as SVGElement | null;
      const target = hit?.getAttribute('data-target');
      if (target && FLOW_SUBSYSTEMS[target]) {
         this.zoomFromRect = hit!.getBoundingClientRect();
         this.navigateTo([...this.path(), target]);
      }
   }

   private navigateTo(segments: string[]): void {
      if (segments.length > FLOW_MAX_DEPTH) {
         this.snackBar.open('Maximum depth reached', '', { duration: 2000 });
         return;
      }
      const path = segments.length === 0 ? null : segments.join(',');
      this.router.navigate([], {
         relativeTo: this.route,
         queryParams: { path },
         queryParamsHandling: 'merge',
      });
   }

   private playZoomIn(svg: SVGSVGElement, source: DOMRect): void {
      if (this.reducedMotion() || typeof svg.animate !== 'function') {
         return;
      }
      const parent = svg.parentElement;
      if (!parent) {
         return;
      }
      const parentRect = parent.getBoundingClientRect();
      if (parentRect.width === 0 || parentRect.height === 0) {
         return;
      }
      const dx = source.left - parentRect.left;
      const dy = source.top - parentRect.top;
      const sx = source.width / parentRect.width;
      const sy = source.height / parentRect.height;
      svg.style.transformOrigin = '0 0';
      svg.style.transform = `translate(${dx}px, ${dy}px) scale(${sx}, ${sy})`;
      void svg.getBoundingClientRect();
      const animation = svg.animate(
         [
            { transform: `translate(${dx}px, ${dy}px) scale(${sx}, ${sy})` },
            { transform: 'translate(0, 0) scale(1, 1)' },
         ],
         { duration: FLOW_ANIM_MS, easing: 'cubic-bezier(0.22, 1, 0.36, 1)', fill: 'forwards' },
      );
      animation.finished.finally(() => {
         svg.style.transform = '';
         svg.style.transformOrigin = '';
      });
   }

   zoomIn(): void {
      this.viewer()?.zoomIn();
      this.viewer()?.focus();
   }

   zoomOut(): void {
      this.viewer()?.zoomOut();
      this.viewer()?.focus();
   }

   resetView(): void {
      this.viewer()?.reset();
      this.viewer()?.focus();
   }
}
