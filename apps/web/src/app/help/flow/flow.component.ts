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
import { ChangeDetectionStrategy, Component, ElementRef, computed, effect, inject, signal, untracked, viewChild } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { toSignal } from '@angular/core/rxjs-interop';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatSnackBar } from '@angular/material/snack-bar';
import { MatTableModule, MatTableDataSource } from '@angular/material/table';
import { CopyrightComponent } from '../../ui/copyright/copyright.component';
import { SubLabelComponent } from './sub-label/sub-label.component';
import { PanZoomDirective } from './pan-zoom/pan-zoom.directive';
import { SvgInlineDirective } from './svg-inline/svg-inline.directive';
import { FLOW_ANIM_MS, FLOW_MAX_DEPTH, FLOW_OVERVIEWS, FLOW_SUBSYSTEMS, FlowItem } from './flow.config';

interface BreadcrumbChip {
   label: string;
   queryParams: Record<string, string | null> | null;
}

interface FlowSearchItem {
   key: string;
   label: string;
   tokens: string;
}

function lookupSegment(segment: string, index: number): FlowItem | null {
   return index === 0 ? FLOW_OVERVIEWS[segment] ?? null : FLOW_SUBSYSTEMS[segment] ?? null;
}

// Searchable tokens: words from the label, the svg filename split on '_', and
// the optional manual search keywords.
function searchTokens(sub: FlowItem): string {
   const file = sub.svg.slice(sub.svg.lastIndexOf('/') + 1).replace(/\.svg$/, '');
   const parts = [...sub.label.split(/\s+/), ...file.split('_')];
   if (sub.search) {
      parts.push(...sub.search.split(/\s+/));
   }
   return parts.join(' ').toLowerCase();
}

function flowSearchItems(overview: string): FlowSearchItem[] {
   const flow = FLOW_OVERVIEWS[overview];
   const items: FlowSearchItem[] = [{ key: overview, label: flow.label, tokens: searchTokens(flow) }];
   for (const key of flow.subsystems) {
      const sub = FLOW_SUBSYSTEMS[key];
      items.push({ key, label: sub.label, tokens: searchTokens(sub) });
   }
   return items;
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
      MatTableModule,
   ],
})
export class FlowComponent {
   private readonly _route = inject(ActivatedRoute);
   private readonly _router = inject(Router);
   private readonly _snackBar = inject(MatSnackBar);
   private readonly _params = toSignal(this._route.queryParamMap, { requireSync: true });
   readonly viewer = viewChild<PanZoomDirective>('viewer');
   readonly reducedMotion = signal(false);
   private _zoomFromRect: DOMRect | null = null;
   readonly overviewEntries = Object.entries(FLOW_OVERVIEWS) as [string, FlowItem][];

   readonly searchData = new MatTableDataSource<FlowSearchItem>([]);
   readonly searchColumns = ['label'];
   readonly searchTerm = signal('');
   readonly searchOpen = signal(false);
   readonly searchResultCount = signal(0);
   readonly searchActiveIndex = signal(-1);
   private readonly _searchPanel = viewChild<ElementRef<HTMLElement>>('searchPanel');

   // Parses ?path=<seg0>,<seg1>,... and truncates to the longest valid prefix.
   readonly path = computed<string[]>(() => {
      const raw = this._params().get('path');
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
      const path = this.path();
      if (path.length === 0) {
         return null;
      }
      return lookupSegment(path[path.length - 1], path.length - 1);
   });

   readonly mode = computed<'grid' | 'node'>(() => (this.path().length === 0 ? 'grid' : 'node'));

   readonly breadcrumbs = computed<BreadcrumbChip[]>(() => {
      const chips: BreadcrumbChip[] = [];
      const path = this.path();
      if (path.length === 0) {
         chips.push({ label: 'Overview', queryParams: null });
         return chips;
      }
      chips.push({ label: 'Overview', queryParams: { path: null } });
      for (let i = 0; i < path.length; i++) {
         const item = lookupSegment(path[i], i);
         if (!item) {
            continue;
         }
         const last = i === path.length - 1;
         chips.push({
            label: item.label,
            queryParams: last ? null : { path: path.slice(0, i + 1).join(',') },
         });
      }
      return chips;
   });

   constructor() {
      const origFilterPredicate = this.searchData.filterPredicate;
      this.searchData.filterPredicate = (item, filter) =>
         filter.split(',').some(part => {
            const term = part.trim();
            return term !== '' && origFilterPredicate(item, term);
         });

      const initialSearch = this._params().get('search');
      if (initialSearch) {
         this.searchTerm.set(initialSearch);
         this.searchOpen.set(true);
      }

      effect(() => {
         const overview = this.path()[0];
         untracked(() => {
            if (overview) {
               this.searchData.data = flowSearchItems(overview);
               this._applyFilter(this.searchTerm());
            } else {
               this.searchData.data = [];
               this._resetSearch();
            }
         });
      });

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
         this._zoomFromRect = sourceRect;
      }
      this._navigateTo([overviewId]);
   }

   onCrumbClick(event: MouseEvent, queryParams: Record<string, string | null>): void {
      event.preventDefault();
      this._router.navigate([], {
         relativeTo: this._route,
         queryParams,
         queryParamsHandling: 'merge',
      });
   }

   onSvgLoaded(svg: SVGSVGElement): void {
      svg.querySelectorAll<SVGElement>('[data-target]').forEach(elem => {
         const target = elem.getAttribute('data-target');
         if (!target || !FLOW_SUBSYSTEMS[target]) {
            return;
         }
         elem.setAttribute('tabindex', '0');
         elem.setAttribute('role', 'link');
         elem.setAttribute('aria-label', FLOW_SUBSYSTEMS[target].label);
         elem.addEventListener('keydown', event => {
            if (event.key === 'Enter' || event.key === ' ') {
               event.preventDefault();
               event.stopPropagation();
               this._zoomFromRect = elem.getBoundingClientRect();
               this._navigateTo([...this.path(), target]);
            }
         });
      });
      if (this._zoomFromRect) {
         this._playZoomIn(svg, this._zoomFromRect);
         this._zoomFromRect = null;
      }
   }

   onSvgClick(event: MouseEvent): void {
      if (this.viewer()?.wasDrag()) {
         return;
      }
      const hit = (event.target as Element | null)?.closest('[data-target]') as SVGElement | null;
      const target = hit?.getAttribute('data-target');
      if (target && FLOW_SUBSYSTEMS[target]) {
         this._zoomFromRect = hit!.getBoundingClientRect();
         this._navigateTo([...this.path(), target]);
      }
   }

   onSearchInput(value: string): void {
      this.searchTerm.set(value);
      this.searchActiveIndex.set(-1);
      this.searchOpen.set(value.trim() !== '');
      this._applyFilter(value);
   }

   onSearchFocus(): void {
      this.searchActiveIndex.set(-1);
      this.searchOpen.set(this.searchTerm().trim() !== '');
      this._applyFilter(this.searchTerm());
   }

   onSearchClick(): void {
      this.searchOpen.set(this.searchTerm().trim() !== '');
   }

   clearSearch(input: HTMLInputElement): void {
      this._resetSearch();
      input.focus();
   }

   onSearchBlur(): void {
      this.searchOpen.set(false);
   }

   onSearchKeydown(event: KeyboardEvent, input: HTMLInputElement): void {
      const count = this.searchData.filteredData.length;
      switch (event.key) {
         case 'ArrowDown':
            event.preventDefault();
            if (this.searchOpen() && count) {
               this._setActive(Math.min(this.searchActiveIndex() + 1, count - 1));
            }
            break;
         case 'ArrowUp':
            event.preventDefault();
            if (this.searchOpen() && count) {
               this._setActive(Math.max(this.searchActiveIndex() - 1, 0));
            }
            break;
         case 'Enter': {
            if (this.searchOpen() && count) {
               // Default to the first result unless one is chosen with the arrows.
               const index = this.searchActiveIndex() >= 0 ? this.searchActiveIndex() : 0;
               this.selectSearchResult(this.searchData.filteredData[index].key, event);
            }
            break;
         }
         case 'Escape':
            this.searchTerm.set('');
            this.searchActiveIndex.set(-1);
            this._applyFilter('');
            this.searchOpen.set(false);
            input.blur();
            break;
      }
   }

   selectSearchResult(key: string, event: Event): void {
      event.preventDefault();
      this.searchActiveIndex.set(-1);
      this.searchOpen.set(false);
      const path = this.path();
      if (key !== path[path.length - 1]) {
         this._navigateTo(FLOW_OVERVIEWS[key] ? [key] : [...path, key]);
      }
   }

   private _resetSearch(): void {
      this.searchTerm.set('');
      this.searchActiveIndex.set(-1);
      this.searchOpen.set(false);
      this._applyFilter('');
   }

   private _applyFilter(term: string): void {
      this.searchData.filter = term.trim().toLowerCase();
      this.searchResultCount.set(this.searchData.filteredData.length);
   }

   private _setActive(index: number): void {
      this.searchActiveIndex.set(index);
      const panel = this._searchPanel();
      if (panel) {
         const rows = panel.nativeElement.querySelectorAll<HTMLElement>('tr.flow-search-row');
         rows[index].scrollIntoView({ block: 'nearest' });
      }
   }

   private _navigateTo(segments: string[]): void {
      if (segments.length > FLOW_MAX_DEPTH) {
         this._snackBar.open('Maximum depth reached', '', { duration: 2000 });
         return;
      }
      const path = segments.length === 0 ? null : segments.join(',');
      this._router.navigate([], {
         relativeTo: this._route,
         queryParams: { path },
         queryParamsHandling: 'merge',
      });
   }

   private _playZoomIn(svg: SVGSVGElement, source: DOMRect): void {
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
