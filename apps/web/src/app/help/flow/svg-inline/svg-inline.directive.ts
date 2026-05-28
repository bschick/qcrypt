import {
   DestroyRef,
   Directive,
   ElementRef,
   Renderer2,
   effect,
   inject,
   input,
   output,
} from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';

@Directive({
   selector: '[svgInline]',
})
export class SvgInlineDirective {
   private readonly host = inject(ElementRef<HTMLElement>);
   private readonly renderer = inject(Renderer2);
   private readonly http = inject(HttpClient);
   private readonly destroyRef = inject(DestroyRef);

   readonly svgInline = input.required<string>();
   readonly svgLoaded = output<SVGSVGElement>();

   constructor() {
      effect(() => {
         const url = this.svgInline();
         this.clearHost();
         this.http
            .get(url, { responseType: 'text' })
            .pipe(takeUntilDestroyed(this.destroyRef))
            .subscribe({
               next: text => this.insertSvg(text),
               error: () => { /* same-origin static asset; failure is a deploy bug */ },
            });
      });
   }

   private clearHost(): void {
      const host = this.host.nativeElement;
      while (host.firstChild) {
         this.renderer.removeChild(host, host.firstChild);
      }
   }

   private insertSvg(text: string): void {
      const parsed = new DOMParser().parseFromString(text, 'image/svg+xml');
      const root = parsed.documentElement;
      if (!(root instanceof SVGSVGElement)) {
         return;
      }
      this.renderer.setAttribute(root, 'width', '100%');
      this.renderer.setAttribute(root, 'height', '100%');
      this.renderer.setAttribute(root, 'preserveAspectRatio', 'xMidYMid meet');
      this.renderer.setStyle(root, 'display', 'block');
      this.injectInteractionStyles(root);
      this.renderer.appendChild(this.host.nativeElement, root);
      this.svgLoaded.emit(root);
   }

   private injectInteractionStyles(root: SVGSVGElement): void {
      // The SVG carries its own styling for clickable boxes. This keeps the
      // affordance self-contained (no Angular view-encapsulation gymnastics)
      // and means any SVG inlined through this directive - D2-generated today,
      // hand-crafted later - gets the same hover/focus behaviour from just
      // declaring class="qc-clickable" on its boxes.
      const style = document.createElementNS('http://www.w3.org/2000/svg', 'style');
      style.textContent = `
         .qc-clickable { cursor: pointer; }
         .qc-clickable,
         .qc-clickable rect,
         .qc-clickable path {
            transition: stroke 120ms ease, stroke-width 120ms ease;
         }
         .qc-clickable:hover,
         .qc-clickable:hover rect,
         .qc-clickable:hover path {
            stroke: #1a73e8;
            stroke-width: 3;
         }
         .qc-clickable:focus { outline: none; }
         .qc-clickable:focus-visible { outline: none; }
         /* Lucidchart renders text as <use> glyphs sibling to box paths; make
            them transparent to pointer events so clicks reach the box. */
         use { pointer-events: none; }
      `;
      this.renderer.insertBefore(root, style, root.firstChild);
   }
}
