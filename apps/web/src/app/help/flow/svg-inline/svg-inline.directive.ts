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
import DOMPurify from 'dompurify';
import { bufferToBase64URLString } from '@qcrypt/crypto';
import { FLOW_SVG_HASHES } from '../flow.config';

@Directive({
   selector: '[svgInline]',
   host: { class: 'qc-inline-svg' },
})
export class SvgInlineDirective {
   private readonly _host = inject(ElementRef<HTMLElement>);
   private readonly _renderer = inject(Renderer2);
   private readonly _http = inject(HttpClient);
   private readonly _destroyRef = inject(DestroyRef);

   readonly svgInline = input.required<string>();
   readonly svgLoaded = output<SVGSVGElement>();

   constructor() {
      effect(() => {
         const url = this.svgInline();
         this._clearHost();
         this._http
            .get(url, { responseType: 'arraybuffer' })
            .pipe(takeUntilDestroyed(this._destroyRef))
            .subscribe({
               next: bytes => void this._verifyAndInsert(url, bytes),
               error: () => { /* same-origin static asset; failure is a deploy bug */ },
            });
      });
   }

   // Refuse any asset whose bytes don't match the build-time hash, then strip
   // active content before it reaches the DOM. Fails closed on any error.
   private async _verifyAndInsert(url: string, bytes: ArrayBuffer): Promise<void> {
      try {
         const expected = FLOW_SVG_HASHES[url];
         const digest = await crypto.subtle.digest('SHA-256', bytes);
         if (!expected || `sha256-${bufferToBase64URLString(digest)}` !== expected) {
            console.error(`flow: refusing SVG that failed its integrity check: ${url}`);
            return;
         }
         this._insertSvg(new TextDecoder().decode(bytes));
      } catch {
         console.error(`flow: integrity check could not run for ${url}`);
      }
   }

   private _clearHost(): void {
      const host = this._host.nativeElement;
      while (host.firstChild) {
         this._renderer.removeChild(host, host.firstChild);
      }
   }

   private _insertSvg(text: string): void {
      const fragment = DOMPurify.sanitize(text, {
         USE_PROFILES: { svg: true, svgFilters: true },
         ADD_TAGS: ['use'],
         ADD_ATTR: ['xlink:href'],
         RETURN_DOM_FRAGMENT: true,
      });
      fragment.querySelectorAll('use').forEach((use: SVGElement) => {
         const ref = use.getAttribute('xlink:href') ?? use.getAttribute('href') ?? '';
         if (!ref.trim().startsWith('#')) {
            use.remove();
         }
      });
      const root = fragment.querySelector('svg');
      if (!(root instanceof SVGSVGElement)) {
         return;
      }
      this._renderer.setAttribute(root, 'width', '100%');
      this._renderer.setAttribute(root, 'height', '100%');
      this._renderer.setAttribute(root, 'preserveAspectRatio', 'xMidYMid meet');
      this._renderer.setStyle(root, 'display', 'block');
      this._renderer.appendChild(this._host.nativeElement, root);
      this.svgLoaded.emit(root);
   }
}
