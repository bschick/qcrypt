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
import { ChangeDetectionStrategy, Component, computed, input } from '@angular/core';

export interface LabelSegment {
   text: string;
   sub: boolean;
}

export function parseSubscripts(text: string): LabelSegment[] {
   const out: LabelSegment[] = [];
   let buf = '';
   let i = 0;
   while (i < text.length) {
      if (text[i] === '_' && i + 1 < text.length && /[A-Za-z0-9]/.test(text[i + 1])) {
         if (buf) {
            out.push({ text: buf, sub: false });
            buf = '';
         }
         i++;
         let sub = '';
         while (i < text.length && /[A-Za-z0-9]/.test(text[i])) {
            sub += text[i++];
         }
         out.push({ text: sub, sub: true });
      } else {
         buf += text[i++];
      }
   }
   if (buf) {
      out.push({ text: buf, sub: false });
   }
   return out;
}

@Component({
   selector: 'sub-label',
   changeDetection: ChangeDetectionStrategy.OnPush,
   template:
      '@for (seg of segments(); track $index) {' +
      '@if (seg.sub) {<sub>{{ seg.text }}</sub>}' +
      '@else {<span>{{ seg.text }}</span>}' +
      '}',
   styles: `
      :host { white-space: nowrap; }
      sub {
         font-size: 0.72em;
         vertical-align: baseline;
         position: relative;
         top: 0.32em;
      }
   `,
})
export class SubLabelComponent {
   text = input.required<string>();
   segments = computed(() => parseSubscripts(this.text()));
}
