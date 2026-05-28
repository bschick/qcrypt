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
