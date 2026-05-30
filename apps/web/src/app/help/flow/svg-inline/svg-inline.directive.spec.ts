import { Component, signal } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { bufferToBase64URLString } from '@qcrypt/crypto';
import { SvgInlineDirective } from './svg-inline.directive';
import { FLOW_SVG_HASHES } from '../flow.config';

@Component({
   standalone: true,
   imports: [SvgInlineDirective],
   template: `<div [svgInline]="url()"></div>`,
})
class HostComponent {
   readonly url = signal('/test.svg');
}

const SAMPLE_SVG =
   '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">' +
   '<rect width="100" height="100" fill="red"/></svg>';

// Records the hash the directive will expect, in the same format it computes,
// and returns the bytes to flush as the HTTP response.
async function registerHash(url: string, svg: string): Promise<ArrayBuffer> {
   const bytes = new TextEncoder().encode(svg);
   const digest = await crypto.subtle.digest('SHA-256', bytes);
   FLOW_SVG_HASHES[url] = 'sha256-' + bufferToBase64URLString(digest);
   return bytes.buffer;
}

// Let the directive's async verify-then-insert settle.
const settle = () => new Promise<void>(resolve => setTimeout(resolve, 0));

describe('SvgInlineDirective', () => {
   let fixture: ComponentFixture<HostComponent>;
   let httpController: HttpTestingController;

   beforeEach(async () => {
      await TestBed.configureTestingModule({
         imports: [HostComponent],
         providers: [provideHttpClient(), provideHttpClientTesting()],
      }).compileComponents();
      fixture = TestBed.createComponent(HostComponent);
      httpController = TestBed.inject(HttpTestingController);
   });

   afterEach(() => httpController.verify());

   it('verifies the hash, then inserts a <svg> child', async () => {
      const buf = await registerHash('/test.svg', SAMPLE_SVG);
      fixture.detectChanges();

      const req = httpController.expectOne('/test.svg');
      expect(req.request.responseType).toBe('arraybuffer');
      req.flush(buf);
      await settle();

      const host: HTMLElement = fixture.nativeElement.querySelector('div');
      const svg = host.querySelector('svg');
      expect(svg).toBeTruthy();
      expect(svg?.getAttribute('viewBox')).toBe('0 0 100 100');
      expect(svg?.getAttribute('width')).toBe('100%');
      expect(svg?.getAttribute('height')).toBe('100%');
   });

   it('replaces the existing SVG when the URL changes', async () => {
      const buf1 = await registerHash('/test.svg', SAMPLE_SVG);
      fixture.detectChanges();
      httpController.expectOne('/test.svg').flush(buf1);
      await settle();

      const buf2 = await registerHash(
         '/other.svg',
         '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 50 50"></svg>',
      );
      fixture.componentInstance.url.set('/other.svg');
      fixture.detectChanges();
      httpController.expectOne('/other.svg').flush(buf2);
      await settle();

      const host: HTMLElement = fixture.nativeElement.querySelector('div');
      const svgs = host.querySelectorAll('svg');
      expect(svgs.length).toBe(1);
      expect(svgs[0].getAttribute('viewBox')).toBe('0 0 50 50');
   });

   it('refuses to insert when the bytes do not match the recorded hash', async () => {
      await registerHash('/test.svg', SAMPLE_SVG);
      fixture.detectChanges();

      // Flush different bytes than were hashed.
      const tampered = new TextEncoder().encode(SAMPLE_SVG.replace('red', 'blue')).buffer;
      httpController.expectOne('/test.svg').flush(tampered);
      await settle();

      const host: HTMLElement = fixture.nativeElement.querySelector('div');
      expect(host.querySelector('svg')).toBeNull();
   });

   it('strips active content and external <use>, keeps internal use/defs/data-target', async () => {
      const dirty =
         '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 10 10">' +
         '<script>globalThis.__pwn = true;</script>' +
         '<defs><path id="g" d="M0 0h1v1H0z"/></defs>' +
         '<use xlink:href="http://evil.example/x.svg#a"/>' +
         '<use href="http://evil.example/y.svg#b"/>' +
         '<g class="qc-clickable" data-target="01" onclick="globalThis.__pwn = true">' +
         '<use xlink:href="#g"/></g></svg>';
      const buf = await registerHash('/danger.svg', dirty);
      fixture.componentInstance.url.set('/danger.svg');
      fixture.detectChanges();
      httpController.expectOne('/danger.svg').flush(buf);
      await settle();

      const svg: SVGSVGElement = fixture.nativeElement.querySelector('svg');
      expect(svg).toBeTruthy();
      expect(svg.querySelector('script')).toBeNull();
      expect(svg.querySelector('[onclick]')).toBeNull();

      // Custom tweak: <use> is re-allowed (DOMPurify drops it by default), but
      // only same-document (#id) refs. The one internal glyph survives with its
      // ref; both external <use> (xlink:href and plain href) are gone.
      const uses = svg.querySelectorAll('use');
      expect(uses.length).toBe(1);
      expect(uses[0].getAttribute('xlink:href') ?? uses[0].getAttribute('href')).toBe('#g');
      expect(svg.outerHTML).not.toContain('evil.example');
      expect(svg.querySelector('[data-target="01"]')).toBeTruthy();
   });

   it('removes a <script> element and an on* (script) attribute', async () => {
      const dirty =
         '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10">' +
         '<script>globalThis.__pwn = true;</script>' +
         '<rect width="10" height="10" onload="globalThis.__pwn = true"/>' +
         '</svg>';
      const buf = await registerHash('/script.svg', dirty);
      fixture.componentInstance.url.set('/script.svg');
      fixture.detectChanges();
      httpController.expectOne('/script.svg').flush(buf);
      await settle();

      const svg: SVGSVGElement = fixture.nativeElement.querySelector('svg');
      expect(svg).toBeTruthy();
      expect(svg.querySelector('script')).toBeNull();
      // The element survives but its event-handler attribute is gone.
      const rect = svg.querySelector('rect');
      expect(rect).toBeTruthy();
      expect(rect?.hasAttribute('onload')).toBe(false);
   });
});
