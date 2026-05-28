import { Component, signal } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { SvgInlineDirective } from './svg-inline.directive';

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
      fixture.detectChanges();
   });

   afterEach(() => httpController.verify());

   it('fetches the URL and inserts a <svg> child', () => {
      const req = httpController.expectOne('/test.svg');
      expect(req.request.responseType).toBe('text');
      req.flush(SAMPLE_SVG);

      const host: HTMLElement = fixture.nativeElement.querySelector('div');
      const svg = host.querySelector('svg');
      expect(svg).toBeTruthy();
      expect(svg?.getAttribute('viewBox')).toBe('0 0 100 100');
      expect(svg?.getAttribute('width')).toBe('100%');
      expect(svg?.getAttribute('height')).toBe('100%');
   });

   it('replaces the existing SVG when the URL changes', () => {
      httpController.expectOne('/test.svg').flush(SAMPLE_SVG);

      fixture.componentInstance.url.set('/other.svg');
      fixture.detectChanges();

      const req2 = httpController.expectOne('/other.svg');
      req2.flush(
         '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 50 50"></svg>',
      );

      const host: HTMLElement = fixture.nativeElement.querySelector('div');
      const svgs = host.querySelectorAll('svg');
      expect(svgs.length).toBe(1);
      expect(svgs[0].getAttribute('viewBox')).toBe('0 0 50 50');
   });
});
