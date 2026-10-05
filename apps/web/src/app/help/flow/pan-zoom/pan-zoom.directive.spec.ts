import { Component, viewChild } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { PanZoomDirective } from './pan-zoom.directive';

@Component({
   standalone: true,
   imports: [PanZoomDirective],
   template: `<div panZoom #viewer="panZoom" style="width:400px;height:300px"><img alt="x" /></div>`,
})
class HostComponent {
   readonly viewer = viewChild.required<PanZoomDirective>('viewer');
}

describe('PanZoomDirective', () => {
   let fixture: ComponentFixture<HostComponent>;
   let directive: PanZoomDirective;

   beforeEach(async () => {
      await TestBed.configureTestingModule({ imports: [HostComponent] }).compileComponents();
      fixture = TestBed.createComponent(HostComponent);
      fixture.detectChanges();
      directive = fixture.componentInstance.viewer();
   });

   it('starts at identity transform', () => {
      expect(directive.scale()).toBe(1);
      expect(directive.panX()).toBe(0);
      expect(directive.panY()).toBe(0);
      expect(directive.dragging()).toBe(false);
   });

   it('zoomIn raises scale and zoomOut never goes below 1', () => {
      expect(directive.scale()).toBe(1);
      directive.zoomIn();
      expect(directive.scale()).toBeGreaterThan(1);
      directive.zoomOut();
      directive.zoomOut();
      expect(directive.scale()).toBe(1);
   });

   it('reset returns to identity', () => {
      directive.zoomIn();
      directive.panBy(-30, -20);
      directive.reset();
      expect(directive.scale()).toBe(1);
      expect(directive.panX()).toBe(0);
      expect(directive.panY()).toBe(0);
   });

   it('panBy is bounded by the max pan at the current zoom', () => {
      directive.zoomIn();
      const scale = directive.scale();
      // No <svg> present, so the SVG fills the 400x300 host at scale 1; max pan
      // is then half the overhang past the fit rectangle: size * (scale - 1) / 2.
      const maxPanX = (400 * (scale - 1)) / 2;
      const maxPanY = (300 * (scale - 1)) / 2;

      directive.panBy(-9999, -9999);
      expect(directive.panX()).toBe(-maxPanX);
      expect(directive.panY()).toBe(-maxPanY);

      directive.panBy(9999, 9999);
      expect(directive.panX()).toBe(maxPanX);
      expect(directive.panY()).toBe(maxPanY);
   });
});
