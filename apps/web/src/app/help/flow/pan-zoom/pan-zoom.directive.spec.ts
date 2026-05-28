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
      expect(directive.tx()).toBe(0);
      expect(directive.ty()).toBe(0);
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
      expect(directive.tx()).toBe(0);
      expect(directive.ty()).toBe(0);
   });

   it('panBy is bounded so the SVG edges cannot move past the host edges', () => {
      directive.zoomIn();
      const scale = directive.scale();
      // At scale s in a 400-wide host, tx range is [400*(1-s), 0].
      const minTx = 400 * (1 - scale);
      directive.panBy(-9999, -9999);
      expect(directive.tx()).toBe(minTx);
      directive.panBy(9999, 9999);
      expect(directive.tx()).toBe(0);
      expect(directive.ty()).toBe(0);
   });
});
