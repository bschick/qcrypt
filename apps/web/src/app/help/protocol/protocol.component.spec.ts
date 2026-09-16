import { ComponentFixture, TestBed } from '@angular/core/testing';
import { Protocol8Component, ProtocolComponent } from './protocol.component';
import { provideRouter } from '@angular/router';

describe('ProtocolComponent', () => {
   let component: ProtocolComponent;
   let fixture: ComponentFixture<ProtocolComponent>;

   beforeEach(async () => {
      await TestBed.configureTestingModule({
         imports: [ProtocolComponent],
         providers: [provideRouter([])],
      }).compileComponents();

      fixture = TestBed.createComponent(ProtocolComponent);
      component = fixture.componentInstance;
      fixture.detectChanges();
   });

   it('should create', () => {
      expect(component).toBeTruthy();
   });
});

describe('Protocol8Component', () => {
   let component: Protocol8Component;
   let fixture: ComponentFixture<Protocol8Component>;

   beforeEach(async () => {
      await TestBed.configureTestingModule({
         imports: [Protocol8Component],
         providers: [provideRouter([])],
      }).compileComponents();

      fixture = TestBed.createComponent(Protocol8Component);
      component = fixture.componentInstance;
      fixture.detectChanges();
   });

   it('should create', () => {
      expect(component).toBeTruthy();
   });
});
