import { ComponentFixture, TestBed } from '@angular/core/testing';
import { Protocol6Component } from './protocol6.component';
import { Protocol7Component } from './protocol7.component';
import { Protocol8Component } from './protocol8.component';
import { provideRouter } from '@angular/router';

describe('Protocol6Component', () => {
   let component: Protocol6Component;
   let fixture: ComponentFixture<Protocol6Component>;

   beforeEach(async () => {
      await TestBed.configureTestingModule({
         imports: [Protocol6Component],
         providers: [provideRouter([])],
      }).compileComponents();

      fixture = TestBed.createComponent(Protocol6Component);
      component = fixture.componentInstance;
      fixture.detectChanges();
   });

   it('should create', () => {
      expect(component).toBeTruthy();
   });
});

describe('Protocol7Component', () => {
   let component: Protocol7Component;
   let fixture: ComponentFixture<Protocol7Component>;

   beforeEach(async () => {
      await TestBed.configureTestingModule({
         imports: [Protocol7Component],
         providers: [provideRouter([])],
      }).compileComponents();

      fixture = TestBed.createComponent(Protocol7Component);
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
