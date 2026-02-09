import { ComponentFixture, TestBed } from '@angular/core/testing';
import { NoopAnimationsModule } from '@angular/platform-browser/animations';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { Recovery2Component } from './recovery2.component';
import { RouterModule } from '@angular/router';
import { provideHttpClient, withInterceptorsFromDi } from '@angular/common/http';

describe('RecoveryComponent', () => {
   let component: Recovery2Component;
   let fixture: ComponentFixture<Recovery2Component>;

   beforeEach(async () => {
      await TestBed.configureTestingModule({
         imports: [Recovery2Component, RouterModule.forRoot([]), NoopAnimationsModule],
         providers: [provideHttpClient(withInterceptorsFromDi()), provideHttpClientTesting()]
      }).compileComponents();

      fixture = TestBed.createComponent(Recovery2Component);
      component = fixture.componentInstance;
      fixture.detectChanges();
   });

   it('should create', () => {
      expect(component).toBeTruthy();
   });
});
