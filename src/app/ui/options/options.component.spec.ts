import { ComponentFixture, TestBed } from '@angular/core/testing';
import { OptionsComponent } from './options.component';
import { NoopAnimationsModule } from '@angular/platform-browser/animations';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { RouterModule } from '@angular/router';
import { provideHttpClient, withInterceptorsFromDi } from '@angular/common/http';


describe('OptionsComponent', () => {
   let component: OptionsComponent;
   let fixture: ComponentFixture<OptionsComponent>;

   beforeEach(async () => {
      await TestBed.configureTestingModule({
         imports: [OptionsComponent, RouterModule.forRoot([]), NoopAnimationsModule],
         providers: [provideHttpClient(withInterceptorsFromDi()), provideHttpClientTesting()]
      }).compileComponents();

      fixture = TestBed.createComponent(OptionsComponent);
      component = fixture.componentInstance;
      fixture.detectChanges();
   });

   it('should create', () => {
      expect(component).toBeTruthy();
   });
});
