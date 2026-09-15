import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { WelcomeComponent } from './welcome.component';
import { RouterModule } from '@angular/router';
import { provideHttpClient, withInterceptorsFromDi, withXhr } from '@angular/common/http';

describe('WelcomeComponent', () => {
   let component: WelcomeComponent;
   let fixture: ComponentFixture<WelcomeComponent>;

   beforeEach(async () => {
      await TestBed.configureTestingModule({
         imports: [WelcomeComponent, RouterModule.forRoot([])],
         providers: [provideHttpClient(withXhr(), withInterceptorsFromDi()), provideHttpClientTesting()],
      }).compileComponents();

      fixture = TestBed.createComponent(WelcomeComponent);
      component = fixture.componentInstance;
      fixture.detectChanges();
   });

   it('should create', () => {
      expect(component).toBeTruthy();
   });
});
