import { ComponentFixture, TestBed } from '@angular/core/testing';
import { NoopAnimationsModule } from '@angular/platform-browser/animations';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { WelcomeComponent } from './welcome.component';
import { RouterModule } from '@angular/router';
import { provideHttpClient, withInterceptorsFromDi } from '@angular/common/http';

describe('WelcomeComponent', () => {
   let component: WelcomeComponent;
   let fixture: ComponentFixture<WelcomeComponent>;

   beforeEach(async () => {
      await TestBed.configureTestingModule({
    imports: [WelcomeComponent, NoopAnimationsModule, RouterModule.forRoot([])],
    providers: [provideHttpClient(withInterceptorsFromDi()), provideHttpClientTesting()]
})
         .compileComponents();

      fixture = TestBed.createComponent(WelcomeComponent);
      component = fixture.componentInstance;
      fixture.detectChanges();
   });

   it('should create', () => {
      expect(component).toBeTruthy();
   });
});
