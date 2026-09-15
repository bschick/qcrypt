import { ComponentFixture, TestBed } from '@angular/core/testing';
import { OptionsComponent } from './options.component';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { RouterModule } from '@angular/router';
import { provideHttpClient, withInterceptorsFromDi, withXhr } from '@angular/common/http';

describe('OptionsComponent', () => {
   let component: OptionsComponent;
   let fixture: ComponentFixture<OptionsComponent>;

   beforeEach(async () => {
      await TestBed.configureTestingModule({
         imports: [OptionsComponent, RouterModule.forRoot([])],
         providers: [provideHttpClient(withXhr(), withInterceptorsFromDi()), provideHttpClientTesting()],
      }).compileComponents();

      fixture = TestBed.createComponent(OptionsComponent);
      component = fixture.componentInstance;
      fixture.detectChanges();
   });

   it('should create', () => {
      expect(component).toBeTruthy();
   });
});
