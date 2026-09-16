import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { CoreComponent } from './core.component';
import { provideRouter } from '@angular/router';
import { provideHttpClient, withInterceptorsFromDi, withXhr } from '@angular/common/http';
import { routes } from '../qcrypt.routes';

describe('CoreComponent', () => {
   let component: CoreComponent;
   let fixture: ComponentFixture<CoreComponent>;

   beforeEach(async () => {
      await TestBed.configureTestingModule({
         imports: [CoreComponent],
         providers: [
            provideRouter(routes),
            provideHttpClient(withXhr(), withInterceptorsFromDi()),
            provideHttpClientTesting(),
         ],
      }).compileComponents();

      fixture = TestBed.createComponent(CoreComponent);
      component = fixture.componentInstance;
      fixture.detectChanges();
   });

   it('should create', () => {
      //    expect(true).toBeTruthy();
      expect(component).toBeTruthy();
   });

   it('keeps the clear and cipher text away from browser text assistance', () => {
      for (const id of ['#clearInput', '#cipherInput']) {
         const textArea = fixture.nativeElement.querySelector(id);
         expect(textArea.getAttribute('spellcheck')).toBe('false');
         expect(textArea.getAttribute('autocomplete')).toBe('off');
         expect(textArea.getAttribute('autocorrect')).toBe('off');
         expect(textArea.getAttribute('autocapitalize')).toBe('off');
      }
   });
});
