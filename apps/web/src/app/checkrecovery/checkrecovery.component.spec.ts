import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { CheckRecoveryComponent } from './checkrecovery.component';
import { provideRouter } from '@angular/router';
import { provideHttpClient, withInterceptorsFromDi, withXhr } from '@angular/common/http';

describe('CheckRecoveryComponent', () => {
   let component: CheckRecoveryComponent;
   let fixture: ComponentFixture<CheckRecoveryComponent>;

   beforeEach(async () => {
      await TestBed.configureTestingModule({
         imports: [CheckRecoveryComponent],
         providers: [
            provideRouter([]),
            provideHttpClient(withXhr(), withInterceptorsFromDi()),
            provideHttpClientTesting(),
         ],
      }).compileComponents();

      fixture = TestBed.createComponent(CheckRecoveryComponent);
      component = fixture.componentInstance;
      fixture.detectChanges();
   });

   it('should create', () => {
      expect(component).toBeTruthy();
   });

   it('keeps the recovery words away from browser text assistance', () => {
      const wordsArea = fixture.nativeElement.querySelector('#wordsArea');
      expect(wordsArea.getAttribute('spellcheck')).toBe('false');
      expect(wordsArea.getAttribute('autocomplete')).toBe('off');
      expect(wordsArea.getAttribute('autocorrect')).toBe('off');
      expect(wordsArea.getAttribute('autocapitalize')).toBe('off');
   });
});
