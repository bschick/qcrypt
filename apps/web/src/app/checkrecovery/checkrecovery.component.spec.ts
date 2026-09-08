import { ComponentFixture, TestBed } from '@angular/core/testing';
import { NoopAnimationsModule } from '@angular/platform-browser/animations';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { CheckRecoveryComponent } from './checkrecovery.component';
import { RouterModule } from '@angular/router';
import { provideHttpClient, withInterceptorsFromDi } from '@angular/common/http';

describe('CheckRecoveryComponent', () => {
   let component: CheckRecoveryComponent;
   let fixture: ComponentFixture<CheckRecoveryComponent>;

   beforeEach(async () => {
      await TestBed.configureTestingModule({
         imports: [CheckRecoveryComponent, RouterModule.forRoot([]), NoopAnimationsModule],
         providers: [provideHttpClient(withInterceptorsFromDi()), provideHttpClientTesting()],
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
