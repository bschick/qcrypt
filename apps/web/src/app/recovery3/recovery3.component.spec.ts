import { ComponentFixture, TestBed } from '@angular/core/testing';
import { NoopAnimationsModule } from '@angular/platform-browser/animations';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { Recovery3Component } from './recovery3.component';
import { RouterModule } from '@angular/router';
import { provideHttpClient, withInterceptorsFromDi } from '@angular/common/http';

describe('RecoveryComponent', () => {
   let component: Recovery3Component;
   let fixture: ComponentFixture<Recovery3Component>;

   beforeEach(async () => {
      await TestBed.configureTestingModule({
         imports: [Recovery3Component, RouterModule.forRoot([]), NoopAnimationsModule],
         providers: [provideHttpClient(withInterceptorsFromDi()), provideHttpClientTesting()],
      }).compileComponents();

      fixture = TestBed.createComponent(Recovery3Component);
      component = fixture.componentInstance;
      fixture.detectChanges();
   });

   it('should create', () => {
      expect(component).toBeTruthy();
   });

   it('keeps the recovery words away from browser text assistance', () => {
      component.ready = true;
      fixture.detectChanges();

      const wordsArea = fixture.nativeElement.querySelector('#wordsArea');
      expect(wordsArea.getAttribute('spellcheck')).toBe('false');
      expect(wordsArea.getAttribute('autocomplete')).toBe('off');
      expect(wordsArea.getAttribute('autocorrect')).toBe('off');
      expect(wordsArea.getAttribute('autocapitalize')).toBe('off');
   });
});
