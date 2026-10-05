import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { CheckRecoveryComponent } from './checkrecovery.component';
import { Router, provideRouter } from '@angular/router';
import { provideHttpClient, withInterceptorsFromDi } from '@angular/common/http';
import { AuthenticatorService } from '../services/authenticator.service';

describe('CheckRecoveryComponent', () => {
   let component: CheckRecoveryComponent;
   let fixture: ComponentFixture<CheckRecoveryComponent>;

   beforeEach(async () => {
      await TestBed.configureTestingModule({
         imports: [CheckRecoveryComponent],
         providers: [provideRouter([]), provideHttpClient(withInterceptorsFromDi()), provideHttpClientTesting()],
      }).compileComponents();

      fixture = TestBed.createComponent(CheckRecoveryComponent);
      component = fixture.componentInstance;
      // hasSession must return true for the component to render its content
      vi.spyOn(TestBed.inject(AuthenticatorService), 'hasSession').mockReturnValue(true);
      fixture.detectChanges();
   });

   it('should create', () => {
      expect(component).toBeTruthy();
   });

   // Creating an account in another tab clears this session and triggers the forgetUser flow
   it('returns to the start when the user is forgotten', () => {
      const router = TestBed.inject(Router);
      const navSpy = vi.spyOn(router, 'navigateByUrl');
      const authSvc = TestBed.inject(AuthenticatorService);
      vi.spyOn(authSvc, 'hasSession').mockReturnValue(false);

      authSvc.forgetUser(false);

      expect(navSpy).toHaveBeenCalledWith('/');
   });

   it('renders nothing once the session ends', () => {
      vi.spyOn(TestBed.inject(AuthenticatorService), 'hasSession').mockReturnValue(false);
      const signedOut = TestBed.createComponent(CheckRecoveryComponent);
      signedOut.detectChanges();

      expect(signedOut.nativeElement.querySelector('#wordsArea')).toBeNull();
      expect(signedOut.nativeElement.textContent).not.toContain('Check Recovery Words');
   });

   it('keeps the recovery words away from browser text assistance', () => {
      const wordsArea = fixture.nativeElement.querySelector('#wordsArea');
      expect(wordsArea.getAttribute('spellcheck')).toBe('false');
      expect(wordsArea.getAttribute('autocomplete')).toBe('off');
      expect(wordsArea.getAttribute('autocorrect')).toBe('off');
      expect(wordsArea.getAttribute('autocapitalize')).toBe('off');
   });
});
