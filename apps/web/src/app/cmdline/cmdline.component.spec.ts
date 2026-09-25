import { ComponentFixture, TestBed } from '@angular/core/testing';
import { CmdLineComponent } from './cmdline.component';
import { Router, provideRouter } from '@angular/router';
import { AuthenticatorService } from '../services/authenticator.service';

describe('CmdLineComponent', () => {
   let component: CmdLineComponent;
   let fixture: ComponentFixture<CmdLineComponent>;

   beforeEach(async () => {
      await TestBed.configureTestingModule({
         imports: [CmdLineComponent],
         providers: [provideRouter([])],
      }).compileComponents();

      fixture = TestBed.createComponent(CmdLineComponent);
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
      const signedOut = TestBed.createComponent(CmdLineComponent);
      signedOut.detectChanges();

      expect(signedOut.nativeElement.querySelector('#credential')).toBeNull();
   });

   it('keeps the user credential away from browser text assistance', () => {
      // @ts-expect-error — exercising protected state to render the credential field
      component.showProgress.set(false);
      // @ts-expect-error — exercising protected state to render the credential field
      component.error.set('');
      fixture.detectChanges();

      const credential = fixture.nativeElement.querySelector('#credential');
      expect(credential.getAttribute('spellcheck')).toBe('false');
      expect(credential.getAttribute('autocomplete')).toBe('off');
      expect(credential.getAttribute('autocorrect')).toBe('off');
      expect(credential.getAttribute('autocapitalize')).toBe('off');
   });
});
