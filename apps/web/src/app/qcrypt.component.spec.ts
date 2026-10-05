import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { QCryptComponent } from './qcrypt.component';
import { AuthenticatorService } from './services/authenticator.service';

describe('QCryptComponent', () => {
   let component: QCryptComponent;
   let fixture: ComponentFixture<QCryptComponent>;
   let authSvc: AuthenticatorService;

   beforeEach(async () => {
      await TestBed.configureTestingModule({
         imports: [QCryptComponent],
         providers: [provideRouter([])],
      }).compileComponents();

      fixture = TestBed.createComponent(QCryptComponent);
      component = fixture.componentInstance;
      authSvc = TestBed.inject(AuthenticatorService);
      fixture.detectChanges();
   });

   it('should create', () => {
      expect(component).toBeTruthy();
   });

   // Creating an account in another tab clears this session and triggers the forgetUser flow
   it('hides the passkey button when the user is forgotten', () => {
      authSvc.forgetUser(false);
      fixture.detectChanges();

      const button: HTMLButtonElement = fixture.nativeElement.querySelector('button[aria-label="Passkey information"]');
      expect(button.style.visibility).toBe('hidden');
   });
});
