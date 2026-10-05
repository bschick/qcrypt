import { ComponentFixture, TestBed } from '@angular/core/testing';
import { RegenrecoveryComponent } from './regenrecovery.component';
import { Router, provideRouter } from '@angular/router';
import { Subject, filter } from 'rxjs';
import { AuthEvent, type AuthEventData, AuthenticatorService } from '../services/authenticator.service';

describe('RegenrecoveryComponent', () => {
   let component: ComponentFixture<RegenrecoveryComponent>['componentInstance'];
   let fixture: ComponentFixture<RegenrecoveryComponent>;
   let authEvents: Subject<AuthEventData>;
   let signedIn: boolean;

   // signedIn decides whether the component renders any content at all
   const authStub = {
      hasSession: () => signedIn,
      hasRecoveryId: () => false,
      // Filters by event like the real service
      on: (events: AuthEvent[]) => authEvents.pipe(filter((data: AuthEventData) => events.includes(data.event))),
   };

   beforeEach(async () => {
      authEvents = new Subject<AuthEventData>();
      signedIn = true;
      await TestBed.configureTestingModule({
         imports: [RegenrecoveryComponent],
         providers: [provideRouter([]), { provide: AuthenticatorService, useValue: authStub }],
      }).compileComponents();

      fixture = TestBed.createComponent(RegenrecoveryComponent);
      component = fixture.componentInstance;
      fixture.detectChanges();
   });

   it('should create', () => {
      expect(component).toBeTruthy();
   });

   it('renders nothing once the session ends', () => {
      signedIn = false;
      const signedOut = TestBed.createComponent(RegenrecoveryComponent);
      signedOut.detectChanges();

      expect(signedOut.nativeElement.textContent).not.toContain('Replace Recovery Words');
   });

   it('returns to the start on logout so the sign-in dialog can show', () => {
      const router = TestBed.inject(Router);
      const navSpy = vi.spyOn(router, 'navigateByUrl');
      authEvents.next({ event: AuthEvent.Logout, userId: null, userName: null });
      expect(navSpy).toHaveBeenCalledWith('/');
   });

   // Another tab creating an account clears this session and reports Forget rather than Logout
   it('returns to the start when the user is forgotten', () => {
      const router = TestBed.inject(Router);
      const navSpy = vi.spyOn(router, 'navigateByUrl');
      authEvents.next({ event: AuthEvent.Forget, userId: null, userName: null });
      expect(navSpy).toHaveBeenCalledWith('/');
   });
});
