import { ComponentFixture, TestBed } from '@angular/core/testing';
import { RegenrecoveryComponent } from './regenrecovery.component';
import { Router, provideRouter } from '@angular/router';
import { Subject } from 'rxjs';
import { AuthEvent, type AuthEventData, AuthenticatorService } from '../services/authenticator.service';

describe('RegenrecoveryComponent', () => {
   let component: ComponentFixture<RegenrecoveryComponent>['componentInstance'];
   let fixture: ComponentFixture<RegenrecoveryComponent>;
   let authEvents: Subject<AuthEventData>;

   // The route guard guarantees a session, so the component renders assuming one.
   const authStub = {
      hasSession: () => true,
      hasRecoveryId: () => false,
      on: () => authEvents,
   };

   beforeEach(async () => {
      authEvents = new Subject<AuthEventData>();
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

   it('returns to the start on logout so the sign-in dialog can show', () => {
      const router = TestBed.inject(Router);
      const navSpy = vi.spyOn(router, 'navigateByUrl');
      authEvents.next({ event: AuthEvent.Logout, userId: null, userName: null });
      expect(navSpy).toHaveBeenCalledWith('/');
   });
});
