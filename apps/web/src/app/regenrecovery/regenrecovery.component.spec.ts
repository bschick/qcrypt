import { ComponentFixture, TestBed } from '@angular/core/testing';
import { NoopAnimationsModule } from '@angular/platform-browser/animations';
import { RegenrecoveryComponent } from './regenrecovery.component';
import { Router, RouterModule } from '@angular/router';
import { Subscription } from 'rxjs';
import { AuthenticatorService } from '../services/authenticator.service';

describe('RegenrecoveryComponent', () => {
   let component: RegenrecoveryComponent;
   let fixture: ComponentFixture<RegenrecoveryComponent>;
   let logoutHandler: () => void;

   // The route guard guarantees a session, so the component renders assuming one.
   const authStub = {
      hasSession: () => true,
      hasRecoveryId: () => false,
      on: (_events: unknown, action: () => void) => {
         logoutHandler = action;
         return new Subscription();
      },
   };

   beforeEach(async () => {
      await TestBed.configureTestingModule({
         imports: [RegenrecoveryComponent, RouterModule.forRoot([]), NoopAnimationsModule],
         providers: [{ provide: AuthenticatorService, useValue: authStub }]
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
      logoutHandler();
      expect(navSpy).toHaveBeenCalledWith('/');
   });
});
