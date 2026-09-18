import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { RecoveryComponent } from './recovery.component';
import { ActivatedRoute, provideRouter } from '@angular/router';
import { provideHttpClient, withInterceptorsFromDi, withXhr } from '@angular/common/http';
import { AuthenticatorService } from '../services/authenticator.service';
import { bytesToBase64, cryptoReady, getRandom } from '@qcrypt/crypto';
import * as cc from '@qcrypt/crypto/consts';

describe('RecoveryComponent', () => {
   let component: RecoveryComponent;
   let fixture: ComponentFixture<RecoveryComponent>;
   let getUserCred: () => Promise<Uint8Array>;
   let userId: string;
   let userCred: string;
   let routeStub: { snapshot: { queryParamMap: Map<string, string>; toString: () => string } };
   let authStub: {
      ready: Promise<void>;
      loadKnownUser: () => string[];
      hasSession: () => boolean;
      hasRecoveryId: () => boolean;
      getUserCred: () => Promise<Uint8Array>;
   };

   beforeEach(async () => {
      await cryptoReady();

      userId = bytesToBase64(getRandom(cc.USERID_BYTES));
      userCred = bytesToBase64(getRandom(cc.USERCRED_BYTES));
      getUserCred = () => Promise.resolve(getRandom(cc.USERCRED_BYTES));

      // A link carrying both parameters is well formed, whatever the credential fetch later does
      routeStub = {
         snapshot: {
            queryParamMap: new Map([
               ['userid', userId],
               ['usercred', userCred],
            ]),
            toString: () => `/recovery?userid=${userId}&usercred=${userCred}`,
         },
      };

      authStub = {
         ready: Promise.resolve(),
         loadKnownUser: () => [userId, 'test-user'],
         hasSession: () => true,
         hasRecoveryId: () => false,
         getUserCred: () => getUserCred(),
      };

      await TestBed.configureTestingModule({
         imports: [RecoveryComponent],
         providers: [
            provideRouter([]),
            provideHttpClient(withXhr(), withInterceptorsFromDi()),
            provideHttpClientTesting(),
            { provide: AuthenticatorService, useValue: authStub },
            { provide: ActivatedRoute, useValue: routeStub },
         ],
      }).compileComponents();

      fixture = TestBed.createComponent(RecoveryComponent);
      component = fixture.componentInstance;
      fixture.detectChanges();
   });

   it('should create', () => {
      expect(component).toBeTruthy();
   });

   it('accepts a link carrying both parameters', async () => {
      await authStub.ready;
      await fixture.whenStable();

      // @ts-expect-error — asserting protected state
      expect(component.validRecoveryLink()).toBe(true);
      // @ts-expect-error — asserting protected state
      expect(component.error()).toBe('');
   });

   it('keeps the link valid when the credential fetch fails', async () => {
      getUserCred = () => Promise.reject(new Error('passkey prompt dismissed'));

      fixture = TestBed.createComponent(RecoveryComponent);
      component = fixture.componentInstance;
      fixture.detectChanges();

      await authStub.ready;
      await fixture.whenStable();

      // A failed credential fetch says nothing about the link, so it must stay usable
      // @ts-expect-error — asserting protected state
      expect(component.validRecoveryLink()).toBe(true);
      // @ts-expect-error — asserting protected state
      expect(component.error()).not.toBe('Recovery link is invalid');
   });
});
