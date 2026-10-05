import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { RecoveryComponent } from './recovery.component';
import { provideRouter } from '@angular/router';
import { provideHttpClient, withInterceptorsFromDi } from '@angular/common/http';
import { AuthenticatorService } from '../services/authenticator.service';
import { bytesToBase64, cryptoReady, getRandom } from '@qcrypt/crypto';
import * as cc from '@qcrypt/crypto/consts';

describe('RecoveryComponent', () => {
   let component: RecoveryComponent;
   let fixture: ComponentFixture<RecoveryComponent>;
   let getUserCred: () => Promise<Uint8Array>;
   let userId: string;
   let userCred: string;
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
            provideHttpClient(withInterceptorsFromDi()),
            provideHttpClientTesting(),
            { provide: AuthenticatorService, useValue: authStub },
         ],
      }).compileComponents();

      // Both link parameters are set, so the link is valid whatever the credential fetch returns
      createComponent({ userid: userId, usercred: userCred });
   });

   function createComponent(link: { userid?: string; usercred?: string }) {
      fixture = TestBed.createComponent(RecoveryComponent);
      component = fixture.componentInstance;
      for (const [name, value] of Object.entries(link)) {
         fixture.componentRef.setInput(name, value);
      }
      fixture.detectChanges();
   }

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
      createComponent({ userid: userId, usercred: userCred });

      await authStub.ready;
      await fixture.whenStable();

      // A failed credential fetch says nothing about the link, so it must stay usable
      // @ts-expect-error — asserting protected state
      expect(component.validRecoveryLink()).toBe(true);
      // @ts-expect-error — asserting protected state
      expect(component.error()).not.toBe('Recovery link is invalid');
   });

   it('rejects a link without a user credential', async () => {
      const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      createComponent({ userid: userId });

      await authStub.ready;
      await fixture.whenStable();
      errorSpy.mockRestore();

      // @ts-expect-error — asserting protected state
      expect(component.validRecoveryLink()).toBe(false);
      // @ts-expect-error — asserting protected state
      expect(component.error()).toBe('Recovery link is invalid');
   });
});
