import { CanActivateFn } from '@angular/router';
import { inject } from '@angular/core';
import { Router } from '@angular/router';
import { AuthenticatorService } from '../services/authenticator.service';

export const showRecoveryGuard: CanActivateFn = (route, state) => {
   const authSvc = inject(AuthenticatorService);
   const router = inject(Router);

   // don't need to be authenticated because the page itself
   // does a passkey check regardless
   if (authSvc.isUserKnown()) {
      return true;
   }

   return router.parseUrl('/welcome');
};
