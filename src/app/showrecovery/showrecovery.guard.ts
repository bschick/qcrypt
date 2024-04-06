import { CanActivateFn } from '@angular/router';
import { inject } from '@angular/core';
import { Router } from '@angular/router';
import { AuthenticatorService } from '../services/authenticator.service';

export const showRecoveryGuard: CanActivateFn = (route, state) => {
   const authSvc = inject(AuthenticatorService);
   const router = inject(Router);

   if (authSvc.isAuthenticated()) {
      return true;
   } else if(authSvc.isUserKnown()) {
      return router.parseUrl('/');
   }

   return router.parseUrl('/welcome');
};
