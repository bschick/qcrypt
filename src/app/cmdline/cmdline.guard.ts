import { CanActivateFn } from '@angular/router';
import { inject } from '@angular/core';
import { Router } from '@angular/router';
import { AuthenticatorService } from '../services/authenticator.service';

export const cmdlineGuard: CanActivateFn = (route, state) => {
   const authSvc = inject(AuthenticatorService);
   const router = inject(Router);

    if (authSvc.authenticated()) {
      return true;
   } else if(authSvc.validKnownUser()) {
      return router.parseUrl('/');
   }

   return router.parseUrl('/welcome');
};
