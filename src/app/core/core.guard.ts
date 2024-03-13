import { CanActivateFn } from '@angular/router';
import { inject } from '@angular/core';
import { Router } from '@angular/router';
import { AuthenticatorService } from '../services/authenticator.service';

export const coreGuard: CanActivateFn = (route, state) => {
   const authSvc = inject(AuthenticatorService);
   const router = inject(Router);

   if (authSvc.isUserKnown()) {
      return true;
   }

   return router.parseUrl('/welcome');
};
