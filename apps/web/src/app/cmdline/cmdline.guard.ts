import type { CanActivateFn } from '@angular/router';
import { inject } from '@angular/core';
import { Router } from '@angular/router';
import { AuthenticatorService } from '../services/authenticator.service';

export const cmdlineGuard: CanActivateFn = async () => {
   const authSvc = inject<AuthenticatorService>(AuthenticatorService);
   const router = inject<Router>(Router);

   await authSvc.ready;
   if (authSvc.hasSession()) {
      return true;
   } else if(authSvc.validKnownUser()) {
      return router.parseUrl('/');
   }

   return router.parseUrl('/welcome');
};
