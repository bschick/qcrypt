import type { CanActivateFn } from '@angular/router';
import { inject } from '@angular/core';
import { Router } from '@angular/router';
import { AuthenticatorService } from '../services/authenticator.service';
import { HttpParams } from '@angular/common/http';

function paramsToQueryString(): string {
   const params = new HttpParams({ fromString: window.location.search });
   return params.toString() ? `?${params.toString()}` : '';
}

export const welcomeGuard: CanActivateFn = async () => {
   const authSvc = inject<AuthenticatorService>(AuthenticatorService);
   const router = inject<Router>(Router);

   await authSvc.ready;
   if (!authSvc.validKnownUser()) {
      return true;
   }

   return router.parseUrl('/' + paramsToQueryString());
};
