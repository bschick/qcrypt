import { CanActivateFn } from '@angular/router';
import { inject } from '@angular/core';
import { Router } from '@angular/router';
import { AuthenticatorService } from '../services/authenticator.service';
import { HttpParams } from '@angular/common/http';

function paramsToQueryString(): string {
   const params = new HttpParams({ fromString: window.location.search });
   return params.toString() ? `?${params.toString()}` : '';
}

export const coreGuard: CanActivateFn = async (route, state) => {
   const authSvc = inject(AuthenticatorService);
   const router = inject(Router);

   await authSvc.ready;
   if (authSvc.validKnownUser()) {
      return true;
   }

   return router.parseUrl('/welcome' + paramsToQueryString());
};
