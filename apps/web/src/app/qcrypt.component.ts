/* MIT License

Copyright (c) 2025 Brad Schick

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE. */

import { Component, DestroyRef, type OnInit, ChangeDetectionStrategy, inject } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatToolbarModule } from '@angular/material/toolbar';
import { Router, RouterOutlet, RouterLink } from '@angular/router';
import { MatMenuModule } from '@angular/material/menu';
import { MatSidenav, MatSidenavModule } from '@angular/material/sidenav';
import { CredentialsComponent } from './credentials/credentials.component';
import { HaltedComponent } from './halted/halted.component';
import { AuthEvent, type AuthEventData, AuthenticatorService } from './services/authenticator.service';

@Component({
   selector: 'qcrypt-root',
   templateUrl: './qcrypt.component.html',
   styleUrl: './qcrypt.component.scss',
   changeDetection: ChangeDetectionStrategy.Eager,
   imports: [
      RouterOutlet,
      MatToolbarModule,
      MatIconModule,
      MatButtonModule,
      RouterLink,
      MatMenuModule,
      MatSidenavModule,
      CredentialsComponent,
      HaltedComponent,
   ],
})
export class QCryptComponent implements OnInit {
   private readonly _router = inject(Router);
   private readonly _authSvc = inject(AuthenticatorService);

   private readonly _destroyRef = inject(DestroyRef);
   public bgColorDefault = '';
   public bgColorFocus = 'color-mix(in srgb,var(--mat-sys-primary) 10%,transparent)';
   public showPKButton = false;

   ngOnInit(): void {
      this.showPKButton = this._authSvc.hasSession();
      this._authSvc
         .on([AuthEvent.Logout, AuthEvent.Login])
         .pipe(takeUntilDestroyed(this._destroyRef))
         .subscribe((data) => this.onAuthEvent(data));
   }

   onAuthEvent(data: AuthEventData) {
      this.showPKButton = data.event === AuthEvent.Login;
   }

   // Help stays readable so the user can look up what the halt means
   showHalted(): boolean {
      return this._authSvc.halted && !window.location.pathname.startsWith('/help');
   }

   toggleNav(nav: MatSidenav) {
      if (this._authSvc.hasSession()) {
         // Open with a mouse focus origin so the focus restored to this toggle when the
         // panel closes doesn't leave the keyboard-focus highlight on the button.
         nav.toggle(!nav.opened, 'mouse');
      } else {
         nav.close();
      }
   }

   focusColor(test?: string) {
      const location = window.location;
      if (test) {
         return location.pathname.startsWith(test) ? this.bgColorFocus : this.bgColorDefault;
      } else {
         return ['', '/newuser', '/welcome', '/', undefined].includes(location.pathname)
            ? this.bgColorFocus
            : this.bgColorDefault;
      }
   }

   isWelcomePage(): boolean {
      return this._router.url.startsWith('/welcome');
   }

   onOpenedCredentials() {}
}
