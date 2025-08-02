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

import { Component, OnDestroy, OnInit } from '@angular/core';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatToolbarModule } from '@angular/material/toolbar';
import { Router, RouterOutlet, RouterLink } from '@angular/router';
import { MatMenuModule } from '@angular/material/menu';
import { MatSidenav, MatSidenavModule } from '@angular/material/sidenav';
import { CredentialsComponent } from './credentials/credentials.component';
import { AuthEvent, AuthEventData, AuthenticatorService } from './services/authenticator.service';
import { Subscription } from 'rxjs';


@Component({
    selector: 'qcrypt-root',
    templateUrl: './qcrypt.component.html',
    styleUrl: './qcrypt.component.scss',
    imports: [RouterOutlet, MatToolbarModule, MatIconModule, MatButtonModule,
        RouterLink, MatMenuModule, MatSidenavModule, CredentialsComponent
    ]
})
export class QCryptComponent implements OnInit, OnDestroy {

   private authSub!: Subscription;
   public bgColorDefault = '';
   public bgColorFocus = 'color-mix(in srgb,var(--mat-sys-primary) 10%,transparent)';
   public showPKButton = false;

   constructor(
      public router: Router,
      public authSvc: AuthenticatorService
   ) {
   }

   ngOnInit(): void {
      this.showPKButton = this.authSvc.authenticated();
      this.authSub = this.authSvc.on(
         [AuthEvent.Logout, AuthEvent.Login],
         this.onAuthEvent.bind(this)
      );
   }

   onAuthEvent(data: AuthEventData) {
      this.showPKButton = data.event === AuthEvent.Login;
   }

   ngOnDestroy(): void {
      if( this.authSub) {
         this.authSub.unsubscribe();
      }
   }

   toggleNav(nav: MatSidenav) {
      if (this.authSvc.authenticated()) {
         nav.toggle();
      } else {
         nav.close();
      }
   }

   focusColor(test?: string) {
      const location = window.location;
      if (test) {
         return location.pathname.startsWith(test) ? this.bgColorFocus : this.bgColorDefault;
      } else {
         return ['', '/newuser', '/welcome', '/', undefined].includes(location.pathname) ? this.bgColorFocus : this.bgColorDefault;
      }
   }

   onOpenedCredentials() {
   }
}
