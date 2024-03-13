/* MIT License

Copyright (c) 2024 Brad Schick

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

import { Component, OnInit } from '@angular/core';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatToolbarModule } from '@angular/material/toolbar';
import { Router, RouterOutlet, RouterLink } from '@angular/router';
import { MatMenuModule } from '@angular/material/menu';
import { MatSidenav, MatSidenavModule } from '@angular/material/sidenav';
import { CredentialsComponent } from './credentials/credentials.component';
import { AuthenticatorService, AuthenticatorInfo } from './services/authenticator.service';


@Component({
   selector: 'qcrypt-root',
   standalone: true,
   templateUrl: './qcrypt.component.html',
   styleUrl: './qcrypt.component.scss',
   imports: [RouterOutlet, MatToolbarModule, MatIconModule, MatButtonModule,
      RouterLink, MatMenuModule, MatSidenavModule, CredentialsComponent
   ],
})
export class QCryptComponent implements OnInit {

   public bgColorDefault = '#4351AF';
   public bgColorFocus = '#3B479A';
   public countdown = 0;

   constructor(
      public router: Router,
      public authSvc: AuthenticatorService
   ) {
   }

   ngOnInit(): void {
      setInterval(() => this.countdown = this.authSvc.secondsRemaining(), 5000);
   }

   toggleNav(nav: MatSidenav) {
      if (this.authSvc.isAuthenticated()) {
         nav.toggle();
      } else {
         nav.close();
      }
   }

   focusColor(test?: string) {
      if (test) {
         return this.router.url.startsWith(test) ? this.bgColorFocus : this.bgColorDefault;
      } else {
         return ['', '/', undefined].includes(this.router.url) ? this.bgColorFocus : this.bgColorDefault;
      }
   }

   onOpenedCredentials() {
   }
}
