/* MIT License

Copyright (c) 2026 Brad Schick

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

import { Component, type OnDestroy, type OnInit } from '@angular/core';
import { AuthEvent, AuthenticatorService } from '../services/authenticator.service';
import { Router } from '@angular/router';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatCardModule } from '@angular/material/card';
import { Subscription } from 'rxjs';

@Component({
   selector: 'app-regenrecovery',
   templateUrl: './regenrecovery.component.html',
   styleUrl: './regenrecovery.component.scss',
   imports: [MatIconModule, MatButtonModule, MatProgressSpinnerModule, MatCardModule]
})
export class RegenrecoveryComponent implements OnInit, OnDestroy {

   public showProgress = false;
   public error = '';
   private _authSub!: Subscription;

   constructor(
      public authSvc: AuthenticatorService,
      private router: Router) {
   }

   ngOnInit() {
      this._authSub = this.authSvc.on(
         [AuthEvent.Logout],
         () => {
            this.error = '';
            this.router.navigateByUrl('/');
         }
      );
   }

   ngOnDestroy() {
      if (this._authSub) {
         this._authSub.unsubscribe();
      }
   }

   onClickGenerate() {
      this.showProgress = true;
      this.error = '';

      // changeRecoveryWords flips hasRecoveryId true, so capture which prior recovery
      // method is being replaced before calling it. Note that other navigators to
      // /showrecovery only set `replacedWords`
      const replacedLink = !this.authSvc.hasRecoveryId();
      const replacedWords = !replacedLink;

      this.authSvc.changeRecoveryWords().then(() => {
         this.router.navigateByUrl('/showrecovery', { state: { replacedLink, replacedWords } });
      }).catch((err) => {
         console.error(err);
         if (err instanceof Error && err.message.includes("fetch")) {
            this.error = 'Could not replace recovery words, check your connection and try again';
         } else {
            this.error = 'Could not replace recovery words, try again';
         }
      }).finally(
         () => this.showProgress = false
      );
   }
}
