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

import { Component, type OnInit, inject, ChangeDetectionStrategy, signal } from '@angular/core';
import { AuthenticatorService } from '../services/authenticator.service';
import { Router, RouterLink, ActivatedRoute } from '@angular/router';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatCardModule } from '@angular/material/card';
import { bytesToBase64 } from '@qcrypt/crypto';

@Component({
   selector: 'app-recovery',
   templateUrl: './recovery.component.html',
   styleUrl: './recovery.component.scss',
   changeDetection: ChangeDetectionStrategy.Eager,
   imports: [MatIconModule, MatButtonModule, RouterLink, MatProgressSpinnerModule, MatCardModule],
})
export class RecoveryComponent implements OnInit {
   protected readonly validRecoveryLink = signal(false);
   protected readonly error = signal('');
   protected readonly hasRecoveryWords = signal(false);
   protected readonly ready = signal(false);
   protected readonly showProgress = signal(false);
   protected readonly authenticated = signal(false);
   protected readonly selfRecovery = signal(false);
   protected readonly currentUserName = signal<string | null>(null);
   private _recoveryUserId: string | null = null;
   private _recoverUserCred: string | null = null;

   private readonly _authSvc = inject<AuthenticatorService>(AuthenticatorService);
   private readonly _router = inject<Router>(Router);
   private readonly _activeRoute = inject<ActivatedRoute>(ActivatedRoute);

   ngOnInit() {
      const [userId, userName] = this._authSvc.loadKnownUser();
      if (userId && userName) {
         this.currentUserName.set(userName);
      }

      this.showProgress.set(true);

      this._authSvc.ready
         .then(async () => {
            this.authenticated.set(this._authSvc.hasSession());

            if (this.authenticated() && this._authSvc.hasRecoveryId()) {
               this._router.navigateByUrl('/recovery3');
            } else {
               this._recoveryUserId = this._activeRoute.snapshot.queryParamMap.get('userid');
               this._recoverUserCred = this._activeRoute.snapshot.queryParamMap.get('usercred');

               if (this._recoveryUserId && this._recoverUserCred) {
                  this.validRecoveryLink.set(true);
               } else {
                  console.error(`recovery link missing userid or usercred: ${this._activeRoute.snapshot.toString()}`);
                  this.error.set('Recovery link is invalid');
                  this.validRecoveryLink.set(false);
               }

               // A failed credential read says nothing about the link, so it leaves validity alone
               if (this.validRecoveryLink() && this.authenticated()) {
                  try {
                     const userCred = await this._authSvc.getUserCred();
                     this.selfRecovery.set(this._recoverUserCred === bytesToBase64(userCred));
                     userCred.fill(0);
                  } catch (err) {
                     console.error(err);
                     this.error.set('Could not read your user credential, try again');
                  }
               }
            }
         })
         .finally(() => {
            this.ready.set(true);
            this.showProgress.set(false);
         });
   }

   protected async onClickSignin(): Promise<void> {
      try {
         this.error.set('');
         this.showProgress.set(true);
         await this._authSvc.createDefaultSession();
         this._router.navigateByUrl('/');
      } catch (err) {
         console.error(err);
         if (err instanceof Error && err.message.includes('fetch')) {
            this.error.set('Sign in failed, check your connection');
         } else {
            this.error.set('Sign in failed, try again or change users');
         }
      } finally {
         this.showProgress.set(false);
      }
   }

   protected async onClickStartRecovery(_event: MouseEvent) {
      try {
         this.showProgress.set(true);
         await this._authSvc.recover(this._recoveryUserId!, this._recoverUserCred!);
         this._recoverUserCred = null;
         this._recoveryUserId = null;
         this._router.navigateByUrl('/');
      } catch (err) {
         if (err instanceof Error && err.message.includes('instead')) {
            this.error.set('You must user recovery words');
            this.hasRecoveryWords.set(true);
         } else {
            console.error(err);
            this.error.set('The operation was not allowed or timed out');
         }
      } finally {
         this.showProgress.set(false);
      }
   }
}
