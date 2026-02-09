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
import { AuthenticatorService } from '../services/authenticator.service';
import { Router, RouterLink, ActivatedRoute } from '@angular/router';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatCardModule } from '@angular/material/card';
import { bytesToBase64 } from '../services/utils';

@Component({
   selector: 'app-recovery',
   templateUrl: './recovery.component.html',
   styleUrl: './recovery.component.scss',
   imports: [MatIconModule, MatButtonModule, RouterLink,
      MatProgressSpinnerModule, MatCardModule
   ]
})
export class RecoveryComponent implements OnInit {

   public validRecoveryLink = false;
   public error = '';
   public hasRecoveryWords = false;
   public ready = false;
   public showProgress = false;
   public authenticated = false;
   public selfRecovery = false;
   public currentUserName: string | null = null;
   private recoveryUserId: string | null = null;
   private recoverUserCred: string | null = null;

   constructor(
      private authSvc: AuthenticatorService,
      private router: Router,
      private activeRoute: ActivatedRoute) {
   }

   ngOnInit() {
      const [userId, userName] = this.authSvc.loadKnownUser();
      if (userId && userName) {
         this.currentUserName = userName;
      }

      this.showProgress = true;

      this.authSvc.ready.then( () => {
         this.authenticated = this.authSvc.authenticated();

         if (this.authenticated && this.authSvc.hasRecoveryId()) {
             this.router.navigateByUrl('/recovery2');
         } else {
            try {
               this.recoveryUserId = this.activeRoute.snapshot.queryParamMap.get('userid');
               this.recoverUserCred = this.activeRoute.snapshot.queryParamMap.get('usercred');
               if (!this.recoveryUserId || !this.recoverUserCred) {
                  throw new Error("recovery link missing userid or usercred: " + this.activeRoute.snapshot.toString());
               }
               this.validRecoveryLink = true;
               if (this.authenticated) {
                  this.selfRecovery = this.recoverUserCred === bytesToBase64(this.authSvc.userCred);
               }
            } catch (err) {
               console.error(err);
               this.error = 'Recovery link is invalid';
               this.validRecoveryLink = false;
            }
         }
      }).finally( () => {
         this.ready = true;
         this.showProgress = false;
      });

   }

   async onClickSignin(): Promise<void> {
      try {
         this.error = '';
         this.showProgress = true;
         await this.authSvc.defaultLogin();
         this.router.navigateByUrl('/');
      } catch (err) {
         console.error(err);
         if (err instanceof Error && err.message.includes("fetch")) {
            this.error = 'Sign in failed, check your connection';
         } else {
            this.error = 'Sign in failed, try again or change users';
         }
      } finally {
         this.showProgress = false;
      }
   }

   async onClickStartRecovery(event: any) {
      try {
         this.showProgress = true;
         await this.authSvc.recover(this.recoveryUserId!, this.recoverUserCred!);
         this.router.navigateByUrl('/');
      } catch (err) {
         if (err instanceof Error && err.message.includes('instead')) {
            this.error = 'You must user recovery words';
            this.hasRecoveryWords = true;
         } else {
            console.error(err);
            this.error = 'The operation was not allowed or timed out';
         }

      } finally {
         this.showProgress = false;
      }
   }
}
