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
import { FormControl, ReactiveFormsModule } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { Subscription } from 'rxjs';
import { bytesToBase64 } from '@qcrypt/crypto';
import { AuthEvent, AuthenticatorService, type RecoveryWordsState } from '../services/authenticator.service';
import { RecoverySheetComponent } from '../ui/recoverysheet/recoverysheet.component';

const SHEET_TITLE = 'quick_crypt_account_recovery';

@Component({
   selector: 'app-checkrecovery',
   templateUrl: './checkrecovery.component.html',
   styleUrl: './checkrecovery.component.scss',
   imports: [
      ReactiveFormsModule,
      RouterLink,
      MatButtonModule,
      MatCardModule,
      MatFormFieldModule,
      MatInputModule,
      MatProgressSpinnerModule,
      RecoverySheetComponent,
   ],
})
export class CheckRecoveryComponent implements OnInit, OnDestroy {
   public showProgress = false;
   public error = '';
   public result?: RecoveryWordsState;
   public sheetUserCred = '';
   public recoveryWords = new FormControl<string>('');
   private _authSub!: Subscription;
   private _priorTitle?: string;

   constructor(
      public authSvc: AuthenticatorService,
      private router: Router,
   ) {}

   ngOnInit() {
      this._authSub = this.authSvc.on([AuthEvent.Logout], () => {
         this.error = '';
         this.router.navigateByUrl('/');
      });
   }

   ngOnDestroy() {
      this.recoveryWords.setValue('');
      this._clearSheet();
      if (this._authSub) {
         this._authSub.unsubscribe();
      }
   }

   async onClickPrint(): Promise<void> {
      this.error = '';

      try {
         const userCred = await this.authSvc.getUserCred();
         try {
            this.sheetUserCred = bytesToBase64(userCred);
         } finally {
            userCred.fill(0);
         }
      } catch (err) {
         console.error(err);
         this.error = 'Could not build the backup sheet, try again';
      }

      if (this.sheetUserCred) {
         this._priorTitle = document.title;
         document.title = SHEET_TITLE;

         window.addEventListener('afterprint', this._clearSheet, { once: true });

         // Let the sheet render before the print dialog samples the page
         setTimeout(() => window.print(), 0);
      }
   }

   private _clearSheet = (): void => {
      this.sheetUserCred = '';
      if (this._priorTitle !== undefined) {
         document.title = this._priorTitle;
         this._priorTitle = undefined;
      }
      window.removeEventListener('afterprint', this._clearSheet);
   };

   onClickCheck() {
      this.error = '';
      this.result = undefined;
      const words = this.recoveryWords.value;

      if (words) {
         this.showProgress = true;
         this.authSvc
            .checkRecoveryWords(words)
            .then((state) => (this.result = state))
            .catch((err) => {
               console.error(err);
               this.error = 'Could not validate recovery words, check your connection and try again';
            })
            .finally(() => (this.showProgress = false));
      } else {
         this.error = 'Enter your recovery words to check them';
      }
   }
}
