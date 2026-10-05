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

import { Component, DestroyRef, type OnDestroy, type OnInit, inject, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { bytesToBase64 } from '@qcrypt/crypto';
import { AuthEvent, AuthenticatorService, type RecoveryWordsState } from '../services/authenticator.service';
import { RecoverySheetComponent } from '../ui/recoverysheet/recoverysheet.component';
import { NoAssistDirective } from '../ui/noassist.directive';

const SHEET_TITLE = 'quick_crypt_account_recovery';

@Component({
   selector: 'app-checkrecovery',
   templateUrl: './checkrecovery.component.html',
   styleUrl: './checkrecovery.component.scss',
   imports: [
      FormsModule,
      RouterLink,
      MatButtonModule,
      MatCardModule,
      MatFormFieldModule,
      MatInputModule,
      MatProgressSpinnerModule,
      RecoverySheetComponent,
      NoAssistDirective,
   ],
})
export class CheckRecoveryComponent implements OnInit, OnDestroy {
   protected readonly authSvc = inject(AuthenticatorService);
   private readonly _router = inject(Router);

   protected readonly showProgress = signal(false);
   protected readonly error = signal('');
   protected readonly result = signal<RecoveryWordsState | undefined>(undefined);
   protected readonly sheetUserCred = signal('');
   protected readonly recoveryWords = signal('');
   private readonly _destroyRef = inject(DestroyRef);
   private _priorTitle?: string;

   ngOnInit() {
      this.authSvc
         .on([AuthEvent.Logout, AuthEvent.Forget])
         .pipe(takeUntilDestroyed(this._destroyRef))
         .subscribe(() => {
            this.error.set('');
            // Clear before navigating so the credential is not briefly visible during the transition
            this._clearSheet();
            this._router.navigateByUrl('/');
         });
   }

   ngOnDestroy() {
      this.recoveryWords.set('');
      this._clearSheet();
   }

   protected async onClickPrint(): Promise<void> {
      this.error.set('');

      try {
         const userCred = await this.authSvc.getUserCred();
         try {
            this.sheetUserCred.set(bytesToBase64(userCred));
         } finally {
            userCred.fill(0);
         }
      } catch (err) {
         console.error(err);
         this.error.set('Could not build the backup sheet, try again');
      }

      if (this.sheetUserCred()) {
         this._priorTitle = document.title;
         document.title = SHEET_TITLE;

         window.addEventListener('afterprint', this._clearSheet, { once: true });

         // Let the sheet render before the print dialog samples the page
         setTimeout(() => window.print(), 0);
      }
   }

   private _clearSheet = (): void => {
      this.sheetUserCred.set('');
      if (this._priorTitle !== undefined) {
         document.title = this._priorTitle;
         this._priorTitle = undefined;
      }
      window.removeEventListener('afterprint', this._clearSheet);
   };

   protected onClickCheck() {
      this.error.set('');
      this.result.set(undefined);
      const words = this.recoveryWords();

      if (words) {
         this.showProgress.set(true);
         this.authSvc
            .checkRecoveryWords(words)
            .then((state) => this.result.set(state))
            .catch((err) => {
               console.error(err);
               this.error.set('Could not validate recovery words, check your connection and try again');
            })
            .finally(() => this.showProgress.set(false));
      } else {
         this.error.set('Enter your recovery words to check them');
      }
   }
}
