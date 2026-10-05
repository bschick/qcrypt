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

import { Component, DestroyRef, type OnDestroy, type OnInit, inject, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatSnackBar } from '@angular/material/snack-bar';
import { ClipboardModule } from '@angular/cdk/clipboard';
import { Router, RouterLink } from '@angular/router';
import { MatInputModule } from '@angular/material/input';
import { MatFormFieldModule } from '@angular/material/form-field';
import { AuthEvent, AuthenticatorService } from '../services/authenticator.service';
import { MatCardModule } from '@angular/material/card';
import { bytesToBase64 } from '@qcrypt/crypto';
import { RecoverySheetComponent } from '../ui/recoverysheet/recoverysheet.component';
import { NoAssistDirective } from '../ui/noassist.directive';

// Browsers name a "Save as PDF" print after the document title
const SHEET_TITLE = 'quick_crypt_account_recovery';

@Component({
   selector: 'app-show-recovery',
   templateUrl: './showrecovery.component.html',
   styleUrl: './showrecovery.component.scss',
   imports: [
      MatIconModule,
      MatButtonModule,
      ClipboardModule,
      RouterLink,
      MatInputModule,
      MatCardModule,
      MatFormFieldModule,
      RecoverySheetComponent,
      NoAssistDirective,
   ],
})
export class ShowRecoveryComponent implements OnInit, OnDestroy {
   protected readonly authSvc = inject(AuthenticatorService);
   private readonly _router = inject(Router);
   private readonly _snackBar = inject(MatSnackBar);

   protected readonly error = signal('');
   protected readonly replacedLink = signal(false);
   protected readonly replacedWords = signal(false);
   protected readonly unconfirmed = signal(false);
   protected readonly sheetUserCred = signal('');
   private readonly _destroyRef = inject(DestroyRef);
   private _priorTitle?: string;
   protected readonly recoveryWords = signal('');

   ngOnInit() {
      // True when these recovery words just replaced an old recovery link or
      // a previous set of recovery words.
      this.replacedLink.set(!!history.state?.replacedLink);
      this.replacedWords.set(!!history.state?.replacedWords);
      this.unconfirmed.set(!!history.state?.unconfirmed);

      this.authSvc
         .on([AuthEvent.Logout, AuthEvent.Forget])
         .pipe(takeUntilDestroyed(this._destroyRef))
         .subscribe(() => {
            this.error.set('');
            // Clear before navigating so the credential is not briefly visible during the transition
            this._clearSheet();
            this._router.navigateByUrl('/');
         });

      this.reloadData();
   }

   protected reloadData() {
      this.error.set('');

      if (this.authSvc.hasRecoveryWords()) {
         this.recoveryWords.set(this.authSvc.consumeRecoveryWords());
      } else {
         this._router.navigateByUrl('/regenrecovery');
      }
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

   protected toastMessage(msg: string) {
      this._snackBar.open(msg, '', {
         duration: 2000,
      });
   }

   protected onClickSaved() {
      // If the user previous didn't have a recoveryId, refresh the user
      // so the warning doesn't show. If the user refreshes the page without
      // clicking, keeping showing to warning to encourage saving
      if (!this.authSvc.hasRecoveryId()) {
         // let this happen async
         this.authSvc.refreshUserInfo().catch((err) => console.error(err));
      }
   }
}
