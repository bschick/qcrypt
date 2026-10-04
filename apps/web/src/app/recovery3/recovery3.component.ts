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

import { type AfterViewInit, Component, type OnDestroy, type OnInit, Renderer2, inject, signal } from '@angular/core';
import { AuthenticatorService, normalizeRecoveryWords } from '../services/authenticator.service';
import { Router, RouterLink } from '@angular/router';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { FormsModule } from '@angular/forms';
import { MatCardModule } from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { MAT_DIALOG_DATA, MatDialog, MatDialogModule } from '@angular/material/dialog';
import { firstValueFrom } from 'rxjs';
import { NoAssistDirective } from '../ui/noassist.directive';

@Component({
   selector: 'app-recovery3',
   templateUrl: './recovery3.component.html',
   styleUrl: './recovery3.component.scss',
   imports: [
      MatIconModule,
      MatButtonModule,
      RouterLink,
      FormsModule,
      MatProgressSpinnerModule,
      MatCardModule,
      MatFormFieldModule,
      MatInputModule,
      NoAssistDirective,
   ],
})
export class Recovery3Component implements OnInit, OnDestroy, AfterViewInit {
   private readonly _r2 = inject(Renderer2);
   private readonly _authSvc = inject(AuthenticatorService);
   private readonly _router = inject(Router);
   private readonly _dialog = inject(MatDialog);

   protected readonly error = signal('');
   protected readonly ready = signal(false);
   protected readonly showProgress = signal(false);
   protected readonly authenticated = signal(false);
   protected readonly currentUserName = signal<string | null>(null);
   protected readonly recoveryWords = signal('');

   ngOnInit() {
      const [userId, userName] = this._authSvc.loadKnownUser();
      if (userId && userName) {
         this.currentUserName.set(userName);
      }

      this.showProgress.set(true);

      this._authSvc.ready
         .then(() => {
            this.authenticated.set(this._authSvc.hasSession());
         })
         .finally(() => {
            this.ready.set(true);
            this.showProgress.set(false);
         });
   }

   ngAfterViewInit(): void {
      // Make this async to avoid ExpressionChangedAfterItHasBeenCheckedError errors
      setTimeout(() => {
         try {
            this._r2.selectRootElement('#wordsArea').focus();
         } catch (err) {
            console.error(err);
         }
      }, 0);
   }

   ngOnDestroy() {
      this.recoveryWords.set('');
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
         this.error.set('');
         const rawString = this.recoveryWords().trim();

         if (!rawString) {
            this.error.set('No recovery words were entered.');
         } else {
            const cleanedWords = normalizeRecoveryWords(rawString);
            if (!validateMnemonic(cleanedWords, wordlist)) {
               this.error.set('The recovery pattern contains incorrect words.');
            } else {
               const proceed = await this._checkProceed(cleanedWords);
               if (proceed) {
                  this.showProgress.set(true);
                  await this._authSvc.recover3(cleanedWords);
                  this._router.navigateByUrl('/');
               }
            }
         }
      } catch (err) {
         console.error(err);
         this.error.set('The operation was not allowed or timed out.');
      } finally {
         this.showProgress.set(false);
         if (this.error()) {
            this.error.update(
               (msg) =>
                  `${msg} Ensure you are using the recovery word pattern provided when you created your account, then try again.`,
            );
         }
      }
   }

   private async _checkProceed(recoveryWords: string): Promise<boolean> {
      const userId = this._authSvc.getRecoveryUserId(recoveryWords);
      if (!this._authSvc.hasSession() || userId === this._authSvc.userId) {
         return true;
      }

      const dialogRef = this._dialog.open(ConfirmDialog, {
         data: { userName: this._authSvc.userName },
      });
      return await firstValueFrom(dialogRef.afterClosed());
   }
}

export interface ConfirmData {
   userName: string;
}

@Component({
   selector: 'recovery-confirm-dialog',
   templateUrl: 'confirm-dialog.html',
   styleUrl: './recovery3.component.scss',
   imports: [MatDialogModule, MatIconModule, MatButtonModule],
})
export class ConfirmDialog {
   private readonly _data = inject<ConfirmData>(MAT_DIALOG_DATA);

   protected readonly currentUserName: string;

   constructor() {
      this.currentUserName = this._data.userName;
   }
}
