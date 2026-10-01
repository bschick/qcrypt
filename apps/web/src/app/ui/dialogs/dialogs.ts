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
import {
   Component,
   Renderer2,
   ViewEncapsulation,
   type AfterViewInit,
   type OnDestroy,
   ChangeDetectionStrategy,
   inject,
   signal,
   viewChild,
} from '@angular/core';
import { MAT_DIALOG_DATA, MatDialogRef, MatDialogModule } from '@angular/material/dialog';

import { MatTooltipModule } from '@angular/material/tooltip';
import { FormsModule } from '@angular/forms';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatInputModule } from '@angular/material/input';
import { MatFormFieldModule } from '@angular/material/form-field';
import { Router } from '@angular/router';
import { type AcceptableState, StrengthMeterComponent } from '../strengthmeter/strengthmeter.component';
import { AuthenticatorService } from '../../services/authenticator.service';
import { BubbleDirective } from '../bubble/bubble.directive';
import { NoAssistDirective } from '../noassist.directive';
import * as cc from '@qcrypt/crypto/consts';
import { Ciphers } from '@qcrypt/crypto';
import type { CipherDataInfo } from '../../services/cipher.service';

const PWD_CLOSE_TIMEOUT = 1000 * 60 * 5;

export type PwdDialogData = {
   message: string;
   hint: string;
   encrypting: boolean;
   minStrength: number;
   hidePwd: boolean;
   loopCount: number;
   loops: number;
   checkPwned: boolean;
   welcomed: boolean;
   userName: string;
   cipherMode: string;
   usedPasswords: string[];
};

const NAMES = ['terrible', 'weak', 'decent', 'good', 'strong'];

@Component({
   selector: 'password.dialog',
   templateUrl: './password.dialog.html',
   styleUrl: './dialogs.scss',
   encapsulation: ViewEncapsulation.None, // Needed to change styles of strength meter
   changeDetection: ChangeDetectionStrategy.Eager,
   imports: [
      MatDialogModule,
      MatFormFieldModule,
      MatInputModule,
      MatIconModule,
      StrengthMeterComponent,
      FormsModule,
      MatTooltipModule,
      MatButtonModule,
      BubbleDirective,
      NoAssistDirective,
   ],
})
export class PasswordDialog implements AfterViewInit, OnDestroy {
   private readonly _r2 = inject(Renderer2);
   private readonly _dialogRef = inject<MatDialogRef<PasswordDialog>>(MatDialogRef);
   private readonly _data = inject<PwdDialogData>(MAT_DIALOG_DATA);

   protected readonly hidePwd = signal(this._data.hidePwd);
   protected readonly passwd = signal('');
   protected readonly hint = signal(this._data.hint);
   protected readonly strengthPhrase = signal('Password is empty');
   protected readonly strengthAlert = signal(false);
   protected readonly cipherShow = signal(false);

   protected readonly minStrength = this._data.minStrength;
   protected readonly loopCount = this._data.loopCount;
   protected readonly loops = this._data.loops;
   protected readonly encrypting = this._data.encrypting;
   protected readonly userName = this._data.userName;
   protected readonly cipherMode = this._data.cipherMode;
   protected readonly checkPwned = this._data.checkPwned;
   protected readonly usedPasswords = this._data.usedPasswords;
   protected readonly maxHintLen = cc.HINT_MAX_LEN;

   private readonly _welcomed = this._data.welcomed;
   private _timerId = -1;
   private _acceptable = !this._data.encrypting;

   readonly bubbleTip = viewChild.required<BubbleDirective>('bubbleTip');
   readonly strengthMeter = viewChild(StrengthMeterComponent);

   ngAfterViewInit(): void {
      if (!this._welcomed) {
         this.bubbleTip().show();
      }
   }

   ngOnDestroy(): void {
      if (!this._welcomed) {
         this.bubbleTip().hide();
      }
   }

   protected async checkPassword() {
      const strengthMeter = this.strengthMeter();
      if (strengthMeter) {
         this.onAcceptableChanged(await strengthMeter.checkIfPwned());
      }
   }

   protected async onAcceptClicked() {
      await this.checkPassword();

      if (this.passwd() && this._acceptable) {
         this._dialogRef.close([this.passwd(), this.hint()]);
      } else {
         this.strengthAlert.set(true);
         this._r2.selectRootElement('#password').focus();
      }
   }

   protected onPasswordChange() {
      // Don't want to leave an open pwd dialog if, there are characters entered
      // and not activity for a few minutes minutes, close the dialog
      if (this._timerId >= 0) {
         window.clearTimeout(this._timerId);
      }

      this._timerId = window.setTimeout(() => this._dialogRef.close(), PWD_CLOSE_TIMEOUT);
   }

   onAcceptableChanged(state: AcceptableState) {
      if (!this.encrypting) {
         return;
      }

      this._acceptable = state.acceptable;

      if (!this.passwd()) {
         this.strengthPhrase.set('Password is empty');
      } else if (!state.acceptable) {
         this.strengthPhrase.set('Password is too weak');
      } else {
         this.strengthAlert.set(false);
         const qualifier = state.strength < 2 ? 'but' : 'and';
         this.strengthPhrase.set(`Password is allowed... ${qualifier} ${NAMES[state.strength]}`);
      }
   }
}

@Component({
   selector: 'cipher-info.dialog',
   templateUrl: './cipher-info.dialog.html',
   styleUrl: './dialogs.scss',
   changeDetection: ChangeDetectionStrategy.Eager,
   imports: [MatDialogModule, MatIconModule, MatButtonModule],
})
export class CipherInfoDialog {
   private readonly _data = inject<CipherDataInfo>(MAT_DIALOG_DATA);

   public error;
   public ic!: string;
   public alg!: string;
   public ver!: string;
   public lps!: number;
   public hint?: string;

   constructor() {
      const data = this._data;

      if (!data) {
         this.error = 'The wrong passkey was selected or the cipher armor is invalid';
      } else {
         if (!data.ic) {
            throw new Error('Invalid iter count');
         }
         this.ic = data.ic.toLocaleString();
         this.alg = Ciphers.algDescription(data.alg);
         this.hint = data.hint;
         this.lps = data.lpEnd;
         this.ver = data.ver.toString();
      }
   }
}

@Component({
   selector: 'signin.dialog',
   templateUrl: './signin.dialog.html',
   styleUrl: './dialogs.scss',
   changeDetection: ChangeDetectionStrategy.Eager,
   imports: [MatDialogModule, MatProgressSpinnerModule, MatIconModule, MatTooltipModule, MatButtonModule],
})
export class SigninDialog implements OnDestroy {
   private readonly _authSvc = inject(AuthenticatorService);
   private readonly _router = inject(Router);
   private readonly _dialogRef = inject<MatDialogRef<SigninDialog>>(MatDialogRef);

   public userName: string | null;
   public userId: string | null;
   public notice: string = '';
   public noticeClass: string = 'error-msg';
   public showProgress: boolean = false;
   private _noticeTimerId = 0;
   private _userActed = false;

   constructor() {
      const dialogRef = this._dialogRef;

      dialogRef.disableClose = true;
      [this.userId, this.userName] = this._authSvc.loadKnownUser();

      this._authSvc.logoutResult().then((result) => {
         if (!this._userActed) {
            if (result === 'error') {
               this.notice = 'Sign out failed, sign in then out again to retry.';
            } else if (result === 'success') {
               this.noticeClass = 'success-msg';
               this.notice = 'Sign out succeeded';
               this._noticeTimerId = window.setTimeout(() => {
                  this._noticeTimerId = 0;
                  this.notice = '';
               }, 4000);
            }
         }
      });
   }

   ngOnDestroy(): void {
      this._userActed = true;
      this._clearNoticeTimer();
   }

   private _clearNoticeTimer(): void {
      if (this._noticeTimerId) {
         window.clearTimeout(this._noticeTimerId);
         this._noticeTimerId = 0;
      }
   }

   // Would be cleaner to move navigation to core.component, but doing
   // it in the dialog gives us a good place to show errors.
   async onClickSignin(_event: MouseEvent) {
      try {
         this._userActed = true;
         this._clearNoticeTimer();
         this.notice = '';
         this.noticeClass = 'error-msg';

         // This can happen if another tab logs out or changes passkeys while the
         // dialog is open. Not a great UX, but it's likely a rare race condition
         if (!this._authSvc.validKnownUser()) {
            // don't kill other tab sessions
            this._authSvc.forgetUser(false);
            this._router.navigateByUrl('/welcome');
            this._dialogRef.close('Navigate');
         } else {
            this.showProgress = true;
            await this._authSvc.createDefaultSession();
            this._dialogRef.close('Login');
         }
      } catch (err) {
         console.error(err);
         if (err instanceof Error && err.message.includes('fetch')) {
            this.notice = 'Sign in failed, check your connection';
         } else {
            this.notice = 'Sign in failed, try again or change users';
         }
      } finally {
         this.showProgress = false;
      }
   }

   onClickForget(_event: MouseEvent) {
      this._userActed = true;
      this._clearNoticeTimer();
      this.notice = '';
      // kill other tab sessions
      this._authSvc.forgetUser(true);
      this._router.navigateByUrl('/welcome');
      this._dialogRef.close('Forget');
   }
}
