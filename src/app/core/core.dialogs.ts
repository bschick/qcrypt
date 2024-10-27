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
import {
   Component,
   Renderer2,
   Inject,
   ViewEncapsulation,
   OnInit,
   ViewChild,
   AfterViewInit,
   OnDestroy,
} from '@angular/core';
import {
   MAT_DIALOG_DATA,
   MatDialogRef,
   MatDialogModule,
} from '@angular/material/dialog';
import { CommonModule, NgIf } from '@angular/common';
import { MatTooltipModule } from '@angular/material/tooltip';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';
import { MatMenuModule } from '@angular/material/menu';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatSnackBar } from '@angular/material/snack-bar';
import { MatInputModule } from '@angular/material/input';
import { MatFormFieldModule } from '@angular/material/form-field';
import { Router } from '@angular/router';
import { PasswordStrengthMeterComponent } from 'angular-password-strength-meter';
import { AuthenticatorService } from '../services/authenticator.service';
import { ZxcvbnOptionsService } from '../services/zxcvbn-options.service';
import { BubbleDirective } from '../ui/bubble/bubble.directive';
import * as cc from '../services/cipher.consts';
import { bytesToBase64 } from '../services/utils';
import { CipherService, CipherDataInfo } from '../services/cipher.service';


export type PwdDialogData = {
   message: string;
   hint: string;
   askHint: boolean;
   minStrength: number;
   hidePwd: boolean;
   loopCount: number;
   loops: number;
   checkPwned: boolean;
   welcomed: boolean;
   userName: string;
};


@Component({
   selector: 'password-dialog',
   templateUrl: './password-dialog.html',
   styleUrl: './core.dialogs.scss',
   standalone: true,
   encapsulation: ViewEncapsulation.None, // Needed to change stypes of stength meter
   imports: [MatDialogModule, CommonModule, NgIf, MatFormFieldModule, MatMenuModule, MatInputModule,
      MatIconModule, PasswordStrengthMeterComponent, FormsModule, ReactiveFormsModule,
      MatTooltipModule, MatButtonModule, BubbleDirective
   ],
})
export class PasswordDialog implements OnInit, AfterViewInit, OnDestroy {
   public hidePwd = false;
   public passwd = '';
   public hint = '';
   public strengthPhrase = 'Strength';
   public strengthAlert = false;
   public strength = 0;
   public minStrength = 3;
   public loopCount = 0;
   public loops = 0;
   public askHint = false;
   public userName = '';
   private checkPwned = false;
   private welcomed = true;
   public maxHintLen = cc.HINT_MAX_LEN;

   @ViewChild('bubbleTip') bubbleTip!: BubbleDirective;

   constructor(
      private r2: Renderer2,
      private zxcvbnOptions: ZxcvbnOptionsService,
      public dialogRef: MatDialogRef<PasswordDialog>,
      @Inject(MAT_DIALOG_DATA) public data: PwdDialogData
   ) {
      this.hint = data.hint;
      this.askHint = data.askHint;
      this.minStrength = data.minStrength;
      this.hidePwd = data.hidePwd;
      this.loopCount = data.loopCount;
      this.loops = data.loops;
      this.onPasswordStrengthChange(0);
      this.checkPwned = data.checkPwned;
      this.welcomed = data.welcomed;
      this.userName = data.userName;
   }

   ngOnInit(): void {
      this.zxcvbnOptions.checkPwned(this.checkPwned);
   }

   ngAfterViewInit(): void {
      if (!this.welcomed) {
         this.bubbleTip.show();
      }
   }

   ngOnDestroy(): void {
      if (!this.welcomed) {
         this.bubbleTip.hide();
      }
   }

   onAcceptClicked() {
      if (this.passwd && this.strength >= this.minStrength) {
         this.dialogRef.close([this.passwd, this.hint]);
      } else {
         this.strengthAlert = true;
         this.r2.selectRootElement('#password').focus();
      }
   }

   onPasswordStrengthChange(strength: number | null) {
      if (this.minStrength < 0) {
         return;
      }

      if (strength == null) {
         this.strength = 0;
      } else {
         this.strength = strength;
      }

      if (!this.passwd) {
         this.strengthPhrase = 'Password is empty';
      } else if (this.strength < this.minStrength) {
         this.strengthPhrase = 'Password is too weak'; // + this.strength;
      } else {
         this.strengthAlert = false;
         this.strengthPhrase = 'Password is acceptable'; // + this.strength;
      }
   }
}

@Component({
   selector: 'cipher-info-dialog',
   templateUrl: './cipher-info-dialog.html',
   styleUrl: './core.dialogs.scss',
   standalone: true,
   imports: [MatDialogModule, MatIconModule, CommonModule, NgIf, MatButtonModule],
})

export class CipherInfoDialog {
   public error;
   public ic!: string;
   public alg!: string;
   public slt!: string;
   public iv!: string;
   public ver!: string;
   public lps!: number;
   public hint!: string;

   constructor(
      private r2: Renderer2,
      private cipherSvc: CipherService,
      public dialogRef: MatDialogRef<CipherInfoDialog>,
      @Inject(MAT_DIALOG_DATA) public data: CipherDataInfo
   ) {
      if (!data) {
         this.error = 'The wrong passkey was selected or the cipher armor is invalid';
      } else {
         this.ic = data.ic.toLocaleString();
         this.alg = this.cipherSvc.algDescription(data.alg);
         this.iv = bytesToBase64(data.iv as Uint8Array);
         this.slt = bytesToBase64(data.slt as Uint8Array);
         this.hint = data.hint ? 'yes' : 'no';
         this.lps = data.lpEnd;
         this.ver = data.ver.toString();
      }
   }
}


@Component({
   selector: 'signin-dialog',
   templateUrl: './signin-dialog.html',
   styleUrl: './core.dialogs.scss',
   standalone: true,
   imports: [MatDialogModule, CommonModule, NgIf, MatProgressSpinnerModule,
      MatIconModule, MatTooltipModule, MatButtonModule],
})
export class SigninDialog {

   public userName: string;
   public error: string = '';
   public showProgress: boolean = false;

   constructor(
      private authSvc: AuthenticatorService,
      private router: Router,
      public dialogRef: MatDialogRef<SigninDialog>,
      private snackBar: MatSnackBar,
      @Inject(MAT_DIALOG_DATA) public data: SigninDialog
   ) {
      dialogRef.disableClose = true;
      const [_, userName] = this.authSvc.getUserInfo();
      this.userName = userName!;
   }

   async onClickSignin(event: any) {
      try {
         this.error = '';
         this.showProgress = true;
         await this.authSvc.defaultLogin();
         this.dialogRef.close();
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

   onClickForget(event: any) {
      this.error = '';
      this.authSvc.forgetUserInfo();
      this.router.navigateByUrl('/welcome');
      this.dialogRef.close(null);
   }

}
