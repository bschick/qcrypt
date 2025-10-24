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

import { AfterViewInit, Component, Inject, OnDestroy, OnInit, Renderer2 } from '@angular/core';
import { AuthenticatorService } from '../services/authenticator.service';
import { Router, RouterLink, ActivatedRoute } from '@angular/router';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { FormsModule, ReactiveFormsModule, FormControl } from '@angular/forms';
import { MatCardModule}  from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { MAT_DIALOG_DATA, MatDialog, MatDialogModule, MatDialogRef } from '@angular/material/dialog';
import { firstValueFrom } from 'rxjs';

@Component({
    selector: 'app-recovery',
    templateUrl: './recovery2.component.html',
    styleUrl: './recovery2.component.scss',
    imports: [MatIconModule, MatButtonModule, RouterLink, FormsModule, ReactiveFormsModule,
      MatProgressSpinnerModule, MatCardModule, MatFormFieldModule, MatInputModule
    ]
})
export class Recovery2Component implements OnInit, OnDestroy, AfterViewInit{

   public validRecoveryWords = false;
   public error = '';
   public ready = false;
   public showProgress = false;
   public authenticated = false;
   public currentUserName: string | null = null;
   public recoveryWords = new FormControl<string>('');

   constructor(
      private r2: Renderer2,
      private authSvc: AuthenticatorService,
      private router: Router,
      private dialog: MatDialog,
      private activeRoute: ActivatedRoute) {
   }

   ngOnInit() {
      const [userId, userName] = this.authSvc.loadKnownUser();
      if(userId && userName) {
         this.currentUserName = userName;
      }

      this.showProgress = true;

      this.authSvc.ready.then( () => {
         this.authenticated = this.authSvc.authenticated();
      }).finally( () => {
         this.ready = true;
         this.showProgress = false;
      });
   }

   ngAfterViewInit(): void {
      try {
         // Make this async to avoid ExpressionChangedAfterItHasBeenCheckedError errors
         setTimeout(
            () => this.r2.selectRootElement('#wordsArea').focus(), 0
         );
      } catch (err) {
         console.error(err);
      }
   }

   ngOnDestroy() {
      this.recoveryWords.setValue('');
   }

   async onClickSignin(): Promise<void> {
      try {
         this.error = '';
         this.showProgress = true;
         await this.authSvc.defaultLogin();
         this.router.navigateByUrl('/');
      } catch (err) {
         console.error(err);
         if(err instanceof Error && err.message.includes("fetch")) {
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
         this.error = '';
         const rawString = this.recoveryWords.value?.trim();

         if(!rawString) {
            this.error = 'No recovery words were entered.';
         } else {
            const words = rawString.split(/\s+/);
            const cleanedWords = words.join(' ');
            if(!validateMnemonic(cleanedWords, wordlist)) {
               this.error = 'The recovery pattern contains incorrect words.';
            } else {
               const proceed = await this._checkProceed(cleanedWords);
               if (proceed) {
                  this.showProgress = true;
                  await this.authSvc.recover2(cleanedWords);
                  this.router.navigateByUrl('/');
               }

            }
         }
      } catch (err) {
         console.error(err);
         this.error = 'The operation was not allowed or timed out.';
      } finally {
         this.showProgress = false;
         if(this.error) {
            this.error += ' Ensure you are using the recovery word pattern provided when you created your account, then try again.'
         }
      }
   }

   private async _checkProceed(recoveryWords: string): Promise<boolean> {

      const [_, userId] = this.authSvc.getRecoveryValues(recoveryWords);
      if (!this.authSvc.authenticated() || userId === this.authSvc.userId) {
         return true;
      }

      const dialogRef = this.dialog.open(ConfirmDialog, {
         data: { userName: this.authSvc.userName }
      });
      return await firstValueFrom(dialogRef.afterClosed());
   }
}

export interface ConfirmData {
   userName: string;
}


@Component({
   selector: 'confirm-dialog',
   templateUrl: 'confirm-dialog.html',
   styleUrl: './recovery2.component.scss',
   imports: [MatDialogModule, MatIconModule, MatButtonModule
   ]
})
export class ConfirmDialog {

   public currentUserName: string;

   constructor(
      public dialogRef: MatDialogRef<ConfirmDialog>,
      @Inject(MAT_DIALOG_DATA) public data: ConfirmData
   ) {
      this.currentUserName = data.userName;
   }
}