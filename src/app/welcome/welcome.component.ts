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
import { Component } from '@angular/core';
import { MatInputModule } from '@angular/material/input';
import { MatFormFieldModule } from '@angular/material/form-field';
import { FormsModule } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { AuthenticatorService } from '../services/authenticator.service';
import { Router, RouterLink } from '@angular/router';
import { MatDialog, MatDialogModule, MatDialogRef } from '@angular/material/dialog';
import { MatIconModule } from '@angular/material/icon';
import { CommonModule } from '@angular/common';
import { MatTooltipModule } from '@angular/material/tooltip';
import { HttpParams } from '@angular/common/http';

function paramsToQueryString(): string {
   const params = new HttpParams({ fromString: window.location.search });
   return params.toString() ? `?${params.toString()}` : '';
}

@Component({
    selector: 'app-welcome',
    templateUrl: './welcome.component.html',
    styleUrl: './welcome.component.scss',
    imports: [MatInputModule, MatFormFieldModule, FormsModule, MatButtonModule,
        MatProgressSpinnerModule, RouterLink
    ]
})
export class WelcomeComponent {

   public error: string = '';
   public showProgress: boolean = false;

   constructor(
      private dialog: MatDialog,
      private authSvc: AuthenticatorService,
      private router: Router
   ) {
   }

   async onClickExisting(event: any) {
      try {
         this.error = '';
         this.showProgress = true;
         await this.authSvc.findLogin();
         this.router.navigateByUrl('/' + paramsToQueryString());
      } catch (err) {
         console.error(err);
         if (err instanceof Error && err.message.includes("fetch")) {
            this.error = 'Sign in failed, check your internet connection';
         } else {
            this.error = 'Passkey not recognized. Either try again or select another option above.';
         }
      } finally {
         this.showProgress = false;
      }

   }

   onClickNew(event: any) {
   }

   onClickRecovery(event: any) {
      var dialogRef = this.dialog.open(RecoveryDialog);
   }
}


@Component({
    selector: 'recovery-dialog',
    templateUrl: './recovery-dialog.html',
    styleUrl: './welcome.component.scss',
    imports: [MatDialogModule, CommonModule, MatIconModule, MatTooltipModule,
        MatButtonModule, RouterLink]
})
export class RecoveryDialog {
   constructor(
      public dialogRef: MatDialogRef<RecoveryDialog>,
      private router: Router) {
   }

   onClickNewUser(event: Event) {
      event.stopPropagation();
      this.dialogRef.close();
      this.router.navigateByUrl('/newuser');
   }

   onClickRecovery2(event: Event) {
      event.stopPropagation();
      this.dialogRef.close();
      this.router.navigateByUrl('/recovery2');
   }
}