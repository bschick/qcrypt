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
import { Component, ChangeDetectionStrategy, inject, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { AuthenticatorService } from '../services/authenticator.service';
import { Router, RouterLink } from '@angular/router';
import { MatDialog, MatDialogModule, MatDialogRef } from '@angular/material/dialog';
import { MatIconModule } from '@angular/material/icon';
import { MatDividerModule } from '@angular/material/divider';

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
   changeDetection: ChangeDetectionStrategy.Eager,
   imports: [MatButtonModule, MatProgressSpinnerModule, MatIconModule, MatDividerModule, RouterLink],
})
export class WelcomeComponent {
   private readonly _dialog = inject(MatDialog);
   private readonly _authSvc = inject(AuthenticatorService);
   private readonly _router = inject(Router);

   protected readonly error = signal('');
   protected readonly showProgress = signal(false);

   async onClickExisting(_event: MouseEvent) {
      try {
         this.error.set('');
         this.showProgress.set(true);
         await this._authSvc.createSession();
         this._router.navigateByUrl(`/${paramsToQueryString()}`);
      } catch (err) {
         console.error(err);
         if (err instanceof Error && err.message.includes('fetch')) {
            this.error.set('Sign in failed, check your internet connection');
         } else {
            this.error.set('Passkey not recognized. Either try again or select another option above.');
         }
      } finally {
         this.showProgress.set(false);
      }
   }

   protected onClickRecovery(_event: MouseEvent) {
      this._dialog.open(RecoveryDialog);
   }
}

@Component({
   selector: 'recovery-dialog',
   templateUrl: './recovery-dialog.html',
   styleUrl: './welcome.component.scss',
   changeDetection: ChangeDetectionStrategy.Eager,
   imports: [MatDialogModule, MatIconModule, MatTooltipModule, MatButtonModule, RouterLink],
})
export class RecoveryDialog {
   private readonly _dialogRef = inject<MatDialogRef<RecoveryDialog>>(MatDialogRef);
   private readonly _router = inject(Router);

   protected onClickNewUser(event: Event) {
      event.stopPropagation();
      this._dialogRef.close();
      this._router.navigateByUrl('/newuser');
   }

   protected onClickRecovery3(event: Event) {
      event.stopPropagation();
      this._dialogRef.close();
      this._router.navigateByUrl('/recovery3');
   }
}
