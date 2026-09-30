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
   DestroyRef,
   type OnInit,
   computed,
   effect,
   Renderer2,
   ChangeDetectionStrategy,
   inject,
   output,
   signal,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';

import { MatSnackBar } from '@angular/material/snack-bar';
import { MatDividerModule } from '@angular/material/divider';
import { MatTableModule } from '@angular/material/table';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatInputModule } from '@angular/material/input';
import { AuthenticatorService, AuthEvent, PrfUnsupportedError } from '../services/authenticator.service';
import * as api from '@qcrypt/api';
import { EditableComponent } from '../ui/editable/editable.component';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MAT_DIALOG_DATA, MatDialog, MatDialogModule, MatDialogRef } from '@angular/material/dialog';
import { Router, RouterLink, NavigationStart } from '@angular/router';
import type { Event as RouterEvent } from '@angular/router';
import { MatFormFieldModule } from '@angular/material/form-field';
import { FormsModule, ReactiveFormsModule, FormControl } from '@angular/forms';
import { MatCardModule } from '@angular/material/card';

// Include routerLink to render text as a link or exclude for plain text
export type ErrorPart = {
   text: string;
   routerLink?: string;
};

@Component({
   selector: 'app-credentials',
   templateUrl: './credentials.component.html',
   styleUrl: './credentials.component.scss',
   changeDetection: ChangeDetectionStrategy.Eager,
   imports: [
      MatDividerModule,
      MatTableModule,
      MatIconModule,
      MatButtonModule,
      MatInputModule,
      EditableComponent,
      MatTooltipModule,
      RouterLink,
      MatCardModule,
   ],
})
export class CredentialsComponent implements OnInit {
   protected readonly authSvc = inject(AuthenticatorService);
   private readonly _dialog = inject(MatDialog);
   private readonly _router = inject(Router);
   private readonly _snackBar = inject(MatSnackBar);

   private readonly _destroyRef = inject(DestroyRef);
   protected readonly error = signal<ErrorPart[]>([]);
   protected readonly userName = signal('');
   protected readonly passKeys = computed<api.AuthenticatorInfoResponse[]>(() => this.authSvc.authenticators);
   protected readonly displayedColumns: string[] = ['image', 'description', 'delete'];
   readonly done = output<boolean>();

   constructor() {
      effect(() => this.userName.set(this.authSvc.hasSession() ? this.authSvc.userName : ''));
   }

   ngOnInit(): void {
      this._router.events.pipe(takeUntilDestroyed(this._destroyRef)).subscribe((event: RouterEvent) => {
         if (event instanceof NavigationStart) {
            this.done.emit(true);
         }
      });

      this.authSvc
         .on([AuthEvent.Logout, AuthEvent.Forget])
         .pipe(takeUntilDestroyed(this._destroyRef))
         .subscribe(() => this.refresh());
   }

   protected clearError(): void {
      this.error.set([]);
   }

   private _setError(...parts: (string | ErrorPart)[]): void {
      const message: ErrorPart[] = [];
      for (const part of parts) {
         if (typeof part === 'string') {
            message.push({ text: part });
         } else {
            message.push(part);
         }
      }
      this.error.set(message);
   }

   protected toastMessage(msg: string): void {
      this._snackBar.open(msg, '', {
         duration: 2000,
      });
   }

   protected onClickDelete(passkey: api.AuthenticatorInfoResponse) {
      this.clearError();
      let pkState = ConfirmDialog.NONE_PK;

      if (this.passKeys().length === 1) {
         pkState = ConfirmDialog.LAST_PK;
      } else if (this.isCurrentPk(passkey.credentialId)) {
         pkState = ConfirmDialog.ACTIVE_PK;
      }

      var dialogRef = this._dialog.open(ConfirmDialog, {
         data: {
            pkState,
            userName: this.userName(),
         },
      });

      dialogRef.afterClosed().subscribe(async (result: string) => {
         if (result === 'Yes') {
            try {
               const remainingAuths = await this.authSvc.deletePasskey(passkey.credentialId);
               if (remainingAuths === 0) {
                  this._router.navigateByUrl('/welcome');
               }
            } catch (err) {
               console.error(err);
               this._setError('Passkey not deleted, try again');
            }
         }
      });
   }

   protected async onClickAdd() {
      try {
         this.clearError();
         await this.authSvc.addPasskey();
      } catch (err) {
         if (err instanceof PrfUnsupportedError) {
            this._setError(
               'This account requires passkeys that support',
               { text: 'local key creation.', routerLink: '/help/faqs/2f8' },
               'Please use a passkey with the PRF extension.',
            );
         } else {
            console.error(err);
            if (err instanceof Error && err.name === 'InvalidStateError') {
               this._setError('Your passkey manager only allows one credential');
            } else {
               this._setError('Passkey not created, try again');
            }
         }
      }
   }

   protected isCurrentPk(credentialId: string): boolean {
      return this.authSvc.isCurrentPk(credentialId);
   }

   protected async refresh(): Promise<void> {
      this.clearError();
      if (this.authSvc.hasSession()) {
         // This runs async handle updates in signal
         this.authSvc.refreshUserInfo().catch((err) => {
            console.error(err);
         });
      } else {
         this.done.emit(true);
      }
   }

   protected async onUserNameChanged(component: EditableComponent): Promise<void> {
      try {
         this.clearError();
         const userInfo = await this.authSvc.setUserName(component.typed());
         component.commit(userInfo.userName);
         this.toastMessage('User name updated');
      } catch (err) {
         console.error(err);
         this._setError('Name change failed, must be 6 to 31 characters after unsupported characters are removed');
         component.focus();
      }
   }

   protected async onClickSignout(): Promise<void> {
      this.clearError();
      this.authSvc.logout(true);
      this.refresh();
   }

   protected async onDescriptionChanged(
      component: EditableComponent,
      passkey: api.AuthenticatorInfoResponse,
   ): Promise<void> {
      try {
         this.clearError();
         const userInfo = await this.authSvc.setPasskeyDescription(passkey.credentialId, component.typed());
         const saved = userInfo.authenticators.find((auth) => auth.credentialId === passkey.credentialId);
         component.commit(saved!.description);
         this.toastMessage('Passkey description updated');
      } catch (err) {
         console.error(err);
         this._setError(
            'Description change failed, must be 6 to 42 characters after unsupported characters are removed',
         );
         component.focus();
      }
   }
}

export interface ConfirmData {
   pkState: number;
   userName: string;
}

/*
Starting to expiriment with reactive forms.
https://angular.dev/guide/forms
https://angular.dev/guide/forms/reactive-forms
*/
@Component({
   selector: 'confirm-dialog',
   templateUrl: 'confirm-dialog.html',
   styleUrl: './credentials.component.scss',
   changeDetection: ChangeDetectionStrategy.Eager,
   imports: [
      MatDialogModule,
      MatIconModule,
      MatTooltipModule,
      MatButtonModule,
      MatFormFieldModule,
      MatInputModule,
      FormsModule,
      ReactiveFormsModule,
   ],
})
export class ConfirmDialog {
   private readonly _dialogRef = inject<MatDialogRef<ConfirmDialog>>(MatDialogRef);
   private readonly _r2 = inject(Renderer2);
   private readonly _data = inject<ConfirmData>(MAT_DIALOG_DATA);

   protected pkState = 0;
   protected userName = '';
   protected readonly confirmInput = new FormControl('');

   static readonly NONE_PK = 0;
   static readonly LAST_PK = 1;
   static readonly ACTIVE_PK = 2;

   // A bit ugly but needed to access constant from template
   protected get NONE_PK(): number {
      return ConfirmDialog.NONE_PK;
   }
   protected get LAST_PK(): number {
      return ConfirmDialog.LAST_PK;
   }
   protected get ACTIVE_PK(): number {
      return ConfirmDialog.ACTIVE_PK;
   }

   constructor() {
      this.pkState = this._data.pkState;
      this.userName = this._data.userName;
   }

   protected onYesClicked() {
      if (this.pkState !== this.LAST_PK || (this.confirmInput.value && this.confirmInput.value === this.userName)) {
         this._dialogRef.close('Yes');
      } else {
         try {
            this._r2.selectRootElement('#confirmInput').focus();
         } catch (err) {
            console.error(err);
         }
      }
   }
}
