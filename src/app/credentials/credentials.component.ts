import {
   Component, EventEmitter, Inject, OnInit,
   Output, effect, Renderer2
} from '@angular/core';
import { CommonModule } from '@angular/common';
import { MatSnackBar } from '@angular/material/snack-bar';
import { MatDividerModule } from '@angular/material/divider';
import { MatTableModule } from '@angular/material/table';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatInputModule } from '@angular/material/input';
import { AuthenticatorService, AuthenticatorInfo } from '../services/authenticator.service';
import { EditableComponent } from '../editable/editable.component';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MAT_DIALOG_DATA, MatDialog, MatDialogModule, MatDialogRef } from '@angular/material/dialog';
import { Router } from '@angular/router';
import { MatFormFieldModule } from '@angular/material/form-field';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';
import { ClipboardModule } from '@angular/cdk/clipboard';


export interface ConfirmData {
   last: boolean;
}

@Component({
   selector: 'app-credentials',
   standalone: true,
   templateUrl: './credentials.component.html',
   styleUrl: './credentials.component.scss',
   imports: [MatDividerModule, MatTableModule,
      MatIconModule, MatButtonModule, MatInputModule, EditableComponent,
      MatTooltipModule, ClipboardModule,
   ],
})
export class CredentialsComponent implements OnInit {

   public error = '';
   public recoveryLink: string = '';
   public passKeys: AuthenticatorInfo[] = [];
   public showProgress = false;
   public displayedColumns: string[] = ['image', 'description', 'delete'];
   @Output() done = new EventEmitter<boolean>();

   constructor(
      public authSvc: AuthenticatorService,
      public dialog: MatDialog,
      private router: Router,
      private snackBar: MatSnackBar
   ) {
      effect(() => {
         this.passKeys = this.authSvc.passKeys();

         this.recoveryLink = new URL(
            window.location.origin + '/recovery' +
            '?userid=' + this.authSvc.userId +
            '&usercred=' + this.authSvc.userCred
         ).toString();
      });
   }

   ngOnInit() {
      this.passKeys = this.authSvc.passKeys();
   }

   toastMessage(msg: string): void {
      this.snackBar.open(msg, '', {
         duration: 2000,
      });
   }

   onClickDelete(passkey: AuthenticatorInfo) {
      this.error = '';
      const lastPasskey = this.authSvc.passKeys().length > 1 ? false : true;
      var dialogRef = this.dialog.open(ConfirmDialog, {
         data: {
            last: lastPasskey
         },
      });

      dialogRef.afterClosed().subscribe(async (result: string) => {
         if (result == 'Yes') {
            try {
               const deletedInfo = await this.authSvc.deletePasskey(passkey.credentialId);
               this.refresh();
               if (deletedInfo.userId) {
                  this.router.navigateByUrl('/welcome');
               }
            } catch (err) {
               console.error(err);
               this.error = 'Passkey not deleted, try again';
            }
         }
      });
   }

   async onClickAdd() {
      try {
         this.error = '';
         const registrationInfo = await this.authSvc.addPasskey();
         this.refresh();
      } catch (err) {
         console.error(err);
         this.error = 'Passkey not created, try again';
      }
   }

   async onClickFind() {
      try {
         this.error = '';
         await this.authSvc.findLogin();
      } catch (err) {
         console.error(err);
         this.error = 'Passkey not found, try again';
      }
   }

   async refresh(): Promise<void> {
      this.error = '';
      if (this.authSvc.isAuthenticated()) {
         this.authSvc.refreshPasskeys().catch((err) => {
            console.error(err);
         });
      } else {
         this.done.emit(true);
      }
   }

   async onUserNameChanged(component: EditableComponent): Promise<void> {
      try {
         this.error = '';
         await this.authSvc.setUserName(component.value);
         this.toastMessage('User name updated');
      } catch (err) {
         console.error(err);
         // failed, put back the old value by setting [value] again...
         component.value = this.authSvc.userName!;
      }
   }

   async onClickSignout(): Promise<void> {
      this.error = '';
      this.authSvc.logout();
      this.refresh();
   }

   async onDescriptionChanged(component: EditableComponent, passkey: AuthenticatorInfo): Promise<void> {
      try {
         this.error = '';
         await this.authSvc.setPasskeyDescription(passkey.credentialId, component.value);
         // worked, update with new value
         passkey.description = component.value;
         this.toastMessage('Passkey description updated');

      } catch (err) {
         console.error(err);
         //failed, put back the old value by setting [value] again...
         component.value = passkey.description;
      }
   }
}

@Component({
   selector: 'confirm-dialog',
   templateUrl: 'confirm-dialog.html',
   styleUrl: './credentials.component.scss',
   standalone: true,
   imports: [MatDialogModule, CommonModule, MatIconModule, MatTooltipModule,
      MatButtonModule, MatFormFieldModule, MatInputModule, FormsModule,
      ReactiveFormsModule
   ],
})
export class ConfirmDialog {

   public lastPasskey = false;
   public confirmed = '';

   constructor(
      public dialogRef: MatDialogRef<ConfirmDialog>,
      private r2: Renderer2,
      @Inject(MAT_DIALOG_DATA) public data: ConfirmData
   ) {
      this.lastPasskey = data.last;
   }

   onYesClicked() {
      if (this.confirmed === 'confirm') {
         this.dialogRef.close('Yes');
      } else {
         this.r2.selectRootElement('#confirmInput').focus();
      }
   }
}