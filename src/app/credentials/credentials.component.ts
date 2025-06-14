import {
   Component, EventEmitter, Inject, OnInit,
   Output, effect, Renderer2, OnDestroy
} from '@angular/core';
import { CommonModule, NgIf } from '@angular/common';
import { MatSnackBar } from '@angular/material/snack-bar';
import { MatDividerModule } from '@angular/material/divider';
import { MatTableModule } from '@angular/material/table';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatInputModule } from '@angular/material/input';
import { AuthenticatorService, AuthenticatorInfo, AuthEvent } from '../services/authenticator.service';
import { EditableComponent } from '../ui/editable/editable.component';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MAT_DIALOG_DATA, MatDialog, MatDialogModule, MatDialogRef } from '@angular/material/dialog';
import { Router, RouterLink, NavigationStart } from '@angular/router';
import { MatFormFieldModule } from '@angular/material/form-field';
import { FormsModule, ReactiveFormsModule, FormControl } from '@angular/forms';
import { Subscription } from 'rxjs';

@Component({
   selector: 'app-credentials',
   templateUrl: './credentials.component.html',
   styleUrl: './credentials.component.scss',
   imports: [MatDividerModule, MatTableModule,
      MatIconModule, MatButtonModule, MatInputModule, EditableComponent,
      MatTooltipModule, RouterLink, CommonModule
   ]
})
export class CredentialsComponent implements OnInit, OnDestroy {

   private authSub!: Subscription;
   private routeSub!: Subscription;
   public error = '';
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
      });
   }

   ngOnInit(): void {
      this.passKeys = this.authSvc.passKeys();

      this.routeSub = this.router.events.subscribe((event) => {
         if (event instanceof NavigationStart) {
            this.done.emit(true);
         }
      });

      this.authSub = this.authSvc.on(
         [AuthEvent.Logout],
         () => this.done.emit(true)
      );
   }

   ngOnDestroy(): void {
      if (this.authSub) {
         this.authSub.unsubscribe();
      }
      if (this.routeSub) {
         this.routeSub.unsubscribe();
      }
   }

   toastMessage(msg: string): void {
      this.snackBar.open(msg, '', {
         duration: 2000,
      });
   }

   onClickDelete(passkey: AuthenticatorInfo) {
      this.error = '';
      let pkState = ConfirmDialog.NONE_PK;
      if (this.authSvc.passKeys().length == 1) {
         pkState = ConfirmDialog.LAST_PK;
      } else if (this.authSvc.pkId == passkey.credentialId) {
         pkState = ConfirmDialog.ACTIVE_PK;
      }

      var dialogRef = this.dialog.open(ConfirmDialog, {
         data: {
            pkState: pkState,
            userName: this.authSvc.userName
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

   isCurrentPk(credentialId: string): boolean {
      return credentialId == this.authSvc.pkId;
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
   imports: [MatDialogModule, CommonModule, MatIconModule, MatTooltipModule,
      MatButtonModule, MatFormFieldModule, NgIf, MatInputModule, FormsModule,
      ReactiveFormsModule
   ]
})
export class ConfirmDialog {

   public pkState = 0;
   public userName = '';
   public confirmInput = new FormControl('');

   static readonly NONE_PK = 0;
   static readonly LAST_PK = 1;
   static readonly ACTIVE_PK = 2;

   // A bit ugly but needed to access constant from template
   get NONE_PK(): number {
      return ConfirmDialog.NONE_PK;
   }
   get LAST_PK(): number {
      return ConfirmDialog.LAST_PK;
   }
   get ACTIVE_PK(): number {
      return ConfirmDialog.ACTIVE_PK;
   }

   constructor(
      public dialogRef: MatDialogRef<ConfirmDialog>,
      private r2: Renderer2,
      @Inject(MAT_DIALOG_DATA) public data: ConfirmData
   ) {
      this.pkState = data.pkState;
      this.userName = data.userName;
   }

   onYesClicked() {
      if (this.pkState != this.LAST_PK ||
         (this.confirmInput.value && this.confirmInput.value === this.userName)
      ) {
         this.dialogRef.close('Yes');
      } else {
         try {
            this.r2.selectRootElement('#confirmInput').focus();
         } catch (err) {
            console.error(err);
         }
      }
   }
}