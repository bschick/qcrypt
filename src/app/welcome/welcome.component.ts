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


@Component({
  selector: 'app-welcome',
  standalone: true,
  templateUrl: './welcome.component.html',
  styleUrl: './welcome.component.scss',
  imports: [MatInputModule, MatFormFieldModule, FormsModule, MatButtonModule,
    MatProgressSpinnerModule, RouterLink
  ],

})
export class WelcomeComponent {

  public error: string = '';
  public showProgress: boolean = false;

  constructor(
    private dialog: MatDialog,
    private authSvc: AuthenticatorService,
    private router: Router) {
  }

  async onClickExisting(event: any) {
    try {
      this.error = '';
      this.showProgress = true;
      await this.authSvc.findLogin();
      this.router.navigateByUrl('/');
    } catch (err) {
      console.error(err);
      this.error = 'Passkey not found. Either try again or select another option.';
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
  standalone: true,
  imports: [MatDialogModule, CommonModule, MatIconModule, MatTooltipModule,
    MatButtonModule],
})
export class RecoveryDialog {
  constructor(
    public dialogRef: MatDialogRef<RecoveryDialog>
  ) { }

}