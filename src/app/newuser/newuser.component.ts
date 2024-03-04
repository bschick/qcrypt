import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { MatInputModule } from '@angular/material/input';
import { MatFormFieldModule } from '@angular/material/form-field';
import { FormsModule } from '@angular/forms';
import { AuthenticatorService } from '../services/authenticator.service';
import { Router, RouterLink, ActivatedRoute } from '@angular/router';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatSnackBar } from '@angular/material/snack-bar';
import { ClipboardModule } from '@angular/cdk/clipboard';


@Component({
  selector: 'app-newuser',
  standalone: true,
  templateUrl: './newuser.component.html',
  styleUrl: './newuser.component.scss',
  imports: [MatIconModule, MatButtonModule, RouterLink, CommonModule,
    MatProgressSpinnerModule, MatInputModule, MatFormFieldModule,
    FormsModule, ClipboardModule,
  ],
})
export class NewUserComponent implements OnInit {

  public showProgress = false;
  public error = '';
  public newUserName = '';
  public currentUserName: string | null = null;
  public completed = false;
  public recoveryLink = '';

  constructor(
    private authSvc: AuthenticatorService,
    private router: Router,
    private snackBar: MatSnackBar,
    private activeRoute: ActivatedRoute) {
  }

  ngOnInit() {
    const [userId, userName] = this.authSvc.getUserInfo();
    if (userId && userName) {
      this.currentUserName = userName;
    }
  }

  toastMessage(msg: string): void {
    this.snackBar.open(msg, '', {
      duration: 2000,
    });
  }

  async onClickSignin(): Promise<void> {
    try {
      this.error = '';
      this.showProgress = true;
      await this.authSvc.passkeyLogin();
      this.router.navigateByUrl('/');
    } catch (err) {
      console.error(err);
      this.error = 'Sign in failed, try again or create a new user';
    } finally {
      this.showProgress = false;
    }
  }

  async onClickNewUser(event: any): Promise<void> {
    this.error = '';

    if (!this.newUserName || this.newUserName.length < 6 || this.newUserName.length > 31) {
      this.error = 'User name must be 6 to 31 characters long';
      return;
    }

    try {
      this.showProgress = true;
      const passkeyInfo = await this.authSvc.newUser(this.newUserName);
      this.recoveryLink = new URL(
        window.location.origin + '/recovery' +
        '?userid=' + passkeyInfo.userId +
        '&sitekey=' + passkeyInfo.siteKey
      ).toString();

      this.completed = true;
    } catch (err) {
      console.error(err);
      if (err instanceof Error) {
        this.error = err.message ?? err.name;
      }
    } finally {
      this.showProgress = false;
    }
  }
}
