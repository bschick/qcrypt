import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatInputModule } from '@angular/material/input';
import { MatFormFieldModule } from '@angular/material/form-field';
import { FormsModule } from '@angular/forms';
import { AuthenticatorService } from '../services/authenticator.service';
import { Router, RouterLink } from '@angular/router';
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
      FormsModule, ClipboardModule, MatTooltipModule,
   ],
})
export class NewUserComponent implements OnInit {

   public showProgress = false;
   public error = '';
   public newUserName = '';
   public currentUserName: string | null = null;
   public recoveryLink = '';
   public authenticated = false;

   constructor(
      private authSvc: AuthenticatorService,
      private router: Router,
      private snackBar: MatSnackBar) {
   }

   ngOnInit() {
      const [userId, userName] = this.authSvc.getUserInfo();
      if (userId && userName) {
         this.currentUserName = userName;
      }
      this.authenticated = this.authSvc.isAuthenticated();
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

   async onClickNewUser(event: any): Promise<void> {
      this.error = '';

      if (!this.newUserName || this.newUserName.length < 6 || this.newUserName.length > 31) {
         this.error = 'User name must be 6 to 31 characters long';
         return;
      }

      try {
         this.showProgress = true;
         this.authSvc.forgetUserInfo();
         await this.authSvc.newUser(this.newUserName);
         this.router.navigateByUrl('/showrecovery');
      } catch (err) {
         console.error(err);
         if(err instanceof Error && err.message.includes("fetch")) {
            this.error = 'New user creation failed, check your internet connection';
         } else {
            this.error = 'New user creation failed, please try again';
         }
      } finally {
         this.showProgress = false;
      }
   }
}
