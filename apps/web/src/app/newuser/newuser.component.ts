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

import { AfterViewInit, Component, OnInit, Renderer2 } from '@angular/core';

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
    templateUrl: './newuser.component.html',
    styleUrl: './newuser.component.scss',
    imports: [MatIconModule, MatButtonModule, RouterLink, MatProgressSpinnerModule, MatInputModule, MatFormFieldModule, FormsModule, ClipboardModule, MatTooltipModule]
})
export class NewUserComponent implements OnInit, AfterViewInit {

   public showProgress = false;
   public error = '';
   public newUserName = '';
   public currentUserName: string | null = null;
   public recoveryLink = '';
   public authenticated = false;

   constructor(
      private r2: Renderer2,
      private authSvc: AuthenticatorService,
      private router: Router,
      private snackBar: MatSnackBar) {
   }

   ngOnInit() {
      const [userId, userName] = this.authSvc.loadKnownUser();
      if (userId && userName) {
         this.currentUserName = userName;
      }
      this.authenticated = this.authSvc.authenticated();
   }

   ngAfterViewInit(): void {
      try {
         // Make this async to avoid ExpressionChangedAfterItHasBeenCheckedError errors
         setTimeout(
            () => this.r2.selectRootElement('#userName').focus(), 0
         );
      } catch (err) {
         console.error(err);
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
         // Session will be replaced, so don't need to kill direclty
         this.authSvc.forgetUser(false);
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
