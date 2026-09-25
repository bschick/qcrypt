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
   type AfterViewInit,
   Component,
   type OnInit,
   Renderer2,
   ChangeDetectionStrategy,
   inject,
   signal,
} from '@angular/core';

import { MatTooltipModule } from '@angular/material/tooltip';
import { MatInputModule } from '@angular/material/input';
import { MatFormFieldModule } from '@angular/material/form-field';
import { FormsModule } from '@angular/forms';
import { firstValueFrom } from 'rxjs';
import { AuthenticatorService } from '../services/authenticator.service';
import { Router, RouterLink } from '@angular/router';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatDialog, MatDialogModule } from '@angular/material/dialog';
import { ClipboardModule } from '@angular/cdk/clipboard';
import { NoAssistDirective } from '../ui/noassist.directive';

@Component({
   selector: 'app-newuser',
   templateUrl: './newuser.component.html',
   styleUrl: './newuser.component.scss',
   changeDetection: ChangeDetectionStrategy.Eager,
   imports: [
      MatIconModule,
      MatButtonModule,
      RouterLink,
      MatProgressSpinnerModule,
      MatInputModule,
      MatFormFieldModule,
      FormsModule,
      ClipboardModule,
      MatTooltipModule,
      NoAssistDirective,
   ],
})
export class NewUserComponent implements OnInit, AfterViewInit {
   private readonly _r2 = inject(Renderer2);
   private readonly _authSvc = inject(AuthenticatorService);
   private readonly _router = inject(Router);
   private readonly _dialog = inject(MatDialog);

   protected readonly showProgress = signal(false);
   protected readonly error = signal('');
   protected readonly newUserName = signal('');
   protected readonly currentUserName = signal<string | null>(null);
   protected readonly authenticated = signal(false);

   ngOnInit() {
      const [userId, userName] = this._authSvc.loadKnownUser();
      if (userId && userName) {
         this.currentUserName.set(userName);
      }
      this.authenticated.set(this._authSvc.hasSession());
   }

   ngAfterViewInit(): void {
      // Make this async to avoid ExpressionChangedAfterItHasBeenCheckedError errors
      setTimeout(() => {
         try {
            this._r2.selectRootElement('#userName').focus();
         } catch (err) {
            console.error(err);
         }
      }, 0);
   }

   protected async onClickSignin(): Promise<void> {
      try {
         this.error.set('');
         this.showProgress.set(true);
         await this._authSvc.createDefaultSession();
         this._router.navigateByUrl('/');
      } catch (err) {
         console.error(err);
         if (err instanceof Error && err.message.includes('fetch')) {
            this.error.set('Sign in failed, check your connection');
         } else {
            this.error.set('Sign in failed, try again or change users');
         }
      } finally {
         this.showProgress.set(false);
      }
   }

   protected async onClickNewUser(_event: MouseEvent): Promise<void> {
      this.error.set('');
      const userName = this.newUserName();

      if (!userName || userName.length < 6 || userName.length > 31) {
         this.error.set('User name must be 6 to 31 characters long');
         return;
      }

      try {
         this.showProgress.set(true);
         // Session will be replaced, so don't need to kill direclty
         this._authSvc.forgetUser(false);
         await this._authSvc.newUser(userName, () => this._decidePrfFallback());
         this._router.navigateByUrl('/showrecovery');
      } catch (err) {
         console.error(err);
         if (err instanceof Error && err.message.includes('fetch')) {
            this.error.set('New user creation failed, check your internet connection');
         } else {
            this.error.set('New user creation failed, please try again');
         }
      } finally {
         this.showProgress.set(false);
      }
   }

   // The dialog cannot be dismissed, so it always resolves to a definite choice.
   private async _decidePrfFallback(): Promise<'standard' | 'different'> {
      this.showProgress.set(false);
      const choice = await firstValueFrom(this._dialog.open(PrfFallbackDialog, { disableClose: true }).afterClosed());
      if (choice !== 'standard' && choice !== 'different') {
         throw new Error('PRF fallback dialog returned an invalid choice');
      }
      this.showProgress.set(true);
      return choice;
   }
}

@Component({
   selector: 'prf-fallback-dialog',
   templateUrl: './prf-fallback-dialog.html',
   styleUrl: './prf-fallback-dialog.scss',
   changeDetection: ChangeDetectionStrategy.Eager,
   imports: [MatDialogModule, MatButtonModule, RouterLink],
})
export class PrfFallbackDialog {}
