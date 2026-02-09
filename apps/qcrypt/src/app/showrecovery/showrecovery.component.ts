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
   OnDestroy,
   OnInit,
   Renderer2
} from '@angular/core';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatSnackBar } from '@angular/material/snack-bar';
import { ClipboardModule } from '@angular/cdk/clipboard';
import { Router, RouterLink } from '@angular/router';
import { MatInputModule } from '@angular/material/input';
import { MatFormFieldModule } from '@angular/material/form-field';
import { AuthEvent, AuthenticatorService } from '../services/authenticator.service';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { Subscription } from 'rxjs';
import { MatCardModule } from '@angular/material/card';
import { FormsModule, ReactiveFormsModule, FormControl } from '@angular/forms';


@Component({
   selector: 'app-show-recovery',
   templateUrl: './showrecovery.component.html',
   styleUrl: './showrecovery.component.scss',
   imports: [MatIconModule, MatButtonModule, ClipboardModule, RouterLink,
      MatInputModule, MatCardModule, MatProgressSpinnerModule, MatFormFieldModule,
      FormsModule, ReactiveFormsModule
   ]
})
export class ShowRecoveryComponent implements OnInit, OnDestroy {

   public showProgress = true;
   public error = '';
   private authSub!: Subscription;
   public recoveryWords = new FormControl<string>('');

   constructor(
      public authSvc: AuthenticatorService,
      private r2: Renderer2,
      private router: Router,
      private snackBar: MatSnackBar) {
   }

   ngOnInit() {
      this.authSub = this.authSvc.on(
         [AuthEvent.Logout],
         () => {
            this.error = '';
            this.router.navigateByUrl('/');
         }
      );

      this.reloadData();
   }

   reloadData() {
      this.showProgress = true;
      this.error = '';

      this.authSvc.getRecoveryWords().then( (words) => {
         this.recoveryWords.setValue(words);

         try {
            // Make this async to avoid ExpressionChangedAfterItHasBeenCheckedError errors
            setTimeout(
               () => this.r2.selectRootElement('#wordsArea').focus(), 0
            );
         } catch (err) {
            console.error(err);
         }
      }).catch( (err) => {
         console.error(err);
         if(err instanceof Error && err.message.includes("fetch")) {
            this.error = 'Retrieval failed, check your connection try again';
         } else {
            this.error = 'Retrieval failed, try again';
         }
      }).finally(
        () => this.showProgress = false
      );
   }

   ngOnDestroy() {
      this.recoveryWords.setValue('');
      if (this.authSub) {
         this.authSub.unsubscribe();
      }
   }

   toastMessage(msg: string) {
      this.snackBar.open(msg, '', {
         duration: 2000,
      });
   }

   onClickSaved() {
      // If the user previous didn't have a recoveryId, refresh the user
      // so the warning doesn't show. If the user refreshes the page without
      // clicking, keeping showing to warning to encourage saving
      if(!this.authSvc.hasRecoveryId()) {
         // let this happen async
         this.authSvc.refreshUserInfo();
      }
   }
}
