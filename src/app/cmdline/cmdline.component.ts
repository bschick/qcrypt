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

import {
   Component,
   OnDestroy,
   OnInit
} from '@angular/core';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatSnackBar } from '@angular/material/snack-bar';
import { MatTooltipModule } from '@angular/material/tooltip';
import { ClipboardModule } from '@angular/cdk/clipboard';
import { Router } from '@angular/router';
import { MatInputModule } from '@angular/material/input';
import { MatFormFieldModule } from '@angular/material/form-field';
import { AuthEvent, AuthenticatorService } from '../services/authenticator.service';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { Subscription } from 'rxjs';
import { FormsModule, ReactiveFormsModule, FormControl } from '@angular/forms';


@Component({
   selector: 'app-cmd-line',
   templateUrl: './cmdline.component.html',
   styleUrl: './cmdline.component.scss',
   imports: [MatIconModule, MatButtonModule, ClipboardModule,
      MatInputModule, MatProgressSpinnerModule, MatFormFieldModule,
      MatTooltipModule, FormsModule, ReactiveFormsModule
   ]
})
export class CmdLineComponent implements OnInit, OnDestroy {

   public showProgress = true;
   public hideCred = true;
   public error = '';
   private authSub!: Subscription;
   public userCredential = new FormControl<string>('');

   constructor(
      public authSvc: AuthenticatorService,
      private router: Router,
      private snackBar: MatSnackBar) {
   }

   ngOnInit() {
      this.authSub = this.authSvc.on(
         [AuthEvent.Logout],
         () => this.router.navigateByUrl('/')
      );

      this.reloadData();
   }

   reloadData() {
      this.showProgress = true;
      this.error = '';

      // Not actually using recovery words, just an existing way
      // to force reauthentication
      this.authSvc.getRecoveryWords().then( () => {
         this.userCredential.setValue(this.authSvc.userCred);
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
      this.userCredential.setValue('');
      if (this.authSub) {
         this.authSub.unsubscribe();
      }
   }

   toastMessage(msg: string) {
      this.snackBar.open(msg, '', {
         duration: 2000,
      });
   }

}
