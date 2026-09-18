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
   DestroyRef,
   type OnDestroy,
   type OnInit,
   ChangeDetectionStrategy,
   inject,
   signal,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatTooltipModule } from '@angular/material/tooltip';
import { ClipboardModule } from '@angular/cdk/clipboard';
import { Router } from '@angular/router';
import { MatInputModule } from '@angular/material/input';
import { MatFormFieldModule } from '@angular/material/form-field';
import { AuthEvent, AuthenticatorService } from '../services/authenticator.service';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { FormsModule, ReactiveFormsModule, FormControl } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { bytesToBase64 } from '@qcrypt/crypto';
import { NoAssistDirective } from '../ui/noassist.directive';

@Component({
   selector: 'app-cmd-line',
   templateUrl: './cmdline.component.html',
   styleUrl: './cmdline.component.scss',
   changeDetection: ChangeDetectionStrategy.Eager,
   imports: [
      MatIconModule,
      MatButtonModule,
      ClipboardModule,
      MatInputModule,
      MatProgressSpinnerModule,
      MatFormFieldModule,
      MatTooltipModule,
      FormsModule,
      ReactiveFormsModule,
      RouterLink,
      NoAssistDirective,
   ],
})
export class CmdLineComponent implements OnInit, OnDestroy {
   private readonly _authSvc = inject(AuthenticatorService);
   private readonly _router = inject(Router);
   private readonly _destroyRef = inject(DestroyRef);

   protected readonly showProgress = signal(true);
   protected readonly hideCred = signal(true);
   protected readonly error = signal('');
   public userCredential = new FormControl<string>('');

   ngOnInit() {
      this._authSvc
         .on([AuthEvent.Logout])
         .pipe(takeUntilDestroyed(this._destroyRef))
         .subscribe(() => {
            this.error.set('');
            this._router.navigateByUrl('/');
         });

      this.reloadData();
   }

   ngOnDestroy() {
      this.userCredential.setValue('');
   }

   protected reloadData() {
      this.showProgress.set(true);
      this.error.set('');

      this._authSvc
         .reauthenticate()
         .then(async () => {
            const userCred = await this._authSvc.getUserCred();
            this.userCredential.setValue(bytesToBase64(userCred));
            userCred.fill(0);
         })
         .catch((err) => {
            console.error(err);
            if (err instanceof Error && err.message.includes('fetch')) {
               this.error.set('Retrieval failed, check your connection try again');
            } else {
               this.error.set('Retrieval failed, try again');
            }
         })
         .finally(() => this.showProgress.set(false));
   }
}
