import {
   Component,
   OnDestroy,
   OnInit,
   Renderer2
} from '@angular/core';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatSnackBar } from '@angular/material/snack-bar';
import { MatTooltipModule } from '@angular/material/tooltip';
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
      MatInputModule, MatFormFieldModule, MatCardModule, MatProgressSpinnerModule,
      MatTooltipModule, FormsModule, ReactiveFormsModule
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
            this.error = 'Retrieval failed, check your connection and reload this page';
         } else {
            this.error = 'Retrieval failed, try reloading this page';
         }
      }).finally(
        () => this.showProgress = false
      );

      this.authSub = this.authSvc.on(
         [AuthEvent.Logout],
         () => this.router.navigateByUrl('/')
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
