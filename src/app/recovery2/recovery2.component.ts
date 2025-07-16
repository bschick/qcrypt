import { Component, OnDestroy, OnInit } from '@angular/core';
import { AuthenticatorService } from '../services/authenticator.service';
import { Router, RouterLink, ActivatedRoute } from '@angular/router';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { FormsModule, ReactiveFormsModule, FormControl } from '@angular/forms';
import { MatCardModule}  from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';

@Component({
    selector: 'app-recovery',
    templateUrl: './recovery2.component.html',
    styleUrl: './recovery2.component.scss',
    imports: [MatIconModule, MatButtonModule, RouterLink, FormsModule, ReactiveFormsModule,
      MatProgressSpinnerModule, MatCardModule, MatFormFieldModule, MatInputModule
    ]
})
export class Recovery2Component implements OnInit, OnDestroy {

   public validRecoveryWords = false;
   public error = '';
   public showProgress = false;
   public authenticated = false;
   public currentUserName: string | null = null;
   public recoveryWords = new FormControl<string>('');

   constructor(
      private authSvc: AuthenticatorService,
      private router: Router,
      private activeRoute: ActivatedRoute) {
   }

   ngOnInit() {
      this.authenticated = this.authSvc.isAuthenticated();
      const [userId, userName] = this.authSvc.loadKnownUser();
      if(userId && userName) {
         this.currentUserName = userName;
      }
   }

   ngOnDestroy() {
      this.recoveryWords.setValue('');
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

   async onClickStartRecovery(event: any) {
      try {
         this.error = '';
         const rawString = this.recoveryWords.value?.trim();

         if(!rawString) {
            this.error = 'Recovery failed because no recovery words were entered.';
         } else {
            const words = rawString.split(/\s+/);
            const cleanedWords = words.join(' ');
            if(!validateMnemonic(cleanedWords, wordlist)) {
               this.error = 'Recovery failed because the recovery pattern contains incorrect words.';
            } else {
               this.showProgress = true;
               await this.authSvc.recover2(cleanedWords);
               this.router.navigateByUrl('/');
            }
         }
      } catch (err) {
         console.error(err);
         this.error = 'The operation was not allowed or timed out.';
      } finally {
         this.showProgress = false;
         if(this.error) {
            this.error += ' Ensure you are using the correct recovery word pattern provided when you created your account, then try again.'
         }
      }
   }
}
