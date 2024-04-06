import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { AuthenticatorService } from '../services/authenticator.service';
import { Router, RouterLink, ActivatedRoute } from '@angular/router';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';


@Component({
   selector: 'app-recovery',
   standalone: true,
   templateUrl: './recovery.component.html',
   styleUrl: './recovery.component.scss',
   imports: [MatIconModule, MatButtonModule, RouterLink, CommonModule,
      MatProgressSpinnerModule,
   ],
})
export class RecoveryComponent implements OnInit {

   public validRecoveryLink = true;
   public error = '';
   public showProgress = false;
   public authenticated = false;
   public selfRecovery = false;
   public currentUserName: string | null = null;
   private recoveryUserId: string | null = null;
   private recoverUserCred: string | null = null;

   constructor(
      private authSvc: AuthenticatorService,
      private router: Router,
      private activeRoute: ActivatedRoute) {
   }

   ngOnInit() {
      this.recoveryUserId = this.activeRoute.snapshot.queryParamMap.get('userid');
      this.recoverUserCred = this.activeRoute.snapshot.queryParamMap.get('usercred');
      if (!this.recoveryUserId || !this.recoverUserCred) {
         this.error = 'userid or usercred is missing';
         this.validRecoveryLink = false;
      }
      this.authenticated = this.authSvc.isAuthenticated();
      if (this.authenticated) {
         this.selfRecovery = this.recoverUserCred === this.authSvc.userCred;
      }
      const [userId, userName] = this.authSvc.getUserInfo();
      if (userId && userName) {
         this.currentUserName = userName;
      }
   }

   async onClickSignin(): Promise<void> {
      try {
         this.error = '';
         this.showProgress = true;
         await this.authSvc.defaultLogin();
         this.router.navigateByUrl('/');
      } catch (err) {
         console.error(err);
         this.error = 'Sign in failed, try again or continue with recovery';
      } finally {
         this.showProgress = false;
      }
   }

   async onClickStartRecovery(event: any) {
      try {
         this.showProgress = true;
         await this.authSvc.recover(this.recoveryUserId!, this.recoverUserCred!);
         this.router.navigateByUrl('/');
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
