import {
   AfterViewInit,
   Component,
   OnDestroy,
   OnInit,
   Renderer2
} from '@angular/core';
import { CommonModule } from '@angular/common';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatSnackBar } from '@angular/material/snack-bar';
import { ClipboardModule } from '@angular/cdk/clipboard';
import { Router, RouterLink } from '@angular/router';
import { MatInputModule } from '@angular/material/input';
import { MatFormFieldModule } from '@angular/material/form-field';
import { AuthEvent, AuthenticatorService } from '../services/authenticator.service';
import { Subscription } from 'rxjs';

@Component({
   selector: 'app-show-recovery',
   standalone: true,
   templateUrl: './showrecovery.component.html',
   styleUrl: './showrecovery.component.scss',
   imports: [MatIconModule, MatButtonModule, ClipboardModule, RouterLink,
      MatInputModule, MatFormFieldModule, CommonModule,
   ],
})
export class ShowRecoveryComponent implements OnInit, OnDestroy, AfterViewInit {

   public recoveryLink = '';
   private authSub!: Subscription;

   constructor(
      private r2: Renderer2,
      private authSvc: AuthenticatorService,
      private router: Router,
      private snackBar: MatSnackBar) {
   }

   ngOnInit(): void {
      if (this.authSvc.isAuthenticated()) {
         this.recoveryLink = this.authSvc.getRecoveryLink();
      }
      this.authSub = this.authSvc.on(
         [AuthEvent.Logout],
         () => this.router.navigateByUrl('/')
      );
   }

   ngAfterViewInit(): void {
      try {
         this.r2.selectRootElement('#linkInput').focus();
      } catch (err) {
         console.error(err);
      }
   }

   ngOnDestroy(): void {
      if (this.authSub) {
         this.authSub.unsubscribe();
      }
   }

   toastMessage(msg: string): void {
      this.snackBar.open(msg, '', {
         duration: 2000,
      });
   }
}
