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
import { MatCardModule } from '@angular/material/card';

@Component({
   selector: 'app-show-recovery',
   templateUrl: './showrecovery.component.html',
   styleUrl: './showrecovery.component.scss',
   imports: [MatIconModule, MatButtonModule, ClipboardModule, RouterLink,
      MatInputModule, MatFormFieldModule, MatCardModule, CommonModule
   ]
})
export class ShowRecoveryComponent implements OnInit, OnDestroy, AfterViewInit {

   public recoveryWords = '';
   public oldRecovery = false;
   private authSub!: Subscription;

   constructor(
      private r2: Renderer2,
      private authSvc: AuthenticatorService,
      private router: Router,
      private snackBar: MatSnackBar) {
   }

   ngOnInit(): void {
      if (this.authSvc.isAuthenticated()) {
         this.recoveryWords = this.authSvc.getRecoveryWords();
         this.oldRecovery =  this.authSvc.recoveryId.length > 0 ? false : true;
      }
      this.authSub = this.authSvc.on(
         [AuthEvent.Logout],
         () => this.router.navigateByUrl('/')
      );
   }

   ngAfterViewInit(): void {
      try {
         // Make this async to avoid ExpressionChangedAfterItHasBeenCheckedError errors
         setTimeout(
            () => this.r2.selectRootElement('#linkInput').focus(), 0
         );
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
