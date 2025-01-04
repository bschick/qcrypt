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
  selector: 'app-sender-link',
  templateUrl: './senderlink.component.html',
  styleUrl: './senderlink.component.scss',
  imports: [MatIconModule, MatButtonModule, ClipboardModule, RouterLink,
    MatInputModule, MatFormFieldModule, CommonModule,
]

})
export class SenderLinkComponent implements OnInit, OnDestroy, AfterViewInit {

  public senderLink = '';
  private authSub!: Subscription;

  constructor(
     private r2: Renderer2,
     private authSvc: AuthenticatorService,
     private router: Router,
     private snackBar: MatSnackBar) {
  }

  ngOnInit(): void {
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
