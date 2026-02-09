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
   effect,
   OnDestroy,
   OnInit,
   Renderer2,
   ViewChild
} from '@angular/core';
import sodium from 'libsodium-wrappers';


import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatSnackBar } from '@angular/material/snack-bar';
import { ClipboardModule } from '@angular/cdk/clipboard';
import { Router, RouterLink } from '@angular/router';
import { MatTableModule } from '@angular/material/table';
import { MatInputModule } from '@angular/material/input';
import { MatFormFieldModule } from '@angular/material/form-field';
import { AuthEvent, AuthenticatorService, SenderLinkInfo } from '../services/authenticator.service';
import { Subscription } from 'rxjs';
import { base64URLStringToBuffer, bufferToBase64URLString } from '../services/base64';
import { OptionsComponent } from '../ui/options/options.component'


//const seed = 'DcQc3_gNiK9ONmCjTM8xP2HiI0LVm6kwwkX_lrOCeH0=';

@Component({
   selector: 'app-sender-links',
   templateUrl: './senderlinks.component.html',
   styleUrl: './senderlinks.component.scss',
   imports: [MatIconModule, MatButtonModule, ClipboardModule, RouterLink, MatInputModule, MatFormFieldModule, OptionsComponent, MatTableModule]

})
export class SenderLinksComponent implements OnInit, OnDestroy, AfterViewInit {

   public senderLinks: SenderLinkInfo[] = [];
   public displayedColumns: string[] = ['description', 'encrypt', 'copy', 'delete'];
   private authSub!: Subscription;

   @ViewChild('options') options!: OptionsComponent;

   constructor(
      private r2: Renderer2,
      private authSvc: AuthenticatorService,
      private router: Router,
      private snackBar: MatSnackBar) {
      effect(() => {
         this.senderLinks = this.authSvc.senderLinks();
      });
   }

   ngOnInit(): void {
      this.senderLinks = this.authSvc.senderLinks();

      this.authSub = this.authSvc.on(
         [AuthEvent.Logout],
         () => this.router.navigateByUrl('/')
      );
   }

   ngAfterViewInit(): void {
   }

   ngOnDestroy(): void {
      if (this.authSub) {
         this.authSub.unsubscribe();
      }
   }

   onClickDelete(passkey: SenderLinkInfo) {
      alert(JSON.stringify(passkey));
   }

   async doit(): Promise<void> {


      /*
      this.message = 'hola';
      const seedBuf = base64URLStringToBuffer(seed);
      const keyPair = sodium.crypto_box_seed_keypair(new Uint8Array(seedBuf));

      console.log(`${keyPair.keyType}\n
         Private: ${bufferToBase64URLString(keyPair.privateKey.buffer)}\n
         Public: ${bufferToBase64URLString(keyPair.publicKey.buffer)}`
      );

      const keyPairR = sodium.crypto_box_keypair();

      const ct = sodium.crypto_box_seal("this is a message", keyPair.publicKey);
      console.log(`ciphertxt: ${bufferToBase64URLString(ct)}`);
*/
//      const clear = sodium.crypto_box_seal_open(ct, keyPair.publicKey, keyPair.privateKey);
  //    console.log(`cleartxt: ${new TextDecoder().decode(clear)}`);

/*      try {
         encryptedBytes = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
            clear,
            additionalData ?? null,
            null,
            iv,
            keyBytes,
            "uint8array"
         );
      } catch (err) {
         // Match behavior of Web Crytpo functions that throws limited DOMException
         const msg = err instanceof Error ? err.message : '';
         throw new DOMException(msg, 'OperationError ');
      }*/
   }

   toastMessage(msg: string): void {
      this.snackBar.open(msg, '', {
         duration: 2000,
      });
   }
}
