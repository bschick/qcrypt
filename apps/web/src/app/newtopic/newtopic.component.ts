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
   ViewChild,
   ViewChildren,
   QueryList,
   inject
} from '@angular/core';

import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatSnackBar } from '@angular/material/snack-bar';
import { ClipboardModule } from '@angular/cdk/clipboard';
import { Router, RouterLink } from '@angular/router';
import { MatTableModule } from '@angular/material/table';
import { MatInputModule } from '@angular/material/input';
import { MatSlideToggleModule } from '@angular/material/slide-toggle';
import { MatFormFieldModule } from '@angular/material/form-field';
import { AuthEvent, AuthenticatorService, SenderLinkInfo } from '../services/authenticator.service';
import { Subscription } from 'rxjs';
import { base64URLStringToBuffer, bufferToBase64URLString } from '@qcrypt/crypto';
import { OptionsComponent } from '../ui/options/options.component';
import { MatTooltipModule } from '@angular/material/tooltip';
import { FormControl, ReactiveFormsModule, FormBuilder, Validators, FormsModule } from '@angular/forms';
import {MatTabsModule} from '@angular/material/tabs';
import {MatStepperModule} from '@angular/material/stepper';
import { MatButtonToggle } from "@angular/material/button-toggle";
import { MatButtonToggleModule } from '@angular/material/button-toggle';
import { EditableComponent } from '../ui/editable/editable.component';
import { StepperSelectionEvent } from '@angular/cdk/stepper';
import * as api from '@qcrypt/api';

export type ParticipantInfo = {
   invitableId: string;
   description?: string;
   error?: boolean;
};

@Component({
   selector: 'app-new-topic',
   templateUrl: './newtopic.component.html',
   styleUrl: './newtopic.component.scss',
   imports: [MatIconModule, MatButtonModule, ClipboardModule, RouterLink, MatInputModule,
    MatFormFieldModule, OptionsComponent, MatTableModule, ReactiveFormsModule,
    MatTooltipModule, MatTabsModule, MatStepperModule, MatButtonToggleModule,
    MatButtonToggle, EditableComponent, MatSlideToggleModule]

})
export class NewTopicComponent implements OnInit, OnDestroy, AfterViewInit {

   public participants: ParticipantInfo[] = [];
   public displayedColumns: string[] = ['invitableId', 'description', 'delete'];
   private authSub!: Subscription;
   public descriptionInput = new FormControl('');
   public participantsControl = new FormControl('all');
   public forkToggle = new FormControl(false);


   private _formBuilder = inject(FormBuilder);
   public readonly TOPIC_USERS_MAX = api.TOPIC_USERS_MAX;

   // firstFormGroup = this._formBuilder.group({
   //    firstCtrl: ['', Validators.required],
   // });
   newTopicForm = this._formBuilder.group({
      topicUsers: [1, [Validators.required, Validators.min(1), Validators.max(this.TOPIC_USERS_MAX)]],
   });

   participantsError(): string {
      const ctrl = this.newTopicForm.get('topicUsers');
      if (ctrl?.hasError('min')) {
         return 'Must be at least 1';
      } else if (ctrl?.hasError('max')) {
         return `Must be less than ${this.TOPIC_USERS_MAX + 1}`;
      } else { 
         return '';
      }
   }

   @ViewChild('options') options!: OptionsComponent;
   @ViewChildren(EditableComponent) editables!: QueryList<EditableComponent>;

   constructor(
      private authSvc: AuthenticatorService,
      private router: Router,
      private snackBar: MatSnackBar) {

   }

   ngOnInit(): void {

      // this.participants.push({
      //    invitableId: "",
      //    description: ''
      // });

      this.authSub = this.authSvc.on(
         [AuthEvent.Logout],
         () => this.router.navigateByUrl('/')
      );
   }

   ngAfterViewInit(): void {
   }

   onSubmit(): void {
      console.log('submit');
   }

   onStepChange(event: StepperSelectionEvent): void {
      if (event.selectedIndex === 1) {
         if (this.participants.length === 0) {
            this.onClickAdd();
         } else {
            // Wait for the step animation and DOM render to finish before focusing
            setTimeout(() => {
               if (!this.editables.last?.value) {
                  this.editables.last?.focus();
               }
            }, 0);
         }
      }
   }

   ngOnDestroy(): void {
      if (this.authSub) {
         this.authSub.unsubscribe();
      }
   }

   onClickDelete(index: number) {
      this.participants = this.participants.filter((_, i) => i !== index);
   }

   onClickAdd() {
      this.participants = [...this.participants, {
         invitableId: '',
         description: ''
      }];
      
      setTimeout(() => {
         this.editables.last.focus();
      }, 0);
   }

   async onInvitableIdChanged(
      component: EditableComponent, 
      participant: ParticipantInfo
   ): Promise<void> {
      try {
         participant.error = false;
         participant.invitableId = component.value.trim();
         if( participant.invitableId ) {
            const invitableInfo = await this.authSvc.getInvitableInfo(participant.invitableId);
            participant.description = invitableInfo.description!
            this.toastMessage('Passkey description updated');
         } else {
            participant.description = '';
         }
      } catch (err) {
         console.error(err);
         participant.description = 'Invalid Participant Id';
         participant.error = true;
      }
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
