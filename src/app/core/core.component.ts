/* MIT License

Copyright (c) 2024 Brad Schick

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
   Renderer2,
   ViewChild,
   ElementRef,
   OnInit, AfterViewInit,
   OnDestroy,
   ChangeDetectorRef,
   HostListener,
   SecurityContext,
   NgZone,
} from '@angular/core';
import { makeCipherArmor, parseCipherArmor } from './armor';
import { CommonModule } from '@angular/common';
import { MatDialog, MatDialogRef } from '@angular/material/dialog';
import { MatRippleModule } from '@angular/material/core';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatInputModule } from '@angular/material/input';
import { MatFormFieldModule } from '@angular/material/form-field';
import { FormsModule } from '@angular/forms';
import { MatMenuModule } from '@angular/material/menu';
import { MatSelectModule } from '@angular/material/select';
import { MatIconModule } from '@angular/material/icon';
import { MatIconRegistry } from '@angular/material/icon';
import { DomSanitizer } from '@angular/platform-browser';
import { MatButtonModule } from '@angular/material/button';
import { MatButtonToggleModule } from '@angular/material/button-toggle';
import { MatSlideToggleModule } from '@angular/material/slide-toggle';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatSnackBar } from '@angular/material/snack-bar';
import { HttpParams } from '@angular/common/http';
import { DateTime } from 'luxon';
import { CdkAccordionModule } from '@angular/cdk/accordion';
import { MatExpansionModule } from '@angular/material/expansion';
import { ClipboardModule } from '@angular/cdk/clipboard';
import * as cc from '../services/cipher.consts';
import { CipherService, CipherDataInfo } from '../services/cipher.service';
import {
   base64ToBytes,
   browserSupportsFilePickers,
   readStreamAll,
   selectWriteableFile,
   selectWriteableJsonFile,
   selectWriteableQQFile,
   selectWriteableTxtFile,
   selectCipherFile,
   selectClearFile,
   browserSupportsBytesStream,
   ProcessCancelled,
   makeTookMsg
} from '../services/utils';
import { AuthenticatorService, AuthEvent, AuthEventData } from '../services/authenticator.service';
import {
   PasswordDialog,
   CipherInfoDialog,
   SigninDialog,
} from './core.dialogs';
import { BubbleDirective } from '../ui/bubble/bubble.directive';
import { OptionsComponent } from '../ui/options/options.component';
import { Subscription } from 'rxjs';
import { CopyrightComponent } from "../ui/copyright/copyright.component";


@Component({
   selector: 'app-core',
   templateUrl: './core.component.html',
   styleUrl: './core.component.scss',
   imports: [MatProgressSpinnerModule, MatMenuModule, MatIconModule,
      MatButtonModule, MatFormFieldModule, MatInputModule, FormsModule,
      ClipboardModule, CdkAccordionModule, MatSlideToggleModule,
      MatExpansionModule, MatSelectModule, MatButtonToggleModule,
      MatTooltipModule, MatRippleModule, CommonModule, BubbleDirective,
      OptionsComponent, CopyrightComponent]
})
export class CoreComponent implements OnInit, AfterViewInit, OnDestroy {

   protected clearFile?: File;
   protected cipherFile?: File;
   protected readonly useFilePicker = browserSupportsFilePickers();
   protected readonly useByteStream = browserSupportsBytesStream();

   private signinDialogRef?: MatDialogRef<SigninDialog, any>
   private mouseDown = false;
   private cachedPassword = '';
   private cachedHint = '';
   private intervalId = 0;
   private spinnerAbove = 1500000; // Default since benchmark is async
   private actionStart = 0;
   private authSub!: Subscription;
   public cacheTimeout!: DateTime;
   public clearText = '';
   public pwdCached = false;
   public cipherLabel = 'Cipher Armor';
   public clearLabel = 'Clear Text';
   public cipherArmor = '';
   public showProgress = false;
   public usingFile = false;
   public cipherMsg = '';
   public cipherMsgClass = 'errorBox';
   public clearMsg = '';
   public clearMsgClass = 'errorBox';
   public secondsRemaining = 0;
   public welcomed: boolean = true;

   //  @ViewChild(MatRipple) ripple: MatRipple;
   @ViewChild('clearField') clearField!: ElementRef;
   @ViewChild('cipherField') cipherField!: ElementRef;
   @ViewChild('inputArea') inputArea!: ElementRef;
   @ViewChild('fileUpload') fileUpload!: ElementRef;
   @ViewChild('formatLabel') formatLabel!: ElementRef;
   @ViewChild('minStrLabel') minStrLabel!: ElementRef;
   @ViewChild('bubbleTip1') bubbleTip1!: BubbleDirective;
   @ViewChild('bubbleTip2') bubbleTip2!: BubbleDirective;
   @ViewChild('options') options!: OptionsComponent;

   constructor(
      private authSvc: AuthenticatorService,
      private cipherSvc: CipherService,
      private r2: Renderer2,
      private dialog: MatDialog,
      private snackBar: MatSnackBar,
      private matIconRegistry: MatIconRegistry,
      private domSanitizer: DomSanitizer,
      private changeRef: ChangeDetectorRef,
      private ngZone: NgZone
   ) {
      this.matIconRegistry.addSvgIcon(
         'github',
         this.domSanitizer.bypassSecurityTrustResourceUrl(
            '../assets/github-circle-white-transparent.svg'
         )
      );
      this.matIconRegistry.addSvgIcon(
         'encrypted_add',
         this.domSanitizer.bypassSecurityTrustResourceUrl(
            '../assets/encrypted_add_circle.svg'
         )
      );
      this.matIconRegistry.addSvgIcon(
         'encrypted_minus',
         this.domSanitizer.bypassSecurityTrustResourceUrl(
            '../assets/encrypted_minus_circle.svg'
         )
      );
   }

   async showTextFromParams() {
      await this.options.optionsLoaded();

      const params = new HttpParams({ fromString: window.location.search });
      if (params.get('cipherarmor')) {
         const cipherData = parseCipherArmor(params.get('cipherarmor')!);
         this.showCipherData(cipherData);
      }
      if (params.get('cleartext')) {
         this.showClearText(decodeURIComponent(params.get('cleartext')!));
      }
   }

   ngAfterViewInit() {
      if (this.authSvc.authenticated()) {
         this.showTextFromParams();
         if (localStorage.getItem(this.authSvc.userId + "welcomed") != 'yup') {
            setTimeout(() => {
               this.welcomed = false;
               this.bubbleTip1.show();
            }, 1000);
         }
      }

      try {
         // Make this async to avoid ExpressionChangedAfterItHasBeenCheckedError errors
         setTimeout(
            () => this.r2.selectRootElement('#clearInput').focus(), 0
         );
      } catch (err) {
         console.error(err);
      }
   }

   ngOnInit() {
      // This can be greatly delayed is there is a long running async benchmark or
      // encrpt or decrypt from a previous instance (tab that has not fully closed).
      // Seems to be no way to prevent that or abort an ongoing SubtleCrypto action.
      this.cipherSvc.benchmark(cc.ICOUNT_MIN)
         .then(([icount, icountMax, hashRate]) => {
            // progress spinner about 1.25 secs of estimated delay
            const target_spinner_millis = 1250;
            this.spinnerAbove = Math.round(target_spinner_millis * hashRate)
         });

      // subscribe to auth events
      this.authSub = this.authSvc.on(
         [AuthEvent.Logout, AuthEvent.Login, AuthEvent.Delete],
         this.onAuthEvent.bind(this)
      );

      // core.guard doesn't allow reaching this point if the
      // user is unknown, If not authenticated, ask the user
      // to sign in
      this.trySigninDialog();
   }

   ngOnDestroy() {
      if (this.authSub) {
         this.authSub.unsubscribe();
      }
      if (this.signinDialogRef) {
         this.signinDialogRef.close();
         this.signinDialogRef = undefined;
      }
   }

   onAuthEvent(data: AuthEventData) {
      if (data.event === AuthEvent.Login) {
         this.options.loadOptions();
         this.showTextFromParams();
      } else if (data.event === AuthEvent.Logout) {
         this.options.defaultOptions();
         this.privacyClear();
         this.onClearCipher();
         this.trySigninDialog();
      } else if (data.event === AuthEvent.Delete) {
         localStorage.removeItem(data.userId + "welcomed");
         this.options.nukeOptions();
      }
   }

   async trySigninDialog(): Promise<void> {
      if (!this.signinDialogRef) {
         if(this.authSvc.validSession()) {
            // noop if ready is resolved
            this.showProgress = true;
            await this.authSvc.ready;
            this.showProgress = false;
         }

         if(!this.authSvc.authenticated()) {
            this.signinDialogRef = this.dialog.open(SigninDialog, {
               backdropClass: 'signinBackdrop',
               closeOnNavigation: true
            });

            this.signinDialogRef.afterClosed().subscribe((result:string) => {
               this.signinDialogRef = undefined;
               if (result === 'Login') {
                  this.r2.selectRootElement('#clearInput').focus();
               }
            });
         }
      }
   }

   timerTick() {
      if (DateTime.now() > this.cacheTimeout) {
         this.privacyClear();
      }
      let result = 0;
      if (this.pwdCached) {
         const diff = this.cacheTimeout.diff(DateTime.now());
         result = Math.max(0, Math.round(diff.toMillis() / 1000));
      }
      if (result != this.secondsRemaining) {
         // Do this to avoid setting a template value after it has been checked,
         // which triggers an ExpressionChangedAfterItHasBeenCheckedError
         this.secondsRemaining = result;
         this.changeRef.detectChanges();
      }
   }

   restartTimer() {
      if (this.intervalId != 0) {
         clearInterval(this.intervalId);
         this.intervalId = 0;
      }

      this.cacheTimeout = DateTime.now().plus({ seconds: this.options.cacheTime });
      this.secondsRemaining = this.options.cacheTime;

      // @ts-ignore
      this.intervalId = setInterval(() => this.timerTick(), 1000);
   }

   clearPassword() {
      this.pwdCached = false;
      this.cachedPassword = '';
      this.cachedHint = '';
      if (this.intervalId != 0) {
         clearInterval(this.intervalId);
         this.intervalId = 0;
      }
   }

   @HostListener('document:visibilitychange', ['$event'])
   visibilitychange() {
      if (document.hidden && this.options.visClear) {
         this.privacyClear();
      }
   }

   onDraggerMouseDown() {
      this.mouseDown = true;
   }

   onDraggerMouseMove(event: MouseEvent) {
      if (this.mouseDown) {
         var pointerRelativeXpos =
            event.clientX - this.inputArea.nativeElement.offsetLeft;
         const minWidth = 200;

         const areaWidth = this.inputArea.nativeElement.offsetWidth - 16; // 16 for the size of the drag area
         //      const clearWidth = this.clearField.nativeElement.offsetWidth;
         //      const cipherWidth = this.cipherField.nativeElement.offsetWidth;

         var newclearWidth = Math.max(minWidth, pointerRelativeXpos - 8); // 8 to center in drag area

         this.clearField.nativeElement.style.flexGrow = newclearWidth / areaWidth;
         this.cipherField.nativeElement.style.flexGrow =
            (areaWidth - newclearWidth) / areaWidth;
      }
   }

   onDraggerMouseUp() {
      this.mouseDown = false;
   }

   onPwdOptionsChange() {
      this.clearPassword();
   }

   toastMessage(msg: string) {
      this.snackBar.open(msg, '', {
         duration: 2000,
      });
   }

   onClearCipher() {
      this.cipherMsg = '';
      this.cipherFile = undefined;
      this.cipherArmor = '';
      this.cipherLabel = 'Cipher Armor';
   }

   onClearClear() {
      this.clearMsg = '';
      this.clearFile = undefined;
      this.clearText = '';
      this.clearLabel = 'Clear Text';
      if (!this.welcomed && this.authSvc.authenticated()) {
         this.bubbleTip1.show();
         this.bubbleTip2.hide();
      }
   }

   onClearInput() {
      if (!this.welcomed && this.authSvc.authenticated()) {
         this.bubbleTip1.hide();
         this.bubbleTip2.show();
      }
   }

   privacyClear() {
      this.clearPassword();
      this.onClearClear();
   }

   async passwordProvider(
      cdInfo: CipherDataInfo,
      encrypting: boolean
   ): Promise<[string, string | undefined]> {

      let pwdResult: [string, string | undefined];
      if (this.pwdCached && cdInfo.lpEnd == 1) {
         this.restartTimer();
         pwdResult = [this.cachedPassword, this.cachedHint];
      } else {
         //-1 minStrength means no pwd strength requirments
         pwdResult = await this.askForPassword(cdInfo, encrypting);
      }

      // This can run outside of Angular's zone because the  callback
      // comes from within streem connections
      this.ngZone.run(() => {
         // Avoid briefly putting up spinner and disabling buttons
         if (cdInfo.ic > this.spinnerAbove || this.usingFile) {
            this.showProgress = true;
         }
      });

      this.actionStart = Date.now();
      return pwdResult;
   }

   async askForPassword(
      cdInfo: CipherDataInfo,
      encrypting: boolean
   ): Promise<[string, string]> {

      this.clearPassword();
      return new Promise((resolve, reject) => {
         // This can run outside of Angular's zone because the password callback
         // comes from within streem connections
         this.ngZone.run(() => {
            let dialogRef = this.dialog.open(PasswordDialog, {
               data: {
                  hint: cdInfo.hint,
                  encrypting: encrypting,
                  minStrength: +this.options.minPwdStrength,
                  hidePwd: this.options.hidePwd,
                  loopCount: cdInfo.lp,
                  loops: cdInfo.lpEnd,
                  checkPwned: this.options.checkPwned,
                  welcomed: this.welcomed,
                  userName: this.authSvc.userName,
                  cipherMode: cdInfo.alg
               },
            });

            dialogRef.afterClosed().subscribe((result) => {
               if (!result) {
                  // intentially do not rejct with "new Error()" so this isn't
                  // caught as an error, just cancelation
                  reject(new ProcessCancelled());
               } else {
                  this.clearPassword();
                  if (this.options.cacheTime > 0 && result[0] && cdInfo.lpEnd == 1) {
                     this.cachedPassword = result[0];
                     this.cachedHint = result[1];
                     this.pwdCached = true;
                     this.restartTimer();
                  }
                  resolve([result[0], result[1]]);
               }
            });
         });
      });
   }

   setCipherFile(cipherFile: File, saved: boolean = false) {
      this.onClearCipher();
      this.cipherFile = cipherFile;
      let msg = saved ? 'file saved and ' : '';
      this.showCipherFile(msg + 'selected for decryption', saved, cipherFile.name);
   }

   setClearFile(clearFile: File, saved: boolean = false) {
      this.onClearClear();
      this.clearFile = clearFile;
      let msg = saved ? 'file saved and ' : '';
      this.showClearFile(msg + 'selected for encryption', saved, clearFile.name);

      if (!this.welcomed) {
         this.bubbleTip1.hide();
         this.bubbleTip2.show();
      }
   }

   async onEncrypt(): Promise<void> {
      if ((!this.clearFile && this.clearText.length < 1)) {
         this.onClearClear();
         this.showCipherError('Missing clear text. Enter clear text or select a file, then encrypt');
         this.r2.selectRootElement('#clearInput').focus();
         return;
      }

      if (!this.authSvc.authenticated()) {
         this.showClearError('User not authenticated, try refreshing this page');
         return;
      }

      this.authSvc.activity();
      this.onClearCipher();

      if (!this.welcomed) {
         this.bubbleTip1.hide();
         this.bubbleTip2.hide();
      }

      try {
         if (this.options.loops > 1) {
            // it's confusing to use cached password when looping so
            // start from scratch
            this.clearPassword();
         }

         const [clearStream, streamSize] = this.getClearStream();
         if (streamSize > cc.CLEAR_DATA_MAX_BYTES) {
            this.showCipherError(
               `Clear data must be smaller than ${Math.round(cc.CLEAR_DATA_MAX_BYTES / 1024 / 1024)} MB to display`,
               'Try Encrypt to File');
            return;
         }

         const cipherStream = await this.makeCipherStream(clearStream);
         if (cipherStream) {
            const cipherData = await readStreamAll(cipherStream);
            this.showCipherDataAndTime(cipherData);
            this.toastMessage('Congratulations, data encrypted');

            // it worked, so stop showing tips (setting this before next loop)
            this.welcomed = true;
            localStorage.setItem(this.authSvc.userId + "welcomed", "yup");
         }

         /* A bit torn about always clearing this when not caching...
         if (completed && !this.pwdCached) {
            this.onClearClear();
         }*/
      } catch (something) {
         if (!ProcessCancelled.isProcessCancelled(something)) {
            console.error(something);
            let msg = 'Could not encrypt text';
            if (something instanceof Error) {
               msg += ` because:</br>${something.message}`;
            }
            this.showCipherError(msg);
         }
         if (!this.welcomed) {
            this.bubbleTip2.show();
         }
      } finally {
         this.showProgress = false;
         this.usingFile = false;
      }
   }

   async onEncryptToFile(): Promise<void> {
      if ((!this.clearFile && this.clearText.length < 1)) {
         this.onClearClear();
         this.showCipherError('Missing clear text.  Enter clear text or select a file, then encrypt');
         this.r2.selectRootElement('#clearInput').focus();
         return;
      }

      if (!this.authSvc.authenticated()) {
         this.showClearError('User not authenticated, try refreshing this page');
         return;
      }

      this.authSvc.activity();
      this.onClearCipher();

      if (!this.welcomed) {
         this.bubbleTip1.hide();
         this.bubbleTip2.hide();
      }

      try {
         let baseName: string;

         if (this.clearFile) {
            baseName = this.clearFile.name;
         } else {
            baseName = 'armor';
         }

         if (this.options.loops > 1) {
            // it's confusing to use cached password when looping so
            // start from scratch
            this.clearPassword();
         }

         const [clearStream, streamSize] = this.getClearStream();
         this.usingFile = true;

         // Ordered like this to show file picker before password dialog(s)
         if (this.useFilePicker) {
            const saveFile = await selectWriteableQQFile(baseName);
            const writeable = await saveFile.createWritable();
            const cipherStream = await this.makeCipherStream(clearStream);

            await cipherStream.pipeTo(writeable);
            this.setCipherFile(await saveFile.getFile(), true);
            this.toastMessage('Data encrypted');
         } else {
            // Safari doesn't support byte steam or > 2G downloads
            if (!this.useByteStream && streamSize > 2 * 1024 * 1024 * 1024) {
               this.showCipherError('Your browser does not support files larger than 2 GB. Try Chrome, Firefox, or Edge.');
            } else {
               const cipherStream = await this.makeCipherStream(clearStream);

               const response = new Response(cipherStream);
               const blob = await response.blob();
               this.fileDownload(baseName + '.qq', blob);
               this.showCipherFile('Encrypted file will be in your downloads folder', true);
               this.toastMessage('Data encrypted');
            }
         }

         // If the user got this far, stop showing tips
         this.welcomed = true;
         localStorage.setItem(this.authSvc.userId + "welcomed", "yup");

      } catch (something) {
         if (!ProcessCancelled.isProcessCancelled(something)) {
            console.error(something);
            let msg = 'Could not encrypt text';
            if (something instanceof Error) {
               msg += ` because:</br>${something.message}`;
            }
            this.showCipherError(msg);
         }
         if (!this.welcomed) {
            this.bubbleTip2.show();
         }
      } finally {
         this.showProgress = false;
         this.usingFile = false;
      }
   }

   getClearStream(): [ReadableStream<Uint8Array>, number] {
      let size = 0;
      let clearStream: ReadableStream<Uint8Array>;

      if (this.clearFile) {
         size = this.clearFile.size;
         clearStream = this.clearFile.stream();
         this.usingFile = true;
      } else {
         const clearData = new TextEncoder().encode(this.clearText);
         size = clearData.byteLength;
         const blob = new Blob([clearData], { type: 'application/octet-stream' });
         clearStream = blob.stream();
      }

      return [clearStream, size];
   }

   // Return value is false if the process was aborted
   async makeCipherStream(
      clearStream: ReadableStream<Uint8Array>
   ): Promise<ReadableStream<Uint8Array>> {

      const econtext = {
         // Need to slice because modes length is the max number of modes
         // that have been set, which may be larger than the current # of loops
         algs: this.options.algorithms,
         ic: this.options.icount
      };

      return this.cipherSvc.encryptStream(
         econtext,
         this.passwordProvider.bind(this),
         base64ToBytes(this.authSvc.userCred!),
         clearStream
      );
   }

   async onDecrypt(): Promise<void> {
      if ((!this.cipherFile && this.cipherArmor.length < (cc.HEADER_BYTES + cc.PAYLOAD_SIZE_MIN))) {
         this.onClearCipher();
         this.showClearError('Missing cipher armor. Enter cipher armor text or select a file, then decrypt');
         this.r2.selectRootElement('#cipherInput').focus();
         return;
      }

      if (!this.authSvc.authenticated()) {
         this.showClearError('User not authenticated, try refreshing this page');
         return;
      }

      this.authSvc.activity();
      this.onClearClear();

      try {
         const [cipherStream, size] = await this.getCipherStream();
         if (size > cc.CLEAR_DATA_MAX_BYTES) {
            this.showClearError(
               `Cipher data must be smaller than ${Math.round(cc.CLEAR_DATA_MAX_BYTES / 1024 / 1024)} MB to display`,
               'Try Decrypt to File');
            return;
         }

         const clearStream = await this.makeClearStream(cipherStream);
         if (clearStream) {
            this.showClearTextAndTime(await readStreamAll(clearStream, true));
            this.toastMessage('Data decrypted');
         }
      } catch (something) {
         if (!ProcessCancelled.isProcessCancelled(something)) {
            console.error(something);
            this.clearPassword();
            this.showClearError(
               'Could not decrypt cipher armor text. You may be using the wrong password or passkey, or the cipher armor is invalid'
            );
         }
      } finally {
         this.showProgress = false;
         this.usingFile = false;
      }
   }

   async onDecryptToFile(): Promise<void> {
      if ((!this.cipherFile && this.cipherArmor.length < 1)) {
         this.onClearCipher();
         this.showClearError('Missing cipher armor. Enter cipher armor text or select a file, then decrypt');
         this.r2.selectRootElement('#cipherInput').focus();
         return;
      }

      if (!this.authSvc.authenticated()) {
         this.showClearError('User not authenticated, try refreshing this page');
         return;
      }

      this.authSvc.activity();
      this.onClearClear();

      try {
         let baseName: string;

         if (this.cipherFile) {
            if (this.cipherFile.type.includes('json') && this.cipherFile.size > cc.CLEAR_DATA_MAX_BYTES) {
               // limited because it will all be read into memory at once
               this.showClearError(`File must be smaller than ${Math.round(cc.CLEAR_DATA_MAX_BYTES / 1024 / 1024)} MB`);
               return;
            }
            const re = /^(.*[\\/])?(\.*.*?)(\.[^.]+?|)$/;
            baseName = re.exec(this.cipherFile.name)![2];
            if (baseName.startsWith('armor.')) {
               baseName = 'clear';
            }
         } else {
            if (this.cipherArmor.length > cc.CLEAR_DATA_MAX_BYTES) {
               // limited because it will all be read into memory at once
               this.showClearError(`Data must be smaller than ${Math.round(cc.CLEAR_DATA_MAX_BYTES / 1024 / 1024)} MB`);
               return;
            }
            baseName = 'clear';
         }

         const [cipherStream, streamSize] = await this.getCipherStream();
         this.usingFile = true;

         if (this.useFilePicker) {
            const saveFile = await selectWriteableFile(baseName);
            const writeable = await saveFile.createWritable();
            const clearStream = await this.makeClearStream(cipherStream);

            await clearStream.pipeTo(writeable);
            this.setClearFile(await saveFile.getFile(), true);
            this.toastMessage('Data decrypted');

         } else {
            // This indicates Safari, which also doesn't support > 2G downloads
            if (!this.useByteStream && streamSize > 2 * 1024 * 1024 * 1024) {
               this.showClearError('Your browser does not support files larger than 2 GB. Try Chrome, Firefox, or Edge.');
            } else {
               const clearStream = await this.makeClearStream(cipherStream);

               const response = new Response(clearStream);
               const blob = await response.blob();
               this.fileDownload(baseName, blob);
               this.showClearFile('Decrypted file will be in your downloads folder', true);
               this.toastMessage('Data decrypted');
            }
         }
      } catch (something) {
         if (!ProcessCancelled.isProcessCancelled(something)) {
            console.error(something);
            this.clearPassword();
            this.showClearError(
               'Could not decrypt cipher armor text. You may be using the wrong password or passkey, or the cipher armor is invalid'
            );
         }
      } finally {
         this.showProgress = false;
         this.usingFile = false;
      }
   }

   async getCipherStream(): Promise<[ReadableStream<Uint8Array>, number]> {

      let size = 0;
      let cipherStream: ReadableStream<Uint8Array>;

      if (this.cipherFile && !this.cipherFile.type.includes('json')) {
         size = this.cipherFile.size;
         cipherStream = this.cipherFile.stream();
         this.usingFile = true;
      } else {
         let cipherArmor: string;
         if (this.cipherFile) {
            // It is a json file that contains plain text cipher armor. Don't count
            // as "usingFile" since size is limited
            cipherArmor = await readStreamAll(this.cipherFile.stream(), true);
         } else {
            cipherArmor = this.cipherArmor;
         }

         const cipherData = parseCipherArmor(cipherArmor);
         size = cipherData.byteLength;
         const blob = new Blob([cipherData], { type: 'application/octet-stream' });
         cipherStream = blob.stream();
      }

      return [cipherStream, size];
   }

   async makeClearStream(
      cipherStream: ReadableStream<Uint8Array>
   ): Promise<ReadableStream<Uint8Array>> {

      return await this.cipherSvc.decryptStream(
         this.passwordProvider.bind(this),
         base64ToBytes(this.authSvc.userCred!),
         cipherStream
      );
   }

   showClearError(msg: string, hdr: string | null = null): void {
      this.showClearMsg('errorBox', 'Error', msg, hdr);
   }

   showClearFile(msg: string, took: boolean, hdr: string | null = null): void {
      const label = took ? `File (${makeTookMsg(this.actionStart, Date.now())})` : 'File';
      this.showClearMsg('fileBox', label, msg, hdr);
   }

   showClearMsg(cls: string, label: string, msg: string, hdr: string | null = null): void {
      //      this.clearFile = undefined;
      this.clearText = '';
      this.clearMsg = '';

      if (hdr) {
         const safeHdr = this.domSanitizer.sanitize(SecurityContext.HTML, hdr);
         this.clearMsg += `<b>${safeHdr}</b><br />`;
      }
      if (msg) {
         const safeMsg = this.domSanitizer.sanitize(SecurityContext.HTML, msg);
         this.clearMsg += safeMsg;
      }
      this.clearMsgClass = cls;
      this.clearLabel = 'Clear Text ' + label;
   }

   showClearText(clearText: string, extra: string = ''): void {
      this.clearText = clearText;
      this.clearFile = undefined;
      this.clearMsg = '';
      this.clearLabel = 'Clear Text ' + extra;
   }

   showClearTextAndTime(clearText: string): void {
      const tookMsg = makeTookMsg(this.actionStart, Date.now());
      this.showClearText(clearText, `(${tookMsg})`);
   }

   showCipherError(msg: string, hdr: string | null = null): void {
      this.showCipherMsg('errorBox', 'Error', msg, hdr);
   }

   showCipherFile(msg: string, took: boolean, hdr: string | null = null): void {
      const label = took ? `File (${makeTookMsg(this.actionStart, Date.now())})` : 'File';
      this.showCipherMsg('fileBox', label, msg, hdr);
   }

   showCipherMsg(cls: string, label: string, msg: string, hdr: string | null = null): void {
      this.cipherArmor = '';
      this.cipherMsg = '';

      if (hdr) {
         const safeHdr = this.domSanitizer.sanitize(SecurityContext.HTML, hdr);
         this.cipherMsg += `<b>${safeHdr}</b><br />`;
      }
      if (msg) {
         const safeMsg = this.domSanitizer.sanitize(SecurityContext.HTML, msg);
         this.cipherMsg += safeMsg;
      }
      this.cipherMsgClass = cls;
      this.cipherLabel = 'Cipher Armor ' + label;
   }

   showCipherData(cipherData: Uint8Array, extra: string = ''): void {
      const cipherArmor = makeCipherArmor(cipherData, this.options.format, this.options.reminder);
      this.cipherArmor = cipherArmor;
      this.cipherFile = undefined;
      this.cipherMsg = '';
      this.cipherLabel = 'Cipher Armor ' + extra;
   }

   showCipherDataAndTime(cipherData: Uint8Array): void {
      const tookMsg = makeTookMsg(this.actionStart, Date.now());
      this.showCipherData(cipherData, `(${tookMsg})`);
   }

   onFormatOptionsChange() {
      this.reformatCipherArmor();
   }

   reformatCipherArmor() {
      if (this.cipherArmor) {
         try {
            const cipherData = parseCipherArmor(this.cipherArmor);
            this.showCipherData(cipherData);
         } catch (err) {
            console.error(err);
         }
      }
   }

   onClickFileUpload(event: any) {
      // needed to clear previous value so that onchange fires
      event.target.value = '';
   }

   async onLoadCipherFile() {
      if (this.useFilePicker) {
         this.cipherFilePicker();
      } else {
         this.cipherFileLoader();
      }
   }

   async cipherFilePicker() {
      const fileHandle = await selectCipherFile();
      if (fileHandle) {
         this.setCipherFile(await fileHandle.getFile());
      }
   }

   async cipherFileLoader() {
      this.fileUpload.nativeElement.onchange = (event: any) => {
         const file: File = event.target.files[0];
         if (file) {
            this.setCipherFile(file);
         }
      };
      this.fileUpload.nativeElement.click();
   }

   async onLoadClearFile() {
      if (this.useFilePicker) {
         this.clearFilePicker();
      } else {
         this.clearFileLoader();
      }
   }

   async clearFilePicker() {
      const fileHandle = await selectClearFile();
      if (fileHandle) {
         this.setClearFile(await fileHandle.getFile());
      }
   }

   async clearFileLoader() {
      this.fileUpload.nativeElement.onchange = (event: any) => {
         const file: File = event.target.files[0];
         if (file) {
            this.setClearFile(file);
         }
      };
      this.fileUpload.nativeElement.click();
   }

   fileDownload(filename: string, blob: Blob): void {
      let alink = document.createElement('a');
      alink.style.display = 'none';
      document.body.appendChild(alink);

      alink.href = URL.createObjectURL(blob);
      alink.download = filename;
      alink.click();

      document.body.removeChild(alink);
   }

   async onSaveCipherFile(): Promise<void> {
      if (this.useFilePicker) {
         const saveFile = await selectWriteableJsonFile("armor");
         const writeable = await saveFile.createWritable();
         await writeable.write(this.cipherArmor);
         writeable.close();
      } else {
         const buffer = new TextEncoder().encode(this.cipherArmor);
         const blob = new Blob([buffer], { type: 'text/plain;charset=utf-8' });
         this.fileDownload('armor.json', blob);
      }
   }

   async onSaveClearFile(): Promise<void> {
      if (this.useFilePicker) {
         const saveFile = await selectWriteableTxtFile("clear");
         const writeable = await saveFile.createWritable();
         await writeable.write(this.clearText);
         writeable.close();
      } else {
         const buffer = new TextEncoder().encode(this.clearText);
         const blob = new Blob([buffer], { type: 'text/plain;charset=utf-8' });
         this.fileDownload('clear.txt', blob);
      }
   }

   onCacheTimeChange(cacheTime: number): void {
      if (this.pwdCached) {
         this.restartTimer();
      }
   }

   async onCipherTextInfo(): Promise<void> {
      try {
         if (!this.authSvc.authenticated()) {
            throw new Error('User not authenticated, try refreshing this page')
         }

         const cdInfo = await this.getCipherDataInfo();
         this.dialog.open(CipherInfoDialog, { data: cdInfo });
      } catch (err) {
         console.error(err);
         this.dialog.open(CipherInfoDialog, { data: null });
      }
   }

   // note that we aren't checking plain text cipher armor for loops because
   // the original version of loop decryption is broken (don't think it was
   // ever used in the wild)
   async getCipherDataInfo(): Promise<CipherDataInfo> {
      if (!this.authSvc.authenticated()) {
         throw new Error('User not authenticated, try refreshing this page')
      }

      const [cipherStream, size] = await this.getCipherStream();
      if (size < cc.HEADER_BYTES + cc.PAYLOAD_SIZE_MIN) {
         throw new Error('Missing cipher armor');
      }
      return await this.cipherSvc.getCipherStreamInfo(
         base64ToBytes(this.authSvc.userCred!),
         cipherStream
      );
   }

   algDescription(alg: string): string {
      return this.cipherSvc.algDescription(alg);
   }
}

