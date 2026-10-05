/* MIT License

Copyright (c) 2025-2026 Brad Schick

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
   Renderer2,
   ElementRef,
   type OnInit,
   type AfterViewInit,
   type OnDestroy,
   SecurityContext,
   inject,
   signal,
   viewChild,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { makeCipherArmor, parseCipherArmor, PWDKeyProvider } from '@qcrypt/crypto';

import { MatDialog, MatDialogRef } from '@angular/material/dialog';
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
import { CdkAccordionModule } from '@angular/cdk/accordion';
import { MatExpansionModule } from '@angular/material/expansion';
import { ClipboardModule } from '@angular/cdk/clipboard';
import { environment } from '../../environments/environment';
import * as cc from '@qcrypt/crypto/consts';
import { CipherService, type CipherDataInfo } from '../services/cipher.service';
import {
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
   makeTookMsg,
} from '@qcrypt/crypto';
import { AuthenticatorService, AuthEvent, type AuthEventData } from '../services/authenticator.service';
import { PasswordDialog, CipherInfoDialog, SigninDialog } from '../ui/dialogs/dialogs';
import { BubbleDirective } from '../ui/bubble/bubble.directive';
import { NoAssistDirective } from '../ui/noassist.directive';
import { OptionsComponent } from '../ui/options/options.component';
import { Router } from '@angular/router';

const INJECTED_WARNING = 'Content was copied from the address bar. Please confirm its validity.';
const BLOCK_ORDER_WARNING =
   'Protocol version 4 does not detect block manipulation. Please confirm the result is correct and re-encrypt with the current version.';

@Component({
   selector: 'app-core',
   templateUrl: './core.component.html',
   styleUrl: './core.component.scss',
   host: {
      '(document:visibilitychange)': 'visibilitychange()',
   },
   imports: [
      MatProgressSpinnerModule,
      MatMenuModule,
      MatIconModule,
      MatButtonModule,
      MatFormFieldModule,
      MatInputModule,
      FormsModule,
      ClipboardModule,
      CdkAccordionModule,
      MatSlideToggleModule,
      MatExpansionModule,
      MatSelectModule,
      MatButtonToggleModule,
      MatTooltipModule,
      BubbleDirective,
      NoAssistDirective,
      OptionsComponent,
   ],
})
export class CoreComponent implements OnInit, AfterViewInit, OnDestroy {
   private readonly _authSvc = inject(AuthenticatorService);
   private readonly _cipherSvc = inject(CipherService);
   private readonly _r2 = inject(Renderer2);
   private readonly _dialog = inject(MatDialog);
   private readonly _snackBar = inject(MatSnackBar);
   private readonly _matIconRegistry = inject(MatIconRegistry);
   private readonly _domSanitizer = inject(DomSanitizer);
   private readonly _router = inject(Router);

   private _clearFile?: File;
   protected readonly cipherFile = signal<File | undefined>(undefined);
   private readonly _useFilePicker = browserSupportsFilePickers();
   private readonly _useByteStream = browserSupportsBytesStream();

   private _signinDialogRef?: MatDialogRef<SigninDialog>;
   private _mouseDown = false;
   private _cachedPassword?: Uint8Array;
   private _cachedHint?: Uint8Array;
   private _intervalId = 0;
   private _spinnerAbove = 1500000; // Default since benchmark is async
   private _actionStart = 0;
   private readonly _destroyRef = inject(DestroyRef);
   private _usedPasswords: string[] = [];
   private _cacheTimeout = 0;
   protected readonly clearText = signal('');
   protected readonly pwdCached = signal(false);
   protected readonly cipherLabel = signal('Cipher Armor');
   protected readonly clearLabel = signal('Clear Text');
   protected readonly cipherArmor = signal('');
   protected readonly showProgress = signal(false);
   private _usingFile = false;
   protected readonly cipherMsg = signal('');
   protected readonly cipherMsgClass = signal('errorBox');
   protected readonly clearMsg = signal('');
   protected readonly clearMsgClass = signal('errorBox');
   protected readonly secondsRemaining = signal(0);
   private _welcomed: boolean = true;
   protected readonly clearWarning = signal('');
   protected readonly cipherWarning = signal('');

   readonly clearField = viewChild.required<ElementRef>('clearField');
   readonly cipherField = viewChild.required<ElementRef>('cipherField');
   readonly inputArea = viewChild.required<ElementRef>('inputArea');
   readonly fileUpload = viewChild.required<ElementRef>('fileUpload');
   readonly bubbleTip1 = viewChild.required<BubbleDirective>('bubbleTip1');
   readonly bubbleTip2 = viewChild.required<BubbleDirective>('bubbleTip2');
   readonly bubbleTip3 = viewChild.required<BubbleDirective>('bubbleTip3');
   readonly options = viewChild.required<OptionsComponent>('options');

   constructor() {
      this._matIconRegistry.addSvgIcon(
         'encrypted_add',
         this._domSanitizer.bypassSecurityTrustResourceUrl('../assets/encrypted_add_circle.svg'),
      );
      this._matIconRegistry.addSvgIcon(
         'encrypted_minus',
         this._domSanitizer.bypassSecurityTrustResourceUrl('../assets/encrypted_minus_circle.svg'),
      );
   }

   private async _showTextFromParams() {
      await this.options().optionsLoaded();

      const params = new HttpParams({ fromString: window.location.search });
      if (params.get('cipherarmor')) {
         const cipherData = parseCipherArmor(params.get('cipherarmor')!);
         this.cipherWarning.set(INJECTED_WARNING);
         this._showCipherData(cipherData);
      }
      if (params.get('cleartext')) {
         this.clearWarning.set(INJECTED_WARNING);
         this._showClearText(decodeURIComponent(params.get('cleartext')!));
      }
   }

   ngAfterViewInit() {
      if (this._authSvc.hasSession()) {
         this._showTextFromParams();
         if (localStorage.getItem(`${this._authSvc.userId}welcomed`) !== 'yup') {
            setTimeout(() => {
               this._welcomed = false;
               this.bubbleTip1().show();
            }, 500);
         }
      }

      // Make this async to avoid ExpressionChangedAfterItHasBeenCheckedError errors
      setTimeout(() => {
         try {
            this._r2.selectRootElement('#clearInput').focus();
         } catch (err) {
            console.error(err);
         }
      }, 0);
   }

   ngOnInit() {
      // This can be greatly delayed is there is a long running async benchmark or
      // encrpt or decrypt from a previous instance (tab that has not fully closed).
      // Seems to be no way to prevent that or abort an ongoing SubtleCrypto action.
      this._cipherSvc.benchmark(cc.ICOUNT_MIN).then(([_icount, _icountMax, hashRate]) => {
         // progress spinner about 1.25 secs of estimated delay
         const target_spinner_millis = 1250;
         this._spinnerAbove = Math.round(target_spinner_millis * hashRate);
      });

      // subscribe to auth events
      this._authSvc
         .on([AuthEvent.Logout, AuthEvent.Forget, AuthEvent.Login, AuthEvent.Delete])
         .pipe(takeUntilDestroyed(this._destroyRef))
         .subscribe((data) => this._onAuthEvent(data));

      // core.guard doesn't allow reaching this point if the
      // user is unknown, If not authenticated, ask the user
      // to sign in
      this._trySigninDialog();
   }

   ngOnDestroy() {
      if (this._signinDialogRef) {
         this._signinDialogRef.close();
         this._signinDialogRef = undefined;
      }
   }

   private _onAuthEvent(data: AuthEventData) {
      if (data.event === AuthEvent.Login) {
         this.options().loadOptions(data.userId!);
         this._showTextFromParams();
      } else if (data.event === AuthEvent.Logout || data.event === AuthEvent.Forget) {
         // Dismiss first, so nothing failing below can leave a dialog over the stop page
         if (this._authSvc.halted) {
            this._dialog.closeAll();
         }
         this.privacyClear();
         this.onClearCipher();
         if (data.event === AuthEvent.Logout) {
            this.options().detachOptions();
            this._trySigninDialog();
         } else {
            this.options().nukeSensitiveOptions();
            this._router.navigateByUrl('/welcome');
         }
      } else if (data.event === AuthEvent.Delete) {
         localStorage.removeItem(`${data.userId}welcomed`);
         this.options().nukeAllOptions();
      }
   }

   private async _trySigninDialog(): Promise<void> {
      // Signing in again would only repeat whatever caused the halt
      if (!this._signinDialogRef && !this._authSvc.halted) {
         // This check prevents showing progreess when there is no
         // valid session, aka nothing to wait for (like when a new tab is opened)
         if (this._authSvc.potentialSession()) {
            // no-op if ready is resolved
            this.showProgress.set(true);
            await this._authSvc.ready;
            this.showProgress.set(false);
         }

         // happens when another tab does forget or changes passkey
         if (!this._authSvc.validKnownUser()) {
            this._router.navigateByUrl('/welcome');
         } else if (!this._authSvc.hasSession()) {
            this._signinDialogRef = this._dialog.open(SigninDialog, {
               backdropClass: 'signinBackdrop',
               closeOnNavigation: true,
            });

            this._signinDialogRef.afterClosed().subscribe((result: string) => {
               this._signinDialogRef = undefined;
               if (result === 'Login') {
                  this._r2.selectRootElement('#clearInput').focus();
               }
            });
         }
      }
   }

   private _timerTick() {
      if (Date.now() > this._cacheTimeout) {
         this.privacyClear();
      }
      let result = 0;
      if (this.pwdCached()) {
         result = Math.max(0, Math.round((this._cacheTimeout - Date.now()) / 1000));
      }
      this.secondsRemaining.set(result);
   }

   private _restartTimer() {
      if (this._intervalId !== 0) {
         clearInterval(this._intervalId);
         this._intervalId = 0;
      }

      this._cacheTimeout = Date.now() + this.options().cacheTime * 1000;
      this.secondsRemaining.set(this.options().cacheTime);

      // @ts-ignore
      this._intervalId = setInterval(() => this._timerTick(), 1000);
   }

   private _clearPassword() {
      this.pwdCached.set(false);
      if (this._cachedPassword) {
         this._cachedPassword.fill(0);
         this._cachedPassword = undefined;
      }
      if (this._cachedHint) {
         this._cachedHint.fill(0);
         this._cachedHint = undefined;
      }
      if (this._intervalId !== 0) {
         clearInterval(this._intervalId);
         this._intervalId = 0;
      }
   }

   protected visibilitychange() {
      if (document.hidden && this.options().visClear) {
         this.privacyClear();
      }
   }

   protected onDraggerMouseDown() {
      this._mouseDown = true;
   }

   protected onDraggerMouseMove(event: MouseEvent) {
      if (this._mouseDown) {
         const pointerRelativeXpos = event.clientX - this.inputArea().nativeElement.offsetLeft;
         const minWidth = 200;

         const areaWidth = this.inputArea().nativeElement.offsetWidth - 16; // 16 for the size of the drag area
         //      const clearWidth = this.clearField.nativeElement.offsetWidth;
         //      const cipherWidth = this.cipherField.nativeElement.offsetWidth;

         const newclearWidth = Math.max(minWidth, pointerRelativeXpos - 8); // 8 to center in drag area

         this.clearField().nativeElement.style.flexGrow = newclearWidth / areaWidth;
         this.cipherField().nativeElement.style.flexGrow = (areaWidth - newclearWidth) / areaWidth;
      }
   }

   protected onDraggerMouseUp() {
      this._mouseDown = false;
   }

   protected onPwdOptionsChange() {
      this._clearPassword();
   }

   protected toastMessage(msg: string) {
      this._snackBar.open(msg, '', {
         duration: 2000,
      });
   }

   protected onClearCipher() {
      this.cipherMsg.set('');
      this.cipherFile.set(undefined);
      this.cipherArmor.set('');
      this.cipherLabel.set('Cipher Armor');
      this.cipherWarning.set('');
   }

   protected onClearClear() {
      this.clearMsg.set('');
      this._clearFile = undefined;
      this.clearText.set('');
      this.clearLabel.set('Clear Text');
      this.clearWarning.set('');
      if (!this._welcomed && this._authSvc.hasSession()) {
         this.bubbleTip1().show();
         this.bubbleTip2().hide();
         this.bubbleTip3().hide();
      }
   }

   protected onClearInput() {
      if (!this.clearText()) {
         this.clearWarning.set('');
      }
      if (!this._welcomed && this._authSvc.hasSession()) {
         if (this.clearText()) {
            this.bubbleTip1().hide();
            this.bubbleTip2().show();
         } else {
            this.bubbleTip1().show();
            this.bubbleTip2().hide();
         }
         this.bubbleTip3().hide();
      }
   }

   protected onCipherInput() {
      if (!this.cipherArmor()) {
         this.cipherWarning.set('');
      }
   }

   protected privacyClear() {
      this._clearPassword();
      this.onClearClear();
   }

   private async _passwordProvider(cdInfo: CipherDataInfo, encrypting: boolean): Promise<[string, string | undefined]> {
      if (cdInfo.ic === undefined) {
         throw new Error('Missing CipherDataInfo iter count');
      }

      let pwd: string;
      let hint: string | undefined;

      if (cdInfo.lp === 1) {
         this._usedPasswords = [];
      }

      if (this.pwdCached() && cdInfo.lpEnd === 1) {
         this._restartTimer();
         const decoder = new TextDecoder();
         [pwd, hint] = [decoder.decode(this._cachedPassword), decoder.decode(this._cachedHint)];
      } else {
         [pwd, hint] = await this._askForPassword(cdInfo, encrypting);
      }

      // Avoid briefly putting up spinner and disabling buttons
      if (cdInfo.ic > this._spinnerAbove || this._usingFile) {
         this.showProgress.set(true);
      }

      if (cdInfo.lp === cdInfo.lpEnd) {
         this._usedPasswords = [];
      } else {
         this._usedPasswords.push(pwd);
      }

      this._actionStart = Date.now();
      return [pwd, hint];
   }

   private async _askForPassword(cdInfo: CipherDataInfo, encrypting: boolean): Promise<[string, string]> {
      this._clearPassword();
      return new Promise((resolve, reject) => {
         const dialogRef = this._dialog.open(PasswordDialog, {
            data: {
               hint: cdInfo.hint,
               encrypting,
               minStrength: +this.options().minPwdStrength,
               hidePwd: this.options().hidePwd,
               loopCount: cdInfo.lp,
               loops: cdInfo.lpEnd,
               checkPwned: this.options().checkPwned,
               welcomed: this._welcomed,
               userName: this._authSvc.userName,
               cipherMode: cdInfo.alg,
               usedPasswords: [...this._usedPasswords],
            },
         });

         dialogRef.afterClosed().subscribe((result) => {
            if (!result) {
               // intentially do not rejct with "new Error()" so this isn't
               // caught as an error, just cancelation
               reject(new ProcessCancelled());
            } else {
               this._clearPassword();
               if (this.options().cacheTime > 0 && result[0] && cdInfo.lpEnd === 1) {
                  const encoder = new TextEncoder();
                  this._cachedPassword = encoder.encode(result[0]);
                  this._cachedHint = encoder.encode(result[1]);
                  this.pwdCached.set(true);
                  this._restartTimer();
               }
               resolve([result[0], result[1]]);
            }
         });
      });
   }

   private _setCipherFile(cipherFile: File, saved: boolean = false) {
      this.onClearCipher();
      this.cipherFile.set(cipherFile);
      const msg = saved ? 'file saved and ' : '';
      this._showCipherFile(`${msg}selected for decryption`, saved, cipherFile.name);
   }

   private _setClearFile(clearFile: File, saved: boolean = false) {
      this._clearFile = clearFile;
      const msg = saved ? 'file saved and ' : '';
      this._showClearFile(`${msg}selected for encryption`, saved, clearFile.name);

      if (!this._welcomed) {
         this.bubbleTip1().hide();
         this.bubbleTip2().show();
         this.bubbleTip3().hide();
      }
   }

   protected async onEncrypt(): Promise<void> {
      if (!this._clearFile && this.clearText().length < 1) {
         this.onClearClear();
         this._showCipherError('Missing clear text. Enter clear text or select a file, then encrypt');
         this._r2.selectRootElement('#clearInput').focus();
         return;
      }

      if (!this._authSvc.hasSession()) {
         this._showClearError('User not authenticated, try refreshing this page');
         return;
      }

      this._authSvc.activity();
      this.onClearCipher();

      if (!this._welcomed) {
         this.bubbleTip1().hide();
         this.bubbleTip2().hide();
         this.bubbleTip3().hide();
      }

      try {
         if (this.options().loops > 1) {
            // it's confusing to use cached password when looping so
            // start from scratch
            this._clearPassword();
         }

         const [clearStream, streamSize] = this._getClearStream();
         if (streamSize > cc.CLEAR_DATA_MAX_BYTES) {
            this._showCipherError(
               `Clear data must be smaller than ${Math.round(cc.CLEAR_DATA_MAX_BYTES / 1024 / 1024)} MB to display`,
               'Try Encrypt to File',
            );
            return;
         }

         const cipherStream = await this._makeCipherStream(clearStream);
         if (cipherStream) {
            const cipherData = await readStreamAll(cipherStream);
            this._showCipherDataAndTime(cipherData);
            this.toastMessage('Congratulations, data encrypted');
            if (!this._welcomed) {
               this.bubbleTip3().show();
               setTimeout(() => {
                  this.bubbleTip3().hide();
               }, 5000);
            }

            // it worked, so stop showing tips (setting this before next loop)
            this._welcomed = true;
            localStorage.setItem(`${this._authSvc.userId}welcomed`, 'yup');
         }

         /* A bit torn about always clearing this when not caching...
         if (completed && !this.pwdCached()) {
            this.onClearClear();
         }*/
      } catch (something) {
         this._usedPasswords = [];
         if (!ProcessCancelled.isProcessCancelled(something)) {
            console.error(something);
            let msg = 'Could not encrypt text';
            if (something instanceof Error) {
               msg += ` because:</br>${something.message}`;
            }
            this._showCipherError(msg);
         }
         if (!this._welcomed) {
            this.bubbleTip2().show();
         }
      } finally {
         this.showProgress.set(false);
         this._usingFile = false;
      }
   }

   protected async onEncryptToFile(): Promise<void> {
      if (!this._clearFile && this.clearText().length < 1) {
         this.onClearClear();
         this._showCipherError('Missing clear text.  Enter clear text or select a file, then encrypt');
         this._r2.selectRootElement('#clearInput').focus();
         return;
      }

      if (!this._authSvc.hasSession()) {
         this._showClearError('User not authenticated, try refreshing this page');
         return;
      }

      this._authSvc.activity();
      this.onClearCipher();

      if (!this._welcomed) {
         this.bubbleTip1().hide();
         this.bubbleTip2().hide();
         this.bubbleTip3().hide();
      }

      try {
         let baseName: string;

         if (this._clearFile) {
            baseName = this._clearFile.name;
         } else {
            baseName = 'armor';
         }

         if (this.options().loops > 1) {
            // it's confusing to use cached password when looping so
            // start from scratch
            this._clearPassword();
         }

         const [clearStream, streamSize] = this._getClearStream();
         this._usingFile = true;

         // Ordered like this to show file picker before password dialog(s)
         if (this._useFilePicker) {
            const saveFile = await selectWriteableQQFile(baseName);
            const writeable = await saveFile.createWritable();
            const cipherStream = await this._makeCipherStream(clearStream);

            await cipherStream.pipeTo(writeable);
            this._setCipherFile(await saveFile.getFile(), true);
            this.toastMessage('Data encrypted');
         } else {
            // Safari doesn't support byte steam or > 2G downloads
            if (!this._useByteStream && streamSize > 2 * 1024 * 1024 * 1024) {
               this._showCipherError(
                  'Your browser does not support files larger than 2 GB. Try Chrome, Firefox, or Edge.',
               );
            } else {
               const cipherStream = await this._makeCipherStream(clearStream);

               const response = new Response(cipherStream);
               const blob = await response.blob();
               this._fileDownload(`${baseName}.qq`, blob);
               this._showCipherFile('Encrypted file will be in your downloads folder', true);
               this.toastMessage('Data encrypted');
            }
         }

         // If the user got this far, stop showing tips
         this._welcomed = true;
         localStorage.setItem(`${this._authSvc.userId}welcomed`, 'yup');
      } catch (something) {
         if (!ProcessCancelled.isProcessCancelled(something)) {
            console.error(something);
            let msg = 'Could not encrypt text';
            if (something instanceof Error) {
               msg += ` because:</br>${something.message}`;
            }
            this._showCipherError(msg);
         }
         if (!this._welcomed) {
            this.bubbleTip2().show();
         }
      } finally {
         this.showProgress.set(false);
         this._usingFile = false;
      }
   }

   private _getClearStream(): [ReadableStream<Uint8Array>, number] {
      let size = 0;
      let clearStream: ReadableStream<Uint8Array>;

      if (this._clearFile) {
         size = this._clearFile.size;
         clearStream = this._clearFile.stream();
         this._usingFile = true;
      } else {
         const clearData = new TextEncoder().encode(this.clearText());
         size = clearData.byteLength;
         const blob = new Blob([clearData], { type: 'application/octet-stream' });
         clearStream = blob.stream();
      }

      return [clearStream, size];
   }

   // Return value is false if the process was aborted
   private async _makeCipherStream(clearStream: ReadableStream<Uint8Array>): Promise<ReadableStream<Uint8Array>> {
      const econtext = {
         algs: this.options().algorithms,
         ic: this.options().icount,
      };

      // PWDKeyProvider takes ownershp of userCred
      const keyProvider = new PWDKeyProvider(await this._authSvc.getUserCred(), (cdInfo, encrypting) =>
         this._passwordProvider(cdInfo, encrypting),
      );
      return this._cipherSvc.encryptStream(clearStream, keyProvider, econtext);
   }

   protected async onDecrypt(): Promise<void> {
      if (!this.cipherFile() && this.cipherArmor().length < cc.HEADER_BYTES_6P + cc.PAYLOAD_SIZE_MIN) {
         this.onClearCipher();
         this._showClearError('Missing cipher armor. Enter cipher armor text or select a file, then decrypt');
         this._r2.selectRootElement('#cipherInput').focus();
         return;
      }

      if (!this._authSvc.hasSession()) {
         this._showClearError('User not authenticated, try refreshing this page');
         return;
      }

      this._authSvc.activity();
      this.onClearClear();

      try {
         const [cipherStream, size] = await this._getCipherStream();
         if (size > cc.CLEAR_DATA_MAX_BYTES) {
            this._showClearError(
               `Cipher data must be smaller than ${Math.round(cc.CLEAR_DATA_MAX_BYTES / 1024 / 1024)} MB to display`,
               'Try Decrypt to File',
            );
            return;
         }

         const clearStream = await this._makeClearStream(cipherStream);
         if (clearStream) {
            this._showClearTextAndTime(await readStreamAll(clearStream, true));
            this.toastMessage('Data decrypted');
         }
      } catch (something) {
         if (!ProcessCancelled.isProcessCancelled(something)) {
            console.error(something);
            this._clearPassword();
            this._showClearError(
               'Could not decrypt cipher armor text. You may be using the wrong password or passkey, or the cipher armor is invalid',
            );
         }
      } finally {
         this.showProgress.set(false);
         this._usingFile = false;
      }
   }

   protected async onDecryptToFile(): Promise<void> {
      const cipherFile = this.cipherFile();
      if (!cipherFile && this.cipherArmor().length < 1) {
         this.onClearCipher();
         this._showClearError('Missing cipher armor. Enter cipher armor text or select a file, then decrypt');
         this._r2.selectRootElement('#cipherInput').focus();
         return;
      }

      if (!this._authSvc.hasSession()) {
         this._showClearError('User not authenticated, try refreshing this page');
         return;
      }

      this._authSvc.activity();
      this.onClearClear();

      try {
         let baseName: string;

         if (cipherFile) {
            if (cipherFile.type.includes('json') && cipherFile.size > cc.CLEAR_DATA_MAX_BYTES) {
               // limited because it will all be read into memory at once
               this._showClearError(
                  `File must be smaller than ${Math.round(cc.CLEAR_DATA_MAX_BYTES / 1024 / 1024)} MB`,
               );
               return;
            }
            const re = /^(.*[\\/])?(\.*.*?)(\.[^.]+?|)$/;
            baseName = re.exec(cipherFile.name)![2];
            if (baseName.startsWith('armor.')) {
               baseName = 'clear';
            }
         } else {
            if (this.cipherArmor().length > cc.CLEAR_DATA_MAX_BYTES) {
               // limited because it will all be read into memory at once
               this._showClearError(
                  `Data must be smaller than ${Math.round(cc.CLEAR_DATA_MAX_BYTES / 1024 / 1024)} MB`,
               );
               return;
            }
            baseName = 'clear';
         }

         const [cipherStream, streamSize] = await this._getCipherStream();
         this._usingFile = true;

         if (this._useFilePicker) {
            const saveFile = await selectWriteableFile(baseName);
            const writeable = await saveFile.createWritable();
            const clearStream = await this._makeClearStream(cipherStream);

            await clearStream.pipeTo(writeable);
            this._setClearFile(await saveFile.getFile(), true);
            this.toastMessage('Data decrypted');
         } else {
            // This indicates Safari, which also doesn't support > 2G downloads
            if (!this._useByteStream && streamSize > 2 * 1024 * 1024 * 1024) {
               this._showClearError(
                  'Your browser does not support files larger than 2 GB. Try Chrome, Firefox, or Edge.',
               );
            } else {
               const clearStream = await this._makeClearStream(cipherStream);

               const response = new Response(clearStream);
               const blob = await response.blob();
               this._fileDownload(baseName, blob);
               this._showClearFile('Decrypted file will be in your downloads folder', true);
               this.toastMessage('Data decrypted');
            }
         }
      } catch (something) {
         if (!ProcessCancelled.isProcessCancelled(something)) {
            console.error(something);
            this._clearPassword();
            this._showClearError(
               'Could not decrypt cipher armor text. You may be using the wrong password or passkey, or the cipher armor is invalid',
            );
         }
      } finally {
         this.showProgress.set(false);
         this._usingFile = false;
      }
   }

   private async _getCipherStream(): Promise<[ReadableStream<Uint8Array>, number]> {
      let size = 0;
      let cipherStream: ReadableStream<Uint8Array>;
      const cipherFile = this.cipherFile();

      if (cipherFile && !cipherFile.type.includes('json')) {
         size = cipherFile.size;
         cipherStream = cipherFile.stream();
         this._usingFile = true;
      } else {
         let cipherArmor: string;
         if (cipherFile) {
            // It is a json file that contains plain text cipher armor. Don't count
            // as "usingFile" since size is limited
            cipherArmor = await readStreamAll(cipherFile.stream(), true);
         } else {
            cipherArmor = this.cipherArmor();
         }

         const cipherData = parseCipherArmor(cipherArmor);
         size = cipherData.byteLength;
         const blob = new Blob([cipherData], { type: 'application/octet-stream' });
         cipherStream = blob.stream();
      }

      return [cipherStream, size];
   }

   private async _makeClearStream(cipherStream: ReadableStream<Uint8Array>): Promise<ReadableStream<Uint8Array>> {
      // PWDKeyProvider takes ownershp of userCred
      const keyProvider = new PWDKeyProvider(await this._authSvc.getUserCred(), (cdInfo, encrypting) =>
         this._passwordProvider(cdInfo, encrypting),
      );
      return await this._cipherSvc.decryptStream(cipherStream, keyProvider, (ver, multiBlock) => {
         if (ver === cc.VERSION4 && multiBlock) {
            this.clearWarning.set(BLOCK_ORDER_WARNING);
         }
      });
   }

   private _showClearError(msg: string, hdr: string | null = null): void {
      this._showClearMsg('errorBox', 'Error', msg, hdr);
   }

   private _showClearFile(msg: string, took: boolean, hdr: string | null = null): void {
      const label = took ? `File (${makeTookMsg(this._actionStart, Date.now())})` : 'File';
      this._showClearMsg('fileBox', label, msg, hdr);
   }

   private _showClearMsg(cls: string, label: string, msg: string, hdr: string | null = null): void {
      //      this._clearFile = undefined;
      this.clearText.set('');
      let clearMsg = '';

      if (hdr) {
         const safeHdr = this._domSanitizer.sanitize(SecurityContext.HTML, hdr);
         clearMsg += `<b>${safeHdr}</b><br />`;
      }
      if (msg) {
         const safeMsg = this._domSanitizer.sanitize(SecurityContext.HTML, msg);
         clearMsg += safeMsg;
      }
      this.clearMsg.set(clearMsg);
      this.clearMsgClass.set(cls);
      this.clearLabel.set(`Clear Text ${label}`);
   }

   private _showClearText(clearText: string, extra: string = ''): void {
      this.clearText.set(clearText);
      this._clearFile = undefined;
      this.clearMsg.set('');
      this.clearLabel.set(`Clear Text ${extra}`);
   }

   private _showClearTextAndTime(clearText: string): void {
      const tookMsg = makeTookMsg(this._actionStart, Date.now());
      this._showClearText(clearText, `(${tookMsg})`);
   }

   private _showCipherError(msg: string, hdr: string | null = null): void {
      this._showCipherMsg('errorBox', 'Error', msg, hdr);
   }

   private _showCipherFile(msg: string, took: boolean, hdr: string | null = null): void {
      const label = took ? `File (${makeTookMsg(this._actionStart, Date.now())})` : 'File';
      this._showCipherMsg('fileBox', label, msg, hdr);
   }

   private _showCipherMsg(cls: string, label: string, msg: string, hdr: string | null = null): void {
      this.cipherArmor.set('');
      let cipherMsg = '';

      if (hdr) {
         const safeHdr = this._domSanitizer.sanitize(SecurityContext.HTML, hdr);
         cipherMsg += `<b>${safeHdr}</b><br />`;
      }
      if (msg) {
         const safeMsg = this._domSanitizer.sanitize(SecurityContext.HTML, msg);
         cipherMsg += safeMsg;
      }
      this.cipherMsg.set(cipherMsg);
      this.cipherMsgClass.set(cls);
      this.cipherLabel.set(`Cipher Armor ${label}`);
   }

   private _showCipherData(cipherData: Uint8Array, extra: string = ''): void {
      const cipherArmor = makeCipherArmor(cipherData, this.options().format, this.options().reminder, environment.host);
      this.cipherArmor.set(cipherArmor);
      this.cipherFile.set(undefined);
      this.cipherMsg.set('');
      this.cipherLabel.set(`Cipher Armor ${extra}`);
   }

   private _showCipherDataAndTime(cipherData: Uint8Array): void {
      const tookMsg = makeTookMsg(this._actionStart, Date.now());
      this._showCipherData(cipherData, `(${tookMsg})`);
   }

   protected onFormatOptionsChange() {
      this._reformatCipherArmor();
   }

   private _reformatCipherArmor() {
      if (this.cipherArmor()) {
         try {
            const cipherData = parseCipherArmor(this.cipherArmor());
            this._showCipherData(cipherData);
         } catch (err) {
            console.error(err);
         }
      }
   }

   protected onClickFileUpload(event: MouseEvent) {
      // needed to clear previous value so that onchange fires
      (event.target as HTMLInputElement).value = '';
   }

   protected async onLoadCipherFile() {
      if (this._useFilePicker) {
         this._cipherFilePicker();
      } else {
         this._cipherFileLoader();
      }
   }

   private async _cipherFilePicker() {
      const fileHandle = await selectCipherFile();
      if (fileHandle) {
         this._setCipherFile(await fileHandle.getFile());
      }
   }

   private async _cipherFileLoader() {
      const fileUpload = this.fileUpload();
      fileUpload.nativeElement.onchange = (event: Event) => {
         const file = (event.target as HTMLInputElement).files?.[0];
         if (file) {
            this._setCipherFile(file);
         }
      };
      fileUpload.nativeElement.click();
   }

   protected async onLoadClearFile() {
      if (this._useFilePicker) {
         this._clearFilePicker();
      } else {
         this._clearFileLoader();
      }
   }

   private async _clearFilePicker() {
      const fileHandle = await selectClearFile();
      if (fileHandle) {
         this.onClearClear();
         this._setClearFile(await fileHandle.getFile());
      }
   }

   private async _clearFileLoader() {
      const fileUpload = this.fileUpload();
      fileUpload.nativeElement.onchange = (event: Event) => {
         const file = (event.target as HTMLInputElement).files?.[0];
         if (file) {
            this.onClearClear();
            this._setClearFile(file);
         }
      };
      fileUpload.nativeElement.click();
   }

   private _fileDownload(filename: string, blob: Blob): void {
      const alink = document.createElement('a');
      alink.style.display = 'none';
      document.body.appendChild(alink);

      alink.href = URL.createObjectURL(blob);
      alink.download = filename;
      alink.click();

      document.body.removeChild(alink);
   }

   protected async onSaveCipherFile(): Promise<void> {
      if (this._useFilePicker) {
         const saveFile = await selectWriteableJsonFile('armor');
         const writeable = await saveFile.createWritable();
         await writeable.write(this.cipherArmor());
         await writeable.close();
      } else {
         const buffer = new TextEncoder().encode(this.cipherArmor());
         const blob = new Blob([buffer], { type: 'text/plain;charset=utf-8' });
         this._fileDownload('armor.json', blob);
      }
   }

   protected async onSaveClearFile(): Promise<void> {
      if (this._useFilePicker) {
         const saveFile = await selectWriteableTxtFile('clear');
         const writeable = await saveFile.createWritable();
         await writeable.write(this.clearText());
         await writeable.close();
      } else {
         const buffer = new TextEncoder().encode(this.clearText());
         const blob = new Blob([buffer], { type: 'text/plain;charset=utf-8' });
         this._fileDownload('clear.txt', blob);
      }
   }

   protected onCacheTimeChange(_cacheTime: number): void {
      if (this.pwdCached()) {
         this._restartTimer();
      }
   }

   protected async onCipherTextInfo(): Promise<void> {
      try {
         if (!this._authSvc.hasSession()) {
            throw new Error('User not authenticated, try refreshing this page');
         }

         const cdInfo = await this._getCipherDataInfo();
         this._dialog.open(CipherInfoDialog, { data: cdInfo });
      } catch (err) {
         console.error(err);
         this._dialog.open(CipherInfoDialog, { data: null });
      }
   }

   // note that we aren't checking plain text cipher armor for loops because
   // it was never used in the wild
   private async _getCipherDataInfo(): Promise<CipherDataInfo> {
      if (!this._authSvc.hasSession()) {
         throw new Error('User not authenticated, try refreshing this page');
      }

      const [cipherStream, size] = await this._getCipherStream();
      if (size < cc.HEADER_BYTES_6P + cc.PAYLOAD_SIZE_MIN) {
         throw new Error('Missing cipher armor');
      }

      // PWDKeyProvider takes ownershp of userCred
      const keyProvider = new PWDKeyProvider(await this._authSvc.getUserCred());
      return await this._cipherSvc.getCipherStreamInfo(cipherStream, keyProvider);
   }
}
