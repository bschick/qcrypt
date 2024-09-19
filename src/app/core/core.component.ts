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
   Inject,
   ViewChild,
   ElementRef,
   OnInit, AfterViewInit,
   PLATFORM_ID,
   OnDestroy,
   ChangeDetectorRef,
   HostListener,
   SecurityContext,
} from '@angular/core';
import { CommonModule } from '@angular/common';
import { MatDialog, MatDialogRef } from '@angular/material/dialog';
import { MatRippleModule } from '@angular/material/core';
import { MatTooltipModule } from '@angular/material/tooltip';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';
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
import { MatInputModule } from '@angular/material/input';
import { MatFormFieldModule } from '@angular/material/form-field';
import { HttpParams } from '@angular/common/http';
import { Duration, DateTime } from 'luxon';
import { CdkAccordionModule } from '@angular/cdk/accordion';
import { MatExpansionModule } from '@angular/material/expansion';
import { ClipboardModule } from '@angular/cdk/clipboard';
import { RouterLink } from '@angular/router';
import * as cc from '../services/cipher.consts';
import { CipherService, EParams, CipherDataInfo } from '../services/cipher.service';
import {
   base64ToBytes,
   browserSupportsFilePickers,
   bytesToBase64,
   readStreamAll,
   selectWriteableFile,
   selectWriteableJsonFile,
   selectWriteableQQFile,
   selectWriteableTxtFile,
   selectCipherFile,
   selectClearFile,
   browserSupportsBytesStream,
   ProcessCancelled
} from '../services/utils';
import { AuthenticatorService, AuthEvent, AuthEventData, INACTIVITY_TIMEOUT } from '../services/authenticator.service';
import {
   PasswordDialog,
   CipherInfoDialog,
   SigninDialog,
} from './core.dialogs';
import { BubbleDirective } from '../ui/bubble/bubble.directive';
import { Subscription } from 'rxjs';

const MAX_LOOPS = 10;
const TARGET_HASH_MILLIS = 500;
const MAX_HASH_MILLIS = 5 * 60 * 1000; //5 minutes

type Context = {
   readonly lpEnd: number;
   lp: number;
}

type EncContext = Context & {
   alg: string;
   ic: number;
   ctFormat: string;
   reminder: boolean;
   trueRand: boolean;
   fallbackRand: boolean;
   clearData?: Uint8Array;
};

type EncContext2 = Context & {
   alg: string;
   ic: number;
   ctFormat: string;
   reminder: boolean;
   trueRand: boolean;
   fallbackRand: boolean;
};

type DecContext = Context & {
   cipherData: Uint8Array;
};

function isDecContext(context: Context): context is DecContext {
   return (context as DecContext).cipherData !== undefined;
}

// Set only if num is betwee min and max (inclusive) when min and max are not null
function setIfBetween(
   check: string | null,
   min: number | null,
   max: number | null,
   setter: (num: number) => void
): void {
   const num = Number(check);
   if (check != null && !Number.isNaN(num)) {
      if ((min == null || num >= min) && (max == null || num <= max)) {
         setter(num);
      }
   }
}

function makeTookMsg(start: number, end: number, word: string = 'took'): string {
   const duration = Duration.fromMillis(end - start);
   if (duration.as('minutes') >= 1.1) {
      return `${word} ${Math.round(duration.as('minutes') * 10) / 10} minutes`;
   } else if (duration.as('seconds') >= 2) {
      return `${word} ${Math.round(duration.as('seconds'))} seconds`;
   }
   return `${word} ${duration.toMillis()} millis`;
}

function setIfBoolean(
   check: string | null,
   setter: (bool: boolean) => void
): void {
   if (check != null) {
      if (['true', '1', 'yes', 'on'].includes(check.toLowerCase())) {
         setter(true);
      } else if (['false', '0', 'no', 'off'].includes(check.toLowerCase())) {
         setter(false);
      }
   }
}

@Component({
   selector: 'app-core',
   standalone: true,
   templateUrl: './core.component.html',
   styleUrl: './core.component.scss',
   imports: [MatProgressSpinnerModule, MatMenuModule, MatIconModule,
      MatButtonModule, MatFormFieldModule, MatInputModule, FormsModule,
      ReactiveFormsModule, ClipboardModule, CdkAccordionModule, MatSlideToggleModule,
      MatExpansionModule, MatSelectModule, MatButtonToggleModule,
      MatTooltipModule, MatRippleModule, CommonModule, BubbleDirective,
      RouterLink,
   ],
})
export class CoreComponent implements OnInit, AfterViewInit, OnDestroy {

   protected clearFile?: File;
   protected cipherFile?: File;
   protected readonly useFilePicker = browserSupportsFilePickers();
   protected readonly useByteStream = browserSupportsBytesStream();

   private signinDialogRef?: MatDialogRef<SigninDialog, any>
   private optionsLoaded = false;
   private mouseDown = false;
   private cachedPassword = '';
   private cachedHint = '';
   private intervalId = 0;
   private spinnerAbove = 1500000; // Default since benchmark is async
   private actionStart = 0;
   private authSub!: Subscription;
   private lastReminder = true;
   public readonly INACTIVITY_TIMEOUT = INACTIVITY_TIMEOUT;
   public readonly LOOP_MAX = 10;
   public cacheTimeout!: DateTime;
   public icountMin: number = cc.ICOUNT_MIN;
   public icountMax: number = cc.ICOUNT_MAX; // Default since benchmark is async
   public icountDefault: number = cc.ICOUNT_DEFAULT; // Default since benchmark is async
   public hashTimeWarning = '';
   public clearText = '';
   public pwdCached = false;
   public cipherLabel = 'Cipher Armor';
   public clearLabel = 'Clear Text';
   public cipherArmor = '';
   public showProgress = false;
   public cipherMsg = '';
   public cipherMsgClass = 'errorBox';
   public clearMsg = '';
   public clearMsgClass = 'errorBox';
   public expandOptions = false;
   public cipherPanelExpanded = false;
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

   // options
   public algorithm = 'X20-PLY';
   public icount: number = cc.ICOUNT_DEFAULT; // Default since benchmark is async
   public hidePwd = true;
   public cacheTime = 0;
   public minPwdStrength = '3';
   public ctFormat = 'compact';
   public loops = 1;
   public checkPwned = false;
   public visibilityClear = true;
   public reminder = true;
   public trueRand = false;
   public pseudoRand = true;

   constructor(
      private authSvc: AuthenticatorService,
      private cipherSvc: CipherService,
      private r2: Renderer2,
      private dialog: MatDialog,
      private snackBar: MatSnackBar,
      private matIconRegistry: MatIconRegistry,
      private domSanitizer: DomSanitizer,
      private changeRef: ChangeDetectorRef,
      @Inject(PLATFORM_ID) private platformId: Object
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

   setAlgorithm(alg: string | null): void {
      if (this.cipherSvc.validateAlg(alg!)) {
         this.algorithm = alg!;
      }
   }

   setIcount(ic: string | null): void {
      // Ignores if out of range or NaN
      setIfBetween(ic, this.icountMin, this.icountMax, (num) => {
         this.icount = num;
      });
   }

   setHidePwd(hide: string | null) {
      setIfBoolean(hide, (bool) => {
         this.hidePwd = bool;
      });
   }

   setCacheTime(tm: string | null): void {
      setIfBetween(tm, 0, this.INACTIVITY_TIMEOUT, (num) => {
         this.cacheTime = num;
      });
   }

   setCheckPwned(check: string | null): void {
      setIfBoolean(check, (bool) => {
         this.checkPwned = bool;
      });
   }

   setMinPwdStrength(stren: string | null): void {
      if (['0', '1', '2', '3', '4'].includes(stren!)) {
         this.minPwdStrength = stren!;
      }
   }

   setLoops(lpEnd: string | null): void {
      setIfBetween(lpEnd, 1, this.LOOP_MAX, (num) => {
         this.loops = num;
      });
   }

   setCTFormat(ctFormat: string | null): void {
      if (['link', 'compact', 'indent'].includes(ctFormat!)) {
         this.ctFormat = ctFormat!;
      }
   }

   setReminder(reminder: string | null): void {
      setIfBoolean(reminder, (bool) => {
         this.reminder = bool;
         this.lastReminder = bool;
      });
   }

   setVisibilityClear(clear: string | null): void {
      setIfBoolean(clear, (bool) => {
         this.visibilityClear = bool;
      });
   }

   setTrueRand(trand: string | null): void {
      setIfBoolean(trand, (bool) => {
         this.trueRand = bool;
      });
   }

   setPseudoRand(prand: string | null): void {
      setIfBoolean(prand, (bool) => {
         this.pseudoRand = bool;
      });
   }

   lsGet(key: string): string | null {
      const [userId, _] = this.authSvc.getUserInfo();
      return localStorage.getItem(userId + key);
   }

   lsSet(key: string, value: string) {
      const [userId, _] = this.authSvc.getUserInfo();
      localStorage.setItem(userId + key, value);
   }

   lsDel(key: string) {
      const [userId, _] = this.authSvc.getUserInfo();
      localStorage.removeItem(userId + key);
   }

   setIcountWarning() {
      this.hashTimeWarning = '';
      const hashMillis = this.icount / this.cipherSvc.hashRate;

      // if greater than 15 seconds show message
      if (hashMillis > 15 * 1000) {
         const takeMsg = makeTookMsg(0, hashMillis, 'take');
         this.hashTimeWarning = `*password hash may ${takeMsg}`
      }
   }

   ngAfterViewInit() {
      // ugly hack to make angular not clip the label for dropdown select elements
      this.formatLabel.nativeElement.parentElement.style.maxWidth = "calc(100%/0.7)";
      this.minStrLabel.nativeElement.parentElement.style.maxWidth = "calc(100%/0.7)";

      if (this.authSvc.isAuthenticated() &&
         localStorage.getItem(this.authSvc.userId + "welcomed") != 'yup') {
         setTimeout(() => {
            this.welcomed = false;
            this.bubbleTip1.show();
         }, 1200);
      }
   }

   ngOnInit(): void {
      // This can be greatly delayed is there is a long running async benchmark or
      // encrpt or decrypt from a previous instance (tab that has not fully closed).
      // Seems to be no way to prevent that or abort an ongoing SubtleCrypto action.
      this.cipherSvc.benchmark(this.icountMin, TARGET_HASH_MILLIS, MAX_HASH_MILLIS)
         .then(([icount, icountMax, hashRate]) => {
            this.icount = icount;
            this.icountDefault = this.icount;
            this.icountMax = icountMax;

            // progress spinner about 1.25 secs of estimated delay
            const target_spinner_millis = 1250;
            this.spinnerAbove = Math.round(target_spinner_millis * hashRate)
         }).finally(() => {
            // load after benchmakr to overwrite icount with saved value
            if (this.authSvc.isAuthenticated()) {
               this.loadOptions();
            }
         });

      // subscribe to auth events
      this.authSub = this.authSvc.on(
         [AuthEvent.Logout, AuthEvent.Forget, AuthEvent.Login],
         this.onAuthEvent.bind(this)
      );

      // core.guard doesn't allow reaching this point if the
      // user is unknown, If not authenticated, ask the user
      // to sign in
      if (!this.authSvc.isAuthenticated()) {
         this.showSigninDialog();
      }
   }

   loadOptions() {
      // First check localStorage, then apply params (which take president)
      // (not that change are not presisted until the encrypt button is used)
      /* debug
      for (let i = 0; i < localStorage.length; i++) {
        let key = localStorage.key(i)!;
        console.log(`${key}: ${this.lsGet(key)}`);
       } */
      if (!this.optionsLoaded) {
         this.setAlgorithm(this.lsGet('algorithm'));
         this.setIcount(this.lsGet('icount'));
         this.setHidePwd(this.lsGet('hidepwd'));
         this.setCacheTime(this.lsGet('cachetime'));
         this.setCheckPwned(this.lsGet('checkpwned'));
         this.setMinPwdStrength(this.lsGet('minpwdstrength'));
         this.setLoops(this.lsGet('loops'));
         this.setCTFormat(this.lsGet('ctformat'));
         this.setVisibilityClear(this.lsGet('vclear'));
         this.setReminder(this.lsGet('reminder'));
         this.setTrueRand(this.lsGet('trand'));
         this.setPseudoRand(this.lsGet('prand'));

         let params = new HttpParams({ fromString: window.location.search });

         if (params.get('cipherarmor')) {
            this.showCipherArmor(decodeURIComponent(params.get('cipherarmor')!));
            this.onFormatChange();
            params = params.delete('cipherarmor');
         }
         if (params.get('cleartext')) {
            this.showClearText(decodeURIComponent(params.get('cleartext')!));
            params = params.delete('cleartext');
         }

         // If there are customized options, expand the panel by default
         if (params.keys().length > 0) {
            this.expandOptions = true;
         }

         this.setAlgorithm(params.get('algorithm'));
         this.setIcount(params.get('icount'));
         this.setHidePwd(params.get('hidepwd'));
         this.setCacheTime(params.get('cachetime'));
         this.setCheckPwned(params.get('checkpwned'));
         this.setMinPwdStrength(params.get('minpwdstrength'));
         this.setLoops(params.get('loops'));
         this.setCTFormat(params.get('ctformat'));
         this.setVisibilityClear(params.get('vclear'));
         this.setReminder(params.get('reminder'));
         this.setTrueRand(params.get('trand'));
         this.setPseudoRand(params.get('prand'));
         this.optionsLoaded = true;

         this.setIcountWarning();
      }
   }

   ngOnDestroy(): void {
      if (this.authSub) {
         this.authSub.unsubscribe();
      }
      if (this.signinDialogRef) {
         this.signinDialogRef.close();
         this.signinDialogRef = undefined;
      }
   }

   onAuthEvent(data: AuthEventData) {
      //      console.log('authevent ', data);
      if (data.event === AuthEvent.Logout) {
         this.resetOptions();
         this.onClearCipher();
         this.showSigninDialog();
      } else if (data.event === AuthEvent.Login) {
         this.loadOptions();
      }
   }

   showSigninDialog() {
      if (!this.signinDialogRef && this.authSvc.isUserKnown() && !this.authSvc.isAuthenticated()) {
         this.signinDialogRef = this.dialog.open(SigninDialog, {
            backdropClass: 'signinBackdrop',
            closeOnNavigation: true
         });
         this.signinDialogRef.afterClosed().subscribe(() => {
            this.signinDialogRef = undefined;
            if (this.authSvc.isAuthenticated()) {
               this.authSvc.refreshPasskeys().catch((err) => {
                  console.error(err);
               });
            }
         });
      }
   }

   onClickResetOptions(): void {
      this.nukeOptions();
   }

   resetOptions(): void {
      this.algorithm = 'X20-PLY';
      this.icount = this.icountDefault;
      this.hidePwd = true;
      this.cacheTime = 0;
      this.minPwdStrength = '3';
      this.checkPwned = false;
      this.loops = 1;
      this.ctFormat = 'compact';
      this.visibilityClear = true;
      this.reminder = true;
      this.lastReminder = true;
      this.trueRand = false;
      this.pseudoRand = true;

      this.clearPassword();
      this.saveOptions();
      this.optionsLoaded = false;
   }

   nukeOptions(): void {
      this.resetOptions();
      try {
         this.lsDel('welcomed');
         this.lsDel('algorithm');
         this.lsDel('icount');
         this.lsDel('hidepwd');
         this.lsDel('cachetime');
         this.lsDel('checkpwned');
         this.lsDel('minpwdstrength');
         this.lsDel('loops');
         this.lsDel('ctformat');
         this.lsDel('vclear');
         this.lsDel('reminder');
         this.lsDel('trand');
         this.lsDel('prand');
      } catch (err) {
         console.error(err);
         //otherwise ignore
      }
   }

   saveOptions(): void {
      try {
         if (this.authSvc.isAuthenticated()) {
            this.lsSet('algorithm', this.algorithm);
            this.lsSet('icount', this.icount.toString());
            this.lsSet('hidepwd', this.hidePwd.toString());
            this.lsSet('cachetime', this.cacheTime.toString());
            this.lsSet('checkpwned', this.checkPwned.toString());
            this.lsSet('minpwdstrength', this.minPwdStrength);
            this.lsSet('loops', this.loops.toString());
            this.lsSet('ctformat', this.ctFormat.toString());
            this.lsSet('vclear', this.visibilityClear.toString());
            this.lsSet('reminder', this.reminder.toString());
            this.lsSet('trand', this.trueRand.toString());
            this.lsSet('prand', this.pseudoRand.toString());
         }
      } catch (err) {
         console.error(err);
         //otherwise ignore
      }
   }

   timerTick(): void {
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

   restartTimer(): void {
      if (this.intervalId != 0) {
         clearInterval(this.intervalId);
         this.intervalId = 0;
      }
      this.cacheTimeout = DateTime.now().plus({ seconds: this.cacheTime });
      this.secondsRemaining = this.cacheTime;

      // @ts-ignore
      this.intervalId = setInterval(() => this.timerTick(), 1000);
   }

   clearPassword(): void {
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
      if (document.hidden && this.visibilityClear) {
         this.privacyClear();
      }
   }

   onDraggerMouseDown(): void {
      this.mouseDown = true;
   }

   onDraggerMouseMove(event: MouseEvent): void {
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

   onDraggerMouseUp(): void {
      this.mouseDown = false;
   }

   onLoopsChange() {
      this.loops = Math.max(this.loops, 1);
      this.loops = Math.min(this.loops, this.LOOP_MAX);
      this.lsSet('loops', this.loops.toString());
   }

   onAlgorithmChange(value: string): void {
      this.lsSet('algorithm', this.algorithm);
   }

   onPasswordOptionChange(): void {
      this.lsSet('checkpwned', this.checkPwned.toString());
      this.lsSet('minpwdstrength', this.minPwdStrength);
      this.clearPassword();
   }

   toastMessage(msg: string): void {
      this.snackBar.open(msg, '', {
         duration: 2000,
      });
   }

   onClearCipher(): void {
      this.cipherMsg = '';
      this.cipherFile = undefined;
      this.cipherArmor = '';
      this.cipherLabel = 'Cipher Armor';
   }

   onClearClear(): void {
      this.clearMsg = '';
      this.clearFile = undefined;
      this.clearText = '';
      this.clearLabel = 'Clear Text';
      if (!this.welcomed) {
         this.bubbleTip1.show();
         this.bubbleTip2.hide();
      }
   }

   onClearInput() {
      if (!this.welcomed) {
         this.bubbleTip1.hide();
         this.bubbleTip2.show();
      }
   }

   privacyClear(): void {
      this.clearPassword();
      this.onClearClear();
   }

   cipherReadyNotice(cdInfo: CipherDataInfo) {
      this.actionStart = Date.now();
      // Avoid briefly putting up spinner and disabling buttons
      if (cdInfo.ic > this.spinnerAbove) {
         this.showProgress = true;
      }
   }

   setCipherFile(cipherFile: File, saved: boolean = false) {
      this.onClearCipher();
      this.cipherFile = cipherFile;
      let msg = saved ? 'file saved and ' : '';
      this.showCipherFile(msg + 'selected for decryption', cipherFile.name);
   }

   setClearFile(clearFile: File, saved: boolean = false) {
      this.onClearClear();
      this.clearFile = clearFile;
      let msg = saved ? 'file saved and ' : '';

      this.showClearFile(msg + 'selected for encryption', clearFile.name);
      if (!this.welcomed) {
         this.bubbleTip1.hide();
         this.bubbleTip2.show();
      }
   }

   /*
      ╔═══════════════╦═══════════╦═════════╦════════════╦═══════╦═══════════╗
      ║ Button        ║ Source    ║ Dest    ║ Size Limit ║ Loops ║ Operation ║
      ╠═══════════════╬═══════════╬═════════╬════════════╬═══════╬═══════════╣
      ║ encrypt       ║ screen    ║ screen  ║ yes        ║ yes   ║ encBuffer ║
      ║               ║ file.*    ║ screen  ║ yes        ║ yes   ║ encBuffer ║
      ║ encryptToFile ║ screen    ║ file.qq ║ no         ║ no    ║ encStream ║
      ║               ║ file.*    ║ file.qq ║ no         ║ no    ║ encStream ║
      ╚═══════════════╩═══════════╩═════════╩════════════╩═══════╩═══════════╝
   */

   async onEncrypt(): Promise<void> {
      if ((!this.clearFile && this.clearText.length < 1)) {
         this.onClearClear();
         this.showCipherError('Missing clear text. Enter or load clear text, then encrypt');
         this.r2.selectRootElement('#clearInput').focus();
         return;
      }

      if (!this.authSvc.isAuthenticated()) {
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
         this.loops = Math.min(
            Math.max(1, Number(this.loops) ? Number(this.loops) : 0),
            MAX_LOOPS
         );
         if (this.icount < this.icountMin) {
            this.icount = this.icountMin;
         }

         if (this.loops > 1) {
            // it's confusing to use cached password when looping so
            // start from scratch
            this.clearPassword();
         }

         const econtext: EncContext2 = {
            lpEnd: this.loops,
            lp: 0,
            alg: this.algorithm,
            ic: this.icount,
            ctFormat: this.ctFormat,
            reminder: this.reminder,
            trueRand: this.trueRand,
            fallbackRand: this.pseudoRand
         };

         const [clearStream, streamSize] = this.getClearStream(econtext);
         if (streamSize > cc.CLEAR_DATA_MAX_BYTES) {
            this.showCipherError(`Clear data must be smaller than ${Math.round(cc.CLEAR_DATA_MAX_BYTES / 1024 / 1024)} MB to display`, 'Try Encrypt to File');
            return;
         }

         const cipherStream = await this.makeCipherStream2(econtext, clearStream);
         if (cipherStream) {
            const cipherData = await readStreamAll(cipherStream);
            const cipherArmor = this.getCipherArmorFor(cipherData, econtext);
            this.showCipherArmorAndTime(cipherArmor);
            this.toastMessage('Congratulations, data encrypted');
         }

         /* A bit torn about always clearing this when not caching...
         if (completed && !this.pwdCached) {
            this.onClearClear();
         }*/
      } catch (something) {
         console.error(something);
         if (!ProcessCancelled.isProcessCancelled(something)) {
            this.showCipherError('Could not encrypt text');
         }
         if (!this.welcomed) {
            this.bubbleTip2.show();
         }
      } finally {
         this.showProgress = false;
      }
   }

   async onEncryptToFile(): Promise<void> {
      if ((!this.clearFile && this.clearText.length < 1)) {
         this.onClearClear();
         this.showCipherError('Missing clear text. Enter or load clear text, then encrypt');
         this.r2.selectRootElement('#clearInput').focus();
         return;
      }

      if (!this.authSvc.isAuthenticated()) {
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

         const econtext: EncContext = {
            lpEnd: 1,
            lp: 0,
            alg: this.algorithm,
            ic: this.icount,
            ctFormat: this.ctFormat,
            reminder: this.reminder,
            trueRand: this.trueRand,
            fallbackRand: this.pseudoRand
         };

         if (this.useFilePicker) {
            const saveFile = await selectWriteableQQFile(baseName);
            const writeable = await saveFile.createWritable();
            const [cipherStream] = await this.makeCipherStream(econtext);

            if (cipherStream) {
               await cipherStream.pipeTo(writeable);
               this.setCipherFile(await saveFile.getFile(), true);
               this.toastMessage('Data encrypted');
            }
         } else {
            const [cipherStream, streamSize] = await this.makeClearStream();
            if (cipherStream) {
               if (!this.useByteStream && streamSize > 2 * 1024 * 1024 * 1024) {
                  this.showCipherError('File must be smaller than 2 GB');
               } else {
                  const response = new Response(cipherStream);
                  const blob = await response.blob();
                  this.fileDownload(baseName + '.qq', blob);
                  this.showCipherFile('Encrypted file will be in your downloads folder');
                  this.toastMessage('Data encrypted');
               }
            }
         }

      } catch (something) {
         console.error(something);
         if (!ProcessCancelled.isProcessCancelled(something)) {
            this.showCipherError('Could not encrypt text');
         }
      } finally {
         this.showProgress = false;
      }
   }

   async makeCipherStream(
      econtext: EncContext
   ): Promise<[ReadableStream<Uint8Array> | null, number]> {

      let size = 0;
      let cipherStream: ReadableStream<Uint8Array> | null = null;

      if(this.clearFile) {
         size = this.clearFile.size;

         const [pwd, hint] = await this.getPassword(
            +this.minPwdStrength,
            '',
            { lpEnd: 1, lp: 0 }
         );

         const eparams: EParams = {
            ...econtext,
            userCred: base64ToBytes(this.authSvc.userCred!),
            pwd: pwd,
            hint: hint
         }

         cipherStream = this.cipherSvc.encryptStream(
            eparams,
            this.clearFile.stream(),
            this.cipherReadyNotice.bind(this)
         );

         this.showProgress = true;
      } else {

         const clearData = new TextEncoder().encode(this.clearText);
         size = clearData.byteLength;
         econtext.clearData = clearData;

         const cipherData = await this.makeCipherData(econtext);
         if (cipherData) {
            size = cipherData.byteLength;
            const blob = new Blob([cipherData], { type: 'application/octet-stream' });
            cipherStream = blob.stream();
         }
      }

      return [cipherStream, size];
   }

   getClearStream(
      econtext: EncContext
   ): [ReadableStream<Uint8Array>, number] {

      let size = 0;
      let clearStream: ReadableStream<Uint8Array>;

      if(this.clearFile) {
         size = this.clearFile.size;
         clearStream = this.clearFile.stream();
      } else {

         const clearData = new TextEncoder().encode(this.clearText);
         size = clearData.byteLength;
         const blob = new Blob([clearData], { type: 'application/octet-stream' });
         clearStream = blob.stream();
      }

      return [clearStream, size];
   }

   // Return value is false if the process was aborted
   async makeCipherStream2(
      econtext: EncContext2,
      clearStream: ReadableStream<Uint8Array>
   ): Promise<ReadableStream<Uint8Array>> {

      const [pwd, hint] = await this.getPassword(+this.minPwdStrength, '', econtext);

      const eparams: EParams = {
         ...econtext,
         userCred: base64ToBytes(this.authSvc.userCred!),
         pwd: pwd,
         hint: hint
      }

      const cipherStream = this.cipherSvc.encryptStream(
         eparams,
         clearStream,
         this.cipherReadyNotice.bind(this)
      );

      econtext.lp += 1;

      // it worked, so stop showing tips (setting this before next loop)
      this.welcomed = true;
      localStorage.setItem(this.authSvc.userId + "welcomed", "yup");

      if (econtext.lp < econtext.lpEnd) {
         this.clearPassword();
         return this.makeCipherStream2(econtext, cipherStream);
      }
      return cipherStream;
   }

   // Return value is false if the process was aborted
   async makeCipherData(econtext: EncContext): Promise<Uint8Array> {

      if(!econtext.clearData) {
         throw new Error('missing clear data');
      }

      const [pwd, hint] = await this.getPassword(+this.minPwdStrength, '', econtext);

      const eparams: EParams = {
         ...econtext,
         userCred: base64ToBytes(this.authSvc.userCred!),
         pwd: pwd,
         hint: hint
      }

      const encrypted = await this.cipherSvc.encryptBuffer(
         eparams, econtext.clearData, this.cipherReadyNotice.bind(this)
      );

      econtext.lp += 1;
      //         const b64Encrypted = bytesToBase64(encrypted);
//      const cipherArmor = this.getCipherArmorFor(encrypted, econtext);

      // it worked, so stop showing tips (setting this before next loop)
      this.welcomed = true;
      localStorage.setItem(this.authSvc.userId + "welcomed", "yup");

      if (econtext.lp < econtext.lpEnd) {
         //            this.privacyClear();
         //            this.showClearText(this.cipherArmor);
         this.clearPassword();
         econtext.clearData = encrypted;
         return this.makeCipherData(econtext);
      }
      return encrypted;
   }

   /*
      ╔═══════════════╦═══════════╦═════════╦════════════╦═══════╦═══════════╗
      ║ Button        ║ Source    ║ Dest    ║ Size Limit ║ Loops ║ Operation ║
      ╠═══════════════╬═══════════╬═════════╬════════════╬═══════╬═══════════╣
      ║ decrypt       ║ screen    ║ screen  ║ yes        ║ yes   ║ decBuffer ║
      ║               ║ file.json ║ screen  ║ yes        ║ yes   ║ decBuffer ║
      ║               ║ file.qq   ║ screen  ║ yes        ║ no    ║ decStream ║
      ║ decryptToFile ║ screen    ║ file.*  ║ yes        ║ yes   ║ decBuffer ║
      ║               ║ file.json ║ file.*  ║ yes        ║ yes   ║ decBuffer ║
      ║               ║ file.qq   ║ file.*  ║ no         ║ no    ║ decStream ║
      ╚═══════════════╩═══════════╩═════════╩════════════╩═══════╩═══════════╝
   */
   async onDecrypt(): Promise<void> {
      if ((!this.cipherFile && this.cipherArmor.length < 1)) {
         this.onClearCipher();
         this.showClearError('Missing cipher armor. Enter or load cipher armor text, then decrypt');
         this.r2.selectRootElement('#cipherInput').focus();
         return;
      }

      if (!this.authSvc.isAuthenticated()) {
         this.showClearError('User not authenticated, try refreshing this page');
         return;
      }

      this.authSvc.activity();
      this.onClearClear();

      try {
         if (this.cipherFile) {
            if (this.cipherFile.size > cc.CLEAR_DATA_MAX_BYTES) {
               this.showClearError(`File must be smaller than ${Math.round(cc.CLEAR_DATA_MAX_BYTES / 1024 / 1024)} MB to display`, 'Try Decrypt to File');
               return;
            }
         } else {
            if (this.cipherArmor.length > cc.CLEAR_DATA_MAX_BYTES) {
               this.showClearError(`Data must be smaller than ${Math.round(cc.CLEAR_DATA_MAX_BYTES / 1024 / 1024)} MB to display`, 'Try Decrypt to File');
               return;
            }
         }

         const [clearStream] = await this.makeClearStream();
         if (clearStream) {
            this.showClearTextAndTime(await readStreamAll(clearStream, true));
            this.toastMessage('Data decrypted');
         }
      } catch (something) {
         console.error(something);
         if (!ProcessCancelled.isProcessCancelled(something)) {
            this.clearPassword();
            this.showClearError(
               'Could not decrypt cipher armor text. You may be using the wrong password or passkey, or the cipher armor is invalid'
            );
         }
      } finally {
         this.showProgress = false;
      }
   }

   async onDecryptToFile(): Promise<void> {
      if ((!this.cipherFile && this.cipherArmor.length < 1)) {
         this.onClearCipher();
         this.showClearError('Missing cipher armor. Enter or load cipher armor text, then decrypt');
         this.r2.selectRootElement('#cipherInput').focus();
         return;
      }

      if (!this.authSvc.isAuthenticated()) {
         this.showClearError('User not authenticated, try refreshing this page');
         return;
      }

      this.authSvc.activity();
      this.onClearClear();

      try {
         let baseName: string;

         if (this.cipherFile) {
            if (this.cipherFile.type.includes('json') && this.cipherFile.size > cc.CLEAR_DATA_MAX_BYTES) {
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
               this.showClearError(`Data must be smaller than ${Math.round(cc.CLEAR_DATA_MAX_BYTES / 1024 / 1024)} MB`);
               return;
            }
            baseName = 'clear';
         }

         if (this.useFilePicker) {
            const saveFile = await selectWriteableFile(baseName);
            const writeable = await saveFile.createWritable();
            const [clearStream] = await this.makeClearStream();
            if (clearStream) {
               await clearStream.pipeTo(writeable);
               this.setClearFile(await saveFile.getFile(), true);
               this.toastMessage('Data decrypted');
            }
         } else {
            const [clearStream, fileSize] = await this.makeClearStream();
            if (clearStream) {
               if (!this.useByteStream && fileSize > 2 * 1024 * 1024 * 1024) {
                  this.showClearError('File must be smaller than 2 GB');
               } else {
                  const response = new Response(clearStream);
                  const blob = await response.blob();
                  this.fileDownload(baseName, blob);
                  this.showClearFile('Decrypted file will be in your downloads folder');
                  this.toastMessage('Data decrypted');
               }
            }
         }
      } catch (something) {
         console.error(something);
         if (!ProcessCancelled.isProcessCancelled(something)) {
            this.clearPassword();
            this.showClearError(
               'Could not decrypt cipher armor text. You may be using the wrong password or passkey, or the cipher armor is invalid'
            );
         }
      } finally {
         this.showProgress = false;
      }
   }

   async makeClearStream(): Promise<[ReadableStream<Uint8Array> | null, number]> {

      let size = 0;
      let clearStream: ReadableStream<Uint8Array> | null = null;
      if (this.cipherFile && !this.cipherFile.type.includes('json')) {
         size = this.cipherFile.size;
         clearStream = this.cipherSvc.decryptStream(
            async (hint) => {
               const [pwd, _] = await this.getPassword(
                  -1,
                  hint,
                  { lpEnd: 1, lp: 0 }
               );
               this.showProgress = true;
               return pwd;
            },
            base64ToBytes(this.authSvc.userCred!),
            this.cipherFile.stream(),
            this.cipherReadyNotice.bind(this)
         );

      } else {
         let cipherArmor: string;
         if (this.cipherFile) {
            // It is a json file that contains plain text cipher armor
            cipherArmor = await readStreamAll(this.cipherFile.stream(), true);
         } else {
            cipherArmor = this.cipherArmor;
         }

         const dcontext = this.getDecContextFrom(cipherArmor);
         if (dcontext.lpEnd! > 1) {
            // it's confusing to use cached password when looping so
            // start from scratch
            this.clearPassword();
         }

         const clearData = await this.makeClearData(dcontext);
         if (clearData) {
            size = clearData.byteLength;
            const blob = new Blob([clearData], { type: 'application/octet-stream' });
            clearStream = blob.stream();
         }
      }

      return [clearStream, size];
   }

   async makeClearData(dcontext: DecContext): Promise<Uint8Array> {

      const decrypted = await this.cipherSvc.decryptBuffer(
         async (hint) => {
            const [pwd, _] = await this.getPassword(-1, hint, dcontext);
            return pwd;
         },
         base64ToBytes(this.authSvc.userCred!),
         dcontext.cipherData,
         this.cipherReadyNotice.bind(this)
      );

//      const decryptedText = new TextDecoder().decode(decrypted);
      dcontext.lp += 1;

      if (dcontext.lp < dcontext.lpEnd) {
         //            this.cipherArmor = this.clearText;
  //       const nextContext = this.getDecContextFrom(decryptedText);
         // A bit hacky... preserve top level loop information
//         (nextContext.lpEnd as number) = dcontext.lpEnd;
//         nextContext.lp = dcontext.lp;
         this.privacyClear();
         dcontext.cipherData = decrypted;
         return this.makeClearData(dcontext);
      }

      return decrypted;
   }

   showClearError(msg: string, hdr: string | null = null): void {
      this.showClearMsg('errorBox', 'Error', msg, hdr);
   }

   showClearFile(msg: string, hdr: string | null = null): void {
      this.showClearMsg('fileBox', 'File', msg, hdr);
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

   showCipherFile(msg: string, hdr: string | null = null): void {
      this.showCipherMsg('fileBox', 'File', msg, hdr);
   }

   showCipherMsg(cls: string, label: string, msg: string, hdr: string | null = null): void {
      //      this.cipherFile = undefined;
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

   showCipherArmor(cipherArmor: string, extra: string = ''): void {
      this.cipherArmor = cipherArmor;
      this.cipherFile = undefined;
      this.cipherMsg = '';
      this.cipherLabel = 'Cipher Armor ' + extra;
   }

   showCipherArmorAndTime(cipherArmor: string): void {
      const tookMsg = makeTookMsg(this.actionStart, Date.now());
      this.showCipherArmor(cipherArmor, `(${tookMsg})`);
   }

   getCipherArmorFor(cipherData: Uint8Array, econtext: EncContext): string {
      // Rebuild object to control ordering (better way to do this?)
      let result: { [key: string]: string | number } = {};
      result['ct'] = bytesToBase64(cipherData);

      // To reduce CT size, only include this extra stuff at the
      // outer most loop
      if (econtext.lp == econtext.lpEnd) {
         if (econtext.lp > 1) {
            result['lps'] = econtext.lpEnd;
         }

         if (econtext.ctFormat == 'link') {
            const ctParam = encodeURIComponent(JSON.stringify(result));
            return 'https://' + location.host + '?cipherarmor=' + ctParam;
         } else {
            if (econtext.reminder) {
               result['reminder'] = 'decrypt with quick crypt';
            }
            const space = this.ctFormat == 'indent' ? 3 : 0;
            return JSON.stringify(result, null, space);
         }
      }

      return JSON.stringify(result);
   }

   getDecContextFrom(cipherArmor: string): DecContext {
      try {
         let trimmed = cipherArmor.trim();
         if (trimmed.startsWith('https://')) {
            const ct = new URL(trimmed).searchParams.get('cipherarmor');
            if (ct == null) {
               let err = Error();
               err.name = 'Url missing cipherarmor';
               throw err;
            }
            trimmed = ct;
         } else if (trimmed.startsWith('cipherarmor=')) {
            trimmed = trimmed.slice('cipherarmor='.length);
         }

         // %7B is urlencoded '{' character, so decode
         if (trimmed.startsWith('%7B')) {
            trimmed = decodeURIComponent(trimmed);
         }

         var jsonParts = JSON.parse(trimmed);
      } catch (err) {
         console.error(err);
         if (err instanceof Error) {
            throw new Error('Cipher armor text not formatted correctly. ' + err.name);
         }
      }
      if (!('ct' in jsonParts)) {
         throw new Error('Missing ct in cipher armor text');
      }
      const ct = jsonParts.ct;
      const lps = Math.min(
         MAX_LOOPS,
         Math.max(1, +jsonParts.lps ? +jsonParts.lps : 0)
      );

      return {
         lpEnd: lps,
         lp: 0,
         cipherData: base64ToBytes(ct)
      };
   }

   //-1 minStrength means no pwd strength requirments
   async getPassword(
      minStrength: number,
      hint: string,
      context: Context
   ): Promise<[string, string]> {
      if (this.pwdCached) {
         this.restartTimer();
         return Promise.resolve([this.cachedPassword, this.cachedHint]);
      } else {
         return this.askForPassword(minStrength, hint, context);
      }
   }

   async askForPassword(
      minStrength: number,
      hint: string,
      context: Context
   ): Promise<[string, string]> {

      let loopCount = context.lp + 1;
      let askHint = true;
      if (isDecContext(context)) {
         loopCount = context.lpEnd - context.lp;
         askHint = false;
      }

      let dialogRef = this.dialog.open(PasswordDialog, {
         data: {
            hint: hint,
            askHint: askHint,
            minStrength: minStrength,
            hidePwd: this.hidePwd,
            loopCount: loopCount,
            loops: context.lpEnd,
            checkPwned: this.checkPwned,
            welcomed: this.welcomed,
            userName: this.authSvc.userName,
         },
      });

      return new Promise((resolve, reject) => {
         dialogRef.afterClosed().subscribe((result) => {
            if (!result) {
               // intentially do not rejct with "new Error()" so this isn't
               // caught as an error, just cancelation
               reject(new ProcessCancelled());
            } else {
               this.clearPassword();
               if (this.cacheTime > 0 && result[0]) {
                  this.cachedPassword = result[0];
                  this.cachedHint = result[1];
                  this.pwdCached = true;
                  this.restartTimer();
               }
               resolve([result[0], result[1]]);
            }
         });
      });
   }

   onReminderChange() {
      this.lastReminder = this.reminder;
      this.lsSet('reminder', this.reminder.toString());
      this.reformatCipherArmor();
   }

   onVClearChnage() {
      this.lsSet('vclear', this.visibilityClear.toString());
   }


   onFormatChange(selected?: string) {
      if (selected == 'link') {
         this.lastReminder = this.reminder;
         this.reminder = false;
      } else {
         this.reminder = this.lastReminder;
      }
      this.lsSet('ctformat', this.ctFormat.toString());
      this.reformatCipherArmor();
   }

   reformatCipherArmor() {
      if (this.cipherArmor) {
         try {
            let dcontext = this.getDecContextFrom(this.cipherArmor);
            // make it the "last loop" so we get the full cipher armor
            let econtext: EncContext = {
               ...dcontext,
               lp: dcontext.lpEnd,
               ctFormat: this.ctFormat,
               reminder: this.reminder,
               // Improve this at some point, the following values are required,
               // by EncContext not used by getCipherArmorFor
               alg: this.algorithm,
               ic: this.icount,
               trueRand: this.trueRand,
               fallbackRand: this.pseudoRand,
               clearData: new Uint8Array()
            };

            this.showCipherArmor(this.getCipherArmorFor(dcontext.cipherData, econtext));
         } catch (err) {
         }
      }
   }

   onTrueRandChanged(checked: boolean) {
      if (!checked) {
         this.pseudoRand = true;
      }
      this.lsSet('trand', this.trueRand.toString());
   }

   onPseudoRandChange() {
      this.lsSet('prand', this.pseudoRand.toString());
   }

   onICountChange() {
      this.icount = Math.max(this.icount, this.icountMin);
      this.icount = Math.min(this.icount, this.icountMax);
      this.lsSet('icount', this.icount.toString());
      this.setIcountWarning();
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

   onHidePwdChanged(): void {
      this.lsSet('hidepwd', this.hidePwd.toString());
   }

   onCacheTimerChange(): void {
      this.cacheTime = Math.max(this.cacheTime, 0);
      this.cacheTime = Math.min(this.cacheTime, this.INACTIVITY_TIMEOUT);
      if (this.pwdCached) {
         this.restartTimer();
      }
      this.lsSet('cachetime', this.cacheTime.toString());
   }

   async onCipherTextInfo(): Promise<void> {
      try {
         if (!this.authSvc.isAuthenticated()) {
            throw new Error('User not authenticated, try refreshing this page')
         }

         let cdInfo: CipherDataInfo;
         let lps = 0;
         if (this.cipherFile && !this.cipherFile.type.includes('json')) {
            cdInfo = await this.cipherSvc.getCipherStreamInfo(
               base64ToBytes(this.authSvc.userCred!),
               this.cipherFile.stream()
            );
            lps = 1;
         } else {
            let cipherArmor: string;
            if (this.cipherFile) {
               cipherArmor = await readStreamAll(this.cipherFile.stream(), true);
            } else {
               cipherArmor = this.cipherArmor;
            }

            const dcontext = this.getDecContextFrom(cipherArmor);
            lps = dcontext.lpEnd;
            cdInfo = await this.cipherSvc.getCipherTextInfo(
               base64ToBytes(this.authSvc.userCred!),
               dcontext.cipherData
            );
         }

         this.dialog.open(CipherInfoDialog, { data: {cdInfo:cdInfo, lps: lps} });
      } catch (err) {
         console.error(err);
         this.dialog.open(CipherInfoDialog, { data: {cdInfo:null, lps: 0} });
      }
   }

   algDescription(alg: string): string {
      return this.cipherSvc.algDescription(alg);
   }
}

