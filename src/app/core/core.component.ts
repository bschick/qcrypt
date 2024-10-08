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
import * as cs from '../services/cipher.service';
import { AuthenticatorService, AuthEvent, AuthEventData, INACTIVITY_TIMEOUT } from '../services/authenticator.service';
import {
   PasswordDialog,
   CipherInfoDialog,
   SigninDialog,
} from './core.dialogs';
import { BubbleDirective } from '../ui/bubble/bubble.directive';
import { Subscription } from 'rxjs';

const MAX_LOOPS = 10;

type Context = {
   readonly lpEnd: number;
   lp: number;
   userCred: Uint8Array;
}

type EncContext = Context & {
   alg: string;
   ic: number;
   ctFormat: string;
   reminder: boolean;
   trueRand: boolean;
   fallbackRand: boolean;
};

type DecContext = Context & {
   ct: string;
};

function isDecContext(context: Context): context is DecContext {
   return (context as DecContext).ct !== undefined;
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

   private signinDialogRef?: MatDialogRef<SigninDialog, any>
   private optionsLoaded = false;
   private mouseDown = false;
   private cachedPassword: string = '';
   private cachedHint: string = '';
   private intervalId: number = 0;
   private spinnerAbove: number = 1500000; // Default since benchmark is async
   private actionStart: number = 0;
   private authSub!: Subscription;
   private lastReminder: boolean = true;
   public readonly INACTIVITY_TIMEOUT = INACTIVITY_TIMEOUT;
   public readonly LOOP_MAX = 10;
   public cacheTimeout!: DateTime;
   public icountMin: number = cs.ICOUNT_MIN;
   public icountMax: number = cs.ICOUNT_MAX; // Default since benchmark is async
   public icountDefault: number = cs.ICOUNT_DEFAULT; // Default since benchmark is async
   public hashTimeWarning = '';
   public clearText = '';
   public pwdCached = false;
   public cipherLabel = 'Cipher Armor';
   public clearLabel = 'Clear Text';
   public cipherArmor = '';
   public showProgress = false;
   public errorCipher = false;
   public errorClear = false;
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
   public icount: number = cs.ICOUNT_DEFAULT; // Default since benchmark is async
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
      private cipherSvc: cs.CipherService,
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
   }

   setAlgorithm(alg: string | null): void {
      if (Object.keys(cs.AlgInfo).includes(alg!)) {
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
      if( hashMillis > 15 * 1000) {
         const takeMsg = makeTookMsg(0, hashMillis, 'take');
         this.hashTimeWarning = `*password hash may ${takeMsg}`
      }
   }

   ngAfterViewInit() {
      // ugly hack to make angular not clip the label for dropdown select elements
      this.formatLabel.nativeElement.parentElement.style.maxWidth = "calc(100%/0.7)";
      this.minStrLabel.nativeElement.parentElement.style.maxWidth = "calc(100%/0.7)";

      if (this.authSvc.isAuthenticated() && !localStorage.getItem(this.authSvc.userId + "welcomed")) {
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
      this.cipherSvc.benchmark(this.icountMin).then(([icount, icountMax, hashRate]) => {
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
            this.cipherArmor = decodeURIComponent(params.get('cipherarmor')!);
            this.onFormatChange();
            params = params.delete('cipherarmor');
         }
         if (params.get('cleartext')) {
            this.clearText = decodeURIComponent(params.get('cleartext')!);
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
      this.errorCipher = false;
      this.cipherArmor = '';
      this.cipherLabel = 'Cipher Armor';
   }

   onClearClear(): void {
      this.errorClear = false;
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

   cipherReadyNotice(params: cs.Params) {
      this.actionStart = Date.now();
      // Avoid briefly putting up spinner and disabling buttons
      if (params.ic > this.spinnerAbove) {
         this.showProgress = true;
      }
   }

   async onClickEncrypt(): Promise<void> {
      if (this.clearText.length < 1 || this.errorClear) {
         this.onClearClear();
         this.showEncryptError('Enter clear text to encrypt');
         this.r2.selectRootElement('#clearInput').focus();
         return;
      }

      if (!this.welcomed) {
         this.bubbleTip1.hide();
         this.bubbleTip2.hide();
      }

      const savedClearText = this.clearText;
      try {
         if (!this.authSvc.isAuthenticated()) {
            throw new Error('User not authenticated, try refreshing this page')
         }

         this.authSvc.activity();

         this.loops =1;

         if (this.icount < this.icountMin) {
            this.icount = this.icountMin;
         }

         if (this.loops > 1) {
            // it's confusing to use cached password when looping so
            // start from scratch
            this.clearPassword();
         }

         let econtext: EncContext = {
            lpEnd: this.loops,
            lp: 0,
            alg: this.algorithm,
            ic: this.icount,
            userCred: cs.base64ToBytes(this.authSvc.userCred!),
            ctFormat: this.ctFormat,
            reminder: this.reminder,
            trueRand: this.trueRand,
            fallbackRand: this.pseudoRand
         };

         const completed = await this.makeCipherArmor(econtext);

         if (!this.welcomed && !completed) {
            this.bubbleTip2.show();
         }

         if(completed) {
            this.toastMessage('Congratulations, data encrypted');
         }

         /* A bit torn about always clearing this when not caching...
         if (completed && !this.pwdCached) {
            this.onClearClear();
         }*/
      } catch (something) {
         console.error(something);
         if (something instanceof Error) {
            this.showEncryptError('Could not encrypt text');
         }
      } finally {
         this.showProgress = false;
         // After > 1 loop, its confusing to leave intermediate stuff
         this.clearText = savedClearText;
      }
   }

   // Return value is false if the process was aborted
   async makeCipherArmor(econtext: EncContext): Promise<boolean> {
      this.onClearCipher();

      try {
         var [pwd, hint] = await this.getPassword(+this.minPwdStrength, '', econtext);

         const clearBytes = new TextEncoder().encode(this.clearText);
         const eparams: cs.EParams = {
            ...econtext,
            pwd: pwd,
            hint: hint,
            clear: clearBytes
         }

         const encrypted = await this.cipherSvc.encrypt(
            eparams, this.cipherReadyNotice.bind(this)
         );

         econtext.lp += 1;
         this.showCipherArmorAndTime(this.getCipherArmorFor(encrypted, econtext));

         // it worked, so stop showing tips (setting this before next loop)
         this.welcomed = true;
         localStorage.setItem(this.authSvc.userId + "welcomed", "yup");

         if (econtext.lp < econtext.lpEnd) {
            this.privacyClear();
            this.clearText = this.cipherArmor;
            return this.makeCipherArmor(econtext);
         }
         return true;

      } catch (something) {
         // canceling password throws, but not an Error
         if (something instanceof Error) {
            throw something;
         }
         return false;
      }
   }

   async onClickDecrypt(): Promise<void> {
      if (this.cipherArmor.length < 1 || this.errorCipher) {
         this.onClearCipher();
         this.showDecryptError('Enter cipher armor text to decrypt');
         this.r2.selectRootElement('#cipherInput').focus();
         return;
      }

      const savedCipherArmor = this.cipherArmor;
      try {
         if (!this.authSvc.isAuthenticated()) {
            throw new Error('User not authenticated, try refreshing this page')
         }

         this.authSvc.activity();

         const dcontext = this.getDecContextFrom(this.cipherArmor);
         if (dcontext.lpEnd! > 1) {
            // it's confusing to use cached password when looping so
            // start from scratch
            this.clearPassword();
         }

         // This updates Cipher Armor UI field
         const completed = await this.makeClearText(dcontext);
         if (completed) {
            this.toastMessage('Data decrypted');
         }

      } catch (something) {
         console.error(something);
         if (something instanceof Error) {
            this.showDecryptError(
               'Could not decrypt cipher armor text. You may be using the wrong password or passkey, or the cipher armor was changed'
            );
         }
      } finally {
         this.showProgress = false;
         // In case > 1 loops, tbere is intermediate stuff in cipherArmor
         this.cipherArmor = savedCipherArmor;
      }
   }

   async makeClearText(dcontext: DecContext): Promise<boolean> {
      this.onClearClear();

      try {
         const decrypted = await this.cipherSvc.decrypt(
            async (hint) => {
               const [pwd, _] = await this.getPassword(-1, hint, dcontext);
               return pwd;
            },
            cs.base64ToBytes(this.authSvc.userCred!),
            dcontext.ct,
            this.cipherReadyNotice.bind(this)
         );
         this.showClearTextAndTime(decrypted);
         dcontext.lp += 1;

         if (dcontext.lp < dcontext.lpEnd) {
            this.cipherArmor = this.clearText;
            const nextContext = this.getDecContextFrom(this.clearText);
            // A bit hacky... preserve top level loop information
            (nextContext.lpEnd as number) = dcontext.lpEnd;
            nextContext.lp = dcontext.lp;
            this.privacyClear();
            return this.makeClearText(nextContext);
         }

         return true;
      } catch (something) {
         // cancelling password throws, but not an Error. so eat it
         if (something instanceof Error) {
            throw something;
         }
         return false;
      }
   }

   showDecryptError(msg: string): void {
      this.clearText = msg;
      this.errorClear = true;
      this.clearLabel = 'Error';
   }

   showEncryptError(msg: string): void {
      this.cipherArmor = msg;
      this.errorCipher = true;
      this.cipherLabel = 'Error';
   }

   showCipherArmorAndTime(cipherArmor: string): void {
      this.cipherArmor = cipherArmor;
      this.errorCipher = false;

      const tookMsg = makeTookMsg(this.actionStart, Date.now());
      this.cipherLabel = `Cipher Armor (${tookMsg})`;
   }

   showClearTextAndTime(clear: ArrayBuffer): void {
      this.clearText = new TextDecoder().decode(clear);
      this.errorClear = false;

      const tookMsg = makeTookMsg(this.actionStart, Date.now());
      this.cipherLabel = `Clear Text (${tookMsg})`;
   }

   getCipherArmorFor(ct: string, econtext: EncContext): string {
      // Rebuild object to control ordering (better way to do this?)
      let result: { [key: string]: string | number } = {};
      result['ct'] = ct;

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
            if(econtext.reminder) {
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
         lpEnd: jsonParts.lps,
         lp: 0,
         userCred: cs.base64ToBytes(this.authSvc.userCred!),
         ct: ct,
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

      let loopCount: number = context.lp + 1;
      let askHint: boolean = true;
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
               reject('process cancelled');
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
      if(selected == 'link') {
         this.lastReminder = this.reminder;
         this.reminder = false;
      } else {
         this.reminder = this.lastReminder;
      }
      this.lsSet('ctformat', this.ctFormat.toString());
      this.reformatCipherArmor();
   }

   reformatCipherArmor() {
      if(this.cipherArmor) {
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
               fallbackRand: this.pseudoRand
            };

            this.cipherArmor = this.getCipherArmorFor(dcontext.ct, econtext);
         } catch(err) {
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

   onFileUpload(event: any, setter: (val: string) => void): void {
      let fileReader = new FileReader();
      fileReader.onload = (e) => {
         if (fileReader.result) {
            setter(fileReader.result.toString());
         } else {
            this.toastMessage('File was empty');
         }
      };
      fileReader.readAsText(event.target.files[0]);
   }

   onCipherFileUpload(event: any): void {
      this.fileUpload.nativeElement.onchange = (event: any) => {
         this.onFileUpload(event, (val) => {
            this.cipherArmor = val;
            this.errorCipher = false;
         });
      };
      this.fileUpload.nativeElement.click();
   }

   onClearFileUpload(event: any): void {
      this.fileUpload.nativeElement.onchange = (event: any) => {
         this.onFileUpload(event, (val) => {
            this.clearText = val;
            this.errorClear = false;
         });
      };
      this.fileUpload.nativeElement.click();
   }

   onFileDownload(filename: string, getter: () => string): void {
      let alink = document.createElement('a');
      alink.style.display = 'none';
      document.body.appendChild(alink);

      const buffer = new TextEncoder().encode(getter());
      const file = new Blob([buffer], { type: 'text/plain;charset=utf-8' });
      alink.href = URL.createObjectURL(file);
      alink.download = filename;
      alink.click();

      document.body.removeChild(alink);
   }

   onCipherFileDownload(event: any): void {
      this.onFileDownload('cipher.json', () => {
         return this.cipherArmor;
      });
   }
   onClearFileDownload(event: any): void {
      this.onFileDownload('clear.txt', () => {
         return this.clearText;
      });
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

         const dcontext = this.getDecContextFrom(this.cipherArmor);
         const cipherData = await this.cipherSvc.getCipherData(
            cs.base64ToBytes(this.authSvc.userCred!),
            dcontext.ct
         );
         this.dialog.open(CipherInfoDialog, { data: cipherData });
      } catch (err) {
         console.error(err);
         this.dialog.open(CipherInfoDialog, { data: null });
      }
   }

   algDescription(alg: string): string {
      return cs.AlgInfo[alg] ? String(cs.AlgInfo[alg]['description']) : 'Invalid';
   }
}

