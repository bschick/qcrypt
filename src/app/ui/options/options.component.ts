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
   AfterViewInit,
   Component,
   ElementRef,
   EventEmitter,
   Input,
   OnInit,
   Output,
   ViewChild
} from '@angular/core';
import { CdkAccordionModule } from '@angular/cdk/accordion';
import { MatExpansionModule } from '@angular/material/expansion';
import { AlgorithmsComponent } from '../algorithms/algorithms.component';
import { MatRippleModule } from '@angular/material/core';
import { RouterLink } from '@angular/router';
import { MatIconModule } from '@angular/material/icon';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatSelectModule } from '@angular/material/select';
import { MatButtonModule } from '@angular/material/button';
import { MatButtonToggleModule } from '@angular/material/button-toggle';
import { MatSlideToggleModule } from '@angular/material/slide-toggle';
import { MatInputModule } from '@angular/material/input';
import { MatFormFieldModule } from '@angular/material/form-field';
import { FormsModule, ReactiveFormsModule, FormControl, Validators } from '@angular/forms';
import { AuthenticatorService, INACTIVITY_TIMEOUT } from '../../services/authenticator.service';
import { CipherService } from '../../services/cipher.service';
import { makeTookMsg } from '../../services/utils';
import * as cc from '../../services/cipher.consts';
import { HttpParams } from '@angular/common/http';

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
   selector: 'enc-options',
   imports: [CdkAccordionModule, MatExpansionModule, AlgorithmsComponent, MatRippleModule,
      RouterLink, MatIconModule, MatInputModule, MatFormFieldModule, MatTooltipModule,
      MatSelectModule, MatButtonToggleModule, MatSlideToggleModule, FormsModule,
      MatButtonModule, ReactiveFormsModule
   ],
   templateUrl: './options.component.html',
   styleUrl: './options.component.scss'
})
export class OptionsComponent implements OnInit, AfterViewInit {

   public expandOptions = false;
   public cipherPanelExpanded = false;
   public hashTimeWarning = '';

   public readonly INACTIVITY_TIMEOUT = INACTIVITY_TIMEOUT;
   public readonly LOOPS_MAX = 10;
   public readonly LOOPS_DEFAULT = 1;
   public readonly ICOUNT_MIN = cc.ICOUNT_MIN;
   public ICOUNT_MAX = cc.ICOUNT_MAX; // Default since benchmark is async
   public ICOUNT_DEFAULT = cc.ICOUNT_DEFAULT; // Default since benchmark is async

   // options
   public algorithm = ['X20-PLY'];

   //   private _icount: number = cc.ICOUNT_DEFAULT; // Default since benchmark is async
   //   private _loops = 4;
   private _lastReminder = true;
   //   public _cacheTime = 0;
   //   public _minPwdStrength = '3';
   //   public _checkPwned = false;
   //   public visibilityClear = true;
   //   public hidePwd = true;
   // public trueRand = false;
   //public pseudoRand = true;
   // public ctFormat = 'compact';
   //   public reminder = true;


   public loopsInput = new FormControl(1);
   public cacheTimeInput = new FormControl(0);
   public icountInput = new FormControl(cc.ICOUNT_DEFAULT);

   public strengthSelect = new FormControl('3');
   public checkPwnedToggle = new FormControl(false);
   public clearToggle = new FormControl(true);
   public hidePwdToggle = new FormControl(true);
   public trueRandToggle = new FormControl(false);
   public pseudoRandToggle = new FormControl({ value: true, disabled: true });
   public formatSelect = new FormControl('compact');
   public reminderToggle = new FormControl(true);

   private _optionsLoaded = false;

   @ViewChild('formatLabel') formatLabel!: ElementRef;
   @ViewChild('minStrLabel') minStrLabel!: ElementRef;
   @ViewChild('algorithms') algorithms!: AlgorithmsComponent;

   constructor(
      private authSvc: AuthenticatorService,
      private cipherSvc: CipherService,
   ) {
   }

   ngOnInit() {
      //      this.loopsInput.valueChanges.subscribe(this.onLoopsChange.bind(this));
      //      this.cacheTimeInput.valueChanges.subscribe(this.onCacheTimerChange.bind(this));
      //      this.icountInput.valueChanges.subscribe(this.onICountChange.bind(this));
      this.strengthSelect.valueChanges.subscribe(this.onPwdStrengthChange.bind(this));
      this.checkPwnedToggle.valueChanges.subscribe(this.onCheckPwnedChange.bind(this));

      this.clearToggle.valueChanges.subscribe(this.onVClearChnage.bind(this));
      this.hidePwdToggle.valueChanges.subscribe(this.onHidePwdChanged.bind(this));
      this.trueRandToggle.valueChanges.subscribe(this.onTrueRandChanged.bind(this));
      this.pseudoRandToggle.valueChanges.subscribe(this.onPseudoRandChange.bind(this));
      this.formatSelect.valueChanges.subscribe(this.onFormatChange.bind(this));
      this.reminderToggle.valueChanges.subscribe(this.onReminderChange.bind(this));

      // This can be greatly delayed is there is a long running async benchmark or
      // encrpt or decrypt from a previous instance (tab that has not fully closed).
      // Seems to be no way to prevent that or abort an ongoing SubtleCrypto action.
      this.cipherSvc.benchmark(this.ICOUNT_MIN)
         .then(([icount, icountMax, hashRate]) => {
            this.icountInput.setValue(icount);
            this.ICOUNT_DEFAULT = icount;
            this.ICOUNT_MAX = icountMax;
         }).finally(() => {
            // load after benchmark to overwrite icount with saved value
            if (this.authSvc.isAuthenticated()) {
               this.loadOptions();
            }
         });
   }

   loadOptions() {
      // First check localStorage, then apply params (which take president)
      // (not that change are not presisted until the encrypt button is used)
      /* debug
      for (let i = 0; i < localStorage.length; i++) {
        let key = localStorage.key(i)!;
        console.log(`${key}: ${this.authSvc.lsGet(key)}`);
       } */
      if (!this._optionsLoaded) {
         this.setAlgorithm(this.authSvc.lsGet('algorithm'));
         this.setIcount(this.authSvc.lsGet('icount'));
         this.setHidePwd(this.authSvc.lsGet('hidepwd'));
         this.setCacheTime(this.authSvc.lsGet('cachetime'));
         this.setCheckPwned(this.authSvc.lsGet('checkpwned'));
         this.setMinPwdStrength(this.authSvc.lsGet('minpwdstrength'));
         this.setLoops(this.authSvc.lsGet('loops'));
         this.setCTFormat(this.authSvc.lsGet('ctformat'));
         this.setVisibilityClear(this.authSvc.lsGet('vclear'));
         this.setReminder(this.authSvc.lsGet('reminder'));
         this.setPseudoRand(this.authSvc.lsGet('prand'));
         this.setTrueRand(this.authSvc.lsGet('trand'));

         let params = new HttpParams({ fromString: window.location.search });

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
         this.setPseudoRand(params.get('prand'));
         this.setTrueRand(params.get('trand'));
         this._optionsLoaded = true;

         this.setIcountWarning();
         // order is important, set modes first
         this.algorithms.modes = this.algorithm;
         this.algorithms.count = this.loopsInput.value || this.LOOPS_DEFAULT;
      }
   }

   defaultOptions(): void {
      this.algorithm = ['X20-PLY'];
      this.icountInput.setValue(this.ICOUNT_DEFAULT);
      this.hidePwdToggle.setValue(true);
      this.cacheTimeInput.setValue(0);
      this.strengthSelect.setValue('3');
      this.checkPwnedToggle.setValue(false);
      this.loopsInput.setValue(1);
      this.formatSelect.setValue('compact');
      this.clearToggle.setValue(true);
      this.reminderToggle.setValue(true);
      this._lastReminder = true;
      this.pseudoRandToggle.setValue(true);
      this.trueRandToggle.setValue(false);

//      this.clearPassword();
      this._optionsLoaded = false;

      // order is important, set modes first
      this.algorithms.modes = this.algorithm;
      this.algorithms.count = this.loopsInput.value || this.LOOPS_DEFAULT;
   }

   nukeOptions(): void {
      this.defaultOptions();
      try {
         this.authSvc.lsDel('welcomed');
         this.authSvc.lsDel('algorithm');
         this.authSvc.lsDel('icount');
         this.authSvc.lsDel('hidepwd');
         this.authSvc.lsDel('cachetime');
         this.authSvc.lsDel('checkpwned');
         this.authSvc.lsDel('minpwdstrength');
         this.authSvc.lsDel('loops');
         this.authSvc.lsDel('ctformat');
         this.authSvc.lsDel('vclear');
         this.authSvc.lsDel('reminder');
         this.authSvc.lsDel('prand');
         this.authSvc.lsDel('trand');
      } catch (err) {
         console.error(err);
         //otherwise ignore
      }
   }

   ngAfterViewInit() {
      // ugly hack to make angular not clip the label for dropdown select elements
      this.formatLabel.nativeElement.parentElement.style.maxWidth = "calc(100%/0.7)";
      this.minStrLabel.nativeElement.parentElement.style.maxWidth = "calc(100%/0.7)";

//      this.algorithms.modes = this.algorithm;
  //    this.algorithms.count = this.loopsInput.value || this.LOOPS_DEFAULT;
   }

   setAlgorithm(alg: string | null): void {
      if (alg) {
         try {
            var algs = JSON.parse(alg);
         } catch (err) { }

         // transition from v4 and earlier
         if (!algs) {
            algs = [alg];
         }

         if (this.cipherSvc.validateAlgs(algs)) {
            this.algorithm = algs;
         }
      }
   }

   setIcount(ic: string | null): void {
      // Ignores if out of range or NaN
      setIfBetween(ic, this.ICOUNT_MIN, this.ICOUNT_MAX, (num) => {
         this.icountInput.setValue(num);
      });
   }

   setHidePwd(hide: string | null) {
      setIfBoolean(hide, (bool) => {
         this.hidePwdToggle.setValue(bool);
      });
   }

   setCacheTime(tm: string | null): void {
      setIfBetween(tm, 0, this.INACTIVITY_TIMEOUT, (num) => {
         //         this._cacheTime = num;
         this.cacheTimeInput.setValue(num);
      });
   }

   setCheckPwned(check: string | null): void {
      setIfBoolean(check, (bool) => {
         this.checkPwnedToggle.setValue(bool);
      });
   }

   setMinPwdStrength(stren: string | null): void {
      if (['0', '1', '2', '3', '4'].includes(stren!)) {
         this.strengthSelect.setValue(stren!);
      }
   }

   setLoops(lpEnd: string | null): void {
      setIfBetween(lpEnd, 1, this.LOOPS_MAX, (num) => {
         this.loopsInput.setValue(num);
      });
   }

   setCTFormat(ctFormat: string | null): void {
      if (['link', 'compact', 'indent'].includes(ctFormat!)) {
         this.formatSelect.setValue(ctFormat!);
      }
   }

   setReminder(reminder: string | null): void {
      setIfBoolean(reminder, (bool) => {
         this.reminderToggle.setValue(bool);
         this._lastReminder = bool;
      });
   }

   setVisibilityClear(clear: string | null): void {
      setIfBoolean(clear, (bool) => {
         this.clearToggle.setValue(bool);
      });
   }

   setTrueRand(trand: string | null): void {
      setIfBoolean(trand, (bool) => {
         this.trueRandToggle.setValue(bool);
//         if (!bool) {
  //          this.pseudoRand = true;
    //     }
      });
   }

   setPseudoRand(prand: string | null): void {
      setIfBoolean(prand, (bool) => {
         this.pseudoRandToggle.setValue(bool);
         if (!bool) {
            this.trueRandToggle.setValue(true);
         }
      });
   }

   @Input() set expand(expandOptions: boolean) {
      this.expandOptions = expandOptions;
   }

   @Output() loopsChange = new EventEmitter<number>();

   /*   get loops(): number {
         return this._loops;
      }

      @Input() set loops(count: number) {
         this._loops = Math.max(count, 1);
         this._loops = Math.min(count, this.LOOPS_MAX);
         this.loopsInput.setValue(this._loops);
         //      this.algorithms.count = count;
      }
   */
   setIcountWarning() {
      this.hashTimeWarning = '';
      if (this.icountInput.value) {
         const hashMillis = this.icountInput.value / this.cipherSvc.hashRate;

         // if greater than 15 seconds show message
         if (hashMillis > 15 * 1000) {
            const takeMsg = makeTookMsg(0, hashMillis, 'take');
            this.hashTimeWarning = `*password hash may ${takeMsg}`
         }
      }
   }

   onHidePwdChanged(hide: boolean | null): void {
      this.authSvc.lsSet('hidepwd', hide);
   }

   onModesChanged(modes: string[]): void {
      // Note that modes length is the max number of modes that have
      // been set, which may be larger than the current # of loops
      // This is done to preserve default values
      this.algorithm = modes;
      this.authSvc.lsSet('algorithm', JSON.stringify(modes));
   }

   onBlurLoops() {
      let loops = this.loopsInput.value || this.LOOPS_DEFAULT;
      loops = Math.max(loops, 1);
      loops = Math.min(loops, this.LOOPS_MAX);

      this.algorithms.count = loops;
      this.loopsInput.setValue(loops);
      this.authSvc.lsSet('loops', loops);

      this.loopsChange.emit(loops);
   }

   onBlurICount() {
      let icount = this.icountInput.value || this.ICOUNT_MIN;
      icount = Math.max(icount, this.ICOUNT_MIN);
      icount = Math.min(icount, this.ICOUNT_MAX);

      this.icountInput.setValue(icount);
      this.authSvc.lsSet('icount', icount);
      this.setIcountWarning();

//      this.loopsChange.emit(loops);
   }

   onBlurCacheTime() {
      let cacheTime = this.cacheTimeInput.value || 0;
      cacheTime = Math.max(cacheTime, 0);
      cacheTime = Math.min(cacheTime, this.INACTIVITY_TIMEOUT);

      this.cacheTimeInput.setValue(cacheTime);
      this.authSvc.lsSet('cachetime', cacheTime);

      //         this.loopsChange.emit(loops);

      //      if (this.pwdCached) {
      //         this.restartTimer();
      //      }
   }

   onPwdStrengthChange(minStrength: string | null): void {
      this.authSvc.lsSet('minpwdstrength', minStrength);
      //      this.clearPassword();
   }

   onCheckPwnedChange(check: boolean | null): void {
      this.authSvc.lsSet('checkpwned', check);
      //      this.clearPassword();
   }

   /*   onCacheTimerChange(cacheTime: number | null): void {
         if (cacheTime != null) {
            this._cacheTime = Math.max(cacheTime, 0);
            this._cacheTime = Math.min(this._cacheTime, this.INACTIVITY_TIMEOUT);
            //      this.authSvc.lsSet('cachetime', this.cacheTime.toString());
         }
         //      if (this.pwdCached) {
         //         this.restartTimer();
         //      }
      }*/

   onReminderChange(reminder: boolean | null) {
      if (reminder != null) {
         this._lastReminder = reminder;
         this.authSvc.lsSet('reminder', reminder);
         //     this.reformatCipherArmor();
      }
   }


   onVClearChnage(vclear: boolean | null) {
      this.authSvc.lsSet('vclear', vclear);
   }

   onFormatChange(selected: string | null) {
      if (selected == 'link') {
         const saved = this.reminderToggle.value || false;
         this.reminderToggle.setValue(false);
         this.reminderToggle.disable();
         this._lastReminder = saved;
      } else {
         this.reminderToggle.setValue(this._lastReminder);
         this.reminderToggle.enable();
      }
      this.authSvc.lsSet('ctformat', selected);
      //      this.reformatCipherArmor();
   }

   onTrueRandChanged(checked: boolean | null) {
      if (!checked) {
         this.pseudoRandToggle.disable();
         this.pseudoRandToggle.setValue(true);
      } else {
         this.pseudoRandToggle.enable();
      }
      this.authSvc.lsSet('trand', checked);
   }

   onPseudoRandChange(checked: boolean | null) {
      this.authSvc.lsSet('prand', checked);
   }

   onClickResetOptions(): void {
      this.nukeOptions();
   }

}
