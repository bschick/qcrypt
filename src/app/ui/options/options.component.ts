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
   OnInit,
   Input,
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
import { FormsModule, ReactiveFormsModule, FormControl } from '@angular/forms';
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
   public readonly FORMAT_DEFAULT = 'compact';
   public readonly CACHE_TIME_DEFAULT = 0;
   public readonly PWD_STRENGTH_DEFAULT = '3';
   public readonly REMINDER_DEFAULT = true;
   public readonly CHECK_PWNED_DEFAULT = false;
   public readonly VIS_CLEAR_DEFAULT = true;
   public readonly HIDE_PWD_DEFAULT = true;
   public readonly TRUE_RAND_DEFAULT = false;
   public readonly PSEUDO_RAND_DEFAULT = true;

   public ICOUNT_MAX = cc.ICOUNT_MAX; // Default since benchmark is async
   public ICOUNT_DEFAULT = cc.ICOUNT_DEFAULT; // Default since benchmark is async

   public loopsInput = new FormControl(this.LOOPS_DEFAULT);
   public cacheTimeInput = new FormControl(this.CACHE_TIME_DEFAULT);
   public icountInput = new FormControl(cc.ICOUNT_DEFAULT);

   public strengthSelect = new FormControl(this.PWD_STRENGTH_DEFAULT);
   public checkPwnedToggle = new FormControl(this.CHECK_PWNED_DEFAULT);
   public visClearToggle = new FormControl(this.VIS_CLEAR_DEFAULT);
   public hidePwdToggle = new FormControl(this.HIDE_PWD_DEFAULT);
   public trueRandToggle = new FormControl(this.TRUE_RAND_DEFAULT);
   public pseudoRandToggle = new FormControl({ value: this.PSEUDO_RAND_DEFAULT, disabled: true });
   public formatSelect = new FormControl(this.FORMAT_DEFAULT);
   public reminderToggle = new FormControl(this.REMINDER_DEFAULT);

   private _optionsLoaded = false;
   private _lastReminder = this.REMINDER_DEFAULT;
   private _algorithmList = ['X20-PLY'];

   @ViewChild('formatLabel') formatLabel!: ElementRef;
   @ViewChild('minStrLabel') minStrLabel!: ElementRef;
   @ViewChild('algorithms') algorithmsCmp!: AlgorithmsComponent;

   constructor(
      private authSvc: AuthenticatorService,
      private cipherSvc: CipherService,
   ) {
   }

   @Input() set expand(expandOptions: boolean) {
      this.expandOptions = expandOptions;
   }

   @Output() loopsChange = new EventEmitter<number>();
   @Output() icountChange = new EventEmitter<number>();
   @Output() cacheTimeChange = new EventEmitter<number>();
   @Output() pwdOptionsChange = new EventEmitter<boolean>();
   @Output() formatOptionsChange = new EventEmitter<boolean>();

   ngOnInit() {
      this.cacheTimeInput.valueChanges.subscribe(this.onCacheTimeChange.bind(this));
      this.strengthSelect.valueChanges.subscribe(this.onPwdStrengthChange.bind(this));
      this.checkPwnedToggle.valueChanges.subscribe(this.onCheckPwnedChange.bind(this));

      this.visClearToggle.valueChanges.subscribe(this.onVisClearChnage.bind(this));
      this.hidePwdToggle.valueChanges.subscribe(this.onHidePwdChange.bind(this));
      this.trueRandToggle.valueChanges.subscribe(this.onTrueRandChange.bind(this));
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
            // load after benchmark to overwrite benchmarks with saved values
            if (this.authSvc.isAuthenticated()) {
               this.loadOptions();
            } else {
               this.defaultOptions();
            }
         });
   }

   ngAfterViewInit() {
      // ugly hack to make angular not clip the label for dropdown select elements
      this.formatLabel.nativeElement.parentElement.style.maxWidth = "calc(100%/0.7)";
      this.minStrLabel.nativeElement.parentElement.style.maxWidth = "calc(100%/0.7)";
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
         this.algorithmsCmp.modes = this._algorithmList;
         this.algorithmsCmp.count = this.loopsInput.value || this.LOOPS_DEFAULT;
      }
   }

   async optionsLoaded() {
      while(!this._optionsLoaded) {
         await new Promise((resolve) => setTimeout(resolve, 500));
      }
   }

   defaultOptions(): void {
      this._algorithmList = ['X20-PLY'];
      this.icountInput.setValue(this.ICOUNT_DEFAULT);
      this.hidePwdToggle.setValue(this.HIDE_PWD_DEFAULT);
      this.cacheTimeInput.setValue(this.CACHE_TIME_DEFAULT);
      this.strengthSelect.setValue(this.PWD_STRENGTH_DEFAULT);
      this.checkPwnedToggle.setValue(this.CHECK_PWNED_DEFAULT);
      this.loopsInput.setValue(this.LOOPS_DEFAULT);
      this.formatSelect.setValue(this.FORMAT_DEFAULT);
      this.visClearToggle.setValue(this.VIS_CLEAR_DEFAULT);
      this.reminderToggle.setValue(this.REMINDER_DEFAULT);
      this._lastReminder = this.REMINDER_DEFAULT;
      this.pseudoRandToggle.setValue(this.PSEUDO_RAND_DEFAULT);
      this.trueRandToggle.setValue(this.TRUE_RAND_DEFAULT);

      this._optionsLoaded = false;

      // order is important, set modes first
      this.algorithmsCmp.modes = this._algorithmList;
      this.algorithmsCmp.count = this.loopsInput.value || this.LOOPS_DEFAULT;
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

   get loops(): number {
      return this.loopsInput.value || this.LOOPS_DEFAULT;
   }

   get algorithms(): string[] {
      return this._algorithmList.slice(0, this.loops);
   }

   get cacheTime(): number {
      return this.cacheTimeInput.value || this.CACHE_TIME_DEFAULT;
   }

   get icount(): number {
      return this.icountInput.value || this.ICOUNT_DEFAULT;
   }

   get minPwdStrength(): string {
      return this.strengthSelect.value || this.PWD_STRENGTH_DEFAULT;
   }

   get checkPwned(): boolean {
      return this.checkPwnedToggle.value || false;
   }

   get visClear(): boolean {
      return this.visClearToggle.value || false;
   }

   get hidePwd(): boolean {
      return this.hidePwdToggle.value || false;
   }

   get trueRand(): boolean {
      return this.trueRandToggle.value || false;
   }

   get pseudoRand(): boolean {
      return this.pseudoRandToggle.value || false;
   }

   get format(): string {
      return this.formatSelect.value || this.FORMAT_DEFAULT;
   }

   get reminder(): boolean {
      return this.reminderToggle.value || false;
   }

   private setAlgorithm(alg: string | null): void {
      if (alg) {
         try {
            var algs = JSON.parse(alg);
         } catch (err) { }

         // transition from v4 and earlier
         if (!algs) {
            algs = [alg];
         }

         if (this.cipherSvc.validateAlgs(algs)) {
            this._algorithmList = algs;
         }
      }
   }

   private setIcount(ic: string | null): void {
      // Ignores if out of range or NaN
      setIfBetween(ic, this.ICOUNT_MIN, this.ICOUNT_MAX, (num) => {
         this.icountInput.setValue(num);
      });
   }

   private setHidePwd(hide: string | null) {
      setIfBoolean(hide, (bool) => {
         this.hidePwdToggle.setValue(bool);
      });
   }

   private setCacheTime(tm: string | null): void {
      setIfBetween(tm, 0, this.INACTIVITY_TIMEOUT, (num) => {
         //         this._cacheTime = num;
         this.cacheTimeInput.setValue(num);
      });
   }

   private setCheckPwned(check: string | null): void {
      setIfBoolean(check, (bool) => {
         this.checkPwnedToggle.setValue(bool);
      });
   }

   private setMinPwdStrength(stren: string | null): void {
      if (['0', '1', '2', '3', '4'].includes(stren!)) {
         this.strengthSelect.setValue(stren!);
      }
   }

   private setLoops(lpEnd: string | null): void {
      setIfBetween(lpEnd, 1, this.LOOPS_MAX, (num) => {
         this.loopsInput.setValue(num);
      });
   }

   private setCTFormat(ctFormat: string | null): void {
      if (['link', 'compact', 'indent'].includes(ctFormat!)) {
         this.formatSelect.setValue(ctFormat!);
      }
   }

   private setReminder(reminder: string | null): void {
      setIfBoolean(reminder, (bool) => {
         this.reminderToggle.setValue(bool);
         this._lastReminder = bool;
      });
   }

   private setVisibilityClear(clear: string | null): void {
      setIfBoolean(clear, (bool) => {
         this.visClearToggle.setValue(bool);
      });
   }

   private setTrueRand(trand: string | null): void {
      setIfBoolean(trand, (bool) => {
         this.trueRandToggle.setValue(bool);
      });
   }

   private setPseudoRand(prand: string | null): void {
      setIfBoolean(prand, (bool) => {
         this.pseudoRandToggle.setValue(bool);
         if (!bool) {
            this.trueRandToggle.setValue(true);
         }
      });
   }

   private setIcountWarning() {
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

   onHidePwdChange(hide: boolean | null): void {
      this.authSvc.lsSet('hidepwd', hide);
   }

   onModesChange(modes: string[]): void {
      // Note that modes length is the max number of modes that have
      // been set, which may be larger than the current # of loops
      // This is done to preserve default values
      this._algorithmList = modes;
      this.authSvc.lsSet('algorithm', JSON.stringify(modes));
   }

   onBlurLoops() {
      let loops = this.loopsInput.value || this.LOOPS_DEFAULT;
      loops = Math.max(loops, 1);
      loops = Math.min(loops, this.LOOPS_MAX);

      this.algorithmsCmp.count = loops;
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

      this.icountChange.emit(icount);
   }

   onBlurCacheTime() {
      if (this.cacheTimeInput.value == null) {
         this.onCacheTimeChange(this.CACHE_TIME_DEFAULT);
      }
   }

   onCacheTimeChange(cacheTime: number | null) {
      if (cacheTime != null) {
         cacheTime = Math.max(cacheTime, 0);
         cacheTime = Math.min(cacheTime, this.INACTIVITY_TIMEOUT);

         if (cacheTime != this.cacheTimeInput.value) {
            this.cacheTimeInput.setValue(cacheTime);
         } else {
            this.authSvc.lsSet('cachetime', cacheTime);
            this.cacheTimeChange.emit(cacheTime);
         }
      }
   }

   onPwdStrengthChange(minStrength: string | null): void {
      this.authSvc.lsSet('minpwdstrength', minStrength);
      this.pwdOptionsChange.emit(true);
   }

   onCheckPwnedChange(check: boolean | null): void {
      this.authSvc.lsSet('checkpwned', check);
      this.pwdOptionsChange.emit(true);
   }

   onReminderChange(reminder: boolean | null) {
      if (reminder != null) {
         this._lastReminder = reminder;
         this.authSvc.lsSet('reminder', reminder);
      }
      this.formatOptionsChange.emit(true);
   }

   onVisClearChnage(vclear: boolean | null) {
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
      this.formatOptionsChange.emit(true);
   }

   onTrueRandChange(checked: boolean | null) {
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
