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
   type AfterViewInit,
   Component,
   DestroyRef,
   ElementRef,
   type OnInit,
   computed,
   inject,
   output,
   signal,
   viewChild,
} from '@angular/core';
import { CdkAccordionModule } from '@angular/cdk/accordion';
import { MatExpansionModule } from '@angular/material/expansion';
import { AlgorithmsComponent, fillModes } from '../algorithms/algorithms.component';
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
import { FormsModule } from '@angular/forms';
import { AuthenticatorService, ACTIVITY_TIMEOUT_SEC } from '../../services/authenticator.service';
import { CipherService } from '../../services/cipher.service';
import { Ciphers, makeTookMsg } from '@qcrypt/crypto';
import * as cc from '@qcrypt/crypto/consts';
import { HttpParams } from '@angular/common/http';

// Set only if num is betwee min and max (inclusive) when min and max are not null
function setIfBetween(
   check: number | string | null,
   min: number | null,
   max: number | null,
   setter: (num: number) => void,
): void {
   const num = Number(check);
   if (check != null && !Number.isNaN(num)) {
      if ((min == null || num >= min) && (max == null || num <= max)) {
         setter(num);
      }
   }
}

function setIfBoolean(check: boolean | string | null, setter: (bool: boolean) => void): void {
   if (check != null) {
      if (typeof check === 'boolean') {
         setter(check);
      } else if (['true', '1', 'yes', 'on'].includes(check.toLowerCase())) {
         setter(true);
      } else if (['false', '0', 'no', 'off'].includes(check.toLowerCase())) {
         setter(false);
      }
   }
}

@Component({
   selector: 'enc-options',
   imports: [
      CdkAccordionModule,
      MatExpansionModule,
      AlgorithmsComponent,
      MatRippleModule,
      RouterLink,
      MatIconModule,
      MatInputModule,
      MatFormFieldModule,
      MatTooltipModule,
      MatSelectModule,
      MatButtonToggleModule,
      MatSlideToggleModule,
      FormsModule,
      MatButtonModule,
   ],
   templateUrl: './options.component.html',
   styleUrl: './options.component.scss',
})
export class OptionsComponent implements OnInit, AfterViewInit {
   private readonly _authSvc = inject(AuthenticatorService);
   private readonly _cipherSvc = inject(CipherService);
   private readonly _destroyRef = inject(DestroyRef);

   protected readonly expandOptions = signal(false);
   protected readonly cipherPanelExpanded = signal(false);
   protected readonly hashTimeWarning = signal('');

   public readonly ACTIVITY_TIMEOUT = ACTIVITY_TIMEOUT_SEC;
   public readonly LOOPS_MAX = 6;
   public readonly LOOPS_DEFAULT = 1;
   public readonly ICOUNT_MIN = cc.ICOUNT_MIN;
   public readonly FORMAT_DEFAULT = 'compact';
   public readonly CACHE_TIME_DEFAULT = 0;
   public readonly PWD_STRENGTH_DEFAULT = '3';
   public readonly REMINDER_DEFAULT = true;
   public readonly CHECK_PWNED_DEFAULT = false;
   public readonly VIS_CLEAR_DEFAULT = true;
   public readonly HIDE_PWD_DEFAULT = true;

   protected readonly icountMax = signal<number>(cc.ICOUNT_MAX); // Default since benchmark is async
   public ICOUNT_DEFAULT = cc.ICOUNT_DEFAULT; // Default since benchmark is async

   protected readonly loopsInput = signal<number | null>(this.LOOPS_DEFAULT);
   protected readonly cacheTimeInput = signal<number | null>(this.CACHE_TIME_DEFAULT);
   protected readonly icountInput = signal<number | null>(cc.ICOUNT_DEFAULT);

   protected readonly strengthSelect = signal<string>(this.PWD_STRENGTH_DEFAULT);
   protected readonly checkPwnedToggle = signal<boolean>(this.CHECK_PWNED_DEFAULT);
   protected readonly visClearToggle = signal<boolean>(this.VIS_CLEAR_DEFAULT);
   protected readonly hidePwdToggle = signal<boolean>(this.HIDE_PWD_DEFAULT);
   protected readonly formatSelect = signal<string>(this.FORMAT_DEFAULT);
   protected readonly reminderToggle = signal<boolean>(this.REMINDER_DEFAULT);
   protected readonly reminderLocked = computed(() => this.formatSelect() === 'link');

   protected readonly algorithmList = signal<cc.CipherAlgs[]>(['X20-PLY']);
   protected readonly loopCount = signal<number>(this.LOOPS_DEFAULT);

   private _optionsLoaded = false;
   private _lastReminder = this.REMINDER_DEFAULT;
   private _userId: string | null = null;

   readonly formatLabel = viewChild.required<ElementRef>('formatLabel');
   readonly minStrLabel = viewChild.required<ElementRef>('minStrLabel');

   readonly loopsChange = output<number>();
   readonly icountChange = output<number>();
   readonly cacheTimeChange = output<number>();
   readonly pwdOptionsChange = output<boolean>();
   readonly formatOptionsChange = output<boolean>();

   ngOnInit() {
      // This can be greatly delayed is there is a long running async benchmark or
      // encrpt or decrypt from a previous instance (tab that has not fully closed).
      // Seems to be no way to prevent that or abort an ongoing SubtleCrypto action.
      this._cipherSvc
         .benchmark(this.ICOUNT_MIN)
         .then(([icount, icountMax, _hashRate]) => {
            this._setIcount(icount);
            this.ICOUNT_DEFAULT = icount;
            this.icountMax.set(icountMax);
         })
         .finally(() => {
            // load after benchmark to overwrite benchmarks with saved values
            this._authSvc.ready.then(() => {
               // The benchmark can finish after this component is destroyed, and loading then emits to
               // destroyed outputs
               if (!this._destroyRef.destroyed) {
                  if (this._authSvc.hasSession()) {
                     this.loadOptions(this._authSvc.userId);
                  } else {
                     this._defaultOptions();
                  }
               }
            });
         });
   }

   ngAfterViewInit() {
      // ugly hack to make angular not clip the label for dropdown select elements
      this.formatLabel().nativeElement.parentElement.style.maxWidth = 'calc(100%/0.7)';
      this.minStrLabel().nativeElement.parentElement.style.maxWidth = 'calc(100%/0.7)';
   }

   loadOptions(userId: string) {
      // URL parameters are applied after the stored values, so they take precedence.
      /* debug
      for (let i = 0; i < localStorage.length; i++) {
        let key = localStorage.key(i)!;
        console.log(`${key}: ${this._authSvc.lsGet(key)}`);
       } */
      this._userId = userId;
      if (!this._optionsLoaded) {
         this._optionsLoaded = true;

         // set reminder first to reload _lastReminder, which get used in other settings
         this._setReminder(this._lsGet('reminder'));
         this._setAlgorithm(this._lsGet('algorithm'));
         this._setIcount(this._lsGet('icount'));
         this._setHidePwd(this._lsGet('hidepwd'));
         this._setCacheTime(this._lsGet('cachetime'));
         this._setCheckPwned(this._lsGet('checkpwned'));
         this._setMinPwdStrength(this._lsGet('minpwdstrength'));
         this._setLoops(this._lsGet('loops'));
         this._setCTFormat(this._lsGet('ctformat'));
         this._setVisibilityClear(this._lsGet('vclear'));

         const params = new HttpParams({ fromString: window.location.search });

         // If there are customized options, expand the panel by default
         if (params.keys().some((p) => !['cipherarmor', 'cleartext'].includes(p))) {
            this.expandOptions.set(true);
         }

         this._setReminder(params.get('reminder'));
         this._setAlgorithm(params.get('algorithm'));
         this._setIcount(params.get('icount'));
         this._setHidePwd(params.get('hidepwd'));
         this._setCacheTime(params.get('cachetime'));
         this._setCheckPwned(params.get('checkpwned'));
         this._setMinPwdStrength(params.get('minpwdstrength'));
         this._setLoops(params.get('loops'));
         this._setCTFormat(params.get('ctformat'));
         this._setVisibilityClear(params.get('vclear'));

         this._setIcountWarning();
         this.loopCount.set(this.loops);
      }
   }

   async optionsLoaded() {
      while (!this._optionsLoaded) {
         await new Promise((resolve) => setTimeout(resolve, 500));
      }
   }

   private _defaultOptions(): void {
      this._setIcount(this.ICOUNT_DEFAULT);
      this._setHidePwd(this.HIDE_PWD_DEFAULT);
      this._setCacheTime(this.CACHE_TIME_DEFAULT);
      this._setCheckPwned(this.CHECK_PWNED_DEFAULT);
      this._setMinPwdStrength(this.PWD_STRENGTH_DEFAULT);
      this._setLoops(this.LOOPS_DEFAULT);
      this._setCTFormat(this.FORMAT_DEFAULT);
      this._setVisibilityClear(this.VIS_CLEAR_DEFAULT);
      // set reminder last to override other changes above
      this._setReminder(this.REMINDER_DEFAULT);

      this.algorithmList.set(['X20-PLY']);
      this.loopCount.set(this.loops);
      this._lsSet('algorithm', JSON.stringify(this.algorithmList()));

      // these values are only stored when during onblur, so set manually
      this._lsSet('loops', this.LOOPS_DEFAULT);
      this._lsSet('icount', this.ICOUNT_DEFAULT);
   }

   detachOptions(): void {
      this._optionsLoaded = false;
      this._userId = null;
      this._defaultOptions();
   }

   nukeSensitiveOptions(): void {
      try {
         this._lsDel('algorithm');
         this._lsDel('minpwdstrength');
         this._lsDel('loops');
         this.detachOptions();
      } catch (err) {
         console.error(err);
         //otherwise ignore
      }
   }

   nukeAllOptions(): void {
      try {
         this._lsDel('algorithm');
         this._lsDel('icount');
         this._lsDel('hidepwd');
         this._lsDel('cachetime');
         this._lsDel('checkpwned');
         this._lsDel('minpwdstrength');
         this._lsDel('loops');
         this._lsDel('ctformat');
         this._lsDel('vclear');
         this._lsDel('reminder');
         this.detachOptions();
      } catch (err) {
         console.error(err);
         //otherwise ignore
      }
   }

   get loops(): number {
      return this.loopsInput() || this.LOOPS_DEFAULT;
   }

   get algorithms(): cc.CipherAlgs[] {
      return fillModes(this.algorithmList(), this.loops);
   }

   get cacheTime(): number {
      return this.cacheTimeInput() || this.CACHE_TIME_DEFAULT;
   }

   get icount(): number {
      return this.icountInput() || this.ICOUNT_DEFAULT;
   }

   get minPwdStrength(): string {
      return this.strengthSelect() || this.PWD_STRENGTH_DEFAULT;
   }

   get checkPwned(): boolean {
      return this.checkPwnedToggle() || false;
   }

   get visClear(): boolean {
      return this.visClearToggle() || false;
   }

   get hidePwd(): boolean {
      return this.hidePwdToggle() || false;
   }

   get format(): string {
      return this.formatSelect() || this.FORMAT_DEFAULT;
   }

   get reminder(): boolean {
      return this.reminderToggle() || false;
   }

   private _setAlgorithm(alg: string | null): void {
      if (alg) {
         let algs: string[] | undefined;
         try {
            algs = JSON.parse(alg);
         } catch {}

         // transition from v4 and earlier
         if (!algs) {
            algs = [alg];
         }

         this.algorithmList.set(Ciphers.validateAlgs(algs));
      }
   }

   // Where an option has a change handler, its setter calls it directly so the value is saved and
   // announced even when set programmatically
   private _setIcount(ic: number | string | null): void {
      // Ignores if out of range or NaN
      setIfBetween(ic, this.ICOUNT_MIN, this.icountMax(), (num) => {
         this.icountInput.set(num);
      });
   }

   private _setHidePwd(hide: boolean | string | null) {
      setIfBoolean(hide, (bool) => {
         this.hidePwdToggle.set(bool);
         this.onHidePwdChange(bool);
      });
   }

   private _setCacheTime(tm: number | string | null): void {
      setIfBetween(tm, 0, this.ACTIVITY_TIMEOUT, (num) => {
         //         this._cacheTime = num;
         this.cacheTimeInput.set(num);
         this.onCacheTimeChange(num);
      });
   }

   private _setCheckPwned(check: boolean | string | null): void {
      setIfBoolean(check, (bool) => {
         this.checkPwnedToggle.set(bool);
         this.onCheckPwnedChange(bool);
      });
   }

   private _setMinPwdStrength(stren: string | null): void {
      if (['0', '1', '2', '3', '4'].includes(stren!)) {
         this.strengthSelect.set(stren!);
         this.onPwdStrengthChange(stren);
      }
   }

   private _setLoops(lpEnd: number | string | null): void {
      setIfBetween(lpEnd, 1, this.LOOPS_MAX, (num) => {
         this.loopsInput.set(num);
      });
   }

   private _setCTFormat(ctFormat: string | null): void {
      if (['link', 'compact', 'indent'].includes(ctFormat!)) {
         this.formatSelect.set(ctFormat!);
         this.onFormatChange(ctFormat);
      }
   }

   private _setReminder(reminder: boolean | string | null): void {
      setIfBoolean(reminder, (bool) => {
         this.reminderToggle.set(bool);
         this.onReminderChange(bool);
      });
   }

   private _setVisibilityClear(clear: boolean | string | null): void {
      setIfBoolean(clear, (bool) => {
         this.visClearToggle.set(bool);
         this.onVisClearChnage(bool);
      });
   }

   private _setIcountWarning() {
      this.hashTimeWarning.set('');
      const icount = this.icountInput();
      if (icount) {
         const hashMillis = icount / this._cipherSvc.hashRate;

         // if greater than 15 seconds show message
         if (hashMillis > 15 * 1000) {
            const takeMsg = makeTookMsg(0, hashMillis, 'take');
            this.hashTimeWarning.set(`*password hash may ${takeMsg}`);
         }
      }
   }

   protected onHidePwdChange(hide: boolean | null): void {
      this._lsSet('hidepwd', hide);
   }

   protected onModesChange(modes: cc.CipherAlgs[]): void {
      // Note that modes length is the max number of modes that have
      // been set, which may be larger than the current # of loops
      // This is done to preserve default values
      this.algorithmList.set(modes);
      this._lsSet('algorithm', JSON.stringify(modes));
   }

   protected onBlurLoops() {
      let loops = this.loopsInput() || this.LOOPS_DEFAULT;
      loops = Math.max(loops, 1);
      loops = Math.min(loops, this.LOOPS_MAX);

      this.loopCount.set(loops);
      this._setLoops(loops);
      this._lsSet('loops', loops);

      this.loopsChange.emit(loops);
   }

   protected onBlurICount() {
      let icount = this.icountInput() || this.ICOUNT_MIN;
      icount = Math.max(icount, this.ICOUNT_MIN);
      icount = Math.min(icount, this.icountMax());

      this._setIcount(icount);
      this._lsSet('icount', icount);
      this._setIcountWarning();

      this.icountChange.emit(icount);
   }

   protected onBlurCacheTime() {
      if (this.cacheTimeInput() == null) {
         this.onCacheTimeChange(this.CACHE_TIME_DEFAULT);
      }
   }

   protected onCacheTimeChange(cacheTime: number | null) {
      if (cacheTime != null) {
         cacheTime = Math.max(cacheTime, 0);
         cacheTime = Math.min(cacheTime, this.ACTIVITY_TIMEOUT);

         if (cacheTime !== this.cacheTimeInput()) {
            this._setCacheTime(cacheTime);
         } else {
            this._lsSet('cachetime', cacheTime);
            this.cacheTimeChange.emit(cacheTime);
         }
      }
   }

   protected onPwdStrengthChange(minStrength: string | null): void {
      this._lsSet('minpwdstrength', minStrength);
      this.pwdOptionsChange.emit(true);
   }

   protected onCheckPwnedChange(check: boolean | null): void {
      this._lsSet('checkpwned', check);
      this.pwdOptionsChange.emit(true);
   }

   protected onReminderChange(reminder: boolean | null) {
      // don't save reminder state if in link format (reminder is always false)
      if (this.formatSelect() !== 'link') {
         if (this._lsSet('reminder', reminder)) {
            this._lastReminder = reminder!;
         }
         this.formatOptionsChange.emit(true);
      }
   }

   protected onVisClearChnage(vclear: boolean | null) {
      this._lsSet('vclear', vclear);
   }

   protected onFormatChange(selected: string | null) {
      if (selected === 'link') {
         const saved = this.reminderToggle() || false;
         this._setReminder(false);
         this._lastReminder = saved;
      } else {
         this._setReminder(this._lastReminder);
      }
      this._lsSet('ctformat', selected);
      this.formatOptionsChange.emit(true);
   }

   protected onClickResetOptions(): void {
      this._defaultOptions();
   }

   private _lsGet(key: string): string | null {
      if (this._userId) {
         return localStorage.getItem(this._userId + key);
      }
      return null;
   }

   private _lsSet(key: string, value: string | number | boolean | null): boolean {
      if (value != null && this._userId) {
         localStorage.setItem(this._userId + key, value.toString());
         return true;
      }
      return false;
   }

   private _lsDel(key: string) {
      if (this._userId) {
         localStorage.removeItem(this._userId + key);
      }
   }
}
