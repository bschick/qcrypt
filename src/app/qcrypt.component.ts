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
  ViewEncapsulation,
} from '@angular/core';
import { CommonModule, isPlatformBrowser } from '@angular/common';
import { A11yModule } from '@angular/cdk/a11y';
import {
  MatDialog,
  MAT_DIALOG_DATA,
  MatDialogRef,
  MatDialogModule,
} from '@angular/material/dialog';
import { MatRippleModule } from '@angular/material/core';
import { MatTooltipModule } from '@angular/material/tooltip';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';
import { MatMenuModule } from '@angular/material/menu';
import { MatSelectModule } from '@angular/material/select';
import { RouterOutlet } from '@angular/router';
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
import { Matcher, zxcvbnOptions } from '@zxcvbn-ts/core';
import * as zxcvbnCommonPackage from '@zxcvbn-ts/language-common';
import * as zxcvbnEnPackage from '@zxcvbn-ts/language-en';
import { translations } from '@zxcvbn-ts/language-en';
import { matcherPwnedFactory } from '@zxcvbn-ts/matcher-pwned';
import { Duration, DateTime } from 'luxon';
import { PasswordStrengthMeterComponent } from 'angular-password-strength-meter';
import { CdkAccordionModule } from '@angular/cdk/accordion';
import { MatExpansionModule } from '@angular/material/expansion';
import { ClipboardModule } from '@angular/cdk/clipboard';

type PwdDialogData = {
  message: string;
  hint: string;
  askHint: boolean;
  minStrength: number;
  hidePwd: boolean;
  loopCount: number;
  loops: number;
};

/*type Muteable<T> = { -readonly [P in keyof T]: T[P] };
type MuteableLps = { -readonly [P in keyof T]: T[P] };
type mlp = Muteable<EncContext["lps"]>;
*/
type CParams = {
  readonly alg: string;
  readonly ic: number;
  readonly mac: boolean;
  iv: Uint8Array;
  slt: Uint8Array;
};

type EncContext = {
  readonly lps: number;
  readonly v: number;
  p: CParams;
  lpCount: number;
};

type DecContext = EncContext & {
  ct: Uint8Array;
  hint?: string;
};

function isDecContext(context: EncContext | DecContext): context is DecContext {
  return (context as DecContext).ct !== undefined;
}

const ICOUNT_DEFAULT = 800000;
const ENC_VERSION = 1;

const AlgNames: { [key: string]: string } = {
  'AES-GCM': 'Galois Counter (GCM)',
  'AES-CBC': 'Cipher Block Chaining (CBC)',
  'AES-CTR': 'Counter (CTR)',
};

interface EncDecParams {
  name: string;
  [key: string]: any;
}

function bytesToBase64(bytes: Uint8Array): string {
  var binString = '';
  bytes.forEach((b, i) => {
    binString += String.fromCharCode(b);
  });
  return btoa(binString);
}

function base64ToBytes(b64: string): Uint8Array {
  var binString: string = atob(b64);
  // @ts-ignore
  return Uint8Array.from(binString, (m) => m.codePointAt(0));
}

// Min and max are inclusive and only used if not null
/*function setClamped(
  check: string | null,
  min: number | null,
  max: number | null,
  setter: (num: number) => void
): void {
  let num = Number(check);
  if (check != null && !Number.isNaN(num)) {
    if (min != null) {
      num = Math.max(num, min);
    }
    if (max != null) {
      num = Math.min(num, max);
    }
    setter(num);
  }
}*/

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

function makeTookMsg(start: number, end: number): string {
  const duration = Duration.fromMillis(end - start);
  if (duration.as('minutes') >= 1) {
    return `(took ${Math.round(duration.as('minutes') * 100) / 100} minutes)`;
  } else if (duration.as('seconds') >= 1) {
    return `(took ${Math.round(duration.as('seconds') * 100) / 100} seconds)`;
  }
  return `(took ${duration.toMillis()} millis)`;
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

class Random32 {
  private trueRandCache: Promise<Uint8Array>;

  constructor() {
    this.trueRandCache = this.downloadTrueRand();
  }

  async getRandomArray(
    trueRand: boolean,
    fallback: boolean
  ): Promise<Uint8Array> {
    if (!trueRand) {
      return crypto.getRandomValues(new Uint8Array(32));
    } else {
      const lastCache = this.trueRandCache;
      this.trueRandCache = this.downloadTrueRand();
      return lastCache
        .then((buffer) => {
          return buffer;
        })
        .catch((err) => {
          console.error(err);
          // If pseudo random fallback is disabled, then throw error
          if (!fallback) {
            throw new Error('no connection to random.org: ' + err.message);
          }
          return crypto.getRandomValues(new Uint8Array(32));
        });
    }
  }

  async downloadTrueRand(): Promise<Uint8Array> {
    const url = 'https://www.random.org/cgi-bin/randbyte?nbytes=' + 32;

    return fetch(url, {
      cache: 'no-store',
    })
      .then((response) => {
        if (response.ok) {
          return response.arrayBuffer();
        } else {
          throw new Error('random.org response: ' + response.statusText);
        }
      })
      .then((array) => {
        if (array.byteLength != 32) {
          throw new Error('missing bytes from random.org');
        }
        return new Uint8Array(array!);
      });
  }
}

@Component({
  selector: 'qcrypt-root',
  standalone: true,
  templateUrl: './qcrypt.component.html',
  styleUrl: './qcrypt.component.css',
  imports: [RouterOutlet, MatProgressSpinnerModule, MatMenuModule, MatIconModule,
    MatButtonModule, MatFormFieldModule, MatInputModule, FormsModule,
    ReactiveFormsModule, ClipboardModule, CdkAccordionModule, MatSlideToggleModule,
    MatExpansionModule, MatSelectModule, MatButtonToggleModule, A11yModule,
    MatTooltipModule, MatRippleModule, CommonModule
  ],
})
export class QCryptComponent implements OnInit, AfterViewInit {
  private mouseDown = false;
  private password: string = '';
  private hint: string | undefined;
  private addMacChanged = false;
  private intervalId: number = 0;
  //  private loopCount = 0;
  private hashRate: number = 1000; // Default since benchmark is async
  private spinnerAbove: number = 1500000; // Default since benchmark is async
  private random32: Random32;
  private actionStart: number = 0;
  private matcherPwned: Matcher;
  public cacheTimeout!: DateTime;
  public icountMin: number = 400000;
  public icountMax: number = 400000000; // Default since benchmark is async
  public icountDefault: number = ICOUNT_DEFAULT; // Default since benchmark is async
  public clearText = '';
  public stuffCached = false;
  public cipherLabel = 'Cipher Text';
  public clearLabel = 'Clear Text';
  public cipherText = '';
  public showProgress = false;
  public errorCipher = false;
  public errorClear = false;
  public expandOptions = false;
  //  @ViewChild(MatRipple) ripple: MatRipple;
  @ViewChild('clearField') clearField!: ElementRef;
  @ViewChild('cipherField') cipherField!: ElementRef;
  @ViewChild('inputArea') inputArea!: ElementRef;
  @ViewChild('fileUpload') fileUpload!: ElementRef;
  @ViewChild('formatLabel') formatLabel!: ElementRef;
  @ViewChild('minStrLabel') minStrLabel!: ElementRef;

  // options
  public algorithm = 'AES-GCM';
  public icount: number = ICOUNT_DEFAULT; // Default since benchmark is async
  public addMac = false;
  public hidePwd = true;
  public cacheTime = 30;
  public minPwdStrength = '3';
  public ctFormat = 'link';
  public loops = 1;
  public checkPwned = false;
  public trueRandom = true;
  public pseudoRandom = true;

  constructor(
    private r2: Renderer2,
    public dialog: MatDialog,
    private snackBar: MatSnackBar,
    private matIconRegistry: MatIconRegistry,
    private domSanitizer: DomSanitizer,
    @Inject(PLATFORM_ID) private platformId: Object
  ) {
    this.matIconRegistry.addSvgIcon(
      'github',
      this.domSanitizer.bypassSecurityTrustResourceUrl(
        '../assets/github-circle-white-transparent.svg'
      )
    );

    const options = {
      translations,
      dictionary: {
        ...zxcvbnCommonPackage.dictionary,
        ...zxcvbnEnPackage.dictionary,
      },
      graphs: zxcvbnCommonPackage.adjacencyGraphs,
      useLevenshteinDistance: true,
    };
    zxcvbnOptions.setOptions(options);
    this.matcherPwned = matcherPwnedFactory(fetch, zxcvbnOptions);

    // cache in case any use of true random
    this.random32 = new Random32();
  }

  setAlgorithmAndMac(alg: string | null, mac: string | null): void {
    if (['AES-GCM', 'AES-CBC', 'AES-CTR'].includes(alg!)) {
      this.algorithm = alg!;
    }
    setIfBoolean(mac, (bool) => {
      this.addMac = bool;
      if (
        (this.algorithm == 'AES-GCM' && bool) ||
        (this.algorithm != 'AES-GCM' && !bool)
      ) {
        this.addMacChanged = true;
      }
    });
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
    setIfBetween(tm, 0, 604800, (num) => {
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

  setLoops(lps: string | null): void {
    setIfBetween(lps, 0, 10, (num) => {
      this.loops = num;
    });
  }

  setCTFormat(ctFormat: string | null): void {
    if (['link', 'compact', 'indent'].includes(ctFormat!)) {
      this.ctFormat = ctFormat!;
    }
  }

  setTrueRandom(trand: string | null): void {
    setIfBoolean(trand, (bool) => {
      this.trueRandom = bool;
    });
  }

  setPseudoRandom(prand: string | null): void {
    setIfBoolean(prand, (bool) => {
      this.pseudoRandom = bool;
    });
  }

  ngAfterViewInit() {
    // ugly hack to make angular not clip the label for dropdown select elements
    this.formatLabel.nativeElement.parentElement.style.maxWidth = "calc(100%/0.75)";
    this.minStrLabel.nativeElement.parentElement.style.maxWidth = "calc(100%/0.75)";
  }

  ngOnInit(): void {
    // Is is can be greatly delayed is there is a  long running encrpt or decrypt
    // from a previous instance (tab that has not fully closed). Seems to be no way
    // to prevent that or abort an ongoing SubtleCrypto action.

    this.benchmark().finally(() => {

      // First check localStorage, then apply params (which take president)
      // (not that change are not presisted until the encrypt button is used)
      if (isPlatformBrowser(this.platformId)) {
        /* debug  
        for (let i = 0; i < localStorage.length; i++) {
          let key = localStorage.key(i)!;
          console.log(`${key}: ${localStorage.getItem(key)}`);
         } */

        this.setAlgorithmAndMac(
          localStorage.getItem('algorithm'),
          localStorage.getItem('addmac')
        );
        this.setIcount(localStorage.getItem('icount'));
        this.setHidePwd(localStorage.getItem('hidepwd'));
        this.setCacheTime(localStorage.getItem('cachetime'));
        this.setCheckPwned(localStorage.getItem('checkpwned'));
        this.setMinPwdStrength(localStorage.getItem('minpwdstrength'));
        this.setLoops(localStorage.getItem('loops'));
        this.setCTFormat(localStorage.getItem('ctformat'));
        this.setTrueRandom(localStorage.getItem('trand'));
        this.setPseudoRandom(localStorage.getItem('prand'));
      }

      let params = new HttpParams({ fromString: window.location.search });

      if (params.get('ciphertext')) {
        this.cipherText = decodeURIComponent(params.get('ciphertext')!);
        params = params.delete('ciphertext');
      }
      if (params.get('cleartext')) {
        this.clearText = decodeURIComponent(params.get('cleartext')!);
        params = params.delete('cleartext');
      }

      // If there are customized options, expand the panel by default
      if (params.keys().length > 0) {
        this.expandOptions = true;
      }

      this.setAlgorithmAndMac(params.get('algorithm'), params.get('addmac'));
      this.setIcount(params.get('icount'));
      this.setHidePwd(params.get('hidepwd'));
      this.setCacheTime(params.get('cachetime'));
      this.setCheckPwned(params.get('checkpwned'));
      this.setMinPwdStrength(params.get('minpwdstrength'));
      this.setLoops(params.get('loops'));
      this.setCTFormat(params.get('ctformat'));
      this.setTrueRandom(params.get('trand'));
      this.setPseudoRandom(params.get('prand'));

    });
  }

  async benchmark(): Promise<void> {
    // Test performance of key generation to determine when to show spinner
    // load this from advanced options
    const test_size = this.icountMin;
    const target_spinner_millis = 1250;
    const target_hash_millis = 500;
    const max_hash_millis = 5 * 60 * 1000; //5 minutes

    const pseudoRand = await this.random32.getRandomArray(false, true);

    // Pseudo-random is good enough for testing
    var cparams: CParams = {
      slt: pseudoRand.slice(0, 16),
      iv: pseudoRand.slice(16),
      ic: test_size,
      alg: 'AES-GCM',
      mac: false,
    };

    const start = Date.now();
    await this.genKeys(cparams, 'AVeryBogusPwd');
    const test_millis = Date.now() - start;

    // Calculate how many iterations take target_spinner_millis. Above that we'll show spinner
    this.hashRate = test_size / test_millis;

    // Don't allow more then ~5 minutes of pwd hashing (rounded to millions)
    this.icountMax =
      Math.round((max_hash_millis * this.hashRate) / 1000000) * 1000000;

    let rounded =
      Math.round((this.hashRate * target_hash_millis) / 100000) * 100000;
    rounded += rounded % 200000;
    const default_icount = Math.max(ICOUNT_DEFAULT, rounded);

    const spinner_icount = Math.round(target_spinner_millis * this.hashRate);

    this.icount = default_icount;
    this.icountDefault = default_icount;
    this.spinnerAbove = spinner_icount;

    console.log(
      `bench: ${test_size}i, in: ${test_millis}ms, rate: ${Math.round(
        this.hashRate
      )}i/ms, ic: ${this.icount}i, icm: ${this.icountMax}i, spin: ${this.spinnerAbove
      }i`
    );
  }

  onNewPage(): void {
    var url = window.location.origin;
    var params = new HttpParams();

    if (this.algorithm != 'AES-GCM') {
      params = params.append('algorithm', this.algorithm);
    }

    if (this.addMacChanged) {
      params = params.append('addmac', this.addMac);
    }

    if (this.icount != this.icountDefault) {
      params = params.append('icount', this.icount);
    }

    if (!this.hidePwd) {
      params = params.append('hidepwd', false);
    }

    if (this.cacheTime > 0) {
      params = params.append('cachetime', this.cacheTime);
    }

    if (this.checkPwned) {
      params = params.append('checkpwned', true);
    }

    if (this.minPwdStrength != '3') {
      params = params.append('minpwdstrength', this.minPwdStrength);
    }

    if (this.cipherText.length > 1) {
      params = params.append('ciphertext', encodeURIComponent(this.cipherText));
    }

    if (this.loops > 1) {
      params = params.append('loops', this.loops);
    }

    if (this.ctFormat != 'link') {
      params = params.append('ctformat', this.ctFormat);
    }

    if (this.trueRandom) {
      params = params.append('trand', true);
    }

    if (this.pseudoRandom) {
      params = params.append('prand', true);
    }

    if (params.keys().length > 0) {
      url += `?${params.toString()}`;
    }
    window.open(url);
  }

  onResetOptions(): void {
    this.algorithm = 'AES-GCM';
    this.icount = this.icountDefault;
    this.addMac = false;
    this.addMacChanged = false;
    this.hidePwd = true;
    this.cacheTime = 30;
    this.minPwdStrength = '3';
    this.checkPwned = false;
    this.loops = 1;
    this.ctFormat = 'link';
    this.trueRandom = true;
    this.pseudoRandom = true;

    if (isPlatformBrowser(this.platformId)) {
      localStorage.clear();
    }
    this.clearCaches();
  }

  saveOptions(): void {
    try {
      if (isPlatformBrowser(this.platformId)) {
        localStorage.setItem('algorithm', this.algorithm);
        localStorage.setItem('addmac', this.addMac.toString());
        localStorage.setItem('icount', this.icount.toString());
        localStorage.setItem('hidepwd', this.hidePwd.toString());
        localStorage.setItem('cachetime', this.cacheTime.toString());
        localStorage.setItem('checkpwned', this.checkPwned.toString());
        localStorage.setItem('minpwdstrength', this.minPwdStrength);
        localStorage.setItem('loops', this.loops.toString());
        localStorage.setItem('ctformat', this.ctFormat.toString());
        localStorage.setItem('trand', this.trueRandom.toString());
        localStorage.setItem('prand', this.pseudoRandom.toString());
      }
    } catch (err) {
      console.error(err);
      //otherwise ignore
    }
  }

  secondsRemaining() {
    let result = 0;
    if (this.stuffCached) {
      const diff = this.cacheTimeout.diff(DateTime.now());
      result = Math.max(0, Math.round(diff.toMillis() / 1000));
    }
    return result;
  }

  timerTick(): void {
    if (DateTime.now() > this.cacheTimeout) {
      this.clearCaches();
    }
  }

  restartTimer(): void {
    if (this.intervalId != 0) {
      clearInterval(this.intervalId);
      this.intervalId = 0;
    }
    this.cacheTimeout = DateTime.now().plus({ seconds: this.cacheTime });
    // @ts-ignore
    this.intervalId = setInterval(() => this.timerTick(), 1000);
  }

  clearPassword(): void {
    this.stuffCached = false;
    this.password = '';
    this.hint = '';
    if (this.intervalId != 0) {
      clearInterval(this.intervalId);
      this.intervalId = 0;
    }
  }

  clearCaches(): void {
    this.clearPassword();
    this.onClearClear();
  }

  async askForPassword(
    minStrength: number,
    context: EncContext | DecContext
  ): Promise<[string, string | undefined]> {
    if (this.checkPwned) {
      if (!zxcvbnOptions.matchers['pwned']) {
        zxcvbnOptions.addMatcher('pwned', this.matcherPwned);
      }
    } else {
      delete zxcvbnOptions.matchers['pwned'];
    }

    let hint: undefined | string;
    let loopCount: number;
    let askHint: boolean;
    if (isDecContext(context)) {
      loopCount = context.lps - context.lpCount;
      hint = context.hint;
      askHint = false;
    } else {
      loopCount = context.lpCount + 1;
      askHint = true;
    }

    var dialogRef = this.dialog.open(PasswordDialog, {
      data: {
        hint: hint,
        askHint: askHint,
        minStrength: minStrength,
        hidePwd: this.hidePwd,
        loopCount: loopCount,
        loops: context.lps,
      },
    });

    return new Promise((resolve, reject) => {
      dialogRef.afterClosed().subscribe((result) => {
        if (!result) {
          reject('process cancelled');
        } else {
          this.clearPassword();
          if (this.cacheTime > 0 && result[0]) {
            this.password = result[0];
            this.hint = result[1];
            this.stuffCached = true;
            this.restartTimer();
          }
          resolve([result[0], result[1]]);
        }
      });
    });
  }

  //-1 minStrength means no pwd strength requirments
  async getPassword(
    minStrength: number,
    context: EncContext | DecContext
  ): Promise<[string, string | undefined]> {
    if (this.stuffCached) {
      this.restartTimer();
      return Promise.resolve([this.password, this.hint]);
    } else {
      return this.askForPassword(minStrength, context);
    }
  }

  async genKeys(
    cparams: CParams,
    pwd: string
  ): Promise<[CryptoKey, CryptoKey]> {
    // may want to add a key-length option at some point, using max available now
    const KEYBYTES = 32;

    if (!pwd) {
      throw new Error('password is empty');
    }

    // Avoid briefly putting up spinner and disabling buttons
    if (cparams.ic > this.spinnerAbove) {
      this.showProgress = true;
    }

    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
      'raw',
      enc.encode(pwd),
      'PBKDF2',
      false,
      ['deriveBits', 'deriveKey']
    );

    const kbits = await window.crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: cparams.slt as Uint8Array,
        iterations: cparams.ic,
        hash: 'SHA-512',
      },
      keyMaterial,
      KEYBYTES * 2 * 8
    );

    const ebits = kbits.slice(0, KEYBYTES);
    const sbits = kbits.slice(KEYBYTES);

    const ek = await window.crypto.subtle.importKey(
      'raw',
      ebits,
      { name: cparams.alg, length: 256 },
      false,
      ['encrypt', 'decrypt']
    );

    const sk = await window.crypto.subtle.importKey(
      'raw',
      sbits,
      { name: 'HMAC', hash: 'SHA-256', length: 256 },
      false,
      ['sign', 'verify']
    );

    return [ek, sk];
  }

  async doEncrypt(
    clear_buffer: Uint8Array,
    cparams: CParams,
    pwd: string
  ): Promise<ArrayBuffer | null> {
    const [ek, sk] = await this.genKeys(cparams, pwd);
    let ed_params: EncDecParams = {
      name: cparams.alg,
    };

    if (cparams.alg == 'AES-CTR') {
      ed_params['counter'] = cparams.iv;
      ed_params['length'] = 64;
    } else {
      ed_params['iv'] = cparams.iv;
    }

    let cipherText = await window.crypto.subtle.encrypt(
      ed_params,
      ek,
      clear_buffer
    );

    if (cparams.mac) {
      const algEnc = new TextEncoder().encode(cparams.alg);
      const icEnc = new TextEncoder().encode(cparams.ic.toString());
      let ct = new Uint8Array(
        cipherText.byteLength +
        cparams.iv.length +
        cparams.slt.length +
        algEnc.length +
        icEnc.length
      );

      let offset = 0;
      ct.set(new Uint8Array(cipherText), offset);
      offset += cipherText.byteLength;
      ct.set(cparams.iv as Uint8Array, offset);
      offset += cparams.iv.length;
      ct.set(cparams.slt as Uint8Array, offset);
      offset += cparams.slt.length;
      ct.set(algEnc, offset);
      offset += algEnc.length;
      ct.set(icEnc, offset);
      const hmac = await crypto.subtle.sign('HMAC', sk, ct);

      let extended = new Uint8Array(hmac.byteLength + cipherText.byteLength);
      extended.set(new Uint8Array(hmac));
      extended.set(new Uint8Array(cipherText), hmac.byteLength);
      cipherText = extended;
    }
    return cipherText;
  }

  async doDecrypt(
    cipher_buffer: Uint8Array,
    cparams: CParams,
    pwd: string
  ): Promise<ArrayBuffer> {
    const [ek, sk] = await this.genKeys(cparams, pwd);

    let ed_params: EncDecParams = {
      name: cparams.alg,
    };

    if (cparams.alg == 'AES-CTR') {
      ed_params['counter'] = cparams.iv;
      ed_params['length'] = 64;
    } else {
      ed_params['iv'] = cparams.iv;
    }

    if (cparams.mac) {
      const hmac = cipher_buffer.slice(0, 32);
      const cipherText = cipher_buffer.slice(32);

      const algEnc = new TextEncoder().encode(cparams.alg);
      const icEnc = new TextEncoder().encode(cparams.ic.toString());
      let ct = new Uint8Array(
        cipherText.byteLength +
        cparams.iv.length +
        cparams.slt.length +
        algEnc.length +
        icEnc.length
      );

      let offset = 0;
      ct.set(cipherText, offset);
      offset += cipherText.byteLength;
      ct.set(cparams.iv as Uint8Array, offset);
      offset += cparams.iv.length;
      ct.set(cparams.slt as Uint8Array, offset);
      offset += cparams.slt.length;
      ct.set(algEnc, offset);
      offset += algEnc.length;
      ct.set(icEnc, offset);

      const valid = await crypto.subtle.verify('HMAC', sk, hmac, ct);
      if (!valid) {
        throw new Error('HMAC does not match');
      }
      cipher_buffer = cipherText;
    }

    let decrypted = window.crypto.subtle.decrypt(ed_params, ek, cipher_buffer);
    return decrypted;
  }

  /* Considered encrypting CParams for storage, but it would have to use the
  same PWD and the clearText with fixed cipher settings, and if those settings
  are less secure than the settings selected by the user for the main
  cipher it could be the weak link in guessing their PWD. So just encode
  the data to base64 to reduce desire to tamper */
  encodeCParams(cparams: CParams): string {
    let cp_copy: { [key: string]: any } = { ...cparams };
    cp_copy['slt'] = bytesToBase64(cparams.slt!);
    cp_copy['iv'] = bytesToBase64(cparams.iv!);

    // only include these if needed (helps keep cipher text small)
    if (!cp_copy['mac']) {
      delete cp_copy['mac'];
    }

    const p_buffer = new TextEncoder().encode(JSON.stringify(cp_copy));
    return bytesToBase64(p_buffer);
  }

  /* caller should catch json parse and base64 decode errors */
  decodeCParams(b64Params: string): CParams {
    const jsbytes = base64ToBytes(b64Params);
    const json = JSON.parse(new TextDecoder().decode(jsbytes));

    // Just in case someone messed with these, constrain them
    // Need to merge this with the logic in ngOnInit...
    if (!('ic' in json) || !('iv' in json) || !('slt' in json)) {
      throw new Error(
        'cipher params formatted correctly. Missing one of ic, iv, slt'
      );
    }

    if (!['AES-GCM', 'AES-CBC', 'AES-CTR'].includes(json.alg)) {
      throw new Error(
        'cipher params formatted correctly. alg was: ' + json.alg
      );
    }

    json.ic = Math.min(
      this.icountMax,
      Math.max(this.icountMin, Number(json.ic) ? Number(json.ic) : 0)
    );

    return {
      alg: json.alg,
      ic: json.ic,
      mac: json.mac ? true : false,
      iv: base64ToBytes(json.iv),
      slt: base64ToBytes(json.slt),
    };
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

  onAlgorithmChange(value: string): void {
    if (!this.addMacChanged) {
      this.addMac = value != 'AES-GCM';
    }
  }

  onMacChange(value: boolean) {
    this.addMacChanged = true;
  }

  toastMessage(msg: string): void {
    this.snackBar.open(msg, '', {
      duration: 2000,
    });
  }

  showHelp(): void {
    var dialogRef = this.dialog.open(HelpDialog);
  }

  onClearCipher(): void {
    this.errorCipher = false;
    this.cipherText = '';
    this.cipherLabel = 'Cipher Text';
    //    this.toastMessage('Cipher Text Cleared');
  }

  onClearClear(): void {
    this.errorClear = false;
    this.clearText = '';
    this.clearLabel = 'Clear Text';
    //    this.toastMessage('Cleat Text Cleared');
  }

  onEncryptClicked(): void {
    if (this.clearText.length < 1) {
      this.showEncryptError('Enter clear text to encrypt');
      this.r2.selectRootElement('#clearInput').focus();
      return;
    }

    const savedClearText = this.clearText;
    this.loops = Math.min(
      Math.max(1, Number(this.loops) ? Number(this.loops) : 0),
      10
    );
    if (this.icount < this.icountMin) {
      this.icount = this.icountMin;
    }

    if (this.loops > 1) {
      // it's confusing to use cached password when looping so
      // start from scratch
      this.clearPassword();
    }

    let cp: CParams = {
      alg: this.algorithm,
      ic: this.icount,
      mac: this.addMac,
      iv: new Uint8Array(), // placeholder
      slt: new Uint8Array(), // placeholder
    };
    let econtext: EncContext = {
      lps: this.loops,
      lpCount: 0,
      v: ENC_VERSION,
      p: cp,
    };

    this.makeCipherText(econtext).then(() => {
      this.saveOptions();
      // After > 1 loop, its confusing to leave intermediate stuff
      if (this.stuffCached) {
        this.clearText = savedClearText;
      } else {
        this.onClearClear();
      }
    });
  }

  async makeCipherText(econtext: EncContext): Promise<void> {
    this.onClearCipher();

    try {
      var [pwd, hint] = await this.getPassword(+this.minPwdStrength, econtext);
    } catch (err) {
      // ignore since it was likely a cancel of the password dialog
      console.log(err);
      return;
    }

    try {
      const randomArray = await this.random32.getRandomArray(
        this.trueRandom,
        this.pseudoRandom
      );

      // Create a new salt each time a key is derviced from the password.
      // https://crypto.stackexchange.com/questions/53032/salt-for-non-stored-passwords
      econtext.p.slt = randomArray.slice(0, 16);
      econtext.p.iv = randomArray.slice(16);

      const clearBuffer = new TextEncoder().encode(this.clearText);
      this.actionStart = Date.now();
      const encrypted = await this.doEncrypt(clearBuffer, econtext.p, pwd);

      // null means aborted, without an error to report
      if (encrypted != null) {
        econtext.lpCount += 1;

        const dcontext: DecContext = {
          ct: new Uint8Array(encrypted),
          hint: hint,
          ...econtext,
        };
        this.showCipherText(this.getCiherTextFrom(dcontext));

        if (econtext.lpCount < econtext.lps) {
          this.clearCaches();
          this.clearText = this.cipherText;
          return this.makeCipherText(econtext);
        }
      }
    } catch (something) {
      console.error(something);
      if (something instanceof Error) {
        this.showEncryptError(
          'Could not encrypt text: (' + something.message + ')'
        );
      }
    } finally {
      this.showProgress = false;
    }
  }

  onDecryptClicked(): void {
    if (this.cipherText.length < 1) {
      this.showDecryptError('Enter cipher text to decrypt');
      this.r2.selectRootElement('#cipherInput').focus();
      return;
    }

    const savedCipherText = this.cipherText;

    try {
      const dcontext = this.getDecContextFrom(this.cipherText);

      if (dcontext.lps! > 1) {
        // it's confusing to use cached password when looping so
        // start from scratch
        this.clearPassword();
      }

      this.makeClearText(dcontext).then(() => {
        // After > 1 loops, tbere is intermediate stuff in cipherText
        this.cipherText = savedCipherText;
      });
    } catch (err) {
      if (err instanceof Error) {
        this.showDecryptError(err.message);
      }
    }
  }

  async makeClearText(dcontext: DecContext): Promise<void> {
    this.onClearClear();

    try {
      //-1 means no pwd strength requirments
      var [pwd, _] = await this.getPassword(-1, dcontext);
    } catch (err) {
      // ignore since it was likely a cancel of the password dialog
      console.log(err);
      return;
    }

    try {
      this.actionStart = Date.now();
      const decrypted = await this.doDecrypt(dcontext.ct, dcontext.p, pwd);

      // null means aborted, without an error to report
      if (decrypted != null) {
        this.showClearText(decrypted);
        dcontext.lpCount += 1;

        if (dcontext.lpCount < dcontext.lps!) {
          this.cipherText = this.clearText;
          const nextContext = this.getDecContextFrom(this.clearText);
          // A bit hacky... preserve top level loop information
          (nextContext.lps as number) = dcontext.lps;
          nextContext.lpCount = dcontext.lpCount;
          this.clearCaches();
          return this.makeClearText(nextContext);
        }
      }
    } catch (something) {
      console.error(something);
      if (something instanceof Error) {
        this.showDecryptError(
          'Could not decrypt Cipher Text. You may be using the wrong password or the Cipher Text was changed. (' +
          something.message + ')'
        );
      }
    } finally {
      this.showProgress = false;
    }
  }

  showDecryptError(msg: string): void {
    this.clearText = msg;
    this.errorClear = true;
    this.clearLabel = 'Error';
  }

  showEncryptError(msg: string): void {
    this.cipherText = msg;
    this.errorCipher = true;
    this.cipherLabel = 'Error';
  }

  showCipherText(cipherText: string): void {
    this.cipherText = cipherText;
    this.errorCipher = false;

    const tookMsg = makeTookMsg(this.actionStart, Date.now());
    this.cipherLabel = 'Cipher Text ' + tookMsg;
  }

  showClearText(clear: ArrayBuffer): void {
    this.clearText = new TextDecoder().decode(clear);
    this.errorClear = false;

    const tookMsg = makeTookMsg(this.actionStart, Date.now());
    this.clearLabel = 'Clear Text ' + tookMsg;
  }

  getCiherTextFrom(dcontext: DecContext): string {
    // Rebuild object to control ordering (better way to do this?)
    let result: { [key: string]: string | number } = {};
    if (dcontext.hint) {
      result['hint'] = dcontext.hint;
    }

    result['ct'] = bytesToBase64(dcontext.ct);
    result['p'] = this.encodeCParams(dcontext.p);

    // To reduce CT size, only include this stuff at the outer
    // most loop (and lps when there is > 1). Should consider moving cparams.mac
    // to context since it cannot change during loops
    if (dcontext.lpCount == dcontext.lps) {
      if (dcontext.v) {
        result['v'] = dcontext.v;
      }
      if (dcontext.lps > 1) {
        result['lps'] = dcontext.lps;
      }
    }

    // Link injection and indenting only happen at the last loop
    if (dcontext.lpCount == dcontext.lps) {
      if (this.ctFormat == 'link') {
        const ctParam = encodeURIComponent(JSON.stringify(result));
        return 'https://' + location.host + '?ciphertext=' + ctParam;
      } else {
        const space = this.ctFormat == 'indent' ? 3 : 0;
        return JSON.stringify(result, null, space);
      }
    } else {
      return JSON.stringify(result);
    }
  }

  getDecContextFrom(cipherText: string): DecContext {
    try {
      let trimmed = cipherText.trim();
      if (trimmed.startsWith('https://')) {
        const ct = new URL(trimmed).searchParams.get('ciphertext');
        if (ct != null) {
          trimmed = ct;
        } else {
          const err = new Error();
          err.name = 'Url missing cihpertext';
          throw err;
        }
      } else if (trimmed.startsWith('ciphertext=')) {
        trimmed = trimmed.slice('ciphertext='.length);
      }

      // %7B is urlencoded '{' character, so decode
      if (trimmed.startsWith('%7B')) {
        trimmed = decodeURIComponent(trimmed);
      }

      var jsonParts = JSON.parse(trimmed);
    } catch (err) {
      console.error(err);
      if (err instanceof Error) {
        throw new Error('Cipher text not formatted correctly. ' + err.name);
      }
    }

    if (!('ct' in jsonParts) || !('p' in jsonParts)) {
      throw new Error(
        'Cipher text not formatted correctly. Missing one of ct or p'
      );
    }

    try {
      var cparams = this.decodeCParams(jsonParts.p);
    } catch (err) {
      console.error(err);
      if (err instanceof Error) {
        throw new Error(err.name + ' while decoding Cipher Text.p');
      } else {
        throw err;
      }
    }

    try {
      var ctBytes = base64ToBytes(jsonParts.ct);
    } catch (err) {
      console.error(err);
      if (err instanceof Error) {
        throw new Error(err.name + ' while decoding Cipher Text.ct');
      } else {
        throw err;
      }
    }

    jsonParts.lps = Math.min(
      10,
      Math.max(1, Number(jsonParts.lps) ? Number(jsonParts.lps) : 0)
    );

    return {
      lps: jsonParts.lps,
      lpCount: 0,
      v: jsonParts.v,
      p: cparams,
      ct: ctBytes,
      hint: jsonParts.hint,
    };
  }

  onTrueRandomChanged(checked: boolean) {
    if (!checked) {
      this.pseudoRandom = true;
    }
    this.clearCaches();
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
        this.cipherText = val;
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
      return this.cipherText;
    });
  }
  onClearFileDownload(event: any): void {
    this.onFileDownload('clear.txt', () => {
      return this.clearText;
    });
  }

  onClearTimerChange(): void {
    if (this.stuffCached) {
      this.restartTimer();
    }
  }

  onCipherTextInfo(): void {
    try {
      const dcontext = this.getDecContextFrom(this.cipherText);
      this.dialog.open(CipherInfoDialog, { data: dcontext.p });
    } catch (err) {
      console.error(err);
      this.dialog.open(CipherInfoDialog, { data: null });
    }
  }

  algName(alg: string): string {
    return AlgNames[alg] ? AlgNames[alg] : 'Invalid';
  }
}

@Component({
  selector: 'password-dialog',
  standalone: true,
  templateUrl: './password-dialog.html',
  encapsulation: ViewEncapsulation.None, // Needed to change stypes of stength meter
  imports: [MatDialogModule, CommonModule, MatFormFieldModule, MatMenuModule, MatInputModule,
    MatIconModule, PasswordStrengthMeterComponent, FormsModule, ReactiveFormsModule,
    MatTooltipModule, MatButtonModule],
})
export class PasswordDialog {
  public hidePwd = false;
  public passwd = '';
  public hint = '';
  public strengthPhrase = 'Strength';
  public strengthAlert = false;
  public strength = 0;
  public minStrength = 3;
  public loopCount = 0;
  public loops = 0;
  public askHint = false;

  constructor(
    private r2: Renderer2,
    public dialogRef: MatDialogRef<PasswordDialog>,
    @Inject(MAT_DIALOG_DATA) public data: PwdDialogData
  ) {
    this.hint = data.hint;
    this.askHint = data.askHint;
    this.minStrength = data.minStrength;
    this.hidePwd = data.hidePwd;
    this.loopCount = data.loopCount;
    this.loops = data.loops;
    this.onPasswordStrengthChange(0);
  }

  onAcceptClicked() {
    if (this.passwd && this.strength >= this.minStrength) {
      this.dialogRef.close([this.passwd, this.hint]);
    } else {
      this.strengthAlert = true;
      this.r2.selectRootElement('#password').focus();
    }
  }

  onPasswordStrengthChange(strength: number | null) {
    if (this.minStrength < 0) {
      return;
    }

    if (strength == null) {
      this.strength = 0;
    } else {
      this.strength = strength;
    }

    if (!this.passwd) {
      this.strengthPhrase = 'Password is empty';
    } else if (this.strength < this.minStrength) {
      this.strengthPhrase = 'Password is too weak'; // + this.strength;
    } else {
      this.strengthAlert = false;
      this.strengthPhrase = 'Password is acceptable'; // + this.strength;
    }
  }
}

@Component({
  selector: 'cipher-info-dialog',
  standalone: true,
  templateUrl: './cipher-info-dialog.html',
  imports: [MatDialogModule, MatIconModule, CommonModule, MatButtonModule],
})
export class CipherInfoDialog {
  public error;
  public ic!: number;
  public alg!: string;
  public mac!: string;
  public slt!: string;
  public iv!: string;

  constructor(
    private r2: Renderer2,
    public dialogRef: MatDialogRef<CipherInfoDialog>,
    @Inject(MAT_DIALOG_DATA) public cparams: CParams | null
  ) {
    if (cparams == null) {
      this.error = 'Invalid cipher text format';
    } else {
      this.ic = cparams.ic;
      this.alg = AlgNames[cparams.alg] ? AlgNames[cparams.alg] : 'Invalid';
      this.iv = bytesToBase64(cparams.iv as Uint8Array);
      this.slt = bytesToBase64(cparams.slt as Uint8Array);
      this.mac = cparams.mac ? 'yes' : 'no';
    }
  }
}

@Component({
  selector: 'help-dialog',
  standalone: true,
  templateUrl: './help-dialog.html',
  imports: [MatDialogModule, CommonModule, MatIconModule, MatTooltipModule,
    MatButtonModule],
})
export class HelpDialog {
  constructor(
    public dialogRef: MatDialogRef<HelpDialog>,
    @Inject(MAT_DIALOG_DATA) public data: PwdDialogData,
    private snackBar: MatSnackBar
  ) { }

}
