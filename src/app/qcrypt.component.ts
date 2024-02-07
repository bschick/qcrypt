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
import * as sodium from 'libsodium-wrappers';
import * as cs from './cipher-stuff';

const MAX_LOOPS = 10;

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

type Context = {
  readonly lpEnd: number;
  lp: number;
}
type EncContext = Context & {
  cipher: cs.Cipher;
};

type DecContext = Context & {
  ct: string;
};

function isDecContext(context: Context): context is DecContext {
  return (context as DecContext).ct !== undefined;
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
  private pksig = new Uint8Array([101, 246, 72, 149, 67, 228, 149, 35, 60, 124, 81, 187, 157, 96, 208, 217, 123, 147, 228, 60, 84, 214, 198, 116, 192, 162, 178, 147, 50, 119, 97, 251]);
  private mouseDown = false;
  private cachedPassword: string = '';
  private cachedHint: string = '';
  private intervalId: number = 0;
  private hashRate: number = 1000; // Default since benchmark is async
  private spinnerAbove: number = 1500000; // Default since benchmark is async
  private actionStart: number = 0;
  private matcherPwned: Matcher;
  public cacheTimeout!: DateTime;
  public icountMin: number = cs.ICOUNT_MIN;
  public icountMax: number = cs.ICOUNT_MAX; // Default since benchmark is async
  public icountDefault: number = cs.ICOUNT_DEFAULT; // Default since benchmark is async
  public clearText = '';
  public stuffCached = false;
  public cipherLabel = 'Cipher Armor';
  public clearLabel = 'Clear Text';
  public cipherArmor = '';
  public showProgress = false;
  public errorCipher = false;
  public errorClear = false;
  public expandOptions = false;

  public challenge = new Uint8Array([87, 77, 111, 230, 232, 248, 72, 143, 107, 250, 84, 22, 31, 111, 131, 234, 158, 121, 216, 207, 213, 49, 35, 230, 235, 129, 43, 41, 224, 197, 190, 70]);
  public uid = new Uint8Array([143, 101, 176, 207, 203, 0, 213, 172, 64, 130, 128, 168, 47, 111, 85, 72, 92, 131, 0, 76, 97, 205, 129, 141, 34, 246, 141, 247, 222, 243, 224, 20]);

  //  @ViewChild(MatRipple) ripple: MatRipple;
  @ViewChild('clearField') clearField!: ElementRef;
  @ViewChild('cipherField') cipherField!: ElementRef;
  @ViewChild('inputArea') inputArea!: ElementRef;
  @ViewChild('fileUpload') fileUpload!: ElementRef;
  @ViewChild('formatLabel') formatLabel!: ElementRef;
  @ViewChild('minStrLabel') minStrLabel!: ElementRef;

  // options
  public algorithm = 'AES-GCM';
  public icount: number = cs.ICOUNT_DEFAULT; // Default since benchmark is async
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

  setLoops(lpEnd: string | null): void {
    setIfBetween(lpEnd, 0, 10, (num) => {
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

    // This can be greatly delayed is there is a long running async benchmark or
    // encrpt or decrypt from a previous instance (tab that has not fully closed). 
    // Seems to be no way to prevent that or abort an ongoing SubtleCrypto action.

    this.benchmark().finally(() => {

      // First check localStorage, then apply params (which take president)
      // (not that change are not presisted until the encrypt button is used)
      if (isPlatformBrowser(this.platformId)) {
        /* debug  
        for (let i = 0; i < localStorage.length; i++) {
          let key = localStorage.key(i)!;
          console.log(`${key}: ${localStorage.getItem(key)}`);
         } */

        this.setAlgorithm(localStorage.getItem('algorithm'));
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

      if (params.get('cipherarmor')) {
        this.cipherArmor = decodeURIComponent(params.get('cipherarmor')!);
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
      this.setTrueRandom(params.get('trand'));
      this.setPseudoRandom(params.get('prand'));

    });

    this.getPKSignature().catch(
      () => {
        console.log('fail1')
        this.createPKSignature().then( () => {
          // 1pass for example fails if call too quickly
          setTimeout( () => {
            this.getPKSignature();
          }, 2000);
        })
      }
    ).then( () => {
      console.log('worked')
    }).catch( (err) => {
      console.log('fail2')
    });

  }

  async getPKSignature() : Promise<Credential | null> {

    console.log('enter getPKSignature')

    const publicKey = {
      challenge: this.challenge,
      userVerification: "discouraged" as UserVerificationRequirement,
    }
    return navigator.credentials.get({ publicKey }).then((publicKeyCredential) => {
      if( publicKeyCredential && publicKeyCredential instanceof PublicKeyCredential) {
        const response = publicKeyCredential.response;
        if (response && response instanceof AuthenticatorAssertionResponse) {
          console.log(response.clientDataJSON);

          console.log(response.authenticatorData);

          console.log(
            "Signature: " + response.signature.byteLength + " : " +
            new Uint8Array(response.signature));

          console.log(response.userHandle);

          return null;
        }
      }

      throw new Error("unknown user");
    });
  }

  async createPKSignature() : Promise<Credential | null> {
    console.log('enter createPKSignature')

    const publicKey: PublicKeyCredentialCreationOptions = {
      authenticatorSelection: {
        residentKey: "required"
      },
      challenge: this.challenge,
      rp: {
        id: "t1.schicks.net",
        name: "Quick Crypt" }, // For testing, do not include Id directly (comes from browser)
      user: {
        id: this.uid,
        name: "user@qcrypt.schicks.net",
        displayName: "Quick Crypt User"
      },
      pubKeyCredParams: [
        { type: "public-key", alg: 3 },
        { type: "public-key", alg: 24 },
        { type: "public-key", alg: 1 },
        { type: "public-key", alg: 7 },
        { type: "public-key", alg: -7 },]
    };

    return navigator.credentials.create({ publicKey }).then((publicKeyCredential) => {
      if (publicKeyCredential && publicKeyCredential instanceof PublicKeyCredential) {
        const response = publicKeyCredential.response;
        if (response && response instanceof AuthenticatorAttestationResponse) {

          // Access attestationObject ArrayBuffer
          const attestationObj = response.attestationObject;
          console.log(attestationObj);

          // Access client JSON
          const clientJSON = response.clientDataJSON;
          console.log(clientJSON);

          // Return authenticator data ArrayBuffer
          const authenticatorData = response.getAuthenticatorData();
          console.log(authenticatorData);

          // Return public key ArrayBuffer
          const pk = response.getPublicKey();
          console.log(pk);

          // Return public key algorithm identifier
          const pkAlgo = response.getPublicKeyAlgorithm();
          console.log(pkAlgo);

          // Return permissible transports array
          const transports = response.getTransports();
          console.log(transports);

          return null;
        }
      }
      throw new Error("pk creation failed");
    });

  }

  async benchmark(): Promise<void> {
    // Test performance of key generation to determine when to show spinner
    // load this from advanced options
    const test_size = this.icountMin;
    const target_spinner_millis = 1250;
    const target_hash_millis = 500;
    const max_hash_millis = 5 * 60 * 1000; //5 minutes

    let cipher = new cs.Cipher('AES-GCM', test_size, false);

    const start = Date.now();
    await cipher.genCipherKey('AVeryBogusPwd', this.pksig, new Uint8Array(cs.SLT_BYTES));
    const test_millis = Date.now() - start;

    // Calculate how many iterations take target_spinner_millis. Above that we'll show spinner
    this.hashRate = test_size / test_millis;

    // Don't allow more then ~5 minutes of pwd hashing (rounded to millions)
    this.icountMax =
      Math.min(cs.ICOUNT_MAX,
        Math.round((max_hash_millis * this.hashRate) / 1000000) * 1000000);

    let target_icount = Math.round((this.hashRate * target_hash_millis) / 100000) * 100000;
    target_icount += 200000;
    const default_icount = Math.max(cs.ICOUNT_DEFAULT, target_icount);

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

    if (this.cipherArmor.length > 1) {
      params = params.append('cipherarmor', encodeURIComponent(this.cipherArmor));
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
    this.cachedPassword = '';
    this.cachedHint = '';
    if (this.intervalId != 0) {
      clearInterval(this.intervalId);
      this.intervalId = 0;
    }
  }

  clearCaches(): void {
    this.clearPassword();
    this.onClearClear();
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
    this.cipherArmor = '';
    this.cipherLabel = 'Cipher Armor';
    //    this.toastMessage('Cipher Armor Text Cleared');
  }

  onClearClear(): void {
    this.errorClear = false;
    this.clearText = '';
    this.clearLabel = 'Clear Text';
    //    this.toastMessage('Cleat Text Cleared');
  }

  cipherReadyNotice(cparams: cs.CParams) {
    this.actionStart = Date.now();
    // Avoid briefly putting up spinner and disabling buttons
    if (cparams.ic > this.spinnerAbove) {
      this.showProgress = true;
    }
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

    let cipher = new cs.Cipher(
      this.algorithm,
      this.icount,
      this.trueRandom,
      this.pseudoRandom
    );

    let econtext: EncContext = {
      lpEnd: this.loops,
      lp: 0,
      cipher: cipher
    };

    // Don't expect makeCipherArmor to throw
    this.makeCipherArmor(econtext).then(() => {
      this.saveOptions();
      // After > 1 loop, its confusing to leave intermediate stuff
      if (this.stuffCached) {
        this.clearText = savedClearText;
      } else {
        this.onClearClear();
      }
    });
  }

  async makeCipherArmor(econtext: EncContext): Promise<void> {
    this.onClearCipher();

    try {
      try {
        var [pwd, hint] = await this.getPassword(+this.minPwdStrength, '', econtext);
      } catch (err) {
        // ignore since it was likely a cancel of the password dialog
        console.log(err);
        return;
      }

      const clearBytes = new TextEncoder().encode(this.clearText);
      const encryptedBytes = await econtext.cipher.encrypt(
        pwd, hint, this.pksig, clearBytes, this.cipherReadyNotice.bind(this)
      );

      // null means aborted, without an error to report
      if (encryptedBytes != null) {
        econtext.lp += 1;

        const dcontext: DecContext = {
          ct: encryptedBytes,
          ...econtext,
        };
        this.showCipherArmorAndTime(this.getCipherArmorFrom(dcontext));

        if (econtext.lp < econtext.lpEnd) {
          this.clearCaches();
          this.clearText = this.cipherArmor;
          return this.makeCipherArmor(econtext);
        }
      }
    } catch (something) {
      console.error(something);
      if (something instanceof Error) {
        this.showEncryptError('Could not encrypt text');
      }
    } finally {
      this.showProgress = false;
    }
  }

  onDecryptClicked(): void {
    if (this.cipherArmor.length < 1) {
      this.showDecryptError('Enter cipher armor text to decrypt');
      this.r2.selectRootElement('#cipherInput').focus();
      return;
    }

    const savedCipherArmor = this.cipherArmor;

    // There may be a cleaner way to do this, but create an async wrapper
    // so that we can have a unified catch hanlder with extra try catch nesting
    const awrap = async () => {
      const dcontext = this.getDecContextFrom(this.cipherArmor);
      if (dcontext.lpEnd! > 1) {
        // it's confusing to use cached password when looping so
        // start from scratch
        this.clearPassword();
      }

      // This updates Cipher Armor UI field
      await this.makeClearText(dcontext);

      // In case > 1 loops, tbere is intermediate stuff in cipherArmor
      this.cipherArmor = savedCipherArmor;
    }

    // Execute and catch error from sync or async code
    awrap().catch((err) => {
      if (err instanceof Error) {
        this.showDecryptError(err.message);
      }
    });
  }

  async makeClearText(dcontext: DecContext): Promise<void> {
    this.onClearClear();

    try {
      const decrypted = await cs.Cipher.decrypt(
        async (hint) => {
          const [pwd, _] = await this.getPassword(-1, hint, dcontext);
          return pwd;
        },
        this.pksig,
        dcontext.ct,
        this.cipherReadyNotice.bind(this)
      );

      // null means aborted, without an error to report
      if (decrypted != null) {
        this.showClearTextAndTime(decrypted);
        dcontext.lp += 1;

        if (dcontext.lp < dcontext.lpEnd) {
          this.cipherArmor = this.clearText;
          const nextContext = this.getDecContextFrom(this.clearText);
          // A bit hacky... preserve top level loop information
          (nextContext.lpEnd as number) = dcontext.lpEnd;
          nextContext.lp = dcontext.lp;
          this.clearCaches();
          return this.makeClearText(nextContext);
        }
      }
    } catch (something) {
      console.error(something);
      if (something instanceof Error) {
        this.showDecryptError(
          'Could not decrypt cipher armor text. You may be using the wrong password or the cipher armor was changed'
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
    this.cipherArmor = msg;
    this.errorCipher = true;
    this.cipherLabel = 'Error';
  }

  showCipherArmorAndTime(cipherArmor: string): void {
    this.cipherArmor = cipherArmor;
    this.errorCipher = false;

    const tookMsg = makeTookMsg(this.actionStart, Date.now());
    this.cipherLabel = 'Cipher Armor ' + tookMsg;
  }

  showClearTextAndTime(clear: ArrayBuffer): void {
    this.clearText = new TextDecoder().decode(clear);
    this.errorClear = false;

    const tookMsg = makeTookMsg(this.actionStart, Date.now());
    this.clearLabel = 'Clear Text ' + tookMsg;
  }

  getCipherArmorFrom(dcontext: DecContext): string {
    // Rebuild object to control ordering (better way to do this?)
    let result: { [key: string]: string | number } = {};
    result['ct'] = dcontext.ct;

    // To reduce CT size, only include this extra stuff at the
    // outer most loop
    if (dcontext.lp == dcontext.lpEnd) {
      if (dcontext.lp > 1) {
        result['lps'] = dcontext.lpEnd;
      }

      if (this.ctFormat == 'link') {
        const ctParam = encodeURIComponent(JSON.stringify(result));
        return 'https://' + location.host + '?cipherarmor=' + ctParam;
      } else {
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
      ct: ct,
    };
  }

  //-1 minStrength means no pwd strength requirments
  async getPassword(
    minStrength: number,
    hint: string,
    context: Context
  ): Promise<[string, string]> {
    if (this.stuffCached) {
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
    if (this.checkPwned) {
      if (!zxcvbnOptions.matchers['pwned']) {
        zxcvbnOptions.addMatcher('pwned', this.matcherPwned);
      }
    } else {
      delete zxcvbnOptions.matchers['pwned'];
    }

    let loopCount: number = context.lp + 1;
    let askHint: boolean = true;
    if (isDecContext(context)) {
      loopCount = context.lpEnd - context.lp;
      askHint = false;
    }

    var dialogRef = this.dialog.open(PasswordDialog, {
      data: {
        hint: hint,
        askHint: askHint,
        minStrength: minStrength,
        hidePwd: this.hidePwd,
        loopCount: loopCount,
        loops: context.lpEnd,
      },
    });

    return new Promise((resolve, reject) => {
      dialogRef.afterClosed().subscribe((result) => {
        if (!result) {
          reject('process cancelled');
        } else {
          this.clearPassword();
          if (this.cacheTime > 0 && result[0]) {
            this.cachedPassword = result[0];
            this.cachedHint = result[1];
            this.stuffCached = true;
            this.restartTimer();
          }
          resolve([result[0], result[1]]);
        }
      });
    });
  }

  onFormatChange(selected: string) {
    let dcontext = this.getDecContextFrom(this.cipherArmor);
    // make it the "last loop" so we get the full cipher armor
    dcontext.lp = dcontext.lpEnd;
    this.cipherArmor = this.getCipherArmorFrom(dcontext);
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

  onClearTimerChange(): void {
    if (this.stuffCached) {
      this.restartTimer();
    }
  }

  onCipherTextInfo(): void {
    // There may be a cleaner way to do this, but create an async wrapper
    // so that we can have a unified catch hanlder with extra try catch nesting
    const awrap = async () => {
      const dcontext = this.getDecContextFrom(this.cipherArmor);
      const cparams = await cs.Cipher.getCipherParams(this.pksig, dcontext.ct);
      this.dialog.open(CipherInfoDialog, { data: cparams });
    };

    // Execute and catch error from sync or async code
    awrap().catch((err) => {
      console.error(err);
      this.dialog.open(CipherInfoDialog, { data: null })
    });
  }

  algName(alg: string): string {
    return cs.AlgInfo[alg] ? cs.AlgInfo[alg][0] : 'Invalid';
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
  public slt!: string;
  public iv!: string;
  public hint!: string;

  constructor(
    private r2: Renderer2,
    public dialogRef: MatDialogRef<CipherInfoDialog>,
    @Inject(MAT_DIALOG_DATA) public cparams: cs.CParams | null
  ) {
    if (cparams == null) {
      this.error = 'Invalid cipher armor text';
    } else {
      this.ic = cparams.ic;
      this.alg = cs.AlgInfo[cparams.alg] ? cs.AlgInfo[cparams.alg][0] : 'Invalid';
      this.iv = cs.bytesToBase64(cparams.iv as Uint8Array);
      this.slt = cs.bytesToBase64(cparams.slt as Uint8Array);
      this.hint = cparams.hint;
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

