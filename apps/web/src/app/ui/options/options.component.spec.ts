import { ComponentFixture, TestBed } from '@angular/core/testing';
import { OptionsComponent } from './options.component';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { provideHttpClient, withInterceptorsFromDi } from '@angular/common/http';
import type { HarnessLoader } from '@angular/cdk/testing';
import { TestbedHarnessEnvironment } from '@angular/cdk/testing/testbed';
import { MatButtonHarness } from '@angular/material/button/testing';
import { MatInputHarness } from '@angular/material/input/testing';
import { MatSelectHarness } from '@angular/material/select/testing';
import { MatSlideToggleHarness } from '@angular/material/slide-toggle/testing';
import * as cc from '@qcrypt/crypto/consts';
import { CipherService } from '../../services/cipher.service';
import { AuthenticatorService } from '../../services/authenticator.service';

const USER_ID = 'optionsSpecUser';

function stored(key: string): string | null {
   return localStorage.getItem(USER_ID + key);
}

describe('OptionsComponent', () => {
   let component: OptionsComponent;
   let fixture: ComponentFixture<OptionsComponent>;
   let loader: HarnessLoader;
   let originalUrl: string;

   beforeEach(async () => {
      originalUrl = location.href;

      await TestBed.configureTestingModule({
         imports: [OptionsComponent],
         providers: [provideRouter([]), provideHttpClient(withInterceptorsFromDi()), provideHttpClientTesting()],
      }).compileComponents();

      // Options load when each test says so, never when the benchmark finishes in the background
      vi.spyOn(TestBed.inject(CipherService), 'benchmark').mockReturnValue(new Promise(() => {}));

      fixture = TestBed.createComponent(OptionsComponent);
      component = fixture.componentInstance;
      loader = TestbedHarnessEnvironment.loader(fixture);
      fixture.detectChanges();
   });

   afterEach(() => {
      history.replaceState(null, '', originalUrl);
      for (const key of Object.keys(localStorage)) {
         if (key.startsWith(USER_ID)) {
            localStorage.removeItem(key);
         }
      }
   });

   function panelTitle(): string {
      return fixture.nativeElement.querySelector('.panel-title').textContent.trim();
   }

   it('should create', () => {
      expect(component).toBeTruthy();
   });

   it('ignores option values in the URL', () => {
      localStorage.setItem(`${USER_ID}cachetime`, '60');
      localStorage.setItem(`${USER_ID}hidepwd`, 'true');
      history.replaceState(null, '', `${location.pathname}?cachetime=30&hidepwd=false`);
      const cacheTimes: number[] = [];
      component.cacheTimeChange.subscribe((secs) => cacheTimes.push(secs));

      component.loadOptions(USER_ID);
      fixture.detectChanges();

      expect(component.cacheTime).toBe(60);
      expect(component.hidePwd).toBe(true);
      expect(stored('cachetime')).toBe('60');
      expect(stored('hidepwd')).toBe('true');
      expect(cacheTimes).toContain(60);
      expect(cacheTimes).not.toContain(30);
      expect(fixture.nativeElement.querySelector('mat-expansion-panel.mat-expanded')).toBeNull();
   });

   it('reset to defaults saves every option', async () => {
      const nonDefaults: Record<string, string> = {
         algorithm: '["AES-GCM","AEGIS-256"]',
         loops: '2',
         icount: String(cc.ICOUNT_MIN),
         hidepwd: 'false',
         cachetime: '30',
         checkpwned: 'true',
         minpwdstrength: '1',
         ctformat: 'indent',
         vclear: 'false',
         reminder: 'false',
      };
      for (const [key, value] of Object.entries(nonDefaults)) {
         localStorage.setItem(USER_ID + key, value);
      }
      component.loadOptions(USER_ID);
      expect(component.loops).toBe(2);

      await (await loader.getHarness(MatButtonHarness.with({ text: 'Reset To Defaults' }))).click();

      expect(stored('algorithm')).toBe('["X20-PLY"]');
      expect(stored('loops')).toBe('1');
      expect(stored('icount')).toBe(String(cc.ICOUNT_DEFAULT));
      expect(stored('hidepwd')).toBe('true');
      expect(stored('cachetime')).toBe('0');
      expect(stored('checkpwned')).toBe('false');
      expect(stored('minpwdstrength')).toBe('3');
      expect(stored('ctformat')).toBe('compact');
      expect(stored('vclear')).toBe('true');
      expect(stored('reminder')).toBe('true');
   });

   it('link format turns the reminder off and locks it until another format is chosen', async () => {
      component.loadOptions(USER_ID);
      const format = await loader.getHarness(MatSelectHarness.with({ selector: '#format' }));
      const reminder = await loader.getHarness(MatSlideToggleHarness.with({ label: /Decryption\s+Reminder/ }));
      expect(await reminder.isChecked()).toBe(true);

      await format.open();
      await format.clickOptions({ text: 'Link' });

      expect(await reminder.isChecked()).toBe(false);
      expect(await reminder.isDisabled()).toBe(true);
      expect(stored('reminder')).not.toBe('false');

      await format.open();
      await format.clickOptions({ text: 'Compact' });

      expect(await reminder.isChecked()).toBe(true);
      expect(await reminder.isDisabled()).toBe(false);
   });

   it('committing a loop count gives every loop a mode', async () => {
      localStorage.setItem(`${USER_ID}algorithm`, '["AES-GCM"]');
      component.loadOptions(USER_ID);
      fixture.detectChanges();
      expect(panelTitle()).toBe('Encryption Mode');

      const loops = await loader.getHarness(MatInputHarness.with({ selector: 'input[name="loops"]' }));
      await loops.setValue('3');
      await loops.blur();

      expect(component.algorithms).toEqual(['AES-GCM', 'X20-PLY', 'AEGIS-256']);
      expect(fixture.nativeElement.querySelectorAll('app-algorithms tr').length).toBe(3);
      expect(panelTitle()).toBe('Encryption Modes');
   });

   it('ignores a benchmark that finishes after the options are gone', async () => {
      const warn = vi.spyOn(console, 'warn');
      let finishBenchmark: (result: [number, number, number]) => void = () => {};
      vi.spyOn(TestBed.inject(CipherService), 'benchmark').mockReturnValue(
         new Promise((resolve) => {
            finishBenchmark = resolve;
         }),
      );
      const lateFixture = TestBed.createComponent(OptionsComponent);
      lateFixture.detectChanges();
      lateFixture.destroy();

      finishBenchmark([cc.ICOUNT_DEFAULT, cc.ICOUNT_MAX, 1000]);
      await TestBed.inject(AuthenticatorService).ready;
      await new Promise((resolve) => setTimeout(resolve, 0));

      expect(warn).not.toHaveBeenCalledWith(expect.stringContaining('NG0953'));
   });
});
