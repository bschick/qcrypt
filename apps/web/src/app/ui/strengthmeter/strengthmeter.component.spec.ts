import { ComponentFixture, TestBed } from '@angular/core/testing';
import { StrengthMeterComponent } from './strengthmeter.component';

const PWNED_URL = 'https://api.pwnedpasswords.com/range/';
const PASSWORD = 'Xk7$pLm2#qRw9';

describe('StrengthMeterComponent', () => {
   let component: StrengthMeterComponent;
   let fixture: ComponentFixture<StrengthMeterComponent>;
   let originalFetch: typeof fetch;
   let pwnedUrls: string[] = [];
   let pwnedBody = '';

   // A range response listing the password's own hash suffix, which reports it as breached
   async function breached(password: string): Promise<string> {
      const digest = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(password));
      const hash = Array.from(new Uint8Array(digest))
         .map((byte) => byte.toString(16).padStart(2, '0'))
         .join('')
         .toUpperCase();
      return `${hash.slice(5)}:3`;
   }

   beforeAll(() => {
      // The breach matcher captures fetch when zxcvbn first loads, so replace it before any test runs
      originalFetch = window.fetch;
      window.fetch = ((input: RequestInfo | URL, init?: RequestInit) => {
         const url = String(input);
         if (!url.startsWith(PWNED_URL)) {
            return originalFetch(input, init);
         }
         pwnedUrls.push(url);
         return Promise.resolve({ status: 200, text: () => Promise.resolve(pwnedBody) });
      }) as unknown as typeof fetch;
   });

   afterAll(() => {
      window.fetch = originalFetch;
   });

   beforeEach(async () => {
      pwnedUrls = [];
      pwnedBody = '';

      await TestBed.configureTestingModule({
         imports: [StrengthMeterComponent],
      }).compileComponents();

      fixture = TestBed.createComponent(StrengthMeterComponent);
      component = fixture.componentInstance;
      setInputs({ pwned: true, minStrength: 3 });
   });

   afterEach(async () => {
      // An unfinished lookup would send its request during the next test, which counts requests.
      // Clearing the password first means this cannot start one.
      setInputs({ password: '' });
      await component.checkIfPwned();
      fixture.destroy();
   });

   // Scoring runs from an effect, so the inputs only take hold once change detection runs
   function setInputs(inputs: Record<string, unknown>): void {
      for (const [name, value] of Object.entries(inputs)) {
         fixture.componentRef.setInput(name, value);
      }
      fixture.detectChanges();
   }

   function strength(): number {
      return component['strength']();
   }

   function warning(): string {
      return component['warning']();
   }

   // Strength leaves its -1 start only once zxcvbn has scored something
   function scored(): Promise<void> {
      return vi.waitFor(() => expect(strength()).toBeGreaterThanOrEqual(0), { timeout: 5000 });
   }

   function delay(millis: number): Promise<void> {
      return new Promise((resolve) => setTimeout(resolve, millis));
   }

   it('should create', () => {
      expect(component).toBeTruthy();
   });

   it('does not check for breaches while typing', async () => {
      for (const partial of ['Xk7', 'Xk7$pLm', PASSWORD]) {
         setInputs({ password: partial });
         // Longer than the meter's scoring interval, so every entry is scored on its own
         await delay(250);
      }
      await vi.waitFor(() => expect(strength()).toBe(4), { timeout: 5000 });

      expect(pwnedUrls).toEqual([]);
   });

   it('checks once per password', async () => {
      setInputs({ password: PASSWORD });
      await scored();

      const first = await component.checkIfPwned();
      const second = await component.checkIfPwned();

      await vi.waitFor(() => expect(pwnedUrls.length).toBe(1), { timeout: 5000 });
      expect(first).toEqual({ acceptable: true, strength: 4 });
      expect(second).toEqual(first);
   });

   it('checks again after the password changes', async () => {
      setInputs({ password: PASSWORD });
      await scored();
      await component.checkIfPwned();

      setInputs({ password: `${PASSWORD}Zq` });
      await scored();
      await component.checkIfPwned();

      await vi.waitFor(() => expect(pwnedUrls.length).toBe(2), { timeout: 5000 });
      expect(pwnedUrls[0]).not.toBe(pwnedUrls[1]);
   });

   it('does not check when breach checking is off', async () => {
      setInputs({ pwned: false, password: PASSWORD });
      await scored();

      const state = await component.checkIfPwned();

      expect(pwnedUrls).toEqual([]);
      expect(state).toEqual({ acceptable: true, strength: 4 });
   });

   it('does not check an empty password', async () => {
      setInputs({ password: '' });

      const state = await component.checkIfPwned();

      expect(pwnedUrls).toEqual([]);
      expect(state).toEqual({ acceptable: false, strength: -1 });
   });

   it('keeps a breached password rejected while the hint is edited', async () => {
      pwnedBody = await breached(PASSWORD);
      setInputs({ password: PASSWORD });
      await scored();
      await component.checkIfPwned();
      await vi.waitFor(() => expect(warning()).toContain('data breach'), { timeout: 5000 });

      setInputs({ hint: 'a hint' });
      await delay(250);

      expect(strength()).toBe(-1);
      expect(warning()).toContain('data breach');
   });

   it('scores the password in the field before reporting whether it is acceptable', async () => {
      setInputs({ pwned: false, password: PASSWORD });
      await scored();
      expect((await component.checkIfPwned()).acceptable).toBe(true);

      setInputs({ password: 'a' });
      const state = await component.checkIfPwned();

      expect(state.acceptable).toBe(false);
   });

   it('drops a score that finishes after the password is cleared', async () => {
      setInputs({ pwned: false, password: PASSWORD });
      const scoring = component.checkIfPwned();
      setInputs({ password: '' });
      await scoring;

      expect(strength()).toBe(-1);
      expect(warning()).toBe('');
   });

   it('drops a pending score when the password is cleared', async () => {
      setInputs({ password: PASSWORD });
      setInputs({ password: '' });
      await delay(250);

      expect(strength()).toBe(-1);
      expect(warning()).toBe('');
   });

   describe('reuse and hint similarity', () => {
      it('scores a password reused from an earlier loop at the minimum', async () => {
         setInputs({ usedPasswords: [PASSWORD], password: PASSWORD });

         await vi.waitFor(() => expect(warning()).toContain('previous loop'), { timeout: 5000 });
         expect(strength()).toBe(0);
      });

      it('scores a password close to an earlier one at the minimum', async () => {
         setInputs({ usedPasswords: [PASSWORD], password: `${PASSWORD}1` });

         await vi.waitFor(() => expect(warning()).toContain('previous loop'), { timeout: 5000 });
         expect(strength()).toBe(0);
      });

      it('scores a password resembling its own hint at the minimum', async () => {
         setInputs({ hint: PASSWORD, password: PASSWORD });

         await vi.waitFor(() => expect(warning()).toContain('hint'), { timeout: 5000 });
         expect(strength()).toBe(0);
      });

      it('leaves a password unrelated to the hint or earlier loops alone', async () => {
         setInputs({ usedPasswords: ['completely-different-9042'], hint: 'nothing alike', password: PASSWORD });

         await vi.waitFor(() => expect(strength()).toBe(4), { timeout: 5000 });
         expect(warning()).not.toContain('previous loop');
         expect(warning()).not.toContain('hint');
      });
   });
});
