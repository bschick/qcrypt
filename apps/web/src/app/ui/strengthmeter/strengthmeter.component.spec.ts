import { ComponentFixture, TestBed } from '@angular/core/testing';
import { StrengthMeterComponent } from './strengthmeter.component';

const PWNED_URL = 'https://api.pwnedpasswords.com/range/';
const PASSWORD = 'Xk7$pLm2#qRw9';

describe('StrengthMeterComponent', () => {
   let component: StrengthMeterComponent;
   let fixture: ComponentFixture<StrengthMeterComponent>;
   let originalFetch: typeof fetch;
   let pwnedUrls: string[] = [];

   beforeAll(() => {
      // The breach matcher captures fetch when zxcvbn first loads, so replace it before any test runs
      originalFetch = window.fetch;
      window.fetch = ((input: RequestInfo | URL, init?: RequestInit) => {
         const url = String(input);
         if (!url.startsWith(PWNED_URL)) {
            return originalFetch(input, init);
         }
         pwnedUrls.push(url);
         return Promise.resolve({ status: 200, text: () => Promise.resolve('') });
      }) as unknown as typeof fetch;
   });

   afterAll(() => {
      window.fetch = originalFetch;
   });

   beforeEach(async () => {
      pwnedUrls = [];

      await TestBed.configureTestingModule({
         imports: [StrengthMeterComponent],
      }).compileComponents();

      fixture = TestBed.createComponent(StrengthMeterComponent);
      component = fixture.componentInstance;
      component.pwned = true;
      component.minStrength = 3;
      fixture.detectChanges();
   });

   afterEach(async () => {
      // An unfinished lookup would send its request during the next test, which counts requests.
      // Clearing the password first means this cannot start one.
      component.password = '';
      await component.checkIfPwned();
      fixture.destroy();
   });

   // Strength leaves its -1 start only once zxcvbn has scored something
   function scored(): Promise<void> {
      return vi.waitFor(() => expect(component.strength).toBeGreaterThanOrEqual(0));
   }

   function delay(millis: number): Promise<void> {
      return new Promise((resolve) => setTimeout(resolve, millis));
   }

   it('should create', () => {
      expect(component).toBeTruthy();
   });

   it('does not check for breaches while typing', async () => {
      for (const partial of ['Xk7', 'Xk7$pLm', PASSWORD]) {
         component.password = partial;
         // Longer than the meter's debounce, so every entry is scored on its own
         await delay(250);
      }
      await vi.waitFor(() => expect(component.strength).toBe(4));

      expect(pwnedUrls).toEqual([]);
   });

   it('checks once per password', async () => {
      component.password = PASSWORD;
      await scored();

      const first = await component.checkIfPwned();
      const second = await component.checkIfPwned();

      await vi.waitFor(() => expect(pwnedUrls.length).toBe(1));
      expect(first).toEqual({ acceptable: true, strength: 4 });
      expect(second).toEqual(first);
   });

   it('checks again after the password changes', async () => {
      component.password = PASSWORD;
      await scored();
      await component.checkIfPwned();

      component.password = `${PASSWORD}Zq`;
      await scored();
      await component.checkIfPwned();

      await vi.waitFor(() => expect(pwnedUrls.length).toBe(2));
      expect(pwnedUrls[0]).not.toBe(pwnedUrls[1]);
   });

   it('does not check when breach checking is off', async () => {
      component.pwned = false;
      component.password = PASSWORD;
      await scored();

      const state = await component.checkIfPwned();

      expect(pwnedUrls).toEqual([]);
      expect(state).toEqual({ acceptable: true, strength: 4 });
   });

   it('does not check an empty password', async () => {
      component.password = '';

      const state = await component.checkIfPwned();

      expect(pwnedUrls).toEqual([]);
      expect(state).toEqual({ acceptable: false, strength: -1 });
   });
});
