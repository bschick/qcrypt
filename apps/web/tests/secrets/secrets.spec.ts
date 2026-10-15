import { test, expect, type Page } from '@playwright/test';
import { randomBytes } from 'node:crypto';
import type { HmacSecretMode } from 'nid-webauthn-emulator';
import {
   testWithAuth,
   fillPwdAndAccept,
   openCredentials,
   deleteFirstPasskey,
   readPrfKey,
   type Authenticator,
   type CreatedTestUser,
} from '../common';
import {
   HEAP_SCAN_TEST_OPTIONS,
   byteSecret,
   describeFinding,
   plantCanaryNextTo,
   scanHeap,
   textSecret,
   type Finding,
   type Secret,
} from './heapscan';
import { cipherSecrets, recoverySecrets, userCredSecrets } from './derive';

test.use(HEAP_SCAN_TEST_OPTIONS);
// A secret left in memory is found on every attempt, so a retry would only double the run time and the accounts
test.describe.configure({ retries: 0 });

// Every tracked secret has one of these lifetimes, which set when finding it is a leak:
// - 'gone': values the app can derive again only from new user input, such as passwords and the keys derived
//   from them, hint text, recovery words and the values derived from them, and PRF outputs. Each must leave
//   memory when the operation that used it ends, so every scan flags it, including the scan right after that
//   operation.
// - 'session': values the app can derive again without user input while signed in, such as userCred, its proof
//   seed and ML-DSA signing key, and the cipher signing and hint keys. A breakpoint in the running app can read
//   them at any time during the session, so only scans after sign-out flag them.
// - 'canary': bytes planted next to a secret as a positive control. A canary is never a leak; a checkpoint
//   can require that the scan finds it.
type Lifetime = 'session' | 'gone' | 'canary';
type Expectation = { secret: string; kind: Finding['kind'] };
type CheckpointOptions = {
   // Must be found, which shows the scan can see them at this point
   present?: Expectation[];
   // Session secrets that must be gone at this checkpoint even though the user is signed in
   gone?: Expectation[];
   signedOut?: boolean;
};

function matches(finding: Finding, expectations: Expectation[] | undefined): boolean {
   return (expectations ?? []).some((expected) => expected.secret === finding.secret && expected.kind === finding.kind);
}

class SecretTracker {
   private readonly _lifetimes = new Map<string, Lifetime>();
   private readonly _secrets: Secret[] = [];
   private readonly _report: string[] = [];

   constructor(private readonly _page: Page) {}

   add(secrets: Secret[], lifetime: Lifetime): void {
      for (const secret of secrets) {
         if (!this._lifetimes.has(secret.name)) {
            this._secrets.push(secret);
         }
         this._lifetimes.set(secret.name, lifetime);
      }
   }

   async plantCanaryNextTo(name: string, secretBytes: Uint8Array): Promise<void> {
      const canary = randomBytes(32);
      const holders = await plantCanaryNextTo(this._page, secretBytes, canary);
      expect.soft(holders, `${name}: found no holder to plant the canary next to`).not.toEqual([]);
      this.add([byteSecret(name, canary, false)], 'canary');
      this._report.push(`-- canary ${name} planted next to ${holders.join(', ')}`);
   }

   async checkpoint(label: string, options: CheckpointOptions = {}): Promise<void> {
      await test.step(`heap scan: ${label}`, async () => {
         const scan = await scanHeap(this._page, label, this._secrets);
         const leaks = scan.findings.filter((finding) => {
            const lifetime = this._lifetimes.get(finding.secret);
            const sessionOver = options.signedOut || matches(finding, options.gone);
            const forbidden = lifetime === 'gone' || (lifetime === 'session' && sessionOver);
            return forbidden && finding.reachable && !matches(finding, options.present);
         });

         this._report.push(`== ${label}: ${scan.summary}`);
         for (const finding of scan.findings) {
            const status = leaks.includes(finding) ? 'LEAK' : finding.reachable ? 'ok  ' : 'tool';
            this._report.push(`   ${status} ${describeFinding(finding)}`);
         }
         for (const path of scan.unresolved) {
            this._report.push(`   UNRESOLVED ${path}`);
         }

         expect.soft(leaks.map(describeFinding), `${label}: secrets still in memory`).toEqual([]);
         for (const expected of options.present ?? []) {
            expect
               .soft(
                  scan.findings.some((finding) => matches(finding, [expected])),
                  `${label}: the scan should find ${expected.secret} (${expected.kind})`,
               )
               .toBe(true);
         }
         expect.soft(scan.unresolved, `${label}: buffers the scan could not read`).toEqual([]);
      });
   }

   report(): string {
      return this._report.join('\n');
   }
}

const CIPHERS: [string, string][] = [
   ['AES-GCM', 'AES 256 GCM'],
   ['X20-PLY', 'XChaCha20 Poly1305'],
   ['AEGIS-256', 'AEGIS 256'],
];

// The first encrypted block holds at most 1 MiB of clear text, so a longer message also uses a block key
const LONG_TEXT_CHARS = 1048576 + 4096;

type Message = {
   // Prefix for the names of this message's secrets
   label: string;
   alg: string;
   password: string;
   hint: string | undefined;
   clearText: string;
};

function newPassword(): string {
   return `Pw-${randomBytes(12).toString('base64url')}`;
}

// A long message also has a hint, so its encryption derives a hint key and a block key besides the cipher key
function newMessage(label: string, alg: string, long: boolean): Message {
   const clearText = `heap scan ${label} ${randomBytes(6).toString('hex')} `;
   return {
      label,
      alg,
      password: newPassword(),
      hint: long ? `hint ${randomBytes(4).toString('hex')}` : undefined,
      clearText: long ? clearText.padEnd(LONG_TEXT_CHARS, '0123456789abcdef') : clearText,
   };
}

// The page's keys are found by decrypting its cipher armor in Node, because decryption derives the same keys
// from the salt in the armor. Returns the cipher armor and the names of the tracked keys.
async function encrypt(
   page: Page,
   tracker: SecretTracker,
   user: CreatedTestUser,
   message: Message,
): Promise<{ armor: string; keyNames: string[] }> {
   tracker.add([textSecret(`${message.label}.password`, message.password)], 'gone');
   if (message.hint) {
      tracker.add([textSecret(`${message.label}.hint`, message.hint)], 'gone');
   }
   const cipherInput = page.locator('textarea#cipherInput');
   await cipherInput.fill('');
   await page.locator('textarea#clearInput').fill(message.clearText);
   await page.getByRole('button', { name: 'Encrypt Text' }).click();
   await fillPwdAndAccept(page, new RegExp(user.userName), message.password, message.hint, 'enc', async () => {});
   await expect(cipherInput).not.toBeEmpty({ timeout: 10000 });

   const armor = await cipherInput.inputValue();
   const keys = await cipherSecrets(message.label, armor, user.userCred, message.password, message.clearText);
   expect(keys.alg).toBe(message.alg);
   tracker.add(keys.passwordKeys, 'gone');
   tracker.add(keys.userCredKeys, 'session');
   return { armor, keyNames: [...keys.passwordKeys, ...keys.userCredKeys].map((secret) => secret.name) };
}

async function decrypt(page: Page, user: CreatedTestUser, message: Message, armor: string): Promise<void> {
   const clearInput = page.locator('textarea#clearInput');
   await clearInput.fill('');
   await page.locator('textarea#cipherInput').fill(armor);
   await page.getByRole('button', { name: 'Decrypt Text' }).click();
   await fillPwdAndAccept(page, new RegExp(user.userName), message.password, undefined, 'dec', async () => {
      if (message.hint) {
         // Compared in Node, because a Playwright assertion copies its expected value into the page heap
         await expect.poll(() => page.locator('input#hint').inputValue()).toBe(message.hint);
      }
   });
   await expect(clearInput).not.toBeEmpty({ timeout: 10000 });
   expect(await clearInput.inputValue()).toBe(message.clearText);
}

// The app decrypts the hint from the cipher armor without user input, so the hint is only gone once the cipher
// armor is cleared
async function clearCipherArmor(page: Page): Promise<void> {
   await page.locator('button[mattooltip="Clear cipher armor"]').click();
   await expect(page.locator('textarea#cipherInput')).toBeEmpty();
}

for (const prf of [true, false]) {
   const mode: HmacSecretMode = prf ? 'hmac-secret-mc' : 'none';
   const label = prf ? 'PRF' : 'no-PRF';

   testWithAuth(`${label} account: secrets leave memory`, async ({ authFixture }, testInfo) => {
      test.setTimeout(900000);
      const { page } = authFixture;
      const baseURL = (testInfo.project.use as { baseURL: string }).baseURL;
      const origin = new URL(baseURL).origin;
      const rpId = new URL(baseURL).hostname;
      const tracker = new SecretTracker(page);
      const trackPrfOutput = (name: string, authenticator: Authenticator, credentialId: string) => {
         if (prf) {
            const prfOutput = readPrfKey(authenticator.emulator, origin, rpId, credentialId);
            tracker.add([byteSecret(name, prfOutput)], 'gone');
         }
      };

      try {
         const authenticator1 = authFixture.memAuthenticator(mode);
         const user = await authFixture.createTestUser(authenticator1);
         tracker.add(await userCredSecrets(user.userCred), 'session');
         tracker.add(await recoverySecrets('recovery1', user.recoveryWords), 'gone');
         trackPrfOutput('passkey1.prfOutput', authenticator1, user.credentialId);

         // Each part of the test below starts with a page load, scans once its operation completes, then signs out
         // and scans again. The load clears the page heap, so both scans show what the part's own operation left in
         // memory.
         const signIn = async (authenticator: Authenticator) => {
            await page.goto('/');
            await authFixture.passkeyAuth(authenticator, async () => {
               await page.getByRole('button', { name: new RegExp(`Sign in as ${user.userName}`) }).click();
            });
            await expect(page.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({ timeout: 10000 });
         };
         const signOut = async (operation: string) => {
            await openCredentials(page);
            await page.getByRole('button', { name: /Sign out/ }).click();
            await expect(page.locator('.signin div.success-msg')).toContainText(/Sign out succeeded/);
            await tracker.checkpoint(`after ${operation} and sign-out`, { signedOut: true });
         };
         // Option panels are closed after every page load
         const selectCipher = async (description: string) => {
            await page.getByRole('button', { name: 'Encryption Mode' }).click();
            await page.locator('mat-button-toggle', { hasText: description }).click();
         };
         const setCacheTime = async (seconds: number) => {
            await page.getByRole('button', { name: 'Advanced Options' }).click();
            await page.getByLabel('Cache Time (secs)').fill(String(seconds));
            await page.keyboard.press('Tab');
         };

         await tracker.checkpoint('after account creation');
         await signOut('account creation');

         // Users reach /cmdline only by URL, and loading it signs in with the passkey again
         await signIn(authenticator1);
         await authFixture.passkeyAuth(authenticator1, async () => {
            await page.goto('/cmdline');
         });
         const credentialInput = page.locator('input#credential');
         await expect(credentialInput).toBeVisible();
         expect(await credentialInput.inputValue()).toBe(user.userCred);
         await tracker.checkpoint('/cmdline showing userCred', { present: [{ secret: 'userCred', kind: 'string' }] });

         await page.getByRole('link', { name: /command-line/ }).click();
         await expect(page).toHaveURL(/\/help\/faqs/);
         await tracker.checkpoint('after leaving /cmdline', { gone: [{ secret: 'userCred', kind: 'string' }] });
         await page.getByRole('button', { name: 'Quick Crypt' }).click();
         await expect(page.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({ timeout: 10000 });
         await signOut('/cmdline');

         // Encryption and decryption run in separate parts, because each one's final WASM calls overwrite what
         // earlier calls left in WASM memory
         let hinted: { message: Message; armor: string } | undefined;
         for (const [alg, description] of CIPHERS) {
            for (const long of [false, true]) {
               const message = newMessage(`${alg}.${long ? 'long' : 'short'}`, alg, long);
               await signIn(authenticator1);
               await selectCipher(description);
               const { armor, keyNames } = await encrypt(page, tracker, user, message);
               if (long) {
                  expect(keyNames).toEqual(
                     expect.arrayContaining([`${message.label}.hintKey`, `${message.label}.blockKey1`]),
                  );
                  hinted = { message, armor };
               }
               await clearCipherArmor(page);
               await tracker.checkpoint(`after ${message.label} encryption`);
               await signOut(`${message.label} encryption`);

               await signIn(authenticator1);
               await decrypt(page, user, message, armor);
               await clearCipherArmor(page);
               await tracker.checkpoint(`after ${message.label} decryption`);
               await signOut(`${message.label} decryption`);
            }
         }

         // The cipher info dialog decrypts and shows the hint without asking for the password
         const { message: infoMessage, armor: infoArmor } = hinted!;
         await signIn(authenticator1);
         await page.locator('textarea#cipherInput').fill(infoArmor);
         await page.getByRole('button', { name: 'Info', exact: true }).click();
         const infoDialog = page.getByLabel('Cipher Armor Info');
         await expect.poll(() => infoDialog.innerText()).toContain(infoMessage.hint!);
         await infoDialog.getByRole('button', { name: 'Close' }).click();
         await expect(infoDialog).toBeHidden();
         await clearCipherArmor(page);
         await tracker.checkpoint('after showing cipher info');
         await signOut('showing cipher info');

         // While caching is on, the app stores the password by design, so its bytes serve as the positive
         // control. After the flush, the canary placed next to the password must still be found.
         const cached = newMessage('cached', 'AEGIS-256', false);
         await signIn(authenticator1);
         await selectCipher('AEGIS 256');
         await setCacheTime(600);
         await encrypt(page, tracker, user, cached);
         await tracker.plantCanaryNextTo('cached.canary', Buffer.from(cached.password, 'utf8'));
         await tracker.checkpoint('password cached', {
            present: [
               { secret: 'cached.password', kind: 'bytes' },
               { secret: 'cached.canary', kind: 'bytes' },
            ],
         });

         await page.locator('button.clear-button').click();
         await expect(page.locator('button.clear-button')).toBeHidden();
         await tracker.checkpoint('after flushing the cached password', {
            present: [{ secret: 'cached.canary', kind: 'bytes' }],
         });
         await signOut('flushing the cached password');

         // A password that is still cached at sign-out
         const cachedAtSignOut = newMessage('cachedAtSignOut', 'AEGIS-256', false);
         await signIn(authenticator1);
         await selectCipher('AEGIS 256');
         await setCacheTime(600);
         await encrypt(page, tracker, user, cachedAtSignOut);
         await expect(page.locator('button.clear-button')).toBeVisible();
         await signOut('caching a password');

         await signIn(authenticator1);
         await openCredentials(page);
         const authenticator2 = authFixture.memAuthenticator(mode);
         const credentialId2 = await authFixture.addPasskey(user.userId, authenticator2, async () => {
            await page.getByRole('button', { name: /New Passkey/ }).click();
         });
         await expect(page.locator('table.credtable tbody tr')).toHaveCount(2);
         trackPrfOutput('passkey2.prfOutput', authenticator2, credentialId2);
         await tracker.checkpoint('after adding a passkey');
         await signOut('adding a passkey');

         await signIn(authenticator1);
         await openCredentials(page);
         await page.getByRole('button', { name: /Replace recovery words/ }).click();
         await expect(page).toHaveURL(/\/regenrecovery$/);
         await authFixture.passkeyAuth(authenticator1, async () => {
            await page.getByRole('button', { name: /Generate new recovery words/ }).click();
         });
         await expect(page).toHaveURL(/\/showrecovery$/, { timeout: 10000 });
         const newWords = await page.locator('textarea#wordsArea').inputValue();
         tracker.add(await recoverySecrets('recovery2', newWords), 'gone');
         await tracker.checkpoint('/showrecovery showing new words', {
            present: [{ secret: 'recovery2.words', kind: 'string' }],
         });

         await page.getByRole('button', { name: /I saved my recovery words securely/ }).click();
         await expect(page).toHaveURL(/\/$/);
         await tracker.checkpoint('after replacing recovery words');
         await signOut('replacing recovery words');

         await page.goto('/');
         await page.getByRole('button', { name: /Sign in as a different user/ }).click();
         await expect(page).toHaveURL(/\/welcome$/);
         await page.getByRole('button', { name: /I am returning but cannot sign in/ }).click();
         await page.getByRole('link', { name: /Restore access to your account/ }).click();
         await expect(page).toHaveURL(/\/recovery3$/);
         await page.locator('textarea#wordsArea').fill(newWords);
         const authenticator3 = authFixture.memAuthenticator(mode);
         const credentialId3 = await authFixture.addPasskey(user.userId, authenticator3, async () => {
            await page.getByRole('button', { name: /Start Recovery/ }).click();
         });
         await expect(page).toHaveURL(/\/$/);
         await expect(page.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({ timeout: 10000 });
         trackPrfOutput('passkey3.prfOutput', authenticator3, credentialId3);
         await tracker.checkpoint('after recovery');
         await signOut('recovery');

         // Recovery removed the registration passkey, so the account is deleted here with the recovery passkey
         await signIn(authenticator3);
         await openCredentials(page);
         await deleteFirstPasskey(page, user.userName, (trigger) => authFixture.passkeyAuth(authenticator3, trigger));
         await expect(page).toHaveURL(/\/welcome$/);
         authFixture.untrackUser(user.userId);
      } finally {
         const report = tracker.report();
         await testInfo.attach('heap-scans', { body: report, contentType: 'text/plain' });
         console.log(`[heap scans] ${testInfo.title}\n${report}`);
      }
   });
}
