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
import { cipherSecrets, decodeRecoveryWords, masterKeySecrets, recoverySecrets, userCredSecrets } from './derive';

test.use(HEAP_SCAN_TEST_OPTIONS);
// A secret left in memory is found on every attempt, so a retry would only double the run time and the accounts
test.describe.configure({ retries: 0 });

// Every secret the scans search for has one of these lifetimes, which set when finding it is a leak:
// - 'gone': values the app can derive again only from new user input, such as passwords and the keys derived
//   from them, clear text, hint text, recovery words and the values derived from them, and PRF outputs and the
//   keys derived from them. Each must leave memory when the operation that used it ends, so every scan flags it,
//   including the scan right after that operation. Clear text and hint text are in use until the text box that
//   holds them is cleared.
// - 'session': values the app can derive again without user input while signed in, such as userCred, its proof
//   seed and ML-DSA signing key, the cipher signing and hint keys, and each session's keystore key and the keys
//   derived from it. A breakpoint in the running app can read them at any time during the session, so only scans
//   after sign-out flag them.
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
const FIRST_BLOCK_CHARS = 1048576;
const LONG_TEXT_CHARS = FIRST_BLOCK_CHARS + 4096;

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

// A long message also has a hint, so its encryption derives a hint key and a block key besides the cipher key.
// Its clear text is random throughout, so a slice from any block matches nothing else in memory.
function newMessage(label: string, alg: string, long: boolean): Message {
   const clearText = `heap scan ${label} ${randomBytes(6).toString('hex')} `;
   return {
      label,
      alg,
      password: newPassword(),
      hint: long ? `hint ${randomBytes(4).toString('hex')}` : undefined,
      clearText: long
         ? (clearText + randomBytes(LONG_TEXT_CHARS).toString('base64url')).slice(0, LONG_TEXT_CHARS)
         : clearText,
   };
}

// The ciphers read and write clear text one block at a time, and a buffer holding only the second block does not
// contain the start of the text
function clearTextSecrets(message: Message): Secret[] {
   const secrets = [textSecret(`${message.label}.clearText`, message.clearText.slice(0, 64))];
   if (message.clearText.length > FIRST_BLOCK_CHARS) {
      const block1 = message.clearText.slice(FIRST_BLOCK_CHARS, FIRST_BLOCK_CHARS + 64);
      secrets.push(textSecret(`${message.label}.clearTextBlock1`, block1));
   }
   return secrets;
}

// The page's keys are found by decrypting its cipher armor in Node, because decryption derives the same keys
// from the salt in the armor. Returns the cipher armor and the names of the tracked keys.
async function encrypt(
   page: Page,
   tracker: SecretTracker,
   user: CreatedTestUser,
   message: Message,
): Promise<{ armor: string; keyNames: string[] }> {
   tracker.add([textSecret(`${message.label}.password`, message.password), ...clearTextSecrets(message)], 'gone');
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
async function clearTextBoxes(page: Page): Promise<void> {
   await page.locator('button[mattooltip="Clear text"]').click();
   await page.locator('button[mattooltip="Clear cipher armor"]').click();
   await expect(page.locator('textarea#clearInput')).toBeEmpty();
   await expect(page.locator('textarea#cipherInput')).toBeEmpty();
}

// Must match the IndexedDB names in keystore.service.ts and the slot in authenticator.service.ts. A wrong name
// throws in the page, and a wrong key fails to decrypt the session's copy of userCred.
const KEYSTORE_DB = 'quickcrypt';
const KEYSTORE_STORE = 'keys';
const KEYSTORE_SLOT = 'user-cred-key';

// Derives the session's keystore key the way the app does. The copies this leaves in the page are unreachable,
// so the next scan's garbage collection removes them.
async function readKeystoreKey(page: Page, pkId: string): Promise<Uint8Array> {
   const hmacInput = [...Buffer.concat([Buffer.from(KEYSTORE_SLOT), Buffer.from(pkId, 'base64url')])];
   const hmac = await page.evaluate(
      async ({ dbName, storeName, slot, input }) => {
         const db = await new Promise<IDBDatabase>((resolve, reject) => {
            const request = indexedDB.open(dbName);
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
         });
         try {
            const entry = await new Promise<{ masterKey: CryptoKey }>((resolve, reject) => {
               const request = db.transaction(storeName, 'readonly').objectStore(storeName).get(slot);
               request.onsuccess = () => resolve(request.result);
               request.onerror = () => reject(request.error);
            });
            return [...new Uint8Array(await crypto.subtle.sign('HMAC', entry.masterKey, new Uint8Array(input)))];
         } finally {
            db.close();
         }
      },
      { dbName: KEYSTORE_DB, storeName: KEYSTORE_STORE, slot: KEYSTORE_SLOT, input: hmacInput },
   );
   // The app uses the second half of the HMAC output as the key
   return new Uint8Array(hmac.slice(32));
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
      // A PRF account encrypts copies of userCred with each PRF output and recovery secret as the master key
      const masterKeys: { name: string; key: Uint8Array; copies: number }[] = [];
      const trackPrfOutput = (name: string, authenticator: Authenticator, credentialId: string) => {
         if (prf) {
            const prfOutput = readPrfKey(authenticator.emulator, origin, rpId, credentialId);
            tracker.add([byteSecret(name, prfOutput)], 'gone');
            masterKeys.push({ name, key: prfOutput, copies: 0 });
         }
      };
      const trackRecoveryWords = async (prefix: string, words: string) => {
         tracker.add(await recoverySecrets(prefix, words), 'gone');
         if (prf) {
            masterKeys.push({ name: `${prefix}.secret`, key: decodeRecoveryWords(words), copies: 0 });
         }
      };

      // Encrypted copies of userCred from API request and response bodies
      const userCredEncs = new Set<string>();
      const pendingBodies: Promise<void>[] = [];
      const collectUserCredEncs = (body: unknown) => {
         if (body && typeof body === 'object') {
            for (const [key, value] of Object.entries(body)) {
               if (/userCredEnc$/i.test(key) && typeof value === 'string') {
                  userCredEncs.add(value);
               } else {
                  collectUserCredEncs(value);
               }
            }
         }
      };
      page.on('request', (request) => {
         if (request.resourceType() === 'fetch') {
            collectUserCredEncs(request.postDataJSON());
         }
      });
      page.on('response', (response) => {
         if (response.request().resourceType() === 'fetch') {
            pendingBodies.push(response.json().then(collectUserCredEncs, () => {}));
         }
      });

      try {
         const authenticator1 = authFixture.memAuthenticator(mode);
         const user = await authFixture.createTestUser(authenticator1);
         tracker.add(await userCredSecrets(user.userCred), 'session');
         await trackRecoveryWords('recovery1', user.recoveryWords);
         trackPrfOutput('passkey1.prfOutput', authenticator1, user.credentialId);

         // Each sign-in creates a new keystore key, which encrypts the session's copy of userCred in sessionStorage.
         // trackAppKeys tracks the keys derived from every keystore key, and from every master key that decrypts a
         // captured copy of userCred.
         const triedCopies = new Set<string>();
         let keystoreKeyHex = '';
         let sessions = 0;
         const trackAppKeys = async () => {
            await Promise.all(pendingBodies.splice(0));
            for (const master of masterKeys) {
               for (const userCredEnc of userCredEncs) {
                  const pair = `${master.name} ${userCredEnc}`;
                  if (!triedCopies.has(pair)) {
                     triedCopies.add(pair);
                     const prefix = `${master.name}.copy${master.copies + 1}`;
                     const secrets = await masterKeySecrets(
                        prefix,
                        userCredEnc,
                        master.key,
                        user.userId,
                        user.userCred,
                     );
                     if (secrets) {
                        master.copies++;
                        tracker.add(secrets, 'gone');
                     }
                  }
               }
            }

            const sessionState = await page.evaluate(() => sessionStorage.getItem('sessionstate'));
            const state = JSON.parse(sessionState ?? '{}') as { pkId?: string; userId: string; userCredEnc?: string };
            // Sign-out keeps the session state but removes pkId and userCredEnc from it
            if (state.pkId && state.userCredEnc) {
               const keystoreKey = await readKeystoreKey(page, state.pkId);
               if (Buffer.from(keystoreKey).toString('hex') !== keystoreKeyHex) {
                  keystoreKeyHex = Buffer.from(keystoreKey).toString('hex');
                  sessions++;
                  const prefix = `session${sessions}`;
                  const secrets = await masterKeySecrets(
                     prefix,
                     state.userCredEnc,
                     keystoreKey,
                     state.userId,
                     user.userCred,
                  );
                  expect(secrets, `${prefix}: the keystore key does not decrypt the session's userCred`).toBeDefined();
                  tracker.add([byteSecret(`${prefix}.keystoreKey`, keystoreKey), ...secrets!], 'session');
               }
            }
         };
         const checkpoint = async (label: string, options?: CheckpointOptions) => {
            await trackAppKeys();
            await tracker.checkpoint(label, options);
         };

         // Each part of the test below starts with a page load, scans once its operation completes, then signs out
         // and scans again. The load clears the page heap, so both scans show what the part's own operation left in
         // memory.
         const signIn = async (authenticator: Authenticator) => {
            await page.goto('/');
            await authFixture.passkeyAuth(authenticator, async () => {
               await page.getByRole('button', { name: new RegExp(`Sign in as ${user.userName}`) }).click();
            });
            await expect(page.getByRole('button', { name: 'Encryption Mode' })).toBeVisible({ timeout: 10000 });
            await trackAppKeys();
         };
         // The session's keystore key is readable only until sign-out
         const signOut = async (operation: string) => {
            await trackAppKeys();
            await openCredentials(page);
            await page.getByRole('button', { name: /Sign out/ }).click();
            await expect(page.locator('.signin div.success-msg')).toContainText(/Sign out succeeded/);
            await checkpoint(`after ${operation} and sign-out`, { signedOut: true });
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

         await checkpoint('after account creation');
         await signOut('account creation');

         // Users reach /cmdline only by URL, and loading it signs in with the passkey again
         await signIn(authenticator1);
         await authFixture.passkeyAuth(authenticator1, async () => {
            await page.goto('/cmdline');
         });
         const credentialInput = page.locator('input#credential');
         await expect(credentialInput).toBeVisible();
         expect(await credentialInput.inputValue()).toBe(user.userCred);
         await checkpoint('/cmdline showing userCred', { present: [{ secret: 'userCred', kind: 'string' }] });

         await page.getByRole('link', { name: /command-line/ }).click();
         await expect(page).toHaveURL(/\/help\/faqs/);
         await checkpoint('after leaving /cmdline', { gone: [{ secret: 'userCred', kind: 'string' }] });
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
               await clearTextBoxes(page);
               await checkpoint(`after ${message.label} encryption`);
               await signOut(`${message.label} encryption`);

               await signIn(authenticator1);
               await decrypt(page, user, message, armor);
               await clearTextBoxes(page);
               await checkpoint(`after ${message.label} decryption`);
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
         await clearTextBoxes(page);
         await checkpoint('after showing cipher info');
         await signOut('showing cipher info');

         // While caching is on, the app stores the password by design, so its bytes serve as the positive
         // control. After the flush, the canary placed next to the password must still be found.
         const cached = newMessage('cached', 'AEGIS-256', false);
         await signIn(authenticator1);
         await selectCipher('AEGIS 256');
         await setCacheTime(600);
         await encrypt(page, tracker, user, cached);
         await clearTextBoxes(page);
         await tracker.plantCanaryNextTo('cached.canary', Buffer.from(cached.password, 'utf8'));
         await checkpoint('password cached', {
            present: [
               { secret: 'cached.password', kind: 'bytes' },
               { secret: 'cached.canary', kind: 'bytes' },
            ],
         });

         await page.locator('button.clear-button').click();
         await expect(page.locator('button.clear-button')).toBeHidden();
         await checkpoint('after flushing the cached password', {
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
         await checkpoint('after adding a passkey');
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
         await trackRecoveryWords('recovery2', newWords);
         await checkpoint('/showrecovery showing new words', {
            present: [{ secret: 'recovery2.words', kind: 'string' }],
         });

         await page.getByRole('button', { name: /I saved my recovery words securely/ }).click();
         await expect(page).toHaveURL(/\/$/);
         await checkpoint('after replacing recovery words');
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
         await checkpoint('after recovery');
         // Every master key encrypted a copy of userCred that the API traffic carried, so a key without one shows
         // that the capture missed it
         expect
            .soft(
               masterKeys.filter((master) => !master.copies).map((master) => master.name),
               'master keys with no captured copy of userCred',
            )
            .toEqual([]);
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
