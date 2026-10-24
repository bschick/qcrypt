import { expect, test, type Page } from '@playwright/test';
import { randomBytes } from 'node:crypto';
import {
   testWithAuth,
   fillPwdAndAccept,
   downloadFileAccess,
   pickerFileAccess,
   selectClearFile,
   selectCipherFile,
   encryptToFile,
   decryptToFile,
   type FileAccess,
} from '.././common';

const PASSWORD = 'Xk7$pLm2#qRw9';
// The ciphers read 1 MiB first and then 2 MiB, so this fills two blocks and leaves 17 bytes for a third
const FILE_BYTES = 3 * 1024 * 1024 + 17;

const FILE_ACCESS: [string, (page: Page) => Promise<FileAccess>][] = [
   ['downloads', downloadFileAccess],
   ['pickers', pickerFileAccess],
];

test.describe('file encryption', () => {
   for (const [label, fileAccess] of FILE_ACCESS) {
      testWithAuth(`a clear file encrypts to a cipher file and decrypts back (${label})`, async ({ authFixture }) => {
         const { page } = authFixture;
         const files = await fileAccess(page);
         const testUser = await authFixture.createTestUser(authFixture.memAuthenticator());
         const heading = new RegExp(testUser.userName);
         const clear = new Uint8Array(randomBytes(FILE_BYTES));

         await selectClearFile(page, files, 'clear.bin', clear);
         const cipherData = await encryptToFile(page, files, heading, PASSWORD);
         expect(cipherData.length).toBeGreaterThan(clear.length);

         await selectCipherFile(page, files, 'clear.bin.qq', cipherData);
         const decrypted = await decryptToFile(page, files, heading, PASSWORD);
         expect(Buffer.from(decrypted).equals(clear)).toBe(true);
      });

      testWithAuth(`clear text and cipher armor encrypt and decrypt to files (${label})`, async ({ authFixture }) => {
         const { page } = authFixture;
         test.setTimeout(60000);
         const files = await fileAccess(page);
         const testUser = await authFixture.createTestUser(authFixture.memAuthenticator());
         const heading = new RegExp(testUser.userName);
         const clearText = 'this is very secret, do not 🦜';
         const clearBytes = new TextEncoder().encode(clearText);

         await page.locator('textarea#clearInput').fill(clearText);
         const cipherData = await encryptToFile(page, files, heading, PASSWORD);

         await page.getByRole('button', { name: 'Encrypt Text' }).click();
         await fillPwdAndAccept(page, heading, PASSWORD, undefined, 'enc', async () => {});
         await expect(page.locator('textarea#cipherInput')).not.toBeEmpty({ timeout: 10000 });
         const fromArmor = await decryptToFile(page, files, heading, PASSWORD);
         expect(Buffer.from(fromArmor).equals(clearBytes)).toBe(true);

         await selectCipherFile(page, files, 'armor.qq', cipherData);
         const fromFile = await decryptToFile(page, files, heading, PASSWORD);
         expect(Buffer.from(fromFile).equals(clearBytes)).toBe(true);
      });
   }
});
