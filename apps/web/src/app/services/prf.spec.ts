/* MIT License

Copyright (c) 2026 Brad Schick

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

import { cryptoReady, getRandom, bytesToBase64 } from '@qcrypt/crypto';
import * as cc from '@qcrypt/crypto/consts';
import {
   PRF_SALT,
   injectPrfExtension,
   prfEnabled,
   prfReadKey,
   prfEncrypt,
   prfDecrypt,
} from './prf';

function prfExtensionResults(first: ArrayBuffer | Uint8Array | number[]): AuthenticationExtensionsClientOutputs {
   return { prf: { results: { first } } } as AuthenticationExtensionsClientOutputs;
}

describe('prf helpers', () => {
   beforeEach(async () => {
      await cryptoReady();
   });

   it('PRF_SALT is 32 bytes', () => {
      expect(PRF_SALT.byteLength).toBe(cc.KEY_BYTES);
   });

   it('injectPrfExtension sets the prf eval and preserves existing extensions', () => {
      const optionsJson: any = { extensions: { appid: 'keep-me' } };
      injectPrfExtension(optionsJson);
      expect(optionsJson.extensions.appid).toBe('keep-me');
      expect(optionsJson.extensions.prf.eval.first).toBe(PRF_SALT);
   });

   it('injectPrfExtension creates extensions when absent', () => {
      const optionsJson: any = {};
      injectPrfExtension(optionsJson);
      expect(optionsJson.extensions.prf.eval.first).toBe(PRF_SALT);
   });

   it('prfReadKey returns the 32-byte result', () => {
      const rawKey = getRandom(cc.KEY_BYTES);
      const output = prfReadKey(prfExtensionResults(rawKey.buffer));
      expect(output).not.toBeNull();
      expect([...output!]).toEqual([...rawKey]);
   });

   it('prfReadKey reads a typed-array view returned by some providers', () => {
      const rawKey = getRandom(cc.KEY_BYTES);
      // A partial view into a larger buffer, as an intercepting provider might return
      const backing = new Uint8Array(cc.KEY_BYTES + 8);
      backing.set(rawKey, 4);
      const view = new Uint8Array(backing.buffer, 4, cc.KEY_BYTES);
      const output = prfReadKey(prfExtensionResults(view));
      expect(output).not.toBeNull();
      expect([...output!]).toEqual([...rawKey]);
   });

   it('prfReadKey reads a plain number[] result (1Password on Chrome)', () => {
      const rawKey = getRandom(cc.KEY_BYTES);
      const output = prfReadKey(prfExtensionResults([...rawKey]));
      expect(output).not.toBeNull();
      expect([...output!]).toEqual([...rawKey]);
   });

   it('prfReadKey returns null when no result is present', () => {
      expect(prfReadKey({} as AuthenticationExtensionsClientOutputs)).toBeNull();
      expect(prfReadKey({ prf: { enabled: true } } as AuthenticationExtensionsClientOutputs)).toBeNull();
   });

   it('prfReadKey throws on an unexpected length', () => {
      const shortBuffer = getRandom(16).buffer;
      expect(() => prfReadKey(prfExtensionResults(shortBuffer))).toThrow();
   });

   it('prfEnabled reflects the enabled flag', () => {
      expect(prfEnabled({ prf: { enabled: true } } as AuthenticationExtensionsClientOutputs)).toBe(true);
      expect(prfEnabled({ prf: {} } as AuthenticationExtensionsClientOutputs)).toBe(false);
      expect(prfEnabled({} as AuthenticationExtensionsClientOutputs)).toBe(false);
   });

   it('prfEncrypt then prfDecrypt round-trips the plaintext', async () => {
      const userId = bytesToBase64(getRandom(cc.USERID_BYTES));
      const plainText = getRandom(cc.USERCRED_BYTES);
      const prfKey = getRandom(cc.KEY_BYTES);
      const prfKeyCopy = prfKey.slice(0);

      const cipherText = await prfEncrypt(plainText, prfKey, userId);
      const recovered = await prfDecrypt(cipherText, prfKeyCopy, userId);
      expect([...recovered]).toEqual([...plainText]);
   });

   it('prfDecrypt with the wrong key fails', async () => {
      const userId = bytesToBase64(getRandom(cc.USERID_BYTES));
      const plainText = getRandom(cc.USERCRED_BYTES);
      const prfKey = getRandom(cc.KEY_BYTES);
      const wrongKey = getRandom(cc.KEY_BYTES);

      const cipherText = await prfEncrypt(plainText, prfKey, userId);
      await expect(prfDecrypt(cipherText, wrongKey, userId)).rejects.toThrow();
   });

   it('prfEncrypt rejects an all-zero key', async () => {
      const userId = bytesToBase64(getRandom(cc.USERID_BYTES));
      const plainText = getRandom(cc.USERCRED_BYTES);
      const zeroKey = new Uint8Array(cc.KEY_BYTES) as Uint8Array<ArrayBuffer>;
      await expect(prfEncrypt(plainText, zeroKey, userId)).rejects.toThrow();
   });

   it('prfEncrypt rejects a wrong-length key', async () => {
      const userId = bytesToBase64(getRandom(cc.USERID_BYTES));
      const plainText = getRandom(cc.USERCRED_BYTES);
      const shortKey = getRandom(16);
      await expect(prfEncrypt(plainText, shortKey, userId)).rejects.toThrow();
   });
});
