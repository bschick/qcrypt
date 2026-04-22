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

import { describe, it, expect } from 'vitest';
import {
   ParamError,
   AuthError,
   NotFoundError,
   sanitizeString,
   validB64,
   base64UrlEncode,
   base64UrlDecode,
   base64Decode,
   timingSafeEqual,
} from '../src/utils';

describe('Error classes', () => {
   it('ParamError is an Error', () => {
      const e = new ParamError('bad param');
      expect(e).toBeInstanceOf(Error);
      expect(e).toBeInstanceOf(ParamError);
      expect(e.message).toBe('bad param');
   });

   it('AuthError defaults to "not authorized"', () => {
      const e = new AuthError();
      expect(e).toBeInstanceOf(Error);
      expect(e).toBeInstanceOf(AuthError);
      expect(e.message).toBe('not authorized');
   });

   it('AuthError accepts a custom message', () => {
      const e = new AuthError('custom reason');
      expect(e.message).toBe('custom reason');
   });

   it('NotFoundError is an Error', () => {
      const e = new NotFoundError('missing');
      expect(e).toBeInstanceOf(Error);
      expect(e).toBeInstanceOf(NotFoundError);
      expect(e.message).toBe('missing');
   });
});

describe('sanitizeString', () => {
   it('returns a trimmed plain string unchanged', () => {
      expect(sanitizeString('hello world')).toBe('hello world');
      expect(sanitizeString('  padded  ')).toBe('padded');
   });

   it('strips HTML tags but keeps text content', () => {
      expect(sanitizeString('<b>hi</b>')).toBe('hi');
      expect(sanitizeString('<script>alert(1)</script>safe')).toBe('alert(1)safe');
   });

   it('strips inline tags surrounded by text', () => {
      expect(sanitizeString('a<b>c')).toBe('ac');
   });

   it('strips anything between angle brackets as a pseudo-tag', () => {
      // The XSS parser treats "< 2 >" as a tag and strips it entirely
      expect(sanitizeString('1 < 2 > 0')).toBe('1  0');
   });

   it('throws ParamError on non-string input', () => {
      expect(() => sanitizeString(undefined as unknown as string)).toThrow(ParamError);
      expect(() => sanitizeString(null as unknown as string)).toThrow(ParamError);
      expect(() => sanitizeString(42 as unknown as string)).toThrow(ParamError);
   });

   it('throws ParamError on empty string input', () => {
      expect(() => sanitizeString('')).toThrow(ParamError);
   });

   it('throws ParamError when sanitization yields empty', () => {
      expect(() => sanitizeString('<>')).toThrow(ParamError);
   });
});

describe('validB64', () => {
   it('accepts standard base64', () => {
      expect(validB64('abcDEF123+/=')).toBe(true);
   });

   it('accepts base64url characters', () => {
      expect(validB64('abc-DEF_123')).toBe(true);
   });

   it('rejects empty, null, undefined', () => {
      expect(validB64('')).toBe(false);
      expect(validB64(null)).toBe(false);
      expect(validB64(undefined)).toBe(false);
   });

   it('rejects non-string input', () => {
      expect(validB64(123 as unknown as string)).toBe(false);
   });

   it('rejects strings with invalid characters', () => {
      expect(validB64('has space')).toBe(false);
      expect(validB64('has.dot')).toBe(false);
      expect(validB64('has!bang')).toBe(false);
   });
});

describe('base64UrlEncode', () => {
   it('encodes bytes to base64url (no padding, - and _ instead of + and /)', () => {
      const bytes = new Uint8Array([0xfb, 0xff, 0xbf]);
      // Standard base64 would be "+/+/"; base64url is "-_-_"
      expect(base64UrlEncode(bytes)).toBe('-_-_');
   });

   it('encodes known ASCII bytes', () => {
      const bytes = new Uint8Array([0x68, 0x65, 0x6c, 0x6c, 0x6f]); // 'hello'
      expect(base64UrlEncode(bytes)).toBe('aGVsbG8');
   });

   it('returns undefined for undefined input', () => {
      expect(base64UrlEncode(undefined)).toBeUndefined();
   });

   it('roundtrips with base64UrlDecode', () => {
      const bytes = new Uint8Array([0, 1, 2, 250, 251, 252, 253, 254, 255]);
      const encoded = base64UrlEncode(bytes)!;
      const decoded = base64UrlDecode(encoded)!;
      expect(Array.from(decoded)).toEqual(Array.from(bytes));
   });
});

describe('base64UrlDecode', () => {
   it('decodes base64url to bytes', () => {
      const decoded = base64UrlDecode('aGVsbG8')!;
      expect(Array.from(decoded)).toEqual([0x68, 0x65, 0x6c, 0x6c, 0x6f]);
   });

   it('decodes url-safe characters', () => {
      const decoded = base64UrlDecode('-_-_')!;
      expect(Array.from(decoded)).toEqual([0xfb, 0xff, 0xbf]);
   });

   it('returns undefined for undefined input', () => {
      expect(base64UrlDecode(undefined)).toBeUndefined();
   });

   it('returns a Uint8Array backed by its own buffer slice', () => {
      const decoded = base64UrlDecode('aGVsbG8')!;
      expect(decoded).toBeInstanceOf(Uint8Array);
      expect(decoded.byteLength).toBe(5);
   });
});

describe('base64Decode', () => {
   it('decodes standard base64 (with + / and padding)', () => {
      const decoded = base64Decode('+/+/')!;
      expect(Array.from(decoded)).toEqual([0xfb, 0xff, 0xbf]);
   });

   it('decodes base64url variants too', () => {
      const decoded = base64Decode('-_-_')!;
      expect(Array.from(decoded)).toEqual([0xfb, 0xff, 0xbf]);
   });

   it('returns undefined for undefined input', () => {
      expect(base64Decode(undefined)).toBeUndefined();
   });
});

describe('timingSafeEqual', () => {
   it('returns true for identical strings', () => {
      expect(timingSafeEqual(Buffer.from(''), Buffer.from(''))).toBe(true);
      expect(timingSafeEqual(Buffer.from('abc'), Buffer.from('abc'))).toBe(true);
      expect(timingSafeEqual(Buffer.from('aGVsbG8'), Buffer.from('aGVsbG8'))).toBe(true);
   });

   it('returns false for strings of different lengths', () => {
      expect(timingSafeEqual(Buffer.from('abc'), Buffer.from('abcd'))).toBe(false);
      expect(timingSafeEqual(Buffer.from('abcd'), Buffer.from('abc'))).toBe(false);
      expect(timingSafeEqual(Buffer.from(''), Buffer.from('a'))).toBe(false);
   });

   it('returns false for equal-length strings that differ', () => {
      expect(timingSafeEqual(Buffer.from('abc'), Buffer.from('abd'))).toBe(false);
      expect(timingSafeEqual(Buffer.from('abc'), Buffer.from('xbc'))).toBe(false);
      expect(timingSafeEqual(Buffer.from('abcd'), Buffer.from('abce'))).toBe(false);
   });

   it('is case-sensitive', () => {
      expect(timingSafeEqual(Buffer.from('Abc'), Buffer.from('abc'))).toBe(false);
   });

   it('handles unicode BMP code units identically', () => {
      expect(timingSafeEqual(Buffer.from('é'), Buffer.from('é'))).toBe(true);
      expect(timingSafeEqual(Buffer.from('é'), Buffer.from('e'))).toBe(false);
   });
});
