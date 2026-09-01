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
   knownLenTimingSafeEqual,
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

// The stripped set was checked against the PRECIS (RFC 8264) derived properties published at
// https://github.com/byllyfish/precis_i18n/blob/master/test/derived-props-17.0.txt, which matched
// this runtime's Unicode 17.0. Every codepoint that file marks DISALLOWED/controls or
// DISALLOWED/precis_ignorable_properties is stripped here; the only characters we strip that it
// permits are the join controls, which are invisible and so can still disguise one name as another.
// The file is not vendored because it is pinned to one Unicode version and goes stale.
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

   it('strips control characters that would split a value across log lines', () => {
      expect(sanitizeString('dave\u000Acap of 25 reached')).toBe('davecap of 25 reached');
      expect(sanitizeString('dave\u000Dmore')).toBe('davemore');
      expect(sanitizeString('dave\u0000more')).toBe('davemore');
      expect(sanitizeString('dave\u007Fmore')).toBe('davemore');
   });

   it('strips format characters that occupy no visible width', () => {
      expect(sanitizeString('da\u200Bve')).toBe('dave');
      expect(sanitizeString('da\u200Dve')).toBe('dave');
      expect(sanitizeString('\u2066da\u2069ve')).toBe('dave');
      expect(sanitizeString('da\uFEFFve')).toBe('dave');
      expect(sanitizeString('da\u00ADve')).toBe('dave');
   });

   it('leaves nothing that makes a stored value render as different text', () => {
      // U+202E reverses the run that follows it, so the raw value below reads as 'pwtesty_dave'
      const displayForm = (value: string): string => {
         const at = value.indexOf('\u202E');
         return at === -1 ? value : value.slice(0, at) + [...value.slice(at + 1)].reverse().join('');
      };

      const twin = sanitizeString('pwtesty_\u202Eevad');
      expect(displayForm(twin)).toBe(twin);
      expect(twin).not.toBe(sanitizeString('pwtesty_dave'));
   });

   it('trims whitespace left behind by stripping', () => {
      expect(sanitizeString(' \u202E dave ')).toBe('dave');
   });

   it('strips characters that render as nothing despite being letters', () => {
      // Hangul fillers are category Lo, so no control or format based filter reaches them
      expect(sanitizeString('da\u3164ve')).toBe('dave');
      expect(sanitizeString('da\u115Fve')).toBe('dave');
      expect(sanitizeString('da\uFFA0ve')).toBe('dave');
      expect(() => sanitizeString('\u3164'.repeat(6))).toThrow(ParamError);
   });

   it('strips variation selectors and noncharacters', () => {
      expect(sanitizeString('da\uFE0Fve')).toBe('dave');
      expect(sanitizeString('da\uFDD0ve')).toBe('dave');
   });

   it('normalizes so one name cannot be stored under two encodings', () => {
      const composed = sanitizeString('jos\u00E9');
      const decomposed = sanitizeString('jose\u0301');
      expect(decomposed).toBe(composed);
   });

   it('keeps characters that carry a visible glyph', () => {
      expect(sanitizeString('dave smith')).toBe('dave smith');
      expect(sanitizeString('\u00E9\u4E2D\u6587')).toBe('\u00E9\u4E2D\u6587');
      expect(sanitizeString('dave \u{1F44D}')).toBe('dave \u{1F44D}');
   });

   // Running the output back through must not change it again, which fails if normalizing and
   // stripping can expose new work for each other
   it('is idempotent', () => {
      for (const raw of ['dave', 'jose\u0301', 'da\u200Bve', ' \u202E dave ', 'jos\u00E9 \u3164 smith']) {
         const once = sanitizeString(raw);
         expect(sanitizeString(once)).toBe(once);
      }
   });

   it('throws ParamError when a value holds nothing but stripped characters', () => {
      expect(() => sanitizeString('\u202E\u200B')).toThrow(ParamError);
      expect(() => sanitizeString('\u000A\u000D')).toThrow(ParamError);
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
      expect(knownLenTimingSafeEqual(Buffer.from(''), Buffer.from(''))).toBe(true);
      expect(knownLenTimingSafeEqual(Buffer.from('abc'), Buffer.from('abc'))).toBe(true);
      expect(knownLenTimingSafeEqual(Buffer.from('aGVsbG8'), Buffer.from('aGVsbG8'))).toBe(true);
   });

   it('returns false for strings of different lengths', () => {
      expect(knownLenTimingSafeEqual(Buffer.from('abc'), Buffer.from('abcd'))).toBe(false);
      expect(knownLenTimingSafeEqual(Buffer.from('abcd'), Buffer.from('abc'))).toBe(false);
      expect(knownLenTimingSafeEqual(Buffer.from(''), Buffer.from('a'))).toBe(false);
   });

   it('returns false for equal-length strings that differ', () => {
      expect(knownLenTimingSafeEqual(Buffer.from('abc'), Buffer.from('abd'))).toBe(false);
      expect(knownLenTimingSafeEqual(Buffer.from('abc'), Buffer.from('xbc'))).toBe(false);
      expect(knownLenTimingSafeEqual(Buffer.from('abcd'), Buffer.from('abce'))).toBe(false);
   });

   it('is case-sensitive', () => {
      expect(knownLenTimingSafeEqual(Buffer.from('Abc'), Buffer.from('abc'))).toBe(false);
   });

   it('handles unicode BMP code units identically', () => {
      expect(knownLenTimingSafeEqual(Buffer.from('é'), Buffer.from('é'))).toBe(true);
      expect(knownLenTimingSafeEqual(Buffer.from('é'), Buffer.from('e'))).toBe(false);
   });
});
