#!/usr/bin/env node
/* MIT License

Copyright (c) 2024-2026 Brad Schick

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

// Inspect the structure of a Quick Crypt encrypted file. Wire format
// reference: apps/web/src/assets/quickcrypt{5,6}.tcl (Hex Fiend templates)
// and libs/crypto/src/lib/cipher.consts.ts. All multi-byte integers on
// disk are little-endian (see numToBytes/bytesToNum in libs/crypto/utils.ts).
//
// The parser is intentionally fault-tolerant: bad values are recorded in
// each field's "Note" column and accumulated as a list of errors printed
// after the block tables. We trust the on-disk payload sizes to skip past
// blocks we can't fully decode (e.g., unknown algorithm), and only stop
// when the file is truly truncated or overruns past a header.
//
// Run with Node 24+ (native TypeScript stripping):
//   node apps/web/scripts/parse-qcrypt.ts <file...>

import { readFileSync, statSync, writeFileSync } from 'node:fs';
import { basename, dirname, extname, join } from 'node:path';
import yargs from 'yargs';
import { hideBin } from 'yargs/helpers';

const MAC_BYTES = 32;
const VER_BYTES = 2;
const PAYLOAD_SIZE_BYTES = 3;
const FLAGS_BYTES = 1;
const ALG_BYTES = 2;
const SLT_BYTES = 16;
const IC_BYTES = 4;
const LPP_BYTES = 1;
const HINT_LEN_BYTES = 1;

// V4/V5 keep the flags byte in the header; V6+ moves it into the payload's
// additional-data section. V4's flags byte is reserved (always 0); V5 uses
// bit 0 as the terminal-block flag.
const HEADER_BYTES_OLD = MAC_BYTES + VER_BYTES + PAYLOAD_SIZE_BYTES + FLAGS_BYTES;
const HEADER_BYTES_V6PLUS = MAC_BYTES + VER_BYTES + PAYLOAD_SIZE_BYTES;

// Validation ranges from libs/crypto/src/lib/cipher.consts.ts
const ICOUNT_MIN = 420000;
const ICOUNT_MAX = 4294000000;
const LP_MAX = 16;
const PAYLOAD_SIZE_MIN = 31;
const PAYLOAD_SIZE_MAX = 16777215;

// V1 has no per-block headers and no payload size; the entire file is a
// single document with the version embedded in the middle. See DecipherV1
// in libs/crypto/src/lib/deciphers-old.ts.
const SUPPORTED_VERSIONS = [1, 4, 5, 6, 7] as const;
type SupportedVersion = (typeof SUPPORTED_VERSIONS)[number];

// Version we fall back to when the on-disk version is unrecognized.
const FALLBACK_VERSION: SupportedVersion = 6;

type AlgInfo = {
   id: number;
   name: string;
   description: string;
   ivBytes: number;
};

const ALGS_BY_ID: Record<number, AlgInfo> = {
   1: { id: 1, name: 'AES-GCM', description: 'AES 256 GCM', ivBytes: 12 },
   2: { id: 2, name: 'X20-PLY', description: 'XChaCha20 Poly1305', ivBytes: 24 },
   3: { id: 3, name: 'AEGIS-256', description: 'AEGIS 256', ivBytes: 32 },
};

type Field = {
   name: string;
   offset: number;
   length: number;
   value: string;
   note: string;
};

type ParsedBlock = {
   index: number;
   start: number;
   end: number;
   payloadSize: number;
   // null when the format has no terminal-block bit (V1, V4) or when we
   // could not read the flags byte for this block.
   terminal: number | null;
   fields: Field[];
};

type ErrorRecord = {
   where: string;
   message: string;
   // Fatal = the file was truncated, the parser couldn't make progress, or
   // some other "the bytes don't add up" condition. Recoverable errors
   // (bad version, bad alg, terminal-flag misuse, etc) leave the parsed
   // structure intact and are safe to operate on.
   fatal: boolean;
};

type ParsedFile = {
   path: string;
   size: number;
   buffer: Buffer;
   version: SupportedVersion;
   versionFallback: { observed: number } | null;
   blocks: ParsedBlock[];
   errors: ErrorRecord[];
};

type Options = {
   maxHex: number;
   maxBlocks: number;
};

class Reader {
   readonly data: Buffer;
   pos: number;

   constructor(data: Buffer, pos = 0) {
      this.data = data;
      this.pos = pos;
   }

   get remaining(): number {
      return this.data.length - this.pos;
   }

   canRead(n: number): boolean {
      return this.pos + n <= this.data.length;
   }

   readBytes(n: number): Buffer {
      const out = this.data.subarray(this.pos, this.pos + n);
      this.pos += out.length;
      return out;
   }

   readU8(): number {
      const v = this.data.readUInt8(this.pos);
      this.pos += 1;
      return v;
   }

   readU16LE(): number {
      const v = this.data.readUInt16LE(this.pos);
      this.pos += 2;
      return v;
   }

   readU24LE(): number {
      const lo = this.data.readUInt16LE(this.pos);
      const hi = this.data.readUInt8(this.pos + 2);
      this.pos += 3;
      return lo | (hi << 16);
   }

   readU32LE(): number {
      const v = this.data.readUInt32LE(this.pos);
      this.pos += 4;
      return v;
   }
}

function fmtHex(buf: Buffer, maxBytes: number): string {
   if (buf.length === 0) {
      return '(empty)';
   }
   if (buf.length <= maxBytes) {
      return buf.toString('hex');
   }
   const half = Math.max(1, Math.floor(maxBytes / 2));
   const head = buf.subarray(0, half).toString('hex');
   const tail = buf.subarray(buf.length - half).toString('hex');
   return `${head}…${tail}`;
}

function joinNotes(...parts: string[]): string {
   return parts.filter((p) => p.length > 0).join('; ');
}

function recordError(errors: ErrorRecord[], where: string, message: string): string {
   errors.push({ where, message, fatal: false });
   return `ERROR: ${message}`;
}

// Use for truncation / overrun / can't-make-progress conditions — anything
// that means the file's bytes don't actually add up to a complete structure.
// `--morph` refuses to run when any fatal error is present.
function recordFatal(errors: ErrorRecord[], where: string, message: string): string {
   errors.push({ where, message, fatal: true });
   return `ERROR: ${message}`;
}

function isSupportedVersion(ver: number): ver is SupportedVersion {
   return (SUPPORTED_VERSIONS as readonly number[]).includes(ver);
}

// V1's "version" lives in the middle of the document, not at offset MAC_BYTES.
// The two bytes after the MAC are instead the algorithm id (1-3). Distinguish
// V1 from V4+ by checking whether that uint16 is below V1_BELOW (=4).
// See libs/crypto/src/lib/ciphers.ts and DecipherV1 for the original logic.
function detectVersion(buffer: Buffer): {
   version: SupportedVersion;
   fallback: { observed: number } | null;
} {
   const verOrAlg = buffer.readUInt16LE(MAC_BYTES);
   if (verOrAlg > 0 && verOrAlg < 4) {
      return { version: 1, fallback: null };
   }
   if (isSupportedVersion(verOrAlg)) {
      return { version: verOrAlg, fallback: null };
   }
   return { version: FALLBACK_VERSION, fallback: { observed: verOrAlg } };
}

// ---- Header / payload-AD field readers ----

type HeaderResult = {
   payloadSize: number;
   // Only populated when the header carries the flags byte (V4/V5).
   // For V4 the bit is unused; for V5 bit 0 is the terminal-block flag.
   headerFlags: number | null;
};

// Builds the note string for a flags byte in V5/V6/V7 — the formats that
// carry a terminal-block bit. Records errors for unexpected reserved bits,
// for early termination (terminal=1 mid-stream), and for missing termination
// (last block has terminal=0).
function flagsNote(
   flags: number,
   isLastBlock: boolean,
   blockIndex: number,
   errors: ErrorRecord[]
): string {
   const where = `block ${blockIndex}`;
   const terminal = flags & 0x01;
   const reserved = flags & 0xFE;
   const parts: string[] = [`terminal=${terminal}`];
   if (reserved !== 0) {
      parts.push(
         recordError(errors, where, `flags has unexpected bits set (0x${reserved.toString(16).padStart(2, '0')})`)
      );
   }
   if (isLastBlock && terminal === 0) {
      parts.push(recordError(errors, where, 'missing termination (last block has terminal flag clear)'));
   }
   if (!isLastBlock && terminal === 1) {
      parts.push(recordError(errors, where, 'early termination (terminal flag set on non-last block)'));
   }
   return joinNotes(...parts);
}

function parseHeader(
   reader: Reader,
   fileVersion: SupportedVersion,
   blockIndex: number,
   fields: Field[],
   errors: ErrorRecord[],
   opts: Options
): HeaderResult {
   const where = `block ${blockIndex}`;

   const macOffset = reader.pos;
   const mac = reader.readBytes(MAC_BYTES);
   fields.push({
      name: 'hmac',
      offset: macOffset,
      length: MAC_BYTES,
      value: fmtHex(mac, opts.maxHex),
      note: '',
   });

   const verOffset = reader.pos;
   const ver = reader.readU16LE();
   let verNote = '';
   if (ver !== fileVersion) {
      verNote = recordError(
         errors,
         where,
         `header version ${ver} does not match file version ${fileVersion}`
      );
   }
   fields.push({
      name: 'version',
      offset: verOffset,
      length: VER_BYTES,
      value: String(ver),
      note: verNote,
   });

   const sizeOffset = reader.pos;
   const payloadSize = reader.readU24LE();
   let sizeNote = '';
   if (payloadSize < PAYLOAD_SIZE_MIN || payloadSize > PAYLOAD_SIZE_MAX) {
      sizeNote = recordError(
         errors,
         where,
         `payload size ${payloadSize} out of range [${PAYLOAD_SIZE_MIN}, ${PAYLOAD_SIZE_MAX}]`
      );
   }
   fields.push({
      name: 'payload len',
      offset: sizeOffset,
      length: PAYLOAD_SIZE_BYTES,
      value: String(payloadSize),
      note: sizeNote,
   });

   let headerFlags: number | null = null;
   if (fileVersion === 4 || fileVersion === 5) {
      const flagsOffset = reader.pos;
      const flags = reader.readU8();
      headerFlags = flags;

      let label: string;
      let note: string;
      if (fileVersion === 4) {
         label = 'reserved';
         note = 'reserved (V4 unused)';
         if (flags !== 0) {
            note = joinNotes(note, recordError(errors, where, `reserved byte non-zero (0x${flags.toString(16)})`));
         }
      } else {
         label = 'flags';
         // V5 places the flags byte in the header — the payload starts at
         // reader.pos + 1, so payloadStart + payloadSize tells us whether
         // this block reaches end-of-file.
         const payloadStart = reader.pos + FLAGS_BYTES;
         const isLastBlock = payloadStart + payloadSize >= reader.data.length;
         note = flagsNote(flags, isLastBlock, blockIndex, errors);
      }
      fields.push({
         name: label,
         offset: flagsOffset,
         length: FLAGS_BYTES,
         value: `0x${flags.toString(16).padStart(2, '0')}`,
         note,
      });
   }

   return { payloadSize, headerFlags };
}

// Returns the flags byte value, or null if it could not be read.
function parseFlagsInPayload(
   reader: Reader,
   blockIndex: number,
   isLastBlock: boolean,
   fields: Field[],
   errors: ErrorRecord[]
): number | null {
   if (!reader.canRead(FLAGS_BYTES)) {
      return null;
   }
   const flagsOffset = reader.pos;
   const flags = reader.readU8();
   fields.push({
      name: 'flags',
      offset: flagsOffset,
      length: FLAGS_BYTES,
      value: `0x${flags.toString(16).padStart(2, '0')}`,
      note: flagsNote(flags, isLastBlock, blockIndex, errors),
   });
   return flags;
}

// Parses alg id and IV. Returns the algorithm info, or null if the alg id
// is invalid (in which case caller should skip the rest of the payload).
function parseAlgAndIv(
   reader: Reader,
   blockIndex: number,
   fields: Field[],
   errors: ErrorRecord[],
   opts: Options
): AlgInfo | null {
   const where = `block ${blockIndex}`;

   if (!reader.canRead(ALG_BYTES)) {
      return null;
   }
   const algOffset = reader.pos;
   const algId = reader.readU16LE();
   const alg = ALGS_BY_ID[algId];
   if (!alg) {
      const note = recordError(errors, where, `invalid algorithm id ${algId}`);
      fields.push({
         name: 'alg',
         offset: algOffset,
         length: ALG_BYTES,
         value: String(algId),
         note,
      });
      return null;
   }
   fields.push({
      name: 'alg',
      offset: algOffset,
      length: ALG_BYTES,
      value: String(algId),
      note: `${alg.name} (${alg.description})`,
   });

   const ivOffset = reader.pos;
   const ivAvailable = Math.min(alg.ivBytes, reader.remaining);
   const iv = reader.readBytes(ivAvailable);
   let ivNote = '';
   if (ivAvailable < alg.ivBytes) {
      ivNote = recordFatal(
         errors,
         where,
         `iv truncated: expected ${alg.ivBytes} bytes, only ${ivAvailable} available`
      );
   }
   fields.push({
      name: 'iv',
      offset: ivOffset,
      length: ivAvailable,
      value: fmtHex(iv, opts.maxHex),
      note: ivNote,
   });

   return alg;
}

// Helper that consumes the rest of the block's payload as one opaque chunk.
// Used when an earlier field fails validation and we can no longer interpret
// the remaining bytes (e.g., unknown algorithm).
function consumeRemainder(
   reader: Reader,
   payloadStart: number,
   payloadSize: number,
   blockIndex: number,
   fields: Field[],
   errors: ErrorRecord[],
   reason: string,
   opts: Options
): void {
   const where = `block ${blockIndex}`;
   const claimedRemaining = payloadSize - (reader.pos - payloadStart);
   if (claimedRemaining <= 0) {
      return;
   }
   const available = Math.min(claimedRemaining, reader.remaining);
   const offset = reader.pos;
   const blob = reader.readBytes(available);
   let note = `ERROR: ${reason}`;
   if (available < claimedRemaining) {
      note = joinNotes(
         note,
         recordFatal(
            errors,
            where,
            `payload truncated: claimed ${claimedRemaining} more bytes, only ${available} available`
         )
      );
   }
   fields.push({
      name: 'unparsed payload',
      offset,
      length: available,
      value: fmtHex(blob, opts.maxHex),
      note,
   });
}

// ---- Block 0 / Block N parsing ----

function parseBlock(
   reader: Reader,
   fileVersion: SupportedVersion,
   blockIndex: number,
   isFirst: boolean,
   opts: Options,
   errors: ErrorRecord[]
): ParsedBlock {
   const where = `block ${blockIndex}`;
   const blockStart = reader.pos;
   const fields: Field[] = [];

   const headerBytes = fileVersion >= 6 ? HEADER_BYTES_V6PLUS : HEADER_BYTES_OLD;
   if (reader.remaining < headerBytes) {
      const offset = reader.pos;
      const blob = reader.readBytes(reader.remaining);
      const note = recordFatal(
         errors,
         where,
         `truncated header: needed ${headerBytes} bytes, only ${blob.length} available`
      );
      fields.push({
         name: 'truncated header',
         offset,
         length: blob.length,
         value: fmtHex(blob, opts.maxHex),
         note: `ERROR: ${note.replace(/^ERROR: /, '')}`,
      });
      return {
         index: blockIndex,
         start: blockStart,
         end: reader.pos,
         payloadSize: 0,
         terminal: null,
         fields,
      };
   }

   const { payloadSize, headerFlags } = parseHeader(reader, fileVersion, blockIndex, fields, errors, opts);
   const payloadStart = reader.pos;

   // If payloadSize is wildly out of range we still try to honor it for
   // alignment, but cap reads at what's actually in the buffer.
   const claimedEnd = payloadStart + payloadSize;
   if (claimedEnd > reader.data.length) {
      recordFatal(
         errors,
         where,
         `payload claims ${payloadSize} bytes but only ${reader.data.length - payloadStart} remain in file`
      );
   }

   // A block is "last" when its claimed payload reaches (or overshoots)
   // end-of-file. parseHeader already used this to annotate V5's flags
   // byte; for V6+ we hand the same bit to parseFlagsInPayload below.
   const isLastBlock = claimedEnd >= reader.data.length;

   let terminal: number | null = null;
   if (fileVersion === 5 && headerFlags !== null) {
      terminal = headerFlags & 0x01;
   }

   if (fileVersion >= 6) {
      const flags = parseFlagsInPayload(reader, blockIndex, isLastBlock, fields, errors);
      if (flags !== null) {
         terminal = flags & 0x01;
      }
   }

   const alg = parseAlgAndIv(reader, blockIndex, fields, errors, opts);
   if (alg === null) {
      consumeRemainder(reader, payloadStart, payloadSize, blockIndex, fields, errors, 'cannot parse without valid alg', opts);
      return {
         index: blockIndex,
         start: blockStart,
         end: reader.pos,
         payloadSize,
         terminal,
         fields,
      };
   }

   if (isFirst) {
      parseBlock0Tail(reader, payloadStart, payloadSize, blockIndex, fields, errors, opts);
   } else {
      parseBlockNTail(reader, payloadStart, payloadSize, blockIndex, fields, errors, opts);
   }

   return {
      index: blockIndex,
      start: blockStart,
      end: reader.pos,
      payloadSize,
      terminal,
      fields,
   };
}

function parseBlock0Tail(
   reader: Reader,
   payloadStart: number,
   payloadSize: number,
   blockIndex: number,
   fields: Field[],
   errors: ErrorRecord[],
   opts: Options
): void {
   const where = `block ${blockIndex}`;

   if (reader.remaining < SLT_BYTES) {
      consumeRemainder(reader, payloadStart, payloadSize, blockIndex, fields, errors, 'truncated before salt', opts);
      return;
   }
   const sltOffset = reader.pos;
   const slt = reader.readBytes(SLT_BYTES);
   fields.push({
      name: 'salt',
      offset: sltOffset,
      length: SLT_BYTES,
      value: fmtHex(slt, opts.maxHex),
      note: '',
   });

   if (reader.remaining < IC_BYTES) {
      consumeRemainder(reader, payloadStart, payloadSize, blockIndex, fields, errors, 'truncated before iterations', opts);
      return;
   }
   const icOffset = reader.pos;
   const ic = reader.readU32LE();
   let icNote = '';
   if (ic < ICOUNT_MIN || ic > ICOUNT_MAX) {
      icNote = recordError(
         errors,
         where,
         `iterations ${ic} out of range [${ICOUNT_MIN}, ${ICOUNT_MAX}]`
      );
   }
   fields.push({
      name: 'iterations',
      offset: icOffset,
      length: IC_BYTES,
      value: String(ic),
      note: icNote,
   });

   if (reader.remaining < LPP_BYTES) {
      consumeRemainder(reader, payloadStart, payloadSize, blockIndex, fields, errors, 'truncated before loop byte', opts);
      return;
   }
   const lppOffset = reader.pos;
   const lppByte = reader.readU8();
   const lp = (lppByte & 0x0F) + 1;
   const lpEnd = ((lppByte >> 4) & 0x0F) + 1;
   const noteParts: string[] = [`loop=${lp} loopEnd=${lpEnd}`];
   if (lpEnd < 1 || lpEnd > LP_MAX) {
      noteParts.push(recordError(errors, where, `loopEnd ${lpEnd} out of range [1, ${LP_MAX}]`));
   }
   if (lp < 1 || lp > lpEnd) {
      noteParts.push(recordError(errors, where, `loop ${lp} out of range [1, loopEnd=${lpEnd}]`));
   }
   fields.push({
      name: 'loop / end',
      offset: lppOffset,
      length: LPP_BYTES,
      value: `0x${lppByte.toString(16).padStart(2, '0')}`,
      note: joinNotes(...noteParts),
   });

   if (reader.remaining < HINT_LEN_BYTES) {
      consumeRemainder(reader, payloadStart, payloadSize, blockIndex, fields, errors, 'truncated before hint len', opts);
      return;
   }
   const hlenOffset = reader.pos;
   const hintLen = reader.readU8();
   const remainingPayload = payloadSize - (reader.pos - payloadStart);
   let hlenNote = '';
   // The hint must fit inside the remaining payload, leaving at least one
   // byte for the encrypted data.
   if (hintLen >= remainingPayload) {
      hlenNote = recordError(
         errors,
         where,
         `hint len ${hintLen} would consume entire remaining payload of ${remainingPayload} bytes`
      );
   }
   fields.push({
      name: 'hint len',
      offset: hlenOffset,
      length: HINT_LEN_BYTES,
      value: String(hintLen),
      note: hlenNote,
   });

   const hintAvailable = Math.min(hintLen, reader.remaining, Math.max(0, payloadSize - (reader.pos - payloadStart)));
   if (hintLen > 0) {
      const hintOffset = reader.pos;
      const hint = reader.readBytes(hintAvailable);
      let hintNote = '';
      if (hintAvailable < hintLen) {
         hintNote = recordFatal(
            errors,
            where,
            `hint truncated: expected ${hintLen} bytes, only ${hintAvailable} available`
         );
      }
      fields.push({
         name: 'hint encrypted',
         offset: hintOffset,
         length: hintAvailable,
         value: fmtHex(hint, opts.maxHex),
         note: hintNote,
      });
      if (hintAvailable < hintLen) {
         return;
      }
   }

   readEncryptedData(reader, payloadStart, payloadSize, blockIndex, fields, errors, opts);
}

function parseBlockNTail(
   reader: Reader,
   payloadStart: number,
   payloadSize: number,
   blockIndex: number,
   fields: Field[],
   errors: ErrorRecord[],
   opts: Options
): void {
   readEncryptedData(reader, payloadStart, payloadSize, blockIndex, fields, errors, opts);
}

function readEncryptedData(
   reader: Reader,
   payloadStart: number,
   payloadSize: number,
   blockIndex: number,
   fields: Field[],
   errors: ErrorRecord[],
   opts: Options
): void {
   const where = `block ${blockIndex}`;
   const consumed = reader.pos - payloadStart;
   const claimed = payloadSize - consumed;

   if (claimed <= 0) {
      recordFatal(errors, where, `no bytes left for encrypted data (consumed ${consumed} of ${payloadSize})`);
      return;
   }

   const available = Math.min(claimed, reader.remaining);
   const offset = reader.pos;
   const edata = reader.readBytes(available);
   let note = '';
   if (available < claimed) {
      note = recordFatal(
         errors,
         where,
         `encrypted data truncated: expected ${claimed} bytes, only ${available} available`
      );
   }
   fields.push({
      name: 'encrypted data',
      offset,
      length: available,
      value: fmtHex(edata, opts.maxHex),
      note,
   });
}

// V1 layout (the entire file is a single block):
//   mac(32) alg(2) iv(var) slt(16) ic(4) ver(2) hint_len(1) hint encrypted_data
function parseV1Document(
   reader: Reader,
   totalSize: number,
   opts: Options,
   errors: ErrorRecord[]
): ParsedBlock {
   const blockIndex = 0;
   const where = `block ${blockIndex}`;
   const blockStart = reader.pos;
   const fields: Field[] = [];

   const macOffset = reader.pos;
   const mac = reader.readBytes(MAC_BYTES);
   fields.push({
      name: 'hmac',
      offset: macOffset,
      length: MAC_BYTES,
      value: fmtHex(mac, opts.maxHex),
      note: '',
   });

   const alg = parseAlgAndIv(reader, blockIndex, fields, errors, opts);
   if (alg === null) {
      const offset = reader.pos;
      const remaining = reader.remaining;
      const blob = reader.readBytes(remaining);
      fields.push({
         name: 'unparsed remainder',
         offset,
         length: remaining,
         value: fmtHex(blob, opts.maxHex),
         note: 'ERROR: cannot parse without valid alg',
      });
      return {
         index: blockIndex,
         start: blockStart,
         end: reader.pos,
         payloadSize: totalSize - blockStart,
         terminal: null,
         fields,
      };
   }

   if (reader.remaining < SLT_BYTES) {
      recordFatal(errors, where, 'truncated before salt');
   } else {
      const sltOffset = reader.pos;
      const slt = reader.readBytes(SLT_BYTES);
      fields.push({
         name: 'salt',
         offset: sltOffset,
         length: SLT_BYTES,
         value: fmtHex(slt, opts.maxHex),
         note: '',
      });
   }

   if (reader.remaining >= IC_BYTES) {
      const icOffset = reader.pos;
      const ic = reader.readU32LE();
      let icNote = '';
      if (ic < ICOUNT_MIN || ic > ICOUNT_MAX) {
         icNote = recordError(errors, where, `iterations ${ic} out of range [${ICOUNT_MIN}, ${ICOUNT_MAX}]`);
      }
      fields.push({
         name: 'iterations',
         offset: icOffset,
         length: IC_BYTES,
         value: String(ic),
         note: icNote,
      });
   } else {
      recordFatal(errors, where, 'truncated before iterations');
   }

   if (reader.remaining >= VER_BYTES) {
      const verOffset = reader.pos;
      const ver = reader.readU16LE();
      let verNote = '';
      if (ver !== 1) {
         verNote = recordError(errors, where, `V1 inner version field expected 1, got ${ver}`);
      }
      fields.push({
         name: 'version',
         offset: verOffset,
         length: VER_BYTES,
         value: String(ver),
         note: verNote,
      });
   } else {
      recordFatal(errors, where, 'truncated before inner version');
   }

   let hintLen = 0;
   if (reader.remaining >= HINT_LEN_BYTES) {
      const hlenOffset = reader.pos;
      hintLen = reader.readU8();
      fields.push({
         name: 'hint len',
         offset: hlenOffset,
         length: HINT_LEN_BYTES,
         value: String(hintLen),
         note: '',
      });
   } else {
      recordFatal(errors, where, 'truncated before hint len');
   }

   if (hintLen > 0) {
      const hintAvailable = Math.min(hintLen, reader.remaining);
      const hintOffset = reader.pos;
      const hint = reader.readBytes(hintAvailable);
      let hintNote = '';
      if (hintAvailable < hintLen) {
         hintNote = recordFatal(errors, where, `hint truncated: expected ${hintLen} bytes, only ${hintAvailable} available`);
      }
      fields.push({
         name: 'hint encrypted',
         offset: hintOffset,
         length: hintAvailable,
         value: fmtHex(hint, opts.maxHex),
         note: hintNote,
      });
   }

   const edataLen = totalSize - reader.pos;
   if (edataLen > 0) {
      const edataOffset = reader.pos;
      const edata = reader.readBytes(edataLen);
      fields.push({
         name: 'encrypted data',
         offset: edataOffset,
         length: edataLen,
         value: fmtHex(edata, opts.maxHex),
         note: '',
      });
   } else {
      recordFatal(errors, where, 'no bytes left for encrypted data');
   }

   return {
      index: blockIndex,
      start: blockStart,
      end: reader.pos,
      payloadSize: totalSize - blockStart,
      terminal: null,
      fields,
   };
}

function parseFile(path: string, opts: Options): ParsedFile {
   const buffer = readFileSync(path);
   const errors: ErrorRecord[] = [];

   if (buffer.length < MAC_BYTES + VER_BYTES) {
      recordFatal(errors, 'file', `file too small (${buffer.length} bytes) to contain a header`);
      return {
         path,
         size: buffer.length,
         buffer,
         version: FALLBACK_VERSION,
         versionFallback: null,
         blocks: [],
         errors,
      };
   }

   const detected = detectVersion(buffer);
   const version = detected.version;
   if (detected.fallback) {
      recordError(errors, 'file', `unrecognized version ${detected.fallback.observed}; assuming v${FALLBACK_VERSION}`);
   }

   const reader = new Reader(buffer);

   if (version === 1) {
      const block = parseV1Document(reader, buffer.length, opts, errors);
      return {
         path,
         size: buffer.length,
         buffer,
         version,
         versionFallback: detected.fallback,
         blocks: [block],
         errors,
      };
   }

   const blocks: ParsedBlock[] = [];
   while (reader.remaining > 0) {
      if (blocks.length >= opts.maxBlocks) {
         recordFatal(
            errors,
            'file',
            `parsed ${opts.maxBlocks} blocks but ${reader.remaining} bytes remain (raise --max-blocks to continue)`
         );
         break;
      }
      const before = reader.pos;
      const block = parseBlock(reader, version, blocks.length, blocks.length === 0, opts, errors);
      blocks.push(block);
      // Guard against infinite loops if the parser somehow fails to advance.
      if (reader.pos === before) {
         recordFatal(errors, `block ${block.index}`, 'parser made no progress; aborting');
         break;
      }
   }

   return {
      path,
      size: buffer.length,
      buffer,
      version,
      versionFallback: detected.fallback,
      blocks,
      errors,
   };
}

// ---- Table rendering ----

const ANSI = {
   reset: '\x1b[0m',
   bold: '\x1b[1m',
   dim: '\x1b[2m',
   red: '\x1b[31m',
   green: '\x1b[32m',
   yellow: '\x1b[33m',
   cyan: '\x1b[36m',
   boldCyan: '\x1b[1;36m',
};

// Set in main() based on --color, NO_COLOR, FORCE_COLOR, and stdout.isTTY.
let useColor = false;

function paint(text: string, code: string): string {
   if (!useColor || code === '') {
      return text;
   }
   return `${code}${text}${ANSI.reset}`;
}

// A cell can be a plain string or a colored cell. Width is computed from
// `text`; `color` is applied after padding so it doesn't perturb alignment.
type Cell = string | { text: string; color: string };
type Row = readonly Cell[];

function cellText(c: Cell): string {
   return typeof c === 'string' ? c : c.text;
}

function cellColor(c: Cell): string {
   return typeof c === 'string' ? '' : c.color;
}

function longestLine(s: string): number {
   let max = 0;
   for (const line of s.split('\n')) {
      if (line.length > max) {
         max = line.length;
      }
   }
   return max;
}

function renderTable(headers: readonly string[], rows: readonly Row[]): string {
   const widths = headers.map((h, i) => {
      let w = h.length;
      for (const r of rows) {
         w = Math.max(w, longestLine(cellText(r[i] ?? '')));
      }
      return w;
   });

   const border = (l: string, m: string, r: string) => {
      const raw = l + widths.map((w) => '─'.repeat(w + 2)).join(m) + r;
      return paint(raw, ANSI.dim);
   };

   const v = paint('│', ANSI.dim);
   const renderRow = (cells: Row): string => {
      const wrapped = cells.map((c) => ({
         lines: cellText(c).split('\n'),
         color: cellColor(c),
      }));
      const height = wrapped.reduce((h, w) => Math.max(h, w.lines.length), 1);
      const out: string[] = [];
      for (let i = 0; i < height; i++) {
         const parts = wrapped.map((w, j) => paint((w.lines[i] ?? '').padEnd(widths[j]), w.color));
         out.push(`${v} ${parts.join(` ${v} `)} ${v}`);
      }
      return out.join('\n');
   };

   const lines: string[] = [border('┌', '┬', '┐'), renderRow(headers), border('├', '┼', '┤')];
   for (const r of rows) {
      lines.push(renderRow(r));
   }
   lines.push(border('└', '┴', '┘'));
   return lines.join('\n');
}

function fmtBytes(n: number): string {
   if (n < 1024) {
      return `${n} B`;
   }
   if (n < 1024 * 1024) {
      return `${(n / 1024).toFixed(1)} KiB`;
   }
   return `${(n / (1024 * 1024)).toFixed(2)} MiB`;
}

function noteCell(note: string): Cell {
   if (note.length === 0) {
      return note;
   }
   if (note.includes('ERROR:')) {
      return { text: note, color: ANSI.red };
   }
   return note;
}

function renderSummary(parsed: ParsedFile): string {
   const versionCell: Cell = parsed.versionFallback
      ? {
           text: `${parsed.version}  (fallback; observed ${parsed.versionFallback.observed})`,
           color: ANSI.yellow,
        }
      : String(parsed.version);

   const fatalCount = parsed.errors.filter((e) => e.fatal).length;
   const validCell: Cell =
      parsed.errors.length === 0
         ? { text: 'yes', color: ANSI.green }
         : {
              text:
                 `no (${parsed.errors.length} error${parsed.errors.length === 1 ? '' : 's'}` +
                 (fatalCount > 0 ? `, ${fatalCount} fatal` : '') +
                 ')',
              color: ANSI.red,
           };

   return renderTable(
      ['Property', 'Value'],
      [
         ['File', parsed.path],
         ['Size', `${parsed.size} bytes (${fmtBytes(parsed.size)})`],
         ['Version', versionCell],
         ['Blocks', String(parsed.blocks.length)],
         ['Valid parse', validCell],
      ]
   );
}

function renderBlocks(parsed: ParsedFile): string[] {
   return parsed.blocks.map((b) => {
      const headers = ['Field', 'Offset', 'Length', 'Value', 'Note'] as const;
      const rows: Row[] = b.fields.map((f) => [
         f.name,
         String(f.offset),
         String(f.length),
         f.value,
         noteCell(f.note),
      ]);
      const heading = paint(
         `── Block ${b.index} ── offset ${b.start}, ${b.end - b.start} bytes (payload ${b.payloadSize})`,
         ANSI.boldCyan
      );
      return `${heading}\n${renderTable(headers, rows)}`;
   });
}

function renderErrors(parsed: ParsedFile): string | null {
   if (parsed.errors.length === 0) {
      return null;
   }
   const errorRows: Row[] = parsed.errors.map((e) => {
      const color = e.fatal ? ANSI.red : ANSI.yellow;
      const tag = e.fatal ? 'fatal' : 'warn';
      return [
         { text: e.where, color },
         { text: tag, color },
         { text: e.message, color },
      ];
   });
   const heading = paint('── Errors ──', ANSI.boldCyan);
   return `${heading}\n${renderTable(['Where', 'Kind', 'Message'], errorRows)}`;
}

function render(parsed: ParsedFile): string {
   const sections: string[] = [renderSummary(parsed), ...renderBlocks(parsed)];
   const errors = renderErrors(parsed);
   if (errors) {
      sections.push(errors);
   }
   return sections.join('\n\n');
}

// ---- Block-morph DSL ----
//
// Three operators, all shell-safe (no quoting needed):
//   bA^bB  — swap original blocks A and B
//   bN-    — delete original block N (slot stays as a placeholder so later
//            swaps can still target the original index)
//   bNxK   — repeat: original block N's emit-count multiplies by K, so
//            `b1x3 b1x2` produces 6 copies of block 1
//
// Sequence separators: comma, whitespace, or underscore. The output
// filename gets the DSL with all separators normalized to '_'.
//
// References stay bound to original indices throughout the sequence —
// after `b2^b7`, `b2-` deletes the slot that originally held block 2
// (now sitting where block 7 used to be).

type Op =
   | { kind: 'swap'; a: number; b: number; raw: string }
   | { kind: 'delete'; n: number; raw: string }
   | { kind: 'repeat'; n: number; count: number; raw: string };

type Slot = {
   origIdx: number;
   count: number; // 0 = no emit (deleted via `-` or count*0)
   deleted: boolean;
   touched: boolean; // any op (other than initial swap) referenced this block
   moved: boolean; // currently sits at a different slot position than origIdx
};

function parseOpsString(input: string): Op[] {
   const tokens = input.split(/[,\s_]+/).filter((s) => s.length > 0);
   if (tokens.length === 0) {
      throw new Error('--morph is empty');
   }
   return tokens.map(parseSingleOp);
}

function parseSingleOp(raw: string): Op {
   let m = raw.match(/^b(\d+)\^b(\d+)$/);
   if (m) {
      return { kind: 'swap', a: Number(m[1]), b: Number(m[2]), raw };
   }
   m = raw.match(/^b(\d+)-$/);
   if (m) {
      return { kind: 'delete', n: Number(m[1]), raw };
   }
   // Accept either `x` or `*` as the repeat operator. The output filename
   // normalizes both to `x`.
   m = raw.match(/^b(\d+)[x*](\d+)$/);
   if (m) {
      return { kind: 'repeat', n: Number(m[1]), count: Number(m[2]), raw };
   }
   throw new Error(`Invalid op "${raw}". Expected bA^bB (swap), bN- (delete), or bNxK (repeat)`);
}

function findSlot(slots: readonly Slot[], origIdx: number): number {
   const i = slots.findIndex((s) => s.origIdx === origIdx);
   if (i < 0) {
      throw new Error(`block ${origIdx} not found (file has ${slots.length} blocks)`);
   }
   return i;
}

function applyOps(blockCount: number, ops: readonly Op[]): Slot[] {
   const slots: Slot[] = [];
   for (let i = 0; i < blockCount; i++) {
      slots.push({ origIdx: i, count: 1, deleted: false, touched: false, moved: false });
   }
   for (const op of ops) {
      if (op.kind === 'swap') {
         const ai = findSlot(slots, op.a);
         const bi = findSlot(slots, op.b);
         const tmp = slots[ai];
         slots[ai] = slots[bi];
         slots[bi] = tmp;
         slots[ai].touched = true;
         slots[bi].touched = true;
      } else if (op.kind === 'delete') {
         const i = findSlot(slots, op.n);
         slots[i].deleted = true;
         slots[i].count = 0;
         slots[i].touched = true;
      } else {
         const i = findSlot(slots, op.n);
         if (slots[i].deleted) {
            throw new Error(
               `cannot repeat block ${op.n}: it was already deleted by an earlier op (op "${op.raw}")`
            );
         }
         slots[i].count *= op.count;
         slots[i].touched = true;
      }
   }
   for (let i = 0; i < slots.length; i++) {
      slots[i].moved = slots[i].origIdx !== i;
   }
   return slots;
}

function buildOutputBytes(buffer: Buffer, blocks: readonly ParsedBlock[], slots: readonly Slot[]): Buffer {
   const parts: Buffer[] = [];
   for (const slot of slots) {
      if (slot.deleted || slot.count <= 0) {
         continue;
      }
      const blk = blocks[slot.origIdx];
      const bytes = buffer.subarray(blk.start, blk.end);
      for (let i = 0; i < slot.count; i++) {
         parts.push(bytes);
      }
   }
   return Buffer.concat(parts);
}

function deriveOutputPath(inPath: string, dsl: string): string {
   const ext = extname(inPath);
   const base = basename(inPath, ext);
   const dir = dirname(inPath);
   const suffix = dsl.replace(/\*/g, 'x').replace(/[,\s_]+/g, '_');
   return join(dir, `${base}_${suffix}${ext}`);
}

function renderPlan(slots: readonly Slot[], blocks: readonly ParsedBlock[]): string {
   const heading = paint('── Plan ──', ANSI.boldCyan);

   let outIndex = 0;
   let totalBytes = 0;
   const rows: Row[] = slots.map((slot, slotPos) => {
      const blk = blocks[slot.origIdx];
      const blockBytes = blk.end - blk.start;
      const slotEmitBytes = slot.deleted ? 0 : slot.count * blockBytes;
      totalBytes += slotEmitBytes;

      const notes: string[] = [];
      if (slot.moved) {
         notes.push(`moved from pos ${slot.origIdx}`);
      }
      if (slot.deleted) {
         notes.push('deleted');
      } else if (slot.count !== 1) {
         notes.push(`×${slot.count}`);
      }
      const emitsLabel = slot.deleted || slot.count <= 0
         ? '—'
         : slot.count === 1
           ? String(outIndex)
           : `${outIndex}..${outIndex + slot.count - 1}`;
      if (!slot.deleted && slot.count > 0) {
         outIndex += slot.count;
      }

      const noteText = notes.join(', ');
      const noteCellValue: Cell =
         slot.deleted
            ? { text: noteText || 'deleted', color: ANSI.red }
            : slot.touched
              ? { text: noteText, color: ANSI.yellow }
              : noteText;

      return [
         String(slotPos),
         `b${slot.origIdx}`,
         emitsLabel,
         String(slot.count),
         `${blockBytes}`,
         `${slotEmitBytes}`,
         noteCellValue,
      ];
   });

   const table = renderTable(
      ['Slot', 'From', 'Output #', 'Count', 'Bytes', 'Emit bytes', 'Note'],
      rows
   );
   const footer = `Output: ${outIndex} block${outIndex === 1 ? '' : 's'}, ${totalBytes} bytes`;
   return `${heading}\n${table}\n${footer}`;
}

type ColorMode = 'auto' | 'always' | 'never';

function resolveColor(mode: ColorMode): boolean {
   if (mode === 'never') {
      return false;
   }
   if (process.env.NO_COLOR && process.env.NO_COLOR.length > 0) {
      return false;
   }
   if (mode === 'always') {
      return true;
   }
   if (process.env.FORCE_COLOR && process.env.FORCE_COLOR.length > 0) {
      return true;
   }
   return Boolean(process.stdout.isTTY);
}

// ---- CLI ----

async function main(): Promise<number> {
   // When piped into a pager (e.g. `| less`) and the user quits before all
   // output drains, Node prints an unhandled EPIPE stack trace. Swallow it.
   process.stdout.on('error', (err: NodeJS.ErrnoException) => {
      if (err.code === 'EPIPE') {
         process.exit(0);
      }
      throw err;
   });

   const argv = await yargs(hideBin(process.argv))
      .scriptName('parse-qcrypt')
      .usage(
         '$0 <files..>',
         'Display the structure of one or more Quick Crypt encrypted files',
         (y) =>
            y
               .positional('files', {
                  describe: 'Path(s) to Quick Crypt encrypted file(s)',
                  type: 'string',
               })
               .demandOption('files')
      )
      .option('max-hex', {
         type: 'number',
         default: 32,
         describe: 'Maximum bytes of any binary field to print before truncating with "…"',
      })
      .option('max-blocks', {
         type: 'number',
         default: 4096,
         describe: 'Safety cap on the number of blocks to parse',
      })
      .option('color', {
         choices: ['auto', 'always', 'never'] as const,
         default: 'auto',
         describe:
            'Colorize output. "auto" uses color when stdout is a TTY. ' +
            'NO_COLOR disables; FORCE_COLOR enables (e.g., when piping to `less -R`).',
      })
      .option('morph', {
         type: 'string',
         describe:
            'Apply a sequence of block operations and write a modified file. DSL: ' +
            'bA^bB swap; bN- delete; bNxK repeat (count multiplies). ' +
            'Separate ops with comma, space, or underscore. Example: --morph "b2^b7,b3-,b1x4". ' +
            'Output filename is the input base + _<sanitized-DSL> + extension.',
      })
      .check((args) => {
         if (!Number.isInteger(args['max-hex']) || args['max-hex'] <= 0) {
            throw new Error('--max-hex must be a positive integer');
         }
         if (!Number.isInteger(args['max-blocks']) || args['max-blocks'] <= 0) {
            throw new Error('--max-blocks must be a positive integer');
         }
         return true;
      })
      .strict()
      .help()
      .alias('help', 'h')
      .version(false)
      .parseAsync();

   const opts: Options = {
      maxHex: argv['max-hex'] as number,
      maxBlocks: argv['max-blocks'] as number,
   };

   useColor = resolveColor(argv.color as ColorMode);

   const morphString = (argv.morph as string | undefined) ?? null;
   const ops = morphString !== null ? parseOpsString(morphString) : null;

   // Yargs returns positionals as either string or string[]; normalize.
   const rawFiles = argv.files as string | string[] | undefined;
   const files = (Array.isArray(rawFiles) ? rawFiles : rawFiles ? [rawFiles] : []).map(String);

   let exitCode = 0;
   for (let i = 0; i < files.length; i++) {
      const file = files[i];
      if (i > 0) {
         console.log();
      }
      try {
         const stat = statSync(file);
         if (!stat.isFile()) {
            throw new Error('Not a regular file');
         }
         const parsed = parseFile(file, opts);

         if (ops !== null && morphString !== null) {
            // Morph mode: summary + plan + write file. Per spec, do NOT
            // print per-block tables or the full errors table.
            console.log(renderSummary(parsed));

            const fatal = parsed.errors.filter((e) => e.fatal);
            if (fatal.length > 0) {
               const lines = fatal.map((e) => `  ${e.where}: ${e.message}`);
               console.error(
                  `\n${paint('Aborting --morph:', ANSI.red)} input file has ${fatal.length} fatal parse error${
                     fatal.length === 1 ? '' : 's'
                  }; cannot reliably modify.\n${lines.join('\n')}`
               );
               exitCode = 1;
               continue;
            }

            const slots = applyOps(parsed.blocks.length, ops);

            // No-op plan = every slot still in its original position with
            // count 1 and not deleted. Skip the write in that case.
            const isNoop = slots.every(
               (s, i) => s.origIdx === i && s.count === 1 && !s.deleted
            );
            if (isNoop) {
               console.log(
                  `\n${paint('No-op:', ANSI.yellow)} operations cancel out; input file unchanged. Not writing output.`
               );
               continue;
            }

            console.log();
            console.log(renderPlan(slots, parsed.blocks));

            const outBytes = buildOutputBytes(parsed.buffer, parsed.blocks, slots);
            const outPath = deriveOutputPath(file, morphString);
            writeFileSync(outPath, outBytes);
            console.log(`\n${paint('Wrote', ANSI.green)} ${outPath} (${outBytes.length} bytes)`);
         } else {
            console.log(render(parsed));
            if (parsed.errors.length > 0) {
               exitCode = 1;
            }
         }
      } catch (err) {
         const msg = err instanceof Error ? err.message : String(err);
         console.error(`${basename(file)}: ${msg}`);
         exitCode = 1;
      }
   }
   return exitCode;
}

main().then(
   (code) => process.exit(code),
   (err) => {
      console.error(err instanceof Error ? err.message : String(err));
      process.exit(1);
   }
);
