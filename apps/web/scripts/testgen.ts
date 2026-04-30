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

// Generates Quick Crypt test fixtures by applying named morph sequences
// to an input file and emitting the resulting bytes (Uint8Array literal
// or base64url) on stdout, ready to paste into a vitest test file.
//
// All morphing happens in memory via parser.ts; nothing is written to
// disk. The morph sequence syntax is the same one accepted by morpher.ts
// (see parser.ts for the DSL reference).
//
// Run with Node 24+ (native TypeScript stripping):
//   node apps/web/scripts/testgen.ts <file> --set 1 --set 2
//   cat secret.qq | node apps/web/scripts/testgen.ts --set 1

import { readFileSync, statSync } from 'node:fs';
import { basename } from 'node:path';
import yargs from 'yargs';
import { hideBin } from 'yargs/helpers';
import {
   decodeBase64UrlInput,
   decodesInput,
   encodesOutput,
   morphInMemory,
   parseBuffer,
   readAllStdin,
} from './parser.ts';
import type { B64UrlMode, Options, ParsedFile } from './parser.ts';

// ---- Test set catalogue ----
//
// EDIT THIS to add, change, or remove test sets. The numeric `id` is the
// stable handle that downstream tests reference — never reuse or reassign
// an id, even if a set is removed (treat the id as permanently retired).

type Morph = {
   readonly name: string;
   readonly morph: string;
};

type TestSet = {
   readonly id: number;
   readonly description: string;
   readonly morphs: readonly Morph[];
};

const TEST_SETS: readonly TestSet[] = [
   {
      id: 1,
      description: 'Unchanged',
      morphs: [
         { name: 'noop', morph: '' },
      ],
   },
   {
      id: 2,
      description: 'Encryption and decryption (ciphers.spec.ts)',
      morphs: [
         { name: 'correct cipherdata info and decryption',     morph: '' },
         { name: 'missing terminal block indicator',           morph: 'b-1-' },
      ],
   },
   {
      id: 3,
      description: 'Block ordering and counts',
      morphs: [
         { name: 'swap b0 and b1',  morph: 'b0^b1' },
         { name: 'duplicate b1',    morph: 'b1x2' },
         { name: 'delete b0',       morph: 'b0-' },
      ],
   },
];

function findTestSet(id: number): TestSet | null {
   return TEST_SETS.find((s) => s.id === id) ?? null;
}

// ---- Output formatting ----

type OutputFormat = 'uint8' | 'b64url';

const BYTES_PER_LINE = 15;

// Worst-case visual width of one wrapped uint8 line: 3-space indent + N
// items (up to 3 chars each for "255") + (N-1) ", " separators (2 chars
// each) + trailing ",". 15 bytes/line keeps the worst case at 77 chars,
// inside an ~80 column budget. b64url wraps to the same width so both
// formats stack cleanly side by side in test files.
const UINT8_LINE_WIDTH = 3 + BYTES_PER_LINE * 3 + (BYTES_PER_LINE - 1) * 2 + 1;

function formatUint8Array(buf: Buffer, wrap: boolean): string {
   if (buf.length === 0) {
      return 'new Uint8Array(0)';
   }
   const decimals = Array.from(buf, (b) => String(b));
   if (!wrap) {
      return `new Uint8Array([${decimals.join(', ')}])`;
   }
   const indent = '   ';
   const lines: string[] = [];
   for (let i = 0; i < decimals.length; i += BYTES_PER_LINE) {
      const slice = decimals.slice(i, i + BYTES_PER_LINE).join(', ');
      const trailingComma = i + BYTES_PER_LINE < decimals.length ? ',' : '';
      lines.push(`${indent}${slice}${trailingComma}`);
   }
   return `new Uint8Array([\n${lines.join('\n')}\n])`;
}

function formatBase64Url(buf: Buffer, wrap: boolean): string {
   const s = buf.toString('base64url');
   if (!wrap) {
      return JSON.stringify(s);
   }
   // Multi-line backtick template literal. Embedded newlines are part of
   // the runtime string, but Node's Buffer.from(s, 'base64url') ignores
   // whitespace, so the value still decodes cleanly. base64url's alphabet
   // (A-Za-z0-9-_) contains nothing that needs escaping inside `...`.
   if (s.length <= UINT8_LINE_WIDTH) {
      return `\`${s}\``;
   }
   const lines: string[] = [];
   for (let i = 0; i < s.length; i += UINT8_LINE_WIDTH) {
      lines.push(s.substring(i, i + UINT8_LINE_WIDTH));
   }
   return `\`${lines.join('\n')}\``;
}

function formatBytes(buf: Buffer, format: OutputFormat, wrap: boolean): string {
   if (format === 'b64url') {
      return formatBase64Url(buf, wrap);
   }
   return formatUint8Array(buf, wrap);
}

// ---- Summary header (table style, matches morpher.ts look) ----

function fmtBytes(n: number): string {
   if (n < 1024) {
      return `${n} B`;
   }
   if (n < 1024 * 1024) {
      return `${(n / 1024).toFixed(1)} KiB`;
   }
   return `${(n / (1024 * 1024)).toFixed(2)} MiB`;
}

// Heavy banner that opens each input file's section. The full-block char
// `█` is intentionally distinct from the `═` used for per-test-set banners
// so a file boundary stands out when multiple inputs are processed.
function renderFileHeader(parsed: ParsedFile, position: number, total: number): string {
   const bar = '█'.repeat(75);
   const counter = total > 1 ? ` (${position}/${total})` : '';
   return `${bar}\n█  ${parsed.path}${counter}\n${bar}`;
}

function renderSummary(parsed: ParsedFile, requested: readonly TestSet[]): string {
   const rows: [string, string][] = [
      ['File',        parsed.path],
      ['Size',        `${parsed.size} bytes (${fmtBytes(parsed.size)})`],
      ['Version',     String(parsed.version)],
      ['Blocks',      String(parsed.blocks.length)],
      ['Test sets',   requested.map((s) => `${s.id} (${s.description})`).join('\n            ')],
   ];
   const labelW = Math.max(...rows.map((r) => r[0].length));
   const valueW = Math.max(...rows.flatMap((r) => r[1].split('\n').map((s) => s.length)));
   const border = (l: string, m: string, r: string): string =>
      l + '─'.repeat(labelW + 2) + m + '─'.repeat(valueW + 2) + r;
   const lines: string[] = [border('┌', '┬', '┐')];
   for (const [k, v] of rows) {
      const valueLines = v.split('\n');
      for (let i = 0; i < valueLines.length; i++) {
         const label = i === 0 ? k.padEnd(labelW) : ''.padEnd(labelW);
         lines.push(`│ ${label} │ ${valueLines[i].padEnd(valueW)} │`);
      }
   }
   lines.push(border('└', '┴', '┘'));
   return lines.join('\n');
}

function renderTestSet(set: TestSet, parsed: ParsedFile, format: OutputFormat, wrap: boolean): string {
   const lines: string[] = [];
   const bar = '═'.repeat(70);
   lines.push('');
   lines.push(bar);
   lines.push(`Test Set ${set.id} — ${set.description}`);
   lines.push(bar);

   for (const morph of set.morphs) {
      lines.push('');
      lines.push(`// "${morph.name}" | morph: ${morph.morph}`);
      try {
         const result = morphInMemory(parsed, morph.morph);
         lines.push(formatBytes(result.bytes, format, wrap));
      } catch (err) {
         const msg = err instanceof Error ? err.message : String(err);
         lines.push(`// ERROR: ${msg}`);
      }
   }
   return lines.join('\n');
}

// ---- CLI ----

function buildEpilogue(): string {
   const lines = ['Available test sets (use --set, repeatable):'];
   for (const set of TEST_SETS) {
      lines.push(`  ${String(set.id).padStart(3)}  ${set.description}`);
      for (const morph of set.morphs) {
         lines.push(`         · ${morph.name}  (${morph.morph})`);
      }
   }
   lines.push('');
   lines.push(
      'Quick Crypt files are little-endian: V7 = "0700" on disk, plen 0x94 ' +
      '= "940000". Write bytes in LE order when adding morphs that touch ' +
      'multi-byte integer fields (ver, plen, alg, ic).'
   );
   lines.push('');
   lines.push('Edit TEST_SETS in testgen.ts to add or modify cases.');
   return lines.join('\n');
}

async function main(): Promise<number> {
   process.stdout.on('error', (err: NodeJS.ErrnoException) => {
      if (err.code === 'EPIPE') {
         process.exit(0);
      }
      throw err;
   });

   const argv = await yargs(hideBin(process.argv))
      .scriptName('testgen')
      .usage(
         '$0 [files..]',
         'Apply morph sequences to one or more Quick Crypt files and emit the bytes as test fixtures. ' +
            'When no files are given, a single input is read from stdin.',
         (y) =>
            y.positional('files', {
               describe:
                  'Path(s) to source Quick Crypt encrypted file(s); omit to read from stdin',
               type: 'string',
            })
      )
      .option('set', {
         type: 'array',
         describe: 'Test set ID(s) to run (repeat for multiple, e.g. --set 1 --set 2)',
         demandOption: true,
      })
      .option('b64url', {
         choices: ['in', 'out', 'both'] as const,
         describe:
            'Treat input ("in") as base64url-encoded text instead of raw binary, and/or ' +
            'emit fixture bytes as base64url ("out"). "both" applies to input and output. ' +
            'When --b64url is unset or only "in", fixture bytes are emitted as a Uint8Array literal.',
      })
      .option('wrap', {
         type: 'boolean',
         default: false,
         describe:
            'Wrap fixture bytes onto multiple lines. Uint8 wraps at 12 bytes/line; ' +
            'b64url uses a backtick template literal with line-continuation `\\` so the ' +
            'runtime string stays clean.',
      })
      .option('max-blocks', {
         type: 'number',
         default: 4096,
         describe: 'Safety cap on the number of blocks to parse',
      })
      .check((args) => {
         const ids = (args.set as readonly (string | number)[]).map((s) => Number(s));
         for (const id of ids) {
            if (!Number.isInteger(id) || id <= 0) {
               throw new Error(`--set values must be positive integers (got ${id})`);
            }
            if (findTestSet(id) === null) {
               const known = TEST_SETS.map((s) => s.id).join(', ');
               throw new Error(`unknown test set id ${id}. Known ids: ${known}`);
            }
         }
         if (!Number.isInteger(args['max-blocks']) || args['max-blocks'] <= 0) {
            throw new Error('--max-blocks must be a positive integer');
         }
         return true;
      })
      .epilogue(buildEpilogue())
      .strict()
      .help()
      .alias('help', 'h')
      .version(false)
      .wrap(Math.min(110, yargs().terminalWidth()))
      .parseAsync();

   const rawFiles = argv.files as string | string[] | undefined;
   const files = (Array.isArray(rawFiles) ? rawFiles : rawFiles ? [rawFiles] : []).map(String);
   const requestedIds = (argv.set as readonly (string | number)[]).map((s) => Number(s));
   const requested = requestedIds.map((id) => findTestSet(id)!);
   const wrap = argv.wrap as boolean;
   const b64url = (argv['b64url'] as B64UrlMode | undefined) ?? null;
   const format: OutputFormat = encodesOutput(b64url) ? 'b64url' : 'uint8';

   const opts: Options = {
      maxHex: 32, // unused by testgen but required by parser.Options
      maxBlocks: argv['max-blocks'] as number,
   };

   const useStdin = files.length === 0;
   const sources: string[] = useStdin ? ['<stdin>'] : files;

   let exitCode = 0;
   for (let i = 0; i < sources.length; i++) {
      const source = sources[i];
      if (i > 0) {
         console.log('\n');
      }
      try {
         let inputBytes: Buffer;
         if (useStdin) {
            inputBytes = readAllStdin();
         } else {
            const stat = statSync(source);
            if (!stat.isFile()) {
               throw new Error('not a regular file');
            }
            inputBytes = readFileSync(source);
         }
         if (decodesInput(b64url)) {
            inputBytes = decodeBase64UrlInput(inputBytes);
         }
         const parsed = parseBuffer(inputBytes, source, opts);
         const fatal = parsed.errors.filter((e) => e.fatal);
         if (fatal.length > 0) {
            console.log(renderFileHeader(parsed, i + 1, sources.length));
            console.error(
               `${useStdin ? source : basename(source)}: input has ${fatal.length} fatal parse error${fatal.length === 1 ? '' : 's'}; cannot generate fixtures.`
            );
            for (const e of fatal) {
               console.error(`  ${e.where}: ${e.message}`);
            }
            exitCode = 1;
            continue;
         }

         console.log(renderFileHeader(parsed, i + 1, sources.length));
         console.log(renderSummary(parsed, requested));
         for (const set of requested) {
            console.log(renderTestSet(set, parsed, format, wrap));
         }
         console.log();
      } catch (err) {
         const msg = err instanceof Error ? err.message : String(err);
         console.error(`${useStdin ? source : basename(source)}: ${msg}`);
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
