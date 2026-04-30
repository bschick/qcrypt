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

// CLI for inspecting and morphing Quick Crypt encrypted files. Pure parser
// logic lives in parser.ts; this file only does rendering, CLI option
// handling, and disk I/O for the morph output.
//
// Run with Node 24+ (native TypeScript stripping):
//   node apps/web/scripts/morpher.ts <file...>
//   node apps/web/scripts/morpher.ts <file> --morph "b2^b7,b1x4"
//   cat secret.qq | node apps/web/scripts/morpher.ts --morph "b0-"

import { readFileSync, statSync, writeFileSync } from 'node:fs';
import { basename, dirname, extname, join } from 'node:path';
import yargs from 'yargs';
import { hideBin } from 'yargs/helpers';
import {
   applyOps,
   buildOutputBytes,
   decodeBase64UrlInput,
   decodesInput,
   DSL_FIELD_DOCS,
   encodesOutput,
   findFieldByDslId,
   parseBuffer,
   parseOpsString,
   readAllStdin,
   resolveOpIndexes,
} from './parser.ts';
import type {
   B64UrlMode,
   ErrorRecord,
   Field,
   Op,
   Options,
   ParsedBlock,
   ParsedFile,
   Slot,
} from './parser.ts';

// ---- Color / paint ----

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

let useColor = false;

function paint(text: string, code: string): string {
   if (!useColor || code === '') {
      return text;
   }
   return `${code}${text}${ANSI.reset}`;
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

// ---- Table rendering ----

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

// ---- Per-section renderers ----

export function renderSummary(parsed: ParsedFile): string {
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

function renderFile(parsed: ParsedFile): string {
   const sections: string[] = [renderSummary(parsed), ...renderBlocks(parsed)];
   const errors = renderErrors(parsed);
   if (errors) {
      sections.push(errors);
   }
   return sections.join('\n\n');
}

function renderMoves(slots: readonly Slot[], blocks: readonly ParsedBlock[]): string {
   const heading = paint('── Moves ──', ANSI.boldCyan);

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

function renderWrites(ops: readonly Op[], blocks: readonly ParsedBlock[]): string | null {
   const writes = ops.filter((o): o is Op & { kind: 'write' } => o.kind === 'write');
   if (writes.length === 0) {
      return null;
   }
   const heading = paint('── Writes ──', ANSI.boldCyan);
   const rows: Row[] = writes.map((op) => {
      const field = findFieldByDslId(blocks[op.n], op.field);
      const fileOffset = field !== null ? field.offset + op.offset : -1;
      const valueStr = op.values
         .map((v) => (v.kind === 'flip' ? '^' : v.byte.toString(16).padStart(2, '0')))
         .join('');
      return [
         `b${op.n}`,
         op.field,
         `[${op.offset}]`,
         String(op.values.length),
         valueStr,
         fileOffset >= 0 ? `@ file offset ${fileOffset}` : '(field missing)',
      ];
   });
   return `${heading}\n${renderTable(['Block', 'Field', 'Offset', 'Bytes', 'Value', 'Note'], rows)}`;
}

// Turn a morph DSL string into a filename-safe suffix.
function dslSuffix(dsl: string): string {
   return dsl.replace(/\*/g, 'x').replace(/[,\s_]+/g, '_');
}

function deriveOutputPath(inPath: string, dsl: string): string {
   const ext = extname(inPath);
   const base = basename(inPath, ext);
   const dir = dirname(inPath);
   return join(dir, `${base}_${dslSuffix(dsl)}${ext}`);
}

// When the input came from stdin there's no source path to derive from.
// Mirror the file-input naming (`<base>_<sanitized-DSL><ext>`) using a
// fixed base of "morphed" in the current directory; the extension
// reflects the output encoding so it's obvious whether the file is
// binary or base64url text.
function defaultStdinOutputPath(dsl: string, b64urlOut: boolean): string {
   const ext = b64urlOut ? '.b64' : '.qq';
   return `morphed_${dslSuffix(dsl)}${ext}`;
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

   const parser = yargs(hideBin(process.argv))
      .scriptName('morpher')
      .usage(
         '$0 [files..]',
         'Inspect Quick Crypt files; optionally apply a morph and write a modified copy. ' +
            'When no files are given, a single input is read from stdin.',
         (y) =>
            y.positional('files', {
               describe:
                  'Path(s) to Quick Crypt encrypted file(s); omit to read from stdin',
               type: 'string',
            })
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
      .option('b64url', {
         choices: ['in', 'out', 'both'] as const,
         describe:
            'Treat input ("in"), morph output ("out"), or both ("both") as base64url-encoded ' +
            'text instead of raw binary. Whitespace in base64url input is ignored.',
      })
      .option('morph', {
         type: 'string',
         describe:
            'Apply a sequence of block operations and write a modified file. DSL: ' +
            'bA^bB swap; bN- delete; bNxK repeat (count multiplies); ' +
            'bN!FIELD[OFFSET]=BYTES write into a field. ' +
            'Block indexes may be negative (Python-style: b-1 = last block). ' +
            'Separate ops with comma, space, or underscore. ' +
            'Example: --morph "b2^b-1,b-1-,b1x4,b0!plen[1]=1B03". ' +
            'When input came from a file, output is written next to it as ' +
            '<base>_<sanitized-DSL><ext>. When input came from stdin, output is ' +
            'written to ./morphed_<sanitized-DSL>.qq (or .b64 with --b64url out|both).',
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
      .epilogue(
         '--morph field IDs (for "bN!FIELD[OFFSET]=BYTES"):\n' +
            DSL_FIELD_DOCS.map((d) => `  ${d.id.padEnd(5)} ${d.description}`).join('\n') +
            '\n\nValue bytes are either two-char hex pairs (e.g. "1B03") or single ' +
            '"^" chars to flip one byte (XOR 0xFF). Example: "=A0^B1" writes 0xA0, ' +
            'flips one byte, writes 0xB1. Writes mutate the source bytes for the ' +
            'block, so all repeated copies see the modification. Writes cannot ' +
            'extend past the field’s on-disk length.\n\n' +
            'Quick Crypt files store all multi-byte integers little-endian, so ' +
            'e.g. version 7 is "0700" on disk and a payload length of 0x000094 is ' +
            '"940000" — write the bytes in LE order.'
      )
      .strict()
      .help()
      .alias('help', 'h')
      .version(false)
      .wrap(Math.min(110, yargs().terminalWidth()));
   const argv = await parser.parseAsync();

   const opts: Options = {
      maxHex: argv['max-hex'] as number,
      maxBlocks: argv['max-blocks'] as number,
   };

   useColor = resolveColor(argv.color as ColorMode);

   const b64url = (argv['b64url'] as B64UrlMode | undefined) ?? null;

   const morphString = (argv.morph as string | undefined) ?? null;
   const ops = morphString !== null ? parseOpsString(morphString) : null;
   // The parser accepts empty input (returns []) so testgen can use it for
   // baseline fixtures. For an interactive --morph invocation an empty
   // string is almost certainly a typo — fail fast instead of silently
   // running the no-op path.
   if (ops !== null && ops.length === 0) {
      console.error('--morph: morph string is empty');
      process.exit(1);
   }

   // Yargs returns positionals as either string or string[]; normalize.
   const rawFiles = argv.files as string | string[] | undefined;
   const files = (Array.isArray(rawFiles) ? rawFiles : rawFiles ? [rawFiles] : []).map(String);

   // No positional files = read a single input from stdin. The morph
   // result (when --morph is set) is still written to a file in the
   // current directory rather than stdout — see defaultStdinOutputPath.
   const useStdin = files.length === 0;
   // Bare invocation in a terminal — no files, nothing piped in. Show
   // help instead of silently blocking on a stdin read.
   if (useStdin && process.stdin.isTTY) {
      parser.showHelp('log');
      return 0;
   }
   const sources: string[] = useStdin ? ['<stdin>'] : files;

   let exitCode = 0;
   for (let i = 0; i < sources.length; i++) {
      const source = sources[i];
      if (i > 0) {
         console.log();
      }
      try {
         let inputBytes: Buffer;
         if (useStdin) {
            inputBytes = readAllStdin();
         } else {
            const stat = statSync(source);
            if (!stat.isFile()) {
               throw new Error('Not a regular file');
            }
            inputBytes = readFileSync(source);
         }
         if (decodesInput(b64url)) {
            inputBytes = decodeBase64UrlInput(inputBytes);
         }
         const parsed = parseBuffer(inputBytes, source, opts);

         if (ops !== null && morphString !== null) {
            // Morph mode: summary + moves + write file. Per spec, do NOT
            // print per-block tables or the full errors table.
            console.log(renderSummary(parsed));

            const fatal = parsed.errors.filter((e) => e.fatal);
            if (fatal.length > 0) {
               const lines = fatal.map((e) => `  ${e.where}: ${e.message}`);
               console.error(
                  `\n${paint('Aborting --morph:', ANSI.red)} input has ${fatal.length} fatal parse error${
                     fatal.length === 1 ? '' : 's'
                  }; cannot reliably modify.\n${lines.join('\n')}`
               );
               exitCode = 1;
               continue;
            }

            // Resolve negative block indexes (Python-style: -1 = last
            // block) to positives so every downstream consumer — applyOps,
            // renderMoves, renderWrites — sees only positive indexes.
            const resolvedOps = resolveOpIndexes(ops, parsed.blocks.length);

            // Work on a copy so write ops don't mutate the parsed buffer
            // (which we still need around for the no-op byte comparison).
            const workingBuffer = Buffer.from(parsed.buffer);
            const slots = applyOps(parsed.blocks, resolvedOps, workingBuffer);
            const outBytes = buildOutputBytes(workingBuffer, parsed.blocks, slots);

            // No-op = output bytes match the input bytes exactly. This
            // covers cancellation cases (b0^b1 b0^b1) AND identity writes
            // (writing a byte to its own current value).
            if (outBytes.equals(parsed.buffer)) {
               console.log(
                  `\n${paint('No-op:', ANSI.yellow)} operations net to zero changes; input unchanged. Not writing output.`
               );
               continue;
            }

            console.log();
            console.log(renderMoves(slots, parsed.blocks));

            const writesTable = renderWrites(resolvedOps, parsed.blocks);
            if (writesTable) {
               console.log();
               console.log(writesTable);
            }

            const outPath = useStdin
               ? defaultStdinOutputPath(morphString, encodesOutput(b64url))
               : deriveOutputPath(source, morphString);
            const fileBytes = encodesOutput(b64url)
               ? Buffer.from(`${outBytes.toString('base64url')}\n`, 'utf8')
               : outBytes;
            writeFileSync(outPath, fileBytes);
            console.log(
               `\n${paint('Wrote', ANSI.green)} ${outPath} (${fileBytes.length} byte${fileBytes.length === 1 ? '' : 's'}` +
                  (encodesOutput(b64url) ? ', base64url' : '') +
                  ')'
            );
         } else {
            console.log(renderFile(parsed));
            if (parsed.errors.length > 0) {
               exitCode = 1;
            }
         }
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
