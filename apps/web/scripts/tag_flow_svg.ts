// Prepare hand-crafted SVGs for the Flow help component.
//
// Two operations per file, both idempotent:
//   1. Add viewBox="0 0 W H" on the root <svg> if missing, computed from its
//      width and height attributes (pixel values or "Npx").
//   2. Find every element with fill="#f4d9NN" (NN != ff) and:
//        * replace the fill with the canonical "#f4d9ff"
//        * add class="qc-clickable" and data-target="<NN-lowercased>"
//      NN is looked up in FLOW_SUBSYSTEMS (imported from flow.config.ts) so
//      the tagger and runtime navigation share a single source of truth.
//
// Disabling pointer-events on <use> glyphs (needed so Lucidchart text doesn't
// swallow clicks on subprocess boxes) lives in SvgInlineDirective at runtime,
// not in this script - if it were applied to the asset file, svgo would hoist
// it back out on every run and we'd churn the file repeatedly.
//
// Usage:
//   pnpm exec tsx apps/web/scripts/tag_flow_svg.ts <svg-file> [<svg-file> ...]

import { readFileSync, writeFileSync, existsSync, statSync } from 'node:fs';
import { FLOW_SUBSYSTEMS } from '../src/app/help/flow/flow.config';

const SVG_TAG_RE = /<svg\b([^>]*)>/i;
const ATTR_RE = /([\w:.-]+)\s*=\s*"([^"]*)"/g;
const DIM_RE = /^\s*(-?\d+(?:\.\d+)?)\s*(?:px)?\s*$/i;
// Match a self-contained start tag (open or self-closing) with a #f4d9NN fill.
// Captures: 1=full attr string, 2=hex byte (case-insensitive).
const FILL_RE = /<([a-zA-Z][\w-]*)\b([^>]*\sfill\s*=\s*"#[fF]4[dD]9([0-9a-fA-F]{2})"[^>]*?)(\/?)>/g;
const CANONICAL_FILL = '#f4d9ff';

interface ParseResult {
   text: string;
   message: string;
   tagged?: number;
}

function parseAttrs(attrText: string): Record<string, string> {
   const out: Record<string, string> = {};
   for (const m of attrText.matchAll(ATTR_RE)) {
      out[m[1]] = m[2];
   }
   return out;
}

function addViewBox(text: string): ParseResult {
   const match = SVG_TAG_RE.exec(text);
   if (!match) {
      throw new Error('no <svg> root element found');
   }
   const attrs = parseAttrs(match[1]);
   if ('viewBox' in attrs || 'viewbox' in attrs) {
      return { text, message: 'viewBox present' };
   }
   const widthRaw = attrs['width'];
   const heightRaw = attrs['height'];
   if (!widthRaw || !heightRaw) {
      throw new Error('root <svg> lacks width and/or height attributes');
   }
   const w = DIM_RE.exec(widthRaw);
   const h = DIM_RE.exec(heightRaw);
   if (!w || !h) {
      throw new Error(`cannot parse width/height as pixels: width=${widthRaw!}, height=${heightRaw!}`);
   }
   const inner = match[1].replace(/\s+$/, '');
   const replacement = `<svg${inner} viewBox="0 0 ${w[1]} ${h[1]}">`;
   const start = match.index;
   const end = start + match[0].length;
   return {
      text: text.slice(0, start) + replacement + text.slice(end),
      message: `added viewBox="0 0 ${w[1]} ${h[1]}"`,
   };
}

function tagClickables(text: string, fileLabel: string): ParseResult {
   let tagged = 0;
   let unknown = 0;
   const result = text.replace(FILL_RE, (full, tag: string, attrs: string, hex: string, slash: string) => {
      const byte = hex.toLowerCase();
      if (byte === 'ff') {
         return full; // canonical fill: already tagged or untagged-but-canonical, skip
      }
      if (!FLOW_SUBSYSTEMS[byte]) {
         console.warn(`${fileLabel}: skipping #f4d9${hex} - no FLOW_SUBSYSTEMS entry`);
         unknown++;
         return full;
      }
      tagged++;
      const newAttrs = attrs.replace(
         /\sfill\s*=\s*"#[fF]4[dD]9[0-9a-fA-F]{2}"/,
         ` fill="${CANONICAL_FILL}"`,
      );
      return `<${tag}${newAttrs} class="qc-clickable" data-target="${byte}"${slash}>`;
   });
   const parts: string[] = [`tagged ${tagged}`];
   if (unknown > 0) {
      parts.push(`${unknown} unknown byte(s)`);
   }
   return { text: result, message: parts.join(', '), tagged };
}

function processFile(path: string): boolean {
   if (!existsSync(path) || !statSync(path).isFile()) {
      console.error(`${path}: not a file`);
      return false;
   }
   const original = readFileSync(path, 'utf8');
   let text = original;
   let vbMsg: string;
   try {
      const r1 = addViewBox(text);
      text = r1.text;
      vbMsg = r1.message;
   } catch (err) {
      console.error(`${path}: ERROR - ${(err as Error).message}`);
      return false;
   }
   const r2 = tagClickables(text, path);
   text = r2.text;
   if (text !== original) {
      writeFileSync(path, text);
   }
   console.log(`${path}: ${vbMsg}; ${r2.message}`);
   return true;
}

const args = process.argv.slice(2);
if (args.length === 0) {
   console.error('usage: tsx tag_flow_svg.ts <svg-file> [<svg-file> ...]');
   process.exit(1);
}
let ok = true;
for (const arg of args) {
   if (!processFile(arg)) {
      ok = false;
   }
}
process.exit(ok ? 0 : 1);
