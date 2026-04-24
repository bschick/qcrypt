#!/usr/bin/env node
/**
 * postbuild-preload-check.mjs
 *
 * Runs after `pnpm build:web`. Emits `<!-- csp-hash sha384-... -->` comments
 * in index.html's <head>, one per chunk the module graph can load (initial
 * + lazy). The Python Lambda (`apps/server/src/nonce/lambda_function.py`)
 * scrapes these into the CSP's `script-src`. Comments don't trigger browser
 * fetches, so lazy chunks stay lazy.
 *
 * Prerequisite: `pnpm build:web` must be run with NG_BUILD_OPTIMIZE_CHUNKS=1
 * (Angular's experimental chunk optimizer, which rebundles with Rolldown to
 * collapse initial shared chunks into main-*.js). This removes the need for
 * us to inject modulepreload hints: there simply aren't enough initial
 * chunks to exceed Angular's MODULE_PRELOAD_MAX = 10 cap. The build script
 * sets the env var automatically.
 *
 * If someone removes the optimizer env var, esbuild's default splitting
 * produces 15+ initial chunks and CSP will block everything past the cap.
 * This script fails the build in that case with a clear message.
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';

const browserDir = process.argv[2] ?? 'dist/web/browser';
const indexPath = join(browserDir, 'index.html');

// Any quoted (single, double, or backtick) reference to a chunk filename.
// The optimizer uses template literals; non-optimized builds use plain
// quotes. Mixed case matters — Rolldown-output names include lowercase.
const CHUNK_REF_RE = /["'`](\.\/chunk-[A-Za-z0-9_-]+\.js)["'`]/g;

// Narrower: static imports only — `from "..."` or bare `import "..."`.
// Used to detect whether the optimizer ran.
const STATIC_IMPORT_RE = /(?:from|\bimport)\s*["'`](\.\/chunk-[A-Za-z0-9_-]+\.js)["'`]/g;

const html = readFileSync(indexPath, 'utf8');

// Starting points: every <script type="module" src="…"> in the index.
const SCRIPT_TAG_RE = /<script\b[^>]*>/g;
const TYPE_MODULE_RE = /type\s*=\s*["']module["']/;
const SRC_ATTR_RE = /src\s*=\s*["']([^"']+)["']/;
const entries = [];
for (const m of html.matchAll(SCRIPT_TAG_RE)) {
   if (TYPE_MODULE_RE.test(m[0])) {
      const src = m[0].match(SRC_ATTR_RE);
      if (src) {
         entries.push(src[1]);
      }
   }
}
if (entries.length === 0) {
   console.error('postbuild-preload-check: no <script type="module"> entries found in index.html');
   process.exit(1);
}

// BFS every chunk reachable from the entries.
const visited = new Set();
const allChunks = new Set();
const staticallyImported = new Set();
const queue = [...entries];
while (queue.length > 0) {
   const file = queue.shift();
   if (visited.has(file)) {
      continue;
   }
   visited.add(file);
   const src = readFileSync(join(browserDir, file), 'utf8');
   for (const m of src.matchAll(CHUNK_REF_RE)) {
      const name = m[1].slice(2);
      if (!allChunks.has(name)) {
         allChunks.add(name);
         queue.push(name);
      }
   }
   for (const m of src.matchAll(STATIC_IMPORT_RE)) {
      staticallyImported.add(m[1].slice(2));
   }
}

// If any chunk is statically imported by main, the optimizer didn't run —
// some initial shared chunk was extracted, and if we have more than 10 of
// them Angular won't emit modulepreload hints for all and CSP will block.
// The build script sets NG_BUILD_OPTIMIZE_CHUNKS=1; if someone removed it,
// surface that as a clear failure.
if (staticallyImported.size > 0) {
   console.error(
      `postbuild-preload-check: ${staticallyImported.size} chunk(s) are statically imported\n` +
      '  by main, which means Angular\'s experimental chunk optimizer did not run.\n' +
      '  Expected `NG_BUILD_OPTIMIZE_CHUNKS=1` in the build command. Without it,\n' +
      '  esbuild\'s default splitting extracts shared code and CSP will block\n' +
      '  anything past Angular\'s MODULE_PRELOAD_MAX = 10 cap.\n' +
      '\n' +
      '  Statically-imported chunks: ' +
      [...staticallyImported].sort().join(', '),
   );
   process.exit(1);
}

if (allChunks.size === 0) {
   console.log('postbuild-preload-check: no lazy chunks discovered; nothing to do');
   process.exit(0);
}

// Emit csp-hash comments for every discovered chunk.
const cspHashComments = [...allChunks].sort().map((name) => {
   const body = readFileSync(join(browserDir, name));
   const hash = 'sha384-' + createHash('sha384').update(body).digest('base64');
   return `<!-- csp-hash ${hash} -->`;
}).join('');

const patched = html.replace('</head>', cspHashComments + '</head>');
if (patched === html) {
   console.error('postbuild-preload-check: could not find </head> to insert comments before');
   process.exit(1);
}

writeFileSync(indexPath, patched);
console.log(`postbuild-preload-check: emitted ${allChunks.size} csp-hash comment(s) for lazy chunks`);
