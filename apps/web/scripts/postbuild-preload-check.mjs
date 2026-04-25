#!/usr/bin/env node
/**
 * postbuild-preload-check.mjs
 *
 * Runs after `pnpm build:web`. Sanity-checks that Angular's experimental
 * chunk optimizer collapsed the initial module graph into main-*.js, so
 * nothing in the initial graph is connected via a static `from "./chunk-X.js"`
 * import. If any such chunk is found, fail the build with a clear message.
 *
 * Why this matters
 * ----------------
 * The CSP served by `apps/server/src/nonce/lambda_function.py` uses hashes
 * for the entry-point scripts (main, polyfills, inline nonce listener) and
 * 'self' for dynamic imports. It does NOT use 'strict-dynamic' — Chrome
 * doesn't propagate hash-based trust to dynamic imports — and it has no
 * machinery for authorizing initial static-imported chunks by content hash.
 *
 * Which means: if Angular's optimizer ever doesn't run, esbuild's default
 * splitting produces ~15 initial chunks connected via static imports from
 * main. Those chunks are parser-inserted-by-inheritance and would need
 * modulepreload hints with integrity to get authorized by CSP. Rather than
 * re-invent that machinery, this script fails the build loudly and tells
 * you to check that `NG_BUILD_OPTIMIZE_CHUNKS=1` is in the build command.
 *
 * Dynamic imports of lazy chunks are fine — those load via `import()` and
 * are authorized by the `'self'` source in the CSP's script-src.
 */

import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const browserDir = process.argv[2] ?? 'dist/web/browser';
const indexPath = join(browserDir, 'index.html');

// Matches static imports only — `from "./chunk-X.js"` and bare
// `import "./chunk-X.js"`. Dynamic `import("./chunk-X.js")` is not matched.
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

// Any chunk reachable via a static import chain from an entry is a failure.
const staticallyImported = new Set();
for (const entry of entries) {
   const src = readFileSync(join(browserDir, entry), 'utf8');
   for (const m of src.matchAll(STATIC_IMPORT_RE)) {
      staticallyImported.add(m[1].slice(2));
   }
}

if (staticallyImported.size > 0) {
   console.error(
      `postbuild-preload-check: ${staticallyImported.size} chunk(s) are statically imported\n` +
      '  by main, which means Angular\'s experimental chunk optimizer did not run.\n' +
      '  Expected `NG_BUILD_OPTIMIZE_CHUNKS=1` in the build command. Without it,\n' +
      '  esbuild\'s default splitting extracts shared code into initial chunks and\n' +
      '  the current CSP cannot authorize them.\n' +
      '\n' +
      '  Statically-imported chunks: ' +
      [...staticallyImported].sort().join(', '),
   );
   process.exit(1);
}

console.log('postbuild-preload-check: initial graph clean (no static chunk imports from main)');
