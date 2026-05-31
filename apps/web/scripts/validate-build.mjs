#!/usr/bin/env node
/**
 * validate-build.mjs
 *
 * Asserts a built web `index.html` carries the load-bearing properties the
 * nonce lambda (apps/server/src/nonce/lambda_function.py) depends on. Runs
 * both as the post-build gate (replacing postbuild-preload-check) and as a
 * pre-upload gate inside deploy.mjs, so a build that would break under the
 * deployed CSP can never reach S3.
 *
 * Why each check exists — the lambda rewrites index.html per request:
 *   - It scrapes `integrity` attrs into the CSP script-src/style-src. For any
 *     script/style WITHOUT integrity it stamps sha384(inline-text) onto the
 *     element. An external <script src> has empty inline text, so a missing
 *     integrity becomes a wrong hash on both the element and the CSP, and the
 *     browser SRI-rejects the real bundle. (This is what broke prod.)
 *   - It find-replaces a single hard-coded nonce placeholder; any other nonce
 *     value survives unreplaced and fails the per-request CSP.
 *   - The CSP authorizes initial scripts by hash and lazy chunks by 'self',
 *     with no machinery for statically-imported initial chunks — those only
 *     exist when the chunk optimizer didn't run.
 *
 * Exports `validateBuild(browserDir)` -> string[] of problems (empty = OK).
 */

import { readFileSync, existsSync, realpathSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

// Must match `nonce_replace` in apps/server/src/nonce/lambda_function.py and
// the ngCspNonce in apps/web/src/index.html.
export const KNOWN_NONCE = 'ew26COJKMG8qrA/bjTcl0w==';

// Static imports only — `from "./chunk-X.js"` and bare `import "./chunk-X.js"`.
// Dynamic `import("./chunk-X.js")` (lazy chunks, authorized by 'self') is fine.
const STATIC_IMPORT_RE = /(?:from|\bimport)\s*["'`](\.\/chunk-[A-Za-z0-9_-]+\.js)["'`]/g;

function attr(tag, name) {
   const m = tag.match(new RegExp(`\\b${name}\\s*=\\s*["']([^"']*)["']`, 'i'));
   return m ? m[1] : null;
}

function hasAttr(tag, name) {
   return new RegExp(`\\b${name}\\b`, 'i').test(tag);
}

export function validateBuild(browserDir) {
   const problems = [];
   const indexPath = join(browserDir, 'index.html');
   if (!existsSync(indexPath)) {
      return [`index.html not found in ${browserDir}`];
   }
   const html = readFileSync(indexPath, 'utf8');

   const scriptTags = [...html.matchAll(/<script\b[^>]*>/gi)].map((m) => m[0]);
   const linkTags = [...html.matchAll(/<link\b[^>]*>/gi)].map((m) => m[0]);

   // External scripts need sha384 integrity + crossorigin, else the lambda
   // stamps a hash of empty text and the browser SRI-rejects the bundle.
   const moduleEntries = [];
   for (const tag of scriptTags) {
      const src = attr(tag, 'src');
      if (!src) {
         continue;
      }
      if (/type\s*=\s*["']module["']/i.test(tag)) {
         moduleEntries.push(src);
      }
      if (!/^sha384-/.test(attr(tag, 'integrity') ?? '')) {
         problems.push(`<script src="${src}"> is missing a sha384 integrity attribute`);
      }
      if (!hasAttr(tag, 'crossorigin')) {
         problems.push(`<script src="${src}"> is missing crossorigin`);
      }
   }

   // Stylesheet links: integrity is scraped into the CSP style-src.
   for (const tag of linkTags) {
      if (!/stylesheet/i.test(attr(tag, 'rel') ?? '')) {
         continue;
      }
      const href = attr(tag, 'href') ?? '(no href)';
      if (!/^sha384-/.test(attr(tag, 'integrity') ?? '')) {
         problems.push(`<link rel="stylesheet" href="${href}"> is missing a sha384 integrity attribute`);
      }
      if (!hasAttr(tag, 'crossorigin')) {
         problems.push(`<link rel="stylesheet" href="${href}"> is missing crossorigin`);
      }
   }

   // <qcrypt-root> must carry the exact nonce the lambda replaces; Angular's
   // runtime-injected styles inherit it.
   const root = html.match(/<qcrypt-root\b[^>]*>/i);
   if (!root) {
      problems.push('missing <qcrypt-root> element');
   } else if (attr(root[0], 'ngcspnonce') !== KNOWN_NONCE) {
      problems.push(`<qcrypt-root> ngCspNonce is "${attr(root[0], 'ngcspnonce') ?? ''}", expected "${KNOWN_NONCE}"`);
   }

   // Every nonce in the document must be the known placeholder — a random one
   // would survive the lambda's single find-replace and fail the CSP.
   for (const m of html.matchAll(/\b(?:ngcspnonce|nonce)\s*=\s*["']([^"']*)["']/gi)) {
      if (m[1] !== KNOWN_NONCE) {
         problems.push(`unexpected nonce "${m[1]}" (expected the known placeholder)`);
      }
   }

   // No entry script may statically import a ./chunk-*.js: the deployed CSP
   // can't authorize initial chunks (optimizer collapses them into main).
   const staticChunks = new Set();
   for (const entry of moduleEntries) {
      const entryPath = join(browserDir, entry);
      if (!existsSync(entryPath)) {
         continue;
      }
      for (const m of readFileSync(entryPath, 'utf8').matchAll(STATIC_IMPORT_RE)) {
         staticChunks.add(m[1].slice(2));
      }
   }
   if (staticChunks.size > 0) {
      problems.push(
         `${staticChunks.size} chunk(s) statically imported by an entry script ` +
         '(chunk optimizer did not run — expected NG_BUILD_OPTIMIZE_CHUNKS=1): ' +
         [...staticChunks].sort().join(', '),
      );
   }

   // Every local file index.html references must exist on disk.
   for (const m of html.matchAll(/\b(?:src|href)\s*=\s*["']([^"']+)["']/gi)) {
      const url = m[1].split(/[?#]/)[0];
      if (url === '/' || /^(?:[a-z]+:)?\/\//i.test(url) || url.startsWith('data:') || url.startsWith('mailto:')) {
         continue;
      }
      if (!existsSync(join(browserDir, url))) {
         problems.push(`index.html references missing file: ${url}`);
      }
   }

   // Sanity: the expected entry bundles are present.
   if (!moduleEntries.some((s) => /(?:^|\/)main-[A-Za-z0-9]+\.js$/.test(s))) {
      problems.push('no main-*.js module entry found in index.html');
   }
   if (!moduleEntries.some((s) => /(?:^|\/)polyfills-[A-Za-z0-9]+\.js$/.test(s))) {
      problems.push('no polyfills-*.js module entry found in index.html');
   }

   return problems;
}

function isDirectRun() {
   try {
      return realpathSync(process.argv[1]) === fileURLToPath(import.meta.url);
   } catch {
      return false;
   }
}

if (isDirectRun()) {
   const dir = process.argv[2] ?? 'dist/web/browser';
   const problems = validateBuild(dir);
   if (problems.length > 0) {
      console.error(`validate-build: ${problems.length} problem(s) in ${dir}/index.html:`);
      for (const problem of problems) {
         console.error(`  - ${problem}`);
      }
      process.exit(1);
   }
   console.log(`validate-build: ${dir}/index.html OK`);
}
