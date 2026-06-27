#!/usr/bin/env node
//
// AI-Assist: 100% Claude Code Generated
//
/**
 * deploy.mjs
 *
 * Uploads the built SPA to S3, preserving in-flight clients' access to chunks
 * the current build no longer references for a configurable grace period.
 *
 * ============================================================
 * Why this script exists
 * ============================================================
 *
 * No existing npm package (s3-spa-upload, aws-spa, s3-deploy, scottyjs, etc.)
 * implements the retention semantic SPAs need:
 *
 *   Files should only be deleted after they have been absent from the
 *   current deploy for >= N days — NOT after N days since upload.
 *
 * The two obvious approaches both fail:
 *
 *   - `--delete` on sync (`aws s3 sync --delete`, s3-spa-upload's --delete):
 *     immediately removes anything not in the new build, breaking any
 *     browser session still fetching chunks referenced by a cached older
 *     `index.html`.
 *   - S3 lifecycle rule by object age: unchanged files (e.g. polyfills
 *     whose content didn't change) are never re-uploaded, so their
 *     `LastModified` stays at original-upload time — the rule eventually
 *     deletes them while they're still in use by the live site.
 *
 * The fix is to track orphan status explicitly. This script keeps a small
 * manifest file in S3 that records:
 *
 *   - `current`  : files the most recent deploy uploaded, with the date
 *                  each was last actually transferred (preserved across
 *                  deploys when `aws s3 sync` skipped re-uploading, so
 *                  files like robots.txt show their true last-upload time)
 *   - `orphans`  : previously-current files now absent, with the date they
 *                  were orphaned
 *   - `expected` : manually-registered keys and/or glob patterns the script
 *                  should never delete or flag as leaks (AWS virus-scan
 *                  artifacts, domain-proof files, anything else you want
 *                  kept but the build does not produce). Supports `*` and
 *                  `?` wildcards, e.g. `.well-known/*`.
 *
 * Each deploy reconciles these categories:
 *
 *   - In the new build, not in prev.current       → marked current
 *   - In prev.current, not in the new build       → newly orphaned (today)
 *   - In prev.orphans, back in the new build      → marked current, clock reset
 *   - In prev.orphans, still not in the new build → stays orphaned (clock ticking)
 *   - Orphan older than --expiration-days         → DELETED
 *
 * Files not in `current`, `orphans`, or `expected` but present in the bucket
 * are reported as "untracked" in the deploy summary (potential leaks). Two
 * companion commands let you act on them: `expect` registers files you want
 * kept, `prune` removes everything the manifest does not recognise.
 *
 * ============================================================
 * Ordering
 * ============================================================
 *
 * During a deploy, `index.html` is uploaded LAST, after every chunk it can
 * possibly reference is already live. A client who loads the new
 * `index.html` will never find a missing chunk from the current deploy.
 * (The Lambda in `apps/server/src/nonce/lambda_function.py` rewrites the
 * index.html's `Cache-Control` header per-request, so the S3 object's
 * cache-control is arbitrary for index.html — we give it the same immutable
 * value as everything else to avoid implying the S3-level value has meaning.)
 *
 * ============================================================
 * AWS auth
 * ============================================================
 *
 * Mode is selected by --prod presence: --prod (with any alias value) selects
 * prod mode; absence selects test mode. The alias value itself is unused on
 * the web side — there's no Lambda alias to track — but kept symmetric with
 * the server script so the wrappers can share auth resolution logic.
 *
 * Every `aws` invocation is called with an explicit --profile and --region
 * resolved at startup. Resolution order (per option):
 *
 *   1. CLI flag (--profile / --region) if given
 *   2. env var QC_{PROD,TEST}_AWS_PROFILE / QC_{PROD,TEST}_AWS_REGION (chosen
 *      by --prod presence)
 *
 * If neither source provides a value the script exits with a clear error.
 * The AWS CLI's own AWS_PROFILE / AWS_REGION env vars are intentionally
 * never consulted — keeps the active account explicit and prevents an
 * unrelated env from silently routing a deploy to the wrong account.
 *
 * ============================================================
 * Usage
 * ============================================================
 *
 *   deploy.mjs <bucket> [options]                     deploy the built SPA
 *   deploy.mjs deploy <bucket> [options]              same as above (explicit)
 *   deploy.mjs bdeploy <bucket> [options]             build then deploy
 *   deploy.mjs bootstrap <bucket>                     seed manifest.current from bucket
 *   deploy.mjs manifest <bucket>                      print the current manifest
 *   deploy.mjs leaks <bucket>                         list untracked bucket files
 *   deploy.mjs info <bucket>                          prints files counts and last deploy information
 *   deploy.mjs expect <bucket> <patterns..>           register expected files (globs ok)
 *   deploy.mjs unexpect <bucket> <patterns..>         remove expected entries
 *   deploy.mjs prune <bucket>                         remove untracked files and expired orphans
 *   deploy.mjs reset <bucket>                         clear the manifest (no file deletion)
 *   deploy.mjs rollback <bucket>                      delete latest index.html version (break-glass)
 *
 * Run any subcommand with --help for its option list. --dry-run logs
 * actions without performing them for every command.
 */

import { readdirSync, statSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import yargs from 'yargs/yargs';
import { hideBin } from 'yargs/helpers';
import {
   aws,
   confirmProdAction,
   ensureAuth,
   relToRoot,
   suggestCommandTypo,
} from '../../../scripts/deploy-common.mjs';
import { validateBuild } from './validate-build.mjs';

// ---------------------------------------------------------------------------
// Helpers (all take `argv` so they can be shared by every command)
// ---------------------------------------------------------------------------

// Known OS/editor metadata files we don't want to upload, but without
// blanket-skipping dotfiles (e.g. `.well-known/` is legitimate).
const METADATA_SKIP_RE = /^(?:\.DS_Store|\._.*|Thumbs\.db|desktop\.ini)$/;

function collectLocalFiles(root, recursive) {
   const out = [];
   const walk = (dir, rel) => {
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
         if (METADATA_SKIP_RE.test(entry.name)) {
            continue;
         }
         const full = join(dir, entry.name);
         const key = rel ? `${rel}/${entry.name}` : entry.name;
         if (entry.isDirectory()) {
            if (recursive) {
               walk(full, key);
            }
         } else if (entry.isFile()) {
            out.push({ relKey: key, absPath: full });
         }
      }
   };
   walk(root, '');
   return out;
}

function emptyManifest() {
   return { version: 1, current: {}, orphans: {}, expected: [] };
}

// JSON preserves insertion order; sorting keys keeps manifest diffs stable.
function sortedDict(d) {
   const out = {};
   for (const k of Object.keys(d).sort()) {
      out[k] = d[k];
   }
   return out;
}

function readManifest(argv) {
   const key = `s3://${argv.bucket}/${argv.manifestKey}`;
   const r = aws(argv, ['s3', 'cp', key, '-'], { allowFailure: true, readOnly: true });
   let manifest;
   if (r.status !== 0) {
      // `allowFailure` is set so a never-deployed bucket (manifest object
      // missing) returns the empty manifest instead of crashing — but ANY
      // other failure (NoSuchBucket, AccessDenied, expired SSO token, etc.)
      // would silently masquerade as an empty manifest, which is dangerous.
      // Treat only object-missing patterns as "no manifest yet"; everything
      // else exits, with the bucket-specific hint when the bucket itself
      // doesn't exist (the resource-specific message that the generic
      // shared aws() can't produce because it doesn't know argv.bucket).
      const stderr = r.stderr ?? '';
      if (!/NoSuchKey|Not Found|\b404\b/i.test(stderr)) {
         process.stderr.write(stderr);
         if (/NoSuchBucket/i.test(stderr)) {
            console.error(`Error: bucket '${argv.bucket}' does not exist. Check the bucket name and your AWS account/profile.`);
         } else {
            console.error(`Failed to read manifest at ${key}.`);
         }
         process.exit(1);
      }
      manifest = emptyManifest();
   } else {
      try {
         manifest = JSON.parse(r.stdout);
         manifest.current ??= {};
         manifest.orphans ??= {};
         manifest.expected ??= [];
      } catch (e) {
         console.warn(`Existing manifest at ${key} is invalid JSON; treating as empty: ${e.message}`);
         manifest = emptyManifest();
      }
   }
   // The manifest file is always considered tracked (otherwise `prune` would
   // remove the very file we're trying to preserve). Use a Set for dedup so
   // repeated reads/writes don't accumulate duplicate entries.
   const expected = new Set(manifest.expected);
   expected.add(argv.manifestKey);
   manifest.expected = [...expected];
   return manifest;
}

function writeManifest(argv, m) {
   const body = JSON.stringify(m, null, 2);
   aws(argv, [
      's3', 'cp', '-', `s3://${argv.bucket}/${argv.manifestKey}`,
      '--content-type', 'application/json',
      '--cache-control', 'no-store',
   ], { input: body });
}

// Uses `aws s3api` rather than `aws s3 ls` because the high-level `s3`
// command family doesn't produce structured JSON output; `s3api` maps
// directly to the S3 API and returns the JSON we need to parse.
//
// Returned keys are filtered through getScope so the same scope rule
// applies everywhere (deploy/prune/leaks/info/bootstrap).
function listBucket(argv) {
   const r = aws(argv, ['s3api', 'list-objects-v2', '--bucket', argv.bucket, '--output', 'json'], { readOnly: true });
   if (!r.stdout) {
      return [];
   }
   const parsed = JSON.parse(r.stdout);
   const keys = (parsed.Contents ?? []).map((o) => o.Key);
   return keys.filter(getScope(argv).inScope);
}

// Convert a shell-style glob to an anchored RegExp. `*` matches any run of
// characters (including `/`), `?` matches one character. All other regex
// metacharacters are escaped to literals.
function globToRegex(pattern) {
   const escaped = pattern.replace(/[.+^$(){}|[\]\\]/g, '\\$&');
   const re = escaped.replace(/\*/g, '.*').replace(/\?/g, '.');
   return new RegExp(`^${re}$`);
}

// Build a predicate that matches a key against a mix of literal entries and
// glob patterns. Patterns containing `*` or `?` are compiled to regexes;
// the rest are O(1) Set lookups.
function matcherFor(patterns) {
   const literals = new Set();
   const regexes = [];
   for (const p of patterns) {
      if (p.includes('*') || p.includes('?')) {
         regexes.push(globToRegex(p));
      } else {
         literals.add(p);
      }
   }
   return (key) => literals.has(key) || regexes.some((re) => re.test(key));
}

function cloudfrontDistributionId(value) {
   if (value.startsWith('arn:')) {
      return value.split('/').pop();
   }
   return value;
}

function invalidateCloudFront(argv) {
   if (!argv.cfDistribution) {
      return;
   }
   const distId = cloudfrontDistributionId(argv.cfDistribution);
   const r = aws(argv, [
      'cloudfront', 'create-invalidation',
      '--distribution-id', distId,
      '--paths', '/*',
   ]);
   let invalidationId;
   if (!argv.dryRun && r.stdout) {
      try {
         invalidationId = JSON.parse(r.stdout).Invalidation?.Id;
      } catch {
         // Non-JSON stdout; skip the id (and the wait below) silently.
      }
   }
   const idSuffix = invalidationId ? ` id=${invalidationId}` : '';
   console.log(`  cloudfront: created /* invalidation for distribution ${distId}${idSuffix}${argv.dryRun ? ' (DRY RUN)' : ''}`);

   if (!invalidationId) {
      return;
   }
   // Block until the edge caches are purged so the deploy doesn't return
   // "done" while stale assets are still being served. `wait` polls every
   // ~20s and gives up after ~10min; a timeout is non-fatal here because the
   // upload + manifest already succeeded and the invalidation will still
   // finish on its own — surface it rather than aborting.
   console.log('  cloudfront: waiting for invalidation to complete...');
   const waitResult = aws(argv, [
      'cloudfront', 'wait', 'invalidation-completed',
      '--distribution-id', distId,
      '--id', invalidationId,
   ], { allowFailure: true });
   if (waitResult.status === 0) {
      console.log('  cloudfront: invalidation completed');
   } else {
      console.error(`  cloudfront: wait did not confirm completion (invalidation ${invalidationId} is likely still in progress; check the AWS console)`);
   }
}

// "Is this key tracked by the manifest?" — union of current, orphans keys,
// and the expected list (with glob support). readManifest guarantees the
// manifest's own key is in expected, so no special case is needed here.
function trackedMatcher(manifest) {
   const literals = new Set([
      ...Object.keys(manifest.current),
      ...Object.keys(manifest.orphans),
   ]);
   const expectedMatch = matcherFor(manifest.expected);
   return (key) => literals.has(key) || expectedMatch(key);
}

// Single source of truth for the active scope. Three modes:
//   - default            all keys (recursive)
//   - --no-subdirs       top-level keys only
//   - --aaguids          only keys under the assets/aaguid/ prefix
// Used by local file enumeration, bucket listing, manifest reconciliation,
// and the deploy s3 sync source/destination.
function getScope(argv) {
   if (argv.aaguids) {
      const prefix = 'assets/aaguid/';
      return {
         recursive: true,
         inScope: (k) => k.startsWith(prefix),
         label: 'aaguids',
         localSubpath: 'assets/aaguid',
         s3Prefix: prefix,
      };
   }
   return {
      recursive: !!argv.subdirs,
      inScope: (k) => argv.subdirs || !k.includes('/'),
      label: argv.subdirs ? 'all' : 'top-level',
      localSubpath: '',
      s3Prefix: '',
   };
}

// Files that must exist in the build dir for a given scope, independent of
// index.html's internal validity. Catches a wrong --build-dir or a partial
// build before anything is uploaded. `keys` are the in-scope relative keys.
function checkEssentialFiles(scope, keys) {
   const problems = [];
   const hasMatch = (re) => [...keys].some((key) => re.test(key));
   if (scope.label === 'aaguids') {
      if (!keys.has('assets/aaguid/combined.json')) {
         problems.push('missing assets/aaguid/combined.json');
      }
      if (!hasMatch(/^assets\/aaguid\/img\//)) {
         problems.push('missing assets/aaguid/img/ (no files found)');
      }
      return problems;
   }
   if (!keys.has('index.html')) {
      problems.push('missing index.html');
   }
   if (!hasMatch(/^main-[A-Za-z0-9_-]+\.js$/)) {
      problems.push('missing main-*.js');
   }
   if (!hasMatch(/^polyfills-[A-Za-z0-9_-]+\.js$/)) {
      problems.push('missing polyfills-*.js');
   }
   if (!hasMatch(/^styles-[A-Za-z0-9_-]+\.css$/)) {
      problems.push('missing styles-*.css');
   }
   return problems;
}

function inScopeFor(argv) {
   return getScope(argv).inScope;
}

// Bucket keys not covered by any of the manifest's tracking sets.
function untrackedKeys(argv, manifest) {
   const isTracked = trackedMatcher(manifest);
   return listBucket(argv).filter((k) => !isTracked(k));
}

// Orphans whose retention clock has run out. `inScope` lets the caller skip
// out-of-scope keys (subdir entries on a top-level run) so they aren't touched.
function findExpiredOrphans(orphans, expirationDays, inScope) {
   const cutoffMs = Date.now() - expirationDays * 86400 * 1000;
   const expired = [];
   for (const [key, orphanedAt] of orphans) {
      if (!inScope(key)) {
         continue;
      }
      const whenMs = Date.parse(orphanedAt);
      if (Number.isFinite(whenMs) && whenMs < cutoffMs) {
         expired.push(key);
      }
   }
   return expired;
}

// One `aws s3api delete-objects` call removes up to 1000 keys at a time
// instead of one `s3 rm` per CLI invocation, turning a per-file ~1-2s spawn
// cost into a single batched request. Larger sets are chunked. The Delete
// spec is handed to aws via `--delete file://<tmp>`: a temp file rather
// than inline JSON (Linux caps a single argv string at 128KB, which a
// 1000-key spec can exceed) or stdin (aws fails to read file:///dev/stdin
// from a spawned pipe). Failures are tolerated so one bad batch doesn't
// abort the rest.
function deleteKeys(argv, keys) {
   const deleted = [];
   const CHUNK_SIZE = 1000;
   const tmpDir = mkdtempSync(join(tmpdir(), 'qc-delete-'));
   try {
      for (let offset = 0; offset < keys.length; offset += CHUNK_SIZE) {
         const chunk = keys.slice(offset, offset + CHUNK_SIZE);
         const payload = JSON.stringify({
            Objects: chunk.map((key) => ({ Key: key })),
            Quiet: true,
         });
         const specPath = join(tmpDir, `delete-${offset}.json`);
         writeFileSync(specPath, payload);
         const r = aws(argv, [
            's3api', 'delete-objects',
            '--bucket', argv.bucket,
            '--delete', `file://${specPath}`,
         ], { allowFailure: true });
         if (r.status !== 0) {
            // Whole-chunk failure (auth, network, etc.); leave none recorded.
            continue;
         }
         // With Quiet=true, a successful response is either empty or contains
         // only an Errors array for the keys that failed.
         let errors = [];
         try {
            const parsed = JSON.parse(r.stdout || '{}');
            errors = parsed.Errors ?? [];
         } catch {
            // Empty stdout is fine when Quiet=true and nothing errored.
         }
         const failed = new Set(errors.map((err) => err.Key));
         for (const key of chunk) {
            if (!failed.has(key)) {
               deleted.push(key);
            }
         }
         if (errors.length > 0) {
            console.error(`Failed to delete ${errors.length} of ${chunk.length} keys in batch:`);
            for (const err of errors.slice(0, argv.printLimit ?? 5)) {
               console.error(`  ${err.Key}: ${err.Message ?? err.Code ?? ''}`);
            }
         }
      }
   } finally {
      rmSync(tmpDir, { recursive: true, force: true });
   }
   return deleted;
}

function printKeyList(keys, heading, limit) {
   if (keys.length === 0) {
      return;
   }
   console.log(`  ${heading}`);
   for (const key of keys.slice(0, limit)) {
      console.log(`    ${key}`);
   }
   if (keys.length > limit) {
      console.log(`    ...and ${keys.length - limit} more`);
   }
}

// ---------------------------------------------------------------------------
// deploy (default command)
// ---------------------------------------------------------------------------

async function runDeploy(argv) {
   const scope = getScope(argv);
   // 1. Enumerate the local build, filtered to the active scope.
   const files = collectLocalFiles(argv.buildDir, scope.recursive)
      .filter((f) => scope.inScope(f.relKey));
   const newKeys = new Set(files.map((f) => f.relKey));
   if (newKeys.size === 0) {
      console.error(`No files found under ${argv.buildDir} (scope=${scope.label})`);
      process.exit(1);
   }

   // Refuse before uploading if the build dir is missing files essential to
   // this scope — a wrong --build-dir or a partial/broken build. A full site
   // needs index.html + the entry bundles; --aaguids needs the aaguid data.
   const missing = checkEssentialFiles(scope, newKeys);
   if (missing.length > 0) {
      console.error(`deploy: refusing to deploy — essential files missing under ${relToRoot(argv.buildDir)} (scope=${scope.label}):`);
      for (const problem of missing) {
         console.error(`  - ${problem}`);
      }
      console.error('Check --build-dir points at the build output directory (web: dist/web[-test]/browser).');
      process.exit(1);
   }

   // Gate: never upload an index.html that would break under the deployed CSP
   // (missing SRI, wrong nonce, un-collapsed chunks). Skipped for prefix
   // scopes like --aaguids, which legitimately have no index.html.
   if (newKeys.has('index.html')) {
      if (argv.skipValidate) {
         console.warn('⚠  deploy: build validation SKIPPED (--skip-validate)');
      } else {
         const problems = validateBuild(argv.buildDir);
         if (problems.length > 0) {
            console.error(`deploy: refusing to deploy — ${relToRoot(argv.buildDir)}/index.html failed validation:`);
            for (const problem of problems) {
               console.error(`  - ${problem}`);
            }
            console.error('Rebuild with `pnpm build:web:prod` (or `pnpm build:web`), or override with --skip-validate.');
            process.exit(1);
         }
         console.log(`deploy: build validation passed (${relToRoot(argv.buildDir)}/index.html)`);
      }
   }

   // 2. Upload everything except index.html, then index.html last.
   // Known OS/editor metadata files are excluded (matches METADATA_SKIP_RE
   // used locally) while legitimate dotdirs like `.well-known/` are kept.
   // `--exact-timestamps` forces re-upload when sizes match but mtimes differ,
   // covering edge cases where build tooling regenerates files with identical
   // sizes but different content (e.g. Rolldown's chunk naming isn't always
   // pure content-hash).
   //
   // For a prefixed scope (--aaguids) the sync source/destination are scoped
   // to the prefix so only matching files are walked and S3 keys land at the
   // right spot.
   const localSrc = scope.localSubpath ? join(argv.buildDir, scope.localSubpath) : argv.buildDir;
   const s3Dest = `s3://${argv.bucket}/${scope.s3Prefix}`;
   const bulkArgs = [
      's3', 'sync', localSrc, s3Dest,
      '--exact-timestamps',
      '--no-progress',
      '--exclude', 'index.html',
      '--exclude', '.DS_Store', '--exclude', '*/.DS_Store',
      '--exclude', '._*', '--exclude', '*/._*',
      '--exclude', 'Thumbs.db', '--exclude', '*/Thumbs.db',
      '--exclude', 'desktop.ini', '--exclude', '*/desktop.ini',
      '--cache-control', argv.cacheControl,
   ];
   if (!scope.recursive) {
      bulkArgs.push('--exclude', '*/*');
   }
   console.log(`deploy: syncing ${newKeys.size} local files from ${relToRoot(localSrc)} to ${s3Dest} (changed files upload)...`);
   const bulkResult = aws(argv, bulkArgs);

   // `aws s3 sync --no-progress` prints one line per transferred file:
   //   upload: <local path> to s3://<bucket>/<key>
   // Parse out the trailing s3 key so we can update each transferred key's
   // uploadedAt timestamp (skipped files keep their prior timestamp). Splits
   // on \r and \n so progress-overlay output (if --no-progress is ever
   // dropped) still parses cleanly.
   const parseUploadedKeys = (out) => {
      const keys = new Set();
      if (!out) {
         return keys;
      }
      for (const line of out.split(/[\r\n]+/)) {
         const m = line.match(/^upload: \S+ to s3:\/\/[^/]+\/(.+)$/);
         if (m) {
            keys.add(m[1]);
         }
      }
      return keys;
   };
   const uploadedKeys = parseUploadedKeys(bulkResult.stdout);

   // index.html is sync'd separately so it lands AFTER its chunks. Using sync
   // (not cp) means it's skipped when unchanged.
   if (newKeys.has('index.html')) {
      const indexResult = aws(argv, [
         's3', 'sync', argv.buildDir, `s3://${argv.bucket}/`,
         '--exact-timestamps',
         '--no-progress',
         '--exclude', '*',
         '--include', 'index.html',
         '--cache-control', argv.cacheControl,
      ]);
      for (const k of parseUploadedKeys(indexResult.stdout)) {
         uploadedKeys.add(k);
      }
   }
   const totalUploads = uploadedKeys.size;

   const manifest = readManifest(argv);
   const manifestOrphans = new Map(Object.entries(manifest.orphans));

   // 3. Short-circuit on a true no-op: nothing transferred ⇒ nothing to
   //    reconcile, no manifest rewrite, no invalidation. Still scan for
   //    leaks so untracked-in-bucket reports continue to surface.
   if (!argv.dryRun && totalUploads === 0) {
      const untracked = untrackedKeys(argv, manifest);
      console.log(`deploy #${manifest.deployCount ?? 0}: from=${relToRoot(localSrc)} no changes  untracked=${untracked.length}`);
      printKeyList(untracked, "untracked in bucket (use 'expect' or 'unexpect' to update, 'prune' to remove):", argv.printLimit);
      return;
   }

   // 4. Reconcile the manifest. Only in-scope keys are reconciled — out-of-scope
   //    entries (subdir files under --no-subdirs, or non-aaguid files under
   //    --aaguids) are preserved verbatim so a narrowed-scope deploy doesn't
   //    mis-orphan state a wider deploy put there.
   const prevCurrent = manifest.current;
   const inScope = inScopeFor(argv);

   const now = new Date().toISOString();
   // Build new current dict: in-scope keys that aws s3 sync actually
   // transferred this run get `now`; in-scope keys that sync skipped
   // (size+mtime matched the bucket version) keep their prior timestamp
   // — so "uploadedAt" reflects the last time the file was actually put
   // on the wire, not the first time the key joined the current set.
   // Out-of-scope entries are preserved verbatim.
   const newCurrent = {};
   for (const key of newKeys) {
      if (inScope(key)) {
         if (uploadedKeys.has(key)) {
            newCurrent[key] = now;
         } else {
            newCurrent[key] = prevCurrent[key] ?? now;
         }
      }
   }
   for (const [key, ts] of Object.entries(prevCurrent)) {
      if (!inScope(key)) {
         newCurrent[key] = ts;
      }
   }

   const orphans = new Map();
   for (const [key, orphanedAt] of manifestOrphans) {
      if (!inScope(key)) {
         orphans.set(key, orphanedAt);
      } else if (!newKeys.has(key)) {
         orphans.set(key, orphanedAt);
      }
      // else: in-scope orphan that reappeared in the new build — dropped; it
      // ends up in newCurrent via newKeys with a reset clock.
   }
   for (const key of Object.keys(prevCurrent)) {
      if (inScope(key) && !newKeys.has(key) && !orphans.has(key)) {
         orphans.set(key, now);
      }
   }

   // 4. Delete expired orphans (in-scope only — we don't touch out-of-scope).
   const expired = findExpiredOrphans(orphans, argv.expirationDays, inScope);
   const deletedFromS3 = deleteKeys(argv, expired);
   for (const key of deletedFromS3) {
      orphans.delete(key);
   }

   // 6. Write the updated manifest. `deployComment` reflects only the latest
   //    deploy (defaults to '' so omitting --comment clears any prior comment).
   const deployCount = (manifest.deployCount ?? 0) + 1;
   writeManifest(argv, {
      version: 1,
      deployDate: now,
      deployCount,
      deployComment: argv.comment,
      current: sortedDict(newCurrent),
      orphans: Object.fromEntries(orphans),
      expected: [...manifest.expected].sort(),
   });

   // 7. Leak detection: compare S3 listing against tracked sets.
   // listBucket respects --subdirs for scope.
   const untracked = untrackedKeys(argv, {
      current: newCurrent,
      orphans: Object.fromEntries(orphans),
      expected: manifest.expected,
   });

   // 8. Summary.
   const newlyOrphaned = [...orphans.keys()].filter((k) => !manifestOrphans.has(k));
   const dryRunTag = argv.dryRun ? ' (DRY RUN — no writes)' : '';
   console.log(
      `deploy #${deployCount}: from=${relToRoot(localSrc)} uploaded=${totalUploads} newly-orphaned=${newlyOrphaned.length}` +
      ` tracked-orphans=${orphans.size} expired-deleted=${deletedFromS3.length}` +
      ` untracked=${untracked.length}${dryRunTag}`,
   );
   printKeyList(deletedFromS3, 'deleted (expired orphans):', argv.printLimit);
   printKeyList(newlyOrphaned, 'newly orphaned (retention clock starts now):', argv.printLimit);
   printKeyList(untracked, "untracked in bucket (use 'expect' or 'unexpect' to update, 'prune' to remove):", argv.printLimit);
   invalidateCloudFront(argv);
}

// ---------------------------------------------------------------------------
// bdeploy — build then deploy
// ---------------------------------------------------------------------------

// Convenience wrapper: builds with the environment matching the target
// mode (`pnpm build:web:prod` when --prod is set, `pnpm build:web` for
// test), then defers to runDeploy with the same argv so all deploy
// options (including --comment) flow through.
async function runBdeploy(argv) {
   const cmd = 'pnpm';
   const args = [argv.prod ? 'build:web:prod' : 'build:web'];
   // QC_WEB_OUT forces the build to write into the exact dir the deploy step
   // reads from. argv.buildDir is the `…/browser` upload dir; Angular's
   // output base is its parent, and it writes the browser files back under
   // `<base>/browser`, so build output and deploy source can't diverge.
   const outBase = relToRoot(dirname(argv.buildDir));
   console.log(`bdeploy: building into ${outBase} via ${args[0]}...`);
   if (argv.dryRun) {
      console.log(`[dry-run] QC_WEB_OUT=${outBase} ${cmd} ${args.join(' ')}`);
   } else {
      const r = spawnSync(cmd, args, { stdio: 'inherit', env: { ...process.env, QC_WEB_OUT: outBase } });
      if (r.error) {
         console.error(`Failed to spawn ${cmd}: ${r.error.message}`);
         process.exit(1);
      }
      if (r.status !== 0) {
         console.error(`bdeploy: ${cmd} ${args.join(' ')} failed (exit ${r.status})`);
         process.exit(r.status ?? 1);
      }
   }
   await runDeploy(argv);
}

// ---------------------------------------------------------------------------
// rollback (no deploy) — revert index.html to its previous S3 version
// ---------------------------------------------------------------------------

// Break-glass for troubleshooting a bad deploy. Permanently deletes the
// current version of index.html so the previous version becomes current.
// Requires S3 bucket versioning.
//
// Not a steady-state: just flips index.html. Intended to give you time to
// debug on the prior release, then either redeploy the fix or investigate
// further. Don't leave a bucket sitting in rolled-back state for days.
//
// Caveat — retention-window gap: the chunks the restored index.html
// references must still exist in the bucket. Immediately after a failed
// deploy they will: the just-replaced prior chunks are sitting in the
// manifest's `orphans` with today's date, well within their retention
// clock. But rolling back to an older index.html (multiple rollbacks
// in a row, or rollback after a long stretch of deploys) can land on a
// version whose chunks were already expired and deleted by a past run —
// at which point the site 404s on chunk load. Use soon after the bad
// deploy, not weeks later.
//
// The current/orphans/expected sets are intentionally NOT rolled back here:
// the next real deploy reconciles against whichever manifest state is
// current, and any lingering drift (chunks from the aborted deploy) is
// handled by the normal orphan clock. The manifest IS rewritten — but only
// to refresh `deployDate` and `deployComment`, since the rule is that
// deploy/bdeploy/rollback are the only commands that touch those fields.
async function runRollback(argv) {
   const key = 'index.html';
   const listResult = aws(argv, [
      's3api', 'list-object-versions',
      '--bucket', argv.bucket,
      '--prefix', key,
      '--output', 'json',
   ], { readOnly: true });
   const parsed = JSON.parse(listResult.stdout || '{}');
   const versions = (parsed.Versions ?? []).filter((v) => v.Key === key);
   if (versions.length < 2) {
      console.error(
         `rollback: need at least 2 versions of ${key} to roll back; found ${versions.length}.` +
         ' Is bucket versioning enabled?',
      );
      process.exit(1);
   }
   const latest = versions.find((v) => v.IsLatest);
   if (!latest) {
      console.error(`rollback: no current version found for ${key}.`);
      process.exit(1);
   }
   aws(argv, [
      's3api', 'delete-object',
      '--bucket', argv.bucket,
      '--key', key,
      '--version-id', latest.VersionId,
   ]);

   const manifest = readManifest(argv);
   writeManifest(argv, {
      ...manifest,
      deployDate: new Date().toISOString(),
      deployComment: argv.comment,
   });

   console.log(
      `rollback: deleted ${key} version ${latest.VersionId};` +
      ` previous version is now current${argv.dryRun ? ' (DRY RUN)' : ''}`,
   );
   console.log('  WARNING: This is not a permanent rollback. Fix issues and redeploy.');
   invalidateCloudFront(argv);
}

// ---------------------------------------------------------------------------
// reset (no deploy) — clear the manifest
// ---------------------------------------------------------------------------

// Overwrites the manifest with empty current/orphans/expected. Does not
// touch any other bucket contents — files remain; they just stop being
// tracked. `readManifest` re-seeds the manifest key into `expected` on
// next read, which is why the subsequent `prune` command's safety check
// still refuses to run.
function runReset(argv) {
   writeManifest(argv, emptyManifest());
   console.log(`reset: manifest cleared${argv.dryRun ? ' (DRY RUN)' : ''}`);
}

// ---------------------------------------------------------------------------
// bootstrap (no deploy) — seed `current` from an existing bucket
// ---------------------------------------------------------------------------

// Takes whatever is already in the bucket and writes it into manifest.current,
// resets orphans, and leaves expected alone. Useful when adopting the script
// on a bucket that was populated by a previous deploy mechanism. Respects
// --subdirs for scope.
function runBootstrap(argv) {
   const manifest = readManifest(argv);
   // Anything already covered by `expected` (including the manifest file, which
   // readManifest always seeds into expected) is kept out of `current` so each
   // key is only tracked once. Running `expect` before or after bootstrap
   // yields the same end state.
   const isExpected = matcherFor(manifest.expected);
   const keys = listBucket(argv).filter((k) => !isExpected(k));
   // We don't know when each key was uploaded; today's date is the best
   // approximation. The deploy that follows bootstrap will preserve these
   // timestamps for any keys it considers still current.
   const now = new Date().toISOString();
   const current = {};
   for (const k of keys.sort()) {
      current[k] = now;
   }
   // `deployDate`, `deployCount`, and `deployComment` are deploy-only fields.
   // Preserve whatever was there (or leave unset if the bucket has never seen
   // a real deploy).
   const next = {
      version: 1,
      current,
      orphans: {},
      expected: [...manifest.expected].sort(),
   };
   if (manifest.deployDate) {
      next.deployDate = manifest.deployDate;
   }
   if (manifest.deployCount !== undefined) {
      next.deployCount = manifest.deployCount;
   }
   if (manifest.deployComment !== undefined) {
      next.deployComment = manifest.deployComment;
   }
   writeManifest(argv, next);
   console.log(
      `bootstrap: current=${keys.length} expected-retained=${manifest.expected.length}` +
      `${argv.dryRun ? ' (DRY RUN)' : ''}`,
   );
}

// ---------------------------------------------------------------------------
// manifest (no deploy) — print the current manifest
// ---------------------------------------------------------------------------

function runManifest(argv) {
   console.log(JSON.stringify(readManifest(argv), null, 2));
}

// ---------------------------------------------------------------------------
// leaks (no deploy) — list S3 files not tracked by the manifest
// ---------------------------------------------------------------------------

function runLeaks(argv) {
   const untracked = untrackedKeys(argv, readManifest(argv));
   console.log(`leaks: scope=${getScope(argv).label} untracked=${untracked.length}`);
   printKeyList(untracked, 'untracked in bucket:', argv.printLimit);
}

// ---------------------------------------------------------------------------
// current (no deploy) — list manifest.current entries with timestamps
// ---------------------------------------------------------------------------

function runCurrent(argv) {
   const manifest = readManifest(argv);
   const scope = getScope(argv);
   const entries = Object.entries(manifest.current)
      .filter(([k]) => scope.inScope(k))
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
   console.log(`current: scope=${scope.label} count=${entries.length}`);
   for (const [key, uploadedAt] of entries.slice(0, argv.printLimit)) {
      console.log(`  ${uploadedAt}  ${key}`);
   }
   if (entries.length > argv.printLimit) {
      console.log(`  ...and ${entries.length - argv.printLimit} more`);
   }
}

// ---------------------------------------------------------------------------
// info (no deploy) — print file counts plus last deploy info
// ---------------------------------------------------------------------------

// Scope filter applies to current/orphans keys (top-level vs all). `expected`
// is always the raw entry count — it's a registry of patterns, not a file
// listing, and a glob like `.well-known/*` doesn't have a meaningful "scope"
// (it covers subdir files but lives as one registry entry). Showing the
// scope-filtered count was confusing because it conveyed neither the entry
// count nor the actual matched-file count.
function runInfo(argv) {
   const manifest = readManifest(argv);
   const scope = getScope(argv);
   const current = Object.keys(manifest.current).filter(scope.inScope).length;
   const orphaned = Object.keys(manifest.orphans).filter(scope.inScope).length;
   const expected = manifest.expected.length;
   const untracked = untrackedKeys(argv, manifest).length;
   console.log(`info: scope=${scope.label} current=${current} orphaned=${orphaned} expected=${expected} untracked=${untracked}`);
   if (manifest.deployDate) {
      console.log(`  last-deploy: ${manifest.deployDate}`);
      console.log(`  comment: ${manifest.deployComment ?? ''}`);
   }
}

// ---------------------------------------------------------------------------
// expect / unexpect (no deploy)
// ---------------------------------------------------------------------------

function runExpect(argv) {
   const manifest = readManifest(argv);
   const expected = new Set(manifest.expected);
   const added = new Set();
   for (const f of argv.patterns) {
      if (!expected.has(f)) {
         expected.add(f);
         added.add(f);
      }
   }
   // Remove newly expected entries (literal or wildcard) from current and
   // orphans so a key is tracked via only one mechanism. Matching covers the
   // glob case: `expect .well-known/*` also drops .well-known/foo etc.
   const matchesNewlyExpected = matcherFor([...added]);
   const current = Object.fromEntries(
      Object.entries(manifest.current).filter(([k]) => !matchesNewlyExpected(k)),
   );
   const orphans = Object.fromEntries(
      Object.entries(manifest.orphans).filter(([k]) => !matchesNewlyExpected(k)),
   );
   const currentRemoved = Object.keys(manifest.current).length - Object.keys(current).length;
   const orphansRemoved = Object.keys(manifest.orphans).length - Object.keys(orphans).length;

   writeManifest(argv, {
      ...manifest,
      current,
      orphans,
      expected: [...expected].sort(),
   });
   console.log(
      `expect: added=${added.size} total-expected=${expected.size}` +
      ` removed-from-current=${currentRemoved} removed-from-orphans=${orphansRemoved}` +
      `${argv.dryRun ? ' (DRY RUN)' : ''}`,
   );
   if (added.size > 0) {
      console.log(`  added: ${[...added].join(', ')}`);
   }
}

function runUnexpect(argv) {
   const manifest = readManifest(argv);
   const expected = new Set(manifest.expected);
   const removed = new Set();
   for (const f of argv.patterns) {
      if (expected.delete(f)) {
         removed.add(f);
      }
   }
   writeManifest(argv, { ...manifest, expected: [...expected].sort() });
   console.log(`unexpect: removed=${removed.size} total-expected=${expected.size}${argv.dryRun ? ' (DRY RUN)' : ''}`);
   if (removed.size > 0) {
      console.log(`  removed: ${[...removed].join(', ')}`);
   }
}

// ---------------------------------------------------------------------------
// prune (no deploy) — remove untracked S3 objects and expired orphans
// ---------------------------------------------------------------------------

async function runPrune(argv) {
   const manifest = readManifest(argv);
   // readManifest always seeds `expected` with the manifest key, so check the
   // other buckets to decide whether this looks like a never-deployed bucket.
   const hasData = Object.keys(manifest.current).length > 0
      || Object.keys(manifest.orphans).length > 0
      || manifest.expected.length > 1;
   if (!hasData) {
      console.error('prune: manifest is empty or missing — refusing to run. Deploy first, or seed expected entries with `expect`.');
      process.exit(1);
   }

   const orphans = new Map(Object.entries(manifest.orphans));
   const expired = findExpiredOrphans(orphans, argv.expirationDays, inScopeFor(argv));

   // Compute untracked against the unmodified manifest so expired orphans
   // (still tracked at this point) aren't double-counted as untracked.
   const untracked = untrackedKeys(argv, manifest);

   if (untracked.length === 0 && expired.length === 0) {
      console.log('prune: nothing to delete (no untracked files, no expired orphans)');
      return;
   }

   const deletedOrphans = deleteKeys(argv, expired);
   for (const key of deletedOrphans) {
      orphans.delete(key);
   }
   const deletedUntracked = deleteKeys(argv, untracked);

   if (deletedOrphans.length > 0) {
      writeManifest(argv, {
         ...manifest,
         orphans: Object.fromEntries(orphans),
      });
   }

   const dryRunTag = argv.dryRun ? ' (DRY RUN)' : '';
   console.log(
      `prune: deleted-untracked=${deletedUntracked.length}/${untracked.length}` +
      ` deleted-orphans=${deletedOrphans.length}/${expired.length}${dryRunTag}`,
   );
   printKeyList(deletedUntracked, 'deleted untracked:', argv.printLimit);
   printKeyList(deletedOrphans, 'deleted orphans:', argv.printLimit);
}

// ---------------------------------------------------------------------------
// yargs wiring
// ---------------------------------------------------------------------------

// Listed here (rather than derived from yargs internals) for the same
// reason as bash's COMMON_VALUE_FLAGS — keep the list explicit and easy
// to audit. Used by the shared suggestCommandTypo helper to walk argv
// past flag-value pairs when identifying a typo'd subcommand. Mirror any
// new value-taking option here.
const VALUE_FLAGS = new Set([
   '--prod', '--profile', '--region', '--manifest-key', '--print-limit',
   '--build-dir', '--cache-control', '--expiration-days', '--cf-distribution',
   '--comment',
]);

const addGlobalOpts = (y) => y
   .option('prod', { type: 'string', describe: 'Presence selects prod mode (test mode otherwise). Alias-name value is unused on the web side; kept symmetric with server.' })
   .option('profile', { type: 'string', describe: 'AWS CLI profile (falls back to QC_PROD_AWS_PROFILE; required)' })
   .option('region', { type: 'string', describe: 'AWS region (falls back to QC_PROD_AWS_REGION; required)' })
   .option('manifest-key', { type: 'string', default: '_build/manifest.json', describe: 'S3 key for the deploy manifest' })
   .option('dry-run', { type: 'boolean', default: false, describe: 'Log actions without executing them' })
   .option('print-limit', { type: 'number', default: 20, describe: 'Max file keys to print in listings (deploy, leaks, prune)' })
   .option('yes', { type: 'boolean', alias: 'y', default: false, describe: 'Bypass the prod-action confirmation prompt for destructive commands (deploy, bdeploy, prune, rollback).' });

// Constrains the command to the assets/aaguid/ key prefix only — local
// enumeration, bucket listing, and manifest reconciliation all skip
// anything outside that subtree. Takes precedence over --subdirs/--no-subdirs.
const addAaguidsOpt = (y) => y
   .option('aaguids', { type: 'boolean', default: false, describe: 'Limit scope to the assets/aaguid/ subtree (takes precedence over --subdirs).' });

// Used to detect typo'd commands that would otherwise be silently consumed by
// the default `$0 <bucket>` positional.
const COMMANDS = [
   'deploy', 'bdeploy', 'rollback', 'reset', 'bootstrap', 'manifest',
   'leaks', 'info', 'current', 'expect', 'unexpect', 'prune',
];

const deployBuilder = (y) => addAaguidsOpt(addGlobalOpts(y))
   .positional('bucket', { type: 'string', describe: 'Target S3 bucket' })
   .option('build-dir', { type: 'string', default: 'dist/web/browser', describe: 'Local directory to upload' })
   .option('subdirs', { type: 'boolean', default: true, describe: 'Upload files in subdirectories (default: true; use --no-subdirs for top-level only)' })
   .option('cache-control', { type: 'string', default: 'public, max-age=31536000, immutable', describe: 'Cache-Control header for uploaded files' })
   .option('expiration-days', { type: 'number', default: 30, describe: 'Days an orphan persists before deletion' })
   .option('cf-distribution', { type: 'string', describe: 'CloudFront distribution ID or ARN to invalidate (/*) after deploy. Omit to skip.' })
   .option('comment', { type: 'string', default: '', describe: 'Comment recorded in the manifest (only the latest is kept).' })
   .option('skip-validate', { type: 'boolean', default: false, describe: 'Break-glass: skip the pre-upload index.html validation (SRI, nonce, chunk checks). Only when you know the build is good.' })
   .check((argv) => {
      if (!Number.isFinite(argv.expirationDays) || argv.expirationDays < 0) {
         throw new Error('--expiration-days must be a non-negative integer');
      }
      try {
         if (!statSync(argv.buildDir).isDirectory()) {
            throw new Error('not a directory');
         }
      } catch {
         throw new Error(`--build-dir does not exist or is not a directory: ${argv.buildDir}`);
      }
      return true;
   });

// Commands that mutate prod and so require the confirmation gate. The bare
// `$0 <bucket>` invocation runs bdeploy, so map an empty command to it.
const DESTRUCTIVE_COMMANDS = new Set(['deploy', 'bdeploy', 'prune', 'rollback']);

// Global middleware runs before the matched command handler. Order matters:
// the prod confirmation (destructive + --prod only) comes first so the
// warning precedes any AWS work, then ensureAuth handles SSO login. Both
// previously lived in the bash wrapper / handlers; centralizing here keeps
// "warn, then authenticate, then act" ordering in one place.
async function preflight(argv) {
   const command = String(argv._[0] ?? 'bdeploy');
   if (argv.prod && DESTRUCTIVE_COMMANDS.has(command)) {
      const from = (command === 'deploy' || command === 'bdeploy')
         ? `\n      from:   ${relToRoot(argv.buildDir)}`
         : '';
      await confirmProdAction(argv, command, `bucket: ${argv.bucket}${from}`);
   }
   await ensureAuth(argv);
}

await yargs(hideBin(process.argv))
   .scriptName('deploy.mjs')
   .middleware(preflight)
   .command(
      '$0 <bucket>',
      'Build (production with --prod, else test) then deploy the SPA to S3 with orphan-based retention.',
      deployBuilder,
      runBdeploy,
   )
   .command(
      'deploy <bucket>',
      'Deploy the already-built SPA without rebuilding (validation still runs unless --skip-validate).',
      deployBuilder,
      runDeploy,
   )
   .command(
      'bdeploy <bucket>',
      'Build either production (--prod) or test, then deploy.',
      deployBuilder,
      runBdeploy,
   )
   .command(
      'rollback <bucket>',
      'Break-glass: delete the current S3 version of index.html so the previous version becomes current. Requires bucket versioning.',
      (y) => addGlobalOpts(y)
         .positional('bucket', { type: 'string', describe: 'Target S3 bucket' })
         .option('cf-distribution', { type: 'string', describe: 'CloudFront distribution ID or ARN to invalidate (/*) after rollback. Omit to skip.' })
         .option('comment', { type: 'string', default: '', describe: 'Comment recorded in the manifest (only the latest is kept).' }),
      runRollback,
   )
   .command(
      'reset <bucket>',
      'Clear the manifest (no file deletion in the bucket).',
      (y) => addGlobalOpts(y)
         .positional('bucket', { type: 'string', describe: 'Target S3 bucket' }),
      runReset,
   )
   .command(
      'bootstrap <bucket>',
      'Seed manifest.current from the existing bucket contents (no deploy). Resets orphans; leaves expected alone.',
      (y) => addAaguidsOpt(addGlobalOpts(y))
         .positional('bucket', { type: 'string', describe: 'Target S3 bucket' })
         .option('subdirs', { type: 'boolean', default: true, describe: 'Include files in subdirectories (default: true; use --no-subdirs for top-level only)' }),
      runBootstrap,
   )
   .command(
      'manifest <bucket>',
      'Print the current deploy manifest as JSON.',
      (y) => addGlobalOpts(y)
         .positional('bucket', { type: 'string', describe: 'Target S3 bucket' }),
      runManifest,
   )
   .command(
      'leaks <bucket>',
      'List S3 files not tracked by the manifest (no deploy).',
      (y) => addAaguidsOpt(addGlobalOpts(y))
         .positional('bucket', { type: 'string', describe: 'Target S3 bucket' })
         .option('subdirs', { type: 'boolean', default: true, describe: 'Consider files in subdirectories (default: true; use --no-subdirs for top-level only)' }),
      runLeaks,
   )
   .command(
      'info <bucket>',
      'Print files counts and last deploy information (no deploy).',
      (y) => addAaguidsOpt(addGlobalOpts(y))
         .positional('bucket', { type: 'string', describe: 'Target S3 bucket' })
         .option('subdirs', { type: 'boolean', default: true, describe: 'Count files in subdirectories (default: true; use --no-subdirs for top-level only)' }),
      runInfo,
   )
   .command(
      'current <bucket>',
      "Print the manifest's current files with their uploaded-at timestamps (no deploy).",
      (y) => addAaguidsOpt(addGlobalOpts(y))
         .positional('bucket', { type: 'string', describe: 'Target S3 bucket' })
         .option('subdirs', { type: 'boolean', default: true, describe: 'Include files in subdirectories (default: true; use --no-subdirs for top-level only)' }),
      runCurrent,
   )
   .command(
      'expect <bucket> <patterns..>',
      "Add S3 keys or glob patterns to the manifest's expected list; also removes any matching entries from current/orphans (no deploy).",
      (y) => addGlobalOpts(y)
         .positional('bucket', { type: 'string', describe: 'Target S3 bucket' })
         .positional('patterns', { type: 'string', array: true, describe: "S3 keys or globs, e.g. 'foo.txt' or '.well-known/*' (quote to avoid shell expansion)" }),
      runExpect,
   )
   .command(
      'unexpect <bucket> <patterns..>',
      "Remove keys or glob patterns from the manifest's expected list (no deploy). Does NOT repopulate current/orphans — run bootstrap if needed.",
      (y) => addGlobalOpts(y)
         .positional('bucket', { type: 'string', describe: 'Target S3 bucket' })
         .positional('patterns', { type: 'string', array: true, describe: 'S3 keys or globs to remove from expected (quote to avoid shell expansion)' }),
      runUnexpect,
   )
   .command(
      'prune <bucket>',
      'Remove S3 files not tracked by the manifest, plus orphans past the retention window (no deploy).',
      (y) => addAaguidsOpt(addGlobalOpts(y))
         .positional('bucket', { type: 'string', describe: 'Target S3 bucket' })
         .option('subdirs', { type: 'boolean', default: true, describe: 'Consider files in subdirectories (default: true; use --no-subdirs for top-level only)' })
         .option('expiration-days', { type: 'number', default: 30, describe: 'Days an orphan persists before deletion' })
         .check((argv) => {
            if (!Number.isFinite(argv.expirationDays) || argv.expirationDays < 0) {
               throw new Error('--expiration-days must be a non-negative integer');
            }
            return true;
         }),
      runPrune,
   )
   .demandCommand(1)
   .fail((msg, err) => {
      if (err) {
         throw err;
      }
      // Typos like `deploy.mjs leaked my-bucket` or `deploy.mjs --prod prod
      // inf my-bucket` get a "did you mean ...?" suggestion if they're close
      // to a known command. Returns silently if no typo is detected so the
      // bucket-positional rewrite below can still fire.
      suggestCommandTypo(msg, COMMANDS, VALUE_FLAGS);
      const rewritten = /Not enough non-option arguments/.test(msg ?? '')
         ? 'Error: you must specify the target S3 bucket. Run with --help for usage.'
         : msg;
      console.error(rewritten);
      process.exit(1);
   })
   .strict()
   .help()
   .version(false)
   .parseAsync();
