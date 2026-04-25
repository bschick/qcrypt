#!/usr/bin/env node
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
 *   - `current`  : files the most recent deploy uploaded
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
 * This script shells out to the `aws` CLI for all S3 operations, so it
 * picks up credentials the same way `aws` itself does: environment
 * variables (AWS_PROFILE, AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY,
 * AWS_REGION), `~/.aws/credentials`, or IAM role. Use --profile and
 * --region for explicit selection.
 *
 * ============================================================
 * Usage
 * ============================================================
 *
 *   deploy.mjs <bucket> [options]                     deploy the built SPA
 *   deploy.mjs deploy <bucket> [options]              same as above (explicit)
 *   deploy.mjs bootstrap <bucket>                     seed manifest.current from bucket
 *   deploy.mjs manifest <bucket>                      print the current manifest
 *   deploy.mjs leaks <bucket>                         list untracked bucket files
 *   deploy.mjs expect <bucket> <patterns..>           register expected files (globs ok)
 *   deploy.mjs unexpect <bucket> <patterns..>         remove expected entries
 *   deploy.mjs prune <bucket>                         remove untracked files
 *   deploy.mjs reset <bucket>                         clear the manifest (no file deletion)
 *   deploy.mjs rollback <bucket>                      delete latest index.html version (break-glass)
 *
 * Run any subcommand with --help for its option list. --dry-run logs
 * actions without performing them for every command.
 */

import { readdirSync, statSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import yargs from 'yargs/yargs';
import { hideBin } from 'yargs/helpers';

// ---------------------------------------------------------------------------
// Helpers (all take `argv` so they can be shared by every command)
// ---------------------------------------------------------------------------

function aws(argv, args, { input, allowFailure = false, readOnly = false } = {}) {
   const full = [];
   if (argv.profile) {
      full.push('--profile', argv.profile);
   }
   if (argv.region) {
      full.push('--region', argv.region);
   }
   full.push(...args);

   // Read-only calls (list, fetch manifest) always execute so --dry-run still
   // produces accurate diagnostics. Only mutating calls are suppressed.
   if (argv.dryRun && !readOnly) {
      console.log(`[dry-run] aws ${full.map(shellQuote).join(' ')}`);
      return { status: 0, stdout: '', stderr: '' };
   }

   const r = spawnSync('aws', full, {
      input,
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe'],
   });
   if (r.error) {
      console.error(`Failed to spawn aws: ${r.error.message}`);
      process.exit(1);
   }
   if (r.status !== 0 && !allowFailure) {
      process.stderr.write(r.stderr);
      const combined = `${r.stderr ?? ''}${r.stdout ?? ''}`;
      if (/NoSuchBucket/i.test(combined)) {
         console.error(`Error: bucket '${argv.bucket}' does not exist. Check the bucket name and your AWS account/profile.`);
      } else if (/AccessDenied|Access Denied/i.test(combined)) {
         console.error(
            `  - Verify the bucket name '${argv.bucket}' exists.\n` +
            '  - Verify your AWS profile / SSO session is authenticated to the right account.\n' +
            '  - Verify the role has the S3 permissions this command needs.',
         );
      } else {
         console.error(`aws ${args.join(' ')} failed (exit ${r.status})`);
      }
      process.exit(1);
   }
   return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}

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
   return { version: 1, current: [], orphans: {}, expected: [] };
}

function readManifest(argv) {
   const key = `s3://${argv.bucket}/${argv.manifestKey}`;
   const r = aws(argv, ['s3', 'cp', key, '-'], { allowFailure: true, readOnly: true });
   let manifest;
   if (r.status !== 0) {
      manifest = emptyManifest();
   } else {
      try {
         manifest = JSON.parse(r.stdout);
         manifest.current ??= [];
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
// Returns only top-level keys unless argv.includeSubdirs is true, matching
// the scope rule the deploy/prune commands use for uploading and removing.
function listBucket(argv) {
   const r = aws(argv, ['s3api', 'list-objects-v2', '--bucket', argv.bucket, '--output', 'json'], { readOnly: true });
   if (!r.stdout) {
      return [];
   }
   const parsed = JSON.parse(r.stdout);
   const keys = (parsed.Contents ?? []).map((o) => o.Key);
   return argv.includeSubdirs ? keys : keys.filter((k) => !k.includes('/'));
}

// POSIX single-quote a shell arg: safe wrap for anything containing spaces
// or shell metachars. Used only for the --dry-run log so previewed commands
// can be copy-pasted into a shell.
function shellQuote(arg) {
   if (arg === '' || /[^\w@%+=:,./-]/.test(arg)) {
      return `'${arg.replace(/'/g, `'\\''`)}'`;
   }
   return arg;
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

// Accept either a bare CloudFront distribution ID (e.g. <id>) or
// a full ARN (arn:aws:cloudfront::ACCT:distribution/<id>) and
// return the ID the CLI expects.
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
   let idSuffix = '';
   if (!argv.dryRun && r.stdout) {
      try {
         const parsed = JSON.parse(r.stdout);
         if (parsed.Invalidation?.Id) {
            idSuffix = ` id=${parsed.Invalidation.Id}`;
         }
      } catch {
         // Non-JSON stdout; skip the id suffix silently.
      }
   }
   console.log(`  cloudfront: created /* invalidation for distribution ${distId}${idSuffix}${argv.dryRun ? ' (DRY RUN)' : ''}`);
}

// "Is this key tracked by the manifest?" — union of current, orphans keys,
// and the expected list (with glob support). readManifest guarantees the
// manifest's own key is in expected, so no special case is needed here.
function trackedMatcher(manifest) {
   const literals = new Set([
      ...manifest.current,
      ...Object.keys(manifest.orphans),
   ]);
   const expectedMatch = matcherFor(manifest.expected);
   return (key) => literals.has(key) || expectedMatch(key);
}

function printUntracked(untracked, heading, limit) {
   if (untracked.length === 0) {
      return;
   }
   console.log(`  ${heading}`);
   for (const k of untracked.slice(0, limit)) {
      console.log(`    ${k}`);
   }
   if (untracked.length > limit) {
      console.log(`    ...and ${untracked.length - limit} more`);
   }
}

// ---------------------------------------------------------------------------
// deploy (default command)
// ---------------------------------------------------------------------------

function runDeploy(argv) {
   // 1. Enumerate the local build.
   const files = collectLocalFiles(argv.buildDir, argv.includeSubdirs);
   const newKeys = new Set(files.map((f) => f.relKey));
   if (newKeys.size === 0) {
      console.error(`No files found under ${argv.buildDir}${argv.includeSubdirs ? '' : ' (top-level only)'}`);
      process.exit(1);
   }

   // 2. Upload everything except index.html, then index.html last.
   // Known OS/editor metadata files are excluded (matches METADATA_SKIP_RE
   // used locally) while legitimate dotdirs like `.well-known/` are kept.
   // `--exact-timestamps` forces re-upload when sizes match but mtimes differ,
   // covering edge cases where build tooling regenerates files with identical
   // sizes but different content (e.g. Rolldown's chunk naming isn't always
   // pure content-hash).
   const bulkArgs = [
      's3', 'sync', argv.buildDir, `s3://${argv.bucket}/`,
      '--exact-timestamps',
      '--exclude', 'index.html',
      '--exclude', '.DS_Store', '--exclude', '*/.DS_Store',
      '--exclude', '._*', '--exclude', '*/._*',
      '--exclude', 'Thumbs.db', '--exclude', '*/Thumbs.db',
      '--exclude', 'desktop.ini', '--exclude', '*/desktop.ini',
      '--cache-control', argv.cacheControl,
   ];
   if (!argv.includeSubdirs) {
      bulkArgs.push('--exclude', '*/*');
   }
   aws(argv, bulkArgs);

   if (newKeys.has('index.html')) {
      aws(argv, [
         's3', 'cp', join(argv.buildDir, 'index.html'),
         `s3://${argv.bucket}/index.html`,
         '--cache-control', argv.cacheControl,
      ]);
   }

   // 3. Reconcile the manifest. Only in-scope keys are reconciled — out-of-scope
   //    entries (subdir files when --include-subdirs is off) are preserved
   //    verbatim so a top-level deploy doesn't mis-orphan subdir state a
   //    recursive bootstrap/deploy put there.
   const manifest = readManifest(argv);
   const manifestCurrent = new Set(manifest.current);
   const manifestOrphans = new Map(Object.entries(manifest.orphans));
   const inScope = (k) => argv.includeSubdirs || !k.includes('/');

   const now = new Date().toISOString();
   const newCurrent = new Set(newKeys);
   for (const key of manifestCurrent) {
      if (!inScope(key)) {
         newCurrent.add(key);
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
   for (const key of manifestCurrent) {
      if (inScope(key) && !newKeys.has(key) && !orphans.has(key)) {
         orphans.set(key, now);
      }
   }

   // 4. Delete expired orphans (in-scope only — we don't touch out-of-scope).
   const cutoffMs = Date.now() - argv.expirationDays * 86400 * 1000;
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
   const deletedFromS3 = [];
   for (const key of expired) {
      const r = aws(argv, ['s3', 'rm', `s3://${argv.bucket}/${key}`], { allowFailure: true });
      if (r.status === 0) {
         orphans.delete(key);
         deletedFromS3.push(key);
      }
   }

   // 5. Write the updated manifest.
   const deployCount = (manifest.deployCount ?? 0) + 1;
   writeManifest(argv, {
      version: 1,
      lastDeploy: now,
      deployCount,
      current: [...newCurrent].sort(),
      orphans: Object.fromEntries(orphans),
      expected: [...manifest.expected].sort(),
   });

   // 6. Leak detection: compare S3 listing against tracked sets.
   // listBucket respects --include-subdirs for scope.
   const isTracked = trackedMatcher({
      current: [...newCurrent],
      orphans: Object.fromEntries(orphans),
      expected: manifest.expected,
   });
   const untracked = listBucket(argv).filter((k) => !isTracked(k));

   // 7. Summary.
   const newlyOrphaned = [...orphans.keys()].filter((k) => !manifestOrphans.has(k));
   const dryRunTag = argv.dryRun ? ' (DRY RUN — no writes)' : '';
   console.log(
      `deploy #${deployCount}: uploaded=${newKeys.size} newly-orphaned=${newlyOrphaned.length}` +
      ` tracked-orphans=${orphans.size} expired-deleted=${deletedFromS3.length}` +
      ` untracked=${untracked.length}${dryRunTag}`,
   );
   if (deletedFromS3.length > 0) {
      console.log(`  deleted: ${deletedFromS3.join(', ')}`);
   }
   printUntracked(newlyOrphaned, 'newly orphaned (retention clock starts now):', argv.printLimit);
   printUntracked(untracked, "untracked in bucket (use 'expect' or 'unexpect' to update, 'prune' to remove):", argv.printLimit);
   invalidateCloudFront(argv);
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
// The manifest is intentionally NOT rolled back here. The next real deploy
// reconciles against whichever manifest state is current, and any lingering
// drift (chunks from the aborted deploy) is handled by the normal orphan
// clock.
function runRollback(argv) {
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
// --include-subdirs for scope.
function runBootstrap(argv) {
   const manifest = readManifest(argv);
   // Anything already covered by `expected` (including the manifest file, which
   // readManifest always seeds into expected) is kept out of `current` so each
   // key is only tracked once. Running `expect` before or after bootstrap
   // yields the same end state.
   const isExpected = matcherFor(manifest.expected);
   const current = listBucket(argv).filter((k) => !isExpected(k)).sort();
   // `lastDeploy` and `deployCount` are deploy-only fields. Preserve whatever
   // was there (or leave unset if the bucket has never seen a real deploy).
   const next = {
      version: 1,
      current,
      orphans: {},
      expected: [...manifest.expected].sort(),
   };
   if (manifest.lastDeploy) {
      next.lastDeploy = manifest.lastDeploy;
   }
   if (manifest.deployCount !== undefined) {
      next.deployCount = manifest.deployCount;
   }
   writeManifest(argv, next);
   console.log(
      `bootstrap: current=${current.length} expected-retained=${manifest.expected.length}` +
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
   const manifest = readManifest(argv);
   const isTracked = trackedMatcher(manifest);
   const untracked = listBucket(argv).filter((k) => !isTracked(k));
   console.log(`leaks: untracked=${untracked.length}`);
   printUntracked(untracked, 'untracked in bucket:', argv.printLimit);
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
   const current = manifest.current.filter((k) => !matchesNewlyExpected(k));
   const orphans = Object.fromEntries(
      Object.entries(manifest.orphans).filter(([k]) => !matchesNewlyExpected(k)),
   );
   const currentRemoved = manifest.current.length - current.length;
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
// prune (no deploy) — remove untracked S3 objects
// ---------------------------------------------------------------------------

function runPrune(argv) {
   const manifest = readManifest(argv);
   // readManifest always seeds `expected` with the manifest key, so check the
   // other buckets to decide whether this looks like a never-deployed bucket.
   const hasData = manifest.current.length > 0
      || Object.keys(manifest.orphans).length > 0
      || manifest.expected.length > 1;
   if (!hasData) {
      console.error('prune: manifest is empty or missing — refusing to run. Deploy first, or seed expected entries with `expect`.');
      process.exit(1);
   }

   const isTracked = trackedMatcher(manifest);
   const untracked = listBucket(argv).filter((k) => !isTracked(k));
   if (untracked.length === 0) {
      console.log('prune: no untracked files found');
      return;
   }

   const deleted = [];
   for (const key of untracked) {
      const r = aws(argv, ['s3', 'rm', `s3://${argv.bucket}/${key}`], { allowFailure: true });
      if (r.status === 0) {
         deleted.push(key);
      }
   }
   console.log(`prune: deleted=${deleted.length}/${untracked.length}${argv.dryRun ? ' (DRY RUN)' : ''}`);
   printUntracked(deleted, 'deleted:', argv.printLimit);
}

// ---------------------------------------------------------------------------
// yargs wiring
// ---------------------------------------------------------------------------

const addGlobalOpts = (y) => y
   .option('profile', { type: 'string', describe: 'AWS CLI profile (defaults to env/config)' })
   .option('region', { type: 'string', describe: 'AWS region (defaults to env/config)' })
   .option('manifest-key', { type: 'string', default: '_build/manifest.json', describe: 'S3 key for the deploy manifest' })
   .option('dry-run', { type: 'boolean', default: false, describe: 'Log actions without executing them' })
   .option('print-limit', { type: 'number', default: 20, describe: 'Max file keys to print in listings (deploy, leaks, prune)' });

const deployBuilder = (y) => addGlobalOpts(y)
   .positional('bucket', { type: 'string', describe: 'Target S3 bucket' })
   .option('build-dir', { type: 'string', default: 'dist/web/browser', describe: 'Local directory to upload' })
   .option('include-subdirs', { type: 'boolean', default: false, describe: 'Upload files in subdirectories (default: top-level only)' })
   .option('cache-control', { type: 'string', default: 'public, max-age=31536000, immutable', describe: 'Cache-Control header for uploaded files' })
   .option('expiration-days', { type: 'number', default: 30, describe: 'Days an orphan persists before deletion' })
   .option('cf-distribution', { type: 'string', describe: 'CloudFront distribution ID or ARN to invalidate (/*) after deploy. Omit to skip.' })
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

yargs(hideBin(process.argv))
   .scriptName('deploy.mjs')
   .command(
      '$0 <bucket>',
      'Deploy the built SPA to S3 with orphan-based retention.',
      deployBuilder,
      runDeploy,
   )
   .command(
      'deploy <bucket>',
      'Deploy the built SPA (explicit form of the default command).',
      deployBuilder,
      runDeploy,
   )
   .command(
      'rollback <bucket>',
      'Break-glass: delete the current S3 version of index.html so the previous version becomes current. Requires bucket versioning.',
      (y) => addGlobalOpts(y)
         .positional('bucket', { type: 'string', describe: 'Target S3 bucket' })
         .option('cf-distribution', { type: 'string', describe: 'CloudFront distribution ID or ARN to invalidate (/*) after rollback. Omit to skip.' }),
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
      (y) => addGlobalOpts(y)
         .positional('bucket', { type: 'string', describe: 'Target S3 bucket' })
         .option('include-subdirs', { type: 'boolean', default: false, describe: 'Include files in subdirectories (default: top-level only)' }),
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
      (y) => addGlobalOpts(y)
         .positional('bucket', { type: 'string', describe: 'Target S3 bucket' })
         .option('include-subdirs', { type: 'boolean', default: false, describe: 'Also consider files in subdirectories (default: top-level only)' }),
      runLeaks,
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
      'Remove S3 files not tracked by the manifest (no deploy).',
      (y) => addGlobalOpts(y)
         .positional('bucket', { type: 'string', describe: 'Target S3 bucket' })
         .option('include-subdirs', { type: 'boolean', default: false, describe: 'Also consider files in subdirectories (default: top-level only)' }),
      runPrune,
   )
   .demandCommand(1)
   .fail((msg, err, y) => {
      if (err) {
         throw err;
      }
      const rewritten = /Not enough non-option arguments/.test(msg ?? '')
         ? 'Error: you must specify the target S3 bucket. Run with --help for usage.'
         : msg;
      console.error(rewritten);
      process.exit(1);
   })
   .strict()
   .help()
   .version(false)
   .parseSync();
