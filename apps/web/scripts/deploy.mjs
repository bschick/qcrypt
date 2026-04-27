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
 * Web deploys are always prod-mode. --prod <alias> is required (the alias
 * value is currently unused on the web side — there's no Lambda alias to
 * track — but kept symmetric with the server script so the wrappers can
 * share auth resolution logic).
 *
 * Every `aws` invocation is called with an explicit --profile and --region
 * resolved at startup. Resolution order (per option):
 *
 *   1. CLI flag (--profile / --region) if given
 *   2. env var QC_PROD_AWS_PROFILE / QC_PROD_AWS_REGION
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

import { readdirSync, statSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import yargs from 'yargs/yargs';
import { hideBin } from 'yargs/helpers';
import {
   aws as awsBase,
   resolveAwsCreds,
   suggestCommandTypo,
} from '../../../scripts/deploy-common.mjs';

// ---------------------------------------------------------------------------
// Helpers (all take `argv` so they can be shared by every command)
// ---------------------------------------------------------------------------

// Web is always prod-mode. Resolves to QC_PROD_AWS_* env vars (or --profile
// / --region overrides) via the shared resolver, after enforcing the
// always-prod precondition.
function resolveCreds(argv) {
   if (!argv.prod) {
      console.error('Web deploys are always prod-mode. Pass --prod <alias> (e.g. --prod prod).');
      process.exit(1);
   }
   return resolveAwsCreds(argv, 'QC_PROD_AWS_PROFILE', 'QC_PROD_AWS_REGION');
}

// Wrapper around the shared aws() that ensures creds are resolved (so
// every command path gets the always-prod check) before delegating.
function aws(argv, args, opts) {
   resolveCreds(argv);
   return awsBase(argv, args, opts);
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
// Returns only top-level keys unless argv.subdirs is true, matching
// the scope rule the deploy/prune commands use for uploading and removing.
function listBucket(argv) {
   const r = aws(argv, ['s3api', 'list-objects-v2', '--bucket', argv.bucket, '--output', 'json'], { readOnly: true });
   if (!r.stdout) {
      return [];
   }
   const parsed = JSON.parse(r.stdout);
   const keys = (parsed.Contents ?? []).map((o) => o.Key);
   return argv.subdirs ? keys : keys.filter((k) => !k.includes('/'));
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

// Single source of truth for the subdirs scope rule. Top-level only
// unless --subdirs is set; used by manifest reconciliation and by
// listBucket-derived filters.
function inScopeFor(argv) {
   return (k) => argv.subdirs || !k.includes('/');
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

// Sequentially `aws s3 rm` each key, returning the subset that succeeded.
// Failures are tolerated so one bad key doesn't abort the whole batch.
function deleteKeys(argv, keys) {
   const deleted = [];
   for (const key of keys) {
      const r = aws(argv, ['s3', 'rm', `s3://${argv.bucket}/${key}`], { allowFailure: true });
      if (r.status === 0) {
         deleted.push(key);
      }
   }
   return deleted;
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
   const files = collectLocalFiles(argv.buildDir, argv.subdirs);
   const newKeys = new Set(files.map((f) => f.relKey));
   if (newKeys.size === 0) {
      console.error(`No files found under ${argv.buildDir}${argv.subdirs ? '' : ' (top-level only)'}`);
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
      '--no-progress',
      '--exclude', 'index.html',
      '--exclude', '.DS_Store', '--exclude', '*/.DS_Store',
      '--exclude', '._*', '--exclude', '*/._*',
      '--exclude', 'Thumbs.db', '--exclude', '*/Thumbs.db',
      '--exclude', 'desktop.ini', '--exclude', '*/desktop.ini',
      '--cache-control', argv.cacheControl,
   ];
   if (!argv.subdirs) {
      bulkArgs.push('--exclude', '*/*');
   }
   const bulkResult = aws(argv, bulkArgs);

   // `aws s3 sync --no-progress` prints one "upload: ..." line per transferred
   // file (without the carriage-return progress overlay). Match anchored to
   // start-of-line / \r / \n so we'd still count correctly if the flag were
   // ever dropped or a CLI variant left the progress overlay intact.
   const countUploads = (out) => (out ?? '').match(/(?:^|[\r\n])upload: /g)?.length ?? 0;
   let totalUploads = countUploads(bulkResult.stdout);

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
      totalUploads += countUploads(indexResult.stdout);
   }

   const manifest = readManifest(argv);
   const manifestOrphans = new Map(Object.entries(manifest.orphans));

   // 3. Short-circuit on a true no-op: nothing transferred ⇒ nothing to
   //    reconcile, no manifest rewrite, no invalidation. Still scan for
   //    leaks so untracked-in-bucket reports continue to surface.
   if (!argv.dryRun && totalUploads === 0) {
      const untracked = untrackedKeys(argv, manifest);
      console.log(`deploy #${manifest.deployCount ?? 0}: no changes  untracked=${untracked.length}`);
      printUntracked(untracked, "untracked in bucket (use 'expect' or 'unexpect' to update, 'prune' to remove):", argv.printLimit);
      return;
   }

   // 4. Reconcile the manifest. Only in-scope keys are reconciled — out-of-scope
   //    entries (subdir files when --subdirs is off) are preserved
   //    verbatim so a top-level deploy doesn't mis-orphan subdir state a
   //    recursive bootstrap/deploy put there.
   const manifestCurrent = new Set(manifest.current);
   const inScope = inScopeFor(argv);

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
      current: [...newCurrent].sort(),
      orphans: Object.fromEntries(orphans),
      expected: [...manifest.expected].sort(),
   });

   // 7. Leak detection: compare S3 listing against tracked sets.
   // listBucket respects --subdirs for scope.
   const untracked = untrackedKeys(argv, {
      current: [...newCurrent],
      orphans: Object.fromEntries(orphans),
      expected: manifest.expected,
   });

   // 8. Summary.
   const newlyOrphaned = [...orphans.keys()].filter((k) => !manifestOrphans.has(k));
   const dryRunTag = argv.dryRun ? ' (DRY RUN — no writes)' : '';
   console.log(
      `deploy #${deployCount}: uploaded=${totalUploads} newly-orphaned=${newlyOrphaned.length}` +
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
// bdeploy — build then deploy
// ---------------------------------------------------------------------------

// Convenience wrapper: runs `pnpm build:web` (always — there's no
// minification toggle on the web side), then defers to runDeploy with the
// same argv so all deploy options (including --comment) flow through.
function runBdeploy(argv) {
   const cmd = 'pnpm';
   const args = ['build:web'];
   if (argv.dryRun) {
      console.log(`[dry-run] ${cmd} ${args.join(' ')}`);
   } else {
      const r = spawnSync(cmd, args, { stdio: 'inherit' });
      if (r.error) {
         console.error(`Failed to spawn ${cmd}: ${r.error.message}`);
         process.exit(1);
      }
      if (r.status !== 0) {
         console.error(`bdeploy: ${cmd} ${args.join(' ')} failed (exit ${r.status})`);
         process.exit(r.status ?? 1);
      }
   }
   runDeploy(argv);
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
   const current = listBucket(argv).filter((k) => !isExpected(k)).sort();
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
   const untracked = untrackedKeys(argv, readManifest(argv));
   console.log(`leaks: untracked=${untracked.length}`);
   printUntracked(untracked, 'untracked in bucket:', argv.printLimit);
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
   const inScope = inScopeFor(argv);
   const current = manifest.current.filter(inScope).length;
   const orphaned = Object.keys(manifest.orphans).filter(inScope).length;
   const expected = manifest.expected.length;
   const untracked = untrackedKeys(argv, manifest).length;
   const scope = argv.subdirs ? 'all' : 'top-level';
   console.log(`info: scope=${scope} current=${current} orphaned=${orphaned} expected=${expected} untracked=${untracked}`);
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
// prune (no deploy) — remove untracked S3 objects and expired orphans
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
   printUntracked(deletedUntracked, 'deleted untracked:', argv.printLimit);
   printUntracked(deletedOrphans, 'deleted orphans:', argv.printLimit);
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
   .option('prod', { type: 'string', describe: 'Required. Alias name (currently unused on the web side; kept symmetric with server). Web is always prod-mode.' })
   .option('profile', { type: 'string', describe: 'AWS CLI profile (falls back to QC_PROD_AWS_PROFILE; required)' })
   .option('region', { type: 'string', describe: 'AWS region (falls back to QC_PROD_AWS_REGION; required)' })
   .option('manifest-key', { type: 'string', default: '_build/manifest.json', describe: 'S3 key for the deploy manifest' })
   .option('dry-run', { type: 'boolean', default: false, describe: 'Log actions without executing them' })
   .option('print-limit', { type: 'number', default: 20, describe: 'Max file keys to print in listings (deploy, leaks, prune)' });

// Used to detect typo'd commands that would otherwise be silently consumed by
// the default `$0 <bucket>` positional.
const COMMANDS = [
   'deploy', 'bdeploy', 'rollback', 'reset', 'bootstrap', 'manifest',
   'leaks', 'info', 'expect', 'unexpect', 'prune',
];

const deployBuilder = (y) => addGlobalOpts(y)
   .positional('bucket', { type: 'string', describe: 'Target S3 bucket' })
   .option('build-dir', { type: 'string', default: 'dist/web/browser', describe: 'Local directory to upload' })
   .option('subdirs', { type: 'boolean', default: false, describe: 'Upload files in subdirectories (default: top-level only)' })
   .option('cache-control', { type: 'string', default: 'public, max-age=31536000, immutable', describe: 'Cache-Control header for uploaded files' })
   .option('expiration-days', { type: 'number', default: 30, describe: 'Days an orphan persists before deletion' })
   .option('cf-distribution', { type: 'string', describe: 'CloudFront distribution ID or ARN to invalidate (/*) after deploy. Omit to skip.' })
   .option('comment', { type: 'string', default: '', describe: 'Comment recorded in the manifest (only the latest is kept).' })
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
      'bdeploy <bucket>',
      'Run `pnpm build:web`, then deploy.',
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
      (y) => addGlobalOpts(y)
         .positional('bucket', { type: 'string', describe: 'Target S3 bucket' })
         .option('subdirs', { type: 'boolean', default: false, describe: 'Include files in subdirectories (default: top-level only)' }),
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
         .option('subdirs', { type: 'boolean', default: false, describe: 'Also consider files in subdirectories (default: top-level only)' }),
      runLeaks,
   )
   .command(
      'info <bucket>',
      'Print files counts and last deploy information (no deploy).',
      (y) => addGlobalOpts(y)
         .positional('bucket', { type: 'string', describe: 'Target S3 bucket' })
         .option('subdirs', { type: 'boolean', default: false, describe: 'Also count files in subdirectories (default: top-level only)' }),
      runInfo,
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
      (y) => addGlobalOpts(y)
         .positional('bucket', { type: 'string', describe: 'Target S3 bucket' })
         .option('subdirs', { type: 'boolean', default: false, describe: 'Also consider files in subdirectories (default: top-level only)' })
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
   .parseSync();
