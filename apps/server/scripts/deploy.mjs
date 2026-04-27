#!/usr/bin/env node
/**
 * deploy.mjs
 *
 * Uploads a built Lambda function (dist/server/index.zip) to AWS, with
 * optional version-publish + alias bump for prod.
 *
 * ============================================================
 * Why this script exists
 * ============================================================
 *
 * AWS Lambda already gives us per-version metadata (Description,
 * LastModified) and a moveable alias, so we don't need a separate
 * S3 manifest the way the SPA deploy does. The script's job is just to
 * orchestrate `update-function-code` + `publish-version` + `update-alias`
 * in the right order, with the right account / alias semantics for our
 * test vs prod split.
 *
 * Test mode (default): update-function-code only. The function's $LATEST
 * gets the new code; nothing is published or aliased. The test env points
 * its API Gateway / etc. at $LATEST so the change is live immediately.
 *
 * Prod mode (--prod <alias>): update-function-code, then publish-version
 * with the supplied --comment as the version Description, then update-alias
 * to point <alias> at the new version. Prod traffic flows through the
 * alias, so the bump is what actually swaps the live code.
 *
 * `bdeploy` is `pnpm build:server:min` (or `build:server` with --no-min)
 * followed by `deploy`, so a one-liner can build and ship.
 *
 * ============================================================
 * AWS auth
 * ============================================================
 *
 * Every `aws` invocation is called with an explicit --profile and --region
 * resolved at startup. Resolution order (per option):
 *
 *   1. CLI flag (--profile / --region) if given
 *   2. env var QC_PROD_AWS_PROFILE / QC_PROD_AWS_REGION when --prod is set
 *      else QC_TEST_AWS_PROFILE / QC_TEST_AWS_REGION
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
 *   deploy.mjs [options]                    deploy (default)
 *   deploy.mjs deploy [options]             same as above (explicit)
 *   deploy.mjs bdeploy [options]            build then deploy
 *   deploy.mjs rollback [options]           bump alias back a version (--prod only)
 *   deploy.mjs info [options]               show $LATEST status; with --prod, also list versions + alias
 *
 * Run any subcommand with --help for its option list. --dry-run logs
 * actions without performing them for every command.
 */

import { statSync } from 'node:fs';
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
// Helpers
// ---------------------------------------------------------------------------

// Pick the env-var pair for AWS profile/region — prod-mode uses QC_PROD_*,
// test-mode uses QC_TEST_*. The shared resolver enforces "explicit profile
// / region required" semantics; this wrapper just hands it the names.
function resolveCreds(argv) {
   const prefix = isProd(argv) ? 'QC_PROD' : 'QC_TEST';
   return resolveAwsCreds(argv, `${prefix}_AWS_PROFILE`, `${prefix}_AWS_REGION`);
}

// Wrapper around the shared aws() that ensures creds are resolved (and
// memoized on argv) before the shared helper runs. Keeps every call path
// honoring the prod/test env-var split without each runX needing to
// remember to call resolveCreds first.
function aws(argv, args, opts) {
   resolveCreds(argv);
   return awsBase(argv, args, opts);
}

function isProd(argv) {
   return Boolean(argv.prod);
}

// Unwraps argv.prod (the alias name). Caller must verify isProd first;
// this throws if prod-mode isn't active so a logic bug surfaces loudly
// rather than passing an empty string into update-alias.
function aliasName(argv) {
   if (!isProd(argv)) {
      throw new Error('aliasName: called outside prod-mode');
   }
   return argv.prod;
}

// Returns the alias's full descriptor ({FunctionVersion, Description,
// AliasArn, ...}), or null if the alias doesn't exist (first-time deploy).
// Other failures bubble up.
function getAlias(argv, alias) {
   const r = aws(argv, [
      'lambda', 'get-alias',
      '--function-name', argv.lambda,
      '--name', alias,
      '--output', 'json',
   ], { readOnly: true, allowFailure: true });
   if (r.status !== 0) {
      const stderr = r.stderr ?? '';
      if (/ResourceNotFoundException/i.test(stderr)) {
         return null;
      }
      process.stderr.write(stderr);
      console.error(`Failed to read alias ${alias} on ${argv.lambda}.`);
      process.exit(1);
   }
   return JSON.parse(r.stdout || '{}');
}

// Convenience accessor preserved for the rollback path that only needs the
// version pointer.
function getAliasVersion(argv, alias) {
   return getAlias(argv, alias)?.FunctionVersion ?? null;
}

// Returns $LATEST's configuration (most importantly LastModified and
// CodeSha256) — the function-level "what's deployed right now to test"
// signal. Updates to the function code or config bump LastModified;
// publish-version alone does not.
//
// Uses allowFailure to surface the lambda-specific hint when the function
// name itself is wrong — a common first-time-misconfig case. Other
// failures bubble through with the shared aws()'s generic auth hints.
function getFunctionConfig(argv) {
   const r = aws(argv, [
      'lambda', 'get-function-configuration',
      '--function-name', argv.lambda,
      '--output', 'json',
   ], { readOnly: true, allowFailure: true });
   if (r.status !== 0) {
      process.stderr.write(r.stderr);
      if (/ResourceNotFoundException/i.test(r.stderr ?? '')) {
         console.error(`Error: Lambda '${argv.lambda}' not found. Check --lambda and your AWS account/profile.`);
      } else {
         console.error(`aws lambda get-function-configuration failed (exit ${r.status})`);
      }
      process.exit(1);
   }
   return JSON.parse(r.stdout || '{}');
}

// Returns published versions newest-first. AWS CLI v2 auto-paginates by
// default so a single call suffices. `$LATEST` is filtered out — it's
// always present but isn't a publishable version that the alias can target.
function listVersions(argv) {
   const r = aws(argv, [
      'lambda', 'list-versions-by-function',
      '--function-name', argv.lambda,
      '--output', 'json',
   ], { readOnly: true });
   const parsed = JSON.parse(r.stdout || '{}');
   const versions = parsed.Versions ?? [];
   return versions
      .filter((v) => v.Version !== '$LATEST')
      .sort((a, b) => parseInt(b.Version, 10) - parseInt(a.Version, 10));
}

function runBuild(argv) {
   const cmd = 'pnpm';
   const args = argv.noMin ? ['build:server'] : ['build:server:min'];
   if (argv.dryRun) {
      console.log(`[dry-run] ${cmd} ${args.join(' ')}`);
      return;
   }
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

// ---------------------------------------------------------------------------
// deploy (default command)
// ---------------------------------------------------------------------------

function runDeploy(argv) {
   const zipPath = join(argv.buildDir, 'index.zip');
   try {
      if (!statSync(zipPath).isFile()) {
         throw new Error('not a file');
      }
   } catch {
      console.error(`Deploy artifact not found: ${zipPath}. Did you build first (pnpm build:server[:min])?`);
      process.exit(1);
   }

   // 1. Upload code. Captures CodeSha256 for the summary line so it's easy
   // to confirm the artifact actually changed on the function.
   const updateResult = aws(argv, [
      'lambda', 'update-function-code',
      '--function-name', argv.lambda,
      '--zip-file', `fileb://${zipPath}`,
      '--output', 'json',
   ]);
   let codeSha = '';
   if (!argv.dryRun) {
      try {
         codeSha = (JSON.parse(updateResult.stdout || '{}').CodeSha256 ?? '').slice(0, 12);
      } catch {
         // Non-JSON stdout; leave codeSha blank.
      }
   }

   // 1.5 Wait for the code update to settle. UpdateFunctionCode is async
   // — the function transitions through `LastUpdateStatus=InProgress`
   // before `Successful`. In prod-mode this also avoids the
   // ResourceConflictException PublishVersion / UpdateAlias would hit if
   // called during that window. In test-mode there's no follow-up call,
   // but waiting still gives the user a clear "deploy is live" signal at
   // exit instead of returning while the function is still updating.
   // The CLI's `lambda wait function-updated` waiter polls (default 5s ×
   // 60 attempts) until LastUpdateStatus is Successful (or fails loudly).
   if (!argv.dryRun) {
      console.log(`deploy: waiting for ${argv.lambda} to finish updating...`);
   }
   aws(argv, [
      'lambda', 'wait', 'function-updated',
      '--function-name', argv.lambda,
   ]);

   const dryRunTag = argv.dryRun ? ' (DRY RUN)' : '';
   if (!isProd(argv)) {
      console.log(`deploy: lambda=${argv.lambda} code-sha=${codeSha}${dryRunTag}`);
      return;
   }

   const alias = aliasName(argv);

   // 2. Publish the just-uploaded code as a numbered version. The
   // --description IS the comment we surface in `info` listings.
   const publishResult = aws(argv, [
      'lambda', 'publish-version',
      '--function-name', argv.lambda,
      '--description', argv.comment,
      '--output', 'json',
   ]);
   let newVersion = '';
   if (!argv.dryRun) {
      try {
         newVersion = JSON.parse(publishResult.stdout || '{}').Version ?? '';
      } catch {
         // Non-JSON stdout; leave blank — we'll exit on the alias step if
         // we genuinely have no version to point at.
      }
   }
   if (!argv.dryRun && !newVersion) {
      console.error('deploy: publish-version did not return a Version; aborting before alias bump.');
      process.exit(1);
   }

   // 3. Bump the alias. Dry-run uses <NEW> as a placeholder so the logged
   // command is readable rather than `--function-version ` with an empty arg.
   // Alias description is hard-coded — argv.comment is recorded on the
   // version (above), and copying it onto the alias would just duplicate
   // the same text. The alias-level description tracks what kind of move
   // was last made ("new deploy" vs "rolled back").
   aws(argv, [
      'lambda', 'update-alias',
      '--function-name', argv.lambda,
      '--name', alias,
      '--function-version', newVersion || '<NEW>',
      '--description', 'new deploy',
      '--output', 'json',
   ]);

   console.log(`deploy: lambda=${argv.lambda} code-sha=${codeSha} version=${newVersion || '<NEW>'} alias=${alias}${dryRunTag}`);
}

// ---------------------------------------------------------------------------
// bdeploy — build then deploy
// ---------------------------------------------------------------------------

function runBdeploy(argv) {
   runBuild(argv);
   runDeploy(argv);
}

// ---------------------------------------------------------------------------
// rollback (prod-only) — move alias back a version
// ---------------------------------------------------------------------------

// Without --version: targets the version immediately preceding the current
// alias target. With --version: targets exactly that version (validated
// against the function's published versions).
//
// Doesn't delete or modify any version — only moves the alias. Re-deploy or
// a forward `update-alias` reverses the rollback at any time.
function runRollback(argv) {
   if (!isProd(argv)) {
      console.error('rollback: requires --prod <alias>.');
      process.exit(1);
   }
   const alias = aliasName(argv);
   const versions = listVersions(argv);
   if (versions.length === 0) {
      console.error(`rollback: function ${argv.lambda} has no published versions.`);
      process.exit(1);
   }

   const oldVersion = getAliasVersion(argv, alias);
   let target;
   if (argv.version) {
      target = argv.version;
      if (!versions.some((v) => v.Version === target)) {
         console.error(`rollback: version ${target} not found for function ${argv.lambda}.`);
         process.exit(1);
      }
   } else {
      if (!oldVersion) {
         console.error(`rollback: alias ${alias} doesn't exist on ${argv.lambda}; pass --version explicitly.`);
         process.exit(1);
      }
      const idx = versions.findIndex((v) => v.Version === oldVersion);
      if (idx < 0 || idx >= versions.length - 1) {
         console.error(`rollback: no version older than ${oldVersion}; nothing to roll back to.`);
         process.exit(1);
      }
      target = versions[idx + 1].Version;
   }

   aws(argv, [
      'lambda', 'update-alias',
      '--function-name', argv.lambda,
      '--name', alias,
      '--function-version', target,
      '--description', 'rolled back',
      '--output', 'json',
   ]);

   const dryRunTag = argv.dryRun ? ' (DRY RUN)' : '';
   console.log(`rollback: alias=${alias} from=${oldVersion ?? '(none)'} to=${target}${dryRunTag}`);
}

// ---------------------------------------------------------------------------
// info — show $LATEST status (always); add alias target + version history
// when --prod <alias> is given.
// ---------------------------------------------------------------------------

function runInfo(argv) {
   // Always surface $LATEST's modification timestamp + code sha. This is
   // the function-level "when was the last test deploy" signal — bumped on
   // every update-function-code, untouched by publish-version alone.
   const latest = getFunctionConfig(argv);
   const latestSha = (latest.CodeSha256 ?? '').slice(0, 12);
   const latestModified = latest.LastModified ?? '(unknown)';
   console.log(`info: lambda=${argv.lambda} latest-modified=${latestModified} latest-code-sha=${latestSha}`);

   if (!isProd(argv)) {
      return;
   }

   // Prod-mode adds the alias snapshot and full published-version history.
   const alias = aliasName(argv);
   const aliasInfo = getAlias(argv, alias);
   const current = aliasInfo?.FunctionVersion ?? null;
   const aliasComment = aliasInfo?.Description ?? '';
   console.log(`  alias=${alias} current-version=${current ?? '(none)'} alias-comment=${aliasComment}`);

   const allVersions = listVersions(argv);
   const shown = allVersions.slice(0, argv.printLimit);
   for (const v of shown) {
      const marker = v.Version === current ? '*' : ' ';
      const desc = v.Description ?? '';
      const date = v.LastModified ?? '';
      console.log(`  ${marker} ${v.Version.padStart(4)}  ${date}  ${desc}`);
   }
   if (allVersions.length === 0) {
      console.log('  (no published versions)');
   } else if (allVersions.length > shown.length) {
      console.log(`    ...and ${allVersions.length - shown.length} more`);
   }
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
   '--prod', '--lambda', '--profile', '--region', '--print-limit',
   '--build-dir', '--comment', '--version',
]);

const addGlobalOpts = (y) => y
   .option('prod', { type: 'string', describe: 'Enable prod-mode targeting <alias> (e.g. --prod prod). Absent ⇒ test-mode.' })
   .option('lambda', { type: 'string', demandOption: true, describe: 'Lambda function name or ARN' })
   .option('profile', { type: 'string', describe: 'AWS CLI profile (falls back to QC_{PROD,TEST}_AWS_PROFILE; required)' })
   .option('region', { type: 'string', describe: 'AWS region (falls back to QC_{PROD,TEST}_AWS_REGION; required)' })
   .option('dry-run', { type: 'boolean', default: false, alias: 'dryrun', describe: 'Log actions without executing them' })
   .option('print-limit', { type: 'number', default: 10, describe: 'Max version rows to print (info)' });

// Used to detect typo'd commands so the fail handler can suggest the
// closest match.
const COMMANDS = ['deploy', 'bdeploy', 'rollback', 'info'];

const deployBuilder = (y) => addGlobalOpts(y)
   .option('build-dir', { type: 'string', default: 'dist/server', describe: 'Directory containing index.zip' })
   .option('comment', { type: 'string', default: '', describe: 'Description recorded on the new published version (prod-mode only).' })
   .check((argv) => {
      try {
         if (!statSync(argv.buildDir).isDirectory()) {
            throw new Error('not a directory');
         }
      } catch {
         throw new Error(`--build-dir does not exist or is not a directory: ${argv.buildDir}`);
      }
      return true;
   });

const bdeployBuilder = (y) => deployBuilder(y)
   .option('no-min', { type: 'boolean', default: false, describe: 'Build with `pnpm build:server` (unminified) instead of `pnpm build:server:min`' });

const rollbackBuilder = (y) => addGlobalOpts(y)
   .option('version', { type: 'string', describe: 'Specific version to roll back to (default: version preceding current alias target)' });

yargs(hideBin(process.argv))
   .scriptName('deploy.mjs')
   .command('$0', 'Deploy the built Lambda artifact to AWS.', deployBuilder, runDeploy)
   .command('deploy', 'Deploy the built Lambda artifact (explicit form of the default command).', deployBuilder, runDeploy)
   .command('bdeploy', 'Build (`pnpm build:server:min`, or `build:server` with --no-min) then deploy.', bdeployBuilder, runBdeploy)
   .command('rollback', 'Move the prod alias to a previous version. Requires --prod <alias>.', rollbackBuilder, runRollback)
   .command('info', 'Show $LATEST modification time + code sha. With --prod <alias>, also list published versions and the current alias target.', addGlobalOpts, runInfo)
   .demandCommand(0)
   .fail((msg, err) => {
      if (err) {
         throw err;
      }
      // Typos like `bdeplo`, `rollbac`, etc. — get a "did you mean ...?"
      // suggestion when close to a registered command. Returns silently
      // otherwise so we fall through to the bare msg below.
      suggestCommandTypo(msg, COMMANDS, VALUE_FLAGS);
      console.error(msg);
      process.exit(1);
   })
   .strict()
   .help()
   .version(false)
   .parseSync();
