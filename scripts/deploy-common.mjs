// scripts/deploy-common.mjs — shared infrastructure for the apps/{web,server}
// deploy.mjs scripts. Companion to scripts/deploy-common.sh; this side
// covers the JS-level helpers (AWS-CLI invocation, profile/region
// resolution, argv positional walking, typo-suggestion) that otherwise
// drift out of sync between projects.
//
// Each deploy.mjs supplies:
//   - VALUE_FLAGS set (used with realPositionals to skip flag values
//     when scanning argv — required because flags like `--profile foo`
//     interleave the value as a positional-shaped token)
//   - A small wrapper around resolveAwsCreds that picks the right env-var
//     names (web → always QC_PROD_*; server → QC_PROD_* or QC_TEST_*
//     based on argv.prod)
//   - Resource-specific error hints (NoSuchBucket / ResourceNotFoundException
//     / etc.) inside helpers that own the AWS resource — `aws()` here
//     only emits hints that apply to *every* AWS call (auth/role).

import { spawnSync } from 'node:child_process';
import { hideBin } from 'yargs/helpers';
import { closest } from '../apps/web/src/app/services/levenshtein.ts';

// POSIX single-quote a shell arg: safe wrap for anything containing spaces
// or shell metachars. Used only for the --dry-run log so previewed commands
// can be copy-pasted into a shell.
export function shellQuote(arg) {
   if (arg === '' || /[^\w@%+=:,./-]/.test(arg)) {
      return `'${arg.replace(/'/g, `'\\''`)}'`;
   }
   return arg;
}

// Symbol-keyed memoization on the argv object so resolution work / error
// messages happen at most once per process invocation.
const AWS_CREDS_KEY = Symbol('awsCreds');

// Resolve --profile / --region with strict precedence: CLI flag > env var.
// Caller passes the actual env-var names (e.g. 'QC_PROD_AWS_PROFILE'),
// which lets each project encode its own prod/test logic without making
// this function aware of those rules. Errors loudly with the missing
// variable name in the message; never falls through to AWS_PROFILE /
// AWS_REGION (intentional — keeps the active account explicit).
export function resolveAwsCreds(argv, envProfileName, envRegionName) {
   if (argv[AWS_CREDS_KEY]) {
      return argv[AWS_CREDS_KEY];
   }
   const profile = argv.profile ?? process.env[envProfileName];
   const region = argv.region ?? process.env[envRegionName];
   if (!profile) {
      console.error(`Missing AWS profile: pass --profile or set ${envProfileName}.`);
      process.exit(1);
   }
   if (!region) {
      console.error(`Missing AWS region: pass --region or set ${envRegionName}.`);
      process.exit(1);
   }
   argv[AWS_CREDS_KEY] = { profile, region };
   return argv[AWS_CREDS_KEY];
}

// Run the aws CLI. Always splices --profile/--region into the call (the
// caller resolves these via resolveAwsCreds and stores them on argv via
// the Symbol). Honors --dry-run by logging mutating calls instead of
// running them; read-only calls always execute so dry-run diagnostics
// stay accurate.
//
// On non-zero exit (and not allowFailure): writes stderr through, prints
// generic auth/role hints (which apply to any aws call regardless of
// service), then a "aws X failed" line, then process.exit(1).
// Resource-specific hints (NoSuchBucket / ResourceNotFoundException) are
// the caller's responsibility — they live in helpers like readManifest /
// getFunctionConfig where the resource type is known.
export function aws(argv, args, { input, allowFailure = false, readOnly = false } = {}) {
   const creds = argv[AWS_CREDS_KEY];
   if (!creds) {
      throw new Error('aws(): caller must invoke resolveAwsCreds(argv, ...) first');
   }
   const full = ['--profile', creds.profile, '--region', creds.region, ...args];

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
      if (/AccessDenied|Access Denied|ForbiddenException/i.test(combined)) {
         console.error(
            '  - Verify your AWS profile / SSO session is authenticated to the right account.\n' +
            '  - Verify the role has the permissions this command needs.',
         );
      }
      console.error(`aws ${args.join(' ')} failed (exit ${r.status})`);
      process.exit(1);
   }
   return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}

// Walk an argv array (typically `hideBin(process.argv)`) and return only
// the non-flag positionals, skipping the value tokens of known flag-with-
// value options. Used by .fail() to identify the user's typo'd subcommand
// even when flags precede it.
export function realPositionals(argv, valueFlags) {
   const out = [];
   let expectValue = false;
   for (const arg of argv) {
      if (expectValue) {
         expectValue = false;
         continue;
      }
      if (valueFlags.has(arg)) {
         expectValue = true;
         continue;
      }
      if (!arg.startsWith('-')) {
         out.push(arg);
      }
   }
   return out;
}

// If yargs' fail-message names an unknown argument and the first
// real positional in argv isn't one of the registered commands, treat it
// as a typo'd subcommand and print a "did you mean X?" suggestion (or
// "Available: ..." for a far-off match), then process.exit(1).
//
// Returns silently if no typo is detected so the caller can continue on
// to project-specific message handling.
export function suggestCommandTypo(msg, commands, valueFlags) {
   if (!msg || !/Unknown argument/.test(msg)) {
      return;
   }
   const candidate = realPositionals(hideBin(process.argv), valueFlags).find((p) => !commands.includes(p));
   if (!candidate) {
      return;
   }
   const match = closest(candidate, commands);
   if (match.dist <= 2) {
      console.error(`Unknown command '${candidate}'. Did you mean '${match.closest}'?`);
   } else {
      console.error(`Unknown command '${candidate}'. Available: ${commands.join(', ')}.`);
   }
   process.exit(1);
}
