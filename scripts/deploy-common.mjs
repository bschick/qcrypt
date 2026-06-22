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
//   - Resource-specific error hints (NoSuchBucket / ResourceNotFoundException
//     / etc.) inside helpers that own the AWS resource — `aws()` here
//     only emits hints that apply to *every* AWS call (auth/role).

import { spawnSync, spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { resolve, relative, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { hideBin } from 'yargs/helpers';
import { closest } from '../apps/web/src/app/services/levenshtein.ts';

// Project root, derived from this module's location (repo-root/scripts).
const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

// Shorten a path for display: relative to the project root when it sits
// under it (the common case), otherwise the path unchanged.
export function relToRoot(p) {
   const rel = relative(REPO_ROOT, resolve(p));
   return rel && !rel.startsWith('..') ? rel : p;
}

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

// Project policy for which env vars supply the AWS profile/region: --prod
// presence selects QC_PROD_*, absence selects QC_TEST_*. CLI --profile /
// --region still override via resolveAwsCreds. Both deploy.mjs scripts share
// this rule; `aws()` calls it so callers never resolve creds by hand.
export function resolveCreds(argv) {
   const prefix = argv.prod ? 'QC_PROD' : 'QC_TEST';
   return resolveAwsCreds(argv, `${prefix}_AWS_PROFILE`, `${prefix}_AWS_REGION`);
}

const AUTH_OK_KEY = Symbol('awsAuthOk');

// Ensure the resolved profile has a live session before any AWS work. A
// quick `sts get-caller-identity` probe; on failure, run the interactive
// `aws sso login --use-device-code` and stream its output, injecting a
// copy-pasteable macOS Chrome-profile launch command when the device URL
// appears (QC_{PROD,TEST}_CHROME_PROFILE, picked by --prod) — the
// wrong-Identity-Center-account guard. Memoized per argv so it runs once.
// Lives here (not the bash wrapper) so the prod confirm can run first and
// so bare `node deploy.mjs` gets the same login behavior.
export async function ensureAuth(argv) {
   if (argv[AUTH_OK_KEY]) {
      return;
   }
   const creds = resolveCreds(argv);
   const probe = spawnSync(
      'aws',
      ['--profile', creds.profile, '--region', creds.region, 'sts', 'get-caller-identity'],
      { stdio: 'ignore' },
   );
   if (probe.status === 0) {
      argv[AUTH_OK_KEY] = true;
      return;
   }

   const chromeProfile = argv.prod ? process.env.QC_PROD_CHROME_PROFILE : process.env.QC_TEST_CHROME_PROFILE;
   console.error(`AWS SSO session for profile '${creds.profile}' is not active; launching login...`);
   await new Promise((resolveLogin, rejectLogin) => {
      const child = spawn('aws', ['--profile', creds.profile, 'sso', 'login', '--use-device-code'], {
         stdio: ['inherit', 'pipe', 'pipe'],
      });
      const relay = (buf) => {
         const text = buf.toString();
         process.stdout.write(text);
         if (chromeProfile) {
            const match = /(https:\/\/\S*device\S*)/.exec(text);
            if (match) {
               process.stdout.write(
                  `\n-> To open this URL in the right Chrome profile, run on your local macOS terminal:\n` +
                  `open -na "Google Chrome" --args --profile-directory='${chromeProfile}' '${match[1]}'\n\n`,
               );
            }
         }
      };
      child.stdout.on('data', relay);
      child.stderr.on('data', relay);
      child.on('error', rejectLogin);
      child.on('close', (code) => {
         if (code === 0) {
            resolveLogin();
         } else {
            rejectLogin(new Error(`aws sso login exited ${code}`));
         }
      });
   }).catch((err) => {
      console.error(`SSO login failed: ${err.message}`);
      process.exit(1);
   });
   argv[AUTH_OK_KEY] = true;
}

// Run the aws CLI. Resolves --profile/--region via resolveCreds (memoized
// on argv) and splices them into the call. Honors --dry-run by logging
// mutating calls instead of
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
   const creds = resolveCreds(argv);
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

// Yargs lists both kebab and camelCase aliases of an unknown flag (default
// camel-case-expansion). Dedupe by kebab form so the user sees what they
// typed, not the internal alias too.
function stripCamelCaseDuplicates(msg) {
   const m = /^Unknown arguments?:\s*(.+)$/.exec(msg);
   if (!m) {
      return msg;
   }
   const args = m[1].split(/,\s*/);
   const toKebab = (s) => s.replace(/[A-Z]/g, (c) => '-' + c.toLowerCase());
   const seen = new Set();
   const unique = [];
   for (const a of args) {
      const k = toKebab(a);
      if (!seen.has(k)) {
         seen.add(k);
         unique.push(a);
      }
   }
   const label = unique.length === 1 ? 'argument' : 'arguments';
   return `Unknown ${label}: ${unique.join(', ')}`;
}

// Handles yargs "Unknown argument" failures with two modes:
//   - real command in positionals → print yargs' message and a hint to run
//     `<command> --help` for valid options. The unknown is a flag/arg, not
//     a typo'd subcommand.
//   - no real command in positionals → treat the first stray positional as
//     a typo'd subcommand: "did you mean X?" or "Available: ...".
// Either branch process.exit(1)s; returns silently when no Unknown-argument
// failure is in play so callers can continue on to other message handling.
export function suggestCommandTypo(msg, commands, valueFlags) {
   if (!msg || !/Unknown argument/.test(msg)) {
      return;
   }
   const positionals = realPositionals(hideBin(process.argv), valueFlags);
   const matchedCommand = positionals.find((p) => commands.includes(p));
   if (matchedCommand) {
      console.error(stripCamelCaseDuplicates(msg));
      console.error(`Run with \`${matchedCommand} --help\` to see valid options for the '${matchedCommand}' command.`);
      process.exit(1);
   }
   const candidate = positionals.find((p) => !commands.includes(p));
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

// Interactively confirm a destructive prod action. No-op when --prod is
// absent (test mode), when --dry-run is set, or when --yes / -y bypassed
// the gate. Non-interactive stdin aborts unless --yes was passed, so a
// piped or CI invocation can't sleepwalk past the prompt. Accepts y, Y,
// yes, YES (any case); anything else aborts.
export async function confirmProdAction(argv, subcmd, target) {
   if (!argv.prod || argv.dryRun || argv.yes) {
      return;
   }
   if (!process.stdin.isTTY) {
      console.error(`Refusing to run prod '${subcmd}' non-interactively. Pass --yes (or -y) to skip the prompt.`);
      process.exit(1);
   }
   console.log();
   console.log('  =====================================');
   console.log('    About to modify PRODUCTION:');
   console.log(`      command: ${subcmd}`);
   console.log(`      ${target}`);
   console.log('  =====================================');
   const rl = createInterface({ input: process.stdin, output: process.stdout });
   try {
      const response = await new Promise((resolve) => {
         rl.question(`  Type 'yes' (or 'y') to proceed, anything else aborts: `, resolve);
      });
      if (!/^\s*(y|yes)\s*$/i.test(response)) {
         console.error('  Aborted.');
         process.exit(1);
      }
   } finally {
      rl.close();
   }
   console.log();
}
