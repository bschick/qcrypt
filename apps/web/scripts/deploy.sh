#!/usr/bin/env bash
#
# AI-Assist: 100% Claude Code Generated
#
# deploy.sh — thin wrapper that invokes deploy.mjs with this project's defaults.
#
# Typical usage (from the repo root):
#   ./apps/web/scripts/deploy.sh                             # build then deploy (test)
#   ./apps/web/scripts/deploy.sh --prod prod                 # build then deploy (prod)
#   ./apps/web/scripts/deploy.sh deploy                      # deploy already-built dir, no rebuild (test)
#   ./apps/web/scripts/deploy.sh --prod prod prune           # subcommand (prod)
#   ./apps/web/scripts/deploy.sh expect 'foo*'               # subcommand with extra args (test)
#
# Mode is selected by --prod presence: --prod (with any value) selects prod
# mode; absence selects test mode. The --prod value itself is unused on the
# web side, but kept symmetric with the server script.
#
# Profile/region/bucket/CF/Chrome-profile env vars are picked per mode from
# the QC_{PROD,TEST}_* pair below.
#
# Bucket env var is required (wrapper errors if unset). CF-distribution env
# var is optional — when unset the wrapper omits --cf-distribution and
# CloudFront isn't invalidated. Pass --cf-distribution on the CLI to
# override for one-off targets.
#
# AWS auth (and the optional QC_{PROD,TEST}_CHROME_PROFILE SSO-login hint)
# is handled inside deploy.mjs, after the prod confirmation — see ensureAuth
# in scripts/deploy-common.mjs. The wrapper no longer probes or logs in.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
source "$REPO_ROOT/scripts/deploy-common.sh"

# pnpm passes `--` through to the script unchanged; drop it so subcommand
# detection sees the real first arg.
if [ "${1:-}" = "--" ]; then
   shift
fi

# --help / -h short-circuit: skip env-var resolution and SSO probe so help
# text doesn't trigger an auth prompt. Just hand the args to yargs.
if [ "$(is_help_mode "$@")" = "1" ]; then
   exec node "$SCRIPT_DIR/deploy.mjs" "$@"
fi

# Pick env-var pair names per prod/test mode (--prod presence = prod-mode).
# Per-mode build-dir avoids the wrong artifact being deployed to the wrong
# environment if someone test-builds then runs deploy:web:prod (or vice
# versa) — each mode reads from its own output directory.
if [ "$(is_prod_mode "$@")" = "1" ]; then
   BUCKET_ENV_NAME="QC_PROD_BUCKET"
   CF_DIST_ENV_NAME="QC_PROD_CF_DISTRIBUTION"
   BUILD_DIR_DEFAULT="${QC_PROD_WEB_DIST:-$REPO_ROOT/dist/web/browser}"
   EXPIRATION_DAYS_DEFAULT=14
else
   BUCKET_ENV_NAME="QC_TEST_BUCKET"
   CF_DIST_ENV_NAME="QC_TEST_CF_DISTRIBUTION"
   BUILD_DIR_DEFAULT="${QC_TEST_WEB_DIST:-$REPO_ROOT/dist/web-test/browser}"
   EXPIRATION_DAYS_DEFAULT=7
fi

# Bucket is required and not committed to repo (account-identifying).
if [ -z "${!BUCKET_ENV_NAME:-}" ]; then
   echo "deploy.sh: $BUCKET_ENV_NAME env var must be set to the target S3 bucket name." >&2
   exit 1
fi

# AWS auth (SSO login when the session is stale) now happens inside
# deploy.mjs, after the prod confirmation, so the warning precedes any
# login. It reads QC_{PROD,TEST}_AWS_PROFILE / _CHROME_PROFILE directly.

# Subcommand drives DEFAULTS selection AND has to be spliced in front of
# the hardcoded bucket positional in the deploy.mjs invocation.
SUBCMD="$(detect_subcommand "$@")"
remove_subcommand_from_args "$SUBCMD" "$@"

# Per-command project defaults. Each command in deploy.mjs only accepts a
# subset of options under strict mode, so the wrapper must scope flags to
# the command being invoked. default_unless_user_supplied skips injection
# when the user already passed the same flag — yargs would otherwise array
# (or sum, for `type: number`) the two values.
DEFAULTS=()
default_unless_user_supplied --print-limit 150 "$@"
case "${SUBCMD:-bdeploy}" in
   deploy|bdeploy)
      default_unless_user_supplied --build-dir "$BUILD_DIR_DEFAULT" "$@"
      default_unless_user_supplied --cache-control "public, max-age=31536000, immutable" "$@"
      default_unless_user_supplied --expiration-days "$EXPIRATION_DAYS_DEFAULT" "$@"
      if [ -n "${!CF_DIST_ENV_NAME:-}" ]; then
         default_unless_user_supplied --cf-distribution "${!CF_DIST_ENV_NAME}" "$@"
      fi
      default_comment_from_git_tag "$@"
      ;;
   rollback)
      if [ -n "${!CF_DIST_ENV_NAME:-}" ]; then
         default_unless_user_supplied --cf-distribution "${!CF_DIST_ENV_NAME}" "$@"
      fi
      default_comment_from_git_tag "$@"
      ;;
   prune)
      # Match the deploy retention so on-demand prune uses the same window.
      default_unless_user_supplied --expiration-days "$EXPIRATION_DAYS_DEFAULT" "$@"
      ;;
esac

# Splice subcommand before bucket; user args last so user values show up
# exactly once. Always pass an explicit subcommand (defaulting to "bdeploy"
# — build-then-deploy — when none was given) so suggestCommandTypo can
# distinguish "bucket positional" from "typo'd subcommand"; without it, a
# bare `deploy:web --bad-flag` would have the bucket reported as the command.
node "$SCRIPT_DIR/deploy.mjs" \
   "${SUBCMD:-bdeploy}" \
   "${!BUCKET_ENV_NAME}" \
   "${DEFAULTS[@]}" \
   "${ARGS_WITHOUT_SUBCMD[@]}"
