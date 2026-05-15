#!/usr/bin/env bash
# deploy.sh — thin wrapper that invokes the server deploy.mjs with this
# project's per-environment defaults.
#
# Typical usage (from the repo root):
#   ./apps/server/scripts/deploy.sh                          # test deploy
#   ./apps/server/scripts/deploy.sh --prod prod              # prod deploy
#   ./apps/server/scripts/deploy.sh bdeploy                  # build then deploy (test)
#   ./apps/server/scripts/deploy.sh --prod prod info         # list prod versions
#   ./apps/server/scripts/deploy.sh --prod prod rollback     # bump prod alias back one version
#   ./apps/server/scripts/deploy.sh --dry-run                 # log actions only
#
# Profile/region come from --profile/--region flags or QC_{PROD,TEST}_AWS_*
# env vars (deploy.mjs hard-errors if neither source provides a value). The
# wrapper only uses those env vars for its own SSO liveness probe — when
# unset, the probe is skipped on the assumption the user is providing
# --profile and managing their own session.
#
# Lambda function names come from QC_PROD_LAMBDA / QC_TEST_LAMBDA env vars
# (used as the default for --lambda). Pass --lambda on the CLI to override
# for one-off targets. Wrapper errors out if neither the env var nor a
# --lambda flag is provided for the active mode.
#
# Optional: set QC_PROD_CHROME_PROFILE / QC_TEST_CHROME_PROFILE to your
# Chrome profile directory name (the BASENAME, e.g. "Default" or "Profile 3"
# — NOT a full path; Chrome resolves it under its own user-data-dir). When
# set, the wrapper prints a copy-pasteable macOS `open -na "Google Chrome"
# ...` command alongside the SSO device URL so the link opens in the right
# Identity Center user's profile (dodges the "device flow silently re-uses
# the wrong user's session" trap).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
source "$REPO_ROOT/scripts/deploy-common.sh"

# pnpm passes `--` through to the script unchanged; drop it so subcommand
# detection sees the real first arg.
if [ "${1:-}" = "--" ]; then
   shift
fi

# Pick env-var pair names per prod/test mode (--prod presence = prod-mode).
if [ "$(is_prod_mode "$@")" = "1" ]; then
   LAMBDA_ENV_NAME="QC_PROD_LAMBDA"
   PROFILE_ENV_NAME="QC_PROD_AWS_PROFILE"
   CHROME_PROFILE_ENV_NAME="QC_PROD_CHROME_PROFILE"
else
   LAMBDA_ENV_NAME="QC_TEST_LAMBDA"
   PROFILE_ENV_NAME="QC_TEST_AWS_PROFILE"
   CHROME_PROFILE_ENV_NAME="QC_TEST_CHROME_PROFILE"
fi

# Resolve --lambda: CLI flag has precedence; otherwise fall back to the
# env var picked above. The resolved value flows back into DEFAULTS so
# deploy.mjs sees it even when the env var was the source.
LAMBDA="$(resolve_flag --lambda "$@")"
LAMBDA="${LAMBDA:-${!LAMBDA_ENV_NAME:-}}"
if [ -z "$LAMBDA" ]; then
   echo "deploy.sh: $LAMBDA_ENV_NAME env var must be set (or pass --lambda)." >&2
   exit 1
fi

# Resolve --profile for the SSO probe (CLI takes precedence over env).
PROFILE="$(resolve_flag --profile "$@")"
PROFILE="${PROFILE:-${!PROFILE_ENV_NAME:-}}"
do_sso_check "$PROFILE" "${!CHROME_PROFILE_ENV_NAME:-}"

# Subcommand drives DEFAULTS selection. Server's deploy.mjs has no
# positional args, so we don't need to splice it back in — it can ride
# through "$@" untouched.
SUBCMD="$(detect_subcommand "$@")"

# Per-subcommand project defaults. Each command in deploy.mjs only accepts
# a subset of options under strict mode, so the wrapper must scope flags
# to the command being invoked. default_unless_user_supplied skips
# injection when the user already passed the same flag — yargs would
# otherwise array (or sum, for `type: number`) the two values.
DEFAULTS=()
case "${SUBCMD:-deploy}" in
   deploy|bdeploy)
      default_unless_user_supplied --build-dir "$REPO_ROOT/dist/server" "$@"
      default_unless_user_supplied --lambda "$LAMBDA" "$@"
      default_comment_from_git_tag "$@"
      ;;
   rollback)
      default_unless_user_supplied --lambda "$LAMBDA" "$@"
      ;;
   info)
      default_unless_user_supplied --lambda "$LAMBDA" "$@"
      ;;
esac

# Defaults present once at most; user args follow.
node "$SCRIPT_DIR/deploy.mjs" \
   "${DEFAULTS[@]}" \
   "$@"
