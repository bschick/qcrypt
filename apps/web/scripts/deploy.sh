#!/usr/bin/env bash
# deploy.sh — thin wrapper that invokes deploy.mjs with this project's defaults.
#
# Typical usage (from the repo root):
#   ./apps/web/scripts/deploy.sh --prod prod                 # default deploy
#   ./apps/web/scripts/deploy.sh --prod prod bdeploy         # build then deploy
#   ./apps/web/scripts/deploy.sh --prod prod prune           # subcommand
#   ./apps/web/scripts/deploy.sh --prod prod expect 'foo*'   # subcommand with extra args
#
# Web deploys are always prod — --prod is required (use --prod prod, the
# alias value is currently unused on the web side but kept symmetric with
# the server script). The wrapper errors clearly if --prod is missing.
#
# Profile/region come from --profile/--region flags or QC_PROD_AWS_PROFILE
# / QC_PROD_AWS_REGION env vars (deploy.mjs hard-errors if neither source
# provides a value).
#
# Bucket comes from QC_PROD_BUCKET (required; wrapper errors if unset).
# CloudFront distribution ID comes from QC_PROD_CF_DISTRIBUTION (optional;
# when unset the wrapper omits --cf-distribution and CloudFront isn't
# invalidated). Pass --cf-distribution on the CLI to override for one-off
# targets.
#
# Optional: set QC_PROD_CHROME_PROFILE to your Chrome profile directory
# name (BASENAME, e.g. "Default" or "Profile 3" — NOT a full path; Chrome
# resolves it under its own user-data-dir). When set, the wrapper prints
# a copy-pasteable macOS `open -na "Google Chrome" ...` command alongside
# the SSO device URL so the link opens in the right Identity Center user's
# profile (dodges the "device flow silently re-uses the wrong user's
# session" trap).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
source "$REPO_ROOT/scripts/deploy-common.sh"

# pnpm passes `--` through to the script unchanged; drop it so subcommand
# detection sees the real first arg.
if [ "${1:-}" = "--" ]; then
   shift
fi

# Web is always prod — fail fast with a clearer error than the deeper
# "Missing AWS profile" deploy.mjs would otherwise hit.
if [ "$(is_prod_mode "$@")" != "1" ]; then
   echo "deploy.sh: web deploys are always prod-mode. Pass --prod (e.g. --prod prod)." >&2
   exit 1
fi

# Bucket is required and not committed to repo (account-identifying).
if [ -z "${QC_PROD_BUCKET:-}" ]; then
   echo "deploy.sh: QC_PROD_BUCKET env var must be set to the target S3 bucket name." >&2
   exit 1
fi

# Resolve --profile for the SSO probe (CLI takes precedence over env).
PROFILE="$(resolve_flag --profile "$@")"
PROFILE="${PROFILE:-${QC_PROD_AWS_PROFILE:-}}"
do_sso_check "$PROFILE" "${QC_PROD_CHROME_PROFILE:-}"

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
case "${SUBCMD:-deploy}" in
   deploy|bdeploy)
      default_unless_user_supplied --build-dir "$REPO_ROOT/dist/web/browser" "$@"
      default_unless_user_supplied --cache-control "public, max-age=31536000, immutable" "$@"
      default_unless_user_supplied --expiration-days 30 "$@"
      if [ -n "${QC_PROD_CF_DISTRIBUTION:-}" ]; then
         default_unless_user_supplied --cf-distribution "$QC_PROD_CF_DISTRIBUTION" "$@"
      fi
      default_comment_from_git_tag "$@"
      ;;
   rollback)
      if [ -n "${QC_PROD_CF_DISTRIBUTION:-}" ]; then
         default_unless_user_supplied --cf-distribution "$QC_PROD_CF_DISTRIBUTION" "$@"
      fi
      default_comment_from_git_tag "$@"
      ;;
   prune)
      # Match the deploy retention so on-demand prune uses the same window.
      default_unless_user_supplied --expiration-days 30 "$@"
      ;;
esac

# Splice: subcommand (if any) before bucket; user args last so user values
# show up exactly once.
node "$SCRIPT_DIR/deploy.mjs" \
   ${SUBCMD:+"$SUBCMD"} \
   "$QC_PROD_BUCKET" \
   "${DEFAULTS[@]}" \
   "${ARGS_WITHOUT_SUBCMD[@]}"
