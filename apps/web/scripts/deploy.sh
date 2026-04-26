#!/usr/bin/env bash
# deploy.sh — thin wrapper that invokes deploy.mjs with this project's defaults.
#
# Typical usage (from the repo root):
#   ./apps/web/scripts/deploy.sh                 # default deploy
#   ./apps/web/scripts/deploy.sh prune           # subcommand
#   ./apps/web/scripts/deploy.sh expect 'foo*'   # subcommand with extra args
#   ./apps/web/scripts/deploy.sh --dry-run       # flag for default deploy
#
# AWS credentials are picked up from the environment the same way the `aws`
# CLI does (AWS_PROFILE, AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY, ~/.aws/…,
# or instance role). Use --profile to select an explicit profile.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# pnpm passes `--` through to the script unchanged; drop it so subcommand
# detection sees the real first arg.
if [ "${1:-}" = "--" ]; then
   shift
fi

# Hoist any leading non-flag arg ahead of the hardcoded bucket. Real
# subcommands route correctly; typo'd ones flow through with the typo as
# positional[0] so deploy.mjs can suggest the closest match.
LEADING=()
if [ $# -gt 0 ] && [[ "$1" != -* ]]; then
   LEADING=("$1")
   shift
fi

# Ensure we have a valid AWS session before doing any work. `aws sts
# get-caller-identity` is a cheap liveness probe; `aws sso login` is a no-op
# when the current SSO token is still valid and prompts otherwise.
if ! aws sts get-caller-identity >/dev/null 2>&1; then
   aws sso login --use-device-code
fi

# Per-command project defaults. Each command in deploy.mjs only accepts a
# subset of options under strict mode, so the wrapper must scope flags to
# the command being invoked.
case "${LEADING[0]:-deploy}" in
   deploy)
      DEFAULTS=(
         --build-dir "$REPO_ROOT/dist/web/browser"
         --cache-control "public, max-age=31536000, immutable"
         --expiration-days 30
         --cf-distribution <id>
      )
      ;;
   rollback)
      DEFAULTS=(--cf-distribution <id>)
      ;;
   prune)
      # Match the deploy retention so on-demand prune uses the same window.
      DEFAULTS=(--expiration-days 30)
      ;;
   *)
      DEFAULTS=()
      ;;
esac

node "$SCRIPT_DIR/deploy.mjs" \
   "${LEADING[@]}" \
   quickcrypt \
   --print-limit 300 \
   "${DEFAULTS[@]}" \
   "$@"
