#!/usr/bin/env bash
# rollback.sh — thin wrapper that invokes deploy.mjs to rollback to previous index.html
#
# Typical usage (from the repo root):
#   ./apps/web/scripts/rollback.sh
#
# Any extra args are passed through to deploy.mjs, e.g. to override a default
# for a one-off run:
#   ./apps/web/scripts/rollback.sh --dry-run
#
# AWS credentials are picked up from the environment the same way the `aws`
# CLI does (AWS_PROFILE, AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY, ~/.aws/…,
# or instance role). Use --profile to select an explicit profile.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# Ensure we have a valid AWS session before doing any work. `aws sts
# get-caller-identity` is a cheap liveness probe; `aws sso login` is a no-op
# when the current SSO token is still valid and prompts otherwise.
if ! aws sts get-caller-identity >/dev/null 2>&1; then
   aws sso login --use-device-code
fi

node "$SCRIPT_DIR/deploy.mjs" \
   rollback \
   quickcrypt \
   --cf-distribution <id> \
   "$@"
