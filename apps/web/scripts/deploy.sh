#!/usr/bin/env bash
# deploy.sh — thin wrapper that invokes deploy.mjs with this project's defaults.
#
# Typical usage (from the repo root):
#   ./apps/web/scripts/deploy.sh
#
# Any extra args are passed through to deploy.mjs, e.g. to override a default
# for a one-off run:
#   ./apps/web/scripts/deploy.sh --dry-run
#   ./apps/web/scripts/deploy.sh --expiration-days 60
#   ./apps/web/scripts/deploy.sh --profile qcrypt-prod
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
   quickcrypt \
   --build-dir "$REPO_ROOT/dist/web/browser" \
   --cache-control "public, max-age=31536000, immutable" \
   --expiration-days 30 \
   --print-limit 300 \
   --cf-distribution <id> \
   "$@"
