#!/usr/bin/env bash
#
# run_e2e.sh — wraps the two-stage Playwright e2e suite (sequential then
# parallel). Optional --loops N repeats the whole suite; exits on the first
# failing iteration.
#
# Usage:
#   run_e2e.sh --project local|prod [--loops N] [extra playwright args...]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$REPO_ROOT"

PROJECT=""
LOOPS=1
PASSTHROUGH=()

while [[ $# -gt 0 ]]; do
   case "$1" in
      --project)
         PROJECT="$2"
         shift 2
         ;;
      --loops)
         LOOPS="$2"
         shift 2
         ;;
      --)
         shift
         ;;
      *)
         PASSTHROUGH+=("$1")
         shift
         ;;
   esac
done

if [[ -z "$PROJECT" ]]; then
   echo "run_e2e.sh: --project local|prod is required" >&2
   exit 2
fi

if ! [[ "$LOOPS" =~ ^[0-9]+$ ]] || [[ "$LOOPS" -lt 1 ]]; then
   echo "run_e2e.sh: --loops must be a positive integer (got: $LOOPS)" >&2
   exit 2
fi

if [[ "$PROJECT" == "local" ]]; then
   export NODE_EXTRA_CA_CERTS=./apps/web/localssl/qcrypt.pem
fi

# Run a Playwright stage. Tolerates "No tests found" by treating it as a
# skip so a grep that only matches the parallel suite doesn't abort the run.
run_stage() {
   local label="$1"
   shift
   local out
   out=$(mktemp)
   set +e
   "$@" 2>&1 | tee "$out"
   local rc=${PIPESTATUS[0]}
   set -e
   if [[ $rc -ne 0 ]] && grep -q "No tests found" "$out"; then
      echo "run_e2e.sh: no tests matched the $label stage; skipping"
      rc=0
   fi
   rm -f "$out"
   return $rc
}

for ((i = 1; i <= LOOPS; i++)); do
   if [[ "$LOOPS" -gt 1 ]]; then
      echo "===== run_e2e.sh: iteration $i of $LOOPS ====="
   fi
   run_stage "sequential" \
      pnpm exec playwright test --config apps/web/playwright.config.ts \
      --project="$PROJECT" --workers=1 apps/web/tests/sequential \
      ${PASSTHROUGH[@]+"${PASSTHROUGH[@]}"}
   pnpm exec playwright test --config apps/web/playwright.config.ts \
      --project="$PROJECT" apps/web/tests/parallel \
      --grep-invert "/@fullfuzz/" \
      ${PASSTHROUGH[@]+"${PASSTHROUGH[@]}"}
done
