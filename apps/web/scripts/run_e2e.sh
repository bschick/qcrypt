#!/usr/bin/env bash
#
# run_e2e.sh — wraps the two-stage Playwright e2e suite (sequential then
# parallel). Optional --loops N repeats the whole suite; exits on the first
# failing iteration.
#
# For --project local it also owns a frozen dev serve (no watch/live-reload) so
# a file save during a run can't trigger a reload that aborts in-flight
# requests; the serve is stopped on exit.
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

SERVE_URL="https://t1.quickcrypt.org:4200"
SERVE_PID=""
SERVE_LOG=""

# Kill the whole serve process group (nx spawns children) and drop its log,
# preserving the script's exit status so cleanup can't mask a test failure.
stop_serve() {
   local rc=$?
   if [[ -n "$SERVE_PID" ]]; then
      echo "run_e2e.sh: stopping frozen serve"
      kill -- -"$SERVE_PID" 2>/dev/null || true
      wait "$SERVE_PID" 2>/dev/null || true
   fi
   if [[ -n "$SERVE_LOG" ]]; then
      rm -f "$SERVE_LOG"
   fi
   return $rc
}
trap stop_serve EXIT

# True if something is already listening on the serve port.
port_in_use() {
   (echo > /dev/tcp/127.0.0.1/4200) >/dev/null 2>&1
}

serve_ready() {
   curl -sk -o /dev/null --max-time 3 "$SERVE_URL"
}

# Start a dev serve with watch and live-reload off, so a file save during a run
# can't reload the page and abort an in-flight request. setsid puts it in its
# own process group so stop_serve can take down the whole tree.
start_frozen_serve() {
   SERVE_LOG="$(mktemp -t run_e2e_serve.XXXXXX.log)"
   echo "run_e2e.sh: starting frozen serve (no watch, no live-reload); log: $SERVE_LOG"
   setsid pnpm exec nx serve web --hmr false --live-reload false --watch false \
      --host 0.0.0.0 --ssl \
      --ssl-cert apps/web/localssl/localhost.crt \
      --ssl-key apps/web/localssl/localhost.key > "$SERVE_LOG" 2>&1 &
   SERVE_PID=$!

   local waited=0
   until serve_ready; do
      if ! kill -0 "$SERVE_PID" 2>/dev/null; then
         echo "run_e2e.sh: frozen serve exited before becoming ready; last log lines:" >&2
         tail -n 20 "$SERVE_LOG" >&2
         exit 1
      fi
      if [[ "$waited" -ge 180 ]]; then
         echo "run_e2e.sh: frozen serve not ready after ${waited}s; last log lines:" >&2
         tail -n 20 "$SERVE_LOG" >&2
         exit 1
      fi
      sleep 3
      waited=$((waited + 3))
   done
   echo "run_e2e.sh: frozen serve ready at $SERVE_URL"
}

if [[ "$PROJECT" == "local" ]]; then
   if port_in_use; then
      echo "run_e2e.sh: port 4200 is already in use; stop the existing server and retry" >&2
      exit 1
   fi
   start_frozen_serve
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
