#!/usr/bin/env bash
# Prepare and optimize SVG files in apps/web/src/assets/flow/v7/.
#
# Two-step pass over each target file:
#   1. tag_flow_svg.ts - inserts viewBox if missing AND converts
#      Lucidchart placeholder fills (#f4d9NN, NN != ff) into
#      class="qc-clickable" data-target="NN" with canonical fill.
#   2. svgo - applies the repo's default optimization config.
# Both steps are idempotent; safe to re-run on already-processed files.
#
# Finally regenerates the integrity hashes in flow.config.ts, since processing
# changes the asset bytes the runtime verifies against.
#
# Usage:
#   pnpm svgo:flow                            # all .svg files in flow dir (recursive)
#   pnpm svgo:flow derive_enc_kM0.svg         # one file, path rooted in flow dir
#   pnpm svgo:flow encryption.svg encrypt_m0.svg   # multiple
#
# svgo config: svgo.config.js at repo root.

set -euo pipefail

FLOW_DIR="apps/web/src/assets/flow/v7"
TAG_SCRIPT="apps/web/scripts/tag_flow_svg.ts"

if [[ ! -d "$FLOW_DIR" ]]; then
   echo "svgo:flow: $FLOW_DIR not found (run from repo root)" >&2
   exit 1
fi

if [[ $# -gt 0 ]]; then
   files=()
   for arg in "$@"; do
      path="$FLOW_DIR/$arg"
      if [[ ! -f "$path" ]]; then
         echo "svgo:flow: not a file: $path" >&2
         exit 1
      fi
      files+=("$path")
   done
else
   mapfile -t files < <(find "$FLOW_DIR" -type f -name '*.svg' | sort)
   if [[ ${#files[@]} -eq 0 ]]; then
      echo "svgo:flow: no .svg files under $FLOW_DIR"
      exit 0
   fi
fi

for file in "${files[@]}"; do
   echo
   pnpm exec tsx "$TAG_SCRIPT" "$file"
   pnpm exec svgo "$file" | sed '/./,$!d'
done

echo
pnpm exec tsx apps/web/scripts/hash_flow_svgs.ts
