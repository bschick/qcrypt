#!/bin/bash

export NODE_EXTRA_CA_CERTS=./localssl/ca.pem
PROJ="${2:-"local"}"

LAST_DIR=$(basename "$(pwd)")
if [[ "$LAST_DIR" == "tests"* ]]; then
  TESTS_PATH="."
else
  TESTS_PATH="./tests"
fi

COMMAND=(
  "npx"
  "playwright"
  "test"
  "--project=$PROJ"
  "$TESTS_PATH/parallel/"
  "--workers=1"
)

# Add test filter if we have one
if [ -n "$1" ]; then
  COMMAND+=("-g" "$1")
fi

# printf " > %s\n" "${COMMAND[@]}"
"${COMMAND[@]}"
