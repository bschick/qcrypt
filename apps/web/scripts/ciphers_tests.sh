#!/bin/bash

PLAIN='A nice 🦫 came to say hello'
PWD='a 🌲 of course'
HINT='🌧️'
CRED='Ohyqajb6nFOm2Y5lOTkIkhc3uAaF8sUrYrQ9pts2pDc='
IC=1800000
ALGS='AES-GCM X20-PLY AEGIS-256'

qcrypt() {
  node ../../../dist/cli/qcrypt.cjs "$@"
}

cols=$(tput cols)
echo "correct cipherdata info and decryption"
spaces=$(printf "%${cols}s" "")
line="${spaces// /═}"
echo "$line"

for alg in $ALGS
do
   ciphertxt=$(echo -n $PLAIN | qcrypt enc --cred $CRED --pwds "$PWD" --hints "$HINT" --iters $IC --algs "$alg" --b64url out --silent)
   echo "               '$alg': '$ciphertxt',"
#   echo "      const [cipherStream] = streamFromBase64Url('$ciphertxt');"
done
echo
