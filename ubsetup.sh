#!/bin/bash

curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
apt-get install -y nodejs=22.20.0-1nodesource1
apt-mark hold nodejs

npm install -g npm@latest

npm install

cd localssl
./localssl.sh

cp qcrypt.crt /usr/local/share/ca-certificates/.
update-ca-certificates

mkdir -p "$HOME/.pki/nssdb"
certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n "My Custom CA" -i qcrypt.crt

cd ..

npx playwright install-deps
npx playwright install

echo "Done."
