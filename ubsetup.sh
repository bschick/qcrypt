#!/bin/bash

sudo apt install -y zip curl tmux libnss3-tools
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt install -y nodejs=22.20.0-1nodesource1
sudo apt-mark hold nodejs

sudo npm install -g npm@latest

npm install

cd localssl
./localssl.sh

sudo cp qcrypt.crt /usr/local/share/ca-certificates/.
sudo update-ca-certificates

mkdir -p "$HOME/.pki/nssdb"
certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n "My Custom CA" -i qcrypt.crt

cd ..

sudo npx playwright install-deps
npx playwright install

echo "Done."
