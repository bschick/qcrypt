#!/bin/bash

sudo apt install -y zip curl tmux podman
curl -fsSL https://deb.nodesource.com/setup_24.x | sudo -E bash -
sudo apt-get install -y nodejs

node -v

sudo corepack enable pnpm

pnpm install

cd apps/web/localssl
./localssl.sh
cd ..

# Setup VM mounts for isolated node_modules
./setup-vm-mounts.sh


sudo npx playwright install-deps
npx playwright install chromium firefox

echo "Done."
