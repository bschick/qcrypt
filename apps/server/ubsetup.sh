#!/bin/bash

sudo apt install -y zip curl tmux
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt install -y nodejs=22.20.0-1nodesource1
sudo apt-mark hold nodejs

sudo npm install -g pnpm@latest

pnpm install

echo "Done."
