#!/bin/bash

# This script sets up bind mounts for node_modules and .nx directories
# to allow running pnpm and tests from both the macOS host and the Linux VM.
# It shadows the shared folders with VM-local directories.

set -e

PROJECT_DIR=$(pwd)
VM_HOME_DIR=$HOME
LOCAL_NODE_MODULES="$VM_HOME_DIR/qcrypt_node_modules"
LOCAL_NX="$VM_HOME_DIR/qcrypt_nx"

echo "Setting up VM local mounts..."

# Create local directories if they don't exist
if [ ! -d "$LOCAL_NODE_MODULES" ]; then
    echo "Creating $LOCAL_NODE_MODULES..."
    mkdir -p "$LOCAL_NODE_MODULES"
fi

if [ ! -d "$LOCAL_NX" ]; then
    echo "Creating $LOCAL_NX..."
    mkdir -p "$LOCAL_NX"
fi

# Ensure target directories exist in the project
if [ ! -d "$PROJECT_DIR/node_modules" ]; then
    echo "Creating $PROJECT_DIR/node_modules..."
    mkdir -p "$PROJECT_DIR/node_modules"
fi

if [ ! -d "$PROJECT_DIR/.nx" ]; then
    echo "Creating $PROJECT_DIR/.nx..."
    mkdir -p "$PROJECT_DIR/.nx"
fi

# Unmount old mounts if they exist (ignore errors if not mounted)
echo "Unmounting old mounts..."
sudo umount "$PROJECT_DIR/node_modules" 2>/dev/null || true
sudo umount "$PROJECT_DIR/.nx" 2>/dev/null || true

# Bind mount node_modules
echo "Mounting $LOCAL_NODE_MODULES to $PROJECT_DIR/node_modules..."
sudo mount --bind "$LOCAL_NODE_MODULES" "$PROJECT_DIR/node_modules"

# Bind mount .nx
echo "Mounting $LOCAL_NX to $PROJECT_DIR/.nx..."
sudo mount --bind "$LOCAL_NX" "$PROJECT_DIR/.nx"

echo "VM mounts setup complete. You can now run 'pnpm install' safely in this VM."
