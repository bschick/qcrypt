#!/bin/bash

# Universal cleanup script.
# Detects if node_modules or .nx are mounted and applies the appropriate cleanup procedure.

set -e

PROJECT_DIR=$(pwd)
VM_HOME_DIR=$HOME
LOCAL_NODE_MODULES="$VM_HOME_DIR/qcrypt_node_modules"
LOCAL_NX="$VM_HOME_DIR/qcrypt_nx"

# Check for active mounts on standard Linux/Unix tools
IS_MOUNTED=0

# naive check with mount command which exists on both macOS and Linux
if mount | grep -q "$PROJECT_DIR/node_modules" || mount | grep -q "$PROJECT_DIR/.nx"; then
    IS_MOUNTED=1
fi

if [ "$IS_MOUNTED" -eq 1 ]; then
    echo "Detected active mounts. Assuming VM/Container environment."
    
    echo "Unmounting directories..."
    sudo umount "$PROJECT_DIR/node_modules" 2>/dev/null || true
    sudo umount "$PROJECT_DIR/.nx" 2>/dev/null || true

    echo "Cleaning shadow directories..."
    rm -rf "$LOCAL_NODE_MODULES" "$LOCAL_NX"

    echo "Re-running setup to recreate mounts..."
    ./setup-vm-mounts.sh

    echo "Installing dependencies..."
    pnpm install

else
    echo "No active mounts detected. Assuming Host environment."
    
    echo "Cleaning up local node_modules and .nx..."
    rm -rf node_modules .nx

    echo "Reinstalling dependencies..."
    pnpm install

    echo ""
    echo "--------------------------------------------------------"
    echo "NOTE: If you have a VM running, its mounts are now broken."
    echo "Please switch to your VM terminal and run:"
    echo ""
    echo "  ./clean-packages.sh"
    echo ""
    echo "This will repair the mounts and reinstall VM dependencies."
    echo "--------------------------------------------------------"
fi
