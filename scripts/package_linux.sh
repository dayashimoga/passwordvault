#!/usr/bin/env bash
# Antigravity Vault - Linux Release Packaging
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CORE_DIR="$WORKSPACE_ROOT/core"
FLUTTER_DIR="$WORKSPACE_ROOT/apps/flutter"
DIST_DIR="$WORKSPACE_ROOT/dist/linux"

echo "=========================================================="
echo "  ANTIGRAVITY VAULT - LINUX RELEASE PACKAGING             "
echo "=========================================================="

mkdir -p "$DIST_DIR"

# 1. Build release Rust FFI and Native Host
echo -e "\n[1/4] Compiling Rust Release Binaries..."
cd "$CORE_DIR"
cargo build --release -p pwdvault-ffi
cargo build --release -p pwdvault-native-host

# 2. Build Flutter Linux Bundle
echo -e "\n[2/4] Building Flutter Linux Release Bundle..."
cd "$FLUTTER_DIR"
flutter build linux --release

# 3. Assemble Portable Tarball
echo -e "\n[3/4] Assembling Portable Distribution..."
STAGE_DIR="$DIST_DIR/antigravity-vault-linux-x64"
mkdir -p "$STAGE_DIR"
cp -r "$FLUTTER_DIR/build/linux/x64/release/bundle/"* "$STAGE_DIR/"
cp "$CORE_DIR/target/release/libpwdvault_ffi.so" "$STAGE_DIR/lib/" || true
cp "$CORE_DIR/target/release/pwdvault-native-host" "$STAGE_DIR/"
cp "$WORKSPACE_ROOT/apps/browser_extension/manifest/com.antigravity.pwdvault.json" "$STAGE_DIR/"
cp "$WORKSPACE_ROOT/apps/flutter/linux/pwdvault.desktop" "$STAGE_DIR/"
cp "$WORKSPACE_ROOT/apps/flutter/linux/com.antigravity.pwdvault.metainfo.xml" "$STAGE_DIR/"

cd "$DIST_DIR"
tar -czvf "AntigravityVault-v1.0.0-Linux-x64.tar.gz" "antigravity-vault-linux-x64"

# 4. Generate Checksums
echo -e "\n[4/4] Generating SHA-256 Checksums..."
sha256sum AntigravityVault-v1.0.0-Linux-x64.tar.gz > SHA256SUMS.txt

echo "=========================================================="
echo "  LINUX PACKAGING COMPLETE                               "
echo "=========================================================="
