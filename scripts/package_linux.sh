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
flutter config --enable-linux-desktop
flutter pub get
flutter build linux --release

# 3. Assemble Portable Tarball
echo -e "\n[3/4] Assembling Portable Distribution..."
STAGE_DIR="$DIST_DIR/antigravity-vault-linux-x64"
mkdir -p "$STAGE_DIR/lib"

# Locate flutter release bundle
BUNDLE_DIR=""
if [ -d "$FLUTTER_DIR/build/linux/x64/release/bundle" ]; then
    BUNDLE_DIR="$FLUTTER_DIR/build/linux/x64/release/bundle"
elif [ -d "$FLUTTER_DIR/build/linux/release/bundle" ]; then
    BUNDLE_DIR="$FLUTTER_DIR/build/linux/release/bundle"
fi

if [ -n "$BUNDLE_DIR" ]; then
    cp -r "$BUNDLE_DIR/"* "$STAGE_DIR/"
    echo "  [OK] Staged bundle from $BUNDLE_DIR"
else
    echo "  [WARN] Bundle directory not found directly, copying binary"
    find "$FLUTTER_DIR/build" -name "pwdvault_flutter" -exec cp {} "$STAGE_DIR/" \;
fi

# Copy FFI library to both root and lib/
if [ -f "$CORE_DIR/target/release/libpwdvault_ffi.so" ]; then
    cp "$CORE_DIR/target/release/libpwdvault_ffi.so" "$STAGE_DIR/lib/"
    cp "$CORE_DIR/target/release/libpwdvault_ffi.so" "$STAGE_DIR/"
fi

# Copy native messaging host
if [ -f "$CORE_DIR/target/release/pwdvault-native-host" ]; then
    cp "$CORE_DIR/target/release/pwdvault-native-host" "$STAGE_DIR/"
fi

# Copy browser extension manifests and desktop integration files
for manifest_dir in "$WORKSPACE_ROOT/apps/browser_extension/native_host" "$WORKSPACE_ROOT/apps/browser_extension/manifest"; do
    if [ -d "$manifest_dir" ]; then
        [ -f "$manifest_dir/com.antigravity.pwdvault.json" ] && cp "$manifest_dir/com.antigravity.pwdvault.json" "$STAGE_DIR/" || true
        [ -f "$manifest_dir/com.antigravity.pwdvault.firefox.json" ] && cp "$manifest_dir/com.antigravity.pwdvault.firefox.json" "$STAGE_DIR/" || true
    fi
done
if [ -f "$WORKSPACE_ROOT/apps/flutter/linux/pwdvault.desktop" ]; then
    cp "$WORKSPACE_ROOT/apps/flutter/linux/pwdvault.desktop" "$STAGE_DIR/"
fi
if [ -f "$WORKSPACE_ROOT/apps/flutter/linux/com.antigravity.pwdvault.metainfo.xml" ]; then
    cp "$WORKSPACE_ROOT/apps/flutter/linux/com.antigravity.pwdvault.metainfo.xml" "$STAGE_DIR/"
fi
if [ -f "$WORKSPACE_ROOT/docs/UserGuide.md" ]; then
    cp "$WORKSPACE_ROOT/docs/UserGuide.md" "$STAGE_DIR/README.txt"
fi

cd "$DIST_DIR"
tar -czvf "AntigravityVault-v1.0.0-Linux-x64.tar.gz" "antigravity-vault-linux-x64"

# 4. Generate Checksums
echo -e "\n[4/4] Generating SHA-256 Checksums..."
sha256sum AntigravityVault-v1.0.0-Linux-x64.tar.gz > SHA256SUMS.txt

echo "=========================================================="
echo "  LINUX PACKAGING COMPLETE                               "
echo "=========================================================="
