#!/usr/bin/env bash
# Antigravity Vault - macOS Release Packaging
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CORE_DIR="$WORKSPACE_ROOT/core"
FLUTTER_DIR="$WORKSPACE_ROOT/apps/flutter"
DIST_DIR="$WORKSPACE_ROOT/dist/macos"

echo "=========================================================="
echo "  ANTIGRAVITY VAULT - MACOS RELEASE PACKAGING             "
echo "=========================================================="

mkdir -p "$DIST_DIR"

# 1. Build release Rust FFI and Native Host
echo -e "\n[1/4] Compiling Rust Release Binaries..."
cd "$CORE_DIR"
cargo build --release -p pwdvault-ffi
cargo build --release -p pwdvault-native-host

# 2. Build Flutter macOS Release Bundle
echo -e "\n[2/4] Building Flutter macOS Release Bundle..."
cd "$FLUTTER_DIR"
flutter config --enable-macos-desktop
flutter pub get
flutter build macos --release

# 3. Assemble Distribution
echo -e "\n[3/4] Assembling macOS Distribution..."
BUILD_PRODUCTS="$FLUTTER_DIR/build/macos/Build/Products/Release"
APP_PATH=$(find "$BUILD_PRODUCTS" -maxdepth 1 -name "*.app" 2>/dev/null | head -n 1 || true)

if [ -z "$APP_PATH" ]; then
    APP_PATH=$(find "$FLUTTER_DIR/build" -name "*.app" 2>/dev/null | head -n 1 || true)
fi

if [ -z "$APP_PATH" ]; then
    echo "Error: No .app bundle found in $BUILD_PRODUCTS or $FLUTTER_DIR/build"
    exit 1
fi

APP_NAME="$(basename "$APP_PATH")"
echo "Found application bundle: $APP_NAME"

STAGE_DIR="$DIST_DIR/AntigravityVault-macOS"
mkdir -p "$STAGE_DIR"
cp -R "$APP_PATH" "$STAGE_DIR/"

# Ad-hoc sign bundle if codesign is available
if command -v codesign &>/dev/null; then
    codesign --force --deep --sign - "$STAGE_DIR/$APP_NAME" || true
fi

# Stage FFI dynamic library and native messaging host
if [ -f "$CORE_DIR/target/release/libpwdvault_ffi.dylib" ]; then
    cp "$CORE_DIR/target/release/libpwdvault_ffi.dylib" "$STAGE_DIR/"
fi
if [ -f "$CORE_DIR/target/release/pwdvault-native-host" ]; then
    cp "$CORE_DIR/target/release/pwdvault-native-host" "$STAGE_DIR/"
fi

# Stage browser extension manifests
for manifest_dir in "$WORKSPACE_ROOT/apps/browser_extension/native_host" "$WORKSPACE_ROOT/apps/browser_extension/manifest"; do
    if [ -d "$manifest_dir" ]; then
        [ -f "$manifest_dir/com.antigravity.pwdvault.json" ] && cp "$manifest_dir/com.antigravity.pwdvault.json" "$STAGE_DIR/" || true
        [ -f "$manifest_dir/com.antigravity.pwdvault.firefox.json" ] && cp "$manifest_dir/com.antigravity.pwdvault.firefox.json" "$STAGE_DIR/" || true
    fi
done

if [ -f "$WORKSPACE_ROOT/docs/UserGuide.md" ]; then
    cp "$WORKSPACE_ROOT/docs/UserGuide.md" "$STAGE_DIR/README.txt"
fi
if [ -f "$WORKSPACE_ROOT/docs/RecoveryGuide.md" ]; then
    cp "$WORKSPACE_ROOT/docs/RecoveryGuide.md" "$STAGE_DIR/"
fi

cd "$STAGE_DIR"
zip -r "../AntigravityVault-v1.0.0-macOS.zip" .
cd "$DIST_DIR"
shasum -a 256 AntigravityVault-v1.0.0-macOS.zip > SHA256SUMS.txt

echo "=========================================================="
echo "  MACOS PACKAGING COMPLETE                               "
echo "=========================================================="
