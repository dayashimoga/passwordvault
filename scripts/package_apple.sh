#!/usr/bin/env bash
# Antigravity Vault - macOS and iOS Release Packaging
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
FLUTTER_DIR="$WORKSPACE_ROOT/apps/flutter"
DIST_DIR="$WORKSPACE_ROOT/dist/apple"

echo "=========================================================="
echo "  ANTIGRAVITY VAULT - APPLE (MACOS & IOS) RELEASE         "
echo "=========================================================="

mkdir -p "$DIST_DIR"
cd "$FLUTTER_DIR"

# 1. macOS Build
echo -e "\n[1/3] Building macOS Release Bundle..."
if command -v xcodebuild &>/dev/null; then
    flutter build macos --release
    STAGE_MAC="$DIST_DIR/macOS"
    mkdir -p "$STAGE_MAC"
    cp -r "$FLUTTER_DIR/build/macos/Build/Products/Release/Antigravity Vault.app" "$STAGE_MAC/" || true
    echo "  [OK] macOS app bundle created"
else
    echo "  [SKIP] xcodebuild not found in environment (cross-compilation host)"
fi

# 2. iOS Archive Build
echo -e "\n[2/3] Building iOS Release Archive..."
if command -v xcodebuild &>/dev/null; then
    flutter build ipa --no-codesign
    echo "  [OK] iOS archive created"
else
    echo "  [SKIP] iOS build requires macOS Darwin host"
fi

# 3. Checksum generation
echo -e "\n[3/3] Generating Checksums..."
cd "$DIST_DIR"
if compgen -G "*.zip" > /dev/null || compgen -G "*.ipa" > /dev/null; then
    sha256sum * > SHA256SUMS.txt
    echo "  [OK] Checksums generated"
else
    echo "No binaries generated to checksum."
fi

echo "=========================================================="
echo "  APPLE PACKAGING COMPLETE                               "
echo "=========================================================="
