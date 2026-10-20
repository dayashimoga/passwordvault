#!/usr/bin/env bash
# Antigravity Vault - Android Release Packaging
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
FLUTTER_DIR="$WORKSPACE_ROOT/apps/flutter"
DIST_DIR="$WORKSPACE_ROOT/dist/android"

echo "=========================================================="
echo "  ANTIGRAVITY VAULT - ANDROID RELEASE PACKAGING           "
echo "=========================================================="

mkdir -p "$DIST_DIR"
cd "$FLUTTER_DIR"

echo -e "\n[1/3] Validating Android Configuration & ProGuard Rules..."
test -f "$FLUTTER_DIR/android/app/proguard-rules.pro"
echo "  [OK] ProGuard & R8 configuration verified"

echo -e "\n[2/3] Building Release APK with R8 Optimization..."
flutter build apk --release

APK_PATH="$FLUTTER_DIR/build/app/outputs/flutter-apk/app-release.apk"
if [ -f "$APK_PATH" ]; then
    cp "$APK_PATH" "$DIST_DIR/AntigravityVault-v1.0.0-release.apk"
    echo "  [OK] Staged $DIST_DIR/AntigravityVault-v1.0.0-release.apk"
fi

echo -e "\n[3/3] Generating Release Checksum..."
cd "$DIST_DIR"
sha256sum AntigravityVault-v1.0.0-release.apk > SHA256SUMS.txt
echo "  [OK] Checksum generated"

echo "=========================================================="
echo "  ANDROID PACKAGING COMPLETE                             "
echo "=========================================================="
