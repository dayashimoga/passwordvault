#!/usr/bin/env bash
# Antigravity Vault - Phase 5 Verification Gate (iPhone/iPad & Desktops)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CORE_DIR="$WORKSPACE_ROOT/core"
FLUTTER_DIR="$WORKSPACE_ROOT/apps/flutter"

echo "=========================================================="
echo "  PWDVAULT PHASE 5 VERIFICATION GATE: IPHONE/IPAD & DESKTOPS"
echo "=========================================================="

echo -e "\n[Step 1/6] Checking Toolchains..."
rustc --version
cargo --version
flutter --version | head -n 1

echo -e "\n[Step 2/6] Running Rust Core Workspace Tests..."
cd "$CORE_DIR"
cargo test --workspace

echo -e "\n[Step 3/6] Running Rust Clippy Lint Audit (-D warnings)..."
cargo clippy --workspace --all-targets -- -D warnings

echo -e "\n[Step 4/6] Verifying iOS, macOS, and Linux Integration Files..."
test -f "$FLUTTER_DIR/ios/Runner/AppDelegate.swift"
test -f "$FLUTTER_DIR/ios/Runner/Info.plist"
test -f "$FLUTTER_DIR/ios/CredentialProviderExtension/CredentialProviderViewController.swift"
test -f "$FLUTTER_DIR/ios/CredentialProviderExtension/Info.plist"
test -f "$FLUTTER_DIR/ios/CredentialProviderExtension/CredentialProviderExtension.entitlements"
test -f "$FLUTTER_DIR/macos/Runner/AppDelegate.swift"
test -f "$FLUTTER_DIR/macos/Runner/MainFlutterWindow.swift"
test -f "$FLUTTER_DIR/linux/runner/my_application.cc"
test -f "$FLUTTER_DIR/linux/pwdvault.desktop"
test -f "$FLUTTER_DIR/linux/com.antigravity.pwdvault.metainfo.xml"
test -f "$FLUTTER_DIR/linux/debian/control"
echo "  All platform architecture files verified"

echo -e "\n[Step 5/6] Running Flutter Static Analysis..."
cd "$FLUTTER_DIR"
flutter analyze

echo -e "\n[Step 6/6] Running Flutter Test Suite..."
flutter test

echo -e "\n=========================================================="
echo "  PHASE 5 VERIFICATION GATE PASSED SUCCESSFULLY!          "
echo "=========================================================="
