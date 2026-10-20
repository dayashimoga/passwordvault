#!/usr/bin/env bash
# Antigravity Vault - Phase 4 Verification Gate (Autofill & Browser Integration)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CORE_DIR="$WORKSPACE_ROOT/core"
FLUTTER_DIR="$WORKSPACE_ROOT/apps/flutter"
EXT_DIR="$WORKSPACE_ROOT/apps/browser_extension"

echo "=========================================================="
echo "  PWDVAULT PHASE 4 VERIFICATION GATE: AUTOFILL & BROWSER  "
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

echo -e "\n[Step 4/6] Building Native Messaging Host..."
cargo build -p pwdvault-native-host

echo -e "\n[Step 5/6] Verifying Browser Extension Structure..."
test -f "$EXT_DIR/manifest.json"
test -f "$EXT_DIR/background/service_worker.js"
test -f "$EXT_DIR/popup/popup.html"
test -f "$EXT_DIR/popup/popup.js"
test -f "$EXT_DIR/popup/popup.css"
test -f "$EXT_DIR/content/content.js"
test -f "$EXT_DIR/content/content.css"
test -f "$EXT_DIR/icons/icon16.png"
test -f "$EXT_DIR/icons/icon48.png"
test -f "$EXT_DIR/icons/icon128.png"
echo "  Browser extension structure verified"

echo -e "\n[Step 6/6] Running Flutter Static Analysis and Tests..."
cd "$FLUTTER_DIR"
flutter analyze
flutter test

echo -e "\n=========================================================="
echo "  PHASE 4 VERIFICATION GATE PASSED SUCCESSFULLY!          "
echo "=========================================================="
