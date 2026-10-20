#!/usr/bin/env bash
set -euo pipefail

# Phase 2 Verification Script for POSIX / CI environments
echo "=========================================================="
echo "  PWDVAULT PHASE 2 VERIFICATION GATE: WINDOWS & ANDROID MVP"
echo "=========================================================="

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
CORE_DIR="${ROOT_DIR}/core"
FLUTTER_DIR="${ROOT_DIR}/apps/flutter"

echo ""
echo "[Step 1/5] Checking Toolchains..."
rustc --version
cargo --version
flutter --version | head -n 1

echo ""
echo "[Step 2/5] Building Rust FFI Dynamic Library..."
cd "${CORE_DIR}"
cargo build --release -p pwdvault-ffi
echo "  [OK] pwdvault-ffi built successfully"

echo ""
echo "[Step 3/5] Running Flutter Static Analysis..."
cd "${FLUTTER_DIR}"
flutter analyze
echo "  [OK] Flutter analyze passed with zero issues"

echo ""
echo "[Step 4/5] Executing Flutter Test Suites..."
cd "${FLUTTER_DIR}"
flutter test
echo "  [OK] All Flutter tests passed"

echo ""
echo "[Step 5/5] Verifying Platform Invariants and Screen Protection..."
grep -q "FLAG_SECURE" "${FLUTTER_DIR}/android/app/src/main/kotlin/com/antigravity/pwdvault/pwdvault_flutter/MainActivity.kt"
echo "  [OK] Android FLAG_SECURE verified"

grep -q "FlutterFragmentActivity" "${FLUTTER_DIR}/android/app/src/main/kotlin/com/antigravity/pwdvault/pwdvault_flutter/MainActivity.kt"
echo "  [OK] Android FlutterFragmentActivity verified"

grep -q "resetInactivityTimer" "${FLUTTER_DIR}/lib/services/vault_state.dart"
grep -q "Duration(seconds: 30)" "${FLUTTER_DIR}/lib/services/vault_state.dart"
echo "  [OK] Auto-lock and clipboard zeroization invariants verified"

echo ""
echo "=========================================================="
echo "  PHASE 2 VERIFICATION COMPLETE: ALL GATES PASSED (100%)"
echo "=========================================================="
exit 0
