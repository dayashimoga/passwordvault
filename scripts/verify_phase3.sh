#!/usr/bin/env bash
# PwdVault Phase 3 Verification Gate (Backup, Recovery, Portability)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CORE_DIR="$ROOT_DIR/core"
FLUTTER_DIR="$ROOT_DIR/apps/flutter"

echo "=========================================================="
echo "  PWDVAULT PHASE 3 VERIFICATION GATE: BACKUP & PORTABILITY"
echo "=========================================================="

echo -e "\n[Step 1/7] Checking Toolchains..."
rustc --version
cargo --version
flutter --version | head -n 1

echo -e "\n[Step 2/7] Running Rust Core Workspace Tests..."
(cd "$CORE_DIR" && cargo test)

echo -e "\n[Step 3/7] Running Rust Workspace Clippy Audit..."
(cd "$CORE_DIR" && cargo clippy --all-targets -- -D warnings)

echo -e "\n[Step 4/7] Building and Deploying Release FFI Dynamic Library..."
(cd "$CORE_DIR" && cargo build --release -p pwdvault-ffi)
if [ -f "$CORE_DIR/target/release/libpwdvault_ffi.so" ]; then
    cp "$CORE_DIR/target/release/libpwdvault_ffi.so" "$FLUTTER_DIR/"
elif [ -f "$CORE_DIR/target/release/libpwdvault_ffi.dylib" ]; then
    cp "$CORE_DIR/target/release/libpwdvault_ffi.dylib" "$FLUTTER_DIR/"
fi

echo -e "\n[Step 5/7] Running Flutter Static Analysis..."
(cd "$FLUTTER_DIR" && flutter analyze)

echo -e "\n[Step 6/7] Executing Flutter Test Suites..."
(cd "$FLUTTER_DIR" && flutter test)

echo -e "\n[Step 7/7] Verifying Phase 3 Security Invariants..."
# Invariant checks
grep -q "PVBAK001" "$CORE_DIR/backup/src/archive.rs"
grep -q "rehearse_restore" "$CORE_DIR/backup/src/archive.rs"
grep -q "CROCKFORD_ALPHABET" "$CORE_DIR/backup/src/recovery_kit.rs"
grep -q "ZeroizeOnDrop" "$CORE_DIR/backup/src/recovery_kit.rs"
grep -q "ConflictDiff" "$CORE_DIR/import_export/src/dedup.rs"
grep -q "revision_history\.push" "$CORE_DIR/import_export/src/dedup.rs"
grep -q "Re-authenticate Master Passphrase" "$FLUTTER_DIR/lib/views/settings/import_export_sheet.dart"

echo "=========================================================="
echo "  PHASE 3 VERIFICATION COMPLETE: ALL GATES PASSED (100%)"
echo "=========================================================="
exit 0
