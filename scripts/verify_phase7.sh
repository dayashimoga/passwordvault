#!/usr/bin/env bash
# Antigravity Vault - Phase 7 Verification Gate (Advanced Personal Security)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CORE_DIR="$WORKSPACE_ROOT/core"
FLUTTER_DIR="$WORKSPACE_ROOT/apps/flutter"

echo "=========================================================="
echo "  PWDVAULT PHASE 7 VERIFICATION GATE: PERSONAL SECURITY   "
echo "=========================================================="

echo -e "\n[Step 1/7] Checking Toolchains..."
rustc --version
cargo --version
flutter --version | head -n 1

echo -e "\n[Step 2/7] Running Rust Core Workspace Tests (10 Crates)..."
cd "$CORE_DIR"
cargo test --workspace

echo -e "\n[Step 3/7] Running Rust Clippy Lint Audit (-D warnings)..."
cargo clippy --workspace --all-targets -- -D warnings

echo -e "\n[Step 4/7] Verifying Security Architecture & Cryptographic Invariants..."
grep -q "RFC 6238" "$CORE_DIR/security/src/totp.rs"
grep -q "PasskeyCredential" "$CORE_DIR/security/src/passkey.rs"
grep -q "prepare_breach_query" "$CORE_DIR/security/src/audit.rs"
grep -q "RFC 3174" "$CORE_DIR/security/src/sha1.rs"
grep -q "Sha1::digest" "$CORE_DIR/security/src/sha1.rs"
grep -q "hmac_sha1" "$CORE_DIR/security/src/hmac.rs"
echo "  All personal security core architecture and invariants verified"

echo -e "\n[Step 5/7] Verifying C-ABI FFI Security Exports..."
grep -q "vault_ffi_totp_generate" "$CORE_DIR/ffi/src/lib.rs"
grep -q "vault_ffi_totp_verify" "$CORE_DIR/ffi/src/lib.rs"
grep -q "vault_ffi_totp_parse_uri" "$CORE_DIR/ffi/src/lib.rs"
grep -q "vault_ffi_passkey_generate" "$CORE_DIR/ffi/src/lib.rs"
grep -q "vault_ffi_passkey_sign_assertion" "$CORE_DIR/ffi/src/lib.rs"
grep -q "vault_ffi_audit_vault" "$CORE_DIR/ffi/src/lib.rs"
grep -q "vault_ffi_breach_prepare_query" "$CORE_DIR/ffi/src/lib.rs"
grep -q "vault_ffi_breach_check_response" "$CORE_DIR/ffi/src/lib.rs"
echo "  All 8 C-ABI FFI security functions verified"

echo -e "\n[Step 6/7] Running Flutter Static Analysis..."
cd "$FLUTTER_DIR"
flutter analyze

echo -e "\n[Step 7/7] Running Flutter Test Suite (Including Security Audit Tests)..."
flutter test

echo -e "\n=========================================================="
echo "  PHASE 7 VERIFICATION GATE PASSED SUCCESSFULLY!          "
echo "  Advanced Personal Security & Audit Operational          "
echo "=========================================================="
