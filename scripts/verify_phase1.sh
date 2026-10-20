#!/usr/bin/env bash
# Phase 1 Verification Script for Linux / macOS / CI

set -euo pipefail

echo "=========================================================="
echo "  PWDVAULT PHASE 1 VERIFICATION GATE: RUST SECURITY CORE"
echo "=========================================================="

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
CORE_DIR="${ROOT_DIR}/core"
BENCH_DIR="${ROOT_DIR}/benchmarks"

# Step 1: Toolchain check
echo -e "\n[Step 1/6] Checking Toolchains..."
rustc --version
cargo --version

# Step 2: Unsafe code audit
echo -e "\n[Step 2/6] Auditing Unsafe Code Invariants..."
CRATES=("crypto" "vault" "generator" "search" "backup" "import_export" "sync")
for CRATE in "${CRATES[@]}"; do
    LIB_FILE="${CORE_DIR}/${CRATE}/src/lib.rs"
    if [ -f "$LIB_FILE" ]; then
        if grep -q '#!\[deny(unsafe_code)\]' "$LIB_FILE"; then
            echo "  [OK] ${CRATE}: strictly forbids unsafe code"
        else
            echo "  [FAIL] ${CRATE} is missing #![deny(unsafe_code)]"
            exit 1
        fi
    fi
done

# Step 3: Formatting check
echo -e "\n[Step 3/6] Checking Formatting..."
(cd "$CORE_DIR" && cargo fmt --check)
(cd "$BENCH_DIR" && cargo fmt --check)
echo "  [OK] All code formatted cleanly"

# Step 4: Clippy linter
echo -e "\n[Step 4/6] Running Clippy (-D warnings)..."
(cd "$CORE_DIR" && cargo clippy --all-targets -- -D warnings)
(cd "$BENCH_DIR" && cargo clippy --all-targets -- -D warnings)
echo "  [OK] All crates passed clippy with zero warnings"

# Step 5: Test suites
echo -e "\n[Step 5/6] Executing Complete Test Suite (Unit, Proptest, Security)..."
(cd "$CORE_DIR" && cargo test)
echo "  [OK] All unit, property, and security integration tests passed"

# Step 6: Benchmarks and latency verification
echo -e "\n[Step 6/6] Executing Cryptographic & Search Scale Benchmarks..."
(cd "$BENCH_DIR" && cargo run --release --bin kdf_bench)
(cd "$BENCH_DIR" && cargo run --release --bin search_bench)
echo "  [OK] All performance and latency requirements verified"

echo -e "\n=========================================================="
echo "  PHASE 1 VERIFICATION COMPLETE: ALL GATES PASSED (100%)"
echo "=========================================================="
exit 0
