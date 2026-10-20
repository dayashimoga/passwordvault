#!/usr/bin/env bash
# Antigravity Vault - Phase 8 Verification Gate (Hardening, Packaging & Release)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CORE_DIR="$WORKSPACE_ROOT/core"
FLUTTER_DIR="$WORKSPACE_ROOT/apps/flutter"
DOCS_DIR="$WORKSPACE_ROOT/docs"
PACK_DIR="$WORKSPACE_ROOT/packaging"

echo "=========================================================="
echo "  PWDVAULT PHASE 8 VERIFICATION GATE: PRODUCTION RELEASE  "
echo "=========================================================="

echo -e "\n[Step 1/7] Checking Toolchains..."
rustc --version
cargo --version
flutter --version | head -n 1

echo -e "\n[Step 2/7] Running Rust Core Workspace Tests & Hardening Suites..."
cd "$CORE_DIR"
cargo test --workspace

echo -e "\n[Step 3/7] Running Rust Clippy Lint Audit (-D warnings)..."
cargo clippy --workspace --all-targets -- -D warnings

echo -e "\n[Step 4/7] Verifying Packaging Configurations & Artifacts..."
test -f "$PACK_DIR/windows/installer.iss"
test -f "$WORKSPACE_ROOT/scripts/package_windows.ps1"
test -f "$FLUTTER_DIR/android/app/proguard-rules.pro"
test -f "$WORKSPACE_ROOT/scripts/package_android.sh"
test -f "$WORKSPACE_ROOT/scripts/package_linux.sh"
test -f "$WORKSPACE_ROOT/scripts/package_apple.sh"
grep -q "proguard-rules.pro" "$FLUTTER_DIR/android/app/build.gradle.kts"
echo "  All cross-platform packaging configurations verified"

echo -e "\n[Step 5/7] Verifying SBOM & Release Documentation..."
test -f "$DOCS_DIR/SBOM.json"
test -f "$DOCS_DIR/SBOM.md"
test -f "$DOCS_DIR/PerformanceProfiling.md"
test -f "$DOCS_DIR/ReleaseChecklist.md"
grep -q "CycloneDX" "$DOCS_DIR/SBOM.json"
grep -q "Argon2id" "$DOCS_DIR/PerformanceProfiling.md"
grep -q "Production Release Candidate" "$DOCS_DIR/ReleaseChecklist.md"
echo "  All SBOM and production release documentation verified"

echo -e "\n[Step 6/7] Running Flutter Static Analysis..."
cd "$FLUTTER_DIR"
flutter analyze

echo -e "\n[Step 7/7] Running Flutter Test Suite..."
flutter test

echo -e "\n=========================================================="
echo "  PHASE 8 VERIFICATION GATE PASSED SUCCESSFULLY!          "
echo "  Production Release Ready Across All Platforms           "
echo "=========================================================="
