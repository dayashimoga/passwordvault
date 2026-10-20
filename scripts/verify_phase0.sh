#!/usr/bin/env bash
set -euo pipefail

echo "=========================================================="
echo "  PWDVAULT PHASE 0 VERIFICATION GATE (POSIX)"
echo "=========================================================="

echo "[1/4] Checking documentation completeness..."
for doc in \
  docs/Requirements.md \
  docs/Architecture.md \
  docs/SecurityArchitecture.md \
  docs/ADR/ADR-001-vault-format-and-storage.md \
  docs/ADR/ADR-002-cryptographic-primitives-and-kdf.md \
  docs/ADR/ADR-003-ffi-and-ui-integration.md \
  docs/ADR/ADR-004-memory-zeroization-and-sanitization.md \
  docs/ImplementationPlan.md \
  docs/Setup.md \
  docs/DeveloperGuide.md \
  docs/CodeUnderstanding.md \
  docs/UserGuide.md \
  docs/TestingStrategy.md \
  docs/PerformanceStrategy.md \
  docs/RecoveryGuide.md \
  docs/Troubleshooting.md \
  docs/ReleaseProcess.md \
  docs/RiskRegister.md \
  docs/CHANGELOG.md \
  docs/TODO.md; do
  if [ ! -f "$doc" ]; then
    echo "Missing mandatory documentation: $doc"
    exit 1
  fi
  echo "  [OK] $doc"
done

echo "[2/4] Running format and clippy checks..."
(cd core && cargo fmt --all -- --check)
(cd core && cargo clippy --workspace --all-targets -- -D warnings)

echo "[3/4] Running core unit and integration tests..."
(cd core && cargo test --workspace -- --nocapture)

echo "[4/4] Running cryptographic benchmarks..."
(cd benchmarks && cargo run --release --bin kdf_bench)

echo "=========================================================="
echo "  PHASE 0 VERIFICATION COMPLETED SUCCESSFULLY"
echo "=========================================================="
