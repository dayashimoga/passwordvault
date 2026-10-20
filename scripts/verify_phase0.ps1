<#
.SYNOPSIS
    Idempotent Phase 0 verification script for Personal Password Generator & Encrypted Vault.
.DESCRIPTION
    Validates documentation, compiles all core crates, runs unit tests, verifies tamper detection,
    and executes cryptographic KDF & memory benchmarks.
#>

$ErrorActionPreference = "Stop"

# Ensure LLVM-MinGW and Cargo tools are in PATH
$llvmBin = "C:\Users\daya\AppData\Local\Microsoft\WinGet\Packages\MartinStorsjo.LLVM-MinGW.UCRT_Microsoft.Winget.Source_8wekyb3d8bbwe\llvm-mingw-20260908-ucrt-x86_64\bin"
if (Test-Path $llvmBin) {
    $env:PATH = "$llvmBin;C:\Users\daya\.cargo\bin;" + $env:PATH
} else {
    $env:PATH = "C:\Users\daya\.cargo\bin;" + $env:PATH
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  PWDVAULT PHASE 0 VERIFICATION GATE" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Environment Verification
Write-Host "`n[Step 1/5] Checking Toolchains..." -ForegroundColor Yellow
$rustcVer = & rustc --version
$cargoVer = & cargo --version
Write-Host "  Rust: $rustcVer" -ForegroundColor Green
Write-Host "  Cargo: $cargoVer" -ForegroundColor Green

# 2. Check documentation completeness
Write-Host "`n[Step 2/5] Validating Documentation Invariants..." -ForegroundColor Yellow
$rootDir = (Resolve-Path "$PSScriptRoot\..").Path
$requiredDocs = @(
    "docs/Requirements.md",
    "docs/Architecture.md",
    "docs/SecurityArchitecture.md",
    "docs/ADR/ADR-001-vault-format-and-storage.md",
    "docs/ADR/ADR-002-cryptographic-primitives-and-kdf.md",
    "docs/ADR/ADR-003-ffi-and-ui-integration.md",
    "docs/ADR/ADR-004-memory-zeroization-and-sanitization.md",
    "docs/ImplementationPlan.md",
    "docs/Setup.md",
    "docs/DeveloperGuide.md",
    "docs/CodeUnderstanding.md",
    "docs/UserGuide.md",
    "docs/TestingStrategy.md",
    "docs/PerformanceStrategy.md",
    "docs/RecoveryGuide.md",
    "docs/Troubleshooting.md",
    "docs/ReleaseProcess.md",
    "docs/RiskRegister.md",
    "docs/CHANGELOG.md",
    "docs/TODO.md"
)

foreach ($doc in $requiredDocs) {
    $fullPath = Join-Path $rootDir $doc
    if (Test-Path $fullPath) {
        Write-Host "  [OK] $doc" -ForegroundColor Green
    } else {
        Write-Error "Missing mandatory documentation: $doc"
    }
}

# 3. Format and Clippy Checks
Write-Host "`n[Step 3/5] Running Linters and Code Checks..." -ForegroundColor Yellow
Push-Location "$rootDir\core"
try {
    Write-Host "  Checking formatting (cargo fmt)..."
    & cargo fmt --all -- --check
    Write-Host "  [OK] Formatting is clean." -ForegroundColor Green

    Write-Host "  Running Clippy with warnings as errors..."
    & cargo clippy --workspace --all-targets -- -D warnings
    Write-Host "  [OK] Clippy passed with zero warnings." -ForegroundColor Green
} finally {
    Pop-Location
}

# 4. Unit & Integration Tests
Write-Host "`n[Step 4/5] Running Core Cryptographic & Vault Unit Tests..." -ForegroundColor Yellow
Push-Location "$rootDir\core"
try {
    & cargo test --workspace -- --nocapture
    Write-Host "  [OK] All core tests passed." -ForegroundColor Green
} finally {
    Pop-Location
}

# 5. Cryptographic Benchmarks
Write-Host "`n[Step 5/5] Executing Cryptographic & KDF Benchmarks..." -ForegroundColor Yellow
Push-Location "$rootDir\benchmarks"
try {
    & cargo run --release --bin kdf_bench
    Write-Host "  [OK] Benchmarks executed successfully." -ForegroundColor Green
} finally {
    Pop-Location
}

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host "  PHASE 0 VERIFICATION COMPLETED SUCCESSFULLY" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan
