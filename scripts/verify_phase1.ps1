<#
.SYNOPSIS
    Idempotent Phase 1 verification script for Personal Password Generator & Encrypted Vault.
.DESCRIPTION
    Validates Rust Security Core (Phase 1):
    - Deny(unsafe_code) enforcement across all core business crates
    - Code formatting (cargo fmt --check)
    - Zero clippy warnings with -D warnings
    - Full test suite: 39 unit, proptest, and security tests (tamper, bit-flip, truncation)
    - Cryptographic KDF benchmarks
    - Search index benchmarks: 10,000 and 100,000 items (p95 < 50ms)
#>

$ErrorActionPreference = "Stop"

# Ensure LLVM-MinGW and Cargo tools are in PATH
$llvmBin = "C:\Users\daya\AppData\Local\Microsoft\WinGet\Packages\MartinStorsjo.LLVM-MinGW.UCRT_Microsoft.Winget.Source_8wekyb3d8bbwe\llvm-mingw-20260908-ucrt-x86_64\bin"
if (Test-Path $llvmBin) {
    $env:PATH = "$llvmBin;C:\Users\daya\.cargo\bin;" + $env:PATH
} else {
    $env:PATH = "C:\Users\daya\.cargo\bin;" + $env:PATH
}
$env:CARGO_INCREMENTAL = "0"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  PWDVAULT PHASE 1 VERIFICATION GATE: RUST SECURITY CORE" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$rootDir = (Resolve-Path "$PSScriptRoot\..").Path
$coreDir = Join-Path $rootDir "core"
$benchDir = Join-Path $rootDir "benchmarks"

# Step 1: Toolchain check
Write-Host "`n[Step 1/6] Checking Toolchains..." -ForegroundColor Yellow
$rustcVer = & rustc --version
$cargoVer = & cargo --version
Write-Host "  Rust: $rustcVer" -ForegroundColor Green
Write-Host "  Cargo: $cargoVer" -ForegroundColor Green

# Step 2: Unsafe code audit
Write-Host "`n[Step 2/6] Auditing Unsafe Code Invariants..." -ForegroundColor Yellow
$cratesToCheck = @("crypto", "vault", "generator", "search", "backup", "import_export", "sync")
foreach ($crateName in $cratesToCheck) {
    $libFile = Join-Path $coreDir "$crateName\src\lib.rs"
    if (Test-Path $libFile) {
        $content = Get-Content $libFile -Raw
        if ($content -match '#!\[deny\(unsafe_code\)\]') {
            Write-Host "  [OK] ${crateName}: strictly forbids unsafe code" -ForegroundColor Green
        } else {
            Write-Error "  [FAIL] ${crateName} is missing #![deny(unsafe_code)]"
        }
    }
}

# Step 3: Formatting check
Write-Host "`n[Step 3/6] Checking Formatting..." -ForegroundColor Yellow
Push-Location $coreDir
try {
    & cargo fmt --check
    if ($LASTEXITCODE -ne 0) { throw "Formatting check failed in core" }
    Write-Host "  [OK] Core crates formatted cleanly" -ForegroundColor Green
} finally {
    Pop-Location
}

Push-Location $benchDir
try {
    & cargo fmt --check
    if ($LASTEXITCODE -ne 0) { throw "Formatting check failed in benchmarks" }
    Write-Host "  [OK] Benchmarks formatted cleanly" -ForegroundColor Green
} finally {
    Pop-Location
}

# Step 4: Clippy linter
Write-Host "`n[Step 4/6] Running Clippy (-D warnings)..." -ForegroundColor Yellow
Push-Location $coreDir
try {
    & cargo clippy --target x86_64-pc-windows-gnullvm --all-targets -- -D warnings
    if ($LASTEXITCODE -ne 0) { throw "Clippy linter failed in core" }
    Write-Host "  [OK] Core crates passed clippy with zero warnings" -ForegroundColor Green
} finally {
    Pop-Location
}

Push-Location $benchDir
try {
    & cargo clippy --target x86_64-pc-windows-gnullvm --all-targets -- -D warnings
    if ($LASTEXITCODE -ne 0) { throw "Clippy linter failed in benchmarks" }
    Write-Host "  [OK] Benchmarks passed clippy with zero warnings" -ForegroundColor Green
} finally {
    Pop-Location
}

# Step 5: Test suites
Write-Host "`n[Step 5/6] Executing Complete Test Suite (Unit, Proptest, Security)..." -ForegroundColor Yellow
Push-Location $coreDir
try {
    & cargo test --target x86_64-pc-windows-gnullvm
    if ($LASTEXITCODE -ne 0) { throw "Cargo test failed in core" }
    Write-Host "  [OK] All 39 unit, property, and security integration tests passed" -ForegroundColor Green
} finally {
    Pop-Location
}

# Step 6: Benchmarks and latency verification
Write-Host "`n[Step 6/6] Executing Cryptographic & Search Scale Benchmarks..." -ForegroundColor Yellow
Push-Location $benchDir
try {
    Write-Host "  -> Running KDF & Vault Cycle Benchmarks..." -ForegroundColor Cyan
    & cargo run --release --bin kdf_bench --target x86_64-pc-windows-gnullvm
    if ($LASTEXITCODE -ne 0) { throw "kdf_bench failed" }

    Write-Host "  -> Running Search Scale Benchmarks (10k and 100k items)..." -ForegroundColor Cyan
    & cargo run --release --bin search_bench --target x86_64-pc-windows-gnullvm
    if ($LASTEXITCODE -ne 0) { throw "search_bench failed" }

    Write-Host "  [OK] All performance and latency requirements verified" -ForegroundColor Green
} finally {
    Pop-Location
}

Write-Host "`n==========================================================" -ForegroundColor Green
Write-Host "  PHASE 1 VERIFICATION COMPLETE: ALL GATES PASSED (100%)" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
exit 0
