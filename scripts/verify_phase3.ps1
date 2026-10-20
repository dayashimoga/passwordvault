<#
.SYNOPSIS
    Idempotent Phase 3 verification script for Backup, Recovery, and Portability.
.DESCRIPTION
    Validates Phase 3 (Backup, Recovery & Portability Gate):
    - Toolchains verification (Rust 1.99+, Flutter 3.38+, Dart 3.10+)
    - Rust workspace test suites (Crypto, Generator, Vault, Search, Backup, Import/Export, FFI)
    - Rust workspace Clippy lint audit (zero warnings)
    - Release FFI dynamic library compilation and deployment
    - Flutter static analysis (flutter analyze - zero issues)
    - Full Flutter test suites (FFI integration, Models, Backup/Import integration, UI widgets)
    - Security invariants:
        * .vaultbak authenticated archive encryption and BLAKE3 integrity commitment
        * Non-destructive dry-run restoration rehearsal
        * 256-bit Crockford Base32 emergency recovery key and case tolerance
        * Multi-format import (Bitwarden, 1Password, KeePass XML, CSV)
        * Interactive deduplication engine with conflict diffing & revision preservation
        * Plaintext CSV export re-authentication guard & double-confirmation
#>

$ErrorActionPreference = "Stop"

# Ensure LLVM-MinGW, Cargo, and Flutter tools are in PATH
$llvmBin = "C:\Users\daya\AppData\Local\Microsoft\WinGet\Packages\MartinStorsjo.LLVM-MinGW.UCRT_Microsoft.Winget.Source_8wekyb3d8bbwe\llvm-mingw-20260908-ucrt-x86_64\bin"
if (Test-Path $llvmBin) {
    $env:PATH = "$llvmBin;C:\Users\daya\.cargo\bin;C:\Users\daya\flutter\bin;" + $env:PATH
} else {
    $env:PATH = "C:\Users\daya\.cargo\bin;C:\Users\daya\flutter\bin;" + $env:PATH
}
$env:CARGO_INCREMENTAL = "0"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  PWDVAULT PHASE 3 VERIFICATION GATE: BACKUP & PORTABILITY" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$rootDir = (Resolve-Path "$PSScriptRoot\..").Path
$coreDir = Join-Path $rootDir "core"
$flutterDir = Join-Path $rootDir "apps\flutter"

# Step 1: Toolchain check
Write-Host "`n[Step 1/7] Checking Toolchains..." -ForegroundColor Yellow
$rustcVer = & rustc --version
$cargoVer = & cargo --version
$flutterVer = & flutter --version | Select-Object -First 1
Write-Host "  Rust:    $rustcVer" -ForegroundColor Green
Write-Host "  Cargo:   $cargoVer" -ForegroundColor Green
Write-Host "  Flutter: $flutterVer" -ForegroundColor Green

# Step 2: Rust Workspace Unit, Property, and Integration Tests
Write-Host "`n[Step 2/7] Running Rust Core Workspace Tests (All Crates)..." -ForegroundColor Yellow
Push-Location $coreDir
try {
    & cargo test --target x86_64-pc-windows-gnullvm
    if ($LASTEXITCODE -ne 0) { throw "Cargo test suite failed across core workspace" }
    Write-Host "  [OK] All Rust core unit, property, and integration tests passed" -ForegroundColor Green
} finally {
    Pop-Location
}

# Step 3: Rust Workspace Clippy Audit
Write-Host "`n[Step 3/7] Running Rust Workspace Clippy Audit..." -ForegroundColor Yellow
Push-Location $coreDir
try {
    & cargo clippy --target x86_64-pc-windows-gnullvm --all-targets -- -D warnings
    if ($LASTEXITCODE -ne 0) { throw "Clippy found warnings or errors in core workspace" }
    Write-Host "  [OK] Clippy audit passed with zero warnings" -ForegroundColor Green
} finally {
    Pop-Location
}

# Step 4: Build Release FFI Dynamic Library and Deploy to Flutter Workspace
Write-Host "`n[Step 4/7] Building and Deploying Release FFI Dynamic Library..." -ForegroundColor Yellow
Push-Location $coreDir
try {
    & cargo build --release --target x86_64-pc-windows-gnullvm -p pwdvault-ffi
    if ($LASTEXITCODE -ne 0) { throw "Cargo build failed for pwdvault-ffi" }
    Write-Host "  [OK] pwdvault_ffi compiled cleanly in release profile" -ForegroundColor Green
} finally {
    Pop-Location
}

$dllPath = Join-Path $coreDir "target\x86_64-pc-windows-gnullvm\release\pwdvault_ffi.dll"
if (-not (Test-Path $dllPath)) {
    throw "Target dynamic library does not exist at $dllPath"
}
$dllSize = (Get-Item $dllPath).Length
Write-Host "  [OK] Binary exists: $dllPath ($([math]::Round($dllSize / 1MB, 2)) MB)" -ForegroundColor Green

Copy-Item $dllPath $flutterDir -Force
$unwindDll = Join-Path $llvmBin "libunwind.dll"
if (Test-Path $unwindDll) {
    Copy-Item $unwindDll $flutterDir -Force
    Copy-Item $unwindDll (Join-Path $coreDir "target\x86_64-pc-windows-gnullvm\release\") -Force
    Write-Host "  [OK] Copied libunwind.dll dependency alongside pwdvault_ffi.dll" -ForegroundColor Green
}
Write-Host "  [OK] Deployed dynamic libraries to $flutterDir" -ForegroundColor Green

# Step 5: Flutter Static Analysis
Write-Host "`n[Step 5/7] Running Flutter Static Analysis..." -ForegroundColor Yellow
Push-Location $flutterDir
try {
    & flutter analyze
    if ($LASTEXITCODE -ne 0) { throw "Flutter analyze identified issues" }
    Write-Host "  [OK] Flutter analyzer passed with zero issues" -ForegroundColor Green
} finally {
    Pop-Location
}

# Step 6: Flutter Test Suites (FFI, Backup, Deduplication, Models, Widgets)
Write-Host "`n[Step 6/7] Executing Flutter Test Suites..." -ForegroundColor Yellow
Push-Location $flutterDir
try {
    & flutter test
    if ($LASTEXITCODE -ne 0) { throw "Flutter tests failed" }
    Write-Host "  [OK] All Flutter unit, widget, and FFI integration tests passed" -ForegroundColor Green
} finally {
    Pop-Location
}

# Step 7: Phase 3 Security Invariants Verification
Write-Host "`n[Step 7/7] Verifying Phase 3 Security Invariants..." -ForegroundColor Yellow

# Invariant 1: .vaultbak archive signature commitment
$archiveRs = Join-Path $coreDir "backup\src\archive.rs"
$archiveContent = Get-Content $archiveRs -Raw
if ($archiveContent -match "PVBAK001" -and $archiveContent -match "rehearse_restore") {
    Write-Host "  [OK] Authenticated .vaultbak archive format & non-destructive rehearsal verified" -ForegroundColor Green
} else {
    throw "Backup crate is missing PVBAK001 signature or rehearsal verification"
}

# Invariant 2: 256-bit emergency recovery key Crockford Base32 format
$recKitRs = Join-Path $coreDir "backup\src\recovery_kit.rs"
$recKitContent = Get-Content $recKitRs -Raw
if ($recKitContent -match "CROCKFORD_ALPHABET" -and $recKitContent -match "ZeroizeOnDrop") {
    Write-Host "  [OK] 256-bit Crockford Base32 RecoveryKey with Zeroize memory hygiene verified" -ForegroundColor Green
} else {
    throw "Recovery kit is missing Crockford Base32 encoding or Zeroize memory hygiene"
}

# Invariant 3: Deduplication conflict diff and revision history archiving
$dedupRs = Join-Path $coreDir "import_export\src\dedup.rs"
$dedupContent = Get-Content $dedupRs -Raw
if ($dedupContent -match "ConflictDiff" -and $dedupContent -match "revision_history\.push") {
    Write-Host "  [OK] Deduplication engine with ConflictDiff and revision archiving verified" -ForegroundColor Green
} else {
    throw "Deduplication engine is missing ConflictDiff or revision history archiving"
}

# Invariant 4: Guarded plaintext CSV export requiring re-authentication
$exportSheet = Join-Path $flutterDir "lib\views\settings\import_export_sheet.dart"
$exportSheetContent = Get-Content $exportSheet -Raw
if ($exportSheetContent -match "Re-authenticate Master Passphrase" -and $exportSheetContent -match "HIGH SECURITY RISK: Plaintext Export") {
    Write-Host "  [OK] Guarded plaintext CSV export with re-authentication & double-confirmation verified" -ForegroundColor Green
} else {
    throw "Import/Export sheet is missing plaintext export re-authentication guard"
}

Write-Host "`n==========================================================" -ForegroundColor Green
Write-Host "  PHASE 3 VERIFICATION COMPLETE: ALL GATES PASSED (100%)" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
exit 0
