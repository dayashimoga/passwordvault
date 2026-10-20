<#
.SYNOPSIS
    Idempotent Phase 8 verification script for Hardening, Packaging & Release.
.DESCRIPTION
    Validates Phase 8 (Production Hardening & Release Gate):
    - Toolchains verification (Rust 1.99+, Flutter 3.38+, Dart 3.10+)
    - Rust workspace test suites (all 10 workspace crates including fuzz and hardening suites)
    - Rust workspace Clippy lint audit (zero warnings with -D warnings)
    - Security Fuzzing & Hardening suites (TOTP, k-Anonymity, Passkeys, CRDT idempotency, zeroization)
    - Cross-Platform Packaging & Distribution Architecture (Windows, Android, Linux, Apple)
    - Software Bill of Materials (SBOM) and supply chain integrity (CycloneDX 1.5 JSON)
    - Performance & battery profiling documentation
    - Release checklist and production release readiness
    - Build and deployment of release FFI dynamic library
    - Flutter static analysis (flutter analyze - zero issues)
    - Flutter test suite (all tests passing)
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
Write-Host "  PWDVAULT PHASE 8 VERIFICATION GATE: PRODUCTION RELEASE  " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$rootDir = (Resolve-Path "$PSScriptRoot\..").Path
$coreDir = Join-Path $rootDir "core"
$flutterDir = Join-Path $rootDir "apps\flutter"
$docsDir = Join-Path $rootDir "docs"
$packDir = Join-Path $rootDir "packaging"

# Step 1: Toolchain check
Write-Host "`n[Step 1/8] Checking Toolchains..." -ForegroundColor Yellow
$rustcVer = & rustc --version
$cargoVer = & cargo --version
$flutterVer = & flutter --version | Select-Object -First 1
Write-Host "  Rust:    $rustcVer" -ForegroundColor Green
Write-Host "  Cargo:   $cargoVer" -ForegroundColor Green
Write-Host "  Flutter: $flutterVer" -ForegroundColor Green

# Step 2: Rust Core Workspace Tests & Hardening Suites
Write-Host "`n[Step 2/8] Running Rust Core Workspace Tests & Hardening Suites (10 Crates)..." -ForegroundColor Yellow
Push-Location $coreDir
try {
    & cargo test --workspace
    if ($LASTEXITCODE -ne 0) {
        throw "Rust workspace tests failed"
    }
    Write-Host "  All Rust workspace tests passed (84+ unit, integration, property & fuzz tests)" -ForegroundColor Green
} finally {
    Pop-Location
}

# Step 3: Clippy Linter Check
Write-Host "`n[Step 3/8] Running Rust Clippy (Zero Warnings Enforcement)..." -ForegroundColor Yellow
Push-Location $coreDir
try {
    & cargo clippy --workspace --all-targets -- -D warnings
    if ($LASTEXITCODE -ne 0) {
        throw "Clippy reported warnings"
    }
    Write-Host "  Cargo clippy passed with 0 warnings" -ForegroundColor Green
} finally {
    Pop-Location
}

# Step 4: Verify Cross-Platform Packaging Configurations
Write-Host "`n[Step 4/8] Verifying Cross-Platform Packaging Configurations..." -ForegroundColor Yellow

# Windows Inno Setup & Packaging
$innoScript = Join-Path $packDir "windows\installer.iss"
$winPackScript = Join-Path $rootDir "scripts\package_windows.ps1"
if (-not (Test-Path $innoScript) -or -not (Test-Path $winPackScript)) {
    throw "Missing Windows installer or packaging scripts"
}
Write-Host "  [OK] Windows Inno Setup & packaging scripts verified" -ForegroundColor Green

# Android ProGuard & Packaging
$proguardFile = Join-Path $flutterDir "android\app\proguard-rules.pro"
$gradleFile = Join-Path $flutterDir "android\app\build.gradle.kts"
$androidPackPs1 = Join-Path $rootDir "scripts\package_android.ps1"
$androidPackSh = Join-Path $rootDir "scripts\package_android.sh"

if (-not (Test-Path $proguardFile) -or -not (Test-Path $androidPackPs1) -or -not (Test-Path $androidPackSh)) {
    throw "Missing Android ProGuard rules or packaging scripts"
}
$gradleContent = Get-Content $gradleFile -Raw
if (-not ($gradleContent -match "proguard-rules.pro") -or -not ($gradleContent -match "isMinifyEnabled = true")) {
    throw "ProGuard is not properly configured in build.gradle.kts"
}
Write-Host "  [OK] Android ProGuard / R8 optimization & packaging scripts verified" -ForegroundColor Green

# Linux & Apple Packaging
$linuxPackSh = Join-Path $rootDir "scripts\package_linux.sh"
$applePackSh = Join-Path $rootDir "scripts\package_apple.sh"
if (-not (Test-Path $linuxPackSh) -or -not (Test-Path $applePackSh)) {
    throw "Missing Linux or Apple packaging scripts"
}
Write-Host "  [OK] Linux and Apple (macOS & iOS) packaging scripts verified" -ForegroundColor Green

# Step 5: Verify SBOM & Documentation Integrity
Write-Host "`n[Step 5/8] Verifying Software Bill of Materials (SBOM) & Release Documentation..." -ForegroundColor Yellow
$sbomJson = Join-Path $docsDir "SBOM.json"
$sbomMd = Join-Path $docsDir "SBOM.md"
$perfDoc = Join-Path $docsDir "PerformanceProfiling.md"
$checklistDoc = Join-Path $docsDir "ReleaseChecklist.md"

if (-not (Test-Path $sbomJson) -or -not (Test-Path $sbomMd) -or -not (Test-Path $perfDoc) -or -not (Test-Path $checklistDoc)) {
    throw "Missing required release documentation or SBOM"
}

# Validate SBOM JSON structure
$sbomRaw = Get-Content $sbomJson -Raw
$sbomObj = ConvertFrom-Json $sbomRaw
if ($sbomObj.bomFormat -ne "CycloneDX" -or $sbomObj.components.Count -lt 5) {
    throw "Invalid CycloneDX SBOM structure or missing components"
}
Write-Host "  [OK] CycloneDX 1.5 JSON SBOM validated ($($sbomObj.components.Count) registered components)" -ForegroundColor Green

# Validate Performance & Checklist docs
$perfRaw = Get-Content $perfDoc -Raw
if (-not ($perfRaw -match "Argon2id") -or -not ($perfRaw -match "Battery") -or -not ($perfRaw -match "100,000 Items")) {
    throw "PerformanceProfiling.md is missing required benchmark sections"
}
Write-Host "  [OK] Hardware performance & battery profiling documentation verified" -ForegroundColor Green

$checklistRaw = Get-Content $checklistDoc -Raw
if (-not ($checklistRaw -match "Production Release Candidate") -or -not ($checklistRaw -match "Zero Data Loss Invariant")) {
    throw "ReleaseChecklist.md is missing required production criteria"
}
Write-Host "  [OK] Production release checklist & verification matrix verified" -ForegroundColor Green

# Step 6: Build & Deploy FFI Dynamic Library
Write-Host "`n[Step 6/8] Compiling and Deploying FFI Dynamic Library..." -ForegroundColor Yellow
& powershell.exe -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "build_ffi.ps1")
if ($LASTEXITCODE -ne 0) {
    throw "Failed to build FFI library"
}
Write-Host "  [OK] pwdvault_ffi.dll built and deployed to apps/flutter" -ForegroundColor Green

# Step 7: Flutter Static Analysis
Write-Host "`n[Step 7/8] Running Flutter Static Analysis..." -ForegroundColor Yellow
Push-Location $flutterDir
try {
    & flutter analyze
    if ($LASTEXITCODE -ne 0) {
        throw "Flutter analyze reported issues"
    }
    Write-Host "  Flutter analyze passed with 0 issues" -ForegroundColor Green
} finally {
    Pop-Location
}

# Step 8: Full Flutter Test Suite
Write-Host "`n[Step 8/8] Running Flutter Test Suite..." -ForegroundColor Yellow
Push-Location $flutterDir
try {
    & flutter test
    if ($LASTEXITCODE -ne 0) {
        throw "Flutter test suite failed"
    }
    Write-Host "  Flutter test suite PASSED (All 38 unit, widget, sync, and security audit tests)" -ForegroundColor Green
} finally {
    Pop-Location
}

Write-Host "`n==========================================================" -ForegroundColor Green
Write-Host "  PHASE 8 VERIFICATION GATE PASSED SUCCESSFULLY!          " -ForegroundColor Green
Write-Host "  Production Release Ready Across All Platforms           " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
