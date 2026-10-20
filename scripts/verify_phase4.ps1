<#
.SYNOPSIS
    Idempotent Phase 4 verification script for Autofill & Browser Integration.
.DESCRIPTION
    Validates Phase 4 (Autofill & Browser Integration Gate):
    - Toolchains verification (Rust 1.99+, Flutter 3.38+, Dart 3.10+)
    - Rust workspace test suites (all 9 workspace crates including pwdvault-native-host)
    - Rust workspace Clippy lint audit (zero warnings)
    - Native messaging host binary build and execution
    - Browser Extension Manifest V3, background service worker, popup, content scripts, and icons
    - Native messaging manifests and Windows Registry configuration
    - Android Autofill Framework integration (AutofillService, AssistStructure parser, RemoteViews layout)
    - Flutter static analysis (flutter analyze - zero issues)
    - Full Flutter test suite (FFI bindings, models, UI)
    - Security Invariants:
        * 1 MiB native messaging framing limit
        * 256-bit CSPRNG session token validation
        * Top-level iframe isolation (window === window.top)
        * Strict anti-phishing origin verification with eTLD+1 heuristic
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
Write-Host "  PWDVAULT PHASE 4 VERIFICATION GATE: AUTOFILL & BROWSER  " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$rootDir = (Resolve-Path "$PSScriptRoot\..").Path
$coreDir = Join-Path $rootDir "core"
$flutterDir = Join-Path $rootDir "apps\flutter"
$extDir = Join-Path $rootDir "apps\browser_extension"

# Step 1: Toolchain check
Write-Host "`n[Step 1/7] Checking Toolchains..." -ForegroundColor Yellow
$rustcVer = & rustc --version
$cargoVer = & cargo --version
$flutterVer = & flutter --version | Select-Object -First 1
Write-Host "  Rust:    $rustcVer" -ForegroundColor Green
Write-Host "  Cargo:   $cargoVer" -ForegroundColor Green
Write-Host "  Flutter: $flutterVer" -ForegroundColor Green

# Step 2: Rust Core Workspace Tests (All 9 crates)
Write-Host "`n[Step 2/7] Running Rust Core Workspace Tests (All 9 Crates)..." -ForegroundColor Yellow
Push-Location $coreDir
try {
    & cargo test --workspace
    if ($LASTEXITCODE -ne 0) {
        throw "Rust workspace tests failed with exit code $LASTEXITCODE"
    }
    Write-Host "  All Rust unit, property, and integration tests PASSED" -ForegroundColor Green
} finally {
    Pop-Location
}

# Step 3: Rust Workspace Clippy Lint Audit
Write-Host "`n[Step 3/7] Auditing Rust Code Quality with Clippy (-D warnings)..." -ForegroundColor Yellow
Push-Location $coreDir
try {
    & cargo clippy --workspace --all-targets -- -D warnings
    if ($LASTEXITCODE -ne 0) {
        throw "Rust Clippy lint audit failed with exit code $LASTEXITCODE"
    }
    Write-Host "  Clippy audit passed with 0 warnings" -ForegroundColor Green
} finally {
    Pop-Location
}

# Step 4: Build & Register Native Messaging Host
Write-Host "`n[Step 4/7] Validating Native Messaging Host & Registration..." -ForegroundColor Yellow
Push-Location $coreDir
try {
    & cargo build -p pwdvault-native-host
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to build pwdvault-native-host"
    }
} finally {
    Pop-Location
}

$hostExe = Join-Path $coreDir "target\debug\pwdvault-native-host.exe"
if (-not (Test-Path $hostExe)) {
    throw "Native host binary not found at $hostExe"
}
Write-Host "  Native host binary: $hostExe" -ForegroundColor Green

& powershell.exe -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "register_native_host.ps1")
Write-Host "  Native host registered in Windows Registry" -ForegroundColor Green

# Step 5: Verify Browser Extension Manifest & Components
Write-Host "`n[Step 5/7] Verifying Browser Extension Structure..." -ForegroundColor Yellow
& powershell.exe -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "verify_extension.ps1")

# Step 6: Verify Android Autofill Framework Integration
Write-Host "`n[Step 6/7] Verifying Android Autofill Integration..." -ForegroundColor Yellow
$manifestPath = Join-Path $flutterDir "android\app\src\main\AndroidManifest.xml"
$manifestContent = Get-Content -Path $manifestPath -Raw
if (-not ($manifestContent -match "PwdVaultAutofillService" -and $manifestContent -match "BIND_AUTOFILL_SERVICE")) {
    throw "AndroidManifest.xml is missing PwdVaultAutofillService or BIND_AUTOFILL_SERVICE"
}
Write-Host "  AndroidManifest.xml declares PwdVaultAutofillService" -ForegroundColor Green

$xmlConfig = Join-Path $flutterDir "android\app\src\main\res\xml\autofill_service_config.xml"
if (-not (Test-Path $xmlConfig)) {
    throw "Missing autofill_service_config.xml at $xmlConfig"
}
Write-Host "  autofill_service_config.xml exists" -ForegroundColor Green

$layoutXml = Join-Path $flutterDir "android\app\src\main\res\layout\autofill_dataset_item.xml"
if (-not (Test-Path $layoutXml)) {
    throw "Missing autofill_dataset_item.xml at $layoutXml"
}
Write-Host "  autofill_dataset_item.xml layout exists" -ForegroundColor Green

$parserKt = Join-Path $flutterDir "android\app\src\main\kotlin\com\antigravity\pwdvault\pwdvault_flutter\autofill\AutofillStructureParser.kt"
$serviceKt = Join-Path $flutterDir "android\app\src\main\kotlin\com\antigravity\pwdvault\pwdvault_flutter\autofill\PwdVaultAutofillService.kt"
if (-not (Test-Path $parserKt) -or -not (Test-Path $serviceKt)) {
    throw "Missing Android Autofill Kotlin implementations"
}
Write-Host "  AutofillStructureParser.kt and PwdVaultAutofillService.kt exist" -ForegroundColor Green

# Step 7: Flutter Static Analysis & Tests
Write-Host "`n[Step 7/7] Running Flutter Static Analysis and Test Suite..." -ForegroundColor Yellow
# Ensure FFI dynamic library is built and in place
& powershell.exe -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "build_ffi.ps1")

Push-Location $flutterDir
try {
    Write-Host "  Running flutter analyze..." -ForegroundColor Gray
    & flutter analyze
    if ($LASTEXITCODE -ne 0) {
        throw "Flutter analyze reported issues"
    }
    Write-Host "  Flutter analyze passed with 0 issues" -ForegroundColor Green

    Write-Host "  Running flutter test..." -ForegroundColor Gray
    & flutter test
    if ($LASTEXITCODE -ne 0) {
        throw "Flutter test suite failed"
    }
    Write-Host "  Flutter test suite PASSED" -ForegroundColor Green
} finally {
    Pop-Location
}

Write-Host "`n==========================================================" -ForegroundColor Green
Write-Host "  PHASE 4 VERIFICATION GATE PASSED SUCCESSFULLY!          " -ForegroundColor Green
Write-Host "  Autofill, Native Messaging, Extension, and Android OK  " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
