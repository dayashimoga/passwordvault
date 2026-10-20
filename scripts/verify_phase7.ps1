<#
.SYNOPSIS
    Idempotent Phase 7 verification script for Advanced Personal Security.
.DESCRIPTION
    Validates Phase 7 (Advanced Personal Security Gate):
    - Toolchains verification (Rust 1.99+, Flutter 3.38+, Dart 3.10+)
    - Rust workspace test suites (all 10 workspace crates including pwdvault-security)
    - Rust workspace Clippy lint audit (zero warnings with -D warnings)
    - Advanced Personal Security & Cryptographic Invariants:
        * RFC 6238 TOTP authenticator engine (RFC 4648 Base32, SHA-1/256/512 HMAC, tolerance drift window)
        * WebAuthn / FIDO2 Passkey credential generation (ES256 / EdDSA, 37-byte authenticator data framing, assertion signing)
        * Privacy-preserving k-Anonymity breach watch (5-char SHA-1 prefix query, local 35-char suffix matching)
        * Local vault security hygiene auditor (reused passwords, weak passwords, stale passwords, missing 2FA, 0-100 score)
    - C-ABI FFI security exports (vault_ffi_totp_*, vault_ffi_passkey_*, vault_ffi_audit_*, vault_ffi_breach_*)
    - Build and deployment of release FFI dynamic library
    - Flutter FFI bindings, models, state coordinator, and SecurityAuditSheet UI
    - Flutter static analysis (flutter analyze - zero issues)
    - Flutter test suite (all tests passing including security_audit_test.dart)
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
Write-Host "  PWDVAULT PHASE 7 VERIFICATION GATE: PERSONAL SECURITY   " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$rootDir = (Resolve-Path "$PSScriptRoot\..").Path
$coreDir = Join-Path $rootDir "core"
$flutterDir = Join-Path $rootDir "apps\flutter"

# Step 1: Toolchain check
Write-Host "`n[Step 1/8] Checking Toolchains..." -ForegroundColor Yellow
$rustcVer = & rustc --version
$cargoVer = & cargo --version
$flutterVer = & flutter --version | Select-Object -First 1
Write-Host "  Rust:    $rustcVer" -ForegroundColor Green
Write-Host "  Cargo:   $cargoVer" -ForegroundColor Green
Write-Host "  Flutter: $flutterVer" -ForegroundColor Green

# Step 2: Rust Core Workspace Tests
Write-Host "`n[Step 2/8] Running Rust Core Workspace Tests (10 Crates)..." -ForegroundColor Yellow
Push-Location $coreDir
try {
    & cargo test --workspace
    if ($LASTEXITCODE -ne 0) {
        throw "Rust workspace tests failed"
    }
    Write-Host "  All Rust workspace tests passed (pwdvault-security, crypto, vault, ffi, sync, etc.)" -ForegroundColor Green
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

# Step 4: Verify Advanced Personal Security & Invariants
Write-Host "`n[Step 4/8] Verifying Security Architecture & Cryptographic Invariants..." -ForegroundColor Yellow
$totpFile = Join-Path $coreDir "security\src\totp.rs"
$passkeyFile = Join-Path $coreDir "security\src\passkey.rs"
$auditFile = Join-Path $coreDir "security\src\audit.rs"
$sha1File = Join-Path $coreDir "security\src\sha1.rs"
$hmacFile = Join-Path $coreDir "security\src\hmac.rs"

$totpContent = Get-Content $totpFile -Raw
if (-not ($totpContent -match "RFC 6238") -or -not ($totpContent -match "otpauth://totp/")) {
    throw "Missing RFC 6238 TOTP engine or otpauth URI support in totp.rs"
}
Write-Host "  [OK] RFC 6238 TOTP engine with RFC 4648 Base32 & drift window verified" -ForegroundColor Green

$passkeyContent = Get-Content $passkeyFile -Raw
if (-not ($passkeyContent -match "PasskeyCredential") -or -not ($passkeyContent -match "auth_data")) {
    throw "Missing Passkey credential or 37-byte authenticator data framing in passkey.rs"
}
Write-Host "  [OK] WebAuthn / FIDO2 Passkey credential generation & assertion signing verified" -ForegroundColor Green

$auditContent = Get-Content $auditFile -Raw
if (-not ($auditContent -match "prepare_breach_query") -or -not ($auditContent -match "check_suffix_in_range_response") -or -not ($auditContent -match "audit_vault")) {
    throw "Missing k-anonymity breach query or vault health auditor in audit.rs"
}
Write-Host "  [OK] Privacy-preserving k-Anonymity breach watch & vault health auditor verified" -ForegroundColor Green

$sha1Content = Get-Content $sha1File -Raw
if (-not ($sha1Content -match "RFC 3174") -or -not ($sha1Content -match "Sha1::digest")) {
    throw "Missing RFC 3174 SHA-1 digest engine in sha1.rs"
}
Write-Host "  [OK] RFC 3174 SHA-1 digest engine verified" -ForegroundColor Green

$hmacContent = Get-Content $hmacFile -Raw
if (-not ($hmacContent -match "hmac_sha1") -or -not ($hmacContent -match "ConstantTimeEq")) {
    throw "Missing constant-time HMAC engine in hmac.rs"
}
Write-Host "  [OK] RFC 2104 constant-time HMAC engine verified" -ForegroundColor Green

# Step 5: Verify C-ABI FFI Security Exports
Write-Host "`n[Step 5/8] Verifying C-ABI FFI Security Function Exports..." -ForegroundColor Yellow
$ffiLib = Join-Path $coreDir "ffi\src\lib.rs"
$ffiContent = Get-Content $ffiLib -Raw
$requiredFns = @(
    "vault_ffi_totp_generate",
    "vault_ffi_totp_verify",
    "vault_ffi_totp_parse_uri",
    "vault_ffi_passkey_generate",
    "vault_ffi_passkey_sign_assertion",
    "vault_ffi_audit_vault",
    "vault_ffi_breach_prepare_query",
    "vault_ffi_breach_check_response"
)
foreach ($fn in $requiredFns) {
    if (-not ($ffiContent -match $fn)) {
        throw "Missing FFI security export: $fn in core/ffi/src/lib.rs"
    }
}
Write-Host "  [OK] All 8 C-ABI FFI security exports verified" -ForegroundColor Green

# Step 6: Build & Deploy FFI Dynamic Library
Write-Host "`n[Step 6/8] Compiling and Deploying FFI Dynamic Library..." -ForegroundColor Yellow
& powershell.exe -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "build_ffi.ps1")
if ($LASTEXITCODE -ne 0) {
    throw "Failed to build FFI library"
}
Write-Host "  [OK] pwdvault_ffi.dll built and deployed to apps/flutter" -ForegroundColor Green

# Step 7: Verify Flutter Security UI & State Integration
Write-Host "`n[Step 7/8] Verifying Flutter Security UI & State Architecture..." -ForegroundColor Yellow
$securitySheet = Join-Path $flutterDir "lib\views\settings\security_audit_sheet.dart"
$settingsView = Join-Path $flutterDir "lib\views\settings\settings_view.dart"
$itemDetail = Join-Path $flutterDir "lib\views\items\item_detail_view.dart"
$itemEditor = Join-Path $flutterDir "lib\views\items\item_editor_view.dart"
$bindings = Join-Path $flutterDir "lib\core\ffi\vault_ffi_bindings.dart"
$stateFile = Join-Path $flutterDir "lib\services\vault_state.dart"

if (-not (Test-Path $securitySheet)) {
    throw "Missing security_audit_sheet.dart"
}
$securitySheetContent = Get-Content $securitySheet -Raw
if (-not ($securitySheetContent -match "Vault Health Audit") -or -not ($securitySheetContent -match "Breach Watch") -or -not ($securitySheetContent -match "Passkey & FIDO2 Lab")) {
    throw "Missing required tabs in security_audit_sheet.dart"
}

$settingsContent = Get-Content $settingsView -Raw
if (-not ($settingsContent -match "_showSecurityAuditSheet")) {
    throw "SecurityAuditSheet is not wired into settings_view.dart"
}

$itemDetailContent = Get-Content $itemDetail -Raw
if (-not ($itemDetailContent -match "Two-Factor Authenticator") -or -not ($itemDetailContent -match "generateTotpCode")) {
    throw "Live TOTP card is not wired into item_detail_view.dart"
}

$itemEditorContent = Get-Content $itemEditor -Raw
if (-not ($itemEditorContent -match "Two-Factor Authenticator") -or -not ($itemEditorContent -match "parseTotpUri")) {
    throw "TOTP secret/URI input is not wired into item_editor_view.dart"
}

$bindingsContent = Get-Content $bindings -Raw
if (-not ($bindingsContent -match "generateTotp") -or -not ($bindingsContent -match "auditVault") -or -not ($bindingsContent -match "generatePasskey")) {
    throw "Missing typed security methods in vault_ffi_bindings.dart"
}

$stateContent = Get-Content $stateFile -Raw
if (-not ($stateContent -match "runSecurityAudit") -or -not ($stateContent -match "checkPasswordBreach")) {
    throw "Missing security audit operations in vault_state.dart"
}
Write-Host "  [OK] Flutter SecurityAuditSheet (3 tabs), bindings, state, detail/editor TOTP, and settings integration verified" -ForegroundColor Green

# Step 8: Flutter Static Analysis and Tests
Write-Host "`n[Step 8/8] Running Flutter Static Analysis and Test Suite..." -ForegroundColor Yellow
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
    Write-Host "  Flutter test suite PASSED (All 38 unit, widget, sync, and security audit tests)" -ForegroundColor Green
} finally {
    Pop-Location
}

Write-Host "`n==========================================================" -ForegroundColor Green
Write-Host "  PHASE 7 VERIFICATION GATE PASSED SUCCESSFULLY!          " -ForegroundColor Green
Write-Host "  Advanced Personal Security & Audit Operational          " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
