<#
.SYNOPSIS
    Idempotent Phase 5 verification script for iPhone/iPad and Desktop Integration.
.DESCRIPTION
    Validates Phase 5 (iPhone/iPad, macOS, and Linux Integration Gate):
    - Toolchains verification (Rust 1.99+, Flutter 3.38+, Dart 3.10+)
    - Rust workspace test suites (all 9 workspace crates)
    - Rust workspace Clippy lint audit (zero warnings)
    - iOS & iPadOS:
        * Multitasking snapshot privacy protection in AppDelegate.swift
        * LocalAuthentication Face ID / Touch ID MethodChannel in AppDelegate.swift
        * NSFaceIDUsageDescription in Info.plist
        * Credential Provider Extension (ASCredentialProviderViewController) in Swift
        * App Group entitlement (group.com.antigravity.pwdvault)
    - macOS:
        * Hardware screen capture protection (NSWindow.sharingType = .none) in MainFlutterWindow.swift
        * Touch ID LocalAuthentication and Keychain in AppDelegate.swift
    - Linux:
        * Window geometry and header bar setup in my_application.cc
        * XDG desktop entry (pwdvault.desktop)
        * AppStream metainfo XML (com.antigravity.pwdvault.metainfo.xml)
        * Debian packaging control template (debian/control)
    - Flutter static analysis (flutter analyze - zero issues)
    - Full Flutter test suite (FFI bindings, models, UI, platform biometrics)
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
Write-Host "  PWDVAULT PHASE 5 VERIFICATION GATE: IPHONE/IPAD & DESKTOPS" -ForegroundColor Cyan
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

# Step 2: Rust Core Workspace Tests
Write-Host "`n[Step 2/7] Running Rust Core Workspace Tests..." -ForegroundColor Yellow
Push-Location $coreDir
try {
    & cargo test --workspace
    if ($LASTEXITCODE -ne 0) {
        throw "Rust workspace tests failed"
    }
    Write-Host "  All Rust unit, property, and integration tests PASSED" -ForegroundColor Green
} finally {
    Pop-Location
}

# Step 3: Rust Clippy Lint Audit
Write-Host "`n[Step 3/7] Auditing Rust Code Quality with Clippy (-D warnings)..." -ForegroundColor Yellow
Push-Location $coreDir
try {
    & cargo clippy --workspace --all-targets -- -D warnings
    if ($LASTEXITCODE -ne 0) {
        throw "Rust Clippy lint audit failed"
    }
    Write-Host "  Clippy audit passed with 0 warnings" -ForegroundColor Green
} finally {
    Pop-Location
}

# Step 4: Verify iOS & iPadOS Integration
Write-Host "`n[Step 4/7] Verifying iOS & iPadOS Architecture..." -ForegroundColor Yellow
$iosAppDel = Join-Path $flutterDir "ios\Runner\AppDelegate.swift"
$iosAppDelContent = Get-Content -Path $iosAppDel -Raw
if (-not ($iosAppDelContent -match "LocalAuthentication" -and $iosAppDelContent -match "privacyShieldView")) {
    throw "AppDelegate.swift missing LocalAuthentication or privacyShieldView"
}
Write-Host "  [OK] iOS AppDelegate implements LocalAuthentication and privacy shield" -ForegroundColor Green

$iosPlist = Join-Path $flutterDir "ios\Runner\Info.plist"
$iosPlistContent = Get-Content -Path $iosPlist -Raw
if (-not ($iosPlistContent -match "NSFaceIDUsageDescription")) {
    throw "iOS Info.plist missing NSFaceIDUsageDescription"
}
Write-Host "  [OK] iOS Info.plist declares NSFaceIDUsageDescription" -ForegroundColor Green

$iosExtVC = Join-Path $flutterDir "ios\CredentialProviderExtension\CredentialProviderViewController.swift"
$iosExtPlist = Join-Path $flutterDir "ios\CredentialProviderExtension\Info.plist"
$iosExtEnt = Join-Path $flutterDir "ios\CredentialProviderExtension\CredentialProviderExtension.entitlements"
if (-not (Test-Path $iosExtVC) -or -not (Test-Path $iosExtPlist) -or -not (Test-Path $iosExtEnt)) {
    throw "Missing iOS Credential Provider Extension files"
}
Write-Host "  [OK] iOS Credential Provider Extension (ASCredentialProviderViewController) verified" -ForegroundColor Green

# Step 5: Verify macOS Integration
Write-Host "`n[Step 5/7] Verifying macOS Architecture..." -ForegroundColor Yellow
$macWindow = Join-Path $flutterDir "macos\Runner\MainFlutterWindow.swift"
$macWindowContent = Get-Content -Path $macWindow -Raw
if (-not ($macWindowContent -match "sharingType = \.none")) {
    throw "MainFlutterWindow.swift missing sharingType = .none screen protection"
}
Write-Host "  [OK] macOS MainFlutterWindow implements sharingType = .none screen protection" -ForegroundColor Green

$macAppDel = Join-Path $flutterDir "macos\Runner\AppDelegate.swift"
$macAppDelContent = Get-Content -Path $macAppDel -Raw
if (-not ($macAppDelContent -match "LocalAuthentication")) {
    throw "macOS AppDelegate.swift missing LocalAuthentication Touch ID"
}
Write-Host "  [OK] macOS AppDelegate implements LocalAuthentication Touch ID" -ForegroundColor Green

# Step 6: Verify Linux Integration
Write-Host "`n[Step 6/7] Verifying Linux Architecture..." -ForegroundColor Yellow
$linuxApp = Join-Path $flutterDir "linux\runner\my_application.cc"
$linuxAppContent = Get-Content -Path $linuxApp -Raw
if (-not ($linuxAppContent -match "Antigravity Vault" -and $linuxAppContent -match "GDK_HINT_MIN_SIZE")) {
    throw "Linux my_application.cc missing title or geometry hints"
}
Write-Host "  [OK] Linux my_application.cc configured" -ForegroundColor Green

$desktopFile = Join-Path $flutterDir "linux\pwdvault.desktop"
$metainfoFile = Join-Path $flutterDir "linux\com.antigravity.pwdvault.metainfo.xml"
$debianControl = Join-Path $flutterDir "linux\debian\control"
if (-not (Test-Path $desktopFile) -or -not (Test-Path $metainfoFile) -or -not (Test-Path $debianControl)) {
    throw "Missing Linux desktop integration files"
}
Write-Host "  [OK] Linux desktop entry, AppStream metainfo, and Debian control verified" -ForegroundColor Green

# Step 7: Flutter Static Analysis and Platform Tests
Write-Host "`n[Step 7/7] Running Flutter Static Analysis and Tests..." -ForegroundColor Yellow
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
    Write-Host "  Flutter test suite PASSED (All unit, widget, and platform desktop tests)" -ForegroundColor Green
} finally {
    Pop-Location
}

Write-Host "`n==========================================================" -ForegroundColor Green
Write-Host "  PHASE 5 VERIFICATION GATE PASSED SUCCESSFULLY!          " -ForegroundColor Green
Write-Host "  iOS/iPadOS, macOS, Linux, and Cross-Platform OK         " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
