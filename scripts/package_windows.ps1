<#
.SYNOPSIS
    Packages Antigravity Vault for Windows x64 Release.
.DESCRIPTION
    - Compiles release Rust C-ABI FFI library (pwdvault_ffi.dll)
    - Compiles release Rust Native Messaging Host (pwdvault-native-host.exe)
    - Assembles standalone portable distribution (AntigravityVault-Windows-x64-Portable.zip)
    - Generates SHA-256 integrity checksums
#>

$ErrorActionPreference = "Stop"

$llvmBin = "C:\Users\daya\AppData\Local\Microsoft\WinGet\Packages\MartinStorsjo.LLVM-MinGW.UCRT_Microsoft.Winget.Source_8wekyb3d8bbwe\llvm-mingw-20260908-ucrt-x86_64\bin"
if (Test-Path $llvmBin) {
    $env:PATH = "$llvmBin;" + $env:PATH
}
if (Test-Path "C:\Users\daya\.cargo\bin") {
    $env:PATH = "C:\Users\daya\.cargo\bin;" + $env:PATH
}
if (Test-Path "C:\Users\daya\flutter\bin") {
    $env:PATH = "C:\Users\daya\flutter\bin;" + $env:PATH
}

$rootDir = (Resolve-Path "$PSScriptRoot\..").Path
$coreDir = Join-Path $rootDir "core"
$flutterDir = Join-Path $rootDir "apps\flutter"
$distDir = Join-Path $rootDir "dist\windows"
$portableDir = Join-Path $distDir "AntigravityVault-x64"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  ANTIGRAVITY VAULT - WINDOWS RELEASE PACKAGING           " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Clean & prepare output directories
if (Test-Path $distDir) {
    Remove-Item -Recurse -Force $distDir
}
New-Item -ItemType Directory -Force -Path $portableDir | Out-Null

# 2. Build Release Rust FFI Library
Write-Host "`n[1/5] Building Release Rust FFI Dynamic Library..." -ForegroundColor Yellow
Push-Location $coreDir
try {
    & cargo build --release -p pwdvault-ffi
    if ($LASTEXITCODE -ne 0) { throw "Cargo build failed for pwdvault-ffi" }
    
    $ffiDll = Join-Path $coreDir "target\release\pwdvault_ffi.dll"
    if (-not (Test-Path $ffiDll)) {
        $altDll = Get-ChildItem -Path (Join-Path $coreDir "target") -Filter "pwdvault_ffi.dll" -Recurse | Select-Object -First 1
        if ($altDll) { $ffiDll = $altDll.FullName }
    }
    Copy-Item $ffiDll -Destination (Join-Path $flutterDir "pwdvault_ffi.dll") -Force
    Copy-Item $ffiDll -Destination (Join-Path $portableDir "pwdvault_ffi.dll") -Force
    Write-Host "  [OK] pwdvault_ffi.dll deployed" -ForegroundColor Green
} finally {
    Pop-Location
}

# 3. Build Release Rust Native Host
Write-Host "`n[2/5] Building Release Rust Native Messaging Host..." -ForegroundColor Yellow
Push-Location $coreDir
try {
    & cargo build --release -p pwdvault-native-host
    if ($LASTEXITCODE -ne 0) { throw "Cargo build failed for pwdvault-native-host" }
    
    $hostExe = Join-Path $coreDir "target\release\pwdvault-native-host.exe"
    if (-not (Test-Path $hostExe)) {
        $altExe = Get-ChildItem -Path (Join-Path $coreDir "target") -Filter "pwdvault-native-host.exe" -Recurse | Select-Object -First 1
        if ($altExe) { $hostExe = $altExe.FullName }
    }
    Copy-Item $hostExe -Destination (Join-Path $portableDir "pwdvault-native-host.exe") -Force
    Write-Host "  [OK] pwdvault-native-host.exe deployed" -ForegroundColor Green
} finally {
    Pop-Location
}

# 3b. Copy Flutter Windows Release Binaries (if available)
$flutterReleaseDirs = @(
    (Join-Path $flutterDir "build\windows\x64\runner\Release"),
    (Join-Path $flutterDir "build\windows\runner\Release")
)
$foundFlutterDir = $false
foreach ($cand in $flutterReleaseDirs) {
    if (Test-Path $cand) {
        Copy-Item "$cand\*" -Destination $portableDir -Recurse -Force
        Write-Host "  [OK] Flutter Windows release binaries staged from $cand" -ForegroundColor Green
        $foundFlutterDir = $true
        break
    }
}
if (-not $foundFlutterDir) {
    $flutterExe = Get-ChildItem -Path (Join-Path $flutterDir "build") -Filter "pwdvault_flutter.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($flutterExe) {
        $parentDir = $flutterExe.DirectoryName
        Copy-Item "$parentDir\*" -Destination $portableDir -Recurse -Force
        Write-Host "  [OK] Staged from $($parentDir)" -ForegroundColor Green
    }
}

# 4. Copy Browser Extension Manifests & Documentation
Write-Host "`n[3/5] Copying Browser Manifests and Licenses..." -ForegroundColor Yellow
$manifestDirs = @(
    (Join-Path $rootDir "apps\browser_extension\native_host"),
    (Join-Path $rootDir "apps\browser_extension\manifest")
)
foreach ($dir in $manifestDirs) {
    if (Test-Path $dir) {
        $c1 = Join-Path $dir "com.antigravity.pwdvault.json"
        $c2 = Join-Path $dir "com.antigravity.pwdvault.firefox.json"
        if (Test-Path $c1) { Copy-Item $c1 -Destination $portableDir -Force }
        if (Test-Path $c2) { Copy-Item $c2 -Destination $portableDir -Force }
    }
}
$userGuide = Join-Path $rootDir "docs\UserGuide.md"
if (Test-Path $userGuide) {
    Copy-Item $userGuide -Destination (Join-Path $portableDir "README.txt") -Force
}
$recGuide = Join-Path $rootDir "docs\RecoveryGuide.md"
if (Test-Path $recGuide) {
    Copy-Item $recGuide -Destination $portableDir -Force
}
Write-Host "  [OK] Manifests and documentation staged" -ForegroundColor Green

# 5. Create Standalone Portable ZIP
Write-Host "`n[4/5] Creating Standalone Portable Distribution ZIP..." -ForegroundColor Yellow
$zipOutput = Join-Path $distDir "AntigravityVault-v1.0.0-Windows-x64-Portable.zip"
Compress-Archive -Path "$portableDir\*" -DestinationPath $zipOutput -CompressionLevel Optimal -Force
Write-Host "  [OK] Created $zipOutput" -ForegroundColor Green

# 6. Generate Cryptographic Checksums (SHA-256)
Write-Host "`n[5/5] Generating Cryptographic SHA-256 Checksums..." -ForegroundColor Yellow
$hash = (Get-FileHash $zipOutput -Algorithm SHA256).Hash
$checksumFile = Join-Path $distDir "SHA256SUMS.txt"
"$hash  AntigravityVault-v1.0.0-Windows-x64-Portable.zip" | Out-File -FilePath $checksumFile -Encoding utf8
Write-Host "  SHA-256: $hash" -ForegroundColor Cyan
Write-Host "  [OK] Checksum manifest written to $checksumFile" -ForegroundColor Green

Write-Host "`n==========================================================" -ForegroundColor Green
Write-Host "  WINDOWS PACKAGING COMPLETE                             " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
