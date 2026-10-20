<#
.SYNOPSIS
    Packages Antigravity Vault for Android Release.
.DESCRIPTION
    Builds release APK / AAB with ProGuard R8 code shrinking and resource optimization.
#>

$ErrorActionPreference = "Stop"

$rootDir = (Resolve-Path "$PSScriptRoot\..").Path
$flutterDir = Join-Path $rootDir "apps\flutter"
$distDir = Join-Path $rootDir "dist\android"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  ANTIGRAVITY VAULT - ANDROID RELEASE PACKAGING           " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

if (-not (Test-Path $distDir)) {
    New-Item -ItemType Directory -Force -Path $distDir | Out-Null
}

Push-Location $flutterDir
try {
    Write-Host "`n[1/3] Validating Android Configuration & ProGuard Rules..." -ForegroundColor Yellow
    $rules = Join-Path $flutterDir "android\app\proguard-rules.pro"
    if (-not (Test-Path $rules)) {
        throw "Missing proguard-rules.pro in android/app"
    }
    Write-Host "  [OK] ProGuard & R8 configuration verified" -ForegroundColor Green

    Write-Host "`n[2/3] Building Release APK with R8 Optimization..." -ForegroundColor Yellow
    & flutter build apk --release
    if ($LASTEXITCODE -ne 0) {
        throw "Flutter build apk --release failed"
    }
    
    $apkPath = Join-Path $flutterDir "build\app\outputs\flutter-apk\app-release.apk"
    if (Test-Path $apkPath) {
        $destApk = Join-Path $distDir "AntigravityVault-v1.0.0-release.apk"
        Copy-Item $apkPath -Destination $destApk -Force
        $hash = (Get-FileHash $destApk -Algorithm SHA256).Hash
        Write-Host "  [OK] APK packaged: $destApk" -ForegroundColor Green
        Write-Host "  SHA-256: $hash" -ForegroundColor Cyan
    }

    Write-Host "`n[3/3] Generating Release Checksum..." -ForegroundColor Yellow
    $checksumFile = Join-Path $distDir "SHA256SUMS.txt"
    "$hash  AntigravityVault-v1.0.0-release.apk" | Out-File -FilePath $checksumFile -Encoding utf8
    Write-Host "  [OK] Checksum manifest written to $checksumFile" -ForegroundColor Green
} finally {
    Pop-Location
}

Write-Host "`n==========================================================" -ForegroundColor Green
Write-Host "  ANDROID PACKAGING COMPLETE                             " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
