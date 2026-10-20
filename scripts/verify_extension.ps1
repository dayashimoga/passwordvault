# Antigravity Vault - Browser Extension Verification Script
$ErrorActionPreference = "Stop"

$workspaceRoot = Split-Path -Parent $PSScriptRoot
$extDir = Join-Path $workspaceRoot "apps\browser_extension"

Write-Host "--- Verifying Browser Extension Architecture ---" -ForegroundColor Cyan

# 1. Verify manifest.json
$manifestPath = Join-Path $extDir "manifest.json"
if (-not (Test-Path $manifestPath)) {
    throw "Missing manifest.json at $manifestPath"
}
$manifest = Get-Content -Path $manifestPath -Raw | ConvertFrom-Json
if ($manifest.manifest_version -ne 3) {
    throw "Expected manifest_version: 3, got: $($manifest.manifest_version)"
}
Write-Host "Manifest V3 is valid: $($manifest.name) v$($manifest.version)" -ForegroundColor Green

# 2. Verify all referenced files exist
$filesToCheck = @(
    $manifest.background.service_worker,
    $manifest.action.default_popup,
    "popup/popup.js",
    "popup/popup.css",
    "content/content.js",
    "content/content.css",
    "icons/icon16.png",
    "icons/icon48.png",
    "icons/icon128.png"
)

foreach ($relPath in $filesToCheck) {
    $fullPath = Join-Path $extDir $relPath
    if (-not (Test-Path $fullPath)) {
        throw "Referenced extension file missing: $relPath at $fullPath"
    }
    Write-Host "  [OK] $relPath exists" -ForegroundColor Gray
}

# 3. Verify Native Messaging Host binary & Registry
$hostBin = Join-Path $workspaceRoot "core\target\debug\pwdvault-native-host.exe"
if (-not (Test-Path $hostBin)) {
    throw "Native host binary missing: $hostBin"
}
Write-Host "Native host binary exists: $hostBin" -ForegroundColor Green

# Check Chrome registry key
$chromeKey = "HKCU:\Software\Google\Chrome\NativeMessagingHosts\com.antigravity.pwdvault"
if (Test-Path $chromeKey) {
    $val = (Get-ItemProperty -Path $chromeKey).'(default)'
    Write-Host "Chrome native messaging registered at: $val" -ForegroundColor Green
} else {
    Write-Warning "Chrome native messaging host key not found in registry"
}

Write-Host "Browser Extension Verification PASSED!" -ForegroundColor Cyan
