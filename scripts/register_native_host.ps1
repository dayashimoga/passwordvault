# Antigravity Vault - Windows Native Messaging Host Registration Script
# Registers pwdvault-native-host for Google Chrome, Microsoft Edge, and Mozilla Firefox

$ErrorActionPreference = "Stop"

$workspaceRoot = Split-Path -Parent $PSScriptRoot
$hostBinDebug = Join-Path $workspaceRoot "core\target\debug\pwdvault-native-host.exe"
$hostBinRelease = Join-Path $workspaceRoot "core\target\release\pwdvault-native-host.exe"

$hostBin = if (Test-Path $hostBinRelease) {
    $hostBinRelease
} elseif (Test-Path $hostBinDebug) {
    $hostBinDebug
} else {
    Write-Host "Building pwdvault-native-host binary..." -ForegroundColor Cyan
    & powershell.exe -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "cargo_run.ps1") build -p pwdvault-native-host
    if (Test-Path $hostBinDebug) {
        $hostBinDebug
    } else {
        throw "Failed to locate or build pwdvault-native-host.exe"
    }
}

Write-Host "Found native host binary at: $hostBin" -ForegroundColor Green

# Manifest directory in user AppData
$manifestDir = Join-Path $env:LOCALAPPDATA "AntigravityVault\NativeMessaging"
if (-not (Test-Path $manifestDir)) {
    New-Item -ItemType Directory -Path $manifestDir -Force | Out-Null
}

$chromeManifestPath = Join-Path $manifestDir "com.antigravity.pwdvault.json"
$firefoxManifestPath = Join-Path $manifestDir "com.antigravity.pwdvault.firefox.json"

# Escape backslashes for JSON
$escapedBinPath = $hostBin.Replace("\", "\\")

# 1. Chromium / Edge Manifest
$chromeManifest = @"
{
  "name": "com.antigravity.pwdvault",
  "description": "Antigravity Vault Native Messaging Host",
  "path": "$escapedBinPath",
  "type": "stdio",
  "allowed_origins": [
    "chrome-extension://*",
    "edge-extension://*"
  ]
}
"@
Set-Content -Path $chromeManifestPath -Value $chromeManifest -Encoding UTF8
Write-Host "Wrote Chrome/Edge manifest to: $chromeManifestPath" -ForegroundColor Gray

# 2. Firefox Manifest
$firefoxManifest = @"
{
  "name": "com.antigravity.pwdvault",
  "description": "Antigravity Vault Native Messaging Host",
  "path": "$escapedBinPath",
  "type": "stdio",
  "allowed_extensions": [
    "pwdvault@antigravity.internal"
  ]
}
"@
Set-Content -Path $firefoxManifestPath -Value $firefoxManifest -Encoding UTF8
Write-Host "Wrote Firefox manifest to: $firefoxManifestPath" -ForegroundColor Gray

# 3. Windows Registry Keys
$registryTargets = @(
    @{ Name = "Google Chrome"; Path = "HKCU:\Software\Google\Chrome\NativeMessagingHosts\com.antigravity.pwdvault"; Manifest = $chromeManifestPath },
    @{ Name = "Microsoft Edge"; Path = "HKCU:\Software\Microsoft\Edge\NativeMessagingHosts\com.antigravity.pwdvault"; Manifest = $chromeManifestPath },
    @{ Name = "Mozilla Firefox"; Path = "HKCU:\Software\Mozilla\NativeMessagingHosts\com.antigravity.pwdvault"; Manifest = $firefoxManifestPath }
)

foreach ($target in $registryTargets) {
    try {
        $parent = Split-Path -Parent $target.Path
        if (-not (Test-Path $parent)) {
            New-Item -Path $parent -Force | Out-Null
        }
        New-Item -Path $target.Path -Value $target.Manifest -Force | Out-Null
        Write-Host "Successfully registered $($target.Name) native messaging host" -ForegroundColor Green
    } catch {
        Write-Warning "Could not register $($target.Name): $_"
    }
}

Write-Host "Native host registration complete." -ForegroundColor Cyan
