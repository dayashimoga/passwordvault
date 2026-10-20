#!/usr/bin/env bash
# Antigravity Vault - Linux & macOS Native Messaging Host Registration Script
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

HOST_BIN="$WORKSPACE_ROOT/core/target/release/pwdvault-native-host"
if [ ! -f "$HOST_BIN" ]; then
    HOST_BIN="$WORKSPACE_ROOT/core/target/debug/pwdvault-native-host"
fi

if [ ! -f "$HOST_BIN" ]; then
    echo "Building pwdvault-native-host..."
    cargo build -p pwdvault-native-host
    HOST_BIN="$WORKSPACE_ROOT/core/target/debug/pwdvault-native-host"
fi

echo "Found native host binary at: $HOST_BIN"

# Targets for Chrome, Chromium, and Firefox
CHROME_DIR=""
FIREFOX_DIR=""

if [[ "$OSTYPE" == "darwin"* ]]; then
    CHROME_DIR="$HOME/Library/Application Support/Google/Chrome/NativeMessagingHosts"
    FIREFOX_DIR="$HOME/Library/Application Support/Mozilla/NativeMessagingHosts"
else
    CHROME_DIR="$HOME/.config/google-chrome/NativeMessagingHosts"
    FIREFOX_DIR="$HOME/.mozilla/native-messaging-hosts"
fi

mkdir -p "$CHROME_DIR" "$FIREFOX_DIR"

cat <<EOF > "$CHROME_DIR/com.antigravity.pwdvault.json"
{
  "name": "com.antigravity.pwdvault",
  "description": "Antigravity Vault Native Messaging Host",
  "path": "$HOST_BIN",
  "type": "stdio",
  "allowed_origins": [
    "chrome-extension://*",
    "edge-extension://*"
  ]
}
EOF

cat <<EOF > "$FIREFOX_DIR/com.antigravity.pwdvault.json"
{
  "name": "com.antigravity.pwdvault",
  "description": "Antigravity Vault Native Messaging Host",
  "path": "$HOST_BIN",
  "type": "stdio",
  "allowed_extensions": [
    "pwdvault@antigravity.internal"
  ]
}
EOF

echo "Native host manifests registered successfully."
