# Troubleshooting & Diagnostic Guide

## 1. Common Issues & Solutions

### Issue: "Authentication Failed / Corrupted Vault File"
- **Cause:** The master passphrase or recovery key entered does not match the key that encrypted the vault, or the vault file suffered filesystem bit corruption.
- **Resolution:**
  - Verify keyboard layout (caps lock, num lock, alternative IME).
  - Attempt unlock with your Emergency Recovery Key.
  - Check if an automatic backup exists in the vault directory (e.g. `vault.v1.backup`).

### Issue: "Memory Allocation Failed during Unlock"
- **Cause:** The vault was created with high Argon2id memory settings ($m > 256\text{ MiB}$) on a device with severely constrained free RAM.
- **Resolution:**
  - Close background applications to free at least 256 MiB of physical RAM.
  - Unlock the vault on a desktop device and adjust KDF memory settings in Settings -> Security.

### Issue: "Biometric Unlock Invalidation"
- **Cause:** Adding or removing a fingerprint or facial biometric profile on Android or iOS automatically invalidates hardware-backed cryptographic keys in the OS Keystore/Secure Enclave.
- **Resolution:**
  - Enter your Master Passphrase to unlock the vault.
  - Re-enable Biometric Unlock in Settings.

---

## 2. Platform-Specific Diagnostic Tips
- **Windows:** Check Windows Event Viewer under `Applications and Services Logs -> Microsoft -> Windows -> HelloForBusiness` if Windows Hello fails to prompt.
- **Android:** Check Logcat for `BiometricPrompt` error codes (e.g. `ERROR_LOCKOUT` or `ERROR_HW_UNAVAILABLE`).
