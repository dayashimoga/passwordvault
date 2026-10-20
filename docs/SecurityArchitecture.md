# Security Architecture & Comprehensive Threat Model

## 1. Security Philosophy & Guiding Tenets
1. **No System Is Unhackable:** Security is a continuous engineering discipline of threat minimization, defense in depth, blast radius reduction, and transparent disclosure of residual risks. Test coverage or static analysis does not certify immunity to compromise.
2. **Offline-First Sovereignty:** The system has no remote servers, telemetry, registration, analytics, or background internet access. The user's device is the primary perimeter.
3. **Cryptographic Standard Compliance:** Only peer-reviewed, standard cryptographic algorithms with wide cryptanalysis are employed.
4. **Defense in Depth:** Hardware enclaves, memory zeroization, OS-level window masking, and strict typed FFI boundaries prevent accidental leakage.

---

## 2. Threat Model Matrix (STRIDE & Threat Catalogue)

| Threat ID | Threat Vector | Description | Protections & Mitigations | Residual Risks |
| :--- | :--- | :--- | :--- | :--- |
| **THREAT-01** | **Copied Vault / Backup Theft** | Attacker gains access to raw vault `.vault.v1` file or `.vaultbak` file from filesystem, USB, or cloud sync folder. | Authenticated AEAD encryption (XChaCha20-Poly1305) with 256-bit DEK wrapped with Argon2id KDF-derived Master KEK. Unique 32-byte salts prevent rainbow tables. Nonce reuse impossible. | Offline dictionary attacks if the user chooses an exceptionally weak master passphrase (mitigated by KDF memory hardness). |
| **THREAT-02** | **Stolen Physical Device** | Physical seizure of locked device running Windows, Android, iOS, or macOS. | Hardware-backed key management (TPM, Android KeyStore StrongBox, Apple Secure Enclave). Biometrics authorize key release, never act as standalone crypto material. Rate-limited hardware PIN/biometric unlock. | Sophisticated physical attacks against chip vulnerabilities (e.g. cold boot attack on DRAM if device is seized while unlocked or sleeping without suspend-to-disk encryption). |
| **THREAT-03** | **Offline Brute-Force & Guessing** | Attacker executes parallelized GPU/ASIC brute-force on captured vault header. | Argon2id KDF with high memory cost (64 MiB default on mobile, 128 MiB on desktop), 3 iterations, and 4 parallel lanes. Strict bounded parameter validation prevents attacker-crafted parameter spoofing. | Master passphrases with low entropy (< 40 bits) remain susceptible to massive distributed cluster attacks. Passphrase entropy enforcement guide provided. |
| **THREAT-04** | **Host Malware / Infostealers** | Keyloggers, memory dumpers, or trojans executing on host OS with user privileges. | Explicit Rust `Zeroize` and `ZeroizeOnDrop` on all sensitive buffers; memory locking (`VirtualLock` / `mlock`); auto-lock on inactivity or display sleep; no unencrypted temporary files or swap writes. | Full root/admin or kernel-level malware can hook API calls, read process virtual memory while unlocked, or capture raw keystrokes. Disclosed clearly as an out-of-scope OS-level compromise. |
| **THREAT-05** | **Hostile Websites & Phishing** | Browser phishing pages attempting to harvest credentials or trick autofill extensions. | Strict origin and eTLD+1 matching in autofill provider and browser extension. No automatic filling into iframes or cross-origin domains. User confirmation required before filling credentials. | User manual override or trickery on lookalike unicode domains (punycode attacks) where user forces autofill. |
| **THREAT-06** | **Malicious Import Payloads** | Crafted KDBX, CSV, or JSON import files designed to trigger memory corruption, buffer overflows, or injection attacks. | 100% memory-safe Rust parsers. Explicit size bounds on all fields (titles, usernames, passwords, notes). No dynamic shell execution or eval. Strict schema validation prior to vault ingestion. | Denial of Service via massive import files (bounded by streaming parsers and max file size limits). |
| **THREAT-07** | **Sync Tampering & Replay** | Attacker intercepts or modifies synced files or LAN packets during synchronization. | All sync packets are authenticated and encrypted end-to-end. File-based sync validates BLAKE3 checksums and AEAD tags. LAN sync requires mutual out-of-band cryptographic pairing (QR code with ephemeral public keys and session tokens). | Replay of valid older vault states (mitigated by monotonic vector clocks and transaction counters). |
| **THREAT-08** | **Supply Chain & Dependency Risk** | Malicious code injected into third-party crate or package update. | Pinned dependency versions in `Cargo.lock` and `pubspec.lock`. Automated `cargo-audit` and `cargo-vet` in CI. SBOM generation on every release. Zero unnecessary dependencies; no heavy telemetry or web frameworks. | Zero-day compromises in fundamental cryptographic crates (e.g., `ring`, `argon2`, `chacha20poly1305`). Mitigated by relying solely on widely-audited RustCrypto libraries. |
| **THREAT-09** | **Malicious Update Delivery** | Attacker attempts to distribute a trojaned binary update. | Signed binaries on Windows (Authenticode), Android (APK Signature Scheme v3), Apple (Apple Developer Code Signing). SHA-256 and BLAKE3 release checksums published out-of-band. No silent background auto-updates. | Compromise of private release signing keys (mitigated by HSM/hardware token signing requirements and CI secrets protection). |
| **THREAT-10** | **Unlocked Device Residual Risk** | Physical shoulder surfing, unauthorized person accessing device while unlocked, or app switcher preview snooping. | Configurable auto-lock (1 to 15 minutes, default: 5 minutes); instant lock on screen lock / workstation lock; OS window masking (`FLAG_SECURE` / `WDA_MONITOR`); biometric re-authentication for sensitive actions (viewing password, exporting vault). | Immediate visual capture if screen is viewed while user is actively revealing a secret in person. |

---

## 3. Cryptographic Key Lifecycle & Architecture

```text
+--------------------------------------------------------------------------+
|                       Master Passphrase (User Secret)                    |
+--------------------------------------------------------------------------+
                                     |
                          Argon2id (Salt, m, t, p)
                                     v
+--------------------------------------------------------------------------+
|                 Master Key-Encryption Key (M-KEK, 256-bit)               |
+--------------------------------------------------------------------------+
                                     |
                   XChaCha20-Poly1305 Unwrap / Decrypt
                                     v
+--------------------------------------------------------------------------+
|                    Vault Data Key (DEK, 256-bit Cryptographic)           |
|                    *Zeroized on Vault Lock or Inactivity*                |
+--------------------------------------------------------------------------+
         |                                                 |
  HKDF-Expand (Info: "records")                     HKDF-Expand (Info: "attachments")
         v                                                 v
+-----------------------------------+             +------------------------+
| Record Encryption Key (R-DEK)     |             | Attachment Key (A-DEK) |
+-----------------------------------+             +------------------------+
```

### 3.1 Biometric Convenience Unlock
- Biometrics (Face ID, Touch ID, Windows Hello, Android BiometricPrompt) do **not** derive the Data Encryption Key.
- Instead, upon successful initial unlock with the Master Passphrase, the system generates a random 256-bit Biometric Wrapping Key (B-KEK).
- The DEK is encrypted with B-KEK and stored in the OS-managed secure keystore (Secure Enclave, Android StrongBox, Windows TPM CNG).
- Hardware biometrics authorize the release of the B-KEK.
- If biometric configuration changes (e.g. a new fingerprint is enrolled on Android/iOS), the OS keystore invalidates the key, forcing the user to re-enter their Master Passphrase.

---

## 4. Clipboard vs Autofill Security Disclosure
- **Autofill (Preferred):** Interacts directly with OS credential provider APIs, populating form fields directly in the focused target application without exposing secrets to system-wide clipboard listeners.
- **Clipboard Fallback:** When autofill is unsupported or rejected by the target application, the vault allows user-initiated copying with:
  1. Automatic timer-based clipboard clearing (default: 30 seconds).
  2. Guard against overwriting newer user copies (if the clipboard content changed before 30 seconds elapsed, the vault does not erase the user's new content).
  3. Prominent user disclosure: *Operating system clipboard history managers, accessibility services, and third-party keyboard apps may capture copied credentials before clearing occurs.*
