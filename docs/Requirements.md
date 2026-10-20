# Requirements Specification: Personal Password Generator & Encrypted Vault

## 1. Executive Summary
This document defines the functional, non-functional, security, and architectural requirements for a production-grade personal password manager, generator, and encrypted vault. The application targets Windows (x64/ARM64), Android (phones & tablets, ARM64), Apple iOS/iPadOS (ARM64), macOS (Intel/Apple Silicon), and Linux (x64/ARM64).

The system operates strictly offline with zero mandatory network connectivity, no user registration, no telemetry, no analytics, no subscription tier, and no external cloud dependency.

---

## 2. Platform Matrix & Capability Fallbacks

| Platform | Architectures | Minimum OS Version | Native Integration Tier | Hardware Biometrics | Credential Provider / Autofill |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Windows** | x64, ARM64 | Windows 10 (1809+) / Windows 11 | Win32 / WinRT | Windows Hello (TPM 2.0 / Hello Pin / Biometrics) | Windows Credential Provider / UI Automation Autofill |
| **Android** | ARM64 (arm64-v8a) | Android 10 (API 29+) | Kotlin / Android NDK | BiometricPrompt (StrongClass3 / AndroidKeyStore / Keymaster / StrongBox) | Android Autofill Framework + Credential Manager API |
| **iOS / iPadOS**| ARM64 | iOS 16.0+ | Swift / Obj-C Bridge | LocalAuthentication (FaceID / TouchID + Secure Enclave) | AutoFill Credential Provider Extension |
| **macOS** | Apple Silicon, Intel | macOS 13.0+ (Ventura) | Swift / AppKit | Touch ID + Secure Enclave / Keychain | macOS AutoFill Extension |
| **Linux** | x64, ARM64 | glibc 2.31+ / Wayland & X11 | FreeDesktop Secret Service / DBus | FIDO2 / PAM / TPM2 integration where available | Browser Extension via Native Messaging / Portal |

### Fallback Matrix
- When hardware-backed biometrics are unavailable or disabled by policy, the system falls back exclusively to the Master Passphrase or explicit Cryptographic Recovery Key.
- Short PINs or device lock passwords are **never** used as standalone cryptographic keys; they only unlock hardware-bound authorization keys when backed by a hardware rate-limiting enclave (e.g. Android StrongBox, Apple Secure Enclave, Windows TPM).
- Where clipboard access is the only available autofill mechanism, time-bounded configurable auto-clearing (default: 30 seconds) is enforced, with an explicit notification to the user that modern OS clipboards may sync or be monitored by background accessibility services.

---

## 3. Cryptographic & Security Requirements

1. **No Proprietary Algorithms:** Standard, battle-tested cryptographic primitives only:
   - Key Derivation Function (KDF): **Argon2id** (RFC 9106) with bounded, authenticated configuration parameters.
   - Authenticated Encryption with Associated Data (AEAD): **XChaCha20-Poly1305** (preferred for 192-bit random nonce collision resistance) and **AES-256-GCM** (NIST SP 800-38D).
   - Cryptographic Hash / MAC: **BLAKE3** and **HMAC-SHA256**.
   - CSPRNG: OS cryptographically secure pseudo-random number generator (`getrandom` / `BCryptGenRandom` / `SecRandomCopyBytes`).
2. **Key Hierarchy:**
   - **Data Encryption Key (DEK):** 256-bit cryptographically random symmetric key generated per-vault, never directly stored in plaintext.
   - **Key Encryption Key (KEK):** 256-bit key derived via Argon2id from the user's Master Passphrase with a unique 32-byte salt.
   - **Recovery Key Encryption Key (R-KEK):** 256-bit key derived from a 128-bit/256-bit BIP-39 mnemonic or high-entropy Base32 token.
   - **Biometric Unlock Key (B-KEK):** Hardware-backed key stored in Secure Enclave / Android KeyStore / Windows Hello CNG TPM container, released only upon successful user authentication.
3. **Data-at-Rest Protection:**
   - 100% of sensitive fields (titles, usernames, passwords, URLs, notes, custom key-value pairs, attachments, history, tags, search indexes) are stored exclusively in AEAD ciphertexts.
   - Unauthenticated plaintext headers are restricted to: Magic Bytes (`VAULT01`), Format Version (`u16`), KDF Algorithm ID (`u8`), KDF Salt (`[u8; 32]`), KDF Memory KiB (`u32`), KDF Iterations (`u32`), KDF Parallelism (`u32`), and DEK Wrapped Envelope (`[u8; 48]`).
4. **Memory Hygiene & Zeroization:**
   - All cryptographic keys, intermediate KDF buffers, plaintext secrets, and unencrypted record structs implement strict `Zeroize` and `ZeroizeOnDrop` traits.
   - Prevent plaintext leakage into swap/paging files using `mlock` / `VirtualLock` where permitted by OS privileges.
   - Managed runtime memory (Dart/Flutter) isolation: Decrypted secrets are kept in Dart memory only during active display; string buffers are overwritten upon lock.
5. **Screen & App Switcher Masking:**
   - Mobile and desktop windows enable secure flags (`FLAG_SECURE` on Android, screen masking overlay on iOS backgrounding, Windows window display affinity `WDA_MONITOR`).

---

## 4. Functional Requirements

### 4.1 Vault Data Management (CRUD)
- Support item types:
  - **Login:** Service Name, URL(s), Username, Password, TOTP Seed, Notes, Custom Fields, Passkey credentials.
  - **Secure Note:** Title, Markdown/Plaintext content, Tags, Attachments.
  - **Payment Card:** Cardholder Name, Number, Expiration (MM/YY), CVV, PIN, Billing Address.
  - **Identity:** Full Name, DOB, National ID / SSN, Passport Number, Email, Phone, Address.
  - **Recovery Codes:** Multi-code list, Service, Remaining usage status.
- Support organization: Folders/Collections, Tags, Favorites, Trash/Recycle Bin with 30-day auto-purge option, Revision History (retaining prior versions with encrypted snapshots).
- Bounded file attachments (up to 10MB per attachment, total vault cap configurable) encrypted with dedicated child keys derived from the DEK.

### 4.2 Generator Core
- Cryptographically secure generation with zero modulo bias:
  - Configurable lengths (8 to 128 characters).
  - Character set selection (Uppercase, Lowercase, Digits, Symbols, Extended ASCII).
  - Ambiguous character filtering (e.g. `1`, `l`, `I`, `0`, `O`).
  - Passphrase generation using EFF Long Wordlist (3 to 10 words, custom separators).
  - Entropy calculation (Shannon entropy + realistic crack-time estimations based on offline GPU brute-force models).
  - Ephemeral generation history (stored strictly in encrypted RAM, cleared on vault lock).

### 4.3 Search Core
- In-memory decrypted fast search index:
  - Sub-millisecond search query evaluation using trigram / token inverted index built upon vault unlock.
  - Fuzzy matching for typo tolerance on titles and domains without leaking tokens to disk.
  - P95 query latency under 50ms for 100,000 items.

### 4.4 Import / Export & Portability
- **Import Support:**
  - KeePass KDBX v4 / v3.
  - Bitwarden JSON (unencrypted and password-protected encrypted export).
  - 1Password 1PUX / CSV.
  - Generic RFC 4180 CSV with interactive column mapping and deduplication preview.
- **Export Support:**
  - Native Encrypted Backup (`.vaultbak` AEAD envelope).
  - Plaintext CSV / JSON (requires double-confirmation, explicit master passphrase re-authentication, and prominent security disclaimer).
- **Atomic Operations:**
  - ACID persistence: writes to temporary file (`.tmp`), calls `fsync`/`FlushFileBuffers`, performs atomic rename (`MoveFileExW` / `rename`).
  - Automatic backup of previous vault state prior to migration or write commit.

### 4.5 Security Auditing & Health Checks
- Offline local analysis:
  - Detection of weak passwords (length < 12, low entropy).
  - Reused password clusters across accounts.
  - Compromised/outdated 2FA seeds.
  - Inactive accounts and stale credentials.
  - Opt-in breach lookup via k-Anonymity (SHA-1 / SHA-256 prefix lookup, no secrets sent over the wire).

---

## 5. Non-Functional & Performance Targets

1. **Cold Startup:** < 2.0 seconds from binary launch to unlocked UI (excluding deliberate Argon2id KDF compute time).
2. **Search Latency:** p95 < 50ms across 10,000 records; p99 < 80ms across 100,000 records.
3. **Memory Footprint:** Steady-state idle memory < 150 MB on desktop; < 100 MB on mobile. Peak memory during Argon2id derivation bounded to configured KDF memory budget + 30 MB.
4. **UI Responsiveness:** 60/120 FPS scrolling on mobile and desktop. All cryptography, parsing, disk I/O, and search indexing dispatched to dedicated Rust worker threads.
5. **Zero Telemetry:** Zero outbound network calls unless explicitly triggered by user for opt-in breach check or paired LAN sync.
