# Antigravity Vault (`pwdvault`)

> **Production-Grade Personal Password Generator & Encrypted Zero-Knowledge Vault**  
> Built with safe **Rust**, modern **Flutter**, and strict cryptographic invariants across **Windows, Android, iOS/iPadOS, macOS, and Linux**.

---

## Architecture Overview

```
┌────────────────────────────────────────────────────────────────────────┐
│                        ANTIGRAVITY VAULT                               │
├────────────────────────────────────────────────────────────────────────┤
│  Flutter Multi-Platform UI (Desktop, Tablet, Mobile)                   │
│  - Slate Cyberpunk Theme, Biometrics, Live TOTP, Security Auditor      │
├────────────────────────────────────────────────────────────────────────┤
│  Typed C-ABI FFI Boundary (Rust Dynamic Library `pwdvault_ffi.dll/.so`) │
├────────────────────────────────────────────────────────────────────────┤
│  Rust Security & Cryptographic Core                                    │
│  ├── pwdvault-crypto        Argon2id KDF, XChaCha20-Poly1305, BLAKE3    │
│  ├── pwdvault-vault         Versioned atomic storage, key envelopes   │
│  ├── pwdvault-generator     CSPRNG rejection sampling, Shannon entropy │
│  ├── pwdvault-search        Inverted posting index (p95 < 1.35ms)      │
│  ├── pwdvault-security      RFC 6238 TOTP, FIDO2 Passkeys, Breach Watch│
│  ├── pwdvault-sync          CRDT Zero Data Loss, Vector Clocks, SyncPack│
│  ├── pwdvault-backup        .vaultbak archives, 256-bit Recovery Kit   │
│  ├── pwdvault-import-export Bitwarden, 1Password, KeePass, CSV parsers │
│  └── pwdvault-native-host   4-byte length-framed Native Messaging Host │
├────────────────────────────────────────────────────────────────────────┤
│  Cross-Platform Integration                                            │
│  ├── Browser Extension      Manifest V3 (Chrome, Edge, Firefox)        │
│  ├── Android Autofill       RemoteViews AutofillService + StrongBox    │
│  ├── Apple Ecosystem        iOS Credential Provider & macOS blur shield│
│  └── Linux Packaging        AppStream metadata, XDG desktop shortcut   │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Core Security Invariants

1. **Zero Data Loss CRDT Invariant**: Multi-device concurrent edits are deterministically reconciled via Last-Write-Wins with tie-breaking BLAKE3 payload commitments. Losing concurrent edits are converted into immutable `ItemRevision` history snapshots and prepended to the winning item's revision history.
2. **Strict k-Anonymity Invariant**: Candidate passwords and 35-character hashes never leave the client device over the network. Only the 5-character SHA-1 prefix is queried against HaveIBeenPwned over HTTPS.
3. **Volatile Memory Hygiene**: Master passphrases, derived DEK/KEK keys, private keys, and recovery keys implement `Zeroize` and `ZeroizeOnDrop` to overwrite memory upon drop or vault lock.
4. **Timing-Attack Resistance**: All HMAC, token, and hash verifications employ `subtle::ConstantTimeEq`.
5. **Compositor Screen Protection**: Hardware screenshot and screen recording blocking via `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)` on Windows, `FLAG_SECURE` on Android, and `NSWindow.sharingType = .none` on macOS.

---

## Features

- **Personal Password & Passphrase Generator**:
  - Unbiased CSPRNG rejection sampling with embedded EFF Long Wordlist.
  - Character class enforcement (uppercase, lowercase, digits, symbols) and ambiguous character exclusions (`1lI|0OQ8B`).
  - Real-time Shannon entropy calculation and GPU cluster crack-time estimation.
  - Ephemeral zeroized RAM generation history buffer.
- **Two-Factor Authenticator (TOTP)**:
  - RFC 6238 compliant engine with RFC 4648 Base32 decoding, HMAC-SHA1/256/512, and drift tolerance.
  - Live 30-second circular countdown progress gauge with 1-click clipboard copy.
  - Automatic `otpauth://totp/` URI parser.
- **WebAuthn / FIDO2 Passkeys**:
  - Keypair generation for ES256 (NIST P-256) and EdDSA (Ed25519).
  - 37-byte Authenticator Data framing (`rp_id_hash` || `flags` || `sign_count`) and assertion challenge signing.
- **Vault Health Auditor & Breach Watch**:
  - 0–100 Cryptographic Health Score analyzing reused passwords, weak passwords (< 12 chars), stale entries (> 90 days), and missing 2FA.
  - Full-vault batch breach scanner leveraging k-anonymity range queries.
- **Encrypted Synchronization**:
  - Authenticated `.syncpack` container (magic `PVSYNC01`, 100-byte header, XChaCha20-Poly1305 AEAD).
  - Out-of-band ephemeral QR pairing (`pwdvault://pair`) with 15-minute validity window.
  - Direct local network (LAN) sync via mutual zero-knowledge proof of possession.
- **Backup, Recovery & Multi-Format Portability**:
  - Encrypted `.vaultbak` archives with non-destructive dry-run restoration rehearsals.
  - 256-bit Crockford Base32 Emergency Recovery Key (`PV-XXXX-XXXX-...`) with printable offline kit.
  - Streaming parsers for Bitwarden JSON, 1Password 1PUX/CSV, KeePass 2.x XML, and RFC 4180 CSV.
  - Intelligent deduplication engine with interactive conflict diff tables.

---

## Project Structure

```
├── core/                  # Safe Rust workspace (10 crates)
│   ├── crypto/            # Argon2id, XChaCha20-Poly1305, BLAKE3, memory zeroization
│   ├── vault/             # Versioned storage, authenticated headers, key envelopes
│   ├── generator/         # Password & passphrase engine, entropy models
│   ├── search/            # Trigram inverted posting search index
│   ├── security/          # TOTP, Passkeys, k-Anonymity breach watch, health auditor
│   ├── sync/              # Vector clocks, CRDT merge, .syncpack, QR pairing, LAN sync
│   ├── backup/            # .vaultbak archive, 256-bit Emergency Recovery Kit
│   ├── import_export/     # Bitwarden, 1Password, KeePass, CSV parsers & deduplication
│   ├── ffi/               # C-ABI export layer with safe pointer deallocation
│   └── native_host/       # Chromium/Firefox length-prefixed native messaging host
├── apps/
│   ├── flutter/           # Multi-platform Flutter UI (Windows, Android, iOS, macOS, Linux)
│   └── browser_extension/ # Cross-browser Manifest V3 extension (Chrome, Edge, Firefox)
├── packaging/             # Inno Setup Windows installer and packaging manifests
├── scripts/               # Automated verification gates (verify_phase0 to verify_phase8)
└── docs/                  # Architecture, ADRs, Threat Model, SBOM, and User Guides
```

---

## Verification & Testing

The repository includes idempotent automated verification scripts validating all 8 implementation phases:

```powershell
# Execute the complete production release verification gate (Phase 8):
powershell -ExecutionPolicy Bypass -File scripts\verify_phase8.ps1

# Or on Linux / macOS:
bash scripts/verify_phase8.sh
```

Every verification gate enforces:
- All 10 Rust crates compile cleanly with zero warnings (`cargo clippy --workspace --all-targets -- -D warnings`).
- 94 unit, property, security, and fuzzing tests pass (`cargo test --workspace`).
- Flutter static analysis reports zero issues (`flutter analyze`).
- Flutter test suite passes completely (`flutter test`).

---

## Documentation

- [System Architecture](docs/Architecture.md)
- [Security Architecture & Threat Model](docs/SecurityArchitecture.md)
- [Software Bill of Materials (SBOM)](docs/SBOM.md) / [Machine-readable SBOM JSON](docs/SBOM.json)
- [Hardware Performance & Battery Profiling](docs/PerformanceProfiling.md)
- [Production Release Checklist](docs/ReleaseChecklist.md)
- [Developer Guide](docs/DeveloperGuide.md)
- [User Guide](docs/UserGuide.md)
- [Emergency Recovery Guide](docs/RecoveryGuide.md)

---

## License

Licensed under the [MIT License](LICENSE).
