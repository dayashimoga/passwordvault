# Master Implementation Plan: Sequential Verified Phases

## Phase Overview & Quality Gates

Each phase requires full documentation, clean compilation without warnings, zero clippy lints, high unit/integration test coverage, and reproducible verification evidence before progression.

---

### Phase 0 — Design and Foundation (CURRENT PHASE)
- **Scope:**
  - Establish complete architectural blueprints, threat model, requirements, platform matrix, and ADRs.
  - Evaluate KDBX compatibility vs versioned store design (ADR-001).
  - Setup Rust Cargo workspace (`core/*`) and Flutter app workspace (`apps/flutter`).
  - Create core cryptographic prototype: Argon2id KDF derivation, XChaCha20-Poly1305 authenticated envelope, and memory zeroization.
  - Implement benchmark harness to measure KDF time and memory across desktop and simulated mobile constraints.
  - Implement typed FFI skeleton linking Rust core to Flutter Dart.
  - Establish reproducible test, lint, and verification scripts (`/scripts/`).
  - Setup GitHub Actions CI workflow covering multi-platform validation.
- **Exit Gates:**
  - `cargo check --workspace`, `cargo clippy --workspace -- -D warnings`, `cargo fmt -- --check` pass cleanly.
  - Cryptographic test vectors and benchmark tests execute and verify bounds.
  - All Phase 0 documentation complete and committed.

---

### Phase 1 — Rust Security Core
- **Scope:**
  - Password & Passphrase Generator: CSPRNG, zero-modulo bias, EFF wordlists, entropy scoring, crack-time models.
  - Vault Domain & Storage Engine: Item models (Logins, Notes, Cards, Identities, Custom fields), atomic write-then-rename persistence, integrity verification, corruption detection, migration framework.
  - In-Memory Search Engine: Trigram and inverted token index for fast sub-50ms search over 10k/100k items.
  - Key Lifecycle: Passphrase change, DEK rotation, recovery key derivation, session auto-lock.
  - Multi-tier testing: Wrong-password tests, file truncation/bit-flip tamper tests, power-loss simulations, property tests, fuzzing harnesses.
- **Exit Gates:**
  - ≥ 90% core test coverage.
  - 100% of tamper and truncation tests correctly reject corrupted files without crashing or leaking partial data.
  - Benchmarks prove search p95 < 50ms on 10,000 items.

---

### Phase 2 — Windows & Android MVP
- **Scope:**
  - Adaptive Flutter UI: Responsive layouts for desktop, tablet, and mobile.
  - Design System: Curated accessible theme (Dark/Light mode, high contrast, WCAG AAA contrast, dynamic font scaling).
  - Secure reveal/copy controls with time-bounded clipboard auto-clearing.
  - Windows Hello (TPM/CNG) native convenience unlock integration.
  - Android BiometricPrompt & KeyStore StrongBox integration.
  - Screen protection: `FLAG_SECURE` on Android, `WDA_MONITOR` on Windows.
- **Exit Gates:**
  - Standalone Windows executable and Android APK built and verified.
  - Hardware biometric convenience unlock cycle verified with automatic fallback to master passphrase.
  - Zero plaintext secrets lingering in memory post-lock.

---

### Phase 3 — Backup, Recovery, and Portability
- **Scope:**
  - Encrypted versioned backups (`.vaultbak`) with authenticated headers.
  - Offline Cryptographic Recovery Kit generation (PDF/Text with printable BIP-39 mnemonic / Base32 recovery key).
  - Restore rehearsal: dry-run restoration verifying backup integrity before overwriting.
  - High-fidelity import parsers: KeePass KDBX v4, Bitwarden JSON, 1Password 1PUX/CSV, RFC 4180 CSV.
  - Interactive deduplication, conflict preview, and tag merging.
  - Item revision history and encrypted trash bin with auto-purge.
- **Exit Gates:**
  - Import of 10,000+ KeePassXC/Bitwarden items succeeds without data loss.
  - Restore from damaged backups fails safely with clear diagnostic error messages.

---

### Phase 4 — Autofill and Browser Integration
- **Scope:**
  - Chrome, Edge, Firefox Manifest V3 browser extension.
  - Authenticated restricted Native Messaging host communicating with Rust core.
  - Android Autofill Service and Credential Manager API provider.
  - Strict domain/origin matching, iframe isolation, punycode defense, and user authorization prompt.
- **Exit Gates:**
  - Autofill successfully matches domains without leaking credentials to cross-origin frames.
  - Spoofed native IPC messages are rejected with cryptographic challenge-response authentication.

---

### Phase 5 — iOS/iPadOS and Remaining Desktops (macOS & Linux)
- **Scope:**
  - iOS/iPadOS UI, Credential Provider Extension, LocalAuthentication (Face ID / Touch ID + Secure Enclave).
  - macOS AppKit integration, Touch ID, Keychain services.
  - Linux packaging (AppImage / Flatpak / deb / rpm), Secret Service DBus integration, Wayland/X11 screenshot protections.
- **Exit Gates:**
  - Successful execution on native runners and simulators.
  - Documented platform limitation and capability matrix.

---

### Phase 6 — Optional Encrypted Synchronization
- **Scope:**
  - Encrypted file transfer sync (USB, local folder, shared drive).
  - Paired peer-to-peer LAN sync with out-of-band QR pairing.
  - Monotonic vector clocks, CRDT record merging, cryptographic tombstones.
  - Replay and rollback attack prevention.
- **Exit Gates:**
  - Concurrent offline edits on 3 devices merge deterministically without data loss.

---

### Phase 7 — Advanced Personal Security
- **Scope:**
  - Native Passkey (FIDO2 / WebAuthn) creation and authentication provider.
  - Time-Based One-Time Password (TOTP) generator with RFC 6238 / RFC 4226 support.
  - Account recovery dependency graph and health audit.
  - Local breach detection via k-Anonymity API (opt-in).
  - Separately scoped developer secrets (SSH keys, API tokens).
- **Exit Gates:**
  - Passkey login passes WebAuthn conformance tests.
  - TOTP codes match standard authenticator apps down to the second.

---

### Phase 8 — Hardening, Auditing, and Release
- **Scope:**
  - Comprehensive static analysis, dependency vulnerability scan (`cargo audit`), and SBOM generation (CycloneDX / SPDX).
  - Fuzzing campaign (AFL / libFuzzer / cargo-fuzz) on all parsers and FFI boundaries.
  - Battery profiling and cold-startup benchmarks on physical baseline hardware.
  - Release packaging with cryptographic checksums and code signing.
- **Exit Gates:**
  - Zero critical/high CVEs in dependency tree.
  - Clean audit report, signed release artifacts, completed risk register.
