# Changelog & Decision History

All notable changes and architectural decisions for this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Phase 8 Complete] - 2026-10-20

### Added
- **Security Fuzzing, Property Suites & Memory Hygiene:**
  - `core/security/tests/fuzz_and_hardening_tests.rs`: Proptest fuzzing suites verifying that `parse_otpauth_uri` never panics across malformed/unicode schemes, `check_suffix_in_range_response` gracefully handles corrupted HIBP response bodies, k-anonymity query formulations strictly preserve SHA-1 integrity, TOTP drift windows operate predictably across arbitrary timestamps, and Passkey assertions enforce monotonic signature counter progression.
  - `core/sync/tests/sync_fuzz_tests.rs`: Ingestion fuzzing testing `read_syncpack` and `verify_pairing_qr_data` against randomized bitstream corruptions, and asserting mathematical CRDT merge idempotency.
  - Volatile memory zeroization validation asserting `Zeroize` and `ZeroizeOnDrop` overwrite sensitive cryptographic memory.
- **Cross-Platform Packaging & Distribution Architecture:**
  - **Windows**: Inno Setup installer script (`packaging/windows/installer.iss`) supporting per-user installations, desktop shortcuts, uninstaller registry cleanup, and automatic native messaging host registry setup for Chrome, Edge, and Firefox. Standalone portable packaging script (`scripts/package_windows.ps1`) bundling release binaries, manifests, and SHA-256 checksums.
  - **Android**: ProGuard / R8 code shrinking rules (`apps/flutter/android/app/proguard-rules.pro` and `build.gradle.kts`) protecting JNI/Dart FFI entrypoints, Android Autofill framework service, and biometric hardware brokers. Release packaging scripts (`scripts/package_android.ps1`, `scripts/package_android.sh`).
  - **Linux**: Release bundle packaging script (`scripts/package_linux.sh`) assembling standalone tarballs, XDG desktop shortcut (`pwdvault.desktop`), and AppStream metadata (`com.antigravity.pwdvault.metainfo.xml`).
  - **Apple (macOS & iOS)**: Release staging scripts (`scripts/package_apple.sh`) for macOS app bundle (`NSWindow.sharingType = .none`) and iOS xcarchive with Credential Provider Extension.
- **Software Bill of Materials (SBOM) & Supply Chain Security:**
  - Machine-readable CycloneDX 1.5 JSON SBOM (`docs/SBOM.json`) cataloging all 10 direct/transitive Rust and Flutter dependencies.
  - Comprehensive human-readable SBOM document (`docs/SBOM.md`) detailing license compatibility, cryptographic algorithm roles, and zero-known-vulnerability audit sign-off.
- **Hardware Performance & Battery Profiling:**
  - Benchmark report (`docs/PerformanceProfiling.md`) documenting Argon2id KDF latency (78–114ms), inverted index search latency (< 1.35ms for 10k items, < 21.04ms for 100k items), memory footprints (< 56 MB desktop, < 40 MB mobile), and zero-drain background idle power characteristics.
- **Production Release Checklist:**
  - Formal production sign-off matrix (`docs/ReleaseChecklist.md`) certifying all security invariants (Zero Data Loss, strict k-Anonymity, constant-time operations, and zeroization).
- **Verification & Testing:**
  - Automated Phase 8 verification gate (`scripts/verify_phase8.ps1` and `scripts/verify_phase8.sh`).
  - All 10 Rust crates passing (94 tests total across unit, property, security, and fuzzing suites).
  - Zero Rust Clippy warnings (`-D warnings`).
  - Zero Flutter analyzer issues (`flutter analyze`).
  - All 38 Flutter tests passed (`flutter test`).

## [Phase 7 Complete] - 2026-10-20

### Added
- **Core Security & Cryptography Engine (`pwdvault-security`):**
  - **RFC 6238 Time-Based One-Time Password (TOTP) Authenticator (`totp.rs`):** Standard RFC 4648 Base32 decoding/encoding, HMAC (SHA-1, SHA-256, SHA-512) computation, dynamic truncation, countdown time calculation, tolerance drift window verification, and full `otpauth://totp/` URI parser and formatter. Tested against RFC 6238 Appendix B test vectors.
  - **Pure Rust SHA-1 Digest Engine (`sha1.rs`):** RFC 3174 compliant safe Rust implementation for standard TOTP hashing and k-anonymity query formulations.
  - **Constant-Time HMAC Engine (`hmac.rs`):** RFC 2104 compliant Keyed-Hashing with `subtle::ConstantTimeEq` verification protecting against timing attacks.
  - **WebAuthn / FIDO2 Passkey Credential Engine (`passkey.rs`):** ES256 (NIST P-256) and EdDSA (Ed25519) keypair generation, 37-byte authenticator data framing (`rp_id_hash` || `flags` || `sign_count`), and assertion challenge signing with monotonic counter increments.
  - **Privacy-Preserving k-Anonymity Breach Watch (`audit.rs`):** Generates 5-character SHA-1 prefix queries for HaveIBeenPwned API range lookups, keeping candidate passwords and 35-character suffixes strictly local on the device.
  - **Vault Security Hygiene Auditor (`audit.rs`):** Analyzes vault contents for reused password clusters, weak passwords (< 12 chars or low Shannon entropy), stale passwords (> 90 days), and missing two-factor authentication, generating a 0–100 Cryptographic Health Score and actionable remediation items.
- **C-ABI FFI Security Exports (`pwdvault-ffi`):**
  - `vault_ffi_totp_generate`: generates current TOTP code and remaining seconds in period.
  - `vault_ffi_totp_verify`: validates code against Base32 secret within drift window.
  - `vault_ffi_totp_parse_uri`: parses `otpauth://totp/` URI into structured JSON.
  - `vault_ffi_passkey_generate`: generates ES256/EdDSA passkey credential.
  - `vault_ffi_passkey_sign_assertion`: signs WebAuthn challenge with authenticator data.
  - `vault_ffi_audit_vault`: executes security hygiene audit and returns comprehensive report JSON.
  - `vault_ffi_breach_prepare_query`: computes k-anonymity prefix and suffix.
  - `vault_ffi_breach_check_response`: searches suffix in range response body.
- **Flutter UI & Dart Bindings (`apps/flutter`):**
  - High-level typed FFI bridge methods in `vault_ffi_bindings.dart` with automatic memory zeroization and deallocation.
  - Security coordinator methods in `VaultState` (`runSecurityAudit`, `checkPasswordBreach`, `generateTotpCode`, `parseTotpUri`).
  - `SecurityAuditSheet` (`security_audit_sheet.dart`) with Slate Cyberpunk styling:
    * Tab 1: Vault Health Audit (interactive 0–100 health score gauge, metric breakdown tiles, reused password cluster cards, weak password alerts, and security recommendations).
    * Tab 2: Breach Watch (privacy k-anonymity explanation banner, single password checker, and full-vault batch breach scanner).
    * Tab 3: Passkey & FIDO2 Lab (ES256 / EdDSA passkey generator and WebAuthn assertion challenge tester).
  - Two-Factor Authenticator Card in `ItemDetailView` with real-time 30-second countdown circular indicator and 1-click clipboard copy.
  - Two-Factor Authenticator Secret / URI input field in `ItemEditorView` with automatic URI parsing and visual confirmation.
  - Cryptographic Health Score Banner and navigation tile in `SettingsView`.
- **Verification & Testing:**
  - Automated Phase 7 verification gate (`scripts/verify_phase7.ps1` and `scripts/verify_phase7.sh`).
  - All 10 Rust workspace crates pass unit, property, and integration tests (84 tests passing).
  - Zero Rust warnings (`cargo clippy --workspace --all-targets -- -D warnings`).
  - Zero Flutter analyzer issues (`flutter analyze`).
  - All 38 Flutter tests passed (`flutter test` including `security_audit_test.dart`).

## [Phase 6 Complete] - 2026-10-20

### Added
- **Core Encrypted Synchronization Crate (`pwdvault-sync`):**
  - **Monotonic Vector Clocks (`vector_clock.rs`):** Monotonic Lamport logical counters per device with causality checking (`dominates`), concurrency detection (`is_concurrent`), and component-wise merge.
  - **Zero Data Loss CRDT Merge Engine (`crdt.rs`):** Deterministic Last-Write-Wins (LWW) conflict resolution with tie-breaking BLAKE3 payload hashes. Invariant: losing variants in concurrent multi-device edits are converted to `ItemRevision` snapshots and prepended to the winner's revision history, guaranteeing zero data loss.
  - **Authenticated `.syncpack` Container (`syncpack.rs`):** 100-byte binary header with magic `PVSYNC01`, version, 24-byte random nonce, 32-byte salt, and 32-byte BLAKE3 payload commitment. Header is authenticated as Associated Data (AAD) in XChaCha20-Poly1305 AEAD, ensuring immediate rejection of tampered packages before deserialization.
  - **Out-of-Band Device Pairing (`pairing.rs`):** Generates `pwdvault://pair?data=...` URIs with 15-minute validity window and public BLAKE3 sync key fingerprint to verify device authenticity and prevent MITM attacks.
  - **Direct LAN Synchronization Protocol (`lan_sync.rs`):** Mutual zero-knowledge proof of possession protocol proving knowledge of the shared 256-bit sync key via challenge-response hashing (`BLAKE3(sync_key || challenge || "PWDVAULT_LAN_SYNC_AUTH_V1")`) without transmitting key material over the wire.
- **C-ABI FFI Synchronization Exports (`pwdvault-ffi`):**
  - `vault_ffi_sync_create_syncpack`: creates encrypted `.syncpack` from vault payload and vector clock.
  - `vault_ffi_sync_apply_syncpack`: ingests `.syncpack`, performs CRDT merge, and updates vector clock.
  - `vault_ffi_sync_generate_pairing_qr`: encodes out-of-band device pairing URI.
  - `vault_ffi_sync_verify_pairing_qr`: validates pairing URI and returns peer metadata.
  - `vault_ffi_sync_merge_payloads`: direct CRDT merge of two vault payloads with report.
- **Flutter UI & Dart Bindings (`apps/flutter`):**
  - `RustVaultFfi` bindings (`vault_ffi_bindings.dart`): added typed functions `createSyncPack`, `applySyncPack`, `generatePairingQrUri`, `verifyPairingQrUri`, `mergePayloads`.
  - `VaultState` (`vault_state.dart`): integrated device ID, device name, monotonic vector clock, `exportSyncPack()`, and `ingestSyncPack()`.
  - Sync Sheet (`sync_sheet.dart`): 3-tab modal sheet with Slate Cyberpunk styling:
    * Tab 1: Sync Package File Transfer (export and ingest `.syncpack` with CRDT reconciliation report).
    * Tab 2: Out-of-band QR Device Pairing & Direct LAN Sync.
    * Tab 3: Monotonic Vector Clocks logical causality tracker.
  - Settings Integration (`settings_view.dart`): added "Encrypted Synchronization & Multi-Device" card.
  - Sync Integration Test Suite (`sync_test.dart`): verifies CRDT conflict preservation with historical snapshots, pairing QR roundtrip, direct payload merge, and widget tab rendering.
- **Verification & Testing:**
  - Automated Phase 6 verification gate (`scripts/verify_phase6.ps1` and `scripts/verify_phase6.sh`).
  - All 9 Rust crates pass unit, integration, and property tests (76 tests passing).
  - Zero Rust warnings (`cargo clippy --workspace --all-targets -- -D warnings`).
  - Zero Flutter analyzer issues (`flutter analyze`).
  - All 31 Flutter tests passed (`flutter test`).

## [Phase 5 Complete] - 2026-10-20

### Added
- **iOS & iPadOS Native Architecture (`apps/flutter/ios`):**
  - `AppDelegate.swift`: `LocalAuthentication` Face ID and Touch ID platform channel (`com.antigravity.pwdvault/biometrics`) supporting hardware biometric challenges.
  - Multitasking Privacy Blur Shield (`privacyShieldView`): automatically blurs window upon `applicationWillResignActive` preventing password, token, or note exposure in the iOS App Switcher snapshot, and cleanly dissolves on `applicationDidBecomeActive`.
  - `Info.plist`: added `NSFaceIDUsageDescription` privacy disclosure.
  - Credential Provider Extension (`apps/flutter/ios/CredentialProviderExtension`):
    * `CredentialProviderViewController.swift`: implements `ASCredentialProviderViewController` enabling system-wide autofill in Safari and iOS third-party apps.
    * Integrated with App Group shared container (`group.com.antigravity.pwdvault`) to securely locate the encrypted vault container file across the main application and extension sandboxes.
    * Entitlements file (`CredentialProviderExtension.entitlements`) with application group configuration.
- **macOS Native Architecture (`apps/flutter/macos`):**
  - Hardware Screen Recording / Screenshot Protection: configured `NSWindow.sharingType = .none` in `MainFlutterWindow.swift`, completely preventing macOS WindowServer from capturing, recording, or previewing the window during screen recording, remote desktop, or screenshots.
  - `AppDelegate.swift`: Touch ID `LocalAuthentication` channel and minimum window constraints (800x600).
- **Linux Native Architecture (`apps/flutter/linux`):**
  - Runner configuration in `runner/my_application.cc`: updated application header bar and title to "Antigravity Vault" with geometry size hints (`GDK_HINT_MIN_SIZE` min 800x600).
  - Desktop entry file (`pwdvault.desktop`): standard XDG compliant desktop shortcut with `Utility;Security;` categorization.
  - AppStream metadata (`com.antigravity.pwdvault.metainfo.xml`): Open Collaboration Services compliant metadata for GNOME Software, Discover, and Flathub distribution.
  - Debian packaging template (`debian/control`): build dependencies including `libgtk-3-dev` and `libsecret-1-dev`.
- **Cross-Platform Biometrics & Responsive UI:**
  - Enhanced `BiometricService` (`apps/flutter/lib/services/biometric_service.dart`) with hardware biometric detection, modality classification (`BiometricType.faceID`, `touchID`, `windowsHello`, `fingerprint`, `linuxKeyring`), and simulated test fallbacks.
  - Platform integration test suite (`apps/flutter/test/platform_desktop_test.dart`) covering modality detection, toggling, and authentication.
- **Verification & Testing:**
  - Automated Phase 5 verification script (`scripts/verify_phase5.ps1` and `scripts/verify_phase5.sh`).
  - Zero warnings across all 9 Rust workspace crates (`cargo clippy`).
  - Zero Flutter analyzer issues (`flutter analyze`).
  - 27 Flutter tests passed (`flutter test`).

## [Phase 4 Complete] - 2026-10-19

### Added
- **Native Messaging Host (`pwdvault-native-host`):**
  - Binary and library targets implementing the Chromium/Firefox length-prefixed native messaging protocol over standard input/output.
  - Strict 1 MiB message bounds enforcement preventing memory exhaustion attacks from untrusted IPC buffers.
  - 256-bit CSPRNG session token authentication (`HostSession`) with handshake challenge/response.
  - Robust eTLD+1 heuristic domain parser (`extract_base_domain`) and domain matching (`domains_match`) enabling subdomains to share credentials seamlessly while isolating cross-origin origins.
  - Anti-Phishing Origin Verification: strictly validates requested items against active tab domains, rejecting cross-origin credential extraction (`Origin mismatch`).
  - Atomic credential persistence from browser via `VaultContainer::create` + `VaultStorage::save_atomic`.
- **Browser Extension (`apps/browser_extension`):**
  - Cross-browser Manifest V3 compatibility (Google Chrome, Microsoft Edge, Brave, and Mozilla Firefox Gecko).
  - Background Service Worker (`service_worker.js`): connection management, session state caching, and asynchronous request dispatch.
  - In-Page Content Script (`content.js` & `content.css`):
    * Top-level iframe isolation check (`window === window.top`) preventing clickjacking and credential extraction in untrusted frames.
    * Unobtrusive Slate Cyberpunk shield badge anchored to password/username fields.
    * Interactive dropdown menu querying matching credentials.
    * Synthetic bubbling `InputEvent`, `change`, and `blur` dispatch bypassing React, Vue, Angular, and Flutter web property descriptor overrides.
    * Form submission detection and floating credential capture confirmation toast.
  - Extension Popup UI (`popup.html`, `popup.css`, `popup.js`):
    * Slate Cyberpunk dark graphite theme (`#0d1117`), electric cyan accent (`#00f0ff`), and neon purple accents.
    * Active tab domain detection with matching logins listing and 1-click autofill.
    * Integrated password generator with Shannon entropy meter, crack-time rating, length slider, and symbol toggles.
    * Vault lock/unlock controls and host connection retry.
  - Windows Registry native messaging registration script (`scripts/register_native_host.ps1`) and POSIX script (`scripts/register_native_host.sh`).
- **Android Autofill Framework Integration (`apps/flutter/android`):**
  - `AndroidManifest.xml` declaration with `BIND_AUTOFILL_SERVICE` permission and metadata.
  - `autofill_service_config.xml` compatibility configuration.
  - `autofill_dataset_item.xml` RemoteViews layout for system autofill drop-downs.
  - `AutofillStructureParser.kt`: recursive `AssistStructure.ViewNode` walker extracting `webDomain`, `packageName`, username IDs, and password IDs.
  - `PwdVaultAutofillService.kt`: handles `onFillRequest` (generating `Dataset` items with `RemoteViews`) and `onSaveRequest` (capturing submitted credentials).
- **Verification & Testing:**
  - Full automated Phase 4 verification script (`scripts/verify_phase4.ps1` and `scripts/verify_phase4.sh`).
  - Native host unit and integration test suite (`tests/integration_test.rs`) covering the entire autofill lifecycle and anti-phishing defense.
  - Browser extension structural and registry validation (`scripts/verify_extension.ps1`).
  - Zero warnings across all 9 Rust workspace crates (`cargo clippy`) and zero Flutter analysis issues (`flutter analyze`).

## [Phase 3 Complete] - 2026-10-19

### Added
- **Authenticated Backup Engine (`pwdvault-backup`):**
  - Authenticated `.vaultbak` archive format with 92-byte binary header (magic `PVBAK001`), Argon2id KDF parameters, `KeyEnvelope` wrapping DEK with AEAD magic commitment, and BLAKE3 integrity commitment.
  - Supports credential types: Master Passphrase (Argon2id KDF) or 256-bit Emergency Recovery Key (keyed BLAKE3 KEK derivation).
  - Dry-run non-destructive restoration rehearsal (`rehearse_restore`) providing `BackupRehearsalReport` (verifying integrity, decrypting payload, counting active/trashed items, and breaking down categories without disk modification).
- **Offline Emergency Recovery Kit:**
  - 256-bit CSPRNG `RecoveryKey` wrapped with `Zeroize` and `ZeroizeOnDrop` memory sanitization.
  - Crockford Base32 formatting (`PV-XXXX-XXXX-...`) with case insensitivity and visual ambiguity tolerance (0/O, 1/I/L).
  - Printable Markdown document generator (`RecoveryKitDocument`) with fireproof safe offline storage guidance.
- **Portability & Multi-Format Import Engine (`pwdvault-import-export`):**
  - Zero-dependency RFC 4180 streaming CSV parser and exporter handling quotes, escaped `""`, multiline text, and CRLF/LF.
  - Bitwarden JSON export parser for Logins, SecureNotes, Cards, Identities, custom fields, and folder mapping.
  - 1Password 1PUX JSON (`export.json`) and CSV export parser.
  - KeePass 2.x XML export parser (`<KeePassFile>` / `<Entry>`).
  - Intelligent Deduplication Engine: classifies incoming candidates into `New`, `ExactDuplicate`, and `Conflict`, generates field diffs (`ConflictDiff`), and applies resolution strategies (`Skip`, `Overwrite` with revision history archiving, `KeepBoth`).
- **Typed C-ABI FFI Exports & Flutter Dart Bridge:**
  - Added 9 C-ABI exports: `vault_ffi_create_backup`, `vault_ffi_rehearse_restore`, `vault_ffi_restore_backup`, `vault_ffi_generate_recovery_key`, `vault_ffi_generate_recovery_kit_doc`, `vault_ffi_parse_import`, `vault_ffi_analyze_dedup`, `vault_ffi_apply_import`, and `vault_ffi_export_csv`.
  - Added typed Dart FFI wrappers and models in `apps/flutter/lib/core/ffi/vault_ffi_bindings.dart` and `apps/flutter/lib/models/vault_models.dart`.
- **Flutter UI Integration (`apps/flutter/lib/views/settings`):**
  - `BackupRestoreSheet`: tabbed UI to create `.vaultbak` archives or dry-run rehearsal verification prior to restoring.
  - `RecoveryKitSheet`: view copyable Crockford Base32 key with 30s clipboard auto-clear and save printable Markdown kit.
  - `ImportExportSheet`: multi-format file picker, auto-detection, statistics summary cards, interactive conflict diff comparison, individual and bulk strategy controls (`Skip All Duplicates`, `Overwrite All Conflicts`, `Keep Both`).
  - Plaintext CSV Export Guard: requires master passphrase re-authentication and double-confirmation warning before writing unencrypted CSV to disk.
- **Verification & Testing:**
  - Automated Phase 3 verification script (`scripts/verify_phase3.ps1` and `scripts/verify_phase3.sh`).
  - 54 passing tests in Rust core workspace, zero warnings in `cargo clippy`.
  - 25 passing tests in Flutter test suite (FFI integration, models, backup/restore, deduplication, widgets), zero issues in `flutter analyze`.

## [Phase 2 Complete] - 2026-10-19

### Added
- **Multi-Platform Adaptive Flutter Client (`apps/flutter`):**
  - Responsive 3-pane layout for Desktop and Tablets (>=900px) and compact single-pane layout with bottom navigation for Mobile (<900px).
  - Slate Cyberpunk dark theme (`#0B0F19`, `#111827`, cyan `#06B6D4`, emerald `#10B981`) and clean high-contrast light theme.
  - Interactive Password & Passphrase Generator sheet with real-time Shannon entropy meter, crack-time estimates, sliders, and ephemeral session history buffer.
  - Vault item details view with 1-click clipboard copy, conceal/reveal toggles, custom key-value fields, and expandable revision history snapshots.
  - Item editor with category classification (Logins, Secure Notes, Cards, Identities, Recovery Codes) and generator quick-fill integration.
  - Settings view with master passphrase re-wrapping, Argon2id KDF parameter inspection, database statistics, and auto-lock timeout preferences.
- **Typed C-ABI FFI Integration Bridge (`apps/flutter/lib/core/ffi`):**
  - Dynamic library loader searching runner directories, workspace targets, and runtime paths.
  - Complete typed Dart wrappers for `vault_ffi_create_vault`, `vault_ffi_save_vault`, `vault_ffi_unlock_vault`, `vault_ffi_generate_password`, `vault_ffi_generate_passphrase`, `vault_ffi_estimate_crack_time`, `vault_ffi_search`, `vault_ffi_free_string`, and `vault_ffi_free_bytes`.
  - Automatic memory management with `calloc.free` and native C-memory deallocation.
- **Hardware Biometrics & Convenience Unlock:**
  - `BiometricService` abstraction supporting Windows Hello and Android BiometricPrompt.
  - Windows Hello credential broker integration.
  - Android `FlutterFragmentActivity` compatibility for `BiometricPrompt` and KeyStore StrongBox.
- **Screen Protection & Memory Hygiene Invariants:**
  - Native Windows screen protection enabled via `SetWindowDisplayAffinity(GetHandle(), WDA_EXCLUDEFROMCAPTURE / WDA_MONITOR)` in `flutter_window.cpp` preventing screenshots and OBS recording.
  - Android screen protection enabled via `WindowManager.LayoutParams.FLAG_SECURE` in `MainActivity.kt` preventing screenshots and recent-apps preview capture.
  - Inactivity auto-lock timer (configurable 30s to 30m, default 5m) sanitizing master passphrase and active payload in RAM on trigger.
  - 30-second clipboard clearing timer ensuring copied passwords do not linger in system clipboard.
- **Verification & Testing:**
  - Automated Phase 2 verification script (`scripts/verify_phase2.ps1` and `scripts/verify_phase2.sh`).
  - 13 automated Flutter tests passing (100% pass rate): FFI integration, VaultModels roundtrip, and responsive UI widgets.
  - Zero warnings or errors in `flutter analyze`.

## [Phase 1 Complete] - 2026-10-19

### Added
- **Cryptographic Security Core & Generator (`pwdvault-generator`):**
  - CSPRNG rejection sampling algorithm eliminating modulo bias.
  - Configurable password generator (length 8-128, upper, lower, digits, symbols, ambiguous char exclusion `1lI|0OQ8B`, custom exclusion).
  - Embedded EFF Long Wordlist passphrase generator (3-10 words, custom separator, lowercase/TitleCase/uppercase, number insertion).
  - Shannon entropy scoring and offline GPU (100 GH/s) / cluster (10 TH/s) crack-time models.
  - Ephemeral bounded in-memory generation history ring buffer zeroized on drop.
- **Encrypted Vault Storage & Domain Model (`pwdvault-vault`):**
  - Extended domain model: `VaultItem`, `VaultPayload`, `CustomField` (Text, Concealed, Boolean, Date), `AttachmentMeta` (bounded to 10 MiB, BLAKE3 checksum, per-attachment AEAD nonce), `ItemRevision` history snapshots, encrypted trash bin.
  - ACID atomic storage engine (`VaultStorage::save_atomic`): writes to `.tmp`, calls `FlushFileBuffers` / `sync_all`, creates `.backup` fallback, and atomically replaces target.
  - Key lifecycle management (`VaultSession`): master passphrase re-wrapping, DEK re-encryption key rotation, emergency recovery key generation with Zeroize hygiene.
- **In-Memory Posting & Trigram Search Engine (`pwdvault-search`):**
  - Inverted token posting lists and trigram indices with clean URL domain extraction.
  - Top-K candidate ranking using flat score arrays and score-indexed sorting to eliminate memory reallocation.
  - Query latency benchmarks verified: 10,000 items at p95 = 1.35ms (< 50ms requirement); 100,000 items at p95 = 21.04ms (< 50ms requirement) and p99 = 32.80ms (< 80ms requirement).
- **Quality, Property & Security Verification:**
  - Automated Phase 1 verification script (`scripts/verify_phase1.ps1`, `scripts/verify_phase1.sh`).
  - Total 39 tests passing cleanly across workspace:
    - 6 crypto unit tests
    - 10 generator unit tests + 2 proptests (length/classes and EFF wordlist invariants)
    - 2 search unit tests
    - 11 vault unit tests + 2 proptests (payload roundtrips and trash lifecycle)
    - 4 security integration tests (single bit-flip corruption sweep, truncation sweep 0..len-1, wrong-passphrase variations, header magic tampering)
    - 2 typed FFI tests
  - Zero warnings under `cargo clippy --all-targets -- -D warnings`.
  - Clean code formatting under `cargo fmt --check`.

## [Phase 0 Complete] - 2026-10-19

### Added
- **Foundational Architecture & Threat Modeling:**
  - Complete Requirements specification across 5 platform tiers (`docs/Requirements.md`).
  - System architecture with crate breakdown and data flow (`docs/Architecture.md`).
  - Threat model addressing 10 critical threat vectors and residual risks (`docs/SecurityArchitecture.md`).
  - ADR-001 evaluating KDBX4 vs native versioned store (`docs/ADR/ADR-001-vault-format-and-storage.md`).
  - ADR-002 defining Argon2id KDF parameters and XChaCha20-Poly1305 AEAD (`docs/ADR/ADR-002-cryptographic-primitives-and-kdf.md`).
  - ADR-003 defining typed FFI boundary and UI integration (`docs/ADR/ADR-003-ffi-and-ui-integration.md`).
  - ADR-004 defining memory zeroization and hygiene strategy (`docs/ADR/ADR-004-memory-zeroization-and-sanitization.md`).
  - Master Implementation Plan covering Phases 0 through 8 (`docs/ImplementationPlan.md`).
  - Setup, DeveloperGuide, CodeUnderstanding, UserGuide, TestingStrategy, PerformanceStrategy, RecoveryGuide, Troubleshooting, ReleaseProcess, and RiskRegister.
- **Rust Core Workspace (`core/`):**
  - Crates: `pwdvault-crypto`, `pwdvault-vault`, `pwdvault-generator`, `pwdvault-search`, `pwdvault-backup`, `pwdvault-import-export`, `pwdvault-sync`, `pwdvault-ffi`.
  - Cryptographic prototype: Argon2id KDF with bounded parameter validation (16 MiB - 1 GiB), XChaCha20-Poly1305 authenticated encryption, BLAKE3 checksum commitment, zeroization via `Zeroize` and `ZeroizeOnDrop`.
  - Vault container format (`.vault.v1`): 64-byte authenticated binary header, 72-byte MasterKeyEnvelope wrapping DataKey, and AEAD-encrypted payload.
  - Typed C-ABI FFI boundary with catch_unwind and zero-leak string/buffer deallocators.
- **Flutter Workspace (`apps/flutter/`):**
  - Initialized multi-platform application supporting Windows, Android, iOS, macOS, and Linux.
- **Quality Assurance & Verification:**
  - Automated verification script (`scripts/verify_phase0.ps1` and `scripts/verify_phase0.sh`).
  - Multi-platform CI workflow (`.github/workflows/ci.yml`).
  - Verification results: 14 passing unit tests, zero warnings in `cargo clippy`, clean formatting (`cargo fmt`).
  - KDF & Vault benchmarks executed on host:
    - Fast test profile (16 MiB, 1 iter): 12.47 ms
    - Mobile baseline profile (64 MiB, 3 iter, 4 lanes): 113.86 ms
    - Desktop baseline profile (128 MiB, 3 iter, 4 lanes): 240.18 ms
    - Vault create & encrypt (100 items): 12.65 ms
    - Vault unlock & decrypt (100 items): 12.66 ms
