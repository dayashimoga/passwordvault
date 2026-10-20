# Implementation Task Tracker (TODO)

## Phase 0: Design & Foundation [COMPLETED - 2026-10-19]
- [x] Inspect existing workspace and environment tooling (Rust 1.99.1, Flutter 3.38.4, Git 2.56.0).
- [x] Create comprehensive Requirements specification (`docs/Requirements.md`).
- [x] Create System Architecture blueprint (`docs/Architecture.md`).
- [x] Create Threat Model covering 10 threat vectors & residual risks (`docs/SecurityArchitecture.md`).
- [x] Create ADR-001: KDBX4 evaluation vs. Versioned Store (`docs/ADR/ADR-001-vault-format-and-storage.md`).
- [x] Create ADR-002: Cryptographic Primitives & Argon2id KDF (`docs/ADR/ADR-002-cryptographic-primitives-and-kdf.md`).
- [x] Create ADR-003: FFI Boundary and UI Integration (`docs/ADR/ADR-003-ffi-and-ui-integration.md`).
- [x] Create ADR-004: Memory Zeroization & Hygiene (`docs/ADR/ADR-004-memory-zeroization-and-sanitization.md`).
- [x] Create Setup, DevGuide, CodeUnderstanding, UserGuide, Testing, Performance, Recovery, Troubleshooting, ReleaseProcess, RiskRegister.
- [x] Initialize Rust workspace (`core/Cargo.toml`) and crates (`crypto`, `vault`, `generator`, `search`, `backup`, `import_export`, `sync`, `ffi`).
- [x] Initialize Flutter multi-platform workspace (`apps/flutter`) for Windows, Android, iOS, macOS, and Linux.
- [x] Implement Cryptographic Prototype (`core/crypto`): Argon2id KDF, bounded parameter checks, XChaCha20-Poly1305 AEAD, zeroization, BLAKE3 checksums.
- [x] Implement Vault Creation & Unlock prototype with authenticated 64-byte header and 72-byte key envelope (`core/vault`).
- [x] Implement KDF & Memory Benchmarks (`benchmarks/src/kdf_bench.rs`).
- [x] Implement typed C-ABI FFI skeleton (`core/ffi/src/lib.rs`).
- [x] Setup reproducible build/test scripts (`scripts/verify_phase0.ps1`, `scripts/verify_phase0.sh`, `scripts/Dockerfile`).
- [x] Setup multi-platform CI workflow (`.github/workflows/ci.yml`).
- [x] Execute automated Phase 0 verification gate: 14 passing tests, 0 clippy warnings, clean formatting, benchmark verification.

## Phase 1: Rust Security Core [COMPLETED - 2026-10-19]
- [x] Password generator with unbiased CSPRNG rejection sampling & embedded EFF Long Wordlist (`core/generator`).
- [x] Character class enforcement (upper, lower, digits, symbols), ambiguous character exclusion (`1lI|0OQ8B`), custom exclusions.
- [x] Passphrase generator with 3–10 words, custom separators, TitleCase/Uppercase/lowercase, number insertion.
- [x] Shannon entropy calculation and online/offline GPU (100 GH/s) / cluster (10 TH/s) crack-time models.
- [x] Ephemeral bounded generation history buffer in zeroized RAM, flushed on drop/lock.
- [x] Complete encrypted CRUD domain model (`VaultItem`, `VaultPayload`, `CustomField`, `AttachmentMeta`, `ItemRevision`, encrypted trash bin).
- [x] Atomic storage engine with `.tmp` write, explicit `FlushFileBuffers` / `sync_all`, automatic `.backup` creation, and atomic replacement (`core/vault/src/storage.rs`).
- [x] In-memory inverted posting and trigram search index with domain extraction, prefix lookup, and top-K candidate ranking (`core/search/src/index.rs`).
- [x] Search performance verified: p95 = 1.35ms for 10k items (< 50ms requirement); p95 = 21.04ms / p99 = 32.80ms for 100k items (< 80ms requirement).
- [x] Key lifecycle: master passphrase change (re-wrapping existing DEK), DEK rotation (re-encrypting payload with fresh DEK), emergency recovery key generation.
- [x] Comprehensive security integration tests: single bit-flip corruption sweep across all positions, truncation sweep from 0 to len-1, wrong-passphrase variations, header magic tampering.
- [x] Proptest property suites for password & passphrase generation and vault serialization/encryption roundtrips.
- [x] Automated Phase 1 verification gate (`scripts/verify_phase1.ps1`, `scripts/verify_phase1.sh`): 39 unit/property/security tests passing, zero clippy warnings, clean formatting.

## Phase 2: Windows and Android MVP [COMPLETED - 2026-10-19]
- [x] Adaptive Flutter UI (Desktop, Tablet, Mobile) with slate cyberpunk dark/light themes (`apps/flutter/lib/core/theme/app_theme.dart`, `apps/flutter/lib/views/vault_shell.dart`).
- [x] Wire Flutter UI to Rust core via C-ABI FFI (`pwdvault-ffi` with dynamic library loading, typed Dart wrappers, and automatic memory cleanup).
- [x] Windows Hello convenience unlock abstraction with biometric hardware handshake (`apps/flutter/lib/services/biometric_service.dart`).
- [x] Android BiometricPrompt & KeyStore StrongBox integration with `FlutterFragmentActivity` compatibility (`apps/flutter/android/app/src/main/kotlin/.../MainActivity.kt`).
- [x] Auto-lock (configurable inactivity timer), 30-second clipboard clearing, and platform screen protection (`FLAG_SECURE` on Android, `SetWindowDisplayAffinity(WDA_MONITOR/WDA_EXCLUDEFROMCAPTURE)` on Windows).
- [x] Automated Phase 2 verification gate (`scripts/verify_phase2.ps1`, `scripts/verify_phase2.sh`): 13 tests passing, zero analyzer warnings, platform screen protection verified.

## Phase 3: Backup, Recovery, and Portability [COMPLETED - 2026-10-19]
- [x] Encrypted backup container (`.vaultbak`) with Argon2id KDF, XChaCha20-Poly1305 AEAD, and BLAKE3 integrity commitment (`core/backup/src/archive.rs`).
- [x] Non-destructive dry-run restoration rehearsal returning `BackupRehearsalReport` without disk I/O.
- [x] 256-bit CSPRNG Emergency Recovery Key with Crockford Base32 formatting (`PV-XXXX-XXXX-...`), case/ambiguity tolerance, and `ZeroizeOnDrop` hygiene (`core/backup/src/recovery_kit.rs`).
- [x] Printable offline Emergency Recovery Kit document generator with physical safe storage instructions.
- [x] Zero-dependency RFC 4180 streaming CSV parser (escaped `""`, quoted commas, CRLF/LF) and exporter (`core/import_export/src/csv.rs`).
- [x] High-fidelity Bitwarden JSON export parser (Logins, SecureNotes, Cards, Identities, custom fields, folder mapping).
- [x] 1Password 1PUX JSON (`export.json`) and CSV parser.
- [x] KeePass 2.x XML export parser (`<KeePassFile>` / `<Entry>`).
- [x] Intelligent Deduplication Engine (`New`, `ExactDuplicate`, `Conflict` classification, `ConflictDiff` generation, and strategy application with revision snapshotting).
- [x] 9 C-ABI FFI exports: `vault_ffi_create_backup`, `vault_ffi_rehearse_restore`, `vault_ffi_restore_backup`, `vault_ffi_generate_recovery_key`, `vault_ffi_generate_recovery_kit_doc`, `vault_ffi_parse_import`, `vault_ffi_analyze_dedup`, `vault_ffi_apply_import`, `vault_ffi_export_csv`.
- [x] Typed Flutter Dart FFI bridge methods with safe C-string and buffer deallocations (`apps/flutter/lib/core/ffi/vault_ffi_bindings.dart`).
- [x] Interactive Flutter UI sheets: `BackupRestoreSheet` (create/rehearse/restore), `RecoveryKitSheet` (copy/export kit), and `ImportExportSheet` (interactive conflict diff resolution table).
- [x] Guarded plaintext CSV export requiring master passphrase re-authentication and double-confirmation warning.
- [x] Automated Phase 3 verification gate (`scripts/verify_phase3.ps1`, `scripts/verify_phase3.sh`): 54 Rust tests passing, 25 Flutter tests passing, zero clippy warnings, zero analyzer issues.

## Phase 4: Autofill and Browser Integration [COMPLETED - 2026-10-19]
- [x] Rust Native Messaging Host (`core/native_host`) implementing 4-byte length-prefixed protocol with 1 MiB bounds checking.
- [x] 256-bit CSPRNG `HostSession` token authentication and error reporting.
- [x] Base domain extraction and eTLD+1 heuristic domain matching (`domains_match`) for subdomain routing.
- [x] Anti-phishing origin verification: strictly rejects credential autofill requests across mismatched web domains.
- [x] Atomic credential saving from browser via `VaultContainer::create` + `VaultStorage::save_atomic`.
- [x] Manifest V3 Browser Extension (`apps/browser_extension`):
  * `manifest.json`: Chromium and Firefox Gecko compatible (`pwdvault@antigravity.internal`).
  * `background/service_worker.js`: Native messaging connection management, session token caching, and request routing.
  * `content/content.js` & `content/content.css`: Top-level window execution check (`window === window.top`) for iframe isolation, in-field shield badge injection, synthetic bubbling `InputEvent`/`change` event dispatch, and form submit credential capture toast.
  * `popup/popup.html`, `popup.css`, `popup.js`: Slate Cyberpunk theme, active tab domain detector, matching logins list with 1-click autofill, and quick password generator with entropy meter.
  * Native messaging manifests (`com.antigravity.pwdvault.json` for Chrome/Edge and `com.antigravity.pwdvault.firefox.json` for Firefox).
  * Automated host registration script (`scripts/register_native_host.ps1` and `scripts/register_native_host.sh`) for Windows Registry.
- [x] Android Autofill Framework Integration (`apps/flutter/android`):
  * `AndroidManifest.xml` declaration with `BIND_AUTOFILL_SERVICE` permission and metadata.
  * `res/xml/autofill_service_config.xml` service configuration.
  * `res/layout/autofill_dataset_item.xml` RemoteViews layout.
  * `AutofillStructureParser.kt`: traverses `AssistStructure.ViewNode` tree, extracts web domain/package name, detects username and password fields.
  * `PwdVaultAutofillService.kt`: handles `onFillRequest` (constructs `Dataset`s with `RemoteViews` presentation) and `onSaveRequest` (credential capture).
- [x] Automated Phase 4 verification gate (`scripts/verify_phase4.ps1`, `scripts/verify_phase4.sh`, `scripts/verify_extension.ps1`): all 9 Rust crates passing (including native host integration test), zero clippy warnings, extension structure verified, Android autofill verified, and Flutter test suite passing.

## Phase 5: iPhone/iPad & Desktops [COMPLETED - 2026-10-20]
- [x] iOS & iPadOS Integration (`apps/flutter/ios`):
  * `AppDelegate.swift`: `LocalAuthentication` Face ID / Touch ID platform channel and automatic multitasking snapshot obfuscation privacy blur view (`privacyShieldView`).
  * `Info.plist`: `NSFaceIDUsageDescription` privacy declaration.
  * Credential Provider Extension (`apps/flutter/ios/CredentialProviderExtension`): `CredentialProviderViewController.swift` extending `ASCredentialProviderViewController` for system-wide autofill across Safari and third-party iOS apps.
  * App Group entitlement (`group.com.antigravity.pwdvault`) configured for shared container access between main app and extension.
- [x] macOS Integration (`apps/flutter/macos`):
  * Hardware Screen Protection: `NSWindow.sharingType = .none` in `MainFlutterWindow.swift` preventing WindowServer screen recording, remote desktop preview, and screen capture.
  * `AppDelegate.swift`: Touch ID `LocalAuthentication` channel and minimum window geometry constraints (800x600).
- [x] Linux Integration (`apps/flutter/linux`):
  * `runner/my_application.cc`: window title, header bar, and `GDK_HINT_MIN_SIZE` geometry constraints.
  * `pwdvault.desktop`: XDG-compliant desktop entry with `Utility;Security;` categorization.
  * `com.antigravity.pwdvault.metainfo.xml`: AppStream metainfo for Linux software distribution.
  * `debian/control`: Debian/Ubuntu packaging control template with `libsecret-1-dev` dependency.
- [x] Cross-Platform UI & Services:
  * `BiometricService` (`apps/flutter/lib/services/biometric_service.dart`): supports Face ID, Touch ID, Windows Hello, Android BiometricPrompt, and Linux Keyring with graceful test fallbacks.
  * Adaptive responsiveness across desktop (3-column), iPad / tablet (2-column/compact rail), and mobile (single-column).
- [x] Automated Phase 5 verification gate (`scripts/verify_phase5.ps1`, `scripts/verify_phase5.sh`): all 9 Rust crates passing, zero clippy warnings, platform files verified, and 27 Flutter tests passing (including `platform_desktop_test.dart`).

## Phase 6: Encrypted Synchronization [COMPLETED - 2026-10-20]
- [x] Monotonic Vector Clocks & Causal Tracking (`core/sync/src/vector_clock.rs`):
  * Monotonic Lamport logical counters per device with component-wise merge.
  * Strict causal dominance check (`dominates`) and concurrency detection (`is_concurrent`).
- [x] Zero Data Loss CRDT Conflict Resolution (`core/sync/src/crdt.rs`):
  * Deterministic Last-Write-Wins (LWW) conflict resolution with tie-breaking BLAKE3 payload hashes.
  * Invariant: Zero Data Loss — losing variants in concurrent multi-device edits are converted to `ItemRevision` snapshots and prepended to the winner's revision history.
  * Tombstone synchronization: deterministic deletion propagation and edit-vs-deletion precedence.
- [x] Authenticated `.syncpack` Container (`core/sync/src/syncpack.rs`):
  * 100-byte authenticated header: magic `PVSYNC01`, version, 24-byte random nonce, 32-byte salt, and 32-byte BLAKE3 payload commitment.
  * Header authenticated as AAD in XChaCha20-Poly1305 AEAD; immediate tamper detection prior to deserialization.
- [x] Out-of-Band Device Pairing (`core/sync/src/pairing.rs`):
  * QR Code URI generator (`pwdvault://pair?data=...`) with 15-minute validity window.
  * Public BLAKE3 fingerprint of pre-shared sync key to prevent MITM attacks during pairing.
  * Mutual zero-knowledge proof of possession (`core/sync/src/lan_sync.rs`) via `BLAKE3(sync_key || challenge || "PWDVAULT_LAN_SYNC_AUTH_V1")` for LAN direct sync.
- [x] C-ABI FFI Sync Layer (`core/ffi/src/lib.rs`):
  * `vault_ffi_sync_create_syncpack`
  * `vault_ffi_sync_apply_syncpack`
  * `vault_ffi_sync_generate_pairing_qr`
  * `vault_ffi_sync_verify_pairing_qr`
  * `vault_ffi_sync_merge_payloads`
- [x] Flutter UI & Bindings (`apps/flutter`):
  * `vault_ffi_bindings.dart`: High-level typed sync methods (`createSyncPack`, `applySyncPack`, `generatePairingQrUri`, `verifyPairingQrUri`, `mergePayloads`).
  * `vault_state.dart`: Vector clock state, device identity, `exportSyncPack()`, and `ingestSyncPack()`.
  * `sync_sheet.dart`: 3-tab modal sheet (Sync Package file transfer, Device Pairing & LAN Sync, Vector Clocks causality tracker).
  * `settings_view.dart`: Integrated "Encrypted Synchronization & Multi-Device" settings card.
  * `sync_test.dart`: Complete sync integration test suite (CRDT conflict preservation roundtrip, QR pairing verification, direct merge, and widget UI test).
- [x] Automated Phase 6 verification gate (`scripts/verify_phase6.ps1`, `scripts/verify_phase6.sh`): all 9 Rust crates passing (76 Rust tests), zero clippy warnings, FFI deployed, zero Flutter analyzer issues, and all 31 Flutter tests passing.

## Phase 7: Advanced Personal Security [COMPLETED - 2026-10-20]
- [x] RFC 6238 Time-Based One-Time Password (TOTP) Authenticator Engine (`core/security/src/totp.rs`):
  * RFC 4648 standard Base32 encoder and decoder with padding tolerance.
  * Dynamic binary truncation and modulo reduction yielding 6, 7, or 8-digit verification codes.
  * Tolerance drift window verification (`-toleranceSteps` to `+toleranceSteps`).
  * `otpauth://totp/` URI parsing and formatting with secret, issuer, account, algorithm, and period extraction.
  * Standard vector validation against RFC 6238 Appendix B test vectors (SHA-1, SHA-256, SHA-512).
- [x] WebAuthn / FIDO2 Passkey Engine (`core/security/src/passkey.rs`):
  * Cryptographic credential keypair generation supporting ES256 (NIST P-256) and EdDSA (Ed25519).
  * 37-byte Authenticator Data framing (`rp_id_hash` [32] || `flags` [1] || `sign_count` [4]).
  * Assertion signing over `authenticator_data || sha256(client_data_json)` with monotonic counter progression.
- [x] Privacy-Preserving k-Anonymity Breach Watch (`core/security/src/audit.rs`):
  * Zero-knowledge query formulation: only the first 5 hexadecimal characters of SHA-1(password) leave the device over HTTPS.
  * Local 35-character suffix lookup against the HaveIBeenPwned range response without candidate disclosure.
- [x] Vault Security Hygiene Auditor (`core/security/src/audit.rs`):
  * Identification of reused password clusters across different services.
  * Weak password detection (< 12 characters or Shannon entropy < 40 bits).
  * Stale password detection (last modified > 90 days).
  * Missing two-factor authentication (2FA) audit on critical login items.
  * Dynamic 0–100 Cryptographic Health Score calculation with actionable remediation advice.
- [x] C-ABI FFI Security Exports (`core/ffi/src/lib.rs`):
  * `vault_ffi_totp_generate`, `vault_ffi_totp_verify`, `vault_ffi_totp_parse_uri`.
  * `vault_ffi_passkey_generate`, `vault_ffi_passkey_sign_assertion`.
  * `vault_ffi_audit_vault`, `vault_ffi_breach_prepare_query`, `vault_ffi_breach_check_response`.
- [x] Flutter UI & Bindings (`apps/flutter`):
  * Typed FFI bridge methods in `vault_ffi_bindings.dart` with automatic buffer and memory lifecycle management.
  * `VaultState` security methods (`runSecurityAudit`, `checkPasswordBreach`, `generateTotpCode`, `parseTotpUri`).
  * `SecurityAuditSheet` (`apps/flutter/lib/views/settings/security_audit_sheet.dart`) featuring 3 tabs:
    - Tab 1: Vault Health Audit (health score gauge, metric cards, reused clusters, weak password alerts, and recommendations).
    - Tab 2: Breach Watch (privacy k-anonymity single password tester and full-vault batch breach scanner).
    - Tab 3: Passkey & FIDO2 Lab (ES256 / EdDSA passkey generator and WebAuthn assertion challenge tester).
  * Live Two-Factor Authenticator (TOTP) card with real-time countdown progress indicator and copy in `ItemDetailView`.
  * Automatic TOTP Key/URI parser and validator in `ItemEditorView`.
  * Cryptographic Health Banner & Settings entry in `SettingsView`.
- [x] Automated Phase 7 verification gate (`scripts/verify_phase7.ps1`, `scripts/verify_phase7.sh`): all 10 Rust crates passing (84 Rust tests), zero clippy warnings (`-D warnings`), FFI deployed, zero Flutter analyzer issues, and all 38 Flutter tests passing (including `security_audit_test.dart`).

## Phase 8: Hardening, Packaging & Release [COMPLETED - 2026-10-20]
- [x] Security Fuzzing & Property Suites:
  * `core/security/tests/fuzz_and_hardening_tests.rs`: Fuzzing TOTP URI parser across arbitrary UTF-8/schemes, k-Anonymity range response parser resilience, k-anonymity invariant verification (5-char prefix + 35-char suffix == SHA-1), TOTP generation and drift windows, and WebAuthn Passkey credential assertion lifecycle and monotonic counter verification.
  * `core/sync/tests/sync_fuzz_tests.rs`: Fuzzing arbitrary byte ingestion in `read_syncpack`, arbitrary pairing URI fuzzing in `verify_pairing_qr_data`, and CRDT merge idempotency & Zero Data Loss invariants.
- [x] Memory Hygiene & Zeroization Verification:
  * Explicit testing of `Zeroize` and `ZeroizeOnDrop` across sensitive cryptographic buffers, private keys, and recovery secrets.
  * Verified constant-time comparisons (`subtle::ConstantTimeEq`) across all HMAC and token verifications.
- [x] Cross-Platform Release Packaging & Distribution:
  * **Windows**: Inno Setup installer script (`packaging/windows/installer.iss`) and portable distribution packaging (`scripts/package_windows.ps1`) bundling release runner, FFI DLL, native host executable, and extension manifests with SHA-256 verification.
  * **Android**: ProGuard / R8 optimization configuration (`apps/flutter/android/app/proguard-rules.pro` and `build.gradle.kts`) protecting JNI/Dart symbols, Autofill service, and biometrics while enabling code shrinking, plus release packaging scripts (`scripts/package_android.ps1`, `scripts/package_android.sh`).
  * **macOS / iOS**: Release packaging and archive staging scripts (`scripts/package_apple.sh`) for macOS app bundle and iOS release archives.
  * **Linux**: Release tarball packaging script (`scripts/package_linux.sh`) bundling release bundle, desktop entry, AppStream metadata, and native messaging host.
- [x] Software Bill of Materials (SBOM) & Supply Chain Security:
  * CycloneDX 1.5 JSON formatted SBOM ([`docs/SBOM.json`](file:///j:/rustpwdvault/docs/SBOM.json)) and human-readable document ([`docs/SBOM.md`](file:///j:/rustpwdvault/docs/SBOM.md)) covering all Rust, Dart, and Flutter dependencies with license compatibility audits.
- [x] Hardware Performance & Battery Profiling Documentation:
  * Comprehensive benchmarks in [`docs/PerformanceProfiling.md`](file:///j:/rustpwdvault/docs/PerformanceProfiling.md) covering Argon2id unlock latencies, inverted index search scalability (p95 = 1.35ms for 10k items, p95 = 21.04ms for 100k items), memory baselines (< 56 MB desktop, < 40 MB mobile), and zero idle battery drain.
- [x] Production Release Checklist & Verification Matrix:
  * Production release verification matrix signed off in [`docs/ReleaseChecklist.md`](file:///j:/rustpwdvault/docs/ReleaseChecklist.md).
- [x] Automated Phase 8 verification gate (`scripts/verify_phase8.ps1`, `scripts/verify_phase8.sh`): all 10 Rust crates passing (94 tests total including unit, property, security, and fuzzing suites), zero clippy warnings (`-D warnings`), all packaging configurations verified, CycloneDX SBOM validated, zero Flutter analyzer issues, and all 38 Flutter tests passing.


