# System Architecture: Cross-Platform Encrypted Password Vault

## 1. Architectural Philosophy & Design Principles

The Personal Password Generator and Encrypted Vault is designed around five core principles:
1. **Core Domain Independence:** 100% of cryptographic logic, data model transformations, persistence, search, generation, and import/export reside in standalone, portable Rust crates under `/core/`. These crates have zero Flutter, Dart, or platform UI dependencies.
2. **Minimal, Typed FFI Surface:** The boundary between Rust core and Flutter/native UI is strictly isolated through typed C-ABI / `flutter_rust_bridge` patterns. FFI interfaces pass strictly validated data structures and return structured `Result<T, VaultError>` codes. No raw pointers or unmanaged memory handles leak across FFI boundaries.
3. **Defense in Depth & Zeroization:** Memory allocated for secrets (passwords, encryption keys, decrypted item buffers) implements compile-time and run-time zeroization via `zeroize::Zeroize` and `zeroize::ZeroizeOnDrop`. Plaintext secrets never touch permanent storage, swap (where `mlock` is supported), crash dumps, or unencrypted IPC pipes.
4. **Offline First & Sovereign:** The application operates completely offline without user registration, backend servers, analytics, or background internet polling.
5. **ACID Storage with Integrity Proofs:** Vault storage uses atomic write-then-rename semantics backed by BLAKE3 cryptographic hashes and AEAD authentication tags to eliminate state corruption or partial write hazards during system crashes or power failures.

---

## 2. Workspace and Repository Layout

```text
/
├── .github/
│   └── workflows/              # CI/CD pipelines (fmt, clippy, test, audit, SBOM, release)
├── apps/
│   └── flutter/                # Flutter UI (Desktop, Mobile, Tablet)
│       ├── lib/
│       │   ├── domain/         # State management, viewmodels, providers
│       │   ├── presentation/   # Adaptive widgets, design system, screens
│       │   └── bridge/         # Rust FFI client bindings
│       └── test/               # Flutter widget, integration, and golden tests
├── core/                       # Reusable, UI-independent Rust workspace
│   ├── Cargo.toml              # Top-level workspace manifest
│   ├── crypto/                 # Argon2id, XChaCha20-Poly1305, AES-256-GCM, Zeroize
│   ├── vault/                  # Record domain, envelopes, serialization, atomic storage
│   ├── generator/              # Unbiased CSPRNG password & passphrase generation
│   ├── search/                 # In-memory trigram index, fuzzy token search
│   ├── backup/                 # Encrypted backups, recovery kit, restore rehearsal
│   ├── import_export/          # KDBX4, Bitwarden, 1Password, CSV parsers
│   ├── sync/                   # Authenticated paired LAN & encrypted file synchronization
│   └── ffi/                    # Typed C-ABI & Flutter Rust Bridge bindings
├── platform/
│   ├── windows/                # Windows Hello (WebAuthn/CNG), DPAPI, Screen Affinity
│   ├── android/                # Android KeyStore, BiometricPrompt, Autofill Service
│   ├── apple/                  # Swift/Obj-C bridge, Secure Enclave, iOS Credential Provider
│   └── linux/                  # FreeDesktop Secret Service, Wayland/X11 protocols
├── extensions/
│   └── browser/                # Manifest V3 extension with native messaging host
├── tests/                      # End-to-end, cross-crate integration, and tamper tests
├── benchmarks/                 # Criterion microbenchmarks & memory profiling
├── scripts/                    # Idempotent build, test, lint, and packaging scripts
└── docs/                       # Specifications, ADRs, Threat Models, Guides
```

---

## 3. Data Flow and Concurrency Architecture

```mermaid
graph TD
    UI[Flutter UI Layer<br/>Desktop / Mobile / Tablet]
    FFI[Typed FFI Bridge<br/>core/ffi]
    
    subgraph Rust Security Core
        Dispatcher[Task Dispatcher / Rayon Pool]
        VaultMgr[Vault Manager<br/>Session State & Auto-Lock]
        CryptoCore[Crypto Engine<br/>Argon2id / XChaCha20-Poly1305]
        SearchIdx[In-Memory Search Index<br/>Trigram / Inverted Index]
        Storage[Atomic Storage Engine<br/>Write-Temp + fsync + Atomic Rename]
    end
    
    HardwareKey[Hardware Enclave / TPM / KeyStore]
    DiskStorage[(Encrypted Vault File<br/>.vault.v1)]
    
    UI -->|Async Request<br/>(e.g. Search, Unlock)| FFI
    FFI -->|Dispatch to worker thread| Dispatcher
    Dispatcher --> VaultMgr
    VaultMgr -->|Key Derivation & Decryption| CryptoCore
    CryptoCore <-->|Authorize / Release B-KEK| HardwareKey
    CryptoCore -->|Read Raw Bytes| Storage
    Storage <-->|Atomic I/O| DiskStorage
    VaultMgr -->|Populate Decrypted Records| SearchIdx
    SearchIdx -->|Matching Results| FFI
    FFI -->|Render Stream / Result| UI
```

### 3.1 Concurrency & Thread Isolation
- **UI Thread Safety:** The Flutter UI thread executes purely visual composition and user interactions. No cryptographic KDF, serialization, file I/O, or search index operations ever execute on the main thread.
- **Worker Thread Pool:** Rust operations are dispatched asynchronously to dedicated worker threads using Rust standard threading and thread pools.
- **Session Lifecycle & Auto-Lock:** A central `VaultSession` holds the derived `DataKey` wrapped in a zeroizing container. An atomic timestamp tracks user interaction. A background timer triggers lock upon reaching the configured inactivity timeout, immediately zeroizing all in-memory keys and decrypted records.

---

## 4. Cryptographic Envelope & Storage Engine

The vault storage format is an authenticated versioned container (`.vault.v1`):

```text
+-----------------------------------------------------------------------+
| File Header (64 bytes)                                                |
| - Magic Bytes: "VAULT" (5 bytes: 0x56, 0x41, 0x55, 0x4C, 0x54)        |
| - Format Version: 0x0001 (u16, big-endian)                            |
| - KDF Algorithm: 0x01 (Argon2id, u8)                                  |
| - KDF Salt: 32 bytes (Cryptographically random)                       |
| - KDF Parameters: m_cost (u32), t_cost (u32), p_cost (u32) (12 bytes) |
| - Cipher Suite: 0x01 (XChaCha20-Poly1305, u8)                         |
| - Header Flags / Reserved: 7 bytes (zero-padded)                      |
+-----------------------------------------------------------------------+
| Master Key Envelope (48 bytes)                                        |
| - Nonce: 24 bytes                                                     |
| - Ciphertext + Poly1305 Tag: 32 bytes DEK + 16 bytes Tag              |
+-----------------------------------------------------------------------+
| Recovery Key Envelope (48 bytes)                                      |
| - Nonce: 24 bytes                                                     |
| - Ciphertext + Poly1305 Tag: 32 bytes DEK + 16 bytes Tag              |
+-----------------------------------------------------------------------+
| Payload Envelope                                                      |
| - Nonce: 24 bytes                                                     |
| - Length: 64-bit integer                                              |
| - AEAD Ciphertext: CBOR/Bincode serialized VaultPayload               |
| - Poly1305 Tag: 16 bytes (Authenticates Header + Nonce + Payload)     |
+-----------------------------------------------------------------------+
| Checksum & Commitment                                                 |
| - BLAKE3 Checksum: 32 bytes                                           |
+-----------------------------------------------------------------------+
```

### 4.1 Storage Invariants
- **Atomic Commits:** The file is never modified in-place. The engine writes the new payload to a temporary sibling file (`vault.v1.tmp`), forces a metadata and data flush to physical media (`fsync` / `FlushFileBuffers`), and executes an atomic filesystem rename over the target file.
- **Rollback Safety:** If any step fails before the atomic rename succeeds, the original vault file remains completely intact and uncorrupted.
- **Tamper Rejection:** Any bit flip in the header, envelopes, payload, or nonces immediately results in an authenticated decryption error (`VaultError::AuthenticationFailed`), refusing to decrypt or parse partial data.
