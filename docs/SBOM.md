# Software Bill of Materials (SBOM) & Supply Chain Security

## 1. Overview
This document specifies the Software Bill of Materials (SBOM) for Antigravity Vault v1.0.0, adhering to the CycloneDX 1.5 specification. The machine-readable version is located at [`docs/SBOM.json`](file:///j:/rustpwdvault/docs/SBOM.json).

## 2. Supply Chain Security Principles
- **Zero Un-audited Dependencies**: All third-party crates are vetted against RustSec advisory databases.
- **Pure Safe Rust Cryptography**: All cryptographic implementations operate in `#![deny(unsafe_code)]` modules where possible, with zero platform C bindings for core crypto.
- **Zero Network Ingestion**: The core vault engine performs zero background telemetry or remote dependency resolution.
- **Strict License Compatibility**: Every component is licensed under permissive, enterprise-friendly licenses (MIT, Apache-2.0, or BSD-3-Clause).

---

## 3. Cryptographic Primitives & Dependency Matrix

| Component | Version | Role / Purpose | License | Security Invariants |
| :--- | :--- | :--- | :--- | :--- |
| **argon2** | `0.5.3` | Key Derivation Function (Argon2id) | Apache-2.0 / MIT | Memory-hard (64 MiB RAM), 3 iterations, GPU cracking resistance. |
| **chacha20poly1305** | `0.10.1` | Primary AEAD (XChaCha20-Poly1305) | Apache-2.0 / MIT | 192-bit nonce, 256-bit key, authenticated associated data (AAD). |
| **zeroize** | `1.8.1` | Volatile Memory Hygiene | Apache-2.0 / MIT | Guarantees zeroization on drop for passphrases, keys, and tokens. |
| **blake3** | `1.5.5` | Checksums, Fingerprints, KEK | Apache-2.0 / CC0 | Tree-hashing, 256-bit commitment, sub-millisecond verification. |
| **subtle** | `2.6.1` | Constant-Time Comparison | BSD-3-Clause | Prevents timing attacks on HMACs, tags, and tokens. |
| **sha2** | `0.10.8` | SHA-256 / SHA-512 Digests | Apache-2.0 / MIT | Standard WebAuthn passkey commitments and TOTP algorithms. |
| **hkdf** | `0.12.4` | Key Expansion (RFC 5869) | Apache-2.0 / MIT | Sub-key derivation from master secrets without key reuse. |
| **serde** / **serde_json** | `1.0` | Secure Serialization | Apache-2.0 / MIT | Bounded deserialization preventing memory exhaustion. |
| **flutter** | `3.38.4` | Cross-Platform UI Framework | BSD-3-Clause | Native canvas rendering with hardware acceleration. |
| **ffi** | `2.1.3` | Dart C-ABI Interoperability | BSD-3-Clause | Memory-safe pointers and manual allocation tracking. |

---

## 4. Supply Chain Audit & Vulnerability Scanning
- **RustSec Advisory Audit**: `cargo audit` verified zero known CVEs across all workspace dependencies.
- **Cargo Deny Policy**: Rejects copyleft licenses (GPL/AGPL) and duplicate crate versions.
- **ProGuard / R8 Optimization**: Strips unused metadata, debugging symbols, and minimizes code surface on Android.
- **Authenticode & Checksum Integrity**: Release archives are published alongside canonical SHA-256 checksums (`SHA256SUMS.txt`).
