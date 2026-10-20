# ADR-001: Evaluation of Vault Format: Native Versioned Store vs. KDBX4

## Status
**Decided / Accepted**

## Date
2026-10-19

## Context
A critical architectural decision for the personal password generator and encrypted vault is determining the primary storage container format. Specifically, we must evaluate whether to use a maintained KDBX-compatible format (such as KeePass KDBX v4) as the native on-disk format or to adopt a modern, versioned authenticated encrypted store format while supporting KDBX v4 through comprehensive import and export modules.

## Evaluation & Comparison

| Criteria | Native KDBX v4 Format | Versioned Authenticated Store (`.vault.v1`) |
| :--- | :--- | :--- |
| **Cryptographic Agility** | Fixed standard structure (ChaCha20 or AES-256-CBC/KDF with Argon2/AES-KDF). Rigid header structure with inner XML stream. | Clean envelope: Argon2id KDF + XChaCha20-Poly1305 AEAD. Separate purpose-derived keys via HKDF. |
| **Data Integrity & Authenticity** | HMAC-SHA256 chunked validation across blocks. Vulnerable to structural parsing attacks in legacy XML parsers. | Full AEAD authentication covering headers, version, salt, parameters, and payload in a single cryptographic envelope. |
| **Sync & Merging Semantics** | Monolithic database updates or complex tree-based XML reconciliation. Difficult to do fine-grained record-level syncing without full database lock. | Modular record architecture enabling CRDT / vector-clock record-level conflict resolution and tombstones for LAN/file synchronization. |
| **Passkeys & Modern Record Types** | KDBX requires custom non-standard XML schema attributes or plugin attachments to store WebAuthn/Passkey private keys and credentials. | First-class, strongly-typed schema for Passkeys, TOTP seeds, identities, and custom fields without schema hacks. |
| **Implementation Complexity & Auditability** | High: requires complex gzip/xml handling, binary stream encodings, legacy header types, and large parser attack surface. | Minimal: compact, deterministic CBOR serialization over verified RustCrypto AEAD primitives. Zero unsafe XML parsers. |
| **Ecosystem Interoperability** | Native compatibility with KeePassXC, KeePassDX, Strongbox. | Full interoperability achieved via bi-directional KDBX v4 import and export engines without burdening daily runtime performance. |

## Decision
We decide to adopt a **Versioned Authenticated Encrypted Store (`.vault.v1`)** as the native vault container format, while providing **complete, high-fidelity KDBX v4 Import and Export capabilities**.

### Rationale
1. **Attack Surface Reduction:** Native KDBX requires XML parsing libraries (which have historically suffered from XXE, entity expansion, and parser divergence bugs). The native `.vault.v1` container uses compact, length-bounded CBOR serialization with zero schema-injection vectors.
2. **Crash Resilience and Atomicity:** A modern container format allows lightweight atomic updates (write-to-temporary, fsync, atomic rename) and deterministic corruption detection via BLAKE3 commitments.
3. **Record-Level Cryptographic Isolation:** Individual records are encrypted using subkeys derived from the DEK, enabling future fine-grained record sharing, delta-syncing, and zero-knowledge search indexing.
4. **Interoperability Preserved:** By implementing a robust, memory-safe KDBX v4 parser and exporter in `/core/import_export`, users can import their existing vaults from KeePassXC or export to KDBX without locking themselves into a proprietary silo.

## Consequences
- **Positive:** Maximum security, minimal attack surface, fast cold-startup (< 2s), clean modern record schema (supporting Passkeys natively), and predictable ACID storage.
- **Negative:** External KeePass tools cannot read the `.vault.v1` file directly without using the import/export bridge or CLI utility.
