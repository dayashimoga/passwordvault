# ADR-002: Cryptographic Primitives, KDF Parameters, and Key Derivation

## Status
**Decided / Accepted**

## Date
2026-10-19

## Context
The security of an offline password vault depends directly upon:
1. The resistance of its Key Derivation Function (KDF) against massively parallelized GPU and ASIC brute-force attacks.
2. The cryptographic strength and side-channel resistance of its symmetric cipher.
3. The cryptographic isolation between the Master Passphrase, the Data Encryption Key (DEK), and peripheral keys (biometric wraps, recovery keys, search indexes).

## Decisions

### 1. KDF: Argon2id (RFC 9106)
- **Algorithm:** Argon2id (hybrid version of Argon2 combining Argon2d's resistance to GPU/ASIC cracking with Argon2i's resistance to side-channel cache attacks).
- **Default Baseline Parameters:**
  - Salt: 32 bytes from OS CSPRNG (`getrandom`).
  - Memory Cost ($m$):
    - Desktop (Windows / macOS / Linux): $131,072\text{ KiB}$ (128 MiB).
    - Mobile (Android / iOS): $65,536\text{ KiB}$ (64 MiB).
  - Time Cost / Iterations ($t$): 3 passes.
  - Parallelism ($p$): 4 threads (clamped to available CPU cores at runtime).
- **Attacker-Controlled Parameter Validation Bounds:**
  - $16,384\text{ KiB} \le m \le 1,048,576\text{ KiB}$ (16 MiB to 1 GiB). Any vault file specifying $m < 16\text{ MiB}$ or $m > 1\text{ GiB}$ is rejected before allocation.
  - $1 \le t \le 10$ passes.
  - $1 \le p \le 16$ threads.
  - Salt length must equal exactly 32 bytes.

### 2. Symmetric AEAD: XChaCha20-Poly1305
- **Algorithm:** XChaCha20-Poly1305 (256-bit key, 192-bit extended nonce, 128-bit Poly1305 authentication tag).
- **Rationale:**
  - 192-bit nonces allow safe random nonce generation without risk of catastrophic nonce-reuse collision (unlike standard 96-bit AES-GCM where birthday bound collisions become significant after $2^{32}$ encryptions).
  - Constant-time software execution across all CPU architectures (x86_64, ARM64, RISC-V) without hardware AES-NI requirements or cache-timing leakage.
- **Secondary Cipher Support:** AES-256-GCM is supported as an optional cipher suite ID where hardware acceleration is verified.

### 3. Key Derivation & Purpose Separation (HKDF)
- The Data Encryption Key (DEK) is a 256-bit random key generated upon vault creation.
- Subkeys are derived strictly using HKDF-SHA256 (RFC 5869) with domain-separated info strings:
  - `vault:record-encryption:v1`
  - `vault:attachment-encryption:v1`
  - `vault:search-token-hash:v1`
  - `vault:sync-authentication:v1`

## Consequences
- **Positive:** Uncompromising defense against GPU/ASIC password cracking clusters; constant-time cryptographic operations eliminate cache timing side-channels; safe random nonces.
- **Negative:** Memory allocation during vault unlock is intentional (64–128 MiB) and takes ~100–300ms of compute, which must be clearly visualized to the user as cryptographic work rather than an app freeze.
