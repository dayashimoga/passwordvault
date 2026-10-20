# Code Understanding & Deep Architectural Tour

## 1. Domain Modeling (`core/vault`)
- `VaultHeader`: The 64-byte unauthenticated binary header establishing magic bytes, version, KDF algorithm, parameters, and salt.
- `MasterKeyEnvelope`: AEAD encrypted envelope holding the 256-bit Data Encryption Key (DEK) wrapped by the Master KEK.
- `RecoveryKeyEnvelope`: Secondary AEAD envelope holding the same DEK wrapped by a high-entropy recovery key.
- `VaultPayload`: Decrypted container holding the list of `VaultItem`s, folders, tags, settings, and revision history.
- `VaultItem`: Strongly-typed enum/struct representing a credential entry:
  - `LoginItem`: URLs, username, password, TOTP seed, passkey references.
  - `SecureNote`: Markdown/text content, tags.
  - `PaymentCard`: Encrypted PAN, CVV, expiry, cardholder name.
  - `IdentityItem`: Full name, personal ID, address.
  - `CustomField`: Key-value pairs with field types (text, concealed, boolean).

---

## 2. Cryptographic Engine (`core/crypto`)
- `KdfEngine`: Encapsulates Argon2id hashing, parameter validation, and salt generation.
- `AeadCipher`: Abstracts XChaCha20-Poly1305 and AES-256-GCM authenticated encryption. Enforces 192-bit extended random nonces and 128-bit Poly1305 MAC verification.
- `SecureBuffer`: Heap-allocated buffer wrapped in `ZeroizeOnDrop` ensuring automatic zeroing when dropping out of scope.
- `KeyDerivation`: HKDF-SHA256 purpose-separated subkey generation.

---

## 3. Search Index (`core/search`)
- `SearchEngine`: In-memory inverted index constructed upon vault unlock.
- Records are indexed by tokenized, lowercased trigrams of titles, usernames, URLs, and tags.
- Secrets (passwords, notes, keys) are strictly **excluded** from the search index to eliminate unnecessary plaintext retention.

---

## 4. FFI Boundary (`core/ffi`)
- Exposes a minimal, typed C-ABI interface for Flutter and native platform callers:
  - `vault_session_create(master_passphrase, kdf_params) -> SessionHandle`
  - `vault_session_unlock(vault_bytes, master_passphrase) -> SessionHandle`
  - `vault_session_search(handle, query) -> FfiSearchResults`
  - `vault_session_lock(handle) -> ResultCode`
  - `vault_generator_generate(config) -> FfiStringResult`
- Translates Rust panics into structured error codes without causing host process crashes.
