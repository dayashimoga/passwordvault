#![deny(unsafe_code)]
#![warn(missing_docs)]

//! # pwdvault-crypto
//! Production-grade cryptographic primitives, key derivation (Argon2id),
//! authenticated encryption (XChaCha20-Poly1305), memory zeroization, and hashing.

/// XChaCha20-Poly1305 authenticated symmetric encryption and decryption.
pub mod aead;
/// Cryptographic error types.
pub mod error;
/// Cryptographic hashing and constant-time verification using BLAKE3.
pub mod hash;
/// Memory-hard key derivation using Argon2id with strict parameter bounding.
pub mod kdf;
/// Cryptographic key wrappers enforcing automatic zeroization on drop.
pub mod keys;

pub use aead::{decrypt_xchacha20, encrypt_xchacha20, generate_nonce, KEY_LEN, NONCE_LEN, TAG_LEN};
pub use error::CryptoError;
pub use hash::{hash_blake3, verify_blake3, HASH_LEN};
pub use kdf::{derive_kek, KdfParams, SALT_LEN};
pub use keys::{DataKey, KeyEncryptionKey};
