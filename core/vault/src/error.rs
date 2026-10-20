use pwdvault_crypto::CryptoError;
use thiserror::Error;

/// Vault domain error conditions.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum VaultError {
    /// Low-level cryptographic operation failed.
    #[error("Cryptographic operation failed: {0}")]
    Crypto(#[from] CryptoError),

    /// File header magic bytes do not match expected "VAULT".
    #[error("Invalid vault file: invalid magic header bytes")]
    InvalidMagic,

    /// Container format version is not supported by this engine.
    #[error("Unsupported vault format version: {0}")]
    UnsupportedVersion(u16),

    /// Incomplete or truncated data file.
    #[error("Vault file is truncated or contains incomplete data")]
    TruncatedData,

    /// BLAKE3 checksum or authenticated tag commitment verification failed.
    #[error("Vault integrity commitment failed: file has been tampered with or corrupted")]
    IntegrityCheckFailed,

    /// Error during JSON/CBOR serialization or deserialization.
    #[error("Payload serialization / deserialization error: {0}")]
    SerializationError(String),

    /// Authentication failure caused by wrong passphrase, recovery key, or tampered envelope.
    #[error("Authentication failed: wrong passphrase or recovery key")]
    AuthenticationFailed,
}
