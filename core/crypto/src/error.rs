use thiserror::Error;

/// Cryptographic error types.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum CryptoError {
    /// Out-of-bounds or unsafe KDF configuration.
    #[error("KDF parameters out of safe bounds: {0}")]
    InvalidKdfParams(&'static str),

    /// Argon2id derivation computational failure.
    #[error("Argon2id key derivation failed: {0}")]
    KdfFailed(String),

    /// AEAD MAC tag or ciphertext mismatch.
    #[error("AEAD authenticated decryption failed: invalid ciphertext or MAC tag")]
    DecryptionFailed,

    /// AEAD cipher encryption error.
    #[error("AEAD encryption failed")]
    EncryptionFailed,

    /// Failure accessing OS cryptographically secure random number generator.
    #[error("OS CSPRNG entropy failure: {0}")]
    RngFailed(String),

    /// HKDF subkey expansion failure.
    #[error("HKDF key expansion failed")]
    KeyExpansionFailed,
}
