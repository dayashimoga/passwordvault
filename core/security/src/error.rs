#![deny(unsafe_code)]
#![warn(missing_docs)]

//! Error types for advanced personal security features (TOTP, Passkeys, Breach Audit).

use thiserror::Error;

/// Errors that can occur during security, authentication, or audit operations.
#[derive(Debug, Error)]
pub enum SecurityError {
    /// Invalid Base32 encoding in secret key.
    #[error("Invalid Base32 secret encoding: {0}")]
    InvalidBase32(String),

    /// Invalid or unsupported OTP URI.
    #[error("Invalid OTP URI format: {0}")]
    InvalidOtpUri(String),

    /// Missing or invalid parameter in TOTP configuration.
    #[error("Invalid TOTP configuration: {0}")]
    InvalidTotpConfig(String),

    /// Passkey generation or validation error.
    #[error("Passkey error: {0}")]
    PasskeyError(String),

    /// Relying party ID domain mismatch.
    #[error("RP ID mismatch: expected '{expected}', got '{actual}'")]
    RpIdMismatch {
        /// Expected RP ID.
        expected: String,
        /// Actual RP ID provided.
        actual: String,
    },

    /// Cryptographic signature verification failed.
    #[error("Signature verification failed: {0}")]
    SignatureVerificationFailed(String),

    /// Breach range query parsing error.
    #[error("Breach response parsing error: {0}")]
    BreachQueryError(String),

    /// Internal or serialization error.
    #[error("Internal security error: {0}")]
    InternalError(String),
}
