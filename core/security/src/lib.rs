#![deny(unsafe_code)]
#![warn(missing_docs)]

//! # pwdvault-security
//! Production-grade security primitives:
//! - RFC 6238 Time-Based One-Time Password (TOTP) authenticator engine
//! - WebAuthn / FIDO2 Passkey credential generation, authenticator framing, and assertion signing
//! - Privacy-preserving k-Anonymity breach check range parser (HIBP protocol)
//! - Comprehensive local vault health & cryptographic hygiene auditor

/// Local vault health audit and privacy-preserving k-Anonymity breach check.
pub mod audit;
/// Security error types.
pub mod error;
/// RFC 2104 Keyed-Hashing for Message Authentication (HMAC).
pub mod hmac;
/// WebAuthn / FIDO2 Passkey credential generation and assertion signing.
pub mod passkey;
/// RFC 3174 SHA-1 digest implementation.
pub mod sha1;
/// RFC 6238 Time-Based One-Time Password (TOTP) authenticator engine.
pub mod totp;

pub use audit::{
    audit_vault, check_suffix_in_range_response, prepare_breach_query, BreachQuery,
    ReusedPasswordGroup, StalePasswordFinding, VaultAuditReport, WeakPasswordFinding,
};
pub use error::SecurityError;
pub use hmac::{hmac_sha1, hmac_sha256, hmac_sha512, verify_mac};
pub use passkey::{
    build_authenticator_data, generate_passkey, sign_assertion, verify_assertion,
    AssertionResponse, PasskeyCredential, COSE_ALG_EDDSA, COSE_ALG_ES256,
};
pub use sha1::Sha1;
pub use totp::{
    current_totp, decode_base32, encode_base32, format_otpauth_uri, generate_totp,
    parse_otpauth_uri, time_remaining, verify_totp, TotpAlgorithm, TotpConfig,
};
