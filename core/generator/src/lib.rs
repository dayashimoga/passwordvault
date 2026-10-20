#![deny(unsafe_code)]
#![warn(missing_docs)]

//! # pwdvault-generator
//! Cryptographically secure personal password and passphrase generator.
//!
//! Features:
//! - Unbiased CSPRNG selection eliminating modulo bias.
//! - Password generation with character classes and ambiguous character filtering.
//! - EFF Long Wordlist passphrase generation with configurable separators and styling.
//! - Shannon entropy scoring and offline GPU crack-time estimations.
//! - Ephemeral zeroized generation history buffer.

/// Shannon entropy and crack-time models.
pub mod entropy;
/// Generator error types.
pub mod error;
/// Ephemeral in-memory generation history.
pub mod history;
/// Wordlist passphrase generator.
pub mod passphrase;
/// Random password generator.
pub mod password;
/// CSPRNG random selection algorithms.
pub mod random;
/// Embedded EFF wordlist.
pub mod wordlist;

pub use entropy::{calculate_entropy, estimate_crack_time, CrackTimeEstimate, StrengthRating};
pub use error::GeneratorError;
pub use history::{EphemeralGenerationHistory, GenerationHistoryEntry};
pub use passphrase::{generate_passphrase, Capitalization, PassphraseOptions};
pub use password::{generate_password, PasswordOptions};
pub use random::{random_index, shuffle};
