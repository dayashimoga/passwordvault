#![deny(unsafe_code)]
#![warn(missing_docs)]

//! # pwdvault-import-export
//! High-fidelity import parsers for KeePass 2.x XML, Bitwarden JSON, 1Password (1PUX & CSV),
//! and RFC 4180 CSV, with intelligent deduplication analysis and conflict resolution.

pub mod bitwarden;
pub mod csv;
pub mod dedup;
pub mod keepass;
pub mod onepassword;

use thiserror::Error;

pub use bitwarden::BitwardenImporter;
pub use csv::{parse_rfc4180_csv, CsvExporter, CsvImporter};
pub use dedup::{
    CandidateStatus, ConflictDiff, DeduplicationEngine, ImportCandidate, ImportPreview,
    ResolutionStrategy,
};
pub use keepass::KeePassXmlImporter;
pub use onepassword::OnePasswordImporter;

/// Import and export error conditions.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum ImportError {
    /// Format parsing failure.
    #[error("Parse error: {0}")]
    ParseFailed(String),
    /// Schema validation failure.
    #[error("Validation error: {0}")]
    ValidationFailed(String),
}

/// Unified entrypoint for importing external credential archives.
pub struct ImportManager;

impl ImportManager {
    /// Auto-detects format from input content or extension and parses into `VaultItem`s.
    pub fn parse_auto(content: &str) -> Result<Vec<pwdvault_vault::VaultItem>, ImportError> {
        let trimmed = content.trim();

        if trimmed.starts_with("<KeePassFile>") || trimmed.contains("<Entry>") {
            KeePassXmlImporter::parse(content)
        } else if trimmed.starts_with('{') {
            if trimmed.contains("\"encrypted\"") || trimmed.contains("\"folders\"") {
                BitwardenImporter::parse(content)
            } else if trimmed.contains("\"accounts\"") || trimmed.contains("\"vaults\"") {
                OnePasswordImporter::parse_1pux_json(content)
            } else {
                // Fallback attempt Bitwarden then 1Password
                BitwardenImporter::parse(content)
                    .or_else(|_| OnePasswordImporter::parse_1pux_json(content))
            }
        } else {
            // Assume CSV format
            CsvImporter::parse(content)
        }
    }
}
