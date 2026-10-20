#![deny(unsafe_code)]
#![warn(missing_docs)]

//! # pwdvault-backup
//! Authenticated encrypted backups (`.vaultbak`), offline emergency recovery kits,
//! and non-destructive dry-run restore rehearsal.

pub mod archive;
pub mod recovery_kit;

use thiserror::Error;

pub use archive::{
    BackupArchive, BackupCredential, BackupHeader, BackupRehearsalReport, BACKUP_HEADER_SIZE,
    BACKUP_MAGIC,
};
pub use recovery_kit::{RecoveryKey, RecoveryKitDocument};

/// Backup and restore error conditions.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum BackupError {
    /// Failure generating backup archive.
    #[error("Backup creation failed: {0}")]
    CreateFailed(String),
    /// Failure verifying backup integrity or rehearsal checks.
    #[error("Backup verification failed: {0}")]
    VerifyFailed(String),
}
