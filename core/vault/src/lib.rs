#![deny(unsafe_code)]
#![warn(missing_docs)]

//! # pwdvault-vault
//! Vault container format, domain models, cryptographic envelopes,
//! atomic persistence, and integrity commitments.

/// Encrypted vault container persistence and unlock logic.
pub mod container;
/// Key-encryption envelopes wrapping the DataKey.
pub mod envelope;
/// Vault domain error types.
pub mod error;
/// Authenticated binary vault headers.
pub mod header;
/// In-memory domain models, revisions, attachments, and trash.
pub mod payload;
/// Active vault session and key lifecycle management.
pub mod session;
/// ACID atomic filesystem persistence and backup retention.
pub mod storage;

pub use container::VaultContainer;
pub use envelope::KeyEnvelope;
pub use error::VaultError;
pub use header::VaultHeader;
pub use payload::{
    AttachmentMeta, CustomField, FieldType, ItemCategory, ItemRevision, VaultItem, VaultPayload,
};
pub use session::VaultSession;
pub use storage::VaultStorage;
