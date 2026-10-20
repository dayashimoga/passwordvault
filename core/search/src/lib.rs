#![deny(unsafe_code)]
#![warn(missing_docs)]

//! # pwdvault-search
//! In-memory trigram and token index for fast sub-50ms fuzzy vault search.
//!
//! Features:
//! - Sub-millisecond search evaluation via inverted token and trigram posting lists.
//! - Domain extraction from stored URLs for seamless autofill and domain matching.
//! - Multi-faceted filtering by category, tag, and favorite status.
//! - Secrets (passwords, notes, keys) are strictly excluded from index memory.

/// In-memory inverted and trigram search index implementation.
pub mod index;
/// Search query parameters and result models.
pub mod query;

pub use index::SearchIndex;
pub use query::{SearchQuery, SearchResult};
