#![deny(unsafe_code)]
#![warn(missing_docs)]

//! Deduplication engine and interactive conflict resolution preview.

use pwdvault_vault::VaultItem;
use serde::{Deserialize, Serialize};

/// Classification of an incoming item compared to the current vault state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CandidateStatus {
    /// Completely novel item with no title or account conflict.
    New,
    /// Identical title, username, and password matching an existing item.
    ExactDuplicate,
    /// Matching title and username, but password, URLs, or notes differ.
    Conflict,
}

/// Strategy for resolving an item during import execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResolutionStrategy {
    /// Discard incoming item; keep existing intact.
    Skip,
    /// Overwrite existing item with incoming data, snapshotting old state into revision history.
    Overwrite,
    /// Import incoming item as a separate new entry with a disambiguated title suffix.
    KeepBoth,
}

/// Item diff inspection for conflicts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictDiff {
    /// Current password in vault.
    pub current_password: Option<String>,
    /// Incoming password from import.
    pub incoming_password: Option<String>,
    /// Current notes in vault.
    pub current_notes: Option<String>,
    /// Incoming notes from import.
    pub incoming_notes: Option<String>,
}

/// Single item candidate analyzed for import.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportCandidate {
    /// Candidate index in incoming array.
    pub index: usize,
    /// Status classification.
    pub status: CandidateStatus,
    /// Incoming imported item.
    pub item: VaultItem,
    /// ID of conflicting existing item in vault, if any.
    pub existing_item_id: Option<String>,
    /// Title of conflicting existing item in vault, if any.
    pub existing_item_title: Option<String>,
    /// Detailed diff if status is `Conflict`.
    pub diff: Option<ConflictDiff>,
    /// Default or user-selected resolution action.
    pub selected_strategy: ResolutionStrategy,
}

/// Comprehensive summary of analyzed import file before committing to vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportPreview {
    /// Total items found in import file.
    pub total_incoming: usize,
    /// Number of completely new items.
    pub new_count: usize,
    /// Number of exact duplicate items.
    pub duplicate_count: usize,
    /// Number of conflicting items.
    pub conflict_count: usize,
    /// All candidates with their status and proposed actions.
    pub candidates: Vec<ImportCandidate>,
}

/// Deduplication engine.
pub struct DeduplicationEngine;

impl DeduplicationEngine {
    /// Analyzes incoming items against current vault items to produce an `ImportPreview`.
    pub fn analyze(current_items: &[VaultItem], incoming_items: &[VaultItem]) -> ImportPreview {
        let mut candidates = Vec::with_capacity(incoming_items.len());
        let mut new_count = 0;
        let mut duplicate_count = 0;
        let mut conflict_count = 0;

        for (idx, incoming) in incoming_items.iter().enumerate() {
            let inc_title_norm = incoming.title.trim().to_lowercase();
            let inc_user_norm = incoming
                .username
                .as_deref()
                .map(|u| u.trim().to_lowercase());

            // Check against active (non-trashed) existing items
            let existing_match = current_items.iter().find(|existing| {
                if existing.trashed_at.is_some() {
                    return false;
                }

                let ex_title_norm = existing.title.trim().to_lowercase();
                let ex_user_norm = existing
                    .username
                    .as_deref()
                    .map(|u| u.trim().to_lowercase());

                // Match if title is identical
                if ex_title_norm == inc_title_norm {
                    return true;
                }

                // Match if username and URL match
                if let (Some(u1), Some(u2)) = (&ex_user_norm, &inc_user_norm) {
                    if u1 == u2 && !u1.is_empty() {
                        let ex_url = existing.urls.first().map(|s| s.as_str()).unwrap_or("");
                        let inc_url = incoming.urls.first().map(|s| s.as_str()).unwrap_or("");
                        if !ex_url.is_empty() && ex_url == inc_url {
                            return true;
                        }
                    }
                }

                false
            });

            match existing_match {
                None => {
                    new_count += 1;
                    candidates.push(ImportCandidate {
                        index: idx,
                        status: CandidateStatus::New,
                        item: incoming.clone(),
                        existing_item_id: None,
                        existing_item_title: None,
                        diff: None,
                        selected_strategy: ResolutionStrategy::KeepBoth,
                    });
                }
                Some(existing) => {
                    let is_exact = existing.title.trim() == incoming.title.trim()
                        && existing.username == incoming.username
                        && existing.password == incoming.password;

                    if is_exact {
                        duplicate_count += 1;
                        candidates.push(ImportCandidate {
                            index: idx,
                            status: CandidateStatus::ExactDuplicate,
                            item: incoming.clone(),
                            existing_item_id: Some(existing.id.clone()),
                            existing_item_title: Some(existing.title.clone()),
                            diff: None,
                            selected_strategy: ResolutionStrategy::Skip, // Default skip exact duplicates
                        });
                    } else {
                        conflict_count += 1;
                        let diff = ConflictDiff {
                            current_password: existing.password.clone(),
                            incoming_password: incoming.password.clone(),
                            current_notes: existing.notes.clone(),
                            incoming_notes: incoming.notes.clone(),
                        };

                        candidates.push(ImportCandidate {
                            index: idx,
                            status: CandidateStatus::Conflict,
                            item: incoming.clone(),
                            existing_item_id: Some(existing.id.clone()),
                            existing_item_title: Some(existing.title.clone()),
                            diff: Some(diff),
                            selected_strategy: ResolutionStrategy::KeepBoth, // Safe default
                        });
                    }
                }
            }
        }

        ImportPreview {
            total_incoming: incoming_items.len(),
            new_count,
            duplicate_count,
            conflict_count,
            candidates,
        }
    }

    /// Applies the resolution strategies from `candidates` to `current_items`.
    pub fn apply(current_items: &mut Vec<VaultItem>, candidates: &[ImportCandidate]) -> usize {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut imported_count = 0;

        for candidate in candidates {
            match candidate.selected_strategy {
                ResolutionStrategy::Skip => {
                    // Do nothing
                }
                ResolutionStrategy::Overwrite => {
                    if let Some(target_id) = &candidate.existing_item_id {
                        if let Some(pos) = current_items.iter().position(|i| &i.id == target_id) {
                            let mut updated = candidate.item.clone();
                            updated.id = target_id.clone();
                            updated.updated_at = now;

                            // Archive existing state into revision history
                            let previous = &current_items[pos];
                            let revision = previous.create_revision(previous.updated_at);
                            updated.revision_history = previous.revision_history.clone();
                            updated.revision_history.push(revision);

                            current_items[pos] = updated;
                            imported_count += 1;
                        } else {
                            // Target not found, insert as new
                            current_items.push(candidate.item.clone());
                            imported_count += 1;
                        }
                    } else {
                        current_items.push(candidate.item.clone());
                        imported_count += 1;
                    }
                }
                ResolutionStrategy::KeepBoth => {
                    let mut new_item = candidate.item.clone();
                    if candidate.status == CandidateStatus::Conflict
                        || candidate.status == CandidateStatus::ExactDuplicate
                    {
                        new_item.title = format!("{} (Imported)", new_item.title);
                    }
                    current_items.push(new_item);
                    imported_count += 1;
                }
            }
        }

        imported_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pwdvault_vault::ItemCategory;

    fn make_item(id: &str, title: &str, user: &str, pass: &str) -> VaultItem {
        VaultItem {
            id: id.to_string(),
            title: title.to_string(),
            category: ItemCategory::Login,
            username: Some(user.to_string()),
            password: Some(pass.to_string()),
            urls: vec!["https://example.com".to_string()],
            notes: None,
            totp_seed: None,
            tags: vec![],
            favorite: false,
            custom_fields: vec![],
            attachments: vec![],
            revision_history: vec![],
            trashed_at: None,
            created_at: 1000,
            updated_at: 1000,
        }
    }

    #[test]
    fn test_deduplication_analysis_and_apply() {
        let mut current = vec![
            make_item("1", "GitHub", "alice", "old-pass"),
            make_item("2", "Google", "alice@gmail.com", "google-pass"),
        ];

        let incoming = vec![
            make_item("in-1", "Google", "alice@gmail.com", "google-pass"), // Exact Duplicate
            make_item("in-2", "GitHub", "alice", "new-github-pass"), // Conflict (different pass)
            make_item("in-3", "Twitter", "alice_tw", "tw-secret"),   // New
        ];

        let preview = DeduplicationEngine::analyze(&current, &incoming);
        assert_eq!(preview.total_incoming, 3);
        assert_eq!(preview.duplicate_count, 1);
        assert_eq!(preview.conflict_count, 1);
        assert_eq!(preview.new_count, 1);

        // Verify conflict diff
        let conflict_cand = preview
            .candidates
            .iter()
            .find(|c| c.status == CandidateStatus::Conflict)
            .unwrap();
        assert_eq!(
            conflict_cand
                .diff
                .as_ref()
                .unwrap()
                .current_password
                .as_deref(),
            Some("old-pass")
        );
        assert_eq!(
            conflict_cand
                .diff
                .as_ref()
                .unwrap()
                .incoming_password
                .as_deref(),
            Some("new-github-pass")
        );

        // Test Apply with custom strategy: Overwrite conflict, Skip duplicate, KeepBoth new
        let mut to_apply = preview.candidates.clone();
        for cand in &mut to_apply {
            if cand.status == CandidateStatus::Conflict {
                cand.selected_strategy = ResolutionStrategy::Overwrite;
            }
        }

        let applied = DeduplicationEngine::apply(&mut current, &to_apply);
        assert_eq!(applied, 2); // 1 overwrite + 1 new (duplicate skipped)

        assert_eq!(current.len(), 3);
        let github = current.iter().find(|i| i.title == "GitHub").unwrap();
        assert_eq!(github.password.as_deref(), Some("new-github-pass"));
        // Revision history should have preserved old password
        assert_eq!(github.revision_history.len(), 1);
        assert_eq!(
            github.revision_history[0].password.as_deref(),
            Some("old-pass")
        );
    }
}
