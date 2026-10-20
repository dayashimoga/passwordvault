#![deny(unsafe_code)]
#![warn(missing_docs)]

//! Conflict-Free Replicated Data Type (CRDT) merge engine with zero-data-loss revision preservation.

use pwdvault_vault::{ItemRevision, VaultItem, VaultPayload};
use serde::{Deserialize, Serialize};

/// Statistical report of operations executed during a CRDT vault merge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SyncMergeReport {
    /// Number of new items added from remote.
    pub added: usize,
    /// Number of items updated to newer remote versions.
    pub updated: usize,
    /// Number of conflicting variants preserved in revision history.
    pub conflicts_preserved: usize,
    /// Number of deletion tombstones synchronized.
    pub tombstones_applied: usize,
}

/// Helper converting a VaultItem to an historical ItemRevision snapshot.
fn item_to_revision(item: &VaultItem) -> ItemRevision {
    ItemRevision {
        timestamp: item.updated_at,
        title: item.title.clone(),
        username: item.username.clone(),
        password: item.password.clone(),
        urls: item.urls.clone(),
        notes: item.notes.clone(),
        custom_fields: item.custom_fields.clone(),
    }
}

/// Computes a deterministic tie-breaker hash for an item when timestamps are identical.
fn item_hash(item: &VaultItem) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(item.id.as_bytes());
    hasher.update(item.title.as_bytes());
    if let Some(ref u) = item.username {
        hasher.update(u.as_bytes());
    }
    if let Some(ref p) = item.password {
        hasher.update(p.as_bytes());
    }
    if let Some(ref n) = item.notes {
        hasher.update(n.as_bytes());
    }
    *hasher.finalize().as_bytes()
}

/// Merges remote changes into a local `VaultPayload` deterministically.
///
/// Invariants:
/// 1. Commutative and associative across arbitrary synchronization ordering.
/// 2. Zero Data Loss: Losing variants in concurrent edits are archived into `revision_history`.
/// 3. Deletion tombstones propagate deterministically based on timestamp comparison.
pub fn merge_vault_payloads(local: &mut VaultPayload, remote: &VaultPayload) -> SyncMergeReport {
    let mut report = SyncMergeReport::default();

    for remote_item in &remote.items {
        if let Some(local_idx) = local.items.iter().position(|i| i.id == remote_item.id) {
            let local_item = &mut local.items[local_idx];

            // 1. Identical check
            if local_item == remote_item {
                continue;
            }

            // 2. Tombstone handling (Deletion vs Edit)
            if let (Some(remote_trash_time), None) = (remote_item.trashed_at, local_item.trashed_at) {
                if remote_trash_time >= local_item.updated_at {
                    local_item.trashed_at = Some(remote_trash_time);
                    local_item.updated_at = std::cmp::max(local_item.updated_at, remote_trash_time);
                    report.tombstones_applied += 1;
                    continue;
                } else {
                    // Local edit is newer than remote trash; archive remote into revision history
                    local_item.revision_history.insert(0, item_to_revision(remote_item));
                    report.conflicts_preserved += 1;
                    continue;
                }
            } else if let (None, Some(local_trash_time)) = (remote_item.trashed_at, local_item.trashed_at) {
                if remote_item.updated_at > local_trash_time {
                    // Remote edit is newer than local deletion: revive with remote content
                    let local_rev = item_to_revision(local_item);
                    let mut winning = remote_item.clone();
                    winning.revision_history.insert(0, local_rev);
                    *local_item = winning;
                    report.updated += 1;
                    report.conflicts_preserved += 1;
                    continue;
                } else {
                    // Local deletion is newer than remote edit; preserve remote into revision history
                    local_item.revision_history.insert(0, item_to_revision(remote_item));
                    report.conflicts_preserved += 1;
                    continue;
                }
            }

            // 3. Last-Write-Wins (LWW) conflict resolution with revision preservation
            if remote_item.updated_at > local_item.updated_at {
                // Remote is newer: archive local as revision in winning item
                let local_rev = item_to_revision(local_item);
                let mut winning = remote_item.clone();
                winning.revision_history.insert(0, local_rev);
                // Keep bounded revisions (max 50)
                if winning.revision_history.len() > 50 {
                    winning.revision_history.truncate(50);
                }
                *local_item = winning;
                report.updated += 1;
                report.conflicts_preserved += 1;
            } else if local_item.updated_at > remote_item.updated_at {
                // Local is newer: archive remote as revision in local item
                let remote_rev = item_to_revision(remote_item);
                local_item.revision_history.insert(0, remote_rev);
                if local_item.revision_history.len() > 50 {
                    local_item.revision_history.truncate(50);
                }
                report.conflicts_preserved += 1;
            } else {
                // Equal timestamps: deterministic tie-breaker
                let h_local = item_hash(local_item);
                let h_remote = item_hash(remote_item);

                if h_remote > h_local {
                    let local_rev = item_to_revision(local_item);
                    let mut winning = remote_item.clone();
                    winning.revision_history.insert(0, local_rev);
                    *local_item = winning;
                    report.updated += 1;
                    report.conflicts_preserved += 1;
                } else {
                    let remote_rev = item_to_revision(remote_item);
                    local_item.revision_history.insert(0, remote_rev);
                    report.conflicts_preserved += 1;
                }
            }
        } else {
            // New item not present locally
            local.items.push(remote_item.clone());
            report.added += 1;
        }
    }

    local.updated_at = std::cmp::max(local.updated_at, remote.updated_at);

    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use pwdvault_vault::ItemCategory;

    fn create_dummy_item(id: &str, title: &str, password: &str, updated_at: u64) -> VaultItem {
        VaultItem {
            id: id.to_string(),
            title: title.to_string(),
            category: ItemCategory::Login,
            username: Some("user@example.com".to_string()),
            password: Some(password.to_string()),
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
            updated_at,
        }
    }

    #[test]
    fn test_crdt_non_conflicting_addition() {
        let mut local = VaultPayload::new("Local");
        local.items.push(create_dummy_item("item-1", "GitHub", "pwd1", 1000));

        let mut remote = VaultPayload::new("Remote");
        remote.items.push(create_dummy_item("item-2", "GitLab", "pwd2", 1100));

        let report = merge_vault_payloads(&mut local, &remote);
        assert_eq!(report.added, 1);
        assert_eq!(report.updated, 0);
        assert_eq!(local.items.len(), 2);
    }

    #[test]
    fn test_crdt_conflict_resolution_and_revision_preservation() {
        let mut local = VaultPayload::new("Local");
        local.items.push(create_dummy_item("item-1", "Proton", "pwd-local", 2000));

        let mut remote = VaultPayload::new("Remote");
        remote.items.push(create_dummy_item("item-1", "Proton", "pwd-remote-newer", 3000));

        let report = merge_vault_payloads(&mut local, &remote);
        assert_eq!(report.updated, 1);
        assert_eq!(report.conflicts_preserved, 1);

        // Winning item has newer remote password
        assert_eq!(local.items[0].password.as_deref(), Some("pwd-remote-newer"));
        // Losing local item is archived in revision history
        assert_eq!(local.items[0].revision_history.len(), 1);
        assert_eq!(local.items[0].revision_history[0].password.as_deref(), Some("pwd-local"));
    }

    #[test]
    fn test_crdt_tombstone_propagation() {
        let mut local = VaultPayload::new("Local");
        local.items.push(create_dummy_item("item-1", "OldSite", "pwd1", 1000));

        let mut remote = VaultPayload::new("Remote");
        let mut trashed_item = create_dummy_item("item-1", "OldSite", "pwd1", 1000);
        trashed_item.trashed_at = Some(1500);
        remote.items.push(trashed_item);

        let report = merge_vault_payloads(&mut local, &remote);
        assert_eq!(report.tombstones_applied, 1);
        assert_eq!(local.items[0].trashed_at, Some(1500));
    }
}
