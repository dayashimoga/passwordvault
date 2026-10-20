#![deny(unsafe_code)]

//! Fuzzing and hardening tests for pwdvault-sync.
//! Asserts crash resistance against corrupted syncpacks, malformed pairing URIs,
//! and verifies CRDT mathematical properties (idempotency, zero loss).

use proptest::prelude::*;
use pwdvault_sync::crdt::merge_vault_payloads;
use pwdvault_sync::pairing::verify_pairing_qr_data;
use pwdvault_sync::syncpack::read_syncpack;
use pwdvault_vault::{ItemCategory, VaultItem, VaultPayload};

proptest! {
    /// Invariant: arbitrary byte sequences must never panic read_syncpack.
    #[test]
    fn fuzz_syncpack_decryption(
        sync_key in proptest::collection::vec(any::<u8>(), 32),
        bytes in proptest::collection::vec(any::<u8>(), 0..1024)
    ) {
        let key_arr: [u8; 32] = sync_key.try_into().unwrap();
        let _ = read_syncpack(&bytes, &key_arr);
    }

    /// Invariant: arbitrary strings must never panic pairing QR URI verification.
    #[test]
    fn fuzz_pairing_uri_verification(
        sync_key in proptest::collection::vec(any::<u8>(), 32),
        uri in "\\PC{0,500}"
    ) {
        let key_arr: [u8; 32] = sync_key.try_into().unwrap();
        let _ = verify_pairing_qr_data(&uri, &key_arr);
    }

    /// Invariant: CRDT merge is idempotent. Merging a payload with itself produces zero conflicts or changes.
    #[test]
    fn prop_crdt_idempotency(
        title in "[a-zA-Z0-9 ]{1,30}",
        username in "[a-zA-Z0-9_]{1,20}"
    ) {
        let now = 1700000000u64;
        let item = VaultItem {
            id: "item-test".to_string(),
            title,
            category: ItemCategory::Login,
            username: Some(username),
            password: Some("pwd123".to_string()),
            urls: vec!["https://example.com".to_string()],
            notes: None,
            totp_seed: None,
            tags: vec![],
            favorite: false,
            custom_fields: vec![],
            attachments: vec![],
            revision_history: vec![],
            trashed_at: None,
            created_at: now,
            updated_at: now,
        };

        let mut local = VaultPayload::new("Test Vault");
        local.items.push(item);
        let remote = local.clone();

        let report = merge_vault_payloads(&mut local, &remote);
        prop_assert_eq!(report.conflicts_preserved, 0);
        prop_assert_eq!(report.added, 0);
        prop_assert_eq!(local.items.len(), remote.items.len());
    }
}
