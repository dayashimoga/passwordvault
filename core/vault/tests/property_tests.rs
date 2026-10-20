use proptest::prelude::*;
use pwdvault_crypto::KdfParams;
use pwdvault_vault::{
    CustomField, FieldType, ItemCategory, VaultContainer, VaultItem, VaultPayload,
};

fn arb_category() -> impl Strategy<Value = ItemCategory> {
    prop_oneof![
        Just(ItemCategory::Login),
        Just(ItemCategory::SecureNote),
        Just(ItemCategory::PaymentCard),
        Just(ItemCategory::Identity),
        Just(ItemCategory::RecoveryCode),
    ]
}

fn arb_custom_field() -> impl Strategy<Value = CustomField> {
    (
        "[a-zA-Z0-9_]{1,16}",
        "[a-zA-Z0-9_ ]{0,32}",
        prop_oneof![
            Just(FieldType::Text),
            Just(FieldType::Concealed),
            Just(FieldType::Boolean),
            Just(FieldType::Date),
        ],
    )
        .prop_map(|(name, value, field_type)| CustomField {
            name,
            value,
            field_type,
        })
}

fn arb_item() -> impl Strategy<Value = VaultItem> {
    (
        "[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}",
        "[a-zA-Z0-9 _-]{1,32}",
        arb_category(),
        prop::option::of("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,4}"),
        prop::option::of("[a-zA-Z0-9!@#$%^&*()_+]{8,32}"),
        prop::collection::vec("https://[a-z0-9.-]+\\.[a-z]{2,4}", 0..=3),
        prop::option::of("[a-zA-Z0-9 .,!?\n]{0,128}"),
        prop::collection::vec("[a-z0-9-]{1,16}", 0..=4),
        any::<bool>(),
        prop::collection::vec(arb_custom_field(), 0..=3),
    )
        .prop_map(
            |(
                id,
                title,
                category,
                username,
                password,
                urls,
                notes,
                tags,
                favorite,
                custom_fields,
            )| {
                VaultItem {
                    id,
                    title,
                    category,
                    username,
                    password,
                    urls,
                    notes,
                    totp_seed: None,
                    tags,
                    favorite,
                    custom_fields,
                    attachments: Vec::new(),
                    revision_history: Vec::new(),
                    trashed_at: None,
                    created_at: 1700000000,
                    updated_at: 1700000000,
                }
            },
        )
}

fn arb_payload() -> impl Strategy<Value = VaultPayload> {
    (
        "[a-zA-Z0-9 ]{3,24}",
        prop::collection::vec(arb_item(), 0..=8),
    )
        .prop_map(|(name, items)| {
            let mut p = VaultPayload::new(name);
            p.items = items;
            p
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(20))]

    #[test]
    fn prop_vault_encryption_roundtrip(
        payload in arb_payload(),
        passphrase in "[a-zA-Z0-9!@#$%^&*()_+ -]{8,32}"
    ) {
        let kdf = KdfParams::test_profile().expect("Test profile");
        let raw = VaultContainer::create(passphrase.as_bytes(), kdf, &payload)
            .expect("Creation must succeed");

        let (header, _dek, decrypted) = VaultContainer::unlock(&raw, passphrase.as_bytes())
            .expect("Unlock must succeed");

        prop_assert_eq!(header.version, 1);
        prop_assert_eq!(decrypted, payload);

        // Incorrect password must fail
        let bad_passphrase = format!("{}_wrong", passphrase);
        let err = VaultContainer::unlock(&raw, bad_passphrase.as_bytes());
        prop_assert!(err.is_err());
    }

    #[test]
    fn prop_trash_lifecycle_invariants(
        mut payload in arb_payload(),
    ) {
        let initial_count = payload.items.len();
        if let Some(first_id) = payload.items.first().map(|i| i.id.clone()) {
            // Trash item
            prop_assert!(payload.trash_item(&first_id, 1700000100));
            prop_assert!(payload.get_active_item(&first_id).is_none());
            prop_assert!(payload.get_item(&first_id).is_some());

            // Restore item
            prop_assert!(payload.restore_item(&first_id, 1700000200));
            prop_assert!(payload.get_active_item(&first_id).is_some());

            // Trash again and empty
            payload.trash_item(&first_id, 1700000300);
            let emptied = payload.empty_trash();
            prop_assert_eq!(emptied, 1);
            prop_assert_eq!(payload.items.len(), initial_count - 1);
        }
    }
}
