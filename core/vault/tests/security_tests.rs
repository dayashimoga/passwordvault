use pwdvault_crypto::{hash_blake3, KdfParams};
use pwdvault_vault::{ItemCategory, VaultContainer, VaultError, VaultItem, VaultPayload};

fn make_sample_vault(passphrase: &[u8]) -> (Vec<u8>, VaultPayload) {
    let kdf = KdfParams::test_profile().expect("Test profile");
    let mut payload = VaultPayload::new("Security Test Vault");
    payload.items.push(VaultItem {
        id: "test-uuid-1".into(),
        title: "Test Secret Account".into(),
        category: ItemCategory::Login,
        username: Some("alice".into()),
        password: Some("super-secret-password-123!".into()),
        urls: vec!["https://example.com/login".into()],
        notes: Some("Confidential note content".into()),
        totp_seed: None,
        tags: vec!["test".into(), "security".into()],
        favorite: true,
        custom_fields: Vec::new(),
        attachments: Vec::new(),
        revision_history: Vec::new(),
        trashed_at: None,
        created_at: 1700000000,
        updated_at: 1700000000,
    });

    let raw = VaultContainer::create(passphrase, kdf, &payload).expect("Create vault");
    (raw, payload)
}

#[test]
fn test_wrong_passphrase_variations_always_rejected() {
    let passphrase = b"Correct-Horse-Battery-Staple-99";
    let (raw, _) = make_sample_vault(passphrase);

    let wrong_attempts: &[&[u8]] = &[
        b"",
        b"correct-horse-battery-staple-99",  // different case
        b"Correct-Horse-Battery-Staple-9",   // 1 missing char
        b"Correct-Horse-Battery-Staple-999", // 1 extra char
        b"wrong-password",
        b"Correct-Horse-Battery-Staple-98", // 1 flipped digit
        &[0u8; 32],
    ];

    for &wrong in wrong_attempts {
        let res = VaultContainer::unlock(&raw, wrong);
        assert!(
            res.is_err(),
            "Unlock should fail with wrong passphrase: {:?}",
            String::from_utf8_lossy(wrong)
        );
        match res.unwrap_err() {
            VaultError::AuthenticationFailed | VaultError::Crypto(_) => {}
            other => panic!("Unexpected error variant: {:?}", other),
        }
    }
}

#[test]
fn test_truncation_sweep_never_panics_and_fails_safely() {
    let passphrase = b"truncation-test-passphrase";
    let (raw, _) = make_sample_vault(passphrase);

    // Truncate at every single byte index from 0 up to len - 1
    for cutoff in 0..raw.len() {
        let truncated = &raw[..cutoff];
        let res = VaultContainer::unlock(truncated, passphrase);
        assert!(
            res.is_err(),
            "Truncated vault of length {} should fail unlock",
            cutoff
        );
    }
}

#[test]
fn test_bit_flip_corruption_sweep() {
    let passphrase = b"bit-flip-sweep-passphrase";
    let (raw, _) = make_sample_vault(passphrase);

    // Systematically flip bits across byte offsets in the file
    let total_len = raw.len();
    let sample_indices: Vec<usize> = (0..total_len)
        .filter(|&i| i < 64 || i >= total_len - 64 || i % 7 == 0)
        .collect();

    for idx in sample_indices {
        for bit in [0x01u8, 0x08u8, 0x80u8] {
            let mut corrupted = raw.clone();
            corrupted[idx] ^= bit;

            let res = VaultContainer::unlock(&corrupted, passphrase);
            assert!(
                res.is_err(),
                "Vault with flipped bit {:02x} at byte {} MUST fail unlock",
                bit,
                idx
            );

            // Verify error is a safe expected error (tampered/invalid)
            match res.err().unwrap() {
                VaultError::InvalidMagic
                | VaultError::UnsupportedVersion(_)
                | VaultError::TruncatedData
                | VaultError::IntegrityCheckFailed
                | VaultError::SerializationError(_)
                | VaultError::AuthenticationFailed
                | VaultError::Crypto(_) => {}
            }
        }
    }
}

#[test]
fn test_header_magic_tampering() {
    let passphrase = b"magic-tamper-passphrase";
    let (mut raw, _) = make_sample_vault(passphrase);

    // 1. Raw byte tampering is first caught by BLAKE3 integrity verification
    raw[0] = b'X';
    let res = VaultContainer::unlock(&raw, passphrase);
    assert_eq!(res, Err(VaultError::IntegrityCheckFailed));

    // 2. If an attacker recomputes the trailing BLAKE3 checksum, Header validation catches InvalidMagic
    let data_len = raw.len() - 32;
    let new_checksum = hash_blake3(&raw[..data_len]);
    raw[data_len..].copy_from_slice(&new_checksum);

    let res = VaultContainer::unlock(&raw, passphrase);
    assert_eq!(res, Err(VaultError::InvalidMagic));
}
