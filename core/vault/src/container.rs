use crate::envelope::{KeyEnvelope, ENVELOPE_LEN};
use crate::error::VaultError;
use crate::header::{VaultHeader, HEADER_LEN};
use crate::payload::VaultPayload;
use pwdvault_crypto::{
    decrypt_xchacha20, derive_kek, encrypt_xchacha20, generate_nonce, hash_blake3, verify_blake3,
    DataKey, KeyEncryptionKey, HASH_LEN, NONCE_LEN,
};

/// Minimum total byte length of an encrypted vault container.
pub const MIN_CONTAINER_LEN: usize = HEADER_LEN + ENVELOPE_LEN + NONCE_LEN + 16 + HASH_LEN;

/// Vault container handling encrypted serialization, unlock, and tamper detection.
pub struct VaultContainer;

impl VaultContainer {
    /// Creates and encrypts a new vault container into raw bytes.
    pub fn create(
        passphrase: &[u8],
        kdf_params: pwdvault_crypto::KdfParams,
        payload: &VaultPayload,
    ) -> Result<Vec<u8>, VaultError> {
        // 1. Generate Header
        let header = VaultHeader::new(kdf_params);
        let header_bytes = header.to_bytes();

        // 2. Generate random Data Encryption Key (DEK)
        let dek = DataKey::generate().map_err(VaultError::Crypto)?;

        // 3. Derive Master KEK via Argon2id
        let kek_bytes = derive_kek(passphrase, &header.kdf_params).map_err(VaultError::Crypto)?;
        let master_kek = KeyEncryptionKey::from_bytes(*kek_bytes);

        // 4. Wrap DEK in MasterKeyEnvelope using header_bytes as Associated Data
        let envelope = KeyEnvelope::wrap(&dek, &master_kek, &header_bytes)?;
        let envelope_bytes = envelope.to_bytes();

        // 5. Serialize payload to bytes
        let payload_json = serde_json::to_vec(payload)
            .map_err(|e| VaultError::SerializationError(e.to_string()))?;

        // 6. Derive payload encryption key from DEK
        let payload_key = dek
            .derive_subkey(b"vault:payload:v1")
            .map_err(VaultError::Crypto)?;

        // 7. Encrypt payload with XChaCha20-Poly1305
        let payload_nonce = generate_nonce().map_err(VaultError::Crypto)?;

        // Authenticate Header + Envelope + Nonce in AAD
        let mut aad = Vec::with_capacity(HEADER_LEN + ENVELOPE_LEN + NONCE_LEN);
        aad.extend_from_slice(&header_bytes);
        aad.extend_from_slice(&envelope_bytes);
        aad.extend_from_slice(&payload_nonce);

        let ciphertext =
            encrypt_xchacha20(payload_key.as_bytes(), &payload_nonce, &payload_json, &aad)
                .map_err(VaultError::Crypto)?;

        // 8. Assemble full container: Header + Envelope + Nonce + Ciphertext
        let mut container = Vec::with_capacity(aad.len() + ciphertext.len() + HASH_LEN);
        container.extend_from_slice(&header_bytes);
        container.extend_from_slice(&envelope_bytes);
        container.extend_from_slice(&payload_nonce);
        container.extend_from_slice(&ciphertext);

        // 9. Compute BLAKE3 checksum commitment over all bytes and append
        let checksum = hash_blake3(&container);
        container.extend_from_slice(&checksum);

        Ok(container)
    }

    /// Unlocks and verifies an encrypted vault container.
    pub fn unlock(
        bytes: &[u8],
        passphrase: &[u8],
    ) -> Result<(VaultHeader, DataKey, VaultPayload), VaultError> {
        if bytes.len() < MIN_CONTAINER_LEN {
            return Err(VaultError::TruncatedData);
        }

        // 1. Verify BLAKE3 Checksum Commitment
        let payload_and_headers_len = bytes.len() - HASH_LEN;
        let data_portion = &bytes[..payload_and_headers_len];
        let mut expected_checksum = [0u8; HASH_LEN];
        expected_checksum.copy_from_slice(&bytes[payload_and_headers_len..]);

        if !verify_blake3(data_portion, &expected_checksum) {
            return Err(VaultError::IntegrityCheckFailed);
        }

        // 2. Parse & validate Header
        let header_bytes = &bytes[0..HEADER_LEN];
        let header = VaultHeader::from_bytes(header_bytes)?;

        // 3. Parse Master Key Envelope
        let envelope_bytes = &bytes[HEADER_LEN..HEADER_LEN + ENVELOPE_LEN];
        let envelope = KeyEnvelope::from_bytes(envelope_bytes)?;

        // 4. Derive KEK via Argon2id
        let kek_bytes = derive_kek(passphrase, &header.kdf_params).map_err(VaultError::Crypto)?;
        let master_kek = KeyEncryptionKey::from_bytes(*kek_bytes);

        // 5. Unwrap DEK using header as AAD
        let dek = envelope.unwrap(&master_kek, header_bytes)?;

        // 6. Extract Payload Nonce and Ciphertext
        let nonce_start = HEADER_LEN + ENVELOPE_LEN;
        let nonce_end = nonce_start + NONCE_LEN;
        let mut payload_nonce = [0u8; NONCE_LEN];
        payload_nonce.copy_from_slice(&bytes[nonce_start..nonce_end]);

        let ciphertext = &bytes[nonce_end..payload_and_headers_len];

        // 7. Derive payload key and decrypt
        let payload_key = dek
            .derive_subkey(b"vault:payload:v1")
            .map_err(VaultError::Crypto)?;

        let mut aad = Vec::with_capacity(HEADER_LEN + ENVELOPE_LEN + NONCE_LEN);
        aad.extend_from_slice(header_bytes);
        aad.extend_from_slice(envelope_bytes);
        aad.extend_from_slice(&payload_nonce);

        let decrypted_bytes =
            decrypt_xchacha20(payload_key.as_bytes(), &payload_nonce, ciphertext, &aad)
                .map_err(|_| VaultError::AuthenticationFailed)?;

        // 8. Deserialize payload
        let payload: VaultPayload = serde_json::from_slice(&decrypted_bytes)
            .map_err(|e| VaultError::SerializationError(e.to_string()))?;

        Ok((header, dek, payload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload::{ItemCategory, VaultItem};
    use pwdvault_crypto::KdfParams;

    fn create_sample_payload() -> VaultPayload {
        let mut p = VaultPayload::new("Personal Vault");
        p.items.push(VaultItem {
            id: "item-uuid-1".into(),
            title: "ProtonMail".into(),
            category: ItemCategory::Login,
            username: Some("user@proton.me".into()),
            password: Some("correct-horse-battery-staple".into()),
            urls: vec!["https://mail.proton.me".into()],
            notes: Some("Primary email".into()),
            totp_seed: None,
            tags: vec!["email".into(), "privacy".into()],
            favorite: true,
            custom_fields: Vec::new(),
            attachments: Vec::new(),
            revision_history: Vec::new(),
            trashed_at: None,
            created_at: 1000,
            updated_at: 1000,
        });
        p
    }

    #[test]
    fn test_vault_create_and_unlock_roundtrip() {
        let sample = create_sample_payload();
        let kdf = KdfParams::test_profile().unwrap();
        let passphrase = b"strong-test-master-passphrase";

        let raw_vault = VaultContainer::create(passphrase, kdf, &sample).unwrap();
        assert!(raw_vault.len() > MIN_CONTAINER_LEN);

        let (header, _dek, payload) = VaultContainer::unlock(&raw_vault, passphrase).unwrap();
        assert_eq!(payload.vault_name, "Personal Vault");
        assert_eq!(payload.items.len(), 1);
        assert_eq!(payload.items[0].title, "ProtonMail");
        assert_eq!(
            payload.items[0].password.as_deref(),
            Some("correct-horse-battery-staple")
        );
        assert_eq!(header.version, 1);
    }

    #[test]
    fn test_vault_wrong_passphrase_fails() {
        let sample = create_sample_payload();
        let kdf = KdfParams::test_profile().unwrap();
        let raw_vault = VaultContainer::create(b"correct-passphrase", kdf, &sample).unwrap();

        let result = VaultContainer::unlock(&raw_vault, b"wrong-passphrase");
        assert_eq!(result.err(), Some(VaultError::AuthenticationFailed));
    }

    #[test]
    fn test_vault_tamper_detection() {
        let sample = create_sample_payload();
        let kdf = KdfParams::test_profile().unwrap();
        let mut raw_vault = VaultContainer::create(b"test-passphrase", kdf, &sample).unwrap();

        // 1. Bit flip in ciphertext (middle byte)
        let mid = raw_vault.len() / 2;
        raw_vault[mid] ^= 0x01;
        assert_eq!(
            VaultContainer::unlock(&raw_vault, b"test-passphrase").err(),
            Some(VaultError::IntegrityCheckFailed)
        );
        raw_vault[mid] ^= 0x01; // Restore

        // 2. Bit flip in magic header byte
        raw_vault[0] ^= 0x01;
        assert_eq!(
            VaultContainer::unlock(&raw_vault, b"test-passphrase").err(),
            Some(VaultError::IntegrityCheckFailed)
        );
        raw_vault[0] ^= 0x01; // Restore

        // 3. Truncation test
        let truncated = &raw_vault[0..raw_vault.len() - 10];
        assert_eq!(
            VaultContainer::unlock(truncated, b"test-passphrase").err(),
            Some(VaultError::IntegrityCheckFailed)
        );
    }
}
