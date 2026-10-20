#![deny(unsafe_code)]
#![warn(missing_docs)]

//! Encrypted backup container (`.vaultbak`) and dry-run rehearsal verification.

use std::collections::HashMap;

use blake3::Hasher;
use pwdvault_crypto::aead::{decrypt_xchacha20, encrypt_xchacha20, generate_nonce};
use pwdvault_crypto::kdf::{derive_kek, KdfParams};
use pwdvault_crypto::keys::{DataKey, KeyEncryptionKey};
use pwdvault_vault::envelope::{KeyEnvelope, ENVELOPE_LEN};
use pwdvault_vault::VaultPayload;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::recovery_kit::RecoveryKey;
use crate::BackupError;

/// Binary magic signature for PwdVault Encrypted Backup archives.
pub const BACKUP_MAGIC: &[u8; 8] = b"PVBAK001";
/// Length of backup header in bytes (92 bytes).
pub const BACKUP_HEADER_SIZE: usize = 92;

/// Authentication header embedded at the beginning of every `.vaultbak` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupHeader {
    /// Schema version (currently 1).
    pub version: u32,
    /// Unix timestamp of backup creation in seconds.
    pub created_at: u64,
    /// Number of items contained in the backup snapshot.
    pub item_count: u32,
    /// Salt for Argon2id KDF (32 bytes).
    pub salt: [u8; 32],
    /// Memory cost in KiB for KDF.
    pub kdf_mem_kib: u32,
    /// Iterations for KDF.
    pub kdf_iterations: u32,
    /// Parallelism threads for KDF.
    pub kdf_parallelism: u32,
    /// AEAD nonce for payload encryption (24 bytes).
    pub payload_nonce: [u8; 24],
}

impl BackupHeader {
    /// Serializes the header into raw binary bytes.
    pub fn to_bytes(&self) -> [u8; BACKUP_HEADER_SIZE] {
        let mut buf = [0u8; BACKUP_HEADER_SIZE];
        buf[0..8].copy_from_slice(BACKUP_MAGIC);
        buf[8..12].copy_from_slice(&self.version.to_le_bytes());
        buf[12..20].copy_from_slice(&self.created_at.to_le_bytes());
        buf[20..24].copy_from_slice(&self.item_count.to_le_bytes());
        buf[24..56].copy_from_slice(&self.salt);
        buf[56..60].copy_from_slice(&self.kdf_mem_kib.to_le_bytes());
        buf[60..64].copy_from_slice(&self.kdf_iterations.to_le_bytes());
        buf[64..68].copy_from_slice(&self.kdf_parallelism.to_le_bytes());
        buf[68..92].copy_from_slice(&self.payload_nonce);
        buf
    }

    /// Deserializes header from binary slice.
    pub fn from_bytes(slice: &[u8]) -> Result<Self, BackupError> {
        if slice.len() < BACKUP_HEADER_SIZE {
            return Err(BackupError::VerifyFailed(format!(
                "Header truncated: {} bytes, expected {}",
                slice.len(),
                BACKUP_HEADER_SIZE
            )));
        }

        if &slice[0..8] != BACKUP_MAGIC {
            return Err(BackupError::VerifyFailed(
                "Invalid backup archive magic header bytes".to_string(),
            ));
        }

        let version = u32::from_le_bytes(slice[8..12].try_into().unwrap());
        let created_at = u64::from_le_bytes(slice[12..20].try_into().unwrap());
        let item_count = u32::from_le_bytes(slice[20..24].try_into().unwrap());

        let mut salt = [0u8; 32];
        salt.copy_from_slice(&slice[24..56]);

        let kdf_mem_kib = u32::from_le_bytes(slice[56..60].try_into().unwrap());
        let kdf_iterations = u32::from_le_bytes(slice[60..64].try_into().unwrap());
        let kdf_parallelism = u32::from_le_bytes(slice[64..68].try_into().unwrap());

        let mut payload_nonce = [0u8; 24];
        payload_nonce.copy_from_slice(&slice[68..92]);

        Ok(Self {
            version,
            created_at,
            item_count,
            salt,
            kdf_mem_kib,
            kdf_iterations,
            kdf_parallelism,
            payload_nonce,
        })
    }
}

/// Authentication target specifying how the backup key envelope was encrypted.
pub enum BackupCredential<'a> {
    /// Encrypted with a backup passphrase using Argon2id KDF.
    Passphrase(&'a str),
    /// Encrypted with a 256-bit Emergency Recovery Key.
    RecoveryKey(&'a RecoveryKey),
}

/// Detailed outcome of a dry-run backup restoration rehearsal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupRehearsalReport {
    /// Whether the backup file authenticated and decrypted without any errors.
    pub is_valid: bool,
    /// Vault title recorded in decrypted payload.
    pub vault_name: String,
    /// Total count of active items.
    pub item_count: usize,
    /// Count of trashed items.
    pub trashed_count: usize,
    /// Breakdown of active items by category.
    pub category_counts: HashMap<String, usize>,
    /// Creation timestamp of backup archive.
    pub backup_created_at: u64,
    /// Error message if rehearsal failed.
    pub error_message: Option<String>,
}

/// High-level encrypted backup engine.
pub struct BackupArchive;

impl BackupArchive {
    /// Creates an authenticated `.vaultbak` archive from a `VaultPayload`.
    pub fn create_backup(
        payload: &VaultPayload,
        credential: BackupCredential<'_>,
        test_mode: bool,
    ) -> Result<Vec<u8>, BackupError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // 1. Generate salt and nonce
        let mut salt = [0u8; 32];
        OsRng
            .try_fill_bytes(&mut salt)
            .map_err(|e| BackupError::CreateFailed(e.to_string()))?;

        let payload_nonce =
            generate_nonce().map_err(|e| BackupError::CreateFailed(e.to_string()))?;

        // 2. Select KDF profile
        let (kdf_mem_kib, kdf_iterations, kdf_parallelism) = if test_mode {
            (16 * 1024, 1, 1) // 16 MiB fast test
        } else {
            (64 * 1024, 3, 4) // 64 MiB mobile baseline
        };

        let kdf_params = KdfParams::new(kdf_mem_kib, kdf_iterations, kdf_parallelism, salt)
            .map_err(|e| BackupError::CreateFailed(format!("KDF config error: {}", e)))?;

        // 3. Derive KEK depending on credential type
        let kek = match credential {
            BackupCredential::Passphrase(pass) => {
                let derived = derive_kek(pass.as_bytes(), &kdf_params)
                    .map_err(|e| BackupError::CreateFailed(format!("KDF error: {}", e)))?;
                KeyEncryptionKey::from_bytes(*derived)
            }
            BackupCredential::RecoveryKey(rec_key) => {
                // Derive 256-bit KEK directly from high-entropy recovery key via keyed BLAKE3
                let mut hasher = Hasher::new_keyed(rec_key.as_bytes());
                hasher.update(b"pwdvault-backup-recovery-kek");
                hasher.update(&salt);
                let derived = hasher.finalize();
                KeyEncryptionKey::from_bytes(*derived.as_bytes())
            }
        };

        // 4. Generate fresh DataKey for payload encryption
        let data_key = DataKey::generate()
            .map_err(|e| BackupError::CreateFailed(format!("Key generation error: {}", e)))?;

        // 5. Wrap DataKey into KeyEnvelope (AAD binds to backup magic)
        let envelope = KeyEnvelope::wrap(&data_key, &kek, BACKUP_MAGIC)
            .map_err(|e| BackupError::CreateFailed(format!("Envelope wrap error: {}", e)))?;

        // 6. Serialize and encrypt payload
        let serialized_payload = serde_json::to_vec(payload)
            .map_err(|e| BackupError::CreateFailed(format!("Serialization error: {}", e)))?;

        let encrypted_payload = encrypt_xchacha20(
            data_key.as_bytes(),
            &payload_nonce,
            &serialized_payload,
            BACKUP_MAGIC,
        )
        .map_err(|e| BackupError::CreateFailed(format!("Payload encryption error: {}", e)))?;

        // 7. Build header
        let header = BackupHeader {
            version: 1,
            created_at: now,
            item_count: payload.items.len() as u32,
            salt,
            kdf_mem_kib,
            kdf_iterations,
            kdf_parallelism,
            payload_nonce,
        };

        // 8. Assemble archive: Header (92 bytes) || KeyEnvelope (72 bytes) || Payload (variable)
        let mut archive =
            Vec::with_capacity(BACKUP_HEADER_SIZE + ENVELOPE_LEN + encrypted_payload.len() + 32);
        archive.extend_from_slice(&header.to_bytes());
        archive.extend_from_slice(&envelope.to_bytes());
        archive.extend_from_slice(&encrypted_payload);

        // 9. Compute BLAKE3 commitment of entire archive and append (32 bytes)
        let checksum = blake3::hash(&archive);
        archive.extend_from_slice(checksum.as_bytes());

        Ok(archive)
    }

    /// Conducts a dry-run restoration rehearsal without persisting anything.
    pub fn rehearse_restore(
        backup_bytes: &[u8],
        credential: BackupCredential<'_>,
    ) -> BackupRehearsalReport {
        match Self::restore_backup(backup_bytes, credential) {
            Ok((payload, header)) => {
                let mut categories = HashMap::new();
                let mut trashed = 0;
                let mut active = 0;

                for item in &payload.items {
                    if item.trashed_at.is_some() {
                        trashed += 1;
                    } else {
                        active += 1;
                        let cat_name = format!("{:?}", item.category);
                        *categories.entry(cat_name).or_insert(0) += 1;
                    }
                }

                BackupRehearsalReport {
                    is_valid: true,
                    vault_name: payload.vault_name,
                    item_count: active,
                    trashed_count: trashed,
                    category_counts: categories,
                    backup_created_at: header.created_at,
                    error_message: None,
                }
            }
            Err(e) => BackupRehearsalReport {
                is_valid: false,
                vault_name: String::new(),
                item_count: 0,
                trashed_count: 0,
                category_counts: HashMap::new(),
                backup_created_at: 0,
                error_message: Some(e.to_string()),
            },
        }
    }

    /// Decrypts and restores an authenticated `VaultPayload` from `.vaultbak` bytes.
    pub fn restore_backup(
        backup_bytes: &[u8],
        credential: BackupCredential<'_>,
    ) -> Result<(VaultPayload, BackupHeader), BackupError> {
        let min_len = BACKUP_HEADER_SIZE + ENVELOPE_LEN + 16 + 32;
        if backup_bytes.len() < min_len {
            return Err(BackupError::VerifyFailed(format!(
                "Backup archive truncated: {} bytes, minimum {}",
                backup_bytes.len(),
                min_len
            )));
        }

        // 1. Validate BLAKE3 checksum commitment
        let content_len = backup_bytes.len() - 32;
        let content = &backup_bytes[..content_len];
        let expected_checksum = &backup_bytes[content_len..];

        let actual_checksum = blake3::hash(content);
        if actual_checksum.as_bytes() != expected_checksum {
            return Err(BackupError::VerifyFailed(
                "Backup integrity commitment failed: file modified or corrupted".to_string(),
            ));
        }

        // 2. Parse Header
        let header = BackupHeader::from_bytes(&content[0..BACKUP_HEADER_SIZE])?;

        // 3. Derive KEK
        let kdf_params = KdfParams::new(
            header.kdf_mem_kib,
            header.kdf_iterations,
            header.kdf_parallelism,
            header.salt,
        )
        .map_err(|e| BackupError::VerifyFailed(format!("Invalid KDF params: {}", e)))?;

        let kek = match credential {
            BackupCredential::Passphrase(pass) => {
                let derived = derive_kek(pass.as_bytes(), &kdf_params)
                    .map_err(|e| BackupError::VerifyFailed(format!("KDF failed: {}", e)))?;
                KeyEncryptionKey::from_bytes(*derived)
            }
            BackupCredential::RecoveryKey(rec_key) => {
                let mut hasher = Hasher::new_keyed(rec_key.as_bytes());
                hasher.update(b"pwdvault-backup-recovery-kek");
                hasher.update(&header.salt);
                let derived = hasher.finalize();
                KeyEncryptionKey::from_bytes(*derived.as_bytes())
            }
        };

        // 4. Unwrap Key Envelope
        let env_start = BACKUP_HEADER_SIZE;
        let env_end = env_start + ENVELOPE_LEN;
        let env_bytes = &content[env_start..env_end];

        let envelope = KeyEnvelope::from_bytes(env_bytes)
            .map_err(|e| BackupError::VerifyFailed(format!("Envelope parse error: {}", e)))?;

        let data_key = envelope.unwrap(&kek, BACKUP_MAGIC).map_err(|_| {
            BackupError::VerifyFailed(
                "Decryption failed: incorrect backup passphrase or recovery key".to_string(),
            )
        })?;

        // 5. Decrypt Payload
        let encrypted_payload = &content[env_end..];
        let decrypted_bytes = decrypt_xchacha20(
            data_key.as_bytes(),
            &header.payload_nonce,
            encrypted_payload,
            BACKUP_MAGIC,
        )
        .map_err(|e| BackupError::VerifyFailed(format!("Payload decryption error: {}", e)))?;

        // 6. Deserialize VaultPayload
        let payload: VaultPayload = serde_json::from_slice(&decrypted_bytes)
            .map_err(|e| BackupError::VerifyFailed(format!("Payload JSON decode error: {}", e)))?;

        Ok((payload, header))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pwdvault_vault::{ItemCategory, VaultItem};

    fn sample_payload() -> VaultPayload {
        let mut payload = VaultPayload::new("Test Vault");
        payload.items.push(VaultItem {
            id: "item-1".to_string(),
            title: "GitHub".to_string(),
            category: ItemCategory::Login,
            username: Some("alice".to_string()),
            password: Some("secure-password-123".to_string()),
            urls: vec!["https://github.com".to_string()],
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
        });
        payload.items.push(VaultItem {
            id: "item-2".to_string(),
            title: "Secret Note".to_string(),
            category: ItemCategory::SecureNote,
            username: None,
            password: None,
            urls: vec![],
            notes: Some("PIN is 4321".to_string()),
            totp_seed: None,
            tags: vec![],
            favorite: false,
            custom_fields: vec![],
            attachments: vec![],
            revision_history: vec![],
            trashed_at: None,
            created_at: 1000,
            updated_at: 1000,
        });
        payload
    }

    #[test]
    fn test_backup_with_passphrase_roundtrip() {
        let payload = sample_payload();
        const PASS: &str = "Super-Backup-Secret-Passphrase-99!";

        let backup =
            BackupArchive::create_backup(&payload, BackupCredential::Passphrase(PASS), true)
                .expect("create backup failed");

        assert!(backup.len() > BACKUP_HEADER_SIZE + ENVELOPE_LEN);

        // Rehearsal check
        let report = BackupArchive::rehearse_restore(&backup, BackupCredential::Passphrase(PASS));
        assert!(report.is_valid);
        assert_eq!(report.vault_name, "Test Vault");
        assert_eq!(report.item_count, 2);
        assert_eq!(report.trashed_count, 0);

        // Full restore check
        let (restored, header) =
            BackupArchive::restore_backup(&backup, BackupCredential::Passphrase(PASS))
                .expect("restore failed");
        assert_eq!(restored.vault_name, "Test Vault");
        assert_eq!(restored.items.len(), 2);
        assert_eq!(header.item_count, 2);
    }

    #[test]
    fn test_backup_with_recovery_key_roundtrip() {
        let payload = sample_payload();
        let rec_key = RecoveryKey::generate().unwrap();

        let backup =
            BackupArchive::create_backup(&payload, BackupCredential::RecoveryKey(&rec_key), true)
                .expect("create backup failed");

        let report =
            BackupArchive::rehearse_restore(&backup, BackupCredential::RecoveryKey(&rec_key));
        assert!(report.is_valid);
        assert_eq!(report.item_count, 2);
    }

    #[test]
    fn test_backup_wrong_passphrase_rejection() {
        let payload = sample_payload();
        let backup = BackupArchive::create_backup(
            &payload,
            BackupCredential::Passphrase("Correct-Passphrase"),
            true,
        )
        .unwrap();

        let report = BackupArchive::rehearse_restore(
            &backup,
            BackupCredential::Passphrase("Wrong-Passphrase"),
        );
        assert!(!report.is_valid);
        assert!(report.error_message.is_some());
    }

    #[test]
    fn test_backup_bit_flip_tamper_rejection() {
        let payload = sample_payload();
        let mut backup = BackupArchive::create_backup(
            &payload,
            BackupCredential::Passphrase("SecretPass123"),
            true,
        )
        .unwrap();

        // Flip a byte in the payload area
        let tamper_idx = BACKUP_HEADER_SIZE + 40;
        backup[tamper_idx] ^= 0xFF;

        let report =
            BackupArchive::rehearse_restore(&backup, BackupCredential::Passphrase("SecretPass123"));
        assert!(!report.is_valid);
        assert!(report
            .error_message
            .unwrap()
            .contains("Backup integrity commitment failed"));
    }
}
