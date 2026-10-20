#![deny(unsafe_code)]
#![warn(missing_docs)]

//! Authenticated `.syncpack` encrypted container format for file and offline synchronization.

use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use pwdvault_crypto::aead::{decrypt_xchacha20, encrypt_xchacha20, generate_nonce, NONCE_LEN};
use pwdvault_vault::VaultPayload;

use crate::crdt::{merge_vault_payloads, SyncMergeReport};
use crate::vector_clock::VectorClock;
use crate::SyncError;

/// 8-byte file magic for authenticated sync packages.
pub const SYNCPACK_MAGIC: &[u8; 8] = b"PVSYNC01";
/// Header length in bytes: 8 (magic) + 4 (version) + 24 (nonce) + 32 (salt) + 32 (commitment).
pub const SYNCPACK_HEADER_LEN: usize = 100;

/// Unencrypted internal payload encapsulated inside a syncpack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncPackPayload {
    /// Originating device identifier.
    pub source_device_id: String,
    /// Originating device human-readable name.
    pub source_device_name: String,
    /// Originating vector clock state.
    pub clock: VectorClock,
    /// Vault payload contents.
    pub vault: VaultPayload,
    /// Timestamp when package was produced.
    pub generated_at: u64,
}

/// Encrypts and packages a vault payload into an authenticated `.syncpack` byte buffer.
pub fn create_syncpack(
    payload: &VaultPayload,
    sync_key: &[u8; 32],
    source_device_id: &str,
    source_device_name: &str,
    clock: &VectorClock,
) -> Result<Vec<u8>, SyncError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let pack_payload = SyncPackPayload {
        source_device_id: source_device_id.to_string(),
        source_device_name: source_device_name.to_string(),
        clock: clock.clone(),
        vault: payload.clone(),
        generated_at: now,
    };

    let plaintext = serde_json::to_vec(&pack_payload)
        .map_err(|e| SyncError::ProtocolError(format!("Serialization error: {}", e)))?;

    let nonce = generate_nonce().map_err(|e| SyncError::ProtocolError(e.to_string()))?;
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);

    let commitment = *blake3::hash(&plaintext).as_bytes();

    // Assemble 100-byte authenticated header
    let mut header = Vec::with_capacity(SYNCPACK_HEADER_LEN);
    header.extend_from_slice(SYNCPACK_MAGIC);
    header.extend_from_slice(&1u32.to_le_bytes());
    header.extend_from_slice(&nonce);
    header.extend_from_slice(&salt);
    header.extend_from_slice(&commitment);

    // AEAD encryption with header as associated data (AAD)
    let ciphertext = encrypt_xchacha20(sync_key, &nonce, &plaintext, &header)
        .map_err(|e| SyncError::ProtocolError(format!("Sync encryption failed: {}", e)))?;

    let mut out = header;
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypts and deserializes an authenticated `.syncpack` byte buffer.
pub fn read_syncpack(pack_bytes: &[u8], sync_key: &[u8; 32]) -> Result<SyncPackPayload, SyncError> {
    if pack_bytes.len() < SYNCPACK_HEADER_LEN + 16 {
        return Err(SyncError::ProtocolError("Syncpack buffer truncated".to_string()));
    }

    let magic = &pack_bytes[0..8];
    if magic != SYNCPACK_MAGIC {
        return Err(SyncError::ProtocolError("Invalid syncpack magic identifier".to_string()));
    }

    let version = u32::from_le_bytes(pack_bytes[8..12].try_into().unwrap());
    if version != 1 {
        return Err(SyncError::ProtocolError(format!("Unsupported syncpack version: {}", version)));
    }

    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&pack_bytes[12..36]);

    let commitment: [u8; 32] = pack_bytes[68..100].try_into().unwrap();
    let header = &pack_bytes[0..SYNCPACK_HEADER_LEN];
    let ciphertext = &pack_bytes[SYNCPACK_HEADER_LEN..];

    let plaintext = decrypt_xchacha20(sync_key, &nonce, ciphertext, header)
        .map_err(|_| SyncError::ProtocolError("Decryption failed: corrupted data or wrong sync key".to_string()))?;

    // Verify BLAKE3 commitment
    let computed_commitment = *blake3::hash(&plaintext).as_bytes();
    if computed_commitment != commitment {
        return Err(SyncError::ProtocolError("BLAKE3 commitment integrity mismatch".to_string()));
    }

    let pack_payload: SyncPackPayload = serde_json::from_slice(&plaintext)
        .map_err(|e| SyncError::ProtocolError(format!("Deserialization error: {}", e)))?;

    Ok(pack_payload)
}

/// Applies a `.syncpack` to a local vault payload and updates the vector clock.
pub fn apply_syncpack(
    local_payload: &mut VaultPayload,
    local_clock: &mut VectorClock,
    pack_bytes: &[u8],
    sync_key: &[u8; 32],
) -> Result<SyncMergeReport, SyncError> {
    let remote = read_syncpack(pack_bytes, sync_key)?;
    let report = merge_vault_payloads(local_payload, &remote.vault);
    local_clock.merge(&remote.clock);
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pwdvault_vault::{ItemCategory, VaultItem};

    #[test]
    fn test_syncpack_roundtrip() {
        let sync_key = [42u8; 32];
        let mut vault = VaultPayload::new("Test Vault");
        vault.items.push(VaultItem {
            id: "sync-1".to_string(),
            title: "Proton".to_string(),
            category: ItemCategory::Login,
            username: Some("user@proton.me".to_string()),
            password: Some("s3cr3t".to_string()),
            urls: vec!["https://mail.proton.me".to_string()],
            notes: None,
            totp_seed: None,
            tags: vec![],
            favorite: true,
            custom_fields: vec![],
            attachments: vec![],
            revision_history: vec![],
            trashed_at: None,
            created_at: 1000,
            updated_at: 1000,
        });

        let mut clock = VectorClock::new();
        clock.increment("device-alpha");

        let pack_bytes = create_syncpack(&vault, &sync_key, "device-alpha", "Alice Laptop", &clock)
            .expect("create failed");
        assert!(pack_bytes.len() > SYNCPACK_HEADER_LEN);

        let decoded = read_syncpack(&pack_bytes, &sync_key).expect("read failed");
        assert_eq!(decoded.source_device_id, "device-alpha");
        assert_eq!(decoded.source_device_name, "Alice Laptop");
        assert_eq!(decoded.vault.items.len(), 1);
        assert_eq!(decoded.vault.items[0].title, "Proton");
    }

    #[test]
    fn test_syncpack_wrong_key_rejection() {
        let sync_key = [42u8; 32];
        let wrong_key = [99u8; 32];
        let vault = VaultPayload::new("Test Vault");
        let clock = VectorClock::new();

        let pack_bytes = create_syncpack(&vault, &sync_key, "dev", "Name", &clock).unwrap();
        assert!(read_syncpack(&pack_bytes, &wrong_key).is_err());
    }

    #[test]
    fn test_syncpack_tampering_rejection() {
        let sync_key = [42u8; 32];
        let vault = VaultPayload::new("Test Vault");
        let clock = VectorClock::new();

        let mut pack_bytes = create_syncpack(&vault, &sync_key, "dev", "Name", &clock).unwrap();
        let last_idx = pack_bytes.len() - 1;
        pack_bytes[last_idx] ^= 0x01; // Tamper with last ciphertext byte

        assert!(read_syncpack(&pack_bytes, &sync_key).is_err());
    }
}
