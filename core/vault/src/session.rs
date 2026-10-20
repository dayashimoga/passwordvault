use crate::container::VaultContainer;
use crate::envelope::KeyEnvelope;
use crate::error::VaultError;
use crate::header::VaultHeader;
use crate::payload::{VaultItem, VaultPayload};
use pwdvault_crypto::{DataKey, KdfParams, KeyEncryptionKey};
use std::time::{Duration, Instant};
use zeroize::Zeroize;

/// Active, unlocked vault session.
///
/// Encapsulates decrypted payload, active Data Encryption Key,
/// auto-lock inactivity timers, and key lifecycle rotations.
pub struct VaultSession {
    header: VaultHeader,
    data_key: Option<DataKey>,
    payload: Option<VaultPayload>,
    last_activity: Instant,
    auto_lock_duration: Duration,
}

impl VaultSession {
    /// Initializes a new session from an unlocked container.
    pub fn new(
        header: VaultHeader,
        data_key: DataKey,
        payload: VaultPayload,
        auto_lock_secs: u64,
    ) -> Self {
        Self {
            header,
            data_key: Some(data_key),
            payload: Some(payload),
            last_activity: Instant::now(),
            auto_lock_duration: Duration::from_secs(auto_lock_secs.clamp(30, 86400)),
        }
    }

    /// Whether the session is currently locked.
    pub fn is_locked(&self) -> bool {
        self.data_key.is_none() || self.payload.is_none()
    }

    /// Records user interaction, resetting the inactivity timeout.
    pub fn record_activity(&mut self) {
        if !self.is_locked() {
            self.last_activity = Instant::now();
        }
    }

    /// Checks if the auto-lock timeout has expired, and automatically locks if so.
    pub fn check_auto_lock(&mut self) -> bool {
        if !self.is_locked() && self.last_activity.elapsed() >= self.auto_lock_duration {
            self.lock();
            true
        } else {
            false
        }
    }

    /// Immediately locks the vault and zeroizes the in-memory DataKey and payload.
    pub fn lock(&mut self) {
        if let Some(mut key) = self.data_key.take() {
            key.zeroize();
        }
        self.payload = None;
    }

    /// Borrows the active payload. Returns `VaultError::AuthenticationFailed` if locked.
    pub fn payload(&self) -> Result<&VaultPayload, VaultError> {
        self.payload
            .as_ref()
            .ok_or(VaultError::AuthenticationFailed)
    }

    /// Mutably borrows the active payload. Returns `VaultError::AuthenticationFailed` if locked.
    pub fn payload_mut(&mut self) -> Result<&mut VaultPayload, VaultError> {
        self.record_activity();
        self.payload
            .as_mut()
            .ok_or(VaultError::AuthenticationFailed)
    }

    /// Adds an item to the session's vault.
    pub fn add_item(&mut self, item: VaultItem) -> Result<(), VaultError> {
        let payload = self.payload_mut()?;
        payload.add_item(item);
        Ok(())
    }

    /// Trashes an item in the session's vault.
    pub fn trash_item(&mut self, id: &str, timestamp: u64) -> Result<bool, VaultError> {
        let payload = self.payload_mut()?;
        Ok(payload.trash_item(id, timestamp))
    }

    /// Restores an item from the session's trash.
    pub fn restore_item(&mut self, id: &str, timestamp: u64) -> Result<bool, VaultError> {
        let payload = self.payload_mut()?;
        Ok(payload.restore_item(id, timestamp))
    }

    /// Permanently deletes an item.
    pub fn delete_permanently(&mut self, id: &str) -> Result<bool, VaultError> {
        let payload = self.payload_mut()?;
        Ok(payload.delete_permanently(id))
    }

    /// Serializes and re-encrypts the current session payload to raw vault container bytes.
    pub fn save_to_bytes(&self, passphrase: &[u8]) -> Result<Vec<u8>, VaultError> {
        let payload = self.payload()?;
        VaultContainer::create(passphrase, self.header.kdf_params.clone(), payload)
    }

    /// Changes the master passphrase without re-encrypting records.
    ///
    /// Derives a new Master KEK and re-wraps the existing Data Encryption Key (DEK).
    pub fn change_passphrase(
        &mut self,
        new_passphrase: &[u8],
        new_kdf_params: KdfParams,
    ) -> Result<Vec<u8>, VaultError> {
        let bytes = {
            let payload = self.payload()?;
            VaultContainer::create(new_passphrase, new_kdf_params.clone(), payload)?
        };
        self.header.kdf_params = new_kdf_params;
        Ok(bytes)
    }

    /// Rotates the Data Encryption Key (DEK).
    ///
    /// Generates a fresh random DEK and re-encrypts the entire vault container.
    pub fn rotate_data_key(&mut self, passphrase: &[u8]) -> Result<Vec<u8>, VaultError> {
        let payload = self.payload()?;
        let bytes = VaultContainer::create(passphrase, self.header.kdf_params.clone(), payload)?;

        // Re-unlock to update session's internal DataKey
        let (header, new_dek, new_payload) = VaultContainer::unlock(&bytes, passphrase)?;
        self.header = header;
        self.data_key = Some(new_dek);
        self.payload = Some(new_payload);

        Ok(bytes)
    }

    /// Generates emergency recovery material and wraps the session's DEK.
    pub fn generate_recovery_envelope(
        &self,
    ) -> Result<(KeyEncryptionKey, KeyEnvelope), VaultError> {
        let dek = self
            .data_key
            .as_ref()
            .ok_or(VaultError::AuthenticationFailed)?;
        let mut raw_key = [0u8; 32];
        getrandom::getrandom(&mut raw_key).map_err(|e| {
            VaultError::Crypto(pwdvault_crypto::CryptoError::RngFailed(e.to_string()))
        })?;
        let recovery_kek = KeyEncryptionKey::from_bytes(raw_key);

        let header_bytes = self.header.to_bytes();
        let envelope = KeyEnvelope::wrap(dek, &recovery_kek, &header_bytes)?;

        Ok((recovery_kek, envelope))
    }
}

impl Drop for VaultSession {
    fn drop(&mut self) {
        self.lock();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload::{ItemCategory, VaultItem};

    fn make_test_item(id: &str, title: &str) -> VaultItem {
        VaultItem {
            id: id.into(),
            title: title.into(),
            category: ItemCategory::Login,
            username: Some("user".into()),
            password: Some("secret".into()),
            urls: vec!["https://example.com".into()],
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
    fn test_session_lifecycle_and_lock() {
        let kdf = KdfParams::test_profile().unwrap();
        let pw = b"session-test-password";
        let mut initial_payload = VaultPayload::new("Session Vault");
        initial_payload.add_item(make_test_item("1", "Service A"));

        let vault_bytes = VaultContainer::create(pw, kdf, &initial_payload).unwrap();
        let (header, dek, payload) = VaultContainer::unlock(&vault_bytes, pw).unwrap();

        let mut session = VaultSession::new(header, dek, payload, 300);
        assert!(!session.is_locked());
        assert_eq!(session.payload().unwrap().items.len(), 1);

        // Add item
        session.add_item(make_test_item("2", "Service B")).unwrap();
        assert_eq!(session.payload().unwrap().items.len(), 2);

        // Manual lock
        session.lock();
        assert!(session.is_locked());
        assert!(session.payload().is_err());
    }

    #[test]
    fn test_session_passphrase_change() {
        let kdf = KdfParams::test_profile().unwrap();
        let pw = b"initial-password";
        let new_pw = b"new-strong-password";
        let initial_payload = VaultPayload::new("Password Change Vault");

        let vault_bytes = VaultContainer::create(pw, kdf.clone(), &initial_payload).unwrap();
        let (header, dek, payload) = VaultContainer::unlock(&vault_bytes, pw).unwrap();

        let mut session = VaultSession::new(header, dek, payload, 300);
        let updated_bytes = session.change_passphrase(new_pw, kdf).unwrap();

        // Old password must fail
        assert_eq!(
            VaultContainer::unlock(&updated_bytes, pw).err(),
            Some(VaultError::AuthenticationFailed)
        );

        // New password must succeed
        let (_h, _d, unlocked_payload) = VaultContainer::unlock(&updated_bytes, new_pw).unwrap();
        assert_eq!(unlocked_payload.vault_name, "Password Change Vault");
    }

    #[test]
    fn test_session_data_key_rotation() {
        let kdf = KdfParams::test_profile().unwrap();
        let pw = b"key-rotation-password";
        let initial_payload = VaultPayload::new("Key Rotation Vault");

        let vault_bytes = VaultContainer::create(pw, kdf, &initial_payload).unwrap();
        let (header, dek, payload) = VaultContainer::unlock(&vault_bytes, pw).unwrap();

        let mut session = VaultSession::new(header, dek, payload, 300);
        let rotated_bytes = session.rotate_data_key(pw).unwrap();

        // Re-unlock rotated container
        let (_h, new_dek, unlocked_payload) = VaultContainer::unlock(&rotated_bytes, pw).unwrap();
        assert_eq!(unlocked_payload.vault_name, "Key Rotation Vault");
        assert_eq!(session.data_key.as_ref().unwrap(), &new_dek);
    }
}
