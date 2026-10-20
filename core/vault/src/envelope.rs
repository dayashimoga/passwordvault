use crate::error::VaultError;
use pwdvault_crypto::{
    decrypt_xchacha20, encrypt_xchacha20, generate_nonce, DataKey, KeyEncryptionKey, KEY_LEN,
    NONCE_LEN, TAG_LEN,
};

/// Total length of serialized KeyEnvelope in bytes.
pub const ENVELOPE_LEN: usize = NONCE_LEN + KEY_LEN + TAG_LEN; // 24 + 32 + 16 = 72 bytes

/// Key encryption envelope wrapping the DataKey using a KeyEncryptionKey (KEK).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyEnvelope {
    /// 192-bit extended nonce for XChaCha20-Poly1305.
    pub nonce: [u8; NONCE_LEN],
    /// 32 bytes encrypted key + 16 bytes Poly1305 authentication tag.
    pub wrapped_key: [u8; KEY_LEN + TAG_LEN],
}

impl KeyEnvelope {
    /// Wraps a DataKey using a KeyEncryptionKey with associated data authentication.
    pub fn wrap(
        data_key: &DataKey,
        kek: &KeyEncryptionKey,
        associated_data: &[u8],
    ) -> Result<Self, VaultError> {
        let nonce = generate_nonce().map_err(VaultError::Crypto)?;
        let ciphertext =
            encrypt_xchacha20(kek.as_bytes(), &nonce, data_key.as_bytes(), associated_data)
                .map_err(VaultError::Crypto)?;

        if ciphertext.len() != KEY_LEN + TAG_LEN {
            return Err(VaultError::Crypto(
                pwdvault_crypto::CryptoError::EncryptionFailed,
            ));
        }

        let mut wrapped_key = [0u8; KEY_LEN + TAG_LEN];
        wrapped_key.copy_from_slice(&ciphertext);

        Ok(Self { nonce, wrapped_key })
    }

    /// Unwraps the DataKey using the provided KeyEncryptionKey and verifying associated data.
    pub fn unwrap(
        &self,
        kek: &KeyEncryptionKey,
        associated_data: &[u8],
    ) -> Result<DataKey, VaultError> {
        let decrypted = decrypt_xchacha20(
            kek.as_bytes(),
            &self.nonce,
            &self.wrapped_key,
            associated_data,
        )
        .map_err(|_| VaultError::AuthenticationFailed)?;

        if decrypted.len() != KEY_LEN {
            return Err(VaultError::AuthenticationFailed);
        }

        let mut key_bytes = [0u8; KEY_LEN];
        key_bytes.copy_from_slice(&decrypted);
        Ok(DataKey::from_bytes(key_bytes))
    }

    /// Serializes envelope to 72 bytes.
    pub fn to_bytes(&self) -> [u8; ENVELOPE_LEN] {
        let mut buf = [0u8; ENVELOPE_LEN];
        buf[0..NONCE_LEN].copy_from_slice(&self.nonce);
        buf[NONCE_LEN..ENVELOPE_LEN].copy_from_slice(&self.wrapped_key);
        buf
    }

    /// Deserializes envelope from a 72-byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VaultError> {
        if bytes.len() < ENVELOPE_LEN {
            return Err(VaultError::TruncatedData);
        }

        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[0..NONCE_LEN]);

        let mut wrapped_key = [0u8; KEY_LEN + TAG_LEN];
        wrapped_key.copy_from_slice(&bytes[NONCE_LEN..ENVELOPE_LEN]);

        Ok(Self { nonce, wrapped_key })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_envelope_wrap_and_unwrap() {
        let dek = DataKey::generate().unwrap();
        let kek = KeyEncryptionKey::from_bytes([0x88u8; 32]);
        let aad = b"authenticated-vault-header-bytes";

        let envelope = KeyEnvelope::wrap(&dek, &kek, aad).unwrap();
        let bytes = envelope.to_bytes();
        assert_eq!(bytes.len(), ENVELOPE_LEN);

        let parsed = KeyEnvelope::from_bytes(&bytes).unwrap();
        let unwrapped_dek = parsed.unwrap(&kek, aad).unwrap();

        assert_eq!(dek, unwrapped_dek);
    }

    #[test]
    fn test_key_envelope_tamper_rejection() {
        let dek = DataKey::generate().unwrap();
        let kek = KeyEncryptionKey::from_bytes([0x88u8; 32]);
        let wrong_kek = KeyEncryptionKey::from_bytes([0x99u8; 32]);
        let aad = b"header-aad";

        let envelope = KeyEnvelope::wrap(&dek, &kek, aad).unwrap();

        // Wrong KEK
        assert_eq!(
            envelope.unwrap(&wrong_kek, aad).err(),
            Some(VaultError::AuthenticationFailed)
        );

        // Wrong AAD
        assert_eq!(
            envelope.unwrap(&kek, b"different-aad").err(),
            Some(VaultError::AuthenticationFailed)
        );
    }
}
