use crate::error::CryptoError;
use hkdf::Hkdf;
use sha2::Sha256;
use std::fmt;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// 256-bit cryptographic Data Encryption Key (DEK).
/// Master secret that encrypts vault records, protected by ZeroizeOnDrop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DataKey([u8; 32]);

impl DataKey {
    /// Generates a new random 256-bit DEK from the OS CSPRNG.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).map_err(|e| CryptoError::RngFailed(e.to_string()))?;
        Ok(Self(key))
    }

    /// Creates a DataKey from existing 32-byte secret slice.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrows the internal 32-byte slice.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Derives a domain-separated subkey using HKDF-SHA256 (RFC 5869).
    pub fn derive_subkey(&self, info: &[u8]) -> Result<DataKey, CryptoError> {
        let hk = Hkdf::<Sha256>::new(None, &self.0);
        let mut subkey = [0u8; 32];
        hk.expand(info, &mut subkey)
            .map_err(|_| CryptoError::KeyExpansionFailed)?;
        Ok(DataKey(subkey))
    }
}

impl PartialEq for DataKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for DataKey {}

impl fmt::Debug for DataKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DataKey([REDACTED])")
    }
}

/// 256-bit Key Encryption Key (KEK) derived from the user's master passphrase or recovery key.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct KeyEncryptionKey([u8; 32]);

impl KeyEncryptionKey {
    /// Creates a KeyEncryptionKey from raw 32 bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrows the internal 32-byte key.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl PartialEq for KeyEncryptionKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for KeyEncryptionKey {}

impl fmt::Debug for KeyEncryptionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyEncryptionKey([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_datakey_generation_and_derivation() {
        let dk = DataKey::generate().unwrap();
        assert_ne!(*dk.as_bytes(), [0u8; 32]);

        let record_key = dk.derive_subkey(b"vault:record-encryption:v1").unwrap();
        let attach_key = dk.derive_subkey(b"vault:attachment-encryption:v1").unwrap();

        // Derived subkeys must be distinct and non-zero
        assert_ne!(dk.as_bytes(), record_key.as_bytes());
        assert_ne!(record_key.as_bytes(), attach_key.as_bytes());
        assert_eq!(dk, dk);
        assert_ne!(dk, record_key);
        assert_eq!(format!("{:?}", dk), "DataKey([REDACTED])");
    }
}
