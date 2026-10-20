use crate::error::VaultError;
use pwdvault_crypto::KdfParams;

/// Exact length of the unauthenticated binary header in bytes.
pub const HEADER_LEN: usize = 64;
/// File magic bytes: "VAULT".
pub const MAGIC: &[u8; 5] = b"VAULT";
/// Format version: 1.
pub const CURRENT_VERSION: u16 = 1;
/// Argon2id KDF algorithm identifier: 1.
pub const KDF_ARGON2ID: u8 = 1;
/// XChaCha20-Poly1305 AEAD cipher suite identifier: 1.
pub const CIPHER_XCHACHA20_POLY1305: u8 = 1;

/// 64-byte authenticated vault header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultHeader {
    /// Format version number.
    pub version: u16,
    /// Key derivation function algorithm ID.
    pub kdf_algo: u8,
    /// Strongly-typed KDF parameters.
    pub kdf_params: KdfParams,
    /// AEAD cipher suite ID.
    pub cipher_suite: u8,
}

impl VaultHeader {
    /// Creates a new `VaultHeader` using the provided KDF parameters.
    pub fn new(kdf_params: KdfParams) -> Self {
        Self {
            version: CURRENT_VERSION,
            kdf_algo: KDF_ARGON2ID,
            kdf_params,
            cipher_suite: CIPHER_XCHACHA20_POLY1305,
        }
    }

    /// Serializes the header into a fixed 64-byte array.
    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut buf = [0u8; HEADER_LEN];
        buf[0..5].copy_from_slice(MAGIC);
        buf[5..7].copy_from_slice(&self.version.to_be_bytes());
        buf[7] = self.kdf_algo;
        buf[8..40].copy_from_slice(&self.kdf_params.salt);
        buf[40..44].copy_from_slice(&self.kdf_params.memory_kib.to_be_bytes());
        buf[44..48].copy_from_slice(&self.kdf_params.iterations.to_be_bytes());
        buf[48..52].copy_from_slice(&self.kdf_params.parallelism.to_be_bytes());
        buf[52] = self.cipher_suite;
        // Remaining bytes 53..64 are zero-padded reserved bytes
        buf
    }

    /// Deserializes and strictly validates a 64-byte header.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VaultError> {
        if bytes.len() < HEADER_LEN {
            return Err(VaultError::TruncatedData);
        }

        if &bytes[0..5] != MAGIC {
            return Err(VaultError::InvalidMagic);
        }

        let version = u16::from_be_bytes([bytes[5], bytes[6]]);
        if version != CURRENT_VERSION {
            return Err(VaultError::UnsupportedVersion(version));
        }

        let kdf_algo = bytes[7];
        if kdf_algo != KDF_ARGON2ID {
            return Err(VaultError::UnsupportedVersion(kdf_algo as u16));
        }

        let mut salt = [0u8; 32];
        salt.copy_from_slice(&bytes[8..40]);

        let memory_kib = u32::from_be_bytes([bytes[40], bytes[41], bytes[42], bytes[43]]);
        let iterations = u32::from_be_bytes([bytes[44], bytes[45], bytes[46], bytes[47]]);
        let parallelism = u32::from_be_bytes([bytes[48], bytes[49], bytes[50], bytes[51]]);

        let kdf_params = KdfParams::new(memory_kib, iterations, parallelism, salt)
            .map_err(VaultError::Crypto)?;

        let cipher_suite = bytes[52];
        if cipher_suite != CIPHER_XCHACHA20_POLY1305 {
            return Err(VaultError::UnsupportedVersion(cipher_suite as u16));
        }

        Ok(Self {
            version,
            kdf_algo,
            kdf_params,
            cipher_suite,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_serialization_roundtrip() {
        let kdf = KdfParams::new(64 * 1024, 3, 4, [0x11u8; 32]).unwrap();
        let header = VaultHeader::new(kdf);

        let bytes = header.to_bytes();
        assert_eq!(bytes.len(), HEADER_LEN);
        assert_eq!(&bytes[0..5], b"VAULT");

        let parsed = VaultHeader::from_bytes(&bytes).unwrap();
        assert_eq!(header, parsed);
    }

    #[test]
    fn test_header_invalid_magic() {
        let kdf = KdfParams::new(64 * 1024, 3, 4, [0x22u8; 32]).unwrap();
        let mut bytes = VaultHeader::new(kdf).to_bytes();
        bytes[0] = b'X';
        assert_eq!(
            VaultHeader::from_bytes(&bytes),
            Err(VaultError::InvalidMagic)
        );
    }
}
