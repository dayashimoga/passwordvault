use crate::error::CryptoError;
use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

/// Minimum allowed memory cost in KiB (16 MiB).
pub const MIN_MEMORY_KIB: u32 = 16 * 1024;
/// Maximum allowed memory cost in KiB (1 GiB).
pub const MAX_MEMORY_KIB: u32 = 1024 * 1024;
/// Minimum allowed time cost / iterations (1 pass).
pub const MIN_ITERATIONS: u32 = 1;
/// Maximum allowed time cost / iterations (10 passes).
pub const MAX_ITERATIONS: u32 = 10;
/// Minimum allowed parallelism / lane count (1 thread).
pub const MIN_PARALLELISM: u32 = 1;
/// Maximum allowed parallelism / lane count (16 threads).
pub const MAX_PARALLELISM: u32 = 16;
/// Required salt length in bytes (32 bytes).
pub const SALT_LEN: usize = 32;

/// Strongly-typed, validated Argon2id KDF parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub memory_kib: u32,
    /// Number of passes / iterations.
    pub iterations: u32,
    /// Number of parallel threads.
    pub parallelism: u32,
    /// 32-byte cryptographic salt.
    pub salt: [u8; SALT_LEN],
}

impl KdfParams {
    /// Validates parameter bounds to protect against DoS or weak configurations.
    pub fn new(
        memory_kib: u32,
        iterations: u32,
        parallelism: u32,
        salt: [u8; SALT_LEN],
    ) -> Result<Self, CryptoError> {
        if !(MIN_MEMORY_KIB..=MAX_MEMORY_KIB).contains(&memory_kib) {
            return Err(CryptoError::InvalidKdfParams(
                "memory_kib must be between 16 MiB and 1 GiB",
            ));
        }
        if !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&iterations) {
            return Err(CryptoError::InvalidKdfParams(
                "iterations must be between 1 and 10",
            ));
        }
        if !(MIN_PARALLELISM..=MAX_PARALLELISM).contains(&parallelism) {
            return Err(CryptoError::InvalidKdfParams(
                "parallelism must be between 1 and 16",
            ));
        }

        Ok(Self {
            memory_kib,
            iterations,
            parallelism,
            salt,
        })
    }

    /// Generates a new `KdfParams` with a cryptographically secure random 32-byte salt.
    pub fn with_random_salt(
        memory_kib: u32,
        iterations: u32,
        parallelism: u32,
    ) -> Result<Self, CryptoError> {
        let mut salt = [0u8; SALT_LEN];
        getrandom::getrandom(&mut salt).map_err(|e| CryptoError::RngFailed(e.to_string()))?;
        Self::new(memory_kib, iterations, parallelism, salt)
    }

    /// Default baseline profile for desktop platforms (128 MiB, 3 passes, 4 lanes).
    pub fn desktop_default() -> Result<Self, CryptoError> {
        Self::with_random_salt(128 * 1024, 3, 4)
    }

    /// Default baseline profile for mobile platforms (64 MiB, 3 passes, 4 lanes).
    pub fn mobile_default() -> Result<Self, CryptoError> {
        Self::with_random_salt(64 * 1024, 3, 4)
    }

    /// Low-latency profile dedicated strictly to fast automated test suites (16 MiB, 1 pass, 1 lane).
    pub fn test_profile() -> Result<Self, CryptoError> {
        Self::with_random_salt(16 * 1024, 1, 1)
    }
}

/// Derives a 256-bit Key-Encryption Key (KEK) using Argon2id.
/// The resulting key is automatically zeroized upon drop.
pub fn derive_kek(
    passphrase: &[u8],
    params: &KdfParams,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let argon2_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(32),
    )
    .map_err(|e| CryptoError::InvalidKdfParams(Box::leak(e.to_string().into_boxed_str())))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    let mut key_bytes = [0u8; 32];
    argon2
        .hash_password_into(passphrase, &params.salt, &mut key_bytes)
        .map_err(|e| CryptoError::KdfFailed(e.to_string()))?;

    Ok(Zeroizing::new(key_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kdf_parameter_bounds() {
        let salt = [0x42u8; SALT_LEN];

        // Too low memory
        assert!(KdfParams::new(MIN_MEMORY_KIB - 1, 3, 4, salt).is_err());
        // Too high memory
        assert!(KdfParams::new(MAX_MEMORY_KIB + 1, 3, 4, salt).is_err());
        // Zero iterations
        assert!(KdfParams::new(64 * 1024, 0, 4, salt).is_err());
        // Too high iterations
        assert!(KdfParams::new(64 * 1024, 11, 4, salt).is_err());
        // Zero parallelism
        assert!(KdfParams::new(64 * 1024, 3, 0, salt).is_err());
        // Too high parallelism
        assert!(KdfParams::new(64 * 1024, 3, 17, salt).is_err());
        // Valid bounds
        assert!(KdfParams::new(64 * 1024, 3, 4, salt).is_ok());
    }

    #[test]
    fn test_kdf_derivation_deterministic() {
        let salt = [0x5au8; SALT_LEN];
        let params = KdfParams::new(16 * 1024, 1, 1, salt).unwrap();
        let pw = b"super-secret-master-passphrase";

        let key1 = derive_kek(pw, &params).unwrap();
        let key2 = derive_kek(pw, &params).unwrap();

        assert_eq!(*key1, *key2);
        assert_ne!(*key1, [0u8; 32]);

        // Different password yields different key
        let key3 = derive_kek(b"different-password", &params).unwrap();
        assert_ne!(*key1, *key3);
    }
}
