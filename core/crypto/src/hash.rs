use subtle::ConstantTimeEq;

/// Length of the BLAKE3 hash digest in bytes (32 bytes).
pub const HASH_LEN: usize = 32;

/// Computes the 256-bit BLAKE3 cryptographic hash over a slice of data.
pub fn hash_blake3(data: &[u8]) -> [u8; HASH_LEN] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(data);
    *hasher.finalize().as_bytes()
}

/// Verifies a 256-bit BLAKE3 hash using constant-time comparison.
pub fn verify_blake3(data: &[u8], expected: &[u8; HASH_LEN]) -> bool {
    let actual = hash_blake3(data);
    actual.ct_eq(expected).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake3_hashing() {
        let msg = b"password-vault-integrity-commitment";
        let h1 = hash_blake3(msg);
        let h2 = hash_blake3(msg);
        assert_eq!(h1, h2);
        assert!(verify_blake3(msg, &h1));

        let mut tampered = h1;
        tampered[0] ^= 0x01;
        assert!(!verify_blake3(msg, &tampered));
    }
}
