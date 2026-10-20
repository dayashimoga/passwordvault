#![deny(unsafe_code)]
#![warn(missing_docs)]

//! RFC 2104 Keyed-Hashing for Message Authentication (HMAC) supporting SHA-1, SHA-256, and SHA-512.

use sha2::{Digest, Sha256, Sha512};
use subtle::ConstantTimeEq;

use crate::sha1::Sha1;

/// Computes HMAC-SHA1 over data using key.
pub fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    const BLOCK_SIZE: usize = 64;
    let mut key_block = [0u8; BLOCK_SIZE];

    if key.len() > BLOCK_SIZE {
        let hash = Sha1::digest(key);
        key_block[..20].copy_from_slice(&hash);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut inner_pad = [0u8; BLOCK_SIZE];
    let mut outer_pad = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        inner_pad[i] = key_block[i] ^ 0x36;
        outer_pad[i] = key_block[i] ^ 0x5C;
    }

    let mut inner_hasher = Sha1::new();
    inner_hasher.update(&inner_pad);
    inner_hasher.update(data);
    let inner_hash = inner_hasher.finalize();

    let mut outer_hasher = Sha1::new();
    outer_hasher.update(&outer_pad);
    outer_hasher.update(&inner_hash);
    outer_hasher.finalize()
}

/// Computes HMAC-SHA256 over data using key.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    const BLOCK_SIZE: usize = 64;
    let mut key_block = [0u8; BLOCK_SIZE];

    if key.len() > BLOCK_SIZE {
        let hash = Sha256::digest(key);
        key_block[..32].copy_from_slice(&hash);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut inner_pad = [0u8; BLOCK_SIZE];
    let mut outer_pad = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        inner_pad[i] = key_block[i] ^ 0x36;
        outer_pad[i] = key_block[i] ^ 0x5C;
    }

    let mut inner_hasher = Sha256::new();
    inner_hasher.update(inner_pad);
    inner_hasher.update(data);
    let inner_hash = inner_hasher.finalize();

    let mut outer_hasher = Sha256::new();
    outer_hasher.update(outer_pad);
    outer_hasher.update(inner_hash);
    let out = outer_hasher.finalize();

    let mut result = [0u8; 32];
    result.copy_from_slice(&out);
    result
}

/// Computes HMAC-SHA512 over data using key.
pub fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    const BLOCK_SIZE: usize = 128;
    let mut key_block = [0u8; BLOCK_SIZE];

    if key.len() > BLOCK_SIZE {
        let hash = Sha512::digest(key);
        key_block[..64].copy_from_slice(&hash);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut inner_pad = [0u8; BLOCK_SIZE];
    let mut outer_pad = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        inner_pad[i] = key_block[i] ^ 0x36;
        outer_pad[i] = key_block[i] ^ 0x5C;
    }

    let mut inner_hasher = Sha512::new();
    inner_hasher.update(inner_pad);
    inner_hasher.update(data);
    let inner_hash = inner_hasher.finalize();

    let mut outer_hasher = Sha512::new();
    outer_hasher.update(outer_pad);
    outer_hasher.update(inner_hash);
    let out = outer_hasher.finalize();

    let mut result = [0u8; 64];
    result.copy_from_slice(&out);
    result
}

/// Verifies whether provided mac matches expected mac in constant time.
pub fn verify_mac(computed: &[u8], provided: &[u8]) -> bool {
    computed.ct_eq(provided).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc2202_hmac_sha1_case1() {
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let mac = hmac_sha1(&key, data);
        let hex = mac.iter().map(|b| format!("{:02x}", b)).collect::<String>();
        assert_eq!(hex, "b617318655057264e28bc0b6fb378c8ef146be00");
    }

    #[test]
    fn test_rfc4231_hmac_sha256_case1() {
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let mac = hmac_sha256(&key, data);
        let hex = mac.iter().map(|b| format!("{:02x}", b)).collect::<String>();
        assert_eq!(
            hex,
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }
}
