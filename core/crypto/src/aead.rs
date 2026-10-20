use crate::error::CryptoError;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use zeroize::Zeroizing;

/// Nonce length in bytes (24 bytes for XChaCha20).
pub const NONCE_LEN: usize = 24;
/// Poly1305 authentication tag length in bytes (16 bytes).
pub const TAG_LEN: usize = 16;
/// Symmetric key length in bytes (32 bytes).
pub const KEY_LEN: usize = 32;

/// Generates a cryptographically random 192-bit (24-byte) nonce from the OS CSPRNG.
pub fn generate_nonce() -> Result<[u8; NONCE_LEN], CryptoError> {
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce).map_err(|e| CryptoError::RngFailed(e.to_string()))?;
    Ok(nonce)
}

/// Encrypts plaintext with XChaCha20-Poly1305 authenticated encryption.
/// Output contains the ciphertext followed by the 16-byte Poly1305 MAC tag.
pub fn encrypt_xchacha20(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher =
        XChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::EncryptionFailed)?;
    let xnonce = XNonce::from_slice(nonce);

    let payload = Payload {
        msg: plaintext,
        aad: associated_data,
    };

    cipher
        .encrypt(xnonce, payload)
        .map_err(|_| CryptoError::EncryptionFailed)
}

/// Decrypts ciphertext and verifies the Poly1305 tag.
/// Returns a zeroizing byte buffer on success; returns `CryptoError::DecryptionFailed` on
/// any bit flip in ciphertext, nonce, or associated data.
pub fn decrypt_xchacha20(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext_with_tag: &[u8],
    associated_data: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let cipher =
        XChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::DecryptionFailed)?;
    let xnonce = XNonce::from_slice(nonce);

    let payload = Payload {
        msg: ciphertext_with_tag,
        aad: associated_data,
    };

    let plaintext = cipher
        .decrypt(xnonce, payload)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xchacha20_roundtrip() {
        let key = [0x7au8; KEY_LEN];
        let nonce = generate_nonce().unwrap();
        let aad = b"authenticated-vault-header-v1";
        let secret = b"my-sensitive-master-data-key-12345678";

        let ciphertext = encrypt_xchacha20(&key, &nonce, secret, aad).unwrap();
        assert_ne!(ciphertext, secret);
        assert_eq!(ciphertext.len(), secret.len() + TAG_LEN);

        let decrypted = decrypt_xchacha20(&key, &nonce, &ciphertext, aad).unwrap();
        assert_eq!(*decrypted, *secret);
    }

    #[test]
    fn test_xchacha20_tamper_rejection() {
        let key = [0x3bu8; KEY_LEN];
        let nonce = generate_nonce().unwrap();
        let aad = b"authenticated-header";
        let secret = b"sensitive-credentials";

        let mut ciphertext = encrypt_xchacha20(&key, &nonce, secret, aad).unwrap();

        // 1. Bit flip in ciphertext
        ciphertext[0] ^= 0x01;
        assert_eq!(
            decrypt_xchacha20(&key, &nonce, &ciphertext, aad),
            Err(CryptoError::DecryptionFailed)
        );
        ciphertext[0] ^= 0x01; // Restore

        // 2. Bit flip in MAC tag (last byte)
        let last_idx = ciphertext.len() - 1;
        ciphertext[last_idx] ^= 0x80;
        assert_eq!(
            decrypt_xchacha20(&key, &nonce, &ciphertext, aad),
            Err(CryptoError::DecryptionFailed)
        );
        ciphertext[last_idx] ^= 0x80; // Restore

        // 3. Bit flip in Associated Data
        let mut tampered_aad = aad.to_vec();
        tampered_aad[0] ^= 0x01;
        assert_eq!(
            decrypt_xchacha20(&key, &nonce, &ciphertext, &tampered_aad),
            Err(CryptoError::DecryptionFailed)
        );

        // 4. Bit flip in Nonce
        let mut tampered_nonce = nonce;
        tampered_nonce[0] ^= 0x01;
        assert_eq!(
            decrypt_xchacha20(&key, &tampered_nonce, &ciphertext, aad),
            Err(CryptoError::DecryptionFailed)
        );
    }
}
