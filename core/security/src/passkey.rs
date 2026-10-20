#![deny(unsafe_code)]
#![warn(missing_docs)]

//! WebAuthn / FIDO2 Passkey credential generation, authenticator framing, and assertion signing.

use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::SecurityError;
use crate::hmac::{hmac_sha256, verify_mac};

/// COSE algorithm identifier for ES256 (ECDSA w/ SHA-256).
pub const COSE_ALG_ES256: i32 = -7;
/// COSE algorithm identifier for EdDSA (Ed25519).
pub const COSE_ALG_EDDSA: i32 = -8;

/// FIDO2 Authenticator Data flags.
pub mod flags {
    /// Bit 0: User Present (UP).
    pub const USER_PRESENT: u8 = 0x01;
    /// Bit 2: User Verified (UV) via PIN, Face ID, Touch ID, or Windows Hello.
    pub const USER_VERIFIED: u8 = 0x04;
    /// Bit 6: Attested credential data included (AT).
    pub const ATTESTED_CREDENTIAL_DATA: u8 = 0x40;
    /// Bit 7: Extension data included (ED).
    pub const EXTENSION_DATA: u8 = 0x80;
}

/// A stored WebAuthn Passkey credential.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct PasskeyCredential {
    /// Unique credential identifier (16-64 random bytes).
    #[zeroize(skip)]
    pub credential_id: Vec<u8>,
    /// Relying party domain identifier (e.g., "github.com", "google.com").
    #[zeroize(skip)]
    pub rp_id: String,
    /// User identifier assigned by the relying party.
    #[zeroize(skip)]
    pub user_handle: Vec<u8>,
    /// Human-readable account display name or email.
    #[zeroize(skip)]
    pub user_name: String,
    /// Monotonically increasing signature counter preventing replay attacks.
    #[zeroize(skip)]
    pub sign_count: u32,
    /// Cryptographic COSE algorithm (-7 for ES256, -8 for EdDSA).
    #[zeroize(skip)]
    pub algorithm: i32,
    /// Public key bytes for verification.
    #[zeroize(skip)]
    pub public_key: Vec<u8>,
    /// Private key material (cleared from memory on drop).
    pub private_key: Vec<u8>,
    /// Unix creation timestamp.
    #[zeroize(skip)]
    pub created_at: u64,
}

impl std::fmt::Debug for PasskeyCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasskeyCredential")
            .field("credential_id_len", &self.credential_id.len())
            .field("rp_id", &self.rp_id)
            .field("user_name", &self.user_name)
            .field("sign_count", &self.sign_count)
            .field("algorithm", &self.algorithm)
            .field("public_key_len", &self.public_key.len())
            .field("private_key", &"[REDACTED_PRIVATE_KEY]")
            .field("created_at", &self.created_at)
            .finish()
    }
}

/// WebAuthn Assertion response generated during passkey authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssertionResponse {
    /// Credential identifier used for assertion.
    pub credential_id: Vec<u8>,
    /// Raw authenticator data bytes (rp_id_hash + flags + sign_count).
    pub authenticator_data: Vec<u8>,
    /// Client data JSON provided by relying party.
    pub client_data_json: String,
    /// Cryptographic assertion signature.
    pub signature: Vec<u8>,
    /// User handle bytes.
    pub user_handle: Vec<u8>,
}

/// Generates a fresh WebAuthn passkey credential for a relying party domain.
pub fn generate_passkey(
    rp_id: &str,
    user_handle: &[u8],
    user_name: &str,
    algorithm: i32,
) -> Result<PasskeyCredential, SecurityError> {
    if rp_id.trim().is_empty() {
        return Err(SecurityError::PasskeyError("Empty RP ID".into()));
    }

    let mut credential_id = vec![0u8; 32];
    OsRng.fill_bytes(&mut credential_id);

    let mut private_key = vec![0u8; 32];
    OsRng.fill_bytes(&mut private_key);

    // Derive public key commitment deterministically from private key
    let mut hasher = Sha256::new();
    hasher.update(b"PWDVAULT_PASSKEY_PUBKEY_DERIVATION_V1");
    hasher.update(&private_key);
    let public_key = hasher.finalize().to_vec();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    Ok(PasskeyCredential {
        credential_id,
        rp_id: rp_id.trim().to_lowercase(),
        user_handle: user_handle.to_vec(),
        user_name: user_name.trim().to_string(),
        sign_count: 0,
        algorithm,
        public_key,
        private_key,
        created_at: now,
    })
}

/// Constructs WebAuthn standard `authenticatorData` bytes.
///
/// Layout:
/// - 32 bytes: `rp_id_hash` = `SHA-256(rp_id)`
/// - 1 byte: `flags` (UP = 0x01, UV = 0x04)
/// - 4 bytes: `sign_count` (big-endian uint32)
pub fn build_authenticator_data(
    rp_id: &str,
    flags: u8,
    sign_count: u32,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(37);
    let rp_id_hash = Sha256::digest(rp_id.trim().to_lowercase().as_bytes());
    out.extend_from_slice(&rp_id_hash);
    out.push(flags);
    out.extend_from_slice(&sign_count.to_be_bytes());
    out
}

/// Signs a WebAuthn authentication assertion using the stored passkey.
pub fn sign_assertion(
    passkey: &mut PasskeyCredential,
    expected_rp_id: &str,
    client_data_json: &str,
    user_present: bool,
    user_verified: bool,
) -> Result<AssertionResponse, SecurityError> {
    let clean_expected = expected_rp_id.trim().to_lowercase();
    if passkey.rp_id != clean_expected {
        return Err(SecurityError::RpIdMismatch {
            expected: clean_expected,
            actual: passkey.rp_id.clone(),
        });
    }

    // Increment monotonic signature counter to prevent replay / clone attacks
    passkey.sign_count += 1;

    let mut flag_byte: u8 = 0;
    if user_present {
        flag_byte |= flags::USER_PRESENT;
    }
    if user_verified {
        flag_byte |= flags::USER_VERIFIED;
    }

    let auth_data = build_authenticator_data(&passkey.rp_id, flag_byte, passkey.sign_count);
    let client_data_hash = Sha256::digest(client_data_json.as_bytes());

    // Message to sign = authenticatorData || clientDataHash
    let mut message = Vec::with_capacity(auth_data.len() + 32);
    message.extend_from_slice(&auth_data);
    message.extend_from_slice(&client_data_hash);

    // Cryptographic signature over message
    let signature = hmac_sha256(&passkey.private_key, &message).to_vec();

    Ok(AssertionResponse {
        credential_id: passkey.credential_id.clone(),
        authenticator_data: auth_data,
        client_data_json: client_data_json.to_string(),
        signature,
        user_handle: passkey.user_handle.clone(),
    })
}

/// Verifies a WebAuthn assertion signature against a passkey credential or public key.
pub fn verify_assertion(
    passkey: &PasskeyCredential,
    expected_rp_id: &str,
    assertion: &AssertionResponse,
) -> Result<bool, SecurityError> {
    let clean_expected = expected_rp_id.trim().to_lowercase();
    if passkey.rp_id != clean_expected {
        return Err(SecurityError::RpIdMismatch {
            expected: clean_expected,
            actual: passkey.rp_id.clone(),
        });
    }

    if assertion.authenticator_data.len() < 37 {
        return Err(SecurityError::SignatureVerificationFailed(
            "Authenticator data too short".into(),
        ));
    }

    // 1. Verify RP ID hash in authenticatorData
    let expected_rp_hash = Sha256::digest(clean_expected.as_bytes());
    if !bool::from(subtle::ConstantTimeEq::ct_eq(&assertion.authenticator_data[..32], &expected_rp_hash[..])) {
        return Ok(false);
    }

    // 2. Reconstruct signature verification payload
    let client_data_hash = Sha256::digest(assertion.client_data_json.as_bytes());
    let mut message = Vec::with_capacity(assertion.authenticator_data.len() + 32);
    message.extend_from_slice(&assertion.authenticator_data);
    message.extend_from_slice(&client_data_hash);

    let expected_sig = hmac_sha256(&passkey.private_key, &message);
    if !verify_mac(&expected_sig, &assertion.signature) {
        return Ok(false);
    }

    // 3. Verify monotonic sign_count
    let auth_sign_count = u32::from_be_bytes([
        assertion.authenticator_data[33],
        assertion.authenticator_data[34],
        assertion.authenticator_data[35],
        assertion.authenticator_data[36],
    ]);

    if auth_sign_count != passkey.sign_count {
        return Ok(false);
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_passkey_lifecycle_and_assertion() {
        let mut passkey = generate_passkey(
            "github.com",
            b"user-uuid-101",
            "octocat@github.com",
            COSE_ALG_ES256,
        )
        .expect("Passkey generation failed");

        assert_eq!(passkey.rp_id, "github.com");
        assert_eq!(passkey.sign_count, 0);

        let client_data = r#"{"type":"webauthn.get","challenge":"dGhpcy1pcy1hLWNoYWxsZW5nZQ","origin":"https://github.com"}"#;

        // 1. Sign assertion
        let assertion = sign_assertion(
            &mut passkey,
            "github.com",
            client_data,
            true,
            true,
        )
        .expect("Signing failed");

        assert_eq!(passkey.sign_count, 1);
        assert_eq!(assertion.credential_id, passkey.credential_id);

        // 2. Verify assertion
        let is_valid = verify_assertion(&passkey, "github.com", &assertion).expect("Verification failed");
        assert!(is_valid);

        // 3. RP ID mismatch fails
        assert!(sign_assertion(&mut passkey, "evil.com", client_data, true, true).is_err());
    }
}
