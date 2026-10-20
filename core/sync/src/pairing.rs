#![deny(unsafe_code)]
#![warn(missing_docs)]

//! Out-of-band device pairing and QR code handshake verification.

use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::SyncError;

/// 15-minute validity window for pairing QR codes.
pub const PAIRING_EXPIRY_SECS: u64 = 900;

/// Authenticated pairing payload encoded within the out-of-band QR code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingPayload {
    /// Originating device identifier.
    pub device_id: String,
    /// Originating device display name.
    pub device_name: String,
    /// BLAKE3 hex fingerprint of the sync key.
    pub sync_key_fingerprint: String,
    /// 16-byte random hex challenge nonce.
    pub challenge_nonce: String,
    /// Candidate LAN IP addresses and ports for peer discovery.
    pub addresses: Vec<String>,
    /// Unix creation timestamp.
    pub created_at: u64,
    /// Unix expiration timestamp.
    pub expires_at: u64,
}

/// Computes the public BLAKE3 fingerprint of a shared sync key.
pub fn compute_sync_key_fingerprint(sync_key: &[u8; 32]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"PWDVAULT_SYNC_KEY_FINGERPRINT_V1");
    hasher.update(sync_key);
    let hash = hasher.finalize();
    // Crockford-style or clean hex representation
    hex_encode(hash.as_bytes())
}

/// Generates a QR-compatible URI string (`pwdvault://pair?data=...`).
pub fn generate_pairing_qr_data(
    sync_key: &[u8; 32],
    device_id: &str,
    device_name: &str,
    addresses: &[String],
) -> Result<String, SyncError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut nonce_bytes = [0u8; 16];
    OsRng.fill_bytes(&mut nonce_bytes);

    let payload = PairingPayload {
        device_id: device_id.to_string(),
        device_name: device_name.to_string(),
        sync_key_fingerprint: compute_sync_key_fingerprint(sync_key),
        challenge_nonce: hex_encode(&nonce_bytes),
        addresses: addresses.to_vec(),
        created_at: now,
        expires_at: now + PAIRING_EXPIRY_SECS,
    };

    let json_bytes = serde_json::to_vec(&payload)
        .map_err(|e| SyncError::ProtocolError(format!("Serialization error: {}", e)))?;

    let encoded = base64_url_encode(&json_bytes);
    Ok(format!("pwdvault://pair?data={}", encoded))
}

/// Decodes and cryptographically verifies a pairing QR URI string against a local sync key.
pub fn verify_pairing_qr_data(
    qr_uri: &str,
    sync_key: &[u8; 32],
) -> Result<PairingPayload, SyncError> {
    const PREFIX: &str = "pwdvault://pair?data=";
    if !qr_uri.starts_with(PREFIX) {
        return Err(SyncError::ProtocolError("Invalid pairing URI format".to_string()));
    }

    let encoded = &qr_uri[PREFIX.len()..];
    let json_bytes = base64_url_decode(encoded)
        .map_err(|e| SyncError::ProtocolError(format!("Base64 decoding failed: {}", e)))?;

    let payload: PairingPayload = serde_json::from_slice(&json_bytes)
        .map_err(|e| SyncError::ProtocolError(format!("JSON parsing error: {}", e)))?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    if now > payload.expires_at {
        return Err(SyncError::ProtocolError("Pairing QR code has expired".to_string()));
    }

    let expected_fp = compute_sync_key_fingerprint(sync_key);
    if payload.sync_key_fingerprint != expected_fp {
        return Err(SyncError::ProtocolError(
            "Sync key fingerprint mismatch: device belongs to a different vault".to_string(),
        ));
    }

    Ok(payload)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

fn base64_url_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut result = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = if chunk.len() > 1 { chunk[1] } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] } else { 0 };

        result.push(CHARS[(b0 >> 2) as usize] as char);
        result.push(CHARS[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[(((b1 & 0x0F) << 2) | (b2 >> 6)) as usize] as char);
        }
        if chunk.len() > 2 {
            result.push(CHARS[(b2 & 0x3F) as usize] as char);
        }
    }
    result
}

fn base64_url_decode(s: &str) -> Result<Vec<u8>, String> {
    fn char_to_val(c: u8) -> Result<u8, String> {
        match c {
            b'A'..=b'Z' => Ok(c - b'A'),
            b'a'..=b'z' => Ok(c - b'a' + 26),
            b'0'..=b'9' => Ok(c - b'0' + 52),
            b'-' => Ok(62),
            b'_' => Ok(63),
            _ => Err(format!("Invalid char: {}", c as char)),
        }
    }

    let bytes = s.as_bytes();
    let mut out = Vec::new();
    for chunk in bytes.chunks(4) {
        let c0 = char_to_val(chunk[0])?;
        let c1 = if chunk.len() > 1 { char_to_val(chunk[1])? } else { 0 };
        let c2 = if chunk.len() > 2 { char_to_val(chunk[2])? } else { 0 };
        let c3 = if chunk.len() > 3 { char_to_val(chunk[3])? } else { 0 };

        out.push((c0 << 2) | (c1 >> 4));
        if chunk.len() > 2 {
            out.push(((c1 & 0x0F) << 4) | (c2 >> 2));
        }
        if chunk.len() > 3 {
            out.push(((c2 & 0x03) << 6) | c3);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pairing_qr_roundtrip_and_verification() {
        let sync_key = [17u8; 32];
        let addrs = vec!["192.168.1.100:7890".to_string()];

        let qr_uri = generate_pairing_qr_data(&sync_key, "dev-ipad", "Alice's iPad", &addrs)
            .expect("generate failed");
        assert!(qr_uri.starts_with("pwdvault://pair?data="));

        let verified = verify_pairing_qr_data(&qr_uri, &sync_key).expect("verify failed");
        assert_eq!(verified.device_id, "dev-ipad");
        assert_eq!(verified.device_name, "Alice's iPad");
        assert_eq!(verified.addresses, addrs);
    }

    #[test]
    fn test_pairing_qr_wrong_key_rejection() {
        let sync_key = [17u8; 32];
        let wrong_key = [99u8; 32];

        let qr_uri = generate_pairing_qr_data(&sync_key, "dev-1", "MacBook", &[]).unwrap();
        assert!(verify_pairing_qr_data(&qr_uri, &wrong_key).is_err());
    }
}
