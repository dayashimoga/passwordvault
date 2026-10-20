#![deny(unsafe_code)]
#![warn(missing_docs)]

//! Offline Emergency Recovery Kit generator and recovery key management.

use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::BackupError;

/// 256-bit emergency recovery key wrapped with Zeroize hygiene.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RecoveryKey {
    raw_bytes: [u8; 32],
}

impl RecoveryKey {
    /// Generates a fresh cryptographically secure 256-bit recovery key.
    pub fn generate() -> Result<Self, BackupError> {
        let mut raw = [0u8; 32];
        OsRng
            .try_fill_bytes(&mut raw)
            .map_err(|e| BackupError::CreateFailed(format!("CSPRNG failure: {}", e)))?;
        Ok(Self { raw_bytes: raw })
    }

    /// Creates a recovery key from raw 32-byte secret.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { raw_bytes: bytes }
    }

    /// Exposes raw secret bytes for cryptographic key derivation.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.raw_bytes
    }

    /// Formats the recovery key as a human-readable Crockford-style Base32 string
    /// grouped in 4-character tokens separated by hyphens (prefix `PV-`).
    pub fn to_formatted_string(&self) -> String {
        const CROCKFORD_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

        let mut bits = 0u32;
        let mut bit_count = 0;
        let mut encoded = String::with_capacity(64);

        for &byte in &self.raw_bytes {
            bits = (bits << 8) | (byte as u32);
            bit_count += 8;
            while bit_count >= 5 {
                bit_count -= 5;
                let idx = ((bits >> bit_count) & 0x1F) as usize;
                encoded.push(CROCKFORD_ALPHABET[idx] as char);
            }
        }

        if bit_count > 0 {
            let idx = ((bits << (5 - bit_count)) & 0x1F) as usize;
            encoded.push(CROCKFORD_ALPHABET[idx] as char);
        }

        // Group into 4-character chunks: PV-XXXX-XXXX-...
        let mut formatted = String::from("PV");
        for (i, c) in encoded.chars().enumerate() {
            if i % 4 == 0 {
                formatted.push('-');
            }
            formatted.push(c);
        }

        formatted
    }

    /// Parses and validates a formatted Crockford-style recovery key string.
    pub fn parse(input: &str) -> Result<Self, BackupError> {
        let mut clean = input.trim().replace(['-', ' '], "");
        if clean.len() == 54
            && (clean.starts_with("PV")
                || clean.starts_with("pv")
                || clean.starts_with("Pv")
                || clean.starts_with("pV"))
        {
            clean = clean[2..].to_string();
        } else if clean.starts_with("PV-") || clean.starts_with("pv-") {
            clean = clean[3..].to_string();
        }

        if clean.is_empty() {
            return Err(BackupError::VerifyFailed(
                "Recovery key string is empty".to_string(),
            ));
        }

        let mut bits = 0u32;
        let mut bit_count = 0;
        let mut bytes = Vec::with_capacity(32);

        for ch in clean.chars() {
            let val: i32 = match ch.to_ascii_uppercase() {
                '0' | 'O' => 0,
                '1' | 'I' | 'L' => 1,
                '2' => 2,
                '3' => 3,
                '4' => 4,
                '5' => 5,
                '6' => 6,
                '7' => 7,
                '8' => 8,
                '9' => 9,
                'A' => 10,
                'B' => 11,
                'C' => 12,
                'D' => 13,
                'E' => 14,
                'F' => 15,
                'G' => 16,
                'H' => 17,
                'J' => 18,
                'K' => 19,
                'M' => 20,
                'N' => 21,
                'P' => 22,
                'Q' => 23,
                'R' => 24,
                'S' => 25,
                'T' => 26,
                'V' => 27,
                'W' => 28,
                'X' => 29,
                'Y' => 30,
                'Z' => 31,
                _ => -1,
            };

            if val < 0 {
                return Err(BackupError::VerifyFailed(format!(
                    "Invalid character in recovery key: '{}'",
                    ch
                )));
            }

            bits = (bits << 5) | (val as u32);
            bit_count += 5;

            if bit_count >= 8 {
                bit_count -= 8;
                bytes.push(((bits >> bit_count) & 0xFF) as u8);
                if bytes.len() == 32 {
                    break;
                }
            }
        }

        if bytes.len() != 32 {
            return Err(BackupError::VerifyFailed(format!(
                "Invalid recovery key length: decoded {} bytes, expected 32",
                bytes.len()
            )));
        }

        let mut raw = [0u8; 32];
        raw.copy_from_slice(&bytes[..32]);
        Ok(Self { raw_bytes: raw })
    }
}

/// Metadata payload representing an Emergency Recovery Kit document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryKitDocument {
    /// Friendly name of the encrypted vault.
    pub vault_name: String,
    /// Unix timestamp of kit generation.
    pub created_at: u64,
    /// Formatted Crockford Base32 recovery key.
    pub formatted_key: String,
    /// Instructions for physical security and storage.
    pub storage_instructions: String,
}

impl RecoveryKitDocument {
    /// Creates a new Emergency Recovery Kit document for a vault.
    pub fn new(vault_name: &str, recovery_key: &RecoveryKey) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            vault_name: vault_name.to_string(),
            created_at: now,
            formatted_key: recovery_key.to_formatted_string(),
            storage_instructions: "Print this document and store it in a secure, fireproof safe or safety deposit box. Do NOT save this key in cloud storage, email, or unencrypted local drives. Anyone possessing this key and your encrypted vault archive can decrypt all credentials without knowing your master passphrase.".to_string(),
        }
    }

    /// Renders a printable Markdown document.
    pub fn render_markdown(&self) -> String {
        format!(
            "# PWDVAULT EMERGENCY RECOVERY KIT\n\n\
            > **CRITICAL SECURITY NOTICE**: This recovery key grants administrative access to decrypt your vault without your master passphrase. Keep it strictly offline.\n\n\
            - **Vault Name**: {}\n\
            - **Created At**: {} (UTC)\n\
            - **Format**: Crockford Base32 (256-bit entropy)\n\n\
            ## YOUR RECOVERY KEY\n\n\
            ```\n\
            {}\n\
            ```\n\n\
            ## Storage Guidelines\n\
            {}\n\n\
            ## How to Restore\n\
            1. Open PwdVault on your device.\n\
            2. Select 'Restore from Backup' or 'Emergency Unlock'.\n\
            3. Choose your encrypted `.vault.v1` or `.vaultbak` archive.\n\
            4. Enter the recovery key shown above exactly as formatted.\n\
            5. Set a new master passphrase and generate a fresh recovery kit immediately.\n",
            self.vault_name,
            self.created_at,
            self.formatted_key,
            self.storage_instructions
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recovery_key_generation_and_format() {
        let key = RecoveryKey::generate().expect("key generation failed");
        let formatted = key.to_formatted_string();

        assert!(formatted.starts_with("PV-"));
        assert!(formatted.len() > 50);

        let parsed = RecoveryKey::parse(&formatted).expect("parse failed");
        assert_eq!(key.as_bytes(), parsed.as_bytes());
    }

    #[test]
    fn test_recovery_key_parse_tolerant_casing_and_hyphens() {
        let key = RecoveryKey::generate().unwrap();
        let formatted = key.to_formatted_string();

        // Test with lowercase and without PV- prefix
        let lower = formatted.to_lowercase();
        let parsed1 = RecoveryKey::parse(&lower).unwrap();
        assert_eq!(key.as_bytes(), parsed1.as_bytes());

        // Test with removed hyphens
        let no_hyphens = formatted.replace('-', "");
        let parsed2 = RecoveryKey::parse(&no_hyphens).unwrap();
        assert_eq!(key.as_bytes(), parsed2.as_bytes());
    }

    #[test]
    fn test_recovery_kit_document_render() {
        let key = RecoveryKey::generate().unwrap();
        let doc = RecoveryKitDocument::new("Personal Vault", &key);
        let md = doc.render_markdown();

        assert!(md.contains("PWDVAULT EMERGENCY RECOVERY KIT"));
        assert!(md.contains("Personal Vault"));
        assert!(md.contains(&key.to_formatted_string()));
    }
}
