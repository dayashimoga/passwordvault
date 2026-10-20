#![deny(unsafe_code)]
#![warn(missing_docs)]

//! RFC 6238 Time-Based One-Time Password (TOTP) authenticator engine.
//!
//! Provides Base32 decoding, dynamic truncation, time remaining calculation,
//! drift tolerance verification, and `otpauth://totp/` URI parsing and formatting.

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::SecurityError;
use crate::hmac::{hmac_sha1, hmac_sha256, hmac_sha512};

/// Supported HMAC hashing algorithms for TOTP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum TotpAlgorithm {
    /// HMAC-SHA1 (default per RFC 6238 compatibility with Google Authenticator).
    #[default]
    Sha1,
    /// HMAC-SHA256.
    Sha256,
    /// HMAC-SHA512.
    Sha512,
}

impl TotpAlgorithm {
    /// Parses an algorithm name from a string (case-insensitive).
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_uppercase().as_str() {
            "SHA1" | "SHA-1" => Some(TotpAlgorithm::Sha1),
            "SHA256" | "SHA-256" => Some(TotpAlgorithm::Sha256),
            "SHA512" | "SHA-512" => Some(TotpAlgorithm::Sha512),
            _ => None,
        }
    }

    /// Returns string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            TotpAlgorithm::Sha1 => "SHA1",
            TotpAlgorithm::Sha256 => "SHA256",
            TotpAlgorithm::Sha512 => "SHA512",
        }
    }
}

/// Configuration parameters defining a TOTP credential.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct TotpConfig {
    /// Raw secret key bytes (protected with zeroization on drop).
    pub secret: Vec<u8>,
    /// Time-step interval in seconds (default 30).
    #[zeroize(skip)]
    pub period_seconds: u32,
    /// Number of output digits (6, 7, or 8; default 6).
    #[zeroize(skip)]
    pub digits: u32,
    /// Hashing algorithm (SHA-1, SHA-256, or SHA-512).
    #[zeroize(skip)]
    pub algorithm: TotpAlgorithm,
    /// Optional service issuer name (e.g., "GitHub", "AWS").
    #[zeroize(skip)]
    pub issuer: Option<String>,
    /// Optional account username or email (e.g., "dev@antigravity.internal").
    #[zeroize(skip)]
    pub account_name: Option<String>,
}

impl Default for TotpConfig {
    fn default() -> Self {
        Self {
            secret: Vec::new(),
            period_seconds: 30,
            digits: 6,
            algorithm: TotpAlgorithm::Sha1,
            issuer: None,
            account_name: None,
        }
    }
}

impl std::fmt::Debug for TotpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TotpConfig")
            .field("secret", &"[REDACTED_SECRET]")
            .field("period_seconds", &self.period_seconds)
            .field("digits", &self.digits)
            .field("algorithm", &self.algorithm)
            .field("issuer", &self.issuer)
            .field("account_name", &self.account_name)
            .finish()
    }
}

/// Decodes standard RFC 4648 Base32 strings (with optional Crockford 0/O, 1/I/L tolerance).
pub fn decode_base32(input: &str) -> Result<Vec<u8>, SecurityError> {
    let clean: String = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-' && *c != '=')
        .collect();

    if clean.is_empty() {
        return Err(SecurityError::InvalidBase32("Empty secret".into()));
    }

    let mut bits: u32 = 0;
    let mut bit_count: u32 = 0;
    let mut out = Vec::new();

    for ch in clean.chars() {
        let val = match ch.to_ascii_uppercase() {
            'A' => 0,
            'B' => 1,
            'C' => 2,
            'D' => 3,
            'E' => 4,
            'F' => 5,
            'G' => 6,
            'H' => 7,
            'I' => 8,
            'J' => 9,
            'K' => 10,
            'L' => 11,
            'M' => 12,
            'N' => 13,
            'O' => 14,
            'P' => 15,
            'Q' => 16,
            'R' => 17,
            'S' => 18,
            'T' => 19,
            'U' => 20,
            'V' => 21,
            'W' => 22,
            'X' => 23,
            'Y' => 24,
            'Z' => 25,
            '2' => 26,
            '3' => 27,
            '4' => 28,
            '5' => 29,
            '6' => 30,
            '7' => 31,
            // User typo tolerance:
            '0' => 14, // '0' treated as 'O'
            '1' => 8,  // '1' treated as 'I'
            _ => return Err(SecurityError::InvalidBase32(format!("Invalid character: '{}'", ch))),
        };

        bits = (bits << 5) | val;
        bit_count += 5;

        if bit_count >= 8 {
            bit_count -= 8;
            out.push((bits >> bit_count) as u8);
            bits &= (1 << bit_count) - 1;
        }
    }

    Ok(out)
}

/// Encodes raw bytes into standard RFC 4648 Base32.
pub fn encode_base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut result = String::new();
    let mut bits: u32 = 0;
    let mut bit_count: u32 = 0;

    for &b in bytes {
        bits = (bits << 8) | (b as u32);
        bit_count += 8;
        while bit_count >= 5 {
            bit_count -= 5;
            let idx = (bits >> bit_count) & 0x1F;
            result.push(ALPHABET[idx as usize] as char);
        }
    }

    if bit_count > 0 {
        let idx = (bits << (5 - bit_count)) & 0x1F;
        result.push(ALPHABET[idx as usize] as char);
    }

    result
}

/// Generates a TOTP code for a specific timestamp (in seconds since UNIX epoch).
pub fn generate_totp(config: &TotpConfig, timestamp_secs: u64) -> String {
    let period = if config.period_seconds == 0 {
        30
    } else {
        config.period_seconds as u64
    };
    let counter = timestamp_secs / period;
    let counter_bytes = counter.to_be_bytes();

    let hmac_bytes: Vec<u8> = match config.algorithm {
        TotpAlgorithm::Sha1 => hmac_sha1(&config.secret, &counter_bytes).to_vec(),
        TotpAlgorithm::Sha256 => hmac_sha256(&config.secret, &counter_bytes).to_vec(),
        TotpAlgorithm::Sha512 => hmac_sha512(&config.secret, &counter_bytes).to_vec(),
    };

    // Dynamic truncation (RFC 4226 Section 5.4)
    let offset = (hmac_bytes[hmac_bytes.len() - 1] & 0x0F) as usize;
    let binary = ((hmac_bytes[offset] as u32 & 0x7F) << 24)
        | ((hmac_bytes[offset + 1] as u32 & 0xFF) << 16)
        | ((hmac_bytes[offset + 2] as u32 & 0xFF) << 8)
        | (hmac_bytes[offset + 3] as u32 & 0xFF);

    let digits = match config.digits {
        7 => 7,
        8 => 8,
        _ => 6,
    };
    let modulo = 10u32.pow(digits);
    let code = binary % modulo;

    format!("{:0width$}", code, width = digits as usize)
}

/// Calculates remaining seconds in the current TOTP validity window.
pub fn time_remaining(config: &TotpConfig, timestamp_secs: u64) -> u64 {
    let period = if config.period_seconds == 0 {
        30
    } else {
        config.period_seconds as u64
    };
    period - (timestamp_secs % period)
}

/// Verifies a user-supplied TOTP code with configurable drift tolerance (default +/- 1 step).
pub fn verify_totp(
    config: &TotpConfig,
    user_code: &str,
    timestamp_secs: u64,
    tolerance_steps: i64,
) -> bool {
    let period = if config.period_seconds == 0 {
        30
    } else {
        config.period_seconds as i64
    };
    let current_step = (timestamp_secs as i64) / period;
    let clean_code = user_code.trim();

    for step_offset in -tolerance_steps..=tolerance_steps {
        let step = current_step + step_offset;
        if step < 0 {
            continue;
        }
        let step_time = (step * period) as u64;
        let expected = generate_totp(config, step_time);
        if subtle::ConstantTimeEq::ct_eq(expected.as_bytes(), clean_code.as_bytes()).into() {
            return true;
        }
    }

    false
}

/// Parses an `otpauth://totp/...` URI into a `TotpConfig`.
pub fn parse_otpauth_uri(uri_str: &str) -> Result<TotpConfig, SecurityError> {
    let trimmed = uri_str.trim();
    if !trimmed.to_lowercase().starts_with("otpauth://totp/") {
        return Err(SecurityError::InvalidOtpUri(
            "URI must start with otpauth://totp/".into(),
        ));
    }

    let without_prefix = &trimmed["otpauth://totp/".len()..];
    let (label_part, query_part) = match without_prefix.split_once('?') {
        Some((l, q)) => (l, q),
        None => (without_prefix, ""),
    };

    let mut config = TotpConfig::default();

    // Parse label (e.g. "GitHub:dev@antigravity" or "dev@antigravity")
    let decoded_label = urlencoding_decode(label_part);
    if let Some((issuer_prefix, account)) = decoded_label.split_once(':') {
        config.issuer = Some(issuer_prefix.trim().to_string());
        config.account_name = Some(account.trim().to_string());
    } else if !decoded_label.is_empty() {
        config.account_name = Some(decoded_label.trim().to_string());
    }

    // Parse query parameters
    let mut secret_found = false;
    for param in query_part.split('&') {
        if let Some((k, v)) = param.split_once('=') {
            let key = k.trim().to_lowercase();
            let val = urlencoding_decode(v.trim());
            match key.as_str() {
                "secret" => {
                    config.secret = decode_base32(&val)?;
                    secret_found = true;
                }
                "issuer" => {
                    config.issuer = Some(val);
                }
                "algorithm" => {
                    if let Some(alg) = TotpAlgorithm::parse(&val) {
                        config.algorithm = alg;
                    }
                }
                "digits" => {
                    if let Ok(d) = val.parse::<u32>() {
                        if d == 6 || d == 7 || d == 8 {
                            config.digits = d;
                        }
                    }
                }
                "period" => {
                    if let Ok(p) = val.parse::<u32>() {
                        if p > 0 && p <= 300 {
                            config.period_seconds = p;
                        }
                    }
                }
                _ => {}
            }
        }
    }

    if !secret_found || config.secret.is_empty() {
        return Err(SecurityError::InvalidOtpUri("Missing required 'secret' parameter".into()));
    }

    Ok(config)
}

/// Formats a `TotpConfig` into an `otpauth://totp/` URI.
pub fn format_otpauth_uri(config: &TotpConfig) -> String {
    let secret_b32 = encode_base32(&config.secret);
    let label = match (&config.issuer, &config.account_name) {
        (Some(iss), Some(acc)) => format!("{}:{}", urlencoding_encode(iss), urlencoding_encode(acc)),
        (None, Some(acc)) => urlencoding_encode(acc),
        (Some(iss), None) => urlencoding_encode(iss),
        (None, None) => "Account".to_string(),
    };

    let mut uri = format!(
        "otpauth://totp/{}?secret={}&algorithm={}&digits={}&period={}",
        label,
        secret_b32,
        config.algorithm.as_str(),
        config.digits,
        config.period_seconds
    );

    if let Some(ref iss) = config.issuer {
        uri.push_str("&issuer=");
        uri.push_str(&urlencoding_encode(iss));
    }

    uri
}

/// Convenience function to get the current TOTP code and time remaining.
pub fn current_totp(config: &TotpConfig) -> (String, u64) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    (generate_totp(config, now), time_remaining(config, now))
}

fn urlencoding_decode(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '%' {
            let h1 = chars.next().unwrap_or('0');
            let h2 = chars.next().unwrap_or('0');
            let hex_str = format!("{}{}", h1, h2);
            if let Ok(byte) = u8::from_str_radix(&hex_str, 16) {
                out.push(byte as char);
            }
        } else if c == '+' {
            out.push(' ');
        } else {
            out.push(c);
        }
    }
    out
}

fn urlencoding_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' || b == b'~' {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc6238_standard_test_vectors() {
        // Test vectors from RFC 6238 Appendix B
        // 20-byte key for SHA1
        let sha1_key = b"12345678901234567890".to_vec();
        // 32-byte key for SHA256
        let sha256_key = b"12345678901234567890123456789012".to_vec();
        // 64-byte key for SHA512
        let sha512_key = b"1234567890123456789012345678901234567890123456789012345678901234".to_vec();

        let cfg_sha1_8 = TotpConfig {
            secret: sha1_key.clone(),
            period_seconds: 30,
            digits: 8,
            algorithm: TotpAlgorithm::Sha1,
            issuer: None,
            account_name: None,
        };

        let cfg_sha256_8 = TotpConfig {
            secret: sha256_key,
            period_seconds: 30,
            digits: 8,
            algorithm: TotpAlgorithm::Sha256,
            issuer: None,
            account_name: None,
        };

        let cfg_sha512_8 = TotpConfig {
            secret: sha512_key,
            period_seconds: 30,
            digits: 8,
            algorithm: TotpAlgorithm::Sha512,
            issuer: None,
            account_name: None,
        };

        // Time = 59
        assert_eq!(generate_totp(&cfg_sha1_8, 59), "94287082");
        assert_eq!(generate_totp(&cfg_sha256_8, 59), "46119246");
        assert_eq!(generate_totp(&cfg_sha512_8, 59), "90693936");

        // Time = 1111111109
        assert_eq!(generate_totp(&cfg_sha1_8, 1111111109), "07081804");
        assert_eq!(generate_totp(&cfg_sha256_8, 1111111109), "68084774");
        assert_eq!(generate_totp(&cfg_sha512_8, 1111111109), "25091201");

        // Time = 1234567890
        assert_eq!(generate_totp(&cfg_sha1_8, 1234567890), "89005924");
        assert_eq!(generate_totp(&cfg_sha256_8, 1234567890), "91819424");
        assert_eq!(generate_totp(&cfg_sha512_8, 1234567890), "93441116");


        // 6-digit variant at 1234567890
        let cfg_sha1_6 = TotpConfig {
            secret: sha1_key,
            period_seconds: 30,
            digits: 6,
            algorithm: TotpAlgorithm::Sha1,
            issuer: None,
            account_name: None,
        };
        assert_eq!(generate_totp(&cfg_sha1_6, 1234567890), "005924");

    }

    #[test]
    fn test_otpauth_uri_roundtrip() {
        let original_uri = "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=6&period=30&issuer=GitHub";
        let config = parse_otpauth_uri(original_uri).expect("URI parse failed");

        assert_eq!(config.issuer, Some("GitHub".to_string()));
        assert_eq!(config.account_name, Some("alice".to_string()));
        assert_eq!(config.digits, 6);
        assert_eq!(config.period_seconds, 30);
        assert_eq!(config.algorithm, TotpAlgorithm::Sha1);

        // Verification tolerance
        let code = generate_totp(&config, 1000);
        assert!(verify_totp(&config, &code, 1000, 1));
        assert!(verify_totp(&config, &code, 1025, 1)); // within 1 step
        assert!(!verify_totp(&config, &code, 1100, 1)); // exceeded drift window
    }
}
