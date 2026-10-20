#![deny(unsafe_code)]
#![warn(missing_docs)]

//! Local vault security health audit and privacy-preserving k-Anonymity breach check.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use pwdvault_generator::{estimate_crack_time, StrengthRating};
use pwdvault_vault::{ItemCategory, VaultItem, VaultPayload};

use crate::sha1::Sha1;

/// Privacy-preserving k-Anonymity breach query info.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BreachQuery {
    /// First 5 hex characters of SHA-1(password) sent to HIBP API (e.g., "5BAA6").
    pub prefix: String,
    /// Remaining 35 hex characters checked purely locally.
    pub suffix: String,
}

/// Generates a k-anonymity 5-character prefix and 35-character suffix from a password.
///
/// Invariant: The password and full hash are NEVER transmitted over the wire.
pub fn prepare_breach_query(password: &str) -> BreachQuery {
    let digest = Sha1::digest(password.as_bytes());
    let hex: String = digest.iter().map(|b| format!("{:02X}", b)).collect();

    BreachQuery {
        prefix: hex[..5].to_string(),
        suffix: hex[5..].to_string(),
    }
}

/// Checks whether the local 35-char suffix exists in the range API response body.
///
/// Returns `Some(breach_count)` if breached, or `None` if safe.
pub fn check_suffix_in_range_response(suffix: &str, response_body: &str) -> Option<u64> {
    let clean_target = suffix.trim().to_uppercase();

    for line in response_body.lines() {
        let trimmed = line.trim();
        if let Some((range_suffix, count_str)) = trimmed.split_once(':') {
            if range_suffix.trim().to_uppercase() == clean_target {
                if let Ok(count) = count_str.trim().parse::<u64>() {
                    return Some(count);
                }
                return Some(1);
            }
        }
    }

    None
}

/// A group of items sharing an identical password.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReusedPasswordGroup {
    /// Number of accounts sharing this exact password.
    pub count: usize,
    /// List of item titles sharing the password.
    pub item_titles: Vec<String>,
    /// List of item IDs sharing the password.
    pub item_ids: Vec<String>,
}

/// Summary of a weak password finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeakPasswordFinding {
    /// Item ID.
    pub item_id: String,
    /// Item title.
    pub title: String,
    /// Shannon entropy in bits.
    pub entropy_bits: u32,
    /// Estimated crack time rating (e.g. "Instant", "Very Weak").
    pub rating: String,
    /// Diagnostic reason (e.g., "Length < 12 characters", "Low entropy").
    pub reason: String,
}

/// Summary of an aged / stale password.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StalePasswordFinding {
    /// Item ID.
    pub item_id: String,
    /// Item title.
    pub title: String,
    /// Days since last password update.
    pub age_days: u64,
}

/// Comprehensive vault health audit report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultAuditReport {
    /// Total active non-trashed items inspected.
    pub total_active_items: usize,
    /// Overall security hygiene score from 0 to 100.
    pub health_score: u32,
    /// Groups of duplicate / reused passwords.
    pub reused_groups: Vec<ReusedPasswordGroup>,
    /// Items with weak passwords.
    pub weak_items: Vec<WeakPasswordFinding>,
    /// Items unmodified for over 90 days.
    pub stale_items: Vec<StalePasswordFinding>,
    /// Login items missing two-factor authentication (TOTP or passkey).
    pub missing_2fa_items: Vec<String>,
    /// Actionable security recommendations.
    pub recommendations: Vec<String>,
}

/// Performs a comprehensive cryptographic and operational audit of a vault payload.
pub fn audit_vault(payload: &VaultPayload) -> VaultAuditReport {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let active_items: Vec<&VaultItem> = payload
        .items
        .iter()
        .filter(|i| i.trashed_at.is_none())
        .collect();
    let total_active_items = active_items.len();

    // 1. Password reuse detection
    let mut password_map: HashMap<&str, Vec<&VaultItem>> = HashMap::new();
    for item in &active_items {
        if let Some(ref pwd) = item.password {
            if !pwd.is_empty() {
                password_map.entry(pwd.as_str()).or_default().push(item);
            }
        }
    }

    let mut reused_groups = Vec::new();
    for items in password_map.values() {
        if items.len() > 1 {
            reused_groups.push(ReusedPasswordGroup {
                count: items.len(),
                item_titles: items.iter().map(|i| i.title.clone()).collect(),
                item_ids: items.iter().map(|i| i.id.clone()).collect(),
            });
        }
    }

    // 2. Weak passwords detection
    let mut weak_items = Vec::new();
    for item in &active_items {
        if let Some(ref pwd) = item.password {
            if !pwd.is_empty() {
                let estimate = estimate_crack_time(pwd);
                let mut reasons = Vec::new();

                if pwd.len() < 12 {
                    reasons.push(format!(
                        "Length is only {} characters (min 14 recommended)",
                        pwd.len()
                    ));
                }
                if estimate.entropy_bits < 50 {
                    reasons.push(format!("Low entropy ({} bits)", estimate.entropy_bits));
                }
                if estimate.rating <= StrengthRating::Weak {
                    reasons.push(format!("Strength rating is {:?}", estimate.rating));
                }

                if !reasons.is_empty() {
                    weak_items.push(WeakPasswordFinding {
                        item_id: item.id.clone(),
                        title: item.title.clone(),
                        entropy_bits: estimate.entropy_bits,
                        rating: format!("{:?}", estimate.rating),
                        reason: reasons.join("; "),
                    });
                }
            }
        }
    }

    // 3. Stale passwords detection (older than 90 days)
    const STALE_THRESHOLD_SECS: u64 = 90 * 86400;
    let mut stale_items = Vec::new();
    for item in &active_items {
        if item.category == ItemCategory::Login
            && item.password.is_some()
            && now > item.updated_at
            && (now - item.updated_at) > STALE_THRESHOLD_SECS
        {
            let age_days = (now - item.updated_at) / 86400;
            stale_items.push(StalePasswordFinding {
                item_id: item.id.clone(),
                title: item.title.clone(),
                age_days,
            });
        }
    }

    // 4. Missing 2FA detection on logins
    let mut missing_2fa_items = Vec::new();
    for item in &active_items {
        if item.category == ItemCategory::Login {
            let has_totp = item.totp_seed.is_some()
                || item.custom_fields.iter().any(|f| {
                    f.name.to_lowercase().contains("totp")
                        || f.name.to_lowercase().contains("otp")
                        || f.value.starts_with("otpauth://")
                })
                || item.notes.as_deref().unwrap_or("").contains("otpauth://");

            let has_passkey = item
                .custom_fields
                .iter()
                .any(|f| f.name.to_lowercase().contains("passkey"));

            if !has_totp && !has_passkey {
                missing_2fa_items.push(item.title.clone());
            }
        }
    }

    // 5. Score calculation (0 to 100)
    let mut score: i32 = 100;
    // Deductions:
    let reused_deduction = (reused_groups.len() as i32 * 15).min(35);
    let weak_deduction = (weak_items.len() as i32 * 10).min(30);
    let stale_deduction = (stale_items.len() as i32 * 2).min(20);
    let missing_2fa_deduction = (missing_2fa_items.len() as i32).min(15);

    score -= reused_deduction;
    score -= weak_deduction;
    score -= stale_deduction;
    score -= missing_2fa_deduction;

    let final_score = score.clamp(0, 100) as u32;

    // 6. Actionable recommendations
    let mut recommendations = Vec::new();
    if !reused_groups.is_empty() {
        recommendations.push(format!(
            "Eliminate {} reused password group(s). Create unique passwords for each service.",
            reused_groups.len()
        ));
    }
    if !weak_items.is_empty() {
        recommendations.push(format!(
            "Upgrade {} weak password(s) to 20+ character passwords or 6-word passphrases.",
            weak_items.len()
        ));
    }
    if !missing_2fa_items.is_empty() {
        recommendations.push(format!(
            "Add TOTP or Passkeys to {} login account(s) for two-factor protection.",
            missing_2fa_items.len()
        ));
    }
    if !stale_items.is_empty() {
        recommendations.push(format!(
            "Review {} login(s) unchanged for over 90 days.",
            stale_items.len()
        ));
    }
    if recommendations.is_empty() {
        recommendations.push("Excellent security hygiene! All active items meet best-practice cryptographic standards.".into());
    }

    VaultAuditReport {
        total_active_items,
        health_score: final_score,
        reused_groups,
        weak_items,
        stale_items,
        missing_2fa_items,
        recommendations,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_k_anonymity_prefix_query_and_response_parsing() {
        // "password" SHA1 is 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        let query = prepare_breach_query("password");
        assert_eq!(query.prefix, "5BAA6");
        assert_eq!(query.suffix, "1E4C9B93F3F0682250B6CF8331B7EE68FD8");

        let mock_api_body = "0018A45C4D1DEF81644B54AB7F969B88D65:3\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:9654321\r\n00D4F6E8FA6ECC350A20C81C3D9D80831E3:1\r\n";

        let count = check_suffix_in_range_response(&query.suffix, mock_api_body);
        assert_eq!(count, Some(9654321));

        // Unknown suffix
        assert_eq!(
            check_suffix_in_range_response("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", mock_api_body),
            None
        );
    }

    #[test]
    fn test_vault_health_audit_detection() {
        fn create_test_item(
            id: &str,
            title: &str,
            password: Option<&str>,
            updated_at: u64,
        ) -> VaultItem {
            VaultItem {
                id: id.to_string(),
                title: title.to_string(),
                category: ItemCategory::Login,
                username: Some("user@test.com".into()),
                password: password.map(String::from),
                urls: vec!["https://example.com".into()],
                notes: None,
                totp_seed: None,
                tags: Vec::new(),
                favorite: false,
                custom_fields: Vec::new(),
                attachments: Vec::new(),
                revision_history: Vec::new(),
                trashed_at: None,
                created_at: updated_at - 1000,
                updated_at,
            }
        }

        let now = 1700000000;
        let payload = VaultPayload {
            schema_version: 1,
            vault_name: "Audit Test".into(),
            created_at: now - 100000,
            updated_at: now,
            items: vec![
                create_test_item(
                    "item-1",
                    "Service 1",
                    Some("reused-pwd-123"),
                    now - (100 * 86400),
                ),
                create_test_item("item-2", "Service 2", Some("reused-pwd-123"), now),
                create_test_item("item-3", "Service 3", Some("short"), now),
            ],
        };

        let report = audit_vault(&payload);
        assert_eq!(report.total_active_items, 3);
        assert_eq!(report.reused_groups.len(), 1);
        assert_eq!(report.weak_items.len(), 1);
        assert!(report.health_score < 100);
        assert!(!report.recommendations.is_empty());
    }
}
