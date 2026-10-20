#![deny(unsafe_code)]
#![warn(missing_docs)]

//! Importer for 1Password 1PUX (JSON) and CSV exports.

use pwdvault_vault::{CustomField, FieldType, ItemCategory, VaultItem};
use serde::Deserialize;

use crate::csv::CsvImporter;
use crate::ImportError;

#[derive(Debug, Deserialize)]
struct OnePasswordLoginField {
    value: Option<String>,
    designation: Option<String>,
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OnePasswordSectionField {
    title: Option<String>,
    value: Option<String>,
    #[serde(rename = "k")]
    kind: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OnePasswordSection {
    fields: Option<Vec<OnePasswordSectionField>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OnePasswordDetails {
    login_fields: Option<Vec<OnePasswordLoginField>>,
    sections: Option<Vec<OnePasswordSection>>,
    notes_plain: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OnePasswordOverview {
    title: Option<String>,
    url: Option<String>,
    tags: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OnePasswordItem {
    category: Option<String>,
    overview: Option<OnePasswordOverview>,
    details: Option<OnePasswordDetails>,
}

#[derive(Debug, Deserialize)]
struct OnePasswordVault {
    items: Option<Vec<OnePasswordItem>>,
}

#[derive(Debug, Deserialize)]
struct OnePasswordAccount {
    vaults: Option<Vec<OnePasswordVault>>,
}

#[derive(Debug, Deserialize)]
struct OnePasswordExport {
    accounts: Option<Vec<OnePasswordAccount>>,
}

/// Importer for 1Password exports (1PUX JSON and CSV).
pub struct OnePasswordImporter;

impl OnePasswordImporter {
    /// Parses 1Password 1PUX JSON export (`export.json`).
    pub fn parse_1pux_json(json_str: &str) -> Result<Vec<VaultItem>, ImportError> {
        let export: OnePasswordExport = serde_json::from_str(json_str)
            .map_err(|e| ImportError::ParseFailed(format!("Invalid 1Password 1PUX JSON: {}", e)))?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut items = Vec::new();

        for account in export.accounts.unwrap_or_default() {
            for vault in account.vaults.unwrap_or_default() {
                for (idx, item) in vault.items.unwrap_or_default().into_iter().enumerate() {
                    let title = item
                        .overview
                        .as_ref()
                        .and_then(|o| o.title.clone())
                        .filter(|t| !t.is_empty())
                        .unwrap_or_else(|| format!("1Password Item {}", idx + 1));

                    let category = match item.category.as_deref().unwrap_or("LOGIN") {
                        "SECURE_NOTE" => ItemCategory::SecureNote,
                        "CREDIT_CARD" => ItemCategory::PaymentCard,
                        "IDENTITY" => ItemCategory::Identity,
                        _ => ItemCategory::Login,
                    };

                    let mut username = None;
                    let mut password = None;
                    let mut totp = None;
                    let mut custom_fields = Vec::new();

                    let mut urls = Vec::new();
                    if let Some(overview) = &item.overview {
                        if let Some(u) = &overview.url {
                            if !u.is_empty() {
                                urls.push(u.clone());
                            }
                        }
                    }

                    let notes = item.details.as_ref().and_then(|d| d.notes_plain.clone());

                    if let Some(details) = &item.details {
                        if let Some(login_fields) = &details.login_fields {
                            for lf in login_fields {
                                match lf.designation.as_deref() {
                                    Some("username") => username = lf.value.clone(),
                                    Some("password") => password = lf.value.clone(),
                                    _ => {
                                        if let (Some(name), Some(val)) = (&lf.name, &lf.value) {
                                            if name.to_lowercase().contains("totp")
                                                || name.to_lowercase().contains("one-time")
                                            {
                                                totp = Some(val.clone());
                                            } else {
                                                custom_fields.push(CustomField {
                                                    name: name.clone(),
                                                    value: val.clone(),
                                                    field_type: FieldType::Text,
                                                });
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        if let Some(sections) = &details.sections {
                            for sec in sections {
                                if let Some(sec_fields) = &sec.fields {
                                    for sf in sec_fields {
                                        if let (Some(title), Some(val)) = (&sf.title, &sf.value) {
                                            let field_type = match sf.kind.as_deref() {
                                                Some("concealed") => FieldType::Concealed,
                                                _ => FieldType::Text,
                                            };
                                            custom_fields.push(CustomField {
                                                name: title.clone(),
                                                value: val.clone(),
                                                field_type,
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }

                    let tags = item
                        .overview
                        .as_ref()
                        .and_then(|o| o.tags.clone())
                        .unwrap_or_else(|| vec!["1password-import".to_string()]);

                    let id = format!("1p-import-{}-{}", now, idx);

                    items.push(VaultItem {
                        id,
                        title,
                        category,
                        username,
                        password,
                        urls,
                        notes,
                        totp_seed: totp,
                        tags,
                        favorite: false,
                        custom_fields,
                        attachments: Vec::new(),
                        revision_history: Vec::new(),
                        trashed_at: None,
                        created_at: now,
                        updated_at: now,
                    });
                }
            }
        }

        Ok(items)
    }

    /// Parses 1Password CSV export.
    pub fn parse_csv(csv_str: &str) -> Result<Vec<VaultItem>, ImportError> {
        CsvImporter::parse(csv_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_1pux_json() {
        let json_str = r#"{
            "accounts": [{
                "vaults": [{
                    "items": [{
                        "category": "LOGIN",
                        "overview": {
                            "title": "AWS Console",
                            "url": "https://aws.amazon.com",
                            "tags": ["cloud", "devops"]
                        },
                        "details": {
                            "notesPlain": "IAM admin account",
                            "loginFields": [
                                {"designation": "username", "value": "cloud-admin"},
                                {"designation": "password", "value": "super-aws-pass-42"},
                                {"name": "one-time password", "value": "JBSWY3DPEHPK3PXP"}
                            ],
                            "sections": [{
                                "fields": [
                                    {"title": "Account ID", "value": "123456789012", "k": "string"}
                                ]
                            }]
                        }
                    }]
                }]
            }]
        }"#;

        let items = OnePasswordImporter::parse_1pux_json(json_str).expect("1pux parse failed");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].title, "AWS Console");
        assert_eq!(items[0].username.as_deref(), Some("cloud-admin"));
        assert_eq!(items[0].password.as_deref(), Some("super-aws-pass-42"));
        assert_eq!(items[0].totp_seed.as_deref(), Some("JBSWY3DPEHPK3PXP"));
        assert!(items[0].tags.contains(&"cloud".to_string()));
        assert_eq!(items[0].custom_fields.len(), 1);
        assert_eq!(items[0].custom_fields[0].name, "Account ID");
    }
}
