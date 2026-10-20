#![deny(unsafe_code)]
#![warn(missing_docs)]

//! High-fidelity importer for Bitwarden JSON export files.

use std::collections::HashMap;

use pwdvault_vault::{CustomField, FieldType, ItemCategory, VaultItem};
use serde::Deserialize;

use crate::ImportError;

#[derive(Debug, Deserialize)]
struct BitwardenFolder {
    id: String,
    name: String,
}

#[derive(Debug, Deserialize)]
struct BitwardenUri {
    uri: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BitwardenLogin {
    uris: Option<Vec<BitwardenUri>>,
    username: Option<String>,
    password: Option<String>,
    totp: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BitwardenCard {
    cardholder_name: Option<String>,
    brand: Option<String>,
    number: Option<String>,
    exp_month: Option<String>,
    exp_year: Option<String>,
    code: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BitwardenIdentity {
    first_name: Option<String>,
    last_name: Option<String>,
    email: Option<String>,
    phone: Option<String>,
    address1: Option<String>,
    city: Option<String>,
    state: Option<String>,
    postal_code: Option<String>,
    country: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BitwardenCustomField {
    name: Option<String>,
    value: Option<String>,
    #[serde(rename = "type")]
    field_type: Option<i32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BitwardenItem {
    id: Option<String>,
    name: Option<String>,
    notes: Option<String>,
    #[serde(rename = "type")]
    item_type: Option<i32>,
    folder_id: Option<String>,
    favorite: Option<bool>,
    login: Option<BitwardenLogin>,
    card: Option<BitwardenCard>,
    identity: Option<BitwardenIdentity>,
    fields: Option<Vec<BitwardenCustomField>>,
}

#[derive(Debug, Deserialize)]
struct BitwardenExport {
    encrypted: Option<bool>,
    folders: Option<Vec<BitwardenFolder>>,
    items: Option<Vec<BitwardenItem>>,
}

/// Importer for Bitwarden JSON exports.
pub struct BitwardenImporter;

impl BitwardenImporter {
    /// Parses Bitwarden JSON export content into `VaultItem`s.
    pub fn parse(json_str: &str) -> Result<Vec<VaultItem>, ImportError> {
        let export: BitwardenExport = serde_json::from_str(json_str)
            .map_err(|e| ImportError::ParseFailed(format!("Invalid Bitwarden JSON: {}", e)))?;

        if export.encrypted == Some(true) {
            return Err(ImportError::ValidationFailed(
                "Password-protected encrypted Bitwarden exports must be exported as unencrypted JSON from Bitwarden before importing into PwdVault.".to_string(),
            ));
        }

        let folder_map: HashMap<String, String> = export
            .folders
            .unwrap_or_default()
            .into_iter()
            .map(|f| (f.id, f.name))
            .collect();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut items = Vec::new();

        for (idx, bw_item) in export.items.unwrap_or_default().into_iter().enumerate() {
            let title = bw_item
                .name
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| format!("Bitwarden Item {}", idx + 1));

            let mut category = ItemCategory::Login;
            let mut username = None;
            let mut password = None;
            let mut urls = Vec::new();
            let mut totp = None;
            let mut custom_fields = Vec::new();

            // Category mapping: 1=Login, 2=SecureNote, 3=Card, 4=Identity
            match bw_item.item_type.unwrap_or(1) {
                1 => {
                    category = ItemCategory::Login;
                    if let Some(login) = bw_item.login {
                        username = login.username;
                        password = login.password;
                        totp = login.totp;
                        if let Some(uri_list) = login.uris {
                            for u in uri_list {
                                if let Some(uri_str) = u.uri {
                                    if !uri_str.is_empty() {
                                        urls.push(uri_str);
                                    }
                                }
                            }
                        }
                    }
                }
                2 => {
                    category = ItemCategory::SecureNote;
                }
                3 => {
                    category = ItemCategory::PaymentCard;
                    if let Some(card) = bw_item.card {
                        if let Some(holder) = card.cardholder_name {
                            custom_fields.push(CustomField {
                                name: "Cardholder".to_string(),
                                value: holder,
                                field_type: FieldType::Text,
                            });
                        }
                        if let Some(brand) = card.brand {
                            custom_fields.push(CustomField {
                                name: "Brand".to_string(),
                                value: brand,
                                field_type: FieldType::Text,
                            });
                        }
                        if let Some(num) = card.number {
                            username = Some(format!(
                                "•••• {}",
                                num.chars()
                                    .rev()
                                    .take(4)
                                    .collect::<String>()
                                    .chars()
                                    .rev()
                                    .collect::<String>()
                            ));
                            password = Some(num);
                        }
                        if let Some(code) = card.code {
                            custom_fields.push(CustomField {
                                name: "CVV/CVC".to_string(),
                                value: code,
                                field_type: FieldType::Concealed,
                            });
                        }
                        if let (Some(m), Some(y)) = (card.exp_month, card.exp_year) {
                            custom_fields.push(CustomField {
                                name: "Expiration".to_string(),
                                value: format!("{}/{}", m, y),
                                field_type: FieldType::Text,
                            });
                        }
                    }
                }
                4 => {
                    category = ItemCategory::Identity;
                    if let Some(id) = bw_item.identity {
                        let full_name = format!(
                            "{} {}",
                            id.first_name.unwrap_or_default(),
                            id.last_name.unwrap_or_default()
                        )
                        .trim()
                        .to_string();

                        if !full_name.is_empty() {
                            username = Some(full_name);
                        }
                        if let Some(email) = id.email {
                            custom_fields.push(CustomField {
                                name: "Email".to_string(),
                                value: email,
                                field_type: FieldType::Text,
                            });
                        }
                        if let Some(phone) = id.phone {
                            custom_fields.push(CustomField {
                                name: "Phone".to_string(),
                                value: phone,
                                field_type: FieldType::Text,
                            });
                        }
                        if let Some(addr) = id.address1 {
                            custom_fields.push(CustomField {
                                name: "Address".to_string(),
                                value: addr,
                                field_type: FieldType::Text,
                            });
                        }
                        if let Some(city) = id.city {
                            custom_fields.push(CustomField {
                                name: "City".to_string(),
                                value: city,
                                field_type: FieldType::Text,
                            });
                        }
                        if let Some(state) = id.state {
                            custom_fields.push(CustomField {
                                name: "State".to_string(),
                                value: state,
                                field_type: FieldType::Text,
                            });
                        }
                        if let Some(zip) = id.postal_code {
                            custom_fields.push(CustomField {
                                name: "Postal Code".to_string(),
                                value: zip,
                                field_type: FieldType::Text,
                            });
                        }
                        if let Some(country) = id.country {
                            custom_fields.push(CustomField {
                                name: "Country".to_string(),
                                value: country,
                                field_type: FieldType::Text,
                            });
                        }
                    }
                }
                _ => {}
            }

            // Custom fields mapping: 0=Text, 1=Hidden, 2=Boolean
            if let Some(extra_fields) = bw_item.fields {
                for f in extra_fields {
                    let field_name = f.name.unwrap_or_default();
                    let field_val = f.value.unwrap_or_default();
                    let field_type = match f.field_type.unwrap_or(0) {
                        1 => FieldType::Concealed,
                        2 => FieldType::Boolean,
                        _ => FieldType::Text,
                    };
                    if !field_name.is_empty() {
                        custom_fields.push(CustomField {
                            name: field_name,
                            value: field_val,
                            field_type,
                        });
                    }
                }
            }

            // Tag mapping: folder name becomes tag
            let mut tags = vec!["bitwarden-import".to_string()];
            if let Some(folder_id) = bw_item.folder_id {
                if let Some(folder_name) = folder_map.get(&folder_id) {
                    tags.push(folder_name.clone());
                }
            }

            let id = bw_item.id.unwrap_or_else(|| format!("bw-import-{}", idx));

            items.push(VaultItem {
                id,
                title,
                category,
                username,
                password,
                urls,
                notes: bw_item.notes,
                totp_seed: totp,
                tags,
                favorite: bw_item.favorite.unwrap_or(false),
                custom_fields,
                attachments: Vec::new(),
                revision_history: Vec::new(),
                trashed_at: None,
                created_at: now,
                updated_at: now,
            });
        }

        Ok(items)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_bitwarden_export_json() {
        let json_data = r#"{
            "encrypted": false,
            "folders": [
                {"id": "f1", "name": "Work Accounts"},
                {"id": "f2", "name": "Finance"}
            ],
            "items": [
                {
                    "id": "item-bw-1",
                    "organizationId": null,
                    "folderId": "f1",
                    "type": 1,
                    "name": "GitHub Corporate",
                    "notes": "Work developer account",
                    "favorite": true,
                    "login": {
                        "uris": [{"uri": "https://github.com/login"}],
                        "username": "dev@enterprise.corp",
                        "password": "corp-secret-pass-99!",
                        "totp": "JBSWY3DPEHPK3PXP"
                    },
                    "fields": [
                        {"name": "SSH Key Fingerprint", "value": "SHA256:abcd...", "type": 0},
                        {"name": "Security PIN", "value": "9988", "type": 1}
                    ]
                },
                {
                    "id": "item-bw-2",
                    "folderId": "f2",
                    "type": 3,
                    "name": "Corporate Visa",
                    "card": {
                        "cardholderName": "Alice Dev",
                        "brand": "Visa",
                        "number": "4111222233334444",
                        "expMonth": "12",
                        "expYear": "2028",
                        "code": "123"
                    }
                }
            ]
        }"#;

        let items = BitwardenImporter::parse(json_data).expect("bitwarden parse failed");
        assert_eq!(items.len(), 2);

        // Check Login item
        let login = &items[0];
        assert_eq!(login.title, "GitHub Corporate");
        assert_eq!(login.category, ItemCategory::Login);
        assert_eq!(login.username.as_deref(), Some("dev@enterprise.corp"));
        assert_eq!(login.password.as_deref(), Some("corp-secret-pass-99!"));
        assert_eq!(login.totp_seed.as_deref(), Some("JBSWY3DPEHPK3PXP"));
        assert!(login.tags.contains(&"Work Accounts".to_string()));
        assert_eq!(login.custom_fields.len(), 2);
        assert_eq!(login.custom_fields[1].name, "Security PIN");
        assert_eq!(login.custom_fields[1].field_type, FieldType::Concealed);

        // Check Card item
        let card = &items[1];
        assert_eq!(card.title, "Corporate Visa");
        assert_eq!(card.category, ItemCategory::PaymentCard);
        assert_eq!(card.password.as_deref(), Some("4111222233334444"));
        assert!(card.tags.contains(&"Finance".to_string()));
    }
}
