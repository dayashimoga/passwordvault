#![deny(unsafe_code)]
#![warn(missing_docs)]

//! RFC 4180 compliant CSV parser and exporter for vault credentials.

use pwdvault_vault::{CustomField, FieldType, ItemCategory, VaultItem};

use crate::ImportError;

/// Parses an RFC 4180 CSV document into a vector of records, where each record
/// is a vector of field strings. Properly handles quotes, escaped quotes `""`,
/// delimiters within quotes, and multiline values.
pub fn parse_rfc4180_csv(input: &str) -> Vec<Vec<String>> {
    let mut records = Vec::new();
    let mut current_record = Vec::new();
    let mut current_field = String::new();

    let mut in_quotes = false;
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if in_quotes {
            if ch == '"' {
                // Check if escaped quote ("")
                if chars.peek() == Some(&'"') {
                    current_field.push('"');
                    chars.next();
                } else {
                    in_quotes = false;
                }
            } else {
                current_field.push(ch);
            }
        } else {
            match ch {
                '"' => {
                    in_quotes = true;
                }
                ',' => {
                    current_record.push(current_field.trim().to_string());
                    current_field = String::new();
                }
                '\r' => {
                    if chars.peek() == Some(&'\n') {
                        chars.next();
                    }
                    current_record.push(current_field.trim().to_string());
                    current_field = String::new();
                    if !current_record.is_empty()
                        && !(current_record.len() == 1 && current_record[0].is_empty())
                    {
                        records.push(current_record);
                    }
                    current_record = Vec::new();
                }
                '\n' => {
                    current_record.push(current_field.trim().to_string());
                    current_field = String::new();
                    if !current_record.is_empty()
                        && !(current_record.len() == 1 && current_record[0].is_empty())
                    {
                        records.push(current_record);
                    }
                    current_record = Vec::new();
                }
                _ => {
                    current_field.push(ch);
                }
            }
        }
    }

    // Push trailing field/record if any
    if in_quotes || !current_field.is_empty() || !current_record.is_empty() {
        current_record.push(current_field.trim().to_string());
        if !current_record.is_empty()
            && !(current_record.len() == 1 && current_record[0].is_empty())
        {
            records.push(current_record);
        }
    }

    records
}

/// Generic CSV credentials importer that dynamically maps columns based on header row.
pub struct CsvImporter;

impl CsvImporter {
    /// Imports a CSV string into a list of `VaultItem`s using header name matching.
    pub fn parse(input: &str) -> Result<Vec<VaultItem>, ImportError> {
        let rows = parse_rfc4180_csv(input);
        if rows.is_empty() {
            return Ok(Vec::new());
        }

        let headers = &rows[0];
        let mut title_idx = None;
        let mut username_idx = None;
        let mut password_idx = None;
        let mut url_idx = None;
        let mut notes_idx = None;
        let mut otp_idx = None;
        let mut category_idx = None;

        for (i, h) in headers.iter().enumerate() {
            let norm = h.to_lowercase().replace(['_', ' ', '-'], "");
            match norm.as_str() {
                "title" | "name" => title_idx = Some(i),
                "username" | "user" | "login" | "email" | "loginusername" => username_idx = Some(i),
                "password" | "pass" | "secret" | "loginpassword" => password_idx = Some(i),
                "url" | "website" | "link" | "loginurl" | "loginuri" => url_idx = Some(i),
                "notes" | "note" | "comment" | "comments" => notes_idx = Some(i),
                "otp" | "totp" | "2fa" | "totpseed" | "logintotp" => otp_idx = Some(i),
                "category" | "type" => category_idx = Some(i),
                _ => {}
            }
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut items = Vec::new();

        for (row_idx, row) in rows.iter().enumerate().skip(1) {
            let get_col = |idx: Option<usize>| -> Option<String> {
                idx.and_then(|i| row.get(i).cloned())
                    .filter(|s| !s.is_empty())
            };

            let title = get_col(title_idx).unwrap_or_else(|| format!("Imported Item {}", row_idx));
            let username = get_col(username_idx);
            let password = get_col(password_idx);
            let url = get_col(url_idx);
            let notes = get_col(notes_idx);
            let totp = get_col(otp_idx);
            let cat_str = get_col(category_idx);

            let category = match cat_str
                .as_deref()
                .unwrap_or("login")
                .to_lowercase()
                .as_str()
            {
                "note" | "securenote" => ItemCategory::SecureNote,
                "card" | "paymentcard" => ItemCategory::PaymentCard,
                "identity" => ItemCategory::Identity,
                "recovery" | "recoverycode" => ItemCategory::RecoveryCode,
                _ => ItemCategory::Login,
            };

            let urls = match url {
                Some(u) => vec![u],
                None => Vec::new(),
            };

            // Custom fields for unrecognized extra columns
            let mut custom_fields = Vec::new();
            for (col_i, cell) in row.iter().enumerate() {
                let is_known = title_idx == Some(col_i)
                    || username_idx == Some(col_i)
                    || password_idx == Some(col_i)
                    || url_idx == Some(col_i)
                    || notes_idx == Some(col_i)
                    || otp_idx == Some(col_i)
                    || category_idx == Some(col_i);

                if !is_known && !cell.is_empty() {
                    let field_name = headers
                        .get(col_i)
                        .cloned()
                        .unwrap_or_else(|| format!("Field {}", col_i));
                    custom_fields.push(CustomField {
                        name: field_name,
                        value: cell.clone(),
                        field_type: FieldType::Text,
                    });
                }
            }

            let id = format!("csv-import-{}-{}", now, row_idx);

            items.push(VaultItem {
                id,
                title,
                category,
                username,
                password,
                urls,
                notes,
                totp_seed: totp,
                tags: vec!["csv-import".to_string()],
                favorite: false,
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

/// Exporter that serializes active vault items into RFC 4180 CSV.
pub struct CsvExporter;

impl CsvExporter {
    /// Serializes active items to CSV format.
    pub fn export(items: &[VaultItem]) -> String {
        let mut out = String::from("Title,Username,Password,URL,Category,Notes,TOTP\r\n");

        for item in items {
            if item.trashed_at.is_some() {
                continue;
            }

            let escape = |val: &str| -> String {
                if val.contains(',')
                    || val.contains('"')
                    || val.contains('\n')
                    || val.contains('\r')
                {
                    format!("\"{}\"", val.replace('"', "\"\""))
                } else {
                    val.to_string()
                }
            };

            let title = escape(&item.title);
            let username = escape(item.username.as_deref().unwrap_or(""));
            let password = escape(item.password.as_deref().unwrap_or(""));
            let url = escape(item.urls.first().map(|s| s.as_str()).unwrap_or(""));
            let category = escape(&format!("{:?}", item.category));
            let notes = escape(item.notes.as_deref().unwrap_or(""));
            let totp = escape(item.totp_seed.as_deref().unwrap_or(""));

            out.push_str(&format!(
                "{},{},{},{},{},{},{}\r\n",
                title, username, password, url, category, notes, totp
            ));
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc4180_quoted_and_escaped_csv() {
        let csv = "Title,Username,Password,Notes\r\n\
        \"GitHub, Inc\",\"alice@test.com\",\"pass\"\"123\"\"\",\"Multi-line\r\nnote\"\r\n\
        Standard,bob,secret,simple note\r\n";

        let items = CsvImporter::parse(csv).expect("parse failed");
        assert_eq!(items.len(), 2);

        assert_eq!(items[0].title, "GitHub, Inc");
        assert_eq!(items[0].username.as_deref(), Some("alice@test.com"));
        assert_eq!(items[0].password.as_deref(), Some("pass\"123\""));
        assert_eq!(items[0].notes.as_deref(), Some("Multi-line\r\nnote"));

        assert_eq!(items[1].title, "Standard");
        assert_eq!(items[1].username.as_deref(), Some("bob"));
    }

    #[test]
    fn test_csv_export_and_reimport_roundtrip() {
        let original = vec![VaultItem {
            id: "1".to_string(),
            title: "Proton, Mail".to_string(),
            category: ItemCategory::Login,
            username: Some("user@proton.me".to_string()),
            password: Some("secret\"quoted\"pass".to_string()),
            urls: vec!["https://proton.me".to_string()],
            notes: Some("Line 1\r\nLine 2".to_string()),
            totp_seed: Some("JBSWY3DPEHPK3PXP".to_string()),
            tags: vec![],
            favorite: false,
            custom_fields: vec![],
            attachments: vec![],
            revision_history: vec![],
            trashed_at: None,
            created_at: 1000,
            updated_at: 1000,
        }];

        let exported = CsvExporter::export(&original);
        let reimported = CsvImporter::parse(&exported).expect("reimport failed");

        assert_eq!(reimported.len(), 1);
        assert_eq!(reimported[0].title, "Proton, Mail");
        assert_eq!(reimported[0].username.as_deref(), Some("user@proton.me"));
        assert_eq!(
            reimported[0].password.as_deref(),
            Some("secret\"quoted\"pass")
        );
        assert_eq!(reimported[0].urls, vec!["https://proton.me"]);
        assert_eq!(reimported[0].totp_seed.as_deref(), Some("JBSWY3DPEHPK3PXP"));
    }
}
