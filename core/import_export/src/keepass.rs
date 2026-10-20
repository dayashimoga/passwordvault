#![deny(unsafe_code)]
#![warn(missing_docs)]

//! KeePass 2.x XML export parser for interoperability with KeePassXC, Strongbox, KeePassDX.

use pwdvault_vault::{CustomField, FieldType, ItemCategory, VaultItem};

use crate::ImportError;

fn unescape_xml(input: &str) -> String {
    input
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

/// Extractor for XML tags: `<tag>content</tag>`.
fn extract_tag<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let open_tag = format!("<{}>", tag);
    let close_tag = format!("</{}>", tag);

    let start = xml.find(&open_tag)? + open_tag.len();
    let end = xml[start..].find(&close_tag)? + start;
    Some(&xml[start..end])
}

/// KeePass XML export parser.
pub struct KeePassXmlImporter;

impl KeePassXmlImporter {
    /// Parses KeePass 2.x XML export content into `VaultItem`s.
    pub fn parse(xml_str: &str) -> Result<Vec<VaultItem>, ImportError> {
        if !xml_str.contains("<KeePassFile>") && !xml_str.contains("<Entry>") {
            return Err(ImportError::ParseFailed(
                "Provided XML document is not a valid KeePass XML export".to_string(),
            ));
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut items = Vec::new();
        let mut entry_cursor = 0;
        let mut entry_idx = 0;

        while let Some(start_rel) = xml_str[entry_cursor..].find("<Entry>") {
            let start = entry_cursor + start_rel;
            let end_rel = match xml_str[start..].find("</Entry>") {
                Some(e) => e,
                None => break,
            };
            let end = start + end_rel + "</Entry>".len();
            let entry_xml = &xml_str[start..end];
            entry_cursor = end;
            entry_idx += 1;

            let mut title = None;
            let mut username = None;
            let mut password = None;
            let mut url = None;
            let mut notes = None;
            let mut totp = None;
            let mut custom_fields = Vec::new();

            // Extract each <String> ... </String> element
            let mut str_cursor = 0;
            while let Some(s_start_rel) = entry_xml[str_cursor..].find("<String>") {
                let s_start = str_cursor + s_start_rel;
                let s_end_rel = match entry_xml[s_start..].find("</String>") {
                    Some(e) => e,
                    None => break,
                };
                let s_end = s_start + s_end_rel + "</String>".len();
                let string_block = &entry_xml[s_start..s_end];
                str_cursor = s_end;

                let key = extract_tag(string_block, "Key").map(unescape_xml);
                let val = extract_tag(string_block, "Value").map(unescape_xml);

                if let (Some(k), Some(v)) = (key, val) {
                    if v.is_empty() {
                        continue;
                    }

                    match k.to_lowercase().as_str() {
                        "title" => title = Some(v),
                        "username" | "user" => username = Some(v),
                        "password" => password = Some(v),
                        "url" => url = Some(v),
                        "notes" | "comment" => notes = Some(v),
                        "otp" | "totp" => totp = Some(v),
                        _ => {
                            custom_fields.push(CustomField {
                                name: k,
                                value: v,
                                field_type: FieldType::Text,
                            });
                        }
                    }
                }
            }

            let item_title = title.unwrap_or_else(|| format!("KeePass Entry {}", entry_idx));
            let urls = match url {
                Some(u) => vec![u],
                None => Vec::new(),
            };

            let id = format!("keepass-import-{}-{}", now, entry_idx);

            items.push(VaultItem {
                id,
                title: item_title,
                category: ItemCategory::Login,
                username,
                password,
                urls,
                notes,
                totp_seed: totp,
                tags: vec!["keepass-import".to_string()],
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_keepass_xml() {
        let xml = r#"<KeePassFile>
            <Root>
                <Group>
                    <Name>Root</Name>
                    <Entry>
                        <UUID>1234567890</UUID>
                        <String>
                            <Key>Title</Key>
                            <Value>DigitalOcean Droplet</Value>
                        </String>
                        <String>
                            <Key>UserName</Key>
                            <Value>root</Value>
                        </String>
                        <String>
                            <Key>Password</Key>
                            <Value>super&amp;secret&quot;pass</Value>
                        </String>
                        <String>
                            <Key>URL</Key>
                            <Value>https://cloud.digitalocean.com</Value>
                        </String>
                        <String>
                            <Key>Notes</Key>
                            <Value>Server IP: 192.168.1.10</Value>
                        </String>
                        <String>
                            <Key>IPAddress</Key>
                            <Value>192.168.1.10</Value>
                        </String>
                    </Entry>
                </Group>
            </Root>
        </KeePassFile>"#;

        let items = KeePassXmlImporter::parse(xml).expect("keepass xml parse failed");
        assert_eq!(items.len(), 1);

        assert_eq!(items[0].title, "DigitalOcean Droplet");
        assert_eq!(items[0].username.as_deref(), Some("root"));
        assert_eq!(items[0].password.as_deref(), Some("super&secret\"pass"));
        assert_eq!(items[0].urls, vec!["https://cloud.digitalocean.com"]);
        assert_eq!(items[0].notes.as_deref(), Some("Server IP: 192.168.1.10"));
        assert_eq!(items[0].custom_fields.len(), 1);
        assert_eq!(items[0].custom_fields[0].name, "IPAddress");
        assert_eq!(items[0].custom_fields[0].value, "192.168.1.10");
    }
}
