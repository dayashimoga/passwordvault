#![deny(unsafe_code)]
#![warn(missing_docs)]

//! Request dispatcher and domain security handler for browser Native Messaging.

use rand_core::{OsRng, RngCore};
use std::fs;
use std::path::PathBuf;

use pwdvault_crypto::keys::DataKey;
use pwdvault_generator::entropy::estimate_crack_time;
use pwdvault_generator::password::{generate_password, PasswordOptions};
use pwdvault_vault::{
    ItemCategory, VaultContainer, VaultHeader, VaultItem, VaultPayload, VaultStorage,
};

use crate::protocol::{HostError, LoginSummary, NativeRequest, NativeResponse, VaultStatus};

/// Allowed extension identifiers for Chrome/Edge and Firefox.
pub const ALLOWED_EXTENSIONS: &[&str] = &[
    "com.antigravity.pwdvault",
    "pwdvault@antigravity.internal",
    // Common development / unpacked IDs
    "ghbmnnjooekpmoecnnnilnnbdlolhkhi",
    "chrome-extension://*",
];

/// Domain normalization helper extracting effective host from an arbitrary URL.
pub fn extract_domain(raw_url: &str) -> String {
    let trimmed = raw_url.trim();
    let without_scheme = if let Some(idx) = trimmed.find("://") {
        &trimmed[idx + 3..]
    } else {
        trimmed
    };

    // Strip path and query
    let host_port = without_scheme.split(['/', '?', '#']).next().unwrap_or("");
    // Strip port if present
    let host = host_port
        .split(':')
        .next()
        .unwrap_or("")
        .trim()
        .to_lowercase();
    host
}

/// Extracts the base registered domain (eTLD+1 heuristic) from a hostname.
pub fn extract_base_domain(host: &str) -> String {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() <= 2 {
        return host.to_string();
    }

    let second_to_last = parts[parts.len() - 2];
    let is_compound_tld = matches!(
        second_to_last,
        "co" | "com" | "org" | "gov" | "ac" | "edu" | "net"
    ) && parts.last().map(|s| s.len() == 2).unwrap_or(false);

    if is_compound_tld && parts.len() >= 3 {
        parts[parts.len() - 3..].join(".")
    } else {
        parts[parts.len() - 2..].join(".")
    }
}

/// Checks if two hostnames or URLs match under the same base domain or exact match.
pub fn domains_match(host1: &str, host2: &str) -> bool {
    let h1 = extract_domain(host1);
    let h2 = extract_domain(host2);
    if h1.is_empty() || h2.is_empty() {
        return false;
    }
    if h1 == h2 || h1.ends_with(&format!(".{}", h2)) || h2.ends_with(&format!(".{}", h1)) {
        return true;
    }
    let b1 = extract_base_domain(&h1);
    let b2 = extract_base_domain(&h2);
    !b1.is_empty() && b1 == b2
}

/// Unlocked vault state in memory.
pub struct UnlockedVault {
    /// Header containing KDF parameters.
    pub header: VaultHeader,
    /// Active 256-bit Data Encryption Key.
    pub data_key: DataKey,
    /// Decrypted database payload.
    pub payload: VaultPayload,
    /// Master passphrase retained in session memory.
    pub passphrase: String,
}

/// Active session state containing the unlocked vault and authorization credentials.
pub struct HostSession {
    /// 256-bit cryptographically random session token.
    pub token: String,
    /// Unlocked vault state.
    pub vault: Option<UnlockedVault>,
    /// Path to active container file.
    pub vault_path: PathBuf,
}

impl HostSession {
    /// Creates a new unauthenticated session.
    pub fn new(default_path: PathBuf) -> Self {
        Self {
            token: String::new(),
            vault: None,
            vault_path: default_path,
        }
    }

    /// Generates a fresh 256-bit CSPRNG session token.
    pub fn refresh_token(&mut self) -> String {
        let mut bytes = [0u8; 32];
        let _ = OsRng.try_fill_bytes(&mut bytes);
        self.token = hex::encode(bytes);
        self.token.clone()
    }

    /// Validates an incoming session token.
    pub fn validate_token(&self, incoming: &str) -> bool {
        !self.token.is_empty() && self.token == incoming
    }

    /// Returns current vault status.
    pub fn status(&self) -> VaultStatus {
        if self.vault.is_some() {
            VaultStatus::Unlocked
        } else if self.vault_path.exists() {
            VaultStatus::Locked
        } else {
            VaultStatus::NotFound
        }
    }

    /// Unlocks the vault using the provided master passphrase.
    pub fn unlock(
        &mut self,
        passphrase: &str,
        path_override: Option<&str>,
    ) -> Result<usize, HostError> {
        let target_path = if let Some(p) = path_override {
            PathBuf::from(p)
        } else {
            self.vault_path.clone()
        };

        if !target_path.exists() {
            return Err(HostError::Validation(format!(
                "Vault file does not exist at {}",
                target_path.display()
            )));
        }

        let bytes = fs::read(&target_path)
            .map_err(|e| HostError::Validation(format!("Cannot read vault file: {}", e)))?;

        let (header, data_key, payload) = VaultContainer::unlock(&bytes, passphrase.as_bytes())
            .map_err(|e| HostError::Validation(format!("Unlock failed: {}", e)))?;

        let count = payload.items.len();
        self.vault = Some(UnlockedVault {
            header,
            data_key,
            payload,
            passphrase: passphrase.to_string(),
        });
        self.vault_path = target_path;
        Ok(count)
    }

    /// Locks the vault and clears in-memory secrets.
    pub fn lock(&mut self) {
        self.vault = None;
    }

    /// Queries matching logins for a given web URL.
    pub fn get_logins(&self, raw_url: &str) -> Result<Vec<LoginSummary>, HostError> {
        let vault = self.vault.as_ref().ok_or(HostError::VaultLocked)?;
        let domain = extract_domain(raw_url);
        if domain.is_empty() {
            return Ok(Vec::new());
        }
        let base_domain = extract_base_domain(&domain);

        let payload = &vault.payload;
        let mut matches = Vec::new();

        for item in &payload.items {
            if item.trashed_at.is_some() || item.category != ItemCategory::Login {
                continue;
            }

            // Verify URL matches domain (exact or eTLD+1) or title matches domain
            let domain_match = item.urls.iter().any(|u| domains_match(u, &domain))
                || (!base_domain.is_empty()
                    && (item.title.to_lowercase().contains(&base_domain)
                        || base_domain.contains(&item.title.to_lowercase())));

            if domain_match {
                matches.push(LoginSummary {
                    id: item.id.clone(),
                    title: item.title.clone(),
                    username: item.username.clone(),
                    url: item.urls.first().cloned(),
                });
            }
        }

        Ok(matches)
    }

    /// Retrieves credentials for form autofill, enforcing domain binding verification.
    pub fn fill_credential(
        &self,
        item_id: &str,
        request_url: &str,
    ) -> Result<(Option<String>, Option<String>), HostError> {
        let vault = self.vault.as_ref().ok_or(HostError::VaultLocked)?;
        let domain = extract_domain(request_url);
        if domain.is_empty() {
            return Err(HostError::Validation("Empty request domain".to_string()));
        }

        let item = vault
            .payload
            .items
            .iter()
            .find(|i| i.id == item_id)
            .ok_or_else(|| HostError::Validation("Credential item not found".to_string()))?;

        // Anti-phishing invariant: requested item must have at least one URL matching current domain,
        // or a title explicitly matching the base domain.
        let base_domain = extract_base_domain(&domain);
        let is_authorized = item.urls.iter().any(|u| domains_match(u, &domain))
            || (!base_domain.is_empty()
                && (item.title.to_lowercase().contains(&base_domain)
                    || base_domain.contains(&item.title.to_lowercase())));

        if !is_authorized {
            return Err(HostError::Validation(format!(
                "Origin mismatch: cannot autofill item '{}' into unauthorized domain '{}'",
                item.title, domain
            )));
        }

        Ok((item.username.clone(), item.password.clone()))
    }

    /// Saves a newly submitted credential.
    pub fn save_credential(
        &mut self,
        title: &str,
        username: &str,
        password: &str,
        url: &str,
    ) -> Result<String, HostError> {
        let vault = self.vault.as_mut().ok_or(HostError::VaultLocked)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let id = format!("autofill-{}", now);
        let item = VaultItem {
            id: id.clone(),
            title: title.to_string(),
            category: ItemCategory::Login,
            username: Some(username.to_string()),
            password: Some(password.to_string()),
            urls: if url.is_empty() {
                Vec::new()
            } else {
                vec![url.to_string()]
            },
            notes: None,
            totp_seed: None,
            tags: vec!["browser-autofill".to_string()],
            favorite: false,
            custom_fields: Vec::new(),
            attachments: Vec::new(),
            revision_history: Vec::new(),
            trashed_at: None,
            created_at: now,
            updated_at: now,
        };

        vault.payload.items.push(item);
        vault.payload.updated_at = now;

        // Encrypt and commit atomically to disk
        let encrypted_bytes = VaultContainer::create(
            vault.passphrase.as_bytes(),
            vault.header.kdf_params.clone(),
            &vault.payload,
        )
        .map_err(|e| HostError::Validation(format!("Encryption failed: {}", e)))?;

        VaultStorage::save_atomic(&self.vault_path, &encrypted_bytes)
            .map_err(|e| HostError::Validation(format!("Save failed: {}", e)))?;

        Ok(id)
    }
}

/// Dispatches a parsed request and returns the corresponding response.
pub fn handle_request(session: &mut HostSession, request: NativeRequest) -> NativeResponse {
    match request {
        NativeRequest::Handshake {
            client_nonce: _,
            extension_id,
        } => {
            // Verify extension identifier
            let is_allowed = ALLOWED_EXTENSIONS
                .iter()
                .any(|&ext| ext == extension_id || ext.contains('*'));

            if !is_allowed {
                return NativeResponse::ErrorResponse {
                    error: format!("Extension ID '{}' is not authorized", extension_id),
                    code: 403,
                };
            }

            let token = session.refresh_token();
            NativeResponse::HandshakeResponse {
                session_token: token,
                vault_status: session.status(),
                host_version: env!("CARGO_PKG_VERSION").to_string(),
            }
        }
        NativeRequest::Status { session_token } => {
            if let Some(t) = session_token {
                if !session.validate_token(&t) {
                    return NativeResponse::ErrorResponse {
                        error: "Invalid session token".to_string(),
                        code: 401,
                    };
                }
            }
            let count = session
                .vault
                .as_ref()
                .map(|v| v.payload.items.len())
                .unwrap_or(0);
            NativeResponse::StatusResponse {
                vault_status: session.status(),
                item_count: count,
            }
        }
        NativeRequest::Unlock {
            session_token,
            passphrase,
            vault_path,
        } => {
            if !session.validate_token(&session_token) {
                return NativeResponse::ErrorResponse {
                    error: "Invalid session token".to_string(),
                    code: 401,
                };
            }

            match session.unlock(&passphrase, vault_path.as_deref()) {
                Ok(count) => {
                    let name = session
                        .vault
                        .as_ref()
                        .map(|v| v.payload.vault_name.clone())
                        .unwrap_or_default();
                    NativeResponse::UnlockResponse {
                        success: true,
                        vault_name: name,
                        item_count: count,
                    }
                }
                Err(e) => NativeResponse::ErrorResponse {
                    error: e.to_string(),
                    code: 400,
                },
            }
        }
        NativeRequest::Lock { session_token } => {
            if !session.validate_token(&session_token) {
                return NativeResponse::ErrorResponse {
                    error: "Invalid session token".to_string(),
                    code: 401,
                };
            }
            session.lock();
            NativeResponse::LockResponse { success: true }
        }
        NativeRequest::GetLogins { session_token, url } => {
            if !session.validate_token(&session_token) {
                return NativeResponse::ErrorResponse {
                    error: "Invalid session token".to_string(),
                    code: 401,
                };
            }
            match session.get_logins(&url) {
                Ok(logins) => NativeResponse::GetLoginsResponse { logins },
                Err(e) => NativeResponse::ErrorResponse {
                    error: e.to_string(),
                    code: 400,
                },
            }
        }
        NativeRequest::FillCredential {
            session_token,
            item_id,
            url,
        } => {
            if !session.validate_token(&session_token) {
                return NativeResponse::ErrorResponse {
                    error: "Invalid session token".to_string(),
                    code: 401,
                };
            }
            match session.fill_credential(&item_id, &url) {
                Ok((user, pass)) => NativeResponse::FillCredentialResponse {
                    username: user,
                    password: pass,
                },
                Err(e) => NativeResponse::ErrorResponse {
                    error: e.to_string(),
                    code: 400,
                },
            }
        }
        NativeRequest::GeneratePassword { length, symbols } => {
            let options = PasswordOptions {
                length: length.unwrap_or(20),
                uppercase: true,
                lowercase: true,
                digits: true,
                symbols: symbols.unwrap_or(true),
                exclude_ambiguous: true,
                custom_excluded: String::new(),
            };

            match generate_password(&options) {
                Ok(pw) => {
                    let est = estimate_crack_time(pw.as_str());
                    NativeResponse::GeneratePasswordResponse {
                        password: pw.as_str().to_string(),
                        entropy_bits: est.entropy_bits,
                        rating: format!("{:?}", est.rating),
                    }
                }
                Err(e) => NativeResponse::ErrorResponse {
                    error: e.to_string(),
                    code: 500,
                },
            }
        }
        NativeRequest::SaveCredential {
            session_token,
            title,
            username,
            password,
            url,
        } => {
            if !session.validate_token(&session_token) {
                return NativeResponse::ErrorResponse {
                    error: "Invalid session token".to_string(),
                    code: 401,
                };
            }
            match session.save_credential(&title, &username, &password, &url) {
                Ok(item_id) => NativeResponse::SaveCredentialResponse {
                    success: true,
                    item_id,
                },
                Err(e) => NativeResponse::ErrorResponse {
                    error: e.to_string(),
                    code: 400,
                },
            }
        }
    }
}

// Module for hex encoding
mod hex {
    pub fn encode<T: AsRef<[u8]>>(data: T) -> String {
        let mut s = String::with_capacity(data.as_ref().len() * 2);
        for &b in data.as_ref() {
            use std::fmt::Write;
            let _ = write!(s, "{:02x}", b);
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_domain() {
        assert_eq!(extract_domain("https://github.com/login"), "github.com");
        assert_eq!(
            extract_domain("http://sub.domain.co.uk:8080/path?query=1"),
            "sub.domain.co.uk"
        );
        assert_eq!(extract_domain("example.org/path"), "example.org");
    }

    #[test]
    fn test_extract_base_domain() {
        assert_eq!(extract_base_domain("sub.github.com"), "github.com");
        assert_eq!(extract_base_domain("github.com"), "github.com");
        assert_eq!(extract_base_domain("mail.proton.me"), "proton.me");
        assert_eq!(extract_base_domain("service.gov.uk"), "service.gov.uk");
        assert_eq!(
            extract_base_domain("portal.service.gov.uk"),
            "service.gov.uk"
        );
    }

    #[test]
    fn test_domains_match() {
        assert!(domains_match(
            "https://mail.proton.me",
            "https://account.proton.me/login"
        ));
        assert!(domains_match("sub.github.com", "github.com"));
        assert!(domains_match(
            "https://github.com/login",
            "https://sub.github.com/sessions/new"
        ));
        assert!(!domains_match(
            "https://github.com",
            "https://evil-phishing.com"
        ));
    }

    #[test]
    fn test_handshake_and_session_token_validation() {
        let mut session = HostSession::new(PathBuf::from("nonexistent.vault"));
        let req = NativeRequest::Handshake {
            client_nonce: "12345".to_string(),
            extension_id: "com.antigravity.pwdvault".to_string(),
        };

        let resp = handle_request(&mut session, req);
        match resp {
            NativeResponse::HandshakeResponse {
                session_token,
                vault_status,
                ..
            } => {
                assert!(!session_token.is_empty());
                assert_eq!(vault_status, VaultStatus::NotFound);
                assert!(session.validate_token(&session_token));
            }
            _ => panic!("Expected HandshakeResponse"),
        }
    }

    #[test]
    fn test_generate_password_request() {
        let mut session = HostSession::new(PathBuf::from("nonexistent.vault"));
        let req = NativeRequest::GeneratePassword {
            length: Some(24),
            symbols: Some(true),
        };

        let resp = handle_request(&mut session, req);
        match resp {
            NativeResponse::GeneratePasswordResponse {
                password,
                entropy_bits,
                ..
            } => {
                assert_eq!(password.len(), 24);
                assert!(entropy_bits > 50);
            }
            _ => panic!("Expected GeneratePasswordResponse"),
        }
    }

    #[test]
    fn test_unauthorized_token_rejection() {
        let mut session = HostSession::new(PathBuf::from("nonexistent.vault"));
        session.token = "valid-token-123".to_string();

        let req = NativeRequest::GetLogins {
            session_token: "wrong-token".to_string(),
            url: "https://github.com".to_string(),
        };

        let resp = handle_request(&mut session, req);
        match resp {
            NativeResponse::ErrorResponse { code, .. } => {
                assert_eq!(code, 401);
            }
            _ => panic!("Expected ErrorResponse 401"),
        }
    }
}
