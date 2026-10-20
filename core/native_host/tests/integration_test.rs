#![deny(unsafe_code)]

use pwdvault_crypto::KdfParams;
use pwdvault_native_host::handler::{handle_request, HostSession};
use pwdvault_native_host::protocol::{NativeRequest, NativeResponse, VaultStatus};
use pwdvault_vault::{ItemCategory, VaultContainer, VaultItem, VaultPayload};
use std::fs;

#[test]
fn test_full_native_host_autofill_lifecycle_and_phishing_defense() {
    let temp_dir = std::env::temp_dir();
    let vault_path = temp_dir.join(format!("test_native_host_{}.vault.v1", std::process::id()));

    // 1. Create a test vault file
    let mut payload = VaultPayload::new("Browser Test Vault");
    payload.items.push(VaultItem {
        id: "item-github-1".to_string(),
        title: "GitHub".to_string(),
        category: ItemCategory::Login,
        username: Some("dev_alice".to_string()),
        password: Some("super-secret-github-password".to_string()),
        urls: vec!["https://github.com/login".to_string()],
        notes: None,
        totp_seed: None,
        tags: vec![],
        favorite: false,
        custom_fields: vec![],
        attachments: vec![],
        revision_history: vec![],
        trashed_at: None,
        created_at: 1000,
        updated_at: 1000,
    });

    const PASS: &str = "MasterPassword2026!";
    let kdf = KdfParams::new(16 * 1024, 1, 1, [7u8; 32]).unwrap();
    let container_bytes = VaultContainer::create(PASS.as_bytes(), kdf, &payload).unwrap();
    fs::write(&vault_path, &container_bytes).unwrap();

    // 2. Initialize host session
    let mut session = HostSession::new(vault_path.clone());
    assert_eq!(session.status(), VaultStatus::Locked);

    // 3. Handshake
    let handshake_req = NativeRequest::Handshake {
        client_nonce: "nonce-101".to_string(),
        extension_id: "com.antigravity.pwdvault".to_string(),
    };
    let handshake_resp = handle_request(&mut session, handshake_req);
    let session_token = match handshake_resp {
        NativeResponse::HandshakeResponse {
            session_token,
            vault_status,
            ..
        } => {
            assert_eq!(vault_status, VaultStatus::Locked);
            session_token
        }
        _ => panic!("Expected HandshakeResponse"),
    };

    // 4. Unlock vault
    let unlock_req = NativeRequest::Unlock {
        session_token: session_token.clone(),
        passphrase: PASS.to_string(),
        vault_path: None,
    };
    let unlock_resp = handle_request(&mut session, unlock_req);
    match unlock_resp {
        NativeResponse::UnlockResponse {
            success,
            item_count,
            ..
        } => {
            assert!(success);
            assert_eq!(item_count, 1);
        }
        _ => panic!("Expected UnlockResponse"),
    }
    assert_eq!(session.status(), VaultStatus::Unlocked);

    // 5. Query matching logins for github.com
    let get_logins_req = NativeRequest::GetLogins {
        session_token: session_token.clone(),
        url: "https://github.com/login".to_string(),
    };
    let logins_resp = handle_request(&mut session, get_logins_req);
    match logins_resp {
        NativeResponse::GetLoginsResponse { logins } => {
            assert_eq!(logins.len(), 1);
            assert_eq!(logins[0].title, "GitHub");
            assert_eq!(logins[0].username.as_deref(), Some("dev_alice"));
            // Password is intentionally NOT in login summary
        }
        _ => panic!("Expected GetLoginsResponse"),
    }

    // 6. Request credential fill for authorized domain
    let fill_req = NativeRequest::FillCredential {
        session_token: session_token.clone(),
        item_id: "item-github-1".to_string(),
        url: "https://sub.github.com/sessions/new".to_string(),
    };
    let fill_resp = handle_request(&mut session, fill_req);
    match fill_resp {
        NativeResponse::FillCredentialResponse { username, password } => {
            assert_eq!(username.as_deref(), Some("dev_alice"));
            assert_eq!(password.as_deref(), Some("super-secret-github-password"));
        }
        _ => panic!("Expected FillCredentialResponse"),
    }

    // 7. ANTI-PHISHING DEFENSE: Request credential fill for attacker-controlled domain
    let attack_req = NativeRequest::FillCredential {
        session_token: session_token.clone(),
        item_id: "item-github-1".to_string(),
        url: "https://evil-phishing-site.com/steal".to_string(),
    };
    let attack_resp = handle_request(&mut session, attack_req);
    match attack_resp {
        NativeResponse::ErrorResponse { error, code } => {
            assert_eq!(code, 400);
            assert!(error.contains("Origin mismatch"));
        }
        _ => panic!("Expected ErrorResponse for origin mismatch"),
    }

    // 8. Save new credential from browser
    let save_req = NativeRequest::SaveCredential {
        session_token: session_token.clone(),
        title: "ProtonMail".to_string(),
        username: "alice@proton.me".to_string(),
        password: "proton-secret-123".to_string(),
        url: "https://mail.proton.me".to_string(),
    };
    let save_resp = handle_request(&mut session, save_req);
    match save_resp {
        NativeResponse::SaveCredentialResponse { success, .. } => {
            assert!(success);
        }
        _ => panic!("Expected SaveCredentialResponse"),
    }

    // 9. Verify new credential matches in proton.me
    let proton_logins_req = NativeRequest::GetLogins {
        session_token: session_token.clone(),
        url: "https://account.proton.me/login".to_string(),
    };
    let proton_resp = handle_request(&mut session, proton_logins_req);
    match proton_resp {
        NativeResponse::GetLoginsResponse { logins } => {
            assert_eq!(logins.len(), 1);
            assert_eq!(logins[0].title, "ProtonMail");
        }
        _ => panic!("Expected GetLoginsResponse for ProtonMail"),
    }

    // 10. Lock vault and ensure subsequent requests fail
    let lock_req = NativeRequest::Lock {
        session_token: session_token.clone(),
    };
    let lock_resp = handle_request(&mut session, lock_req);
    assert!(matches!(
        lock_resp,
        NativeResponse::LockResponse { success: true }
    ));

    let locked_get_req = NativeRequest::GetLogins {
        session_token,
        url: "https://github.com".to_string(),
    };
    let locked_resp = handle_request(&mut session, locked_get_req);
    match locked_resp {
        NativeResponse::ErrorResponse { error, .. } => {
            assert!(error.contains("Vault is locked"));
        }
        _ => panic!("Expected Vault is locked error"),
    }

    let _ = fs::remove_file(vault_path);
}
