#![warn(missing_docs)]

//! # pwdvault-ffi
//! Minimal typed C-ABI FFI boundary linking the Rust security core with Flutter and native platforms.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::panic::catch_unwind;

use pwdvault_backup::{
    BackupArchive, BackupCredential, RecoveryKey, RecoveryKitDocument,
};
use pwdvault_crypto::KdfParams;
use pwdvault_generator::{
    estimate_crack_time, generate_passphrase, generate_password, PassphraseOptions, PasswordOptions,
};
use pwdvault_import_export::{
    dedup::{DeduplicationEngine, ImportCandidate},
    CsvExporter, ImportManager,
};
use pwdvault_search::{SearchIndex, SearchQuery};
use pwdvault_security::{
    audit_vault, check_suffix_in_range_response, decode_base32, generate_passkey, generate_totp,
    parse_otpauth_uri, prepare_breach_query, sign_assertion, time_remaining, verify_totp,
    PasskeyCredential, TotpAlgorithm, TotpConfig,
};
use pwdvault_sync::{
    apply_syncpack, create_syncpack, generate_pairing_qr_data, merge_vault_payloads,
    verify_pairing_qr_data, VectorClock,
};
use pwdvault_vault::{VaultContainer, VaultItem, VaultPayload};

/// Standard FFI return codes.
#[repr(C)]
#[derive(Debug, PartialEq, Eq)]
pub enum FfiResultCode {
    /// Operation succeeded.
    Success = 0,
    /// Null pointer or invalid argument passed.
    InvalidArgument = 1,
    /// Vault authentication failed (incorrect password or corrupted data).
    AuthenticationFailed = 2,
    /// Vault integrity check failed (tampered or truncated data).
    IntegrityFailed = 3,
    /// Internal unexpected error / panic caught.
    InternalError = 4,
}

/// Helper to convert a raw C string pointer to a safe Rust &str.
///
/// # Safety
/// Caller must ensure `ptr` is a valid, null-terminated UTF-8 string pointer.
unsafe fn c_str_to_str<'a>(ptr: *const c_char) -> Result<&'a str, FfiResultCode> {
    if ptr.is_null() {
        return Err(FfiResultCode::InvalidArgument);
    }
    // SAFETY: caller guarantees null termination and valid pointer
    let c_str = unsafe { CStr::from_ptr(ptr) };
    c_str.to_str().map_err(|_| FfiResultCode::InvalidArgument)
}

/// Creates a new encrypted vault container from a passphrase and returns a JSON string with metadata.
///
/// # Safety
/// `passphrase_ptr` and `vault_name_ptr` must be valid, null-terminated C string pointers.
/// `out_bytes` must be a valid pointer to receive a buffer of encrypted bytes.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_create_vault(
    passphrase_ptr: *const c_char,
    vault_name_ptr: *const c_char,
    out_data: *mut *mut u8,
    out_len: *mut usize,
) -> FfiResultCode {
    let result = catch_unwind(|| {
        if out_data.is_null() || out_len.is_null() {
            return FfiResultCode::InvalidArgument;
        }

        // SAFETY: dereferencing checked pointers
        let passphrase = match unsafe { c_str_to_str(passphrase_ptr) } {
            Ok(s) => s,
            Err(e) => return e,
        };

        let vault_name = match unsafe { c_str_to_str(vault_name_ptr) } {
            Ok(s) => s,
            Err(e) => return e,
        };

        let kdf_params = match KdfParams::test_profile() {
            Ok(p) => p,
            Err(_) => return FfiResultCode::InternalError,
        };

        let payload = VaultPayload::new(vault_name);
        let encrypted_bytes =
            match VaultContainer::create(passphrase.as_bytes(), kdf_params, &payload) {
                Ok(b) => b,
                Err(_) => return FfiResultCode::InternalError,
            };

        let len = encrypted_bytes.len();
        let mut boxed = encrypted_bytes.into_boxed_slice();
        let ptr = boxed.as_mut_ptr();
        std::mem::forget(boxed);

        // SAFETY: write to non-null out pointers
        unsafe {
            *out_data = ptr;
            *out_len = len;
        }

        FfiResultCode::Success
    });

    result.unwrap_or(FfiResultCode::InternalError)
}

/// Encrypts an updated vault payload with a passphrase and returns the serialized encrypted container bytes.
///
/// # Safety
/// `passphrase_ptr` and `payload_json_ptr` must be valid, null-terminated C string pointers.
/// `out_data` and `out_len` must be non-null pointers to receive the resulting byte buffer.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_save_vault(
    passphrase_ptr: *const c_char,
    payload_json_ptr: *const c_char,
    out_data: *mut *mut u8,
    out_len: *mut usize,
) -> FfiResultCode {
    let result = catch_unwind(|| {
        if out_data.is_null() || out_len.is_null() {
            return FfiResultCode::InvalidArgument;
        }

        let passphrase = match unsafe { c_str_to_str(passphrase_ptr) } {
            Ok(s) => s,
            Err(e) => return e,
        };

        let payload_json = match unsafe { c_str_to_str(payload_json_ptr) } {
            Ok(s) => s,
            Err(e) => return e,
        };

        let payload: VaultPayload = match serde_json::from_str(payload_json) {
            Ok(p) => p,
            Err(_) => return FfiResultCode::InvalidArgument,
        };

        let kdf_params = match KdfParams::test_profile() {
            Ok(p) => p,
            Err(_) => return FfiResultCode::InternalError,
        };

        let encrypted_bytes =
            match VaultContainer::create(passphrase.as_bytes(), kdf_params, &payload) {
                Ok(b) => b,
                Err(_) => return FfiResultCode::InternalError,
            };

        let len = encrypted_bytes.len();
        let mut boxed = encrypted_bytes.into_boxed_slice();
        let ptr = boxed.as_mut_ptr();
        std::mem::forget(boxed);

        unsafe {
            *out_data = ptr;
            *out_len = len;
        }

        FfiResultCode::Success
    });

    result.unwrap_or(FfiResultCode::InternalError)
}

/// Unlocks an encrypted vault and returns the decrypted payload serialized as JSON.
///
/// # Safety
/// `vault_bytes` must point to a buffer of length `vault_len`.
/// `passphrase_ptr` must be a valid, null-terminated C string pointer.
/// `out_json` must be a non-null pointer to receive the resulting C string.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_unlock_vault(
    vault_bytes: *const u8,
    vault_len: usize,
    passphrase_ptr: *const c_char,
    out_json: *mut *mut c_char,
) -> FfiResultCode {
    let result = catch_unwind(|| {
        if vault_bytes.is_null() || out_json.is_null() || vault_len == 0 {
            return FfiResultCode::InvalidArgument;
        }

        // SAFETY: reading vault buffer of declared length
        let slice = unsafe { std::slice::from_raw_parts(vault_bytes, vault_len) };

        let passphrase = match unsafe { c_str_to_str(passphrase_ptr) } {
            Ok(s) => s,
            Err(e) => return e,
        };

        match VaultContainer::unlock(slice, passphrase.as_bytes()) {
            Ok((_header, _dek, payload)) => {
                let json = match serde_json::to_string(&payload) {
                    Ok(j) => j,
                    Err(_) => return FfiResultCode::InternalError,
                };
                let c_string = match CString::new(json) {
                    Ok(cs) => cs,
                    Err(_) => return FfiResultCode::InternalError,
                };
                // SAFETY: write to non-null out_json
                unsafe {
                    *out_json = c_string.into_raw();
                }
                FfiResultCode::Success
            }
            Err(pwdvault_vault::VaultError::AuthenticationFailed) => {
                FfiResultCode::AuthenticationFailed
            }
            Err(pwdvault_vault::VaultError::IntegrityCheckFailed) => FfiResultCode::IntegrityFailed,
            Err(_) => FfiResultCode::InternalError,
        }
    });

    result.unwrap_or(FfiResultCode::InternalError)
}

/// Generates a random password using JSON configuration options.
///
/// # Safety
/// `options_json` must be a valid, null-terminated C string or null for defaults.
/// `out_password` must be a non-null pointer to receive the resulting C string.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_generate_password(
    options_json: *const c_char,
    out_password: *mut *mut c_char,
) -> FfiResultCode {
    let result = catch_unwind(|| {
        if out_password.is_null() {
            return FfiResultCode::InvalidArgument;
        }

        let options: PasswordOptions = if options_json.is_null() {
            PasswordOptions::default()
        } else {
            // SAFETY: options_json checked non-null
            let json_str = match unsafe { c_str_to_str(options_json) } {
                Ok(s) => s,
                Err(e) => return e,
            };
            match serde_json::from_str(json_str) {
                Ok(opts) => opts,
                Err(_) => return FfiResultCode::InvalidArgument,
            }
        };

        match generate_password(&options) {
            Ok(pw) => {
                let c_string = match CString::new(pw.as_str()) {
                    Ok(cs) => cs,
                    Err(_) => return FfiResultCode::InternalError,
                };
                // SAFETY: write to checked non-null pointer
                unsafe {
                    *out_password = c_string.into_raw();
                }
                FfiResultCode::Success
            }
            Err(_) => FfiResultCode::InternalError,
        }
    });

    result.unwrap_or(FfiResultCode::InternalError)
}

/// Generates an EFF wordlist passphrase using JSON configuration options.
///
/// # Safety
/// `options_json` must be a valid, null-terminated C string or null for defaults.
/// `out_passphrase` must be a non-null pointer to receive the resulting C string.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_generate_passphrase(
    options_json: *const c_char,
    out_passphrase: *mut *mut c_char,
) -> FfiResultCode {
    let result = catch_unwind(|| {
        if out_passphrase.is_null() {
            return FfiResultCode::InvalidArgument;
        }

        let options: PassphraseOptions = if options_json.is_null() {
            PassphraseOptions::default()
        } else {
            // SAFETY: options_json checked non-null
            let json_str = match unsafe { c_str_to_str(options_json) } {
                Ok(s) => s,
                Err(e) => return e,
            };
            match serde_json::from_str(json_str) {
                Ok(opts) => opts,
                Err(_) => return FfiResultCode::InvalidArgument,
            }
        };

        match generate_passphrase(&options) {
            Ok(pass) => {
                let c_string = match CString::new(pass.as_str()) {
                    Ok(cs) => cs,
                    Err(_) => return FfiResultCode::InternalError,
                };
                // SAFETY: write to checked non-null pointer
                unsafe {
                    *out_passphrase = c_string.into_raw();
                }
                FfiResultCode::Success
            }
            Err(_) => FfiResultCode::InternalError,
        }
    });

    result.unwrap_or(FfiResultCode::InternalError)
}

/// Evaluates entropy and crack-time models for a secret string.
///
/// # Safety
/// `secret_ptr` must be a valid, null-terminated C string pointer.
/// `out_json` must be a non-null pointer to receive the resulting C string.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_estimate_crack_time(
    secret_ptr: *const c_char,
    out_json: *mut *mut c_char,
) -> FfiResultCode {
    let result = catch_unwind(|| {
        if out_json.is_null() {
            return FfiResultCode::InvalidArgument;
        }

        // SAFETY: dereferencing checked pointer
        let secret = match unsafe { c_str_to_str(secret_ptr) } {
            Ok(s) => s,
            Err(e) => return e,
        };

        let estimate = estimate_crack_time(secret);
        let json = match serde_json::to_string(&estimate) {
            Ok(j) => j,
            Err(_) => return FfiResultCode::InternalError,
        };

        let c_string = match CString::new(json) {
            Ok(cs) => cs,
            Err(_) => return FfiResultCode::InternalError,
        };

        // SAFETY: write to checked non-null pointer
        unsafe {
            *out_json = c_string.into_raw();
        }
        FfiResultCode::Success
    });

    result.unwrap_or(FfiResultCode::InternalError)
}

/// Executes an in-memory search over a vault payload using query JSON.
///
/// # Safety
/// `payload_json` and `query_json` must be valid, null-terminated C string pointers.
/// `out_json` must be a non-null pointer to receive the ranked search results.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_search(
    payload_json: *const c_char,
    query_json: *const c_char,
    out_json: *mut *mut c_char,
) -> FfiResultCode {
    let result = catch_unwind(|| {
        if out_json.is_null() {
            return FfiResultCode::InvalidArgument;
        }

        // SAFETY: dereferencing checked pointers
        let payload_str = match unsafe { c_str_to_str(payload_json) } {
            Ok(s) => s,
            Err(e) => return e,
        };

        let query_str = match unsafe { c_str_to_str(query_json) } {
            Ok(s) => s,
            Err(e) => return e,
        };

        let payload: VaultPayload = match serde_json::from_str(payload_str) {
            Ok(p) => p,
            Err(_) => return FfiResultCode::InvalidArgument,
        };

        let query: SearchQuery = match serde_json::from_str(query_str) {
            Ok(q) => q,
            Err(_) => return FfiResultCode::InvalidArgument,
        };

        let index = SearchIndex::from_payload(&payload);
        let results = index.search(&query);

        let json = match serde_json::to_string(&results) {
            Ok(j) => j,
            Err(_) => return FfiResultCode::InternalError,
        };

        let c_string = match CString::new(json) {
            Ok(cs) => cs,
            Err(_) => return FfiResultCode::InternalError,
        };

        // SAFETY: write to checked non-null pointer
        unsafe {
            *out_json = c_string.into_raw();
        }
        FfiResultCode::Success
    });

    result.unwrap_or(FfiResultCode::InternalError)
}

/// Creates an encrypted `.vaultbak` backup archive.
///
/// # Safety
/// Pointers must be valid C-strings and output pointers must be non-null.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_create_backup(
    payload_json_ptr: *const c_char,
    passphrase_ptr: *const c_char,
    recovery_key_ptr: *const c_char,
    out_data: *mut *mut u8,
    out_len: *mut usize,
) -> FfiResultCode {
    let result = catch_unwind(|| {
        if payload_json_ptr.is_null() || out_data.is_null() || out_len.is_null() {
            return FfiResultCode::InvalidArgument;
        }

        let payload_json = match unsafe { c_str_to_str(payload_json_ptr) } {
            Ok(s) => s,
            Err(e) => return e,
        };

        let payload: VaultPayload = match serde_json::from_str(payload_json) {
            Ok(p) => p,
            Err(_) => return FfiResultCode::InvalidArgument,
        };

        let recovery_key_obj;
        let credential = if !recovery_key_ptr.is_null() {
            let key_str = match unsafe { c_str_to_str(recovery_key_ptr) } {
                Ok(s) => s,
                Err(e) => return e,
            };
            recovery_key_obj = match RecoveryKey::parse(key_str) {
                Ok(k) => k,
                Err(_) => return FfiResultCode::InvalidArgument,
            };
            BackupCredential::RecoveryKey(&recovery_key_obj)
        } else if !passphrase_ptr.is_null() {
            let pass = match unsafe { c_str_to_str(passphrase_ptr) } {
                Ok(s) => s,
                Err(e) => return e,
            };
            BackupCredential::Passphrase(pass)
        } else {
            return FfiResultCode::InvalidArgument;
        };

        let backup_bytes = match BackupArchive::create_backup(&payload, credential, false) {
            Ok(b) => b,
            Err(_) => return FfiResultCode::InternalError,
        };

        let len = backup_bytes.len();
        let boxed = backup_bytes.into_boxed_slice();
        let raw_ptr = Box::into_raw(boxed) as *mut u8;

        unsafe {
            *out_data = raw_ptr;
            *out_len = len;
        }

        FfiResultCode::Success
    });

    result.unwrap_or(FfiResultCode::InternalError)
}

/// Rehearses a backup restoration dry-run, outputting a verification report JSON.
///
/// # Safety
/// Pointers must be valid buffers / C-strings and output pointers non-null.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_rehearse_restore(
    backup_data_ptr: *const u8,
    backup_len: usize,
    passphrase_ptr: *const c_char,
    recovery_key_ptr: *const c_char,
    out_report_json: *mut *mut c_char,
) -> FfiResultCode {
    let result = catch_unwind(|| {
        if backup_data_ptr.is_null() || backup_len == 0 || out_report_json.is_null() {
            return FfiResultCode::InvalidArgument;
        }

        let slice = unsafe { std::slice::from_raw_parts(backup_data_ptr, backup_len) };

        let recovery_key_obj;
        let credential = if !recovery_key_ptr.is_null() {
            let key_str = match unsafe { c_str_to_str(recovery_key_ptr) } {
                Ok(s) => s,
                Err(e) => return e,
            };
            recovery_key_obj = match RecoveryKey::parse(key_str) {
                Ok(k) => k,
                Err(_) => return FfiResultCode::InvalidArgument,
            };
            BackupCredential::RecoveryKey(&recovery_key_obj)
        } else if !passphrase_ptr.is_null() {
            let pass = match unsafe { c_str_to_str(passphrase_ptr) } {
                Ok(s) => s,
                Err(e) => return e,
            };
            BackupCredential::Passphrase(pass)
        } else {
            return FfiResultCode::InvalidArgument;
        };

        let report = BackupArchive::rehearse_restore(slice, credential);
        let json_str = match serde_json::to_string(&report) {
            Ok(s) => s,
            Err(_) => return FfiResultCode::InternalError,
        };

        let c_str = match CString::new(json_str) {
            Ok(cs) => cs,
            Err(_) => return FfiResultCode::InternalError,
        };

        unsafe {
            *out_report_json = c_str.into_raw();
        }

        FfiResultCode::Success
    });

    result.unwrap_or(FfiResultCode::InternalError)
}

/// Restores an authenticated payload from a `.vaultbak` archive.
///
/// # Safety
/// Pointers must be valid buffers / C-strings and output pointers non-null.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_restore_backup(
    backup_data_ptr: *const u8,
    backup_len: usize,
    passphrase_ptr: *const c_char,
    recovery_key_ptr: *const c_char,
    out_payload_json: *mut *mut c_char,
) -> FfiResultCode {
    let result = catch_unwind(|| {
        if backup_data_ptr.is_null() || backup_len == 0 || out_payload_json.is_null() {
            return FfiResultCode::InvalidArgument;
        }

        let slice = unsafe { std::slice::from_raw_parts(backup_data_ptr, backup_len) };

        let recovery_key_obj;
        let credential = if !recovery_key_ptr.is_null() {
            let key_str = match unsafe { c_str_to_str(recovery_key_ptr) } {
                Ok(s) => s,
                Err(e) => return e,
            };
            recovery_key_obj = match RecoveryKey::parse(key_str) {
                Ok(k) => k,
                Err(_) => return FfiResultCode::InvalidArgument,
            };
            BackupCredential::RecoveryKey(&recovery_key_obj)
        } else if !passphrase_ptr.is_null() {
            let pass = match unsafe { c_str_to_str(passphrase_ptr) } {
                Ok(s) => s,
                Err(e) => return e,
            };
            BackupCredential::Passphrase(pass)
        } else {
            return FfiResultCode::InvalidArgument;
        };

        let (payload, _header) = match BackupArchive::restore_backup(slice, credential) {
            Ok(pair) => pair,
            Err(e) => match e {
                pwdvault_backup::BackupError::VerifyFailed(msg) => {
                    if msg.contains("Decryption failed") {
                        return FfiResultCode::AuthenticationFailed;
                    } else {
                        return FfiResultCode::IntegrityFailed;
                    }
                }
                _ => return FfiResultCode::InternalError,
            },
        };

        let json_str = match serde_json::to_string(&payload) {
            Ok(s) => s,
            Err(_) => return FfiResultCode::InternalError,
        };

        let c_str = match CString::new(json_str) {
            Ok(cs) => cs,
            Err(_) => return FfiResultCode::InternalError,
        };

        unsafe {
            *out_payload_json = c_str.into_raw();
        }

        FfiResultCode::Success
    });

    result.unwrap_or(FfiResultCode::InternalError)
}

/// Generates a fresh 256-bit emergency recovery key in Crockford Base32 format.
///
/// # Safety
/// `out_key` must be a valid non-null pointer.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_generate_recovery_key(
    out_key: *mut *mut c_char,
) -> FfiResultCode {
    let result = catch_unwind(|| {
        if out_key.is_null() {
            return FfiResultCode::InvalidArgument;
        }

        let key = match RecoveryKey::generate() {
            Ok(k) => k,
            Err(_) => return FfiResultCode::InternalError,
        };

        let formatted = key.to_formatted_string();
        let c_str = match CString::new(formatted) {
            Ok(cs) => cs,
            Err(_) => return FfiResultCode::InternalError,
        };

        unsafe {
            *out_key = c_str.into_raw();
        }

        FfiResultCode::Success
    });

    result.unwrap_or(FfiResultCode::InternalError)
}

/// Generates an Emergency Recovery Kit document JSON.
///
/// # Safety
/// Pointers must be valid C-strings and output pointer non-null.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_generate_recovery_kit_doc(
    vault_name_ptr: *const c_char,
    recovery_key_ptr: *const c_char,
    out_doc_json: *mut *mut c_char,
) -> FfiResultCode {
    let result = catch_unwind(|| {
        if vault_name_ptr.is_null() || recovery_key_ptr.is_null() || out_doc_json.is_null() {
            return FfiResultCode::InvalidArgument;
        }

        let vault_name = match unsafe { c_str_to_str(vault_name_ptr) } {
            Ok(s) => s,
            Err(e) => return e,
        };

        let key_str = match unsafe { c_str_to_str(recovery_key_ptr) } {
            Ok(s) => s,
            Err(e) => return e,
        };

        let recovery_key = match RecoveryKey::parse(key_str) {
            Ok(k) => k,
            Err(_) => return FfiResultCode::InvalidArgument,
        };

        let doc = RecoveryKitDocument::new(vault_name, &recovery_key);
        let doc_json = match serde_json::to_string(&doc) {
            Ok(s) => s,
            Err(_) => return FfiResultCode::InternalError,
        };

        let c_str = match CString::new(doc_json) {
            Ok(cs) => cs,
            Err(_) => return FfiResultCode::InternalError,
        };

        unsafe {
            *out_doc_json = c_str.into_raw();
        }

        FfiResultCode::Success
    });

    result.unwrap_or(FfiResultCode::InternalError)
}

/// Parses external export content (Bitwarden, 1Password, KeePass XML, CSV) into JSON items array.
///
/// # Safety
/// Pointers must be valid C-strings and output pointer non-null.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_parse_import(
    content_ptr: *const c_char,
    out_items_json: *mut *mut c_char,
) -> FfiResultCode {
    let result = catch_unwind(|| {
        if content_ptr.is_null() || out_items_json.is_null() {
            return FfiResultCode::InvalidArgument;
        }

        let content = match unsafe { c_str_to_str(content_ptr) } {
            Ok(s) => s,
            Err(e) => return e,
        };

        let items = match ImportManager::parse_auto(content) {
            Ok(it) => it,
            Err(_) => return FfiResultCode::InvalidArgument,
        };

        let json_str = match serde_json::to_string(&items) {
            Ok(s) => s,
            Err(_) => return FfiResultCode::InternalError,
        };

        let c_str = match CString::new(json_str) {
            Ok(cs) => cs,
            Err(_) => return FfiResultCode::InternalError,
        };

        unsafe {
            *out_items_json = c_str.into_raw();
        }

        FfiResultCode::Success
    });

    result.unwrap_or(FfiResultCode::InternalError)
}

/// Analyzes deduplication status between current vault and incoming items.
///
/// # Safety
/// Pointers must be valid C-strings and output pointer non-null.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_analyze_dedup(
    current_items_json_ptr: *const c_char,
    incoming_items_json_ptr: *const c_char,
    out_preview_json: *mut *mut c_char,
) -> FfiResultCode {
    let result = catch_unwind(|| {
        if current_items_json_ptr.is_null()
            || incoming_items_json_ptr.is_null()
            || out_preview_json.is_null()
        {
            return FfiResultCode::InvalidArgument;
        }

        let current_json = match unsafe { c_str_to_str(current_items_json_ptr) } {
            Ok(s) => s,
            Err(e) => return e,
        };

        let incoming_json = match unsafe { c_str_to_str(incoming_items_json_ptr) } {
            Ok(s) => s,
            Err(e) => return e,
        };

        let current_items: Vec<VaultItem> = match serde_json::from_str(current_json) {
            Ok(v) => v,
            Err(_) => return FfiResultCode::InvalidArgument,
        };

        let incoming_items: Vec<VaultItem> = match serde_json::from_str(incoming_json) {
            Ok(v) => v,
            Err(_) => return FfiResultCode::InvalidArgument,
        };

        let preview = DeduplicationEngine::analyze(&current_items, &incoming_items);
        let preview_json = match serde_json::to_string(&preview) {
            Ok(s) => s,
            Err(_) => return FfiResultCode::InternalError,
        };

        let c_str = match CString::new(preview_json) {
            Ok(cs) => cs,
            Err(_) => return FfiResultCode::InternalError,
        };

        unsafe {
            *out_preview_json = c_str.into_raw();
        }

        FfiResultCode::Success
    });

    result.unwrap_or(FfiResultCode::InternalError)
}

/// Applies resolved import candidates to the current items list.
///
/// # Safety
/// Pointers must be valid C-strings and output pointer non-null.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_apply_import(
    current_items_json_ptr: *const c_char,
    candidates_json_ptr: *const c_char,
    out_updated_items_json: *mut *mut c_char,
) -> FfiResultCode {
    let result = catch_unwind(|| {
        if current_items_json_ptr.is_null()
            || candidates_json_ptr.is_null()
            || out_updated_items_json.is_null()
        {
            return FfiResultCode::InvalidArgument;
        }

        let current_json = match unsafe { c_str_to_str(current_items_json_ptr) } {
            Ok(s) => s,
            Err(e) => return e,
        };

        let candidates_json = match unsafe { c_str_to_str(candidates_json_ptr) } {
            Ok(s) => s,
            Err(e) => return e,
        };

        let mut current_items: Vec<VaultItem> = match serde_json::from_str(current_json) {
            Ok(v) => v,
            Err(_) => return FfiResultCode::InvalidArgument,
        };

        let candidates: Vec<ImportCandidate> = match serde_json::from_str(candidates_json) {
            Ok(v) => v,
            Err(_) => return FfiResultCode::InvalidArgument,
        };

        let _count = DeduplicationEngine::apply(&mut current_items, &candidates);
        let updated_json = match serde_json::to_string(&current_items) {
            Ok(s) => s,
            Err(_) => return FfiResultCode::InternalError,
        };

        let c_str = match CString::new(updated_json) {
            Ok(cs) => cs,
            Err(_) => return FfiResultCode::InternalError,
        };

        unsafe {
            *out_updated_items_json = c_str.into_raw();
        }

        FfiResultCode::Success
    });

    result.unwrap_or(FfiResultCode::InternalError)
}

/// Exports a list of vault items to RFC 4180 CSV string.
///
/// # Safety
/// `items_json_ptr` must be valid C-string and `out_csv` non-null.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_export_csv(
    items_json_ptr: *const c_char,
    out_csv: *mut *mut c_char,
) -> FfiResultCode {
    let result = catch_unwind(|| {
        if items_json_ptr.is_null() || out_csv.is_null() {
            return FfiResultCode::InvalidArgument;
        }

        let items_json = match unsafe { c_str_to_str(items_json_ptr) } {
            Ok(s) => s,
            Err(e) => return e,
        };

        let items: Vec<VaultItem> = match serde_json::from_str(items_json) {
            Ok(v) => v,
            Err(_) => return FfiResultCode::InvalidArgument,
        };

        let csv_str = CsvExporter::export(&items);
        let c_str = match CString::new(csv_str) {
            Ok(cs) => cs,
            Err(_) => return FfiResultCode::InternalError,
        };

        unsafe {
            *out_csv = c_str.into_raw();
        }

        FfiResultCode::Success
    });

    result.unwrap_or(FfiResultCode::InternalError)
}

fn parse_sync_key_hex(hex_str: &str) -> Result<[u8; 32], FfiResultCode> {
    let clean = hex_str.trim();
    if clean.len() != 64 {
        return Err(FfiResultCode::InvalidArgument);
    }
    let mut bytes = [0u8; 32];
    for i in 0..32 {
        bytes[i] = u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16)
            .map_err(|_| FfiResultCode::InvalidArgument)?;
    }
    Ok(bytes)
}

/// Creates an encrypted `.syncpack` container from a vault payload.
///
/// # Safety
/// All pointers must be valid C-strings and output pointers non-null.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_sync_create_syncpack(
    payload_json_ptr: *const c_char,
    sync_key_hex_ptr: *const c_char,
    device_id_ptr: *const c_char,
    device_name_ptr: *const c_char,
    clock_json_ptr: *const c_char,
    out_data_ptr: *mut *mut u8,
    out_len_ptr: *mut usize,
) -> FfiResultCode {
    let result = catch_unwind(|| {
        if payload_json_ptr.is_null()
            || sync_key_hex_ptr.is_null()
            || device_id_ptr.is_null()
            || device_name_ptr.is_null()
            || out_data_ptr.is_null()
            || out_len_ptr.is_null()
        {
            return FfiResultCode::InvalidArgument;
        }

        let payload_json = match unsafe { c_str_to_str(payload_json_ptr) } {
            Ok(s) => s,
            Err(e) => return e,
        };

        let payload: VaultPayload = match serde_json::from_str(payload_json) {
            Ok(p) => p,
            Err(_) => return FfiResultCode::InvalidArgument,
        };

        let sync_key_str = match unsafe { c_str_to_str(sync_key_hex_ptr) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let sync_key = match parse_sync_key_hex(sync_key_str) {
            Ok(k) => k,
            Err(e) => return e,
        };

        let device_id = match unsafe { c_str_to_str(device_id_ptr) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let device_name = match unsafe { c_str_to_str(device_name_ptr) } {
            Ok(s) => s,
            Err(e) => return e,
        };

        let clock: VectorClock = if !clock_json_ptr.is_null() {
            let clock_str = match unsafe { c_str_to_str(clock_json_ptr) } {
                Ok(s) => s,
                Err(e) => return e,
            };
            serde_json::from_str(clock_str).unwrap_or_default()
        } else {
            VectorClock::default()
        };

        let pack_bytes = match create_syncpack(&payload, &sync_key, device_id, device_name, &clock) {
            Ok(b) => b,
            Err(_) => return FfiResultCode::InternalError,
        };

        let len = pack_bytes.len();
        let mut boxed_slice = pack_bytes.into_boxed_slice();
        let raw_ptr = boxed_slice.as_mut_ptr();
        std::mem::forget(boxed_slice);

        unsafe {
            *out_data_ptr = raw_ptr;
            *out_len_ptr = len;
        }

        FfiResultCode::Success
    });

    result.unwrap_or(FfiResultCode::InternalError)
}

/// Applies an encrypted `.syncpack` to a local vault payload and updates the vector clock.
///
/// # Safety
/// Pointers must be valid buffers and C-strings. Output pointer must be non-null.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_sync_apply_syncpack(
    local_payload_json_ptr: *const c_char,
    local_clock_json_ptr: *const c_char,
    pack_data_ptr: *const u8,
    pack_len: usize,
    sync_key_hex_ptr: *const c_char,
    out_result_json: *mut *mut c_char,
) -> FfiResultCode {
    let result = catch_unwind(|| {
        if local_payload_json_ptr.is_null()
            || pack_data_ptr.is_null()
            || pack_len == 0
            || sync_key_hex_ptr.is_null()
            || out_result_json.is_null()
        {
            return FfiResultCode::InvalidArgument;
        }

        let local_payload_json = match unsafe { c_str_to_str(local_payload_json_ptr) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let mut local_payload: VaultPayload = match serde_json::from_str(local_payload_json) {
            Ok(p) => p,
            Err(_) => return FfiResultCode::InvalidArgument,
        };

        let mut local_clock: VectorClock = if !local_clock_json_ptr.is_null() {
            let clock_str = match unsafe { c_str_to_str(local_clock_json_ptr) } {
                Ok(s) => s,
                Err(e) => return e,
            };
            serde_json::from_str(clock_str).unwrap_or_default()
        } else {
            VectorClock::default()
        };

        let sync_key_str = match unsafe { c_str_to_str(sync_key_hex_ptr) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let sync_key = match parse_sync_key_hex(sync_key_str) {
            Ok(k) => k,
            Err(e) => return e,
        };

        let pack_slice = unsafe { std::slice::from_raw_parts(pack_data_ptr, pack_len) };
        let report = match apply_syncpack(&mut local_payload, &mut local_clock, pack_slice, &sync_key) {
            Ok(r) => r,
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("Decryption failed") {
                    return FfiResultCode::AuthenticationFailed;
                } else if msg.contains("truncated") || msg.contains("commitment") {
                    return FfiResultCode::IntegrityFailed;
                } else {
                    return FfiResultCode::InternalError;
                }
            }
        };

        #[derive(serde::Serialize)]
        struct ApplySyncResult {
            report: pwdvault_sync::SyncMergeReport,
            merged_payload: VaultPayload,
            merged_clock: VectorClock,
        }

        let res = ApplySyncResult {
            report,
            merged_payload: local_payload,
            merged_clock: local_clock,
        };

        let json_str = match serde_json::to_string(&res) {
            Ok(s) => s,
            Err(_) => return FfiResultCode::InternalError,
        };

        let c_str = match CString::new(json_str) {
            Ok(cs) => cs,
            Err(_) => return FfiResultCode::InternalError,
        };

        unsafe {
            *out_result_json = c_str.into_raw();
        }

        FfiResultCode::Success
    });

    result.unwrap_or(FfiResultCode::InternalError)
}

/// Generates an out-of-band device pairing QR code URI (`pwdvault://pair?data=...`).
///
/// # Safety
/// Pointers must be valid C-strings and output pointer non-null.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_sync_generate_pairing_qr(
    sync_key_hex_ptr: *const c_char,
    device_id_ptr: *const c_char,
    device_name_ptr: *const c_char,
    addresses_csv_ptr: *const c_char,
    out_qr_uri: *mut *mut c_char,
) -> FfiResultCode {
    let result = catch_unwind(|| {
        if sync_key_hex_ptr.is_null()
            || device_id_ptr.is_null()
            || device_name_ptr.is_null()
            || out_qr_uri.is_null()
        {
            return FfiResultCode::InvalidArgument;
        }

        let sync_key_str = match unsafe { c_str_to_str(sync_key_hex_ptr) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let sync_key = match parse_sync_key_hex(sync_key_str) {
            Ok(k) => k,
            Err(e) => return e,
        };

        let device_id = match unsafe { c_str_to_str(device_id_ptr) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let device_name = match unsafe { c_str_to_str(device_name_ptr) } {
            Ok(s) => s,
            Err(e) => return e,
        };

        let mut addrs = Vec::new();
        if !addresses_csv_ptr.is_null() {
            if let Ok(csv) = unsafe { c_str_to_str(addresses_csv_ptr) } {
                for addr in csv.split(',') {
                    let trimmed = addr.trim();
                    if !trimmed.is_empty() {
                        addrs.push(trimmed.to_string());
                    }
                }
            }
        }

        let uri = match generate_pairing_qr_data(&sync_key, device_id, device_name, &addrs) {
            Ok(u) => u,
            Err(_) => return FfiResultCode::InternalError,
        };

        let c_str = match CString::new(uri) {
            Ok(cs) => cs,
            Err(_) => return FfiResultCode::InternalError,
        };

        unsafe {
            *out_qr_uri = c_str.into_raw();
        }

        FfiResultCode::Success
    });

    result.unwrap_or(FfiResultCode::InternalError)
}

/// Verifies an out-of-band device pairing QR URI against the local sync key.
///
/// # Safety
/// Pointers must be valid C-strings and output pointer non-null.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_sync_verify_pairing_qr(
    qr_uri_ptr: *const c_char,
    sync_key_hex_ptr: *const c_char,
    out_json: *mut *mut c_char,
) -> FfiResultCode {
    let result = catch_unwind(|| {
        if qr_uri_ptr.is_null() || sync_key_hex_ptr.is_null() || out_json.is_null() {
            return FfiResultCode::InvalidArgument;
        }

        let qr_uri = match unsafe { c_str_to_str(qr_uri_ptr) } {
            Ok(s) => s,
            Err(e) => return e,
        };

        let sync_key_str = match unsafe { c_str_to_str(sync_key_hex_ptr) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let sync_key = match parse_sync_key_hex(sync_key_str) {
            Ok(k) => k,
            Err(e) => return e,
        };

        let payload = match verify_pairing_qr_data(qr_uri, &sync_key) {
            Ok(p) => p,
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("mismatch") {
                    return FfiResultCode::AuthenticationFailed;
                } else {
                    return FfiResultCode::InvalidArgument;
                }
            }
        };

        let json_str = match serde_json::to_string(&payload) {
            Ok(s) => s,
            Err(_) => return FfiResultCode::InternalError,
        };

        let c_str = match CString::new(json_str) {
            Ok(cs) => cs,
            Err(_) => return FfiResultCode::InternalError,
        };

        unsafe {
            *out_json = c_str.into_raw();
        }

        FfiResultCode::Success
    });

    result.unwrap_or(FfiResultCode::InternalError)
}

/// Merges remote vault payload into local vault payload using CRDT deterministic LWW with revision preservation.
///
/// # Safety
/// Pointers must be valid C-strings and output pointer non-null.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_sync_merge_payloads(
    local_payload_json_ptr: *const c_char,
    remote_payload_json_ptr: *const c_char,
    out_result_json: *mut *mut c_char,
) -> FfiResultCode {
    let result = catch_unwind(|| {
        if local_payload_json_ptr.is_null()
            || remote_payload_json_ptr.is_null()
            || out_result_json.is_null()
        {
            return FfiResultCode::InvalidArgument;
        }

        let local_json = match unsafe { c_str_to_str(local_payload_json_ptr) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let mut local_payload: VaultPayload = match serde_json::from_str(local_json) {
            Ok(p) => p,
            Err(_) => return FfiResultCode::InvalidArgument,
        };

        let remote_json = match unsafe { c_str_to_str(remote_payload_json_ptr) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let remote_payload: VaultPayload = match serde_json::from_str(remote_json) {
            Ok(p) => p,
            Err(_) => return FfiResultCode::InvalidArgument,
        };

        let report = merge_vault_payloads(&mut local_payload, &remote_payload);

        #[derive(serde::Serialize)]
        struct MergePayloadsResult {
            report: pwdvault_sync::SyncMergeReport,
            merged_payload: VaultPayload,
        }

        let res = MergePayloadsResult {
            report,
            merged_payload: local_payload,
        };

        let json_str = match serde_json::to_string(&res) {
            Ok(s) => s,
            Err(_) => return FfiResultCode::InternalError,
        };

        let c_str = match CString::new(json_str) {
            Ok(cs) => cs,
            Err(_) => return FfiResultCode::InternalError,
        };

        unsafe {
            *out_result_json = c_str.into_raw();
        }

        FfiResultCode::Success
    });

    result.unwrap_or(FfiResultCode::InternalError)
}

/// Generates a current TOTP code and remaining seconds in the cycle.
///
/// # Safety
/// `secret_b32_ptr` must be a valid null-terminated C string representing base32 secret.
/// `out_code` must be a valid pointer to receive a null-terminated C string.
/// `out_remaining` must be a valid pointer to receive a u64.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_totp_generate(
    secret_b32_ptr: *const c_char,
    timestamp_secs: u64,
    digits: u32,
    period: u32,
    algorithm_ptr: *const c_char,
    out_code: *mut *mut c_char,
    out_remaining: *mut u64,
) -> FfiResultCode {
    let result = catch_unwind(|| {
        if secret_b32_ptr.is_null() || out_code.is_null() || out_remaining.is_null() {
            return FfiResultCode::InvalidArgument;
        }

        let secret_b32 = match unsafe { c_str_to_str(secret_b32_ptr) } {
            Ok(s) => s,
            Err(e) => return e,
        };

        let secret = match decode_base32(secret_b32) {
            Ok(s) => s,
            Err(_) => return FfiResultCode::InvalidArgument,
        };

        let alg = if !algorithm_ptr.is_null() {
            if let Ok(s) = unsafe { c_str_to_str(algorithm_ptr) } {
                match s.to_uppercase().as_str() {
                    "SHA256" => TotpAlgorithm::Sha256,
                    "SHA512" => TotpAlgorithm::Sha512,
                    _ => TotpAlgorithm::Sha1,
                }
            } else {
                TotpAlgorithm::Sha1
            }
        } else {
            TotpAlgorithm::Sha1
        };

        let now = if timestamp_secs == 0 {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        } else {
            timestamp_secs
        };

        let config = TotpConfig {
            secret,
            digits: if digits == 0 { 6 } else { digits },
            period_seconds: if period == 0 { 30 } else { period },
            algorithm: alg,
            issuer: None,
            account_name: None,
        };

        let code = generate_totp(&config, now);
        let remaining = time_remaining(&config, now);

        let c_code = match CString::new(code) {
            Ok(cs) => cs,
            Err(_) => return FfiResultCode::InternalError,
        };

        unsafe {
            *out_code = c_code.into_raw();
            *out_remaining = remaining;
        }

        FfiResultCode::Success
    });

    result.unwrap_or(FfiResultCode::InternalError)
}

/// Verifies a TOTP code against a secret within a drift tolerance window.
///
/// # Safety
/// `secret_b32_ptr` and `code_ptr` must be valid null-terminated C strings.
/// `out_valid` must be a valid pointer to receive a bool.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_totp_verify(
    secret_b32_ptr: *const c_char,
    code_ptr: *const c_char,
    timestamp_secs: u64,
    tolerance_steps: u32,
    digits: u32,
    period: u32,
    algorithm_ptr: *const c_char,
    out_valid: *mut bool,
) -> FfiResultCode {
    let result = catch_unwind(|| {
        if secret_b32_ptr.is_null() || code_ptr.is_null() || out_valid.is_null() {
            return FfiResultCode::InvalidArgument;
        }

        let secret_b32 = match unsafe { c_str_to_str(secret_b32_ptr) } {
            Ok(s) => s,
            Err(e) => return e,
        };

        let code = match unsafe { c_str_to_str(code_ptr) } {
            Ok(s) => s,
            Err(e) => return e,
        };

        let secret = match decode_base32(secret_b32) {
            Ok(s) => s,
            Err(_) => return FfiResultCode::InvalidArgument,
        };

        let alg = if !algorithm_ptr.is_null() {
            if let Ok(s) = unsafe { c_str_to_str(algorithm_ptr) } {
                match s.to_uppercase().as_str() {
                    "SHA256" => TotpAlgorithm::Sha256,
                    "SHA512" => TotpAlgorithm::Sha512,
                    _ => TotpAlgorithm::Sha1,
                }
            } else {
                TotpAlgorithm::Sha1
            }
        } else {
            TotpAlgorithm::Sha1
        };

        let now = if timestamp_secs == 0 {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        } else {
            timestamp_secs
        };

        let config = TotpConfig {
            secret,
            digits: if digits == 0 { 6 } else { digits },
            period_seconds: if period == 0 { 30 } else { period },
            algorithm: alg,
            issuer: None,
            account_name: None,
        };

        let valid = verify_totp(&config, code, now, tolerance_steps as i64);

        unsafe {
            *out_valid = valid;
        }

        FfiResultCode::Success
    });

    result.unwrap_or(FfiResultCode::InternalError)
}

/// Parses an `otpauth://totp/` URI and exports its configuration as JSON.
///
/// # Safety
/// `uri_ptr` must be a valid null-terminated C string.
/// `out_config_json` must be a valid pointer to receive a null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_totp_parse_uri(
    uri_ptr: *const c_char,
    out_config_json: *mut *mut c_char,
) -> FfiResultCode {
    let result = catch_unwind(|| {
        if uri_ptr.is_null() || out_config_json.is_null() {
            return FfiResultCode::InvalidArgument;
        }

        let uri = match unsafe { c_str_to_str(uri_ptr) } {
            Ok(s) => s,
            Err(e) => return e,
        };

        let config = match parse_otpauth_uri(uri) {
            Ok(c) => c,
            Err(_) => return FfiResultCode::InvalidArgument,
        };

        let json = match serde_json::to_string(&config) {
            Ok(j) => j,
            Err(_) => return FfiResultCode::InternalError,
        };

        let c_str = match CString::new(json) {
            Ok(cs) => cs,
            Err(_) => return FfiResultCode::InternalError,
        };

        unsafe {
            *out_config_json = c_str.into_raw();
        }

        FfiResultCode::Success
    });

    result.unwrap_or(FfiResultCode::InternalError)
}

/// Generates a new WebAuthn / FIDO2 Passkey credential and returns its JSON representation.
///
/// # Safety
/// `rp_id_ptr` and `user_name_ptr` must be valid null-terminated C strings.
/// `out_passkey_json` must be a valid pointer to receive a null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_passkey_generate(
    rp_id_ptr: *const c_char,
    user_handle_ptr: *const c_char,
    user_name_ptr: *const c_char,
    algorithm: i32,
    out_passkey_json: *mut *mut c_char,
) -> FfiResultCode {
    let result = catch_unwind(|| {
        if rp_id_ptr.is_null() || user_name_ptr.is_null() || out_passkey_json.is_null() {
            return FfiResultCode::InvalidArgument;
        }

        let rp_id = match unsafe { c_str_to_str(rp_id_ptr) } {
            Ok(s) => s,
            Err(e) => return e,
        };

        let user_name = match unsafe { c_str_to_str(user_name_ptr) } {
            Ok(s) => s,
            Err(e) => return e,
        };

        let user_handle = if !user_handle_ptr.is_null() {
            if let Ok(s) = unsafe { c_str_to_str(user_handle_ptr) } {
                if s.len() % 2 == 0 && !s.is_empty() {
                    (0..s.len())
                        .step_by(2)
                        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
                        .collect::<Option<Vec<u8>>>()
                        .unwrap_or_else(|| s.as_bytes().to_vec())
                } else {
                    s.as_bytes().to_vec()
                }
            } else {
                user_name.as_bytes().to_vec()
            }
        } else {
            user_name.as_bytes().to_vec()
        };

        let cred = match generate_passkey(rp_id, &user_handle, user_name, algorithm) {
            Ok(c) => c,
            Err(_) => return FfiResultCode::InternalError,
        };

        let json = match serde_json::to_string(&cred) {
            Ok(j) => j,
            Err(_) => return FfiResultCode::InternalError,
        };

        let c_str = match CString::new(json) {
            Ok(cs) => cs,
            Err(_) => return FfiResultCode::InternalError,
        };

        unsafe {
            *out_passkey_json = c_str.into_raw();
        }

        FfiResultCode::Success
    });

    result.unwrap_or(FfiResultCode::InternalError)
}

/// Signs a WebAuthn assertion using a stored passkey credential.
///
/// # Safety
/// `passkey_json_ptr`, `rp_id_ptr`, and `client_data_json_ptr` must be valid null-terminated C strings.
/// `out_assertion_json` and `out_updated_passkey_json` must be valid pointers to receive null-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_passkey_sign_assertion(
    passkey_json_ptr: *const c_char,
    rp_id_ptr: *const c_char,
    client_data_json_ptr: *const c_char,
    user_present: bool,
    user_verified: bool,
    out_assertion_json: *mut *mut c_char,
    out_updated_passkey_json: *mut *mut c_char,
) -> FfiResultCode {
    let result = catch_unwind(|| {
        if passkey_json_ptr.is_null()
            || rp_id_ptr.is_null()
            || client_data_json_ptr.is_null()
            || out_assertion_json.is_null()
            || out_updated_passkey_json.is_null()
        {
            return FfiResultCode::InvalidArgument;
        }

        let passkey_json = match unsafe { c_str_to_str(passkey_json_ptr) } {
            Ok(s) => s,
            Err(e) => return e,
        };

        let rp_id = match unsafe { c_str_to_str(rp_id_ptr) } {
            Ok(s) => s,
            Err(e) => return e,
        };

        let client_data_json = match unsafe { c_str_to_str(client_data_json_ptr) } {
            Ok(s) => s,
            Err(e) => return e,
        };

        let mut passkey: PasskeyCredential = match serde_json::from_str(passkey_json) {
            Ok(p) => p,
            Err(_) => return FfiResultCode::InvalidArgument,
        };

        let assertion = match sign_assertion(
            &mut passkey,
            rp_id,
            client_data_json,
            user_present,
            user_verified,
        ) {
            Ok(a) => a,
            Err(_) => return FfiResultCode::InternalError,
        };

        let assertion_json = match serde_json::to_string(&assertion) {
            Ok(j) => j,
            Err(_) => return FfiResultCode::InternalError,
        };

        let updated_passkey_json = match serde_json::to_string(&passkey) {
            Ok(j) => j,
            Err(_) => return FfiResultCode::InternalError,
        };

        let c_assertion = match CString::new(assertion_json) {
            Ok(cs) => cs,
            Err(_) => return FfiResultCode::InternalError,
        };

        let c_updated = match CString::new(updated_passkey_json) {
            Ok(cs) => cs,
            Err(_) => return FfiResultCode::InternalError,
        };

        unsafe {
            *out_assertion_json = c_assertion.into_raw();
            *out_updated_passkey_json = c_updated.into_raw();
        }

        FfiResultCode::Success
    });

    result.unwrap_or(FfiResultCode::InternalError)
}

/// Performs a local security and cryptographic hygiene audit on a vault payload.
///
/// # Safety
/// `payload_json_ptr` must be a valid null-terminated C string representing VaultPayload.
/// `out_report_json` must be a valid pointer to receive a null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_audit_vault(
    payload_json_ptr: *const c_char,
    _timestamp_secs: u64,
    out_report_json: *mut *mut c_char,
) -> FfiResultCode {
    let result = catch_unwind(|| {
        if payload_json_ptr.is_null() || out_report_json.is_null() {
            return FfiResultCode::InvalidArgument;
        }

        let payload_json = match unsafe { c_str_to_str(payload_json_ptr) } {
            Ok(s) => s,
            Err(e) => return e,
        };

        let payload: VaultPayload = match serde_json::from_str(payload_json) {
            Ok(p) => p,
            Err(_) => return FfiResultCode::InvalidArgument,
        };

        let report = audit_vault(&payload);

        let json = match serde_json::to_string(&report) {
            Ok(j) => j,
            Err(_) => return FfiResultCode::InternalError,
        };

        let c_str = match CString::new(json) {
            Ok(cs) => cs,
            Err(_) => return FfiResultCode::InternalError,
        };

        unsafe {
            *out_report_json = c_str.into_raw();
        }

        FfiResultCode::Success
    });

    result.unwrap_or(FfiResultCode::InternalError)
}

/// Prepares a privacy-preserving k-Anonymity breach query (5-char hex prefix and 35-char suffix).
///
/// # Safety
/// `password_ptr` must be a valid null-terminated C string.
/// `out_prefix` and `out_suffix` must be valid pointers to receive null-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_breach_prepare_query(
    password_ptr: *const c_char,
    out_prefix: *mut *mut c_char,
    out_suffix: *mut *mut c_char,
) -> FfiResultCode {
    let result = catch_unwind(|| {
        if password_ptr.is_null() || out_prefix.is_null() || out_suffix.is_null() {
            return FfiResultCode::InvalidArgument;
        }

        let password = match unsafe { c_str_to_str(password_ptr) } {
            Ok(s) => s,
            Err(e) => return e,
        };

        let query = prepare_breach_query(password);

        let c_prefix = match CString::new(query.prefix) {
            Ok(cs) => cs,
            Err(_) => return FfiResultCode::InternalError,
        };

        let c_suffix = match CString::new(query.suffix) {
            Ok(cs) => cs,
            Err(_) => return FfiResultCode::InternalError,
        };

        unsafe {
            *out_prefix = c_prefix.into_raw();
            *out_suffix = c_suffix.into_raw();
        }

        FfiResultCode::Success
    });

    result.unwrap_or(FfiResultCode::InternalError)
}

/// Searches for a 35-character suffix in an HIBP range response body and outputs breach count.
///
/// # Safety
/// `suffix_ptr` and `response_body_ptr` must be valid null-terminated C strings.
/// `out_count` must be a valid pointer to receive a u64.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_breach_check_response(
    suffix_ptr: *const c_char,
    response_body_ptr: *const c_char,
    out_count: *mut u64,
) -> FfiResultCode {
    let result = catch_unwind(|| {
        if suffix_ptr.is_null() || response_body_ptr.is_null() || out_count.is_null() {
            return FfiResultCode::InvalidArgument;
        }

        let suffix = match unsafe { c_str_to_str(suffix_ptr) } {
            Ok(s) => s,
            Err(e) => return e,
        };

        let response_body = match unsafe { c_str_to_str(response_body_ptr) } {
            Ok(s) => s,
            Err(e) => return e,
        };

        let count = check_suffix_in_range_response(suffix, response_body).unwrap_or(0);

        unsafe {
            *out_count = count;
        }

        FfiResultCode::Success
    });

    result.unwrap_or(FfiResultCode::InternalError)
}

/// Frees a C string allocated by the Rust core.
///
/// # Safety
/// `ptr` must be a pointer returned from an FFI function or null.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        // SAFETY: reclaiming ownership of CString allocated via into_raw
        unsafe {
            let _ = CString::from_raw(ptr);
        }
    }
}

/// Frees a byte buffer allocated by the Rust core.
///
/// # Safety
/// `ptr` must point to a buffer of length `len` previously allocated by Rust.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_free_bytes(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len > 0 {
        // SAFETY: reconstructing slice and deallocating Box
        unsafe {
            let slice = std::slice::from_raw_parts_mut(ptr, len);
            let _ = Box::from_raw(slice);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn test_ffi_create_and_unlock_cycle() {
        let pw = CString::new("test-master-password").unwrap();
        let name = CString::new("Test Vault").unwrap();

        let mut out_data: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;

        let code = unsafe {
            vault_ffi_create_vault(pw.as_ptr(), name.as_ptr(), &mut out_data, &mut out_len)
        };
        assert_eq!(code, FfiResultCode::Success);
        assert!(!out_data.is_null());
        assert!(out_len > 0);

        // Unlock with correct password
        let mut out_json: *mut c_char = std::ptr::null_mut();
        let unlock_code =
            unsafe { vault_ffi_unlock_vault(out_data, out_len, pw.as_ptr(), &mut out_json) };
        assert_eq!(unlock_code, FfiResultCode::Success);
        assert!(!out_json.is_null());

        let json_str = unsafe { CStr::from_ptr(out_json).to_str().unwrap() };
        assert!(json_str.contains("Test Vault"));

        // Test save vault with modified payload
        let mut save_data: *mut u8 = std::ptr::null_mut();
        let mut save_len: usize = 0;
        let save_code =
            unsafe { vault_ffi_save_vault(pw.as_ptr(), out_json, &mut save_data, &mut save_len) };
        assert_eq!(save_code, FfiResultCode::Success);
        assert!(!save_data.is_null());
        assert!(save_len > 0);

        // Cleanup
        unsafe {
            vault_ffi_free_string(out_json);
            vault_ffi_free_bytes(out_data, out_len);
            vault_ffi_free_bytes(save_data, save_len);
        }
    }

    #[test]
    fn test_ffi_generator_and_search() {
        // 1. Password generation
        let mut out_pw: *mut c_char = std::ptr::null_mut();
        let code = unsafe { vault_ffi_generate_password(std::ptr::null(), &mut out_pw) };
        assert_eq!(code, FfiResultCode::Success);
        assert!(!out_pw.is_null());
        let pw_str = unsafe { CStr::from_ptr(out_pw).to_str().unwrap() };
        assert_eq!(pw_str.len(), 20);

        // 2. Crack time estimation
        let mut out_est: *mut c_char = std::ptr::null_mut();
        let code_est = unsafe { vault_ffi_estimate_crack_time(out_pw, &mut out_est) };
        assert_eq!(code_est, FfiResultCode::Success);
        assert!(!out_est.is_null());
        let est_str = unsafe { CStr::from_ptr(out_est).to_str().unwrap() };
        assert!(est_str.contains("entropy_bits"));

        // Cleanup
        unsafe {
            vault_ffi_free_string(out_pw);
            vault_ffi_free_string(out_est);
        }
    }

    #[test]
    fn test_ffi_backup_and_recovery_cycle() {
        // 1. Generate recovery key
        let mut out_key: *mut c_char = std::ptr::null_mut();
        let code_key = unsafe { vault_ffi_generate_recovery_key(&mut out_key) };
        assert_eq!(code_key, FfiResultCode::Success);
        assert!(!out_key.is_null());

        let key_str = unsafe { CStr::from_ptr(out_key).to_str().unwrap() };
        assert!(key_str.starts_with("PV-"));

        // 2. Generate recovery kit document
        let vault_name = CString::new("Personal Vault").unwrap();
        let mut out_doc: *mut c_char = std::ptr::null_mut();
        let code_doc =
            unsafe { vault_ffi_generate_recovery_kit_doc(vault_name.as_ptr(), out_key, &mut out_doc) };
        assert_eq!(code_doc, FfiResultCode::Success);
        assert!(!out_doc.is_null());

        let doc_str = unsafe { CStr::from_ptr(out_doc).to_str().unwrap() };
        assert!(doc_str.contains("Personal Vault"));
        assert!(doc_str.contains(key_str));

        // 3. Create encrypted backup
        let payload = VaultPayload::new("Backup Test Vault");
        let payload_json = serde_json::to_string(&payload).unwrap();
        let c_payload = CString::new(payload_json).unwrap();
        let backup_pass = CString::new("Backup-Secret-123!").unwrap();

        let mut out_backup: *mut u8 = std::ptr::null_mut();
        let mut out_backup_len: usize = 0;

        let code_bak = unsafe {
            vault_ffi_create_backup(
                c_payload.as_ptr(),
                backup_pass.as_ptr(),
                std::ptr::null(),
                &mut out_backup,
                &mut out_backup_len,
            )
        };
        assert_eq!(code_bak, FfiResultCode::Success);
        assert!(!out_backup.is_null());
        assert!(out_backup_len > 0);

        // 4. Rehearse restore
        let mut out_report: *mut c_char = std::ptr::null_mut();
        let code_reh = unsafe {
            vault_ffi_rehearse_restore(
                out_backup,
                out_backup_len,
                backup_pass.as_ptr(),
                std::ptr::null(),
                &mut out_report,
            )
        };
        assert_eq!(code_reh, FfiResultCode::Success);
        assert!(!out_report.is_null());

        let report_str = unsafe { CStr::from_ptr(out_report).to_str().unwrap() };
        assert!(report_str.contains("\"is_valid\":true"));
        assert!(report_str.contains("Backup Test Vault"));

        // 5. Restore backup
        let mut out_restored: *mut c_char = std::ptr::null_mut();
        let code_res = unsafe {
            vault_ffi_restore_backup(
                out_backup,
                out_backup_len,
                backup_pass.as_ptr(),
                std::ptr::null(),
                &mut out_restored,
            )
        };
        assert_eq!(code_res, FfiResultCode::Success);
        assert!(!out_restored.is_null());

        let res_str = unsafe { CStr::from_ptr(out_restored).to_str().unwrap() };
        assert!(res_str.contains("Backup Test Vault"));

        // Cleanup
        unsafe {
            vault_ffi_free_string(out_key);
            vault_ffi_free_string(out_doc);
            vault_ffi_free_string(out_report);
            vault_ffi_free_string(out_restored);
            vault_ffi_free_bytes(out_backup, out_backup_len);
        }
    }

    #[test]
    fn test_ffi_import_dedup_and_csv_export() {
        let csv_data = CString::new("Title,Username,Password\r\nGitHub,dev,pass123\r\n").unwrap();

        // 1. Parse import
        let mut out_items: *mut c_char = std::ptr::null_mut();
        let code_imp = unsafe { vault_ffi_parse_import(csv_data.as_ptr(), &mut out_items) };
        assert_eq!(code_imp, FfiResultCode::Success);
        assert!(!out_items.is_null());

        let items_str = unsafe { CStr::from_ptr(out_items).to_str().unwrap() };
        assert!(items_str.contains("GitHub"));
        assert!(items_str.contains("pass123"));

        // 2. Analyze dedup against empty current items
        let empty_current = CString::new("[]").unwrap();
        let mut out_prev: *mut c_char = std::ptr::null_mut();
        let code_dedup = unsafe {
            vault_ffi_analyze_dedup(empty_current.as_ptr(), out_items, &mut out_prev)
        };
        assert_eq!(code_dedup, FfiResultCode::Success);
        assert!(!out_prev.is_null());

        let prev_str = unsafe { CStr::from_ptr(out_prev).to_str().unwrap() };
        assert!(prev_str.contains("\"new_count\":1"));

        // 3. Export CSV
        let mut out_csv: *mut c_char = std::ptr::null_mut();
        let code_exp = unsafe { vault_ffi_export_csv(out_items, &mut out_csv) };
        assert_eq!(code_exp, FfiResultCode::Success);
        assert!(!out_csv.is_null());

        let exp_str = unsafe { CStr::from_ptr(out_csv).to_str().unwrap() };
        assert!(exp_str.contains("GitHub"));
        assert!(exp_str.contains("dev"));

        // Cleanup
        unsafe {
            vault_ffi_free_string(out_items);
            vault_ffi_free_string(out_prev);
            vault_ffi_free_string(out_csv);
        }
    }

    #[test]
    fn test_ffi_sync_lifecycle() {
        let sync_key_hex = CString::new("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").unwrap();
        let dev_id = CString::new("device-alpha").unwrap();
        let dev_name = CString::new("Alice Phone").unwrap();
        let addrs = CString::new("192.168.1.10:7890").unwrap();

        // 1. Generate & verify pairing QR
        let mut out_qr_uri: *mut c_char = std::ptr::null_mut();
        let code_qr = unsafe {
            vault_ffi_sync_generate_pairing_qr(
                sync_key_hex.as_ptr(),
                dev_id.as_ptr(),
                dev_name.as_ptr(),
                addrs.as_ptr(),
                &mut out_qr_uri,
            )
        };
        assert_eq!(code_qr, FfiResultCode::Success);
        assert!(!out_qr_uri.is_null());

        let qr_str = unsafe { CStr::from_ptr(out_qr_uri).to_str().unwrap() };
        assert!(qr_str.starts_with("pwdvault://pair?data="));

        let mut out_qr_verified: *mut c_char = std::ptr::null_mut();
        let code_ver = unsafe {
            vault_ffi_sync_verify_pairing_qr(
                out_qr_uri,
                sync_key_hex.as_ptr(),
                &mut out_qr_verified,
            )
        };
        assert_eq!(code_ver, FfiResultCode::Success);
        assert!(!out_qr_verified.is_null());

        // 2. Create syncpack
        let payload = VaultPayload::new("Sync FFI Vault");
        let payload_json = CString::new(serde_json::to_string(&payload).unwrap()).unwrap();
        let mut out_pack: *mut u8 = std::ptr::null_mut();
        let mut out_pack_len: usize = 0;

        let code_pack = unsafe {
            vault_ffi_sync_create_syncpack(
                payload_json.as_ptr(),
                sync_key_hex.as_ptr(),
                dev_id.as_ptr(),
                dev_name.as_ptr(),
                std::ptr::null(),
                &mut out_pack,
                &mut out_pack_len,
            )
        };
        assert_eq!(code_pack, FfiResultCode::Success);
        assert!(!out_pack.is_null());
        assert!(out_pack_len > 0);

        // 3. Apply syncpack
        let mut out_apply: *mut c_char = std::ptr::null_mut();
        let code_apply = unsafe {
            vault_ffi_sync_apply_syncpack(
                payload_json.as_ptr(),
                std::ptr::null(),
                out_pack,
                out_pack_len,
                sync_key_hex.as_ptr(),
                &mut out_apply,
            )
        };
        assert_eq!(code_apply, FfiResultCode::Success);
        assert!(!out_apply.is_null());

        let apply_str = unsafe { CStr::from_ptr(out_apply).to_str().unwrap() };
        assert!(apply_str.contains("\"report\""));
        assert!(apply_str.contains("\"merged_payload\""));

        // Cleanup
        unsafe {
            vault_ffi_free_string(out_qr_uri);
            vault_ffi_free_string(out_qr_verified);
            vault_ffi_free_string(out_apply);
            vault_ffi_free_bytes(out_pack, out_pack_len);
        }
    }

    #[test]
    fn test_ffi_totp_lifecycle() {
        // Base32 for ASCII "12345678901234567890"
        let secret = CString::new("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap();
        let alg = CString::new("SHA1").unwrap();

        // 1. Generate TOTP code
        let mut out_code: *mut c_char = std::ptr::null_mut();
        let mut out_rem: u64 = 0;
        let code = unsafe {
            vault_ffi_totp_generate(
                secret.as_ptr(),
                59, // t=59
                8,  // 8 digits
                30, // 30s period
                alg.as_ptr(),
                &mut out_code,
                &mut out_rem,
            )
        };
        assert_eq!(code, FfiResultCode::Success);
        assert!(!out_code.is_null());
        assert_eq!(out_rem, 1); // 59 % 30 = 29 -> remaining 1

        let code_str = unsafe { CStr::from_ptr(out_code).to_str().unwrap() };
        assert_eq!(code_str, "94287082");

        // 2. Verify TOTP code
        let mut out_valid = false;
        let c_good_code = CString::new("94287082").unwrap();
        let ver_code = unsafe {
            vault_ffi_totp_verify(
                secret.as_ptr(),
                c_good_code.as_ptr(),
                59,
                1,
                8,
                30,
                alg.as_ptr(),
                &mut out_valid,
            )
        };
        assert_eq!(ver_code, FfiResultCode::Success);
        assert!(out_valid);

        // 3. Parse otpauth URI
        let uri = CString::new("otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&digits=6&period=30").unwrap();
        let mut out_json: *mut c_char = std::ptr::null_mut();
        let parse_code = unsafe {
            vault_ffi_totp_parse_uri(uri.as_ptr(), &mut out_json)
        };
        assert_eq!(parse_code, FfiResultCode::Success);
        assert!(!out_json.is_null());

        let json_str = unsafe { CStr::from_ptr(out_json).to_str().unwrap() };
        assert!(json_str.contains("\"issuer\":\"GitHub\""));
        assert!(json_str.contains("\"digits\":6"));

        unsafe {
            vault_ffi_free_string(out_code);
            vault_ffi_free_string(out_json);
        }
    }

    #[test]
    fn test_ffi_passkey_lifecycle() {
        let rp_id = CString::new("github.com").unwrap();
        let user_name = CString::new("alice").unwrap();

        // 1. Generate passkey
        let mut out_passkey_json: *mut c_char = std::ptr::null_mut();
        let code = unsafe {
            vault_ffi_passkey_generate(
                rp_id.as_ptr(),
                std::ptr::null(),
                user_name.as_ptr(),
                -7, // ES256
                &mut out_passkey_json,
            )
        };
        assert_eq!(code, FfiResultCode::Success);
        assert!(!out_passkey_json.is_null());

        let passkey_str = unsafe { CStr::from_ptr(out_passkey_json).to_str().unwrap() };
        assert!(passkey_str.contains("\"rp_id\":\"github.com\""));
        assert!(passkey_str.contains("\"sign_count\":0"));

        // 2. Sign assertion
        let client_data = CString::new(r#"{"type":"webauthn.get","challenge":"AAAA","origin":"https://github.com"}"#).unwrap();
        let mut out_assertion: *mut c_char = std::ptr::null_mut();
        let mut out_updated_passkey: *mut c_char = std::ptr::null_mut();

        let sign_code = unsafe {
            vault_ffi_passkey_sign_assertion(
                out_passkey_json,
                rp_id.as_ptr(),
                client_data.as_ptr(),
                true,
                true,
                &mut out_assertion,
                &mut out_updated_passkey,
            )
        };
        assert_eq!(sign_code, FfiResultCode::Success);
        assert!(!out_assertion.is_null());
        assert!(!out_updated_passkey.is_null());

        let assertion_str = unsafe { CStr::from_ptr(out_assertion).to_str().unwrap() };
        assert!(assertion_str.contains("\"authenticator_data\""));
        assert!(assertion_str.contains("\"signature\""));

        let updated_str = unsafe { CStr::from_ptr(out_updated_passkey).to_str().unwrap() };
        assert!(updated_str.contains("\"sign_count\":1"));

        unsafe {
            vault_ffi_free_string(out_passkey_json);
            vault_ffi_free_string(out_assertion);
            vault_ffi_free_string(out_updated_passkey);
        }
    }

    #[test]
    fn test_ffi_audit_and_breach() {
        // 1. Audit vault
        let mut payload = VaultPayload::new("Audit Vault");
        let weak_item = VaultItem {
            id: "item-1".to_string(),
            title: "Insecure Site".to_string(),
            category: pwdvault_vault::ItemCategory::Login,
            username: Some("user".to_string()),
            password: Some("123".to_string()), // weak!
            urls: vec!["https://insecure.local".to_string()],
            notes: None,
            totp_seed: None,
            tags: Vec::new(),
            favorite: false,
            custom_fields: Vec::new(),
            attachments: Vec::new(),
            revision_history: Vec::new(),
            trashed_at: None,
            created_at: 1700000000,
            updated_at: 1700000000,
        };
        payload.add_item(weak_item);

        let payload_json = CString::new(serde_json::to_string(&payload).unwrap()).unwrap();
        let mut out_audit: *mut c_char = std::ptr::null_mut();
        let code_audit = unsafe {
            vault_ffi_audit_vault(payload_json.as_ptr(), 1700000000, &mut out_audit)
        };
        assert_eq!(code_audit, FfiResultCode::Success);
        assert!(!out_audit.is_null());

        let audit_str = unsafe { CStr::from_ptr(out_audit).to_str().unwrap() };
        assert!(audit_str.contains("\"weak_items\""));
        assert!(audit_str.contains("Insecure Site"));

        // 2. Breach k-Anonymity prepare query
        let pw = CString::new("password").unwrap();
        let mut out_prefix: *mut c_char = std::ptr::null_mut();
        let mut out_suffix: *mut c_char = std::ptr::null_mut();

        let code_query = unsafe {
            vault_ffi_breach_prepare_query(pw.as_ptr(), &mut out_prefix, &mut out_suffix)
        };
        assert_eq!(code_query, FfiResultCode::Success);
        assert!(!out_prefix.is_null());
        assert!(!out_suffix.is_null());

        let prefix_str = unsafe { CStr::from_ptr(out_prefix).to_str().unwrap() };
        let suffix_str = unsafe { CStr::from_ptr(out_suffix).to_str().unwrap() };
        assert_eq!(prefix_str.len(), 5);
        assert_eq!(suffix_str.len(), 35);
        // SHA1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        assert_eq!(prefix_str, "5BAA6");

        // 3. Breach check response
        let mock_body = CString::new(format!("{}:3861493\r\nFEEDBEEF000000000000000000000000000:1\r\n", suffix_str)).unwrap();
        let mut out_count: u64 = 0;
        let code_chk = unsafe {
            vault_ffi_breach_check_response(out_suffix, mock_body.as_ptr(), &mut out_count)
        };
        assert_eq!(code_chk, FfiResultCode::Success);
        assert_eq!(out_count, 3861493);

        unsafe {
            vault_ffi_free_string(out_audit);
            vault_ffi_free_string(out_prefix);
            vault_ffi_free_string(out_suffix);
        }
    }
}

