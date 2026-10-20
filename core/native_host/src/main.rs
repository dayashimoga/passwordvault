#![deny(unsafe_code)]

//! Native Messaging binary entry point connecting browser extension to PwdVault core.

use std::io::{self, BufReader, BufWriter};
use std::path::PathBuf;

use pwdvault_native_host::handler::{handle_request, HostSession};
use pwdvault_native_host::protocol::{read_native_message, write_native_message, NativeRequest, NativeResponse};

fn main() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = BufReader::new(stdin.lock());
    let mut writer = BufWriter::new(stdout.lock());

    // Resolve default vault path
    let default_vault = PathBuf::from("personal_vault.vault.v1");
    let mut session = HostSession::new(default_vault);

    while let Ok(Some(json_val)) = read_native_message(&mut reader) {
        let response = match serde_json::from_value::<NativeRequest>(json_val) {
            Ok(req) => handle_request(&mut session, req),
            Err(e) => NativeResponse::ErrorResponse {
                error: format!("Malformed request JSON: {}", e),
                code: 400,
            },
        };

        if let Ok(resp_val) = serde_json::to_value(&response) {
            if write_native_message(&mut writer, &resp_val).is_err() {
                break;
            }
        }
    }
}
