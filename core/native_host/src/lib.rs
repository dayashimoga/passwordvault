#![deny(unsafe_code)]
#![warn(missing_docs)]

//! Authenticated Native Messaging Host library for browser extension communication.

pub mod handler;
pub mod protocol;

pub use handler::{extract_domain, handle_request, HostSession};
pub use protocol::{
    read_native_message, write_native_message, HostError, LoginSummary, NativeRequest,
    NativeResponse, VaultStatus, MAX_MESSAGE_SIZE,
};
