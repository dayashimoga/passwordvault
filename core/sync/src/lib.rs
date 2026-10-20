#![deny(unsafe_code)]
#![warn(missing_docs)]

//! # pwdvault-sync
//! Authenticated peer-to-peer LAN synchronization, encrypted file transport, and CRDT merge engine.
//!
//! Features:
//! - Monotonic vector clocks tracking multi-device logical causality.
//! - Conflict-Free Replicated Data Type (CRDT) merge with deterministic LWW and zero-data-loss revision preservation.
//! - Authenticated `.syncpack` container format encrypted with XChaCha20-Poly1305 and BLAKE3 commitment integrity.
//! - Out-of-band device pairing with ephemeral QR code payloads and fingerprint verification.
//! - Mutual zero-knowledge proof of possession protocol for LAN synchronization.

/// Conflict-Free Replicated Data Type (CRDT) merge engine.
pub mod crdt;
/// Authenticated local network (LAN) synchronization protocol.
pub mod lan_sync;
/// Out-of-band device pairing and QR code handshake.
pub mod pairing;
/// Authenticated `.syncpack` container format.
pub mod syncpack;
/// Monotonic vector clock implementation.
pub mod vector_clock;

pub use crdt::{merge_vault_payloads, SyncMergeReport};
pub use lan_sync::{
    compute_auth_proof, create_handshake_init, process_handshake_init, verify_client_final,
    verify_server_response_and_finalize, LanHandshakeFinal, LanHandshakeInit, LanHandshakeResponse,
};
pub use pairing::{
    compute_sync_key_fingerprint, generate_pairing_qr_data, verify_pairing_qr_data, PairingPayload,
};
pub use syncpack::{
    apply_syncpack, create_syncpack, read_syncpack, SyncPackPayload, SYNCPACK_HEADER_LEN,
    SYNCPACK_MAGIC,
};
pub use vector_clock::VectorClock;

use thiserror::Error;

/// Synchronization protocol error conditions.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum SyncError {
    /// Failure during sync exchange, parsing, or network protocol.
    #[error("Sync protocol error: {0}")]
    ProtocolError(String),
}
