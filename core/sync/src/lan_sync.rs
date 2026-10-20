#![deny(unsafe_code)]
#![warn(missing_docs)]

//! Authenticated peer-to-peer local area network (LAN) synchronization protocol.

use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::SyncError;

const AUTH_DOMAIN_TAG: &[u8] = b"PWDVAULT_LAN_SYNC_AUTH_V1";

/// Computes the zero-knowledge mutual authentication proof for a given challenge nonce.
pub fn compute_auth_proof(sync_key: &[u8; 32], challenge: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(AUTH_DOMAIN_TAG);
    hasher.update(sync_key);
    hasher.update(challenge);
    *hasher.finalize().as_bytes()
}

/// Initial handshake initiation message sent by peer A (client).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LanHandshakeInit {
    /// Client device identifier.
    pub client_device_id: String,
    /// Random 32-byte challenge for the server to prove knowledge of sync key.
    pub client_challenge: [u8; 32],
}

/// Handshake challenge response and reverse challenge sent by peer B (server).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LanHandshakeResponse {
    /// Server device identifier.
    pub server_device_id: String,
    /// Cryptographic proof that server possesses the shared sync key.
    pub server_proof: [u8; 32],
    /// Reverse 32-byte challenge for client to prove knowledge of sync key.
    pub server_challenge: [u8; 32],
}

/// Handshake finalization sent by peer A confirming mutual authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LanHandshakeFinal {
    /// Cryptographic proof that client possesses the shared sync key.
    pub client_proof: [u8; 32],
}

/// Generates a fresh handshake initiation challenge.
pub fn create_handshake_init(client_device_id: &str) -> (LanHandshakeInit, [u8; 32]) {
    let mut challenge = [0u8; 32];
    OsRng.fill_bytes(&mut challenge);

    let msg = LanHandshakeInit {
        client_device_id: client_device_id.to_string(),
        client_challenge: challenge,
    };
    (msg, challenge)
}

/// Evaluates a client initiation challenge and produces the response proof and reverse challenge.
pub fn process_handshake_init(
    init: &LanHandshakeInit,
    sync_key: &[u8; 32],
    server_device_id: &str,
) -> (LanHandshakeResponse, [u8; 32]) {
    let server_proof = compute_auth_proof(sync_key, &init.client_challenge);

    let mut server_challenge = [0u8; 32];
    OsRng.fill_bytes(&mut server_challenge);

    let resp = LanHandshakeResponse {
        server_device_id: server_device_id.to_string(),
        server_proof,
        server_challenge,
    };
    (resp, server_challenge)
}

/// Verifies the server's proof and generates the client's reciprocal proof.
pub fn verify_server_response_and_finalize(
    resp: &LanHandshakeResponse,
    client_challenge: &[u8; 32],
    sync_key: &[u8; 32],
) -> Result<LanHandshakeFinal, SyncError> {
    let expected_server_proof = compute_auth_proof(sync_key, client_challenge);
    if resp.server_proof != expected_server_proof {
        return Err(SyncError::ProtocolError(
            "Server mutual authentication failed: invalid sync key".to_string(),
        ));
    }

    let client_proof = compute_auth_proof(sync_key, &resp.server_challenge);
    Ok(LanHandshakeFinal { client_proof })
}

/// Verifies the client's final proof on the server side to complete mutual authentication.
pub fn verify_client_final(
    final_msg: &LanHandshakeFinal,
    server_challenge: &[u8; 32],
    sync_key: &[u8; 32],
) -> Result<(), SyncError> {
    let expected_client_proof = compute_auth_proof(sync_key, server_challenge);
    if final_msg.client_proof != expected_client_proof {
        return Err(SyncError::ProtocolError(
            "Client mutual authentication failed: invalid sync key".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lan_sync_mutual_authentication_handshake() {
        let sync_key = [77u8; 32];

        // 1. Client creates init
        let (init, client_challenge) = create_handshake_init("client-iphone");

        // 2. Server processes init
        let (resp, server_challenge) = process_handshake_init(&init, &sync_key, "server-desktop");

        // 3. Client verifies server response and generates final
        let final_msg = verify_server_response_and_finalize(&resp, &client_challenge, &sync_key)
            .expect("server auth failed");

        // 4. Server verifies client final
        verify_client_final(&final_msg, &server_challenge, &sync_key)
            .expect("client auth failed");
    }

    #[test]
    fn test_lan_sync_imposter_rejection() {
        let real_key = [77u8; 32];
        let attacker_key = [99u8; 32];

        let (init, client_challenge) = create_handshake_init("client");
        let (resp, _) = process_handshake_init(&init, &attacker_key, "fake-server");

        assert!(verify_server_response_and_finalize(&resp, &client_challenge, &real_key).is_err());
    }
}
