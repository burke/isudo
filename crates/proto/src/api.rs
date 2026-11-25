//! JSON bodies of the relay HTTP API.
//!
//! Identifiers (pairing and request ids) are lowercase hex, because they also
//! appear in URL paths. Keys, signatures, MACs, tokens and envelopes are
//! unpadded base64url.
//!
//! Routes:
//!
//! ```text
//! POST /v1/pairings                         CreatePairing     host, at pairing time
//! POST /v1/pairings/{pid}/claim             Claim             phone
//! GET  /v1/pairings/{pid}/claim             -> ClaimView      host (204 until claimed)
//! POST /v1/pairings/{pid}/ack               Ack               host
//! POST /v1/pairings/{pid}/confirm           Confirm           host
//! GET  /v1/pairings/{pid}                   -> PairingStatus  phone, bearer
//! POST /v1/pairings/{pid}/device            DeviceUpdate      phone, bearer
//! POST /v1/pairings/{pid}/revoke            Revoke            host
//! POST /v1/pairings/{pid}/unpair            (empty)           phone, bearer
//! GET  /v1/pairings/{pid}/requests          -> PendingList    phone, bearer
//! POST /v1/requests                         SubmitRequest     helper
//! GET  /v1/requests/{rid}/response?wait=N   -> Answer         helper (204 until answered)
//! POST /v1/requests/{rid}/response          Answer            phone, bearer
//! ```

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreatePairing {
    pub pairing_id: String,
    pub host_pub: String,
    pub host_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claim {
    pub phone_sign_pub: String,
    pub phone_kem_pub: String,
    pub phone_name: String,
    /// Random value the phone chose after reading the pairing code. The
    /// six-digit code depends on it.
    pub phone_nonce: String,
    pub claim_mac: String,
    /// Bearer token the phone will use for this pairing from now on.
    pub phone_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<DeviceUpdate>,
}

/// What the host sees of a claim. The bearer token and device token are
/// between the phone and the relay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimView {
    pub phone_sign_pub: String,
    pub phone_kem_pub: String,
    pub phone_name: String,
    pub phone_nonce: String,
    pub claim_mac: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ack {
    /// The host's nonce, revealed. The pairing code committed to it before
    /// any phone answered.
    pub nonce: String,
    /// Host signature over `sigs::pair_ack_msg`.
    pub host_sig: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Confirm {
    /// Host signature over `sigs::pair_confirm_msg`.
    pub host_sig: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PairingState {
    /// Created by the host; no phone has answered.
    Pending,
    /// A phone has answered; the host has not yet looked.
    Claimed,
    /// The host has accepted the phone's answer and is waiting for the code.
    Acknowledged,
    /// Confirmed by the host. Requests are accepted.
    Active,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingStatus {
    pub state: PairingState,
    /// Present once the host has accepted this phone's answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ack: Option<Ack>,
    /// Present once active, so the phone can check the host really confirmed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_sig: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceUpdate {
    /// APNs device token, hex.
    pub apns_token: String,
    /// "sandbox" or "production".
    pub apns_env: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Revoke {
    /// Host signature over `sigs::pair_revoke_msg`.
    pub host_sig: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitRequest {
    pub pairing_id: String,
    pub request_id: String,
    pub expires_at: u64,
    /// Host signature over `sigs::ticket_msg`.
    pub ticket_sig: String,
    /// HPKE encapsulated key followed by the ciphertext of
    /// `host_sig || request`. Opaque to the relay.
    pub envelope: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingRequest {
    pub request_id: String,
    pub expires_at: u64,
    pub envelope: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingList {
    pub requests: Vec<PendingRequest>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Approve,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Answer {
    pub decision: Decision,
    /// Phone signature over `sigs::approve_msg` or `sigs::deny_msg`.
    pub sig: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    pub error: String,
}
