//! The relay as a pure state machine.
//!
//! Every method takes the current time as an argument and touches nothing
//! outside `self`: no sockets, no clock, no randomness. The HTTP server is a
//! thin shell that calls these methods and performs the pushes they return.
//! The deterministic simulator calls the same methods directly.
//!
//! The relay is not trusted for safety. It never sees a request in the
//! clear, cannot produce an approval, and cannot make a host pin a key. What
//! it enforces is hygiene: only paired hosts can spend push notifications,
//! only the paired phone can read or answer a pairing's requests, and
//! everything expires.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, VecDeque};

use isudo_proto::api::{
    Ack, Answer, Claim, ClaimView, Confirm, CreatePairing, Decision, DeviceUpdate, PairingState, PairingStatus,
    PendingList, PendingRequest, Revoke, SubmitRequest,
};
use isudo_proto::codec::{b64_decode, b64_decode_array, hex_decode_array, hex_encode};
use isudo_proto::pairing::{decode_pubkey, MAX_NAME_LEN};
use isudo_proto::{
    sigs, MAX_REASON_LEN, MAX_REQUEST_LEN, PAIRING_ID_LEN, PHONE_NONCE_LEN, PUBKEY_LEN, REQUEST_ID_LEN, SIG_LEN,
};
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

type PairingId = [u8; PAIRING_ID_LEN];
type RequestId = [u8; REQUEST_ID_LEN];

/// Why the relay refused something. Deliberately coarse: callers learn a
/// category, never details about other parties' state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    /// The body or an identifier was malformed.
    Invalid,
    /// No such pairing or request (or it has expired).
    NotFound,
    /// A signature, MAC-bearing token or registration token did not check out.
    Unauthorized,
    /// The thing already exists or was already done.
    Conflict,
    /// A rate or capacity limit was reached.
    TooMany,
}

/// Tunable bounds. The defaults suit one person's machines.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Seconds an unconfirmed pairing is kept.
    pub pairing_ttl: u64,
    /// Longest lifetime a request may ask for, in seconds.
    pub max_request_ttl: u64,
    /// Requests a pairing may have waiting at once.
    pub max_pending: usize,
    /// Requests a pairing may submit per `rate_window` seconds.
    pub rate_count: usize,
    pub rate_window: u64,
    /// Pairings the relay will hold in total.
    pub max_pairings: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            pairing_ttl: 600,
            max_request_ttl: 660,
            max_pending: 8,
            rate_count: 30,
            rate_window: 300,
            max_pairings: 1024,
        }
    }
}

/// Where to send a push notification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    pub apns_token: String,
    pub apns_env: String,
}

/// A push the shell should send. It names the request; it does not carry it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Push {
    pub device: Device,
    pub pairing_id: String,
    pub request_id: String,
    pub host_name: String,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ClaimRecord {
    phone_sign_pub: String,
    phone_kem_pub: String,
    phone_name: String,
    /// Absent from records written before the phone sent a nonce. Those
    /// pairings are either already confirmed, where it no longer matters,
    /// or can never be acknowledged.
    #[serde(default)]
    phone_nonce: String,
    claim_mac: String,
    /// SHA-256 of the phone's bearer token, hex. The token itself is not kept.
    token_hash: String,
    device: Option<Device>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PairingRecord {
    host_pub: String,
    host_name: String,
    created_at: u64,
    claim: Option<ClaimRecord>,
    /// The host's acknowledgement of the claim, once given.
    #[serde(default)]
    acked: Option<Ack>,
    /// The host's confirmation signature, once given.
    confirmed: Option<String>,
    /// Submission times inside the rate window. Not persisted.
    #[serde(skip)]
    recent: VecDeque<u64>,
}

#[derive(Debug, Clone)]
struct PendingRecord {
    pairing_id: PairingId,
    expires_at: u64,
    envelope: String,
    answer: Option<Answer>,
}

/// Everything the relay knows.
#[derive(Debug, Default)]
pub struct Relay {
    limits: Limits,
    registration_token_hash: Option<[u8; 32]>,
    pairings: BTreeMap<PairingId, PairingRecord>,
    requests: BTreeMap<RequestId, PendingRecord>,
}

/// The part of the relay's state worth keeping across restarts: pairings.
/// Requests live for at most a few minutes and are simply dropped.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Snapshot {
    pairings: BTreeMap<String, PairingRecord>,
}

fn token_hash(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

fn verified(public_key_b64: &str, message: &[u8], signature_b64: &str) -> bool {
    let Ok(key) = decode_pubkey(public_key_b64) else { return false };
    let Ok(sig) = b64_decode_array::<SIG_LEN>(signature_b64) else { return false };
    let (Ok(key), Ok(sig)) = (VerifyingKey::from_sec1_bytes(&key), Signature::from_slice(&sig)) else {
        return false;
    };
    key.verify(message, &sig).is_ok()
}

fn pairing_id(hex: &str) -> Result<PairingId, Reject> {
    hex_decode_array(hex).map_err(|_e| Reject::Invalid)
}

fn request_id(hex: &str) -> Result<RequestId, Reject> {
    hex_decode_array(hex).map_err(|_e| Reject::Invalid)
}

fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= MAX_NAME_LEN && !name.chars().any(char::is_control)
}

fn valid_device(device: &DeviceUpdate) -> bool {
    let token_ok =
        (32..=200).contains(&device.apns_token.len()) && device.apns_token.bytes().all(|b| b.is_ascii_hexdigit());
    token_ok && matches!(device.apns_env.as_str(), "sandbox" | "production")
}

impl PairingRecord {
    const fn state(&self) -> PairingState {
        match (&self.claim, &self.acked, &self.confirmed) {
            (None, _, _) => PairingState::Pending,
            (Some(_), None, None) => PairingState::Claimed,
            (Some(_), Some(_), None) => PairingState::Acknowledged,
            (Some(_), _, Some(_)) => PairingState::Active,
        }
    }

    /// The claim, if `token` is this pairing's phone token.
    fn authorized(&self, token: &str) -> Result<&ClaimRecord, Reject> {
        let claim = self.claim.as_ref().ok_or(Reject::Unauthorized)?;
        if claim.token_hash == hex_encode(&token_hash(token)) {
            Ok(claim)
        } else {
            Err(Reject::Unauthorized)
        }
    }

    const fn expired(&self, now: u64, limits: &Limits) -> bool {
        self.confirmed.is_none() && now.saturating_sub(self.created_at) > limits.pairing_ttl
    }
}

impl Relay {
    /// `registration_token`, if set, must be presented to create a pairing.
    #[must_use]
    pub fn new(limits: Limits, registration_token: Option<&str>) -> Self {
        Self {
            limits,
            registration_token_hash: registration_token.map(token_hash),
            pairings: BTreeMap::new(),
            requests: BTreeMap::new(),
        }
    }

    /// Restores pairings saved by [`Relay::snapshot`]. Entries with
    /// malformed identifiers are skipped.
    pub fn restore(&mut self, snapshot: Snapshot) {
        for (id, record) in snapshot.pairings {
            if let Ok(id) = pairing_id(&id) {
                let _ = self.pairings.insert(id, record);
            }
        }
    }

    #[must_use]
    pub fn snapshot(&self) -> Snapshot {
        Snapshot { pairings: self.pairings.iter().map(|(id, record)| (hex_encode(id), record.clone())).collect() }
    }

    /// Drops expired requests and unconfirmed pairings.
    pub fn sweep(&mut self, now: u64) {
        let limits = self.limits;
        self.requests.retain(|_, request| request.expires_at >= now);
        self.pairings.retain(|_, pairing| !pairing.expired(now, &limits));
    }

    /// Host, at pairing time.
    ///
    /// # Errors
    /// `Unauthorized` without the registration token, `Conflict` if the id
    /// is taken, `TooMany` at capacity, `Invalid` for a malformed body.
    pub fn create_pairing(&mut self, now: u64, body: &CreatePairing, token: Option<&str>) -> Result<(), Reject> {
        if let Some(expected) = self.registration_token_hash {
            if token.map(token_hash) != Some(expected) {
                return Err(Reject::Unauthorized);
            }
        }
        self.sweep(now);
        let id = pairing_id(&body.pairing_id)?;
        if decode_pubkey(&body.host_pub).is_err() || !valid_name(&body.host_name) {
            return Err(Reject::Invalid);
        }
        if self.pairings.contains_key(&id) {
            return Err(Reject::Conflict);
        }
        if self.pairings.len() >= self.limits.max_pairings {
            return Err(Reject::TooMany);
        }
        let record = PairingRecord {
            host_pub: body.host_pub.clone(),
            host_name: body.host_name.clone(),
            created_at: now,
            claim: None,
            acked: None,
            confirmed: None,
            recent: VecDeque::new(),
        };
        let _ = self.pairings.insert(id, record);
        Ok(())
    }

    /// Phone, after scanning. The first claim wins; a second is a conflict,
    /// which the phone reports loudly.
    ///
    /// # Errors
    /// `NotFound` for an unknown or expired pairing, `Conflict` if already
    /// claimed, `Invalid` for a malformed body.
    pub fn claim(&mut self, now: u64, pairing: &str, body: &Claim) -> Result<(), Reject> {
        self.sweep(now);
        let record = self.pairings.get_mut(&pairing_id(pairing)?).ok_or(Reject::NotFound)?;
        if record.claim.is_some() {
            return Err(Reject::Conflict);
        }
        let keys_ok = decode_pubkey(&body.phone_sign_pub).is_ok() && decode_pubkey(&body.phone_kem_pub).is_ok();
        let nonce_ok = b64_decode_array::<PHONE_NONCE_LEN>(&body.phone_nonce).is_ok();
        let mac_ok = nonce_ok && b64_decode_array::<32>(&body.claim_mac).is_ok();
        let token_ok = b64_decode_array::<32>(&body.phone_token).is_ok();
        let device_ok = body.device.as_ref().is_none_or(valid_device);
        if !(keys_ok && mac_ok && token_ok && device_ok && valid_name(&body.phone_name)) {
            return Err(Reject::Invalid);
        }
        record.claim = Some(ClaimRecord {
            phone_sign_pub: body.phone_sign_pub.clone(),
            phone_kem_pub: body.phone_kem_pub.clone(),
            phone_name: body.phone_name.clone(),
            phone_nonce: body.phone_nonce.clone(),
            claim_mac: body.claim_mac.clone(),
            token_hash: hex_encode(&token_hash(&body.phone_token)),
            device: body
                .device
                .as_ref()
                .map(|d| Device { apns_token: d.apns_token.clone(), apns_env: d.apns_env.clone() }),
        });
        Ok(())
    }

    /// Host: the phone's answer, once there is one.
    ///
    /// # Errors
    /// `NotFound` for an unknown or expired pairing.
    pub fn claim_view(&self, pairing: &str) -> Result<Option<ClaimView>, Reject> {
        let record = self.pairings.get(&pairing_id(pairing)?).ok_or(Reject::NotFound)?;
        Ok(record.claim.as_ref().map(|claim| ClaimView {
            phone_sign_pub: claim.phone_sign_pub.clone(),
            phone_kem_pub: claim.phone_kem_pub.clone(),
            phone_name: claim.phone_name.clone(),
            phone_nonce: claim.phone_nonce.clone(),
            claim_mac: claim.claim_mac.clone(),
        }))
    }

    /// Host: acknowledges the phone answer it has accepted. The phone shows
    /// its code only once it holds this signature over its own keys.
    ///
    /// # Errors
    /// `NotFound`, `Conflict` if not yet claimed or already acknowledged,
    /// `Unauthorized` if the signature is not the host's over these keys.
    pub fn acknowledge(&mut self, pairing: &str, body: &Ack) -> Result<(), Reject> {
        let id = pairing_id(pairing)?;
        let record = self.pairings.get_mut(&id).ok_or(Reject::NotFound)?;
        let (Some(claim), None) = (&record.claim, &record.acked) else {
            return Err(Reject::Conflict);
        };
        let (Ok(sign_pub), Ok(kem_pub)) = (decode_pubkey(&claim.phone_sign_pub), decode_pubkey(&claim.phone_kem_pub))
        else {
            return Err(Reject::Invalid);
        };
        let phone_nonce = b64_decode_array(&claim.phone_nonce).map_err(|_e| Reject::Invalid)?;
        let host_nonce = b64_decode_array(&body.nonce).map_err(|_e| Reject::Invalid)?;
        let message = sigs::pair_ack_msg(&id, &sign_pub, &kem_pub, &phone_nonce, &host_nonce);
        if !verified(&record.host_pub, &message, &body.host_sig) {
            return Err(Reject::Unauthorized);
        }
        record.acked = Some(body.clone());
        Ok(())
    }

    /// Host: activates the pairing. The signature covers the phone keys the
    /// host accepted, so the relay cannot swap them afterwards.
    ///
    /// # Errors
    /// `NotFound`, `Conflict` if not yet acknowledged or already active,
    /// `Unauthorized` if the signature is not the host's.
    pub fn confirm(&mut self, pairing: &str, body: &Confirm) -> Result<(), Reject> {
        let id = pairing_id(pairing)?;
        let record = self.pairings.get_mut(&id).ok_or(Reject::NotFound)?;
        let (Some(claim), Some(_), None) = (&record.claim, &record.acked, &record.confirmed) else {
            return Err(Reject::Conflict);
        };
        let (Ok(sign_pub), Ok(kem_pub)) = (decode_pubkey(&claim.phone_sign_pub), decode_pubkey(&claim.phone_kem_pub))
        else {
            return Err(Reject::Invalid);
        };
        let message = sigs::pair_confirm_msg(&id, &sign_pub, &kem_pub);
        if !verified(&record.host_pub, &message, &body.host_sig) {
            return Err(Reject::Unauthorized);
        }
        record.confirmed = Some(body.host_sig.clone());
        Ok(())
    }

    /// Phone: the state of one of its pairings.
    ///
    /// # Errors
    /// `NotFound`, or `Unauthorized` for the wrong token.
    pub fn status(&self, pairing: &str, token: &str) -> Result<PairingStatus, Reject> {
        let record = self.pairings.get(&pairing_id(pairing)?).ok_or(Reject::NotFound)?;
        let _claim = record.authorized(token)?;
        Ok(PairingStatus { state: record.state(), ack: record.acked.clone(), host_sig: record.confirmed.clone() })
    }

    /// Phone: sets where its pushes go.
    ///
    /// # Errors
    /// `NotFound`, `Unauthorized` for the wrong token, `Invalid` for a
    /// malformed device token.
    pub fn update_device(&mut self, pairing: &str, token: &str, body: &DeviceUpdate) -> Result<(), Reject> {
        let record = self.pairings.get_mut(&pairing_id(pairing)?).ok_or(Reject::NotFound)?;
        let _claim = record.authorized(token)?;
        if !valid_device(body) {
            return Err(Reject::Invalid);
        }
        if let Some(claim) = record.claim.as_mut() {
            claim.device = Some(Device { apns_token: body.apns_token.clone(), apns_env: body.apns_env.clone() });
        }
        Ok(())
    }

    /// Host: deletes a pairing and its waiting requests.
    ///
    /// # Errors
    /// `NotFound`, or `Unauthorized` if the signature is not the host's.
    pub fn revoke_as_host(&mut self, pairing: &str, body: &Revoke) -> Result<(), Reject> {
        let id = pairing_id(pairing)?;
        let record = self.pairings.get(&id).ok_or(Reject::NotFound)?;
        if !verified(&record.host_pub, &sigs::pair_revoke_msg(&id), &body.host_sig) {
            return Err(Reject::Unauthorized);
        }
        self.remove_pairing(&id);
        Ok(())
    }

    /// Phone: deletes one of its pairings and its waiting requests.
    ///
    /// # Errors
    /// `NotFound`, or `Unauthorized` for the wrong token.
    pub fn revoke_as_phone(&mut self, pairing: &str, token: &str) -> Result<(), Reject> {
        let id = pairing_id(pairing)?;
        let _claim = self.pairings.get(&id).ok_or(Reject::NotFound)?.authorized(token)?;
        self.remove_pairing(&id);
        Ok(())
    }

    fn remove_pairing(&mut self, id: &PairingId) {
        let _ = self.pairings.remove(id);
        self.requests.retain(|_, request| request.pairing_id != *id);
    }

    /// Helper: stores an encrypted request and says whether to push.
    ///
    /// The ticket is the host's signature over the pairing, the request id
    /// and the expiry, so only the paired host's setuid binary can cause a
    /// push, and each ticket is good for one request.
    ///
    /// # Errors
    /// `NotFound` for an unknown or inactive pairing, `Unauthorized` for a
    /// bad ticket, `Conflict` for a repeated request id, `TooMany` when
    /// rate-limited, `Invalid` for a malformed or already expired request.
    pub fn submit(&mut self, now: u64, body: &SubmitRequest) -> Result<Option<Push>, Reject> {
        self.sweep(now);
        let pairing = pairing_id(&body.pairing_id)?;
        let request = request_id(&body.request_id)?;
        let limits = self.limits;
        let record = self.pairings.get_mut(&pairing).ok_or(Reject::NotFound)?;
        if record.state() != PairingState::Active {
            return Err(Reject::NotFound);
        }
        if body.expires_at < now || body.expires_at.saturating_sub(now) > limits.max_request_ttl {
            return Err(Reject::Invalid);
        }
        // Base64 of: encapsulated key, host signature, request, AEAD tag.
        let max_envelope = (PUBKEY_LEN.saturating_add(SIG_LEN).saturating_add(MAX_REQUEST_LEN).saturating_add(16))
            .saturating_mul(4)
            .div_ceil(3);
        if body.envelope.len() > max_envelope || b64_decode(&body.envelope).is_err() {
            return Err(Reject::Invalid);
        }
        if !verified(&record.host_pub, &sigs::ticket_msg(&pairing, &request, body.expires_at), &body.ticket_sig) {
            return Err(Reject::Unauthorized);
        }
        if self.requests.contains_key(&request) {
            return Err(Reject::Conflict);
        }

        while record.recent.front().is_some_and(|at| now.saturating_sub(*at) >= limits.rate_window) {
            let _ = record.recent.pop_front();
        }
        let waiting = self.requests.values().filter(|r| r.pairing_id == pairing && r.answer.is_none()).count();
        if record.recent.len() >= limits.rate_count || waiting >= limits.max_pending {
            return Err(Reject::TooMany);
        }
        record.recent.push_back(now);

        let push = record.claim.as_ref().and_then(|claim| claim.device.clone()).map(|device| Push {
            device,
            pairing_id: body.pairing_id.clone(),
            request_id: body.request_id.clone(),
            host_name: record.host_name.clone(),
            expires_at: body.expires_at,
        });
        let pending = PendingRecord {
            pairing_id: pairing,
            expires_at: body.expires_at,
            envelope: body.envelope.clone(),
            answer: None,
        };
        let _ = self.requests.insert(request, pending);
        Ok(push)
    }

    /// Phone: the requests waiting for it.
    ///
    /// # Errors
    /// `NotFound`, or `Unauthorized` for the wrong token.
    pub fn pending(&mut self, now: u64, pairing: &str, token: &str) -> Result<PendingList, Reject> {
        self.sweep(now);
        let id = pairing_id(pairing)?;
        let _claim = self.pairings.get(&id).ok_or(Reject::NotFound)?.authorized(token)?;
        let requests = self
            .requests
            .iter()
            .filter(|(_, request)| request.pairing_id == id && request.answer.is_none())
            .map(|(request_id, request)| PendingRequest {
                request_id: hex_encode(request_id),
                expires_at: request.expires_at,
                envelope: request.envelope.clone(),
            })
            .collect();
        Ok(PendingList { requests })
    }

    /// Phone: its signed answer. The first answer stands.
    ///
    /// The relay cannot check the signature's meaning (it cannot read the
    /// request); the setuid binary does that. It checks shape and sender.
    ///
    /// # Errors
    /// `NotFound` for an unknown or expired request, `Unauthorized` for the
    /// wrong token, `Conflict` if already answered, `Invalid` if malformed.
    pub fn answer(&mut self, now: u64, request: &str, token: &str, body: Answer) -> Result<(), Reject> {
        self.sweep(now);
        let id = request_id(request)?;
        let pending = self.requests.get_mut(&id).ok_or(Reject::NotFound)?;
        let _claim = self.pairings.get(&pending.pairing_id).ok_or(Reject::NotFound)?.authorized(token)?;
        if pending.answer.is_some() {
            return Err(Reject::Conflict);
        }
        let shape_ok = match (body.decision, &body.reason) {
            (Decision::Approve, None) => true,
            (Decision::Approve, Some(_)) => false,
            (Decision::Deny, reason) => reason.as_ref().is_none_or(|r| r.len() <= MAX_REASON_LEN),
        };
        if !shape_ok || b64_decode_array::<SIG_LEN>(&body.sig).is_err() {
            return Err(Reject::Invalid);
        }
        pending.answer = Some(body);
        Ok(())
    }

    /// Helper: the phone's answer, if it has arrived.
    ///
    /// # Errors
    /// `NotFound` for an unknown or expired request.
    pub fn poll_answer(&mut self, now: u64, request: &str) -> Result<Option<Answer>, Reject> {
        self.sweep(now);
        let pending = self.requests.get(&request_id(request)?).ok_or(Reject::NotFound)?;
        Ok(pending.answer.clone())
    }
}

#[cfg(test)]
mod tests;
