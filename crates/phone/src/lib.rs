//! The approver's side of isudo, as pure logic.
//!
//! This is what a phone must check before it shows a request, and what it
//! signs when the person approves or denies. The iOS app implements the same
//! rules in Swift with its signing key in the Secure Enclave; this crate is
//! the reference those rules are tested against, the engine of the terminal
//! test phone, and the phone inside the deterministic simulator.
//!
//! Nothing here does I/O or reads a clock. Randomness comes in as a seed.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fmt;

use isudo_client::envelope;
use isudo_proto::api::{Answer, Claim, Decision, DeviceUpdate, PairingState, PairingStatus, PendingRequest};
use isudo_proto::codec::{b64_decode, b64_decode_array, b64_encode, hex_decode_array, hex_encode};
use isudo_proto::pairing::{self, Offer, Parties};
use isudo_proto::request::Request;
use isudo_proto::{
    sigs, COMMITMENT_LEN, HOST_NONCE_LEN, MAX_REASON_LEN, PAIRING_ID_LEN, PHONE_NONCE_LEN, PUBKEY_LEN, REQUEST_ID_LEN,
    SIG_LEN,
};
use p256::ecdsa::signature::{Signer as _, Verifier as _};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};

/// Seconds a request may appear to be past its expiry, to allow for the
/// host's and phone's clocks disagreeing, before the phone refuses it.
pub const CLOCK_SKEW_SECS: u64 = 30;
/// How many answered or refused request ids are remembered, to refuse
/// showing the same request twice.
const MAX_SEEN: usize = 4096;

/// Why the phone will not show a request. None of these are shown to the
/// person as an approval card; at most they are logged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The pairing has not been confirmed by its host.
    NotActive,
    /// The envelope did not decrypt with this pairing's key.
    Undecryptable,
    /// The request is not signed by the paired host.
    NotFromHost,
    /// The request does not decode, or is for a different pairing, or does
    /// not match the id it was delivered under.
    Malformed,
    /// The request is past its expiry.
    Expired,
    /// This request was already shown.
    AlreadySeen,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotActive => "this pairing is not active",
            Self::Undecryptable => "the request could not be decrypted",
            Self::NotFromHost => "the request was not signed by the paired computer",
            Self::Malformed => "the request is malformed",
            Self::Expired => "the request has expired",
            Self::AlreadySeen => "the request was already handled",
        })
    }
}

impl std::error::Error for Refusal {}

/// Why pairing could not proceed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingError {
    /// The seed did not yield usable keys (astronomically unlikely).
    BadSeed,
    /// The offer carries a host key that is not a curve point.
    BadOffer,
    /// The host accepted an answer, and it was not this phone's: its
    /// acknowledgement is missing or does not cover this phone's keys.
    /// Someone else answered the pairing, or the relay is lying.
    AnotherPhoneWasAccepted,
    /// The acknowledgement reveals a nonce that the pairing code did not
    /// commit to. Whoever wrote the pairing code is trying to choose the
    /// code this phone shows, which an honest computer never does.
    CodeWasSteered,
    /// The relay says the pairing is active, but the host's signature over
    /// this phone's keys is missing or wrong.
    NotConfirmedByHost,
}

impl fmt::Display for PairingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::BadSeed => "could not generate keys",
            Self::BadOffer => "the pairing code is invalid",
            Self::AnotherPhoneWasAccepted => {
                "the computer accepted a different phone; do not enter any code there, and cancel pairing"
            }
            Self::CodeWasSteered => {
                "this pairing code did not come from an honest computer; do not enter any code, and cancel pairing"
            }
            Self::NotConfirmedByHost => "the computer has not confirmed this pairing",
        })
    }
}

impl std::error::Error for PairingError {}

/// The first `N` bytes of a derived value.
fn first<const N: usize>(bytes: &[u8; 32]) -> [u8; N] {
    let mut out = [0; N];
    for (dst, src) in out.iter_mut().zip(bytes) {
        *dst = *src;
    }
    out
}

fn derive(seed: &[u8; 32], purpose: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"isudo/v1/phone-seed\0");
    hash.update(purpose);
    hash.update(seed);
    hash.finalize().into()
}

/// Where a pairing has got to, from the phone's side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Progress {
    /// The host has not yet looked at this phone's answer.
    Waiting,
    /// The host accepted this phone's answer. Show the person this code to
    /// type into the host.
    ShowCode(String),
    /// The host confirmed the pairing. Requests can now arrive.
    Active,
}

/// One pairing, from the phone's point of view.
#[derive(Debug, Clone)]
pub struct Pairing {
    id: [u8; PAIRING_ID_LEN],
    host_pub: [u8; PUBKEY_LEN],
    host_name: String,
    relay_url: String,
    secret: [u8; pairing::SECRET_LEN],
    /// The pairing code's commitment to the host's nonce.
    commitment: [u8; COMMITMENT_LEN],
    /// This phone's nonce, chosen after the pairing code was read.
    phone_nonce: [u8; PHONE_NONCE_LEN],
    sign_key: SigningKey,
    sign_pub: [u8; PUBKEY_LEN],
    kem_private: [u8; envelope::PRIVATE_KEY_LEN],
    kem_pub: [u8; PUBKEY_LEN],
    token: String,
    /// The host's nonce, once its acknowledgement has been verified.
    host_nonce: Option<[u8; HOST_NONCE_LEN]>,
    active: bool,
    seen: BTreeSet<[u8; REQUEST_ID_LEN]>,
}

impl Pairing {
    /// Starts a pairing from a scanned offer, generating this pairing's own
    /// keys from `seed`. Each pairing gets its own keys, so nothing links a
    /// phone's pairings to each other.
    ///
    /// # Errors
    /// Fails if the offer's host key is invalid.
    pub fn begin(offer: &Offer, seed: &[u8; 32]) -> Result<Self, PairingError> {
        let _host = VerifyingKey::from_sec1_bytes(&offer.host_pub).map_err(|_e| PairingError::BadOffer)?;
        let sign_key = SigningKey::from_slice(&derive(seed, b"sign")).map_err(|_e| PairingError::BadSeed)?;
        let sign_pub = sign_key
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .try_into()
            .map_err(|_e| PairingError::BadSeed)?;
        let (kem_private, kem_pub) = envelope::derive(&derive(seed, b"kem")).map_err(|_e| PairingError::BadSeed)?;
        Ok(Self {
            id: offer.pairing_id,
            host_pub: offer.host_pub,
            host_name: offer.host_name.clone(),
            relay_url: offer.relay_url.clone(),
            secret: offer.secret,
            commitment: offer.commitment,
            phone_nonce: first(&derive(seed, b"nonce")),
            sign_key,
            sign_pub,
            kem_private,
            kem_pub,
            token: b64_encode(&derive(seed, b"token")),
            host_nonce: None,
            active: false,
            seen: BTreeSet::new(),
        })
    }

    /// Rebuilds a pairing from what was stored when it was made: the offer,
    /// the seed, and whether the host had confirmed it.
    ///
    /// # Errors
    /// Fails if the stored offer's host key is invalid.
    pub fn resume(offer: &Offer, seed: &[u8; 32], active: bool) -> Result<Self, PairingError> {
        let mut pairing = Self::begin(offer, seed)?;
        pairing.active = active;
        Ok(pairing)
    }

    const fn parties(&self) -> Parties<'_> {
        Parties {
            pairing_id: &self.id,
            host_pub: &self.host_pub,
            phone_sign_pub: &self.sign_pub,
            phone_kem_pub: &self.kem_pub,
        }
    }

    #[must_use]
    pub fn id_hex(&self) -> String {
        hex_encode(&self.id)
    }

    #[must_use]
    pub fn host_name(&self) -> &str {
        &self.host_name
    }

    #[must_use]
    pub fn relay_url(&self) -> &str {
        &self.relay_url
    }

    /// The bearer token this phone presents to the relay for this pairing.
    #[must_use]
    pub fn token(&self) -> &str {
        &self.token
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// The public key whose signatures the host will accept as approvals.
    #[must_use]
    pub const fn sign_pub(&self) -> &[u8; PUBKEY_LEN] {
        &self.sign_pub
    }

    /// What to send the relay to answer the pairing.
    #[must_use]
    pub fn claim(&self, phone_name: &str, device: Option<DeviceUpdate>) -> Claim {
        Claim {
            phone_sign_pub: b64_encode(&self.sign_pub),
            phone_kem_pub: b64_encode(&self.kem_pub),
            phone_name: phone_name.to_owned(),
            phone_nonce: b64_encode(&self.phone_nonce),
            claim_mac: b64_encode(&pairing::claim_mac(
                &self.secret,
                &self.parties(),
                &self.phone_nonce,
                phone_name.as_bytes(),
            )),
            phone_token: self.token.clone(),
            device,
        }
    }

    /// The six digits the person types into the host, available only once
    /// the host has acknowledged this phone's own answer.
    ///
    /// That ordering is what the code's meaning rests on: a phone whose keys
    /// were swapped in transit never gets the host's signature and so never
    /// has a code to show. The code depends on both nonces: the host's,
    /// which the pairing code committed to before this phone chose its own,
    /// and this phone's. So neither side could have chosen it.
    #[must_use]
    pub fn code(&self) -> Option<String> {
        let host_nonce = self.host_nonce.as_ref()?;
        Some(pairing::confirmation_code(&self.secret, &self.parties(), host_nonce, &self.phone_nonce))
    }

    /// Advances the pairing from what the relay reports, believing only the
    /// host's signatures.
    ///
    /// - The code is released only on the host's acknowledgement of this
    ///   phone's own keys and nonce, revealing the nonce the pairing code
    ///   committed to.
    /// - The pairing becomes active only on the host's confirmation of them.
    ///
    /// # Errors
    /// Fails if the relay reports progress that the host's signatures do not
    /// back up. `AnotherPhoneWasAccepted` and `CodeWasSteered` in particular
    /// mean the person must not continue on the host.
    pub fn observe(&mut self, status: &PairingStatus) -> Result<Progress, PairingError> {
        if self.active {
            return Ok(Progress::Active);
        }
        if self.host_nonce.is_none() {
            let claims_progress = matches!(status.state, PairingState::Acknowledged | PairingState::Active);
            let Some(ack) = &status.ack else {
                return if claims_progress { Err(PairingError::AnotherPhoneWasAccepted) } else { Ok(Progress::Waiting) };
            };
            let nonce: [u8; HOST_NONCE_LEN] =
                b64_decode_array(&ack.nonce).map_err(|_e| PairingError::AnotherPhoneWasAccepted)?;
            let message = sigs::pair_ack_msg(&self.id, &self.sign_pub, &self.kem_pub, &self.phone_nonce, &nonce);
            if !self.host_signed(&message, &ack.host_sig) {
                return Err(PairingError::AnotherPhoneWasAccepted);
            }
            // The holder of the host key signed for this phone's answer.
            // The nonce must also be the one fixed before this phone
            // answered; otherwise it could have been picked, after seeing
            // this phone's nonce, to make the code come out as wanted.
            if pairing::commitment(&self.id, &self.host_pub, &nonce) != self.commitment {
                return Err(PairingError::CodeWasSteered);
            }
            self.host_nonce = Some(nonce);
        }
        if status.state == PairingState::Active {
            let message = sigs::pair_confirm_msg(&self.id, &self.sign_pub, &self.kem_pub);
            let signature = status.host_sig.as_deref().ok_or(PairingError::NotConfirmedByHost)?;
            if !self.host_signed(&message, signature) {
                return Err(PairingError::NotConfirmedByHost);
            }
            self.active = true;
            return Ok(Progress::Active);
        }
        self.code().map(Progress::ShowCode).ok_or(PairingError::AnotherPhoneWasAccepted)
    }

    fn host_signed(&self, message: &[u8], signature_b64: &str) -> bool {
        let Ok(sig) = b64_decode_array::<SIG_LEN>(signature_b64) else { return false };
        self.host_signed_raw(message, &sig)
    }

    fn host_signed_raw(&self, message: &[u8], sig: &[u8; SIG_LEN]) -> bool {
        let (Ok(key), Ok(sig)) = (VerifyingKey::from_sec1_bytes(&self.host_pub), Signature::from_slice(sig)) else {
            return false;
        };
        key.verify(message, &sig).is_ok()
    }

    /// Checks a delivered request and, if everything holds, returns the card
    /// to show. `now` is the phone's clock in unix seconds.
    ///
    /// A card exists only for a request that decrypted under this pairing's
    /// key, is signed by the paired host, decodes strictly, names this
    /// pairing, matches the id it was delivered under, has not expired and
    /// has not been shown before.
    ///
    /// # Errors
    /// Returns the first check that failed.
    pub fn open(&mut self, delivered: &PendingRequest, now: u64) -> Result<Card, Refusal> {
        if !self.active {
            return Err(Refusal::NotActive);
        }
        let sealed = b64_decode(&delivered.envelope).map_err(|_e| Refusal::Undecryptable)?;
        let (host_sig, bytes) =
            envelope::open(&self.kem_private, &self.id, &sealed).map_err(|_e| Refusal::Undecryptable)?;
        if !self.host_signed_raw(&sigs::host_request_msg(&bytes), &host_sig) {
            return Err(Refusal::NotFromHost);
        }
        let request = Request::decode(&bytes).map_err(|_e| Refusal::Malformed)?;
        let request_id = sigs::request_id(&bytes);
        if request.pairing_id != self.id || hex_decode_array(&delivered.request_id) != Ok(request_id) {
            return Err(Refusal::Malformed);
        }
        let expires_at = request.issued_at.saturating_add(u64::from(request.ttl_secs));
        if now > expires_at.saturating_add(CLOCK_SKEW_SECS) {
            return Err(Refusal::Expired);
        }
        if !self.seen.insert(request_id) {
            return Err(Refusal::AlreadySeen);
        }
        while self.seen.len() > MAX_SEEN {
            let _ = self.seen.pop_first();
        }
        Ok(Card { digest: sigs::request_digest(&bytes), request_id, expires_at, request })
    }

    /// Signs an approval of a card. On a real phone this is the step behind
    /// Face ID.
    #[must_use]
    pub fn approve(&self, card: &Card) -> Answer {
        let signature: Signature = self.sign_key.sign(&sigs::approve_msg(&card.digest));
        Answer { decision: Decision::Approve, sig: b64_encode(&signature.to_bytes()), reason: None }
    }

    /// Signs a denial of a card, with an optional reason for the caller. The
    /// reason is cut to the protocol's limit at a character boundary.
    #[must_use]
    pub fn deny(&self, card: &Card, reason: &str) -> Answer {
        let mut end = reason.len().min(MAX_REASON_LEN);
        while !reason.is_char_boundary(end) {
            end = end.saturating_sub(1);
        }
        let reason = reason.get(..end).unwrap_or_default();
        let signature: Signature = self.sign_key.sign(&sigs::deny_msg(&card.digest, reason.as_bytes()));
        Answer {
            decision: Decision::Deny,
            sig: b64_encode(&signature.to_bytes()),
            reason: Some(reason.to_owned()).filter(|r| !r.is_empty()),
        }
    }
}

/// A request that passed every check and may be shown to the person.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Card {
    digest: [u8; 32],
    request_id: [u8; REQUEST_ID_LEN],
    expires_at: u64,
    request: Request,
}

impl Card {
    #[must_use]
    pub const fn request(&self) -> &Request {
        &self.request
    }

    #[must_use]
    pub fn request_id_hex(&self) -> String {
        hex_encode(&self.request_id)
    }

    /// The digest an approval or denial of this card signs over.
    #[must_use]
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// When the host stops waiting, by the host's clock, in unix seconds.
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }
}

#[cfg(test)]
mod tests;
