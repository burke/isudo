//! The host's decision about which phone to pin, as types.
//!
//! ```text
//! Offer + phone's answer ──accept──▶ Accepted ──confirm(typed code)──▶ Pinned
//! ```
//!
//! A [`Pinned`] is the only thing `isudo-admin` writes into the pairing
//! file, and the only way to get one is to pass both checks:
//!
//! - [`accept`] verifies the MAC, which shows the answer came from someone
//!   holding the QR code's secret. That excludes the relay and the network.
//! - The host then signs an acknowledgement of exactly the keys it accepted
//!   and a fresh nonce ([`Accepted::ack_message`]). A phone shows its code
//!   only after verifying that signature over its own keys, against the
//!   host key it read from the QR code, and derives the code from the nonce.
//! - [`Accepted::confirm`] compares the code the operator typed, read off
//!   their own phone, with the code these exact keys produce.
//!
//! Together: the operator can only have a code to type if their own phone's
//! keys are the ones the host accepted. Someone who saw the QR code and
//! answered first leaves the operator's phone with no code. A relay that
//! also knows the secret cannot forge the acknowledgement, so again the
//! operator's phone has no code; and it cannot search for substitute keys
//! whose six-digit code matches, because the code depends on a nonce the
//! host chooses only after the keys are fixed.

use isudo_proto::api::ClaimView;
use isudo_proto::codec::b64_decode;
use isudo_proto::pairing::{self, decode_pubkey, Offer, Parties, MAX_NAME_LEN};
use isudo_proto::{sigs, ACK_NONCE_LEN, PAIRING_ID_LEN, PUBKEY_LEN};
use p256::ecdsa::VerifyingKey;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimError {
    /// The answer is not well formed.
    Malformed,
    /// The answer was not made by someone who had the QR code's secret.
    NotFromTheCode,
}

/// A phone's answer that provably came from a holder of the QR code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Accepted {
    phone_sign_pub: [u8; PUBKEY_LEN],
    phone_kem_pub: [u8; PUBKEY_LEN],
    phone_name: String,
    nonce: [u8; ACK_NONCE_LEN],
    code: String,
}

/// The phone whose key will be pinned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pinned {
    sign_pub: [u8; PUBKEY_LEN],
    kem_pub: [u8; PUBKEY_LEN],
    name: String,
}

/// Checks a phone's answer against the offer it claims to answer.
///
/// `nonce` must be freshly random for this call: it goes into the
/// acknowledgement and the code, and being chosen now, after the phone's
/// keys arrived, is what stops anyone searching for keys with a wanted code.
///
/// # Errors
/// Fails if the answer is malformed or its MAC does not verify.
pub fn accept(offer: &Offer, claim: &ClaimView, nonce: [u8; ACK_NONCE_LEN]) -> Result<Accepted, ClaimError> {
    let phone_sign_pub = decode_pubkey(&claim.phone_sign_pub).map_err(|_e| ClaimError::Malformed)?;
    let phone_kem_pub = decode_pubkey(&claim.phone_kem_pub).map_err(|_e| ClaimError::Malformed)?;
    // Both must be real curve points, not just 65 bytes with the right tag.
    if VerifyingKey::from_sec1_bytes(&phone_sign_pub).is_err() || VerifyingKey::from_sec1_bytes(&phone_kem_pub).is_err()
    {
        return Err(ClaimError::Malformed);
    }
    let mac = b64_decode(&claim.claim_mac).map_err(|_e| ClaimError::Malformed)?;
    let name = &claim.phone_name;
    if name.is_empty() || name.len() > MAX_NAME_LEN || name.trim() != name || name.chars().any(char::is_control) {
        return Err(ClaimError::Malformed);
    }
    let parties = Parties {
        pairing_id: &offer.pairing_id,
        host_pub: &offer.host_pub,
        phone_sign_pub: &phone_sign_pub,
        phone_kem_pub: &phone_kem_pub,
    };
    if !pairing::verify_claim_mac(&offer.secret, &parties, name.as_bytes(), &mac) {
        return Err(ClaimError::NotFromTheCode);
    }
    let code = pairing::confirmation_code(&offer.secret, &parties, &nonce);
    Ok(Accepted { phone_sign_pub, phone_kem_pub, phone_name: name.clone(), nonce, code })
}

impl Accepted {
    /// What the host signs to tell this phone its answer was the one
    /// accepted. The host must sign this for at most one answer per offer:
    /// the phone shows its code only when it holds this signature over its
    /// own keys, so a second acknowledgement would give a second phone a
    /// code to show.
    #[must_use]
    pub fn ack_message(&self, pairing_id: &[u8; PAIRING_ID_LEN]) -> Vec<u8> {
        sigs::pair_ack_msg(pairing_id, &self.phone_sign_pub, &self.phone_kem_pub, &self.nonce)
    }

    /// The nonce to send alongside the acknowledgement signature.
    #[must_use]
    pub const fn ack_nonce(&self) -> &[u8; ACK_NONCE_LEN] {
        &self.nonce
    }

    /// The name the answering phone gave, for the prompt.
    #[must_use]
    pub fn phone_name(&self) -> &str {
        &self.phone_name
    }

    /// True if `typed`, ignoring anything that is not a digit, is the code
    /// this phone's keys produce.
    #[must_use]
    pub fn code_matches(&self, typed: &str) -> bool {
        let digits: String = typed.chars().filter(char::is_ascii_digit).collect();
        digits == self.code
    }

    /// Pins the phone if the operator typed its code; otherwise None, and
    /// the operator can be asked again.
    #[must_use]
    pub fn confirm(&self, typed: &str) -> Option<Pinned> {
        self.code_matches(typed).then(|| Pinned {
            sign_pub: self.phone_sign_pub,
            kem_pub: self.phone_kem_pub,
            name: self.phone_name.clone(),
        })
    }
}

impl Pinned {
    #[must_use]
    pub const fn phone_sign_pub(&self) -> &[u8; PUBKEY_LEN] {
        &self.sign_pub
    }

    #[must_use]
    pub const fn phone_kem_pub(&self) -> &[u8; PUBKEY_LEN] {
        &self.kem_pub
    }

    #[must_use]
    pub fn phone_name(&self) -> &str {
        &self.name
    }
}
