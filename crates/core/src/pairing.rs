//! The host's decision about which phone to pin, as types.
//!
//! ```text
//! Opening ──accept(phone's answer)──▶ Accepted ──confirm(typed code)──▶ Pinned
//! ```
//!
//! A [`Pinned`] is the only thing `isudo-admin` writes into the pairing
//! file, and the only way to get one is to pass every step:
//!
//! - [`Opening::new`] fixes the host's nonce and puts a commitment to it in
//!   the pairing code, before any phone has answered.
//! - [`Opening::accept`] verifies the MAC, which shows the answer came from
//!   someone holding the pairing code's secret. That excludes the relay and
//!   the network. It consumes the opening, so the nonce is revealed for one
//!   answer only.
//! - The host then signs an acknowledgement of exactly the answer it
//!   accepted, revealing its nonce ([`Accepted::ack_message`]). A phone
//!   shows its code only after checking the nonce against the commitment it
//!   scanned and verifying that signature over its own keys and nonce.
//! - [`Accepted::confirm`] compares the code the operator typed, read off
//!   their own phone, with the code this exact answer produces.
//!
//! Together: the operator can only have the right code to type if their own
//! phone's answer is the one the host accepted.
//!
//! - Someone who saw the pairing code and answered first leaves the
//!   operator's phone with no code. A relay that also knows the secret
//!   cannot forge the acknowledgement, so again the operator's phone has no
//!   code.
//! - Nobody can make a different exchange produce the same six digits. An
//!   answer has to be fixed before the host reveals its nonce, so it cannot
//!   be chosen to match a code. And a phone that was shown a pairing code
//!   written by an attacker still shows a code the attacker could not pick,
//!   because the attacker's nonce was committed before the phone chose its
//!   own. (Without the commitment, whoever wrote the pairing code could
//!   search for a nonce giving any code they liked; that was a real flaw.)

use isudo_proto::api::ClaimView;
use isudo_proto::codec::{b64_decode, b64_decode_array};
use isudo_proto::pairing::{self, decode_pubkey, Offer, Parties, MAX_NAME_LEN, SECRET_LEN};
use isudo_proto::{sigs, HOST_NONCE_LEN, PAIRING_ID_LEN, PHONE_NONCE_LEN, PUBKEY_LEN};
use p256::ecdsa::VerifyingKey;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimError {
    /// The answer is not well formed.
    Malformed,
    /// The answer was not made by someone who had the pairing code's secret.
    NotFromTheCode,
}

/// A pairing the host has offered and nobody has answered yet: the pairing
/// code to show, and the nonce it commits to.
///
/// Deliberately not `Clone`: [`Opening::accept`] consumes it, and that is
/// what limits the host to one acknowledgement per pairing code.
#[derive(Debug)]
pub struct Opening {
    offer: Offer,
    nonce: [u8; HOST_NONCE_LEN],
}

/// What identifies the host in a pairing code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostIdentity {
    pub relay_url: String,
    pub host_pub: [u8; PUBKEY_LEN],
    pub host_name: String,
}

/// A phone's answer that provably came from a holder of the pairing code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Accepted {
    pairing_id: [u8; PAIRING_ID_LEN],
    phone_sign_pub: [u8; PUBKEY_LEN],
    phone_kem_pub: [u8; PUBKEY_LEN],
    phone_name: String,
    phone_nonce: [u8; PHONE_NONCE_LEN],
    host_nonce: [u8; HOST_NONCE_LEN],
    code: String,
}

/// The phone whose key will be pinned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pinned {
    sign_pub: [u8; PUBKEY_LEN],
    kem_pub: [u8; PUBKEY_LEN],
    name: String,
}

impl Opening {
    /// Starts a pairing. `pairing_id`, `secret` and `nonce` must each be
    /// freshly random.
    ///
    /// The nonce is fixed here, before the pairing code is shown, and stays
    /// inside this value until an answer is accepted.
    #[must_use]
    pub fn new(
        host: HostIdentity,
        pairing_id: [u8; PAIRING_ID_LEN],
        secret: [u8; SECRET_LEN],
        nonce: [u8; HOST_NONCE_LEN],
    ) -> Self {
        let commitment = pairing::commitment(&pairing_id, &host.host_pub, &nonce);
        let offer = Offer {
            relay_url: host.relay_url,
            pairing_id,
            host_pub: host.host_pub,
            secret,
            commitment,
            host_name: host.host_name,
        };
        Self { offer, nonce }
    }

    /// The pairing code to show.
    #[must_use]
    pub const fn offer(&self) -> &Offer {
        &self.offer
    }

    /// Checks a phone's answer to this pairing code.
    ///
    /// This consumes the opening: the host reveals its nonce for the answer
    /// it accepts and for no other. If there were a second acknowledgement,
    /// whoever received the first could choose a second answer to match a
    /// code they had already seen.
    ///
    /// # Errors
    /// Fails if the answer is malformed or its MAC does not verify. The
    /// pairing is over either way; start again with a new pairing code.
    pub fn accept(self, claim: &ClaimView) -> Result<Accepted, ClaimError> {
        let offer = &self.offer;
        let phone_sign_pub = decode_pubkey(&claim.phone_sign_pub).map_err(|_e| ClaimError::Malformed)?;
        let phone_kem_pub = decode_pubkey(&claim.phone_kem_pub).map_err(|_e| ClaimError::Malformed)?;
        // Both must be real curve points, not just 65 bytes with the right tag.
        if VerifyingKey::from_sec1_bytes(&phone_sign_pub).is_err()
            || VerifyingKey::from_sec1_bytes(&phone_kem_pub).is_err()
        {
            return Err(ClaimError::Malformed);
        }
        let phone_nonce: [u8; PHONE_NONCE_LEN] =
            b64_decode_array(&claim.phone_nonce).map_err(|_e| ClaimError::Malformed)?;
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
        if !pairing::verify_claim_mac(&offer.secret, &parties, &phone_nonce, name.as_bytes(), &mac) {
            return Err(ClaimError::NotFromTheCode);
        }
        let code = pairing::confirmation_code(&offer.secret, &parties, &self.nonce, &phone_nonce);
        Ok(Accepted {
            pairing_id: offer.pairing_id,
            phone_sign_pub,
            phone_kem_pub,
            phone_name: name.clone(),
            phone_nonce,
            host_nonce: self.nonce,
            code,
        })
    }
}

impl Accepted {
    /// What the host signs to tell this phone its answer was the one
    /// accepted.
    #[must_use]
    pub fn ack_message(&self) -> Vec<u8> {
        sigs::pair_ack_msg(
            &self.pairing_id,
            &self.phone_sign_pub,
            &self.phone_kem_pub,
            &self.phone_nonce,
            &self.host_nonce,
        )
    }

    /// The host's nonce, to send alongside the acknowledgement signature.
    /// This is the moment it stops being secret.
    #[must_use]
    pub const fn host_nonce(&self) -> &[u8; HOST_NONCE_LEN] {
        &self.host_nonce
    }

    /// The name the answering phone gave, for the prompt.
    #[must_use]
    pub fn phone_name(&self) -> &str {
        &self.phone_name
    }

    /// True if `typed`, ignoring anything that is not a digit, is the code
    /// this phone's answer produces.
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
