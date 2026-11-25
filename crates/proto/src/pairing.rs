//! Pairing a host with a phone.
//!
//! 1. The host picks a random nonce and shows a pairing code (a QR code or
//!    link) holding its public key, a single-use secret, and a commitment
//!    to that nonce.
//! 2. The phone picks a nonce of its own and answers through the relay with
//!    its public keys, its nonce, and a MAC keyed by the secret.
//! 3. The host accepts one answer and signs an acknowledgement of exactly
//!    those keys and that nonce, revealing its own nonce.
//! 4. The phone checks that the revealed nonce is the one the pairing code
//!    committed to, and verifies the acknowledgement over its own answer
//!    against the host key from the pairing code. Only then does it show a
//!    six-digit code, derived from the secret, every key and both nonces.
//! 5. The operator types the code into the host, which pins the phone's key
//!    and signs a confirmation. Only then is the phone active.
//!
//! What each piece is for:
//! - The secret never reaches the relay, so a relay acting alone cannot
//!   answer the pairing with keys of its own: it cannot compute the MAC.
//! - The acknowledgement means a phone has a code to show only if the host
//!   accepted that phone's own answer. Someone who saw the pairing code and
//!   answered first, or a relay that swapped keys in transit, leaves the
//!   operator's phone with an error and no code, so there is nothing to
//!   type.
//! - The two nonces mean nobody can choose the code. Six digits is small,
//!   so the code must not be something either side can search for:
//!   - Whoever wrote the pairing code fixed their nonce, by the commitment,
//!     before the phone chose its own. So a pairing code made by an
//!     attacker and put in front of the phone cannot make the phone show a
//!     code of the attacker's choosing.
//!   - Whoever answers must fix their keys and nonce before the host
//!     reveals its nonce. So an attacker who answers the real pairing code
//!     cannot choose an answer whose code matches one they have seen.
//!
//! `formal/isudo.pv` checks these claims in a symbolic model.

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest as _, Sha256};

use crate::codec::{b64_decode_array, b64_encode, hex_decode_array, hex_encode, DecodeError};
use crate::{COMMITMENT_LEN, HOST_NONCE_LEN, PAIRING_ID_LEN, PHONE_NONCE_LEN, PUBKEY_LEN};

pub const SECRET_LEN: usize = 32;
pub const MAX_NAME_LEN: usize = 64;

const CTX_CLAIM: &[u8] = b"isudo/v1/pair-claim\0";
const CTX_CODE: &[u8] = b"isudo/v1/pair-code\0";
const CTX_COMMIT: &[u8] = b"isudo/v1/pair-commit\0";

/// The public keys that take part in a pairing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Parties<'a> {
    pub pairing_id: &'a [u8; PAIRING_ID_LEN],
    pub host_pub: &'a [u8; PUBKEY_LEN],
    pub phone_sign_pub: &'a [u8; PUBKEY_LEN],
    pub phone_kem_pub: &'a [u8; PUBKEY_LEN],
}

/// Everything in the pairing code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offer {
    pub relay_url: String,
    pub pairing_id: [u8; PAIRING_ID_LEN],
    pub host_pub: [u8; PUBKEY_LEN],
    pub secret: [u8; SECRET_LEN],
    /// [`commitment`] to the nonce the host will reveal when it accepts an
    /// answer.
    pub commitment: [u8; COMMITMENT_LEN],
    pub host_name: String,
}

impl Offer {
    /// `isudo://pair?v=2&r=<relay>&p=<id>&k=<host key>&s=<secret>&c=<commitment>&n=<name>`,
    /// with binary values in unpadded base64url and text percent-encoded.
    #[must_use]
    pub fn to_url(&self) -> String {
        [
            "isudo://pair?v=2&r=",
            &percent_encode(self.relay_url.as_bytes()),
            "&p=",
            &b64_encode(&self.pairing_id),
            "&k=",
            &b64_encode(&self.host_pub),
            "&s=",
            &b64_encode(&self.secret),
            "&c=",
            &b64_encode(&self.commitment),
            "&n=",
            &percent_encode(self.host_name.as_bytes()),
        ]
        .concat()
    }

    /// # Errors
    /// Fails unless the link has exactly the fields [`Offer::to_url`] writes,
    /// each once, with values of the right size.
    pub fn from_url(url: &str) -> Result<Self, DecodeError> {
        const MISSING: DecodeError = DecodeError("pairing link is missing a field");
        let query = url.trim().strip_prefix("isudo://pair?").ok_or(DecodeError("not an isudo pairing link"))?;
        let (mut version, mut relay, mut id, mut key) = (None, None, None, None);
        let (mut secret, mut commitment, mut name) = (None, None, None);
        for pair in query.split('&') {
            let (field, value) = pair.split_once('=').ok_or(DecodeError("malformed pairing link"))?;
            let slot = match field {
                "v" => &mut version,
                "r" => &mut relay,
                "p" => &mut id,
                "k" => &mut key,
                "s" => &mut secret,
                "c" => &mut commitment,
                "n" => &mut name,
                _ => return Err(DecodeError("unknown field in pairing link")),
            };
            if slot.replace(value).is_some() {
                return Err(DecodeError("repeated field in pairing link"));
            }
        }
        match version.ok_or(MISSING)? {
            "2" => {}
            // Version 1 had no commitment, which let whoever wrote the link
            // choose the code the phone would show.
            "1" => return Err(DecodeError("pairing link is from an older isudo; update isudo on the computer")),
            _ => return Err(DecodeError("unsupported pairing link version")),
        }
        let offer = Self {
            relay_url: percent_decode(relay.ok_or(MISSING)?)?,
            pairing_id: b64_decode_array(id.ok_or(MISSING)?)?,
            host_pub: decode_pubkey(key.ok_or(MISSING)?)?,
            secret: b64_decode_array(secret.ok_or(MISSING)?)?,
            commitment: b64_decode_array(commitment.ok_or(MISSING)?)?,
            host_name: percent_decode(name.ok_or(MISSING)?)?,
        };
        if offer.host_name.len() > MAX_NAME_LEN {
            return Err(DecodeError("host name is too long"));
        }
        Ok(offer)
    }
}

/// HMAC-SHA256 keyed with the pairing secret.
fn keyed(secret: &[u8; SECRET_LEN]) -> Hmac<Sha256> {
    // HMAC pads a key shorter than the hash's block with zeros (RFC 2104).
    // Doing that here gives a key of exactly the block size, which is the
    // one constructor that cannot fail.
    let mut key = [0_u8; 64];
    for (dst, src) in key.iter_mut().zip(secret) {
        *dst = *src;
    }
    Hmac::<Sha256>::new(&key.into())
}

fn absorb(mac: &mut Hmac<Sha256>, parties: &Parties<'_>) {
    mac.update(parties.pairing_id);
    mac.update(parties.host_pub);
    mac.update(parties.phone_sign_pub);
    mac.update(parties.phone_kem_pub);
}

/// The commitment a pairing code carries to the host's nonce.
///
/// It fixes the nonce without revealing it. Covering the pairing id and the
/// host key ties it to one pairing code, so it cannot be lifted into another.
#[must_use]
pub fn commitment(
    pairing_id: &[u8; PAIRING_ID_LEN],
    host_pub: &[u8; PUBKEY_LEN],
    host_nonce: &[u8; HOST_NONCE_LEN],
) -> [u8; COMMITMENT_LEN] {
    let mut hash = Sha256::new();
    hash.update(CTX_COMMIT);
    hash.update(pairing_id);
    hash.update(host_pub);
    hash.update(host_nonce);
    hash.finalize().into()
}

fn claim_tag(
    secret: &[u8; SECRET_LEN],
    parties: &Parties<'_>,
    phone_nonce: &[u8; PHONE_NONCE_LEN],
    phone_name: &[u8],
) -> Hmac<Sha256> {
    let mut mac = keyed(secret);
    mac.update(CTX_CLAIM);
    absorb(&mut mac, parties);
    mac.update(phone_nonce);
    mac.update(phone_name);
    mac
}

/// The phone's proof that it read the pairing code: HMAC-SHA256 under the
/// pairing secret over every key in the pairing, the phone's nonce and its
/// display name.
#[must_use]
pub fn claim_mac(
    secret: &[u8; SECRET_LEN],
    parties: &Parties<'_>,
    phone_nonce: &[u8; PHONE_NONCE_LEN],
    phone_name: &[u8],
) -> [u8; 32] {
    claim_tag(secret, parties, phone_nonce, phone_name).finalize().into_bytes().into()
}

/// Constant-time check of a claim MAC.
#[must_use]
pub fn verify_claim_mac(
    secret: &[u8; SECRET_LEN],
    parties: &Parties<'_>,
    phone_nonce: &[u8; PHONE_NONCE_LEN],
    phone_name: &[u8],
    candidate: &[u8],
) -> bool {
    claim_tag(secret, parties, phone_nonce, phone_name).verify_slice(candidate).is_ok()
}

/// The six-digit code shown on the phone and typed into the host.
///
/// It depends on both nonces, and neither side can choose its nonce knowing
/// the other's: the host's is fixed by the commitment in the pairing code
/// before the phone picks one, and is revealed only after the phone's
/// arrived. So nobody can steer the code, whichever side they play.
#[must_use]
pub fn confirmation_code(
    secret: &[u8; SECRET_LEN],
    parties: &Parties<'_>,
    host_nonce: &[u8; HOST_NONCE_LEN],
    phone_nonce: &[u8; PHONE_NONCE_LEN],
) -> String {
    let mut mac = keyed(secret);
    mac.update(CTX_CODE);
    absorb(&mut mac, parties);
    mac.update(host_nonce);
    mac.update(phone_nonce);
    let tag: [u8; 32] = mac.finalize().into_bytes().into();
    let mut head = [0_u8; 8];
    for (dst, src) in head.iter_mut().zip(tag) {
        *dst = src;
    }
    let number = u64::from_be_bytes(head) % 1_000_000;
    format!("{number:06}")
}

fn percent_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for &byte in bytes {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push_str(&hex_encode(&[byte]).to_ascii_uppercase());
        }
    }
    out
}

fn percent_decode(text: &str) -> Result<String, DecodeError> {
    let mut out = Vec::with_capacity(text.len());
    let mut bytes = text.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'%' {
            let digits = [bytes.next(), bytes.next()];
            let [Some(high), Some(low)] = digits else {
                return Err(DecodeError("truncated percent escape"));
            };
            // Two hex digits exactly. (`u8::from_str_radix` would also take
            // a sign, so "%+f" must not get that far.)
            let pair = [high, low];
            let hex = std::str::from_utf8(&pair).map_err(|_e| DecodeError("invalid percent escape"))?;
            let [byte] = hex_decode_array(hex).map_err(|_e| DecodeError("invalid percent escape"))?;
            out.push(byte);
        } else {
            out.push(byte);
        }
    }
    String::from_utf8(out).map_err(|_e| DecodeError("pairing link text is not UTF-8"))
}

/// Decodes a base64url public key and checks its length and SEC1 tag.
///
/// # Errors
/// Fails unless the text decodes to a 65-byte uncompressed point encoding.
pub fn decode_pubkey(text: &str) -> Result<[u8; PUBKEY_LEN], DecodeError> {
    let key: [u8; PUBKEY_LEN] = b64_decode_array(text)?;
    if key.first() != Some(&0x04) {
        return Err(DecodeError("public key is not in uncompressed form"));
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offer() -> Offer {
        let mut host_pub = [0x11; PUBKEY_LEN];
        host_pub[0] = 0x04;
        Offer {
            relay_url: "https://relay.example:8443/base path".into(),
            pairing_id: [0xa5; 16],
            host_pub,
            secret: [0x3c; 32],
            commitment: commitment(&[0xa5; 16], &host_pub, &HOST_NONCE),
            host_name: "burke’s mbp & co".into(),
        }
    }

    const HOST_NONCE: [u8; HOST_NONCE_LEN] = [0x4e; HOST_NONCE_LEN];
    const PHONE_NONCE: [u8; PHONE_NONCE_LEN] = [0x70; PHONE_NONCE_LEN];
    const SIGN: [u8; PUBKEY_LEN] = [2; PUBKEY_LEN];
    const KEM: [u8; PUBKEY_LEN] = [3; PUBKEY_LEN];

    fn parties(offer: &Offer) -> Parties<'_> {
        Parties {
            pairing_id: &offer.pairing_id,
            host_pub: &offer.host_pub,
            phone_sign_pub: &SIGN,
            phone_kem_pub: &KEM,
        }
    }

    #[test]
    fn url_round_trip() {
        let offer = offer();
        let url = offer.to_url();
        assert!(url.starts_with("isudo://pair?v=2&r=https%3A%2F%2Frelay.example%3A8443%2Fbase%20path&p="));
        assert_eq!(Offer::from_url(&url).unwrap(), offer);
    }

    #[test]
    fn url_is_strict() {
        let url = offer().to_url();
        assert!(Offer::from_url(&url.replace("v=2", "v=3")).is_err());
        assert!(Offer::from_url(&format!("{url}&x=1")).is_err());
        assert!(Offer::from_url(&format!("{url}&v=2")).is_err());
        assert!(Offer::from_url(&url.replace("&s=", "&t=")).is_err());
        // The commitment is required, and must be exactly 32 bytes.
        let without = url.split('&').filter(|field| !field.starts_with("c=")).collect::<Vec<_>>().join("&");
        assert!(Offer::from_url(&without).is_err());
        assert!(Offer::from_url(&url.replace("&c=", "&c=A")).is_err());
        assert!(Offer::from_url(&format!("{url}%")).is_err());
        assert!(Offer::from_url(&format!("{url}%zz")).is_err());
        assert!(Offer::from_url(&format!("{url}%+f")).is_err(), "a sign is not a hex digit");
        assert!(Offer::from_url(&format!("{url}%-0")).is_err());
        assert!(Offer::from_url("https://example.com/?v=2").is_err());
        // A link from before the commitment existed is refused, and says why.
        let old = without.replace("v=2", "v=1");
        assert!(Offer::from_url(&old).unwrap_err().0.contains("older"));
        // A host key that is not an uncompressed point.
        let mut bad = offer();
        bad.host_pub[0] = 0x02;
        assert!(Offer::from_url(&bad.to_url()).is_err());
    }

    #[test]
    fn keyed_matches_standard_hmac() {
        // The zero-padded key must give the same MAC as the general
        // constructor, which is what the phone's HMAC implementation uses.
        let secret = [0x3c; 32];
        let mut ours = keyed(&secret);
        ours.update(b"message");
        let mut standard = <Hmac<Sha256> as KeyInit>::new_from_slice(&secret).unwrap();
        standard.update(b"message");
        assert_eq!(ours.finalize().into_bytes(), standard.finalize().into_bytes());
    }

    #[test]
    fn mac_binds_every_input() {
        let o = offer();
        let p = parties(&o);
        let n = PHONE_NONCE;
        let mac = claim_mac(&o.secret, &p, &n, b"iPhone");
        assert!(verify_claim_mac(&o.secret, &p, &n, b"iPhone", &mac));
        assert!(!verify_claim_mac(&[0; 32], &p, &n, b"iPhone", &mac));
        assert!(!verify_claim_mac(&o.secret, &Parties { pairing_id: &[0; 16], ..p }, &n, b"iPhone", &mac));
        assert!(!verify_claim_mac(&o.secret, &Parties { host_pub: &KEM, ..p }, &n, b"iPhone", &mac));
        let swapped = Parties { phone_sign_pub: &KEM, phone_kem_pub: &SIGN, ..p };
        assert!(!verify_claim_mac(&o.secret, &swapped, &n, b"iPhone", &mac));
        assert!(!verify_claim_mac(&o.secret, &p, &[0x71; PHONE_NONCE_LEN], b"iPhone", &mac));
        assert!(!verify_claim_mac(&o.secret, &p, &n, b"iPhone2", &mac));
        assert!(!verify_claim_mac(&o.secret, &p, &n, b"iPhone", &mac[..31]));
    }

    #[test]
    fn code_depends_on_the_keys_the_secret_and_both_nonces() {
        let o = offer();
        let p = parties(&o);
        let code = confirmation_code(&o.secret, &p, &HOST_NONCE, &PHONE_NONCE);
        assert_eq!(code.len(), 6);
        assert!(code.bytes().all(|b| b.is_ascii_digit()));
        let other_key = Parties { phone_sign_pub: &[9; PUBKEY_LEN], ..p };
        assert_ne!(code, confirmation_code(&o.secret, &other_key, &HOST_NONCE, &PHONE_NONCE));
        assert_ne!(code, confirmation_code(&[0; 32], &p, &HOST_NONCE, &PHONE_NONCE));
        assert_ne!(code, confirmation_code(&o.secret, &p, &[2; HOST_NONCE_LEN], &PHONE_NONCE));
        assert_ne!(code, confirmation_code(&o.secret, &p, &HOST_NONCE, &[2; PHONE_NONCE_LEN]));
        // The nonces are not interchangeable.
        assert_ne!(code, confirmation_code(&o.secret, &p, &PHONE_NONCE, &HOST_NONCE));
    }

    #[test]
    fn commitment_binds_the_nonce_to_one_pairing_code() {
        let o = offer();
        let c = commitment(&o.pairing_id, &o.host_pub, &HOST_NONCE);
        assert_eq!(c, o.commitment);
        assert_ne!(c, commitment(&o.pairing_id, &o.host_pub, &[0x4f; HOST_NONCE_LEN]));
        assert_ne!(c, commitment(&[0; 16], &o.host_pub, &HOST_NONCE));
        assert_ne!(c, commitment(&o.pairing_id, &KEM, &HOST_NONCE));
    }
}
