//! End-to-end encryption of requests, so the relay carries only ciphertext.
//!
//! Standard HPKE (RFC 9180), base mode, with DHKEM(P-256, HKDF-SHA256),
//! HKDF-SHA256 and AES-256-GCM: the suite Apple's `CryptoKit` calls
//! `P256_SHA256_AES_GCM_256`. The envelope is the 65-byte encapsulated key
//! followed by the ciphertext of `host signature || request`.

use std::fmt;

use hpke::aead::AesGcm256;
use hpke::kdf::HkdfSha256;
use hpke::kem::DhP256HkdfSha256;
use hpke::{Deserializable as _, Kem, OpModeR, OpModeS, Serializable as _};
use isudo_proto::{sigs, PAIRING_ID_LEN, PUBKEY_LEN, SIG_LEN};

type Suite = DhP256HkdfSha256;
type PublicKey = <Suite as Kem>::PublicKey;
type PrivateKey = <Suite as Kem>::PrivateKey;
type EncappedKey = <Suite as Kem>::EncappedKey;

/// Length of a P-256 private scalar.
pub const PRIVATE_KEY_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeError {
    /// The recipient's public key is not a valid curve point.
    BadKey,
    /// Encryption failed.
    Seal,
    /// The envelope is malformed, was sealed for someone else, or was
    /// tampered with.
    Open,
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::BadKey => "the phone's encryption key is invalid",
            Self::Seal => "the request could not be encrypted",
            Self::Open => "the request could not be decrypted",
        })
    }
}

impl std::error::Error for EnvelopeError {}

/// Encrypts a signed request to a phone.
///
/// # Errors
/// Fails if the phone's key is invalid.
pub fn seal(
    phone_kem_pub: &[u8; PUBKEY_LEN],
    pairing_id: &[u8; PAIRING_ID_LEN],
    host_sig: &[u8; SIG_LEN],
    request: &[u8],
) -> Result<Vec<u8>, EnvelopeError> {
    let recipient = PublicKey::from_bytes(phone_kem_pub).map_err(|_e| EnvelopeError::BadKey)?;
    let plaintext = [host_sig.as_slice(), request].concat();
    let (encapped, ciphertext) = hpke::single_shot_seal::<AesGcm256, HkdfSha256, Suite>(
        &OpModeS::Base,
        &recipient,
        &sigs::envelope_info(pairing_id),
        &plaintext,
        &[],
    )
    .map_err(|_e| EnvelopeError::Seal)?;
    Ok([encapped.to_bytes().as_slice(), &ciphertext].concat())
}

/// Decrypts an envelope, returning the host's signature and the request.
///
/// # Errors
/// Fails if the envelope was not sealed to this key for this pairing.
pub fn open(
    kem_private: &[u8; PRIVATE_KEY_LEN],
    pairing_id: &[u8; PAIRING_ID_LEN],
    envelope: &[u8],
) -> Result<([u8; SIG_LEN], Vec<u8>), EnvelopeError> {
    let (encapped, ciphertext) = envelope.split_at_checked(PUBKEY_LEN).ok_or(EnvelopeError::Open)?;
    let private = PrivateKey::from_bytes(kem_private).map_err(|_e| EnvelopeError::BadKey)?;
    let encapped = EncappedKey::from_bytes(encapped).map_err(|_e| EnvelopeError::Open)?;
    let plaintext = hpke::single_shot_open::<AesGcm256, HkdfSha256, Suite>(
        &OpModeR::Base,
        &private,
        &encapped,
        &sigs::envelope_info(pairing_id),
        ciphertext,
        &[],
    )
    .map_err(|_e| EnvelopeError::Open)?;
    let (host_sig, request) = plaintext.split_first_chunk::<SIG_LEN>().ok_or(EnvelopeError::Open)?;
    Ok((*host_sig, request.to_vec()))
}

/// Derives a key pair for receiving envelopes from secret input keying
/// material, deterministically (RFC 9180 `DeriveKeyPair`).
///
/// # Errors
/// Fails only if the derived key cannot be serialized, which would be a bug
/// in the underlying library.
pub fn derive(ikm: &[u8]) -> Result<([u8; PRIVATE_KEY_LEN], [u8; PUBKEY_LEN]), EnvelopeError> {
    let (private, public) = Suite::derive_keypair(ikm);
    let private = private.to_bytes().as_slice().try_into().map_err(|_e| EnvelopeError::BadKey)?;
    let public = public.to_bytes().as_slice().try_into().map_err(|_e| EnvelopeError::BadKey)?;
    Ok((private, public))
}

/// Generates a key pair for receiving envelopes: (private scalar, public key).
///
/// # Errors
/// Fails only if the generated key cannot be serialized, which would be a
/// bug in the underlying library.
pub fn generate() -> Result<([u8; PRIVATE_KEY_LEN], [u8; PUBKEY_LEN]), EnvelopeError> {
    let (private, public) = Suite::gen_keypair();
    let private = private.to_bytes().as_slice().try_into().map_err(|_e| EnvelopeError::BadKey)?;
    let public = public.to_bytes().as_slice().try_into().map_err(|_e| EnvelopeError::BadKey)?;
    Ok((private, public))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAIRING: [u8; PAIRING_ID_LEN] = [7; PAIRING_ID_LEN];
    const HOST_SIG: [u8; SIG_LEN] = [9; SIG_LEN];

    #[test]
    fn round_trip() {
        let (private, public) = generate().unwrap();
        let envelope = seal(&public, &PAIRING, &HOST_SIG, b"the request").unwrap();
        assert_eq!(open(&private, &PAIRING, &envelope).unwrap(), (HOST_SIG, b"the request".to_vec()));
    }

    #[test]
    fn sealing_is_randomized_and_hides_the_request() {
        let (_, public) = generate().unwrap();
        let first = seal(&public, &PAIRING, &HOST_SIG, b"secret argv").unwrap();
        let second = seal(&public, &PAIRING, &HOST_SIG, b"secret argv").unwrap();
        assert_ne!(first, second);
        assert!(!first.windows(11).any(|w| w == b"secret argv"));
    }

    #[test]
    fn wrong_key_pairing_or_tampering_fails() {
        let (private, public) = generate().unwrap();
        let (other_private, _) = generate().unwrap();
        let envelope = seal(&public, &PAIRING, &HOST_SIG, b"the request").unwrap();
        assert_eq!(open(&other_private, &PAIRING, &envelope), Err(EnvelopeError::Open));
        assert_eq!(open(&private, &[8; PAIRING_ID_LEN], &envelope), Err(EnvelopeError::Open));
        for index in [0, 40, 65, envelope.len() - 1] {
            let mut tampered = envelope.clone();
            tampered[index] ^= 1;
            assert!(open(&private, &PAIRING, &tampered).is_err(), "accepted a flip at byte {index}");
        }
        assert_eq!(open(&private, &PAIRING, &envelope[..64]), Err(EnvelopeError::Open));
        assert_eq!(open(&private, &PAIRING, &[]), Err(EnvelopeError::Open));
    }

    #[test]
    fn derivation_is_deterministic_and_usable() {
        let (private, public) = derive(b"some secret seed material, 32+ bytes").unwrap();
        assert_eq!(derive(b"some secret seed material, 32+ bytes").unwrap(), (private, public));
        assert_ne!(derive(b"other secret seed material, 32+ byte").unwrap().1, public);
        let envelope = seal(&public, &PAIRING, &HOST_SIG, b"x").unwrap();
        assert_eq!(open(&private, &PAIRING, &envelope).unwrap().1, b"x");
    }

    #[test]
    fn rejects_an_invalid_recipient_key() {
        assert_eq!(seal(&[0; PUBKEY_LEN], &PAIRING, &HOST_SIG, b"x"), Err(EnvelopeError::BadKey));
    }
}
