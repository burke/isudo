//! The exact byte strings that get signed.
//!
//! Every signature in the system is ECDSA P-256 over SHA-256 of one of these
//! messages, encoded as raw `r || s` (64 bytes). Each message starts with a
//! distinct NUL-terminated context string, so a signature made for one purpose
//! can never be presented for another.

use sha2::{Digest, Sha256};

use crate::{HOST_NONCE_LEN, PAIRING_ID_LEN, PHONE_NONCE_LEN, PUBKEY_LEN, REQUEST_ID_LEN};

pub const CTX_REQUEST: &[u8] = b"isudo/v1/request\0";
pub const CTX_TICKET: &[u8] = b"isudo/v1/ticket\0";
pub const CTX_APPROVE: &[u8] = b"isudo/v1/approve\0";
pub const CTX_DENY: &[u8] = b"isudo/v1/deny\0";
pub const CTX_PAIR_ACK: &[u8] = b"isudo/v1/pair-ack\0";
pub const CTX_PAIR_CONFIRM: &[u8] = b"isudo/v1/pair-confirm\0";
pub const CTX_PAIR_REVOKE: &[u8] = b"isudo/v1/pair-revoke\0";
/// HPKE `info` prefix for the encrypted request envelope.
pub const CTX_ENVELOPE: &[u8] = b"isudo/v1/envelope\0";

/// SHA-256 of the encoded request. The phone's approval covers this.
#[must_use]
pub fn request_digest(request: &[u8]) -> [u8; 32] {
    Sha256::digest(request).into()
}

/// Public handle for a request: the first half of its digest.
#[must_use]
pub fn request_id(request: &[u8]) -> [u8; REQUEST_ID_LEN] {
    let mut id = [0; REQUEST_ID_LEN];
    for (dst, src) in id.iter_mut().zip(request_digest(request)) {
        *dst = src;
    }
    id
}

/// Signed by the host key. Lets the phone refuse to display a request that
/// did not come from the paired host's setuid binary.
#[must_use]
pub fn host_request_msg(request: &[u8]) -> Vec<u8> {
    [CTX_REQUEST, request].concat()
}

/// Signed by the host key. Lets the relay accept a request (and spend a push
/// notification on it) without being able to read it.
#[must_use]
pub fn ticket_msg(pairing_id: &[u8; PAIRING_ID_LEN], request_id: &[u8; REQUEST_ID_LEN], expires_at: u64) -> Vec<u8> {
    [CTX_TICKET, pairing_id, request_id, &expires_at.to_be_bytes()].concat()
}

/// Signed by the phone key, behind Face ID. This is the approval.
#[must_use]
pub fn approve_msg(request_digest: &[u8; 32]) -> Vec<u8> {
    [CTX_APPROVE, request_digest.as_slice()].concat()
}

/// Signed by the phone key. Denials are signed so that the reason shown to
/// the caller (often an AI agent) provably came from the approver and not
/// from the relay.
#[must_use]
pub fn deny_msg(request_digest: &[u8; 32], reason: &[u8]) -> Vec<u8> {
    [CTX_DENY, request_digest.as_slice(), reason].concat()
}

/// HPKE `info` for sealing a request to a pairing's phone.
#[must_use]
pub fn envelope_info(pairing_id: &[u8; PAIRING_ID_LEN]) -> Vec<u8> {
    [CTX_ENVELOPE, pairing_id.as_slice()].concat()
}

/// Signed by the host key as soon as it accepts a phone's answer.
///
/// The phone shows its code only after verifying this over its own keys and
/// its own nonce, which is what makes the code meaningful: a phone whose
/// answer the host did not receive never has a code to show. The message
/// also reveals the host's nonce, which the pairing code committed to.
#[must_use]
pub fn pair_ack_msg(
    pairing_id: &[u8; PAIRING_ID_LEN],
    phone_sign_pub: &[u8; PUBKEY_LEN],
    phone_kem_pub: &[u8; PUBKEY_LEN],
    phone_nonce: &[u8; PHONE_NONCE_LEN],
    host_nonce: &[u8; HOST_NONCE_LEN],
) -> Vec<u8> {
    [CTX_PAIR_ACK, pairing_id.as_slice(), phone_sign_pub, phone_kem_pub, phone_nonce, host_nonce].concat()
}

/// Signed by the host key once the operator has confirmed the pairing code.
#[must_use]
pub fn pair_confirm_msg(
    pairing_id: &[u8; PAIRING_ID_LEN],
    phone_sign_pub: &[u8; PUBKEY_LEN],
    phone_kem_pub: &[u8; PUBKEY_LEN],
) -> Vec<u8> {
    [CTX_PAIR_CONFIRM, pairing_id.as_slice(), phone_sign_pub, phone_kem_pub].concat()
}

/// Signed by the host key to delete a pairing from the relay.
#[must_use]
pub fn pair_revoke_msg(pairing_id: &[u8; PAIRING_ID_LEN]) -> Vec<u8> {
    [CTX_PAIR_REVOKE, pairing_id.as_slice()].concat()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contexts_are_distinct_and_prefix_free() {
        let all = [
            CTX_REQUEST,
            CTX_TICKET,
            CTX_APPROVE,
            CTX_DENY,
            CTX_PAIR_ACK,
            CTX_PAIR_CONFIRM,
            CTX_PAIR_REVOKE,
            CTX_ENVELOPE,
            crate::delegation::CTX_DELEGATE,
        ];
        for (i, a) in all.iter().enumerate() {
            assert_eq!(a.last(), Some(&0));
            for (j, b) in all.iter().enumerate() {
                if i != j {
                    assert!(!a.starts_with(b), "{a:?} starts with {b:?}");
                }
            }
        }
    }

    #[test]
    fn approve_and_deny_never_collide() {
        let digest = [0x41; 32];
        assert_ne!(approve_msg(&digest), deny_msg(&digest, b""));
    }

    #[test]
    fn request_id_is_digest_prefix() {
        let req = b"anything";
        assert_eq!(request_id(req), request_digest(req)[..16]);
    }

    #[test]
    fn digest_matches_a_known_vector() {
        // SHA-256("abc"), FIPS 180-2 appendix B.1.
        assert_eq!(
            crate::codec::hex_encode(&request_digest(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
