//! Wire formats shared by every isudo component.
//!
//! The rule that keeps this simple: the setuid binary is the only encoder of
//! a request. Everyone else decodes the exact bytes it produced and signs or
//! verifies over those same bytes. Nothing is ever re-serialized, so there is
//! no canonicalization to get wrong.

#![forbid(unsafe_code)]

pub mod codec;
pub mod envrisk;
pub mod frame;
pub mod request;
pub mod sigs;
pub mod text;
pub mod wire;

#[cfg(feature = "api")]
pub mod api;
#[cfg(feature = "pairing")]
pub mod pairing;

/// Length of an uncompressed SEC1 / X9.63 P-256 public key (0x04 || X || Y).
pub const PUBKEY_LEN: usize = 65;
/// Length of a raw ECDSA P-256 signature (r || s).
pub const SIG_LEN: usize = 64;
/// Length of a pairing identifier.
pub const PAIRING_ID_LEN: usize = 16;
/// Length of a request identifier.
pub const REQUEST_ID_LEN: usize = 16;
/// Length of the host's pairing nonce: committed to in the pairing code,
/// revealed in the acknowledgement.
pub const HOST_NONCE_LEN: usize = 16;
/// Length of the phone's pairing nonce, sent with its answer.
pub const PHONE_NONCE_LEN: usize = 16;
/// Length of the commitment to the host's pairing nonce.
pub const COMMITMENT_LEN: usize = 32;
/// Length of a request nonce.
pub const NONCE_LEN: usize = 32;

/// Largest encoded request the system will carry. Anything larger cannot be
/// reviewed on a phone anyway, so the setuid binary refuses to ask.
pub const MAX_REQUEST_LEN: usize = 64 * 1024;
/// Longest denial reason, in bytes of UTF-8.
pub const MAX_REASON_LEN: usize = 512;
