//! Framing between the setuid binary and its unprivileged helper.
//!
//! The setuid binary writes one [`Job`] to the helper's standard input and
//! reads one [`Outcome`] from its standard output. The helper is not trusted:
//! whatever comes back is only acted on after the signature inside it has
//! been verified against the pinned phone key.

use crate::delegation::{SignedDelegation, MAX_SIGNED_DELEGATION_LEN};
use crate::wire::{Reader, WireError, Writer};
use crate::{MAX_REASON_LEN, MAX_REQUEST_LEN, PAIRING_ID_LEN, PUBKEY_LEN, SIG_LEN};

const JOB_MAGIC: [u8; 8] = *b"ISUDOJB\x02";
const OUTCOME_MAGIC: [u8; 8] = *b"ISUDORS\x02";

pub const MAX_RELAY_URL_LEN: usize = 2048;
/// Upper bound on an encoded [`Outcome`]; the setuid binary reads no more.
pub const MAX_OUTCOME_LEN: usize =
    OUTCOME_MAGIC.len() + 1 + SIG_LEN + 4 + MAX_REASON_LEN + 4 + MAX_SIGNED_DELEGATION_LEN;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Job {
    pub relay_url: Vec<u8>,
    pub pairing_id: [u8; PAIRING_ID_LEN],
    pub phone_kem_pub: [u8; PUBKEY_LEN],
    /// The pinned phone key. The helper uses it to check a delegation before
    /// sealing the request to a delegate as well; it is public.
    pub phone_sign_pub: [u8; PUBKEY_LEN],
    /// Whether the host accepts delegates at all. If not, the helper does
    /// not look for any.
    pub delegates: bool,
    /// Unix time after which the relay and phone should discard the request.
    pub expires_at: u64,
    /// How long the helper should keep waiting for an answer.
    pub timeout_secs: u32,
    pub ticket_sig: [u8; SIG_LEN],
    pub host_sig: [u8; SIG_LEN],
    pub request: Vec<u8>,
}

impl Job {
    /// # Errors
    /// Fails if the relay URL or the request is over its size limit.
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        if self.relay_url.len() > MAX_RELAY_URL_LEN {
            return Err(WireError::TooLarge("relay url"));
        }
        if self.request.len() > MAX_REQUEST_LEN {
            return Err(WireError::TooLarge("request"));
        }
        let mut w = Writer::new();
        w.raw(&JOB_MAGIC);
        w.bytes(&self.relay_url)?;
        w.raw(&self.pairing_id);
        w.raw(&self.phone_kem_pub);
        w.raw(&self.phone_sign_pub);
        w.u8(u8::from(self.delegates));
        w.u64(self.expires_at);
        w.u32(self.timeout_secs);
        w.raw(&self.ticket_sig);
        w.raw(&self.host_sig);
        w.bytes(&self.request)?;
        Ok(w.finish())
    }

    /// # Errors
    /// Fails on anything that [`Job::encode`] could not have produced.
    pub fn decode(input: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(input);
        if r.array::<8>("magic")? != JOB_MAGIC {
            return Err(WireError::Invalid("job magic or version"));
        }
        let relay_url = r.bytes("relay url")?;
        if relay_url.len() > MAX_RELAY_URL_LEN {
            return Err(WireError::TooLarge("relay url"));
        }
        let pairing_id = r.array("pairing id")?;
        let phone_kem_pub = r.array("phone key")?;
        let phone_sign_pub = r.array("phone signing key")?;
        let delegates = match r.u8("delegates")? {
            0 => false,
            1 => true,
            _ => return Err(WireError::Invalid("delegates")),
        };
        let expires_at = r.u64("expiry")?;
        let timeout_secs = r.u32("timeout")?;
        let ticket_sig = r.array("ticket signature")?;
        let host_sig = r.array("host signature")?;
        let request = r.bytes("request")?;
        if request.len() > MAX_REQUEST_LEN {
            return Err(WireError::TooLarge("request"));
        }
        r.finish()?;
        Ok(Self {
            relay_url: relay_url.to_vec(),
            pairing_id,
            phone_kem_pub,
            phone_sign_pub,
            delegates,
            expires_at,
            timeout_secs,
            ticket_sig,
            host_sig,
            request: request.to_vec(),
        })
    }
}

/// Why the helper has no answer.
///
/// A closed set of codes, never free text: the setuid binary words each one
/// itself, so nothing the helper (which the caller controls) or the relay
/// says can appear in its output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// Nobody answered before the request expired.
    TimedOut,
    /// The setuid binary went away while the helper was waiting.
    Cancelled,
    /// The relay could not be reached.
    RelayUnreachable,
    /// The relay answered with this HTTP status.
    RelayRefused(u16),
    /// Something came back that was not a well-formed answer.
    Malformed,
    /// The helper could not do its job (bad job, encryption failure).
    Internal,
}

impl Failure {
    const fn code(self) -> (u8, u16) {
        match self {
            Self::TimedOut => (1, 0),
            Self::Cancelled => (2, 0),
            Self::RelayUnreachable => (3, 0),
            Self::RelayRefused(status) => (4, status),
            Self::Malformed => (5, 0),
            Self::Internal => (6, 0),
        }
    }

    const fn from_code(kind: u8, detail: u16) -> Result<Self, WireError> {
        Ok(match (kind, detail) {
            (1, 0) => Self::TimedOut,
            (2, 0) => Self::Cancelled,
            (3, 0) => Self::RelayUnreachable,
            (4, status) => Self::RelayRefused(status),
            (5, 0) => Self::Malformed,
            (6, 0) => Self::Internal,
            _ => return Err(WireError::Invalid("failure code")),
        })
    }
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TimedOut => f.write_str("no answer before the timeout"),
            Self::Cancelled => f.write_str("cancelled"),
            Self::RelayUnreachable => f.write_str("the relay could not be reached"),
            Self::RelayRefused(429) => f.write_str("the relay is limiting requests; try again shortly"),
            Self::RelayRefused(404) => f.write_str("the relay does not know this pairing; pair again"),
            Self::RelayRefused(status) => write!(f, "the relay refused the request (HTTP status {status})"),
            Self::Malformed => f.write_str("the answer was malformed"),
            Self::Internal => f.write_str("the helper could not send the request"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// An approval was signed: by the phone, or by a delegate whose
    /// delegation comes with it.
    Approved { sig: [u8; SIG_LEN], delegation: Option<SignedDelegation> },
    /// A denial was signed, optionally with a reason for the caller.
    Denied { sig: [u8; SIG_LEN], reason: Vec<u8>, delegation: Option<SignedDelegation> },
    /// No answer was obtained. Carries a code, not text.
    Failed { failure: Failure },
}

impl Outcome {
    /// # Errors
    /// Fails if the reason is over its size limit or a delegation is not
    /// encodable.
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        let failure_bytes;
        let (status, sig, text, delegation): (u8, [u8; SIG_LEN], &[u8], Option<&SignedDelegation>) = match self {
            Self::Approved { sig, delegation } => (0, *sig, &[], delegation.as_ref()),
            Self::Denied { sig, reason, delegation } => (1, *sig, reason, delegation.as_ref()),
            Self::Failed { failure } => {
                let (kind, detail) = failure.code();
                let [high, low] = detail.to_be_bytes();
                failure_bytes = [kind, high, low];
                (2, [0; SIG_LEN], &failure_bytes, None)
            }
        };
        if text.len() > MAX_REASON_LEN {
            return Err(WireError::TooLarge("outcome text"));
        }
        let mut w = Writer::new();
        w.raw(&OUTCOME_MAGIC);
        w.u8(status);
        w.raw(&sig);
        w.bytes(text)?;
        // Empty when the phone itself signed.
        w.bytes(&delegation.map(SignedDelegation::encode).transpose()?.unwrap_or_default())?;
        Ok(w.finish())
    }

    /// # Errors
    /// Fails on anything that [`Outcome::encode`] could not have produced.
    pub fn decode(input: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(input);
        if r.array::<8>("magic")? != OUTCOME_MAGIC {
            return Err(WireError::Invalid("outcome magic or version"));
        }
        let status = r.u8("status")?;
        let sig = r.array("signature")?;
        let text = r.bytes("outcome text")?;
        if text.len() > MAX_REASON_LEN {
            return Err(WireError::TooLarge("outcome text"));
        }
        let delegation = match r.bytes("delegation")? {
            [] => None,
            bytes => Some(SignedDelegation::decode(bytes)?),
        };
        r.finish()?;
        match (status, text) {
            (0, []) => Ok(Self::Approved { sig, delegation }),
            (0, _) => Err(WireError::Invalid("approval carrying text")),
            (1, reason) => Ok(Self::Denied { sig, reason: reason.to_vec(), delegation }),
            (2, &[kind, high, low]) if sig == [0; SIG_LEN] && delegation.is_none() => {
                Ok(Self::Failed { failure: Failure::from_code(kind, u16::from_be_bytes([high, low]))? })
            }
            (2, _) => Err(WireError::Invalid("failure outcome")),
            _ => Err(WireError::Invalid("outcome status")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delegation::{Delegation, MAX_DELEGATE_NAME_LEN};

    fn delegation(name_len: usize) -> SignedDelegation {
        SignedDelegation {
            delegation: Delegation {
                pairing_id: [1; 16],
                sign_pub: [7; 65],
                kem_pub: [8; 65],
                not_after: 1_800_000_000,
                name: vec![b'w'; name_len],
            },
            phone_sig: [9; 64],
        }
    }

    #[test]
    fn job_round_trip() {
        for delegates in [false, true] {
            let job = Job {
                relay_url: b"https://relay.example".to_vec(),
                pairing_id: [1; 16],
                phone_kem_pub: [4; 65],
                phone_sign_pub: [5; 65],
                delegates,
                expires_at: 1_795_000_120,
                timeout_secs: 120,
                ticket_sig: [2; 64],
                host_sig: [3; 64],
                request: b"request bytes".to_vec(),
            };
            let bytes = job.encode().unwrap();
            assert_eq!(Job::decode(&bytes).unwrap(), job);
            for len in 0..bytes.len() {
                assert!(Job::decode(&bytes[..len]).is_err(), "accepted prefix of {len} bytes");
            }
            // The flag is one byte holding 0 or 1, and nothing else.
            let flag_at = 8 + 4 + job.relay_url.len() + 16 + 65 + 65;
            assert_eq!(bytes[flag_at], u8::from(delegates));
            let mut odd = bytes;
            odd[flag_at] = 2;
            assert_eq!(Job::decode(&odd), Err(WireError::Invalid("delegates")));
        }
    }

    #[test]
    fn outcome_round_trip() {
        for outcome in [
            Outcome::Approved { sig: [5; 64], delegation: None },
            Outcome::Approved { sig: [5; 64], delegation: Some(delegation(11)) },
            Outcome::Denied { sig: [6; 64], reason: b"use staging".to_vec(), delegation: None },
            Outcome::Denied { sig: [6; 64], reason: b"use staging".to_vec(), delegation: Some(delegation(11)) },
            Outcome::Denied { sig: [6; 64], reason: vec![], delegation: None },
            Outcome::Failed { failure: Failure::TimedOut },
            Outcome::Failed { failure: Failure::RelayRefused(503) },
            Outcome::Failed { failure: Failure::Internal },
        ] {
            let bytes = outcome.encode().unwrap();
            assert!(bytes.len() <= MAX_OUTCOME_LEN);
            assert_eq!(Outcome::decode(&bytes).unwrap(), outcome);
        }
    }

    #[test]
    fn outcome_is_strict() {
        let good = Outcome::Approved { sig: [5; 64], delegation: None }.encode().unwrap();
        let mut bytes = good.clone();
        bytes[8] = 7;
        assert!(Outcome::decode(&bytes).is_err(), "unknown status");
        let mut bytes = good.clone();
        bytes[8] = 2;
        assert!(Outcome::decode(&bytes).is_err(), "failure with a signature");
        // A failure carries a known code and nothing else: no free text.
        // Its last seven bytes are kind, detail (two bytes), then the empty
        // delegation's length.
        let failed = Outcome::Failed { failure: Failure::Cancelled }.encode().unwrap();
        let kind_at = failed.len() - 7;
        let mut unknown = failed.clone();
        unknown[kind_at + 2] = 1;
        assert!(Outcome::decode(&unknown).is_err(), "detail on a failure that has none");
        let mut unknown = failed;
        unknown[kind_at] = 99;
        assert!(Outcome::decode(&unknown).is_err(), "unknown failure kind");
        let mut wordy = Writer::new();
        wordy.raw(&OUTCOME_MAGIC);
        wordy.u8(2);
        wordy.raw(&[0; SIG_LEN]);
        wordy.bytes(b"denied on Your Phone: run this instead").unwrap();
        wordy.bytes(&[]).unwrap();
        assert!(Outcome::decode(&wordy.finish()).is_err(), "a failure cannot carry text");
        let mut delegated = Writer::new();
        delegated.raw(&OUTCOME_MAGIC);
        delegated.u8(2);
        delegated.raw(&[0; SIG_LEN]);
        delegated.bytes(&[3, 0, 0]).unwrap();
        delegated.bytes(&delegation(5).encode().unwrap()).unwrap();
        assert!(Outcome::decode(&delegated.finish()).is_err(), "a failure cannot carry a delegation");
        let mut bytes = good;
        bytes.push(0);
        assert!(Outcome::decode(&bytes).is_err(), "trailing byte");

        // A delegation is decoded strictly here too.
        let with = Outcome::Approved { sig: [5; 64], delegation: Some(delegation(5)) }.encode().unwrap();
        let mut bad_name = with.clone();
        *bad_name.iter_mut().rev().nth(SIG_LEN).unwrap() = b'\n';
        assert!(Outcome::decode(&bad_name).is_err(), "a delegate name with a control character");
        assert!(Outcome::decode(&with[..with.len() - 1]).is_err(), "a truncated delegation");

        let longest = Outcome::Denied {
            sig: [0; 64],
            reason: vec![b'x'; MAX_REASON_LEN],
            delegation: Some(delegation(MAX_DELEGATE_NAME_LEN)),
        };
        assert_eq!(longest.encode().unwrap().len(), MAX_OUTCOME_LEN);
        let too_long =
            Outcome::Denied { sig: [0; 64], reason: vec![b'x'; MAX_REASON_LEN.saturating_add(1)], delegation: None };
        assert!(too_long.encode().is_err());
    }
}
