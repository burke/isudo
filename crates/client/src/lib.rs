//! What the unprivileged tools share: sealing requests to the phone, and
//! talking to the relay.
//!
//! Nothing in this crate is trusted by the setuid binary. Getting it wrong
//! can stop approvals from arriving; it cannot cause one.

#![forbid(unsafe_code)]

pub mod envelope;
pub mod relay;

use isudo_proto::api::{Answer, Decision};
use isudo_proto::codec::b64_decode_array;
use isudo_proto::frame::{Failure, Outcome};
use isudo_proto::MAX_REASON_LEN;

/// Fills an array from the operating system's random number generator.
///
/// # Errors
/// Fails if the system cannot provide randomness.
pub fn random<const N: usize>() -> Result<[u8; N], getrandom::Error> {
    let mut bytes = [0_u8; N];
    getrandom::fill(&mut bytes)?;
    Ok(bytes)
}

/// Reshapes the relay's JSON answer for the setuid binary, which will check
/// the signature. Malformed answers are reported as "no answer".
///
/// # Errors
/// Fails with [`Failure::Malformed`] if the answer is not well formed.
pub fn outcome_of(answer: Answer) -> Result<Outcome, Failure> {
    const MALFORMED: Failure = Failure::Malformed;
    let sig = b64_decode_array(&answer.sig).map_err(|_e| MALFORMED)?;
    match answer.decision {
        Decision::Approve if answer.reason.is_none() => Ok(Outcome::Approved { sig }),
        Decision::Approve => Err(MALFORMED),
        Decision::Deny => {
            let reason = answer.reason.unwrap_or_default().into_bytes();
            if reason.len() > MAX_REASON_LEN {
                return Err(MALFORMED);
            }
            Ok(Outcome::Denied { sig, reason })
        }
    }
}

#[cfg(test)]
mod tests {
    use isudo_proto::codec::b64_encode;

    use super::*;

    fn answer(decision: Decision, reason: Option<&str>) -> Answer {
        Answer { decision, sig: b64_encode(&[7; 64]), reason: reason.map(str::to_owned) }
    }

    #[test]
    fn approvals_and_denials_are_reshaped() {
        assert_eq!(outcome_of(answer(Decision::Approve, None)), Ok(Outcome::Approved { sig: [7; 64] }));
        assert_eq!(
            outcome_of(answer(Decision::Deny, Some("no"))),
            Ok(Outcome::Denied { sig: [7; 64], reason: b"no".to_vec() })
        );
        assert_eq!(
            outcome_of(answer(Decision::Deny, None)),
            Ok(Outcome::Denied { sig: [7; 64], reason: Vec::new() })
        );
    }

    #[test]
    fn malformed_answers_are_not_passed_on() {
        assert!(outcome_of(answer(Decision::Approve, Some("with text"))).is_err());
        assert!(outcome_of(answer(Decision::Deny, Some(&"x".repeat(MAX_REASON_LEN + 1)))).is_err());
        let mut bad = answer(Decision::Approve, None);
        bad.sig = "not base64!".to_owned();
        assert!(outcome_of(bad).is_err());
        bad = answer(Decision::Approve, None);
        bad.sig = b64_encode(&[7; 63]);
        assert!(outcome_of(bad).is_err());
    }
}
