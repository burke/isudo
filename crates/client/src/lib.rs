//! What the unprivileged tools share: sealing requests to the phone, and
//! talking to the relay.
//!
//! Nothing in this crate is trusted by the setuid binary. Getting it wrong
//! can stop approvals from arriving; it cannot cause one.

#![forbid(unsafe_code)]

pub mod envelope;
pub mod relay;

use isudo_proto::api::{Answer, Decision};
use isudo_proto::codec::{b64_decode, b64_decode_array};
use isudo_proto::delegation::{Delegation, SignedDelegation};
use isudo_proto::frame::{Failure, Outcome};
use isudo_proto::{MAX_REASON_LEN, PAIRING_ID_LEN, PUBKEY_LEN};
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature, VerifyingKey};

/// Most delegates a pairing may have. A watch; perhaps a second one.
pub const MAX_DELEGATES: usize = 2;

/// Fills an array from the operating system's random number generator.
///
/// # Errors
/// Fails if the system cannot provide randomness.
pub fn random<const N: usize>() -> Result<[u8; N], getrandom::Error> {
    let mut bytes = [0_u8; N];
    getrandom::fill(&mut bytes)?;
    Ok(bytes)
}

/// Checks a delegation the relay handed over, before a request is sealed to
/// the key it names. The relay is not trusted to say who a pairing's
/// delegates are: only the paired phone's signature is.
///
/// Returns the delegation if the phone signed it for this pairing and it has
/// not run out at `now` (unix seconds).
#[must_use]
pub fn verified_delegation(
    encoded: &str,
    pairing_id: &[u8; PAIRING_ID_LEN],
    phone_sign_pub: &[u8; PUBKEY_LEN],
    now: u64,
) -> Option<Delegation> {
    let signed = SignedDelegation::decode(&b64_decode(encoded).ok()?).ok()?;
    let phone = VerifyingKey::from_sec1_bytes(phone_sign_pub).ok()?;
    let signature = Signature::from_slice(&signed.phone_sig).ok()?;
    let delegation = signed.delegation;
    let current = delegation.pairing_id == *pairing_id && now <= delegation.not_after;
    (current && phone.verify(&delegation.message().ok()?, &signature).is_ok()).then_some(delegation)
}

/// Reshapes the relay's JSON answer for the setuid binary, which will check
/// the signatures. Malformed answers are reported as "no answer".
///
/// # Errors
/// Fails with [`Failure::Malformed`] if the answer is not well formed.
pub fn outcome_of(answer: Answer) -> Result<Outcome, Failure> {
    const MALFORMED: Failure = Failure::Malformed;
    let sig = b64_decode_array(&answer.sig).map_err(|_e| MALFORMED)?;
    let delegation = match answer.delegation {
        None => None,
        Some(encoded) => {
            let bytes = b64_decode(&encoded).map_err(|_e| MALFORMED)?;
            Some(SignedDelegation::decode(&bytes).map_err(|_e| MALFORMED)?)
        }
    };
    match answer.decision {
        Decision::Approve if answer.reason.is_none() => Ok(Outcome::Approved { sig, delegation }),
        Decision::Approve => Err(MALFORMED),
        Decision::Deny => {
            let reason = answer.reason.unwrap_or_default().into_bytes();
            if reason.len() > MAX_REASON_LEN {
                return Err(MALFORMED);
            }
            Ok(Outcome::Denied { sig, reason, delegation })
        }
    }
}

#[cfg(test)]
mod tests {
    use isudo_proto::codec::b64_encode;
    use p256::ecdsa::signature::Signer as _;
    use p256::ecdsa::SigningKey;

    use super::*;

    const NOW: u64 = 1_795_000_000;

    fn answer(decision: Decision, reason: Option<&str>) -> Answer {
        Answer { decision, sig: b64_encode(&[7; 64]), reason: reason.map(str::to_owned), delegation: None, terms: None }
    }

    fn public(key: &SigningKey) -> [u8; PUBKEY_LEN] {
        key.verifying_key().to_sec1_point(false).as_bytes().try_into().unwrap()
    }

    /// A delegation signed by `signer`, and the phone key it should verify under.
    fn signed_by(signer: &SigningKey, change: impl FnOnce(&mut Delegation)) -> SignedDelegation {
        let mut delegation = Delegation {
            pairing_id: [1; PAIRING_ID_LEN],
            sign_pub: public(&SigningKey::from_slice(&[20; 32]).unwrap()),
            kem_pub: public(&SigningKey::from_slice(&[21; 32]).unwrap()),
            not_after: NOW + 10,
            name: b"Test Watch".to_vec(),
        };
        change(&mut delegation);
        let signature: Signature = signer.sign(&delegation.message().unwrap());
        SignedDelegation { delegation, phone_sig: signature.to_bytes().into() }
    }

    #[test]
    fn approvals_and_denials_are_reshaped() {
        assert_eq!(
            outcome_of(answer(Decision::Approve, None)),
            Ok(Outcome::Approved { sig: [7; 64], delegation: None })
        );
        assert_eq!(
            outcome_of(answer(Decision::Deny, Some("no"))),
            Ok(Outcome::Denied { sig: [7; 64], reason: b"no".to_vec(), delegation: None })
        );
        assert_eq!(
            outcome_of(answer(Decision::Deny, None)),
            Ok(Outcome::Denied { sig: [7; 64], reason: Vec::new(), delegation: None })
        );
    }

    #[test]
    fn a_delegates_answer_keeps_its_delegation() {
        let phone = SigningKey::from_slice(&[7; 32]).unwrap();
        let signed = signed_by(&phone, |_| {});
        let mut delegated = answer(Decision::Approve, None);
        delegated.delegation = Some(b64_encode(&signed.encode().unwrap()));
        assert_eq!(outcome_of(delegated), Ok(Outcome::Approved { sig: [7; 64], delegation: Some(signed) }));
        // One that does not decode is not passed on as if the phone had signed.
        for bad in ["", "not base64!", "AAAA"] {
            let mut delegated = answer(Decision::Approve, None);
            delegated.delegation = Some(bad.to_owned());
            assert_eq!(outcome_of(delegated), Err(Failure::Malformed), "{bad:?}");
        }
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

    #[test]
    fn a_request_is_sealed_only_to_delegates_the_phone_signed_for() {
        let phone = SigningKey::from_slice(&[7; 32]).unwrap();
        let phone_pub = public(&phone);
        let check = |signed: &SignedDelegation, now| {
            verified_delegation(&b64_encode(&signed.encode().unwrap()), &[1; PAIRING_ID_LEN], &phone_pub, now)
        };
        let genuine = signed_by(&phone, |_| {});
        assert_eq!(check(&genuine, NOW), Some(genuine.delegation.clone()));
        assert_eq!(check(&genuine, NOW + 10), Some(genuine.delegation.clone()), "its last second");
        assert_eq!(check(&genuine, NOW + 11), None, "run out");
        // A key the relay made up, vouched for by the relay.
        let relay = SigningKey::from_slice(&[9; 32]).unwrap();
        assert_eq!(check(&signed_by(&relay, |_| {}), NOW), None);
        // The phone's genuine signature, for another pairing.
        assert_eq!(check(&signed_by(&phone, |d| d.pairing_id = [2; PAIRING_ID_LEN]), NOW), None);
        // The phone's genuine signature, with the decryption key swapped afterwards.
        let mut swapped = signed_by(&phone, |_| {});
        swapped.delegation.kem_pub = public(&relay);
        assert_eq!(check(&swapped, NOW), None);
        assert_eq!(verified_delegation("not base64!", &[1; PAIRING_ID_LEN], &phone_pub, NOW), None);
    }
}
