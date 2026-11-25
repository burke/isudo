use isudo_proto::api::Ack;
use isudo_proto::request::{EnvOrigin, EnvVar, StdinKind};

use super::*;

const SEED: [u8; 32] = [0x5e; 32];
const NOW: u64 = 1_795_000_010;

fn host_key() -> SigningKey {
    SigningKey::from_slice(&[1; 32]).unwrap()
}

fn public_of(key: &SigningKey) -> [u8; PUBKEY_LEN] {
    key.verifying_key().to_sec1_point(false).as_bytes().try_into().unwrap()
}

fn sign_raw(key: &SigningKey, message: &[u8]) -> [u8; SIG_LEN] {
    let signature: Signature = key.sign(message);
    signature.to_bytes().into()
}

fn offer() -> Offer {
    Offer {
        relay_url: "https://relay.example".into(),
        pairing_id: [0xa1; PAIRING_ID_LEN],
        host_pub: public_of(&host_key()),
        secret: [0x3c; 32],
        host_name: "burke-mbp".into(),
    }
}

const ACK_NONCE: [u8; 16] = [0x4e; 16];

fn ack_by(key: &SigningKey, pairing: &Pairing) -> Ack {
    let message = sigs::pair_ack_msg(&offer().pairing_id, pairing.sign_pub(), &pairing.kem_pub, &ACK_NONCE);
    Ack { nonce: b64_encode(&ACK_NONCE), host_sig: b64_encode(&sign_raw(key, &message)) }
}

fn acknowledged_by(key: &SigningKey, pairing: &Pairing) -> PairingStatus {
    PairingStatus { state: PairingState::Acknowledged, ack: Some(ack_by(key, pairing)), host_sig: None }
}

fn confirmed_by(key: &SigningKey, pairing: &Pairing) -> PairingStatus {
    let message = sigs::pair_confirm_msg(&offer().pairing_id, pairing.sign_pub(), &pairing.kem_pub);
    PairingStatus {
        state: PairingState::Active,
        ack: Some(ack_by(&host_key(), pairing)),
        host_sig: Some(b64_encode(&sign_raw(key, &message))),
    }
}

fn active() -> Pairing {
    let mut pairing = Pairing::begin(&offer(), &SEED).unwrap();
    assert_eq!(pairing.observe(&confirmed_by(&host_key(), &pairing)), Ok(Progress::Active));
    pairing
}

fn request(nonce: u8) -> Request {
    Request {
        nonce: [nonce; 32],
        pairing_id: offer().pairing_id,
        issued_at: 1_795_000_000,
        ttl_secs: 120,
        uid: 501,
        gid: 20,
        user: b"burke".to_vec(),
        host: b"burke-mbp".to_vec(),
        cwd: b"/tmp".to_vec(),
        exe: b"/bin/rm".to_vec(),
        flags: 0,
        stdin: StdinKind::Terminal,
        argv: vec![b"rm".to_vec(), b"-rf".to_vec(), b"/var/tmp/build".to_vec()],
        env: vec![EnvVar { origin: EnvOrigin::Default, name: b"TERM".to_vec(), value: b"xterm".to_vec() }],
        ancestry: Vec::new(),
    }
}

/// What the helper would deliver for `request`, signed by `signer`.
fn deliver(pairing: &Pairing, request: &Request, signer: &SigningKey) -> PendingRequest {
    let bytes = request.encode().unwrap();
    let host_sig = sign_raw(signer, &sigs::host_request_msg(&bytes));
    let sealed = envelope::seal(&pairing.kem_pub, &offer().pairing_id, &host_sig, &bytes).unwrap();
    PendingRequest {
        request_id: hex_encode(&sigs::request_id(&bytes)),
        expires_at: request.issued_at.saturating_add(u64::from(request.ttl_secs)),
        envelope: b64_encode(&sealed),
    }
}

fn verifies(pairing: &Pairing, message: &[u8], answer: &Answer) -> bool {
    let key = VerifyingKey::from_sec1_bytes(pairing.sign_pub()).unwrap();
    let sig = Signature::from_slice(&b64_decode(&answer.sig).unwrap()).unwrap();
    key.verify(message, &sig).is_ok()
}

#[test]
fn the_claim_proves_knowledge_of_the_secret() {
    let pairing = Pairing::begin(&offer(), &SEED).unwrap();
    let claim = pairing.claim("Burke's iPhone", None);
    let mac = b64_decode(&claim.claim_mac).unwrap();
    assert!(pairing::verify_claim_mac(&offer().secret, &pairing.parties(), b"Burke's iPhone", &mac));
    assert!(!pairing::verify_claim_mac(&[0; 32], &pairing.parties(), b"Burke's iPhone", &mac));
}

#[test]
fn each_pairing_has_its_own_keys() {
    let first = Pairing::begin(&offer(), &SEED).unwrap();
    let second = Pairing::begin(&offer(), &[0x5f; 32]).unwrap();
    assert_ne!(first.sign_pub(), second.sign_pub());
    assert_ne!(first.kem_pub, second.kem_pub);
    assert_ne!(first.token(), second.token());
    // And the same seed gives the same pairing, which is how it is stored.
    let again = Pairing::resume(&offer(), &SEED, true).unwrap();
    assert_eq!(again.sign_pub(), first.sign_pub());
    assert!(again.is_active());
}

#[test]
fn the_code_appears_only_after_the_host_acknowledges_these_keys() {
    let mut pairing = Pairing::begin(&offer(), &SEED).unwrap();
    assert_eq!(pairing.code(), None, "no code straight after scanning");

    // Nothing from the host yet.
    let claimed = PairingStatus { state: PairingState::Claimed, ack: None, host_sig: None };
    assert_eq!(pairing.observe(&claimed), Ok(Progress::Waiting));
    assert_eq!(pairing.code(), None);

    // The relay says the host acknowledged, with nothing to show for it.
    let bare = PairingStatus { state: PairingState::Acknowledged, ack: None, host_sig: None };
    assert_eq!(pairing.observe(&bare), Err(PairingError::AnotherPhoneWasAccepted));
    // ...or with an acknowledgement signed by some other key.
    let other = SigningKey::from_slice(&[9; 32]).unwrap();
    assert_eq!(pairing.observe(&acknowledged_by(&other, &pairing)), Err(PairingError::AnotherPhoneWasAccepted));
    // ...or with the host's genuine acknowledgement of a different phone,
    // which is what this phone sees if its keys were swapped on the way.
    let stranger = Pairing::begin(&offer(), &[0x66; 32]).unwrap();
    assert_eq!(pairing.observe(&acknowledged_by(&host_key(), &stranger)), Err(PairingError::AnotherPhoneWasAccepted));
    // ...or a confirmation presented as an acknowledgement.
    let confirm = sigs::pair_confirm_msg(&offer().pairing_id, pairing.sign_pub(), &pairing.kem_pub);
    let crossed = PairingStatus {
        state: PairingState::Acknowledged,
        ack: Some(Ack { nonce: b64_encode(&ACK_NONCE), host_sig: b64_encode(&sign_raw(&host_key(), &confirm)) }),
        host_sig: None,
    };
    assert_eq!(pairing.observe(&crossed), Err(PairingError::AnotherPhoneWasAccepted));
    // ...or the genuine acknowledgement with its nonce changed, which would
    // otherwise let the relay choose the code.
    let renonced = PairingStatus {
        state: PairingState::Acknowledged,
        ack: Some(Ack { nonce: b64_encode(&[0x4f; 16]), ..ack_by(&host_key(), &pairing) }),
        host_sig: None,
    };
    assert_eq!(pairing.observe(&renonced), Err(PairingError::AnotherPhoneWasAccepted));
    assert_eq!(pairing.code(), None, "none of that released a code");

    // The real thing.
    let expected = pairing::confirmation_code(&offer().secret, &pairing.parties(), &ACK_NONCE);
    assert_eq!(pairing.observe(&acknowledged_by(&host_key(), &pairing)), Ok(Progress::ShowCode(expected.clone())));
    assert_eq!(pairing.code(), Some(expected));
    assert!(!pairing.is_active(), "acknowledged is not yet paired");
}

#[test]
fn only_the_hosts_confirmation_activates_a_pairing() {
    let mut pairing = Pairing::begin(&offer(), &SEED).unwrap();
    let ack = Some(ack_by(&host_key(), &pairing));

    // The relay claims the pairing is active, with no confirmation.
    let bare = PairingStatus { state: PairingState::Active, ack: ack.clone(), host_sig: None };
    assert_eq!(pairing.observe(&bare), Err(PairingError::NotConfirmedByHost));
    // ...or with a confirmation by some other key.
    let other = SigningKey::from_slice(&[9; 32]).unwrap();
    assert_eq!(pairing.observe(&confirmed_by(&other, &pairing)), Err(PairingError::NotConfirmedByHost));
    // ...or with the acknowledgement replayed as the confirmation.
    let ack_sig = ack.as_ref().map(|a| a.host_sig.clone());
    let replayed = PairingStatus { state: PairingState::Active, ack, host_sig: ack_sig };
    assert_eq!(pairing.observe(&replayed), Err(PairingError::NotConfirmedByHost));
    assert!(!pairing.is_active());

    assert_eq!(pairing.observe(&confirmed_by(&host_key(), &pairing)), Ok(Progress::Active));
    assert!(pairing.is_active());
}

#[test]
fn a_genuine_request_becomes_a_card() {
    let mut pairing = active();
    let delivered = deliver(&pairing, &request(1), &host_key());
    let card = pairing.open(&delivered, NOW).unwrap();
    assert_eq!(card.request(), &request(1));
    assert_eq!(card.request_id_hex(), delivered.request_id);
    assert_eq!(card.expires_at(), 1_795_000_120);
    assert_eq!(card.digest(), &sigs::request_digest(&request(1).encode().unwrap()));
}

#[test]
fn requests_are_refused_before_the_pairing_is_active() {
    let mut pairing = Pairing::begin(&offer(), &SEED).unwrap();
    let delivered = deliver(&pairing, &request(1), &host_key());
    assert_eq!(pairing.open(&delivered, NOW), Err(Refusal::NotActive));
}

#[test]
fn a_request_not_signed_by_the_host_is_never_shown() {
    let mut pairing = active();
    // Anyone can encrypt to the phone's public key; only the host can sign.
    let attacker = SigningKey::from_slice(&[9; 32]).unwrap();
    let delivered = deliver(&pairing, &request(1), &attacker);
    assert_eq!(pairing.open(&delivered, NOW), Err(Refusal::NotFromHost));
}

#[test]
fn tampered_and_misdirected_envelopes_are_refused() {
    let mut pairing = active();
    let good = deliver(&pairing, &request(1), &host_key());

    let mut sealed = b64_decode(&good.envelope).unwrap();
    sealed[100] ^= 1;
    let tampered = PendingRequest { envelope: b64_encode(&sealed), ..good.clone() };
    assert_eq!(pairing.open(&tampered, NOW), Err(Refusal::Undecryptable));

    let garbage = PendingRequest { envelope: "not base64!".into(), ..good.clone() };
    assert_eq!(pairing.open(&garbage, NOW), Err(Refusal::Undecryptable));

    // Sealed for a different pairing of the same phone key.
    let bytes = request(1).encode().unwrap();
    let host_sig = sign_raw(&host_key(), &sigs::host_request_msg(&bytes));
    let elsewhere = envelope::seal(&pairing.kem_pub, &[0xb2; PAIRING_ID_LEN], &host_sig, &bytes).unwrap();
    let misdirected = PendingRequest { envelope: b64_encode(&elsewhere), ..good };
    assert_eq!(pairing.open(&misdirected, NOW), Err(Refusal::Undecryptable));
}

#[test]
fn a_request_must_name_this_pairing_and_match_its_id() {
    let mut pairing = active();
    // Signed by the host, but describing another pairing.
    let mut other = request(1);
    other.pairing_id = [0xb2; PAIRING_ID_LEN];
    let delivered = deliver(&pairing, &other, &host_key());
    assert_eq!(pairing.open(&delivered, NOW), Err(Refusal::Malformed));

    // Delivered by the relay under a different request's id.
    let mut relabelled = deliver(&pairing, &request(1), &host_key());
    relabelled.request_id = hex_encode(&[7; REQUEST_ID_LEN]);
    assert_eq!(pairing.open(&relabelled, NOW), Err(Refusal::Malformed));
}

#[test]
fn expired_requests_are_refused() {
    let mut pairing = active();
    let delivered = deliver(&pairing, &request(1), &host_key());
    let expiry = 1_795_000_120;
    assert_eq!(pairing.open(&delivered, expiry + CLOCK_SKEW_SECS + 1), Err(Refusal::Expired));
    // Within the allowance for clock disagreement it is still shown.
    assert!(pairing.open(&delivered, expiry + CLOCK_SKEW_SECS).is_ok());
}

#[test]
fn a_request_is_shown_only_once() {
    let mut pairing = active();
    let delivered = deliver(&pairing, &request(1), &host_key());
    assert!(pairing.open(&delivered, NOW).is_ok());
    assert_eq!(pairing.open(&delivered, NOW), Err(Refusal::AlreadySeen));
    // A different request from the same host is fine.
    assert!(pairing.open(&deliver(&pairing, &request(2), &host_key()), NOW).is_ok());
}

#[test]
fn an_approval_signs_exactly_this_request() {
    let mut pairing = active();
    let card = pairing.open(&deliver(&pairing, &request(1), &host_key()), NOW).unwrap();
    let answer = pairing.approve(&card);
    assert_eq!(answer.decision, Decision::Approve);
    assert_eq!(answer.reason, None);
    assert!(verifies(&pairing, &sigs::approve_msg(card.digest()), &answer));
    // It is not an approval of the same command asked again.
    let other = sigs::request_digest(&request(2).encode().unwrap());
    assert!(!verifies(&pairing, &sigs::approve_msg(&other), &answer));
    // And not a denial.
    assert!(!verifies(&pairing, &sigs::deny_msg(card.digest(), b""), &answer));
}

#[test]
fn a_denial_signs_its_reason() {
    let mut pairing = active();
    let card = pairing.open(&deliver(&pairing, &request(1), &host_key()), NOW).unwrap();
    let answer = pairing.deny(&card, "use the staging database");
    assert_eq!(answer.decision, Decision::Deny);
    assert_eq!(answer.reason.as_deref(), Some("use the staging database"));
    assert!(verifies(&pairing, &sigs::deny_msg(card.digest(), b"use the staging database"), &answer));
    assert!(!verifies(&pairing, &sigs::deny_msg(card.digest(), b"something else"), &answer));
    assert!(!verifies(&pairing, &sigs::approve_msg(card.digest()), &answer));

    let silent = pairing.deny(&card, "");
    assert_eq!(silent.reason, None);
    assert!(verifies(&pairing, &sigs::deny_msg(card.digest(), b""), &silent));
}

#[test]
fn long_reasons_are_cut_at_a_character_boundary() {
    let mut pairing = active();
    let card = pairing.open(&deliver(&pairing, &request(1), &host_key()), NOW).unwrap();
    // 'é' is two bytes, so the limit falls in the middle of one.
    let long = "é".repeat(MAX_REASON_LEN);
    let answer = pairing.deny(&card, &long);
    let reason = answer.reason.clone().unwrap();
    assert!(reason.len() <= MAX_REASON_LEN);
    assert_eq!(reason.len(), MAX_REASON_LEN - (MAX_REASON_LEN % 2));
    assert!(verifies(&pairing, &sigs::deny_msg(card.digest(), reason.as_bytes()), &answer));
}
