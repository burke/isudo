use isudo_proto::codec::b64_encode;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::SigningKey;

use super::*;

const PID: PairingId = [0xa1; PAIRING_ID_LEN];
const TOKEN: [u8; 32] = [0x70; 32];
const APNS: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

struct Party {
    key: SigningKey,
}

impl Party {
    fn new(seed: u8) -> Self {
        Self { key: SigningKey::from_slice(&[seed; 32]).unwrap() }
    }

    fn public(&self) -> [u8; PUBKEY_LEN] {
        self.key.verifying_key().to_sec1_point(false).as_bytes().try_into().unwrap()
    }

    fn public_b64(&self) -> String {
        b64_encode(&self.public())
    }

    fn sign(&self, message: &[u8]) -> String {
        let signature: Signature = self.key.sign(message);
        b64_encode(&signature.to_bytes())
    }
}

fn host() -> Party {
    Party::new(1)
}

fn phone() -> Party {
    Party::new(2)
}

fn pid() -> String {
    hex_encode(&PID)
}

fn token() -> String {
    b64_encode(&TOKEN)
}

fn create_body() -> CreatePairing {
    CreatePairing { pairing_id: pid(), host_pub: host().public_b64(), host_name: "burke-mbp".into() }
}

fn claim_body(with_device: bool) -> Claim {
    Claim {
        phone_sign_pub: phone().public_b64(),
        phone_kem_pub: Party::new(3).public_b64(),
        phone_name: "Burke's iPhone".into(),
        phone_nonce: b64_encode(&PHONE_NONCE),
        claim_mac: b64_encode(&[5; 32]),
        phone_token: token(),
        device: with_device.then(|| DeviceUpdate { apns_token: APNS.into(), apns_env: "sandbox".into() }),
    }
}

const PHONE_NONCE: [u8; 16] = [0x70; 16];

fn ack_body(signer: &Party) -> Ack {
    let message = sigs::pair_ack_msg(&PID, &phone().public(), &Party::new(3).public(), &PHONE_NONCE, &[0x4e; 16]);
    Ack { nonce: b64_encode(&[0x4e; 16]), host_sig: signer.sign(&message) }
}

fn confirm_body(signer: &Party) -> Confirm {
    let message = sigs::pair_confirm_msg(&PID, &phone().public(), &Party::new(3).public());
    Confirm { host_sig: signer.sign(&message) }
}

/// A relay with one active pairing.
fn paired(with_device: bool) -> Relay {
    let mut relay = Relay::default();
    relay.create_pairing(100, &create_body(), None).unwrap();
    relay.claim(101, &pid(), &claim_body(with_device)).unwrap();
    relay.acknowledge(&pid(), &ack_body(&host())).unwrap();
    relay.confirm(&pid(), &confirm_body(&host())).unwrap();
    relay
}

fn submit_body(request: u8, expires_at: u64) -> SubmitRequest {
    let rid = [request; REQUEST_ID_LEN];
    SubmitRequest {
        pairing_id: pid(),
        request_id: hex_encode(&rid),
        expires_at,
        ticket_sig: host().sign(&sigs::ticket_msg(&PID, &rid, expires_at)),
        envelope: b64_encode(b"opaque ciphertext"),
    }
}

fn rid(request: u8) -> String {
    hex_encode(&[request; REQUEST_ID_LEN])
}

fn approve() -> Answer {
    Answer { decision: Decision::Approve, sig: b64_encode(&[9; SIG_LEN]), reason: None }
}

#[test]
fn a_request_flows_from_host_to_phone_and_back() {
    let mut relay = paired(true);
    let push = relay.submit(200, &submit_body(1, 320)).unwrap().unwrap();
    assert_eq!(push.device.apns_token, APNS);
    assert_eq!(push.request_id, rid(1));
    assert_eq!(push.host_name, "burke-mbp");

    assert_eq!(relay.poll_answer(201, &rid(1)), Ok(None));
    let pending = relay.pending(201, &pid(), &token()).unwrap();
    assert_eq!(pending.requests.len(), 1);
    assert_eq!(pending.requests[0].envelope, b64_encode(b"opaque ciphertext"));

    relay.answer(202, &rid(1), &token(), approve()).unwrap();
    let answer = relay.poll_answer(203, &rid(1)).unwrap().unwrap();
    assert_eq!(answer.decision, Decision::Approve);
    // Answered requests no longer show as waiting.
    assert_eq!(relay.pending(203, &pid(), &token()).unwrap().requests.len(), 0);
}

#[test]
fn no_push_without_a_registered_device() {
    let mut relay = paired(false);
    assert_eq!(relay.submit(200, &submit_body(1, 320)), Ok(None));
    let device = DeviceUpdate { apns_token: APNS.into(), apns_env: "production".into() };
    relay.update_device(&pid(), &token(), &device).unwrap();
    assert!(relay.submit(201, &submit_body(2, 320)).unwrap().is_some());
}

#[test]
fn pairing_states_advance_in_order() {
    let mut relay = Relay::default();
    assert_eq!(relay.claim(100, &pid(), &claim_body(false)), Err(Reject::NotFound));
    relay.create_pairing(100, &create_body(), None).unwrap();
    assert_eq!(relay.create_pairing(100, &create_body(), None), Err(Reject::Conflict));
    assert_eq!(relay.claim_view(&pid()).unwrap().map(|c| c.phone_name), None);
    assert_eq!(relay.confirm(&pid(), &confirm_body(&host())), Err(Reject::Conflict));

    assert_eq!(relay.acknowledge(&pid(), &ack_body(&host())), Err(Reject::Conflict), "nothing to acknowledge yet");
    relay.claim(101, &pid(), &claim_body(false)).unwrap();
    assert_eq!(relay.status(&pid(), &token()).unwrap().state, PairingState::Claimed);
    assert_eq!(relay.confirm(&pid(), &confirm_body(&host())), Err(Reject::Conflict), "not acknowledged yet");
    assert_eq!(relay.acknowledge(&pid(), &ack_body(&phone())), Err(Reject::Unauthorized));
    relay.acknowledge(&pid(), &ack_body(&host())).unwrap();
    assert_eq!(relay.acknowledge(&pid(), &ack_body(&host())), Err(Reject::Conflict), "one acknowledgement only");
    let status = relay.status(&pid(), &token()).unwrap();
    assert_eq!(status.state, PairingState::Acknowledged);
    assert!(status.ack.is_some() && status.host_sig.is_none());
    // A real signature presented with a different nonce does not verify.
    let mut relay2 = Relay::default();
    relay2.create_pairing(100, &create_body(), None).unwrap();
    relay2.claim(101, &pid(), &claim_body(false)).unwrap();
    let renonced = Ack { nonce: b64_encode(&[0x4f; 16]), ..ack_body(&host()) };
    assert_eq!(relay2.acknowledge(&pid(), &renonced), Err(Reject::Unauthorized));
    let short = Ack { nonce: b64_encode(&[0x4e; 8]), ..ack_body(&host()) };
    assert_eq!(relay2.acknowledge(&pid(), &short), Err(Reject::Invalid));
    // The signature covers the nonce the phone sent with its answer, so an
    // acknowledgement made for one answer does not fit another.
    let mut relay3 = Relay::default();
    relay3.create_pairing(100, &create_body(), None).unwrap();
    let other_nonce = Claim { phone_nonce: b64_encode(&[0x71; 16]), ..claim_body(false) };
    relay3.claim(101, &pid(), &other_nonce).unwrap();
    assert_eq!(relay3.acknowledge(&pid(), &ack_body(&host())), Err(Reject::Unauthorized));
    // An answer must carry a nonce of the right size.
    let mut relay4 = Relay::default();
    relay4.create_pairing(100, &create_body(), None).unwrap();
    let no_nonce = Claim { phone_nonce: String::new(), ..claim_body(false) };
    assert_eq!(relay4.claim(101, &pid(), &no_nonce), Err(Reject::Invalid));
    assert_eq!(relay.claim_view(&pid()).unwrap().unwrap().phone_name, "Burke's iPhone");
    // Requests are refused until the host confirms.
    assert_eq!(relay.submit(102, &submit_body(1, 200)), Err(Reject::NotFound));

    relay.confirm(&pid(), &confirm_body(&host())).unwrap();
    let status = relay.status(&pid(), &token()).unwrap();
    assert_eq!(status.state, PairingState::Active);
    assert!(status.host_sig.is_some());
    assert_eq!(relay.confirm(&pid(), &confirm_body(&host())), Err(Reject::Conflict));
}

#[test]
fn the_first_claim_wins() {
    let mut relay = Relay::default();
    relay.create_pairing(100, &create_body(), None).unwrap();
    relay.claim(101, &pid(), &claim_body(false)).unwrap();
    let mut second = claim_body(false);
    second.phone_sign_pub = Party::new(66).public_b64();
    assert_eq!(relay.claim(102, &pid(), &second), Err(Reject::Conflict));
    assert_eq!(relay.claim_view(&pid()).unwrap().unwrap().phone_sign_pub, phone().public_b64());
}

#[test]
fn only_the_host_key_can_confirm_or_revoke() {
    let mut relay = Relay::default();
    relay.create_pairing(100, &create_body(), None).unwrap();
    relay.claim(101, &pid(), &claim_body(false)).unwrap();
    relay.acknowledge(&pid(), &ack_body(&host())).unwrap();
    assert_eq!(relay.confirm(&pid(), &confirm_body(&phone())), Err(Reject::Unauthorized));
    // A confirmation of different phone keys does not confirm these ones.
    let other = sigs::pair_confirm_msg(&PID, &Party::new(66).public(), &Party::new(3).public());
    assert_eq!(relay.confirm(&pid(), &Confirm { host_sig: host().sign(&other) }), Err(Reject::Unauthorized));
    relay.confirm(&pid(), &confirm_body(&host())).unwrap();

    let forged = Revoke { host_sig: phone().sign(&sigs::pair_revoke_msg(&PID)) };
    assert_eq!(relay.revoke_as_host(&pid(), &forged), Err(Reject::Unauthorized));
    relay.revoke_as_host(&pid(), &Revoke { host_sig: host().sign(&sigs::pair_revoke_msg(&PID)) }).unwrap();
    assert_eq!(relay.status(&pid(), &token()), Err(Reject::NotFound));
}

#[test]
fn tickets_gate_submission() {
    let mut relay = paired(true);
    // Signed by someone else.
    let mut forged = submit_body(1, 320);
    forged.ticket_sig = phone().sign(&sigs::ticket_msg(&PID, &[1; REQUEST_ID_LEN], 320));
    assert_eq!(relay.submit(200, &forged), Err(Reject::Unauthorized));
    // A real ticket stretched to a later expiry.
    let mut stretched = submit_body(1, 320);
    stretched.expires_at = 600;
    assert_eq!(relay.submit(200, &stretched), Err(Reject::Unauthorized));
    // A real ticket moved to another request id.
    let mut moved = submit_body(1, 320);
    moved.request_id = rid(2);
    assert_eq!(relay.submit(200, &moved), Err(Reject::Unauthorized));

    assert!(relay.submit(200, &submit_body(1, 320)).is_ok());
    // One request per ticket.
    assert_eq!(relay.submit(201, &submit_body(1, 320)), Err(Reject::Conflict));
}

#[test]
fn submissions_must_be_current_and_well_formed() {
    let mut relay = paired(true);
    assert_eq!(relay.submit(200, &submit_body(1, 199)), Err(Reject::Invalid), "already expired");
    assert_eq!(relay.submit(200, &submit_body(1, 200 + 661)), Err(Reject::Invalid), "too far ahead");
    let mut padded = submit_body(1, 320);
    padded.envelope = "not base64!".into();
    assert_eq!(relay.submit(200, &padded), Err(Reject::Invalid));
    let mut huge = submit_body(1, 320);
    huge.envelope = "A".repeat(200_000);
    assert_eq!(relay.submit(200, &huge), Err(Reject::Invalid));
    let mut short_id = submit_body(1, 320);
    short_id.request_id = "abcd".into();
    assert_eq!(relay.submit(200, &short_id), Err(Reject::Invalid));
}

#[test]
fn a_pairing_cannot_flood_the_phone() {
    let limits = Limits { max_pending: 3, rate_count: 5, rate_window: 60, ..Limits::default() };
    let mut relay = Relay::new(limits, None);
    relay.create_pairing(100, &create_body(), None).unwrap();
    relay.claim(101, &pid(), &claim_body(true)).unwrap();
    relay.acknowledge(&pid(), &ack_body(&host())).unwrap();
    relay.confirm(&pid(), &confirm_body(&host())).unwrap();

    for n in 1..=3 {
        assert!(relay.submit(200, &submit_body(n, 250)).is_ok());
    }
    assert_eq!(relay.submit(200, &submit_body(4, 250)), Err(Reject::TooMany), "too many waiting");
    relay.answer(201, &rid(1), &token(), approve()).unwrap();
    relay.answer(201, &rid(2), &token(), approve()).unwrap();
    assert!(relay.submit(202, &submit_body(4, 250)).is_ok());
    assert!(relay.submit(202, &submit_body(5, 250)).is_ok());
    assert_eq!(relay.submit(203, &submit_body(6, 250)), Err(Reject::TooMany), "rate limit");
    // The window slides.
    relay.answer(203, &rid(3), &token(), approve()).unwrap();
    relay.answer(203, &rid(4), &token(), approve()).unwrap();
    assert!(relay.submit(262, &submit_body(6, 300)).is_ok());
}

#[test]
fn only_the_paired_phone_reads_and_answers() {
    let mut relay = paired(true);
    let _ = relay.submit(200, &submit_body(1, 320)).unwrap();
    let wrong = b64_encode(&[0x71; 32]);
    assert_eq!(relay.pending(201, &pid(), &wrong).map(|l| l.requests.len()), Err(Reject::Unauthorized));
    assert_eq!(relay.answer(201, &rid(1), &wrong, approve()), Err(Reject::Unauthorized));
    assert_eq!(relay.status(&pid(), &wrong).map(|s| s.state), Err(Reject::Unauthorized));
    assert_eq!(relay.revoke_as_phone(&pid(), &wrong), Err(Reject::Unauthorized));
    let device = DeviceUpdate { apns_token: APNS.into(), apns_env: "sandbox".into() };
    assert_eq!(relay.update_device(&pid(), &wrong, &device), Err(Reject::Unauthorized));
    assert_eq!(relay.poll_answer(202, &rid(1)), Ok(None));
}

#[test]
fn the_first_answer_stands_and_malformed_answers_are_refused() {
    let mut relay = paired(true);
    let _ = relay.submit(200, &submit_body(1, 320)).unwrap();
    let with_text = Answer { reason: Some("x".into()), ..approve() };
    assert_eq!(relay.answer(201, &rid(1), &token(), with_text), Err(Reject::Invalid));
    let bad_sig = Answer { sig: "AAAA".into(), ..approve() };
    assert_eq!(relay.answer(201, &rid(1), &token(), bad_sig), Err(Reject::Invalid));
    let long = Answer { decision: Decision::Deny, reason: Some("x".repeat(MAX_REASON_LEN + 1)), ..approve() };
    assert_eq!(relay.answer(201, &rid(1), &token(), long), Err(Reject::Invalid));

    let deny = Answer { decision: Decision::Deny, reason: Some("use staging".into()), ..approve() };
    relay.answer(202, &rid(1), &token(), deny).unwrap();
    assert_eq!(relay.answer(203, &rid(1), &token(), approve()), Err(Reject::Conflict));
    assert_eq!(relay.poll_answer(204, &rid(1)).unwrap().unwrap().decision, Decision::Deny);
    assert_eq!(relay.answer(204, &rid(9), &token(), approve()), Err(Reject::NotFound));
}

#[test]
fn everything_expires() {
    let mut relay = paired(true);
    let _ = relay.submit(200, &submit_body(1, 320)).unwrap();
    assert_eq!(relay.poll_answer(320, &rid(1)), Ok(None));
    assert_eq!(relay.poll_answer(321, &rid(1)), Err(Reject::NotFound));
    assert_eq!(relay.answer(321, &rid(1), &token(), approve()), Err(Reject::NotFound));
    // An active pairing does not expire.
    assert_eq!(relay.status(&pid(), &token()).unwrap().state, PairingState::Active);

    // An unconfirmed one does.
    let mut relay = Relay::default();
    relay.create_pairing(100, &create_body(), None).unwrap();
    relay.claim(101, &pid(), &claim_body(false)).unwrap();
    relay.sweep(100 + 601);
    assert_eq!(relay.claim_view(&pid()).map(|c| c.is_some()), Err(Reject::NotFound));
}

#[test]
fn unpairing_drops_waiting_requests() {
    let mut relay = paired(true);
    let _ = relay.submit(200, &submit_body(1, 320)).unwrap();
    relay.revoke_as_phone(&pid(), &token()).unwrap();
    assert_eq!(relay.poll_answer(201, &rid(1)), Err(Reject::NotFound));
    assert_eq!(relay.submit(201, &submit_body(2, 320)), Err(Reject::NotFound));
}

#[test]
fn the_registration_token_gates_new_pairings() {
    let mut relay = Relay::new(Limits::default(), Some("let-me-in"));
    assert_eq!(relay.create_pairing(100, &create_body(), None), Err(Reject::Unauthorized));
    assert_eq!(relay.create_pairing(100, &create_body(), Some("wrong")), Err(Reject::Unauthorized));
    assert_eq!(relay.create_pairing(100, &create_body(), Some("let-me-in")), Ok(()));
}

#[test]
fn malformed_pairing_bodies_are_refused() {
    let mut relay = Relay::default();
    let mut body = create_body();
    body.host_pub = b64_encode(&[4; 64]);
    assert_eq!(relay.create_pairing(100, &body, None), Err(Reject::Invalid));
    body = create_body();
    body.host_name = "bad\nname".into();
    assert_eq!(relay.create_pairing(100, &body, None), Err(Reject::Invalid));
    body = create_body();
    body.pairing_id = "zz".into();
    assert_eq!(relay.create_pairing(100, &body, None), Err(Reject::Invalid));

    relay.create_pairing(100, &create_body(), None).unwrap();
    let mut claim = claim_body(true);
    claim.device = Some(DeviceUpdate { apns_token: "nothex".into(), apns_env: "sandbox".into() });
    assert_eq!(relay.claim(101, &pid(), &claim), Err(Reject::Invalid));
    claim = claim_body(false);
    claim.phone_token = "short".into();
    assert_eq!(relay.claim(101, &pid(), &claim), Err(Reject::Invalid));
    claim = claim_body(false);
    claim.phone_name = String::new();
    assert_eq!(relay.claim(101, &pid(), &claim), Err(Reject::Invalid));
}

#[test]
fn capacity_is_bounded() {
    let mut relay = Relay::new(Limits { max_pairings: 2, ..Limits::default() }, None);
    for n in 1..=2_u8 {
        let body = CreatePairing { pairing_id: hex_encode(&[n; PAIRING_ID_LEN]), ..create_body() };
        relay.create_pairing(100, &body, None).unwrap();
    }
    let third = CreatePairing { pairing_id: hex_encode(&[3; PAIRING_ID_LEN]), ..create_body() };
    assert_eq!(relay.create_pairing(100, &third, None), Err(Reject::TooMany));
    // Abandoned pairings free their slots.
    assert_eq!(relay.create_pairing(100 + 601, &third, None), Ok(()));
}

#[test]
fn pairings_survive_a_restart_but_tokens_are_not_stored() {
    let mut relay = paired(true);
    let _ = relay.submit(200, &submit_body(1, 320)).unwrap();
    let saved = serde_json::to_string(&relay.snapshot()).unwrap();
    assert!(!saved.contains(&token()), "the bearer token must not be written to disk");

    let mut restored = Relay::default();
    restored.restore(serde_json::from_str(&saved).unwrap());
    assert_eq!(restored.status(&pid(), &token()).unwrap().state, PairingState::Active);
    // Requests are not persisted; new ones work.
    assert_eq!(restored.poll_answer(201, &rid(1)), Err(Reject::NotFound));
    assert!(restored.submit(201, &submit_body(2, 320)).unwrap().is_some());
}
