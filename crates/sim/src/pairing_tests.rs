//! Pairing under attack, with the real code on every side: the host's
//! decision (`isudo_core::pairing`), the relay state machine, and the phone.
//!
//! The property: the host pins a phone's key only if that phone is the one
//! whose code the operator typed, a phone has a code to show only if the
//! host accepted that phone's own keys, and a phone becomes active only once
//! the host has confirmed them.

use isudo_core::pairing::{accept, Accepted, ClaimError};
use isudo_core::plan::HostKey;
use isudo_phone::{Pairing, PairingError, Progress};
use isudo_proto::api::{Ack, ClaimView, Confirm, CreatePairing, PairingState, PairingStatus};
use isudo_proto::codec::{b64_decode, b64_encode, hex_encode};
use isudo_proto::pairing::{self, Offer, Parties};
use isudo_proto::{sigs, PUBKEY_LEN};
use isudo_relay_core::{Reject, Relay};

use crate::Rng;

const NOW: u64 = 1_795_000_000;
const NONCE: [u8; 16] = [0x4e; 16];

struct Host {
    key: HostKey,
    offer: Offer,
}

fn host(rng: &mut Rng) -> Host {
    let key = loop {
        if let Some(key) = HostKey::new(&rng.bytes()) {
            break key;
        }
    };
    let offer = Offer {
        relay_url: "https://relay.invalid".to_owned(),
        pairing_id: rng.bytes(),
        host_pub: key.public().unwrap(),
        secret: rng.bytes(),
        host_name: "simhost".to_owned(),
    };
    Host { key, offer }
}

impl Host {
    /// What `isudo-admin` sends straight after accepting an answer.
    fn acknowledge(&self, accepted: &Accepted) -> Ack {
        Ack {
            nonce: b64_encode(accepted.ack_nonce()),
            host_sig: b64_encode(&self.key.sign(&accepted.ack_message(&self.offer.pairing_id))),
        }
    }
}

fn relay_with(host: &Host) -> Relay {
    let mut relay = Relay::default();
    let body = CreatePairing {
        pairing_id: hex_encode(&host.offer.pairing_id),
        host_pub: b64_encode(&host.offer.host_pub),
        host_name: host.offer.host_name.clone(),
    };
    relay.create_pairing(NOW, &body, None).unwrap();
    relay
}

fn view(phone: &Pairing, name: &str) -> ClaimView {
    let claim = phone.claim(name, None);
    ClaimView {
        phone_sign_pub: claim.phone_sign_pub,
        phone_kem_pub: claim.phone_kem_pub,
        phone_name: claim.phone_name,
        claim_mac: claim.claim_mac,
    }
}

fn acknowledged(ack: Ack) -> PairingStatus {
    PairingStatus { state: PairingState::Acknowledged, ack: Some(ack), host_sig: None }
}

#[test]
fn an_honest_pairing_pins_exactly_the_scanning_phone() {
    for seed in 0..50 {
        let mut rng = Rng::new(seed);
        let host = host(&mut rng);
        let mut relay = relay_with(&host);
        let pairing_id = hex_encode(&host.offer.pairing_id);

        // The phone scans and answers through the relay. No code yet.
        let mut phone = Pairing::begin(&host.offer, &rng.bytes()).unwrap();
        relay.claim(NOW, &pairing_id, &phone.claim("My Phone", None)).unwrap();
        let status = relay.status(&pairing_id, phone.token()).unwrap();
        assert_eq!(phone.observe(&status), Ok(Progress::Waiting));
        assert_eq!(phone.code(), None);

        // The host accepts the answer and acknowledges it; now there is one.
        let claim = relay.claim_view(&pairing_id).unwrap().unwrap();
        let accepted = accept(&host.offer, &claim, rng.bytes()).unwrap();
        relay.acknowledge(&pairing_id, &host.acknowledge(&accepted)).unwrap();
        let status = relay.status(&pairing_id, phone.token()).unwrap();
        let Ok(Progress::ShowCode(code)) = phone.observe(&status) else { panic!("seed {seed}: no code") };

        // The operator types it; the host pins exactly that phone.
        let pinned = accepted.confirm(&code).unwrap();
        assert_eq!(pinned.phone_sign_pub(), phone.sign_pub(), "seed {seed}");

        // Only now does the host confirm, and only then is the phone active.
        assert!(!phone.is_active());
        let message = sigs::pair_confirm_msg(&host.offer.pairing_id, pinned.phone_sign_pub(), pinned.phone_kem_pub());
        relay.confirm(&pairing_id, &Confirm { host_sig: b64_encode(&host.key.sign(&message)) }).unwrap();
        let status = relay.status(&pairing_id, phone.token()).unwrap();
        assert_eq!(phone.observe(&status), Ok(Progress::Active));
    }
}

#[test]
fn the_relay_cannot_substitute_its_own_phone() {
    let mut rng = Rng::new(1);
    let host = host(&mut rng);
    let honest = Pairing::begin(&host.offer, &rng.bytes()).unwrap();

    // The relay knows the pairing id and the host's public key, but not the
    // secret in the QR code. Its best effort is a phone built from a guess.
    let mut guess = host.offer.clone();
    guess.secret = rng.bytes();
    let relay_phone = Pairing::begin(&guess, &rng.bytes()).unwrap();
    assert_eq!(accept(&host.offer, &view(&relay_phone, "My Phone"), NONCE), Err(ClaimError::NotFromTheCode));

    // Or the honest phone's answer with one key swapped for the relay's.
    let mut swapped = view(&honest, "My Phone");
    swapped.phone_kem_pub = view(&relay_phone, "x").phone_kem_pub;
    assert_eq!(accept(&host.offer, &swapped, NONCE), Err(ClaimError::NotFromTheCode));
    let mut swapped = view(&honest, "My Phone");
    swapped.phone_sign_pub = view(&relay_phone, "x").phone_sign_pub;
    assert_eq!(accept(&host.offer, &swapped, NONCE), Err(ClaimError::NotFromTheCode));

    // Or the honest answer under a misleading name.
    let mut renamed = view(&honest, "My Phone");
    renamed.phone_name = "Definitely Your Phone".to_owned();
    assert_eq!(accept(&host.offer, &renamed, NONCE), Err(ClaimError::NotFromTheCode));

    // The untouched answer is fine.
    assert!(accept(&host.offer, &view(&honest, "My Phone"), NONCE).is_ok());
}

#[test]
fn someone_who_saw_the_qr_code_cannot_get_pinned() {
    for seed in 0..200 {
        let mut rng = Rng::new(seed);
        let host = host(&mut rng);
        let mut relay = relay_with(&host);
        let pairing_id = hex_encode(&host.offer.pairing_id);

        // An onlooker photographs the QR code and answers first.
        let onlooker = Pairing::begin(&host.offer, &rng.bytes()).unwrap();
        relay.claim(NOW, &pairing_id, &onlooker.claim("My Phone", None)).unwrap();

        // The operator's phone is told, loudly, that it lost.
        let mut mine = Pairing::begin(&host.offer, &rng.bytes()).unwrap();
        assert_eq!(relay.claim(NOW, &pairing_id, &mine.claim("My Phone", None)), Err(Reject::Conflict));

        // The host sees a perfectly valid answer (the onlooker had the
        // secret) and acknowledges it.
        let claim = relay.claim_view(&pairing_id).unwrap().unwrap();
        let accepted = accept(&host.offer, &claim, rng.bytes()).unwrap();
        let ack = host.acknowledge(&accepted);

        // The operator's phone, shown that acknowledgement, recognises that
        // it is for someone else's keys. It has no code to offer.
        assert_eq!(mine.observe(&acknowledged(ack)), Err(PairingError::AnotherPhoneWasAccepted), "seed {seed}");
        assert_eq!(mine.code(), None);
        // So there is nothing the operator can type that pins the onlooker.
        assert_eq!(accepted.confirm(""), None);
        assert_eq!(accepted.confirm("000000"), None);
    }
}

/// The attack the acknowledgement and its nonce exist to stop.
///
/// The attacker controls the relay and has also seen the QR code, so knows
/// the secret. It lets the operator's phone answer, then hands the host
/// different keys of its own.
///
/// In the first design the phone showed its code straight away and the code
/// depended only on the secret and the keys. Six digits is about a million
/// possibilities, so the attacker simply tried key pairs until its code
/// equalled the phone's; the operator typed the code, it matched, and the
/// host pinned the attacker.
///
/// Now there are two obstacles, and this test checks both:
/// - the phone has no code until it holds the host's acknowledgement of its
///   own keys, which the attacker cannot forge;
/// - the code depends on a nonce the host picks after the keys are fixed, so
///   there is nothing to search against in advance.
#[test]
fn a_relay_that_knows_the_secret_cannot_get_its_keys_pinned() {
    let mut rng = Rng::new(7);
    let host = host(&mut rng);
    let offer = &host.offer;

    // The operator's phone answers. The attacker sees its keys go by, and
    // answers the host itself with keys of its own.
    let mut mine = Pairing::begin(offer, &rng.bytes()).unwrap();
    let attacker = Pairing::begin(offer, &rng.bytes()).unwrap();

    // The host is handed the attacker's answer. It is valid in every way the
    // host can check: right secret, real keys.
    let accepted = accept(offer, &view(&attacker, "My Phone"), rng.bytes()).unwrap();
    let ack = host.acknowledge(&accepted);

    // Obstacle one. The operator's phone gets no code out of an
    // acknowledgement of someone else's keys, nor out of a forged one.
    assert_eq!(mine.code(), None);
    assert_eq!(mine.observe(&acknowledged(ack.clone())), Err(PairingError::AnotherPhoneWasAccepted));
    let forged = Ack { nonce: ack.nonce, host_sig: b64_encode(&[0x5a; 64]) };
    assert_eq!(mine.observe(&acknowledged(forged)), Err(PairingError::AnotherPhoneWasAccepted));
    assert_eq!(mine.code(), None, "the operator has nothing to type");

    // Obstacle two. Suppose a (buggy) host acknowledged both answers. Each
    // acknowledgement carries its own nonce, so the two codes are unrelated:
    // the attacker's choice of keys, made before either nonce existed, could
    // not have lined them up. Across many honest/attacker pairs the codes
    // collide no more often than chance (one in a million each).
    let mut collisions = 0_u32;
    for _ in 0..300 {
        let honest = Pairing::begin(offer, &rng.bytes()).unwrap();
        let rival = Pairing::begin(offer, &rng.bytes()).unwrap();
        let for_honest = accept(offer, &view(&honest, "My Phone"), rng.bytes()).unwrap();
        let for_rival = accept(offer, &view(&rival, "My Phone"), rng.bytes()).unwrap();
        let mut honest = honest;
        let Ok(Progress::ShowCode(code)) = honest.observe(&acknowledged(host.acknowledge(&for_honest))) else {
            panic!("the honest phone should have a code");
        };
        // The operator types their phone's code at a host that is checking
        // it against the rival's keys.
        if for_rival.confirm(&code).is_some() {
            collisions = collisions.saturating_add(1);
        }
        // Typed where it belongs, it works.
        assert!(for_honest.confirm(&code).is_some());
    }
    assert_eq!(collisions, 0, "a code for one phone's keys pinned another's");

    // And the same keys under two different nonces give different codes, so
    // nothing computed before the acknowledgement predicts the code.
    let first = accept(offer, &view(&attacker, "My Phone"), [1; 16]).unwrap();
    let second = accept(offer, &view(&attacker, "My Phone"), [2; 16]).unwrap();
    let mut probe = attacker;
    let Ok(Progress::ShowCode(code)) = probe.observe(&acknowledged(host.acknowledge(&first))) else {
        panic!("no code");
    };
    assert!(first.confirm(&code).is_some());
    assert!(second.confirm(&code).is_none());
}

#[test]
fn a_phone_is_not_fooled_into_thinking_it_is_paired() {
    let mut rng = Rng::new(3);
    let host = host(&mut rng);
    let mut phone = Pairing::begin(&host.offer, &rng.bytes()).unwrap();
    let onlooker = Pairing::begin(&host.offer, &rng.bytes()).unwrap();
    let my_ack = host.acknowledge(&accept(&host.offer, &view(&phone, "My Phone"), NONCE).unwrap());

    // The relay says "active" with nothing to show for it.
    let bare = PairingStatus { state: PairingState::Active, ack: Some(my_ack.clone()), host_sig: None };
    assert_eq!(phone.observe(&bare), Err(PairingError::NotConfirmedByHost));

    // The relay replays the host's real confirmation of a different phone.
    let message = sigs::pair_confirm_msg(
        &host.offer.pairing_id,
        onlooker.sign_pub(),
        &pairing::decode_pubkey(&onlooker.claim("x", None).phone_kem_pub).unwrap(),
    );
    let replayed = PairingStatus {
        state: PairingState::Active,
        ack: Some(my_ack),
        host_sig: Some(b64_encode(&host.key.sign(&message))),
    };
    assert_eq!(phone.observe(&replayed), Err(PairingError::NotConfirmedByHost));
    assert!(!phone.is_active());
}

#[test]
fn codes_are_typed_however_people_type_them() {
    let mut rng = Rng::new(4);
    let host = host(&mut rng);
    let mut phone = Pairing::begin(&host.offer, &rng.bytes()).unwrap();
    let accepted = accept(&host.offer, &view(&phone, "My Phone"), NONCE).unwrap();
    let Ok(Progress::ShowCode(code)) = phone.observe(&acknowledged(host.acknowledge(&accepted))) else {
        panic!("no code");
    };
    let (first, second) = code.split_at(3);
    assert!(accepted.confirm(&format!("{first} {second}\n")).is_some());
    assert!(accepted.confirm(&format!(" {first}-{second} ")).is_some());
    assert!(accepted.confirm(first).is_none());
}

#[test]
fn malformed_answers_are_rejected_before_any_prompt() {
    let mut rng = Rng::new(5);
    let host = host(&mut rng);
    let phone = Pairing::begin(&host.offer, &rng.bytes()).unwrap();
    for bad_name in ["", " padded ", "two\nlines", &"x".repeat(65)] {
        // Built by a phone that had the secret, so only the name is wrong.
        assert_eq!(accept(&host.offer, &view(&phone, bad_name), NONCE), Err(ClaimError::Malformed), "{bad_name:?}");
    }
    let mut bad_key = view(&phone, "My Phone");
    bad_key.phone_sign_pub = "AAAA".to_owned();
    assert_eq!(accept(&host.offer, &bad_key, NONCE), Err(ClaimError::Malformed));
    let mut bad_mac = view(&phone, "My Phone");
    bad_mac.claim_mac = "not base64!".to_owned();
    assert_eq!(accept(&host.offer, &bad_mac, NONCE), Err(ClaimError::Malformed));

    // Sixty-five bytes with the right tag that are not a point on the curve,
    // with a correct MAC over them (the sender had the secret).
    let mut off_curve = [0x11_u8; PUBKEY_LEN];
    off_curve[0] = 0x04;
    let honest = view(&phone, "My Phone");
    let kem = pairing::decode_pubkey(&honest.phone_kem_pub).unwrap();
    let parties = Parties {
        pairing_id: &host.offer.pairing_id,
        host_pub: &host.offer.host_pub,
        phone_sign_pub: &off_curve,
        phone_kem_pub: &kem,
    };
    let mac = pairing::claim_mac(&host.offer.secret, &parties, b"My Phone");
    let crafted = ClaimView {
        phone_sign_pub: b64_encode(&off_curve),
        claim_mac: b64_encode(&mac),
        ..honest
    };
    assert!(b64_decode(&crafted.claim_mac).is_ok());
    assert_eq!(accept(&host.offer, &crafted, NONCE), Err(ClaimError::Malformed));
}
