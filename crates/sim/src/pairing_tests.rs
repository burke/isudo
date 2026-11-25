//! Pairing under attack, with the real code on every side: the host's
//! decision (`isudo_core::pairing`), the relay state machine, and the phone.
//!
//! The property: the host pins a phone's key only if that phone is the one
//! whose code the operator typed, a phone has a code to show only if the
//! host accepted that phone's own keys, and a phone becomes active only once
//! the host has confirmed them.

use isudo_core::pairing::{Accepted, ClaimError, HostIdentity, Opening};
use isudo_core::plan::HostKey;
use isudo_phone::{Pairing, PairingError, Progress};
use isudo_proto::api::{Ack, ClaimView, Confirm, CreatePairing, PairingState, PairingStatus};
use isudo_proto::codec::{b64_decode, b64_encode, hex_encode};
use isudo_proto::pairing::{self, Offer, Parties};
use isudo_proto::{sigs, HOST_NONCE_LEN, PAIRING_ID_LEN, PUBKEY_LEN};
use isudo_relay_core::{Reject, Relay};

use crate::Rng;

const NOW: u64 = 1_795_000_000;

/// A computer running `isudo-admin pair`: its key, the pairing code it
/// shows, and the nonce that code commits to.
struct Host {
    key: HostKey,
    identity: HostIdentity,
    pairing_id: [u8; PAIRING_ID_LEN],
    secret: [u8; 32],
    nonce: [u8; HOST_NONCE_LEN],
    offer: Offer,
}

fn host_named(rng: &mut Rng, name: &str, relay_url: &str) -> Host {
    let key = loop {
        if let Some(key) = HostKey::new(&rng.bytes()) {
            break key;
        }
    };
    let identity =
        HostIdentity { relay_url: relay_url.to_owned(), host_pub: key.public().unwrap(), host_name: name.to_owned() };
    let (pairing_id, secret, nonce) = (rng.bytes(), rng.bytes(), rng.bytes());
    let offer = Opening::new(identity.clone(), pairing_id, secret, nonce).offer().clone();
    Host { key, identity, pairing_id, secret, nonce, offer }
}

fn host(rng: &mut Rng) -> Host {
    host_named(rng, "simhost", "https://relay.invalid")
}

impl Host {
    /// The host's one decision about an answer. The real host can make it
    /// once per pairing code, because accepting consumes the opening; a test
    /// asks again only to compare what different answers would have got.
    fn accept(&self, claim: &ClaimView) -> Result<Accepted, ClaimError> {
        Opening::new(self.identity.clone(), self.pairing_id, self.secret, self.nonce).accept(claim)
    }

    /// What `isudo-admin` sends straight after accepting an answer.
    fn acknowledge(&self, accepted: &Accepted) -> Ack {
        self.acknowledge_revealing(accepted.host_nonce(), &accepted.ack_message())
    }

    /// An acknowledgement signed by this host's key, revealing `nonce`.
    fn acknowledge_revealing(&self, nonce: &[u8; HOST_NONCE_LEN], message: &[u8]) -> Ack {
        Ack { nonce: b64_encode(nonce), host_sig: b64_encode(&self.key.sign(message)) }
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
        phone_nonce: claim.phone_nonce,
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
        let accepted = host.accept(&claim).unwrap();
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
    assert_eq!(host.accept(&view(&relay_phone, "My Phone")).err(), Some(ClaimError::NotFromTheCode));

    // Or the honest phone's answer with one key swapped for the relay's.
    let mut swapped = view(&honest, "My Phone");
    swapped.phone_kem_pub = view(&relay_phone, "x").phone_kem_pub;
    assert_eq!(host.accept(&swapped).err(), Some(ClaimError::NotFromTheCode));
    let mut swapped = view(&honest, "My Phone");
    swapped.phone_sign_pub = view(&relay_phone, "x").phone_sign_pub;
    assert_eq!(host.accept(&swapped).err(), Some(ClaimError::NotFromTheCode));

    // Or the honest answer under a misleading name.
    let mut renamed = view(&honest, "My Phone");
    renamed.phone_name = "Definitely Your Phone".to_owned();
    assert_eq!(host.accept(&renamed).err(), Some(ClaimError::NotFromTheCode));

    // Or the honest answer with its nonce replaced by one the relay chose.
    let mut renonced = view(&honest, "My Phone");
    renonced.phone_nonce = view(&relay_phone, "x").phone_nonce;
    assert_eq!(host.accept(&renonced).err(), Some(ClaimError::NotFromTheCode));

    // The untouched answer is fine.
    assert!(host.accept(&view(&honest, "My Phone")).is_ok());
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
        let accepted = host.accept(&claim).unwrap();
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

/// The attack the acknowledgement exists to stop.
///
/// The attacker controls the relay and has also seen the pairing code, so
/// knows the secret. It lets the operator's phone answer, then hands the
/// host different keys of its own.
///
/// In the first design the phone showed its code straight away and the code
/// depended only on the secret and the keys. Six digits is about a million
/// possibilities, so the attacker simply tried key pairs until its code
/// equalled the phone's; the operator typed the code, it matched, and the
/// host pinned the attacker.
///
/// Now there are two obstacles, and this test checks both:
/// - the phone has no code until it holds the host's acknowledgement of its
///   own answer, which the attacker cannot forge;
/// - the code depends on a nonce the host reveals only after the answer is
///   fixed, so there is nothing to search against in advance.
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
    let accepted = host.accept(&view(&attacker, "My Phone")).unwrap();
    let ack = host.acknowledge(&accepted);

    // Obstacle one. The operator's phone gets no code out of an
    // acknowledgement of someone else's answer, nor out of a forged one.
    assert_eq!(mine.code(), None);
    assert_eq!(mine.observe(&acknowledged(ack.clone())), Err(PairingError::AnotherPhoneWasAccepted));
    let forged = Ack { nonce: ack.nonce, host_sig: b64_encode(&[0x5a; 64]) };
    assert_eq!(mine.observe(&acknowledged(forged)), Err(PairingError::AnotherPhoneWasAccepted));
    assert_eq!(mine.code(), None, "the operator has nothing to type");

    // Obstacle two. The codes two answers would get are unrelated: across
    // many honest/attacker pairs, the code one phone shows never confirms
    // the other's answer (it would by chance one time in a million).
    let mut collisions = 0_u32;
    for _ in 0..300 {
        let honest = Pairing::begin(offer, &rng.bytes()).unwrap();
        let rival = Pairing::begin(offer, &rng.bytes()).unwrap();
        let for_honest = host.accept(&view(&honest, "My Phone")).unwrap();
        let for_rival = host.accept(&view(&rival, "My Phone")).unwrap();
        let mut honest = honest;
        let Ok(Progress::ShowCode(code)) = honest.observe(&acknowledged(host.acknowledge(&for_honest))) else {
            panic!("the honest phone should have a code");
        };
        // The operator types their phone's code at a host that is checking
        // it against the rival's answer.
        if for_rival.confirm(&code).is_some() {
            collisions = collisions.saturating_add(1);
        }
        // Typed where it belongs, it works.
        assert!(for_honest.confirm(&code).is_some());
    }
    assert_eq!(collisions, 0, "a code for one phone's answer pinned another's");

    // And the attacker cannot work out, before it answers, what code its
    // answer will get: the same answer under two host nonces gives two
    // codes, and the host's nonce is hidden until the answer is accepted.
    let answer = view(&attacker, "My Phone");
    let first = Opening::new(host.identity.clone(), host.pairing_id, host.secret, [1; 16]).accept(&answer).unwrap();
    let second = Opening::new(host.identity.clone(), host.pairing_id, host.secret, [2; 16]).accept(&answer).unwrap();
    let codes = (0..1_000_000_u32).map(|n| format!("{n:06}"));
    let both = codes.filter(|code| first.confirm(code).is_some() && second.confirm(code).is_some()).count();
    assert_eq!(both, 0, "one code confirmed the same answer under two nonces");
}

/// The attack the commitment exists to stop. It was found in an audit, after
/// the design above had shipped, and it worked.
///
/// The attacker has seen the real pairing code, and can also put a pairing
/// code of their own in front of the operator's phone: a link opened on the
/// phone, a clipboard that syncs to it, a second QR code drawn on the same
/// terminal. Theirs names the same computer but holds their own key, secret
/// and relay.
///
/// 1. They answer the real pairing code first, with their own keys. The
///    computer accepts, and now waits for a code the attacker can compute.
/// 2. The operator's phone answers the attacker's pairing code. The attacker
///    is that pairing's "host", so can sign any acknowledgement.
/// 3. Before the commitment, the attacker chose the acknowledgement's nonce
///    after seeing the phone's answer, and searched for one that made the
///    phone show exactly the code the real computer was waiting for. About
///    a million tries; a fraction of a second.
/// 4. The operator typed what their phone showed. The computer pinned the
///    attacker.
#[test]
fn a_pairing_code_written_by_an_attacker_cannot_steer_the_code() {
    let mut rng = Rng::new(11);
    let real = host(&mut rng);

    // Step 1. The attacker answers the real pairing code and learns, from
    // the real acknowledgement, the code the computer is now waiting for.
    let mut attacker_phone = Pairing::begin(&real.offer, &rng.bytes()).unwrap();
    let accepted = real.accept(&view(&attacker_phone, "iPhone")).unwrap();
    let Ok(Progress::ShowCode(wanted)) = attacker_phone.observe(&acknowledged(real.acknowledge(&accepted))) else {
        panic!("the attacker's own answer should get a code");
    };
    assert!(accepted.confirm(&wanted).is_some(), "typing this would pin the attacker");

    // Step 2. The operator's phone is shown the attacker's pairing code.
    let fake = host_named(&mut rng, "simhost", "https://attacker.invalid");
    let mut victim = Pairing::begin(&fake.offer, &rng.bytes()).unwrap();
    let answer = view(&victim, "iPhone");
    let (sign_pub, kem_pub) =
        (pairing::decode_pubkey(&answer.phone_sign_pub).unwrap(), pairing::decode_pubkey(&answer.phone_kem_pub).unwrap());
    let phone_nonce: [u8; 16] = isudo_proto::codec::b64_decode_array(&answer.phone_nonce).unwrap();
    let parties = Parties {
        pairing_id: &fake.offer.pairing_id,
        host_pub: &fake.offer.host_pub,
        phone_sign_pub: &sign_pub,
        phone_kem_pub: &kem_pub,
    };

    // Step 3. The search still succeeds: the attacker holds the secret, so
    // can compute the code for any nonce.
    let steering = (0..100_000_000_u64)
        .map(|n| {
            let mut nonce = [0_u8; 16];
            nonce[..8].copy_from_slice(&n.to_be_bytes());
            nonce
        })
        .find(|nonce| pairing::confirmation_code(&fake.secret, &parties, nonce, &phone_nonce) == wanted)
        .unwrap();
    // But the phone will not show it. The acknowledgement is signed by the
    // key in the pairing code the phone scanned, over the phone's own keys
    // and nonce; what is wrong is the nonce, which that pairing code did not
    // commit to.
    let message = sigs::pair_ack_msg(&fake.offer.pairing_id, &sign_pub, &kem_pub, &phone_nonce, &steering);
    let steered = fake.acknowledge_revealing(&steering, &message);
    assert_eq!(victim.observe(&acknowledged(steered)), Err(PairingError::CodeWasSteered));
    assert_eq!(victim.code(), None, "the operator has nothing to type");

    // Nor can the attacker borrow the real computer's commitment, hoping to
    // reveal the real nonce once the real acknowledgement has disclosed it:
    // a commitment belongs to one pairing code.
    let mut borrowed = fake.offer.clone();
    borrowed.commitment = real.offer.commitment;
    let mut second_victim = Pairing::begin(&borrowed, &rng.bytes()).unwrap();
    let second = view(&second_victim, "iPhone");
    let message = sigs::pair_ack_msg(
        &borrowed.pairing_id,
        &pairing::decode_pubkey(&second.phone_sign_pub).unwrap(),
        &pairing::decode_pubkey(&second.phone_kem_pub).unwrap(),
        &isudo_proto::codec::b64_decode_array(&second.phone_nonce).unwrap(),
        &real.nonce,
    );
    let revealed = fake.acknowledge_revealing(&real.nonce, &message);
    assert_eq!(second_victim.observe(&acknowledged(revealed)), Err(PairingError::CodeWasSteered));

    // Step 4 never happens. What the attacker can still do is play its
    // pairing code straight: reveal the nonce it committed to. Then the
    // phone shows a code, but one fixed by a nonce the phone chose after
    // the commitment was made, so it is right one time in a million.
    let honest_ack = fake.acknowledge(&fake.accept(&answer).unwrap());
    let Ok(Progress::ShowCode(shown)) = victim.observe(&acknowledged(honest_ack)) else {
        panic!("a pairing code played straight should give a code");
    };
    assert!(accepted.confirm(&shown).is_none(), "the phone's code pinned the attacker");
}

/// The same, as a property: however many times the attacker gets a phone to
/// answer a pairing code of theirs, the code that phone shows does not
/// confirm the attacker's answer at the real computer.
#[test]
fn a_substituted_pairing_code_never_yields_the_real_computers_code() {
    for seed in 0..300 {
        let mut rng = Rng::new(seed);
        let real = host(&mut rng);
        let attacker_phone = Pairing::begin(&real.offer, &rng.bytes()).unwrap();
        let accepted = real.accept(&view(&attacker_phone, "iPhone")).unwrap();

        let fake = host_named(&mut rng, "simhost", "https://attacker.invalid");
        let mut victim = Pairing::begin(&fake.offer, &rng.bytes()).unwrap();
        let ack = fake.acknowledge(&fake.accept(&view(&victim, "iPhone")).unwrap());
        let Ok(Progress::ShowCode(shown)) = victim.observe(&acknowledged(ack)) else { panic!("seed {seed}: no code") };
        assert!(accepted.confirm(&shown).is_none(), "seed {seed}: the phone's code pinned the attacker");
    }
}

#[test]
fn a_phone_is_not_fooled_into_thinking_it_is_paired() {
    let mut rng = Rng::new(3);
    let host = host(&mut rng);
    let mut phone = Pairing::begin(&host.offer, &rng.bytes()).unwrap();
    let onlooker = Pairing::begin(&host.offer, &rng.bytes()).unwrap();
    let my_ack = host.acknowledge(&host.accept(&view(&phone, "My Phone")).unwrap());

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
    let accepted = host.accept(&view(&phone, "My Phone")).unwrap();
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
        assert_eq!(host.accept(&view(&phone, bad_name)).err(), Some(ClaimError::Malformed), "{bad_name:?}");
    }
    let mut bad_key = view(&phone, "My Phone");
    bad_key.phone_sign_pub = "AAAA".to_owned();
    assert_eq!(host.accept(&bad_key).err(), Some(ClaimError::Malformed));
    let mut bad_mac = view(&phone, "My Phone");
    bad_mac.claim_mac = "not base64!".to_owned();
    assert_eq!(host.accept(&bad_mac).err(), Some(ClaimError::Malformed));
    let mut bad_nonce = view(&phone, "My Phone");
    bad_nonce.phone_nonce = b64_encode(&[0x70; 8]);
    assert_eq!(host.accept(&bad_nonce).err(), Some(ClaimError::Malformed));

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
    let nonce: [u8; 16] = isudo_proto::codec::b64_decode_array(&honest.phone_nonce).unwrap();
    let mac = pairing::claim_mac(&host.offer.secret, &parties, &nonce, b"My Phone");
    let crafted = ClaimView {
        phone_sign_pub: b64_encode(&off_curve),
        claim_mac: b64_encode(&mac),
        ..honest
    };
    assert!(b64_decode(&crafted.claim_mac).is_ok());
    assert_eq!(host.accept(&crafted).err(), Some(ClaimError::Malformed));
}
