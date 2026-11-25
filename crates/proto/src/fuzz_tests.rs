//! Randomized tests of every decoder and of the text escaping.
//!
//! The properties are the ones a signature scheme over bytes depends on:
//!
//! - **Nothing panics.** Whatever bytes arrive, a decoder returns.
//! - **Round trip.** Anything encoded decodes to itself.
//! - **No aliasing.** Anything a decoder accepts re-encodes to exactly the
//!   bytes it was given, so no two byte strings mean the same thing.
//!
//! Inputs are valid encodings, damaged versions of them, and plain noise.
//! Run with `ISUDO_FUZZ_CASES=1000000` for a long soak.

use std::collections::HashMap;

use crate::codec::{b64_decode, b64_encode, hex_decode, hex_encode};
use crate::delegation::{simple_enough, SignedDelegation, MAX_SIGNED_DELEGATION_LEN};
use crate::frame::{Job, Outcome, MAX_OUTCOME_LEN};
use crate::request::{EnvOrigin, Request, StdinKind, FLAG_EXE_WRITABLE};
use crate::testgen::{cases, Rng};
use crate::text::{escape, is_invisible};

/// Runs the three properties for one format.
fn check<T: PartialEq + std::fmt::Debug>(
    seed: u64,
    make: impl Fn(&mut Rng) -> T,
    encode: impl Fn(&T) -> Vec<u8>,
    decode: impl Fn(&[u8]) -> Option<T>,
    min_accepted_mutants: usize,
) {
    let mut rng = Rng(seed);
    let mut accepted = 0_usize;
    for _ in 0..cases(3000) {
        let value = make(&mut rng);
        let bytes = encode(&value);
        assert_eq!(decode(&bytes).as_ref(), Some(&value), "a value did not survive its own encoding");

        let mut damaged = bytes.clone();
        rng.mutate(&mut damaged);
        if let Some(decoded) = decode(&damaged) {
            accepted = accepted.saturating_add(1);
            assert_eq!(encode(&decoded), damaged, "accepted bytes that are not the encoding of what they decoded to");
        }
        // Noise, sometimes behind a genuine prefix so the fields get reached.
        let mut noise = rng.bytes(300);
        if rng.chance(50) {
            let keep = rng.below(bytes.len().min(16));
            drop(noise.splice(0..noise.len().min(keep), bytes.iter().take(keep).copied()));
        }
        if let Some(decoded) = decode(&noise) {
            assert_eq!(encode(&decoded), noise);
        }
    }
    assert!(accepted >= min_accepted_mutants, "only {accepted} damaged inputs decoded: the aliasing check barely ran");
}

#[test]
fn outcomes_from_the_helper() {
    // The one thing the root process parses that its caller wrote.
    check(0x0c0de, Rng::outcome, |o| o.encode().unwrap(), |b| Outcome::decode(b).ok(), 20);
    // And it never reads more than its bound.
    let mut rng = Rng(0x51ce);
    for _ in 0..cases(3000) {
        assert!(rng.outcome().encode().unwrap().len() <= MAX_OUTCOME_LEN);
    }
}

#[test]
fn delegations() {
    check(0xde1e, Rng::delegation, |d| d.encode().unwrap(), |b| SignedDelegation::decode(b).ok(), 50);
    let mut rng = Rng(0xde1f);
    for _ in 0..cases(3000) {
        let encoded = rng.delegation().encode().unwrap();
        assert!(encoded.len() <= MAX_SIGNED_DELEGATION_LEN);
        // Whatever decodes carries a name that reads the way it is written.
        let mut damaged = encoded;
        rng.mutate(&mut damaged);
        if let Ok(decoded) = SignedDelegation::decode(&damaged) {
            let name = std::str::from_utf8(&decoded.delegation.name).expect("a decoded name is text");
            assert!(!name.is_empty() && name.trim() == name && !name.chars().any(char::is_control), "{name:?}");
        }
    }
}

#[test]
fn jobs_for_the_helper() {
    check(0x10b, Rng::job, |j| j.encode().unwrap(), |b| Job::decode(b).ok(), 50);
}

#[test]
fn requests() {
    check(0x4e9, Rng::request, |r| r.encode().unwrap(), |b| Request::decode(b).ok(), 100);
}

#[test]
fn hex_and_base64() {
    const HEXISH: &[u8] = b"0123456789abcdefABCDEFg ";
    const B64ISH: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=+/ ";
    let mut rng = Rng(0xc0dec);
    let mut accepted = (0_usize, 0_usize);
    for _ in 0..cases(20_000) {
        let bytes = rng.bytes(40);
        assert_eq!(hex_decode(&hex_encode(&bytes)).unwrap(), bytes);
        assert_eq!(b64_decode(&b64_encode(&bytes)).unwrap(), bytes);

        // Text that looks like an encoding. Hex is accepted in either case
        // and nothing else; base64 has exactly one spelling per value.
        let hexish: String = (0..rng.below(12)).map(|_| char::from(*rng.pick(HEXISH).unwrap())).collect();
        if let Ok(decoded) = hex_decode(&hexish) {
            accepted.0 = accepted.0.saturating_add(1);
            assert_eq!(hex_encode(&decoded), hexish.to_ascii_lowercase());
        }
        let b64ish: String = (0..rng.below(12)).map(|_| char::from(*rng.pick(B64ISH).unwrap())).collect();
        if let Ok(decoded) = b64_decode(&b64ish) {
            accepted.1 = accepted.1.saturating_add(1);
            assert_eq!(b64_encode(&decoded), b64ish, "two spellings of one value");
        }
        // And text that does not: never a panic.
        if let Ok(noise) = String::from_utf8(rng.text(24)) {
            drop(hex_decode(&noise));
            drop(b64_decode(&noise));
        }
    }
    assert!(accepted.0 > 50 && accepted.1 > 50, "{accepted:?}");
}

/// What reaches a screen or a terminal contains nothing that acts instead
/// of showing: no control characters, nothing invisible, nothing that
/// reorders its neighbours.
#[test]
fn escaped_text_is_inert() {
    let mut rng = Rng(0xe5c);
    for _ in 0..cases(30_000) {
        let input = if rng.chance(70) { rng.text(40) } else { rng.bytes(24) };
        let shown = escape(&input);
        assert!(!shown.chars().any(|c| c.is_control() || is_invisible(c)), "{input:?} was shown as {shown:?}");
        // Plain printable ASCII without a backslash is shown as it is.
        if input.iter().all(|b| (0x20..=0x7e).contains(b) && *b != b'\\') {
            assert_eq!(shown.as_bytes(), input);
        }
    }
}

/// Two different byte strings are never shown the same way, so what a
/// person reads identifies what will run. Searched for among short strings
/// made of the pieces most likely to collide.
#[test]
fn escaped_text_is_unambiguous() {
    const PIECES: &[&[u8]] = &[
        b"\\",
        b"n",
        b"x",
        b"u",
        b"{",
        b"}",
        b"0",
        b"a",
        b"4",
        b"1",
        b"\n",
        b"\x0a",
        b"\xff",
        b"\x00",
        "\u{202e}".as_bytes(),
        b"e",
    ];
    let mut rng = Rng(0xa3b1);
    let mut seen: HashMap<String, Vec<u8>> = HashMap::new();
    for _ in 0..cases(200_000) {
        let input: Vec<u8> = (0..rng.below(7)).flat_map(|_| rng.pick(PIECES).copied().unwrap().to_vec()).collect();
        let shown = escape(&input);
        if let Some(earlier) = seen.insert(shown.clone(), input.clone()) {
            assert_eq!(earlier, input, "both are shown as {shown:?}");
        }
    }
}

/// The rule for what a watch may approve agrees with what the phone would
/// show: a simple request has nothing to escape and nothing to warn about.
#[test]
fn a_simple_request_is_shown_exactly_as_it_is() {
    let mut rng = Rng(0x51e);
    let mut simple = 0_usize;
    let total = cases(20_000);
    for _ in 0..total {
        let request = rng.request();
        if !simple_enough(&request) {
            continue;
        }
        simple = simple.saturating_add(1);
        for field in [&request.exe, &request.cwd, &request.host].into_iter().chain(&request.argv) {
            assert_ne!(field.as_slice(), b"");
            assert_eq!(
                escape(field).as_bytes(),
                field.as_slice(),
                "a simple request has text that is shown differently"
            );
            assert!(!field.contains(&b'\\'));
        }
        assert_eq!(request.flags & FLAG_EXE_WRITABLE, 0);
        assert!(matches!(request.stdin, StdinKind::Terminal | StdinKind::Null));
        assert!(request.env.iter().all(|var| var.origin != EnvOrigin::Explicit));
    }
    // The generator must produce both kinds, or this proves nothing.
    assert!(
        simple.saturating_mul(50) > total && simple.saturating_mul(2) < total,
        "{simple} of {total} requests were simple"
    );
}

#[cfg(feature = "pairing")]
mod pairing {
    use crate::pairing::Offer;
    use crate::testgen::{cases, Rng};

    fn offer(rng: &mut Rng) -> Offer {
        let mut host_pub: [u8; 65] = rng.array();
        host_pub[0] = 0x04;
        let name = String::from_utf8(rng.plain(20)).unwrap();
        Offer {
            relay_url: ["https://", &String::from_utf8(rng.plain(20)).unwrap(), "/a b"].concat(),
            pairing_id: rng.array(),
            host_pub,
            secret: rng.array(),
            commitment: rng.array(),
            host_name: if rng.chance(30) { [name.as_str(), "\u{2019}s \u{65e5}"].concat() } else { name },
        }
    }

    #[test]
    fn pairing_links() {
        let mut rng = Rng(0x11c);
        let mut accepted = 0_usize;
        for _ in 0..cases(4000) {
            let offer = offer(&mut rng);
            let link = offer.to_url();
            assert_eq!(Offer::from_url(&link).unwrap(), offer);

            let mut damaged = link.into_bytes();
            rng.mutate(&mut damaged);
            let Ok(damaged) = String::from_utf8(damaged) else { continue };
            if let Ok(parsed) = Offer::from_url(&damaged) {
                accepted = accepted.saturating_add(1);
                // A link has more than one spelling (escapes, surrounding
                // space), but what it parses to has one meaning.
                assert_eq!(Offer::from_url(&parsed.to_url()).unwrap(), parsed);
                assert!(parsed.host_name.len() <= crate::pairing::MAX_NAME_LEN);
                assert_eq!(parsed.host_pub[0], 0x04);
            }
        }
        assert!(accepted > 20, "only {accepted} damaged links parsed");
    }
}
