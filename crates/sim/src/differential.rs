//! The corpus that other implementations are checked against.
//!
//! There are two implementations of what an approving device does: the Rust
//! reference in `isudo-phone`, and the Swift one that actually runs on a
//! phone and a watch. They must agree on what a request says, because the
//! Swift one is what the person reads before approving. `testdata/vectors.json`
//! pins a handful of hand-picked cases. This is the other kind of check:
//! thousands of generated inputs, many of them damaged or hostile, each with
//! the reference's verdict, for the Swift tests to replay.
//!
//! The corpus is `testdata/differential.json`. It is deterministic, and the
//! test below fails if the committed file is not what this code generates,
//! so the two cannot drift apart unnoticed. Regenerate with `make vectors`.
//! For a long run, `make differential` generates a much larger corpus and
//! replays that instead.

use std::fmt::Write as _;

use isudo_proto::codec::{b64_decode, b64_encode, hex_decode, hex_encode};
use isudo_proto::delegation::{name_is_valid, simple_enough, SignedDelegation};
use isudo_proto::envrisk::is_risky;
use isudo_proto::pairing::{claim_mac, commitment, confirmation_code, Offer, Parties};
use isudo_proto::request::{Request, FLAG_DELEGABLE};
use isudo_proto::sigs::request_digest;
use isudo_proto::testgen::Rng;
use isudo_proto::text::escape;
use serde_json::{json, Value};

/// Everything a device shows of a request, escaped, one piece per line, and
/// hashed. Escaped text never contains a line break, so the lines cannot
/// run together. Two implementations that agree on this agree on the whole
/// display, character for character.
fn shown(request: &Request) -> String {
    let mut lines = vec![escape(&request.host), escape(&request.user), escape(&request.exe), escape(&request.cwd)];
    lines.extend(request.argv.iter().map(|arg| escape(arg)));
    lines.extend(request.env.iter().map(|var| [escape(&var.name), "=".to_owned(), escape(&var.value)].concat()));
    lines.extend(request.ancestry.iter().map(|ancestor| escape(&ancestor.name)));
    hex_encode(&request_digest(lines.join("\n").as_bytes()))
}

/// Text, as the hex of its UTF-8. Every piece of text in the corpus is
/// carried this way: JSON readers are not all faithful to awkward strings
/// (Foundation's drops a leading byte-order mark), and awkward strings are
/// the point.
fn utf8(text: &str) -> String {
    hex_encode(text.as_bytes())
}

fn requests(rng: &mut Rng, count: usize) -> Vec<Value> {
    let mut cases = Vec::new();
    for index in 0..count {
        let mut bytes = rng.request().encode().unwrap_or_default();
        // Two in three are damaged; most of those no longer decode.
        if index % 3 != 0 {
            rng.mutate(&mut bytes);
        }
        cases.push(match Request::decode(&bytes) {
            Ok(request) => json!({
                "hex": hex_encode(&bytes),
                "ok": true,
                "simple": simple_enough(&request),
                "marked": request.flags & FLAG_DELEGABLE != 0,
                "shown": shown(&request),
            }),
            Err(_) => json!({ "hex": hex_encode(&bytes), "ok": false }),
        });
    }
    cases
}

fn delegations(rng: &mut Rng, count: usize) -> Vec<Value> {
    let mut cases = Vec::new();
    for index in 0..count {
        let mut bytes = rng.delegation().encode().unwrap_or_default();
        if index % 3 != 0 {
            rng.mutate(&mut bytes);
        }
        cases.push(match SignedDelegation::decode(&bytes) {
            Ok(signed) => json!({
                "hex": hex_encode(&bytes),
                "ok": true,
                "name": hex_encode(&signed.delegation.name),
                "not_after": signed.delegation.not_after.to_string(),
            }),
            Err(_) => json!({ "hex": hex_encode(&bytes), "ok": false }),
        });
    }
    cases
}

fn text_of(rng: &mut Rng, max_len: usize) -> String {
    // Awkward text that is still text: the lossy conversion keeps the
    // controls, the invisible characters and the rest.
    String::from_utf8_lossy(&rng.text(max_len)).into_owned()
}

fn links(rng: &mut Rng, count: usize) -> Vec<Value> {
    let mut cases = Vec::new();
    for index in 0..count {
        let mut host_pub: [u8; 65] = rng.array();
        host_pub[0] = 0x04;
        let offer = Offer {
            relay_url: ["https://", &String::from_utf8_lossy(&rng.plain(16)), "/a b"].concat(),
            pairing_id: rng.array(),
            host_pub,
            secret: rng.array(),
            commitment: rng.array(),
            host_name: if rng.chance(50) {
                text_of(rng, 24)
            } else {
                String::from_utf8_lossy(&rng.plain(12)).into_owned()
            },
        };
        let mut link = offer.to_url().into_bytes();
        if index % 3 != 0 {
            rng.mutate(&mut link);
        }
        if rng.chance(15) {
            // Surrounding space of several kinds, which a parser may or may
            // not take to be part of the link.
            let pad = ["\n", " ", "\t", "\u{a0}", "\u{200b}", "\u{feff}", "\u{2028}", "\u{85}"];
            link.extend_from_slice(rng.pick(&pad).copied().unwrap_or(" ").as_bytes());
        }
        let Ok(text) = String::from_utf8(link) else { continue };
        cases.push(match Offer::from_url(&text) {
            Ok(parsed) => json!({
                "text": utf8(&text),
                "ok": true,
                "relay": utf8(&parsed.relay_url),
                "name": utf8(&parsed.host_name),
                "binary": hex_encode(&[&parsed.pairing_id[..], &parsed.host_pub, &parsed.secret, &parsed.commitment].concat()),
            }),
            Err(_) => json!({ "text": utf8(&text), "ok": false }),
        });
    }
    cases
}

fn encodings(rng: &mut Rng, count: usize) -> (Vec<Value>, Vec<Value>) {
    const HEXISH: &[u8] = b"0123456789abcdefABCDEFg ";
    const B64ISH: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=+/ ";
    let (mut hex, mut b64) = (Vec::new(), Vec::new());
    for index in 0..count {
        let bytes = rng.bytes(12);
        let (hex_text, b64_text) = if index % 2 == 0 {
            (hex_encode(&bytes), b64_encode(&bytes))
        } else {
            let from = |rng: &mut Rng, alphabet: &[u8]| -> String {
                (0..rng.below(10)).map(|_| char::from(*rng.pick(alphabet).unwrap_or(&b'A'))).collect()
            };
            (from(rng, HEXISH), from(rng, B64ISH))
        };
        hex.push(json!([utf8(&hex_text), hex_decode(&hex_text).ok().map(|out| hex_encode(&out))]));
        b64.push(json!([utf8(&b64_text), b64_decode(&b64_text).ok().map(|out| hex_encode(&out))]));
    }
    (hex, b64)
}

fn codes(rng: &mut Rng, count: usize) -> Vec<Value> {
    let mut cases = Vec::new();
    for _ in 0..count {
        let (pairing_id, host_pub, sign_pub, kem_pub) = (rng.array(), rng.array(), rng.array(), rng.array());
        let (secret, host_nonce, phone_nonce): ([u8; 32], [u8; 16], [u8; 16]) = (rng.array(), rng.array(), rng.array());
        let name = text_of(rng, 20);
        let parties = Parties {
            pairing_id: &pairing_id,
            host_pub: &host_pub,
            phone_sign_pub: &sign_pub,
            phone_kem_pub: &kem_pub,
        };
        cases.push(json!({
            "inputs": hex_encode(&[&secret[..], &pairing_id, &host_pub, &sign_pub, &kem_pub, &host_nonce, &phone_nonce].concat()),
            "name": utf8(&name),
            "code": confirmation_code(&secret, &parties, &host_nonce, &phone_nonce),
            "mac": hex_encode(&claim_mac(&secret, &parties, &phone_nonce, name.as_bytes())),
            "commitment": hex_encode(&commitment(&pairing_id, &host_pub, &host_nonce)),
        }));
    }
    cases
}

/// The corpus, as text: one case per line, so that a change to it reads as
/// a change to particular cases. `scale` multiplies every section.
pub(crate) fn corpus(scale: usize) -> String {
    let mut rng = Rng(0xd1ff);
    let (hex, b64) = encodings(&mut rng, scale.saturating_mul(150));
    let escape_cases: Vec<Value> = (0..scale.saturating_mul(400))
        .map(|index| {
            let input = if index % 4 == 0 { rng.bytes(16) } else { rng.text(32) };
            json!([hex_encode(&input), utf8(&escape(&input))])
        })
        .collect();
    let risk: Vec<Value> = (0..scale.saturating_mul(150))
        .map(|_| {
            const NAMES: &[&str] = &[
                "LD_PRELOAD",
                "LD_",
                "DYLD_INSERT_LIBRARIES",
                "BASH_ENV",
                "BASH_FUNC_x%%",
                "PYTHONPATH",
                "PYTHON",
                "NODE_OPTIONS",
                "NODE_",
                "GEM_HOME",
                "PIP_INDEX_URL",
                "PATH",
                "HOME",
                "TERM",
                "LANG",
                "DEBUG",
                "FOO",
                "DOCKER_HOST",
                "KUBECONFIG",
                "GIT_SSH_COMMAND",
                "PERL5LIB",
                "RUBYOPT",
                "TMPDIR",
                "IFS",
                "ld_preload",
                "",
            ];
            let mut name = rng.pick(NAMES).copied().unwrap_or("FOO").as_bytes().to_vec();
            // Often with something appended or altered: a combining mark, a
            // lookalike letter, a stray byte.
            if rng.chance(50) {
                name.extend(rng.text(4));
            }
            if rng.chance(15) {
                rng.mutate(&mut name);
            }
            json!([hex_encode(&name), is_risky(&name)])
        })
        .collect();
    let names: Vec<Value> = (0..scale.saturating_mul(200))
        .map(|index| {
            let name = if index % 3 == 0 {
                String::from_utf8_lossy(&rng.delegate_name()).into_owned()
            } else {
                let pad = ["", " ", "\n", "\t", "\u{a0}", "\u{200b}", "\u{feff}", "\u{2028}", "\u{85}", "\u{3000}"];
                [rng.pick(&pad).copied().unwrap_or(""), &text_of(&mut rng, 70), rng.pick(&pad).copied().unwrap_or("")]
                    .concat()
            };
            json!([utf8(&name), name_is_valid(name.as_bytes())])
        })
        .collect();
    let reasons: Vec<Value> = (0..scale.saturating_mul(80))
        .map(|_| {
            // Around the limit, where the cut has to land between characters.
            let filler = ["a", "\u{e9}", "\u{65e5}", "\u{1f512}", "e\u{301}"];
            let mut reason = text_of(&mut rng, 30);
            let target = rng.below(30).saturating_add(500);
            while reason.len() < target {
                reason.push_str(rng.pick(&filler).copied().unwrap_or("a"));
            }
            json!([utf8(&reason), utf8(isudo_phone::clip_reason(&reason))])
        })
        .collect();

    let sections: [(&str, Vec<Value>); 10] = [
        ("requests", requests(&mut rng, scale.saturating_mul(450))),
        ("delegations", delegations(&mut rng, scale.saturating_mul(200))),
        ("links", links(&mut rng, scale.saturating_mul(200))),
        ("escape", escape_cases),
        ("env_risk", risk),
        ("hex", hex),
        ("b64", b64),
        ("names", names),
        ("reasons", reasons),
        ("codes", codes(&mut rng, scale.saturating_mul(60))),
    ];
    let mut out = String::from("{\n");
    writeln!(
        out,
        "\"about\": \"Inputs with the Rust reference's verdict on each, for other implementations to replay. \
         Generated by crates/sim/src/differential.rs; do not edit. Regenerate with `make vectors`.\","
    )
    .unwrap();
    for (index, (name, cases)) in sections.iter().enumerate() {
        writeln!(out, "\"{name}\": [").unwrap();
        for (at, case) in cases.iter().enumerate() {
            let comma = if at.saturating_add(1) == cases.len() { "" } else { "," };
            writeln!(out, "{case}{comma}").unwrap();
        }
        writeln!(out, "]{}", if index.saturating_add(1) == sections.len() { "" } else { "," }).unwrap();
    }
    out.push_str("}\n");
    out
}

const COMMITTED: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/differential.json");

/// The committed corpus is exactly what this code generates. With
/// `ISUDO_WRITE_CORPUS` set, writes it instead (`make vectors`); with a
/// path in `ISUDO_DIFFERENTIAL_OUT` and a scale in `ISUDO_DIFFERENTIAL_SCALE`,
/// writes a larger one there (`make differential`).
#[test]
fn the_committed_corpus_is_current() {
    if let Ok(path) = std::env::var("ISUDO_DIFFERENTIAL_OUT") {
        let scale = std::env::var("ISUDO_DIFFERENTIAL_SCALE").ok().and_then(|text| text.parse().ok()).unwrap_or(20);
        std::fs::write(&path, corpus(scale)).unwrap();
        return;
    }
    let generated = corpus(1);
    if std::env::var_os("ISUDO_WRITE_CORPUS").is_some() {
        std::fs::write(COMMITTED, &generated).unwrap();
        return;
    }
    let committed = std::fs::read_to_string(COMMITTED).unwrap_or_default();
    assert!(
        committed == generated,
        "testdata/differential.json is out of date: run `make vectors` and commit the result"
    );
}

/// The corpus is only worth replaying if it holds both kinds of case in
/// every section that has two kinds.
#[test]
fn the_corpus_exercises_both_acceptance_and_refusal() {
    let parsed: Value = serde_json::from_str(&corpus(1)).unwrap();
    for section in ["requests", "delegations", "links"] {
        let cases = parsed[section].as_array().unwrap();
        let accepted = cases.iter().filter(|case| case["ok"] == true).count();
        assert!(
            accepted * 5 > cases.len() && accepted * 5 < cases.len() * 4,
            "{section}: {accepted} of {}",
            cases.len()
        );
    }
    let requests = parsed["requests"].as_array().unwrap();
    let simple = requests.iter().filter(|case| case["simple"] == true).count();
    let marked = requests.iter().filter(|case| case["marked"] == true).count();
    assert!(simple > 20 && marked > 20, "{simple} simple, {marked} marked");
    for section in ["hex", "b64"] {
        let cases = parsed[section].as_array().unwrap();
        let refused = cases.iter().filter(|case| case[1].is_null()).count();
        assert!(refused > 20 && refused < cases.len().saturating_sub(20), "{section}: {refused} refused");
    }
    for section in ["env_risk", "names"] {
        let cases = parsed[section].as_array().unwrap();
        let yes = cases.iter().filter(|case| case[1] == true).count();
        assert!(yes > 20 && yes < cases.len().saturating_sub(20), "{section}: {yes} of {}", cases.len());
    }
    let escaped = parsed["escape"].as_array().unwrap();
    // 5c is a backslash: the mark of an escape.
    assert!(escaped.iter().filter(|case| case[1].as_str().unwrap().contains("5c")).count() > 100);
}
