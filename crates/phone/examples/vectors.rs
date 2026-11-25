//! Prints test vectors for other implementations of the phone side (the iOS
//! app) as JSON. Everything is derived from fixed inputs except the HPKE
//! envelope, which is randomized by design; implementations check that it
//! opens to the stated plaintext.
//!
//! Regenerate with:
//!   cargo run -p isudo-phone --example vectors > testdata/vectors.json

use std::io::Write as _;

use isudo_client::envelope;
use isudo_proto::codec::{b64_encode, hex_encode};
use isudo_proto::delegation::{self, simple_enough, Delegation, SignedDelegation};
use isudo_proto::envrisk::is_risky;
use isudo_proto::pairing::{self, Offer, Parties};
use isudo_proto::request::{Ancestor, EnvOrigin, EnvVar, Request, StdinKind, FLAG_DELEGABLE, FLAG_EXE_WRITABLE};
use isudo_proto::text::escape;
use isudo_proto::{sigs, PUBKEY_LEN, SIG_LEN};
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use serde_json::{json, Value};

fn public_of(key: &SigningKey) -> Option<[u8; PUBKEY_LEN]> {
    key.verifying_key().to_sec1_point(false).as_bytes().try_into().ok()
}

fn sign(key: &SigningKey, message: &[u8]) -> [u8; SIG_LEN] {
    let signature: Signature = key.sign(message);
    signature.to_bytes().into()
}

fn request(pairing_id: [u8; 16]) -> Request {
    Request {
        nonce: [0x11; 32],
        pairing_id,
        issued_at: 1_795_000_000,
        ttl_secs: 120,
        uid: 501,
        gid: 20,
        user: b"burke".to_vec(),
        host: b"burke-mbp".to_vec(),
        cwd: b"/Users/burke/src/app".to_vec(),
        exe: b"/opt/homebrew/bin/node".to_vec(),
        flags: FLAG_EXE_WRITABLE,
        stdin: StdinKind::Pipe,
        argv: vec![
            b"node".to_vec(),
            b"-e".to_vec(),
            "console.log('caf\u{e9}')\n\u{202e}hidden\x1b[2K".as_bytes().to_vec(),
            b"\xff\xfe".to_vec(),
            Vec::new(),
        ],
        env: vec![
            EnvVar { origin: EnvOrigin::Constructed, name: b"PATH".to_vec(), value: b"/usr/bin:/bin".to_vec() },
            EnvVar { origin: EnvOrigin::Default, name: b"TERM".to_vec(), value: b"xterm-256color".to_vec() },
            EnvVar { origin: EnvOrigin::Explicit, name: b"DEBUG".to_vec(), value: b"1".to_vec() },
            EnvVar {
                origin: EnvOrigin::Explicit,
                name: b"NODE_OPTIONS".to_vec(),
                value: b"--require /tmp/x.js".to_vec(),
            },
        ],
        ancestry: vec![Ancestor { pid: 4242, name: b"zsh".to_vec() }, Ancestor { pid: 4200, name: b"claude".to_vec() }],
    }
}

fn request_json(request: &Request) -> Value {
    json!({
        "nonce_hex": hex_encode(&request.nonce),
        "pairing_id_hex": hex_encode(&request.pairing_id),
        "issued_at": request.issued_at,
        "ttl_secs": request.ttl_secs,
        "uid": request.uid,
        "gid": request.gid,
        "user_hex": hex_encode(&request.user),
        "host_hex": hex_encode(&request.host),
        "cwd_hex": hex_encode(&request.cwd),
        "exe_hex": hex_encode(&request.exe),
        "flags": request.flags,
        "stdin": request.stdin.code(),
        "argv_hex": request.argv.iter().map(|a| hex_encode(a)).collect::<Vec<_>>(),
        "env": request.env.iter().map(|v| json!({
            "origin": v.origin.code(),
            "name_hex": hex_encode(&v.name),
            "value_hex": hex_encode(&v.value),
        })).collect::<Vec<_>>(),
        "ancestry": request.ancestry.iter().map(|a| json!({
            "pid": a.pid,
            "name_hex": hex_encode(&a.name),
        })).collect::<Vec<_>>(),
    })
}

/// A request a watch may approve, and variations on it that it may not.
fn simple_request(pairing_id: [u8; 16]) -> Request {
    Request {
        nonce: [0x22; 32],
        pairing_id,
        issued_at: 1_795_000_000,
        ttl_secs: 120,
        uid: 501,
        gid: 20,
        user: b"burke".to_vec(),
        host: b"burke-mbp".to_vec(),
        cwd: b"/Users/burke".to_vec(),
        exe: b"/usr/sbin/nginx".to_vec(),
        flags: FLAG_DELEGABLE,
        stdin: StdinKind::Terminal,
        argv: vec![b"nginx".to_vec(), b"-s".to_vec(), b"reload".to_vec()],
        env: vec![EnvVar { origin: EnvOrigin::Default, name: b"TERM".to_vec(), value: b"xterm".to_vec() }],
        ancestry: vec![Ancestor { pid: 4242, name: b"zsh".to_vec() }],
    }
}

/// The watch section: a delegation, a watch's signatures, and the rule for
/// what a watch may approve, case by case.
fn delegation_vectors(phone: &SigningKey, pairing_id: [u8; 16]) -> Option<Value> {
    type Change = fn(&mut Request);
    let watch = SigningKey::from_slice(&[0x04; 32]).ok()?;
    let (watch_kem_private, watch_kem_pub) = envelope::derive(&[0x05; 32]).ok()?;
    let delegation = Delegation {
        pairing_id,
        sign_pub: public_of(&watch)?,
        kem_pub: watch_kem_pub,
        not_after: 1_802_776_000,
        name: "Burke\u{2019}s Apple Watch".as_bytes().to_vec(),
    };
    let message = delegation.message().ok()?;
    let signed = SignedDelegation { delegation: delegation.clone(), phone_sig: sign(phone, &message) };

    let base = simple_request(pairing_id);
    let bytes = base.encode().ok()?;
    let digest = sigs::request_digest(&bytes);
    let cases: [(&str, Change); 15] = [
        ("an ordinary command", |_| {}),
        ("no terminal attached", |r| r.stdin = StdinKind::Null),
        ("a program that can be replaced without root", |r| r.flags |= FLAG_EXE_WRITABLE),
        ("input arriving on a pipe", |r| r.stdin = StdinKind::Pipe),
        ("a variable the caller named", |r| {
            r.env.push(EnvVar { origin: EnvOrigin::Explicit, name: b"DEBUG".to_vec(), value: b"1".to_vec() });
        }),
        ("a control character", |r| r.argv.push(b"a\x1b[2Kb".to_vec())),
        ("an invisible character", |r| r.argv.push("a\u{200b}b".as_bytes().to_vec())),
        ("right-to-left text", |r| r.argv.push("/a/\u{5d0}/1".as_bytes().to_vec())),
        ("bytes that are not text", |r| r.argv.push(vec![0xff, 0xfe])),
        ("an empty argument", |r| r.argv.push(Vec::new())),
        ("a backslash", |r| r.argv.push(b"C:\\temp".to_vec())),
        ("an accented program path", |r| r.exe = "/opt/caf\u{e9}/bin/x".as_bytes().to_vec()),
        ("as many arguments as allowed", |r| r.argv = vec![b"a".to_vec(); delegation::MAX_SIMPLE_ARGS]),
        ("one argument too many", |r| r.argv = vec![b"a".to_vec(); delegation::MAX_SIMPLE_ARGS + 1]),
        ("arguments one byte too long", |r| r.argv = vec![vec![b'a'; delegation::MAX_SIMPLE_ARG_BYTES], b"b".to_vec()]),
    ];
    let mut simple = Vec::new();
    for (what, change) in cases {
        let mut request = simple_request(pairing_id);
        change(&mut request);
        simple.push(json!({
            "what": what,
            "request_hex": hex_encode(&request.encode().ok()?),
            "simple_enough": simple_enough(&request),
        }));
    }
    // The host's mark and the rule are separate: a watch needs both.
    let mut unmarked = simple_request(pairing_id);
    unmarked.flags = 0;

    Some(json!({
        "comment": "a watch the phone has authorised: see crates/proto/src/delegation.rs",
        "watch_sign_pub_b64": b64_encode(&delegation.sign_pub),
        "watch_kem_private_hex": hex_encode(&watch_kem_private),
        "watch_kem_pub_b64": b64_encode(&delegation.kem_pub),
        "not_after": delegation.not_after,
        "name": std::str::from_utf8(&delegation.name).ok()?,
        "message_hex": hex_encode(&message),
        "signed_hex": hex_encode(&signed.encode().ok()?),
        "phone_sig_b64": b64_encode(&signed.phone_sig),
        "request_hex": hex_encode(&bytes),
        "unmarked_request_hex": hex_encode(&unmarked.encode().ok()?),
        "watch_approve_sig_b64": b64_encode(&sign(&watch, &sigs::approve_msg(&digest))),
        "watch_deny_sig_b64": b64_encode(&sign(&watch, &sigs::deny_msg(&digest, b"not now"))),
        "watch_deny_reason": "not now",
        "limits": {
            "max_args": delegation::MAX_SIMPLE_ARGS,
            "max_arg_bytes": delegation::MAX_SIMPLE_ARG_BYTES,
            "max_path_len": delegation::MAX_SIMPLE_PATH_LEN,
            "max_name_len": delegation::MAX_DELEGATE_NAME_LEN,
            "max_delegation_secs": delegation::MAX_DELEGATION_SECS,
        },
        "simple_enough": simple,
    }))
}

#[expect(clippy::too_many_lines, reason = "one flat table of vectors reads better than scattered pieces")]
fn build() -> Option<Value> {
    let host = SigningKey::from_slice(&[0x01; 32]).ok()?;
    let phone = SigningKey::from_slice(&[0x02; 32]).ok()?;
    let host_pub = public_of(&host)?;
    let phone_sign_pub = public_of(&phone)?;
    let (kem_private, phone_kem_pub) = envelope::derive(&[0x03; 32]).ok()?;

    let host_nonce = [0x4e_u8; 16];
    let phone_nonce = [0x70_u8; 16];
    // A nonce the pairing code did not commit to, signed by the host key all
    // the same: what a pairing code written to steer the code would send.
    let other_nonce = [0x4f_u8; 16];
    let offer = Offer {
        relay_url: "https://relay.example:8443/base path".into(),
        pairing_id: [0xa1; 16],
        host_pub,
        secret: [0x3c; 32],
        commitment: pairing::commitment(&[0xa1; 16], &host_pub, &host_nonce),
        host_name: "burke\u{2019}s mbp".into(),
    };
    let parties = Parties {
        pairing_id: &offer.pairing_id,
        host_pub: &host_pub,
        phone_sign_pub: &phone_sign_pub,
        phone_kem_pub: &phone_kem_pub,
    };
    let phone_name = "Burke\u{2019}s iPhone";
    let ack = sigs::pair_ack_msg(&offer.pairing_id, &phone_sign_pub, &phone_kem_pub, &phone_nonce, &host_nonce);
    let steered = sigs::pair_ack_msg(&offer.pairing_id, &phone_sign_pub, &phone_kem_pub, &phone_nonce, &other_nonce);

    let request = request(offer.pairing_id);
    let bytes = request.encode().ok()?;
    let digest = sigs::request_digest(&bytes);
    let host_sig = sign(&host, &sigs::host_request_msg(&bytes));
    let sealed = envelope::seal(&phone_kem_pub, &offer.pairing_id, &host_sig, &bytes).ok()?;
    let reason = "use the staging database";

    let escapes: Vec<&[u8]> = vec![
        b"plain text",
        "caf\u{e9} \u{65e5}\u{672c}".as_bytes(),
        b"line\nbreak\ttab\rreturn\\slash",
        b"esc\x1b[2K nul\x00 del\x7f",
        "bidi\u{202e}txt zw\u{200b}sp bom\u{feff} tag\u{e0041}".as_bytes(),
        b"bad\xff\xfe\x80utf8 \xc0\x0a",
        b"",
    ];
    let risky = [
        "LD_PRELOAD",
        "DYLD_INSERT_LIBRARIES",
        "BASH_ENV",
        "PYTHONPATH",
        "NODE_OPTIONS",
        "PATH",
        "GIT_SSH_COMMAND",
        "GIT_CONFIG_GLOBAL",
        "PERL5LIB",
        "BASH_FUNC_x%%",
        "HOME",
        "RUBYOPT",
        "TMPDIR",
    ];
    let safe = ["TERM", "LANG", "LC_ALL", "TZ", "DEBUG", "MY_APP_TOKEN", "CI", "NO_COLOR", "FOO"];
    if !risky.iter().all(|n| is_risky(n.as_bytes())) || safe.iter().any(|n| is_risky(n.as_bytes())) {
        return None;
    }

    let link = offer.to_url();
    let invalid_links = vec![
        link.replace("v=2", "v=3"),
        // The previous version, which carried no commitment.
        link.replace("v=2", "v=1").split('&').filter(|f| !f.starts_with("c=")).collect::<Vec<_>>().join("&"),
        link.split('&').filter(|f| !f.starts_with("c=")).collect::<Vec<_>>().join("&"),
        [link.as_str(), "&x=1"].concat(),
        [link.as_str(), "&v=2"].concat(),
        "https://example.com/?v=2".to_owned(),
    ];
    let plaintext = [host_sig.as_slice(), &bytes].concat();
    let trailing = [bytes.as_slice(), &[0]].concat();
    let wrong_version = [b"ISUDORQ\x02".as_slice(), bytes.get(8..)?].concat();

    Some(json!({
        "about": "Test vectors for the phone side of isudo. Generated by crates/phone/examples/vectors.rs.",
        "codec": {
            "comment": "base64url is unpadded and strict",
            "b64": [["", ""], ["66", "Zg"], ["666f", "Zm8"], ["666f6f", "Zm9v"], ["fbff", "-_8"]],
            "b64_invalid": ["Zg==", "Zh", "Z", "+/8", "Zm9"],
        },
        "request": {
            "bytes_hex": hex_encode(&bytes),
            "fields": request_json(&request),
            "digest_hex": hex_encode(&digest),
            "request_id_hex": hex_encode(&sigs::request_id(&bytes)),
            "invalid_bytes_hex": {
                "trailing_byte": hex_encode(&trailing),
                "truncated": hex_encode(bytes.get(..bytes.len().saturating_sub(1))?),
                "wrong_version": hex_encode(&wrong_version),
            },
        },
        "messages": {
            "comment": "the exact bytes each signature covers",
            "host_request_hex": hex_encode(&sigs::host_request_msg(&bytes)),
            "approve_hex": hex_encode(&sigs::approve_msg(&digest)),
            "deny_reason": reason,
            "deny_hex": hex_encode(&sigs::deny_msg(&digest, reason.as_bytes())),
            "deny_empty_hex": hex_encode(&sigs::deny_msg(&digest, b"")),
            "pair_ack_hex": hex_encode(&ack),
            "pair_confirm_hex": hex_encode(&sigs::pair_confirm_msg(&offer.pairing_id, &phone_sign_pub, &phone_kem_pub)),
            "envelope_info_hex": hex_encode(&sigs::envelope_info(&offer.pairing_id)),
        },
        "signatures": {
            "comment": "ECDSA P-256 over SHA-256 of the message, raw r||s",
            "host_pub_b64": b64_encode(&host_pub),
            "host_request_sig_b64": b64_encode(&host_sig),
            "pair_ack_sig_b64": b64_encode(&sign(&host, &ack)),
            "pair_ack_uncommitted_sig_b64": b64_encode(&sign(&host, &steered)),
            "pair_confirm_sig_b64": b64_encode(&sign(
                &host, &sigs::pair_confirm_msg(&offer.pairing_id, &phone_sign_pub, &phone_kem_pub))),
            "phone_sign_pub_b64": b64_encode(&phone_sign_pub),
            "approve_sig_b64": b64_encode(&sign(&phone, &sigs::approve_msg(&digest))),
            "deny_sig_b64": b64_encode(&sign(&phone, &sigs::deny_msg(&digest, reason.as_bytes()))),
        },
        "pairing": {
            "link": link,
            "relay_url": offer.relay_url,
            "pairing_id_hex": hex_encode(&offer.pairing_id),
            "host_pub_b64": b64_encode(&host_pub),
            "secret_b64": b64_encode(&offer.secret),
            "host_name": offer.host_name,
            "phone_sign_pub_b64": b64_encode(&phone_sign_pub),
            "phone_kem_pub_b64": b64_encode(&phone_kem_pub),
            "phone_name": phone_name,
            "commitment_b64": b64_encode(&offer.commitment),
            "host_nonce_b64": b64_encode(&host_nonce),
            "uncommitted_nonce_b64": b64_encode(&other_nonce),
            "phone_nonce_b64": b64_encode(&phone_nonce),
            "claim_mac_b64": b64_encode(&pairing::claim_mac(
                &offer.secret, &parties, &phone_nonce, phone_name.as_bytes())),
            "confirmation_code": pairing::confirmation_code(&offer.secret, &parties, &host_nonce, &phone_nonce),
            "invalid_links": invalid_links,
        },
        "envelope": {
            "comment": "HPKE base mode, DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-256-GCM; \
                        envelope = 65-byte encapsulated key || ciphertext; plaintext = host_sig || request; \
                        info = messages.envelope_info_hex; empty AAD",
            "kem_private_hex": hex_encode(&kem_private),
            "kem_public_b64": b64_encode(&phone_kem_pub),
            "envelope_b64": b64_encode(&sealed),
            "plaintext_hex": hex_encode(&plaintext),
        },
        "delegation": delegation_vectors(&phone, offer.pairing_id)?,
        "escape": escapes.iter().map(|input| json!([hex_encode(input), escape(input)])).collect::<Vec<_>>(),
        "env_risk": { "risky": risky, "safe": safe },
    }))
}

fn main() -> std::process::ExitCode {
    let Some(vectors) = build() else { return std::process::ExitCode::FAILURE };
    let Ok(text) = serde_json::to_string_pretty(&vectors) else { return std::process::ExitCode::FAILURE };
    let mut out = std::io::stdout().lock();
    if out.write_all(text.as_bytes()).and_then(|()| out.write_all(b"\n")).is_err() {
        return std::process::ExitCode::FAILURE;
    }
    std::process::ExitCode::SUCCESS
}
