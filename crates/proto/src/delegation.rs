//! A second approving device, authorised by the phone.
//!
//! The host pins one key: the phone's. A delegate (in practice, the person's
//! watch) has keys of its own, made on that device and never moved. The
//! phone signs a [`Delegation`] naming those keys, and the delegate presents
//! it alongside each answer. The host pins nothing new and the relay is
//! trusted for nothing new: a delegate's answer is two signatures, checked
//! in a chain that starts at the key the host already holds.
//!
//! A delegate is deliberately the lesser approver.
//!
//! - It has no camera and no face to check, so its idea of presence is
//!   weaker than the phone's: unlocked, and still on the wrist that unlocked
//!   it.
//! - Its screen is small. The point of the whole system is that the person
//!   reads what will run.
//!
//! So a delegate may approve only a request that is [`simple_enough`] to be
//! read in full on a small screen with nothing that needs explaining, and
//! only when the host's root-owned configuration allows delegates at all.
//! The host decides this itself and records the decision in the request it
//! signs ([`FLAG_DELEGABLE`](crate::request::FLAG_DELEGABLE)), then holds a
//! delegate's approval to it. A delegate may deny anything.

use crate::request::{EnvOrigin, Request, StdinKind, FLAG_EXE_WRITABLE};
use crate::wire::{Reader, WireError, Writer};
use crate::{PAIRING_ID_LEN, PUBKEY_LEN, SIG_LEN};

/// Context string for the phone's signature over a delegation.
pub const CTX_DELEGATE: &[u8] = b"isudo/v1/delegate\0";

/// Longest name a delegate may carry, in bytes of UTF-8.
pub const MAX_DELEGATE_NAME_LEN: usize = 64;
/// Longest a delegation may run, in seconds: about three months. The host
/// cannot see when a delegation was issued, only when it ends, so this is a
/// limit the phone keeps and the documentation states.
pub const MAX_DELEGATION_SECS: u64 = 90 * 24 * 60 * 60;
/// Upper bound on an encoded [`SignedDelegation`].
pub const MAX_SIGNED_DELEGATION_LEN: usize =
    PAIRING_ID_LEN + PUBKEY_LEN + PUBKEY_LEN + 8 + 4 + MAX_DELEGATE_NAME_LEN + SIG_LEN;

/// Most arguments a request may have and still be approved by a delegate.
pub const MAX_SIMPLE_ARGS: usize = 12;
/// Most bytes its arguments may total.
pub const MAX_SIMPLE_ARG_BYTES: usize = 240;
/// Longest program path or working directory.
pub const MAX_SIMPLE_PATH_LEN: usize = 128;

/// What the phone signs: these keys may answer for this pairing until then.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delegation {
    pub pairing_id: [u8; PAIRING_ID_LEN],
    /// The delegate's signing key, whose signatures count as answers.
    pub sign_pub: [u8; PUBKEY_LEN],
    /// The delegate's decryption key, to which requests are also sealed.
    pub kem_pub: [u8; PUBKEY_LEN],
    /// Unix time after which the host no longer honours this delegation.
    pub not_after: u64,
    /// What the delegate is called, for messages. Valid UTF-8 with no
    /// control characters; shown escaped all the same.
    pub name: Vec<u8>,
}

/// A delegation and the phone's signature over it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedDelegation {
    pub delegation: Delegation,
    pub phone_sig: [u8; SIG_LEN],
}

/// Whether a delegate may carry this name: some text, no longer than the
/// limit, with no surrounding space and no control characters.
#[must_use]
pub fn name_is_valid(name: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(name) else { return false };
    !text.is_empty()
        && text.len() <= MAX_DELEGATE_NAME_LEN
        && text.trim() == text
        && !text.chars().any(char::is_control)
}

impl Delegation {
    fn write(&self, w: &mut Writer) -> Result<(), WireError> {
        if !name_is_valid(&self.name) {
            return Err(WireError::Invalid("delegate name"));
        }
        w.raw(&self.pairing_id);
        w.raw(&self.sign_pub);
        w.raw(&self.kem_pub);
        w.u64(self.not_after);
        w.bytes(&self.name)
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, WireError> {
        let pairing_id = r.array("pairing id")?;
        let sign_pub = r.array("delegate signing key")?;
        let kem_pub = r.array("delegate decryption key")?;
        let not_after = r.u64("delegation expiry")?;
        let name = r.bytes("delegate name")?;
        if !name_is_valid(name) {
            return Err(WireError::Invalid("delegate name"));
        }
        Ok(Self { pairing_id, sign_pub, kem_pub, not_after, name: name.to_vec() })
    }

    /// The exact bytes the phone signs: the context string, then this
    /// delegation's one encoding.
    ///
    /// # Errors
    /// Fails if the name is not valid.
    pub fn message(&self) -> Result<Vec<u8>, WireError> {
        let mut w = Writer::new();
        w.raw(CTX_DELEGATE);
        self.write(&mut w)?;
        Ok(w.finish())
    }
}

impl SignedDelegation {
    /// # Errors
    /// Fails if the name is not valid.
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        let mut w = Writer::new();
        self.delegation.write(&mut w)?;
        w.raw(&self.phone_sig);
        Ok(w.finish())
    }

    /// # Errors
    /// Fails on anything that [`SignedDelegation::encode`] could not have
    /// produced.
    pub fn decode(input: &[u8]) -> Result<Self, WireError> {
        if input.len() > MAX_SIGNED_DELEGATION_LEN {
            return Err(WireError::TooLarge("delegation"));
        }
        let mut r = Reader::new(input);
        let delegation = Delegation::read(&mut r)?;
        let phone_sig = r.array("delegation signature")?;
        r.finish()?;
        Ok(Self { delegation, phone_sig })
    }
}

/// Printable ASCII, and at least one byte of it. Nothing that needs
/// escaping, nothing invisible, nothing laid out right to left, nothing
/// that looks like another character.
///
/// No backslash either. It is printable, but it is the one printable
/// character that is not shown as it is: display doubles it, so that an
/// escape can never be mistaken for text. A simple request is one whose
/// every character appears on screen exactly as it is in the command.
fn plain(bytes: &[u8]) -> bool {
    !bytes.is_empty() && bytes.iter().all(|byte| (0x20..=0x7e).contains(byte) && *byte != b'\\')
}

/// True if `request` can be read in full on a small screen with nothing that
/// needs explaining: the only kind a delegate may approve.
///
/// - Nothing the phone would warn about: the program cannot be replaced
///   without root, input is not arriving unseen on a pipe or from a file,
///   and the caller named no environment variables.
/// - Every piece of text is plain printable ASCII, so what is shown is what
///   there is.
/// - It is short.
///
/// The request's own `FLAG_DELEGABLE` bit is ignored: this is the rule that
/// decides it.
#[must_use]
pub fn simple_enough(request: &Request) -> bool {
    let quiet = request.flags & FLAG_EXE_WRITABLE == 0
        && matches!(request.stdin, StdinKind::Terminal | StdinKind::Null)
        && request.env.iter().all(|var| var.origin != EnvOrigin::Explicit);
    let readable = plain(&request.exe)
        && plain(&request.cwd)
        && plain(&request.host)
        && (request.user.is_empty() || plain(&request.user))
        && request.argv.iter().all(|arg| plain(arg));
    let argument_bytes = request.argv.iter().fold(0_usize, |total, arg| total.saturating_add(arg.len()));
    let short = !request.argv.is_empty()
        && request.argv.len() <= MAX_SIMPLE_ARGS
        && argument_bytes <= MAX_SIMPLE_ARG_BYTES
        && request.exe.len() <= MAX_SIMPLE_PATH_LEN
        && request.cwd.len() <= MAX_SIMPLE_PATH_LEN;
    quiet && readable && short
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::{Ancestor, EnvVar};

    fn delegation() -> Delegation {
        let mut key = [0x11; PUBKEY_LEN];
        key[0] = 0x04;
        Delegation {
            pairing_id: [0xa1; PAIRING_ID_LEN],
            sign_pub: key,
            kem_pub: [0x22; PUBKEY_LEN],
            not_after: 1_800_000_000,
            name: "Burke\u{2019}s Apple Watch".as_bytes().to_vec(),
        }
    }

    fn request() -> Request {
        Request {
            nonce: [7; 32],
            pairing_id: [0xa1; PAIRING_ID_LEN],
            issued_at: 1_795_000_000,
            ttl_secs: 120,
            uid: 501,
            gid: 20,
            user: b"burke".to_vec(),
            host: b"burke-mbp".to_vec(),
            cwd: b"/Users/burke".to_vec(),
            exe: b"/usr/sbin/nginx".to_vec(),
            flags: 0,
            stdin: StdinKind::Terminal,
            argv: vec![b"nginx".to_vec(), b"-s".to_vec(), b"reload".to_vec()],
            env: vec![EnvVar { origin: EnvOrigin::Default, name: b"TERM".to_vec(), value: b"xterm".to_vec() }],
            ancestry: vec![Ancestor { pid: 1, name: "z\u{200b}sh".as_bytes().to_vec() }],
        }
    }

    #[test]
    fn round_trips_and_is_strict() {
        let signed = SignedDelegation { delegation: delegation(), phone_sig: [0x5a; SIG_LEN] };
        let bytes = signed.encode().unwrap();
        assert!(bytes.len() <= MAX_SIGNED_DELEGATION_LEN);
        assert_eq!(SignedDelegation::decode(&bytes).unwrap(), signed);

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(SignedDelegation::decode(&trailing).is_err());
        assert!(SignedDelegation::decode(&bytes[..bytes.len() - 1]).is_err());
        assert!(SignedDelegation::decode(&[]).is_err());
        assert!(SignedDelegation::decode(&vec![0; MAX_SIGNED_DELEGATION_LEN + 1]).is_err());
    }

    #[test]
    fn the_longest_name_fits_the_bound() {
        let mut longest = delegation();
        longest.name = vec![b'x'; MAX_DELEGATE_NAME_LEN];
        let bytes = SignedDelegation { delegation: longest, phone_sig: [0; SIG_LEN] }.encode().unwrap();
        assert_eq!(bytes.len(), MAX_SIGNED_DELEGATION_LEN);
    }

    #[test]
    fn names_that_would_not_read_as_written_are_refused() {
        for bad in [&b""[..], b" padded", b"two\nlines", b"\xff\xfe", &[b'x'; MAX_DELEGATE_NAME_LEN + 1]] {
            let mut delegation = delegation();
            delegation.name = bad.to_vec();
            assert!(delegation.message().is_err(), "{bad:?}");
            assert!(SignedDelegation { delegation, phone_sig: [0; SIG_LEN] }.encode().is_err(), "{bad:?}");
        }
        // And a decoder never yields one, whatever it is handed.
        let good = SignedDelegation { delegation: delegation(), phone_sig: [0; SIG_LEN] }.encode().unwrap();
        let name_at = PAIRING_ID_LEN + PUBKEY_LEN + PUBKEY_LEN + 8 + 4;
        let mut bad = good;
        bad[name_at] = b'\n';
        assert_eq!(SignedDelegation::decode(&bad), Err(WireError::Invalid("delegate name")));
    }

    #[test]
    fn the_signed_message_covers_every_field() {
        let base = delegation().message().unwrap();
        assert!(base.starts_with(CTX_DELEGATE));
        let changes: [fn(&mut Delegation); 5] = [
            |d| d.pairing_id[0] ^= 1,
            |d| d.sign_pub[5] ^= 1,
            |d| d.kem_pub[5] ^= 1,
            |d| d.not_after += 1,
            |d| d.name.push(b'!'),
        ];
        for change in changes {
            let mut other = delegation();
            change(&mut other);
            assert_ne!(other.message().unwrap(), base);
        }
        // The two keys are not interchangeable.
        let mut swapped = delegation();
        std::mem::swap(&mut swapped.sign_pub, &mut swapped.kem_pub);
        assert_ne!(swapped.message().unwrap(), base);
    }

    #[test]
    fn an_ordinary_command_is_simple_enough() {
        assert!(simple_enough(&request()));
        // Stdin from nowhere is as quiet as a terminal.
        let mut detached = request();
        detached.stdin = StdinKind::Null;
        assert!(simple_enough(&detached));
        // Who asked is shown escaped and does not decide anything.
        let mut anonymous = request();
        anonymous.user.clear();
        anonymous.ancestry.clear();
        assert!(simple_enough(&anonymous));
    }

    #[test]
    fn anything_that_needs_explaining_is_not() {
        type Change = fn(&mut Request);
        let cases: [(&str, Change); 18] = [
            ("replaceable program", |r| r.flags |= FLAG_EXE_WRITABLE),
            ("piped input", |r| r.stdin = StdinKind::Pipe),
            ("input from a file", |r| r.stdin = StdinKind::File),
            ("a variable the caller named", |r| {
                r.env.push(EnvVar { origin: EnvOrigin::Explicit, name: b"DEBUG".to_vec(), value: b"1".to_vec() });
            }),
            ("a control character", |r| r.argv.push(b"a\x1b[2Kb".to_vec())),
            ("a newline", |r| r.argv.push(b"a\nb".to_vec())),
            ("a tab", |r| r.argv.push(b"a\tb".to_vec())),
            ("a backslash", |r| r.argv.push(b"C:\\temp".to_vec())),
            ("an escape written out as text", |r| r.argv.push(b"\\x1b[2K".to_vec())),
            ("an invisible character", |r| r.argv.push("a\u{200b}b".as_bytes().to_vec())),
            ("right-to-left text", |r| r.argv.push("/a/\u{5d0}/1".as_bytes().to_vec())),
            ("a lookalike letter", |r| r.argv.push("p\u{430}sswd".as_bytes().to_vec())),
            ("bytes that are not text", |r| r.argv.push(vec![0xff, 0xfe])),
            ("an empty argument", |r| r.argv.push(Vec::new())),
            ("an unusual program path", |r| r.exe = "/opt/caf\u{e9}/bin/x".as_bytes().to_vec()),
            ("an unusual folder", |r| r.cwd = b"/tmp/a\rb".to_vec()),
            ("an unusual computer name", |r| r.host = "b\u{fc}ro".as_bytes().to_vec()),
            ("an unusual user name", |r| r.user = b"bu\x00rke".to_vec()),
        ];
        for (what, change) in cases {
            let mut request = request();
            change(&mut request);
            assert!(!simple_enough(&request), "{what}");
        }
    }

    #[test]
    fn length_limits_are_exact() {
        let mut request = request();
        request.argv = vec![vec![b'a'; 20]; MAX_SIMPLE_ARGS];
        assert!(simple_enough(&request));
        request.argv.push(b"b".to_vec());
        assert!(!simple_enough(&request), "one argument too many");

        request.argv = vec![vec![b'a'; MAX_SIMPLE_ARG_BYTES]];
        assert!(simple_enough(&request));
        request.argv = vec![vec![b'a'; MAX_SIMPLE_ARG_BYTES], b"b".to_vec()];
        assert!(!simple_enough(&request), "one byte too many");

        request.argv = Vec::new();
        assert!(!simple_enough(&request), "no arguments at all");

        let mut request = self::request();
        request.exe = [&b"/"[..], &[b'x'; MAX_SIMPLE_PATH_LEN - 1]].concat();
        assert!(simple_enough(&request));
        request.exe.push(b'x');
        assert!(!simple_enough(&request));
        let mut request = self::request();
        request.cwd = vec![b'/'; MAX_SIMPLE_PATH_LEN + 1];
        assert!(!simple_enough(&request));
    }

    #[test]
    fn the_flag_itself_does_not_enter_into_it() {
        let mut flagged = request();
        flagged.flags |= crate::request::FLAG_DELEGABLE;
        assert!(simple_enough(&flagged));
    }
}
