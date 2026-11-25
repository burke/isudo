//! Generators for randomized tests: a seedable source of randomness and
//! arbitrary values of the wire types, tilted toward the awkward.
//!
//! Compiled only for tests (and for other crates' tests, through the
//! `testgen` feature). Nothing here reaches a shipped binary.
//!
//! Everything is deterministic in the seed, so a failure reproduces. How
//! many cases a test runs is `cases(default)`: the default in ordinary runs,
//! or `ISUDO_FUZZ_CASES` when set, for a long soak.

use crate::delegation::{Delegation, SignedDelegation, MAX_DELEGATE_NAME_LEN};
use crate::frame::{Failure, Job, Outcome};
use crate::request::{Ancestor, EnvOrigin, EnvVar, Request, StdinKind};

/// How many cases to run: `default`, unless `ISUDO_FUZZ_CASES` says otherwise.
#[must_use]
pub fn cases(default: usize) -> usize {
    std::env::var("ISUDO_FUZZ_CASES").ok().and_then(|text| text.parse().ok()).unwrap_or(default)
}

/// A tiny seedable generator (`SplitMix64`): enough to drive randomized
/// tests without a dependency.
#[derive(Debug, Clone)]
pub struct Rng(pub u64);

/// Text that display code must not let through as it is: escapes, controls,
/// ways of hiding or reordering characters, and bytes that are not text.
const AWKWARD: &[&[u8]] = &[
    b"\x1b[2K",
    b"\n",
    b"\r",
    b"\t",
    b"\0",
    b"\x7f",
    b"\\",
    b"\\n",
    b"\\x41",
    b"\\u{202e}",
    b" ",
    b"=",
    b"%",
    b"&",
    "\u{202e}".as_bytes(),  // right-to-left override
    "\u{2066}".as_bytes(),  // left-to-right isolate
    "\u{200b}".as_bytes(),  // zero-width space
    "\u{200d}".as_bytes(),  // zero-width joiner
    "\u{feff}".as_bytes(),  // byte-order mark
    "\u{00ad}".as_bytes(),  // soft hyphen
    "\u{e0041}".as_bytes(), // tag character
    "\u{fe0f}".as_bytes(),  // variation selector
    "\u{85}".as_bytes(),    // next line (a C1 control)
    "\u{2028}".as_bytes(),  // line separator
    "\u{5d0}".as_bytes(),   // a right-to-left letter
    "\u{430}".as_bytes(),   // a Cyrillic letter that looks Latin
    "\u{301}".as_bytes(),   // a combining accent
    "\u{e9}".as_bytes(),
    "\u{65e5}".as_bytes(),
    "\u{1f512}".as_bytes(),
    b"\xff",
    b"\xfe\x80",
    b"\xc0\xaf",         // an overlong encoding
    b"\xed\xa0\x80",     // a surrogate
    b"\xf4\x90\x80\x80", // past the last code point
    b"\xe2\x82",         // a truncated sequence
];

impl Rng {
    pub const fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A number below `bound` (or 0 if `bound` is 0).
    pub fn below(&mut self, bound: usize) -> usize {
        let bound = u64::try_from(bound.max(1)).unwrap_or(u64::MAX);
        usize::try_from(self.next_u64().checked_rem(bound).unwrap_or(0)).unwrap_or(0)
    }

    pub fn chance(&mut self, percent: usize) -> bool {
        self.below(100) < percent
    }

    pub const fn byte(&mut self) -> u8 {
        self.next_u64().to_le_bytes()[0]
    }

    /// Up to `max_len` arbitrary bytes.
    pub fn bytes(&mut self, max_len: usize) -> Vec<u8> {
        (0..self.below(max_len.saturating_add(1))).map(|_| self.byte()).collect()
    }

    pub fn array<const N: usize>(&mut self) -> [u8; N] {
        std::array::from_fn(|_| self.byte())
    }

    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> Option<&'a T> {
        items.get(self.below(items.len()))
    }

    /// Printable ASCII, at least one byte: what an ordinary argument is.
    pub fn plain(&mut self, max_len: usize) -> Vec<u8> {
        const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCXYZ0123456789-_./: =,@+";
        (0..=self.below(max_len.max(1))).map(|_| *self.pick(ALPHABET).unwrap_or(&b'a')).collect()
    }

    /// Bytes that are mostly text, laced with what display code must catch.
    pub fn text(&mut self, max_len: usize) -> Vec<u8> {
        let mut out = Vec::new();
        for _ in 0..self.below(8) {
            match self.below(10) {
                0..=4 => out.extend(self.plain(8)),
                5..=8 => out.extend_from_slice(self.pick(AWKWARD).copied().unwrap_or(b"")),
                _ => out.extend(self.bytes(3)),
            }
        }
        out.truncate(max_len);
        out
    }

    /// One of the three kinds of field content, so that requests come out
    /// plain often enough to be simple, and awkward often enough to matter.
    fn field(&mut self, max_len: usize, plain_percent: usize) -> Vec<u8> {
        if self.chance(plain_percent) {
            self.plain(max_len.min(24))
        } else if self.chance(70) {
            self.text(max_len)
        } else {
            self.bytes(max_len)
        }
    }

    /// An arbitrary request. About a third are plain throughout.
    ///
    /// # Panics
    /// Never: the codes drawn are always in range.
    pub fn request(&mut self) -> Request {
        // Decide once whether this one is to be plain, so that whole
        // requests are, not just individual fields.
        let plain = if self.chance(35) { 100 } else { 40 };
        let origins = [EnvOrigin::Default, EnvOrigin::Explicit, EnvOrigin::Constructed];
        let stdins = [
            StdinKind::Terminal,
            StdinKind::Null,
            StdinKind::Pipe,
            StdinKind::File,
            StdinKind::Socket,
            StdinKind::Other,
        ];
        Request {
            nonce: self.array(),
            pairing_id: self.array(),
            issued_at: self.next_u64(),
            ttl_secs: u32::from(self.byte()),
            uid: u32::try_from(self.below(70_000)).unwrap_or(0),
            gid: u32::try_from(self.below(70_000)).unwrap_or(0),
            user: self.field(12, plain),
            host: self.field(20, plain),
            cwd: self.field(60, plain),
            exe: self.field(60, plain),
            flags: if plain == 100 && self.chance(70) { 2 } else { self.byte() & 3 },
            stdin: if plain == 100 && self.chance(80) {
                StdinKind::Terminal
            } else {
                self.pick(&stdins).copied().unwrap_or(StdinKind::Other)
            },
            argv: (0..self.below(6)).map(|_| self.field(40, plain)).collect(),
            env: (0..self.below(4))
                .map(|_| EnvVar {
                    origin: if plain == 100 && self.chance(80) {
                        EnvOrigin::Default
                    } else {
                        self.pick(&origins).copied().unwrap_or(EnvOrigin::Default)
                    },
                    name: self.field(12, 80),
                    value: self.field(30, plain),
                })
                .collect(),
            ancestry: (0..self.below(4))
                .map(|_| Ancestor { pid: u32::try_from(self.below(99_999)).unwrap_or(0), name: self.field(16, 70) })
                .collect(),
        }
    }

    /// A name a delegation may carry.
    pub fn delegate_name(&mut self) -> Vec<u8> {
        const PIECES: &[&str] =
            &["Apple Watch", "Burke\u{2019}s", "watch", "\u{65e5}\u{672c}", "2", "\u{e9}t\u{e9}", "-", "x"];
        let mut name = String::new();
        for _ in 0..=self.below(4) {
            let piece = self.pick(PIECES).copied().unwrap_or("x");
            if name.len().saturating_add(piece.len()).saturating_add(1) > MAX_DELEGATE_NAME_LEN {
                break;
            }
            if !name.is_empty() {
                name.push(' ');
            }
            name.push_str(piece);
        }
        if name.is_empty() {
            b"x".to_vec()
        } else {
            name.into_bytes()
        }
    }

    /// An arbitrary well-formed delegation. Its signature is random bytes.
    pub fn delegation(&mut self) -> SignedDelegation {
        SignedDelegation {
            delegation: Delegation {
                pairing_id: self.array(),
                sign_pub: self.array(),
                kem_pub: self.array(),
                not_after: self.next_u64(),
                name: self.delegate_name(),
            },
            phone_sig: self.array(),
        }
    }

    /// An arbitrary well-formed outcome.
    pub fn outcome(&mut self) -> Outcome {
        let delegation = self.chance(40).then(|| self.delegation());
        match self.below(5) {
            0 | 1 => Outcome::Approved { sig: self.array(), delegation },
            2 | 3 => Outcome::Denied { sig: self.array(), reason: self.text(80), delegation },
            _ => {
                let failures = [
                    Failure::TimedOut,
                    Failure::Cancelled,
                    Failure::RelayUnreachable,
                    Failure::RelayRefused(u16::from(self.byte())),
                    Failure::Malformed,
                    Failure::Internal,
                ];
                Outcome::Failed { failure: self.pick(&failures).copied().unwrap_or(Failure::Internal) }
            }
        }
    }

    /// An arbitrary well-formed job.
    pub fn job(&mut self) -> Job {
        Job {
            relay_url: self.text(60),
            pairing_id: self.array(),
            phone_kem_pub: self.array(),
            phone_sign_pub: self.array(),
            delegates: self.chance(50),
            expires_at: self.next_u64(),
            timeout_secs: u32::from(self.byte()),
            ticket_sig: self.array(),
            host_sig: self.array(),
            request: self.bytes(200),
        }
    }

    /// Damages `bytes` a little, the way a hostile or broken sender might:
    /// a flipped bit, a changed byte, a cut, an addition, a length field
    /// altered, a piece repeated.
    pub fn mutate(&mut self, bytes: &mut Vec<u8>) {
        for _ in 0..=self.below(3) {
            if bytes.is_empty() {
                bytes.extend(self.bytes(4));
                continue;
            }
            let at = self.below(bytes.len());
            match self.below(7) {
                0 => {
                    if let Some(byte) = bytes.get_mut(at) {
                        *byte ^= 1_u8.rotate_left(u32::try_from(self.below(8)).unwrap_or(0));
                    }
                }
                1 => {
                    if let Some(byte) = bytes.get_mut(at) {
                        *byte = self.byte();
                    }
                }
                2 => bytes.truncate(at),
                3 => bytes.extend(self.bytes(8)),
                4 => {
                    // Often lands on a length or count: make it one more,
                    // one fewer, zero, or enormous.
                    if let Some(byte) = bytes.get_mut(at) {
                        *byte = match self.below(4) {
                            0 => byte.wrapping_add(1),
                            1 => byte.wrapping_sub(1),
                            2 => 0,
                            _ => 0xff,
                        };
                    }
                }
                5 => {
                    let piece: Vec<u8> = bytes.iter().skip(at).take(self.below(6)).copied().collect();
                    drop(bytes.splice(at..at, piece));
                }
                _ => {
                    let _removed = bytes.remove(at);
                }
            }
        }
    }
}
