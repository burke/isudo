//! The approval request: everything the approver needs to see, and exactly
//! what the setuid binary will execute if it is approved.
//!
//! Layout (all integers big-endian; `bytes` is a u32 length then the data):
//!
//! ```text
//! magic        8     "ISUDORQ" then the format version (1)
//! nonce        32    random, chosen by the setuid binary for this one process
//! pairing_id   16
//! issued_at    u64   unix seconds on the host (informational)
//! ttl_secs     u32   how long the setuid binary will wait
//! uid          u32   real uid of the caller, from the kernel
//! gid          u32   real gid of the caller, from the kernel
//! user         bytes account name for uid, may be empty
//! host         bytes host name from the root-owned pairing file
//! cwd          bytes working directory the command will run in
//! exe          bytes absolute path that will be exec'd
//! flags        u8    bit 0: exe or its directory is writable by a non-root user
//! stdin        u8    what the command's standard input is attached to
//! argv         u32 count, then bytes each
//! env          u32 count, then (u8 origin, bytes name, bytes value) each:
//!              the command's complete environment, in order
//! ancestry     u32 count, then (u32 pid, bytes name) each, nearest parent first
//! ```
//!
//! Decoding is strict: unknown enum values, reserved flag bits and trailing
//! bytes are all errors, so a decoder that accepts a request has seen all of it.

use crate::wire::{Reader, WireError, Writer};
use crate::{MAX_REQUEST_LEN, NONCE_LEN, PAIRING_ID_LEN};

pub const MAGIC: [u8; 8] = *b"ISUDORQ\x01";

pub const MAX_ARGS: usize = 4096;
pub const MAX_ENV: usize = 1024;
pub const MAX_ANCESTRY: usize = 16;

/// The executable, or the directory holding it, can be modified by a user
/// other than root. Approving the argv says little about what will run.
pub const FLAG_EXE_WRITABLE: u8 = 0x01;
const KNOWN_FLAGS: u8 = FLAG_EXE_WRITABLE;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StdinKind {
    Terminal,
    Null,
    Pipe,
    File,
    Socket,
    Other,
}

impl StdinKind {
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Terminal => 0,
            Self::Null => 1,
            Self::Pipe => 2,
            Self::File => 3,
            Self::Socket => 4,
            Self::Other => 5,
        }
    }

    const fn from_code(code: u8) -> Result<Self, WireError> {
        Ok(match code {
            0 => Self::Terminal,
            1 => Self::Null,
            2 => Self::Pipe,
            3 => Self::File,
            4 => Self::Socket,
            5 => Self::Other,
            _ => return Err(WireError::Invalid("stdin kind")),
        })
    }
}

/// Why an environment variable is being handed to the command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvOrigin {
    /// On the short list passed through by default (TERM, LANG, ...).
    Default,
    /// The caller asked for it with `NAME=value` or `--preserve-env`.
    Explicit,
    /// Built by isudo itself (`PATH`, `HOME`, `USER`, ...), not taken from
    /// the caller. Carried so that the signed request describes the whole
    /// environment the command receives, not only the caller's part.
    Constructed,
}

impl EnvOrigin {
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Default => 1,
            Self::Explicit => 2,
            Self::Constructed => 3,
        }
    }

    const fn from_code(code: u8) -> Result<Self, WireError> {
        Ok(match code {
            1 => Self::Default,
            2 => Self::Explicit,
            3 => Self::Constructed,
            _ => return Err(WireError::Invalid("env origin")),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvVar {
    pub origin: EnvOrigin,
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}

/// One process in the caller's ancestry. Names are chosen by the processes
/// themselves, so this is context for the approver, not an identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ancestor {
    pub pid: u32,
    pub name: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub nonce: [u8; NONCE_LEN],
    pub pairing_id: [u8; PAIRING_ID_LEN],
    pub issued_at: u64,
    pub ttl_secs: u32,
    pub uid: u32,
    pub gid: u32,
    pub user: Vec<u8>,
    pub host: Vec<u8>,
    pub cwd: Vec<u8>,
    pub exe: Vec<u8>,
    pub flags: u8,
    pub stdin: StdinKind,
    pub argv: Vec<Vec<u8>>,
    pub env: Vec<EnvVar>,
    pub ancestry: Vec<Ancestor>,
}

impl Request {
    /// # Errors
    /// Fails if a count or the encoded size is over its limit, or if a
    /// reserved flag bit is set.
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        if self.flags & !KNOWN_FLAGS != 0 {
            return Err(WireError::Invalid("flags"));
        }
        if self.argv.len() > MAX_ARGS {
            return Err(WireError::TooLarge("argument count"));
        }
        if self.env.len() > MAX_ENV {
            return Err(WireError::TooLarge("environment count"));
        }
        if self.ancestry.len() > MAX_ANCESTRY {
            return Err(WireError::TooLarge("ancestry count"));
        }

        let mut w = Writer::new();
        w.raw(&MAGIC);
        w.raw(&self.nonce);
        w.raw(&self.pairing_id);
        w.u64(self.issued_at);
        w.u32(self.ttl_secs);
        w.u32(self.uid);
        w.u32(self.gid);
        w.bytes(&self.user)?;
        w.bytes(&self.host)?;
        w.bytes(&self.cwd)?;
        w.bytes(&self.exe)?;
        w.u8(self.flags);
        w.u8(self.stdin.code());

        w.count(self.argv.len(), "argument count")?;
        for arg in &self.argv {
            w.bytes(arg)?;
        }
        w.count(self.env.len(), "environment count")?;
        for var in &self.env {
            w.u8(var.origin.code());
            w.bytes(&var.name)?;
            w.bytes(&var.value)?;
        }
        w.count(self.ancestry.len(), "ancestry count")?;
        for ancestor in &self.ancestry {
            w.u32(ancestor.pid);
            w.bytes(&ancestor.name)?;
        }

        if w.len() > MAX_REQUEST_LEN {
            return Err(WireError::TooLarge("request"));
        }
        Ok(w.finish())
    }

    /// # Errors
    /// Fails on anything that [`Request::encode`] could not have produced.
    pub fn decode(input: &[u8]) -> Result<Self, WireError> {
        if input.len() > MAX_REQUEST_LEN {
            return Err(WireError::TooLarge("request"));
        }
        let mut r = Reader::new(input);
        if r.array::<8>("magic")? != MAGIC {
            return Err(WireError::Invalid("magic or version"));
        }
        let nonce = r.array("nonce")?;
        let pairing_id = r.array("pairing id")?;
        let issued_at = r.u64("issued_at")?;
        let ttl_secs = r.u32("ttl")?;
        let uid = r.u32("uid")?;
        let gid = r.u32("gid")?;
        let user = r.bytes("user")?.to_vec();
        let host = r.bytes("host")?.to_vec();
        let cwd = r.bytes("cwd")?.to_vec();
        let exe = r.bytes("exe")?.to_vec();
        let flags = r.u8("flags")?;
        if flags & !KNOWN_FLAGS != 0 {
            return Err(WireError::Invalid("flags"));
        }
        let stdin = StdinKind::from_code(r.u8("stdin kind")?)?;

        let arg_count = r.count(MAX_ARGS, "argument count")?;
        let mut argv = Vec::with_capacity(arg_count.min(64));
        for _ in 0..arg_count {
            argv.push(r.bytes("argument")?.to_vec());
        }

        let env_count = r.count(MAX_ENV, "environment count")?;
        let mut env = Vec::with_capacity(env_count.min(64));
        for _ in 0..env_count {
            let origin = EnvOrigin::from_code(r.u8("env origin")?)?;
            let name = r.bytes("env name")?.to_vec();
            let value = r.bytes("env value")?.to_vec();
            env.push(EnvVar { origin, name, value });
        }

        let ancestors = r.count(MAX_ANCESTRY, "ancestry count")?;
        let mut ancestry = Vec::with_capacity(ancestors);
        for _ in 0..ancestors {
            let pid = r.u32("ancestor pid")?;
            let name = r.bytes("ancestor name")?.to_vec();
            ancestry.push(Ancestor { pid, name });
        }

        r.finish()?;
        Ok(Self {
            nonce,
            pairing_id,
            issued_at,
            ttl_secs,
            uid,
            gid,
            user,
            host,
            cwd,
            exe,
            flags,
            stdin,
            argv,
            env,
            ancestry,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER: &[u8] = b"burke";
    const HOST: &[u8] = b"burke-mbp";
    const CWD: &[u8] = b"/Users/burke/src/app";
    const EXE: &[u8] = b"/usr/bin/tee";

    fn sample() -> Request {
        Request {
            nonce: [7; 32],
            pairing_id: [9; 16],
            issued_at: 1_795_000_000,
            ttl_secs: 120,
            uid: 501,
            gid: 20,
            user: USER.to_vec(),
            host: HOST.to_vec(),
            cwd: CWD.to_vec(),
            exe: EXE.to_vec(),
            flags: 0,
            stdin: StdinKind::Pipe,
            argv: vec![b"tee".to_vec(), b"/etc/hosts".to_vec()],
            env: vec![
                EnvVar { origin: EnvOrigin::Default, name: b"TERM".to_vec(), value: b"xterm-256color".to_vec() },
                EnvVar {
                    origin: EnvOrigin::Explicit,
                    name: b"NODE_OPTIONS".to_vec(),
                    value: b"--require /tmp/x.js".to_vec(),
                },
            ],
            ancestry: vec![
                Ancestor { pid: 4242, name: b"zsh".to_vec() },
                Ancestor { pid: 4200, name: b"claude".to_vec() },
            ],
        }
    }

    /// Offset of the first length-prefixed field (the user name).
    const USER_LEN_AT: usize = 8 + 32 + 16 + 8 + 4 + 4 + 4;
    /// Offset of the flags byte in `sample()`.
    const FLAGS_AT: usize = USER_LEN_AT + 4 * 4 + USER.len() + HOST.len() + CWD.len() + EXE.len();

    #[test]
    fn round_trip() {
        let req = sample();
        let bytes = req.encode().unwrap();
        assert_eq!(Request::decode(&bytes).unwrap(), req);
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut bytes = sample().encode().unwrap();
        bytes.push(0);
        assert_eq!(Request::decode(&bytes), Err(WireError::TrailingBytes(1)));
    }

    #[test]
    fn rejects_every_truncation() {
        let bytes = sample().encode().unwrap();
        for len in 0..bytes.len() {
            assert!(Request::decode(&bytes[..len]).is_err(), "accepted prefix of {len} bytes");
        }
    }

    #[test]
    fn rejects_wrong_version() {
        let mut bytes = sample().encode().unwrap();
        bytes[7] = 2;
        assert_eq!(Request::decode(&bytes), Err(WireError::Invalid("magic or version")));
    }

    #[test]
    fn rejects_reserved_flags_and_unknown_enums() {
        let mut req = sample();
        req.flags = 0x80;
        assert!(req.encode().is_err());

        let good = sample().encode().unwrap();
        let mut bad = good.clone();
        bad[FLAGS_AT] = 0x02;
        assert_eq!(Request::decode(&bad), Err(WireError::Invalid("flags")));
        let mut bad = good;
        bad[FLAGS_AT + 1] = 9;
        assert_eq!(Request::decode(&bad), Err(WireError::Invalid("stdin kind")));
    }

    #[test]
    fn length_claims_are_checked_before_allocation() {
        let mut bytes = sample().encode().unwrap();
        // Claim a 4 GiB user name.
        bytes[USER_LEN_AT..USER_LEN_AT + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(Request::decode(&bytes), Err(WireError::Truncated("user")));
    }

    #[test]
    fn refuses_oversized_requests() {
        let mut req = sample();
        req.argv.push(vec![b'a'; MAX_REQUEST_LEN]);
        assert_eq!(req.encode(), Err(WireError::TooLarge("request")));
    }

    #[test]
    fn codes_round_trip() {
        for kind in [
            StdinKind::Terminal,
            StdinKind::Null,
            StdinKind::Pipe,
            StdinKind::File,
            StdinKind::Socket,
            StdinKind::Other,
        ] {
            assert_eq!(StdinKind::from_code(kind.code()), Ok(kind));
        }
        for origin in [EnvOrigin::Default, EnvOrigin::Explicit, EnvOrigin::Constructed] {
            assert_eq!(EnvOrigin::from_code(origin.code()), Ok(origin));
        }
        assert!(EnvOrigin::from_code(0).is_err());
    }

    /// A tiny seedable generator, enough to drive randomized tests without
    /// a dependency.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }

        fn below(&mut self, bound: usize) -> usize {
            let bound = u64::try_from(bound.max(1)).unwrap();
            usize::try_from(self.next().checked_rem(bound).unwrap()).unwrap()
        }

        fn bytes(&mut self, max_len: usize) -> Vec<u8> {
            (0..self.below(max_len)).map(|_| self.next().to_le_bytes()[0]).collect()
        }

        fn array<const N: usize>(&mut self) -> [u8; N] {
            std::array::from_fn(|_| self.next().to_le_bytes()[0])
        }

        fn request(&mut self) -> Request {
            Request {
                nonce: self.array(),
                pairing_id: self.array(),
                issued_at: self.next(),
                ttl_secs: self.next().to_le_bytes()[0].into(),
                uid: u32::try_from(self.below(70_000)).unwrap(),
                gid: u32::try_from(self.below(70_000)).unwrap(),
                user: self.bytes(12),
                host: self.bytes(20),
                cwd: self.bytes(60),
                exe: self.bytes(60),
                flags: u8::try_from(self.below(2)).unwrap(),
                stdin: StdinKind::from_code(u8::try_from(self.below(6)).unwrap()).unwrap(),
                argv: (0..self.below(6)).map(|_| self.bytes(40)).collect(),
                env: (0..self.below(4))
                    .map(|_| EnvVar {
                        origin: EnvOrigin::from_code(u8::try_from(self.below(3)).unwrap().saturating_add(1)).unwrap(),
                        name: self.bytes(12),
                        value: self.bytes(30),
                    })
                    .collect(),
                ancestry: (0..self.below(4))
                    .map(|_| Ancestor { pid: u32::try_from(self.below(99_999)).unwrap(), name: self.bytes(16) })
                    .collect(),
            }
        }
    }

    /// Encoding is injective and decoding is its exact inverse: every
    /// request has one byte string, and a byte string that decodes at all
    /// is the one encoding of what it decodes to. This is what makes a
    /// signature over the bytes a signature over the request.
    #[test]
    fn random_requests_round_trip() {
        let mut rng = Rng(0x15_0d0);
        for _ in 0..2000 {
            let request = rng.request();
            let bytes = request.encode().unwrap();
            assert_eq!(Request::decode(&bytes).unwrap(), request);
        }
    }

    /// No input makes the decoder panic, and anything it accepts re-encodes
    /// to exactly the bytes it was given (no two byte strings decode to the
    /// same request).
    #[test]
    fn mutated_bytes_never_panic_and_never_alias() {
        let mut rng = Rng(0xfeed);
        let mut accepted = 0_u32;
        for _ in 0..4000 {
            let mut bytes = rng.request().encode().unwrap();
            for _ in 0..=rng.below(3) {
                if bytes.is_empty() {
                    break;
                }
                match rng.below(4) {
                    0 => {
                        let at = rng.below(bytes.len());
                        bytes[at] ^= 1_u8.rotate_left(u32::try_from(rng.below(8)).unwrap());
                    }
                    1 => bytes.truncate(rng.below(bytes.len())),
                    2 => bytes.extend(rng.bytes(8)),
                    _ => {
                        let at = rng.below(bytes.len());
                        bytes[at] = rng.next().to_le_bytes()[0];
                    }
                }
            }
            if let Ok(decoded) = Request::decode(&bytes) {
                accepted = accepted.saturating_add(1);
                assert_eq!(decoded.encode().unwrap(), bytes, "a request decoded from bytes that are not its encoding");
            }
        }
        // Mutations that only touch free-form fields still decode; make
        // sure the aliasing check above actually ran.
        assert!(accepted > 100, "only {accepted} mutated inputs decoded");
    }

    #[test]
    fn random_garbage_never_panics() {
        let mut rng = Rng(7);
        for _ in 0..4000 {
            let mut bytes = rng.bytes(300);
            if rng.below(2) == 0 {
                // Give it a valid header so the fields get exercised.
                drop(bytes.splice(0..bytes.len().min(8), MAGIC));
            }
            if let Ok(decoded) = Request::decode(&bytes) {
                assert_eq!(decoded.encode().unwrap(), bytes);
            }
        }
    }
}
