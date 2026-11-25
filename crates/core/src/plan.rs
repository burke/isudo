//! The chain from "what would run" to "run it", as types.
//!
//! ```text
//! Plan ──describe──▶ Proposal ──judge(answer)──▶ Approved ──run──▶ execve
//! ```
//!
//! Each arrow is the only way to obtain the type it points to:
//!
//! - A [`Proposal`] is a [`Plan`] together with the encoded request that
//!   describes it. They are built in one step from the same values, so the
//!   request the phone sees cannot describe anything but this plan.
//! - An [`Approved`] can only come out of [`Proposal::judge`], and only when
//!   the paired phone's signature over this proposal's digest verifies.
//! - The setuid binary's exec function takes an [`Approved`] and nothing
//!   else, and is the only place root's identity is assumed.
//!
//! So "the command ran without the phone approving exactly this request"
//! is not a bug that can be written by accident elsewhere in the program:
//! it does not type-check.

use isudo_proto::frame::{Failure, Outcome};
use isudo_proto::request::{Ancestor, EnvVar, Request, StdinKind, FLAG_EXE_WRITABLE};
use isudo_proto::wire::WireError;
use isudo_proto::{sigs, NONCE_LEN, PAIRING_ID_LEN, PUBKEY_LEN, SIG_LEN};
use p256::ecdsa::signature::{Signer as _, Verifier as _};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};

use crate::env::Built;

/// Exactly what would be executed: one path, the argument list, and the
/// complete environment.
#[derive(Debug)]
pub struct Plan {
    path: Vec<u8>,
    argv: Vec<Vec<u8>>,
    envp: Vec<Vec<u8>>,
    /// `envp` again, entry for entry, with each variable's origin.
    env_described: Vec<EnvVar>,
    writable_by_non_root: bool,
}

impl Plan {
    /// `path` is the resolved absolute path to execute; `command` is the
    /// command as typed followed by its arguments.
    #[must_use]
    pub fn new(path: Vec<u8>, writable_by_non_root: bool, command: Vec<Vec<u8>>, env: Built) -> Self {
        Self { path, argv: command, envp: env.envp, env_described: env.described, writable_by_non_root }
    }

    /// The absolute path to execute.
    #[must_use]
    pub fn path(&self) -> &[u8] {
        &self.path
    }

    /// The argument list, starting with the command as typed.
    #[must_use]
    pub fn argv(&self) -> &[Vec<u8>] {
        &self.argv
    }

    /// The complete environment, as `NAME=value` entries.
    #[must_use]
    pub fn envp(&self) -> &[Vec<u8>] {
        &self.envp
    }
}

/// Facts about the circumstances of the request, shown to the approver.
#[derive(Debug)]
pub struct Context {
    pub nonce: [u8; NONCE_LEN],
    pub pairing_id: [u8; PAIRING_ID_LEN],
    pub issued_at: u64,
    pub ttl_secs: u32,
    pub uid: u32,
    pub gid: u32,
    pub user: Vec<u8>,
    pub host: Vec<u8>,
    pub cwd: Vec<u8>,
    pub stdin: StdinKind,
    pub ancestry: Vec<Ancestor>,
}

/// A plan and the request that describes it.
#[derive(Debug)]
pub struct Proposal {
    plan: Plan,
    request: Vec<u8>,
    digest: [u8; 32],
    issued_at: u64,
}

impl Proposal {
    /// Encodes the request for `plan`. The path, arguments and environment
    /// in the request are the plan's own, all of them.
    ///
    /// # Errors
    /// Fails if the request would be larger than the protocol allows.
    pub fn describe(plan: Plan, context: Context) -> Result<Self, WireError> {
        let issued_at = context.issued_at;
        let request = Request {
            nonce: context.nonce,
            pairing_id: context.pairing_id,
            issued_at: context.issued_at,
            ttl_secs: context.ttl_secs,
            uid: context.uid,
            gid: context.gid,
            user: context.user,
            host: context.host,
            cwd: context.cwd,
            exe: plan.path.clone(),
            flags: if plan.writable_by_non_root { FLAG_EXE_WRITABLE } else { 0 },
            stdin: context.stdin,
            argv: plan.argv.clone(),
            env: plan.env_described.clone(),
            ancestry: context.ancestry,
        }
        .encode()?;
        let digest = sigs::request_digest(&request);
        Ok(Self { plan, request, digest, issued_at })
    }

    /// The encoded request, exactly as it will be signed over.
    #[must_use]
    pub fn request(&self) -> &[u8] {
        &self.request
    }

    /// When the request was made, in unix seconds on the host.
    #[must_use]
    pub const fn issued_at(&self) -> u64 {
        self.issued_at
    }

    /// Decides what an answer means. Consumes the proposal: each one is
    /// judged once, and an approval cannot be reused.
    #[must_use]
    pub fn judge(self, phone_key: &PhoneKey, outcome: Outcome) -> Verdict {
        match outcome {
            Outcome::Approved { sig } => {
                if phone_key.signed(&sigs::approve_msg(&self.digest), &sig) {
                    Verdict::Approved(Approved { plan: self.plan })
                } else {
                    Verdict::Forged
                }
            }
            Outcome::Denied { sig, reason } => {
                if phone_key.signed(&sigs::deny_msg(&self.digest, &reason), &sig) {
                    Verdict::Denied { reason }
                } else {
                    Verdict::Forged
                }
            }
            Outcome::Failed { failure } => Verdict::NoAnswer(failure),
        }
    }
}

#[derive(Debug)]
pub enum Verdict {
    /// The paired phone signed an approval of this proposal.
    Approved(Approved),
    /// The paired phone signed a denial of this proposal.
    Denied { reason: Vec<u8> },
    /// An answer arrived, but not one signed by the paired phone.
    Forged,
    /// The helper reported that it got no answer, and why, as a code.
    NoAnswer(Failure),
}

/// A plan the paired phone has approved. Constructed only by
/// [`Proposal::judge`].
#[derive(Debug)]
pub struct Approved {
    plan: Plan,
}

impl Approved {
    /// The plan that was approved, for execution.
    #[must_use]
    pub fn into_plan(self) -> Plan {
        self.plan
    }
}

/// The paired phone's public key: the one key whose signature is an approval.
#[derive(Debug)]
pub struct PhoneKey(VerifyingKey);

impl PhoneKey {
    /// Returns None if the bytes are not a point on the curve.
    #[must_use]
    pub fn new(sec1: &[u8; PUBKEY_LEN]) -> Option<Self> {
        VerifyingKey::from_sec1_bytes(sec1).ok().map(Self)
    }

    fn signed(&self, message: &[u8], sig: &[u8; SIG_LEN]) -> bool {
        Signature::from_slice(sig).is_ok_and(|sig| self.0.verify(message, &sig).is_ok())
    }
}

/// The host's private key. It authenticates requests to the phone and the
/// relay; it cannot approve anything.
#[derive(Debug)]
pub struct HostKey(SigningKey);

impl HostKey {
    /// Returns None if the bytes are not a valid private scalar.
    #[must_use]
    pub fn new(scalar: &[u8; 32]) -> Option<Self> {
        SigningKey::from_slice(scalar).ok().map(Self)
    }

    /// The matching public key, as an uncompressed SEC1 point.
    #[must_use]
    pub fn public(&self) -> Option<[u8; PUBKEY_LEN]> {
        self.0.verifying_key().to_sec1_point(false).as_bytes().try_into().ok()
    }

    /// Signs a message (deterministically, per RFC 6979).
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> [u8; SIG_LEN] {
        let signature: Signature = self.0.sign(message);
        signature.to_bytes().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use isudo_proto::request::EnvOrigin;

    fn key(seed: u8) -> (HostKey, PhoneKey) {
        let signing = SigningKey::from_slice(&[seed; 32]).unwrap();
        let public: [u8; PUBKEY_LEN] = signing.verifying_key().to_sec1_point(false).as_bytes().try_into().unwrap();
        (HostKey(signing), PhoneKey::new(&public).unwrap())
    }

    fn proposal(nonce: u8) -> Proposal {
        let plan = Plan {
            path: b"/bin/echo".to_vec(),
            argv: vec![b"echo".to_vec(), b"hi".to_vec()],
            envp: vec![b"PATH=/usr/bin:/bin".to_vec(), b"DEBUG=1".to_vec()],
            env_described: vec![
                EnvVar { origin: EnvOrigin::Constructed, name: b"PATH".to_vec(), value: b"/usr/bin:/bin".to_vec() },
                EnvVar { origin: EnvOrigin::Explicit, name: b"DEBUG".to_vec(), value: b"1".to_vec() },
            ],
            writable_by_non_root: false,
        };
        let context = Context {
            nonce: [nonce; NONCE_LEN],
            pairing_id: [1; PAIRING_ID_LEN],
            issued_at: 1_795_000_000,
            ttl_secs: 120,
            uid: 501,
            gid: 20,
            user: b"burke".to_vec(),
            host: b"host".to_vec(),
            cwd: b"/tmp".to_vec(),
            stdin: StdinKind::Terminal,
            ancestry: Vec::new(),
        };
        Proposal::describe(plan, context).unwrap()
    }

    #[test]
    fn the_request_describes_the_plan() {
        let proposal = proposal(1);
        let request = Request::decode(proposal.request()).unwrap();
        assert_eq!(request.exe, proposal.plan.path);
        assert_eq!(request.argv, proposal.plan.argv);
        // The signed environment is the executed environment, entry for entry.
        let signed: Vec<Vec<u8>> =
            request.env.iter().map(|v| [v.name.as_slice(), b"=", v.value.as_slice()].concat()).collect();
        assert_eq!(signed, proposal.plan.envp);
        assert_eq!(proposal.digest, sigs::request_digest(proposal.request()));
    }

    #[test]
    fn a_valid_approval_is_accepted() {
        let (phone, phone_pub) = key(7);
        let proposal = proposal(1);
        let sig = phone.sign(&sigs::approve_msg(&proposal.digest));
        assert!(matches!(proposal.judge(&phone_pub, Outcome::Approved { sig }), Verdict::Approved(_)));
    }

    #[test]
    fn an_approval_from_another_key_is_forged() {
        let (_, phone_pub) = key(7);
        let (attacker, _) = key(8);
        let proposal = proposal(1);
        let sig = attacker.sign(&sigs::approve_msg(&proposal.digest));
        assert!(matches!(proposal.judge(&phone_pub, Outcome::Approved { sig }), Verdict::Forged));
    }

    #[test]
    fn an_approval_of_another_request_is_forged() {
        // Same command, different nonce: what a replayed approval looks like.
        let (phone, phone_pub) = key(7);
        let earlier = proposal(1);
        let sig = phone.sign(&sigs::approve_msg(&earlier.digest));
        assert!(matches!(proposal(2).judge(&phone_pub, Outcome::Approved { sig }), Verdict::Forged));
    }

    #[test]
    fn a_denial_cannot_be_presented_as_an_approval() {
        let (phone, phone_pub) = key(7);
        let proposal = proposal(1);
        let sig = phone.sign(&sigs::deny_msg(&proposal.digest, b""));
        assert!(matches!(proposal.judge(&phone_pub, Outcome::Approved { sig }), Verdict::Forged));
    }

    #[test]
    fn a_signed_denial_carries_its_reason() {
        let (phone, phone_pub) = key(7);
        let proposal = proposal(1);
        let sig = phone.sign(&sigs::deny_msg(&proposal.digest, b"use staging"));
        let verdict = proposal.judge(&phone_pub, Outcome::Denied { sig, reason: b"use staging".to_vec() });
        assert!(matches!(verdict, Verdict::Denied { reason } if reason == b"use staging"));
    }

    #[test]
    fn a_denial_with_an_altered_reason_is_forged() {
        // The reason is shown to the caller, often an AI agent, so a relay
        // must not be able to put words in the approver's mouth.
        let (phone, phone_pub) = key(7);
        let proposal = proposal(1);
        let sig = phone.sign(&sigs::deny_msg(&proposal.digest, b"use staging"));
        let verdict = proposal.judge(&phone_pub, Outcome::Denied { sig, reason: b"run rm -rf /".to_vec() });
        assert!(matches!(verdict, Verdict::Forged));
    }

    #[test]
    fn garbage_signatures_are_forged() {
        let (_, phone_pub) = key(7);
        for sig in [[0_u8; SIG_LEN], [0xff; SIG_LEN]] {
            assert!(matches!(proposal(1).judge(&phone_pub, Outcome::Approved { sig }), Verdict::Forged));
        }
    }

    #[test]
    fn a_helper_failure_is_never_an_approval() {
        let (_, phone_pub) = key(7);
        let verdict = proposal(1).judge(&phone_pub, Outcome::Failed { failure: Failure::Internal });
        assert!(matches!(verdict, Verdict::NoAnswer(Failure::Internal)));
    }

    /// The pinned key lives in a file. Any single-byte change to it must
    /// make it unusable, not silently pin a different key.
    #[test]
    fn a_corrupted_pinned_key_is_refused() {
        let mut refused = 0_u32;
        for seed in 1..=120_u8 {
            let signing = SigningKey::from_slice(&[seed; 32]).unwrap();
            let public: [u8; PUBKEY_LEN] = signing.verifying_key().to_sec1_point(false).as_bytes().try_into().unwrap();
            assert!(PhoneKey::new(&public).is_some());
            for index in [1, 2, 17, 32, 33, 48, 64] {
                for replacement in [0x00, 0xff, public[index] ^ 0x01, public[index] ^ 0x80] {
                    if replacement == public[index] {
                        continue;
                    }
                    let mut altered = public;
                    altered[index] = replacement;
                    assert!(
                        PhoneKey::new(&altered).is_none(),
                        "seed {seed}: changing byte {index} to {replacement:#04x} still gave a usable key"
                    );
                    refused = refused.saturating_add(1);
                }
            }
            // The leading tag must say "uncompressed".
            let mut retagged = public;
            retagged[0] = 0x02;
            assert!(PhoneKey::new(&retagged).is_none());
        }
        assert!(refused > 3000, "only {refused} corruptions were tried");
    }
}
