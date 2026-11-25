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

use isudo_proto::delegation::{simple_enough, SignedDelegation};
use isudo_proto::frame::{Failure, Outcome};
use isudo_proto::request::{Ancestor, EnvVar, Request, StdinKind, FLAG_DELEGABLE, FLAG_EXE_WRITABLE};
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
    /// Whether the pairing file allows a watch to answer at all.
    pub watch: bool,
}

/// A plan and the request that describes it.
#[derive(Debug)]
pub struct Proposal {
    plan: Plan,
    request: Vec<u8>,
    digest: [u8; 32],
    issued_at: u64,
    pairing_id: [u8; PAIRING_ID_LEN],
    /// The pairing file allows a watch to answer.
    watch: bool,
    /// This request was marked, in its signed bytes, as one a watch may
    /// approve. A watch's approval of any other request is refused.
    delegable: bool,
}

impl Proposal {
    /// Encodes the request for `plan`. The path, arguments and environment
    /// in the request are the plan's own, all of them.
    ///
    /// # Errors
    /// Fails if the request would be larger than the protocol allows.
    pub fn describe(plan: Plan, context: Context) -> Result<Self, WireError> {
        let (issued_at, pairing_id, watch) = (context.issued_at, context.pairing_id, context.watch);
        let mut request = Request {
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
        };
        // Decided here, once, and written into the bytes that get signed: a
        // watch shows an Approve control for exactly the requests this host
        // will honour it on.
        let delegable = watch && simple_enough(&request);
        if delegable {
            request.flags |= FLAG_DELEGABLE;
        }
        let request = request.encode()?;
        let digest = sigs::request_digest(&request);
        Ok(Self { plan, request, digest, issued_at, pairing_id, watch, delegable })
    }

    /// The encoded request, exactly as it will be signed over.
    #[must_use]
    pub fn request(&self) -> &[u8] {
        &self.request
    }

    /// Whether this request was marked as one a watch may approve.
    #[must_use]
    pub const fn watch_may_approve(&self) -> bool {
        self.delegable
    }

    /// When the request was made, in unix seconds on the host.
    #[must_use]
    pub const fn issued_at(&self) -> u64 {
        self.issued_at
    }

    /// Decides what an answer means. Consumes the proposal: each one is
    /// judged once, and an approval cannot be reused.
    ///
    /// `now` is the host's clock in unix seconds, for a delegation's expiry.
    #[must_use]
    pub fn judge(self, phone_key: &PhoneKey, outcome: Outcome, now: u64) -> Verdict {
        match outcome {
            Outcome::Approved { sig, delegation } => match self.answerer(phone_key, delegation.as_ref(), now, true) {
                Ok((key, _)) if key.signed(&sigs::approve_msg(&self.digest), &sig) => {
                    Verdict::Approved(Approved { plan: self.plan })
                }
                Ok(_) => Verdict::Forged,
                Err(verdict) => verdict,
            },
            Outcome::Denied { sig, reason, delegation } => {
                match self.answerer(phone_key, delegation.as_ref(), now, false) {
                    Ok((key, by)) if key.signed(&sigs::deny_msg(&self.digest, &reason), &sig) => {
                        Verdict::Denied { reason, by }
                    }
                    Ok(_) => Verdict::Forged,
                    Err(verdict) => verdict,
                }
            }
            Outcome::Failed { failure } => Verdict::NoAnswer(failure),
        }
    }

    /// Whose signature would count as this answer: the phone's, or that of a
    /// watch the phone authorised. Every reason to refuse a watch is here.
    fn answerer(
        &self,
        phone_key: &PhoneKey,
        delegation: Option<&SignedDelegation>,
        now: u64,
        approving: bool,
    ) -> Result<(PhoneKey, Answerer), Verdict> {
        let Some(signed) = delegation else {
            return Ok((PhoneKey(phone_key.0), Answerer::Phone));
        };
        let delegation = &signed.delegation;
        if !self.watch {
            return Err(Verdict::WatchRefused(WatchRefusal::Off));
        }
        // The chain starts at the key this host pinned: the phone signed for
        // these keys, for this pairing.
        let authorised = delegation.pairing_id == self.pairing_id
            && delegation.message().is_ok_and(|message| phone_key.signed(&message, &signed.phone_sig));
        let Some(key) = PhoneKey::new(&delegation.sign_pub).filter(|_| authorised) else {
            return Err(Verdict::Forged);
        };
        if now > delegation.not_after {
            return Err(Verdict::WatchRefused(WatchRefusal::Expired));
        }
        // A watch may deny anything. It may approve only what this host
        // marked, in the request itself, as simple enough to read on one.
        if approving && !self.delegable {
            return Err(Verdict::WatchRefused(WatchRefusal::NotSimple));
        }
        Ok((key, Answerer::Watch(delegation.name.clone())))
    }
}

/// Which device signed an answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answerer {
    Phone,
    /// A watch the phone authorised, with the name the phone signed for it.
    Watch(Vec<u8>),
}

/// Why a properly authorised watch's answer was not honoured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchRefusal {
    /// The pairing file does not allow a watch to answer.
    Off,
    /// The phone's authorisation of the watch has run out.
    Expired,
    /// The watch approved a request that only the phone may approve.
    NotSimple,
}

#[derive(Debug)]
pub enum Verdict {
    /// The paired phone, or a watch it authorised, signed an approval of
    /// this proposal.
    Approved(Approved),
    /// One of them signed a denial of this proposal.
    Denied { reason: Vec<u8>, by: Answerer },
    /// An answer arrived, but not one signed by the paired phone or by a
    /// watch the phone authorised for this pairing.
    Forged,
    /// A watch answered, with the phone's authority, and this host does not
    /// honour it.
    WatchRefused(WatchRefusal),
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
    use isudo_proto::delegation::Delegation;
    use isudo_proto::request::EnvOrigin;

    fn key(seed: u8) -> (HostKey, PhoneKey) {
        let signing = SigningKey::from_slice(&[seed; 32]).unwrap();
        let public: [u8; PUBKEY_LEN] = signing.verifying_key().to_sec1_point(false).as_bytes().try_into().unwrap();
        (HostKey(signing), PhoneKey::new(&public).unwrap())
    }

    const NOW: u64 = 1_795_000_030;

    /// `echo hi`, with a variable the caller named: not simple enough for a
    /// watch, whatever the pairing file says.
    fn proposal(nonce: u8) -> Proposal {
        described(nonce, true, true)
    }

    fn described(nonce: u8, names_a_variable: bool, watch: bool) -> Proposal {
        let mut plan = Plan {
            path: b"/bin/echo".to_vec(),
            argv: vec![b"echo".to_vec(), b"hi".to_vec()],
            envp: vec![b"PATH=/usr/bin:/bin".to_vec()],
            env_described: vec![EnvVar {
                origin: EnvOrigin::Constructed,
                name: b"PATH".to_vec(),
                value: b"/usr/bin:/bin".to_vec(),
            }],
            writable_by_non_root: false,
        };
        if names_a_variable {
            plan.envp.push(b"DEBUG=1".to_vec());
            plan.env_described.push(EnvVar {
                origin: EnvOrigin::Explicit,
                name: b"DEBUG".to_vec(),
                value: b"1".to_vec(),
            });
        }
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
            watch,
        };
        Proposal::describe(plan, context).unwrap()
    }

    /// A simple request on a host that allows a watch.
    fn simple() -> Proposal {
        described(1, false, true)
    }

    /// A watch's keys and the phone's authorisation of them.
    fn watch_of(phone: &HostKey, seed: u8, change: impl FnOnce(&mut Delegation)) -> (HostKey, SignedDelegation) {
        let (watch, _) = key(seed);
        let mut delegation = Delegation {
            pairing_id: [1; PAIRING_ID_LEN],
            sign_pub: watch.public().unwrap(),
            kem_pub: key(seed.wrapping_add(1)).0.public().unwrap(),
            not_after: NOW + 1000,
            name: b"Test Watch".to_vec(),
        };
        change(&mut delegation);
        let phone_sig = phone.sign(&delegation.message().unwrap());
        (watch, SignedDelegation { delegation, phone_sig })
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
        assert!(matches!(
            proposal.judge(&phone_pub, Outcome::Approved { sig, delegation: None }, NOW),
            Verdict::Approved(_)
        ));
    }

    #[test]
    fn an_approval_from_another_key_is_forged() {
        let (_, phone_pub) = key(7);
        let (attacker, _) = key(8);
        let proposal = proposal(1);
        let sig = attacker.sign(&sigs::approve_msg(&proposal.digest));
        assert!(matches!(
            proposal.judge(&phone_pub, Outcome::Approved { sig, delegation: None }, NOW),
            Verdict::Forged
        ));
    }

    #[test]
    fn an_approval_of_another_request_is_forged() {
        // Same command, different nonce: what a replayed approval looks like.
        let (phone, phone_pub) = key(7);
        let earlier = proposal(1);
        let sig = phone.sign(&sigs::approve_msg(&earlier.digest));
        assert!(matches!(
            proposal(2).judge(&phone_pub, Outcome::Approved { sig, delegation: None }, NOW),
            Verdict::Forged
        ));
    }

    #[test]
    fn a_denial_cannot_be_presented_as_an_approval() {
        let (phone, phone_pub) = key(7);
        let proposal = proposal(1);
        let sig = phone.sign(&sigs::deny_msg(&proposal.digest, b""));
        assert!(matches!(
            proposal.judge(&phone_pub, Outcome::Approved { sig, delegation: None }, NOW),
            Verdict::Forged
        ));
    }

    #[test]
    fn a_signed_denial_carries_its_reason() {
        let (phone, phone_pub) = key(7);
        let proposal = proposal(1);
        let sig = phone.sign(&sigs::deny_msg(&proposal.digest, b"use staging"));
        let verdict =
            proposal.judge(&phone_pub, Outcome::Denied { sig, reason: b"use staging".to_vec(), delegation: None }, NOW);
        assert!(matches!(verdict, Verdict::Denied { reason, by: Answerer::Phone } if reason == b"use staging"));
    }

    #[test]
    fn a_denial_with_an_altered_reason_is_forged() {
        // The reason is shown to the caller, often an AI agent, so a relay
        // must not be able to put words in the approver's mouth.
        let (phone, phone_pub) = key(7);
        let proposal = proposal(1);
        let sig = phone.sign(&sigs::deny_msg(&proposal.digest, b"use staging"));
        let verdict = proposal.judge(
            &phone_pub,
            Outcome::Denied { sig, reason: b"run rm -rf /".to_vec(), delegation: None },
            NOW,
        );
        assert!(matches!(verdict, Verdict::Forged));
    }

    #[test]
    fn garbage_signatures_are_forged() {
        let (_, phone_pub) = key(7);
        for sig in [[0_u8; SIG_LEN], [0xff; SIG_LEN]] {
            assert!(matches!(
                proposal(1).judge(&phone_pub, Outcome::Approved { sig, delegation: None }, NOW),
                Verdict::Forged
            ));
        }
    }

    #[test]
    fn a_helper_failure_is_never_an_approval() {
        let (_, phone_pub) = key(7);
        let verdict = proposal(1).judge(&phone_pub, Outcome::Failed { failure: Failure::Internal }, NOW);
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

    #[test]
    fn a_request_is_marked_for_the_watch_only_when_simple_and_allowed() {
        let flags = |proposal: &Proposal| Request::decode(proposal.request()).unwrap().flags;
        assert_eq!(flags(&described(1, false, true)), FLAG_DELEGABLE);
        assert_eq!(flags(&described(1, false, false)), 0, "the pairing file does not allow a watch");
        assert_eq!(flags(&described(1, true, true)), 0, "the caller named a variable");
        assert!(simple().delegable && !proposal(1).delegable);
    }

    #[test]
    fn an_authorised_watch_may_approve_a_simple_request() {
        let (phone, phone_pub) = key(7);
        let (watch, delegation) = watch_of(&phone, 20, |_| {});
        let proposal = simple();
        let sig = watch.sign(&sigs::approve_msg(&proposal.digest));
        let outcome = Outcome::Approved { sig, delegation: Some(delegation) };
        assert!(matches!(proposal.judge(&phone_pub, outcome, NOW), Verdict::Approved(_)));
    }

    #[test]
    fn the_phone_may_still_approve_what_a_watch_could() {
        let (phone, phone_pub) = key(7);
        let proposal = simple();
        let sig = phone.sign(&sigs::approve_msg(&proposal.digest));
        assert!(matches!(
            proposal.judge(&phone_pub, Outcome::Approved { sig, delegation: None }, NOW),
            Verdict::Approved(_)
        ));
    }

    #[test]
    fn a_watch_may_not_approve_what_only_the_phone_may() {
        let (phone, phone_pub) = key(7);
        let (watch, delegation) = watch_of(&phone, 20, |_| {});
        let proposal = proposal(1);
        let sig = watch.sign(&sigs::approve_msg(&proposal.digest));
        let verdict = proposal.judge(&phone_pub, Outcome::Approved { sig, delegation: Some(delegation) }, NOW);
        assert!(matches!(verdict, Verdict::WatchRefused(WatchRefusal::NotSimple)));
    }

    #[test]
    fn a_watch_may_deny_anything_and_its_name_is_the_one_the_phone_signed() {
        let (phone, phone_pub) = key(7);
        let (watch, delegation) = watch_of(&phone, 20, |_| {});
        let proposal = proposal(1);
        let sig = watch.sign(&sigs::deny_msg(&proposal.digest, b"not now"));
        let outcome = Outcome::Denied { sig, reason: b"not now".to_vec(), delegation: Some(delegation) };
        let verdict = proposal.judge(&phone_pub, outcome, NOW);
        assert!(
            matches!(verdict, Verdict::Denied { reason, by: Answerer::Watch(name) } if reason == b"not now" && name == b"Test Watch")
        );
    }

    #[test]
    fn a_watch_counts_for_nothing_unless_the_pairing_file_allows_one() {
        let (phone, phone_pub) = key(7);
        let (watch, delegation) = watch_of(&phone, 20, |_| {});
        // The same simple request, on a host whose root has not turned the
        // watch on. Neither an approval nor a denial is honoured.
        let proposal = described(1, false, false);
        let sig = watch.sign(&sigs::approve_msg(&proposal.digest));
        let verdict = proposal.judge(&phone_pub, Outcome::Approved { sig, delegation: Some(delegation.clone()) }, NOW);
        assert!(matches!(verdict, Verdict::WatchRefused(WatchRefusal::Off)));
        let proposal = described(1, false, false);
        let sig = watch.sign(&sigs::deny_msg(&proposal.digest, b""));
        let outcome = Outcome::Denied { sig, reason: Vec::new(), delegation: Some(delegation) };
        assert!(matches!(proposal.judge(&phone_pub, outcome, NOW), Verdict::WatchRefused(WatchRefusal::Off)));
    }

    #[test]
    fn an_authorisation_lasts_until_its_last_second_and_no_longer() {
        let (phone, phone_pub) = key(7);
        for (not_after, honoured) in [(NOW, true), (NOW - 1, false)] {
            let (watch, delegation) = watch_of(&phone, 20, |d| d.not_after = not_after);
            let proposal = simple();
            let sig = watch.sign(&sigs::approve_msg(&proposal.digest));
            let verdict = proposal.judge(&phone_pub, Outcome::Approved { sig, delegation: Some(delegation) }, NOW);
            let as_expected = if honoured {
                matches!(verdict, Verdict::Approved(_))
            } else {
                matches!(verdict, Verdict::WatchRefused(WatchRefusal::Expired))
            };
            assert!(as_expected, "expiring at {not_after}: {verdict:?}");
        }
    }

    #[test]
    fn only_the_pinned_phone_can_authorise_a_watch() {
        let (phone, phone_pub) = key(7);
        let (stranger, _) = key(8);
        let approve = |watch: &HostKey, delegation: SignedDelegation| {
            let proposal = simple();
            let sig = watch.sign(&sigs::approve_msg(&proposal.digest));
            proposal.judge(&phone_pub, Outcome::Approved { sig, delegation: Some(delegation) }, NOW)
        };

        // Signed by some other key: for instance, the watch vouching for itself.
        let (watch, delegation) = watch_of(&stranger, 20, |_| {});
        assert!(matches!(approve(&watch, delegation), Verdict::Forged));
        let (watch, _) = key(20);
        let (_, self_signed) = watch_of(&watch, 20, |_| {});
        assert!(matches!(approve(&watch, self_signed), Verdict::Forged));

        // The phone's genuine authorisation, for a different pairing.
        let (watch, elsewhere) = watch_of(&phone, 20, |d| d.pairing_id = [2; PAIRING_ID_LEN]);
        assert!(matches!(approve(&watch, elsewhere), Verdict::Forged));

        // The phone's genuine authorisation, with any field changed after
        // signing: a later expiry, another watch's key, another name.
        let changes: [fn(&mut Delegation); 4] = [
            |d| d.not_after += 1_000_000,
            |d| d.sign_pub = key(21).0.public().unwrap(),
            |d| d.kem_pub = key(22).0.public().unwrap(),
            |d| d.name = b"Your Watch".to_vec(),
        ];
        for change in changes {
            let (_, mut altered) = watch_of(&phone, 20, |_| {});
            change(&mut altered.delegation);
            // Signed by whichever key the altered authorisation now names.
            let signer =
                [key(20).0, key(21).0].into_iter().find(|k| k.public().unwrap() == altered.delegation.sign_pub);
            assert!(matches!(approve(&signer.unwrap(), altered), Verdict::Forged));
        }

        // A genuine authorisation of one watch, presented with another
        // key's signature (or the phone's own).
        let (_, delegation) = watch_of(&phone, 20, |_| {});
        assert!(matches!(approve(&key(21).0, delegation.clone()), Verdict::Forged));
        assert!(matches!(approve(&phone, delegation), Verdict::Forged));

        // A watch key that is not a point on the curve, properly signed for.
        let (watch, off_curve) = watch_of(&phone, 20, |d| {
            d.sign_pub = [0x11; PUBKEY_LEN];
            d.sign_pub[0] = 0x04;
        });
        assert!(matches!(approve(&watch, off_curve), Verdict::Forged));
    }

    #[test]
    fn a_watchs_signature_is_not_an_answer_without_its_authorisation() {
        // Presented as if the phone had signed, a watch's signature is just
        // a signature by the wrong key.
        let (phone, phone_pub) = key(7);
        let (watch, _) = watch_of(&phone, 20, |_| {});
        let proposal = simple();
        let sig = watch.sign(&sigs::approve_msg(&proposal.digest));
        assert!(matches!(
            proposal.judge(&phone_pub, Outcome::Approved { sig, delegation: None }, NOW),
            Verdict::Forged
        ));
    }

    #[test]
    fn an_authorisation_is_not_an_approval() {
        // The phone's signature over a delegation cannot be passed off as
        // its approval of a request, nor the other way round.
        let (phone, phone_pub) = key(7);
        let (_, delegation) = watch_of(&phone, 20, |_| {});
        let proposal = simple();
        let outcome = Outcome::Approved { sig: delegation.phone_sig, delegation: None };
        assert!(matches!(proposal.judge(&phone_pub, outcome, NOW), Verdict::Forged));
    }
}
