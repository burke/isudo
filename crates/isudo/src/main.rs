//! isudo: run a command as root once a paired phone has approved it.
//!
//! This is the setuid-root binary. Its whole job, in order:
//!
//! 1. Neutralize what it inherited from the caller.
//! 2. Work out exactly what would run: one resolved path, the argument
//!    list, a freshly built environment.
//! 3. Describe that in a request containing a random nonce that exists only
//!    in this process.
//! 4. Hand the request to an unprivileged helper and wait for an answer.
//! 5. Verify that the answer is the paired phone's signature over this
//!    request. Nothing else that comes back is believed.
//! 6. Become root in full and exec, in place, provided the approval has not
//!    gone stale.
//!
//! Steps 2, 5 and 6 are tied together by the types in `isudo_core::plan`: the
//! only way to reach `execve` is with a value that proves step 5 succeeded
//! for the exact plan from step 2.
//!
//! There is no state between runs and nothing to clean up: an approval is
//! useless to any process other than the one that asked for it, and that
//! process either execs or exits.

mod ancestry;
mod exec;
mod helper;
mod resolve;
mod sys;

use std::io::IsTerminal as _;
use std::os::unix::ffi::OsStringExt as _;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use isudo_proto::frame::Job;
use isudo_proto::request::StdinKind;
use isudo_proto::sigs;
use isudo_proto::text::escape;
use isudo_proto::wire::WireError;

use isudo_core::args::{self, Invocation};
use isudo_core::config::{self, Pairing};
use isudo_core::env;
use isudo_core::plan::{Approved, Context, HostKey, PhoneKey, Plan, Proposal, Verdict};

use crate::sys::Caller;

/// A reason to stop, with the exit status to stop with.
#[derive(Debug)]
pub(crate) struct Fatal {
    code: i32,
    message: String,
}

impl Fatal {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self { code: 1, message: message.into() }
    }

    pub(crate) fn with_code(code: i32, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }
}

/// How long after the request's stated expiry an approval may still be acted
/// on, to allow for the answer's journey back.
const LATE_GRACE: Duration = Duration::from_secs(15);

/// False only in development builds, which gain no privilege.
const PRIVILEGED: bool = cfg!(not(feature = "dev-unprivileged"));

/// Where the installed pieces live.
struct Install {
    pairing_file: PathBuf,
    helper: Vec<u8>,
}

/// The directory the helper is installed in. Set at build time by the
/// Makefile so that it matches where `make install` puts things.
const LIBEXEC_DIR: &str = match option_env!("ISUDO_LIBEXEC_DIR") {
    Some(dir) => dir,
    None => "/usr/local/libexec",
};

impl Install {
    #[cfg(not(feature = "dev-unprivileged"))]
    #[expect(clippy::unnecessary_wraps, reason = "the development build's version can fail")]
    fn locate() -> Result<Self, Fatal> {
        Ok(Self {
            pairing_file: "/etc/isudo/pairing.conf".into(),
            helper: [LIBEXEC_DIR, "/isudo-helper"].concat().into_bytes(),
        })
    }

    /// A development build takes both from the environment, and refuses to
    /// run as root so that it cannot be installed by mistake.
    #[cfg(feature = "dev-unprivileged")]
    fn locate() -> Result<Self, Fatal> {
        let _ = LIBEXEC_DIR;
        let var = |name: &str| std::env::var_os(name).ok_or_else(|| Fatal::new(format!("{name} is not set")));
        Ok(Self { pairing_file: var("ISUDO_DEV_CONFIG")?.into(), helper: var("ISUDO_DEV_HELPER")?.into_vec() })
    }
}

fn say(message: &str) {
    sys::write_stderr(["isudo: ", message, "\n"].concat().as_bytes());
}

fn main() {
    let code = match run() {
        Ok(code) => code,
        Err(fatal) => {
            say(&fatal.message);
            fatal.code
        }
    };
    sys::exit(code);
}

fn run() -> Result<i32, Fatal> {
    // 1. Inherited state. Rust's runtime has already made sure descriptors
    //    0-2 are open.
    let caller = sys::caller()?;
    sys::reset_signal_mask()?;
    sys::reset_signal_dispositions();
    sys::cancel_timers();
    sys::set_umask();
    sys::close_inherited_fds()?;
    let saved_core_limit = sys::disable_core_dumps()?;

    // The caller's environment is read exactly once, here, and from now on
    // is only data: nothing in this program changes behaviour because of it.
    let caller_env: Vec<(Vec<u8>, Vec<u8>)> =
        std::env::vars_os().map(|(name, value)| (name.into_vec(), value.into_vec())).collect();

    let invocation = match args::parse(std::env::args_os().skip(1)) {
        Ok(args::Parsed::Help) => {
            sys::write_stderr([args::USAGE, "\n"].concat().as_bytes());
            return Ok(0);
        }
        Ok(args::Parsed::Version) => {
            sys::write_stderr(concat!("isudo ", env!("CARGO_PKG_VERSION"), "\n").as_bytes());
            return Ok(0);
        }
        Ok(args::Parsed::Skill) => {
            sys::write_stdout(args::SKILL.as_bytes());
            return Ok(0);
        }
        Ok(args::Parsed::Run(invocation)) => invocation,
        Err(message) => return Err(Fatal::new([message.as_str(), "\n", args::USAGE].concat())),
    };

    check_privilege()?;
    let install = Install::locate()?;
    let pairing = read_pairing(&install.pairing_file)?;
    let bad_key = |which: &str| Fatal::new(format!("{} holds an invalid {which} key", install.pairing_file.display()));
    let host_key = HostKey::new(&pairing.host_key).ok_or_else(|| bad_key("host"))?;
    let phone_key = PhoneKey::new(&pairing.phone_sign_pub).ok_or_else(|| bad_key("phone"))?;

    // 2. What would run. The filesystem is examined with the caller's own
    //    credentials, so nothing is learned here that the caller could not
    //    have found out by looking. Only then does this process become root
    //    in the real-uid sense too.
    let located = if PRIVILEGED {
        let located = sys::as_caller(&caller, || locate(&invocation, &pairing))??;
        sys::become_real_root()?;
        located
    } else {
        locate(&invocation, &pairing)?
    };

    // 3. The request that describes it.
    let started = Instant::now();
    let proposal = propose(invocation, located, &pairing, &caller, &caller_env)?;
    let job = job_for(&proposal, &pairing, &host_key)?;
    let expiry = exec::Expiry {
        monotonic: started.checked_add(Duration::from_secs(u64::from(pairing.timeout_secs)).saturating_add(LATE_GRACE)),
        wall_clock: job.expires_at.saturating_add(LATE_GRACE.as_secs()),
    };

    // 4. Ask.
    let phone = escape(pairing.phone_name.as_bytes());
    say(&format!(
        "waiting for approval on {phone} (up to {}m{:02}s; Ctrl-C to cancel)",
        pairing.timeout_secs / 60,
        pairing.timeout_secs % 60
    ));
    let outcome = match helper::run(&install.helper, &job, &caller, &caller_env, PRIVILEGED)? {
        helper::Answer::Outcome(outcome) => outcome,
        helper::Answer::Nothing(why) => return Err(Fatal::new(["not approved: ", why].concat())),
    };

    // 5. Believe only a signature.
    let approved = require_approval(proposal.judge(&phone_key, outcome), &phone)?;

    // 6. Run, provided the approval is still current.
    Err(exec::run(approved, &saved_core_limit, &expiry, PRIVILEGED))
}

fn check_privilege() -> Result<(), Fatal> {
    if PRIVILEGED {
        if sys::effective_uid() != 0 {
            return Err(Fatal::new(sys::why_not_root()));
        }
        return Ok(());
    }
    if sys::effective_uid() == 0 {
        return Err(Fatal::new("this is a development build and refuses to run as root"));
    }
    say("DEVELOPMENT BUILD: no privilege is gained and the command runs as you");
    Ok(())
}

/// Where the command would run and which file it names.
struct Located {
    cwd: Vec<u8>,
    resolved: resolve::Resolved,
}

/// Finds the working directory and the command's file. Runs with the
/// caller's effective uid.
fn locate(invocation: &Invocation, pairing: &Pairing) -> Result<Located, Fatal> {
    let cwd = std::env::current_dir()
        .map_err(|e| Fatal::new(format!("cannot determine the working directory: {e}")))?
        .into_os_string()
        .into_vec();
    match resolve::resolve(invocation.name(), &pairing.secure_path, &cwd) {
        Ok(resolved) => Ok(Located { cwd, resolved }),
        Err(resolve::ResolveError::NotFound) => {
            Err(Fatal::with_code(127, format!("{}: command not found", escape(invocation.name()))))
        }
        Err(resolve::ResolveError::NotExecutable(path)) => {
            Err(Fatal::with_code(126, format!("{}: not an executable file", escape(&path))))
        }
    }
}

/// Builds the plan and encodes the request describing it.
fn propose(
    invocation: Invocation,
    located: Located,
    pairing: &Pairing,
    caller: &Caller,
    caller_env: &[(Vec<u8>, Vec<u8>)],
) -> Result<Proposal, Fatal> {
    let Located { cwd, resolved } = located;
    let root = sys::account(0);
    // Empty if the caller's uid has no account.
    let caller_name: Vec<u8> = sys::account(caller.uid).into_iter().flat_map(|account| account.name).collect();
    let fallback_home: &[u8] = if cfg!(target_os = "macos") { b"/var/root" } else { b"/root" };
    let identity = env::Identity {
        secure_path: &pairing.secure_path,
        root_home: root.as_ref().map(|a| a.home.as_slice()).filter(|h| !h.is_empty()).unwrap_or(fallback_home),
        root_shell: root.as_ref().map(|a| a.shell.as_slice()).filter(|s| !s.is_empty()).unwrap_or(b"/bin/sh"),
        caller_name: &caller_name,
        caller_uid: caller.uid,
        caller_gid: caller.gid,
    };
    let built = env::build(&invocation, caller_env, &identity).map_err(Fatal::new)?;
    let plan = Plan::new(resolved.path, resolved.writable_by_non_root, invocation.command, built);

    let context = Context {
        nonce: sys::random_bytes()?,
        pairing_id: pairing.id,
        issued_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| Fatal::new(format!("the system clock is set before 1970: {e}")))?
            .as_secs(),
        ttl_secs: pairing.timeout_secs,
        uid: caller.uid,
        gid: caller.gid,
        user: caller_name,
        host: pairing.host_name.clone().into_bytes(),
        cwd,
        stdin: stdin_kind(),
        ancestry: ancestry::collect(sys::parent_pid()),
    };
    Proposal::describe(plan, context).map_err(|e| match e {
        WireError::TooLarge(_) => Fatal::new("the command is too large to be reviewed on a phone (the limit is 64 KiB)"),
        WireError::Truncated(_) | WireError::TrailingBytes(_) | WireError::Invalid(_) => {
            Fatal::new(format!("cannot encode the request: {e}"))
        }
    })
}

/// Signs the request for the phone and a ticket for the relay.
fn job_for(proposal: &Proposal, pairing: &Pairing, host_key: &HostKey) -> Result<Job, Fatal> {
    let expires_at = proposal
        .issued_at()
        .checked_add(u64::from(pairing.timeout_secs))
        .ok_or_else(|| Fatal::new("the system clock is implausibly far in the future"))?;
    let request_id = sigs::request_id(proposal.request());
    Ok(Job {
        relay_url: pairing.relay_url.clone().into_bytes(),
        pairing_id: pairing.id,
        phone_kem_pub: pairing.phone_kem_pub,
        expires_at,
        timeout_secs: pairing.timeout_secs,
        ticket_sig: host_key.sign(&sigs::ticket_msg(&pairing.id, &request_id, expires_at)),
        host_sig: host_key.sign(&sigs::host_request_msg(proposal.request())),
        request: proposal.request().to_vec(),
    })
}

/// Turns every verdict but an approval into the message the caller sees.
fn require_approval(verdict: Verdict, phone: &str) -> Result<Approved, Fatal> {
    match verdict {
        Verdict::Approved(approved) => Ok(approved),
        Verdict::Denied { reason } if reason.is_empty() => Err(Fatal::new(format!("denied on {phone}"))),
        Verdict::Denied { reason } => Err(Fatal::new(format!("denied on {phone}: \"{}\"", escape(&reason)))),
        Verdict::Forged => Err(Fatal::new("the answer was not signed by the paired phone; not running")),
        Verdict::NoAnswer(failure) => Err(Fatal::new(format!("not approved: {failure}"))),
    }
}

/// Reads the pairing file, which only root may have written. The file is
/// opened once and examined through that handle, so what is checked is what
/// is read.
fn read_pairing(path: &Path) -> Result<Pairing, Fatal> {
    use std::io::Read as _;
    let shown = path.display();
    let file = match std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(Fatal::new("no phone is paired with this machine yet; run: sudo isudo-admin pair"));
        }
        Err(e) => return Err(Fatal::new(format!("cannot open {shown}: {e}"))),
    };
    let meta = file.metadata().map_err(|e| Fatal::new(format!("cannot examine {shown}: {e}")))?;
    if !meta.is_file() {
        return Err(Fatal::new(format!("{shown} is not a regular file")));
    }
    if PRIVILEGED && (meta.uid() != 0 || meta.mode() & 0o077 != 0) {
        return Err(Fatal::new(format!("{shown} must be owned by root and readable only by root (mode 0600)")));
    }
    let limit = u64::try_from(config::MAX_CONFIG_LEN).unwrap_or(u64::MAX);
    let mut text = Vec::new();
    let read = file
        .take(limit.saturating_add(1))
        .read_to_end(&mut text)
        .map_err(|e| Fatal::new(format!("cannot read {shown}: {e}")))?;
    if read > config::MAX_CONFIG_LEN {
        return Err(Fatal::new(format!("{shown} is too large")));
    }
    config::parse(&text).map_err(|e| Fatal::new(format!("{shown} {e}")))
}

/// What the command's standard input is attached to. Shown to the approver
/// because `isudo sh` reading a pipe runs whatever arrives on it.
fn stdin_kind() -> StdinKind {
    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        return StdinKind::Terminal;
    }
    let Some(meta) = stdin_metadata(&stdin) else { return StdinKind::Other };
    let kind = meta.file_type();
    if kind.is_fifo() {
        StdinKind::Pipe
    } else if kind.is_socket() {
        StdinKind::Socket
    } else if meta.is_file() {
        StdinKind::File
    } else if kind.is_char_device() && is_dev_null(&meta) {
        StdinKind::Null
    } else {
        StdinKind::Other
    }
}

/// Examining a descriptor through the standard library means holding a
/// handle to it, so a duplicate is made for that and closed again at once.
fn stdin_metadata(stdin: &std::io::Stdin) -> Option<std::fs::Metadata> {
    use std::os::fd::AsFd as _;
    let duplicate = stdin.as_fd().try_clone_to_owned().ok()?;
    std::fs::File::from(duplicate).metadata().ok()
}

fn is_dev_null(meta: &std::fs::Metadata) -> bool {
    std::fs::metadata("/dev/null").is_ok_and(|null| null.rdev() == meta.rdev())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_pairing_file_says_how_to_pair() {
        let error = read_pairing(Path::new("/nonexistent/isudo/pairing.conf")).unwrap_err();
        assert!(error.message.contains("isudo-admin pair"), "{}", error.message);
    }

    #[test]
    fn dev_null_is_recognized() {
        let meta = std::fs::metadata("/dev/null").unwrap();
        assert!(is_dev_null(&meta));
        assert!(!is_dev_null(&std::fs::metadata("/dev/zero").unwrap()));
    }
}
