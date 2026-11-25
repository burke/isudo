//! Running the network helper without giving it any privilege.
//!
//! Talking to the relay means TLS, HTTP and JSON, none of which belongs in a
//! root process. So the helper runs as a child that has permanently become
//! the caller, and the two talk over a pair of pipes.
//!
//! The helper is not trusted. It runs as the caller, who can replace its
//! memory at will. That is fine: the only thing it can return that has any
//! effect is a signature by the phone's key over this process's own request.

use std::ffi::OsStr;
use std::io::{self, Read as _, Write as _};
use std::os::fd::AsFd as _;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::process::CommandExt as _;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use isudo_proto::frame::{Job, Outcome, MAX_OUTCOME_LEN};

use crate::sys::{self, Caller};
use crate::Fatal;

/// Time allowed on top of the approval timeout for the helper to start,
/// connect and deliver the answer.
const GRACE: Duration = Duration::from_secs(10);

/// POSIX guarantees that a pipe reported writable accepts this many bytes
/// without blocking.
const PIPE_CHUNK: usize = 512;

/// Variables the helper may see. It runs as the caller, so this is not a
/// security boundary; it keeps proxies working and everything else out.
const HELPER_ENV: [&[u8]; 6] =
    [b"HTTPS_PROXY", b"https_proxy", b"ALL_PROXY", b"all_proxy", b"NO_PROXY", b"no_proxy"];

#[derive(Debug)]
pub(crate) enum Answer {
    Outcome(Outcome),
    /// The helper produced nothing usable; the message says why.
    Nothing(&'static str),
}

pub(crate) fn run(
    helper_path: &[u8],
    job: &Job,
    caller: &Caller,
    caller_env: &[(Vec<u8>, Vec<u8>)],
    drop_privileges: bool,
) -> Result<Answer, Fatal> {
    let job_bytes = job.encode().map_err(|e| Fatal::new(format!("cannot encode the request: {e}")))?;
    let wait = Duration::from_secs(u64::from(job.timeout_secs)).saturating_add(GRACE);
    let deadline =
        Instant::now().checked_add(wait).ok_or_else(|| Fatal::new("the approval timeout is too long"))?;

    let mut command = Command::new(OsStr::from_bytes(helper_path));
    let _ = command
        .arg0("isudo-helper")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .envs(
            caller_env
                .iter()
                .filter(|(name, _)| HELPER_ENV.contains(&name.as_slice()))
                .map(|(name, value)| (OsStr::from_bytes(name), OsStr::from_bytes(value))),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        // The helper has nothing to say to the caller; anything it must
        // report comes back as a code this program words itself.
        .stderr(Stdio::null());
    if drop_privileges {
        let caller = caller.clone();
        let become_caller = move || {
            if sys::drop_to_caller(&caller) {
                Ok(())
            } else {
                Err(io::Error::from_raw_os_error(libc::EPERM))
            }
        };
        // SAFETY: the closure runs in the forked child before exec. It only
        // makes async-signal-safe system calls and does not allocate.
        let _ = unsafe { command.pre_exec(become_caller) };
    }

    let mut child = command.spawn().map_err(|e| Fatal::new(format!("cannot start the helper program: {e}")))?;
    let answer = converse(&mut child, &job_bytes, deadline);
    // Whatever happened, nothing we started is left running. The pid is only
    // ours to signal while the child is unreaped, so look first: if it has
    // already been collected there is nothing to kill.
    if matches!(child.try_wait(), Ok(None)) {
        drop(child.kill());
        drop(child.wait());
    }
    answer
}

fn converse(child: &mut Child, job: &[u8], deadline: Instant) -> Result<Answer, Fatal> {
    const TIMED_OUT: Answer = Answer::Nothing("timed out waiting for an answer");
    let (Some(mut stdin), Some(mut stdout)) = (child.stdin.take(), child.stdout.take()) else {
        return Err(Fatal::new("cannot talk to the helper program"));
    };

    let mut rest = job;
    while !rest.is_empty() {
        if !sys::wait_ready(stdin.as_fd(), libc::POLLOUT, deadline)? {
            return Ok(TIMED_OUT);
        }
        let chunk = rest.get(..PIPE_CHUNK).unwrap_or(rest);
        match stdin.write(chunk) {
            Ok(written) => rest = rest.get(written..).unwrap_or_default(),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Ok(Answer::Nothing("the helper exited before reading the request")),
        }
    }
    drop(stdin);

    let mut answer = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        if !sys::wait_ready(stdout.as_fd(), libc::POLLIN, deadline)? {
            return Ok(TIMED_OUT);
        }
        match stdout.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => answer.extend_from_slice(buffer.get(..n).unwrap_or_default()),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Ok(Answer::Nothing("cannot read the helper's answer")),
        }
        if answer.len() > MAX_OUTCOME_LEN {
            return Ok(Answer::Nothing("the helper returned a malformed answer"));
        }
    }
    if answer.is_empty() {
        return Ok(Answer::Nothing("the helper exited without an answer"));
    }
    Ok(Outcome::decode(&answer)
        .map_or(Answer::Nothing("the helper returned a malformed answer"), Answer::Outcome))
}
