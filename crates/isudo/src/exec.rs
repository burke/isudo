//! The last step: become root in full and replace this process.
//!
//! [`run`] takes an [`Approved`], which only signature verification in
//! `isudo-core` can construct. It is the one place in the program where
//! root's identity is assumed and the one place `execve` is called for the
//! command.

use std::ffi::CString;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use isudo_core::plan::Approved;
use isudo_proto::text::escape;

use crate::sys::{self, CoreLimit};
use crate::Fatal;

/// The latest moment an approval may be acted on, on both clocks.
///
/// The wait for an answer has its own deadline, but that only bounds the
/// waiting. Without this, a process stopped from its terminal after the
/// answer arrived, or a machine put to sleep, could run an approved command
/// long after the window the approver was shown.
#[derive(Debug)]
pub(crate) struct Expiry {
    /// None if the deadline could not be represented, which counts as passed.
    pub monotonic: Option<Instant>,
    /// Unix seconds.
    pub wall_clock: u64,
}

impl Expiry {
    fn passed(&self) -> bool {
        let wall = SystemTime::now().duration_since(UNIX_EPOCH).map_or(u64::MAX, |now| now.as_secs());
        wall > self.wall_clock || self.monotonic.is_none_or(|deadline| Instant::now() > deadline)
    }
}

/// Runs the approved plan. Returns only if that could not be done.
///
/// `privileged` is false only in development builds, which run the command
/// as the caller.
pub(crate) fn run(approved: Approved, saved_core_limit: &CoreLimit, expiry: &Expiry, privileged: bool) -> Fatal {
    const NUL: &str = "the command contains a NUL byte";
    let plan = approved.into_plan();
    // Build everything exec needs before changing identity, so that no
    // fallible step is left between becoming root and exec.
    let Ok(path) = CString::new(plan.path()) else { return Fatal::new(NUL) };
    let Some(argv) = c_strings(plan.argv()) else { return Fatal::new(NUL) };
    let Some(envp) = c_strings(plan.envp()) else { return Fatal::new(NUL) };
    let argv_ptrs = pointers(&argv);
    let envp_ptrs = pointers(&envp);

    if let Err(fatal) = sys::restore_core_limit(saved_core_limit).and_then(|()| sys::default_sigpipe()) {
        return fatal;
    }
    if privileged && !sys::assume_root_identity() {
        return Fatal::new("cannot take on root's identity; not running");
    }
    // The last thing before exec, so that nothing can hold the process
    // between this check and the command starting.
    if expiry.passed() {
        return Fatal::new("the approval arrived too late to act on; not running");
    }
    // SAFETY: `path` is a valid C string; both arrays are NULL-terminated
    // lists of pointers to valid C strings that outlive the call.
    let _ = unsafe { libc::execve(path.as_ptr(), argv_ptrs.as_ptr(), envp_ptrs.as_ptr()) };
    let error = std::io::Error::last_os_error();
    Fatal::with_code(126, format!("cannot run {}: {error}", escape(path.as_bytes())))
}

fn c_strings(items: &[Vec<u8>]) -> Option<Vec<CString>> {
    items.iter().map(|item| CString::new(item.as_slice()).ok()).collect()
}

fn pointers(strings: &[CString]) -> Vec<*const libc::c_char> {
    strings.iter().map(|s| s.as_ptr()).chain(std::iter::once(std::ptr::null())).collect()
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn now() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }

    #[test]
    fn a_current_approval_has_not_expired() {
        let soon = Instant::now().checked_add(Duration::from_secs(60));
        assert!(!Expiry { monotonic: soon, wall_clock: now() + 60 }.passed());
    }

    #[test]
    fn either_clock_passing_is_enough() {
        let soon = Instant::now().checked_add(Duration::from_secs(60));
        let earlier = Instant::now().checked_sub(Duration::from_millis(5));
        // The wall clock catches a machine that slept (the monotonic clock
        // does not advance then); the monotonic clock catches a wall clock
        // that was set back.
        assert!(Expiry { monotonic: soon, wall_clock: now() - 1 }.passed());
        assert!(Expiry { monotonic: earlier, wall_clock: now() + 60 }.passed());
        assert!(Expiry { monotonic: None, wall_clock: now() + 60 }.passed());
    }
}
