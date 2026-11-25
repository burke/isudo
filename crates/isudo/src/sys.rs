//! The system calls the setuid binary makes directly.
//!
//! Wherever the standard library has a safe equivalent it is used instead;
//! what is left here is what it does not offer. Rules followed throughout,
//! each one a lesson from sudo's history:
//!
//! - Every call that can fail is checked, and failure is fatal. Privilege
//!   changes are additionally read back and compared (sudo's CVE-2026-35535
//!   was an unchecked `setuid`).
//! - Nothing here consults the caller's environment.
//! - Nothing here prints with macros that can panic on a closed descriptor.

use std::ffi::CStr;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::time::{Duration, Instant};

use crate::Fatal;

pub(crate) type Result<T> = std::result::Result<T, Fatal>;

fn os_error(what: &str) -> Fatal {
    Fatal::new(format!("{what}: {}", io::Error::last_os_error()))
}

fn errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// Turns the usual "negative means failure" return value into a `Result`.
fn check(rc: libc::c_int, what: &str) -> Result<libc::c_int> {
    if rc < 0 {
        Err(os_error(what))
    } else {
        Ok(rc)
    }
}

/// Writes to standard error, ignoring failure. There is nothing useful to do
/// if the caller closed or filled it, and it must never stop the program.
pub(crate) fn write_stderr(bytes: &[u8]) {
    write_fd(2, bytes);
}

/// Writes to standard output, ignoring failure, for the one thing this
/// program prints that is meant to be captured (`--skill`).
pub(crate) fn write_stdout(bytes: &[u8]) {
    write_fd(1, bytes);
}

fn write_fd(fd: libc::c_int, mut bytes: &[u8]) {
    while !bytes.is_empty() {
        // SAFETY: the pointer and length describe a live slice.
        let n = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        match usize::try_from(n) {
            Ok(0) => return,
            Ok(written) => bytes = bytes.get(written..).unwrap_or_default(),
            Err(_) if errno() == libc::EINTR => {}
            Err(_) => return,
        }
    }
}

/// Ends the process immediately, skipping `atexit` handlers, which is what a
/// setuid program wants.
pub(crate) fn exit(code: i32) -> ! {
    // SAFETY: _exit takes an integer and does not return.
    unsafe { libc::_exit(code) }
}

/// Who ran us, as the kernel reports it.
#[derive(Debug, Clone)]
pub(crate) struct Caller {
    pub uid: libc::uid_t,
    pub gid: libc::gid_t,
    pub groups: Vec<libc::gid_t>,
}

pub(crate) fn caller() -> Result<Caller> {
    const WHAT: &str = "cannot read your group list";
    // SAFETY: getuid takes no arguments and cannot fail.
    let uid = unsafe { libc::getuid() };
    // SAFETY: getgid takes no arguments and cannot fail.
    let gid = unsafe { libc::getgid() };
    // SAFETY: a zero-length query only returns the number of groups.
    let count = check(unsafe { libc::getgroups(0, std::ptr::null_mut()) }, WHAT)?;
    let mut groups: Vec<libc::gid_t> = vec![0; usize::try_from(count).map_err(|_e| Fatal::new(WHAT))?];
    // SAFETY: the buffer holds `count` entries.
    let got = check(unsafe { libc::getgroups(count, groups.as_mut_ptr()) }, WHAT)?;
    groups.truncate(usize::try_from(got).map_err(|_e| Fatal::new(WHAT))?);
    Ok(Caller { uid, gid, groups })
}

pub(crate) fn effective_uid() -> libc::uid_t {
    // SAFETY: geteuid takes no arguments and cannot fail.
    unsafe { libc::geteuid() }
}

pub(crate) fn real_uid() -> libc::uid_t {
    // SAFETY: getuid takes no arguments and cannot fail.
    unsafe { libc::getuid() }
}

fn real_gid() -> libc::gid_t {
    // SAFETY: getgid takes no arguments and cannot fail.
    unsafe { libc::getgid() }
}

fn effective_gid() -> libc::gid_t {
    // SAFETY: getegid takes no arguments and cannot fail.
    unsafe { libc::getegid() }
}

pub(crate) fn parent_pid() -> Option<u32> {
    // SAFETY: getppid takes no arguments and cannot fail.
    u32::try_from(unsafe { libc::getppid() }).ok()
}

/// Explains why we are not root, the way sudo does, so that a sandboxed
/// caller gets a reason instead of a mystery.
#[cfg_attr(not(target_os = "linux"), expect(clippy::missing_const_for_fn, reason = "not const on Linux"))]
pub(crate) fn why_not_root() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: PR_GET_NO_NEW_PRIVS takes no pointer arguments.
        if unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) } == 1 {
            return "cannot become root: the \"no new privileges\" flag is set, \
                    which is usual inside containers and sandboxes";
        }
    }
    "cannot become root: isudo must be owned by root with the setuid bit set, \
     on a filesystem not mounted nosuid, and not run from inside a sandbox"
}

/// Unblocks every signal. The caller chooses the mask we inherit, and a
/// blocked SIGINT would make the wait for approval uninterruptible.
pub(crate) fn reset_signal_mask() -> Result<()> {
    const WHAT: &str = "cannot reset the signal mask";
    // SAFETY: sigset_t is plain data for which all-zero is a valid value.
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    // SAFETY: the pointer is to a live sigset_t.
    let _ = check(unsafe { libc::sigemptyset(&raw mut set) }, WHAT)?;
    // SAFETY: `set` was initialized above; a null old-set pointer is allowed.
    let _ = check(unsafe { libc::sigprocmask(libc::SIG_SETMASK, &raw const set, std::ptr::null_mut()) }, WHAT)?;
    Ok(())
}

/// Resets every signal's disposition, which the caller chose and which
/// survives exec.
///
/// Everything goes back to its default except SIGPIPE, which stays ignored
/// while this program runs so that a vanished helper is an error return and
/// not a death; [`default_sigpipe`] puts it back for the command.
///
/// One inherited disposition is dangerous in itself: with SIGCHLD ignored
/// the kernel reaps children as they exit, so the helper's pid could be
/// reused while this process, as root, still meant to kill it.
pub(crate) fn reset_signal_dispositions() {
    for signal in 1..=64 {
        let disposition = match signal {
            libc::SIGKILL | libc::SIGSTOP => continue,
            libc::SIGPIPE => libc::SIG_IGN,
            _ => libc::SIG_DFL,
        };
        // SAFETY: SIG_DFL and SIG_IGN are valid dispositions for any signal;
        // a number that is not a signal here just returns an error.
        let _ = unsafe { libc::signal(signal, disposition) };
    }
}

/// Cancels interval timers the caller may have armed, which would otherwise
/// fire in this process or, later, in the command.
pub(crate) fn cancel_timers() {
    // SAFETY: itimerval is plain data for which all-zero means "disarmed".
    let off: libc::itimerval = unsafe { std::mem::zeroed() };
    for timer in [libc::ITIMER_REAL, libc::ITIMER_VIRTUAL, libc::ITIMER_PROF] {
        // SAFETY: the new-value pointer is to a live itimerval; a null
        // old-value pointer is allowed.
        let _ = unsafe { libc::setitimer(timer, &raw const off, std::ptr::null_mut()) };
    }
}

/// Restores the default action for SIGPIPE.
///
/// Rust ignores SIGPIPE at startup, and an ignored signal stays ignored
/// across exec. The command should get the normal behaviour.
pub(crate) fn default_sigpipe() -> Result<()> {
    // SAFETY: SIG_DFL is a valid disposition for SIGPIPE.
    if unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) } == libc::SIG_ERR {
        return Err(os_error("cannot reset SIGPIPE"));
    }
    Ok(())
}

pub(crate) fn set_umask() {
    // SAFETY: umask takes an integer and cannot fail.
    let _ = unsafe { libc::umask(0o022) };
}

/// Closes every descriptor above standard error. The caller may have left
/// anything open; the command must not inherit it through us.
pub(crate) fn close_inherited_fds() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: close_range takes three integers.
        if unsafe { libc::syscall(libc::SYS_close_range, 3_u32, u32::MAX, 0_u32) } == 0 {
            return Ok(());
        }
    }
    // If the open descriptors cannot be listed, stop. Guessing a range to
    // close would trust a limit the caller set.
    let open = open_fds().ok_or_else(|| Fatal::new("cannot list open file descriptors; not continuing"))?;
    open.into_iter().for_each(close_fd);
    Ok(())
}

fn close_fd(fd: libc::c_int) {
    // SAFETY: closing a descriptor this program does not use. EBADF is fine.
    let _ = unsafe { libc::close(fd) };
}

/// Lists open descriptors above standard error by reading `/dev/fd`.
fn open_fds() -> Option<Vec<libc::c_int>> {
    // SAFETY: the path is a valid C string; the stream is closed below.
    let dir = unsafe { libc::opendir(c"/dev/fd".as_ptr()) };
    if dir.is_null() {
        return None;
    }
    // SAFETY: `dir` is a valid stream until closedir.
    let dir_fd = unsafe { libc::dirfd(dir) };
    let mut open = Vec::new();
    loop {
        // SAFETY: `dir` is a valid stream; the result is null at the end, or
        // points to an entry valid until the next call on this stream.
        let entry = unsafe { libc::readdir(dir) };
        if entry.is_null() {
            break;
        }
        // SAFETY: `entry` is non-null and valid, and d_name lies within it.
        let name_ptr = unsafe { (&raw const (*entry).d_name).cast::<libc::c_char>() };
        // SAFETY: d_name is a NUL-terminated string.
        let name = unsafe { CStr::from_ptr(name_ptr) };
        if let Some(fd) = name.to_str().ok().and_then(|s| s.parse::<libc::c_int>().ok()) {
            if fd > 2 && fd != dir_fd {
                open.push(fd);
            }
        }
    }
    // SAFETY: `dir` came from opendir and is closed exactly once.
    let _ = unsafe { libc::closedir(dir) };
    Some(open)
}

/// The caller's core dump limit, saved so it can be put back for the command.
#[derive(Debug)]
pub(crate) struct CoreLimit(libc::rlimit);

/// Turns off core dumps for this process.
pub(crate) fn disable_core_dumps() -> Result<CoreLimit> {
    // SAFETY: rlimit is plain data for which all-zero is a valid value.
    let mut saved: libc::rlimit = unsafe { std::mem::zeroed() };
    // SAFETY: the pointer is to a live rlimit.
    let _ = check(unsafe { libc::getrlimit(libc::RLIMIT_CORE, &raw mut saved) }, "cannot read the core dump limit")?;
    let none = libc::rlimit { rlim_cur: 0, rlim_max: saved.rlim_max };
    // SAFETY: the pointer is to a live rlimit.
    let _ = check(unsafe { libc::setrlimit(libc::RLIMIT_CORE, &raw const none) }, "cannot disable core dumps")?;
    Ok(CoreLimit(saved))
}

pub(crate) fn restore_core_limit(saved: &CoreLimit) -> Result<()> {
    // SAFETY: the pointer is to a live rlimit.
    let _ = check(unsafe { libc::setrlimit(libc::RLIMIT_CORE, &raw const saved.0) }, "cannot restore the core dump limit")?;
    Ok(())
}

/// Runs `work` with the caller's effective uid, then returns to root.
///
/// Used for looking at the filesystem on the caller's behalf, so that this
/// program never tells a caller anything about files they could not have
/// examined themselves. Supplementary groups and the gid are still the
/// caller's at this point; only the effective uid needs lowering.
///
/// # Errors
/// Fails, and the program must stop, if privilege cannot be lowered or
/// cannot be regained exactly.
pub(crate) fn as_caller<T>(caller: &Caller, work: impl FnOnce() -> T) -> Result<T> {
    // SAFETY: seteuid takes an integer.
    let _ = check(unsafe { libc::seteuid(caller.uid) }, "cannot act as the calling user")?;
    if effective_uid() != caller.uid {
        return Err(Fatal::new("the effective user id did not change to the caller's"));
    }
    let result = work();
    // SAFETY: seteuid takes an integer.
    let _ = check(unsafe { libc::seteuid(0) }, "cannot return to root")?;
    if effective_uid() != 0 {
        return Err(Fatal::new("the effective user id did not return to root"));
    }
    Ok(result)
}

/// Makes the real uid root as well as the effective one, as sudo does. From
/// here on the caller cannot signal or trace this process; the ways to cancel
/// are the terminal (Ctrl-C) and killing the helper, which runs as them.
pub(crate) fn become_real_root() -> Result<()> {
    // SAFETY: setreuid takes two integers.
    let _ = check(unsafe { libc::setreuid(0, 0) }, "cannot set the real user id")?;
    if real_uid() != 0 || effective_uid() != 0 {
        return Err(Fatal::new("the real user id did not change to root"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[expect(clippy::unnecessary_wraps, reason = "matches the signature used on other platforms")]
const fn group_count(len: usize) -> Option<libc::size_t> {
    Some(len)
}

#[cfg(not(target_os = "linux"))]
fn group_count(len: usize) -> Option<libc::c_int> {
    libc::c_int::try_from(len).ok()
}

/// Sets the supplementary groups, then the gid, then the uid: the only order
/// that works, since each step needs the privilege the next one gives up.
/// Every id is then read back.
///
/// Async-signal-safe: no allocation, no locks. Returns false on any failure.
fn set_identity(uid: libc::uid_t, gid: libc::gid_t, groups: &[libc::gid_t]) -> bool {
    let Some(count) = group_count(groups.len()) else { return false };
    // SAFETY: the pointer and count describe a live slice.
    if unsafe { libc::setgroups(count, groups.as_ptr()) } != 0 {
        return false;
    }
    // SAFETY: setgid takes an integer.
    if unsafe { libc::setgid(gid) } != 0 {
        return false;
    }
    // SAFETY: setuid takes an integer.
    if unsafe { libc::setuid(uid) } != 0 {
        return false;
    }
    real_uid() == uid && effective_uid() == uid && real_gid() == gid && effective_gid() == gid
}

/// Takes on root's full identity. Returns false on any failure.
pub(crate) fn assume_root_identity() -> bool {
    if !set_identity(0, 0, &[0]) {
        return false;
    }
    let mut groups: [libc::gid_t; 8] = [libc::gid_t::MAX; 8];
    // SAFETY: the buffer holds eight entries, and eight is passed as its size.
    let count = unsafe { libc::getgroups(8, groups.as_mut_ptr()) };
    usize::try_from(count)
        .ok()
        .and_then(|n| groups.get(..n))
        .is_some_and(|set| set.iter().all(|group| *group == 0))
}

/// Permanently becomes the caller. Used in the child that runs the helper.
///
/// Async-signal-safe: no allocation, no locks. Returns false on any failure.
pub(crate) fn drop_to_caller(caller: &Caller) -> bool {
    if !set_identity(caller.uid, caller.gid, &caller.groups) {
        return false;
    }
    // The drop must be irreversible.
    // SAFETY: setuid takes an integer.
    caller.uid == 0 || unsafe { libc::setuid(0) } != 0
}

pub(crate) fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0_u8; N];
    // SAFETY: the pointer and length describe the array above.
    let _ = check(unsafe { libc::getentropy(out.as_mut_ptr().cast(), N) }, "cannot get random bytes")?;
    Ok(out)
}

/// Waits until `fd` is ready for `events` or the deadline passes. Returns
/// false on timeout.
pub(crate) fn wait_ready(fd: BorrowedFd<'_>, events: libc::c_short, deadline: Instant) -> Result<bool> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(false);
        }
        // Round up so that a sub-millisecond remainder does not spin.
        let millis = remaining.saturating_add(Duration::from_micros(999)).as_millis().min(60_000);
        let timeout = libc::c_int::try_from(millis).unwrap_or(60_000);
        let mut pfd = libc::pollfd { fd: fd.as_raw_fd(), events, revents: 0 };
        // SAFETY: the pointer is to one live pollfd, and one is the count.
        let rc = unsafe { libc::poll(&raw mut pfd, 1, timeout) };
        if rc > 0 {
            return Ok(true);
        }
        if rc < 0 && errno() != libc::EINTR {
            return Err(os_error("cannot wait on the helper"));
        }
    }
}

/// An account's name, home directory and shell.
#[derive(Debug)]
pub(crate) struct Account {
    pub name: Vec<u8>,
    pub home: Vec<u8>,
    pub shell: Vec<u8>,
}

/// Looks up an account by uid. Returns None if there is no such account or
/// the lookup fails; callers have fallbacks and never depend on it.
pub(crate) fn account(uid: libc::uid_t) -> Option<Account> {
    let mut buf: Vec<libc::c_char> = vec![0; 16 * 1024];
    // SAFETY: passwd is plain data (integers and pointers) for which all-zero
    // is a valid value.
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut found: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: every pointer is valid for the length passed with it.
    let rc = unsafe { libc::getpwuid_r(uid, &raw mut pwd, buf.as_mut_ptr(), buf.len(), &raw mut found) };
    if rc != 0 || found.is_null() {
        return None;
    }
    Some(Account { name: c_field(pwd.pw_name), home: c_field(pwd.pw_dir), shell: c_field(pwd.pw_shell) })
}

/// Copies a C string field filled in by `getpwuid_r`.
fn c_field(ptr: *const libc::c_char) -> Vec<u8> {
    if ptr.is_null() {
        return Vec::new();
    }
    // SAFETY: getpwuid_r points its fields at NUL-terminated strings inside
    // the buffer it was given, which is still alive in the caller.
    unsafe { CStr::from_ptr(ptr) }.to_bytes().to_vec()
}

/// A process's name and its parent's pid, or None if it cannot be read.
#[cfg(target_os = "macos")]
pub(crate) fn process_info(pid: u32) -> Option<(Vec<u8>, u32)> {
    let pid = libc::c_int::try_from(pid).ok()?;
    let size = libc::c_int::try_from(size_of::<libc::proc_bsdinfo>()).ok()?;
    // SAFETY: proc_bsdinfo is plain data for which all-zero is a valid value.
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    // SAFETY: the buffer pointer and size describe `info`.
    let got = unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, (&raw mut info).cast(), size) };
    if got != size {
        return None;
    }
    let text = |chars: &[libc::c_char]| -> Vec<u8> {
        chars.iter().map(|c| u8::from_ne_bytes(c.to_ne_bytes())).take_while(|b| *b != 0).collect()
    };
    let name = text(&info.pbi_name);
    Some((if name.is_empty() { text(&info.pbi_comm) } else { name }, info.pbi_ppid))
}
