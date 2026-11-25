//! Building the command's environment from nothing.
//!
//! This follows sudo's `env_reset` model, which is where sudo ended up after
//! two decades of trying to block dangerous variables one at a time:
//!
//! 1. Constructed here, never inherited: `PATH`, `HOME`, `SHELL`, `USER`,
//!    `LOGNAME`, and `SUDO_USER` / `SUDO_UID` / `SUDO_GID` for scripts that
//!    look for them.
//! 2. Passed from the caller by default, after sudo's value checks: `TERM`,
//!    `COLORTERM`, `LANG`, `LANGUAGE`, `LC_*`, `LINGUAS`, `TZ`.
//! 3. Passed only when the caller names them (`NAME=value` or
//!    `--preserve-env`). These are shown to the approver, with a warning if
//!    the variable can inject code.
//!
//! The dynamic loader strips LD_* and DYLD_* from *this* process because it
//! is setuid, but the command runs as plain root and gets no such protection.
//! Rule 3 is the only thing standing between the caller's environment and
//! the command.

use isudo_proto::envrisk::is_shell_function;
use isudo_proto::request::{EnvOrigin, EnvVar};

use crate::args::Invocation;

/// Variables passed through by default if their value passes [`value_is_safe`].
/// This is sudo's `initial_checkenv_table`.
const DEFAULT_PASS: &[&str] = &["COLORTERM", "LANG", "LANGUAGE", "LINGUAS", "TERM", "TZ"];
const DEFAULT_PASS_PREFIX: &str = "LC_";

/// Facts about root and the caller that feed the constructed variables.
#[derive(Debug, Clone, Copy)]
pub struct Identity<'a> {
    pub secure_path: &'a str,
    pub root_home: &'a [u8],
    pub root_shell: &'a [u8],
    pub caller_name: &'a [u8],
    pub caller_uid: u32,
    pub caller_gid: u32,
}

#[derive(Debug)]
pub struct Built {
    /// The complete environment for the command, as `NAME=value` entries.
    pub envp: Vec<Vec<u8>>,
    /// The same environment, entry for entry and in the same order, with
    /// where each one came from. This is what goes into the signed request,
    /// so the approval covers every variable the command receives.
    pub described: Vec<EnvVar>,
}

impl Built {
    /// The entries that came from the caller's environment or command line.
    pub fn from_caller(&self) -> impl Iterator<Item = &EnvVar> {
        self.described.iter().filter(|var| var.origin != EnvOrigin::Constructed)
    }
}

fn passes_by_default(name: &[u8]) -> bool {
    std::str::from_utf8(name).is_ok_and(|n| DEFAULT_PASS.contains(&n) || n.starts_with(DEFAULT_PASS_PREFIX))
}

/// sudo's check for default-passed variables: no `/` or `%` in the value
/// (path traversal and printf-style format bugs in locale handling).
fn value_is_safe(name: &[u8], value: &[u8]) -> bool {
    if is_shell_function(value) {
        return false;
    }
    if name == b"TZ" {
        return tz_is_safe(value);
    }
    !value.iter().any(|b| matches!(b, b'/' | b'%'))
}

/// sudo's `tz_is_safe`, with sudo-rs's tightening. libc opens the file that
/// TZ names, so it must stay inside the zoneinfo directory (CVE-2014-9680).
fn tz_is_safe(value: &[u8]) -> bool {
    let tz = value.strip_prefix(b":").unwrap_or(value);
    if tz.is_empty() || tz.len() >= 1024 {
        return false;
    }
    if !tz.iter().all(|b| b.is_ascii_alphanumeric() || b.is_ascii_punctuation()) {
        return false;
    }
    if tz.windows(2).any(|w| w == b"..") {
        return false;
    }
    if tz.first() == Some(&b'/') {
        const ZONEINFO: &[&[u8]] = &[b"/usr/share/zoneinfo/", b"/var/db/timezone/zoneinfo/"];
        return ZONEINFO.iter().any(|dir| tz.starts_with(dir));
    }
    true
}

/// Builds the environment. `caller_env` is the caller's environment as
/// (name, value) pairs.
///
/// # Errors
/// Fails if a variable the caller named holds an exported shell function or
/// a NUL byte.
pub fn build(
    invocation: &Invocation,
    caller_env: &[(Vec<u8>, Vec<u8>)],
    identity: &Identity<'_>,
) -> Result<Built, String> {
    let lookup = |name: &[u8]| {
        // If the caller's environment repeats a name, take the first, as
        // getenv does. Only one copy is ever passed on (CVE-2010-1646).
        caller_env.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_slice())
    };

    // Ordered list of (name, value, origin).
    let mut entries: Vec<(Vec<u8>, Vec<u8>, EnvOrigin)> = Vec::new();
    let mut set = |name: &[u8], value: &[u8], origin: EnvOrigin| {
        if let Some(existing) = entries.iter_mut().find(|(n, _, _)| n == name) {
            existing.1 = value.to_vec();
            existing.2 = origin;
        } else {
            entries.push((name.to_vec(), value.to_vec(), origin));
        }
    };

    // 1. Constructed.
    set(b"PATH", identity.secure_path.as_bytes(), EnvOrigin::Constructed);
    set(b"HOME", identity.root_home, EnvOrigin::Constructed);
    set(b"SHELL", identity.root_shell, EnvOrigin::Constructed);
    set(b"USER", b"root", EnvOrigin::Constructed);
    set(b"LOGNAME", b"root", EnvOrigin::Constructed);
    set(b"SUDO_USER", identity.caller_name, EnvOrigin::Constructed);
    set(b"SUDO_UID", identity.caller_uid.to_string().as_bytes(), EnvOrigin::Constructed);
    set(b"SUDO_GID", identity.caller_gid.to_string().as_bytes(), EnvOrigin::Constructed);
    set(b"TERM", b"unknown", EnvOrigin::Constructed);

    // 2. Passed by default, in a stable order.
    let mut defaults: Vec<&(Vec<u8>, Vec<u8>)> = Vec::new();
    for pair in caller_env {
        let (name, value) = pair;
        if passes_by_default(name) && value_is_safe(name, value) && !defaults.iter().any(|(n, _)| n == name) {
            defaults.push(pair);
        }
    }
    defaults.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, value) in defaults {
        set(name, value, EnvOrigin::Default);
    }

    // 3. Named by the caller. --preserve-env first, then assignments, so an
    //    assignment wins if both name the same variable.
    for name in &invocation.preserve {
        if let Some(value) = lookup(name) {
            explicit(&mut set, name, value)?;
        }
    }
    for (name, value) in &invocation.assignments {
        explicit(&mut set, name, value)?;
    }

    let described: Vec<EnvVar> =
        entries.into_iter().map(|(name, value, origin)| EnvVar { origin, name, value }).collect();
    let envp = described.iter().map(|var| [var.name.as_slice(), b"=", var.value.as_slice()].concat()).collect();
    Ok(Built { envp, described })
}

fn explicit(set: &mut impl FnMut(&[u8], &[u8], EnvOrigin), name: &[u8], value: &[u8]) -> Result<(), String> {
    if is_shell_function(value) {
        return Err(format!(
            "{} holds an exported shell function, which cannot be passed to a root command",
            String::from_utf8_lossy(name)
        ));
    }
    if value.contains(&0) {
        return Err(format!("{} contains a NUL byte", String::from_utf8_lossy(name)));
    }
    set(name, value, EnvOrigin::Explicit);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> Identity<'static> {
        Identity {
            secure_path: "/usr/bin:/bin",
            root_home: b"/var/root",
            root_shell: b"/bin/sh",
            caller_name: b"burke",
            caller_uid: 501,
            caller_gid: 20,
        }
    }

    fn pairs(list: &[(&str, &str)]) -> Vec<(Vec<u8>, Vec<u8>)> {
        list.iter().map(|(n, v)| (n.as_bytes().to_vec(), v.as_bytes().to_vec())).collect()
    }

    fn invocation(preserve: &[&str], assignments: &[(&str, &str)]) -> Invocation {
        Invocation {
            assignments: pairs(assignments),
            preserve: preserve.iter().map(|n| n.as_bytes().to_vec()).collect(),
            command: vec![b"true".to_vec()],
        }
    }

    fn get<'a>(built: &'a Built, name: &str) -> Option<&'a [u8]> {
        let prefix = format!("{name}=");
        built.envp.iter().find(|e| e.starts_with(prefix.as_bytes())).map(|e| &e[prefix.len()..])
    }

    #[test]
    fn hostile_environment_is_dropped() {
        let caller = pairs(&[
            ("PATH", "/tmp/evil:/usr/bin"),
            ("HOME", "/Users/burke"),
            ("LD_PRELOAD", "/tmp/evil.so"),
            ("DYLD_INSERT_LIBRARIES", "/tmp/evil.dylib"),
            ("BASH_ENV", "/tmp/evil.sh"),
            ("PYTHONPATH", "/tmp"),
            ("SUDO_USER", "root"),
            ("USER", "burke"),
            ("SECRET_TOKEN", "abc"),
        ]);
        let built = build(&invocation(&[], &[]), &caller, &identity()).unwrap();
        assert_eq!(get(&built, "PATH"), Some(&b"/usr/bin:/bin"[..]));
        assert_eq!(get(&built, "HOME"), Some(&b"/var/root"[..]));
        assert_eq!(get(&built, "USER"), Some(&b"root"[..]));
        assert_eq!(get(&built, "SUDO_USER"), Some(&b"burke"[..]));
        assert_eq!(get(&built, "SUDO_UID"), Some(&b"501"[..]));
        for gone in ["LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "BASH_ENV", "PYTHONPATH", "SECRET_TOKEN"] {
            assert_eq!(get(&built, gone), None, "{gone} leaked");
        }
        assert_eq!(built.from_caller().count(), 0);
    }

    #[test]
    fn defaults_pass_when_their_values_are_safe() {
        let caller = pairs(&[
            ("TERM", "xterm-256color"),
            ("LANG", "en_CA.UTF-8"),
            ("LC_ALL", "../../etc/passwd"),
            ("LC_TIME", "en_%n"),
            ("COLORTERM", "truecolor"),
            ("TZ", "America/Toronto"),
        ]);
        let built = build(&invocation(&[], &[]), &caller, &identity()).unwrap();
        assert_eq!(get(&built, "TERM"), Some(&b"xterm-256color"[..]));
        assert_eq!(get(&built, "LANG"), Some(&b"en_CA.UTF-8"[..]));
        assert_eq!(get(&built, "TZ"), Some(&b"America/Toronto"[..]));
        assert_eq!(get(&built, "LC_ALL"), None);
        assert_eq!(get(&built, "LC_TIME"), None);
        let names: Vec<_> = built.from_caller().map(|v| v.name.clone()).collect();
        // TERM keeps the slot of the constructed fallback it replaced.
        assert_eq!(names, vec![b"TERM".to_vec(), b"COLORTERM".to_vec(), b"LANG".to_vec(), b"TZ".to_vec()]);
        assert!(built.from_caller().all(|v| v.origin == EnvOrigin::Default));
    }

    #[test]
    fn term_falls_back_to_unknown() {
        let built = build(&invocation(&[], &[]), &pairs(&[("TERM", "a/b")]), &identity()).unwrap();
        assert_eq!(get(&built, "TERM"), Some(&b"unknown"[..]));
    }

    #[test]
    fn tz_rules() {
        assert!(tz_is_safe(b"America/Toronto"));
        assert!(tz_is_safe(b":Europe/Berlin"));
        assert!(tz_is_safe(b"EST5EDT"));
        assert!(tz_is_safe(b"/usr/share/zoneinfo/UTC"));
        assert!(!tz_is_safe(b"/etc/shadow"));
        assert!(!tz_is_safe(b"../../etc/shadow"));
        assert!(!tz_is_safe(b"/usr/share/zoneinfo/../../../etc/shadow"));
        assert!(!tz_is_safe(b"A B"));
        assert!(!tz_is_safe(b""));
        assert!(!tz_is_safe(&[b'a'; 2000]));
    }

    #[test]
    fn explicit_variables_pass_and_are_reported() {
        let caller = pairs(&[("NODE_OPTIONS", "--require /tmp/x.js"), ("DEBUG", "1")]);
        let inv = invocation(&["NODE_OPTIONS", "NOT_SET"], &[("LD_PRELOAD", "/tmp/x.so"), ("PATH", "/opt/bin")]);
        let built = build(&inv, &caller, &identity()).unwrap();
        assert_eq!(get(&built, "NODE_OPTIONS"), Some(&b"--require /tmp/x.js"[..]));
        assert_eq!(get(&built, "LD_PRELOAD"), Some(&b"/tmp/x.so"[..]));
        assert_eq!(get(&built, "PATH"), Some(&b"/opt/bin"[..]), "an explicit PATH replaces the constructed one");
        assert_eq!(get(&built, "DEBUG"), None, "not named, so not passed");
        assert_eq!(get(&built, "NOT_SET"), None);
        let explicit: Vec<_> = built
            .described
            .iter()
            .filter(|v| v.origin == EnvOrigin::Explicit)
            .map(|v| String::from_utf8(v.name.clone()).unwrap())
            .collect();
        assert_eq!(explicit, ["PATH", "NODE_OPTIONS", "LD_PRELOAD"]);
    }

    #[test]
    fn assignment_beats_preserve_and_names_appear_once() {
        let caller = pairs(&[("FOO", "from-env"), ("FOO", "second-copy")]);
        let inv = invocation(&["FOO"], &[("FOO", "from-arg"), ("FOO", "last")]);
        let built = build(&inv, &caller, &identity()).unwrap();
        assert_eq!(get(&built, "FOO"), Some(&b"last"[..]));
        assert_eq!(built.envp.iter().filter(|e| e.starts_with(b"FOO=")).count(), 1);

        let built = build(&invocation(&["FOO"], &[]), &caller, &identity()).unwrap();
        assert_eq!(get(&built, "FOO"), Some(&b"from-env"[..]));
    }

    #[test]
    fn the_description_is_the_whole_environment() {
        let caller = pairs(&[("TERM", "xterm"), ("FOO", "bar"), ("SECRET", "x")]);
        let built = build(&invocation(&["FOO"], &[("DEBUG", "1")]), &caller, &identity()).unwrap();
        // Entry for entry, in order: what is signed is what is executed.
        let rebuilt: Vec<Vec<u8>> =
            built.described.iter().map(|v| [v.name.as_slice(), b"=", v.value.as_slice()].concat()).collect();
        assert_eq!(rebuilt, built.envp);
        let constructed: Vec<_> = built
            .described
            .iter()
            .filter(|v| v.origin == EnvOrigin::Constructed)
            .map(|v| String::from_utf8(v.name.clone()).unwrap())
            .collect();
        assert_eq!(constructed, ["PATH", "HOME", "SHELL", "USER", "LOGNAME", "SUDO_USER", "SUDO_UID", "SUDO_GID"]);
    }

    #[test]
    fn shell_functions_are_refused() {
        let caller = pairs(&[("BASH_FUNC_x%%", "() { id; }"), ("LANG", "() { id; }"), ("F", "() { id; }")]);
        let built = build(&invocation(&[], &[]), &caller, &identity()).unwrap();
        assert_eq!(get(&built, "LANG"), None);
        assert!(build(&invocation(&["F"], &[]), &caller, &identity()).is_err());
        assert!(build(&invocation(&[], &[("G", "() { id; }")]), &caller, &identity()).is_err());
    }
}
