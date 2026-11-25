//! `isudo-admin check`: is this installation one that can be trusted?
//!
//! The cryptography assumes the programs are the ones that were installed.
//! That fails quietly if they live anywhere a non-root user can write: on
//! many Macs `/usr/local/bin` belongs to the user, and an agent running as
//! that user could replace `isudo-admin` with something else for the next
//! time it is run with `sudo`.

use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use crate::say;

/// Where the helper is installed; set at build time to match `make install`.
const LIBEXEC_DIR: &str = match option_env!("ISUDO_LIBEXEC_DIR") {
    Some(dir) => dir,
    None => "/usr/local/libexec",
};

/// Where the setuid `isudo` is, if not beside this program. NixOS cannot
/// store a setuid file, so its copy is a wrapper in /run/wrappers/bin.
const SETUID_PATH: Option<&str> = option_env!("ISUDO_SETUID_PATH");

const SETUID: u32 = 0o4000;
const SETGID: u32 = 0o2000;
const STICKY: u32 = 0o1000;

/// The first component of `path`, from the file up to the root, that someone
/// other than root could change, with why. Mirrors the rule the setuid
/// binary applies to commands (`crates/isudo/src/resolve.rs`).
fn weak_link(path: &Path) -> Option<String> {
    let mut current = path;
    loop {
        let Ok(meta) = std::fs::metadata(current) else {
            return Some(format!("{} cannot be examined", current.display()));
        };
        if meta.uid() != 0 {
            return Some(format!("{} is not owned by root", current.display()));
        }
        if meta.mode() & 0o022 != 0 && !(meta.is_dir() && meta.mode() & STICKY != 0) {
            return Some(format!("{} is writable by users other than root", current.display()));
        }
        match current.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => current = parent,
            _ => return None,
        }
    }
}

struct Report {
    problems: usize,
}

impl Report {
    fn check(&mut self, what: &str, problem: Option<String>) {
        match problem {
            None => say(&format!("  ok       {what}")),
            Some(why) => {
                self.problems = self.problems.saturating_add(1);
                say(&format!("  PROBLEM  {what}: {why}"));
            }
        }
    }
}

fn setuid_problem(isudo: &Path) -> Option<String> {
    let meta = std::fs::metadata(isudo).ok()?;
    if meta.mode() & SETUID == 0 {
        return Some("the setuid bit is not set, so it cannot become root".to_owned());
    }
    if meta.mode() & SETGID != 0 {
        return Some("the setgid bit is set; it should not be".to_owned());
    }
    None
}

fn pairing_problem(path: &Path) -> Option<String> {
    let Ok(meta) = std::fs::metadata(path) else { return None };
    if meta.uid() != 0 || meta.mode() & 0o077 != 0 {
        return Some("it holds this machine's key and must be owned by root with mode 0600".to_owned());
    }
    None
}

pub(crate) fn run(pairing_file: &Path) -> Result<(), String> {
    let own = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .map_err(|e| format!("cannot find this program's own location: {e}"))?;
    let bin_dir = own.parent().ok_or("this program has no parent directory")?;
    let isudo = SETUID_PATH.map_or_else(|| bin_dir.join("isudo"), PathBuf::from);
    let helper = PathBuf::from(LIBEXEC_DIR).join("isudo-helper");

    say("Checking the isudo installation:");
    let mut report = Report { problems: 0 };
    report.check(&format!("{} cannot be replaced without root", isudo.display()), weak_link(&isudo));
    report.check(&format!("{} is setuid root", isudo.display()), setuid_problem(&isudo));
    report.check(&format!("{} cannot be replaced without root", own.display()), weak_link(&own));
    report.check(&format!("{} cannot be replaced without root", helper.display()), weak_link(&helper));
    if pairing_file.exists() {
        report.check(&format!("{} is private to root", pairing_file.display()), pairing_problem(pairing_file));
    } else {
        say("  note     no phone is paired yet");
    }

    if report.problems == 0 {
        say("All good.");
        return Ok(());
    }
    Err(format!(
        "{} problem(s). Until they are fixed, a non-root user may be able to substitute these programs.\n\
         Installing under a root-owned prefix (the default on macOS is /opt/isudo) avoids this.",
        report.problems
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_paths_are_strong_and_user_paths_are_not() {
        assert_eq!(weak_link(Path::new("/bin/sh")), None);
        // Whoever runs the tests, their temporary directory is not root's
        // alone, or does not hold a root-owned file of this name.
        let mine = std::env::temp_dir().join(format!("isudo-admin-check-{}", std::process::id()));
        std::fs::write(&mine, "x").unwrap();
        std::fs::set_permissions(&mine, std::os::unix::fs::PermissionsExt::from_mode(0o666)).unwrap();
        assert!(weak_link(&mine).is_some());
        std::fs::remove_file(&mine).unwrap();
        assert!(weak_link(Path::new("/nonexistent/isudo")).unwrap().contains("cannot be examined"));
    }

    #[test]
    fn an_ordinary_program_is_not_setuid() {
        assert!(setuid_problem(Path::new("/bin/sh")).unwrap().contains("setuid bit is not set"));
        assert_eq!(setuid_problem(Path::new("/nonexistent")), None);
    }
}
