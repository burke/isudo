//! Finding the file a command name refers to.
//!
//! The command is resolved exactly once. The resulting path goes into the
//! signed request and is the path handed to `execve`; it is never looked up
//! again (sudo-rs's 2026 sudoedit advisory was a second resolution of the
//! same name after the policy check).

use std::ffi::OsStr;
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Resolved {
    /// Absolute path to exec.
    pub path: Vec<u8>,
    /// The file or its directory can be changed by someone other than root.
    pub writable_by_non_root: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ResolveError {
    NotFound,
    NotExecutable(Vec<u8>),
}

fn join(dir: &[u8], name: &[u8]) -> Vec<u8> {
    let mut path = dir.to_vec();
    if path.last() != Some(&b'/') {
        path.push(b'/');
    }
    path.extend_from_slice(name);
    path
}

/// Splits an absolute path into its directory and final component.
fn split_parent(path: &[u8]) -> (&[u8], &[u8]) {
    let mut parts = path.rsplitn(2, |b| *b == b'/');
    let name = parts.next().unwrap_or_default();
    match parts.next() {
        Some([]) | None => (b"/", name),
        Some(parent) => (parent, name),
    }
}

/// What kind of thing is at a path, as far as running it goes.
enum Candidate {
    Missing,
    NotExecutable,
    Executable,
}

fn inspect(path: &[u8]) -> Candidate {
    match std::fs::metadata(Path::new(OsStr::from_bytes(path))) {
        Err(_) => Candidate::Missing,
        Ok(meta) if meta.is_file() && meta.mode() & 0o111 != 0 => Candidate::Executable,
        Ok(_) => Candidate::NotExecutable,
    }
}

/// True if someone other than root could change what `path` leads to: the
/// entry itself, or any directory above it up to the root (whoever can
/// rename a directory can substitute everything beneath it). Anything that
/// cannot be examined is assumed to be changeable.
///
/// A sticky directory is not counted merely for being group- or
/// world-writable: there, only an entry's owner can rename or remove it, and
/// each entry on the way down is itself required to belong to root.
fn changeable(path: &[u8]) -> bool {
    const STICKY: u32 = 0o1000;
    let mut current = Path::new(OsStr::from_bytes(path));
    loop {
        let Ok(meta) = std::fs::metadata(current) else { return true };
        let loosely_writable = meta.mode() & 0o022 != 0;
        let protected_by_sticky = meta.is_dir() && meta.mode() & STICKY != 0;
        if meta.uid() != 0 || (loosely_writable && !protected_by_sticky) {
            return true;
        }
        match current.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => current = parent,
            _ => return false,
        }
    }
}

/// [`changeable`], for the path as it will be executed and, if its last
/// component is a symlink, for where that leads as well.
fn writable_by_non_root(path: &[u8]) -> bool {
    if changeable(path) {
        return true;
    }
    std::fs::canonicalize(Path::new(OsStr::from_bytes(path)))
        .map_or(true, |real| changeable(real.as_os_str().as_bytes()))
}

/// Resolves `command` the way a shell would, except that names without a
/// slash are searched for only in `secure_path`, never the caller's PATH,
/// and never in the current directory.
///
/// Call this with the caller's credentials in effect: it reports only what
/// the caller could have found out by looking.
pub(crate) fn resolve(command: &[u8], secure_path: &str, cwd: &[u8]) -> Result<Resolved, ResolveError> {
    let path = if command.contains(&b'/') { by_path(command, cwd)? } else { by_search(command, secure_path)? };
    let writable = writable_by_non_root(&path);
    Ok(Resolved { path, writable_by_non_root: writable })
}

fn by_path(command: &[u8], cwd: &[u8]) -> Result<Vec<u8>, ResolveError> {
    let absolute = if command.first() == Some(&b'/') { command.to_vec() } else { join(cwd, command) };
    // Canonicalize the directory but keep the final name, so that the
    // approver sees the name that was asked for, in the place it really is.
    let (parent, name) = split_parent(&absolute);
    if matches!(name, b"" | b"." | b"..") {
        return Err(ResolveError::NotExecutable(absolute));
    }
    let parent = std::fs::canonicalize(Path::new(OsStr::from_bytes(parent)))
        .map_err(|_e| ResolveError::NotFound)?
        .into_os_string()
        .into_vec();
    let path = join(&parent, name);
    match inspect(&path) {
        Candidate::Executable => Ok(path),
        Candidate::NotExecutable => Err(ResolveError::NotExecutable(path)),
        Candidate::Missing => Err(ResolveError::NotFound),
    }
}

fn by_search(command: &[u8], secure_path: &str) -> Result<Vec<u8>, ResolveError> {
    let mut not_executable = None;
    for dir in secure_path.split(':').filter(|dir| dir.starts_with('/')) {
        // A directory that someone other than root can write to is not a
        // place to find commands by bare name: whoever can write there
        // chooses what `isudo ls` means. Programs in such places can still
        // be run by giving their path, and the approver is then told.
        if changeable(dir.as_bytes()) {
            continue;
        }
        let path = join(dir.as_bytes(), command);
        match inspect(&path) {
            Candidate::Executable => return Ok(path),
            Candidate::NotExecutable => {
                let _ = not_executable.get_or_insert(path);
            }
            Candidate::Missing => {}
        }
    }
    Err(not_executable.map_or(ResolveError::NotFound, ResolveError::NotExecutable))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    struct Scratch(std::path::PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("isudo-resolve-{tag}-{}", std::process::id()));
            drop(std::fs::remove_dir_all(&dir));
            std::fs::create_dir_all(dir.join("bin")).unwrap();
            // Tests compare against canonical paths (/tmp is a symlink on macOS).
            Self(dir.canonicalize().unwrap())
        }

        fn file(&self, rel: &str, mode: u32) -> Vec<u8> {
            let path = self.0.join(rel);
            std::fs::write(&path, "#!/bin/sh\n").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            path.as_os_str().as_bytes().to_vec()
        }

        fn bytes(&self) -> Vec<u8> {
            self.0.as_os_str().as_bytes().to_vec()
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            drop(std::fs::remove_dir_all(&self.0));
        }
    }

    #[test]
    fn split_parent_cases() {
        assert_eq!(split_parent(b"/bin/sh"), (&b"/bin"[..], &b"sh"[..]));
        assert_eq!(split_parent(b"/sh"), (&b"/"[..], &b"sh"[..]));
        assert_eq!(split_parent(b"/bin/"), (&b"/bin"[..], &b""[..]));
        assert_eq!(split_parent(b"/"), (&b"/"[..], &b""[..]));
    }

    #[test]
    fn bare_names_use_only_the_secure_path() {
        let resolved = resolve(b"sh", "/nonexistent:/bin", b"/").unwrap();
        assert_eq!(resolved.path, b"/bin/sh");
        assert_eq!(resolve(b"sh", "/nonexistent", b"/bin"), Err(ResolveError::NotFound));
        // Relative entries in the secure path are skipped, not searched.
        assert_eq!(resolve(b"sh", "bin:.", b"/"), Err(ResolveError::NotFound));
    }

    #[test]
    fn the_current_directory_is_never_searched() {
        let scratch = Scratch::new("cwd");
        // World-writable, so it is flagged whoever runs the tests (root included).
        let _ = scratch.file("tool", 0o777);
        assert_eq!(resolve(b"tool", "/usr/bin:/bin", &scratch.bytes()), Err(ResolveError::NotFound));
        // ...but asking for it by path works, and is flagged as changeable.
        let resolved = resolve(b"./tool", "/usr/bin:/bin", &scratch.bytes()).unwrap();
        assert_eq!(resolved.path, join(&scratch.bytes(), b"tool"));
        assert!(resolved.writable_by_non_root);
    }

    #[test]
    fn paths_are_made_absolute_and_directories_canonical() {
        let scratch = Scratch::new("canon");
        let _ = scratch.file("bin/tool", 0o755);
        let resolved = resolve(b"bin/../bin/./tool", "/usr/bin", &scratch.bytes()).unwrap();
        assert_eq!(resolved.path, join(&scratch.bytes(), b"bin/tool"));
    }

    #[test]
    fn non_executables_and_directories_are_refused() {
        let scratch = Scratch::new("noexec");
        let plain = scratch.file("bin/data", 0o644);
        assert_eq!(resolve(&plain, "/usr/bin", b"/"), Err(ResolveError::NotExecutable(plain.clone())));
        let dir = join(&scratch.bytes(), b"bin");
        assert_eq!(resolve(&dir, "/usr/bin", b"/"), Err(ResolveError::NotExecutable(dir.clone())));
        assert!(matches!(resolve(b"/bin/", "/usr/bin", b"/"), Err(ResolveError::NotExecutable(_))));
        assert!(matches!(resolve(b"/bin/..", "/usr/bin", b"/"), Err(ResolveError::NotExecutable(_))));
        assert_eq!(resolve(b"/no/such/file", "/usr/bin", b"/"), Err(ResolveError::NotFound));
        // In a search, a non-executable match is reported if nothing better
        // turns up. (/etc is a root-owned directory holding a plain file.)
        assert_eq!(resolve(b"hosts", "/etc", b"/"), Err(ResolveError::NotExecutable(b"/etc/hosts".to_vec())));
        // The scratch directory is not root's, so it is not searched at all.
        let bin = String::from_utf8(dir).unwrap();
        assert_eq!(resolve(b"data", &bin, b"/"), Err(ResolveError::NotFound));
        drop(plain);
    }

    #[test]
    fn writable_directories_are_not_searched() {
        // The scratch directory belongs to whoever runs the tests, or is
        // made world-writable below, so it must be skipped either way.
        let scratch = Scratch::new("search");
        let tool = scratch.file("bin/sh", 0o755);
        let bin = join(&scratch.bytes(), b"bin");
        std::fs::set_permissions(Path::new(OsStr::from_bytes(&bin)), std::fs::Permissions::from_mode(0o777)).unwrap();
        let search = format!("{}:/bin", String::from_utf8(bin).unwrap());
        // `sh` is found in /bin, not in the writable directory listed first.
        assert_eq!(resolve(b"sh", &search, b"/").unwrap().path, b"/bin/sh");
        // Asked for by path, the same file runs, and is flagged.
        let by_path = resolve(&tool, &search, b"/").unwrap();
        assert_eq!(by_path.path, tool);
        assert!(by_path.writable_by_non_root);
    }

    #[test]
    fn a_writable_ancestor_is_enough_to_flag() {
        // The file and its own directory are locked down; a directory two
        // levels up is not. Whoever can rename that can replace the lot.
        let scratch = Scratch::new("ancestor");
        std::fs::create_dir_all(scratch.0.join("bin/inner")).unwrap();
        let tool = scratch.file("bin/inner/tool", 0o555);
        std::fs::set_permissions(scratch.0.join("bin/inner"), std::fs::Permissions::from_mode(0o555)).unwrap();
        std::fs::set_permissions(scratch.0.join("bin"), std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(resolve(&tool, "/bin", b"/").unwrap().writable_by_non_root);
        std::fs::set_permissions(scratch.0.join("bin/inner"), std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn sticky_directories_do_not_count_as_writable_by_themselves() {
        // /tmp is world-writable and sticky; / and (on Linux) /tmp belong to
        // root. A path through it is judged by its other components.
        let tmp = if cfg!(target_os = "macos") { "/private/tmp" } else { "/tmp" };
        assert!(!changeable(tmp.as_bytes()), "{tmp} itself should not count as changeable");
        assert!(changeable(b"/nonexistent/thing"), "what cannot be examined is assumed changeable");
    }

    #[test]
    fn system_binaries_are_not_flagged() {
        let resolved = resolve(b"/bin/sh", "/usr/bin", b"/").unwrap();
        assert!(!resolved.writable_by_non_root);
    }
}
