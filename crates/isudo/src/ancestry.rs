//! Who is asking: the chain of processes above us.
//!
//! This is context for the approver ("claude > zsh > isudo"), not an
//! identity. Processes choose their own names, so the phone presents this as
//! unverified. Everything here is best effort and bounded; any failure just
//! ends the chain early.

use isudo_proto::request::Ancestor;

const MAX_DEPTH: usize = 6;
const MAX_NAME_LEN: usize = 64;

pub(crate) fn collect(start_pid: Option<u32>) -> Vec<Ancestor> {
    let mut chain: Vec<Ancestor> = Vec::new();
    let mut next = start_pid;
    while let Some(pid) = next {
        if pid <= 1 || chain.len() >= MAX_DEPTH || chain.iter().any(|seen| seen.pid == pid) {
            break;
        }
        let Some((mut name, parent)) = lookup(pid) else { break };
        name.truncate(MAX_NAME_LEN);
        chain.push(Ancestor { pid, name });
        next = Some(parent);
    }
    chain
}

#[cfg(target_os = "macos")]
fn lookup(pid: u32) -> Option<(Vec<u8>, u32)> {
    crate::sys::process_info(pid)
}

#[cfg(target_os = "linux")]
fn lookup(pid: u32) -> Option<(Vec<u8>, u32)> {
    use std::io::Read as _;
    let mut stat = Vec::new();
    let file = std::fs::File::open(format!("/proc/{pid}/stat")).ok()?;
    let _ = file.take(1024).read_to_end(&mut stat).ok()?;
    parse_stat(&stat)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn lookup(_pid: u32) -> Option<(Vec<u8>, u32)> {
    None
}

/// Parses `pid (comm) state ppid ...`. The name can itself contain spaces,
/// parentheses and newlines, so the fields after it are located from the
/// *last* closing parenthesis (sudo's CVE-2017-1000367 split on spaces).
#[cfg(any(target_os = "linux", test))]
fn parse_stat(stat: &[u8]) -> Option<(Vec<u8>, u32)> {
    let open = stat.iter().position(|b| *b == b'(')?;
    let close = stat.iter().rposition(|b| *b == b')')?;
    let name = stat.get(open.checked_add(1)?..close)?.to_vec();
    let mut fields = stat.get(close.checked_add(1)?..)?.split(|b| *b == b' ').filter(|field| !field.is_empty());
    let _state = fields.next()?;
    let parent = std::str::from_utf8(fields.next()?).ok()?.parse().ok()?;
    Some((name, parent))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_our_own_ancestors() {
        let chain = collect(Some(std::process::id()));
        assert_eq!(chain[0].pid, std::process::id());
        assert_ne!(chain[0].name, b"");
        assert!(chain.len() <= MAX_DEPTH);
    }

    #[test]
    fn stat_parsing_survives_hostile_names() {
        assert_eq!(parse_stat(b"42 (zsh) S 7 42 42 0"), Some((b"zsh".to_vec(), 7)));
        assert_eq!(parse_stat(b"42 (a) R 1 (b) S 999) S 7 42"), Some((b"a) R 1 (b) S 999".to_vec(), 7)));
        assert_eq!(parse_stat(b"42 (new\nline) S 7 1"), Some((b"new\nline".to_vec(), 7)));
        assert_eq!(parse_stat(b"garbage"), None);
        assert_eq!(parse_stat(b"42 )x( S 7"), None);
        assert_eq!(parse_stat(b"42 (x) S notanumber"), None);
    }

    #[test]
    fn nothing_above_init() {
        assert_eq!(collect(None), []);
        assert_eq!(collect(Some(0)), []);
        assert_eq!(collect(Some(1)), []);
    }
}
