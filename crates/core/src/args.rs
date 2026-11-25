//! Command-line parsing.
//!
//! The grammar is deliberately small:
//!
//! ```text
//! isudo [--preserve-env=NAME[,NAME...]]... [NAME=value]... [--] command [argument...]
//! ```
//!
//! Options and assignments are recognized only before the command. Everything
//! from the command onward is passed through byte for byte and never
//! inspected, unescaped or rejoined (sudo's CVE-2021-3156 and CVE-2023-22809
//! both came from re-parsing arguments in privileged code).

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;

use isudo_proto::text::escape;

/// Instructions for AI agents on using isudo well.
///
/// In the "skill" format: Markdown with a name and description up front.
/// Printed by `isudo --skill` so that it can be saved wherever an agent
/// looks for skills.
pub const SKILL: &str = include_str!("skill.md");

pub const USAGE: &str = "\
usage: isudo [--preserve-env=NAME[,NAME...]] [NAME=value ...] [--] command [argument ...]

Runs a command as root once it has been approved on the paired phone.

  NAME=value             set a variable in the command's environment
  --preserve-env=NAMES   pass these variables from your environment
  --                     treat everything after this as the command
  -h, --help             show this help
  -V, --version          show the version
      --skill            print instructions for AI agents on using isudo

Variables passed either way are shown to the approver. Everything else in
your environment is dropped, apart from TERM, the locale and TZ.";

#[derive(Debug, PartialEq, Eq)]
pub enum Parsed {
    Help,
    Version,
    /// Print the agent skill.
    Skill,
    Run(Invocation),
}

#[derive(Debug, PartialEq, Eq)]
pub struct Invocation {
    /// `NAME=value` assignments, in order.
    pub assignments: Vec<(Vec<u8>, Vec<u8>)>,
    /// Names from `--preserve-env`, in order.
    pub preserve: Vec<Vec<u8>>,
    /// The command as typed, then its arguments. Never empty.
    pub command: Vec<Vec<u8>>,
}

impl Invocation {
    /// The command as typed.
    #[must_use]
    pub fn name(&self) -> &[u8] {
        self.command.first().map_or(&[], Vec::as_slice)
    }
}

/// A valid variable name: a letter or underscore, then letters, digits or
/// underscores.
#[must_use]
pub fn is_env_name(name: &[u8]) -> bool {
    match name.split_first() {
        Some((first, rest)) => {
            (first.is_ascii_alphabetic() || *first == b'_')
                && rest.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'_')
        }
        None => false,
    }
}

fn split_assignment(arg: &[u8]) -> Option<(&[u8], &[u8])> {
    let mut parts = arg.splitn(2, |b| *b == b'=');
    let (name, value) = (parts.next()?, parts.next()?);
    is_env_name(name).then_some((name, value))
}

/// Parses the arguments after the program name.
///
/// # Errors
/// Fails with a message for the caller on an unknown option, a malformed
/// `--preserve-env`, or a missing command.
pub fn parse<I>(args: I) -> Result<Parsed, String>
where
    I: IntoIterator<Item = OsString>,
{
    let mut args = args.into_iter().map(OsString::into_vec).peekable();
    let mut assignments = Vec::new();
    let mut preserve = Vec::new();

    // Options and assignments.
    while let Some(arg) = args.peek() {
        if arg == b"--" {
            let _ = args.next();
            break;
        }
        if arg == b"-h" || arg == b"--help" {
            return Ok(Parsed::Help);
        }
        if arg == b"-V" || arg == b"--version" {
            return Ok(Parsed::Version);
        }
        if arg == b"--skill" {
            return Ok(Parsed::Skill);
        }
        if let Some(list) = arg.strip_prefix(b"--preserve-env=") {
            for name in list.split(|b| *b == b',') {
                if !is_env_name(name) {
                    return Err(format!("--preserve-env: \"{}\" is not a variable name", escape(name)));
                }
                preserve.push(name.to_vec());
            }
            let _ = args.next();
            continue;
        }
        if arg.first() == Some(&b'-') {
            let shown = escape(arg);
            return Err(match shown.as_str() {
                "-E" | "--preserve-env" => {
                    "passing the whole environment is not supported; name the variables with --preserve-env=NAME".into()
                }
                "-u" | "--user" | "-g" | "--group" => "isudo only runs commands as root".into(),
                _ => format!("unknown option {shown}"),
            });
        }
        if let Some((name, value)) = split_assignment(arg) {
            assignments.push((name.to_vec(), value.to_vec()));
            let _ = args.next();
            continue;
        }
        break;
    }

    let command: Vec<Vec<u8>> = args.collect();
    match command.first() {
        None => Err("no command given".into()),
        Some(name) if name.is_empty() => Err("the command name is empty".into()),
        Some(_) => Ok(Parsed::Run(Invocation { assignments, preserve, command })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_strs(args: &[&str]) -> Result<Parsed, String> {
        parse(args.iter().map(OsString::from))
    }

    fn run(args: &[&str]) -> Invocation {
        match parse_strs(args) {
            Ok(Parsed::Run(inv)) => inv,
            other => panic!("expected a command, got {other:?}"),
        }
    }

    #[test]
    fn plain_command() {
        let inv = run(&["ls", "-la", "/root"]);
        assert_eq!(inv.command, vec![b"ls".to_vec(), b"-la".to_vec(), b"/root".to_vec()]);
        assert!(inv.assignments.is_empty() && inv.preserve.is_empty());
    }

    #[test]
    fn assignments_and_preserve() {
        let inv = run(&["--preserve-env=FOO,BAR", "DEBUG=1", "X=a=b", "make", "install"]);
        assert_eq!(inv.preserve, vec![b"FOO".to_vec(), b"BAR".to_vec()]);
        assert_eq!(inv.assignments, vec![(b"DEBUG".to_vec(), b"1".to_vec()), (b"X".to_vec(), b"a=b".to_vec())]);
        assert_eq!(inv.command, vec![b"make".to_vec(), b"install".to_vec()]);
    }

    #[test]
    fn nothing_after_the_command_is_interpreted() {
        let inv = run(&["env", "A=1", "--preserve-env=X", "-h", "--"]);
        assert_eq!(inv.command.len(), 5);
        assert!(inv.assignments.is_empty() && inv.preserve.is_empty());
    }

    #[test]
    fn double_dash_ends_options_and_assignments() {
        let inv = run(&["A=1", "--", "B=2", "-x"]);
        assert_eq!(inv.assignments, vec![(b"A".to_vec(), b"1".to_vec())]);
        assert_eq!(inv.command, vec![b"B=2".to_vec(), b"-x".to_vec()]);
    }

    #[test]
    fn things_that_look_like_assignments_but_are_not() {
        // Not a valid name, so it is the command.
        let inv = run(&["./a=b", "x"]);
        assert_eq!(inv.command[0], b"./a=b");
        let inv = run(&["1A=b"]);
        assert_eq!(inv.command[0], b"1A=b");
    }

    #[test]
    fn help_and_version() {
        assert_eq!(parse_strs(&["--help"]), Ok(Parsed::Help));
        assert_eq!(parse_strs(&["-V"]), Ok(Parsed::Version));
        assert_eq!(parse_strs(&["--skill"]), Ok(Parsed::Skill));
        // After the command they belong to the command.
        assert!(matches!(parse_strs(&["ls", "--help"]), Ok(Parsed::Run(_))));
    }

    #[test]
    fn the_skill_is_a_well_formed_skill() {
        // Front matter with a name and a description, then the body.
        let mut parts = SKILL.splitn(3, "---\n");
        assert_eq!(parts.next(), Some(""));
        let front = parts.next().unwrap();
        assert!(front.lines().any(|line| line == "name: isudo"));
        assert!(front.lines().any(|line| line.starts_with("description: ") && line.len() > 80));
        let body = parts.next().unwrap();
        assert!(body.contains("# Running commands as root with isudo"));
        // It must describe the interface that actually exists.
        assert!(body.contains("--preserve-env=") && USAGE.contains("--preserve-env="));
        for status in ["126", "127"] {
            assert!(body.contains(status));
        }
    }

    #[test]
    fn errors() {
        assert!(parse_strs(&[]).is_err());
        assert!(parse_strs(&["A=1"]).is_err());
        assert!(parse_strs(&["--"]).is_err());
        assert!(parse_strs(&[""]).is_err());
        assert!(parse_strs(&["-E", "ls"]).unwrap_err().contains("--preserve-env=NAME"));
        assert!(parse_strs(&["-u", "bob", "ls"]).unwrap_err().contains("only runs commands as root"));
        assert!(parse_strs(&["--frobnicate", "ls"]).unwrap_err().contains("unknown option"));
        assert!(parse_strs(&["--preserve-env=A=B", "ls"]).is_err());
        assert!(parse_strs(&["--preserve-env=", "ls"]).is_err());
    }
}
