//! Randomized tests of what the root process is handed by its caller: its
//! arguments, its environment, and (by root, but still parsed) its pairing
//! file. Run with `ISUDO_FUZZ_CASES=1000000` for a long soak.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt as _;

use isudo_proto::envrisk::is_shell_function;
use isudo_proto::request::EnvOrigin;
use isudo_proto::testgen::{cases, Rng};

use crate::args::{self, is_env_name, Invocation, Parsed};
use crate::config::{self, Pairing};
use crate::env::{self, Identity};

/// Things an argument list is made of, including every option that exists
/// and several that do not.
const WORDS: &[&[u8]] = &[
    b"--",
    b"-h",
    b"--help",
    b"-V",
    b"--version",
    b"--skill",
    b"--preserve-env=FOO",
    b"--preserve-env=FOO,BAR",
    b"--preserve-env=",
    b"--preserve-env",
    b"--preserve-env=1BAD",
    b"-E",
    b"-u",
    b"-i",
    b"root",
    b"A=1",
    b"LD_PRELOAD=/tmp/x.so",
    b"=x",
    b"1A=2",
    b"A=",
    b"A=b=c",
    b"ls",
    b"-l",
    b"/bin/sh",
    b"./tool",
    b"",
    b"a b",
    b"\xff\xfe",
    b"x\0y",
];

fn word(rng: &mut Rng) -> Vec<u8> {
    if rng.chance(85) {
        rng.pick(WORDS).copied().unwrap().to_vec()
    } else {
        rng.text(12)
    }
}

/// Whatever the caller types, parsing returns. When it yields a command,
/// that command is the tail of what was typed, byte for byte: nothing is
/// reinterpreted on the way to being shown and run.
#[test]
fn arguments_are_parsed_or_refused_and_the_command_is_what_was_typed() {
    let mut rng = Rng(0xa465);
    let (mut ran, mut refused) = (0_usize, 0_usize);
    for _ in 0..cases(20_000) {
        let typed: Vec<Vec<u8>> = (0..rng.below(7)).map(|_| word(&mut rng)).collect();
        match args::parse(typed.iter().cloned().map(OsString::from_vec)) {
            Ok(Parsed::Run(Invocation { assignments, preserve, command })) => {
                ran = ran.saturating_add(1);
                assert!(!command.is_empty() && !command[0].is_empty(), "an empty command from {typed:?}");
                assert!(typed.ends_with(&command), "{command:?} is not the tail of {typed:?}");
                for name in assignments.iter().map(|(name, _)| name).chain(&preserve) {
                    assert!(is_env_name(name), "{name:?} taken as a variable name from {typed:?}");
                }
            }
            Ok(Parsed::Help | Parsed::Version | Parsed::Skill) => {}
            Err(message) => {
                refused = refused.saturating_add(1);
                // What is said back is plain text, whatever was typed.
                assert!(!message.chars().any(|c| c.is_control() && c != '\n'), "{message:?}");
            }
        }
    }
    assert!(ran > 100 && refused > 100, "ran {ran}, refused {refused}");
}

const NAMES: &[&[u8]] = &[
    b"PATH",
    b"HOME",
    b"TERM",
    b"LANG",
    b"LC_ALL",
    b"LC_TIME",
    b"TZ",
    b"COLORTERM",
    b"LD_PRELOAD",
    b"LD_LIBRARY_PATH",
    b"DYLD_INSERT_LIBRARIES",
    b"BASH_ENV",
    b"BASH_FUNC_x%%",
    b"PYTHONPATH",
    b"NODE_OPTIONS",
    b"IFS",
    b"FOO",
    b"BAR",
    b"SECRET",
    b"SUDO_USER",
    b"USER",
    b"",
    b"A=B",
    b"1X",
];

const VALUES: &[&[u8]] = &[
    b"1",
    b"",
    b"xterm-256color",
    b"en_CA.UTF-8",
    b"../../etc/passwd",
    b"/tmp/evil.so",
    b"America/Toronto",
    b"/etc/shadow",
    b"() { :; }; echo pwned",
    b"a%sb",
    b"x\0y",
    b"two\nlines",
];

fn pair(rng: &mut Rng) -> (Vec<u8>, Vec<u8>) {
    let name = if rng.chance(90) { rng.pick(NAMES).copied().unwrap().to_vec() } else { rng.text(8) };
    let value = if rng.chance(80) { rng.pick(VALUES).copied().unwrap().to_vec() } else { rng.text(20) };
    (name, value)
}

/// Whatever environment the caller arrives with and whatever it asks to
/// keep, the command's environment is well formed, says the same thing in
/// both of its forms, and contains nothing from the caller that was not
/// either on the short default list or named outright.
#[test]
fn the_environment_holds_only_what_was_built_defaulted_or_named() {
    let identity = Identity {
        secure_path: "/usr/bin:/bin",
        root_home: b"/var/root",
        root_shell: b"/bin/sh",
        caller_name: b"burke",
        caller_uid: 501,
        caller_gid: 20,
    };
    let mut rng = Rng(0xe47);
    let (mut built_count, mut refused) = (0_usize, 0_usize);
    for _ in 0..cases(20_000) {
        let caller: Vec<(Vec<u8>, Vec<u8>)> = (0..rng.below(10)).map(|_| pair(&mut rng)).collect();
        let invocation = Invocation {
            // Only names the argument parser could have let through.
            assignments: (0..rng.below(3)).map(|_| pair(&mut rng)).filter(|(name, _)| is_env_name(name)).collect(),
            preserve: (0..rng.below(3)).map(|_| pair(&mut rng).0).filter(|name| is_env_name(name)).collect(),
            command: vec![b"true".to_vec()],
        };
        let Ok(built) = env::build(&invocation, &caller, &identity) else {
            refused = refused.saturating_add(1);
            continue;
        };
        built_count = built_count.saturating_add(1);
        assert_eq!(built.envp.len(), built.described.len());
        let mut names = BTreeSet::new();
        for (entry, var) in built.envp.iter().zip(&built.described) {
            // The executed form and the signed form are the same entry.
            assert_eq!(entry, &[var.name.as_slice(), b"=", var.value.as_slice()].concat());
            assert!(is_env_name(&var.name), "{:?} in the environment", var.name);
            assert!(!var.value.contains(&0), "a NUL in the value of {:?}", var.name);
            assert!(names.insert(var.name.clone()), "{:?} appears twice", var.name);
            let asked_for = invocation.preserve.contains(&var.name)
                || invocation.assignments.iter().any(|(name, _)| *name == var.name);
            match var.origin {
                EnvOrigin::Explicit => {
                    assert!(asked_for, "{:?} is marked as named, and was not", var.name);
                    assert!(!is_shell_function(&var.value), "an exported function got through in {:?}", var.name);
                }
                EnvOrigin::Default => {
                    // Passed without being asked for: only the short list,
                    // and only values that cannot name a file or a format.
                    let name = std::str::from_utf8(&var.name).unwrap();
                    let listed = ["COLORTERM", "LANG", "LANGUAGE", "LINGUAS", "TERM", "TZ"].contains(&name)
                        || name.starts_with("LC_");
                    assert!(listed, "{name} passed by default");
                    if name == "TZ" {
                        // The time zone has its own rule, sudo's: libc opens
                        // the file it names, so it must not climb out of
                        // the zone directory or hold anything unprintable.
                        let zone = var.value.strip_prefix(b":").unwrap_or(&var.value);
                        assert!(!zone.windows(2).any(|pair| pair == b".."), "TZ climbs: {zone:?}");
                        assert!(zone.iter().all(u8::is_ascii_graphic), "TZ is not plain: {zone:?}");
                        assert!(
                            zone.first() != Some(&b'/')
                                || zone.starts_with(b"/usr/share/zoneinfo/")
                                || zone.starts_with(b"/var/db/timezone/zoneinfo/")
                        );
                    } else {
                        assert!(!var.value.contains(&b'%'), "{name} passed by default with a % in it");
                        assert!(!var.value.contains(&b'/'), "{name} passed by default with a / in it");
                    }
                    assert!(!is_shell_function(&var.value));
                }
                EnvOrigin::Constructed => {}
            }
        }
        // Nothing the caller merely had, without naming it, is there.
        for (name, _) in &caller {
            let unasked = !invocation.preserve.contains(name) && !invocation.assignments.iter().any(|(n, _)| n == name);
            if unasked
                && (name.starts_with(b"LD_") || name.starts_with(b"DYLD_") || name == b"BASH_ENV" || name == b"SECRET")
            {
                assert!(!names.contains(name), "{name:?} crossed over without being named");
            }
        }
    }
    assert!(built_count > 1000 && refused > 100, "built {built_count}, refused {refused}");
}

fn pairing(rng: &mut Rng) -> Pairing {
    let word = |rng: &mut Rng| String::from_utf8(rng.plain(12)).unwrap().trim().to_owned();
    let name = |rng: &mut Rng| {
        let text = word(rng);
        if text.is_empty() {
            "x".to_owned()
        } else {
            text
        }
    };
    Pairing {
        id: rng.array(),
        host_name: name(rng),
        relay_url: ["https://", &name(rng)].concat(),
        host_key: rng.array(),
        phone_sign_pub: rng.array(),
        phone_kem_pub: rng.array(),
        phone_name: name(rng),
        timeout_secs: u32::try_from(rng.below(500).saturating_add(30)).unwrap(),
        secure_path: ["/", &name(rng).replace(':', "_"), ":/usr/bin"].concat(),
        watch: rng.chance(50),
    }
}

/// A pairing file that was written is read back as written, a damaged one
/// is read as what it now says or refused, and nothing makes the parser
/// panic. Root writes this file, but root's parser should not need luck.
#[test]
fn pairing_files_round_trip_and_damage_is_survived() {
    let mut rng = Rng(0xc0f1);
    let (mut written, mut accepted) = (0_usize, 0_usize);
    for _ in 0..cases(5000) {
        let pairing = pairing(&mut rng);
        let Ok(text) = config::render(&pairing) else { continue };
        written = written.saturating_add(1);
        assert_eq!(config::parse(text.as_bytes()).as_ref(), Ok(&pairing));

        let mut damaged = text.into_bytes();
        rng.mutate(&mut damaged);
        if let Ok(parsed) = config::parse(&damaged) {
            accepted = accepted.saturating_add(1);
            // Whatever it parsed to can be written and read back the same.
            if let Ok(again) = config::render(&parsed) {
                assert_eq!(config::parse(again.as_bytes()), Ok(parsed));
            }
        }
        drop(config::parse(&rng.bytes(200)));
        drop(config::parse(&rng.text(200)));
    }
    assert!(written > 100 && accepted > 20, "wrote {written}, accepted {accepted} damaged files");
}
