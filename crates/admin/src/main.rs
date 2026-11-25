//! isudo-admin: pair this machine with a phone, or remove the pairing.
//!
//! Pairing is the moment trust is established: it decides whose key can
//! approve root commands here. So it is run by root (use `sudo`), at a
//! terminal, by a person, and it ends with that person typing a code read
//! off their own phone. See `isudo_proto::pairing` for what the code proves.

mod check;
mod pair;

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use isudo_client::relay::{Relay, RelayError};
use isudo_core::config::{self, Pairing};
use isudo_core::plan::HostKey;
use isudo_proto::api::Revoke;
use isudo_proto::codec::{b64_encode, hex_encode};
use isudo_proto::sigs;
use isudo_proto::text::escape;

const USAGE: &str = "\
usage: sudo isudo-admin pair --relay URL [--name NAME] [--timeout SECONDS]
                             [--secure-path DIRS] [--registration-token TOKEN]
       sudo isudo-admin unpair
       sudo isudo-admin watch on|off
       sudo isudo-admin status
            isudo-admin check

  pair     show a QR code for the isudo phone app, then pin that phone's key
  unpair   forget the paired phone
  watch    allow, or stop allowing, a watch that the paired phone authorises
           to answer: it may approve simple requests and deny any (default off)
  status   show which phone is paired
  check    verify that the installed programs cannot be replaced without root

  --relay URL          the relay both sides talk through (https://...)
  --name NAME          what to call this machine on the phone (default: its hostname)
  --timeout SECONDS    how long isudo waits for an answer (default 120)
  --secure-path DIRS   colon-separated directories isudo finds commands in
  --config FILE        pairing file to use instead of /etc/isudo/pairing.conf";

pub(crate) const DEFAULT_CONFIG: &str = "/etc/isudo/pairing.conf";

pub(crate) fn say(text: &str) {
    let mut out = std::io::stdout().lock();
    // If standard output is gone there is nobody to tell.
    drop(out.write_all(text.as_bytes()));
    drop(out.write_all(b"\n"));
    drop(out.flush());
}

fn is_root() -> bool {
    // SAFETY: geteuid takes no arguments and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

/// Command-line options, all optional at parse time.
#[derive(Default)]
pub(crate) struct Options {
    pub relay: Option<String>,
    pub name: Option<String>,
    pub timeout: Option<String>,
    pub secure_path: Option<String>,
    pub registration_token: Option<String>,
    pub config: Option<PathBuf>,
}

impl Options {
    pub(crate) fn config_path(&self) -> PathBuf {
        self.config.clone().unwrap_or_else(|| DEFAULT_CONFIG.into())
    }

    /// The real pairing file belongs to root. A file named with `--config`
    /// is the caller's own business (isudo itself never reads one).
    pub(crate) fn require_root(&self) -> Result<(), String> {
        if self.config.is_none() && !is_root() {
            return Err("this changes who can approve root commands, so it must be run as root (use sudo)".to_owned());
        }
        Ok(())
    }
}

fn parse(args: impl Iterator<Item = String>) -> Result<Options, String> {
    let mut options = Options::default();
    let mut args = args;
    while let Some(arg) = args.next() {
        let slot = match arg.as_str() {
            "--relay" => &mut options.relay,
            "--name" => &mut options.name,
            "--timeout" => &mut options.timeout,
            "--secure-path" => &mut options.secure_path,
            "--registration-token" => &mut options.registration_token,
            "--config" => {
                options.config = Some(args.next().ok_or("--config needs a value")?.into());
                continue;
            }
            other => return Err(format!("unknown option {other}")),
        };
        *slot = Some(args.next().ok_or_else(|| format!("{arg} needs a value"))?);
    }
    Ok(options)
}

fn read_pairing(path: &Path) -> Result<Option<Pairing>, String> {
    match std::fs::read(path) {
        Ok(text) => config::parse(&text).map(Some).map_err(|e| format!("{} {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            Err(format!("{} holds this machine's key and is readable only by root; run this with sudo", path.display()))
        }
        Err(e) => Err(format!("cannot read {}: {e}", path.display())),
    }
}

fn status(options: &Options) -> Result<(), String> {
    let path = options.config_path();
    match read_pairing(&path)? {
        None => say("No phone is paired with this machine."),
        Some(pairing) => {
            say(&format!("Paired with:  {}", escape(pairing.phone_name.as_bytes())));
            say(&format!("This machine: {}", escape(pairing.host_name.as_bytes())));
            say(&format!("Relay:        {}", escape(pairing.relay_url.as_bytes())));
            say(&format!("Pairing id:   {}", hex_encode(&pairing.id)));
            say(&format!("Timeout:      {}s", pairing.timeout_secs));
            say(if pairing.watch {
                "Watch:        allowed (a watch the phone authorises may approve simple requests)"
            } else {
                "Watch:        not allowed (only the phone can answer)"
            });
        }
    }
    Ok(())
}

fn unpair(options: &Options) -> Result<(), String> {
    options.require_root()?;
    let path = options.config_path();
    let Some(pairing) = read_pairing(&path)? else {
        say("No phone is paired with this machine.");
        return Ok(());
    };
    // Tell the relay, so the phone learns of it. The pairing file is removed
    // whether or not that works: removing it is what revokes the phone.
    let told =
        HostKey::new(&pairing.host_key).ok_or_else(|| "the stored host key is invalid".to_owned()).and_then(|key| {
            let relay = Relay::new(&pairing.relay_url).map_err(|e| e.to_string())?;
            let body = Revoke { host_sig: b64_encode(&key.sign(&sigs::pair_revoke_msg(&pairing.id))) };
            match relay.revoke_as_host(&hex_encode(&pairing.id), &body) {
                Ok(()) | Err(RelayError::Status(404)) => Ok(()),
                Err(e) => Err(e.to_string()),
            }
        });
    std::fs::remove_file(&path).map_err(|e| format!("cannot remove {}: {e}", path.display()))?;
    say(&format!("Unpaired from {}.", escape(pairing.phone_name.as_bytes())));
    if let Err(why) = told {
        say(&format!("(The relay could not be told: {why}. The phone may still list this machine.)"));
    }
    Ok(())
}

/// Turns the watch on or off in the pairing file.
///
/// This is root's decision, not the phone's. A watch cannot check a face,
/// so its approval says less than the phone's about who gave it; whether
/// that is acceptable on this machine is for whoever administers it.
fn watch(setting: &str, options: &Options) -> Result<(), String> {
    let allow = match setting {
        "on" => true,
        "off" => false,
        _ => return Err(USAGE.to_owned()),
    };
    options.require_root()?;
    let path = options.config_path();
    let Some(mut pairing) = read_pairing(&path)? else {
        return Err("no phone is paired with this machine; pair one first".to_owned());
    };
    pairing.watch = allow;
    pair::write_pairing(&path, &config::render(&pairing)?)?;
    let phone = escape(pairing.phone_name.as_bytes());
    if allow {
        say(&format!("A watch that {phone} authorises may now approve simple requests, and deny any request."));
        say("Authorise one in the isudo app on the phone. Everything else still needs the phone.");
    } else {
        say(&format!("Only {phone} can answer now. A watch's answer is refused from this moment."));
    }
    Ok(())
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let command = args.next().ok_or_else(|| USAGE.to_owned())?;
    if matches!(command.as_str(), "-h" | "--help" | "help") {
        say(USAGE);
        return Ok(());
    }
    // `watch` takes one word before any options.
    let setting = if command == "watch" { Some(args.next().ok_or_else(|| USAGE.to_owned())?) } else { None };
    let options = parse(args).map_err(|e| [e.as_str(), "\n", USAGE].concat())?;
    match (command.as_str(), setting) {
        ("watch", Some(setting)) => return watch(&setting, &options),
        (_, Some(_)) => return Err(USAGE.to_owned()),
        (_, None) => {}
    }
    match command.as_str() {
        "pair" => pair::run(&options),
        "unpair" => unpair(&options),
        "status" => status(&options),
        "check" => check::run(&options.config_path()),
        _ => Err(USAGE.to_owned()),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            let mut err = std::io::stderr().lock();
            drop(err.write_all(["isudo-admin: ", &message, "\n"].concat().as_bytes()));
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(args: &[&str]) -> Result<Options, String> {
        parse(args.iter().map(|arg| (*arg).to_owned()))
    }

    #[test]
    fn options_are_parsed() {
        let options = parsed(&["--relay", "https://r.example", "--name", "box", "--config", "/tmp/p.conf"]).unwrap();
        assert_eq!(options.relay.as_deref(), Some("https://r.example"));
        assert_eq!(options.name.as_deref(), Some("box"));
        assert_eq!(options.config_path(), PathBuf::from("/tmp/p.conf"));
        assert_eq!(parsed(&[]).unwrap().config_path(), PathBuf::from(DEFAULT_CONFIG));
    }

    #[test]
    fn bad_options_are_errors() {
        assert!(parsed(&["--relay"]).is_err());
        assert!(parsed(&["--config"]).is_err());
        assert!(parsed(&["--frobnicate"]).is_err());
        assert!(parsed(&["stray"]).is_err());
    }

    #[test]
    fn a_custom_config_does_not_need_root() {
        let options = parsed(&["--config", "/tmp/p.conf"]).unwrap();
        assert_eq!(options.require_root(), Ok(()));
    }
}
