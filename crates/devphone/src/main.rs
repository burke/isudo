//! isudo-devphone: a phone for the terminal.
//!
//! It pairs with a host and approves or denies requests exactly as the iOS
//! app does, using the same checks (`isudo-phone`), but with its key in a
//! file and no Face ID. It exists for testing and development. Anyone who
//! can read its state file can approve root commands on the paired host, so
//! do not leave a real machine paired with it.

#![forbid(unsafe_code)]

mod render;

use std::collections::BTreeSet;
use std::io::{BufRead as _, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use isudo_client::relay::{Relay, RelayError};
use isudo_phone::{Card, Delegate, Pairing, Progress, Refusal};
use isudo_proto::api::{AddDelegate, Answer, PendingRequest};
use isudo_proto::codec::{b64_decode, b64_encode, hex_decode_array, hex_encode};
use isudo_proto::delegation::SignedDelegation;
use isudo_proto::pairing::Offer;
use serde::{Deserialize, Serialize};

const USAGE: &str = "\
usage: isudo-devphone pair LINK [--state FILE] [--name NAME]
       isudo-devphone watch [--state FILE] [--approve | --deny[=REASON]] [--once]
       isudo-devphone add-watch WATCH_FILE [--state FILE] [--name NAME] [--valid-for SECONDS]
       isudo-devphone unpair [--state FILE]

A stand-in for the phone app, for testing. LINK is the isudo://pair?... link
printed by `isudo-admin pair`. The state file (default ./isudo-devphone.json)
holds this phone's key in the clear.

`watch` waits for requests and answers them. `add-watch` makes a stand-in for
the person's watch: a second device with keys of its own, authorised by this
phone and written to WATCH_FILE. Run `watch --state WATCH_FILE` to be that
watch, which may approve only what the computer marks as simple.";

const DEFAULT_STATE: &str = "isudo-devphone.json";
const PAIRING_WAIT: Duration = Duration::from_secs(300);
const POLL_EVERY: Duration = Duration::from_secs(1);

/// What is kept between runs: enough to rebuild the pairing.
#[derive(Serialize, Deserialize)]
struct Stored {
    offer: String,
    seed: String,
    active: bool,
    /// Present in a watch's state file: the phone's authorisation of it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    delegation: Option<String>,
}

/// How long a stand-in watch is authorised for unless told otherwise.
const DEFAULT_VALID_FOR_SECS: u64 = 24 * 60 * 60;

/// Whichever device a state file describes.
enum Device {
    Phone(Pairing),
    Watch(Delegate),
}

impl Device {
    fn relay_url(&self) -> &str {
        match self {
            Self::Phone(phone) => phone.relay_url(),
            Self::Watch(watch) => watch.relay_url(),
        }
    }

    fn host_name(&self) -> &str {
        match self {
            Self::Phone(phone) => phone.host_name(),
            Self::Watch(watch) => watch.host_name(),
        }
    }

    fn id_hex(&self) -> String {
        match self {
            Self::Phone(phone) => phone.id_hex(),
            Self::Watch(watch) => watch.id_hex(),
        }
    }

    fn token(&self) -> &str {
        match self {
            Self::Phone(phone) => phone.token(),
            Self::Watch(watch) => watch.token(),
        }
    }

    fn open(&mut self, delivered: &PendingRequest, now: u64) -> Result<Card, Refusal> {
        match self {
            Self::Phone(phone) => phone.open(delivered, now),
            Self::Watch(watch) => watch.open(delivered, now),
        }
    }

    /// None if this device may not approve the card: a watch looking at
    /// something only the phone may approve.
    fn approve(&self, card: &Card) -> Option<Answer> {
        match self {
            Self::Phone(phone) => Some(phone.approve(card)),
            Self::Watch(watch) => watch.approve(card),
        }
    }

    fn deny(&self, card: &Card, reason: &str) -> Answer {
        match self {
            Self::Phone(phone) => phone.deny(card, reason),
            Self::Watch(watch) => watch.deny(card, reason),
        }
    }
}

fn say(text: &str) {
    let mut out = std::io::stdout().lock();
    // If standard output is gone there is nobody to tell.
    drop(out.write_all(text.as_bytes()));
    drop(out.write_all(b"\n"));
    drop(out.flush());
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_secs())
}

fn save(path: &Path, stored: &Stored) -> Result<(), String> {
    let json = serde_json::to_vec_pretty(stored).map_err(|e| format!("cannot encode the state: {e}"))?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    file.write_all(&json).map_err(|e| format!("cannot write {}: {e}", path.display()))
}

fn load(path: &Path) -> Result<(Stored, Pairing), String> {
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read {}: {e} (pair first)", path.display()))?;
    let stored: Stored =
        serde_json::from_slice(&bytes).map_err(|e| format!("{} is not a state file: {e}", path.display()))?;
    let offer = Offer::from_url(&stored.offer).map_err(|e| format!("{}: {e}", path.display()))?;
    let seed = hex_decode_array(&stored.seed).map_err(|e| format!("{}: {e}", path.display()))?;
    let pairing = Pairing::resume(&offer, &seed, stored.active).map_err(|e| e.to_string())?;
    Ok((stored, pairing))
}

/// Loads a state file as whichever device it describes.
fn load_device(path: &Path) -> Result<Device, String> {
    let (stored, pairing) = load(path)?;
    let Some(encoded) = &stored.delegation else {
        if !pairing.is_active() {
            return Err("this pairing was never confirmed by the computer; pair again".to_owned());
        }
        return Ok(Device::Phone(pairing));
    };
    let not_ours = || format!("{} does not hold an authorisation for its own keys", path.display());
    let offer = Offer::from_url(&stored.offer).map_err(|e| format!("{}: {e}", path.display()))?;
    let seed = hex_decode_array(&stored.seed).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut watch = Delegate::begin(offer.pairing_id, offer.host_pub, &offer.host_name, &offer.relay_url, &seed)
        .map_err(|e| e.to_string())?;
    let signed =
        b64_decode(encoded).ok().and_then(|bytes| SignedDelegation::decode(&bytes).ok()).ok_or_else(not_ours)?;
    if !watch.accept(signed) {
        return Err(not_ours());
    }
    Ok(Device::Watch(watch))
}

/// The phone authorises a stand-in watch and tells the relay about it.
fn add_watch(state: &Path, watch_state: &Path, name: &str, valid_for: u64) -> Result<(), String> {
    let (stored, phone) = load(state)?;
    if stored.delegation.is_some() {
        return Err(format!("{} is a watch's state file; a watch cannot authorise another", state.display()));
    }
    let offer = Offer::from_url(&stored.offer).map_err(|e| format!("{}: {e}", state.display()))?;
    let seed: [u8; 32] = isudo_client::random().map_err(|e| format!("cannot get random bytes: {e}"))?;
    let mut watch = Delegate::begin(offer.pairing_id, offer.host_pub, &offer.host_name, &offer.relay_url, &seed)
        .map_err(|e| e.to_string())?;
    let signed = phone
        .delegate(watch.sign_pub(), watch.kem_pub(), name, now().saturating_add(valid_for))
        .ok_or("this phone cannot authorise a watch: it is not paired, or the name is not usable")?;
    let encoded = b64_encode(&signed.encode().map_err(|e| e.to_string())?);

    let relay = Relay::new(phone.relay_url()).map_err(|e| e.to_string())?;
    let body = AddDelegate { delegation: encoded.clone(), delegate_token: watch.token().to_owned() };
    relay.add_delegate(&phone.id_hex(), phone.token(), &body).map_err(|e| e.to_string())?;
    if !watch.accept(signed) {
        return Err("the watch did not take its own authorisation".to_owned());
    }
    let stored = Stored { offer: stored.offer, seed: hex_encode(&seed), active: true, delegation: Some(encoded) };
    save(watch_state, &stored)?;
    say(&format!("Authorised {name} to answer for {} for {valid_for}s.", phone.host_name()));
    say("It counts for nothing until root runs `isudo-admin watch on` on that computer.");
    Ok(())
}

fn pair(link: &str, state: &Path, name: &str) -> Result<(), String> {
    let offer = Offer::from_url(link).map_err(|e| e.to_string())?;
    let seed: [u8; 32] = isudo_client::random().map_err(|e| format!("cannot get random bytes: {e}"))?;
    let mut pairing = Pairing::begin(&offer, &seed).map_err(|e| e.to_string())?;
    let relay = Relay::new(pairing.relay_url()).map_err(|e| e.to_string())?;

    match relay.claim(&pairing.id_hex(), &pairing.claim(name, None)) {
        Ok(()) => {}
        Err(RelayError::Status(409)) => {
            return Err("this pairing link was already used by another phone. If that was not you, \
                        answer no on the computer."
                .to_owned());
        }
        Err(e) => return Err(e.to_string()),
    }
    let mut stored = Stored { offer: offer.to_url(), seed: hex_encode(&seed), active: false, delegation: None };
    save(state, &stored)?;

    say(&format!("Pairing with {}.", pairing.host_name()));

    let deadline = Instant::now().checked_add(PAIRING_WAIT);
    let mut code_shown = false;
    loop {
        if deadline.is_some_and(|at| Instant::now() >= at) {
            return Err("the computer did not confirm the pairing in time".to_owned());
        }
        let status = relay.status(&pairing.id_hex(), pairing.token()).map_err(|e| e.to_string())?;
        match pairing.observe(&status).map_err(|e| e.to_string())? {
            Progress::ShowCode(code) if !code_shown => {
                let (first, second) = code.split_at_checked(3).unwrap_or((&code, ""));
                say(&format!("Type this code into the computer:  {first} {second}"));
                code_shown = true;
            }
            Progress::Waiting | Progress::ShowCode(_) => {}
            Progress::Active => break,
        }
        std::thread::sleep(POLL_EVERY);
    }
    stored.active = true;
    save(state, &stored)?;
    say(&format!("Paired with {}.", pairing.host_name()));
    Ok(())
}

/// How `watch` decides: ask the person, or a fixed answer for scripts.
enum Policy {
    Ask,
    Approve,
    Deny(String),
}

enum Choice {
    Approve,
    Deny(String),
}

fn ask() -> Choice {
    say("  approve? [a]pprove, [d]eny, or d followed by a reason");
    let mut answer = String::new();
    if std::io::stdin().lock().read_line(&mut answer).is_err() {
        return Choice::Deny(String::new());
    }
    let answer = answer.trim();
    if matches!(answer, "a" | "A" | "y" | "Y" | "approve") {
        return Choice::Approve;
    }
    let reason = answer.strip_prefix('d').or_else(|| answer.strip_prefix('D')).unwrap_or(answer);
    Choice::Deny(reason.trim().to_owned())
}

fn watch(state: &Path, policy: &Policy, once: bool) -> Result<(), String> {
    let mut pairing = load_device(state)?;
    let relay = Relay::new(pairing.relay_url()).map_err(|e| e.to_string())?;
    let as_what = if matches!(pairing, Device::Watch(_)) { ", as a watch" } else { "" };
    say(&format!("Watching for requests from {}{as_what}. Ctrl-C to stop.", pairing.host_name()));

    // Requests already refused, so each refusal is reported once.
    let mut refused = BTreeSet::new();
    loop {
        let waiting = match relay.pending(&pairing.id_hex(), pairing.token()) {
            Ok(list) => list.requests,
            Err(RelayError::Status(404 | 401)) => return Err("this device is no longer paired".to_owned()),
            Err(e) => {
                say(&format!("  ({e}; retrying)"));
                Vec::new()
            }
        };
        for delivered in waiting {
            if refused.contains(&delivered.request_id) {
                continue;
            }
            let card = match pairing.open(&delivered, now()) {
                Ok(card) => card,
                Err(refusal) => {
                    say(&format!("  refused request {}: {refusal}", delivered.request_id));
                    let _ = refused.insert(delivered.request_id);
                    continue;
                }
            };
            say(&render::card(card.request(), card.expires_at().saturating_sub(now())));
            let choice = match policy {
                Policy::Ask => ask(),
                Policy::Approve => Choice::Approve,
                Policy::Deny(reason) => Choice::Deny(reason.clone()),
            };
            let (answer, verb) = match choice {
                Choice::Approve => {
                    let Some(answer) = pairing.approve(&card) else {
                        // A watch, and not a request a watch may approve. A
                        // real one would say so and leave it for the phone.
                        say("  only the phone may approve this; left for the phone");
                        let _ = refused.insert(delivered.request_id);
                        if once {
                            return Ok(());
                        }
                        continue;
                    };
                    (answer, "approved")
                }
                Choice::Deny(reason) => (pairing.deny(&card, &reason), "denied"),
            };
            match relay.answer(&card.request_id_hex(), pairing.token(), &answer) {
                Ok(()) => say(&format!("  {verb}")),
                Err(e) => say(&format!("  {verb}, but the answer was not delivered: {e}")),
            }
            if once {
                return Ok(());
            }
        }
        std::thread::sleep(POLL_EVERY);
    }
}

fn unpair(state: &Path) -> Result<(), String> {
    let (_stored, pairing) = load(state)?;
    let relay = Relay::new(pairing.relay_url()).map_err(|e| e.to_string())?;
    match relay.revoke_as_phone(&pairing.id_hex(), pairing.token()) {
        Ok(()) | Err(RelayError::Status(404)) => {}
        Err(e) => return Err(e.to_string()),
    }
    std::fs::remove_file(state).map_err(|e| format!("cannot remove {}: {e}", state.display()))?;
    say("Unpaired.");
    Ok(())
}

/// Options shared by the subcommands.
struct Options {
    state: PathBuf,
    name: String,
    valid_for: u64,
    policy: Policy,
    once: bool,
    positional: Vec<String>,
}

fn parse(args: impl Iterator<Item = String>) -> Result<Options, String> {
    let mut options = Options {
        state: DEFAULT_STATE.into(),
        name: "isudo-devphone".to_owned(),
        valid_for: DEFAULT_VALID_FOR_SECS,
        policy: Policy::Ask,
        once: false,
        positional: Vec::new(),
    };
    let mut args = args;
    while let Some(arg) = args.next() {
        let mut value = |flag: &str| args.next().ok_or_else(|| format!("{flag} needs a value"));
        match arg.as_str() {
            "--state" => options.state = value("--state")?.into(),
            "--name" => options.name = value("--name")?,
            "--valid-for" => {
                options.valid_for = value("--valid-for")?.parse().map_err(|e| format!("--valid-for: {e}"))?;
            }
            "--approve" => options.policy = Policy::Approve,
            "--deny" => options.policy = Policy::Deny(String::new()),
            "--once" => options.once = true,
            other => {
                if let Some(reason) = other.strip_prefix("--deny=") {
                    options.policy = Policy::Deny(reason.to_owned());
                } else if other.starts_with('-') {
                    return Err(format!("unknown option {other}"));
                } else {
                    options.positional.push(arg);
                }
            }
        }
    }
    Ok(options)
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let command = args.next().ok_or_else(|| USAGE.to_owned())?;
    let options = parse(args)?;
    match (command.as_str(), options.positional.as_slice()) {
        ("pair", [link]) => pair(link, &options.state, &options.name),
        ("watch", []) => watch(&options.state, &options.policy, options.once),
        ("add-watch", [watch_state]) => {
            add_watch(&options.state, Path::new(watch_state), &options.name, options.valid_for)
        }
        ("unpair", []) => unpair(&options.state),
        _ => Err(USAGE.to_owned()),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            let mut err = std::io::stderr().lock();
            drop(err.write_all(["isudo-devphone: ", &message, "\n"].concat().as_bytes()));
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(args: &[&str]) -> Options {
        parse(args.iter().map(|arg| (*arg).to_owned())).unwrap()
    }

    #[test]
    fn options_are_parsed() {
        let options = parsed(&["LINK", "--state", "s.json", "--name", "phone", "--once"]);
        assert_eq!(options.positional, ["LINK"]);
        assert_eq!(options.state, PathBuf::from("s.json"));
        assert_eq!(options.name, "phone");
        assert!(options.once);
        assert!(matches!(options.policy, Policy::Ask));
        assert!(matches!(parsed(&["--approve"]).policy, Policy::Approve));
        assert!(matches!(parsed(&["--deny"]).policy, Policy::Deny(reason) if reason.is_empty()));
        assert!(matches!(parsed(&["--deny=use staging"]).policy, Policy::Deny(reason) if reason == "use staging"));
    }

    #[test]
    fn bad_options_are_errors() {
        assert!(parse(["--state".to_owned()].into_iter()).is_err());
        assert!(parse(["--frobnicate".to_owned()].into_iter()).is_err());
    }
}
