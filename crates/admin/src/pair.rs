//! `isudo-admin pair`.

use std::io::{BufRead as _, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::path::Path;
use std::time::{Duration, Instant};

use isudo_client::relay::{Relay, RelayError};
use isudo_core::config::{self, Pairing, DEFAULT_SECURE_PATH, DEFAULT_TIMEOUT_SECS};
use isudo_core::pairing::{Accepted, ClaimError, HostIdentity, Opening, Pinned};
use isudo_core::plan::HostKey;
use isudo_proto::api::{Ack, ClaimView, Confirm, CreatePairing, Revoke};
use isudo_proto::codec::{b64_encode, hex_encode};
use isudo_proto::pairing::MAX_NAME_LEN;
use isudo_proto::text::escape;
use isudo_proto::{sigs, PUBKEY_LEN};
use qrcode::render::unicode::Dense1x2;
use qrcode::QrCode;

use crate::{say, Options};

/// How long the QR code stays valid.
const SCAN_WAIT: Duration = Duration::from_secs(300);
const POLL_EVERY: Duration = Duration::from_secs(1);
const CODE_ATTEMPTS: usize = 3;

fn hostname() -> String {
    let mut buffer = [0_u8; 256];
    // SAFETY: the pointer and length describe the buffer above.
    let rc = unsafe { libc::gethostname(buffer.as_mut_ptr().cast(), buffer.len()) };
    let name = buffer.split(|byte| *byte == 0).next().unwrap_or_default();
    let name = String::from_utf8_lossy(name);
    // "burke-mbp.local" is friendlier as "burke-mbp".
    let short = name.split('.').next().unwrap_or_default();
    if rc == 0 && !short.is_empty() {
        short.to_owned()
    } else {
        "this computer".to_owned()
    }
}

/// A fresh host key and its public half.
fn generate_host_key() -> Result<([u8; 32], HostKey, [u8; PUBKEY_LEN]), String> {
    // A random 32-byte string is a valid P-256 scalar except with
    // negligible probability; a few tries is already overcautious.
    for _ in 0..8 {
        let scalar: [u8; 32] = random()?;
        if let Some(key) = HostKey::new(&scalar) {
            if let Some(public) = key.public() {
                return Ok((scalar, key, public));
            }
        }
    }
    Err("could not generate a key".to_owned())
}

fn random<const N: usize>() -> Result<[u8; N], String> {
    isudo_client::random().map_err(|e| format!("cannot get random bytes: {e}"))
}

fn show_qr(link: &str) {
    match QrCode::new(link.as_bytes()) {
        // Light modules drawn as blocks, so the code reads correctly on a
        // dark terminal background.
        Ok(code) => say(&code.render::<Dense1x2>().dark_color(Dense1x2::Light).light_color(Dense1x2::Dark).build()),
        Err(_) => say("(This link is too long to draw as a QR code; paste it into the app instead.)"),
    }
}

/// Waits for a phone to answer, and checks that it read the QR code.
fn await_claim(relay: &Relay, pairing_id: &str) -> Result<ClaimView, String> {
    let deadline = Instant::now().checked_add(SCAN_WAIT);
    loop {
        if deadline.is_some_and(|at| Instant::now() >= at) {
            return Err("no phone scanned the code in time; run the command again for a new one".to_owned());
        }
        match relay.claim_view(pairing_id) {
            Ok(Some(claim)) => return Ok(claim),
            Ok(None) | Err(RelayError::Transport(_)) => {}
            Err(e) => return Err(e.to_string()),
        }
        std::thread::sleep(POLL_EVERY);
    }
}

/// Reads the six-digit code from the terminal until it matches or the
/// attempts run out.
fn confirm_code(accepted: &Accepted) -> Result<Pinned, String> {
    let phone_name = escape(accepted.phone_name().as_bytes());
    for attempt in 1..=CODE_ATTEMPTS {
        {
            let mut out = std::io::stdout().lock();
            let prompt = ["Enter the 6-digit code shown on ", &phone_name, ": "].concat();
            drop(out.write_all(prompt.as_bytes()));
            drop(out.flush());
        }
        let mut typed = String::new();
        let read = std::io::stdin().lock().read_line(&mut typed).map_err(|e| format!("cannot read the code: {e}"))?;
        if read == 0 {
            return Err("no code was entered; nothing was changed".to_owned());
        }
        if let Some(pinned) = accepted.confirm(&typed) {
            return Ok(pinned);
        }
        if attempt < CODE_ATTEMPTS {
            say("That does not match. Check the phone and try again.");
        }
    }
    Err("the code did not match, so nothing was changed.\n\
         If your phone showed an error or a different code, someone else may have answered the pairing code, \
         or your phone was shown a different one. Run the command again somewhere it cannot be seen or altered."
        .to_owned())
}

/// Writes the pairing file so that it is never observable half-written or
/// with loose permissions.
fn write_pairing(path: &Path, text: &str) -> Result<(), String> {
    let failed = |what: &str, e: std::io::Error| format!("cannot {what} {}: {e}", path.display());
    if let Some(directory) = path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o755)
            .create(directory)
            .map_err(|e| format!("cannot create {}: {e}", directory.display()))?;
    }
    let temporary = path.with_extension("conf.new");
    // A leftover from an interrupted run would make the exclusive create
    // below fail; it is ours to remove.
    drop(std::fs::remove_file(&temporary));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary)
        .map_err(|e| failed("write", e))?;
    file.write_all(text.as_bytes()).map_err(|e| failed("write", e))?;
    file.sync_all().map_err(|e| failed("write", e))?;
    std::fs::rename(&temporary, path).map_err(|e| failed("replace", e))
}

pub(crate) fn run(options: &Options) -> Result<(), String> {
    options.require_root()?;
    if options.config.is_none() {
        // Pairing decides who can approve root commands; do not do it with
        // programs a non-root user could have swapped.
        crate::check::run(&options.config_path())?;
    }
    let relay_url = options.relay.as_deref().ok_or("pair needs --relay URL")?;
    let relay = Relay::new(relay_url).map_err(|e| e.to_string())?;
    let path = options.config_path();
    if path.exists() {
        return Err(format!(
            "{} already exists. Run `isudo-admin unpair` first if you mean to replace the paired phone.",
            path.display()
        ));
    }

    let host_name = options.name.clone().unwrap_or_else(hostname);
    if host_name.len() > MAX_NAME_LEN {
        return Err(format!("--name must be at most {MAX_NAME_LEN} bytes"));
    }
    let (host_scalar, host_key, host_pub) = generate_host_key()?;
    // The nonce is fixed now, before anything is shown, and the pairing code
    // commits to it. It is revealed only to the one answer accepted below.
    let opening = Opening::new(
        HostIdentity { relay_url: relay_url.to_owned(), host_pub, host_name: host_name.clone() },
        random()?,
        random()?,
        random()?,
    );
    let offer = opening.offer().clone();
    let pairing_id = hex_encode(&offer.pairing_id);

    // Build and validate the pairing file's contents before involving the
    // relay or the phone, so a bad option fails early. The phone's keys are
    // filled in once known.
    let mut pairing = Pairing {
        id: offer.pairing_id,
        host_name: host_name.clone(),
        relay_url: relay_url.to_owned(),
        host_key: host_scalar,
        phone_sign_pub: [0; PUBKEY_LEN],
        phone_kem_pub: [0; PUBKEY_LEN],
        phone_name: "pending".to_owned(),
        timeout_secs: match &options.timeout {
            None => DEFAULT_TIMEOUT_SECS,
            Some(text) => text.parse().map_err(|e| format!("--timeout: {e}"))?,
        },
        secure_path: options.secure_path.clone().unwrap_or_else(|| DEFAULT_SECURE_PATH.to_owned()),
    };
    let _checked = config::parse(config::render(&pairing)?.as_bytes())?;

    relay
        .create_pairing(
            &CreatePairing { pairing_id: pairing_id.clone(), host_pub: b64_encode(&host_pub), host_name },
            options.registration_token.as_deref(),
        )
        .map_err(|e| e.to_string())?;

    let link = offer.to_url();
    say("Scan this with the isudo app (Pair a computer):\n");
    show_qr(&link);
    say("\nOr paste this link into the app:\n");
    say(&link);
    say("\nThis code is a secret until pairing finishes. Waiting for a phone...");

    let claim = await_claim(&relay, &pairing_id)?;
    let accepted = opening.accept(&claim).map_err(|e| match e {
        ClaimError::Malformed => "the phone's answer was malformed; nothing was changed".to_owned(),
        // Whoever answered did not have the QR code's secret: not a phone
        // that scanned it. The relay itself is the likeliest source.
        ClaimError::NotFromTheCode => {
            "the answer did not come from a phone that scanned this code; nothing was changed".to_owned()
        }
    })?;
    // Tell that phone, and only that phone, that its answer is the one
    // accepted. It will not show a code until it has verified this.
    let ack =
        Ack { nonce: b64_encode(accepted.host_nonce()), host_sig: b64_encode(&host_key.sign(&accepted.ack_message())) };
    relay.acknowledge(&pairing_id, &ack).map_err(|e| e.to_string())?;
    let shown_name = escape(accepted.phone_name().as_bytes());
    say(&format!("\n{shown_name} scanned the code and will now show six digits."));
    say("If your phone shows an error instead, press Control-C: the answer did not come from your phone.");
    let pinned = confirm_code(&accepted)?;

    pairing.phone_sign_pub = *pinned.phone_sign_pub();
    pairing.phone_kem_pub = *pinned.phone_kem_pub();
    pinned.phone_name().clone_into(&mut pairing.phone_name);
    let text = config::render(&pairing)?;

    let confirm = Confirm {
        host_sig: b64_encode(&host_key.sign(&sigs::pair_confirm_msg(
            &offer.pairing_id,
            &pairing.phone_sign_pub,
            &pairing.phone_kem_pub,
        ))),
    };
    relay.confirm(&pairing_id, &confirm).map_err(|e| e.to_string())?;
    if let Err(error) = write_pairing(&path, &text) {
        // Do not leave the relay believing in a pairing this machine did
        // not keep.
        let revoke = Revoke { host_sig: b64_encode(&host_key.sign(&sigs::pair_revoke_msg(&offer.pairing_id))) };
        if relay.revoke_as_host(&pairing_id, &revoke).is_err() {
            say("(The relay could not be told to forget this pairing; it will be unusable there anyway.)");
        }
        return Err(error);
    }
    say(&format!("\nPaired. Commands run with isudo now need approval on {shown_name}."));
    Ok(())
}
