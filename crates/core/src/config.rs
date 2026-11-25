//! The pairing file: which phone may approve, and how to reach it.
//!
//! Written by `isudo-admin pair`, read only by root. A plain `key = value`
//! file so that the setuid binary needs no parser dependency.

use isudo_proto::codec::{hex_decode_array, hex_encode};
use isudo_proto::{PAIRING_ID_LEN, PUBKEY_LEN};

pub const DEFAULT_TIMEOUT_SECS: u32 = 120;
const MIN_TIMEOUT_SECS: u32 = 10;
const MAX_TIMEOUT_SECS: u32 = 600;
pub const MAX_CONFIG_LEN: usize = 16 * 1024;

// Not /usr/local/bin: on many Macs it belongs to the user (Homebrew), and
// whoever can write to a searched directory decides what a bare command name
// means. isudo also skips, at run time, any listed directory that someone
// other than root can write to.
//
// A build may replace it with ISUDO_DEFAULT_SECURE_PATH: NixOS keeps nothing
// in these directories, so its package sets the system profile instead.
#[cfg(target_os = "macos")]
const PLATFORM_SECURE_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";
#[cfg(not(target_os = "macos"))]
const PLATFORM_SECURE_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

pub const DEFAULT_SECURE_PATH: &str = match option_env!("ISUDO_DEFAULT_SECURE_PATH") {
    Some(path) => path,
    None => PLATFORM_SECURE_PATH,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pairing {
    pub id: [u8; PAIRING_ID_LEN],
    pub host_name: String,
    pub relay_url: String,
    /// The host's P-256 private scalar. Authenticates requests to the phone
    /// and relay; it cannot approve anything.
    pub host_key: [u8; 32],
    pub phone_sign_pub: [u8; PUBKEY_LEN],
    pub phone_kem_pub: [u8; PUBKEY_LEN],
    pub phone_name: String,
    pub timeout_secs: u32,
    /// Directories searched for commands, and the command's PATH.
    pub secure_path: String,
    /// Whether a watch the phone has authorised may answer. Off unless root
    /// turns it on: a watch cannot check a face, so its approval says less
    /// than the phone's about who gave it. Even when on, a watch may approve
    /// only requests simple enough to read on it.
    pub watch: bool,
}

/// The raw `key = value` pairs of a pairing file, each at most once.
#[derive(Default)]
struct Fields<'a> {
    version: Option<&'a str>,
    pairing_id: Option<&'a str>,
    host_name: Option<&'a str>,
    relay_url: Option<&'a str>,
    host_key: Option<&'a str>,
    phone_sign_pub: Option<&'a str>,
    phone_kem_pub: Option<&'a str>,
    phone_name: Option<&'a str>,
    timeout_secs: Option<&'a str>,
    secure_path: Option<&'a str>,
    watch: Option<&'a str>,
}

impl<'a> Fields<'a> {
    fn read(text: &'a str) -> Result<Self, String> {
        let mut fields = Self::default();
        for (index, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let at = |message: &str| format!("line {}: {message}", index.saturating_add(1));
            let (key, value) = line.split_once('=').ok_or_else(|| at("expected key = value"))?;
            let (key, value) = (key.trim(), value.trim());
            let slot = match key {
                "version" => &mut fields.version,
                "pairing_id" => &mut fields.pairing_id,
                "host_name" => &mut fields.host_name,
                "relay_url" => &mut fields.relay_url,
                "host_key" => &mut fields.host_key,
                "phone_sign_pub" => &mut fields.phone_sign_pub,
                "phone_kem_pub" => &mut fields.phone_kem_pub,
                "phone_name" => &mut fields.phone_name,
                "timeout_secs" => &mut fields.timeout_secs,
                "secure_path" => &mut fields.secure_path,
                "watch" => &mut fields.watch,
                _ => return Err(at(&format!("unknown key \"{key}\""))),
            };
            if slot.replace(value).is_some() {
                return Err(at(&format!("\"{key}\" is set more than once")));
            }
        }
        Ok(fields)
    }
}

fn required<'a>(value: Option<&'a str>, key: &str) -> Result<&'a str, String> {
    value.ok_or_else(|| format!("is missing \"{key}\""))
}

fn hex_field<const N: usize>(value: Option<&str>, key: &str) -> Result<[u8; N], String> {
    hex_decode_array(required(value, key)?).map_err(|e| format!("\"{key}\": {e}"))
}

/// True if a value can be written on one line of a pairing file and read
/// back unchanged.
fn fits_on_a_line(value: &str) -> bool {
    !value.is_empty() && value.trim() == value && !value.chars().any(char::is_control)
}

/// Writes a pairing file. [`parse`] reads back exactly what was given.
///
/// # Errors
/// Fails if a text field is empty, has surrounding whitespace, or contains a
/// control character, any of which would not survive the line-based format.
pub fn render(pairing: &Pairing) -> Result<String, String> {
    for (key, value) in [
        ("host_name", &pairing.host_name),
        ("relay_url", &pairing.relay_url),
        ("phone_name", &pairing.phone_name),
        ("secure_path", &pairing.secure_path),
    ] {
        if !fits_on_a_line(value) {
            return Err(format!("\"{key}\" must be a single line of text without surrounding spaces"));
        }
    }
    Ok([
        "# Written by isudo-admin. Holds this machine's isudo key: keep it readable by root only.\n",
        "version = 1\n",
        &format!("pairing_id = {}\n", hex_encode(&pairing.id)),
        &format!("host_name = {}\n", pairing.host_name),
        &format!("relay_url = {}\n", pairing.relay_url),
        &format!("host_key = {}\n", hex_encode(&pairing.host_key)),
        &format!("phone_sign_pub = {}\n", hex_encode(&pairing.phone_sign_pub)),
        &format!("phone_kem_pub = {}\n", hex_encode(&pairing.phone_kem_pub)),
        &format!("phone_name = {}\n", pairing.phone_name),
        &format!("timeout_secs = {}\n", pairing.timeout_secs),
        &format!("secure_path = {}\n", pairing.secure_path),
        &format!("watch = {}\n", if pairing.watch { "yes" } else { "no" }),
    ]
    .concat())
}

/// Parses a pairing file.
///
/// # Errors
/// Fails with a description of the first problem found. Unknown keys,
/// repeated keys and missing keys are all errors.
pub fn parse(text: &[u8]) -> Result<Pairing, String> {
    let text = std::str::from_utf8(text).map_err(|e| format!("is not valid UTF-8: {e}"))?;
    let fields = Fields::read(text)?;

    if required(fields.version, "version")? != "1" {
        return Err("has an unsupported version".into());
    }

    let timeout_secs = match fields.timeout_secs {
        None => DEFAULT_TIMEOUT_SECS,
        Some(value) => {
            let secs: u32 = value.parse().map_err(|e| format!("\"timeout_secs\": {e}"))?;
            if !(MIN_TIMEOUT_SECS..=MAX_TIMEOUT_SECS).contains(&secs) {
                return Err(format!("\"timeout_secs\" must be between {MIN_TIMEOUT_SECS} and {MAX_TIMEOUT_SECS}"));
            }
            secs
        }
    };

    let secure_path = fields.secure_path.unwrap_or(DEFAULT_SECURE_PATH);
    if secure_path.is_empty() || secure_path.split(':').any(|dir| !dir.starts_with('/')) {
        return Err("\"secure_path\" must be a colon-separated list of absolute directories".into());
    }

    let watch = match fields.watch {
        None | Some("no") => false,
        Some("yes") => true,
        Some(_) => return Err("\"watch\" must be yes or no".into()),
    };
    let relay_url = required(fields.relay_url, "relay_url")?;
    if !(relay_url.starts_with("https://") || relay_url.starts_with("http://")) {
        return Err("\"relay_url\" must start with https://".into());
    }

    Ok(Pairing {
        id: hex_field(fields.pairing_id, "pairing_id")?,
        host_name: required(fields.host_name, "host_name")?.to_owned(),
        relay_url: relay_url.to_owned(),
        host_key: hex_field(fields.host_key, "host_key")?,
        phone_sign_pub: hex_field(fields.phone_sign_pub, "phone_sign_pub")?,
        phone_kem_pub: hex_field(fields.phone_kem_pub, "phone_kem_pub")?,
        phone_name: required(fields.phone_name, "phone_name")?.to_owned(),
        timeout_secs,
        secure_path: secure_path.to_owned(),
        watch,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> String {
        format!(
            "# written by isudo-admin\n\
             version = 1\n\
             pairing_id = {}\n\
             host_name = burke-mbp\n\
             relay_url = https://relay.example\n\
             host_key = {}\n\
             phone_sign_pub = {}\n\
             phone_kem_pub = {}\n\
             phone_name = Burke's iPhone\n",
            "ab".repeat(16),
            "01".repeat(32),
            "04".repeat(65),
            "04".repeat(65),
        )
    }

    #[test]
    fn parses_a_full_file() {
        let pairing = parse(sample().as_bytes()).unwrap();
        assert_eq!(pairing.id, [0xab; 16]);
        assert_eq!(pairing.host_name, "burke-mbp");
        assert_eq!(pairing.phone_name, "Burke's iPhone");
        assert_eq!(pairing.timeout_secs, DEFAULT_TIMEOUT_SECS);
        assert_eq!(pairing.secure_path, DEFAULT_SECURE_PATH);
    }

    #[test]
    fn optional_keys() {
        let text = format!("{}timeout_secs = 45\nsecure_path = /run/current-system/sw/bin:/usr/bin\n", sample());
        let pairing = parse(text.as_bytes()).unwrap();
        assert_eq!(pairing.timeout_secs, 45);
        assert_eq!(pairing.secure_path, "/run/current-system/sw/bin:/usr/bin");
    }

    #[test]
    fn render_and_parse_round_trip() {
        let mut host_key = [0_u8; 32];
        host_key[31] = 7;
        let pairing = Pairing {
            id: [0x1f; 16],
            host_name: "burke's mbp = fast".into(),
            relay_url: "https://relay.example/base".into(),
            host_key,
            phone_sign_pub: [4; 65],
            phone_kem_pub: [5; 65],
            phone_name: "Burke\u{2019}s iPhone # 2".into(),
            timeout_secs: 90,
            secure_path: "/usr/local/bin:/usr/bin".into(),
            watch: true,
        };
        let text = render(&pairing).unwrap();
        assert_eq!(parse(text.as_bytes()).unwrap(), pairing);
    }

    #[test]
    fn the_watch_is_off_unless_the_file_says_yes() {
        assert!(!parse(sample().as_bytes()).unwrap().watch, "a file from before the setting existed");
        assert!(parse(format!("{}watch = yes\n", sample()).as_bytes()).unwrap().watch);
        assert!(!parse(format!("{}watch = no\n", sample()).as_bytes()).unwrap().watch);
        for odd in ["true", "YES", "1", "", "on"] {
            assert!(parse(format!("{}watch = {odd}\n", sample()).as_bytes()).is_err(), "{odd:?}");
        }
    }

    #[test]
    fn render_refuses_values_that_would_not_survive() {
        let good = parse(sample().as_bytes()).unwrap();
        for bad_name in ["", " padded", "two\nlines", "tab\there", "bell\u{7}"] {
            let pairing = Pairing { phone_name: bad_name.into(), ..good.clone() };
            assert!(render(&pairing).is_err(), "accepted {bad_name:?}");
        }
        let injected = Pairing { host_name: "x\nphone_sign_pub = 00".into(), ..good };
        assert!(render(&injected).is_err());
    }

    #[test]
    fn rejects_bad_files() {
        let missing = sample().replace("host_name = burke-mbp\n", "");
        assert!(parse(missing.as_bytes()).unwrap_err().contains("host_name"));
        assert!(parse(format!("{}version = 1\n", sample()).as_bytes()).unwrap_err().contains("more than once"));
        assert!(parse(format!("{}surprise = 1\n", sample()).as_bytes()).unwrap_err().contains("unknown key"));
        assert!(parse(sample().replace("version = 1", "version = 2").as_bytes()).is_err());
        assert!(parse(format!("{}timeout_secs = 5\n", sample()).as_bytes()).is_err());
        assert!(parse(format!("{}secure_path = bin:/usr/bin\n", sample()).as_bytes()).is_err());
        assert!(parse(format!("{}secure_path = /usr/bin::/bin\n", sample()).as_bytes()).is_err());
        assert!(parse(sample().replace("https://", "ftp://").as_bytes()).is_err());
        assert!(parse(sample().replace(&"ab".repeat(16), "abcd").as_bytes()).is_err());
        assert!(parse(b"just some words").is_err());
    }
}
