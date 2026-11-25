//! HTTP client for the relay.
//!
//! One rule shapes the error handling here: nothing the relay or the network
//! says is ever passed along as text. Errors are a fixed vocabulary chosen
//! by this code, plus HTTP status numbers. The caller of `isudo` is often an
//! AI agent reading standard error, and a relay must not be able to put
//! words in front of it.

use std::fmt;
use std::time::Duration;

use isudo_proto::api::{
    Ack, AddDelegate, Answer, Claim, ClaimView, Confirm, CreatePairing, DelegateList, DeviceUpdate, PairingStatus,
    PendingList, RemoveDelegate, Revoke, SubmitRequest,
};
use serde::de::DeserializeOwned;
use serde::Serialize;
use ureq::http::Response;
use ureq::{Agent, Body};

/// Largest response body that will be read.
const MAX_BODY: u64 = 1024 * 1024;
/// Time allowed for an ordinary request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
/// Extra time allowed on top of a long poll's wait.
const POLL_SLACK: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayError {
    /// The relay URL is not acceptable.
    BadUrl(&'static str),
    /// The request did not complete.
    Transport(&'static str),
    /// The relay answered with an unexpected HTTP status.
    Status(u16),
    /// The relay's answer could not be understood.
    Body,
}

impl fmt::Display for RelayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadUrl(why) => write!(f, "relay address: {why}"),
            Self::Transport(why) => write!(f, "cannot reach the relay: {why}"),
            Self::Status(401 | 403) => f.write_str("the relay refused the request (not authorized)"),
            Self::Status(404) => f.write_str("the relay does not know this pairing or request"),
            Self::Status(409) => f.write_str("the relay refused the request (conflict)"),
            Self::Status(429) => f.write_str("the relay refused the request (too many requests)"),
            Self::Status(code) => write!(f, "the relay answered with HTTP status {code}"),
            Self::Body => f.write_str("the relay's answer could not be understood"),
        }
    }
}

impl std::error::Error for RelayError {}

const fn transport(error: &ureq::Error) -> RelayError {
    #[expect(clippy::wildcard_enum_match_arm, reason = "ureq's error type is non-exhaustive")]
    RelayError::Transport(match error {
        ureq::Error::Timeout(_) => "timed out",
        ureq::Error::HostNotFound => "host not found",
        ureq::Error::Io(_) | ureq::Error::ConnectionFailed => "connection failed",
        ureq::Error::Tls(_) | ureq::Error::Rustls(_) => "TLS error",
        ureq::Error::BadUri(_) => "bad address",
        _ => "request failed",
    })
}

/// True if `http://` is acceptable for this address: only for a relay on the
/// same machine.
fn is_loopback(rest: &str) -> bool {
    let authority = rest.split('/').next().unwrap_or_default();
    let host = authority
        .strip_prefix('[')
        .and_then(|bracketed| bracketed.split(']').next())
        .unwrap_or_else(|| authority.split(':').next().unwrap_or_default());
    matches!(host, "127.0.0.1" | "localhost" | "::1")
}

#[derive(Debug, Clone)]
pub struct Relay {
    agent: Agent,
    base: String,
}

impl Relay {
    /// # Errors
    /// Fails unless the URL is `https://`, or `http://` to this machine.
    pub fn new(base_url: &str) -> Result<Self, RelayError> {
        let base = base_url.trim_end_matches('/');
        let plain_http = if base.strip_prefix("https://").is_some_and(|rest| !rest.is_empty()) {
            false
        } else if let Some(rest) = base.strip_prefix("http://") {
            if !is_loopback(rest) {
                return Err(RelayError::BadUrl("plain http is only allowed for a relay on this machine"));
            }
            true
        } else {
            return Err(RelayError::BadUrl("must start with https://"));
        };
        let agent = Agent::config_builder()
            .timeout_global(Some(REQUEST_TIMEOUT))
            .http_status_as_error(false)
            .max_redirects(0)
            .https_only(!plain_http)
            .user_agent(concat!("isudo/", env!("CARGO_PKG_VERSION")))
            .build()
            .into();
        Ok(Self { agent, base: base.to_owned() })
    }

    fn url(&self, path: &[&str]) -> String {
        let mut url = self.base.clone();
        for segment in path {
            url.push('/');
            url.push_str(segment);
        }
        url
    }

    fn post<B: Serialize>(&self, path: &[&str], bearer: Option<&str>, body: &B) -> Result<Response<Body>, RelayError> {
        let mut request = self.agent.post(self.url(path));
        if let Some(token) = bearer {
            request = request.header("authorization", ["Bearer ", token].concat());
        }
        request.send_json(body).map_err(|e| transport(&e))
    }

    fn get(&self, path: &[&str], bearer: Option<&str>, timeout: Duration) -> Result<Response<Body>, RelayError> {
        let mut request = self.agent.get(self.url(path));
        if let Some(token) = bearer {
            request = request.header("authorization", ["Bearer ", token].concat());
        }
        request.config().timeout_global(Some(timeout)).build().call().map_err(|e| transport(&e))
    }

    /// Host, at pairing time: announces a new pairing.
    ///
    /// # Errors
    /// Fails if the relay cannot be reached or refuses.
    pub fn create_pairing(&self, body: &CreatePairing, registration_token: Option<&str>) -> Result<(), RelayError> {
        done(&self.post(&["v1", "pairings"], registration_token, body)?)
    }

    /// Phone: answers a pairing it scanned.
    ///
    /// # Errors
    /// Fails if the relay cannot be reached or the pairing was already claimed.
    pub fn claim(&self, pairing_id: &str, body: &Claim) -> Result<(), RelayError> {
        done(&self.post(&["v1", "pairings", pairing_id, "claim"], None, body)?)
    }

    /// Host: fetches the phone's answer, if one has arrived.
    ///
    /// # Errors
    /// Fails if the relay cannot be reached or answers unexpectedly.
    pub fn claim_view(&self, pairing_id: &str) -> Result<Option<ClaimView>, RelayError> {
        optional(self.get(&["v1", "pairings", pairing_id, "claim"], None, REQUEST_TIMEOUT)?)
    }

    /// Host: tells the phone its answer was the one accepted.
    ///
    /// # Errors
    /// Fails if the relay cannot be reached or rejects the signature.
    pub fn acknowledge(&self, pairing_id: &str, body: &Ack) -> Result<(), RelayError> {
        done(&self.post(&["v1", "pairings", pairing_id, "ack"], None, body)?)
    }

    /// Host: activates the pairing after the operator confirmed the code.
    ///
    /// # Errors
    /// Fails if the relay cannot be reached or rejects the signature.
    pub fn confirm(&self, pairing_id: &str, body: &Confirm) -> Result<(), RelayError> {
        done(&self.post(&["v1", "pairings", pairing_id, "confirm"], None, body)?)
    }

    /// Phone: reads the state of one of its pairings.
    ///
    /// # Errors
    /// Fails if the relay cannot be reached or does not recognize the token.
    pub fn status(&self, pairing_id: &str, phone_token: &str) -> Result<PairingStatus, RelayError> {
        json(self.get(&["v1", "pairings", pairing_id], Some(phone_token), REQUEST_TIMEOUT)?)
    }

    /// Phone: registers or replaces its push notification address.
    ///
    /// # Errors
    /// Fails if the relay cannot be reached or does not recognize the token.
    pub fn update_device(&self, pairing_id: &str, phone_token: &str, body: &DeviceUpdate) -> Result<(), RelayError> {
        done(&self.post(&["v1", "pairings", pairing_id, "device"], Some(phone_token), body)?)
    }

    /// Phone: registers a delegate it has signed for.
    ///
    /// # Errors
    /// Fails if the relay cannot be reached or rejects the delegation.
    pub fn add_delegate(&self, pairing_id: &str, phone_token: &str, body: &AddDelegate) -> Result<(), RelayError> {
        done(&self.post(&["v1", "pairings", pairing_id, "delegates"], Some(phone_token), body)?)
    }

    /// Phone: removes a delegate.
    ///
    /// # Errors
    /// Fails if the relay cannot be reached or does not recognize the token.
    pub fn remove_delegate(
        &self,
        pairing_id: &str,
        phone_token: &str,
        body: &RemoveDelegate,
    ) -> Result<(), RelayError> {
        done(&self.post(&["v1", "pairings", pairing_id, "delegates", "remove"], Some(phone_token), body)?)
    }

    /// Helper: the delegations registered for a pairing. Each is checked
    /// against the phone's key before use; the relay's word is not enough.
    ///
    /// # Errors
    /// Fails if the relay cannot be reached or does not know the pairing.
    pub fn delegations(&self, pairing_id: &str) -> Result<DelegateList, RelayError> {
        json(self.get(&["v1", "pairings", pairing_id, "delegates"], None, REQUEST_TIMEOUT)?)
    }

    /// Host: deletes a pairing.
    ///
    /// # Errors
    /// Fails if the relay cannot be reached or rejects the signature.
    pub fn revoke_as_host(&self, pairing_id: &str, body: &Revoke) -> Result<(), RelayError> {
        done(&self.post(&["v1", "pairings", pairing_id, "revoke"], None, body)?)
    }

    /// Phone: deletes one of its pairings.
    ///
    /// # Errors
    /// Fails if the relay cannot be reached or does not recognize the token.
    pub fn revoke_as_phone(&self, pairing_id: &str, phone_token: &str) -> Result<(), RelayError> {
        done(&self.post(&["v1", "pairings", pairing_id, "unpair"], Some(phone_token), &())?)
    }

    /// Helper: submits an encrypted request for the phone.
    ///
    /// # Errors
    /// Fails if the relay cannot be reached, rejects the ticket, or is
    /// rate-limiting this pairing.
    pub fn submit(&self, body: &SubmitRequest) -> Result<(), RelayError> {
        done(&self.post(&["v1", "requests"], None, body)?)
    }

    /// Helper: waits up to `wait` for the phone's answer.
    ///
    /// # Errors
    /// Fails if the relay cannot be reached or no longer knows the request.
    pub fn poll_answer(&self, request_id: &str, wait: Duration) -> Result<Option<Answer>, RelayError> {
        let wait_secs = wait.as_secs().to_string();
        let path = ["response?wait=", &wait_secs].concat();
        optional(self.get(&["v1", "requests", request_id, &path], None, wait.saturating_add(POLL_SLACK))?)
    }

    /// Phone: lists requests waiting for it.
    ///
    /// # Errors
    /// Fails if the relay cannot be reached or does not recognize the token.
    pub fn pending(&self, pairing_id: &str, phone_token: &str) -> Result<PendingList, RelayError> {
        json(self.get(&["v1", "pairings", pairing_id, "requests"], Some(phone_token), REQUEST_TIMEOUT)?)
    }

    /// Phone: delivers its signed answer.
    ///
    /// # Errors
    /// Fails if the relay cannot be reached, does not recognize the token,
    /// or no longer knows the request.
    pub fn answer(&self, request_id: &str, phone_token: &str, body: &Answer) -> Result<(), RelayError> {
        done(&self.post(&["v1", "requests", request_id, "response"], Some(phone_token), body)?)
    }
}

/// Accepts any 2xx status and ignores the body.
fn done(response: &Response<Body>) -> Result<(), RelayError> {
    let status = response.status();
    if status.is_success() {
        Ok(())
    } else {
        Err(RelayError::Status(status.as_u16()))
    }
}

/// Reads a JSON body from a 200 response.
fn json<T: DeserializeOwned>(mut response: Response<Body>) -> Result<T, RelayError> {
    if response.status().as_u16() != 200 {
        return Err(RelayError::Status(response.status().as_u16()));
    }
    response.body_mut().with_config().limit(MAX_BODY).read_json().map_err(|_e| RelayError::Body)
}

/// Like [`json`], but 204 means "nothing yet".
fn optional<T: DeserializeOwned>(response: Response<Body>) -> Result<Option<T>, RelayError> {
    if response.status().as_u16() == 204 {
        return Ok(None);
    }
    json(response).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_is_required_except_for_loopback() {
        assert!(Relay::new("https://relay.example").is_ok());
        assert!(Relay::new("https://relay.example/base/").is_ok());
        assert!(Relay::new("http://127.0.0.1:8787").is_ok());
        assert!(Relay::new("http://localhost:8787/x").is_ok());
        assert!(Relay::new("http://[::1]:8787").is_ok());
        assert!(matches!(Relay::new("http://relay.example"), Err(RelayError::BadUrl(_))));
        assert!(matches!(Relay::new("http://127.0.0.1.evil.example"), Err(RelayError::BadUrl(_))));
        assert!(matches!(Relay::new("http://localhost.evil.example:80"), Err(RelayError::BadUrl(_))));
        assert!(matches!(Relay::new("ftp://relay.example"), Err(RelayError::BadUrl(_))));
        assert!(matches!(Relay::new("https://"), Err(RelayError::BadUrl(_))));
        assert!(matches!(Relay::new("relay.example"), Err(RelayError::BadUrl(_))));
    }

    #[test]
    fn urls_are_joined_without_doubling_slashes() {
        let relay = Relay::new("https://relay.example/base/").unwrap();
        assert_eq!(relay.url(&["v1", "requests", "abcd"]), "https://relay.example/base/v1/requests/abcd");
    }

    #[test]
    fn errors_never_carry_remote_text() {
        // Every message is one this crate wrote; only a status number varies.
        assert_eq!(RelayError::Status(500).to_string(), "the relay answered with HTTP status 500");
        assert_eq!(RelayError::Status(429).to_string(), "the relay refused the request (too many requests)");
        assert_eq!(RelayError::Transport("timed out").to_string(), "cannot reach the relay: timed out");
    }
}
