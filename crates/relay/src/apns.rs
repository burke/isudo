//! Sending push notifications through Apple's push service.
//!
//! A push only says "there is a request, here is its id". The request itself
//! is fetched by the app from the relay, encrypted, so Apple learns nothing
//! but timing.

use std::path::Path;
use std::time::Duration;

use isudo_proto::codec::b64_encode;
use isudo_relay_core::{Device, Push, Settled};
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::DecodePrivateKey as _;
use serde_json::json;
use tokio::sync::Mutex;

/// Apple rejects provider tokens older than an hour and asks that they be
/// refreshed no more than once every twenty minutes.
const TOKEN_LIFETIME_SECS: u64 = 40 * 60;

#[derive(Debug)]
pub(crate) struct Apns {
    client: reqwest::Client,
    key: SigningKey,
    key_id: String,
    team_id: String,
    topic: String,
    wording: Wording,
    /// The current provider token and when it was issued.
    token: Mutex<Option<(u64, String)>>,
}

#[derive(Debug, Clone)]
pub(crate) struct ApnsConfig {
    pub key_file: String,
    pub key_id: String,
    pub team_id: String,
    pub topic: String,
    pub wording: Wording,
}

/// What a push says and how the app recognises it. The defaults are
/// isudo's. Another app served by its own instance of this relay sets its
/// own, because the relay cannot read a request to describe it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Wording {
    /// The alert's text. `{host}` stands for the paired computer's name.
    pub body: String,
    /// The notification category, which selects the app's actions.
    pub category: String,
    /// The name of the payload's own dictionary.
    pub key: String,
}

impl Default for Wording {
    fn default() -> Self {
        Self {
            body: "{host} wants to run a command as root".to_owned(),
            category: "ISUDO_REQUEST".to_owned(),
            key: "isudo".to_owned(),
        }
    }
}

impl Apns {
    /// # Errors
    /// Fails with a message for the operator if the key cannot be loaded.
    pub(crate) fn new(config: ApnsConfig) -> Result<Self, String> {
        let pem = std::fs::read_to_string(Path::new(&config.key_file))
            .map_err(|e| format!("cannot read the APNs key {}: {e}", config.key_file))?;
        let key = SigningKey::from_pkcs8_pem(&pem)
            .map_err(|e| format!("{} is not a P-256 private key in PKCS#8 PEM form: {e}", config.key_file))?;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|e| format!("cannot set up the APNs client: {e}"))?;
        Ok(Self {
            client,
            key,
            key_id: config.key_id,
            team_id: config.team_id,
            topic: config.topic,
            wording: config.wording,
            token: Mutex::new(None),
        })
    }

    /// The provider token: a JWT signed with ES256, reused until it ages out.
    async fn provider_token(&self, now: u64) -> String {
        let mut cached = self.token.lock().await;
        if let Some((issued, token)) = cached.as_ref() {
            if now.saturating_sub(*issued) < TOKEN_LIFETIME_SECS {
                return token.clone();
            }
        }
        let token = self.sign_token(now);
        *cached = Some((now, token.clone()));
        token
    }

    fn sign_token(&self, now: u64) -> String {
        let header = b64_encode(json!({ "alg": "ES256", "kid": self.key_id }).to_string().as_bytes());
        let claims = b64_encode(json!({ "iss": self.team_id, "iat": now }).to_string().as_bytes());
        let signing_input = [header.as_str(), ".", claims.as_str()].concat();
        let signature: Signature = self.key.sign(signing_input.as_bytes());
        [signing_input.as_str(), ".", &b64_encode(&signature.to_bytes())].concat()
    }

    /// What the app receives for a waiting request.
    ///
    /// The request itself is never in the clear here. If the pairing has a
    /// watch and the request is small, it rides along sealed to the watch,
    /// so that a watch handed this notification can show it at once.
    fn waiting_payload(&self, push: &Push) -> serde_json::Value {
        let body = self.wording.body.replace("{host}", &push.host_name);
        let mut ours = json!({ "p": push.pairing_id, "r": push.request_id, "x": push.expires_at });
        if let (Some(envelope), Some(fields)) = (&push.delegate_envelope, ours.as_object_mut()) {
            let _ = fields.insert("w".to_owned(), json!(envelope));
        }
        let mut payload = json!({
            "aps": {
                "alert": { "title": "Approval requested", "body": body },
                "sound": "default",
                "interruption-level": "time-sensitive",
                "category": self.wording.category,
                "thread-id": push.pairing_id,
            },
        });
        if let Some(fields) = payload.as_object_mut() {
            let _ = fields.insert(self.wording.key.clone(), ours);
        }
        payload
    }

    /// Sends the push for a waiting request. Returns a short description of
    /// any failure, for the log.
    pub(crate) async fn send(&self, push: &Push, now: u64) -> Result<(), String> {
        let headers = [
            ("apns-push-type", "alert".to_owned()),
            ("apns-priority", "10".to_owned()),
            ("apns-expiration", push.expires_at.to_string()),
            ("apns-collapse-id", push.request_id.clone()),
        ];
        self.post(&push.device, &headers, &self.waiting_payload(push), now).await
    }

    /// Tells the app, without alerting anyone, that a request has been
    /// answered, so it can clear the notification wherever it still shows.
    /// Best effort: the system may delay or drop a background push, and a
    /// stale notification is harmless (the computer has stopped waiting).
    pub(crate) async fn send_settled(&self, settled: &Settled, now: u64) -> Result<(), String> {
        let mut payload = json!({ "aps": { "content-available": 1 } });
        if let Some(fields) = payload.as_object_mut() {
            let ours = json!({ "p": settled.pairing_id, "r": settled.request_id, "done": true });
            let _ = fields.insert(self.wording.key.clone(), ours);
        }
        let headers = [
            ("apns-push-type", "background".to_owned()),
            ("apns-priority", "5".to_owned()),
            ("apns-expiration", now.saturating_add(120).to_string()),
        ];
        self.post(&settled.device, &headers, &payload, now).await
    }

    async fn post(
        &self,
        device: &Device,
        headers: &[(&str, String)],
        payload: &serde_json::Value,
        now: u64,
    ) -> Result<(), String> {
        let host = if device.apns_env == "production" { "api.push.apple.com" } else { "api.sandbox.push.apple.com" };
        let url = ["https://", host, "/3/device/", &device.apns_token].concat();
        let mut request =
            self.client.post(url).bearer_auth(self.provider_token(now).await).header("apns-topic", &self.topic);
        for (name, value) in headers {
            request = request.header(*name, value);
        }
        let response = request.json(payload).send().await.map_err(|e| format!("request failed: {e}"))?;
        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        let reason = response.text().await.unwrap_or_default();
        // One line, whatever Apple sent.
        let reason: String = reason.chars().take(200).map(|c| if c.is_control() { ' ' } else { c }).collect();
        Err(format!("APNs answered {status}: {reason}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use isudo_proto::codec::b64_decode;
    use p256::ecdsa::signature::Verifier as _;

    fn apns() -> Apns {
        // Building an HTTP client needs a TLS provider; a second install in
        // the same process is refused, which is fine.
        drop(rustls::crypto::ring::default_provider().install_default());
        Apns {
            client: reqwest::Client::new(),
            key: SigningKey::from_slice(&[7; 32]).unwrap(),
            key_id: "ABC123DEFG".into(),
            team_id: "TEAM123456".into(),
            topic: "com.example.isudo".into(),
            wording: Wording::default(),
            token: Mutex::new(None),
        }
    }

    #[test]
    fn provider_token_is_a_valid_es256_jwt() {
        let apns = apns();
        let token = apns.sign_token(1_795_000_000);
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        let header: serde_json::Value = serde_json::from_slice(&b64_decode(parts[0]).unwrap()).unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&b64_decode(parts[1]).unwrap()).unwrap();
        assert_eq!(header, json!({ "alg": "ES256", "kid": "ABC123DEFG" }));
        assert_eq!(claims, json!({ "iss": "TEAM123456", "iat": 1_795_000_000_u64 }));

        // JWS ES256 signatures are the raw r || s form.
        let signature = Signature::from_slice(&b64_decode(parts[2]).unwrap()).unwrap();
        let signed = [parts[0], ".", parts[1]].concat();
        assert!(apns.key.verifying_key().verify(signed.as_bytes(), &signature).is_ok());
    }

    #[tokio::test]
    async fn provider_token_is_reused_until_it_ages_out() {
        let apns = apns();
        let first = apns.provider_token(1000).await;
        assert_eq!(apns.provider_token(1000 + TOKEN_LIFETIME_SECS - 1).await, first);
        assert_ne!(apns.provider_token(1000 + TOKEN_LIFETIME_SECS).await, first);
    }

    fn push(delegate_envelope: Option<&str>) -> Push {
        Push {
            device: Device { apns_token: "ab".repeat(32), apns_env: "sandbox".into() },
            pairing_id: "a1".repeat(16),
            request_id: "b2".repeat(16),
            host_name: "burke-mbp".into(),
            expires_at: 1_795_000_120,
            delegate_envelope: delegate_envelope.map(str::to_owned),
        }
    }

    #[test]
    fn the_push_names_the_request_and_may_carry_it_sealed_to_a_watch() {
        let apns = apns();
        let plain = apns.waiting_payload(&push(None));
        assert_eq!(plain["isudo"]["r"], "b2".repeat(16));
        assert_eq!(plain["isudo"]["x"], 1_795_000_120_u64);
        assert!(plain["isudo"].get("w").is_none());
        assert_eq!(plain["aps"]["interruption-level"], "time-sensitive");

        let sealed = "A".repeat(isudo_relay_core::MAX_PUSHED_ENVELOPE);
        let with = apns.waiting_payload(&push(Some(&sealed)));
        assert_eq!(with["isudo"]["w"], sealed);
        // Apple accepts four kilobytes. The largest envelope the relay will
        // attach, with the longest computer name, stays inside that.
        let mut longest = push(Some(&sealed));
        longest.host_name = "x".repeat(64);
        assert!(apns.waiting_payload(&longest).to_string().len() < 4096);
        assert_eq!(plain["aps"]["alert"]["body"], "burke-mbp wants to run a command as root");
    }

    #[test]
    fn another_app_sets_its_own_wording() {
        let wording = Wording {
            body: "A bot on {host} is asking for network access".to_owned(),
            category: "WARDEN_REQUEST".to_owned(),
            key: "warden".to_owned(),
        };
        let apns = Apns { wording, ..apns() };
        let payload = apns.waiting_payload(&push(None));
        assert_eq!(payload["aps"]["alert"]["body"], "A bot on burke-mbp is asking for network access");
        assert_eq!(payload["aps"]["category"], "WARDEN_REQUEST");
        assert_eq!(payload["warden"]["r"], "b2".repeat(16));
        assert!(payload.get("isudo").is_none());
    }
}
