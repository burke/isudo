//! Sending push notifications through Apple's push service.
//!
//! A push only says "there is a request, here is its id". The request itself
//! is fetched by the app from the relay, encrypted, so Apple learns nothing
//! but timing.

use std::path::Path;
use std::time::Duration;

use isudo_proto::codec::b64_encode;
use isudo_relay_core::Push;
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
    /// The current provider token and when it was issued.
    token: Mutex<Option<(u64, String)>>,
}

#[derive(Debug, Clone)]
pub(crate) struct ApnsConfig {
    pub key_file: String,
    pub key_id: String,
    pub team_id: String,
    pub topic: String,
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

    /// Sends one push. Returns a short description of any failure, for the log.
    pub(crate) async fn send(&self, push: &Push, now: u64) -> Result<(), String> {
        let host = if push.device.apns_env == "production" {
            "api.push.apple.com"
        } else {
            "api.sandbox.push.apple.com"
        };
        let url = ["https://", host, "/3/device/", &push.device.apns_token].concat();
        let body = [push.host_name.as_str(), " wants to run a command as root"].concat();
        let payload = json!({
            "aps": {
                "alert": { "title": "Approval requested", "body": body },
                "sound": "default",
                "interruption-level": "time-sensitive",
                "category": "ISUDO_REQUEST",
                "thread-id": push.pairing_id,
            },
            "isudo": { "p": push.pairing_id, "r": push.request_id },
        });
        let response = self
            .client
            .post(url)
            .bearer_auth(self.provider_token(now).await)
            .header("apns-topic", &self.topic)
            .header("apns-push-type", "alert")
            .header("apns-priority", "10")
            .header("apns-expiration", push.expires_at.to_string())
            .header("apns-collapse-id", &push.request_id)
            .json(&payload)
            .send()
            .await
            .map_err(|e| format!("request failed: {e}"))?;
        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        let reason = response.text().await.unwrap_or_default();
        Err(format!("APNs answered {status}: {}", reason.chars().take(200).collect::<String>()))
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
}
