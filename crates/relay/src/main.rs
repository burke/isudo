//! isudo-relay: the server between hosts and phones.
//!
//! It stores encrypted requests for a few minutes, tells the phone one is
//! waiting (by push notification), and carries the signed answer back. It is
//! not trusted with anything that matters: it cannot read a request, forge
//! an approval, or change who is paired. See `isudo-relay-core` for the
//! rules it enforces; this file is the HTTP shell around that state machine.
//!
//! Configuration is by environment variable, or by the same names in a
//! file of `NAME=value` lines given with `--config FILE` (which is what the
//! service definitions in `contrib/` use). The environment wins.
//!
//! ```text
//! ISUDO_RELAY_LISTEN               address to listen on (default 127.0.0.1:8787)
//! ISUDO_RELAY_STATE                file to keep pairings in (default: not kept)
//! ISUDO_RELAY_REGISTRATION_TOKEN   if set, required to create a pairing
//! ISUDO_APNS_KEY_FILE              Apple push key (.p8); pushes are off without it
//! ISUDO_APNS_KEY_ID                the key's ten-character id
//! ISUDO_APNS_TEAM_ID               the Apple developer team id
//! ISUDO_APNS_TOPIC                 the app's bundle identifier
//! ```
//!
//! The server speaks plain HTTP and expects TLS to be terminated in front of
//! it. Hosts and phones refuse to talk to a relay over plain HTTP unless it
//! is on the same machine.

mod apns;

use std::collections::HashMap;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use isudo_proto::api::{
    Ack, Answer, Claim, ClaimView, Confirm, CreatePairing, DeviceUpdate, ErrorBody, PairingStatus, PendingList, Revoke,
    SubmitRequest,
};
use isudo_relay_core::{Limits, Push, Reject, Relay};
use serde::Deserialize;
use tokio::sync::Notify;

use crate::apns::{Apns, ApnsConfig};

/// Largest request body accepted: a full-size envelope, base64, plus slack.
const MAX_BODY: usize = 128 * 1024;
/// Longest a long poll is held open.
const MAX_WAIT_SECS: u64 = 30;
/// How often expired state is swept when nothing else triggers it.
const SWEEP_EVERY: Duration = Duration::from_secs(30);

/// Writes a log line to standard error.
fn log(message: &str) {
    let line = ["isudo-relay: ", message, "\n"].concat();
    // If standard error is gone there is nowhere to report that.
    drop(std::io::stderr().lock().write_all(line.as_bytes()));
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_secs())
}

struct App {
    relay: Mutex<Relay>,
    /// Woken whenever an answer arrives, so long polls can look again.
    answered: Notify,
    apns: Option<Apns>,
    state_file: Option<PathBuf>,
}

impl App {
    /// Runs one step of the state machine.
    fn step<T>(&self, f: impl FnOnce(&mut Relay, u64) -> Result<T, Reject>) -> Result<T, ApiError> {
        // The state machine cannot panic part-way through a step, so state
        // behind a poisoned lock is still consistent.
        let mut relay = self.relay.lock().unwrap_or_else(PoisonError::into_inner);
        f(&mut relay, now()).map_err(ApiError)
    }

    /// Saves pairings so they survive a restart.
    async fn persist(&self) {
        let Some(path) = &self.state_file else { return };
        let snapshot = self.relay.lock().unwrap_or_else(PoisonError::into_inner).snapshot();
        let Ok(json) = serde_json::to_vec_pretty(&snapshot) else { return };
        let temporary = path.with_extension("tmp");
        let written = async {
            let mut options = tokio::fs::OpenOptions::new();
            let mut file = options.write(true).create(true).truncate(true).mode(0o600).open(&temporary).await?;
            tokio::io::AsyncWriteExt::write_all(&mut file, &json).await?;
            file.sync_all().await?;
            tokio::fs::rename(&temporary, path).await
        }
        .await;
        if let Err(error) = written {
            log(&format!("cannot save state to {}: {error}", path.display()));
        }
    }

    /// Sends a push in the background; the request does not wait for Apple.
    fn push(self: &Arc<Self>, push: Push) {
        if self.apns.is_none() {
            return;
        }
        let app = Arc::clone(self);
        drop(tokio::spawn(async move {
            let Some(apns) = &app.apns else { return };
            if let Err(error) = apns.send(&push, now()).await {
                log(&format!("push for request {} failed: {error}", push.request_id));
            }
        }));
    }
}

/// A refusal, as an HTTP response. The body is a fixed word per category.
struct ApiError(Reject);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error) = match self.0 {
            Reject::Invalid => (StatusCode::BAD_REQUEST, "invalid"),
            Reject::NotFound => (StatusCode::NOT_FOUND, "not found"),
            Reject::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Reject::Conflict => (StatusCode::CONFLICT, "conflict"),
            Reject::TooMany => (StatusCode::TOO_MANY_REQUESTS, "too many requests"),
        };
        (status, Json(ErrorBody { error: error.to_owned() })).into_response()
    }
}

type Shared = State<Arc<App>>;
type Done = Result<StatusCode, ApiError>;

/// The bearer token from an `Authorization` header, or the empty string,
/// which matches nothing.
fn bearer(headers: &HeaderMap) -> &str {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .unwrap_or_default()
}

async fn create_pairing(State(app): Shared, headers: HeaderMap, Json(body): Json<CreatePairing>) -> Done {
    let token = Some(bearer(&headers)).filter(|token| !token.is_empty());
    app.step(|relay, now| relay.create_pairing(now, &body, token))?;
    app.persist().await;
    Ok(StatusCode::NO_CONTENT)
}

async fn claim(State(app): Shared, Path(pairing): Path<String>, Json(body): Json<Claim>) -> Done {
    app.step(|relay, now| relay.claim(now, &pairing, &body))?;
    app.persist().await;
    Ok(StatusCode::NO_CONTENT)
}

async fn claim_view(State(app): Shared, Path(pairing): Path<String>) -> Result<Response, ApiError> {
    let view: Option<ClaimView> = app.step(|relay, _| relay.claim_view(&pairing))?;
    Ok(view.map_or_else(|| StatusCode::NO_CONTENT.into_response(), |view| Json(view).into_response()))
}

async fn acknowledge(State(app): Shared, Path(pairing): Path<String>, Json(body): Json<Ack>) -> Done {
    app.step(|relay, _| relay.acknowledge(&pairing, &body))?;
    app.persist().await;
    Ok(StatusCode::NO_CONTENT)
}

async fn confirm(State(app): Shared, Path(pairing): Path<String>, Json(body): Json<Confirm>) -> Done {
    app.step(|relay, _| relay.confirm(&pairing, &body))?;
    app.persist().await;
    Ok(StatusCode::NO_CONTENT)
}

async fn status(
    State(app): Shared,
    Path(pairing): Path<String>,
    headers: HeaderMap,
) -> Result<Json<PairingStatus>, ApiError> {
    app.step(|relay, _| relay.status(&pairing, bearer(&headers))).map(Json)
}

async fn update_device(
    State(app): Shared,
    Path(pairing): Path<String>,
    headers: HeaderMap,
    Json(body): Json<DeviceUpdate>,
) -> Done {
    app.step(|relay, _| relay.update_device(&pairing, bearer(&headers), &body))?;
    app.persist().await;
    Ok(StatusCode::NO_CONTENT)
}

async fn revoke(State(app): Shared, Path(pairing): Path<String>, Json(body): Json<Revoke>) -> Done {
    app.step(|relay, _| relay.revoke_as_host(&pairing, &body))?;
    app.persist().await;
    Ok(StatusCode::NO_CONTENT)
}

async fn unpair(State(app): Shared, Path(pairing): Path<String>, headers: HeaderMap) -> Done {
    app.step(|relay, _| relay.revoke_as_phone(&pairing, bearer(&headers)))?;
    app.persist().await;
    Ok(StatusCode::NO_CONTENT)
}

async fn pending(
    State(app): Shared,
    Path(pairing): Path<String>,
    headers: HeaderMap,
) -> Result<Json<PendingList>, ApiError> {
    app.step(|relay, now| relay.pending(now, &pairing, bearer(&headers))).map(Json)
}

async fn submit(State(app): Shared, Json(body): Json<SubmitRequest>) -> Done {
    if let Some(push) = app.step(|relay, now| relay.submit(now, &body))? {
        app.push(push);
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn answer(State(app): Shared, Path(request): Path<String>, headers: HeaderMap, Json(body): Json<Answer>) -> Done {
    app.step(|relay, now| relay.answer(now, &request, bearer(&headers), body))?;
    app.answered.notify_waiters();
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct Wait {
    #[serde(default)]
    wait: u64,
}

/// Long poll: answers as soon as the phone has, or with 204 after `wait`
/// seconds.
async fn poll_answer(
    State(app): Shared,
    Path(request): Path<String>,
    Query(Wait { wait }): Query<Wait>,
) -> Result<Response, ApiError> {
    let give_up = tokio::time::sleep(Duration::from_secs(wait.min(MAX_WAIT_SECS)));
    tokio::pin!(give_up);
    loop {
        // Register interest before looking, so an answer that arrives
        // between the look and the wait is not missed.
        let answered = app.answered.notified();
        tokio::pin!(answered);
        let _ = answered.as_mut().enable();
        if let Some(found) = app.step(|relay, now| relay.poll_answer(now, &request))? {
            return Ok(Json(found).into_response());
        }
        tokio::select! {
            () = &mut answered => {}
            () = &mut give_up => return Ok(StatusCode::NO_CONTENT.into_response()),
        }
    }
}

fn router(app: Arc<App>) -> Router {
    Router::new()
        .route("/v1/pairings", post(create_pairing))
        .route("/v1/pairings/{pairing}", get(status))
        .route("/v1/pairings/{pairing}/claim", post(claim).get(claim_view))
        .route("/v1/pairings/{pairing}/ack", post(acknowledge))
        .route("/v1/pairings/{pairing}/confirm", post(confirm))
        .route("/v1/pairings/{pairing}/device", post(update_device))
        .route("/v1/pairings/{pairing}/revoke", post(revoke))
        .route("/v1/pairings/{pairing}/unpair", post(unpair))
        .route("/v1/pairings/{pairing}/requests", get(pending))
        .route("/v1/requests", post(submit))
        .route("/v1/requests/{request}/response", post(answer).get(poll_answer))
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .with_state(app)
}

/// Settings read from `--config FILE`, if one was given.
static FILE_SETTINGS: OnceLock<HashMap<String, String>> = OnceLock::new();

/// A setting: from the environment if set there, otherwise from the file.
fn env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .or_else(|| FILE_SETTINGS.get().and_then(|settings| settings.get(name).cloned()))
        .filter(|value| !value.is_empty())
}

/// Parses `NAME=value` lines. Blank lines and lines starting with `#` are
/// skipped; anything else without an `=` is an error.
fn parse_settings(text: &str) -> Result<HashMap<String, String>, String> {
    let mut settings = HashMap::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (name, value) =
            line.split_once('=').ok_or_else(|| format!("line {}: expected NAME=value", index.saturating_add(1)))?;
        let value = value.trim();
        let value = value.strip_prefix('"').and_then(|v| v.strip_suffix('"')).unwrap_or(value);
        let _ = settings.insert(name.trim().to_owned(), value.to_owned());
    }
    Ok(settings)
}

/// Handles the command line: nothing, or `--config FILE`.
fn load_settings() -> Result<(), String> {
    const USAGE: &str = "usage: isudo-relay [--config FILE]";
    let args: Vec<String> = std::env::args().skip(1).collect();
    let path = match args.as_slice() {
        [] => return Ok(()),
        [flag, path] if flag == "--config" => path,
        _ => return Err(USAGE.to_owned()),
    };
    let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    let settings = parse_settings(&text).map_err(|e| format!("{path}: {e}"))?;
    FILE_SETTINGS.set(settings).map_err(|_already| "settings were loaded twice".to_owned())
}

/// Reads the APNs settings: all four or none.
fn apns_from_env() -> Result<Option<Apns>, String> {
    const NAMES: [&str; 4] = ["ISUDO_APNS_KEY_FILE", "ISUDO_APNS_KEY_ID", "ISUDO_APNS_TEAM_ID", "ISUDO_APNS_TOPIC"];
    match NAMES.map(env) {
        [None, None, None, None] => Ok(None),
        [Some(key_file), Some(key_id), Some(team_id), Some(topic)] => {
            Apns::new(ApnsConfig { key_file, key_id, team_id, topic }).map(Some)
        }
        _ => Err(format!("set all of {} or none of them", NAMES.join(", "))),
    }
}

fn load(state_file: Option<&PathBuf>) -> Result<Relay, String> {
    let mut relay = Relay::new(Limits::default(), env("ISUDO_RELAY_REGISTRATION_TOKEN").as_deref());
    if let Some(path) = state_file {
        match std::fs::read(path) {
            Ok(bytes) => {
                let snapshot = serde_json::from_slice(&bytes)
                    .map_err(|e| format!("{} is not a relay state file: {e}", path.display()))?;
                relay.restore(snapshot);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("cannot read {}: {error}", path.display())),
        }
    }
    Ok(relay)
}

async fn serve() -> Result<(), String> {
    load_settings()?;
    // One TLS implementation for the whole process, chosen explicitly.
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_already| "a TLS provider was already installed".to_owned())?;
    let listen = env("ISUDO_RELAY_LISTEN").unwrap_or_else(|| "127.0.0.1:8787".to_owned());
    let state_file = env("ISUDO_RELAY_STATE").map(PathBuf::from);
    let apns = apns_from_env()?;
    let app =
        Arc::new(App { relay: Mutex::new(load(state_file.as_ref())?), answered: Notify::new(), apns, state_file });

    let sweeper = Arc::clone(&app);
    drop(tokio::spawn(async move {
        let mut tick = tokio::time::interval(SWEEP_EVERY);
        loop {
            let _ = tick.tick().await;
            sweeper.relay.lock().unwrap_or_else(PoisonError::into_inner).sweep(now());
        }
    }));

    let listener =
        tokio::net::TcpListener::bind(&listen).await.map_err(|e| format!("cannot listen on {listen}: {e}"))?;
    log(&format!(
        "listening on {listen}; pushes {}; state {}",
        if app.apns.is_some() { "on" } else { "off (no APNs key configured)" },
        app.state_file.as_ref().map_or_else(|| "not kept".to_owned(), |path| path.display().to_string()),
    ));
    axum::serve(listener, router(app))
        .with_graceful_shutdown(async {
            // If the signal handler cannot be installed, run until killed.
            if tokio::signal::ctrl_c().await.is_err() {
                std::future::pending::<()>().await;
            }
        })
        .await
        .map_err(|e| format!("server error: {e}"))
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match serve().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(message) => {
            log(&message);
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_files_are_parsed() {
        let settings = parse_settings(
            "# relay settings\n\nISUDO_RELAY_LISTEN = 127.0.0.1:8787\nISUDO_APNS_TOPIC=\"com.example.isudo\"\nEMPTY=\n",
        )
        .unwrap();
        assert_eq!(settings.get("ISUDO_RELAY_LISTEN").map(String::as_str), Some("127.0.0.1:8787"));
        assert_eq!(settings.get("ISUDO_APNS_TOPIC").map(String::as_str), Some("com.example.isudo"));
        assert_eq!(settings.get("EMPTY").map(String::as_str), Some(""));
        assert!(parse_settings("just words").unwrap_err().contains("line 1"));
    }
}
