//! isudo-helper: carries one request to the relay and one answer back.
//!
//! The setuid binary starts this program as the calling user, writes a job
//! to its standard input, and reads an outcome from its standard output.
//! Nothing here is trusted: the setuid binary acts only on a signature it
//! verifies itself. This program's job is delivery.
//!
//! It is not meant to be run by hand.

#![forbid(unsafe_code)]

use std::io::{Read as _, Write as _};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use isudo_client::envelope;
use isudo_client::relay::{Relay, RelayError};
use isudo_proto::api::{DelegateEnvelope, SubmitRequest};
use isudo_proto::codec::{b64_encode, hex_encode};
use isudo_proto::frame::{Failure, Job, Outcome};
use isudo_proto::{sigs, MAX_REQUEST_LEN};

/// Longest single wait on the relay before asking again.
const POLL: Duration = Duration::from_secs(25);
/// Pause after a failed poll, so a broken connection is not hammered.
const RETRY_PAUSE: Duration = Duration::from_secs(2);

fn main() {
    let outcome = run().unwrap_or_else(|failure| Outcome::Failed { failure });
    let Ok(bytes) = outcome.encode() else { return };
    let mut stdout = std::io::stdout().lock();
    // If the parent has gone there is nobody to tell.
    drop(stdout.write_all(&bytes));
    drop(stdout.flush());
}

const fn relay_failure(error: RelayError) -> Failure {
    match error {
        RelayError::BadUrl(_) | RelayError::Transport(_) => Failure::RelayUnreachable,
        RelayError::Status(status) => Failure::RelayRefused(status),
        RelayError::Body => Failure::Malformed,
    }
}

/// Failures are reported as codes. Nothing received from the relay, and no
/// wording of this program's own, travels back: the setuid binary words
/// every message itself.
fn run() -> Result<Outcome, Failure> {
    let parent = std::os::unix::process::parent_id();
    let started = Instant::now();

    let limit = u64::try_from(MAX_REQUEST_LEN).unwrap_or(u64::MAX).saturating_add(4096);
    let mut input = Vec::new();
    let _ = std::io::stdin().lock().take(limit).read_to_end(&mut input).map_err(|_e| Failure::Internal)?;
    // Not a job: this program was run by hand rather than by isudo.
    let job = Job::decode(&input).map_err(|_e| Failure::Internal)?;

    let relay_url = std::str::from_utf8(&job.relay_url).map_err(|_e| Failure::Internal)?;
    let relay = Relay::new(relay_url).map_err(relay_failure)?;
    let sealed = envelope::seal(&job.phone_kem_pub, &job.pairing_id, &job.host_sig, &job.request)
        .map_err(|_e| Failure::Internal)?;
    let request_id = hex_encode(&sigs::request_id(&job.request));
    let delegate_envelopes = if job.delegates { seal_for_delegates(&relay, &job) } else { Vec::new() };

    relay
        .submit(&SubmitRequest {
            pairing_id: hex_encode(&job.pairing_id),
            request_id: request_id.clone(),
            expires_at: job.expires_at,
            ticket_sig: b64_encode(&job.ticket_sig),
            envelope: b64_encode(&sealed),
            delegate_envelopes,
        })
        .map_err(relay_failure)?;

    let deadline = started.checked_add(Duration::from_secs(u64::from(job.timeout_secs)));
    loop {
        let remaining = deadline.map_or(Duration::ZERO, |at| at.saturating_duration_since(Instant::now()));
        if remaining.is_zero() {
            return Err(Failure::TimedOut);
        }
        if std::os::unix::process::parent_id() != parent {
            // isudo itself is gone (cancelled); nobody is waiting.
            return Err(Failure::Cancelled);
        }
        match relay.poll_answer(&request_id, remaining.min(POLL)) {
            Ok(Some(answer)) => return isudo_client::outcome_of(answer),
            Ok(None) => {}
            // The relay forgot the request: it expired or was never stored.
            Err(RelayError::Status(404 | 410)) => return Err(Failure::TimedOut),
            Err(_) => std::thread::sleep(RETRY_PAUSE.min(remaining)),
        }
    }
}

/// Seals the request to each delegate the phone has signed for, so that a
/// watch can show it too.
///
/// Best effort: if the relay cannot say, or says nothing believable, the
/// request still goes to the phone. What the relay returns is only a hint;
/// a request is sealed to a key only if the pinned phone key signed for it.
fn seal_for_delegates(relay: &Relay, job: &Job) -> Vec<DelegateEnvelope> {
    let Ok(listed) = relay.delegations(&hex_encode(&job.pairing_id)) else { return Vec::new() };
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(u64::MAX, |since| since.as_secs());
    let mut sealed = Vec::new();
    for encoded in listed.delegations.iter().take(isudo_client::MAX_DELEGATES) {
        let Some(delegation) = isudo_client::verified_delegation(encoded, &job.pairing_id, &job.phone_sign_pub, now)
        else {
            continue;
        };
        if let Ok(envelope) = envelope::seal(&delegation.kem_pub, &job.pairing_id, &job.host_sig, &job.request) {
            sealed
                .push(DelegateEnvelope { delegate: b64_encode(&delegation.sign_pub), envelope: b64_encode(&envelope) });
        }
    }
    sealed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_errors_become_codes() {
        assert_eq!(relay_failure(RelayError::Transport("timed out")), Failure::RelayUnreachable);
        assert_eq!(relay_failure(RelayError::Status(429)), Failure::RelayRefused(429));
        assert_eq!(relay_failure(RelayError::Body), Failure::Malformed);
    }
}
