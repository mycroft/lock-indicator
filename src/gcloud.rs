//! gcloud user credentials check.
//!
//! The refresh token stored by `gcloud auth login` has no local expiry: it stops
//! working when the session is revoked or reauthentication is required. The only
//! reliable check is to ask gcloud for an access token, refreshing it if needed.

use std::process::Command;
use std::time::Duration;

use crate::check::Status;
use crate::cmd;

/// Error output fragments meaning that Google could not be reached, in which
/// case the credential state is unknown rather than locked.
const NETWORK_ERRORS: &[&str] = &[
    "Failed to establish a new connection",
    "Max retries exceeded",
    "Temporary failure in name resolution",
    "Name or service not known",
    "Network is unreachable",
    "TransportError",
];

pub fn check(account: &str, timeout: Duration) -> Status {
    let mut command = Command::new("gcloud");
    command
        .args(["auth", "print-access-token", "--quiet", "--verbosity=error"])
        .arg(format!("--account={account}"))
        .env("CLOUDSDK_CORE_DISABLE_PROMPTS", "1");
    match cmd::run(&mut command, timeout) {
        // stdout holds the access token: it is deliberately discarded.
        Ok(out) if out.status.success() => Status::unlocked(),
        Ok(out) => classify_failure(&out.stderr),
        Err(err) => Status::unknown(cmd::describe_error("gcloud", &err)),
    }
}

fn classify_failure(stderr: &str) -> Status {
    let message = cmd::first_line(stderr)
        .unwrap_or("gcloud auth print-access-token failed")
        .trim_start_matches("ERROR: (gcloud.auth.print-access-token) ");
    if NETWORK_ERRORS
        .iter()
        .any(|fragment| stderr.contains(fragment))
    {
        Status::unknown(message)
    } else {
        Status::locked(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::check::State;

    #[test]
    fn reauth_required_is_locked() {
        let stderr = "\
ERROR: (gcloud.auth.print-access-token) There was a problem refreshing your current auth tokens: Reauthentication failed. cannot prompt during non-interactive execution.
Please run:

  $ gcloud auth login

to obtain new credentials.
";
        let status = classify_failure(stderr);
        assert_eq!(status.state, State::Locked);
        assert!(
            status
                .detail
                .unwrap()
                .starts_with("There was a problem refreshing")
        );
    }

    #[test]
    fn network_error_is_unknown() {
        let stderr = "ERROR: (gcloud.auth.print-access-token) There was a problem refreshing your current auth tokens: HTTPSConnectionPool(host='oauth2.googleapis.com', port=443): Max retries exceeded with url: /token\n";
        assert_eq!(classify_failure(stderr).state, State::Unknown);
    }
}
