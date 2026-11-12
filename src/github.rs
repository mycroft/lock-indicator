//! GitHub CLI authentication check.
//!
//! `gh auth status` verifies the token of the active account of a host with the
//! GitHub API, wherever gh stores it (keyring, `hosts.yml` or `GH_TOKEN`). With
//! `--json` it reports the outcome per account and always exits with zero.

use std::collections::HashMap;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use serde::Deserialize;

use crate::check::Status;
use crate::cmd;

#[derive(Deserialize)]
struct AuthStatus {
    hosts: HashMap<String, Vec<Account>>,
}

#[derive(Deserialize)]
struct Account {
    state: String,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    login: String,
    #[serde(default)]
    active: bool,
}

pub fn check(host: &str, program: &Path, timeout: Duration) -> Status {
    let mut command = Command::new(program);
    command
        .args([
            "auth",
            "status",
            "--active",
            "--json",
            "hosts",
            "--hostname",
            host,
        ])
        .env("GH_PROMPT_DISABLED", "1")
        .env("GH_NO_UPDATE_NOTIFIER", "1");
    match cmd::run(&mut command, timeout) {
        Ok(out) if out.status.success() => evaluate(&out.stdout, host),
        Ok(out) => Status::unknown(cmd::first_line(&out.stderr).unwrap_or("gh auth status failed")),
        Err(err) => Status::unknown(cmd::describe_error(program, &err)),
    }
}

fn evaluate(output: &str, host: &str) -> Status {
    let status: AuthStatus = match serde_json::from_str(output) {
        Ok(status) => status,
        Err(err) => return Status::unknown(format!("unexpected gh auth status output: {err}")),
    };
    let account = status
        .hosts
        .get(host)
        .and_then(|accounts| accounts.iter().find(|account| account.active));
    let Some(account) = account else {
        return Status::locked("not logged in");
    };
    match account.state.as_str() {
        "success" => Status::unlocked().with_detail(format!("logged in as {}", account.login)),
        "timeout" => Status::unknown("timed out reaching the GitHub API"),
        _ => {
            let error = account.error.as_deref().unwrap_or("authentication failed");
            // Other errors, such as network failures, say nothing of the token.
            if error.contains("401") || error.contains("Bad credentials") {
                Status::locked("token expired, revoked or invalid")
            } else {
                Status::unknown(error)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::check::State;

    #[test]
    fn valid_token() {
        let output = r#"{"hosts":{"github.com":[{"state":"success","active":true,"host":"github.com","login":"octocat","tokenSource":"keyring","scopes":"repo","gitProtocol":"ssh"}]}}"#;
        let status = evaluate(output, "github.com");
        assert_eq!(status.state, State::Unlocked);
        assert_eq!(status.detail.as_deref(), Some("logged in as octocat"));
    }

    #[test]
    fn bad_credentials_are_locked() {
        let output = r#"{"hosts":{"github.com":[{"state":"error","error":"HTTP 401: Bad credentials (https://api.github.com/)","active":true,"host":"github.com","login":"octocat","tokenSource":"default","gitProtocol":"ssh"}]}}"#;
        let status = evaluate(output, "github.com");
        assert_eq!(status.state, State::Locked);
        assert_eq!(
            status.detail.as_deref(),
            Some("token expired, revoked or invalid")
        );
        // A token from GH_TOKEN is reported differently.
        let output = r#"{"hosts":{"github.com":[{"state":"error","error":"non-200 OK status code: 401 Unauthorized body: \"...\"","active":true,"host":"github.com","login":"","tokenSource":"GH_TOKEN"}]}}"#;
        assert_eq!(evaluate(output, "github.com").state, State::Locked);
    }

    #[test]
    fn network_errors_are_unknown() {
        let output = r#"{"hosts":{"github.com":[{"state":"error","error":"Get \"https://api.github.com/\": dial tcp: lookup api.github.com: no such host","active":true,"host":"github.com","login":"octocat"}]}}"#;
        let status = evaluate(output, "github.com");
        assert_eq!(status.state, State::Unknown);
        assert!(status.detail.unwrap().contains("no such host"));
        let output = r#"{"hosts":{"github.com":[{"state":"timeout","active":true,"host":"github.com","login":"octocat"}]}}"#;
        assert_eq!(evaluate(output, "github.com").state, State::Unknown);
    }

    #[test]
    fn not_logged_in() {
        let status = evaluate(r#"{"hosts":{}}"#, "github.example.com");
        assert_eq!(status.state, State::Locked);
        assert_eq!(status.detail.as_deref(), Some("not logged in"));
    }

    #[test]
    fn invalid_output() {
        assert_eq!(evaluate("nope", "github.com").state, State::Unknown);
    }
}
