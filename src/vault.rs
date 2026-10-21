//! Vault token check.
//!
//! The token read from the file is looked up with `vault token lookup`, so the
//! usual `VAULT_*` environment variables (CA certificates, namespace, ...) apply.

use std::fs;
use std::io;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::Deserialize;

use crate::check::{Status, human_duration, parse_timestamp};
use crate::cmd;

#[derive(Deserialize)]
struct Lookup {
    data: LookupData,
}

#[derive(Deserialize)]
struct LookupData {
    expire_time: Option<String>,
}

pub fn check(
    token_file: &Path,
    addr: Option<&str>,
    timeout: Duration,
    now: DateTime<Utc>,
) -> Status {
    let token = match fs::read_to_string(token_file) {
        Ok(token) => token,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Status::locked(format!("no token file at {}", token_file.display()));
        }
        Err(err) => return Status::unknown(format!("cannot read {}: {err}", token_file.display())),
    };
    let token = token.trim();
    if token.is_empty() {
        return Status::locked(format!("token file {} is empty", token_file.display()));
    }

    let mut command = Command::new("vault");
    command
        .args(["token", "lookup", "-format=json"])
        .env("VAULT_TOKEN", token);
    if let Some(addr) = addr {
        command.env("VAULT_ADDR", addr);
    }
    match cmd::run(&mut command, timeout) {
        Ok(out) if out.status.success() => evaluate(&out.stdout, now),
        Ok(out) if out.stderr.contains("permission denied") => {
            Status::locked("token expired, revoked or invalid")
        }
        Ok(out) => {
            Status::unknown(cmd::first_line(&out.stderr).unwrap_or("vault token lookup failed"))
        }
        Err(err) => Status::unknown(cmd::describe_error("vault", &err)),
    }
}

fn evaluate(lookup: &str, now: DateTime<Utc>) -> Status {
    let lookup: Lookup = match serde_json::from_str(lookup) {
        Ok(lookup) => lookup,
        Err(err) => return Status::unknown(format!("unexpected vault token lookup output: {err}")),
    };
    let Some(expire_time) = lookup.data.expire_time else {
        return Status::unlocked().with_detail("token does not expire");
    };
    match parse_timestamp(&expire_time) {
        Some(expires_at) if expires_at > now => Status::unlocked().expiring_at(expires_at),
        Some(expires_at) => Status::locked(format!(
            "token expired {} ago",
            human_duration(now - expires_at)
        ))
        .expiring_at(expires_at),
        None => Status::unknown(format!("invalid expire_time `{expire_time}`")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::check::State;

    fn now() -> DateTime<Utc> {
        parse_timestamp("2026-10-21T12:00:00Z").unwrap()
    }

    #[test]
    fn valid_token() {
        let lookup = r#"{"request_id": "r", "data": {"id": "hvs.x", "ttl": 3600, "expire_time": "2026-10-21T15:00:00.123456789+02:00"}}"#;
        let status = evaluate(lookup, now());
        assert_eq!(status.state, State::Unlocked);
        assert_eq!(
            status.expires_at,
            parse_timestamp("2026-10-21T13:00:00.123456789Z")
        );
    }

    #[test]
    fn expired_token() {
        let lookup = r#"{"data": {"expire_time": "2026-10-21T11:30:00Z"}}"#;
        assert_eq!(
            evaluate(lookup, now()).detail.as_deref(),
            Some("token expired 30m ago")
        );
    }

    #[test]
    fn non_expiring_token() {
        let lookup = r#"{"data": {"ttl": 0, "expire_time": null}}"#;
        let status = evaluate(lookup, now());
        assert_eq!(status.state, State::Unlocked);
        assert_eq!(status.expires_at, None);
    }

    #[test]
    fn missing_token_file() {
        let status = check(
            Path::new("/nonexistent/.vault-token"),
            None,
            Duration::from_secs(1),
            now(),
        );
        assert_eq!(status.state, State::Locked);
    }
}
