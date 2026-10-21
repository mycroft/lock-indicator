//! AWS IAM Identity Center (SSO) token check.
//!
//! `aws sso login` caches its token in `~/.aws/sso/cache/<sha1>.json`, where the
//! hash is computed from the profile's `sso_session` name or, for legacy
//! profiles, its `sso_start_url`. The check reads that file and compares its
//! `expiresAt` to the current time; nothing is sent over the network.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde::de::IgnoredAny;
use sha1::{Digest, Sha1};

use crate::check::{Status, home_dir, human_duration, parse_timestamp};

type Section = HashMap<String, String>;

/// Maximum depth of `source_profile` chains followed to find the SSO profile.
const MAX_PROFILE_CHAIN: usize = 10;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CachedToken {
    expires_at: String,
    access_token: Option<IgnoredAny>,
    refresh_token: Option<IgnoredAny>,
}

pub fn check(profile: &str, now: DateTime<Utc>) -> Status {
    let config_path = std::env::var_os("AWS_CONFIG_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| home_dir().join(".aws/config"));
    let config = match fs::read_to_string(&config_path) {
        Ok(text) => parse_ini(&text),
        Err(err) => {
            return Status::unknown(format!("cannot read {}: {err}", config_path.display()));
        }
    };
    let cache_key = match sso_cache_key(&config, profile) {
        Ok(key) => key,
        Err(err) => return Status::unknown(err),
    };

    let token_path = home_dir()
        .join(".aws/sso/cache")
        .join(format!("{cache_key}.json"));
    let token = match fs::read_to_string(&token_path) {
        Ok(text) => text,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Status::locked(format!(
                "no cached SSO token, run `aws sso login --profile {profile}`"
            ));
        }
        Err(err) => return Status::unknown(format!("cannot read {}: {err}", token_path.display())),
    };
    match serde_json::from_str::<CachedToken>(&token) {
        Ok(token) => evaluate(&token, now),
        Err(err) => Status::unknown(format!(
            "invalid SSO token cache {}: {err}",
            token_path.display()
        )),
    }
}

fn evaluate(token: &CachedToken, now: DateTime<Utc>) -> Status {
    let Some(expires_at) = parse_timestamp(&token.expires_at) else {
        return Status::unknown(format!(
            "invalid expiresAt `{}` in SSO token cache",
            token.expires_at
        ));
    };
    if token.access_token.is_none() {
        return Status::locked("no SSO access token cached");
    }
    if expires_at > now {
        return Status::unlocked().expiring_at(expires_at);
    }

    let ago = human_duration(now - expires_at);
    let status = if token.refresh_token.is_some() {
        // The CLI renews the access token with the refresh token on next use, as
        // long as the SSO session is still valid, which cannot be known offline.
        Status::unknown(format!(
            "access token expired {ago} ago; the next aws call may refresh it"
        ))
    } else {
        Status::locked(format!("SSO token expired {ago} ago"))
    };
    status.expiring_at(expires_at)
}

/// Computes the name of the SSO token cache file for `profile`.
fn sso_cache_key(config: &HashMap<String, Section>, profile: &str) -> Result<String, String> {
    let mut name = profile;
    for _ in 0..MAX_PROFILE_CHAIN {
        let section = profile_section(config, name)
            .ok_or_else(|| format!("profile `{name}` not found in AWS config"))?;
        if let Some(session) = section.get("sso_session") {
            return Ok(sha1_hex(session));
        }
        if let Some(start_url) = section.get("sso_start_url") {
            return Ok(sha1_hex(start_url));
        }
        match section.get("source_profile") {
            Some(source) => name = source,
            None => return Err(format!("profile `{name}` is not configured for AWS SSO")),
        }
    }
    Err(format!("source_profile chain of `{profile}` is too long"))
}

fn profile_section<'a>(config: &'a HashMap<String, Section>, name: &str) -> Option<&'a Section> {
    let section = config.get(&format!("profile {name}"));
    match name {
        "default" => section.or_else(|| config.get("default")),
        _ => section,
    }
}

fn sha1_hex(s: &str) -> String {
    Sha1::digest(s.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Parses the AWS config file into `section name -> key -> value`. Indented
/// lines are nested sub-settings (e.g. under `s3 =`) and are skipped.
fn parse_ini(text: &str) -> HashMap<String, Section> {
    let mut sections: HashMap<String, Section> = HashMap::new();
    let mut current: Option<String> = None;
    for line in text.lines() {
        if line.starts_with([' ', '\t']) {
            continue;
        }
        let line = line.trim();
        if line.is_empty() || line.starts_with(['#', ';']) {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            let name = name.split_whitespace().collect::<Vec<_>>().join(" ");
            sections.entry(name.clone()).or_default();
            current = Some(name);
        } else if let (Some(section), Some((key, value))) = (&current, line.split_once('=')) {
            sections
                .entry(section.clone())
                .or_default()
                .insert(key.trim().to_string(), value.trim().to_string());
        }
    }
    sections
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::check::State;

    const CONFIG: &str = "\
[default]
region = eu-west-1

[profile legacy]
sso_start_url = https://example.awsapps.com/start
sso_region = us-east-1
sso_account_id = 123456789012
sso_role_name = Admin

[profile modern]
sso_session = my-sso
sso_account_id = 123456789012
sso_role_name = ReadOnly
s3 =
  sso_session = not-this-one

[profile assumed]
role_arn = arn:aws:iam::123456789012:role/deploy
source_profile = modern

[profile static]
aws_access_key_id = AKIAEXAMPLE

[profile loop]
source_profile = loop

[sso-session my-sso]
sso_start_url = https://example.awsapps.com/start
sso_region = us-east-1
";

    fn now() -> DateTime<Utc> {
        parse_timestamp("2026-10-21T12:00:00Z").unwrap()
    }

    fn token(json: &str) -> CachedToken {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn cache_keys() {
        let config = parse_ini(CONFIG);
        assert_eq!(
            sso_cache_key(&config, "legacy").unwrap(),
            "e8be5486177c5b5392bd9aa76563515b29358e6e"
        );
        assert_eq!(
            sso_cache_key(&config, "modern").unwrap(),
            "0ad374308c5a4e22f723adf10145eafad7c4031c"
        );
        assert_eq!(
            sso_cache_key(&config, "assumed").unwrap(),
            "0ad374308c5a4e22f723adf10145eafad7c4031c"
        );
        assert!(
            sso_cache_key(&config, "default")
                .unwrap_err()
                .contains("not configured for AWS SSO")
        );
        assert!(
            sso_cache_key(&config, "static")
                .unwrap_err()
                .contains("not configured for AWS SSO")
        );
        assert!(
            sso_cache_key(&config, "missing")
                .unwrap_err()
                .contains("not found")
        );
        assert!(
            sso_cache_key(&config, "loop")
                .unwrap_err()
                .contains("too long")
        );
    }

    #[test]
    fn valid_token() {
        let status = evaluate(
            &token(r#"{"accessToken": "x", "expiresAt": "2026-10-21T15:00:00Z"}"#),
            now(),
        );
        assert_eq!(status.state, State::Unlocked);
        assert_eq!(status.expires_at, parse_timestamp("2026-10-21T15:00:00Z"));
    }

    #[test]
    fn expired_token() {
        let status = evaluate(
            &token(r#"{"accessToken": "x", "expiresAt": "2026-10-19T16:05:09UTC"}"#),
            now(),
        );
        assert_eq!(status.state, State::Locked);
        assert_eq!(
            status.detail.as_deref(),
            Some("SSO token expired 1d19h ago")
        );
    }

    #[test]
    fn expired_but_refreshable_token() {
        let status = evaluate(
            &token(
                r#"{"accessToken": "x", "refreshToken": "y", "expiresAt": "2026-10-21T11:00:00Z"}"#,
            ),
            now(),
        );
        assert_eq!(status.state, State::Unknown);
    }

    #[test]
    fn client_registration_is_not_a_token() {
        let status = evaluate(
            &token(r#"{"clientId": "x", "expiresAt": "2026-11-01T12:25:22Z"}"#),
            now(),
        );
        assert_eq!(status.state, State::Locked);
    }
}
