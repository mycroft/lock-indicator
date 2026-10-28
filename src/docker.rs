//! Docker registry credentials check.
//!
//! The credentials of a registry are looked up like the docker CLI does: from
//! the credential helper configured for it (`credHelpers`, else `credsStore`),
//! else from the `auths` of the auth file. Tokens carrying an expiry date (JWTs,
//! Amazon ECR tokens) are checked offline. Other credentials, such as passwords
//! and personal access tokens, have none: only the registry can tell whether
//! they still work, and it is asked only when the check is `remote`.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use base64::Engine;
use base64::alphabet;
use base64::engine::general_purpose::STANDARD;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use chrono::{DateTime, Utc};
use serde::Deserialize;

use crate::check::{Status, home_dir, human_duration};
use crate::{cmd, registry};

/// The key of Docker Hub credentials, for historical reasons.
const HUB_KEY: &str = "https://index.docker.io/v1/";
/// The Docker Hub registry API.
const HUB_API: &str = "https://registry-1.docker.io";

/// Base64url, as in JWTs, with or without padding.
const BASE64_URL: GeneralPurpose = GeneralPurpose::new(
    &alphabet::URL_SAFE,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

/// The credentials part of a Docker `config.json`, or of a containers
/// `auth.json` which shares its format.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct AuthFile {
    auths: Option<HashMap<String, AuthEntry>>,
    #[serde(rename = "credsStore")]
    creds_store: Option<String>,
    #[serde(rename = "credHelpers")]
    cred_helpers: Option<HashMap<String, String>>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct AuthEntry {
    /// Base64 of `username:password`.
    auth: Option<String>,
    identitytoken: Option<String>,
    registrytoken: Option<String>,
}

/// Output of `docker-credential-HELPER get`.
#[derive(Deserialize)]
struct HelperCredentials {
    #[serde(rename = "Username")]
    username: String,
    #[serde(rename = "Secret")]
    secret: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Credentials {
    /// A username with a password or an access token.
    Basic { username: String, password: String },
    /// An OAuth2 refresh token, exchanged for registry tokens.
    Identity(String),
    /// A registry bearer token.
    Bearer(String),
}

impl Credentials {
    fn secret(&self) -> &str {
        match self {
            Credentials::Basic { password, .. } => password,
            Credentials::Identity(token) | Credentials::Bearer(token) => token,
        }
    }
}

pub fn check(
    registry: &str,
    auth_file: &Path,
    remote: bool,
    timeout: Duration,
    now: DateTime<Utc>,
) -> Status {
    let config = match load(auth_file) {
        Ok(config) => config,
        Err(status) => return status,
    };
    let helper = |name: &str| PathBuf::from(format!("docker-credential-{name}"));
    let credentials = match credentials(&config, &auth_key(registry), helper, timeout) {
        Ok(Some(credentials)) => credentials,
        Ok(None) => return Status::locked("not logged in"),
        Err(status) => return status,
    };
    match token_expiry(credentials.secret()) {
        Some(expires_at) if expires_at > now => Status::unlocked().expiring_at(expires_at),
        Some(expires_at) => Status::locked(format!(
            "token expired {} ago",
            human_duration(now - expires_at)
        ))
        .expiring_at(expires_at),
        None if remote => registry::verify(&api_url(registry), &credentials, timeout),
        None => Status::unlocked().with_detail("no expiry date, not verified with the registry"),
    }
}

/// `$DOCKER_CONFIG/config.json`, where `DOCKER_CONFIG` defaults to `~/.docker`.
pub fn default_auth_file() -> PathBuf {
    std::env::var_os("DOCKER_CONFIG")
        .filter(|dir| !dir.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home_dir().join(".docker"))
        .join("config.json")
}

/// The default label of a registry: its host, `docker.io` for Docker Hub.
pub fn label(registry: &str) -> String {
    let host = hostname(registry);
    if is_hub(host) { "docker.io" } else { host }.to_string()
}

fn load(path: &Path) -> Result<AuthFile, Status> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Err(Status::locked(format!(
                "no auth file at {}",
                path.display()
            )));
        }
        Err(err) => {
            return Err(Status::unknown(format!(
                "cannot read {}: {err}",
                path.display()
            )));
        }
    };
    serde_json::from_str(&text)
        .map_err(|err| Status::unknown(format!("invalid auth file {}: {err}", path.display())))
}

/// The credentials stored for `key`, `None` when there are none. `helper` maps
/// a credential helper name to its program.
fn credentials(
    config: &AuthFile,
    key: &str,
    helper: impl Fn(&str) -> PathBuf,
    timeout: Duration,
) -> Result<Option<Credentials>, Status> {
    // An empty helper name for the registry overrides `credsStore`: the
    // credentials are then in the file, as with the docker CLI.
    let name = config
        .cred_helpers
        .as_ref()
        .and_then(|helpers| helpers.get(key))
        .or(config.creds_store.as_ref())
        .filter(|name| !name.is_empty());
    match name {
        Some(name) => from_helper(&helper(name), key, timeout),
        None => from_auths(config, key),
    }
}

fn from_helper(
    program: &Path,
    key: &str,
    timeout: Duration,
) -> Result<Option<Credentials>, Status> {
    let mut command = Command::new(program);
    command.arg("get");
    let out = cmd::run_with_input(&mut command, Some(key), timeout)
        .map_err(|err| Status::unknown(cmd::describe_error(program, &err)))?;
    if !out.status.success() {
        // Helpers report errors on stdout.
        let message = cmd::first_line(&out.stdout)
            .or_else(|| cmd::first_line(&out.stderr))
            .unwrap_or("failed");
        if message.contains("credentials not found") {
            return Ok(None);
        }
        return Err(Status::unknown(format!(
            "`{}`: {message}",
            program.display()
        )));
    }
    let HelperCredentials { username, secret } =
        serde_json::from_str(&out.stdout).map_err(|err| {
            Status::unknown(format!("unexpected `{}` output: {err}", program.display()))
        })?;
    Ok(if secret.is_empty() {
        None
    } else if username == "<token>" {
        Some(Credentials::Identity(secret))
    } else {
        Some(Credentials::Basic {
            username,
            password: secret,
        })
    })
}

fn from_auths(config: &AuthFile, key: &str) -> Result<Option<Credentials>, Status> {
    let Some(auths) = &config.auths else {
        return Ok(None);
    };
    // Older docker versions stored keys as URLs, e.g. `https://ghcr.io`.
    let entry = auths.get(key).or_else(|| {
        auths
            .iter()
            .find(|(other, _)| auth_key(other) == key)
            .map(|(_, entry)| entry)
    });
    let Some(entry) = entry else {
        return Ok(None);
    };
    let non_empty = |value: &Option<String>| value.clone().filter(|value| !value.is_empty());
    if let Some(token) = non_empty(&entry.identitytoken) {
        return Ok(Some(Credentials::Identity(token)));
    }
    if let Some(token) = non_empty(&entry.registrytoken) {
        return Ok(Some(Credentials::Bearer(token)));
    }
    match non_empty(&entry.auth) {
        Some(auth) => decode_auth(&auth)
            .map(Some)
            .ok_or_else(|| Status::unknown(format!("invalid `auth` value for {key}"))),
        None => Ok(None),
    }
}

/// Decodes an `auth` value: the base64 of `username:password`.
fn decode_auth(auth: &str) -> Option<Credentials> {
    let decoded = String::from_utf8(STANDARD.decode(auth).ok()?).ok()?;
    let (username, password) = decoded.split_once(':')?;
    (!username.is_empty()).then(|| Credentials::Basic {
        username: username.to_string(),
        password: password.trim_matches('\0').to_string(),
    })
}

/// The expiry date carried by a token: the `exp` claim of a JWT, or the
/// `expiration` of an Amazon ECR token (base64-encoded JSON).
fn token_expiry(token: &str) -> Option<DateTime<Utc>> {
    let claims: serde_json::Value = match token.split('.').collect::<Vec<_>>()[..] {
        [_, payload, _] => serde_json::from_slice(&BASE64_URL.decode(payload).ok()?).ok()?,
        _ => serde_json::from_slice(&STANDARD.decode(token).ok()?).ok()?,
    };
    let seconds = claims
        .get("exp")
        .or_else(|| claims.get("expiration"))?
        .as_f64()?;
    DateTime::from_timestamp(seconds as i64, 0)
}

/// The key of the credentials of `registry` in the auth file and credential
/// helpers: its host, or [`HUB_KEY`] for Docker Hub.
fn auth_key(registry: &str) -> String {
    let host = hostname(registry);
    if is_hub(host) { HUB_KEY } else { host }.to_string()
}

/// The base URL of the registry API: HTTPS, unless `registry` is a URL with
/// another scheme, such as `http://localhost:5000`.
fn api_url(registry: &str) -> String {
    let host = hostname(registry);
    if is_hub(host) {
        return HUB_API.to_string();
    }
    let scheme = registry
        .split_once("://")
        .map_or("https", |(scheme, _)| scheme);
    format!("{scheme}://{host}")
}

/// The `host[:port]` of a registry given as a host or as a URL.
fn hostname(registry: &str) -> &str {
    let rest = registry
        .split_once("://")
        .map_or(registry, |(_, rest)| rest);
    rest.split('/').next().unwrap_or(rest)
}

fn is_hub(host: &str) -> bool {
    matches!(
        host,
        "docker.io" | "index.docker.io" | "registry-1.docker.io"
    )
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    use super::*;
    use crate::check::{State, parse_timestamp};

    fn now() -> DateTime<Utc> {
        parse_timestamp("2026-10-21T12:00:00Z").unwrap()
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("lock-indicator-test-{}-{name}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn auth(username: &str, password: &str) -> String {
        STANDARD.encode(format!("{username}:{password}"))
    }

    fn ecr_token(expiration: i64) -> String {
        STANDARD.encode(format!(
            r#"{{"payload":"p","datakey":"d","version":"2","type":"DATA_KEY","expiration":{expiration}}}"#
        ))
    }

    fn jwt(exp: i64) -> String {
        let claims = URL_SAFE_NO_PAD.encode(format!(r#"{{"sub":"me","exp":{exp}}}"#));
        format!("eyJhbGciOiJSUzI1NiJ9.{claims}.c2ln")
    }

    #[test]
    fn keys_labels_and_urls() {
        assert_eq!(auth_key("ghcr.io"), "ghcr.io");
        assert_eq!(auth_key("https://ghcr.io/"), "ghcr.io");
        assert_eq!(auth_key("localhost:5000"), "localhost:5000");
        assert_eq!(auth_key("docker.io"), HUB_KEY);
        assert_eq!(auth_key(HUB_KEY), HUB_KEY);
        assert_eq!(label(HUB_KEY), "docker.io");
        assert_eq!(
            label("https://registry.example.com:8443/v2/"),
            "registry.example.com:8443"
        );
        assert_eq!(api_url("ghcr.io"), "https://ghcr.io");
        assert_eq!(api_url("http://localhost:5000"), "http://localhost:5000");
        assert_eq!(api_url("index.docker.io"), HUB_API);
    }

    #[test]
    fn token_expiries() {
        let at = DateTime::from_timestamp(1_790_021_424, 0);
        assert_eq!(token_expiry(&ecr_token(1_790_021_424)), at);
        assert_eq!(token_expiry(&jwt(1_790_021_424)), at);
        assert_eq!(token_expiry("hunter22"), None);
        assert_eq!(token_expiry("ghp_0123456789abcdef"), None);
        assert_eq!(token_expiry("a.b.c"), None);
        assert_eq!(token_expiry(""), None);
    }

    #[test]
    fn decodes_auth() {
        assert_eq!(
            decode_auth(&auth("AWS", "pass:word")),
            Some(Credentials::Basic {
                username: "AWS".into(),
                password: "pass:word".into()
            })
        );
        assert_eq!(decode_auth(&auth("", "password")), None);
        assert_eq!(decode_auth("not base64!"), None);
    }

    #[test]
    fn checks_auth_file_entries() {
        let dir = temp_dir("auths");
        let file = dir.join("config.json");
        let in_1h = now().timestamp() + 3600;
        let ago_1h = now().timestamp() - 3600;
        let config = serde_json::json!({
            "auths": {
                "1.dkr.ecr.eu-west-3.amazonaws.com": {"auth": auth("AWS", &ecr_token(in_1h))},
                "2.dkr.ecr.eu-west-3.amazonaws.com": {"auth": auth("AWS", &ecr_token(ago_1h))},
                "https://registry.example.com": {"auth": auth("me", "hunter22")},
                "acr.azurecr.io": {"auth": auth("00000000-0000-0000-0000-000000000000", ""), "identitytoken": jwt(ago_1h)},
                "empty.example.com": {},
                "broken.example.com": {"auth": "!!"},
            }
        });
        fs::write(&file, config.to_string()).unwrap();
        let run = |registry| check(registry, &file, false, Duration::from_secs(5), now());

        let status = run("1.dkr.ecr.eu-west-3.amazonaws.com");
        assert_eq!(status.state, State::Unlocked);
        assert_eq!(status.expires_at, DateTime::from_timestamp(in_1h, 0));

        let status = run("2.dkr.ecr.eu-west-3.amazonaws.com");
        assert_eq!(status.state, State::Locked);
        assert_eq!(status.detail.as_deref(), Some("token expired 1h00m ago"));

        let status = run("registry.example.com");
        assert_eq!(status.state, State::Unlocked);
        assert_eq!(
            status.detail.as_deref(),
            Some("no expiry date, not verified with the registry")
        );

        assert_eq!(run("acr.azurecr.io").state, State::Locked);
        assert_eq!(
            run("empty.example.com").detail.as_deref(),
            Some("not logged in")
        );
        assert_eq!(run("ghcr.io").detail.as_deref(), Some("not logged in"));
        assert_eq!(run("broken.example.com").state, State::Unknown);

        fs::write(&file, "{").unwrap();
        assert_eq!(run("ghcr.io").state, State::Unknown);
        fs::remove_dir_all(&dir).unwrap();
        assert_eq!(run("ghcr.io").state, State::Locked);
    }

    #[test]
    fn reads_credential_helpers() {
        let dir = temp_dir("helpers");
        let script = format!(
            r#"#!/bin/sh
read -r server
case "$server" in
    ghcr.io) echo '{{"ServerURL":"ghcr.io","Username":"me","Secret":"s3cret"}}' ;;
    {HUB_KEY}) echo '{{"ServerURL":"{HUB_KEY}","Username":"<token>","Secret":"{}"}}' ;;
    *) echo "credentials not found in native keychain"; exit 1 ;;
esac
"#,
            jwt(now().timestamp() + 60)
        );
        let program = dir.join("docker-credential-fake");
        fs::write(&program, script).unwrap();
        fs::set_permissions(&program, fs::Permissions::from_mode(0o755)).unwrap();

        let config: AuthFile = serde_json::from_value(serde_json::json!({
            "auths": {"ghcr.io": {}, "registry.example.com": {"auth": auth("me", "pw")}},
            "credsStore": "fake",
            "credHelpers": {"quay.io": "missing", "registry.example.com": ""},
        }))
        .unwrap();
        let lookup = |registry| {
            let helper = |name: &str| dir.join(format!("docker-credential-{name}"));
            credentials(&config, &auth_key(registry), helper, Duration::from_secs(5))
        };

        assert_eq!(
            lookup("ghcr.io"),
            Ok(Some(Credentials::Basic {
                username: "me".into(),
                password: "s3cret".into()
            }))
        );
        assert!(matches!(
            lookup("docker.io"),
            Ok(Some(Credentials::Identity(_)))
        ));
        assert_eq!(lookup("gcr.io"), Ok(None));
        // An empty helper falls back to the file.
        assert!(matches!(
            lookup("registry.example.com"),
            Ok(Some(Credentials::Basic { .. }))
        ));
        let Err(status) = lookup("quay.io") else {
            panic!("expected an error");
        };
        assert_eq!(status.state, State::Unknown);
        fs::remove_dir_all(&dir).unwrap();
    }
}
