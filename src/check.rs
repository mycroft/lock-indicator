//! Check definitions and their outcome.

use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::{DateTime, TimeDelta, Utc};

use crate::spec::Spec;
use crate::{aws, gcloud, gpg, vault};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Gpg,
    Aws,
    Gcloud,
    Vault,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Gpg => "gpg",
            Kind::Aws => "aws",
            Kind::Gcloud => "gcloud",
            Kind::Vault => "vault",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Unlocked,
    Locked,
    /// The state could not be determined (missing tool, network error, ...).
    Unknown,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::Unlocked => "unlocked",
            State::Locked => "locked",
            State::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub state: State,
    pub detail: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

impl Status {
    pub fn unlocked() -> Self {
        Status {
            state: State::Unlocked,
            detail: None,
            expires_at: None,
        }
    }

    pub fn locked(detail: impl Into<String>) -> Self {
        Status {
            state: State::Locked,
            detail: Some(detail.into()),
            expires_at: None,
        }
    }

    pub fn unknown(detail: impl Into<String>) -> Self {
        Status {
            state: State::Unknown,
            detail: Some(detail.into()),
            expires_at: None,
        }
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    pub fn expiring_at(mut self, at: DateTime<Utc>) -> Self {
        self.expires_at = Some(at);
        self
    }
}

#[derive(Debug, Clone)]
pub struct Check {
    pub kind: Kind,
    pub label: String,
    /// What is checked: gpg key, AWS profile, gcloud account or Vault token file.
    pub target: String,
    /// Vault server address.
    pub addr: Option<String>,
}

impl Check {
    pub fn new(kind: Kind, spec: Spec) -> Self {
        let target = match kind {
            Kind::Vault => expand_tilde(&spec.value).display().to_string(),
            _ => spec.value,
        };
        let label = spec
            .label
            .unwrap_or_else(|| default_label(kind, &target, spec.addr.as_deref()));
        Check {
            kind,
            label,
            target,
            addr: spec.addr,
        }
    }

    pub fn run(&self, timeout: Duration) -> Status {
        match self.kind {
            Kind::Gpg => gpg::check(&self.target, timeout),
            Kind::Aws => aws::check(&self.target, Utc::now()),
            Kind::Gcloud => gcloud::check(&self.target, timeout),
            Kind::Vault => vault::check(
                Path::new(&self.target),
                self.addr.as_deref(),
                timeout,
                Utc::now(),
            ),
        }
    }
}

pub struct Outcome {
    pub check: Check,
    pub status: Status,
}

/// Formats a duration compactly, e.g. `2d3h`, `3h05m`, `12m` or `40s`.
pub fn human_duration(delta: TimeDelta) -> String {
    let secs = delta.num_seconds().unsigned_abs();
    let (days, hours, mins) = (secs / 86_400, secs % 86_400 / 3_600, secs % 3_600 / 60);
    if days > 0 {
        format!("{days}d{hours}h")
    } else if hours > 0 {
        format!("{hours}h{mins:02}m")
    } else if mins > 0 {
        format!("{mins}m")
    } else {
        format!("{secs}s")
    }
}

/// Parses an RFC 3339 timestamp, also accepting the `...UTC` suffix written by
/// older AWS CLI versions.
pub fn parse_timestamp(s: &str) -> Option<DateTime<Utc>> {
    let normalized = match s.strip_suffix("UTC") {
        Some(rest) => format!("{rest}Z"),
        None => s.to_string(),
    };
    DateTime::parse_from_rfc3339(&normalized)
        .ok()
        .map(|t| t.with_timezone(&Utc))
}

pub fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default()
}

fn expand_tilde(path: &str) -> PathBuf {
    match path.strip_prefix("~") {
        Some("") => home_dir(),
        Some(rest) if rest.starts_with('/') => home_dir().join(&rest[1..]),
        _ => PathBuf::from(path),
    }
}

fn default_label(kind: Kind, target: &str, addr: Option<&str>) -> String {
    match (kind, addr) {
        (Kind::Vault, Some(addr)) => host(addr).to_string(),
        (Kind::Vault, None) => Path::new(target).file_name().map_or_else(
            || target.to_string(),
            |name| name.to_string_lossy().into_owned(),
        ),
        _ => target.to_string(),
    }
}

/// Extracts the host from a URL such as `https://vault.example.com:8200/`.
fn host(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    rest.split(['/', ':']).next().unwrap_or(rest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(human_duration(TimeDelta::seconds(40)), "40s");
        assert_eq!(human_duration(TimeDelta::seconds(12 * 60 + 5)), "12m");
        assert_eq!(
            human_duration(TimeDelta::seconds(3 * 3600 + 5 * 60)),
            "3h05m"
        );
        assert_eq!(
            human_duration(TimeDelta::seconds(2 * 86_400 + 3 * 3600)),
            "2d3h"
        );
        assert_eq!(human_duration(TimeDelta::seconds(-90)), "1m");
    }

    #[test]
    fn timestamps() {
        let expected = DateTime::parse_from_rfc3339("2026-10-19T16:05:09Z").unwrap();
        assert_eq!(
            parse_timestamp("2026-10-19T16:05:09Z"),
            Some(expected.into())
        );
        assert_eq!(
            parse_timestamp("2026-10-19T16:05:09UTC"),
            Some(expected.into())
        );
        assert_eq!(
            parse_timestamp("2026-10-19T18:05:09.123456789+02:00").map(|t| t.timestamp()),
            Some(expected.timestamp())
        );
        assert_eq!(parse_timestamp("tomorrow"), None);
    }

    #[test]
    fn labels() {
        let spec = |value: &str, addr: Option<&str>| Spec {
            value: value.into(),
            label: None,
            addr: addr.map(Into::into),
        };
        assert_eq!(Check::new(Kind::Aws, spec("main", None)).label, "main");
        assert_eq!(
            Check::new(Kind::Vault, spec("/tmp/.vault-token", None)).label,
            ".vault-token"
        );
        assert_eq!(
            Check::new(
                Kind::Vault,
                spec("/tmp/t", Some("https://vault.example.com:8200"))
            )
            .label,
            "vault.example.com"
        );
        let labelled = Spec {
            label: Some("prod".into()),
            ..spec("main", None)
        };
        assert_eq!(Check::new(Kind::Aws, labelled).label, "prod");
    }

    #[test]
    fn tilde_expansion() {
        let home = home_dir();
        assert_eq!(expand_tilde("~/.vault-token"), home.join(".vault-token"));
        assert_eq!(expand_tilde("~"), home);
        assert_eq!(expand_tilde("/etc/token"), PathBuf::from("/etc/token"));
        assert_eq!(expand_tilde("~other/token"), PathBuf::from("~other/token"));
    }
}
