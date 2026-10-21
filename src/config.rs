//! TOML configuration file.
//!
//! Every setting is optional: command-line options take precedence over the
//! file, and the file over the built-in defaults.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::check::{Kind, home_dir};
use crate::output::Format;
use crate::spec::Spec;

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub format: Option<Format>,
    pub timeout: Option<u64>,
    pub text_format: Option<String>,
    pub item_format: Option<String>,
    pub separator: Option<String>,
    pub icons: Icons,
    gpg: Vec<GpgEntry>,
    aws: Vec<AwsEntry>,
    gcloud: Vec<GcloudEntry>,
    vault: Vec<VaultEntry>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Icons {
    pub unlocked: Option<String>,
    pub locked: Option<String>,
    pub unknown: Option<String>,
    pub partial: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GpgEntry {
    key: String,
    label: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AwsEntry {
    profile: String,
    label: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GcloudEntry {
    account: String,
    label: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VaultEntry {
    token_file: String,
    addr: Option<String>,
    label: Option<String>,
}

impl Config {
    /// The checks defined in the file, grouped by kind like on the command line.
    pub fn checks(&self) -> Vec<(Kind, Spec)> {
        let spec = |value: &str, label: &Option<String>, addr: Option<&String>| Spec {
            value: value.to_string(),
            label: label.clone(),
            addr: addr.cloned(),
        };
        let gpg = self
            .gpg
            .iter()
            .map(|e| (Kind::Gpg, spec(&e.key, &e.label, None)));
        let aws = self
            .aws
            .iter()
            .map(|e| (Kind::Aws, spec(&e.profile, &e.label, None)));
        let gcloud = self
            .gcloud
            .iter()
            .map(|e| (Kind::Gcloud, spec(&e.account, &e.label, None)));
        let vault = self
            .vault
            .iter()
            .map(|e| (Kind::Vault, spec(&e.token_file, &e.label, e.addr.as_ref())));
        gpg.chain(aws).chain(gcloud).chain(vault).collect()
    }
}

/// `$XDG_CONFIG_HOME/lock-indicator/config.toml`, where `XDG_CONFIG_HOME`
/// defaults to `~/.config`.
pub fn default_path() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|dir| dir.is_absolute())
        .unwrap_or_else(|| home_dir().join(".config"))
        .join("lock-indicator/config.toml")
}

/// Loads the configuration from `path`, or from the default path when it is
/// `None`. A missing default file is an empty configuration.
pub fn load(path: Option<&Path>) -> Result<Config, String> {
    let (path, required) = match path {
        Some(path) => (path.to_path_buf(), true),
        None => (default_path(), false),
    };
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(err) if err.kind() == io::ErrorKind::NotFound && !required => {
            return Ok(Config::default());
        }
        Err(err) => return Err(format!("cannot read {}: {err}", path.display())),
    };
    toml::from_str(&text)
        .map_err(|err| format!("invalid configuration file {}: {err}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = r#"
format = "waybar"
timeout = 5
text_format = "{icon} {unlocked}/{total}"
item_format = "{icon} {label}"
separator = " | "

[icons]
unlocked = "U"
partial = "P"

[[gpg]]
key = "0xA629E94B9C4B2A03"
label = "work"

[[aws]]
profile = "main"

[[aws]]
profile = "sbx"
label = "sandbox"

[[gcloud]]
account = "me@example.com"

[[vault]]
token_file = "~/.vault-token"
addr = "https://vault.example.com:8200"
label = "prod"
"#;

    fn spec(value: &str, label: Option<&str>, addr: Option<&str>) -> Spec {
        Spec {
            value: value.into(),
            label: label.map(Into::into),
            addr: addr.map(Into::into),
        }
    }

    #[test]
    fn parses_example() {
        let config: Config = toml::from_str(EXAMPLE).unwrap();
        assert_eq!(config.format, Some(Format::Waybar));
        assert_eq!(config.timeout, Some(5));
        assert_eq!(
            config.text_format.as_deref(),
            Some("{icon} {unlocked}/{total}")
        );
        assert_eq!(config.item_format.as_deref(), Some("{icon} {label}"));
        assert_eq!(config.separator.as_deref(), Some(" | "));
        assert_eq!(config.icons.unlocked.as_deref(), Some("U"));
        assert_eq!(config.icons.locked, None);
        assert_eq!(config.icons.partial.as_deref(), Some("P"));
        assert_eq!(
            config.checks(),
            vec![
                (Kind::Gpg, spec("0xA629E94B9C4B2A03", Some("work"), None)),
                (Kind::Aws, spec("main", None, None)),
                (Kind::Aws, spec("sbx", Some("sandbox"), None)),
                (Kind::Gcloud, spec("me@example.com", None, None)),
                (
                    Kind::Vault,
                    spec(
                        "~/.vault-token",
                        Some("prod"),
                        Some("https://vault.example.com:8200")
                    )
                ),
            ]
        );
    }

    #[test]
    fn empty_file_is_valid() {
        let config: Config = toml::from_str("").unwrap();
        assert!(config.checks().is_empty());
        assert_eq!(config.format, None);
    }

    #[test]
    fn rejects_typos_and_invalid_values() {
        assert!(toml::from_str::<Config>("formt = \"json\"").is_err());
        assert!(toml::from_str::<Config>("format = \"yaml\"").is_err());
        assert!(toml::from_str::<Config>("[[aws]]\nname = \"main\"").is_err());
        assert!(toml::from_str::<Config>("[[gpg]]\nkey = \"x\"\naddr = \"y\"").is_err());
    }

    #[test]
    fn explicit_file_must_exist() {
        let err = load(Some(Path::new("/nonexistent/config.toml"))).unwrap_err();
        assert!(err.starts_with("cannot read /nonexistent/config.toml"));
    }
}
