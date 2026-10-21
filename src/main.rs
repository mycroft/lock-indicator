mod aws;
mod check;
mod cmd;
mod config;
mod gcloud;
mod gpg;
mod output;
mod spec;
mod vault;

use std::path::PathBuf;
use std::process;
use std::thread;
use std::time::Duration;

use chrono::Utc;
use clap::Parser;

use check::{Check, Kind, Outcome, Status};
use config::Config;
use output::{Format, Icons, Style};
use spec::Spec;

const DEFAULT_TIMEOUT: u64 = 10;

const AFTER_HELP: &str = r#"Each check can be given several times. Checks run in parallel.

Checks and options can also be set in a TOML configuration file. Command-line
options take precedence, and checks given on the command line replace the ones
from the file.

Examples:
  lock-indicator --gpg 0xA629E94B9C4B2A03,label=work --aws main --gcloud me@example.com
  lock-indicator --vault ~/.vault-token,addr=https://vault.example.com:8200,label=prod --format json
  lock-indicator --aws main --aws sbx --text-format '{icon} {unlocked}/{total}'

Waybar module ("alt" and "class" are unlocked, partial, locked or unknown):
  "custom/locks": {
      "exec": "lock-indicator --format waybar",
      "return-type": "json",
      "interval": 60,
      "tooltip": true
  }"#;

/// Report whether credentials are unlocked: gpg-agent keys, AWS SSO, gcloud and
/// Vault tokens.
#[derive(Parser)]
#[command(version, about, after_help = AFTER_HELP)]
struct Cli {
    /// Configuration file [default: $XDG_CONFIG_HOME/lock-indicator/config.toml]
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// GPG key (id, fingerprint or user id) whose passphrase must be cached in gpg-agent
    #[arg(long, value_name = "KEY[,label=NAME]", value_parser = spec::parse_basic)]
    gpg: Vec<Spec>,

    /// AWS profile whose `aws sso login` token must not be expired
    #[arg(long, value_name = "PROFILE[,label=NAME]", value_parser = spec::parse_basic)]
    aws: Vec<Spec>,

    /// gcloud account whose `gcloud auth login` credentials must still work
    #[arg(long, value_name = "ACCOUNT[,label=NAME]", value_parser = spec::parse_basic)]
    gcloud: Vec<Spec>,

    /// Vault token file whose token must not be expired; the server defaults to $VAULT_ADDR
    #[arg(long, value_name = "FILE[,addr=URL][,label=NAME]", value_parser = spec::parse_vault)]
    vault: Vec<Spec>,

    /// Output format [default: text]
    #[arg(short, long, value_enum)]
    format: Option<Format>,

    /// Template of the whole text; placeholders: {items}, {icon}, {state}, {unlocked}, {locked},
    /// {unknown}, {total} [default: "{items}"]
    #[arg(long, value_name = "TEMPLATE")]
    text_format: Option<String>,

    /// Template of each check in {items}; placeholders: {icon}, {kind}, {label}, {state},
    /// {expires} [default: "{icon} {kind}:{label}"]
    #[arg(long, value_name = "TEMPLATE")]
    item_format: Option<String>,

    /// Separator between checks in {items} [default: " "]
    #[arg(long, value_name = "STRING")]
    separator: Option<String>,

    /// Icon of unlocked checks [default: 🔓]
    #[arg(long, value_name = "ICON")]
    icon_unlocked: Option<String>,

    /// Icon of locked checks [default: 🔒]
    #[arg(long, value_name = "ICON")]
    icon_locked: Option<String>,

    /// Icon of checks in an unknown state [default: ❓]
    #[arg(long, value_name = "ICON")]
    icon_unknown: Option<String>,

    /// Overall {icon} in --text-format when only some checks are unlocked [default: 🔐]
    #[arg(long, value_name = "ICON")]
    icon_partial: Option<String>,

    /// Timeout of each external command (gpg, gcloud, vault) [default: 10]
    #[arg(long, value_name = "SECONDS")]
    timeout: Option<u64>,
}

/// Command-line options merged with the configuration file and the defaults.
struct Settings {
    checks: Vec<Check>,
    format: Format,
    timeout: Duration,
    style: Style,
}

fn resolve(cli: Cli, config: Config) -> Result<Settings, String> {
    let cli_checks: Vec<(Kind, Spec)> = [
        (Kind::Gpg, cli.gpg),
        (Kind::Aws, cli.aws),
        (Kind::Gcloud, cli.gcloud),
        (Kind::Vault, cli.vault),
    ]
    .into_iter()
    .flat_map(|(kind, specs)| specs.into_iter().map(move |spec| (kind, spec)))
    .collect();
    let checks = if cli_checks.is_empty() {
        config.checks()
    } else {
        cli_checks
    };
    if checks.is_empty() {
        return Err(format!(
            "nothing to check: pass --gpg, --aws, --gcloud or --vault, or add checks to {}",
            config::default_path().display()
        ));
    }

    let defaults = Style::default();
    Ok(Settings {
        checks: checks
            .into_iter()
            .map(|(kind, spec)| Check::new(kind, spec))
            .collect(),
        format: cli.format.or(config.format).unwrap_or(Format::Text),
        timeout: Duration::from_secs(cli.timeout.or(config.timeout).unwrap_or(DEFAULT_TIMEOUT)),
        style: Style {
            text_format: cli
                .text_format
                .or(config.text_format)
                .unwrap_or(defaults.text_format),
            item_format: cli
                .item_format
                .or(config.item_format)
                .unwrap_or(defaults.item_format),
            separator: cli
                .separator
                .or(config.separator)
                .unwrap_or(defaults.separator),
            icons: Icons {
                unlocked: cli
                    .icon_unlocked
                    .or(config.icons.unlocked)
                    .unwrap_or(defaults.icons.unlocked),
                locked: cli
                    .icon_locked
                    .or(config.icons.locked)
                    .unwrap_or(defaults.icons.locked),
                unknown: cli
                    .icon_unknown
                    .or(config.icons.unknown)
                    .unwrap_or(defaults.icons.unknown),
                partial: cli
                    .icon_partial
                    .or(config.icons.partial)
                    .unwrap_or(defaults.icons.partial),
            },
        },
    })
}

fn main() {
    let cli = Cli::parse();
    let settings = config::load(cli.config.as_deref())
        .and_then(|config| resolve(cli, config))
        .unwrap_or_else(|err| {
            eprintln!("error: {err}");
            process::exit(2);
        });

    let statuses: Vec<Status> = thread::scope(|scope| {
        let handles: Vec<_> = settings
            .checks
            .iter()
            .map(|check| scope.spawn(|| check.run(settings.timeout)))
            .collect();
        handles
            .into_iter()
            .map(|handle| {
                handle
                    .join()
                    .unwrap_or_else(|_| Status::unknown("check panicked"))
            })
            .collect()
    });
    let outcomes: Vec<Outcome> = settings
        .checks
        .into_iter()
        .zip(statuses)
        .map(|(check, status)| Outcome { check, status })
        .collect();

    println!(
        "{}",
        output::render(settings.format, &outcomes, &settings.style, Utc::now())
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolve_with(args: &[&str], config: &str) -> Result<Settings, String> {
        let cli = Cli::try_parse_from([&["lock-indicator"], args].concat()).unwrap();
        resolve(cli, toml::from_str(config).unwrap())
    }

    fn targets(settings: &Settings) -> Vec<(Kind, &str)> {
        settings
            .checks
            .iter()
            .map(|check| (check.kind, check.label.as_str()))
            .collect()
    }

    const CONFIG: &str = r#"
format = "json"
item_format = "{label}"
[icons]
locked = "L"
[[aws]]
profile = "main"
[[gpg]]
key = "0xA629E94B9C4B2A03"
label = "work"
"#;

    #[test]
    fn config_fills_in_defaults() {
        let settings = resolve_with(&[], CONFIG).unwrap();
        assert_eq!(
            targets(&settings),
            [(Kind::Gpg, "work"), (Kind::Aws, "main")]
        );
        assert_eq!(settings.format, Format::Json);
        assert_eq!(settings.style.item_format, "{label}");
        assert_eq!(settings.style.icons.locked, "L");
        assert_eq!(settings.style.icons.unlocked, "🔓");
        assert_eq!(settings.style.text_format, "{items}");
        assert_eq!(settings.timeout, Duration::from_secs(DEFAULT_TIMEOUT));
    }

    #[test]
    fn command_line_takes_precedence() {
        let args = [
            "--aws=sbx",
            "--format=waybar",
            "--item-format={icon}",
            "--icon-locked=X",
            "--timeout=3",
        ];
        let settings = resolve_with(&args, CONFIG).unwrap();
        assert_eq!(targets(&settings), [(Kind::Aws, "sbx")]);
        assert_eq!(settings.format, Format::Waybar);
        assert_eq!(settings.style.item_format, "{icon}");
        assert_eq!(settings.style.icons.locked, "X");
        assert_eq!(settings.timeout, Duration::from_secs(3));
    }

    #[test]
    fn requires_a_check() {
        let Err(err) = resolve_with(&["--format=json"], "") else {
            panic!("expected an error");
        };
        assert!(err.starts_with("nothing to check"));
    }
}
