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
use output::{ByState, Format, Style};
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

    /// Template of the whole text; placeholders: {items}, {kinds}, {icon}, {color}, {state},
    /// {unlocked}, {locked}, {unknown}, {total}, and the same for one kind, e.g. {aws.color}
    /// [default: "{items}"]
    #[arg(long, value_name = "TEMPLATE")]
    text_format: Option<String>,

    /// Template of each check in {items}; placeholders: {icon}, {color}, {kind}, {label},
    /// {state}, {expires} [default: "{icon} {kind}:{label}"]
    #[arg(long, value_name = "TEMPLATE")]
    item_format: Option<String>,

    /// Template of each kind of check in {kinds}; placeholders: {kind}, {icon}, {color}, {state},
    /// {unlocked}, {locked}, {unknown}, {total} [default: "{icon} {kind}"]
    #[arg(long, value_name = "TEMPLATE")]
    kind_format: Option<String>,

    /// Separator between the entries of {items} and {kinds} [default: " "]
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

    /// Icon of a group of checks of which only some are unlocked [default: 🔐]
    #[arg(long, value_name = "ICON")]
    icon_partial: Option<String>,

    /// {color} of unlocked checks [default: #98c379]
    #[arg(long, value_name = "COLOR")]
    color_unlocked: Option<String>,

    /// {color} of locked checks [default: #e06c75]
    #[arg(long, value_name = "COLOR")]
    color_locked: Option<String>,

    /// {color} of checks in an unknown state [default: #888888]
    #[arg(long, value_name = "COLOR")]
    color_unknown: Option<String>,

    /// {color} of a group of checks of which only some are unlocked [default: #d19a66]
    #[arg(long, value_name = "COLOR")]
    color_partial: Option<String>,

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
        format: pick(cli.format, config.format, Format::Text),
        timeout: Duration::from_secs(pick(cli.timeout, config.timeout, DEFAULT_TIMEOUT)),
        style: Style {
            text_format: pick(cli.text_format, config.text_format, defaults.text_format),
            item_format: pick(cli.item_format, config.item_format, defaults.item_format),
            kind_format: pick(cli.kind_format, config.kind_format, defaults.kind_format),
            separator: pick(cli.separator, config.separator, defaults.separator),
            icons: ByState {
                unlocked: pick(
                    cli.icon_unlocked,
                    config.icons.unlocked,
                    defaults.icons.unlocked,
                ),
                locked: pick(cli.icon_locked, config.icons.locked, defaults.icons.locked),
                unknown: pick(
                    cli.icon_unknown,
                    config.icons.unknown,
                    defaults.icons.unknown,
                ),
                partial: pick(
                    cli.icon_partial,
                    config.icons.partial,
                    defaults.icons.partial,
                ),
            },
            colors: ByState {
                unlocked: pick(
                    cli.color_unlocked,
                    config.colors.unlocked,
                    defaults.colors.unlocked,
                ),
                locked: pick(
                    cli.color_locked,
                    config.colors.locked,
                    defaults.colors.locked,
                ),
                unknown: pick(
                    cli.color_unknown,
                    config.colors.unknown,
                    defaults.colors.unknown,
                ),
                partial: pick(
                    cli.color_partial,
                    config.colors.partial,
                    defaults.colors.partial,
                ),
            },
        },
    })
}

/// The command-line value, else the configuration file's, else the default.
fn pick<T>(cli: Option<T>, config: Option<T>, default: T) -> T {
    cli.or(config).unwrap_or(default)
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
kind_format = "{kind}"
[icons]
locked = "L"
[colors]
partial = "orange"
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
        assert_eq!(settings.style.kind_format, "{kind}");
        assert_eq!(settings.style.colors.partial, "orange");
        assert_eq!(settings.style.colors.locked, "#e06c75");
        assert_eq!(settings.timeout, Duration::from_secs(DEFAULT_TIMEOUT));
    }

    #[test]
    fn command_line_takes_precedence() {
        let args = [
            "--aws=sbx",
            "--format=waybar",
            "--item-format={icon}",
            "--icon-locked=X",
            "--color-partial=yellow",
            "--kind-format={icon}",
            "--timeout=3",
        ];
        let settings = resolve_with(&args, CONFIG).unwrap();
        assert_eq!(targets(&settings), [(Kind::Aws, "sbx")]);
        assert_eq!(settings.format, Format::Waybar);
        assert_eq!(settings.style.item_format, "{icon}");
        assert_eq!(settings.style.icons.locked, "X");
        assert_eq!(settings.style.colors.partial, "yellow");
        assert_eq!(settings.style.kind_format, "{icon}");
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
