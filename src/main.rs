mod aws;
mod check;
mod cmd;
mod gcloud;
mod gpg;
mod output;
mod spec;
mod vault;

use std::thread;
use std::time::Duration;

use chrono::Utc;
use clap::{ArgGroup, Parser};

use check::{Check, Kind, Outcome, Status};
use output::{Format, Icons, Style};
use spec::Spec;

const AFTER_HELP: &str = r#"Each check can be given several times. Checks run in parallel.

Examples:
  lock-indicator --gpg 0xA629E94B9C4B2A03,label=work --aws main --gcloud me@example.com
  lock-indicator --vault ~/.vault-token,addr=https://vault.example.com:8200,label=prod --format json

Waybar module ("alt" and "class" are unlocked, partial, locked or unknown):
  "custom/locks": {
      "exec": "lock-indicator --format waybar --aws main --gpg 0xA629E94B9C4B2A03",
      "return-type": "json",
      "interval": 60,
      "tooltip": true
  }"#;

/// Report whether credentials are unlocked: gpg-agent keys, AWS SSO, gcloud and
/// Vault tokens.
#[derive(Parser)]
#[command(version, about, after_help = AFTER_HELP)]
#[command(group(ArgGroup::new("checks").required(true).multiple(true).args(["gpg", "aws", "gcloud", "vault"])))]
struct Cli {
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

    #[arg(short, long, value_enum, default_value_t = Format::Text)]
    format: Format,

    /// Template of each check in the text; placeholders: {icon}, {kind}, {label}, {state}, {expires}
    #[arg(long, value_name = "TEMPLATE", default_value = "{icon} {kind}:{label}")]
    item_format: String,

    /// Separator between checks in the text
    #[arg(long, value_name = "STRING", default_value = " ")]
    separator: String,

    #[arg(long, value_name = "ICON", default_value = "🔓")]
    icon_unlocked: String,

    #[arg(long, value_name = "ICON", default_value = "🔒")]
    icon_locked: String,

    #[arg(long, value_name = "ICON", default_value = "❓")]
    icon_unknown: String,

    /// Timeout of each external command (gpg, gcloud, vault)
    #[arg(long, value_name = "SECONDS", default_value_t = 10)]
    timeout: u64,
}

fn main() {
    let cli = Cli::parse();

    let checks: Vec<Check> = [
        (Kind::Gpg, cli.gpg),
        (Kind::Aws, cli.aws),
        (Kind::Gcloud, cli.gcloud),
        (Kind::Vault, cli.vault),
    ]
    .into_iter()
    .flat_map(|(kind, specs)| specs.into_iter().map(move |spec| Check::new(kind, spec)))
    .collect();

    let timeout = Duration::from_secs(cli.timeout);
    let statuses: Vec<Status> = thread::scope(|scope| {
        let handles: Vec<_> = checks
            .iter()
            .map(|check| scope.spawn(move || check.run(timeout)))
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
    let outcomes: Vec<Outcome> = checks
        .into_iter()
        .zip(statuses)
        .map(|(check, status)| Outcome { check, status })
        .collect();

    let style = Style {
        item_format: cli.item_format,
        separator: cli.separator,
        icons: Icons {
            unlocked: cli.icon_unlocked,
            locked: cli.icon_locked,
            unknown: cli.icon_unknown,
        },
    };
    println!(
        "{}",
        output::render(cli.format, &outcomes, &style, Utc::now())
    );
}
