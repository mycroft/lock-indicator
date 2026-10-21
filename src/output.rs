//! Rendering of check outcomes as text, JSON or waybar custom module JSON.

use std::borrow::Cow;

use chrono::{DateTime, Local, Utc};
use serde::Serialize;

use crate::check::{Outcome, State, human_duration};

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Format {
    /// One line, each check rendered with --item-format
    Text,
    /// Detailed report of every check
    Json,
    /// Waybar custom module JSON (`"return-type": "json"`)
    Waybar,
}

pub struct Style {
    pub item_format: String,
    pub separator: String,
    pub icons: Icons,
}

pub struct Icons {
    pub unlocked: String,
    pub locked: String,
    pub unknown: String,
}

impl Icons {
    fn get(&self, state: State) -> &str {
        match state {
            State::Unlocked => &self.unlocked,
            State::Locked => &self.locked,
            State::Unknown => &self.unknown,
        }
    }
}

pub fn render(format: Format, outcomes: &[Outcome], style: &Style, now: DateTime<Utc>) -> String {
    match format {
        Format::Text => text(outcomes, style, now, false),
        Format::Json => json(outcomes, now),
        Format::Waybar => waybar(outcomes, style, now),
    }
}

/// Overall state of all checks: `unlocked`, `partial`, `locked` or `unknown`.
pub fn summary(outcomes: &[Outcome]) -> &'static str {
    let count = |state| outcomes.iter().filter(|o| o.status.state == state).count();
    let unlocked = count(State::Unlocked);
    if unlocked == outcomes.len() {
        "unlocked"
    } else if unlocked > 0 {
        "partial"
    } else if count(State::Locked) > 0 {
        "locked"
    } else {
        "unknown"
    }
}

fn text(outcomes: &[Outcome], style: &Style, now: DateTime<Utc>, markup: bool) -> String {
    outcomes
        .iter()
        .map(|outcome| {
            let status = &outcome.status;
            render_template(&style.item_format, |name| {
                let value: Cow<str> = match name {
                    "icon" => return Some(style.icons.get(status.state).to_string()),
                    "kind" => outcome.check.kind.as_str().into(),
                    "label" => outcome.check.label.as_str().into(),
                    "state" => status.state.as_str().into(),
                    "expires" => remaining(outcome, now).unwrap_or_default().into(),
                    _ => return None,
                };
                Some(escape(&value, markup).into_owned())
            })
        })
        .collect::<Vec<_>>()
        .join(&style.separator)
}

fn tooltip(outcomes: &[Outcome], style: &Style, now: DateTime<Utc>, markup: bool) -> String {
    outcomes
        .iter()
        .map(|outcome| {
            let (check, status) = (&outcome.check, &outcome.status);
            let mut line = format!(
                "{} {}:{} — {}",
                style.icons.get(status.state),
                check.kind.as_str(),
                escape(&check.label, markup),
                status.state.as_str()
            );
            if let (Some(left), Some(at)) = (remaining(outcome, now), status.expires_at) {
                let at = at.with_timezone(&Local).format("%Y-%m-%d %H:%M");
                line.push_str(&format!(", expires in {left} ({at})"));
            }
            if let Some(detail) = &status.detail {
                line.push_str(&format!(": {}", escape(detail, markup)));
            }
            line
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn json(outcomes: &[Outcome], now: DateTime<Utc>) -> String {
    #[derive(Serialize)]
    struct Report<'a> {
        state: &'static str,
        checks: Vec<Check<'a>>,
    }

    #[derive(Serialize)]
    struct Check<'a> {
        kind: &'static str,
        label: &'a str,
        target: &'a str,
        state: &'static str,
        detail: Option<&'a str>,
        expires_at: Option<String>,
        /// Seconds until expiry, negative once expired.
        expires_in: Option<i64>,
    }

    let report = Report {
        state: summary(outcomes),
        checks: outcomes
            .iter()
            .map(|Outcome { check, status }| Check {
                kind: check.kind.as_str(),
                label: &check.label,
                target: &check.target,
                state: status.state.as_str(),
                detail: status.detail.as_deref(),
                expires_at: status.expires_at.map(|at| at.to_rfc3339()),
                expires_in: status.expires_at.map(|at| (at - now).num_seconds()),
            })
            .collect(),
    };
    serde_json::to_string_pretty(&report).expect("report serialization cannot fail")
}

fn waybar(outcomes: &[Outcome], style: &Style, now: DateTime<Utc>) -> String {
    #[derive(Serialize)]
    struct Module {
        text: String,
        tooltip: String,
        alt: &'static str,
        class: &'static str,
        /// Share of unlocked checks.
        percentage: usize,
    }

    let unlocked = outcomes
        .iter()
        .filter(|o| o.status.state == State::Unlocked)
        .count();
    let module = Module {
        text: text(outcomes, style, now, true),
        tooltip: tooltip(outcomes, style, now, true),
        alt: summary(outcomes),
        class: summary(outcomes),
        percentage: (unlocked * 100).checked_div(outcomes.len()).unwrap_or(0),
    };
    serde_json::to_string(&module).expect("module serialization cannot fail")
}

/// Time left before an unlocked check expires, e.g. `3h05m`.
fn remaining(outcome: &Outcome, now: DateTime<Utc>) -> Option<String> {
    let at = outcome.status.expires_at?;
    (outcome.status.state == State::Unlocked).then(|| human_duration(at - now))
}

/// Replaces `{name}` placeholders using `lookup`; unknown placeholders are kept as is.
fn render_template(template: &str, lookup: impl Fn(&str) -> Option<String>) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find('{') {
        out.push_str(&rest[..start]);
        rest = &rest[start..];
        let replaced = rest
            .find('}')
            .and_then(|end| Some((end, lookup(&rest[1..end])?)));
        match replaced {
            Some((end, value)) => {
                out.push_str(&value);
                rest = &rest[end + 1..];
            }
            None => {
                out.push('{');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// Escapes Pango markup special characters when `markup` is set, as waybar
/// interprets its text and tooltip as markup.
fn escape(s: &str, markup: bool) -> Cow<'_, str> {
    if !markup || !s.contains(['&', '<', '>']) {
        return Cow::Borrowed(s);
    }
    Cow::Owned(
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::check::{Check, Kind, Status, parse_timestamp};
    use crate::spec::Spec;

    fn now() -> DateTime<Utc> {
        parse_timestamp("2026-10-21T12:00:00Z").unwrap()
    }

    fn outcome(kind: Kind, label: &str, status: Status) -> Outcome {
        let spec = Spec {
            value: label.into(),
            label: None,
            addr: None,
        };
        Outcome {
            check: Check::new(kind, spec),
            status,
        }
    }

    fn style(item_format: &str) -> Style {
        Style {
            item_format: item_format.into(),
            separator: " ".into(),
            icons: Icons {
                unlocked: "U".into(),
                locked: "L".into(),
                unknown: "?".into(),
            },
        }
    }

    fn sample() -> Vec<Outcome> {
        vec![
            outcome(
                Kind::Gpg,
                "work",
                Status::unlocked().with_detail("passphrase cached for sign"),
            ),
            outcome(
                Kind::Aws,
                "main",
                Status::unlocked().expiring_at(parse_timestamp("2026-10-21T15:05:00Z").unwrap()),
            ),
            outcome(
                Kind::Vault,
                "prod",
                Status::locked("token expired, revoked or invalid"),
            ),
        ]
    }

    #[test]
    fn templates() {
        let lookup = |name: &str| (name == "x").then(|| "X".to_string());
        assert_eq!(render_template("a{x}b", lookup), "aXb");
        assert_eq!(render_template("{y} {x}", lookup), "{y} X");
        assert_eq!(render_template("{x", lookup), "{x");
        assert_eq!(render_template("}{}{x}", lookup), "}{}X");
    }

    #[test]
    fn text_output() {
        assert_eq!(
            text(&sample(), &style("{icon} {kind}:{label}"), now(), false),
            "U gpg:work U aws:main L vault:prod"
        );
        assert_eq!(
            text(&sample(), &style("{label}={state}/{expires}"), now(), false),
            "work=unlocked/ main=unlocked/3h05m prod=locked/"
        );
    }

    #[test]
    fn summaries() {
        let unlocked = |label| outcome(Kind::Aws, label, Status::unlocked());
        let locked = |label| outcome(Kind::Aws, label, Status::locked("x"));
        let unknown = |label| outcome(Kind::Aws, label, Status::unknown("x"));
        assert_eq!(summary(&[unlocked("a"), unlocked("b")]), "unlocked");
        assert_eq!(summary(&[unlocked("a"), locked("b")]), "partial");
        assert_eq!(summary(&[unlocked("a"), unknown("b")]), "partial");
        assert_eq!(summary(&[locked("a"), unknown("b")]), "locked");
        assert_eq!(summary(&[unknown("a")]), "unknown");
    }

    #[test]
    fn json_output() {
        let report: serde_json::Value = serde_json::from_str(&json(&sample(), now())).unwrap();
        assert_eq!(report["state"], "partial");
        assert_eq!(report["checks"][1]["kind"], "aws");
        assert_eq!(report["checks"][1]["expires_in"], 3 * 3600 + 5 * 60);
        assert_eq!(
            report["checks"][2]["detail"],
            "token expired, revoked or invalid"
        );
    }

    #[test]
    fn waybar_output_escapes_markup() {
        let outcomes = vec![outcome(
            Kind::Gpg,
            "Jane <jane@example.com>",
            Status::locked("a & b"),
        )];
        let mut style = style("<b>{label}</b> {icon}");
        style.icons.locked = "<span color='red'>L</span>".into();
        let module: serde_json::Value =
            serde_json::from_str(&waybar(&outcomes, &style, now())).unwrap();
        assert_eq!(
            module["text"],
            "<b>Jane &lt;jane@example.com&gt;</b> <span color='red'>L</span>"
        );
        assert_eq!(
            module["tooltip"],
            "<span color='red'>L</span> gpg:Jane &lt;jane@example.com&gt; — locked: a &amp; b"
        );
        assert_eq!(module["class"], "locked");
        assert_eq!(module["alt"], "locked");
        assert_eq!(module["percentage"], 0);
    }
}
