//! Rendering of check outcomes as text, JSON or waybar custom module JSON.

use std::borrow::Cow;

use chrono::{DateTime, Local, Utc};
use serde::Serialize;

use crate::check::{Kind, Outcome, State, human_duration};

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    /// One line rendered with --text-format and --item-format
    Text,
    /// Detailed report of every check
    Json,
    /// Waybar custom module JSON (`"return-type": "json"`)
    Waybar,
}

pub struct Style {
    /// Template of the whole text, where `{items}` are the rendered checks and
    /// `{kinds}` the rendered kinds.
    pub text_format: String,
    /// Template replacing `text_format` when every counted check is unlocked.
    pub text_format_all_unlocked: Option<String>,
    /// Template of each check in `{items}`.
    pub item_format: String,
    /// Template of each kind of check in `{kinds}`.
    pub kind_format: String,
    pub separator: String,
    pub icons: ByState,
    pub colors: ByState,
}

impl Default for Style {
    fn default() -> Self {
        Style {
            text_format: "{items}".into(),
            text_format_all_unlocked: None,
            item_format: "{icon} {kind}:{label}".into(),
            kind_format: "{icon} {kind}".into(),
            separator: " ".into(),
            icons: ByState {
                unlocked: "🔓".into(),
                locked: "🔒".into(),
                unknown: "❓".into(),
                partial: "🔐".into(),
            },
            colors: ByState {
                unlocked: "#98c379".into(),
                locked: "#e06c75".into(),
                unknown: "#888888".into(),
                partial: "#d19a66".into(),
            },
        }
    }
}

/// A value, such as an icon or a color, for each state.
pub struct ByState {
    pub unlocked: String,
    pub locked: String,
    pub unknown: String,
    /// Value for a group of checks of which only some are unlocked.
    pub partial: String,
}

impl ByState {
    fn get(&self, state: State) -> &str {
        match state {
            State::Unlocked => &self.unlocked,
            State::Locked => &self.locked,
            State::Unknown => &self.unknown,
        }
    }

    fn overall(&self, summary: Summary) -> &str {
        match summary {
            Summary::Unlocked => &self.unlocked,
            Summary::Partial => &self.partial,
            Summary::Locked => &self.locked,
            Summary::Unknown => &self.unknown,
        }
    }
}

/// Overall state of a group of checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Summary {
    Unlocked,
    Partial,
    Locked,
    Unknown,
}

impl Summary {
    fn as_str(self) -> &'static str {
        match self {
            Summary::Unlocked => "unlocked",
            Summary::Partial => "partial",
            Summary::Locked => "locked",
            Summary::Unknown => "unknown",
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

/// Number of checks in each state, for all checks or the checks of one kind.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Counts {
    unlocked: usize,
    locked: usize,
    unknown: usize,
}

impl Counts {
    fn of<'a>(outcomes: impl IntoIterator<Item = &'a Outcome>) -> Self {
        let mut counts = Counts::default();
        for outcome in outcomes {
            match outcome.status.state {
                State::Unlocked => counts.unlocked += 1,
                State::Locked => counts.locked += 1,
                State::Unknown => counts.unknown += 1,
            }
        }
        counts
    }

    fn total(self) -> usize {
        self.unlocked + self.locked + self.unknown
    }

    fn summary(self) -> Summary {
        if self.total() == 0 {
            // A kind without any check, referenced as `{vault.color}` for instance.
            Summary::Unknown
        } else if self.unlocked == self.total() {
            Summary::Unlocked
        } else if self.unlocked > 0 {
            Summary::Partial
        } else if self.locked > 0 {
            Summary::Locked
        } else {
            Summary::Unknown
        }
    }

    /// Placeholders shared by --text-format and --kind-format.
    fn placeholder(self, name: &str, style: &Style) -> Option<String> {
        let summary = self.summary();
        Some(match name {
            "icon" => style.icons.overall(summary).to_string(),
            "color" => style.colors.overall(summary).to_string(),
            "state" => summary.as_str().to_string(),
            "unlocked" => self.unlocked.to_string(),
            "locked" => self.locked.to_string(),
            "unknown" => self.unknown.to_string(),
            "total" => self.total().to_string(),
            _ => return None,
        })
    }
}

/// The checks that make up the text and the overall state: all but the optional ones.
fn counted(outcomes: &[Outcome]) -> impl Iterator<Item = &Outcome> + Clone {
    outcomes.iter().filter(|o| !o.check.optional)
}

fn text(outcomes: &[Outcome], style: &Style, now: DateTime<Utc>, markup: bool) -> String {
    let items = counted(outcomes)
        .map(|outcome| item(outcome, style, now, markup))
        .collect::<Vec<_>>()
        .join(&style.separator);
    let of_kind = |kind| Counts::of(counted(outcomes).filter(move |o| o.check.kind == kind));
    let kinds = Kind::ALL
        .into_iter()
        .filter_map(|kind| {
            let counts = of_kind(kind);
            let rendered = render_template(&style.kind_format, |name| match name {
                "kind" => Some(kind.as_str().to_string()),
                _ => counts.placeholder(name, style),
            });
            (counts.total() > 0).then_some(rendered)
        })
        .collect::<Vec<_>>()
        .join(&style.separator);
    let counts = Counts::of(counted(outcomes));
    let template = match (&style.text_format_all_unlocked, counts.summary()) {
        (Some(template), Summary::Unlocked) => template,
        _ => &style.text_format,
    };
    render_template(template, |name| match name {
        "items" => Some(items.clone()),
        "kinds" => Some(kinds.clone()),
        // `{aws.color}`, `{gpg.state}`...: a placeholder for the checks of one kind.
        _ => match name.split_once('.') {
            Some((kind, name)) => {
                let kind = Kind::ALL.into_iter().find(|k| k.as_str() == kind)?;
                of_kind(kind).placeholder(name, style)
            }
            None => counts.placeholder(name, style),
        },
    })
}

fn item(outcome: &Outcome, style: &Style, now: DateTime<Utc>, markup: bool) -> String {
    let status = &outcome.status;
    render_template(&style.item_format, |name| {
        let value: Cow<str> = match name {
            "icon" => return Some(style.icons.get(status.state).to_string()),
            "color" => return Some(style.colors.get(status.state).to_string()),
            "kind" => outcome.check.kind.as_str().into(),
            "label" => outcome.check.label.as_str().into(),
            "state" => status.state.as_str().into(),
            "expires" => remaining(outcome, now).unwrap_or_default().into(),
            _ => return None,
        };
        Some(escape(&value, markup).into_owned())
    })
}

fn tooltip(outcomes: &[Outcome], style: &Style, now: DateTime<Utc>, markup: bool) -> String {
    outcomes
        .iter()
        .map(|outcome| {
            let (check, status) = (&outcome.check, &outcome.status);
            let mut line = format!(
                "{} {}:{} — {}{}",
                style.icons.get(status.state),
                check.kind.as_str(),
                escape(&check.label, markup),
                status.state.as_str(),
                if check.optional { " (optional)" } else { "" }
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
        /// Left out of the overall state.
        optional: bool,
        detail: Option<&'a str>,
        expires_at: Option<String>,
        /// Seconds until expiry, negative once expired.
        expires_in: Option<i64>,
    }

    let report = Report {
        state: Counts::of(counted(outcomes)).summary().as_str(),
        checks: outcomes
            .iter()
            .map(|Outcome { check, status }| Check {
                kind: check.kind.as_str(),
                label: &check.label,
                target: &check.target,
                state: status.state.as_str(),
                optional: check.optional,
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

    let counts = Counts::of(counted(outcomes));
    let summary = counts.summary().as_str();
    let module = Module {
        text: text(outcomes, style, now, true),
        tooltip: tooltip(outcomes, style, now, true),
        alt: summary,
        class: summary,
        percentage: (counts.unlocked * 100)
            .checked_div(counts.total())
            .unwrap_or(0),
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
    use crate::check::{Check, Status, parse_timestamp};
    use crate::spec::Spec;

    fn now() -> DateTime<Utc> {
        parse_timestamp("2026-10-21T12:00:00Z").unwrap()
    }

    fn outcome(kind: Kind, label: &str, status: Status) -> Outcome {
        let spec = Spec {
            value: label.into(),
            ..Spec::default()
        };
        Outcome {
            check: Check::new(kind, spec),
            status,
        }
    }

    fn style(item_format: &str) -> Style {
        Style {
            text_format: "{items}".into(),
            text_format_all_unlocked: None,
            item_format: item_format.into(),
            kind_format: "{icon} {kind}".into(),
            separator: " ".into(),
            icons: ByState {
                unlocked: "U".into(),
                locked: "L".into(),
                unknown: "?".into(),
                partial: "P".into(),
            },
            colors: ByState {
                unlocked: "green".into(),
                locked: "red".into(),
                unknown: "grey".into(),
                partial: "orange".into(),
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
        let summary = |outcomes: &[Outcome]| Counts::of(outcomes).summary();
        assert_eq!(summary(&[unlocked("a"), unlocked("b")]), Summary::Unlocked);
        assert_eq!(summary(&[unlocked("a"), locked("b")]), Summary::Partial);
        assert_eq!(summary(&[unlocked("a"), unknown("b")]), Summary::Partial);
        assert_eq!(summary(&[locked("a"), unknown("b")]), Summary::Locked);
        assert_eq!(summary(&[unknown("a")]), Summary::Unknown);
    }

    #[test]
    fn text_format() {
        let mut style = style("{label}");
        style.text_format =
            "{icon} {unlocked}/{total} [{items}] {state} {locked} {unknown} {nope}".into();
        assert_eq!(
            text(&sample(), &style, now(), false),
            "P 2/3 [work main prod] partial 1 0 {nope}"
        );
    }

    #[test]
    fn text_format_all_unlocked() {
        let mut style = style("{label}");
        style.text_format = "{unlocked}/{total}: {items}".into();
        style.text_format_all_unlocked = Some("locks: {icon} {total}".into());
        let unlocked = |label| outcome(Kind::Aws, label, Status::unlocked());
        let mut outcomes = vec![unlocked("main"), unlocked("sbx")];
        assert_eq!(text(&outcomes, &style, now(), false), "locks: U 2");

        outcomes.push(outcome(Kind::Gcloud, "perso", Status::locked("expired")));
        assert_eq!(text(&outcomes, &style, now(), false), "2/3: main sbx perso");

        // Optional checks don't prevent it.
        outcomes[2].check.optional = true;
        assert_eq!(text(&outcomes, &style, now(), false), "locks: U 2");
    }

    #[test]
    fn colors() {
        let mut style = style("<span color='{color}'>{label}</span>");
        style.text_format = "{color}: {items}".into();
        assert_eq!(
            text(&sample(), &style, now(), true),
            "orange: <span color='green'>work</span> <span color='green'>main</span> \
             <span color='red'>prod</span>"
        );
    }

    #[test]
    fn placeholders_of_one_kind() {
        let mut outcomes = sample();
        outcomes.push(outcome(Kind::Aws, "sbx", Status::locked("expired")));
        let mut style = style("{label}");
        style.text_format =
            "aws:{aws.color} gpg:{gpg.color} gcp:{gcloud.color} vault:{vault.color} \
                             {aws.icon} {aws.state} {aws.unlocked}/{aws.total} {gcloud.state} \
                             {nope.color} {aws.nope}"
                .into();
        assert_eq!(
            text(&outcomes, &style, now(), false),
            "aws:orange gpg:green gcp:grey vault:red P partial 1/2 unknown {nope.color} {aws.nope}"
        );
    }

    #[test]
    fn optional_checks_are_only_reported() {
        let mut outcomes = vec![
            outcome(Kind::Gcloud, "work", Status::unlocked()),
            outcome(Kind::Gcloud, "perso", Status::locked("no credentials")),
            outcome(Kind::Aws, "main", Status::locked("expired")),
        ];
        outcomes[1].check.optional = true;
        let mut style = style("{icon} {label}");
        style.text_format = "{items} | {kinds} | {gcloud.state} {unlocked}/{total} {state}".into();
        assert_eq!(
            text(&outcomes, &style, now(), false),
            "U work L main | L aws U gcloud | unlocked 1/2 partial"
        );

        let module: serde_json::Value =
            serde_json::from_str(&waybar(&outcomes, &style, now())).unwrap();
        assert_eq!(module["class"], "partial");
        assert_eq!(module["percentage"], 50);
        assert_eq!(
            module["tooltip"],
            "U gcloud:work — unlocked\n\
             L gcloud:perso — locked (optional): no credentials\n\
             L aws:main — locked: expired"
        );

        let report: serde_json::Value = serde_json::from_str(&json(&outcomes, now())).unwrap();
        assert_eq!(report["state"], "partial");
        assert_eq!(report["checks"][1]["optional"], true);
        assert_eq!(report["checks"][1]["state"], "locked");
    }

    #[test]
    fn kinds() {
        let mut outcomes = sample();
        outcomes.push(outcome(Kind::Aws, "sbx", Status::locked("expired")));
        outcomes.push(outcome(Kind::Gcloud, "gcp", Status::unknown("offline")));
        let mut style = style("{label}");
        style.kind_format = "{kind}:<span color='{color}'>{icon}</span>".into();
        style.text_format = "{kinds}".into();
        assert_eq!(
            text(&outcomes, &style, now(), true),
            "gpg:<span color='green'>U</span> aws:<span color='orange'>P</span> \
             gcloud:<span color='grey'>?</span> vault:<span color='red'>L</span>"
        );
        style.kind_format = "{kind} {unlocked}/{total} {state}".into();
        style.separator = ", ".into();
        assert_eq!(
            text(&outcomes, &style, now(), false),
            "gpg 1/1 unlocked, aws 1/2 partial, gcloud 0/1 unknown, vault 0/1 locked"
        );
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
