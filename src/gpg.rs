//! gpg-agent passphrase cache check.
//!
//! The key is resolved to its keygrips with `gpg --list-secret-keys`, then
//! gpg-agent is asked (`KEYINFO --list`) which keygrips have a cached passphrase.
//! The key counts as unlocked when any of its (sub)keys is cached.

use std::collections::HashMap;
use std::process::Command;
use std::time::Duration;

use crate::check::Status;
use crate::cmd;

/// A secret (sub)key as listed by `gpg --list-secret-keys --with-colons --with-keygrip`.
#[derive(Debug, PartialEq, Eq)]
struct SecretKey {
    capabilities: String,
    keygrip: Option<String>,
}

/// What gpg-agent reports about a keygrip.
#[derive(Debug, PartialEq, Eq)]
struct KeyInfo {
    on_card: bool,
    cached: bool,
}

pub fn check(key: &str, timeout: Duration) -> Status {
    let listing = cmd::run(
        Command::new("gpg").args([
            "--batch",
            "--with-colons",
            "--with-keygrip",
            "--list-secret-keys",
            "--",
            key,
        ]),
        timeout,
    );
    let keys = match listing {
        Ok(out) if out.status.success() => parse_secret_keys(&out.stdout),
        Ok(_) => return Status::unknown(format!("no secret key matching `{key}`")),
        Err(err) => return Status::unknown(cmd::describe_error("gpg", &err)),
    };

    let agent = cmd::run(
        Command::new("gpg-connect-agent").args(["--no-autostart", "KEYINFO --list", "/bye"]),
        timeout,
    );
    match agent {
        // gpg-connect-agent exits successfully even when it cannot reach the agent.
        Ok(out) if out.stdout.lines().any(|line| line == "OK") => {
            evaluate(&keys, &parse_keyinfo(&out.stdout))
        }
        Ok(out) if out.stderr.contains("no gpg-agent running") => {
            Status::locked("gpg-agent is not running")
        }
        Ok(out) => {
            Status::unknown(cmd::first_line(&out.stderr).unwrap_or("unexpected gpg-agent response"))
        }
        Err(err) => Status::unknown(cmd::describe_error("gpg-connect-agent", &err)),
    }
}

fn evaluate(keys: &[SecretKey], agent: &HashMap<String, KeyInfo>) -> Status {
    let known: Vec<(&SecretKey, &KeyInfo)> = keys
        .iter()
        .filter_map(|key| Some((key, agent.get(key.keygrip.as_deref()?)?)))
        .collect();
    if known.is_empty() {
        return Status::unknown("secret key material is not available in gpg-agent");
    }

    let mut cached_usages: Vec<&str> = Vec::new();
    for (key, _) in known.iter().filter(|(_, info)| info.cached) {
        for usage in usages(&key.capabilities) {
            if !cached_usages.contains(&usage) {
                cached_usages.push(usage);
            }
        }
    }

    if known.iter().any(|(_, info)| info.cached) {
        let detail = if cached_usages.is_empty() {
            "passphrase cached".to_string()
        } else {
            format!("passphrase cached for {}", cached_usages.join(", "))
        };
        Status::unlocked().with_detail(detail)
    } else if known.iter().all(|(_, info)| info.on_card) {
        Status::unknown(
            "key is on a smartcard; gpg-agent does not expose whether the PIN is cached",
        )
    } else {
        Status::locked("passphrase not cached")
    }
}

/// Maps a (sub)key's capability letters to readable usages. Uppercase letters on
/// a primary key describe the whole key and are ignored.
fn usages(capabilities: &str) -> impl Iterator<Item = &'static str> + '_ {
    capabilities.chars().filter_map(|c| match c {
        's' => Some("sign"),
        'e' => Some("encrypt"),
        'a' => Some("auth"),
        'c' => Some("certify"),
        _ => None,
    })
}

fn parse_secret_keys(colons: &str) -> Vec<SecretKey> {
    let mut keys: Vec<SecretKey> = Vec::new();
    for line in colons.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        match fields[0] {
            "sec" | "ssb" => keys.push(SecretKey {
                capabilities: fields.get(11).unwrap_or(&"").to_string(),
                keygrip: None,
            }),
            "grp" => {
                if let Some(key) = keys.last_mut()
                    && key.keygrip.is_none()
                {
                    key.keygrip = fields.get(9).map(|grip| grip.to_string());
                }
            }
            _ => {}
        }
    }
    keys
}

/// Parses `KEYINFO --list` lines:
/// `S KEYINFO <keygrip> <type> <serialno> <idstr> <cached> <protection> ...`
fn parse_keyinfo(output: &str) -> HashMap<String, KeyInfo> {
    output
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line
                .strip_prefix("S KEYINFO ")?
                .split_whitespace()
                .collect();
            let info = KeyInfo {
                on_card: fields.get(1) == Some(&"T"),
                cached: fields.get(4) == Some(&"1"),
            };
            Some((fields.first()?.to_string(), info))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const LISTING: &str = "\
sec:u:3072:1:A629E94B9C4B2A03:1600000000:::u:::scESC:::+:::23::0:
fpr:::::::::92576285CEEEA6CBB98943E1A629E94B9C4B2A03:
grp:::::::::C708315B8AE79952603667AAF0CEE7379105EE22:
uid:u::::1600000000::0000000000000000000000000000000000000000::Jane Doe <jane@example.com>::::::::::0:
ssb:u:3072:1:17E6AF888899185E:1600000000::::::e:::+:::23:
fpr:::::::::8A6ADEE93E6D9691CBE8EB6717E6AF888899185E:
grp:::::::::939ED2838A8FD10570C656CA88690BC27F99F3AF:
";

    const KEYINFO: &str = "\
S KEYINFO C708315B8AE79952603667AAF0CEE7379105EE22 D - - - P - - -
S KEYINFO 939ED2838A8FD10570C656CA88690BC27F99F3AF D - - 1 P - - -
S KEYINFO 0892D7E61A1816A39A54BB830AF6735CA506DE3E T D2760001240102010006041303640000 OPENPGP.1 - - - - -
OK
";

    fn info(on_card: bool, cached: bool) -> KeyInfo {
        KeyInfo { on_card, cached }
    }

    #[test]
    fn parses_listing() {
        let keys = parse_secret_keys(LISTING);
        assert_eq!(
            keys,
            vec![
                SecretKey {
                    capabilities: "scESC".into(),
                    keygrip: Some("C708315B8AE79952603667AAF0CEE7379105EE22".into()),
                },
                SecretKey {
                    capabilities: "e".into(),
                    keygrip: Some("939ED2838A8FD10570C656CA88690BC27F99F3AF".into()),
                },
            ]
        );
    }

    #[test]
    fn parses_keyinfo() {
        let agent = parse_keyinfo(KEYINFO);
        assert_eq!(agent.len(), 3);
        assert_eq!(
            agent["C708315B8AE79952603667AAF0CEE7379105EE22"],
            info(false, false)
        );
        assert_eq!(
            agent["939ED2838A8FD10570C656CA88690BC27F99F3AF"],
            info(false, true)
        );
        assert_eq!(
            agent["0892D7E61A1816A39A54BB830AF6735CA506DE3E"],
            info(true, false)
        );
    }

    #[test]
    fn unlocked_when_a_subkey_is_cached() {
        let status = evaluate(&parse_secret_keys(LISTING), &parse_keyinfo(KEYINFO));
        assert_eq!(
            status,
            Status::unlocked().with_detail("passphrase cached for encrypt")
        );
    }

    #[test]
    fn locked_when_nothing_is_cached() {
        let agent = HashMap::from([
            (
                "C708315B8AE79952603667AAF0CEE7379105EE22".to_string(),
                info(false, false),
            ),
            (
                "939ED2838A8FD10570C656CA88690BC27F99F3AF".to_string(),
                info(false, false),
            ),
        ]);
        assert_eq!(
            evaluate(&parse_secret_keys(LISTING), &agent),
            Status::locked("passphrase not cached")
        );
    }

    #[test]
    fn unknown_for_smartcard_keys() {
        let agent = HashMap::from([
            (
                "C708315B8AE79952603667AAF0CEE7379105EE22".to_string(),
                info(true, false),
            ),
            (
                "939ED2838A8FD10570C656CA88690BC27F99F3AF".to_string(),
                info(true, false),
            ),
        ]);
        let status = evaluate(&parse_secret_keys(LISTING), &agent);
        assert_eq!(status.state, crate::check::State::Unknown);
    }

    #[test]
    fn unknown_without_key_material() {
        let status = evaluate(&parse_secret_keys(LISTING), &HashMap::new());
        assert_eq!(status.state, crate::check::State::Unknown);
    }
}
