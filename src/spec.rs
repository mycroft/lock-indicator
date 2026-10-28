//! Parsing of the `VALUE[,key=value...]` specifications given on the command line.

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Spec {
    pub value: String,
    pub label: Option<String>,
    /// Vault server address.
    pub addr: Option<String>,
    /// Docker auth file.
    pub auth_file: Option<String>,
    /// Docker: verify credentials without an expiry date with the registry.
    pub remote: bool,
    /// Checked and reported, but left out of the text and the overall state.
    pub optional: bool,
}

/// Parses a spec accepting the `label` and `optional` options.
pub fn parse_basic(s: &str) -> Result<Spec, String> {
    parse(s, &[])
}

/// Parses a Vault token file spec, also accepting the `addr` option.
pub fn parse_vault(s: &str) -> Result<Spec, String> {
    parse(s, &["addr=URL"])
}

/// Parses a Docker registry spec, also accepting the `auth_file` and `remote`
/// options.
pub fn parse_docker(s: &str) -> Result<Spec, String> {
    parse(s, &["auth_file=PATH", "remote"])
}

/// `extra` lists the options accepted besides `label` and `optional`, as shown
/// in the error message.
fn parse(s: &str, extra: &[&str]) -> Result<Spec, String> {
    let mut parts = s.split(',');
    let value = parts.next().unwrap_or_default().trim();
    if value.is_empty() {
        return Err("missing value before the options".into());
    }

    let accepts = |key: &str| {
        extra
            .iter()
            .any(|option| option.split('=').next() == Some(key))
    };
    let mut spec = Spec {
        value: value.to_string(),
        ..Spec::default()
    };
    for option in parts {
        let (key, val) = match option.split_once('=') {
            Some((key, val)) => (key.trim(), Some(val.trim())),
            None => (option.trim(), None),
        };
        let flag = match val {
            None | Some("true") => Some(true),
            Some("false") => Some(false),
            Some(_) => None,
        };
        match (key, val, flag) {
            ("label", Some(label), _) => spec.label = Some(label.to_string()),
            ("addr", Some(addr), _) if accepts(key) => spec.addr = Some(addr.to_string()),
            ("auth_file", Some(path), _) if accepts(key) => {
                spec.auth_file = Some(path.to_string());
            }
            ("remote", _, Some(remote)) if accepts(key) => spec.remote = remote,
            ("optional", _, Some(optional)) => spec.optional = optional,
            _ => {
                let supported: Vec<&str> = ["label=NAME"]
                    .into_iter()
                    .chain(extra.iter().copied())
                    .chain(["optional"])
                    .collect();
                return Err(format!(
                    "invalid option `{option}` (supported: {})",
                    supported.join(", ")
                ));
            }
        }
    }
    Ok(spec)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_only() {
        let spec = parse_basic("main").unwrap();
        assert_eq!(spec.value, "main");
        assert_eq!(spec.label, None);
        assert_eq!(spec.addr, None);
    }

    #[test]
    fn with_label() {
        let spec = parse_basic("0xA629E94B9C4B2A03,label=work").unwrap();
        assert_eq!(spec.value, "0xA629E94B9C4B2A03");
        assert_eq!(spec.label.as_deref(), Some("work"));
    }

    #[test]
    fn vault_with_addr_and_label() {
        let spec =
            parse_vault("~/.vault-token,addr=https://vault.example.com:8200,label=prod").unwrap();
        assert_eq!(spec.value, "~/.vault-token");
        assert_eq!(spec.addr.as_deref(), Some("https://vault.example.com:8200"));
        assert_eq!(spec.label.as_deref(), Some("prod"));
    }

    #[test]
    fn optional() {
        assert!(parse_basic("perso@example.com,optional").unwrap().optional);
        assert!(
            parse_basic("perso@example.com,label=perso,optional=true")
                .unwrap()
                .optional
        );
        assert!(
            !parse_basic("perso@example.com,optional=false")
                .unwrap()
                .optional
        );
        assert!(!parse_basic("perso@example.com").unwrap().optional);
        assert!(
            parse_vault("/tmp/token,optional,addr=http://x")
                .unwrap()
                .optional
        );
        assert!(parse_basic("perso@example.com,optional=maybe").is_err());
    }

    #[test]
    fn addr_is_vault_only() {
        assert!(parse_basic("main,addr=http://x").is_err());
        assert!(parse_docker("ghcr.io,addr=http://x").is_err());
    }

    #[test]
    fn docker_options() {
        let spec = parse_docker("ghcr.io,auth_file=~/.docker/work.json,remote,label=gh").unwrap();
        assert_eq!(spec.value, "ghcr.io");
        assert_eq!(spec.auth_file.as_deref(), Some("~/.docker/work.json"));
        assert!(spec.remote);
        assert_eq!(spec.label.as_deref(), Some("gh"));
        assert!(!parse_docker("ghcr.io,remote=false").unwrap().remote);
        assert!(!parse_docker("ghcr.io").unwrap().remote);
        assert!(parse_docker("ghcr.io,remote=yes").is_err());
        assert!(parse_basic("main,remote").is_err());
        assert!(parse_vault("/tmp/token,auth_file=/tmp/x").is_err());
    }

    #[test]
    fn lists_supported_options() {
        let err = parse_docker("ghcr.io,addr=x").unwrap_err();
        assert_eq!(
            err,
            "invalid option `addr=x` (supported: label=NAME, auth_file=PATH, remote, optional)"
        );
        let err = parse_basic("main,colour=red").unwrap_err();
        assert_eq!(
            err,
            "invalid option `colour=red` (supported: label=NAME, optional)"
        );
    }

    #[test]
    fn rejects_malformed_options() {
        assert!(parse_basic("main,label").is_err());
        assert!(parse_basic("main,colour=red").is_err());
        assert!(parse_basic(",label=x").is_err());
    }
}
