//! Parsing of the `VALUE[,key=value...]` specifications given on the command line.

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Spec {
    pub value: String,
    pub label: Option<String>,
    pub addr: Option<String>,
    /// Checked and reported, but left out of the text and the overall state.
    pub optional: bool,
}

/// Parses a spec accepting the `label` and `optional` options.
pub fn parse_basic(s: &str) -> Result<Spec, String> {
    parse(s, false)
}

/// Parses a Vault token file spec, also accepting the `addr` option.
pub fn parse_vault(s: &str) -> Result<Spec, String> {
    parse(s, true)
}

fn parse(s: &str, with_addr: bool) -> Result<Spec, String> {
    let mut parts = s.split(',');
    let value = parts.next().unwrap_or_default().trim();
    if value.is_empty() {
        return Err("missing value before the options".into());
    }

    let mut spec = Spec {
        value: value.to_string(),
        ..Spec::default()
    };
    for option in parts {
        let (key, val) = match option.split_once('=') {
            Some((key, val)) => (key.trim(), Some(val.trim())),
            None => (option.trim(), None),
        };
        match (key, val) {
            ("label", Some(label)) => spec.label = Some(label.to_string()),
            ("addr", Some(addr)) if with_addr => spec.addr = Some(addr.to_string()),
            ("optional", None | Some("true")) => spec.optional = true,
            ("optional", Some("false")) => spec.optional = false,
            _ => {
                let supported = if with_addr {
                    "label=NAME, addr=URL, optional"
                } else {
                    "label=NAME, optional"
                };
                return Err(format!(
                    "invalid option `{option}` (supported: {supported})"
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
    }

    #[test]
    fn rejects_malformed_options() {
        assert!(parse_basic("main,label").is_err());
        assert!(parse_basic("main,colour=red").is_err());
        assert!(parse_basic(",label=x").is_err());
    }
}
