//! Parsing of the `VALUE[,key=value...]` specifications given on the command line.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spec {
    pub value: String,
    pub label: Option<String>,
    pub addr: Option<String>,
}

/// Parses a spec accepting only the `label` option.
pub fn parse_basic(s: &str) -> Result<Spec, String> {
    parse(s, &["label"])
}

/// Parses a Vault token file spec, accepting the `label` and `addr` options.
pub fn parse_vault(s: &str) -> Result<Spec, String> {
    parse(s, &["label", "addr"])
}

fn parse(s: &str, allowed: &[&str]) -> Result<Spec, String> {
    let mut parts = s.split(',');
    let value = parts.next().unwrap_or_default().trim();
    if value.is_empty() {
        return Err("missing value before the options".into());
    }

    let mut spec = Spec {
        value: value.to_string(),
        label: None,
        addr: None,
    };
    for option in parts {
        let (key, val) = option
            .split_once('=')
            .ok_or_else(|| format!("invalid option `{option}`, expected key=value"))?;
        let val = Some(val.trim().to_string());
        match key.trim() {
            "label" if allowed.contains(&"label") => spec.label = val,
            "addr" if allowed.contains(&"addr") => spec.addr = val,
            other => {
                return Err(format!(
                    "unknown option `{other}` (supported: {})",
                    allowed.join(", ")
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
