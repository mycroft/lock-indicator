# lock-indicator

> A status bar widget that tells you whether your gpg keys, AWS SSO sessions, gcloud credentials and Vault tokens are currently unlocked.

Credentials that expire or need a passphrase tend to fail in the middle of
something else: a commit that won't sign, a `terraform plan` that can't reach
AWS. `lock-indicator` checks them all at once and prints one line, as plain
text, JSON or a [waybar](https://github.com/Alexays/Waybar) custom module. It
runs once and exits; the status bar decides how often to call it.

## Features

- **gpg-agent keys**: whether the passphrase of a key or one of its subkeys is cached, and for which usages (sign, encrypt, auth).
- **AWS SSO profiles**: whether the token cached by `aws sso login` is still valid, and how long it has left. Follows `source_profile` chains and supports both `sso_session` and legacy `sso_start_url` profiles.
- **gcloud accounts**: whether `gcloud auth login` credentials still work or need a new login.
- **Vault tokens**: whether the token in a file is still valid, and how long it has left. Each file can point to its own Vault server.
- **Multiple targets**: every check can be repeated, and all checks run in parallel.
- **Output formats**: a one-line text with configurable templates, a detailed JSON report, or waybar JSON with a tooltip and CSS classes.
- **Configuration file**: checks, output format, templates and icons can be set in a TOML file, and command-line options override it.

## Getting Started

### Prerequisites

- Rust ≥ 1.88 to build.
- At run time, only the tools for the checks you use:

| Check | Needs |
|-------|-------|
| `--gpg` | GnuPG ≥ 2.1 (`gpg` and `gpg-connect-agent` in `PATH`) |
| `--aws` | An `~/.aws/config` with SSO profiles. The `aws` CLI itself is not needed: the check only reads files. |
| `--gcloud` | The `gcloud` CLI in `PATH` |
| `--vault` | The `vault` CLI in `PATH`, and the address of the Vault server |

### Installation

```sh
cd lock-indicator
cargo install --path .
```

This installs the `lock-indicator` binary in `~/.cargo/bin`.

## Usage

Pass one or more checks, on the command line or in the
[configuration file](#configuration-file). On the command line, each check
takes a value and optional comma-separated options:

| Option | Value | Options |
|--------|-------|---------|
| `--gpg` | key id, fingerprint or user id | `label=NAME` |
| `--aws` | profile name | `label=NAME` |
| `--gcloud` | account (e-mail) | `label=NAME` |
| `--vault` | token file | `label=NAME`, `addr=URL` (defaults to `$VAULT_ADDR`) |

The label is what appears in the output. It defaults to the value itself; for
Vault it defaults to the server's host, or the file name when no `addr` is set.

```sh
lock-indicator \
  --gpg 0xA629E94B9C4B2A03,label=work \
  --aws main --aws sbx,label=sandbox \
  --gcloud me@example.com,label=gcp \
  --vault ~/.vault-token,addr=https://vault.example.com:8200,label=vault
```

```
🔓 gpg:work 🔓 aws:main 🔒 aws:sandbox 🔒 gcloud:gcp 🔓 vault:vault
```

### States

Each check ends up in one of three states:

| Check | `unlocked` when | How it is checked | Network |
|-------|-----------------|-------------------|---------|
| gpg | gpg-agent has the passphrase of the key or one of its subkeys cached | `gpg --list-secret-keys --with-keygrip`, then `gpg-connect-agent 'KEYINFO --list'` | no |
| aws | the cached SSO token has not expired | reads `~/.aws/sso/cache/<sha1>.json` | no |
| gcloud | gcloud can get an access token without prompting | `gcloud auth print-access-token --account=…` | yes |
| vault | the token is valid and has not expired | `vault token lookup` with the token from the file | yes |

`unknown` means the state could not be determined. Common causes:

- A required tool is missing, a command timed out, or the server could not be reached.
- The gpg key is on a smartcard. gpg-agent does not report whether the card's PIN has been entered.
- For an AWS profile using `sso_session`, the access token has expired but a refresh token is cached. The next `aws` call may renew it silently; that can't be known without calling AWS.

The checks never print or store any token. The gcloud check refreshes the
access token if needed, as any `gcloud` command would.

### Output formats

Choose the format with `-f`/`--format`.

**`text`** (default): one line, built from two templates. Each check is
rendered with `--item-format` (default `{icon} {kind}:{label}`):

| Placeholder | Value |
|-------------|-------|
| `{icon}` | `--icon-unlocked`, `--icon-locked` or `--icon-unknown` (defaults: 🔓 🔒 ❓) |
| `{kind}` | `gpg`, `aws`, `gcloud` or `vault` |
| `{label}` | the check's label |
| `{state}` | `unlocked`, `locked` or `unknown` |
| `{expires}` | time left before expiry, e.g. `3h05m` (unlocked AWS and Vault checks only) |

The checks are joined with `--separator` (default: a space) and inserted into
`--text-format` (default `{items}`):

| Placeholder | Value |
|-------------|-------|
| `{items}` | the rendered checks |
| `{icon}` | overall icon: the unlocked, locked or unknown icon, or `--icon-partial` (default 🔐) when only some checks are unlocked |
| `{state}` | overall state: `unlocked`, `partial`, `locked` or `unknown` |
| `{unlocked}`, `{locked}`, `{unknown}` | number of checks in that state |
| `{total}` | number of checks |

Unknown placeholders are left as they are.

```sh
lock-indicator --aws main --vault ~/.vault-token --item-format '{icon} {label} {expires}' --separator ' | '
lock-indicator --aws main --aws sbx --gpg 0xA629E94B9C4B2A03 --text-format '{icon} {unlocked}/{total}'
```

```
🔓 main 2h59m | 🔒 .vault-token
🔐 2/3
```

**`json`**: an overall state, plus the details of every check:

```json
{
  "state": "partial",
  "checks": [
    {
      "kind": "aws",
      "label": "main",
      "target": "main",
      "state": "unlocked",
      "detail": null,
      "expires_at": "2026-10-21T18:05:09+00:00",
      "expires_in": 11100
    }
  ]
}
```

`expires_in` is in seconds and goes negative once the token has expired.

**`waybar`**: a [custom module](https://github.com/Alexays/Waybar/wiki/Module:-Custom)
object. `text` is the one-line output, `tooltip` has one line per check with
expiry and details, and `alt` and `class` hold the overall state: `unlocked`,
`partial`, `locked` or `unknown`. `percentage` is the share of unlocked checks.
Labels and details are escaped for Pango markup, while `--item-format` and the
icons are not, so they can contain markup such as `<span color='red'>`.

### Configuration file

Everything above can also be set in a TOML file, by default
`$XDG_CONFIG_HOME/lock-indicator/config.toml` (`~/.config/lock-indicator/config.toml`).
Use `-c`/`--config FILE` to read another file instead. All settings are optional:

```toml
format = "waybar"        # text, json or waybar
timeout = 10             # seconds, for each external command
text_format = "{items}"
item_format = "{icon} {kind}:{label}"
separator = " "

[icons]
unlocked = "🔓"
locked = "🔒"
unknown = "❓"
partial = "🔐"

[[gpg]]
key = "0xA629E94B9C4B2A03"
label = "work"           # optional, like for every check

[[aws]]
profile = "main"

[[aws]]
profile = "sbx"
label = "sandbox"

[[gcloud]]
account = "me@example.com"

[[vault]]
token_file = "~/.vault-token"
addr = "https://vault.example.com:8200"   # optional, defaults to $VAULT_ADDR
```

How the file and the command line combine:

- An option given on the command line overrides the same setting in the file, which overrides the built-in default.
- Checks given on the command line replace all the checks from the file. Use this to run a single check with your usual output settings.
- A missing default file is ignored. A missing `--config` file, an unknown key or an invalid value is an error.

### Waybar

With the checks in the configuration file, the module only needs the output
format:

```jsonc
"custom/locks": {
    "exec": "lock-indicator --format waybar",
    "return-type": "json",
    "interval": 60,
    "tooltip": true
}
```

To show a single icon for the overall state and keep the details in the
tooltip, use `alt` with `format-icons`:

```jsonc
"custom/locks": {
    "exec": "lock-indicator --format waybar --aws main --gcloud me@example.com",
    "return-type": "json",
    "interval": 60,
    "format": "{icon}",
    "format-icons": { "unlocked": "🔓", "partial": "🔐", "locked": "🔒", "unknown": "❓" }
}
```

Style the module from `class`:

```css
#custom-locks.locked  { color: #e06c75; }
#custom-locks.partial { color: #e5c07b; }
#custom-locks.unknown { color: #888888; }
```

### Exit status

`0` whenever the checks ran, whatever their states. `2` on invalid arguments
or configuration, or when there is nothing to check.

## Build & Run

### Development

```sh
cargo run -- --aws main --format json
```

### Production Build

```sh
cargo build --release
./target/release/lock-indicator --help
```

### Tests

```sh
cargo test
```

The tests use fixtures and don't need any credentials.

## Configuration

Besides the command-line options and the
[configuration file](#configuration-file), `lock-indicator` reads these
environment variables, directly or through the tools it runs:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `HOME` | Yes | | Location of `~/.aws/config`, `~/.aws/sso/cache` and `~`-prefixed Vault token paths |
| `XDG_CONFIG_HOME` | No | `~/.config` | Directory containing `lock-indicator/config.toml` |
| `AWS_CONFIG_FILE` | No | `~/.aws/config` | AWS config file used to resolve profiles |
| `VAULT_ADDR` | For `--vault` without `addr=` | | Vault server address |
| `VAULT_CACERT`, `VAULT_NAMESPACE`, … | No | | Passed through to `vault token lookup` |
| `GNUPGHOME` | No | `~/.gnupg` | GnuPG home used by `gpg` and `gpg-connect-agent` |
| `CLOUDSDK_CONFIG` | No | `~/.config/gcloud` | gcloud configuration directory |

## References

- [Waybar custom module](https://github.com/Alexays/Waybar/wiki/Module:-Custom): the JSON format expected with `"return-type": "json"`
- [GnuPG manual](https://www.gnupg.org/documentation/manuals/gnupg/): gpg-agent and `gpg-connect-agent`
- [GnuPG DETAILS](https://github.com/gpg/gnupg/blob/master/doc/DETAILS): the `--with-colons` listing format
- [Configuring IAM Identity Center authentication with the AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html): SSO profiles and `aws sso login`
- [gcloud auth print-access-token](https://cloud.google.com/sdk/gcloud/reference/auth/print-access-token)
- [vault token lookup](https://developer.hashicorp.com/vault/docs/commands/token/lookup)
