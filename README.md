# lock-indicator

> A status bar widget that tells you whether your gpg keys, AWS SSO sessions, gcloud credentials, Vault tokens and Docker registry logins are currently unlocked.

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
- **Docker registries**: whether you are logged in to a registry and, for tokens that carry an expiry date such as Amazon ECR's, how long they have left. Reads the Docker auth file and credential helpers offline; verifying other credentials with the registry is opt-in.
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
| `--docker` | A Docker auth file. The `docker` CLI itself is not needed, but a configured credential helper (`docker-credential-…`) must be in `PATH`. |

When a tool is not in `PATH`, which can happen when waybar starts with a
minimal environment, set its location in the [`[programs]`](#configuration-file)
table of the configuration file.

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
| `--gpg` | key id, fingerprint or user id | `label=NAME`, `optional` |
| `--aws` | profile name | `label=NAME`, `optional` |
| `--gcloud` | account (e-mail) | `label=NAME`, `optional` |
| `--vault` | token file | `label=NAME`, `addr=URL` (defaults to `$VAULT_ADDR`), `optional` |
| `--docker` | registry, e.g. `ghcr.io` or `docker.io` | `label=NAME`, `auth_file=PATH` (defaults to `$DOCKER_CONFIG/config.json`, else `~/.docker/config.json`), `remote`, `optional` |

The label is what appears in the output. It defaults to the value itself; for
Vault it defaults to the server's host, or the file name when no `addr` is set,
and for Docker to the registry's host.

An `optional` check is still run and reported in the waybar tooltip and the JSON
report, but it is left out of the text and of the overall state: `{items}`,
`{kinds}`, the per-kind placeholders, the counts, and waybar's `alt`, `class` and
`percentage`. Use it for credentials you don't always keep unlocked, such as a
personal gcloud account next to a work one: the bar stays green while the
tooltip still shows it.

```sh
lock-indicator \
  --gpg 0xA629E94B9C4B2A03,label=work \
  --aws main --aws sbx,label=sandbox \
  --gcloud me@example.com,label=gcp \
  --vault ~/.vault-token,addr=https://vault.example.com:8200,label=vault \
  --docker 123456789012.dkr.ecr.eu-west-3.amazonaws.com,label=ecr
```

```
🔓 gpg:work 🔓 aws:main 🔒 aws:sandbox 🔒 gcloud:gcp 🔓 vault:vault 🔒 docker:ecr
```

### States

Each check ends up in one of three states:

| Check | `unlocked` when | How it is checked | Network |
|-------|-----------------|-------------------|---------|
| gpg | gpg-agent has the passphrase of the key or one of its subkeys cached | `gpg --list-secret-keys --with-keygrip`, then `gpg-connect-agent 'KEYINFO --list'` | no |
| aws | the cached SSO token has not expired | reads `~/.aws/sso/cache/<sha1>.json` | no |
| gcloud | gcloud can get an access token without prompting | `gcloud auth print-access-token --account=…` | yes |
| vault | the token is valid and has not expired | `vault token lookup` with the token from the file | yes |
| docker | credentials are stored for the registry and, when they carry an expiry date, have not expired | reads the auth file, or runs the credential helper configured for the registry | only with `remote`, or through a credential helper |

`unknown` means the state could not be determined. Common causes:

- A required tool is missing, a command timed out, or the server could not be reached.
- The gpg key is on a smartcard. gpg-agent does not report whether the card's PIN has been entered.
- For an AWS profile using `sso_session`, the access token has expired but a refresh token is cached. The next `aws` call may renew it silently; that can't be known without calling AWS.

The checks never print or store any token. The gcloud check refreshes the
access token if needed, as any `gcloud` command would.

#### Docker registries

The credentials of a registry are looked up as the docker CLI does: with the
credential helper set for it in `credHelpers`, else with the `credsStore`
helper, else in the `auths` of the auth file. The auth file of podman and
skopeo (`$XDG_RUNTIME_DIR/containers/auth.json`) has the same format and works
with `auth_file=`.

Docker stores no expiry date next to credentials, so the check reads it from
the token itself when there is one:

| Credentials | Expiry | Example |
|-------------|--------|---------|
| Amazon ECR token | `expiration` of the token | `aws ecr get-login-password \| docker login …` |
| JWT, as password or identity token | `exp` claim | Azure Container Registry identity tokens |
| Password or personal access token | none | Docker Hub, GHCR, GitLab, Harbor, … |

Credentials without an expiry date are reported `unlocked` with the detail
`no expiry date, not verified with the registry`, because a revoked password
or an expired personal access token can only be detected by the registry. Add
the `remote` option (`remote = true` in the configuration file) to ask it: the
check then authenticates like `docker login` does, directly or through the
registry's token server. It is `locked` when the registry rejects the
credentials, and `unknown` when it can't be reached. HTTPS is used unless the
registry is given as a URL, such as `http://localhost:5000`, and the system CA
certificates are trusted. Tokens with an expiry date are never sent anywhere.

A credential helper runs at each check, as on every `docker pull`. Helpers that
decrypt on demand, such as `pass`, may then ask for a passphrase.

### Output formats

Choose the format with `-f`/`--format`.

**`text`** (default): one line, built from templates. The whole line is
`--text-format` (default `{items}`):

| Placeholder | Value |
|-------------|-------|
| `{items}` | every check, rendered with `--item-format` |
| `{kinds}` | one entry per kind of check (`gpg`, `aws`, …), rendered with `--kind-format` |
| `{icon}` | overall icon: the unlocked, locked or unknown icon, or `--icon-partial` (default 🔐) when only some checks are unlocked |
| `{color}` | overall color, picked the same way from `--color-*` |
| `{state}` | overall state: `unlocked`, `partial`, `locked` or `unknown` |
| `{unlocked}`, `{locked}`, `{unknown}` | number of checks in that state |
| `{total}` | number of checks |
| `{gpg.color}`, `{aws.state}`, … | any of the above for the checks of one kind (`gpg`, `aws`, `gcloud`, `vault` or `docker`) only; a kind without checks is `unknown` |

Each check in `{items}` is rendered with `--item-format` (default
`{icon} {kind}:{label}`):

| Placeholder | Value |
|-------------|-------|
| `{icon}` | `--icon-unlocked`, `--icon-locked` or `--icon-unknown` (defaults: 🔓 🔒 ❓) |
| `{color}` | `--color-unlocked`, `--color-locked` or `--color-unknown` |
| `{kind}` | `gpg`, `aws`, `gcloud`, `vault` or `docker` |
| `{label}` | the check's label |
| `{state}` | `unlocked`, `locked` or `unknown` |
| `{expires}` | time left before expiry, e.g. `3h05m` (unlocked checks with an expiry date only) |

Each kind in `{kinds}` groups all the checks of that kind, and is rendered with
`--kind-format` (default `{icon} {kind}`). Its placeholders are `{kind}`, plus
`{icon}`, `{color}`, `{state}`, `{unlocked}`, `{locked}`, `{unknown}` and
`{total}`, computed over the checks of that kind only. With two AWS profiles of
which one is logged in, `aws` is `partial`.

The entries of `{items}` and `{kinds}` are joined with `--separator` (default: a
space). Unknown placeholders are left as they are.

When every check is unlocked, `--text-format-all-unlocked` replaces
`--text-format` if it is set. It takes the same placeholders, and optional
checks don't prevent it. This keeps the bar short while everything is fine,
for example `--text-format-all-unlocked 'locks: {icon}'`.

With `-v`/`--verbose`, the line is followed by the details of every check, one
per line, as in the waybar tooltip. Optional checks are included:

```
$ lock-indicator -v --gpg 0xA629E94B9C4B2A03,label=work --aws main --aws perso,optional
🔒 gpg:work 🔓 aws:main
🔒 gpg:work — locked: passphrase not cached
🔓 aws:main — unlocked, expires in 2h59m (2026-10-24 23:29)
🔒 aws:perso — locked (optional): no cached SSO token, run `aws sso login --profile perso`
```

`--verbose` only changes the `text` format: `json` already has every detail and
`waybar` has them in its tooltip.

```sh
lock-indicator --aws main --vault ~/.vault-token --item-format '{icon} {label} {expires}' --separator ' | '
lock-indicator --aws main --aws sbx --gpg 0xA629E94B9C4B2A03 --text-format '{icon} {unlocked}/{total}'
lock-indicator --aws main --aws sbx --gpg 0xA629E94B9C4B2A03 --text-format '{kinds}' --kind-format '{icon} {kind} {unlocked}/{total}'
```

```
🔓 main 2h59m | 🔒 .vault-token
🔐 2/3
🔓 gpg 1/1 🔐 aws 1/2
```

`{color}` is meant for waybar, which renders [Pango markup](https://docs.gtk.org/Pango/pango_markup.html):
`<span color='{color}'>{kind}</span>` shows each kind in green (unlocked),
orange (partial), red (locked) or grey (unknown). The default colors are
`#98c379`, `#d19a66`, `#e06c75` and `#888888`; set them with `--color-unlocked`,
`--color-partial`, `--color-locked` and `--color-unknown`, or `[colors]` in the
configuration file. Any Pango color works, such as `orange` or `#ffa500`.

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
      "optional": false,
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
timeout = 10             # seconds, for each external command or registry verification
text_format = "{items}"
text_format_all_unlocked = "locks: {icon}"   # used instead when everything is unlocked
item_format = "{icon} {kind}:{label}"
kind_format = "{icon} {kind}"
separator = " "

[icons]
unlocked = "🔓"
locked = "🔒"
unknown = "❓"
partial = "🔐"

[colors]
unlocked = "#98c379"
locked = "#e06c75"
unknown = "#888888"
partial = "#d19a66"

[[gpg]]
key = "0xA629E94B9C4B2A03"
label = "work"           # every check can have a label

[[aws]]
profile = "main"

[[aws]]
profile = "sbx"
label = "sandbox"

[[gcloud]]
account = "me@example.com"

[[gcloud]]
account = "me@gmail.com"
label = "perso"
optional = true          # reported in the tooltip, left out of the text and state

[[vault]]
token_file = "~/.vault-token"
addr = "https://vault.example.com:8200"   # optional, defaults to $VAULT_ADDR

[[docker]]
registry = "123456789012.dkr.ecr.eu-west-3.amazonaws.com"
label = "ecr"

[[docker]]
registry = "ghcr.io"
auth_file = "~/.docker/config.json"   # optional, defaults to $DOCKER_CONFIG/config.json
remote = true            # verify credentials without an expiry date with the registry
```

The `[programs]` table sets where the external programs are, as a path (`~`
is expanded) or a name looked up in `PATH`. Each one defaults to its own name:

```toml
[programs]
gpg = "gpg"
gpg_connect_agent = "gpg-connect-agent"
gcloud = "gcloud"
vault = "~/.nix-profile/bin/vault"
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

For a colored overview with one entry per kind, such as a green `gpg` and an
orange `aws` when only one of two AWS profiles is logged in, set in the
configuration file:

```toml
format = "waybar"
text_format = "{kinds}"
kind_format = "{kind}:<span color='{color}'>●</span>"
```

The tooltip still lists every check with its details.

`{kinds}` always lists the kinds in the same order (gpg, aws, gcloud, vault, docker)
under their own names. To choose the order and the names, write the line
yourself with the placeholders of each kind:

```toml
format = "waybar"
text_format = "aws:<span color='{aws.color}'>●</span> gpg:<span color='{gpg.color}'>●</span> gcp:<span color='{gcloud.color}'>●</span> vault:<span color='{vault.color}'>●</span>"

[colors]
unlocked = "green"
partial = "orange"
locked = "red"
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

GitHub Actions runs `cargo fmt --check`, `cargo clippy -D warnings` and the tests
on pushes to `main` and on pull requests (`.github/workflows/ci.yml`).

### Releasing

Set the new `version` in `Cargo.toml`, commit, then push a matching tag:

```sh
git tag v0.1.0 && git push origin v0.1.0
```

`.github/workflows/release.yml` runs CI and checks that the tag matches the crate
version. It then builds static binaries for `x86_64-unknown-linux-musl` and
`aarch64-unknown-linux-musl` and publishes them, with SHA-256 checksums, as a
GitHub release. Tags containing a `-` (e.g. `v0.2.0-rc.1`) become pre-releases.

## Configuration

Besides the command-line options and the
[configuration file](#configuration-file), `lock-indicator` reads these
environment variables, directly or through the tools it runs:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `HOME` | Yes | | Location of `~/.aws/config`, `~/.aws/sso/cache`, `~/.docker/config.json` and `~`-prefixed paths |
| `XDG_CONFIG_HOME` | No | `~/.config` | Directory containing `lock-indicator/config.toml` |
| `AWS_CONFIG_FILE` | No | `~/.aws/config` | AWS config file used to resolve profiles |
| `VAULT_ADDR` | For `--vault` without `addr=` | | Vault server address |
| `VAULT_CACERT`, `VAULT_NAMESPACE`, … | No | | Passed through to `vault token lookup` |
| `GNUPGHOME` | No | `~/.gnupg` | GnuPG home used by `gpg` and `gpg-connect-agent` |
| `CLOUDSDK_CONFIG` | No | `~/.config/gcloud` | gcloud configuration directory |
| `DOCKER_CONFIG` | No | `~/.docker` | Directory of the default Docker auth file, `config.json` |
| `HTTPS_PROXY`, `NO_PROXY`, … | No | | Proxy for registry verifications (`remote`) |

## References

- [Waybar custom module](https://github.com/Alexays/Waybar/wiki/Module:-Custom): the JSON format expected with `"return-type": "json"`
- [GnuPG manual](https://www.gnupg.org/documentation/manuals/gnupg/): gpg-agent and `gpg-connect-agent`
- [GnuPG DETAILS](https://github.com/gpg/gnupg/blob/master/doc/DETAILS): the `--with-colons` listing format
- [Configuring IAM Identity Center authentication with the AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html): SSO profiles and `aws sso login`
- [gcloud auth print-access-token](https://cloud.google.com/sdk/gcloud/reference/auth/print-access-token)
- [vault token lookup](https://developer.hashicorp.com/vault/docs/commands/token/lookup)
- [docker login](https://docs.docker.com/reference/cli/docker/login/): the auth file and credential helpers
- [docker-credential-helpers](https://github.com/docker/docker-credential-helpers): the credential helper protocol
- [Distribution token authentication](https://distribution.github.io/distribution/spec/auth/token/): how registries authenticate clients
