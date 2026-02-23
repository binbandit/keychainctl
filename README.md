# keychainctl

`keychainctl` is a tiny command-line tool for storing and reading development secrets from the macOS keychain.

I built this for shell startup and local scripts where I wanted one simple thing:

- read a secret quickly
- keep secrets out of dotfiles
- avoid extra services or background daemons

## What it does

- `get`: print a secret value to stdout
- `set`: create or update a secret
- `delete`: remove a secret
- `list`: show tracked service names per account

The tool uses the system `security` utility under the hood, so secrets stay in your login keychain.

## Install

```bash
cargo install --path .
```

Or build locally:

```bash
cargo build --release
```

## Quick start

Set a secret (interactive hidden prompt):

```bash
keychainctl set github_token
```

Set a secret from stdin:

```bash
printf '%s' "$GITHUB_TOKEN" | keychainctl set github_token --stdin
```

Read a secret:

```bash
keychainctl get github_token
```

Use a specific account:

```bash
keychainctl get github_token --account work-user
```

Delete a secret:

```bash
keychainctl delete github_token
```

## Notes

- Account defaults to `$USER`.
- Service names are tracked in `~/.config/keychainctl/registry.txt` (or `$XDG_CONFIG_HOME/keychainctl/registry.txt`).
- `get` is optimized for common invocation patterns because it is often used in shell startup paths.

## Exit behavior

- Success prints expected output and exits `0`.
- Failures return a non-zero exit code with an error message on stderr.
