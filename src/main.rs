use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};

const SECURITY_BIN: &str = "/usr/bin/security";
const WHOAMI_BIN: &str = "/usr/bin/whoami";

#[derive(Parser)]
#[command(
    author,
    version,
    about = "Manage macOS keychain secrets for development."
)]
struct Cli {
    #[command(subcommand)]
    command: CommandKind,
}

#[derive(Subcommand)]
enum CommandKind {
    /// Fetch a secret from the keychain and print it to stdout
    Get {
        /// Service name
        service: String,
        /// Account owning the secret (defaults to $USER)
        #[arg(short, long)]
        account: Option<String>,
    },
    /// Add or update a secret in the keychain
    Set {
        /// Service name
        service: String,
        /// Account owning the secret (defaults to $USER)
        #[arg(short, long)]
        account: Option<String>,
        /// Provide the secret value directly
        #[arg(short, long)]
        value: Option<String>,
        /// Read the secret value from STDIN
        #[arg(long, conflicts_with = "value")]
        stdin: bool,
        /// Prompt interactively for the secret (hidden input)
        #[arg(long, conflicts_with_all = ["value", "stdin"])]
        prompt: bool,
    },
    /// Delete a secret from the keychain
    Delete {
        /// Service name
        service: String,
        /// Account owning the secret (defaults to $USER)
        #[arg(short, long)]
        account: Option<String>,
        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },
    /// List service names tracked for the account
    List {
        /// Account owning the secrets (defaults to $USER)
        #[arg(short, long)]
        account: Option<String>,
    },
}

fn main() -> Result<()> {
    if try_run_fast_get()? {
        return Ok(());
    }

    let cli = Cli::parse();
    run(cli)
}

fn try_run_fast_get() -> Result<bool> {
    let Some((service, account)) = parse_fast_get_args()? else {
        return Ok(false);
    };

    let account = resolve_account(account)?;
    let value = keychain_get(&account, &service)?;
    println!("{}", value);
    Ok(true)
}

fn parse_fast_get_args() -> Result<Option<(String, Option<String>)>> {
    let arguments: Vec<OsString> = env::args_os().collect();
    if arguments.len() < 3 || arguments[1] != "get" {
        return Ok(None);
    }

    if arguments[2] == "-h" || arguments[2] == "--help" {
        return Ok(None);
    }

    let service = argument_to_string(&arguments[2], "service")?;

    if arguments.len() == 3 {
        return Ok(Some((service, None)));
    }

    if arguments.len() == 5 && (arguments[3] == "-a" || arguments[3] == "--account") {
        let account = argument_to_string(&arguments[4], "account")?;
        return Ok(Some((service, Some(account))));
    }

    Ok(None)
}

fn argument_to_string(value: &OsString, name: &str) -> Result<String> {
    value
        .to_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow!("{} must be valid UTF-8", name))
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        CommandKind::Get { service, account } => run_get(service, account),
        CommandKind::Set {
            service,
            account,
            value,
            stdin,
            prompt,
        } => run_set(service, account, value, stdin, prompt),
        CommandKind::Delete {
            service,
            account,
            yes,
        } => run_delete(service, account, yes),
        CommandKind::List { account } => run_list(account),
    }
}

fn run_get(service: String, account: Option<String>) -> Result<()> {
    let account = resolve_account(account)?;
    let value = keychain_get(&account, &service)?;
    println!("{}", value);
    Ok(())
}

fn run_set(
    service: String,
    account: Option<String>,
    value: Option<String>,
    stdin: bool,
    prompt: bool,
) -> Result<()> {
    let account = resolve_account(account)?;
    let secret = resolve_secret_value(value, stdin, prompt)?;
    keychain_set(&account, &service, &secret)?;
    registry_add(&account, &service)?;
    println!(
        "Saved secret for service `{}` (account {}).",
        service, account
    );
    Ok(())
}

fn run_delete(service: String, account: Option<String>, yes: bool) -> Result<()> {
    let account = resolve_account(account)?;
    if !yes {
        let confirmed = confirm_delete(&service, &account)?;
        if !confirmed {
            println!("Aborted.");
            return Ok(());
        }
    }

    keychain_delete(&account, &service)?;
    registry_remove(&account, &service)?;
    println!(
        "Removed secret for service `{}` (account {}).",
        service, account
    );
    Ok(())
}

fn run_list(account: Option<String>) -> Result<()> {
    let account = resolve_account(account)?;
    let services = registry_list(&account)?;
    if services.is_empty() {
        println!("No tracked secrets for account {}.", account);
        return Ok(());
    }

    for service in services {
        println!("{}", service);
    }
    Ok(())
}

fn resolve_account(account: Option<String>) -> Result<String> {
    if let Some(account) = account.filter(|value| !value.trim().is_empty()) {
        return Ok(account);
    }
    if let Ok(user) = env::var("USER")
        && !user.trim().is_empty()
    {
        return Ok(user);
    }
    let output = Command::new(WHOAMI_BIN)
        .output()
        .context("failed to determine current user")?;
    if !output.status.success() {
        return Err(anyhow!("failed to determine account"));
    }
    Ok(strip_trailing_newlines(String::from_utf8(output.stdout)?))
}

fn resolve_secret_value(
    value: Option<String>,
    stdin_flag: bool,
    prompt_flag: bool,
) -> Result<String> {
    if let Some(value) = value {
        return Ok(value);
    }

    let stdin_is_terminal = io::stdin().is_terminal();
    if stdin_flag || (!stdin_is_terminal && !prompt_flag) {
        let mut buffer = String::new();
        io::stdin()
            .read_to_string(&mut buffer)
            .context("failed to read secret from stdin")?;
        return Ok(strip_trailing_newlines(buffer));
    }

    if prompt_flag || stdin_is_terminal {
        let secret = rpassword::prompt_password("Secret value: ")
            .context("failed to read secret from prompt")?;
        return Ok(secret);
    }

    Err(anyhow!(
        "No secret provided. Use --value, --stdin, or --prompt (or pipe data)."
    ))
}

fn keychain_get(account: &str, service: &str) -> Result<String> {
    let output = Command::new(SECURITY_BIN)
        .args(["find-generic-password", "-w", "-a", account, "-s", service])
        .output()
        .with_context(|| format!("failed to read secret `{}`", service))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("could not be found") {
            return Err(anyhow!("secret not found for service `{}`", service));
        }
        return Err(anyhow!("security command failed: {}", stderr.trim()));
    }

    Ok(strip_trailing_newlines(String::from_utf8(output.stdout)?))
}

fn strip_trailing_newlines(mut value: String) -> String {
    while matches!(value.as_bytes().last(), Some(b'\n' | b'\r')) {
        value.pop();
    }
    value
}

fn keychain_set(account: &str, service: &str, value: &str) -> Result<()> {
    let status = Command::new(SECURITY_BIN)
        .args([
            "add-generic-password",
            "-a",
            account,
            "-s",
            service,
            "-w",
            value,
            "-U",
        ])
        .status()
        .with_context(|| format!("failed to store secret `{}`", service))?;

    if status.success() {
        Ok(())
    } else {
        Err(anyhow!("security command failed with status {}", status))
    }
}

fn keychain_delete(account: &str, service: &str) -> Result<()> {
    let output = Command::new(SECURITY_BIN)
        .args(["delete-generic-password", "-a", account, "-s", service])
        .output()
        .with_context(|| format!("failed to delete secret `{}`", service))?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("could not be found") {
        return Ok(());
    }

    Err(anyhow!("security command failed: {}", stderr.trim()))
}

fn registry_add(account: &str, service: &str) -> Result<()> {
    let mut registry = load_registry()?;
    registry
        .entry(account.to_string())
        .or_default()
        .insert(service.to_string());
    save_registry(&registry)
}

fn registry_remove(account: &str, service: &str) -> Result<()> {
    let mut registry = load_registry()?;
    if let Some(services) = registry.get_mut(account) {
        services.remove(service);
        if services.is_empty() {
            registry.remove(account);
        }
        save_registry(&registry)?;
    }
    Ok(())
}

fn registry_list(account: &str) -> Result<Vec<String>> {
    let registry = load_registry()?;
    let services: Vec<String> = registry
        .get(account)
        .map(|set| set.iter().cloned().collect())
        .unwrap_or_default();
    Ok(services)
}

fn confirm_delete(service: &str, account: &str) -> Result<bool> {
    print!(
        "Remove keychain secret for service `{}` (account {})? [y/N]: ",
        service, account
    );
    io::stdout().flush().context("failed to write prompt")?;

    let mut response = String::new();
    io::stdin()
        .read_line(&mut response)
        .context("failed to read confirmation")?;

    let answer = response.trim();
    Ok(answer.eq_ignore_ascii_case("y") || answer.eq_ignore_ascii_case("yes"))
}

fn config_dir() -> Result<PathBuf> {
    if let Ok(dir) = env::var("XDG_CONFIG_HOME")
        && !dir.trim().is_empty()
    {
        return Ok(Path::new(&dir).join("keychainctl"));
    }
    let home = env::var("HOME").context("HOME not set")?;
    Ok(Path::new(&home).join(".config/keychainctl"))
}

fn registry_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("registry.txt"))
}

fn load_registry() -> Result<BTreeMap<String, BTreeSet<String>>> {
    let mut map: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let path = registry_path()?;
    if let Ok(data) = fs::read_to_string(&path) {
        for line in data.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if let Some((account, service)) = trimmed.split_once('\t') {
                map.entry(account.to_string())
                    .or_default()
                    .insert(service.to_string());
            }
        }
    }
    Ok(map)
}

fn save_registry(map: &BTreeMap<String, BTreeSet<String>>) -> Result<()> {
    let path = registry_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context("failed to create registry directory")?;
    }

    let mut data = String::new();
    for (account, services) in map {
        for service in services {
            data.push_str(account);
            data.push('\t');
            data.push_str(service);
            data.push('\n');
        }
    }

    fs::write(&path, data).context("failed to write registry file")?;
    Ok(())
}
