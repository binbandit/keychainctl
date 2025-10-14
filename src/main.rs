use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs::{self, File};
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use dialoguer::Confirm;

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
    let cli = Cli::parse();
    match cli.command {
        CommandKind::Get { service, account } => {
            let account = resolve_account(account)?;
            let value = keychain_get(&account, &service)?;
            println!("{}", value);
        }
        CommandKind::Set {
            service,
            account,
            value,
            stdin,
            prompt,
        } => {
            let account = resolve_account(account)?;
            let secret = resolve_secret_value(value, stdin, prompt)?;
            keychain_set(&account, &service, &secret)?;
            registry_add(&account, &service)?;
            println!(
                "Saved secret for service `{}` (account {}).",
                service, account
            );
        }
        CommandKind::Delete {
            service,
            account,
            yes,
        } => {
            let account = resolve_account(account)?;
            if !yes {
                let confirmed = Confirm::new()
                    .with_prompt(format!(
                        "Remove keychain secret for service `{}` (account {})?",
                        service, account
                    ))
                    .default(false)
                    .interact()?;
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
        }
        CommandKind::List { account } => {
            let account = resolve_account(account)?;
            let services = registry_list(&account)?;
            if services.is_empty() {
                println!("No tracked secrets for account {}.", account);
            } else {
                for service in services {
                    println!("{}", service);
                }
            }
        }
    }
    Ok(())
}

fn resolve_account(account: Option<String>) -> Result<String> {
    if let Some(account) = account {
        return Ok(account);
    }
    if let Ok(user) = env::var("USER") {
        return Ok(user);
    }
    let output = Command::new("whoami")
        .output()
        .context("failed to determine current user")?;
    if !output.status.success() {
        return Err(anyhow!("failed to determine account"));
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_string())
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
        return Ok(buffer.trim_end_matches(['\n', '\r']).to_string());
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
    let output = Command::new("security")
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

    Ok(String::from_utf8(output.stdout)?.trim().to_string())
}

fn keychain_set(account: &str, service: &str, value: &str) -> Result<()> {
    let status = Command::new("security")
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
    let output = Command::new("security")
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
    let mut services: Vec<String> = registry
        .get(account)
        .map(|set| set.iter().cloned().collect())
        .unwrap_or_default();
    services.sort();
    Ok(services)
}

fn config_dir() -> Result<PathBuf> {
    if let Ok(dir) = env::var("XDG_CONFIG_HOME") {
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
    let mut file = File::create(&path).context("failed to open registry for writing")?;
    for (account, services) in map {
        for service in services {
            writeln!(file, "{}\t{}", account, service)?;
        }
    }
    Ok(())
}
