//! `jarvis-approve`: development stand-in for the approver phone.
//!
//! It holds an ECDSA P-256 key, shows an approval request decoded from the
//! daemon's own payload bytes, and signs it only after you confirm. In
//! production this role moves to the iOS app, with the key in the Secure
//! Enclave behind Face ID.

// An interactive CLI: stdout and stderr are its interface.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::{
    fs,
    io::{self, BufRead, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::ExitCode,
    time::{Duration, SystemTime},
};

use anyhow::{Context, bail};
use base64::Engine;
use clap::{Parser, Subcommand};
use jarvis_daemon::{approval::signed_message, proto::device_v1::ApprovalPayload};
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    elliptic_curve::Generate,
    pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding},
};
use prost::Message;

const DEFAULT_KEY: &str = "~/.config/jarvis/approver-key.pem";

#[derive(Parser)]
#[command(
    name = "jarvis-approve",
    version,
    about = "Review and sign Jarvis command approvals"
)]
struct Cli {
    /// Private key file (PKCS#8 PEM).
    #[arg(long, global = true, default_value = DEFAULT_KEY)]
    key: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new approver key and print the [[approver]] entry for daemon.toml.
    Keygen {
        /// Approver id to put in the printed config entry.
        #[arg(long, default_value = "dev-cli")]
        id: String,
    },
    /// Print the public key (base64 SEC1).
    PublicKey,
    /// Show an approval request and sign it if you confirm.
    Sign {
        /// Approver id configured on the daemon for this key.
        #[arg(long, default_value = "dev-cli")]
        approver_id: String,
        /// Skip the confirmation prompt (for scripted tests only).
        #[arg(long)]
        yes: bool,
        /// `payload` from ApprovalRequired, base64 as grpcurl prints it.
        payload: String,
    },
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("jarvis-approve: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> anyhow::Result<()> {
    let key_path = expand(&cli.key)?;
    match cli.command {
        Command::Keygen { id } => keygen(&key_path, &id),
        Command::PublicKey => {
            println!("{}", public_key(&load_key(&key_path)?));
            Ok(())
        }
        Command::Sign {
            approver_id,
            yes,
            payload,
        } => sign(&key_path, &approver_id, yes, &payload),
    }
}

fn keygen(path: &Path, id: &str) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .with_context(|| format!("cannot create {}", parent.display()))?;
    }
    let key = SigningKey::try_generate().context("system random number generator failed")?;
    let pem = key
        .to_pkcs8_pem(LineEnding::LF)
        .context("cannot encode the key")?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("cannot create {} (does it already exist?)", path.display()))?;
    file.write_all(pem.as_bytes())?;

    eprintln!("Wrote approver key to {} (mode 600).", path.display());
    eprintln!("Add this to the daemon's daemon.toml:\n");
    println!(
        "[[approver]]\nid = \"{id}\"\npublic_key = \"{}\"",
        public_key(&key)
    );
    Ok(())
}

fn load_key(path: &Path) -> anyhow::Result<SigningKey> {
    let metadata = fs::metadata(path).with_context(|| format!("cannot read {}", path.display()))?;
    if metadata.mode() & 0o077 != 0 {
        bail!(
            "{} is readable by other users; run: chmod 600 {}",
            path.display(),
            path.display()
        );
    }
    let pem = fs::read_to_string(path)?;
    SigningKey::from_pkcs8_pem(&pem).context("not a PKCS#8 P-256 private key")
}

fn public_key(key: &SigningKey) -> String {
    base64::engine::general_purpose::STANDARD.encode(key.verifying_key().to_sec1_bytes())
}

fn sign(key_path: &Path, approver_id: &str, yes: bool, payload_b64: &str) -> anyhow::Result<()> {
    let key = load_key(key_path)?;
    let payload = base64::engine::general_purpose::STANDARD
        .decode(payload_b64.trim())
        .context("payload is not base64")?;
    let request =
        ApprovalPayload::decode(payload.as_slice()).context("payload is not an ApprovalPayload")?;

    let expires = request
        .expire_time
        .and_then(|t| SystemTime::try_from(t).ok())
        .context("payload has no expiry")?;
    let remaining = expires
        .duration_since(SystemTime::now())
        .ok()
        .filter(|left| !left.is_zero())
        .context("this approval request has already expired")?;

    describe(&request, remaining);
    if !yes && !confirm()? {
        bail!("not approved");
    }

    let signature: Signature = key.sign(&signed_message(&payload));
    // Values are a UUID, a validated id and base64, so no JSON escaping is needed.
    if !approver_id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        bail!("approver id may only contain A-Z a-z 0-9 - _ .");
    }
    println!(
        "{{\"approval_id\":\"{}\",\"approver_id\":\"{approver_id}\",\"signature\":\"{}\"}}",
        request.approval_id,
        base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
    );
    Ok(())
}

fn describe(request: &ApprovalPayload, remaining: Duration) {
    let grants = request.sandbox.unwrap_or_default();
    let mut access = vec!["read files (except protected ones)"];
    if grants.writable {
        access.push("WRITE inside the working directory");
    }
    if grants.network {
        access.push("NETWORK access");
    }
    if grants.system_services {
        access.push("macOS SERVICES (apps, AppleScript, clipboard)");
    }
    let timeout = request
        .timeout
        .and_then(|t| Duration::try_from(t).ok())
        .map_or_else(|| "?".to_owned(), |t| format!("{}s", t.as_secs()));
    let command: Vec<String> = std::iter::once(request.program.as_str())
        .chain(request.args.iter().map(String::as_str))
        .map(shell_quote)
        .collect();

    eprintln!();
    eprintln!("Jarvis wants to run a command that is not on the allowlist.");
    eprintln!("Only approve if you asked for this.");
    eprintln!();
    eprintln!("  Device:     {}", request.device_name);
    eprintln!("  Command:    {}", command.join(" "));
    eprintln!("  Directory:  {}", request.working_directory);
    eprintln!("  May:        {}", access.join(", "));
    eprintln!("  Timeout:    {timeout}");
    eprintln!(
        "  Request:    {} (expires in {}s)",
        request.approval_id,
        remaining.as_secs()
    );
    eprintln!();
}

fn confirm() -> anyhow::Result<bool> {
    eprint!("Approve? [y/N] ");
    io::stderr().flush()?;
    let mut answer = String::new();
    io::stdin().lock().read_line(&mut answer)?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes" | "YES"))
}

/// Quotes an argument so the displayed command is unambiguous.
fn shell_quote(arg: &str) -> String {
    let plain = !arg.is_empty()
        && arg
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_./:=@%+,".contains(&b));
    if plain {
        arg.to_owned()
    } else {
        format!("'{}'", arg.replace('\'', r"'\''"))
    }
}

fn expand(path: &str) -> anyhow::Result<PathBuf> {
    match path.strip_prefix("~/") {
        Some(rest) => {
            Ok(PathBuf::from(std::env::var_os("HOME").context("HOME is not set")?).join(rest))
        }
        None => Ok(PathBuf::from(path)),
    }
}
