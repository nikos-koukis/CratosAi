//! BYOK Vault server entry point.

use std::process::ExitCode;

use jarvis_common::telemetry;
use jarvis_vault::{config::Config, server};

#[tokio::main]
async fn main() -> ExitCode {
    if let Err(message) =
        telemetry::LogFormat::from_env("VAULT_LOG_FORMAT").and_then(telemetry::init)
    {
        // Logging is not up yet, so this can only go to stderr.
        #[allow(clippy::print_stderr)]
        {
            eprintln!("jarvis-vault: {message}");
        }
        return ExitCode::FAILURE;
    }

    disable_core_dumps();

    let config = match Config::from_env() {
        Ok(config) => config,
        Err(error) => {
            tracing::error!(%error, "invalid configuration");
            return ExitCode::FAILURE;
        }
    };

    match server::run(config).await {
        Ok(()) => {
            tracing::info!("vault stopped");
            ExitCode::SUCCESS
        }
        Err(error) => {
            tracing::error!(error = format!("{error:#}"), "vault failed");
            ExitCode::FAILURE
        }
    }
}

/// Plaintext keys live in this process's memory; a core dump would write them
/// to disk.
fn disable_core_dumps() {
    use rustix::process::{Resource, Rlimit, setrlimit};

    let none = Rlimit {
        current: Some(0),
        maximum: Some(0),
    };
    if let Err(error) = setrlimit(Resource::Core, none) {
        tracing::warn!(%error, "could not disable core dumps");
    }
}
