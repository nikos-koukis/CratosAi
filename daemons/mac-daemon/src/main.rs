//! `jarvisd`: the Jarvis local daemon.

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use jarvis_common::telemetry;
use jarvis_daemon::config::{Config, DEFAULT_CONFIG_PATH};

#[derive(Parser)]
#[command(name = "jarvisd", version, about = "Jarvis local daemon")]
struct Cli {
    /// Configuration file.
    #[arg(long, global = true, default_value = DEFAULT_CONFIG_PATH)]
    config: String,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the daemon (default).
    Serve,
    /// Validate the configuration and print the policy it enforces.
    Check,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    if let Err(message) =
        telemetry::LogFormat::from_env("JARVISD_LOG_FORMAT").and_then(telemetry::init)
    {
        // Logging is not up yet, so this can only go to stderr.
        #[allow(clippy::print_stderr)]
        {
            eprintln!("jarvisd: {message}");
        }
        return ExitCode::FAILURE;
    }
    disable_core_dumps();

    let config = match Config::load(&cli.config) {
        Ok(config) => config,
        Err(error) => {
            tracing::error!(error = %error_chain(&error), config = %cli.config, "invalid configuration");
            return ExitCode::FAILURE;
        }
    };

    match cli.command.unwrap_or(Command::Serve) {
        Command::Check => {
            print_policy(&config);
            ExitCode::SUCCESS
        }
        Command::Serve => match jarvis_daemon::server::run(config).await {
            Ok(()) => {
                tracing::info!("jarvisd stopped");
                ExitCode::SUCCESS
            }
            Err(error) => {
                tracing::error!(error = format!("{error:#}"), "jarvisd failed");
                ExitCode::FAILURE
            }
        },
    }
}

#[allow(clippy::print_stdout)]
fn print_policy(config: &Config) {
    let policy = &config.policy;
    println!("Configuration OK: {}", config.config_path.display());
    println!("Device:     {}", config.device_name);
    println!(
        "Network:    {:?} port {}{}",
        config.network.mode,
        config.network.port,
        if config.network.reflection {
            " (reflection on)"
        } else {
            ""
        }
    );
    println!("Approvers:  {}", config.approvers.len());
    println!("Workspace roots:");
    for root in &policy.workspace_roots {
        println!("  {}", root.display());
    }
    println!("Allowlisted commands:");
    for rule in &policy.rules {
        println!(
            "  {} {}{}  grants={:?}{}",
            rule.program.display(),
            rule.args_prefix.join(" "),
            if rule.allow_extra_args { " …" } else { "" },
            rule.grants,
            if rule.requires_approval {
                "  (approval required)"
            } else {
                ""
            }
        );
    }
    println!("Protected paths: {}", policy.protected_paths.len());
    println!("Denied programs: {}", policy.denied_programs.len());
}

/// Command output and the TLS key live in memory; keep them out of core files.
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

fn error_chain(error: &dyn std::error::Error) -> String {
    let mut message = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        message.push_str(": ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }
    message
}
