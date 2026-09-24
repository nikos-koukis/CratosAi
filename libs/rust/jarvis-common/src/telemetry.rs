//! Structured logging. JSON by default (one object per line, for the log
//! pipeline); `pretty` for local development. Verbosity is controlled with
//! `RUST_LOG`.

use std::env;

use tracing_subscriber::{EnvFilter, fmt};

const DEFAULT_FILTER: &str =
    "info,h2=warn,tower=warn,hyper=warn,rustls=warn,sqlx::postgres::notice=warn";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogFormat {
    Json,
    Pretty,
}

impl LogFormat {
    /// Reads the format from `variable` (`json`, `pretty`, or unset for JSON).
    pub fn from_env(variable: &str) -> Result<Self, String> {
        match env::var(variable).ok().as_deref() {
            None | Some("" | "json") => Ok(Self::Json),
            Some("pretty") => Ok(Self::Pretty),
            Some(other) => Err(format!("{variable} must be json or pretty, got {other:?}")),
        }
    }
}

pub fn init(format: LogFormat) -> Result<(), String> {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(DEFAULT_FILTER));
    let builder = fmt().with_env_filter(filter).with_target(true);
    let result = match format {
        LogFormat::Json => builder
            .json()
            .flatten_event(true)
            .with_current_span(true)
            .with_span_list(false)
            .try_init(),
        LogFormat::Pretty => builder.try_init(),
    };
    result.map_err(|e| format!("cannot initialise logging: {e}"))
}
