//! Server assembly: preflight checks, listen address, mTLS, health,
//! optional reflection, graceful shutdown.

use std::{
    env, fs, future::Future, os::unix::fs::PermissionsExt, path::PathBuf, sync::Arc, time::Duration,
};

use anyhow::{Context, bail};
use jarvis_common::mtls::TlsMaterial;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{codegen::http, transport::Server};

use crate::{
    config::{Config, NetworkMode},
    network,
    proto::{FILE_DESCRIPTOR_SET, device_v1::device_service_server::DeviceServiceServer},
    sandbox::SANDBOX_EXEC,
    service::{DaemonState, DeviceService},
};

/// Largest request or response. Command output is capped well below this.
pub const MAX_MESSAGE_BYTES: usize = 40 * 1024 * 1024;
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const HTTP2_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, Default)]
pub struct ServeOptions {
    pub enable_reflection: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    #[error("gRPC transport error")]
    Transport(#[from] tonic::transport::Error),
    #[error("cannot build reflection service")]
    Reflection(#[from] tonic_reflection::server::Error),
}

/// Serves the daemon on a bound listener until `shutdown` resolves.
pub async fn serve(
    listener: TcpListener,
    state: Arc<DaemonState>,
    tls: &TlsMaterial,
    options: ServeOptions,
    shutdown: impl Future<Output = ()>,
) -> Result<(), ServeError> {
    let device = DeviceServiceServer::new(DeviceService::new(state))
        .max_decoding_message_size(MAX_MESSAGE_BYTES)
        .max_encoding_message_size(MAX_MESSAGE_BYTES);

    let (health_reporter, health) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<DeviceServiceServer<DeviceService>>()
        .await;

    let reflection = if options.enable_reflection {
        Some(
            tonic_reflection::server::Builder::configure()
                .register_encoded_file_descriptor_set(FILE_DESCRIPTOR_SET)
                .register_encoded_file_descriptor_set(tonic_health::pb::FILE_DESCRIPTOR_SET)
                .build_v1()?,
        )
    } else {
        None
    };

    Server::builder()
        .tls_config(tls.server_config(TLS_HANDSHAKE_TIMEOUT))?
        .http2_keepalive_interval(Some(HTTP2_KEEPALIVE_INTERVAL))
        .tcp_nodelay(true)
        .trace_fn(request_span)
        .add_service(health)
        .add_service(device)
        .add_optional_service(reflection)
        .serve_with_incoming_shutdown(TcpListenerStream::new(listener), shutdown)
        .await?;
    Ok(())
}

/// Checks the host, builds the state and serves until SIGTERM or Ctrl-C.
pub async fn run(config: Config) -> anyhow::Result<()> {
    preflight()?;
    let tls = TlsMaterial::load(&config.tls.cert, &config.tls.key, &config.tls.client_ca)?;
    let network = config.network;

    if network.mode == NetworkMode::Loopback {
        tracing::warn!("development mode: listening on 127.0.0.1 only, not on the tailnet");
    }
    if config.approvers.is_empty() {
        tracing::warn!("no approvers configured: only allowlisted commands can run");
    }

    let home = PathBuf::from(env::var_os("HOME").context("HOME is not set")?);
    let user = env::var("USER").unwrap_or_else(|_| "unknown".to_owned());
    let temp_root = env::temp_dir().join("jarvisd");
    fs::create_dir_all(&temp_root)
        .with_context(|| format!("cannot create {}", temp_root.display()))?;
    fs::set_permissions(&temp_root, fs::Permissions::from_mode(0o700))?;

    let rules = config.policy.rules.len();
    let approvers = config.approvers.len();
    let state = Arc::new(DaemonState::new(config, temp_root, home, user));

    let mut shutdown = std::pin::pin!(shutdown_signal());
    let address = tokio::select! {
        address = network::listen_address(network.mode, network.port) => address,
        () = &mut shutdown => return Ok(()),
    };
    let listener = TcpListener::bind(address)
        .await
        .with_context(|| format!("cannot listen on {address}"))?;
    tracing::info!(
        %address,
        mode = ?network.mode,
        allowlisted_commands = rules,
        approvers,
        reflection = network.reflection,
        "jarvisd listening (mTLS required)"
    );

    serve(
        listener,
        state,
        &tls,
        ServeOptions {
            enable_reflection: network.reflection,
        },
        shutdown,
    )
    .await?;
    Ok(())
}

/// The daemon fails closed: without the sandbox it runs nothing at all.
fn preflight() -> anyhow::Result<()> {
    if !cfg!(target_os = "macos") {
        bail!("jarvisd requires macOS (it sandboxes commands with sandbox-exec)");
    }
    let metadata = fs::metadata(SANDBOX_EXEC)
        .with_context(|| format!("{SANDBOX_EXEC} is missing; refusing to run unsandboxed"))?;
    if metadata.permissions().mode() & 0o111 == 0 {
        bail!("{SANDBOX_EXEC} is not executable; refusing to run unsandboxed");
    }
    Ok(())
}

fn request_span(request: &http::Request<()>) -> tracing::Span {
    tracing::info_span!("grpc", method = %request.uri().path())
}

async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    let terminate = async {
        match signal(SignalKind::terminate()) {
            Ok(mut sigterm) => {
                sigterm.recv().await;
            }
            Err(error) => {
                tracing::error!(%error, "cannot listen for SIGTERM");
                std::future::pending::<()>().await;
            }
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        () = terminate => {}
    }
    tracing::info!("shutdown requested; finishing in-flight commands");
}
