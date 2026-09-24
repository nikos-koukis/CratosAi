//! Server assembly: mTLS listener, service wiring, health and reflection,
//! request limits and graceful shutdown.

use std::{future::Future, sync::Arc, time::Duration};

use anyhow::Context;
use sqlx::postgres::PgPoolOptions;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{
    codegen::http,
    transport::{Certificate, Channel, ClientTlsConfig, Identity, Server},
};

pub use jarvis_common::mtls::TlsMaterial;

use crate::{
    audit::{AuditShipper, AuditSink, GrpcAuditSink, TeeAuditSink, TracingAuditSink},
    authz::AuthzPolicy,
    config::{AuditTarget, Config},
    crypto::MasterKey,
    proto::{FILE_DESCRIPTOR_SET, vault_v1::vault_service_server::VaultServiceServer},
    service::VaultService,
    store::{KeyStore, MIGRATOR},
};

/// Largest accepted request or response: provider keys are at most 8 KiB and
/// sealed data at most 64 KiB plus its envelope.
pub const MAX_MESSAGE_BYTES: usize = 128 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CONCURRENT_STREAMS_PER_CONNECTION: usize = 256;
const HTTP2_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
const DB_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub struct Components {
    pub store: KeyStore,
    pub master_key: Arc<MasterKey>,
    pub policy: Arc<AuthzPolicy>,
    pub audit: Arc<dyn AuditSink>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ServeOptions {
    /// Exposes gRPC server reflection (for grpcurl and similar tools).
    pub enable_reflection: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    #[error("gRPC transport error")]
    Transport(#[from] tonic::transport::Error),
    #[error("cannot build reflection service")]
    Reflection(#[from] tonic_reflection::server::Error),
}

/// Serves the Vault on an already bound listener until `shutdown` resolves,
/// then drains in-flight requests.
pub async fn serve(
    listener: TcpListener,
    components: Components,
    tls: &TlsMaterial,
    options: ServeOptions,
    shutdown: impl Future<Output = ()>,
) -> Result<(), ServeError> {
    let tls_config = tls.server_config(TLS_HANDSHAKE_TIMEOUT);

    let vault = VaultServiceServer::new(VaultService::new(
        components.store,
        components.master_key,
        components.policy,
        components.audit,
    ))
    .max_decoding_message_size(MAX_MESSAGE_BYTES)
    .max_encoding_message_size(MAX_MESSAGE_BYTES);

    let (health_reporter, health) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<VaultServiceServer<VaultService>>()
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
        .tls_config(tls_config)?
        .timeout(REQUEST_TIMEOUT)
        .concurrency_limit_per_connection(MAX_CONCURRENT_STREAMS_PER_CONNECTION)
        .http2_keepalive_interval(Some(HTTP2_KEEPALIVE_INTERVAL))
        .tcp_nodelay(true)
        .trace_fn(request_span)
        .add_service(health)
        .add_service(vault)
        .add_optional_service(reflection)
        .serve_with_incoming_shutdown(TcpListenerStream::new(listener), shutdown)
        .await?;
    Ok(())
}

/// Runs the Vault from configuration until SIGTERM or Ctrl-C.
pub async fn run(config: Config) -> anyhow::Result<()> {
    let Config {
        listen_addr,
        database_url,
        database_max_connections,
        run_migrations,
        master_passphrase,
        master_salt,
        tls,
        authz_policy_path,
        enable_reflection,
        audit,
    } = config;

    let policy = AuthzPolicy::load(&authz_policy_path)?;
    if policy.principal_count() == 0 {
        tracing::warn!("authorization policy grants nothing; every call will be denied");
    }
    let tls = TlsMaterial::load(&tls.cert, &tls.key, &tls.client_ca)?;

    let master_key = tokio::task::spawn_blocking(move || {
        MasterKey::derive(master_passphrase.expose().as_bytes(), &master_salt)
    })
    .await
    .context("key derivation task failed")?
    .context("cannot derive master key")?;
    tracing::info!(kek_id = master_key.kek_id(), "master key derived");

    let pool = PgPoolOptions::new()
        .max_connections(database_max_connections)
        .acquire_timeout(DB_ACQUIRE_TIMEOUT)
        .connect(database_url.expose())
        .await
        .context("cannot connect to PostgreSQL")?;
    drop(database_url);
    if run_migrations {
        MIGRATOR
            .run(&pool)
            .await
            .context("database migration failed")?;
        tracing::info!("database schema is up to date");
    }

    let store = KeyStore::new(pool.clone());
    store.register_kek(master_key.kek_id()).await?;

    // Every event goes to the log; with an audit service, also to the trail.
    let (audit, shipper): (Arc<dyn AuditSink>, Option<AuditShipper>) = match audit {
        Some(target) => {
            let (sink, shipper) = GrpcAuditSink::start(audit_channel(&target)?);
            tracing::info!(addr = %target.addr, "audit events are recorded at the audit service");
            (
                Arc::new(TeeAuditSink(vec![
                    Arc::new(TracingAuditSink),
                    Arc::new(sink),
                ])),
                Some(shipper),
            )
        }
        None => {
            tracing::warn!(
                "no audit service configured (VAULT_AUDIT_ADDR): audit events go to the log only"
            );
            (Arc::new(TracingAuditSink), None)
        }
    };

    let listener = TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("cannot listen on {listen_addr}"))?;
    tracing::info!(
        addr = %listener.local_addr()?,
        reflection = enable_reflection,
        principals = policy.principal_count(),
        "vault listening (mTLS required)"
    );

    serve(
        listener,
        Components {
            store,
            master_key: Arc::new(master_key),
            policy: Arc::new(policy),
            audit,
        },
        &tls,
        ServeOptions { enable_reflection },
        shutdown_signal(),
    )
    .await?;

    if let Some(shipper) = shipper {
        shipper.finish(Duration::from_secs(10)).await;
    }
    pool.close().await;
    Ok(())
}

/// A lazily connected mTLS channel to the audit service, as spiffe://…/vault.
fn audit_channel(target: &AuditTarget) -> anyhow::Result<Channel> {
    let read = |path: &std::path::Path| {
        std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))
    };
    let tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(read(&target.ca)?))
        .identity(Identity::from_pem(read(&target.cert)?, read(&target.key)?))
        .domain_name(target.server_name.clone());
    Ok(Channel::from_shared(format!("https://{}", target.addr))
        .context("VAULT_AUDIT_ADDR is not a valid address")?
        .tls_config(tls)
        .context("audit service TLS")?
        .connect_timeout(Duration::from_secs(5))
        .connect_lazy())
}

fn request_span(request: &http::Request<()>) -> tracing::Span {
    tracing::info_span!(
        "grpc",
        method = %request.uri().path(),
        request_id = tracing::field::Empty,
    )
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::error!(%error, "cannot listen for Ctrl-C");
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{SignalKind, signal};
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
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
    tracing::info!("shutdown requested; draining in-flight requests");
}
