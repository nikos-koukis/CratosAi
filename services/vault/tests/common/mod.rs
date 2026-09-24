//! Test harness: a real PostgreSQL in Docker, a throwaway PKI, and the Vault
//! served over mTLS on an ephemeral port.

#![allow(clippy::unwrap_used, clippy::expect_used, dead_code)]

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use jarvis_vault::{
    audit::{AuditEvent, AuditSink},
    authz::AuthzPolicy,
    crypto::MasterKey,
    proto::{
        common_v1::Provider,
        vault_v1::{
            CreateKeyRequest, GetDecryptedKeyRequest, RevocationReason, RevokeKeyRequest,
            get_decrypted_key_request::Selector, vault_service_client::VaultServiceClient,
        },
    },
    server::{Components, ServeOptions, TlsMaterial, serve},
    store::{KeyStore, MIGRATOR},
};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType,
};
use sqlx::{PgPool, postgres::PgPoolOptions};
use testcontainers_modules::{
    postgres::Postgres,
    testcontainers::{ContainerAsync, ImageExt, runners::AsyncRunner},
};
use tokio::{net::TcpListener, sync::oneshot};
use tonic::{
    Status,
    transport::{Certificate, Channel, ClientTlsConfig, Identity},
};
use tonic_types::StatusExt;
use uuid::Uuid;

pub const GATEWAY: &str = "spiffe://jarvis.test/voice-gateway";
pub const DASHBOARD: &str = "spiffe://jarvis.test/dashboard-api";
pub const STRANGER: &str = "spiffe://jarvis.test/stranger";
pub const MCP_ROUTER: &str = "spiffe://jarvis.test/mcp-router";

pub const XAI_SECRET: &str = "xai-TESTKEY-4f1c9a0b7d2e6c3f8a5b1d0e9c7f2a4b";
pub const OPENAI_SECRET: &str = "sk-proj-TESTKEY-0123456789abcdefghijWXYZ";

const POSTGRES_TAG: &str = "18-alpine";

const POLICY: &str = r#"
    [[principal]]
    id = "spiffe://jarvis.test/voice-gateway"
    allow = ["GetDecryptedKey"]

    [[principal]]
    id = "spiffe://jarvis.test/dashboard-api"
    allow = ["CreateKey", "RevokeKey"]

    [[principal]]
    id = "spiffe://jarvis.test/mcp-router"
    allow = ["SealData", "OpenData"]
"#;

#[derive(Debug, Default)]
pub struct MemoryAuditSink(Mutex<Vec<AuditEvent>>);

impl MemoryAuditSink {
    pub fn events(&self) -> Vec<AuditEvent> {
        self.0.lock().unwrap().clone()
    }
}

impl AuditSink for MemoryAuditSink {
    fn record(&self, event: &AuditEvent) {
        self.0.lock().unwrap().push(event.clone());
    }
}

/// A CA plus helpers to mint server and client certificates.
pub struct Pki {
    ca: CertifiedIssuer<'static, KeyPair>,
}

impl Pki {
    pub fn new() -> Self {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, "Jarvis Test CA");
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca = CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap();
        Self { ca }
    }

    pub fn ca_pem(&self) -> String {
        self.ca.pem()
    }

    pub fn server(&self) -> (String, String) {
        let mut params =
            CertificateParams::new(vec!["localhost".to_owned(), "127.0.0.1".to_owned()]).unwrap();
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        self.issue(params)
    }

    pub fn client(&self, uri: &str) -> (String, String) {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.subject_alt_names = vec![SanType::URI(uri.try_into().unwrap())];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        self.issue(params)
    }

    fn issue(&self, mut params: CertificateParams) -> (String, String) {
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let key = KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &self.ca).unwrap();
        (cert.pem(), key.serialize_pem())
    }
}

pub struct TestVault {
    pub addr: SocketAddr,
    pub pool: PgPool,
    pub audit: Arc<MemoryAuditSink>,
    pub pki: Pki,
    shutdown: Option<oneshot::Sender<()>>,
    _postgres: ContainerAsync<Postgres>,
}

impl TestVault {
    pub async fn start() -> Self {
        let postgres = Postgres::default()
            .with_tag(POSTGRES_TAG)
            .start()
            .await
            .expect("cannot start PostgreSQL container; is Docker running?");
        let port = postgres.get_host_port_ipv4(5432).await.unwrap();
        let pool = PgPoolOptions::new()
            .max_connections(16)
            .connect(&format!(
                "postgres://postgres:postgres@127.0.0.1:{port}/postgres"
            ))
            .await
            .unwrap();
        MIGRATOR.run(&pool).await.unwrap();

        let master_key = MasterKey::from_key_bytes(&[42; 32]).unwrap();
        let store = KeyStore::new(pool.clone());
        store.register_kek(master_key.kek_id()).await.unwrap();

        let pki = Pki::new();
        let (cert, key) = pki.server();
        let tls = TlsMaterial::from_pem(cert.into(), key.into(), pki.ca_pem().into());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let audit = Arc::new(MemoryAuditSink::default());
        let components = Components {
            store,
            master_key: Arc::new(master_key),
            policy: Arc::new(AuthzPolicy::from_toml(POLICY).unwrap()),
            audit: audit.clone(),
        };
        let (shutdown, stopped) = oneshot::channel::<()>();
        tokio::spawn(async move {
            let options = ServeOptions {
                enable_reflection: true,
            };
            serve(listener, components, &tls, options, async {
                let _ = stopped.await;
            })
            .await
            .expect("vault server failed");
        });

        Self {
            addr,
            pool,
            audit,
            pki,
            shutdown: Some(shutdown),
            _postgres: postgres,
        }
    }

    fn endpoint(&self) -> String {
        format!("https://127.0.0.1:{}", self.addr.port())
    }

    fn tls_base(&self) -> ClientTlsConfig {
        ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(self.pki.ca_pem()))
            .domain_name("localhost")
    }

    pub async fn channel(&self, principal: &str) -> Channel {
        let (cert, key) = self.pki.client(principal);
        Channel::from_shared(self.endpoint())
            .unwrap()
            .tls_config(self.tls_base().identity(Identity::from_pem(cert, key)))
            .unwrap()
            .connect()
            .await
            .unwrap()
    }

    pub async fn client(&self, principal: &str) -> VaultServiceClient<Channel> {
        VaultServiceClient::new(self.channel(principal).await)
    }

    /// A client presenting no certificate at all.
    pub async fn anonymous_client(
        &self,
    ) -> Result<VaultServiceClient<Channel>, tonic::transport::Error> {
        let channel = Channel::from_shared(self.endpoint())
            .unwrap()
            .tls_config(self.tls_base())?
            .connect()
            .await?;
        Ok(VaultServiceClient::new(channel))
    }
}

impl Drop for TestVault {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
    }
}

// Request builders. The generated types that carry secrets implement Drop,
// which rules out struct-update syntax.

pub fn create_request(
    tenant: Uuid,
    provider: Provider,
    label: &str,
    secret: &str,
) -> CreateKeyRequest {
    let mut request = CreateKeyRequest::default();
    request.tenant_id = tenant.to_string();
    request.provider = provider.into();
    request.label = label.to_owned();
    request.secret = secret.as_bytes().to_vec();
    request
}

pub fn get_by_id(tenant: Uuid, key_id: &str) -> GetDecryptedKeyRequest {
    GetDecryptedKeyRequest {
        tenant_id: tenant.to_string(),
        selector: Some(Selector::KeyId(key_id.to_owned())),
    }
}

pub fn get_by_provider(tenant: Uuid, provider: Provider) -> GetDecryptedKeyRequest {
    GetDecryptedKeyRequest {
        tenant_id: tenant.to_string(),
        selector: Some(Selector::Provider(provider.into())),
    }
}

pub fn revoke_request(tenant: Uuid, key_id: &str, reason: RevocationReason) -> RevokeKeyRequest {
    RevokeKeyRequest {
        tenant_id: tenant.to_string(),
        key_id: key_id.to_owned(),
        reason: reason.into(),
    }
}

/// `google.rpc.ErrorInfo.reason` attached to a status, if any.
pub fn error_reason(status: &Status) -> Option<String> {
    status.get_details_error_info().map(|info| info.reason)
}
