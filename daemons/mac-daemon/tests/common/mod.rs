//! Test harness: a real daemon (config file, PKI, sandbox) served over mTLS
//! on an ephemeral loopback port, plus an approver key.

#![allow(clippy::unwrap_used, clippy::expect_used, dead_code)]

use std::{
    fs,
    net::SocketAddr,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::Arc,
};

use base64::Engine;
use jarvis_common::mtls::TlsMaterial;
use jarvis_daemon::{
    approval::signed_message,
    config::Config,
    proto::device_v1::{
        Approval, ApprovalRequired, ExecuteCommandRequest,
        device_service_client::DeviceServiceClient,
    },
    server::{ServeOptions, serve},
    service::DaemonState,
};
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    elliptic_curve::Generate,
};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType,
};
use tokio::{net::TcpListener, sync::oneshot};
use tonic::{
    Status,
    transport::{Certificate, Channel, ClientTlsConfig, Identity},
};
use tonic_types::StatusExt;

pub const ORCHESTRATOR: &str = "spiffe://jarvis.test/orchestrator";
pub const OBSERVER: &str = "spiffe://jarvis.test/observer";
pub const APPROVER_ID: &str = "test-phone";

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
        Self {
            ca: CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap(),
        }
    }

    pub fn ca_pem(&self) -> String {
        self.ca.pem()
    }

    fn issue(
        &self,
        mut params: CertificateParams,
        usage: ExtendedKeyUsagePurpose,
    ) -> (String, String) {
        params.extended_key_usages = vec![usage];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let key = KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &self.ca).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    pub fn server(&self) -> (String, String) {
        let params =
            CertificateParams::new(vec!["localhost".to_owned(), "127.0.0.1".to_owned()]).unwrap();
        self.issue(params, ExtendedKeyUsagePurpose::ServerAuth)
    }

    pub fn client(&self, uri: &str) -> (String, String) {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.subject_alt_names = vec![SanType::URI(uri.try_into().unwrap())];
        self.issue(params, ExtendedKeyUsagePurpose::ClientAuth)
    }
}

#[derive(Clone, Copy)]
pub struct Options {
    pub with_approver: bool,
    pub max_concurrent: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            with_approver: true,
            max_concurrent: 4,
        }
    }
}

pub struct TestDaemon {
    pub addr: SocketAddr,
    pub base: PathBuf,
    pub workspace: PathBuf,
    pub protected: PathBuf,
    pub approver: SigningKey,
    pki: Pki,
    shutdown: Option<oneshot::Sender<()>>,
}

fn write_private(path: &Path, contents: &str, mode: u32) {
    fs::write(path, contents).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

impl TestDaemon {
    pub async fn start(options: Options) -> Self {
        let base = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("jarvisd-e2e-{}", uuid::Uuid::new_v4()));
        let config_dir = base.join("config");
        let workspace = base.join("workspace");
        let protected = workspace.join("private");
        for dir in [config_dir.join("tls"), protected.clone(), base.join("tmp")] {
            fs::create_dir_all(dir).unwrap();
        }
        fs::write(workspace.join("readme.txt"), "hello from the workspace").unwrap();

        let pki = Pki::new();
        let (cert, key) = pki.server();
        write_private(&config_dir.join("tls/server.pem"), &cert, 0o644);
        write_private(&config_dir.join("tls/server-key.pem"), &key, 0o600);
        write_private(&config_dir.join("tls/ca.pem"), &pki.ca_pem(), 0o644);

        let approver = SigningKey::try_generate().unwrap();
        let approver_entry = if options.with_approver {
            format!(
                "[[approver]]\nid = \"{APPROVER_ID}\"\npublic_key = \"{}\"\n",
                base64::engine::general_purpose::STANDARD
                    .encode(approver.verifying_key().to_sec1_bytes())
            )
        } else {
            String::new()
        };

        let tls = config_dir.join("tls");
        let config = format!(
            r#"
device_name = "Test Mac"

[network]
mode = "loopback"

[tls]
cert = "{tls}/server.pem"
key = "{tls}/server-key.pem"
client_ca = "{tls}/ca.pem"

[[principal]]
id = "{ORCHESTRATOR}"
allow = ["GetCapabilities", "ExecuteCommand"]

[[principal]]
id = "{OBSERVER}"
allow = ["GetCapabilities"]

{approver_entry}
[sandbox]
workspace_roots = ["{workspace}"]
protected_paths = ["{protected}"]

[limits]
max_concurrent_commands = {max_concurrent}
approval_ttl_secs = 60

[[command]]
program = "/bin/echo"
args_prefix = ["hello"]
allow_extra_args = true
description = "Say hello"

[[command]]
program = "/bin/sleep"
allow_extra_args = true
description = "Wait"
"#,
            tls = tls.display(),
            workspace = workspace.display(),
            protected = protected.display(),
            max_concurrent = options.max_concurrent,
        );
        let config_path = config_dir.join("daemon.toml");
        write_private(&config_path, &config, 0o600);

        let config = Config::load(config_path.to_str().unwrap()).expect("test config must load");
        let tls =
            TlsMaterial::load(&config.tls.cert, &config.tls.key, &config.tls.client_ca).unwrap();
        let state = Arc::new(DaemonState::new(
            config,
            base.join("tmp"),
            PathBuf::from(std::env::var_os("HOME").unwrap()),
            std::env::var("USER").unwrap_or_else(|_| "tester".into()),
        ));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (shutdown, stopped) = oneshot::channel::<()>();
        tokio::spawn(async move {
            serve(listener, state, &tls, ServeOptions::default(), async {
                let _ = stopped.await;
            })
            .await
            .expect("daemon server failed");
        });

        Self {
            addr,
            base,
            workspace,
            protected,
            approver,
            pki,
            shutdown: Some(shutdown),
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

    pub async fn client(&self, principal: &str) -> DeviceServiceClient<Channel> {
        DeviceServiceClient::new(self.channel(principal).await)
            .max_decoding_message_size(64 * 1024 * 1024)
    }

    pub async fn anonymous_client(
        &self,
    ) -> Result<DeviceServiceClient<Channel>, tonic::transport::Error> {
        let channel = Channel::from_shared(self.endpoint())
            .unwrap()
            .tls_config(self.tls_base())?
            .connect()
            .await?;
        Ok(DeviceServiceClient::new(channel))
    }

    /// Signs an approval request with the configured approver key.
    pub fn approve(&self, required: &ApprovalRequired) -> Approval {
        sign_with(&self.approver, APPROVER_ID, required)
    }
}

impl Drop for TestDaemon {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let _ = fs::remove_dir_all(&self.base);
    }
}

pub fn sign_with(key: &SigningKey, approver_id: &str, required: &ApprovalRequired) -> Approval {
    let signature: Signature = key.sign(&signed_message(&required.payload));
    Approval {
        approval_id: required.approval_id.clone(),
        approver_id: approver_id.to_owned(),
        signature: signature.to_bytes().to_vec(),
    }
}

pub fn command(program: &str, args: &[&str]) -> ExecuteCommandRequest {
    ExecuteCommandRequest {
        program: program.to_owned(),
        args: args.iter().map(|s| (*s).to_owned()).collect(),
        ..ExecuteCommandRequest::default()
    }
}

pub fn error_reason(status: &Status) -> Option<String> {
    status.get_details_error_info().map(|info| info.reason)
}
