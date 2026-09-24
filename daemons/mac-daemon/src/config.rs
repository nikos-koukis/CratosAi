//! Daemon configuration: one TOML file, validated in full at startup.
//!
//! The daemon refuses to start if the file (or the TLS private key) could be
//! changed or read by another user, if any path is not absolute, or if an
//! allowlisted program is missing or on the deny list. The directory holding
//! the configuration and every TLS file is always a protected path, so no
//! command can read the keys or rewrite its own allowlist.

use std::{
    collections::HashSet,
    env, fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::Duration,
};

use jarvis_common::authz::{AuthzPolicy, PrincipalGrant};
use serde::Deserialize;

use crate::{
    approval::Approvers,
    policy::{CommandPolicy, CommandRule, Grants},
    service::Rpc,
};

pub const DEFAULT_CONFIG_PATH: &str = "~/Library/Application Support/Jarvis/daemon/daemon.toml";

/// Credential stores and private data no command may touch (relative to $HOME).
const PROTECTED_HOME_PATHS: &[&str] = &[
    ".ssh",
    ".gnupg",
    ".aws",
    ".azure",
    ".kube",
    ".docker",
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".git-credentials",
    ".password-store",
    ".config/gcloud",
    ".config/gh",
    ".config/jarvis",
    "Library/Keychains",
    "Library/Cookies",
    "Library/Mail",
    "Library/Messages",
    "Library/Safari",
    "Library/Application Support/Google/Chrome",
    "Library/Application Support/Firefox",
    "Library/Application Support/Jarvis",
];

/// Privilege, persistence and credential tools that never run, even approved.
const DENIED_PROGRAMS: &[&str] = &[
    "/usr/bin/sudo",
    "/usr/bin/su",
    "/usr/bin/login",
    "/usr/bin/security",
    "/usr/bin/sandbox-exec",
    "/bin/launchctl",
    "/usr/bin/crontab",
    "/usr/bin/dscl",
    "/usr/bin/csrutil",
    "/usr/bin/tccutil",
    "/usr/bin/profiles",
    "/usr/sbin/sysadminctl",
    "/usr/sbin/spctl",
    "/usr/sbin/systemsetup",
];

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read {path}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot parse the configuration")]
    Parse(#[from] toml::de::Error),
    #[error("{0}")]
    Invalid(String),
    #[error("refusing insecure {0}")]
    Insecure(String),
}

fn invalid(message: impl Into<String>) -> ConfigError {
    ConfigError::Invalid(message.into())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkMode {
    /// Listen on this Mac's Tailscale address only.
    Tailscale,
    /// Listen on 127.0.0.1 only (development and tests).
    Loopback,
}

#[derive(Clone, Copy, Debug)]
pub struct Network {
    pub mode: NetworkMode,
    pub port: u16,
    /// gRPC server reflection, for grpcurl during development.
    pub reflection: bool,
}

#[derive(Clone, Debug)]
pub struct TlsPaths {
    pub cert: PathBuf,
    pub key: PathBuf,
    pub client_ca: PathBuf,
}

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub default_timeout: Duration,
    pub max_timeout: Duration,
    pub max_output_bytes: usize,
    pub max_concurrent: usize,
    pub approval_ttl: Duration,
    pub max_pending_approvals: usize,
}

#[derive(Debug)]
pub struct Config {
    pub config_path: PathBuf,
    pub device_name: String,
    pub network: Network,
    pub tls: TlsPaths,
    pub authz: AuthzPolicy<Rpc>,
    pub approvers: Approvers,
    pub policy: CommandPolicy,
    pub limits: Limits,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    device_name: String,
    network: RawNetwork,
    tls: RawTls,
    #[serde(default, rename = "principal")]
    principals: Vec<PrincipalGrant<Rpc>>,
    #[serde(default, rename = "approver")]
    approvers: Vec<RawApprover>,
    sandbox: RawSandbox,
    #[serde(default)]
    limits: RawLimits,
    #[serde(default, rename = "command")]
    commands: Vec<RawCommand>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawNetwork {
    mode: NetworkMode,
    #[serde(default = "default_port")]
    port: u16,
    #[serde(default)]
    reflection: bool,
}

const fn default_port() -> u16 {
    7443
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTls {
    cert: String,
    key: String,
    client_ca: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawApprover {
    id: String,
    public_key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSandbox {
    workspace_roots: Vec<String>,
    #[serde(default)]
    protected_paths: Vec<String>,
    #[serde(default)]
    denied_programs: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, default)]
struct RawLimits {
    default_timeout_secs: u64,
    max_timeout_secs: u64,
    max_output_bytes: usize,
    max_concurrent_commands: usize,
    approval_ttl_secs: u64,
    max_pending_approvals: usize,
}

impl Default for RawLimits {
    fn default() -> Self {
        Self {
            default_timeout_secs: 30,
            max_timeout_secs: 300,
            max_output_bytes: 1024 * 1024,
            max_concurrent_commands: 4,
            approval_ttl_secs: 300,
            max_pending_approvals: 32,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCommand {
    program: String,
    #[serde(default)]
    args_prefix: Vec<String>,
    #[serde(default)]
    allow_extra_args: bool,
    #[serde(default)]
    writable: bool,
    #[serde(default)]
    network: bool,
    #[serde(default)]
    system_services: bool,
    #[serde(default)]
    requires_approval: bool,
    #[serde(default)]
    description: String,
}

impl Config {
    /// Loads and validates the configuration file at `path` (`~` allowed).
    pub fn load(path: &str) -> Result<Self, ConfigError> {
        let home = home_dir()?;
        let config_path = expand(path, &home)?;
        check_owned_and_protected(&config_path, "configuration file", 0o022)?;
        let text = fs::read_to_string(&config_path).map_err(|source| ConfigError::Read {
            path: config_path.clone(),
            source,
        })?;
        let raw: RawConfig = toml::from_str(&text)?;
        Self::from_raw(raw, config_path, &home)
    }

    fn from_raw(raw: RawConfig, config_path: PathBuf, home: &Path) -> Result<Self, ConfigError> {
        let device_name = raw.device_name.trim().to_owned();
        if device_name.is_empty() || device_name.chars().count() > 64 {
            return Err(invalid("device_name must be 1 to 64 characters"));
        }

        let tls = TlsPaths {
            cert: expand(&raw.tls.cert, home)?,
            key: expand(&raw.tls.key, home)?,
            client_ca: expand(&raw.tls.client_ca, home)?,
        };
        check_owned_and_protected(&tls.key, "TLS private key", 0o077)?;

        let authz = AuthzPolicy::from_grants(raw.principals)
            .map_err(|e| invalid(format!("[[principal]]: {e}")))?;

        let mut approvers = Approvers::default();
        for approver in &raw.approvers {
            approvers
                .insert(&approver.id, &approver.public_key)
                .map_err(|e| invalid(format!("[[approver]]: {e}")))?;
        }

        let policy = build_policy(raw.sandbox, raw.commands, &config_path, &tls, home)?;
        let limits = build_limits(&raw.limits)?;

        Ok(Self {
            config_path,
            device_name,
            network: Network {
                mode: raw.network.mode,
                port: raw.network.port,
                reflection: raw.network.reflection,
            },
            tls,
            authz,
            approvers,
            policy,
            limits,
        })
    }
}

fn build_policy(
    sandbox: RawSandbox,
    commands: Vec<RawCommand>,
    config_path: &Path,
    tls: &TlsPaths,
    home: &Path,
) -> Result<CommandPolicy, ConfigError> {
    if sandbox.workspace_roots.is_empty() {
        return Err(invalid(
            "sandbox.workspace_roots must list at least one directory",
        ));
    }
    let mut workspace_roots = Vec::new();
    for root in &sandbox.workspace_roots {
        let path = canonical_dir(&expand(root, home)?, "workspace root")?;
        if path == Path::new("/") {
            return Err(invalid("sandbox.workspace_roots must not include /"));
        }
        workspace_roots.push(path);
    }

    let mut protected_paths: Vec<PathBuf> = PROTECTED_HOME_PATHS
        .iter()
        .map(|relative| home.join(relative))
        .collect();
    for file in [config_path, &tls.cert, &tls.key, &tls.client_ca] {
        if let Some(parent) = file.parent() {
            protected_paths.push(parent.to_owned());
        }
    }
    for extra in &sandbox.protected_paths {
        protected_paths.push(expand(extra, home)?);
    }
    let mut protected_paths: Vec<PathBuf> = protected_paths
        .into_iter()
        .map(|path| fs::canonicalize(&path).unwrap_or(path))
        .collect();
    protected_paths.sort();
    protected_paths.dedup();
    for root in &workspace_roots {
        if let Some(path) = protected_paths.iter().find(|path| root.starts_with(path)) {
            return Err(invalid(format!(
                "workspace root {} is inside protected path {}",
                root.display(),
                path.display()
            )));
        }
    }

    let mut denied_programs = HashSet::new();
    for program in DENIED_PROGRAMS
        .iter()
        .map(|p| (*p).to_owned())
        .chain(sandbox.denied_programs)
    {
        let path = expand(&program, home)?;
        denied_programs.insert(fs::canonicalize(&path).unwrap_or(path));
    }

    let mut rules = Vec::new();
    for command in commands {
        let program =
            CommandPolicy::resolve_program(&expand(&command.program, home)?.to_string_lossy())
                .map_err(|e| invalid(format!("[[command]] {}: {e}", command.program)))?;
        if denied_programs.contains(&program) {
            return Err(invalid(format!(
                "[[command]] {} is on the deny list",
                command.program
            )));
        }
        rules.push(CommandRule {
            program,
            args_prefix: command.args_prefix,
            allow_extra_args: command.allow_extra_args,
            grants: Grants {
                writable: command.writable,
                network: command.network,
                system_services: command.system_services,
            },
            requires_approval: command.requires_approval,
            description: command.description,
        });
    }

    Ok(CommandPolicy {
        workspace_roots,
        protected_paths,
        denied_programs,
        rules,
    })
}

fn build_limits(raw: &RawLimits) -> Result<Limits, ConfigError> {
    let check = |ok: bool, message: &str| if ok { Ok(()) } else { Err(invalid(message)) };
    check(
        (1..=3600).contains(&raw.max_timeout_secs),
        "limits.max_timeout_secs must be 1 to 3600",
    )?;
    check(
        (1..=raw.max_timeout_secs).contains(&raw.default_timeout_secs),
        "limits.default_timeout_secs must be 1 to max_timeout_secs",
    )?;
    check(
        (1024..=16 * 1024 * 1024).contains(&raw.max_output_bytes),
        "limits.max_output_bytes must be 1 KiB to 16 MiB",
    )?;
    check(
        (1..=64).contains(&raw.max_concurrent_commands),
        "limits.max_concurrent_commands must be 1 to 64",
    )?;
    check(
        (10..=3600).contains(&raw.approval_ttl_secs),
        "limits.approval_ttl_secs must be 10 to 3600",
    )?;
    check(
        (1..=1000).contains(&raw.max_pending_approvals),
        "limits.max_pending_approvals must be 1 to 1000",
    )?;
    Ok(Limits {
        default_timeout: Duration::from_secs(raw.default_timeout_secs),
        max_timeout: Duration::from_secs(raw.max_timeout_secs),
        max_output_bytes: raw.max_output_bytes,
        max_concurrent: raw.max_concurrent_commands,
        approval_ttl: Duration::from_secs(raw.approval_ttl_secs),
        max_pending_approvals: raw.max_pending_approvals,
    })
}

fn home_dir() -> Result<PathBuf, ConfigError> {
    env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|home| home.is_absolute())
        .ok_or_else(|| invalid("HOME is not set to an absolute path"))
}

/// Expands a leading `~/` and requires the result to be absolute.
fn expand(path: &str, home: &Path) -> Result<PathBuf, ConfigError> {
    let expanded = match path.strip_prefix("~/") {
        Some(rest) => home.join(rest),
        None if path == "~" => home.to_owned(),
        None => PathBuf::from(path),
    };
    if expanded.is_absolute() {
        Ok(expanded)
    } else {
        Err(invalid(format!(
            "path {path:?} must be absolute or start with ~/"
        )))
    }
}

fn canonical_dir(path: &Path, what: &str) -> Result<PathBuf, ConfigError> {
    let canonical = fs::canonicalize(path)
        .map_err(|_| invalid(format!("{what} {} does not exist", path.display())))?;
    if canonical.is_dir() {
        Ok(canonical)
    } else {
        Err(invalid(format!(
            "{what} {} is not a directory",
            path.display()
        )))
    }
}

/// The file must belong to the current user and have none of `forbidden_mode`
/// bits set (e.g. 0o022: not writable by group or others).
fn check_owned_and_protected(
    path: &Path,
    what: &str,
    forbidden_mode: u32,
) -> Result<(), ConfigError> {
    let metadata = fs::metadata(path).map_err(|source| ConfigError::Read {
        path: path.to_owned(),
        source,
    })?;
    if metadata.uid() != rustix::process::getuid().as_raw() {
        return Err(ConfigError::Insecure(format!(
            "{what} {}: it is not owned by the current user",
            path.display()
        )));
    }
    if metadata.mode() & forbidden_mode != 0 {
        return Err(ConfigError::Insecure(format!(
            "{what} {}: permissions {:o} are too open (run: chmod {} {})",
            path.display(),
            metadata.mode() & 0o777,
            if forbidden_mode == 0o077 {
                "600"
            } else {
                "644"
            },
            path.display()
        )));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    struct Fixture {
        dir: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = fs::canonicalize(env::temp_dir())
                .unwrap()
                .join(format!("jarvisd-config-{}", uuid::Uuid::new_v4()));
            fs::create_dir_all(dir.join("workspace")).unwrap();
            fs::create_dir_all(dir.join("config/tls")).unwrap();
            for (name, mode) in [
                ("server.pem", 0o644),
                ("server-key.pem", 0o600),
                ("ca.pem", 0o644),
            ] {
                let file = dir.join("config/tls").join(name);
                fs::write(&file, "pem").unwrap();
                fs::set_permissions(&file, fs::Permissions::from_mode(mode)).unwrap();
            }
            Self { dir }
        }

        fn write(&self, body: &str, mode: u32) -> String {
            let dir = self.dir.display();
            let text = format!(
                r#"
                device_name = "Test Mac"
                [network]
                mode = "loopback"
                [tls]
                cert = "{dir}/config/tls/server.pem"
                key = "{dir}/config/tls/server-key.pem"
                client_ca = "{dir}/config/tls/ca.pem"
                [[principal]]
                id = "spiffe://jarvis.test/orchestrator"
                allow = ["GetCapabilities", "ExecuteCommand"]
                [sandbox]
                workspace_roots = ["{dir}/workspace"]
                {body}
                "#
            );
            let path = self.dir.join("config/daemon.toml");
            fs::write(&path, text).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            path.display().to_string()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn a_valid_config_loads_with_protections_added() {
        let fixture = Fixture::new();
        let path = fixture.write(
            r#"
            [[command]]
            program = "/usr/bin/git"
            args_prefix = ["status"]
            allow_extra_args = true
            "#,
            0o600,
        );
        let config = Config::load(&path).unwrap();
        assert_eq!(config.network.port, 7443);
        assert_eq!(config.policy.rules.len(), 1);
        assert_eq!(config.limits.max_concurrent, 4);
        assert!(
            config
                .policy
                .protected_paths
                .contains(&fixture.dir.join("config")),
            "config directory is protected"
        );
        assert!(
            config
                .policy
                .protected_paths
                .contains(&fixture.dir.join("config/tls")),
            "TLS directory is protected"
        );
        assert!(
            config
                .policy
                .denied_programs
                .contains(Path::new("/usr/bin/sudo"))
        );
    }

    #[test]
    fn insecure_permissions_are_refused() {
        let fixture = Fixture::new();
        let path = fixture.write("", 0o666);
        assert!(matches!(Config::load(&path), Err(ConfigError::Insecure(_))));

        let path = fixture.write("", 0o600);
        fs::set_permissions(
            fixture.dir.join("config/tls/server-key.pem"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(matches!(Config::load(&path), Err(ConfigError::Insecure(_))));
    }

    #[test]
    fn invalid_entries_are_refused() {
        let cases = [
            "[[command]]\nprogram = \"git\"",
            "[[command]]\nprogram = \"/no/such/program\"",
            "[[command]]\nprogram = \"/usr/bin/sudo\"",
            "[[approver]]\nid = \"phone\"\npublic_key = \"AAAA\"",
            "[limits]\ndefault_timeout_secs = 600",
            "[limits]\nmax_output_bytes = 10",
            "unknown_setting = true",
            "protected_paths = [\"WORKSPACE\"]",
        ];
        for body in cases {
            let fixture = Fixture::new();
            let body = body.replace(
                "WORKSPACE",
                &fixture.dir.join("workspace").display().to_string(),
            );
            let path = fixture.write(&body, 0o600);
            assert!(Config::load(&path).is_err(), "accepted: {body}");
        }
    }
}
