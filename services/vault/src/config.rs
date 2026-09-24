//! Runtime configuration from `VAULT_*` environment variables.
//!
//! Secrets can instead be supplied as a file path in `<NAME>_FILE` (Docker or
//! Kubernetes secret mounts), which keeps them out of the process environment.
//! Empty variables count as unset.

use std::{
    env::{self, VarError},
    fmt, fs,
    net::SocketAddr,
    path::PathBuf,
};

use base64::Engine;
use zeroize::Zeroizing;

const DEFAULT_LISTEN_ADDR: &str = "0.0.0.0:50051";
const DEFAULT_DB_MAX_CONNECTIONS: u32 = 16;
const MAX_DB_MAX_CONNECTIONS: u32 = 1_000;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("{0} is required")]
    Missing(String),
    #[error("{name} {reason}")]
    Invalid { name: String, reason: String },
}

impl ConfigError {
    fn invalid(name: &str, reason: impl Into<String>) -> Self {
        Self::Invalid {
            name: name.to_owned(),
            reason: reason.into(),
        }
    }
}

/// A string that is zeroized on drop and never printed.
#[derive(Clone)]
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[derive(Clone, Debug)]
pub struct TlsPaths {
    /// PEM certificate chain the server presents.
    pub cert: PathBuf,
    /// PEM private key for `cert`.
    pub key: PathBuf,
    /// PEM CA bundle that client certificates must chain to.
    pub client_ca: PathBuf,
}

/// Where the Vault records its audit events (the audit service), with its
/// own client identity (spiffe://jarvis.local/vault).
#[derive(Clone, Debug)]
pub struct AuditTarget {
    /// host:port of the audit service.
    pub addr: String,
    /// The name its certificate is checked against.
    pub server_name: String,
    pub cert: PathBuf,
    pub key: PathBuf,
    /// CA the audit service's certificate chains to.
    pub ca: PathBuf,
}

#[derive(Debug)]
pub struct Config {
    pub listen_addr: SocketAddr,
    pub database_url: SecretString,
    pub database_max_connections: u32,
    pub run_migrations: bool,
    pub master_passphrase: SecretString,
    pub master_salt: Vec<u8>,
    pub tls: TlsPaths,
    pub authz_policy_path: PathBuf,
    pub enable_reflection: bool,
    /// None: audit events only go to the log.
    pub audit: Option<AuditTarget>,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|name| match env::var(name) {
            Ok(value) => Ok(Some(value)),
            Err(VarError::NotPresent) => Ok(None),
            Err(VarError::NotUnicode(_)) => Err(ConfigError::invalid(name, "is not valid UTF-8")),
        })
    }

    pub fn from_lookup(
        lookup: impl Fn(&str) -> Result<Option<String>, ConfigError>,
    ) -> Result<Self, ConfigError> {
        let vars = Vars(&lookup);
        Ok(Self {
            listen_addr: vars
                .optional("VAULT_LISTEN_ADDR")?
                .as_deref()
                .unwrap_or(DEFAULT_LISTEN_ADDR)
                .parse()
                .map_err(|_| {
                    ConfigError::invalid(
                        "VAULT_LISTEN_ADDR",
                        "must be host:port, e.g. 0.0.0.0:50051",
                    )
                })?,
            database_url: vars.secret("VAULT_DATABASE_URL")?,
            database_max_connections: vars.max_connections()?,
            run_migrations: vars.bool("VAULT_RUN_MIGRATIONS", true)?,
            master_passphrase: vars.secret("VAULT_MASTER_PASSPHRASE")?,
            master_salt: vars.salt()?,
            tls: TlsPaths {
                cert: vars.required("VAULT_TLS_CERT")?.into(),
                key: vars.required("VAULT_TLS_KEY")?.into(),
                client_ca: vars.required("VAULT_TLS_CLIENT_CA")?.into(),
            },
            authz_policy_path: vars.required("VAULT_AUTHZ_POLICY")?.into(),
            enable_reflection: vars.bool("VAULT_ENABLE_REFLECTION", false)?,
            audit: vars.audit()?,
        })
    }
}

struct Vars<'a, F>(&'a F);

impl<F> Vars<'_, F>
where
    F: Fn(&str) -> Result<Option<String>, ConfigError>,
{
    fn optional(&self, name: &str) -> Result<Option<String>, ConfigError> {
        Ok((self.0)(name)?.filter(|value| !value.is_empty()))
    }

    fn required(&self, name: &str) -> Result<String, ConfigError> {
        self.optional(name)?
            .ok_or_else(|| ConfigError::Missing(name.to_owned()))
    }

    /// Reads `NAME` or the file named by `NAME_FILE` (exactly one of them).
    fn secret(&self, name: &str) -> Result<SecretString, ConfigError> {
        let file_var = format!("{name}_FILE");
        let inline = self.optional(name)?.map(Zeroizing::new);
        match (inline, self.optional(&file_var)?) {
            (Some(_), Some(_)) => Err(ConfigError::invalid(
                name,
                format!("and {file_var} are both set; use only one"),
            )),
            (Some(value), None) => Ok(SecretString(value)),
            (None, Some(path)) => {
                let mut contents = Zeroizing::new(fs::read_to_string(&path).map_err(|e| {
                    ConfigError::invalid(&file_var, format!("cannot be read ({path}): {e}"))
                })?);
                let trimmed = contents.trim_end_matches(['\r', '\n']).len();
                contents.truncate(trimmed);
                if contents.is_empty() {
                    return Err(ConfigError::invalid(
                        &file_var,
                        format!("points to an empty file ({path})"),
                    ));
                }
                Ok(SecretString(contents))
            }
            (None, None) => Err(ConfigError::Missing(format!("{name} or {file_var}"))),
        }
    }

    /// The audit service, when VAULT_AUDIT_ADDR is set; its certificate and
    /// key are then required, and the CA defaults to the client CA.
    fn audit(&self) -> Result<Option<AuditTarget>, ConfigError> {
        let Some(addr) = self.optional("VAULT_AUDIT_ADDR")? else {
            return Ok(None);
        };
        let host = addr
            .rsplit_once(':')
            .filter(|(host, port)| !host.is_empty() && port.parse::<u16>().is_ok())
            .map(|(host, _)| host.to_owned())
            .ok_or_else(|| ConfigError::invalid("VAULT_AUDIT_ADDR", "must be host:port"))?;
        Ok(Some(AuditTarget {
            server_name: self.optional("VAULT_AUDIT_SERVER_NAME")?.unwrap_or(host),
            addr,
            cert: self.required("VAULT_AUDIT_TLS_CERT")?.into(),
            key: self.required("VAULT_AUDIT_TLS_KEY")?.into(),
            ca: match self.optional("VAULT_AUDIT_CA")? {
                Some(ca) => ca.into(),
                None => self.required("VAULT_TLS_CLIENT_CA")?.into(),
            },
        }))
    }

    fn bool(&self, name: &str, default: bool) -> Result<bool, ConfigError> {
        match self.optional(name)?.as_deref() {
            None => Ok(default),
            Some("true" | "1") => Ok(true),
            Some("false" | "0") => Ok(false),
            Some(_) => Err(ConfigError::invalid(name, "must be true or false")),
        }
    }

    fn max_connections(&self) -> Result<u32, ConfigError> {
        const NAME: &str = "VAULT_DATABASE_MAX_CONNECTIONS";
        match self.optional(NAME)? {
            None => Ok(DEFAULT_DB_MAX_CONNECTIONS),
            Some(raw) => raw
                .parse::<u32>()
                .ok()
                .filter(|n| (1..=MAX_DB_MAX_CONNECTIONS).contains(n))
                .ok_or_else(|| {
                    ConfigError::invalid(
                        NAME,
                        format!("must be between 1 and {MAX_DB_MAX_CONNECTIONS}"),
                    )
                }),
        }
    }

    fn salt(&self) -> Result<Vec<u8>, ConfigError> {
        const NAME: &str = "VAULT_MASTER_SALT";
        let salt = base64::engine::general_purpose::STANDARD
            .decode(self.required(NAME)?)
            .map_err(|_| ConfigError::invalid(NAME, "must be standard base64"))?;
        if salt.len() < crate::crypto::MIN_SALT_LEN {
            return Err(ConfigError::invalid(
                NAME,
                format!(
                    "must decode to at least {} bytes",
                    crate::crypto::MIN_SALT_LEN
                ),
            ));
        }
        Ok(salt)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    const SALT_B64: &str = "c2FsdC1zYWx0LXNhbHQtc2FsdA=="; // "salt-salt-salt-salt"

    fn base() -> HashMap<&'static str, String> {
        HashMap::from([
            (
                "VAULT_DATABASE_URL",
                "postgres://vault:pw@db/vault".to_owned(),
            ),
            ("VAULT_MASTER_PASSPHRASE", "p".repeat(40)),
            ("VAULT_MASTER_SALT", SALT_B64.to_owned()),
            ("VAULT_TLS_CERT", "/tls/server.pem".to_owned()),
            ("VAULT_TLS_KEY", "/tls/server-key.pem".to_owned()),
            ("VAULT_TLS_CLIENT_CA", "/tls/ca.pem".to_owned()),
            ("VAULT_AUTHZ_POLICY", "/etc/vault/authz.toml".to_owned()),
        ])
    }

    fn load(vars: &HashMap<&'static str, String>) -> Result<Config, ConfigError> {
        Config::from_lookup(|name| Ok(vars.get(name).cloned()))
    }

    #[test]
    fn minimal_config_uses_defaults() {
        let config = load(&base()).unwrap();
        assert_eq!(config.listen_addr, DEFAULT_LISTEN_ADDR.parse().unwrap());
        assert_eq!(config.database_max_connections, DEFAULT_DB_MAX_CONNECTIONS);
        assert!(config.run_migrations);
        assert!(!config.enable_reflection);
        assert_eq!(config.master_salt, b"salt-salt-salt-salt");
    }

    #[test]
    fn debug_output_redacts_secrets() {
        let rendered = format!("{:?}", load(&base()).unwrap());
        assert!(!rendered.contains("pw@db"), "{rendered}");
        assert!(!rendered.contains(&"p".repeat(40)), "{rendered}");
        assert!(rendered.contains("[REDACTED]"));
    }

    #[test]
    fn missing_and_invalid_values_are_reported_by_name() {
        let mut vars = base();
        vars.remove("VAULT_TLS_CERT");
        assert!(matches!(load(&vars), Err(ConfigError::Missing(n)) if n == "VAULT_TLS_CERT"));

        let cases = [
            ("VAULT_LISTEN_ADDR", "localhost"),
            ("VAULT_DATABASE_MAX_CONNECTIONS", "0"),
            ("VAULT_RUN_MIGRATIONS", "yes"),
            ("VAULT_MASTER_SALT", "c2hvcnQ="),
            ("VAULT_MASTER_SALT", "***"),
        ];
        for (name, value) in cases {
            let mut vars = base();
            vars.insert(name, value.to_owned());
            match load(&vars) {
                Err(ConfigError::Invalid { name: got, .. }) => assert_eq!(got, name),
                other => panic!("{name}={value}: expected Invalid, got {other:?}"),
            }
        }
    }

    #[test]
    fn the_audit_service_is_optional_and_needs_a_client_certificate() {
        assert!(load(&base()).unwrap().audit.is_none());

        let mut vars = base();
        vars.insert("VAULT_AUDIT_ADDR", "audit.internal:50056".to_owned());
        assert!(matches!(load(&vars), Err(ConfigError::Missing(n)) if n == "VAULT_AUDIT_TLS_CERT"));
        vars.insert("VAULT_AUDIT_TLS_CERT", "/tls/vault-client.pem".to_owned());
        vars.insert(
            "VAULT_AUDIT_TLS_KEY",
            "/tls/vault-client-key.pem".to_owned(),
        );
        let audit = load(&vars).unwrap().audit.unwrap();
        assert_eq!(audit.server_name, "audit.internal");
        assert_eq!(audit.ca, std::path::PathBuf::from("/tls/ca.pem"));

        vars.insert("VAULT_AUDIT_SERVER_NAME", "audit".to_owned());
        vars.insert("VAULT_AUDIT_CA", "/tls/audit-ca.pem".to_owned());
        let audit = load(&vars).unwrap().audit.unwrap();
        assert_eq!(
            (audit.server_name.as_str(), audit.ca.to_str()),
            ("audit", Some("/tls/audit-ca.pem"))
        );

        vars.insert("VAULT_AUDIT_ADDR", "audit.internal".to_owned());
        assert!(
            matches!(load(&vars), Err(ConfigError::Invalid { name, .. }) if name == "VAULT_AUDIT_ADDR")
        );
    }

    #[test]
    fn secrets_can_come_from_files_but_not_both_sources() {
        let dir = std::env::temp_dir().join(format!("vault-config-test-{}", uuid::Uuid::now_v7()));
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("passphrase");
        fs::write(&file, format!("{}\n", "f".repeat(40))).unwrap();

        let mut vars = base();
        vars.remove("VAULT_MASTER_PASSPHRASE");
        vars.insert("VAULT_MASTER_PASSPHRASE_FILE", file.display().to_string());
        let config = load(&vars).unwrap();
        assert_eq!(config.master_passphrase.expose(), "f".repeat(40));

        vars.insert("VAULT_MASTER_PASSPHRASE", "p".repeat(40));
        assert!(matches!(load(&vars), Err(ConfigError::Invalid { .. })));

        fs::remove_dir_all(dir).unwrap();
    }
}
