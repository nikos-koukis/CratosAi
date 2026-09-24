//! Mutual TLS: server key material and caller identity.
//!
//! A caller's identity is the single URI SAN of its client certificate, e.g.
//! `spiffe://jarvis.internal/voice-gateway`. Request fields never influence it.

use std::{fmt, fs, io, path::Path, path::PathBuf, time::Duration};

use tonic::transport::{Certificate, Identity, ServerTlsConfig};
use x509_parser::{extensions::GeneralName, parse_x509_certificate};
use zeroize::Zeroizing;

/// An authenticated caller.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Principal(String);

#[derive(Debug, thiserror::Error)]
#[error("caller identity could not be established from the client certificate")]
pub struct UnauthenticatedError;

impl Principal {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Principals are only ever built from verified certificates; tests of
    /// the policy code need to skip that step.
    #[cfg(test)]
    pub(crate) fn from_test_id(id: &str) -> Self {
        Self(id.to_owned())
    }

    /// Extracts the caller from the client certificate chain presented over
    /// mTLS. The leaf must carry exactly one URI SAN.
    pub fn from_peer_certs<C: AsRef<[u8]>>(
        chain: Option<&[C]>,
    ) -> Result<Self, UnauthenticatedError> {
        let leaf = chain.and_then(<[C]>::first).ok_or(UnauthenticatedError)?;
        let (_, cert) = parse_x509_certificate(leaf.as_ref()).map_err(|_| UnauthenticatedError)?;
        let san = cert
            .subject_alternative_name()
            .map_err(|_| UnauthenticatedError)?
            .ok_or(UnauthenticatedError)?;

        let mut uris = san
            .value
            .general_names
            .iter()
            .filter_map(|name| match name {
                GeneralName::URI(uri) => Some(*uri),
                _ => None,
            });
        match (uris.next(), uris.next()) {
            (Some(uri), None) if is_uri(uri) => Ok(Self(uri.to_owned())),
            _ => Err(UnauthenticatedError),
        }
    }
}

impl fmt::Display for Principal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Minimal structural check: `scheme://rest` with a lowercase ASCII scheme.
pub fn is_uri(value: &str) -> bool {
    value.split_once("://").is_some_and(|(scheme, rest)| {
        !scheme.is_empty()
            && scheme
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'+' || b == b'-')
            && !rest.is_empty()
            && !value
                .bytes()
                .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    })
}

#[derive(Debug, thiserror::Error)]
#[error("cannot read TLS {what} {path}")]
pub struct TlsLoadError {
    what: &'static str,
    path: PathBuf,
    #[source]
    source: io::Error,
}

/// PEM material for an mTLS listener. The private key is zeroized on drop.
pub struct TlsMaterial {
    cert_chain: Vec<u8>,
    private_key: Zeroizing<Vec<u8>>,
    client_ca: Vec<u8>,
}

impl TlsMaterial {
    pub fn from_pem(cert_chain: Vec<u8>, private_key: Vec<u8>, client_ca: Vec<u8>) -> Self {
        Self {
            cert_chain,
            private_key: Zeroizing::new(private_key),
            client_ca,
        }
    }

    pub fn load(cert: &Path, key: &Path, client_ca: &Path) -> Result<Self, TlsLoadError> {
        let read = |path: &Path, what: &'static str| {
            fs::read(path).map_err(|source| TlsLoadError {
                what,
                path: path.to_owned(),
                source,
            })
        };
        Ok(Self::from_pem(
            read(cert, "certificate")?,
            read(key, "private key")?,
            read(client_ca, "client CA bundle")?,
        ))
    }

    /// Server configuration that requires a client certificate chaining to
    /// the configured CA.
    pub fn server_config(&self, handshake_timeout: Duration) -> ServerTlsConfig {
        ServerTlsConfig::new()
            .identity(Identity::from_pem(
                &self.cert_chain,
                self.private_key.as_slice(),
            ))
            .client_ca_root(Certificate::from_pem(&self.client_ca))
            .client_auth_optional(false)
            .timeout(handshake_timeout)
    }
}

impl fmt::Debug for TlsMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsMaterial").finish_non_exhaustive()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use rcgen::{CertificateParams, KeyPair, SanType};

    use super::*;

    fn cert_with_sans(sans: Vec<SanType>) -> Vec<u8> {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.subject_alt_names = sans;
        let key = KeyPair::generate().unwrap();
        params.self_signed(&key).unwrap().der().to_vec()
    }

    fn uri(value: &str) -> SanType {
        SanType::URI(value.try_into().unwrap())
    }

    #[test]
    fn principal_is_the_single_uri_san_of_the_leaf() {
        let der = cert_with_sans(vec![
            SanType::DnsName("gateway.local".try_into().unwrap()),
            uri("spiffe://jarvis.test/voice-gateway"),
        ]);
        let principal = Principal::from_peer_certs(Some(&[der][..])).unwrap();
        assert_eq!(principal.as_str(), "spiffe://jarvis.test/voice-gateway");
    }

    #[test]
    fn certificates_without_exactly_one_uri_san_are_rejected() {
        let none = cert_with_sans(vec![SanType::DnsName("x.local".try_into().unwrap())]);
        let two = cert_with_sans(vec![uri("spiffe://a/one"), uri("spiffe://a/two")]);

        for der in [none, two] {
            assert!(Principal::from_peer_certs(Some(&[der][..])).is_err());
        }
        assert!(Principal::from_peer_certs::<Vec<u8>>(None).is_err());
        assert!(Principal::from_peer_certs(Some(&[b"garbage".to_vec()][..])).is_err());
    }

    #[test]
    fn uri_check_is_structural() {
        assert!(is_uri("spiffe://jarvis.local/orchestrator"));
        for bad in [
            "",
            "no-scheme",
            "://x",
            "Spiffe://x",
            "spiffe://",
            "spiffe://a b",
        ] {
            assert!(!is_uri(bad), "accepted {bad:?}");
        }
    }
}
