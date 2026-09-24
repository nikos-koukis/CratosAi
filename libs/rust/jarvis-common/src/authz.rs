//! Per-principal allowlist of RPCs. Anything not granted is denied.
//!
//! Services define their own RPC enum and reuse this policy, either from a
//! standalone file (`[[principal]]` tables) or embedded in a larger config.

use std::{
    collections::{HashMap, HashSet},
    fs,
    hash::Hash,
    io,
    path::{Path, PathBuf},
};

use serde::{Deserialize, de::DeserializeOwned};

use crate::mtls::{Principal, is_uri};

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("cannot read authorization policy {path}")]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("invalid authorization policy")]
    Parse(#[from] toml::de::Error),
    #[error("invalid authorization policy: {0}")]
    Invalid(String),
}

/// One `[[principal]]` entry: a caller identity and the RPCs it may call.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalGrant<R> {
    pub id: String,
    pub allow: Vec<R>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, bound = "R: DeserializeOwned")]
struct PolicyFile<R> {
    #[serde(default, rename = "principal")]
    principals: Vec<PrincipalGrant<R>>,
}

/// Which principal may call which RPC.
#[derive(Debug)]
pub struct AuthzPolicy<R> {
    grants: HashMap<String, HashSet<R>>,
}

impl<R> Default for AuthzPolicy<R> {
    fn default() -> Self {
        Self {
            grants: HashMap::new(),
        }
    }
}

impl<R: DeserializeOwned + Eq + Hash> AuthzPolicy<R> {
    pub fn load(path: &Path) -> Result<Self, PolicyError> {
        let text = fs::read_to_string(path).map_err(|source| PolicyError::Read {
            path: path.to_owned(),
            source,
        })?;
        Self::from_toml(&text)
    }

    pub fn from_toml(text: &str) -> Result<Self, PolicyError> {
        let file: PolicyFile<R> = toml::from_str(text)?;
        Self::from_grants(file.principals)
    }
}

impl<R: Eq + Hash> AuthzPolicy<R> {
    pub fn from_grants(grants: Vec<PrincipalGrant<R>>) -> Result<Self, PolicyError> {
        let mut policy = HashMap::new();
        for grant in grants {
            if !is_uri(&grant.id) {
                return Err(PolicyError::Invalid(format!(
                    "principal id {:?} is not a URI (expected e.g. spiffe://jarvis.internal/voice-gateway)",
                    grant.id
                )));
            }
            if grant.allow.is_empty() {
                return Err(PolicyError::Invalid(format!(
                    "principal {} has an empty allow list",
                    grant.id
                )));
            }
            if policy
                .insert(grant.id.clone(), grant.allow.into_iter().collect())
                .is_some()
            {
                return Err(PolicyError::Invalid(format!(
                    "principal {} is listed more than once",
                    grant.id
                )));
            }
        }
        Ok(Self { grants: policy })
    }

    pub fn is_allowed(&self, principal: &Principal, rpc: R) -> bool {
        self.grants
            .get(principal.as_str())
            .is_some_and(|allowed| allowed.contains(&rpc))
    }

    pub fn principal_count(&self) -> usize {
        self.grants.len()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Deserialize)]
    enum Rpc {
        Read,
        Write,
    }

    const POLICY: &str = r#"
        [[principal]]
        id = "spiffe://jarvis.test/reader"
        allow = ["Read"]

        [[principal]]
        id = "spiffe://jarvis.test/writer"
        allow = ["Read", "Write"]
    "#;

    fn principal(id: &str) -> Principal {
        Principal::from_test_id(id)
    }

    #[test]
    fn grants_are_exact_and_everything_else_is_denied() {
        let policy = AuthzPolicy::<Rpc>::from_toml(POLICY).unwrap();
        let reader = principal("spiffe://jarvis.test/reader");
        let writer = principal("spiffe://jarvis.test/writer");

        assert!(policy.is_allowed(&reader, Rpc::Read));
        assert!(!policy.is_allowed(&reader, Rpc::Write));
        assert!(policy.is_allowed(&writer, Rpc::Write));
        assert!(!policy.is_allowed(&principal("spiffe://jarvis.test/unknown"), Rpc::Read));
        assert!(!AuthzPolicy::<Rpc>::default().is_allowed(&reader, Rpc::Read));
    }

    #[test]
    fn malformed_policies_are_rejected() {
        let cases = [
            r#"[[principal]]
               id = "spiffe://a/b"
               allow = ["DeleteEverything"]"#,
            r#"[[principal]]
               id = "not a uri"
               allow = ["Read"]"#,
            r#"[[principal]]
               id = "spiffe://a/b"
               allow = []"#,
            r#"[[principal]]
               id = "spiffe://a/b"
               allow = ["Read"]
               [[principal]]
               id = "spiffe://a/b"
               allow = ["Write"]"#,
            r#"[[principal]]
               id = "spiffe://a/b"
               allow = ["Read"]
               tenants = ["*"]"#,
        ];
        for case in cases {
            assert!(
                AuthzPolicy::<Rpc>::from_toml(case).is_err(),
                "accepted: {case}"
            );
        }
    }
}
