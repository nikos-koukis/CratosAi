//! Caller authentication (mTLS client certificate) and authorization
//! (per-principal allowlist of RPCs). Anything not granted is denied.
//!
//! The mechanics are shared with the other Jarvis services (`jarvis-common`);
//! this module only names the Vault's RPCs.

use serde::Deserialize;

pub use jarvis_common::{authz::PolicyError, mtls::Principal};

/// Which principal may call which Vault RPC.
pub type AuthzPolicy = jarvis_common::authz::AuthzPolicy<Rpc>;

/// The Vault's RPCs, as named in the policy file and audit log.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Deserialize)]
pub enum Rpc {
    CreateKey,
    GetDecryptedKey,
    RevokeKey,
    ListKeys,
    SealData,
    OpenData,
}

impl Rpc {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CreateKey => "CreateKey",
            Self::GetDecryptedKey => "GetDecryptedKey",
            Self::RevokeKey => "RevokeKey",
            Self::ListKeys => "ListKeys",
            Self::SealData => "SealData",
            Self::OpenData => "OpenData",
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn the_vault_policy_file_names_its_rpcs() {
        let policy = AuthzPolicy::from_toml(
            r#"
            [[principal]]
            id = "spiffe://jarvis.test/voice-gateway"
            allow = ["GetDecryptedKey"]
            "#,
        )
        .unwrap();
        assert_eq!(policy.principal_count(), 1);
        assert!(
            AuthzPolicy::from_toml(
                r#"
            [[principal]]
            id = "spiffe://jarvis.test/x"
            allow = ["DeleteAllKeys"]
            "#
            )
            .is_err()
        );
    }
}
