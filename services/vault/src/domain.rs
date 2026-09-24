//! Domain types and their mapping to the wire (protobuf) and storage (SQL)
//! representations. The database stores stable lowercase names, never enum
//! numbers, so the schema stays readable and independent of the proto.

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::proto::{common_v1, vault_v1};

/// LLM vendor a stored key authenticates against.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Provider {
    OpenAi,
    XAi,
    Anthropic,
    Google,
}

impl Provider {
    /// Storage name; also bound into the ciphertext's associated data.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OpenAi => "openai",
            Self::XAi => "xai",
            Self::Anthropic => "anthropic",
            Self::Google => "google",
        }
    }

    pub fn from_db(value: &str) -> Option<Self> {
        match value {
            "openai" => Some(Self::OpenAi),
            "xai" => Some(Self::XAi),
            "anthropic" => Some(Self::Anthropic),
            "google" => Some(Self::Google),
            _ => None,
        }
    }

    /// Converts a raw proto enum value; `None` for UNSPECIFIED or unknown values.
    pub fn from_proto(value: i32) -> Option<Self> {
        match common_v1::Provider::try_from(value).ok()? {
            common_v1::Provider::Unspecified => None,
            common_v1::Provider::Openai => Some(Self::OpenAi),
            common_v1::Provider::Xai => Some(Self::XAi),
            common_v1::Provider::Anthropic => Some(Self::Anthropic),
            common_v1::Provider::Google => Some(Self::Google),
        }
    }

    pub const fn to_proto(self) -> common_v1::Provider {
        match self {
            Self::OpenAi => common_v1::Provider::Openai,
            Self::XAi => common_v1::Provider::Xai,
            Self::Anthropic => common_v1::Provider::Anthropic,
            Self::Google => common_v1::Provider::Google,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyStatus {
    Active,
    Revoked,
}

impl KeyStatus {
    pub fn from_db(value: &str) -> Option<Self> {
        match value {
            "active" => Some(Self::Active),
            "revoked" => Some(Self::Revoked),
            _ => None,
        }
    }

    pub const fn to_proto(self) -> vault_v1::KeyStatus {
        match self {
            Self::Active => vault_v1::KeyStatus::Active,
            Self::Revoked => vault_v1::KeyStatus::Revoked,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevocationReason {
    UserRequested,
    Rotated,
    Compromised,
}

impl RevocationReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UserRequested => "user_requested",
            Self::Rotated => "rotated",
            Self::Compromised => "compromised",
        }
    }

    pub fn from_db(value: &str) -> Option<Self> {
        match value {
            "user_requested" => Some(Self::UserRequested),
            "rotated" => Some(Self::Rotated),
            "compromised" => Some(Self::Compromised),
            _ => None,
        }
    }

    /// Converts a raw proto enum value; `None` for UNSPECIFIED or unknown values.
    pub fn from_proto(value: i32) -> Option<Self> {
        match vault_v1::RevocationReason::try_from(value).ok()? {
            vault_v1::RevocationReason::Unspecified => None,
            vault_v1::RevocationReason::UserRequested => Some(Self::UserRequested),
            vault_v1::RevocationReason::Rotated => Some(Self::Rotated),
            vault_v1::RevocationReason::Compromised => Some(Self::Compromised),
        }
    }

    pub const fn to_proto(self) -> vault_v1::RevocationReason {
        match self {
            Self::UserRequested => vault_v1::RevocationReason::UserRequested,
            Self::Rotated => vault_v1::RevocationReason::Rotated,
            Self::Compromised => vault_v1::RevocationReason::Compromised,
        }
    }
}

/// Everything known about a stored key except its secret material.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyMetadata {
    pub key_id: Uuid,
    pub tenant_id: Uuid,
    pub provider: Provider,
    pub label: String,
    pub key_hint: String,
    pub status: KeyStatus,
    pub create_time: DateTime<Utc>,
    pub revoke_time: Option<DateTime<Utc>>,
    pub revocation_reason: Option<RevocationReason>,
}

impl From<KeyMetadata> for vault_v1::KeyMetadata {
    fn from(meta: KeyMetadata) -> Self {
        Self {
            key_id: meta.key_id.to_string(),
            tenant_id: meta.tenant_id.to_string(),
            provider: meta.provider.to_proto().into(),
            label: meta.label,
            key_hint: meta.key_hint,
            status: meta.status.to_proto().into(),
            create_time: Some(timestamp(meta.create_time)),
            revoke_time: meta.revoke_time.map(timestamp),
            revocation_reason: meta
                .revocation_reason
                .map_or(
                    vault_v1::RevocationReason::Unspecified,
                    RevocationReason::to_proto,
                )
                .into(),
        }
    }
}

fn timestamp(time: DateTime<Utc>) -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: time.timestamp(),
        // Always < 1e9, so it fits an i32.
        nanos: i32::try_from(time.timestamp_subsec_nanos()).unwrap_or(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROVIDERS: [Provider; 4] = [
        Provider::OpenAi,
        Provider::XAi,
        Provider::Anthropic,
        Provider::Google,
    ];

    #[test]
    fn provider_round_trips_through_db_and_proto() {
        for provider in PROVIDERS {
            assert_eq!(Provider::from_db(provider.as_str()), Some(provider));
            assert_eq!(
                Provider::from_proto(provider.to_proto().into()),
                Some(provider)
            );
        }
    }

    #[test]
    fn unspecified_and_unknown_proto_values_are_rejected() {
        assert_eq!(
            Provider::from_proto(common_v1::Provider::Unspecified.into()),
            None
        );
        assert_eq!(Provider::from_proto(999), None);
        assert_eq!(
            RevocationReason::from_proto(vault_v1::RevocationReason::Unspecified.into()),
            None
        );
        assert_eq!(RevocationReason::from_proto(-1), None);
    }

    #[test]
    fn revocation_reason_round_trips() {
        for reason in [
            RevocationReason::UserRequested,
            RevocationReason::Rotated,
            RevocationReason::Compromised,
        ] {
            assert_eq!(RevocationReason::from_db(reason.as_str()), Some(reason));
            assert_eq!(
                RevocationReason::from_proto(reason.to_proto().into()),
                Some(reason)
            );
        }
    }
}
