//! Service error type and its mapping onto gRPC status codes.
//!
//! Messages of client-facing variants are sent to callers, so they name
//! fields but never echo values. Internal variants are logged server-side and
//! reach the caller only as a generic INTERNAL status.

use std::collections::HashMap;

use tonic::{Code, Status};
use tonic_types::{ErrorDetails, StatusExt};

use crate::{crypto::CryptoError, proto::vault_v1::ErrorReason};

/// `google.rpc.ErrorInfo.domain` for every error this service reports.
pub const ERROR_DOMAIN: &str = "vault.jarvis";

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("{0}")]
    InvalidArgument(String),
    #[error("caller identity could not be established from the client certificate")]
    Unauthenticated,
    #[error("caller is not allowed to call this method")]
    PermissionDenied,
    #[error("key not found")]
    KeyNotFound,
    #[error("key has been revoked")]
    KeyRevoked,
    #[error("tenant already has an active key for this provider")]
    ActiveKeyExists,
    #[error("request_id was already used with a different payload")]
    RequestIdConflict,
    #[error("sealed data does not open under this tenant, purpose and subject")]
    SealedDataInvalid,
    #[error("database error")]
    Database(#[from] sqlx::Error),
    #[error("cryptographic failure")]
    Crypto(#[from] CryptoError),
    #[error("stored data is inconsistent: {0}")]
    DataIntegrity(String),
}

impl VaultError {
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::InvalidArgument(message.into())
    }

    pub const fn code(&self) -> Code {
        match self {
            Self::InvalidArgument(_) => Code::InvalidArgument,
            Self::Unauthenticated => Code::Unauthenticated,
            Self::PermissionDenied => Code::PermissionDenied,
            Self::KeyNotFound => Code::NotFound,
            Self::KeyRevoked | Self::SealedDataInvalid => Code::FailedPrecondition,
            Self::ActiveKeyExists | Self::RequestIdConflict => Code::AlreadyExists,
            Self::Database(_) | Self::Crypto(_) | Self::DataIntegrity(_) => Code::Internal,
        }
    }

    pub const fn reason(&self) -> Option<ErrorReason> {
        match self {
            Self::KeyNotFound => Some(ErrorReason::KeyNotFound),
            Self::KeyRevoked => Some(ErrorReason::KeyRevoked),
            Self::ActiveKeyExists => Some(ErrorReason::ActiveKeyExists),
            Self::RequestIdConflict => Some(ErrorReason::RequestIdConflict),
            Self::SealedDataInvalid => Some(ErrorReason::SealedDataInvalid),
            _ => None,
        }
    }

    pub const fn is_internal(&self) -> bool {
        matches!(self.code(), Code::Internal)
    }
}

impl From<jarvis_common::mtls::UnauthenticatedError> for VaultError {
    fn from(_: jarvis_common::mtls::UnauthenticatedError) -> Self {
        Self::Unauthenticated
    }
}

impl From<VaultError> for Status {
    fn from(error: VaultError) -> Self {
        if error.is_internal() {
            return Status::internal("internal error");
        }
        match error.reason() {
            Some(reason) => Status::with_error_details(
                error.code(),
                error.to_string(),
                ErrorDetails::with_error_info(
                    reason.as_str_name(),
                    ERROR_DOMAIN,
                    HashMap::<String, String>::new(),
                ),
            ),
            None => Status::new(error.code(), error.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_errors_carry_typed_error_info() {
        let status = Status::from(VaultError::ActiveKeyExists);
        assert_eq!(status.code(), Code::AlreadyExists);
        let info = status.get_details_error_info();
        assert_eq!(
            info.as_ref()
                .map(|i| (i.reason.as_str(), i.domain.as_str())),
            Some(("ERROR_REASON_ACTIVE_KEY_EXISTS", ERROR_DOMAIN))
        );
    }

    #[test]
    fn internal_errors_reveal_nothing() {
        let status = Status::from(VaultError::DataIntegrity("row 42 has no ciphertext".into()));
        assert_eq!(status.code(), Code::Internal);
        assert_eq!(status.message(), "internal error");
        assert!(status.get_details_error_info().is_none());
    }

    #[test]
    fn invalid_argument_passes_the_field_message_through() {
        let status = Status::from(VaultError::invalid("tenant_id must be a UUID"));
        assert_eq!(status.code(), Code::InvalidArgument);
        assert_eq!(status.message(), "tenant_id must be a UUID");
    }
}
