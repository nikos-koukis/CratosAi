//! Generated gRPC types for the Vault contract, plus the guarantees prost
//! cannot express on its own for messages that carry plaintext keys:
//! a redacted `Debug` and zeroize-on-drop.

use std::fmt;

use zeroize::Zeroize;

#[allow(clippy::all, clippy::pedantic, missing_debug_implementations)]
pub mod jarvis {
    pub mod common {
        pub mod v1 {
            tonic::include_proto!("jarvis.common.v1");
        }
    }
    pub mod vault {
        pub mod v1 {
            tonic::include_proto!("jarvis.vault.v1");
        }
    }
    pub mod audit {
        pub mod v1 {
            tonic::include_proto!("jarvis.audit.v1");
        }
    }
}

pub use jarvis::audit::v1 as audit_v1;

pub use jarvis::common::v1 as common_v1;
pub use jarvis::vault::v1 as vault_v1;

use vault_v1::{CreateKeyRequest, GetDecryptedKeyResponse, OpenDataResponse, SealDataRequest};

/// Encoded `FileDescriptorSet` for the Vault contract (used by gRPC reflection).
pub const FILE_DESCRIPTOR_SET: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/jarvis_descriptor.bin"));

const REDACTED: &str = "[REDACTED]";

impl fmt::Debug for CreateKeyRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CreateKeyRequest")
            .field("tenant_id", &self.tenant_id)
            .field("provider", &self.provider)
            .field("label", &self.label)
            .field("secret", &REDACTED)
            .field("replace_active", &self.replace_active)
            .field("request_id", &self.request_id)
            .finish()
    }
}

impl Drop for CreateKeyRequest {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl fmt::Debug for GetDecryptedKeyResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GetDecryptedKeyResponse")
            .field("key_id", &self.key_id)
            .field("provider", &self.provider)
            .field("secret", &REDACTED)
            .finish()
    }
}

impl Drop for GetDecryptedKeyResponse {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl fmt::Debug for SealDataRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealDataRequest")
            .field("tenant_id", &self.tenant_id)
            .field("purpose", &self.purpose)
            .field("subject_id", &self.subject_id)
            .field("plaintext", &REDACTED)
            .finish()
    }
}

impl Drop for SealDataRequest {
    fn drop(&mut self) {
        self.plaintext.zeroize();
    }
}

impl fmt::Debug for OpenDataResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenDataResponse")
            .field("plaintext", &REDACTED)
            .finish()
    }
}

impl Drop for OpenDataResponse {
    fn drop(&mut self) {
        self.plaintext.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"xai-SUPERSECRET-0123456789";

    #[test]
    fn secret_bearing_messages_never_print_the_secret() {
        // Struct-update syntax is unavailable: these types implement Drop.
        let mut request = CreateKeyRequest::default();
        request.tenant_id = "t".into();
        request.secret = SECRET.to_vec();
        let mut response = GetDecryptedKeyResponse::default();
        response.key_id = "k".into();
        response.secret = SECRET.to_vec();

        let mut seal = SealDataRequest::default();
        seal.plaintext = SECRET.to_vec();
        let mut open = OpenDataResponse::default();
        open.plaintext = SECRET.to_vec();

        for rendered in [
            format!("{request:?}"),
            format!("{response:?}"),
            format!("{seal:?}"),
            format!("{open:?}"),
        ] {
            assert!(rendered.contains(REDACTED), "{rendered}");
            assert!(!rendered.contains("SUPERSECRET"), "{rendered}");
            // prost renders bytes as a list of integers; make sure that form is absent too.
            assert!(
                !rendered.contains(&format!("{:?}", &SECRET[..4])),
                "{rendered}"
            );
        }
    }
}
