//! gRPC handlers. Each call is authenticated (mTLS), authorised (policy),
//! validated, executed and audited, in that order. Plaintext secrets are held
//! only in zeroizing buffers.

use std::{error::Error, sync::Arc};

use tonic::{Request, Response, Status};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    audit::{AuditEvent, AuditOutcome, AuditSink},
    authz::{AuthzPolicy, Principal, Rpc},
    crypto::{CryptoError, DataBinding, MasterKey, SecretOwner},
    domain::{Provider, RevocationReason},
    error::VaultError,
    proto::vault_v1::{
        CreateKeyRequest, CreateKeyResponse, GetDecryptedKeyRequest, GetDecryptedKeyResponse,
        OpenDataRequest, OpenDataResponse, RevokeKeyRequest, RevokeKeyResponse, SealDataRequest,
        SealDataResponse, get_decrypted_key_request::Selector, vault_service_server,
    },
    store::{Idempotency, KeySelector, KeyStore, NewKey},
};

/// Correlation id header; generated when absent or malformed.
pub const REQUEST_ID_HEADER: &str = "x-request-id";

const MAX_REQUEST_ID_LEN: usize = 128;
const MAX_LABEL_CHARS: usize = 64;
const MIN_SECRET_LEN: usize = 16;
const MAX_SECRET_LEN: usize = 8192;
const KEY_HINT_LEN: usize = 4;
const MAX_PURPOSE_LEN: usize = 64;
const MAX_SUBJECT_LEN: usize = 128;
const MAX_DATA_LEN: usize = 64 * 1024;
/// Envelope overhead on top of the data (format, ids, nonces, tags).
const MAX_SEALED_LEN: usize = MAX_DATA_LEN + 1024;

#[derive(Debug)]
pub struct VaultService {
    store: KeyStore,
    master_key: Arc<MasterKey>,
    policy: Arc<AuthzPolicy>,
    audit: Arc<dyn AuditSink>,
}

/// Per-call facts accumulated for the audit record.
struct Call {
    rpc: Rpc,
    request_id: String,
    caller: Option<Principal>,
    tenant_id: Option<Uuid>,
    key_id: Option<Uuid>,
    subject: Option<String>,
}

impl Call {
    fn start<T>(rpc: Rpc, request: &Request<T>) -> Self {
        let request_id = request
            .metadata()
            .get(REQUEST_ID_HEADER)
            .and_then(|value| value.to_str().ok())
            .filter(|value| is_valid_request_id(value))
            .map_or_else(|| Uuid::now_v7().to_string(), str::to_owned);
        tracing::Span::current().record("request_id", request_id.as_str());
        Self {
            rpc,
            request_id,
            caller: None,
            tenant_id: None,
            key_id: None,
            subject: None,
        }
    }
}

impl VaultService {
    pub fn new(
        store: KeyStore,
        master_key: Arc<MasterKey>,
        policy: Arc<AuthzPolicy>,
        audit: Arc<dyn AuditSink>,
    ) -> Self {
        Self {
            store,
            master_key,
            policy,
            audit,
        }
    }

    fn authorize<T>(&self, call: &mut Call, request: &Request<T>) -> Result<Principal, VaultError> {
        let certs = request.peer_certs();
        let principal = Principal::from_peer_certs(certs.as_deref().map(Vec::as_slice))?;
        call.caller = Some(principal.clone());
        if self.policy.is_allowed(&principal, call.rpc) {
            Ok(principal)
        } else {
            Err(VaultError::PermissionDenied)
        }
    }

    fn finish<T>(&self, call: &Call, result: Result<T, VaultError>) -> Result<Response<T>, Status> {
        let outcome = match &result {
            Ok(_) => AuditOutcome::Success,
            Err(error) => AuditOutcome::Failure {
                code: error.code(),
                reason: error.reason().map(|reason| reason.as_str_name()),
            },
        };
        self.audit.record(&AuditEvent {
            rpc: call.rpc,
            request_id: call.request_id.clone(),
            caller: call.caller.as_ref().map(|p| p.as_str().to_owned()),
            tenant_id: call.tenant_id,
            key_id: call.key_id,
            subject: call.subject.clone(),
            outcome,
        });

        result.map(Response::new).map_err(|error| {
            if error.is_internal() {
                tracing::error!(
                    rpc = call.rpc.as_str(),
                    tenant_id = call.tenant_id.map(tracing::field::display),
                    key_id = call.key_id.map(tracing::field::display),
                    error = %error_chain(&error),
                    "request failed"
                );
            }
            error.into()
        })
    }

    async fn handle_create(
        &self,
        call: &mut Call,
        request: Request<CreateKeyRequest>,
    ) -> Result<CreateKeyResponse, VaultError> {
        let caller = self.authorize(call, &request)?;
        let mut req = request.into_inner();
        let secret = Zeroizing::new(std::mem::take(&mut req.secret));

        let tenant_id = parse_uuid("tenant_id", &req.tenant_id)?;
        call.tenant_id = Some(tenant_id);
        let provider = Provider::from_proto(req.provider)
            .ok_or_else(|| VaultError::invalid("provider is required"))?;
        validate_label(&req.label)?;
        validate_secret(&secret)?;
        let request_id = parse_optional_uuid("request_id", &req.request_id)?;

        let key_id = Uuid::now_v7();
        let sealed = self.master_key.seal(
            &secret,
            &SecretOwner {
                tenant_id,
                key_id,
                provider,
            },
        )?;
        let idempotency = request_id.map(|request_id| Idempotency {
            request_id,
            fingerprint: self.master_key.fingerprint(&[
                provider.as_str().as_bytes(),
                req.label.as_bytes(),
                &secret,
                &[u8::from(req.replace_active)],
            ]),
        });

        let created = self
            .store
            .create(NewKey {
                key_id,
                tenant_id,
                provider,
                label: &req.label,
                key_hint: &key_hint(&secret),
                sealed: &sealed,
                replace_active: req.replace_active,
                created_by: caller.as_str(),
                idempotency,
            })
            .await?;
        call.key_id = Some(created.key.key_id);
        if created.replayed {
            tracing::info!(key_id = %created.key.key_id, "CreateKey retry answered from idempotency record");
        }

        Ok(CreateKeyResponse {
            key: Some(created.key.into()),
            replaced_key: created.replaced.map(Into::into),
        })
    }

    async fn handle_get(
        &self,
        call: &mut Call,
        request: Request<GetDecryptedKeyRequest>,
    ) -> Result<GetDecryptedKeyResponse, VaultError> {
        self.authorize(call, &request)?;
        let req = request.into_inner();

        let tenant_id = parse_uuid("tenant_id", &req.tenant_id)?;
        call.tenant_id = Some(tenant_id);
        let selector = match &req.selector {
            Some(Selector::KeyId(key_id)) => {
                let key_id = parse_uuid("key_id", key_id)?;
                call.key_id = Some(key_id);
                KeySelector::Id(key_id)
            }
            Some(Selector::Provider(provider)) => KeySelector::ActiveFor(
                Provider::from_proto(*provider)
                    .ok_or_else(|| VaultError::invalid("provider must be specified"))?,
            ),
            None => return Err(VaultError::invalid("one of key_id or provider is required")),
        };

        let stored = self.store.fetch_sealed(tenant_id, selector).await?;
        call.key_id = Some(stored.key.key_id);
        let mut plaintext = self.master_key.open(
            &stored.sealed,
            &SecretOwner {
                tenant_id,
                key_id: stored.key.key_id,
                provider: stored.key.provider,
            },
        )?;

        Ok(GetDecryptedKeyResponse {
            key_id: stored.key.key_id.to_string(),
            provider: stored.key.provider.to_proto().into(),
            // Moved, not copied; the response zeroizes it when dropped.
            secret: std::mem::take(&mut *plaintext),
        })
    }

    async fn handle_revoke(
        &self,
        call: &mut Call,
        request: Request<RevokeKeyRequest>,
    ) -> Result<RevokeKeyResponse, VaultError> {
        let caller = self.authorize(call, &request)?;
        let req = request.into_inner();

        let tenant_id = parse_uuid("tenant_id", &req.tenant_id)?;
        call.tenant_id = Some(tenant_id);
        let key_id = parse_uuid("key_id", &req.key_id)?;
        call.key_id = Some(key_id);
        let reason = RevocationReason::from_proto(req.reason)
            .ok_or_else(|| VaultError::invalid("reason is required"))?;

        let key = self
            .store
            .revoke(tenant_id, key_id, reason, caller.as_str())
            .await?;
        Ok(RevokeKeyResponse {
            key: Some(key.into()),
        })
    }
}

impl VaultService {
    async fn handle_seal(
        &self,
        call: &mut Call,
        request: Request<SealDataRequest>,
    ) -> Result<SealDataResponse, VaultError> {
        self.authorize(call, &request)?;
        let mut req = request.into_inner();
        let plaintext = Zeroizing::new(std::mem::take(&mut req.plaintext));
        let binding = self.binding(call, &req.tenant_id, &req.purpose, &req.subject_id)?;
        if plaintext.is_empty() || plaintext.len() > MAX_DATA_LEN {
            return Err(VaultError::invalid(format!(
                "plaintext must be 1 to {MAX_DATA_LEN} bytes"
            )));
        }
        let sealed = self.master_key.seal_data(&plaintext, &binding)?;
        Ok(SealDataResponse { sealed })
    }

    async fn handle_open(
        &self,
        call: &mut Call,
        request: Request<OpenDataRequest>,
    ) -> Result<OpenDataResponse, VaultError> {
        self.authorize(call, &request)?;
        let req = request.into_inner();
        let binding = self.binding(call, &req.tenant_id, &req.purpose, &req.subject_id)?;
        if req.sealed.is_empty() || req.sealed.len() > MAX_SEALED_LEN {
            return Err(VaultError::invalid(format!(
                "sealed must be 1 to {MAX_SEALED_LEN} bytes"
            )));
        }
        let mut plaintext = self
            .master_key
            .open_data(&req.sealed, &binding)
            .map_err(|error| match error {
                // Caller-supplied data that does not verify is the caller's
                // problem (or tampering), not a Vault failure.
                CryptoError::Decrypt
                | CryptoError::Malformed(_)
                | CryptoError::KekMismatch { .. } => {
                    tracing::warn!(subject = ?call.subject, %error, "sealed data failed to open");
                    VaultError::SealedDataInvalid
                }
                other => VaultError::Crypto(other),
            })?;
        Ok(OpenDataResponse {
            plaintext: std::mem::take(&mut *plaintext),
        })
    }

    fn binding<'a>(
        &self,
        call: &mut Call,
        tenant_id: &str,
        purpose: &'a str,
        subject_id: &'a str,
    ) -> Result<DataBinding<'a>, VaultError> {
        let tenant_id = parse_uuid("tenant_id", tenant_id)?;
        call.tenant_id = Some(tenant_id);
        let purpose_ok = !purpose.is_empty()
            && purpose.len() <= MAX_PURPOSE_LEN
            && purpose.bytes().all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
            });
        if !purpose_ok {
            return Err(VaultError::invalid(format!(
                "purpose must be 1 to {MAX_PURPOSE_LEN} of a-z 0-9 . _ -"
            )));
        }
        let subject_ok = !subject_id.is_empty()
            && subject_id.len() <= MAX_SUBJECT_LEN
            && subject_id.bytes().all(|b| (0x21..=0x7e).contains(&b));
        if !subject_ok {
            return Err(VaultError::invalid(format!(
                "subject_id must be 1 to {MAX_SUBJECT_LEN} printable ASCII characters"
            )));
        }
        call.subject = Some(format!("{purpose}/{subject_id}"));
        Ok(DataBinding {
            tenant_id,
            purpose,
            subject_id,
        })
    }
}

#[tonic::async_trait]
impl vault_service_server::VaultService for VaultService {
    async fn create_key(
        &self,
        request: Request<CreateKeyRequest>,
    ) -> Result<Response<CreateKeyResponse>, Status> {
        let mut call = Call::start(Rpc::CreateKey, &request);
        let result = self.handle_create(&mut call, request).await;
        self.finish(&call, result)
    }

    async fn get_decrypted_key(
        &self,
        request: Request<GetDecryptedKeyRequest>,
    ) -> Result<Response<GetDecryptedKeyResponse>, Status> {
        let mut call = Call::start(Rpc::GetDecryptedKey, &request);
        let result = self.handle_get(&mut call, request).await;
        self.finish(&call, result)
    }

    async fn revoke_key(
        &self,
        request: Request<RevokeKeyRequest>,
    ) -> Result<Response<RevokeKeyResponse>, Status> {
        let mut call = Call::start(Rpc::RevokeKey, &request);
        let result = self.handle_revoke(&mut call, request).await;
        self.finish(&call, result)
    }

    async fn seal_data(
        &self,
        request: Request<SealDataRequest>,
    ) -> Result<Response<SealDataResponse>, Status> {
        let mut call = Call::start(Rpc::SealData, &request);
        let result = self.handle_seal(&mut call, request).await;
        self.finish(&call, result)
    }

    async fn open_data(
        &self,
        request: Request<OpenDataRequest>,
    ) -> Result<Response<OpenDataResponse>, Status> {
        let mut call = Call::start(Rpc::OpenData, &request);
        let result = self.handle_open(&mut call, request).await;
        self.finish(&call, result)
    }
}

fn parse_uuid(field: &str, value: &str) -> Result<Uuid, VaultError> {
    if value.is_empty() {
        return Err(VaultError::invalid(format!("{field} is required")));
    }
    Uuid::try_parse(value).map_err(|_| VaultError::invalid(format!("{field} must be a UUID")))
}

fn parse_optional_uuid(field: &str, value: &str) -> Result<Option<Uuid>, VaultError> {
    if value.is_empty() {
        Ok(None)
    } else {
        parse_uuid(field, value).map(Some)
    }
}

fn validate_label(label: &str) -> Result<(), VaultError> {
    let chars = label.chars().count();
    if chars == 0 || chars > MAX_LABEL_CHARS || label.trim().is_empty() {
        return Err(VaultError::invalid(format!(
            "label must be 1 to {MAX_LABEL_CHARS} characters and not blank"
        )));
    }
    if label.chars().any(char::is_control) {
        return Err(VaultError::invalid(
            "label must not contain control characters",
        ));
    }
    Ok(())
}

/// Never echoes the secret, not even its length.
fn validate_secret(secret: &[u8]) -> Result<(), VaultError> {
    let length_ok = (MIN_SECRET_LEN..=MAX_SECRET_LEN).contains(&secret.len());
    let charset_ok = secret.iter().all(|b| (0x21..=0x7e).contains(b));
    if length_ok && charset_ok {
        Ok(())
    } else {
        Err(VaultError::invalid(format!(
            "secret must be {MIN_SECRET_LEN} to {MAX_SECRET_LEN} bytes of printable ASCII without whitespace"
        )))
    }
}

/// Last characters of an already validated (printable ASCII) secret.
fn key_hint(secret: &[u8]) -> String {
    let tail = &secret[secret.len().saturating_sub(KEY_HINT_LEN)..];
    tail.iter().map(|&b| char::from(b)).collect()
}

fn is_valid_request_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_REQUEST_ID_LEN
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
}

fn error_chain(error: &dyn Error) -> String {
    let mut message = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        message.push_str(": ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }
    message
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_are_validated_without_echoing_them() {
        let good = b"sk-proj-abcdefghijklmnop";
        assert!(validate_secret(good).is_ok());

        let too_short = b"sk-short";
        let with_space = b"sk-proj-abcdef ghijklmnop";
        let with_newline = b"sk-proj-abcdefghijklmnop\n";
        let too_long = vec![b'a'; MAX_SECRET_LEN + 1];
        for bad in [&too_short[..], with_space, with_newline, &too_long] {
            match validate_secret(bad) {
                Err(VaultError::InvalidArgument(message)) => {
                    assert!(!message.contains("sk-"), "{message}");
                }
                other => panic!("expected InvalidArgument, got {other:?}"),
            }
        }
    }

    #[test]
    fn labels_are_bounded_and_printable() {
        assert!(validate_label("Production xAI").is_ok());
        assert!(validate_label(&"λ".repeat(MAX_LABEL_CHARS)).is_ok());
        for bad in ["", "   ", "tab\there", &"x".repeat(MAX_LABEL_CHARS + 1)] {
            assert!(validate_label(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn key_hint_is_the_last_four_characters() {
        assert_eq!(key_hint(b"sk-proj-abcdefghijklmnopWXYZ"), "WXYZ");
    }

    #[test]
    fn uuids_are_required_and_parsed() {
        assert!(
            matches!(parse_uuid("tenant_id", ""), Err(VaultError::InvalidArgument(m)) if m.contains("required"))
        );
        assert!(parse_uuid("tenant_id", "not-a-uuid").is_err());
        assert_eq!(parse_optional_uuid("request_id", "").ok(), Some(None));
        let id = Uuid::now_v7();
        assert_eq!(parse_uuid("key_id", &id.to_string()).ok(), Some(id));
    }

    #[test]
    fn request_ids_are_sanitised() {
        assert!(is_valid_request_id("req-123_abc.def:9"));
        for bad in [
            "",
            "has space",
            "new\nline",
            &"a".repeat(MAX_REQUEST_ID_LEN + 1),
        ] {
            assert!(!is_valid_request_id(bad), "accepted {bad:?}");
        }
    }
}
