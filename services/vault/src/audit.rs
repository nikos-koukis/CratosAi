//! Audit trail. One event per RPC, success or failure, carrying who asked for
//! what and the outcome. Events never contain secret material.

use std::fmt::Debug;

use tonic::Code;
use uuid::Uuid;

use crate::authz::Rpc;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEvent {
    pub rpc: Rpc,
    pub request_id: String,
    /// Authenticated caller; `None` if authentication itself failed.
    pub caller: Option<String>,
    pub tenant_id: Option<Uuid>,
    pub key_id: Option<Uuid>,
    /// For sealed data: `purpose/subject_id` (never the data itself).
    pub subject: Option<String>,
    pub outcome: AuditOutcome,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuditOutcome {
    Success,
    Failure {
        code: Code,
        reason: Option<&'static str>,
    },
}

/// Destination for audit events. Implementations must not block for long:
/// `record` runs inline on the request path.
pub trait AuditSink: Debug + Send + Sync + 'static {
    fn record(&self, event: &AuditEvent);
}

/// Emits audit events as structured log records with target `audit`, so the
/// log pipeline can route them separately from operational logs.
#[derive(Debug, Default)]
pub struct TracingAuditSink;

impl AuditSink for TracingAuditSink {
    fn record(&self, event: &AuditEvent) {
        let (outcome, code, reason) = match &event.outcome {
            AuditOutcome::Success => ("success", Code::Ok, None),
            AuditOutcome::Failure { code, reason } => ("failure", *code, *reason),
        };
        tracing::info!(
            target: "audit",
            rpc = event.rpc.as_str(),
            request_id = %event.request_id,
            caller = event.caller.as_deref(),
            tenant_id = event.tenant_id.map(tracing::field::display),
            key_id = event.key_id.map(tracing::field::display),
            subject = event.subject.as_deref(),
            outcome,
            code = ?code,
            reason,
            "vault audit event"
        );
    }
}
