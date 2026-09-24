//! Audit trail. One event per RPC, success or failure, carrying who asked for
//! what and the outcome. Events never contain secret material.

use std::{fmt::Debug, time::Duration};

use tokio::{sync::mpsc, task::JoinHandle};
use tonic::{Code, Status, transport::Channel};
use uuid::Uuid;

use crate::{
    authz::Rpc,
    proto::audit_v1::{self, audit_service_client::AuditServiceClient},
};

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

/// Sends events to several sinks (e.g. the log and the audit service).
#[derive(Debug)]
pub struct TeeAuditSink(pub Vec<std::sync::Arc<dyn AuditSink>>);

impl AuditSink for TeeAuditSink {
    fn record(&self, event: &AuditEvent) {
        for sink in &self.0 {
            sink.record(event);
        }
    }
}

/// The trail entry for a Vault event: key lifecycle and every plaintext read,
/// for the key's tenant. Listing keys and sealing services' own data are not
/// user-visible actions and stay in the log only.
pub fn to_audit_event(event: &AuditEvent, now: std::time::SystemTime) -> Option<audit_v1::Event> {
    let action = match event.rpc {
        Rpc::CreateKey => "key.created",
        Rpc::RevokeKey => "key.revoked",
        Rpc::GetDecryptedKey => "key.read",
        Rpc::ListKeys | Rpc::SealData | Rpc::OpenData => return None,
    };
    let tenant = event.tenant_id?;
    // The caller is a service: its short name (spiffe://jarvis.local/<name>).
    let caller = event
        .caller
        .as_deref()
        .map_or("unauthenticated", |c| c.rsplit('/').next().unwrap_or(c));
    let (outcome, reason) = match &event.outcome {
        AuditOutcome::Success => (audit_v1::Outcome::Success, String::new()),
        AuditOutcome::Failure { code, reason } => {
            let outcome = if matches!(code, Code::PermissionDenied | Code::Unauthenticated) {
                audit_v1::Outcome::Denied
            } else {
                audit_v1::Outcome::Failure
            };
            let reason = reason.map_or_else(|| format!("{code:?}"), |r| r.to_owned());
            (outcome, reason.to_ascii_lowercase())
        }
    };
    Some(audit_v1::Event {
        event_id: Uuid::now_v7().to_string(),
        tenant_id: tenant.to_string(),
        occur_time: Some(prost_types::Timestamp::from(now)),
        actor: Some(audit_v1::Actor {
            kind: audit_v1::ActorKind::Service.into(),
            id: caller.chars().take(128).collect(),
        }),
        action: action.to_owned(),
        target_type: "provider_key".to_owned(),
        target_id: event.key_id.map(|id| id.to_string()).unwrap_or_default(),
        outcome: outcome.into(),
        reason: reason.chars().take(64).collect(),
        request_id: event
            .request_id
            .chars()
            .filter(|c| c.is_ascii_graphic())
            .take(128)
            .collect(),
        ..Default::default()
    })
}

const QUEUE: usize = 10_000;
const BATCH: usize = 200;
const FLUSH_EVERY: Duration = Duration::from_millis(500);
const CALL_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// Records Vault events at the audit service (AuditService.Record) from a
/// background task, so a slow or absent audit service never slows a request.
/// Events wait in a bounded queue; failed batches are retried with backoff
/// (the service ignores events it already has). Events that cannot be
/// delivered are logged ("audit event not delivered"), never silently lost.
#[derive(Debug)]
pub struct GrpcAuditSink {
    queue: mpsc::Sender<audit_v1::Event>,
}

/// The background task of a [`GrpcAuditSink`].
#[derive(Debug)]
pub struct AuditShipper(JoinHandle<()>);

impl GrpcAuditSink {
    /// Starts shipping events through `channel`.
    pub fn start(channel: Channel) -> (Self, AuditShipper) {
        let (queue, events) = mpsc::channel(QUEUE);
        let task = tokio::spawn(ship(AuditServiceClient::new(channel), events));
        (Self { queue }, AuditShipper(task))
    }
}

impl AuditShipper {
    /// Waits (up to `timeout`) for queued events to be sent, once every sink
    /// has been dropped.
    pub async fn finish(self, timeout: Duration) {
        if tokio::time::timeout(timeout, self.0).await.is_err() {
            tracing::warn!(target: "audit", "audit events still queued at shutdown were not delivered");
        }
    }
}

impl AuditSink for GrpcAuditSink {
    fn record(&self, event: &AuditEvent) {
        let Some(entry) = to_audit_event(event, std::time::SystemTime::now()) else {
            return;
        };
        match self.queue.try_send(entry) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(entry)) => {
                undelivered(&entry, "the audit queue is full")
            }
            Err(mpsc::error::TrySendError::Closed(entry)) => {
                undelivered(&entry, "the audit shipper has stopped")
            }
        }
    }
}

fn undelivered(e: &audit_v1::Event, why: &str) {
    tracing::warn!(
        target: "audit",
        why,
        event_id = %e.event_id,
        tenant_id = %e.tenant_id,
        action = %e.action,
        target_id = %e.target_id,
        outcome = e.outcome,
        reason = %e.reason,
        "audit event not delivered"
    );
}

async fn ship(
    mut client: AuditServiceClient<Channel>,
    mut events: mpsc::Receiver<audit_v1::Event>,
) {
    let mut batch: Vec<audit_v1::Event> = Vec::new();
    let mut backoff = Duration::from_secs(1);
    let mut open = true;
    loop {
        // Fill a batch: up to BATCH events, or what arrives within FLUSH_EVERY.
        if open && batch.len() < BATCH {
            match tokio::time::timeout(FLUSH_EVERY, events.recv()).await {
                Ok(Some(event)) => {
                    batch.push(event);
                    continue;
                }
                Ok(None) => open = false, // every sink is gone: flush and stop
                Err(_) => {}              // time to send what there is
            }
        }
        if batch.is_empty() {
            if open {
                continue;
            }
            return;
        }
        let n = batch.len().min(BATCH);
        match send(&mut client, &batch[..n]).await {
            Ok(()) => {
                batch.drain(..n);
                backoff = Duration::from_secs(1);
            }
            Err(status) if !open => {
                tracing::warn!(target: "audit", error = %status, "audit service unreachable at shutdown");
                for event in &batch {
                    undelivered(event, "the audit service was unreachable at shutdown");
                }
                return;
            }
            Err(status) => {
                tracing::warn!(target: "audit", error = %status, events = n, backoff_ms = backoff.as_millis(),
                    "cannot record audit events; retrying");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
        }
    }
}

/// Records a batch. A batch refused as malformed is sent one event at a time,
/// so one bad event does not lose the others.
async fn send(
    client: &mut AuditServiceClient<Channel>,
    batch: &[audit_v1::Event],
) -> Result<(), Status> {
    match call(client, batch.to_vec()).await {
        Err(status) if status.code() == Code::InvalidArgument => {
            for event in batch {
                match call(client, vec![event.clone()]).await {
                    Ok(()) => {}
                    Err(status) if status.code() == Code::InvalidArgument => {
                        tracing::error!(target: "audit", error = %status,
                            "the audit service refused an event (a bug in the Vault)");
                        undelivered(event, "refused as malformed");
                    }
                    Err(status) => return Err(status),
                }
            }
            Ok(())
        }
        other => other,
    }
}

async fn call(
    client: &mut AuditServiceClient<Channel>,
    events: Vec<audit_v1::Event>,
) -> Result<(), Status> {
    let mut request = tonic::Request::new(audit_v1::RecordRequest { events });
    request.set_timeout(CALL_TIMEOUT);
    client.record(request).await.map(|_| ())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn event(rpc: Rpc, outcome: AuditOutcome) -> AuditEvent {
        AuditEvent {
            rpc,
            request_id: "req-1".to_owned(),
            caller: Some("spiffe://jarvis.local/voice-gateway".to_owned()),
            tenant_id: Some(Uuid::nil()),
            key_id: Some(Uuid::max()),
            subject: None,
            outcome,
        }
    }

    #[test]
    fn key_events_become_trail_entries_by_the_calling_service() {
        let now = std::time::SystemTime::now();
        let read =
            to_audit_event(&event(Rpc::GetDecryptedKey, AuditOutcome::Success), now).unwrap();
        assert_eq!(read.action, "key.read");
        assert_eq!(read.actor.as_ref().unwrap().id, "voice-gateway");
        assert_eq!(
            read.actor.as_ref().unwrap().kind(),
            audit_v1::ActorKind::Service
        );
        assert_eq!(read.outcome(), audit_v1::Outcome::Success);
        assert_eq!(read.target_type, "provider_key");
        assert_eq!(read.target_id, Uuid::max().to_string());
        assert_eq!(read.request_id, "req-1");
        assert!(Uuid::parse_str(&read.event_id).is_ok());

        let refused = AuditOutcome::Failure {
            code: Code::PermissionDenied,
            reason: None,
        };
        let denied = to_audit_event(&event(Rpc::CreateKey, refused), now).unwrap();
        assert_eq!(
            (denied.action.as_str(), denied.outcome()),
            ("key.created", audit_v1::Outcome::Denied)
        );
        let revoked_missing = AuditOutcome::Failure {
            code: Code::NotFound,
            reason: Some("ERROR_REASON_KEY_NOT_FOUND"),
        };
        let failed = to_audit_event(&event(Rpc::RevokeKey, revoked_missing), now).unwrap();
        assert_eq!(failed.outcome(), audit_v1::Outcome::Failure);
        assert_eq!(failed.reason, "error_reason_key_not_found");
    }

    #[test]
    fn listing_sealing_and_tenantless_events_stay_in_the_log() {
        let now = std::time::SystemTime::now();
        for rpc in [Rpc::ListKeys, Rpc::SealData, Rpc::OpenData] {
            assert!(to_audit_event(&event(rpc, AuditOutcome::Success), now).is_none());
        }
        let mut anonymous = event(Rpc::GetDecryptedKey, AuditOutcome::Success);
        anonymous.tenant_id = None;
        assert!(to_audit_event(&anonymous, now).is_none());
    }
}
