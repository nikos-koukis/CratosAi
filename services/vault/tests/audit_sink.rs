//! The Vault's audit sink against a fake audit service: delivery in batches,
//! retries while it is down, one refused event not losing the others, and a
//! flush at shutdown.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use jarvis_vault::{
    audit::{AuditEvent, AuditOutcome, AuditSink, GrpcAuditSink},
    authz::Rpc,
    proto::audit_v1::{
        self, RecordRequest, RecordResponse,
        audit_service_server::{AuditService, AuditServiceServer},
    },
};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Request, Response, Status, transport::Channel};
use uuid::Uuid;

/// Stores events by id, like the real service; refuses revocations as
/// malformed, to stand for an event the service rejects.
#[derive(Default)]
struct Fake {
    events: Mutex<HashMap<String, audit_v1::Event>>,
    calls: Mutex<u32>,
    fail_next: Mutex<u32>,
}

impl Fake {
    fn count(&self) -> usize {
        self.events.lock().unwrap().len()
    }
}

struct FakeService(Arc<Fake>);

#[tonic::async_trait]
impl AuditService for FakeService {
    async fn record(
        &self,
        request: Request<RecordRequest>,
    ) -> Result<Response<RecordResponse>, Status> {
        *self.0.calls.lock().unwrap() += 1;
        {
            let mut fail = self.0.fail_next.lock().unwrap();
            if *fail > 0 {
                *fail -= 1;
                return Err(Status::unavailable("down"));
            }
        }
        let events = request.into_inner().events;
        if events.iter().any(|e| e.action == "key.revoked") {
            return Err(Status::invalid_argument("event 0: malformed"));
        }
        let recorded = i32::try_from(events.len()).unwrap();
        let mut stored = self.0.events.lock().unwrap();
        for e in events {
            stored.insert(e.event_id.clone(), e);
        }
        Ok(Response::new(RecordResponse {
            recorded,
            duplicates: 0,
        }))
    }

    async fn list_events(
        &self,
        _: Request<audit_v1::ListEventsRequest>,
    ) -> Result<Response<audit_v1::ListEventsResponse>, Status> {
        Err(Status::unimplemented("not used"))
    }

    async fn verify_chain(
        &self,
        _: Request<audit_v1::VerifyChainRequest>,
    ) -> Result<Response<audit_v1::VerifyChainResponse>, Status> {
        Err(Status::unimplemented("not used"))
    }
}

async fn serve(fake: Arc<Fake>) -> Channel {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(AuditServiceServer::new(FakeService(fake)))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    Channel::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect_lazy()
}

fn event(rpc: Rpc) -> AuditEvent {
    AuditEvent {
        rpc,
        request_id: "req".to_owned(),
        caller: Some("spiffe://jarvis.local/voice-gateway".to_owned()),
        tenant_id: Some(Uuid::now_v7()),
        key_id: Some(Uuid::now_v7()),
        subject: None,
        outcome: AuditOutcome::Success,
    }
}

async fn eventually(what: &str, check: impl Fn() -> bool) {
    for _ in 0..1500 {
        if check() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("timed out waiting for {what}");
}

#[tokio::test]
async fn events_are_sent_in_batches() {
    let fake = Arc::new(Fake::default());
    let (sink, shipper) = GrpcAuditSink::start(serve(fake.clone()).await);
    for _ in 0..450 {
        sink.record(&event(Rpc::GetDecryptedKey));
    }
    // Listings are not trail events.
    sink.record(&event(Rpc::ListKeys));
    eventually("450 key reads", || fake.count() == 450).await;
    assert!(
        *fake.calls.lock().unwrap() <= 4,
        "450 events in batches of 200"
    );
    let stored = fake
        .events
        .lock()
        .unwrap()
        .values()
        .cloned()
        .collect::<Vec<_>>();
    assert!(
        stored
            .iter()
            .all(|e| e.action == "key.read" && e.actor.as_ref().unwrap().id == "voice-gateway")
    );
    drop(sink);
    shipper.finish(Duration::from_secs(5)).await;
}

#[tokio::test]
async fn events_reach_the_audit_service_after_an_outage() {
    let fake = Arc::new(Fake::default());
    *fake.fail_next.lock().unwrap() = 2;
    let (sink, shipper) = GrpcAuditSink::start(serve(fake.clone()).await);
    for _ in 0..3 {
        sink.record(&event(Rpc::CreateKey));
    }
    eventually("delivery after two failed attempts", || fake.count() == 3).await;
    assert_eq!(*fake.calls.lock().unwrap(), 3);
    drop(sink);
    shipper.finish(Duration::from_secs(5)).await;
}

#[tokio::test]
async fn one_refused_event_does_not_lose_the_others() {
    let fake = Arc::new(Fake::default());
    let (sink, shipper) = GrpcAuditSink::start(serve(fake.clone()).await);
    sink.record(&event(Rpc::GetDecryptedKey));
    sink.record(&event(Rpc::RevokeKey)); // refused by the fake
    sink.record(&event(Rpc::CreateKey));
    drop(sink);
    shipper.finish(Duration::from_secs(5)).await;
    let mut actions = fake
        .events
        .lock()
        .unwrap()
        .values()
        .map(|e| e.action.clone())
        .collect::<Vec<_>>();
    actions.sort();
    assert_eq!(actions, ["key.created", "key.read"]);
}

#[tokio::test]
async fn queued_events_are_flushed_at_shutdown() {
    let fake = Arc::new(Fake::default());
    let (sink, shipper) = GrpcAuditSink::start(serve(fake.clone()).await);
    for _ in 0..5 {
        sink.record(&event(Rpc::GetDecryptedKey));
    }
    drop(sink); // the server stopped taking requests
    shipper.finish(Duration::from_secs(5)).await;
    assert_eq!(fake.count(), 5);
}

#[tokio::test]
async fn shutdown_does_not_wait_forever_for_an_absent_service() {
    // Nothing listens here.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let channel = Channel::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect_lazy();
    let (sink, shipper) = GrpcAuditSink::start(channel);
    sink.record(&event(Rpc::GetDecryptedKey));
    drop(sink);
    let started = std::time::Instant::now();
    shipper.finish(Duration::from_secs(5)).await;
    assert!(started.elapsed() < Duration::from_secs(6));
}
