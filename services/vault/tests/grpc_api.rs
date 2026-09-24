//! End-to-end tests of the Vault gRPC API against real PostgreSQL over mTLS.
//! Requires Docker.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::*;
use jarvis_vault::{
    audit::AuditOutcome,
    authz::Rpc,
    proto::{
        common_v1::Provider,
        vault_v1::{KeyStatus, RevocationReason},
    },
    store::{KekRegistryError, KeyStore},
};
use tonic::{Code, Request};
use uuid::Uuid;

#[tokio::test(flavor = "multi_thread")]
async fn stored_keys_decrypt_by_id_and_by_provider() {
    let vault = TestVault::start().await;
    let tenant = Uuid::now_v7();
    let mut dashboard = vault.client(DASHBOARD).await;
    let mut gateway = vault.client(GATEWAY).await;

    let created = dashboard
        .create_key(create_request(
            tenant,
            Provider::Xai,
            "Production xAI",
            XAI_SECRET,
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(created.replaced_key.is_none());
    let key = created.key.unwrap();
    assert_eq!(key.tenant_id, tenant.to_string());
    assert_eq!(key.provider(), Provider::Xai);
    assert_eq!(key.label, "Production xAI");
    assert_eq!(key.key_hint, &XAI_SECRET[XAI_SECRET.len() - 4..]);
    assert_eq!(key.status(), KeyStatus::Active);
    assert!(key.create_time.is_some());
    assert!(key.revoke_time.is_none());

    let by_id = gateway
        .get_decrypted_key(get_by_id(tenant, &key.key_id))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(by_id.key_id, key.key_id);
    assert_eq!(by_id.secret, XAI_SECRET.as_bytes());

    let by_provider = gateway
        .get_decrypted_key(get_by_provider(tenant, Provider::Xai))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(by_provider.key_id, key.key_id);
    assert_eq!(by_provider.secret, XAI_SECRET.as_bytes());

    let no_openai_key = gateway
        .get_decrypted_key(get_by_provider(tenant, Provider::Openai))
        .await
        .unwrap_err();
    assert_eq!(no_openai_key.code(), Code::NotFound);
    assert_eq!(
        error_reason(&no_openai_key).as_deref(),
        Some("ERROR_REASON_KEY_NOT_FOUND")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn database_holds_only_ciphertext() {
    let vault = TestVault::start().await;
    let tenant = Uuid::now_v7();
    let mut dashboard = vault.client(DASHBOARD).await;
    dashboard
        .create_key(create_request(
            tenant,
            Provider::Openai,
            "OpenAI",
            OPENAI_SECRET,
        ))
        .await
        .unwrap();

    // Every table, every column, rendered as text (bytea as hex).
    let dump: Vec<String> = sqlx::query_scalar(
        "SELECT row_to_json(t)::text FROM provider_keys t
         UNION ALL SELECT row_to_json(t)::text FROM create_key_requests t
         UNION ALL SELECT row_to_json(t)::text FROM kek_registry t",
    )
    .fetch_all(&vault.pool)
    .await
    .unwrap();
    let dump = dump.join("\n");
    let secret_hex: String = OPENAI_SECRET.bytes().map(|b| format!("{b:02x}")).collect();

    assert!(
        dump.contains("\"ciphertext\":\"\\\\x"),
        "ciphertext missing: {dump}"
    );
    assert!(!dump.contains(OPENAI_SECRET));
    assert!(!dump.contains(&secret_hex));
    assert!(!dump.contains(&OPENAI_SECRET[..20]));
}

#[tokio::test(flavor = "multi_thread")]
async fn one_active_key_per_provider_with_atomic_rotation() {
    let vault = TestVault::start().await;
    let tenant = Uuid::now_v7();
    let mut dashboard = vault.client(DASHBOARD).await;
    let mut gateway = vault.client(GATEWAY).await;

    let first = dashboard
        .create_key(create_request(tenant, Provider::Xai, "first", XAI_SECRET))
        .await
        .unwrap()
        .into_inner()
        .key
        .unwrap();

    let second_secret = "xai-TESTKEY-SECOND-9999999999999999";
    let conflict = dashboard
        .create_key(create_request(
            tenant,
            Provider::Xai,
            "second",
            second_secret,
        ))
        .await
        .unwrap_err();
    assert_eq!(conflict.code(), Code::AlreadyExists);
    assert_eq!(
        error_reason(&conflict).as_deref(),
        Some("ERROR_REASON_ACTIVE_KEY_EXISTS")
    );

    // A different provider is independent.
    dashboard
        .create_key(create_request(
            tenant,
            Provider::Openai,
            "openai",
            OPENAI_SECRET,
        ))
        .await
        .unwrap();

    let mut rotate = create_request(tenant, Provider::Xai, "second", second_secret);
    rotate.replace_active = true;
    let rotated = dashboard.create_key(rotate).await.unwrap().into_inner();
    let second = rotated.key.unwrap();
    let replaced = rotated.replaced_key.unwrap();
    assert_eq!(replaced.key_id, first.key_id);
    assert_eq!(replaced.status(), KeyStatus::Revoked);
    assert_eq!(replaced.revocation_reason(), RevocationReason::Rotated);

    let current = gateway
        .get_decrypted_key(get_by_provider(tenant, Provider::Xai))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(current.key_id, second.key_id);
    assert_eq!(current.secret, second_secret.as_bytes());

    let old = gateway
        .get_decrypted_key(get_by_id(tenant, &first.key_id))
        .await
        .unwrap_err();
    assert_eq!(old.code(), Code::FailedPrecondition);
    assert_eq!(
        error_reason(&old).as_deref(),
        Some("ERROR_REASON_KEY_REVOKED")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn revocation_destroys_ciphertext_and_is_idempotent() {
    let vault = TestVault::start().await;
    let tenant = Uuid::now_v7();
    let mut dashboard = vault.client(DASHBOARD).await;
    let mut gateway = vault.client(GATEWAY).await;

    let key = dashboard
        .create_key(create_request(tenant, Provider::Xai, "xai", XAI_SECRET))
        .await
        .unwrap()
        .into_inner()
        .key
        .unwrap();

    let revoked = dashboard
        .revoke_key(revoke_request(
            tenant,
            &key.key_id,
            RevocationReason::Compromised,
        ))
        .await
        .unwrap()
        .into_inner()
        .key
        .unwrap();
    assert_eq!(revoked.status(), KeyStatus::Revoked);
    assert_eq!(revoked.revocation_reason(), RevocationReason::Compromised);
    assert!(revoked.revoke_time.is_some());

    let (shredded, revoked_by): (bool, Option<String>) = sqlx::query_as(
        "SELECT ciphertext IS NULL AND wrapped_dek IS NULL AND dek_nonce IS NULL
                AND nonce IS NULL AND kek_id IS NULL,
                revoked_by
         FROM provider_keys WHERE key_id = $1",
    )
    .bind(Uuid::parse_str(&key.key_id).unwrap())
    .fetch_one(&vault.pool)
    .await
    .unwrap();
    assert!(shredded, "revocation must destroy all crypto material");
    assert_eq!(revoked_by.as_deref(), Some(DASHBOARD));

    // Second revocation: success, unchanged metadata (original reason and time).
    let again = dashboard
        .revoke_key(revoke_request(
            tenant,
            &key.key_id,
            RevocationReason::UserRequested,
        ))
        .await
        .unwrap()
        .into_inner()
        .key
        .unwrap();
    assert_eq!(again, revoked);

    let status = gateway
        .get_decrypted_key(get_by_id(tenant, &key.key_id))
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::FailedPrecondition);

    // The provider slot is free again.
    dashboard
        .create_key(create_request(tenant, Provider::Xai, "new", XAI_SECRET))
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn keys_of_other_tenants_are_indistinguishable_from_missing_ones() {
    let vault = TestVault::start().await;
    let owner = Uuid::now_v7();
    let intruder = Uuid::now_v7();
    let mut dashboard = vault.client(DASHBOARD).await;
    let mut gateway = vault.client(GATEWAY).await;

    let key = dashboard
        .create_key(create_request(owner, Provider::Xai, "xai", XAI_SECRET))
        .await
        .unwrap()
        .into_inner()
        .key
        .unwrap();

    let foreign = gateway
        .get_decrypted_key(get_by_id(intruder, &key.key_id))
        .await
        .unwrap_err();
    let missing = gateway
        .get_decrypted_key(get_by_id(intruder, &Uuid::now_v7().to_string()))
        .await
        .unwrap_err();
    assert_eq!(foreign.code(), Code::NotFound);
    assert_eq!(
        (foreign.code(), foreign.message(), error_reason(&foreign)),
        (missing.code(), missing.message(), error_reason(&missing))
    );

    let revoke = dashboard
        .revoke_key(revoke_request(
            intruder,
            &key.key_id,
            RevocationReason::UserRequested,
        ))
        .await
        .unwrap_err();
    assert_eq!(revoke.code(), Code::NotFound);

    // The owner's key is untouched.
    let still_there = gateway
        .get_decrypted_key(get_by_id(owner, &key.key_id))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(still_there.secret, XAI_SECRET.as_bytes());
}

#[tokio::test(flavor = "multi_thread")]
async fn create_is_idempotent_on_request_id() {
    let vault = TestVault::start().await;
    let tenant = Uuid::now_v7();
    let dashboard = vault.client(DASHBOARD).await;
    let request_id = Uuid::now_v7().to_string();

    let build = |secret: &str| {
        let mut request = create_request(tenant, Provider::Xai, "xai", secret);
        request.request_id = request_id.clone();
        request
    };

    // Concurrent retries of the same request all resolve to one key.
    let attempts = (0..5).map(|_| {
        let mut client = dashboard.clone();
        let request = build(XAI_SECRET);
        tokio::spawn(async move { client.create_key(request).await })
    });
    let mut key_ids = Vec::new();
    for attempt in attempts {
        let response = attempt.await.unwrap().unwrap().into_inner();
        key_ids.push(response.key.unwrap().key_id);
    }
    key_ids.dedup();
    assert_eq!(
        key_ids.len(),
        1,
        "retries created different keys: {key_ids:?}"
    );

    let stored: i64 = sqlx::query_scalar("SELECT count(*) FROM provider_keys WHERE tenant_id = $1")
        .bind(tenant)
        .fetch_one(&vault.pool)
        .await
        .unwrap();
    assert_eq!(stored, 1);

    // Same request_id with a different payload is a conflict, not a replay.
    let conflict = dashboard
        .clone()
        .create_key(build("xai-TESTKEY-DIFFERENT-000000000000"))
        .await
        .unwrap_err();
    assert_eq!(conflict.code(), Code::AlreadyExists);
    assert_eq!(
        error_reason(&conflict).as_deref(),
        Some("ERROR_REASON_REQUEST_ID_CONFLICT")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_writers_leave_exactly_one_active_key() {
    let vault = TestVault::start().await;
    let dashboard = vault.client(DASHBOARD).await;

    // With rotation, every writer succeeds and replaces its predecessor.
    let rotating_tenant = Uuid::now_v7();
    let writers = (0..10).map(|i| {
        let mut client = dashboard.clone();
        let mut request = create_request(
            rotating_tenant,
            Provider::Xai,
            &format!("writer {i}"),
            &format!("xai-TESTKEY-CONCURRENT-{i:020}"),
        );
        request.replace_active = true;
        tokio::spawn(async move { client.create_key(request).await })
    });
    for writer in writers {
        writer.await.unwrap().unwrap();
    }

    // Without rotation, exactly one writer wins.
    let racing_tenant = Uuid::now_v7();
    let racers = (0..10).map(|i| {
        let mut client = dashboard.clone();
        let request = create_request(
            racing_tenant,
            Provider::Xai,
            &format!("racer {i}"),
            &format!("xai-TESTKEY-RACING-{i:020}"),
        );
        tokio::spawn(async move { client.create_key(request).await })
    });
    let mut winners = 0;
    for racer in racers {
        match racer.await.unwrap() {
            Ok(_) => winners += 1,
            Err(status) => assert_eq!(status.code(), Code::AlreadyExists),
        }
    }
    assert_eq!(winners, 1);

    for tenant in [rotating_tenant, racing_tenant] {
        let active: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM provider_keys WHERE tenant_id = $1 AND status = 'active'",
        )
        .bind(tenant)
        .fetch_one(&vault.pool)
        .await
        .unwrap();
        assert_eq!(active, 1);
    }
    let rotated: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM provider_keys WHERE tenant_id = $1 AND revocation_reason = 'rotated'",
    )
    .bind(rotating_tenant)
    .fetch_one(&vault.pool)
    .await
    .unwrap();
    assert_eq!(rotated, 9);
}

#[tokio::test(flavor = "multi_thread")]
async fn callers_reach_only_the_rpcs_they_are_granted() {
    let vault = TestVault::start().await;
    let tenant = Uuid::now_v7();
    let mut dashboard = vault.client(DASHBOARD).await;
    let mut gateway = vault.client(GATEWAY).await;
    let mut stranger = vault.client(STRANGER).await;

    let key = dashboard
        .create_key(create_request(tenant, Provider::Xai, "xai", XAI_SECRET))
        .await
        .unwrap()
        .into_inner()
        .key
        .unwrap();

    // The dashboard manages keys but can never read plaintext.
    let status = dashboard
        .get_decrypted_key(get_by_id(tenant, &key.key_id))
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::PermissionDenied);

    // The gateway reads keys but cannot create or revoke them.
    let status = gateway
        .create_key(create_request(tenant, Provider::Openai, "x", OPENAI_SECRET))
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::PermissionDenied);
    let status = gateway
        .revoke_key(revoke_request(
            tenant,
            &key.key_id,
            RevocationReason::UserRequested,
        ))
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::PermissionDenied);

    // A valid certificate that the policy does not mention gets nothing.
    for status in [
        stranger
            .get_decrypted_key(get_by_id(tenant, &key.key_id))
            .await
            .unwrap_err(),
        stranger
            .create_key(create_request(tenant, Provider::Openai, "x", OPENAI_SECRET))
            .await
            .unwrap_err(),
    ] {
        assert_eq!(status.code(), Code::PermissionDenied);
    }

    let denied = vault
        .audit
        .events()
        .into_iter()
        .filter(|e| {
            matches!(
                e.outcome,
                AuditOutcome::Failure {
                    code: Code::PermissionDenied,
                    ..
                }
            )
        })
        .count();
    assert_eq!(denied, 5);
}

#[tokio::test(flavor = "multi_thread")]
async fn clients_without_a_certificate_are_rejected() {
    let vault = TestVault::start().await;

    // Depending on timing the TLS handshake fails at connect or on first use.
    let rejected = match vault.anonymous_client().await {
        Err(_) => true,
        Ok(mut client) => client
            .get_decrypted_key(get_by_provider(Uuid::now_v7(), Provider::Xai))
            .await
            .is_err(),
    };
    assert!(rejected);
    assert!(
        vault.audit.events().is_empty(),
        "no RPC may run without mTLS"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_requests_are_rejected_without_echoing_the_secret() {
    let vault = TestVault::start().await;
    let tenant = Uuid::now_v7();
    let mut dashboard = vault.client(DASHBOARD).await;
    let mut gateway = vault.client(GATEWAY).await;

    let mut bad_creates = Vec::new();
    let mut r = create_request(tenant, Provider::Xai, "x", XAI_SECRET);
    r.tenant_id = "not-a-uuid".into();
    bad_creates.push(r);
    bad_creates.push(create_request(
        tenant,
        Provider::Unspecified,
        "x",
        XAI_SECRET,
    ));
    bad_creates.push(create_request(tenant, Provider::Xai, "", XAI_SECRET));
    bad_creates.push(create_request(tenant, Provider::Xai, "x", "xai-SHORT"));
    bad_creates.push(create_request(
        tenant,
        Provider::Xai,
        "x",
        "xai-TESTKEY with spaces 0000000",
    ));
    let mut r = create_request(tenant, Provider::Xai, "x", XAI_SECRET);
    r.request_id = "retry-1".into();
    bad_creates.push(r);

    for request in bad_creates {
        let status = dashboard.create_key(request).await.unwrap_err();
        assert_eq!(status.code(), Code::InvalidArgument, "{status:?}");
        assert!(!status.message().contains("TESTKEY"), "{status:?}");
        assert!(!status.message().contains("SHORT"), "{status:?}");
    }

    let mut no_selector = get_by_provider(tenant, Provider::Xai);
    no_selector.selector = None;
    for request in [
        no_selector,
        get_by_provider(tenant, Provider::Unspecified),
        get_by_id(tenant, "123"),
    ] {
        let status = gateway.get_decrypted_key(request).await.unwrap_err();
        assert_eq!(status.code(), Code::InvalidArgument, "{status:?}");
    }

    let status = dashboard
        .revoke_key(revoke_request(
            tenant,
            &Uuid::now_v7().to_string(),
            RevocationReason::Unspecified,
        ))
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::InvalidArgument);

    let stored: i64 = sqlx::query_scalar("SELECT count(*) FROM provider_keys")
        .fetch_one(&vault.pool)
        .await
        .unwrap();
    assert_eq!(stored, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn every_call_is_audited_with_the_callers_request_id() {
    let vault = TestVault::start().await;
    let tenant = Uuid::now_v7();
    let mut dashboard = vault.client(DASHBOARD).await;
    let mut gateway = vault.client(GATEWAY).await;

    let mut request = Request::new(create_request(tenant, Provider::Xai, "xai", XAI_SECRET));
    request
        .metadata_mut()
        .insert("x-request-id", "req-create-1".parse().unwrap());
    let key = dashboard
        .create_key(request)
        .await
        .unwrap()
        .into_inner()
        .key
        .unwrap();

    let mut request = Request::new(get_by_provider(tenant, Provider::Xai));
    request
        .metadata_mut()
        .insert("x-request-id", "req-get-1".parse().unwrap());
    gateway.get_decrypted_key(request).await.unwrap();

    gateway
        .get_decrypted_key(get_by_provider(tenant, Provider::Openai))
        .await
        .unwrap_err();

    let events = vault.audit.events();
    assert_eq!(events.len(), 3);

    assert_eq!(events[0].rpc, Rpc::CreateKey);
    assert_eq!(events[0].request_id, "req-create-1");
    assert_eq!(events[0].caller.as_deref(), Some(DASHBOARD));
    assert_eq!(events[0].tenant_id, Some(tenant));
    assert_eq!(
        events[0].key_id.map(|k| k.to_string()),
        Some(key.key_id.clone())
    );
    assert_eq!(events[0].outcome, AuditOutcome::Success);

    assert_eq!(events[1].rpc, Rpc::GetDecryptedKey);
    assert_eq!(events[1].request_id, "req-get-1");
    assert_eq!(events[1].caller.as_deref(), Some(GATEWAY));
    assert_eq!(events[1].key_id.map(|k| k.to_string()), Some(key.key_id));

    // Missing header: a request id is generated.
    assert!(Uuid::parse_str(&events[2].request_id).is_ok());
    assert_eq!(
        events[2].outcome,
        AuditOutcome::Failure {
            code: Code::NotFound,
            reason: Some("ERROR_REASON_KEY_NOT_FOUND")
        }
    );

    let rendered = format!("{events:?}");
    assert!(!rendered.contains("TESTKEY"));
}

#[tokio::test(flavor = "multi_thread")]
async fn health_check_reports_serving() {
    use tonic_health::pb::{
        HealthCheckRequest, health_check_response::ServingStatus, health_client::HealthClient,
    };

    let vault = TestVault::start().await;
    let mut health = HealthClient::new(vault.channel(GATEWAY).await);
    let response = health
        .check(HealthCheckRequest {
            service: "jarvis.vault.v1.VaultService".into(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.status(), ServingStatus::Serving);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_different_master_key_is_refused() {
    let vault = TestVault::start().await;
    let store = KeyStore::new(vault.pool.clone());
    let other = jarvis_vault::crypto::MasterKey::from_key_bytes(&[7; 32]).unwrap();

    match store.register_kek(other.kek_id()).await {
        Err(KekRegistryError::Mismatch { current, .. }) => assert_eq!(current, other.kek_id()),
        other => panic!("expected mismatch, got {other:?}"),
    }
    let registered: i64 = sqlx::query_scalar("SELECT count(*) FROM kek_registry")
        .fetch_one(&vault.pool)
        .await
        .unwrap();
    assert_eq!(registered, 1, "the wrong KEK must not be registered");
}
